// Copyright 2025 RustFS Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Receipt-bound on-disk bitrot workflow and artifact contracts.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail, ensure};
use async_trait::async_trait;
use http::Method;
use serde::{Deserialize, Serialize, de};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    fault::{
        backends::chaos_mesh::{
            ChaosGuard, IoChaosSpec, apply_iochaos, iochaos_record_pod_id, require_iochaos_crd,
        },
        checker,
        config::FaultTestConfig,
        events::{RunEventRecorder, RunEventStatus},
        history::{DurabilityCohort, OperationKind, OperationOutcome, OperationRecord, Recorder},
        plan::{ExecutionPlan, StorageRecoveryExecutionPlan},
        preflight::{PreflightCheck, PreflightPhase, PreflightSummary},
        quorum::{ErasureSetMembership, ErasureSetShape},
        reporting::{ResponsibilityDomain, RunMetadata},
        scenarios::{FaultScenario, scenario_spec},
        shutdown::RunDeadline,
        spec::FaultRunSpec,
        storage_recovery::{
            HealMode, HealProgressState, OfflineVersionShardMappingEvidence, ShardMappingSource,
            StorageRecoveryArtifactIdentity, StorageRecoveryCase, VersionShardMappingObservation,
        },
        storage_recovery_helper::{
            CONTROLLED_SHARD_XOR_MASK, MutationJournalLookup, OfflineShardMutationResponse,
            OfflineShardRecoveryResponse, OfflineXl2InspectResponse,
        },
        storage_recovery_lease::{KubernetesStorageLeaseAdapter, StorageRecoveryCleanupProof},
        storage_recovery_runtime::{
            HostFlockProof, KubectlStorageRecoveryAttemptGuard, KubectlStorageRecoveryHostAdapter,
            KubernetesResourceVersions, OwnedStorageContext, StorageRecoveryExclusiveAccess,
            StorageRecoveryHostOperation, StorageRecoveryOperationReceipt, context_sha256,
            same_storage_volume_generation, storage_scope_sha256,
        },
        workload::execution::{
            POST_RECOVERY_WRITE_HISTORY_ARTIFACT, POST_RECOVERY_WRITE_REPORT_ARTIFACT,
            PostRecoveryWriteRequest, WorkloadPlanArtifact, post_recovery_object_count,
            run_post_recovery_write_probe,
        },
        workload::{ObjectSpec, ObjectVersionEntry, S3WorkloadClient, WorkloadPlan},
        xl2_inspector::{OFFLINE_XL2_INSPECTOR_REVISION, Xl2FormatProfile},
    },
    framework::{
        artifacts::ArtifactCollector,
        kube_client::client_for_context,
        kubectl::Kubectl,
        port_forward::{PortForwardGuard, PortForwardSpec},
        resources,
    },
    rustfs::{RustfsAdminResponse, RustfsAdminTransport},
};

pub const BITROT_SELECTION_ARTIFACT: &str = "bitrot-selection.json";
pub const BITROT_MUTATION_ARTIFACT: &str = "bitrot-mutation.json";
pub const BITROT_CORRUPTION_WINDOW_ARTIFACT: &str = "bitrot-corruption-window.json";
pub const BITROT_HEAL_ARTIFACT: &str = "bitrot-heal.json";
pub const BITROT_HEAL_PROGRESS_ARTIFACT: &str = "bitrot-heal-progress.jsonl";
pub const BITROT_ADMIN_HEAL_START_ARTIFACT: &str = "bitrot-admin-heal-start.json";
pub const BITROT_CLEANUP_ARTIFACT: &str = "bitrot-cleanup.json";
pub const BITROT_WORKFLOW_ARTIFACT: &str = "bitrot-workflow.json";
pub const BITROT_FAILURE_ARTIFACT: &str = "bitrot-failure.json";
pub const BITROT_ARTIFACT_SCHEMA_VERSION: u8 = 2;
const MIN_NON_INLINE_PROBE_BYTES: u64 = 8 * 1024;

fn volume_relative_object_directory(bucket: &str, object_key: &str) -> String {
    format!("{bucket}/{object_key}")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BitrotCapabilityObservation {
    pub cluster_context: String,
    pub tenant_uid: String,
    pub drive_uuid: String,
    pub explicit_version_reads: bool,
    pub offline_xl2_non_inline: bool,
    pub observed_at_ms: u64,
    pub expires_at_ms: u64,
    pub response_sha256: String,
    pub response_body: String,
}

impl BitrotCapabilityObservation {
    pub fn validate_for(&self, context: &OwnedStorageContext, now_ms: u64) -> Result<()> {
        validate_sha256(&self.response_sha256, "bitrot capability response")?;
        ensure!(
            self.cluster_context == context.cluster_context
                && self.tenant_uid == context.tenant_uid
                && self.drive_uuid == context.volume.rustfs_drive_uuid
                && self.explicit_version_reads
                && self.offline_xl2_non_inline
                && self.response_sha256 == sha256_bytes(self.response_body.as_bytes())
                && self.observed_at_ms > 0
                && self.observed_at_ms <= now_ms
                && now_ms < self.expires_at_ms,
            "bitrot capability is absent, stale, or belongs to another storage target"
        );
        Ok(())
    }
}

#[derive(Default)]
pub struct BitrotCapabilityCache {
    observations: BTreeMap<String, BitrotCapabilityObservation>,
}

impl BitrotCapabilityCache {
    pub fn insert(&mut self, observation: BitrotCapabilityObservation) -> Result<()> {
        ensure!(
            observation.explicit_version_reads
                && observation.offline_xl2_non_inline
                && observation.observed_at_ms > 0
                && observation.observed_at_ms < observation.expires_at_ms,
            "only qualified bitrot capability observations may be cached"
        );
        validate_sha256(&observation.response_sha256, "bitrot capability response")?;
        ensure!(
            observation.response_sha256 == sha256_bytes(observation.response_body.as_bytes()),
            "bitrot capability response digest mismatch"
        );
        self.observations.insert(
            capability_key(
                &observation.cluster_context,
                &observation.tenant_uid,
                &observation.drive_uuid,
            ),
            observation,
        );
        Ok(())
    }

    pub fn require(
        &self,
        context: &OwnedStorageContext,
        now_ms: u64,
    ) -> Result<&BitrotCapabilityObservation> {
        let observation = self
            .observations
            .get(&capability_key(
                &context.cluster_context,
                &context.tenant_uid,
                &context.volume.rustfs_drive_uuid,
            ))
            .context("bitrot capability cache has no exact target entry")?;
        observation.validate_for(context, now_ms)?;
        Ok(observation)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExplicitVersionProbe {
    pub operation_id: String,
    pub bucket: String,
    pub object_key: String,
    pub version_id: String,
    pub expected_sha256: String,
    pub size_bytes: u64,
    pub committed_at_ms: u64,
    pub capability_sha256: String,
    pub version_set: BitrotVersionSetEvidence,
}

impl ExplicitVersionProbe {
    fn validate(
        &self,
        identity: &StorageRecoveryArtifactIdentity,
        capability: &BitrotCapabilityObservation,
    ) -> Result<()> {
        validate_sha256(&self.expected_sha256, "bitrot probe object")?;
        ensure!(
            !self.operation_id.trim().is_empty()
                && self.bucket == identity.bucket
                && !self.object_key.trim().is_empty()
                && !self.version_id.trim().is_empty()
                && self.version_id != "null"
                && self.size_bytes >= MIN_NON_INLINE_PROBE_BYTES
                && self.committed_at_ms > 0
                && self.capability_sha256 == capability.response_sha256,
            "bitrot probe is not a sealed explicit non-inline object version"
        );
        self.version_set.validate(self)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BitrotVersionEntry {
    pub key: String,
    pub version_id: String,
    pub is_latest: bool,
    pub is_delete_marker: bool,
}

impl TryFrom<&ObjectVersionEntry> for BitrotVersionEntry {
    type Error = anyhow::Error;

    fn try_from(entry: &ObjectVersionEntry) -> Result<Self> {
        Ok(Self {
            key: entry.key.clone(),
            version_id: entry
                .version_id
                .clone()
                .filter(|version_id| !version_id.is_empty() && version_id != "null")
                .context("bitrot version listing entry lacks an explicit versionId")?,
            is_latest: entry.is_latest,
            is_delete_marker: entry.is_delete_marker,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BitrotVersionSetEvidence {
    pub bucket: String,
    pub object_key: String,
    pub data_version_id: String,
    pub delete_marker_version_id: String,
    pub entries: Vec<BitrotVersionEntry>,
    pub observed_at_ms: u64,
}

impl BitrotVersionSetEvidence {
    fn from_listing(
        bucket: &str,
        object_key: &str,
        data_version_id: &str,
        delete_marker_version_id: &str,
        entries: &[ObjectVersionEntry],
        observed_at_ms: u64,
    ) -> Result<Self> {
        let mut entries = entries
            .iter()
            .filter(|entry| entry.key == object_key)
            .map(BitrotVersionEntry::try_from)
            .collect::<Result<Vec<_>>>()?;
        entries.sort();
        Ok(Self {
            bucket: bucket.to_string(),
            object_key: object_key.to_string(),
            data_version_id: data_version_id.to_string(),
            delete_marker_version_id: delete_marker_version_id.to_string(),
            entries,
            observed_at_ms,
        })
    }

    fn validate(&self, probe: &ExplicitVersionProbe) -> Result<()> {
        ensure!(
            self.bucket == probe.bucket
                && self.object_key == probe.object_key
                && self.data_version_id == probe.version_id
                && !self.delete_marker_version_id.trim().is_empty()
                && self.delete_marker_version_id != "null"
                && self.delete_marker_version_id != self.data_version_id
                && self.observed_at_ms >= probe.committed_at_ms,
            "bitrot version-set identity is not bound to the explicit probe"
        );
        ensure!(
            self.entries.len() == 2
                && self
                    .entries
                    .iter()
                    .all(|entry| entry.key == self.object_key)
                && self
                    .entries
                    .iter()
                    .filter(|entry| {
                        entry.version_id == self.data_version_id
                            && !entry.is_latest
                            && !entry.is_delete_marker
                    })
                    .count()
                    == 1
                && self
                    .entries
                    .iter()
                    .filter(|entry| {
                        entry.version_id == self.delete_marker_version_id
                            && entry.is_latest
                            && entry.is_delete_marker
                    })
                    .count()
                    == 1,
            "bitrot version set does not contain one data version and one latest delete marker"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExactCohortDefinition {
    pub member_pod_uids: BTreeMap<String, String>,
    pub unavailable_pods: Vec<String>,
    pub target_drive_uuid: String,
    pub volume_path: String,
}

impl ExactCohortDefinition {
    fn validate(
        &self,
        context: &OwnedStorageContext,
        shape: &ErasureSetShape,
        membership: &ErasureSetMembership,
    ) -> Result<()> {
        let members = membership
            .members
            .iter()
            .map(|member| member.pod_name.as_str())
            .collect::<BTreeSet<_>>();
        let unavailable = self
            .unavailable_pods
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        ensure!(
            shape.volumes_per_server == 1
                && self.member_pod_uids.len() == members.len()
                && self
                    .member_pod_uids
                    .iter()
                    .all(|(pod, uid)| members.contains(pod.as_str()) && !uid.trim().is_empty())
                && unavailable.len() == self.unavailable_pods.len()
                && !unavailable.contains(context.volume.pod.as_str())
                && self.target_drive_uuid == context.volume.rustfs_drive_uuid
                && self.volume_path == context.volume.mount_path,
            "exact-cohort definition does not bind the complete one-volume-per-server target"
        );
        membership
            .require_selected_boundary(shape, self.unavailable_pods.iter().map(String::as_str))?;
        ensure!(
            self.unavailable_pods.len() == usize::try_from(shape.payload_quorum()?.read_tolerance)?,
            "exact-cohort unavailable set does not equal payload read tolerance"
        );
        Ok(())
    }

    fn sha256(&self, shape: &ErasureSetShape, membership: &ErasureSetMembership) -> Result<String> {
        canonical_sha256(&serde_json::json!({
            "shape": shape,
            "membership": membership,
            "cohort": self,
        }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BitrotSelectionEvidence {
    pub schema_version: u8,
    pub identity: StorageRecoveryArtifactIdentity,
    pub case: StorageRecoveryCase,
    pub context: Box<OwnedStorageContext>,
    pub capability: BitrotCapabilityObservation,
    pub probe: ExplicitVersionProbe,
    pub shape: ErasureSetShape,
    pub membership: ErasureSetMembership,
    pub exact_cohort: ExactCohortDefinition,
    pub mapping: VersionShardMappingObservation,
    pub inspection_receipt: Box<StorageRecoveryOperationReceipt>,
}

impl BitrotSelectionEvidence {
    pub fn validate(&self) -> Result<OfflineXl2InspectResponse> {
        ensure!(
            self.schema_version == BITROT_ARTIFACT_SCHEMA_VERSION
                && matches!(
                    self.case,
                    StorageRecoveryCase::OnDiskBitrotAutomaticScanner
                        | StorageRecoveryCase::OnDiskBitrotAdminDeep
                )
                && self.context.case == self.case
                && self.context.identity == self.identity
                && self.identity.scenario == "on-disk-bitrot",
            "bitrot selection identity or case is invalid"
        );
        self.context.validate()?;
        self.capability
            .validate_for(&self.context, self.inspection_receipt.completed_at_ms)?;
        self.probe.validate(&self.identity, &self.capability)?;
        self.shape.validate()?;
        self.membership.validate(&self.shape)?;
        self.exact_cohort
            .validate(&self.context, &self.shape, &self.membership)?;
        self.inspection_receipt
            .validate_for(&self.context, &self.inspection_receipt.operation)?;
        let StorageRecoveryHostOperation::InspectXlMeta {
            object_directory,
            bucket,
            object_key,
            object_sha256,
            version_id,
            selected_part_number,
            expected_mount_device_id,
            expected_drive_uuid,
            ..
        } = &self.inspection_receipt.operation
        else {
            bail!("bitrot selection receipt is not an XL2 inspection")
        };
        let response = serde_json::from_str::<OfflineXl2InspectResponse>(
            &self.inspection_receipt.response_body,
        )
        .context("decode bitrot selection inspection")?;
        ensure!(
            object_directory
                == &volume_relative_object_directory(&self.probe.bucket, &self.probe.object_key)
                && bucket == &self.probe.bucket
                && object_key == &self.probe.object_key
                && object_sha256 == &self.probe.expected_sha256
                && version_id == &self.probe.version_id
                && *selected_part_number == response.selected_part.part_number
                && expected_mount_device_id == &response.mount_device_id
                && expected_drive_uuid == &response.drive_uuid
                && response.layout.profile == Xl2FormatProfile::LATEST_RUSTFS
                && response.layout.inspector_revision == OFFLINE_XL2_INSPECTOR_REVISION
                && response.layout.version_id == self.probe.version_id
                && self.probe.committed_at_ms < self.inspection_receipt.started_at_ms,
            "bitrot inspection is not bound to the sealed non-inline version and selected shard"
        );
        ensure!(
            self.mapping.source == ShardMappingSource::OfflineXl2Inspector
                && self.mapping.offline_evidence.as_deref()
                    == Some(&OfflineVersionShardMappingEvidence {
                        context: self.context.clone(),
                        inspection_receipt: self.inspection_receipt.clone(),
                    })
                && self
                    .mapping
                    .validated_mapping(&self.membership, &self.shape)?
                    .version_id
                    == self.probe.version_id,
            "bitrot mapping is not derived from the exact inspection receipt"
        );
        Ok(response)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BitrotReadOutcome {
    ExpectedBytes,
    CleanRejected,
    UnexpectedBytes,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExactCohortReadReceipt {
    pub operation_id: String,
    pub context_sha256: String,
    pub cohort_sha256: String,
    pub bucket: String,
    pub object_key: String,
    pub version_id: String,
    pub expected_sha256: String,
    pub observed_sha256: Option<String>,
    pub http_status: Option<u16>,
    pub error: Option<String>,
    pub outcome: BitrotReadOutcome,
    pub target_shard_required: bool,
    pub started_at_ms: u64,
    pub completed_at_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorruptionReadVerdict {
    CleanRejected,
    ProductFailure,
    HarnessUnqualified,
}

impl ExactCohortReadReceipt {
    fn validate_identity(
        &self,
        context: &OwnedStorageContext,
        probe: &ExplicitVersionProbe,
    ) -> Result<()> {
        validate_sha256(&self.context_sha256, "exact-cohort read context")?;
        validate_sha256(&self.cohort_sha256, "exact-cohort membership")?;
        validate_sha256(&self.expected_sha256, "exact-cohort expected object")?;
        if let Some(observed) = &self.observed_sha256 {
            validate_sha256(observed, "exact-cohort observed object")?;
        }
        ensure!(
            Uuid::parse_str(&self.operation_id).is_ok()
                && self.context_sha256 == context_sha256(context)?
                && self.bucket == probe.bucket
                && self.object_key == probe.object_key
                && self.version_id == probe.version_id
                && self.expected_sha256 == probe.expected_sha256
                && self.target_shard_required
                && self.started_at_ms > 0
                && self.started_at_ms <= self.completed_at_ms,
            "exact-cohort read is not bound to the owned context and explicit version"
        );
        Ok(())
    }

    pub fn classify_corruption_window(
        &self,
        context: &OwnedStorageContext,
        probe: &ExplicitVersionProbe,
    ) -> Result<CorruptionReadVerdict> {
        self.validate_identity(context, probe)?;
        let two_xx = self
            .http_status
            .is_some_and(|status| (200..300).contains(&status));
        if two_xx && self.observed_sha256.as_deref() != Some(self.expected_sha256.as_str()) {
            return Ok(CorruptionReadVerdict::ProductFailure);
        }
        if two_xx && self.observed_sha256.as_deref() == Some(self.expected_sha256.as_str()) {
            return Ok(CorruptionReadVerdict::HarnessUnqualified);
        }
        ensure!(
            self.outcome == BitrotReadOutcome::CleanRejected
                && !two_xx
                && self.observed_sha256.is_none()
                && self
                    .error
                    .as_deref()
                    .is_some_and(|error| !error.trim().is_empty()),
            "corruption-window response is neither a clean rejection nor a classifiable 2xx"
        );
        Ok(CorruptionReadVerdict::CleanRejected)
    }

    fn require_expected_success(
        &self,
        context: &OwnedStorageContext,
        probe: &ExplicitVersionProbe,
    ) -> Result<()> {
        self.validate_identity(context, probe)?;
        ensure!(
            self.outcome == BitrotReadOutcome::ExpectedBytes
                && self
                    .http_status
                    .is_some_and(|status| (200..300).contains(&status))
                && self.observed_sha256.as_deref() == Some(self.expected_sha256.as_str())
                && self.error.is_none(),
            "exact-quorum read did not return the expected explicit-version bytes"
        );
        Ok(())
    }

    pub(crate) fn validate_against_history(
        &self,
        probe: &ExplicitVersionProbe,
        history: &[OperationRecord],
    ) -> Result<()> {
        let matches = history
            .iter()
            .filter(|record| record.id == self.operation_id)
            .collect::<Vec<_>>();
        ensure!(
            matches.len() == 1,
            "exact-cohort read operationId does not identify one history GET"
        );
        let record = matches[0];
        ensure!(
            record.kind == OperationKind::Get
                && record.bucket == self.bucket
                && record.key.as_deref() == Some(self.object_key.as_str())
                && record.version_id.as_deref() == Some(self.version_id.as_str())
                && record.http_status == self.http_status
                && record.value_sha256 == self.observed_sha256
                && record.error == self.error
                && record.started_at_ms >= self.started_at_ms
                && record.ended_at_ms <= self.completed_at_ms,
            "exact-cohort read receipt differs from its history GET"
        );
        match self.outcome {
            BitrotReadOutcome::ExpectedBytes => ensure!(
                record.outcome == OperationOutcome::Ok
                    && record.value_sha256.as_deref() == Some(probe.expected_sha256.as_str())
                    && record.size_bytes == Some(usize::try_from(probe.size_bytes)?),
                "successful exact-cohort read history does not contain the expected bytes"
            ),
            BitrotReadOutcome::UnexpectedBytes => ensure!(
                record.outcome == OperationOutcome::Ok
                    && record.value_sha256.is_some()
                    && record.value_sha256.as_deref() != Some(probe.expected_sha256.as_str()),
                "unexpected-byte exact-cohort read history has another outcome"
            ),
            BitrotReadOutcome::CleanRejected => ensure!(
                record.outcome != OperationOutcome::Ok
                    && record.value_sha256.is_none()
                    && record
                        .error
                        .as_deref()
                        .is_some_and(|error| !error.trim().is_empty())
                    && self
                        .error
                        .as_deref()
                        .is_some_and(|error| !error.trim().is_empty()),
                "rejected exact-cohort read history contains a successful body"
            ),
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BitrotMutationEvidence {
    pub schema_version: u8,
    pub selection_operation_id: String,
    pub mutation_receipt: Box<StorageRecoveryOperationReceipt>,
    pub mutated_at_ms: u64,
}

fn retain_mutation_before_persist(
    mutation: &mut Option<BitrotMutationEvidence>,
    pending_mutation: &mut Option<(String, StorageRecoveryHostOperation)>,
    evidence: BitrotMutationEvidence,
    persist: impl FnOnce(&BitrotMutationEvidence) -> Result<()>,
) -> Result<()> {
    *mutation = Some(evidence);
    persist(mutation.as_ref().context("retained mutation is absent")?)?;
    *pending_mutation = None;
    Ok(())
}

impl BitrotMutationEvidence {
    pub(crate) fn validate(
        &self,
        selection: &BitrotSelectionEvidence,
    ) -> Result<OfflineShardMutationResponse> {
        let inspected = selection.validate()?;
        ensure!(
            self.schema_version == BITROT_ARTIFACT_SCHEMA_VERSION
                && self.selection_operation_id == selection.inspection_receipt.operation_id,
            "bitrot mutation does not cite the selected inspection receipt"
        );
        self.mutation_receipt
            .validate_for(&selection.context, &self.mutation_receipt.operation)?;
        let StorageRecoveryHostOperation::MutateShard {
            inspection_operation_id,
            part_number,
            byte_offset,
        } = &self.mutation_receipt.operation
        else {
            bail!("bitrot mutation receipt has the wrong operation")
        };
        let response = serde_json::from_str::<OfflineShardMutationResponse>(
            &self.mutation_receipt.response_body,
        )
        .context("decode bitrot mutation response")?;
        ensure!(
            inspection_operation_id == &self.selection_operation_id
                && *part_number == inspected.selected_part.part_number
                && *byte_offset == response.byte_offset
                && response.journal_operation_id == self.mutation_receipt.operation_id
                && response.relative_part_path == inspected.selected_part.relative_part_path
                && response.shard_device_id == inspected.selected_part.shard_device_id
                && response.shard_inode == inspected.selected_part.shard_inode
                && response.shard_size_bytes == inspected.selected_part.shard_size_bytes
                && response.original_sha256 == inspected.selected_part.original_sha256
                && response.mutated_sha256 != response.original_sha256
                && response.original_byte ^ response.mutated_byte == CONTROLLED_SHARD_XOR_MASK
                && self.mutated_at_ms == self.mutation_receipt.completed_at_ms,
            "bitrot mutation response is not the controlled change to the selected shard"
        );
        Ok(response)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BitrotCorruptionWindowProof {
    pub schema_version: u8,
    pub baseline: ExactCohortReadReceipt,
    pub corrupted: ExactCohortReadReceipt,
    pub opened_at_ms: u64,
    pub closed_at_ms: u64,
}

impl BitrotCorruptionWindowProof {
    pub(crate) fn validate(
        &self,
        selection: &BitrotSelectionEvidence,
        mutation: &BitrotMutationEvidence,
    ) -> Result<()> {
        ensure!(
            self.schema_version == BITROT_ARTIFACT_SCHEMA_VERSION
                && self.baseline.cohort_sha256 == self.corrupted.cohort_sha256
                && self.baseline.cohort_sha256
                    == selection
                        .exact_cohort
                        .sha256(&selection.shape, &selection.membership)?
                && self.opened_at_ms == mutation.mutated_at_ms
                && self.baseline.completed_at_ms < mutation.mutated_at_ms
                && self.corrupted.started_at_ms > mutation.mutated_at_ms
                && self.corrupted.completed_at_ms == self.closed_at_ms,
            "bitrot baseline/corruption probes do not share one ordered active cohort"
        );
        self.baseline
            .require_expected_success(&selection.context, &selection.probe)?;
        ensure!(
            self.corrupted
                .classify_corruption_window(&selection.context, &selection.probe)?
                == CorruptionReadVerdict::CleanRejected,
            "bitrot corruption window did not cleanly reject the required corrupt shard"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RawBitrotEvidenceReceipt {
    pub api_revision: String,
    pub response_sha256: String,
    pub response_body: String,
    pub started_at_ms: u64,
    pub completed_at_ms: u64,
}

impl RawBitrotEvidenceReceipt {
    pub(crate) fn validate(&self, label: &str) -> Result<()> {
        validate_sha256(&self.response_sha256, label)?;
        ensure!(
            !self.api_revision.trim().is_empty()
                && self.response_sha256 == sha256_bytes(self.response_body.as_bytes())
                && self.started_at_ms > 0
                && self.started_at_ms <= self.completed_at_ms,
            "{label} raw response is not digest-bound and ordered"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BitrotHealProgressSource {
    AutomaticScanner,
    AdminDeep,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BitrotHealProgressSample {
    pub schema_version: u8,
    pub source: BitrotHealProgressSource,
    pub ordinal: u64,
    pub client_token_sha256: Option<String>,
    pub state: HealProgressState,
    pub failure_detail: Option<String>,
    pub receipt: RawBitrotEvidenceReceipt,
}

pub(crate) fn validate_heal_progress(
    samples: &[BitrotHealProgressSample],
    source: BitrotHealProgressSource,
    client_token: Option<&str>,
) -> Result<()> {
    ensure!(!samples.is_empty(), "bitrot heal progress is empty");
    let expected_token_sha256 = client_token.map(|token| sha256_bytes(token.as_bytes()));
    let mut previous_completed_at_ms = 0;
    for (ordinal, sample) in samples.iter().enumerate() {
        sample.receipt.validate("bitrot heal progress")?;
        ensure!(
            sample.schema_version == BITROT_ARTIFACT_SCHEMA_VERSION
                && sample.source == source
                && sample.ordinal == u64::try_from(ordinal)?
                && sample.client_token_sha256 == expected_token_sha256
                && sample.receipt.started_at_ms >= previous_completed_at_ms,
            "bitrot heal progress identity or ordering is invalid"
        );
        match sample.state {
            HealProgressState::Failed => ensure!(
                sample
                    .failure_detail
                    .as_deref()
                    .is_some_and(|detail| !detail.trim().is_empty()),
                "failed bitrot heal progress lacks a failure reason"
            ),
            HealProgressState::Completed => ensure!(
                sample.failure_detail.is_none(),
                "completed bitrot heal progress contains a failure reason"
            ),
            HealProgressState::Queued | HealProgressState::Running => {}
        }
        match source {
            BitrotHealProgressSource::AutomaticScanner => {
                let body = serde_json::from_str::<ScannerStatusBody>(&sample.receipt.response_body)
                    .context("decode scanner heal progress")?;
                let failed = matches!(
                    body.metrics.last_cycle_result.as_str(),
                    "failed" | "stopped" | "canceled"
                );
                ensure!(
                    (sample.state != HealProgressState::Completed
                        || body.metrics.last_cycle_result == "completed")
                        && (sample.state != HealProgressState::Failed || failed),
                    "scanner progress state differs from the captured response"
                );
            }
            BitrotHealProgressSource::AdminDeep => {
                let body =
                    serde_json::from_str::<AdminHealStatusBody>(&sample.receipt.response_body)
                        .context("decode admin heal progress")?;
                ensure!(
                    body.settings.scan_mode == AdminHealScanMode::Deep,
                    "admin heal progress was not produced by a Deep scan"
                );
                let expected_state = match body.summary.as_str() {
                    "finished" if body.failure_detail.is_empty() => HealProgressState::Completed,
                    "running" => HealProgressState::Running,
                    _ => HealProgressState::Failed,
                };
                let expected_failure_detail =
                    (expected_state == HealProgressState::Failed).then(|| {
                        if body.failure_detail.trim().is_empty() {
                            format!("admin heal ended in state {:?}", body.summary)
                        } else {
                            body.failure_detail
                        }
                    });
                ensure!(
                    sample.state == expected_state
                        && sample.failure_detail == expected_failure_detail,
                    "admin heal progress state or failure reason differs from the captured response"
                );
            }
        }
        previous_completed_at_ms = sample.receipt.completed_at_ms;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScannerStatusBody {
    pub enabled: bool,
    pub metrics: ScannerMetricsBody,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScannerMetricsBody {
    pub last_cycle_end_unix_secs: u64,
    pub last_cycle_duration_seconds: f64,
    pub last_cycle_result: String,
    pub last_cycle_heal_objects: u64,
    pub versions_scanned: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminHealStartBody {
    pub client_token: String,
    pub client_address: String,
    #[serde(default)]
    pub start_time: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminHealDriveBody {
    pub uuid: String,
    pub endpoint: String,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminHealDriveSetBody {
    pub drives: Vec<AdminHealDriveBody>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminHealResultItem {
    pub bucket: String,
    #[serde(rename = "object")]
    pub object_key: String,
    pub version_id: String,
    pub before: AdminHealDriveSetBody,
    pub after: AdminHealDriveSetBody,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminHealScanMode {
    Unknown,
    Normal,
    Deep,
}

impl Serialize for AdminHealScanMode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(match self {
            Self::Unknown => 0,
            Self::Normal => 1,
            Self::Deep => 2,
        })
    }
}

impl<'de> Deserialize<'de> for AdminHealScanMode {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl de::Visitor<'_> for Visitor {
            type Value = AdminHealScanMode;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a RustFS heal scan mode number or name")
            }

            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
                match value {
                    0 => Ok(AdminHealScanMode::Unknown),
                    1 => Ok(AdminHealScanMode::Normal),
                    2 => Ok(AdminHealScanMode::Deep),
                    _ => Err(E::custom(format!("unknown heal scan mode number: {value}"))),
                }
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                match value {
                    "unknown" => Ok(AdminHealScanMode::Unknown),
                    "normal" => Ok(AdminHealScanMode::Normal),
                    "deep" => Ok(AdminHealScanMode::Deep),
                    _ => Err(E::custom(format!("unknown heal scan mode name: {value}"))),
                }
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminHealSettingsBody {
    pub scan_mode: AdminHealScanMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminHealStatusBody {
    pub summary: String,
    #[serde(rename = "detail", default)]
    pub failure_detail: String,
    #[serde(default)]
    pub start_time: String,
    pub settings: AdminHealSettingsBody,
    pub items: Vec<AdminHealResultItem>,
}

fn admin_item_repairs_exact_drive(item: &AdminHealResultItem, drive_uuid: &str) -> bool {
    let before = item
        .before
        .drives
        .iter()
        .filter(|drive| drive.uuid == drive_uuid)
        .collect::<Vec<_>>();
    let after = item
        .after
        .drives
        .iter()
        .filter(|drive| drive.uuid == drive_uuid)
        .collect::<Vec<_>>();
    before.len() == 1
        && after.len() == 1
        && !before[0].endpoint.trim().is_empty()
        && before[0].endpoint == after[0].endpoint
        && !before[0].state.trim().is_empty()
        && before[0].state != "ok"
        && after[0].state == "ok"
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "kebab-case", deny_unknown_fields)]
pub enum BitrotHealEvidence {
    AutomaticScanner {
        status: RawBitrotEvidenceReceipt,
        progress: Vec<BitrotHealProgressSample>,
        no_admin_operation: bool,
        no_host_restore_before_post_inspect: bool,
    },
    AdminDeep {
        start: RawBitrotEvidenceReceipt,
        progress: Vec<BitrotHealProgressSample>,
        terminal_status: RawBitrotEvidenceReceipt,
        cancel: Option<RawBitrotEvidenceReceipt>,
    },
}

impl BitrotHealEvidence {
    pub fn progress(&self) -> &[BitrotHealProgressSample] {
        match self {
            Self::AutomaticScanner { progress, .. } | Self::AdminDeep { progress, .. } => progress,
        }
    }

    pub(crate) fn validate(
        &self,
        selection: &BitrotSelectionEvidence,
        corruption_closed_at_ms: u64,
        post_inspected_at_ms: u64,
    ) -> Result<()> {
        match self {
            Self::AutomaticScanner {
                status,
                progress,
                no_admin_operation,
                no_host_restore_before_post_inspect,
            } => {
                ensure!(
                    selection.case == StorageRecoveryCase::OnDiskBitrotAutomaticScanner
                        && *no_admin_operation
                        && *no_host_restore_before_post_inspect,
                    "automatic bitrot recovery used an admin or host restore path"
                );
                status.validate("automatic scanner status")?;
                validate_heal_progress(progress, BitrotHealProgressSource::AutomaticScanner, None)?;
                ensure!(
                    progress.last().map(|sample| &sample.receipt) == Some(status)
                        && progress.last().map(|sample| sample.state)
                            == Some(HealProgressState::Completed),
                    "automatic scanner terminal receipt is absent from progress"
                );
                let body = serde_json::from_str::<ScannerStatusBody>(&status.response_body)
                    .context("decode raw automatic scanner status")?;
                let scan_completed_at_ms = body
                    .metrics
                    .last_cycle_end_unix_secs
                    .checked_mul(1_000)
                    .context("scanner completion timestamp overflow")?;
                let scan_duration_ms = (body.metrics.last_cycle_duration_seconds * 1_000.0)
                    .round()
                    .max(0.0) as u64;
                let scan_started_at_ms = scan_completed_at_ms.saturating_sub(scan_duration_ms);
                ensure!(
                    body.enabled
                        && body.metrics.last_cycle_result == "completed"
                        && body.metrics.last_cycle_duration_seconds > 0.0
                        && body.metrics.last_cycle_heal_objects > 0
                        && body.metrics.versions_scanned > 0
                        && scan_started_at_ms >= corruption_closed_at_ms
                        && scan_completed_at_ms <= post_inspected_at_ms
                        && status.completed_at_ms <= post_inspected_at_ms,
                    "automatic scanner status does not bound one completed scan interval"
                );
            }
            Self::AdminDeep {
                start,
                progress,
                terminal_status,
                cancel,
            } => {
                ensure!(
                    selection.case == StorageRecoveryCase::OnDiskBitrotAdminDeep
                        && cancel.is_none(),
                    "successful admin-deep recovery has the wrong case or a cancel receipt"
                );
                start.validate("admin heal start")?;
                terminal_status.validate("admin heal terminal status")?;
                let start_body = serde_json::from_str::<AdminHealStartBody>(&start.response_body)
                    .context("decode raw admin heal start")?;
                validate_heal_progress(
                    progress,
                    BitrotHealProgressSource::AdminDeep,
                    Some(&start_body.client_token),
                )?;
                ensure!(
                    progress.last().map(|sample| &sample.receipt) == Some(terminal_status)
                        && progress.last().map(|sample| sample.state)
                            == Some(HealProgressState::Completed),
                    "admin heal terminal receipt is absent from progress"
                );
                let status_body =
                    serde_json::from_str::<AdminHealStatusBody>(&terminal_status.response_body)
                        .context("decode raw admin heal status")?;
                ensure!(
                    !start_body.client_token.trim().is_empty()
                        && !start_body.client_address.trim().is_empty()
                        && status_body.summary == "finished"
                        && status_body.failure_detail.is_empty()
                        && status_body
                            .items
                            .iter()
                            .filter(|item| {
                                item.bucket == selection.probe.bucket
                                    && item.object_key == selection.probe.object_key
                                    && item.version_id == selection.probe.version_id
                                    && item.before.drives.len() == item.after.drives.len()
                                    && admin_item_repairs_exact_drive(
                                        item,
                                        &selection.context.volume.rustfs_drive_uuid,
                                    )
                            })
                            .count()
                            == 1
                        && start.started_at_ms >= corruption_closed_at_ms
                        && start.completed_at_ms <= terminal_status.started_at_ms
                        && terminal_status.completed_at_ms <= post_inspected_at_ms,
                    "admin-deep raw receipts do not prove one owned exact HealResultItem"
                );
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiagnosticBitrotLogEvidence {
    pub response_sha256: String,
    pub response_body: String,
    pub has_object_version_drive_identity: bool,
}

impl DiagnosticBitrotLogEvidence {
    fn validate_diagnostic_only(&self) -> Result<()> {
        validate_sha256(&self.response_sha256, "bitrot diagnostic log")?;
        ensure!(
            self.response_sha256 == sha256_bytes(self.response_body.as_bytes()),
            "bitrot diagnostic log response digest mismatch"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BitrotCleanupEvidence {
    pub schema_version: u8,
    pub context: Box<OwnedStorageContext>,
    pub post_inspection_receipt: Box<StorageRecoveryOperationReceipt>,
    pub fresh_mapping: VersionShardMappingObservation,
    pub post_heal_exact_quorum: ExactCohortReadReceipt,
    pub final_version_set: BitrotVersionSetEvidence,
    pub helper_cleanup: StorageRecoveryCleanupProof,
    pub completed_at_ms: u64,
}

impl BitrotCleanupEvidence {
    pub(crate) fn validate(
        &self,
        selection: &BitrotSelectionEvidence,
        mutation: &OfflineShardMutationResponse,
        heal: &BitrotHealEvidence,
        corruption_closed_at_ms: u64,
    ) -> Result<()> {
        ensure!(
            self.schema_version == BITROT_ARTIFACT_SCHEMA_VERSION,
            "unsupported bitrot cleanup schema"
        );
        validate_renewed_context(&selection.context, &self.context)?;
        self.post_inspection_receipt
            .validate_for(&self.context, &self.post_inspection_receipt.operation)?;
        let StorageRecoveryHostOperation::InspectXlMeta {
            object_directory,
            bucket,
            object_key,
            ..
        } = &self.post_inspection_receipt.operation
        else {
            bail!("bitrot post-heal receipt is not an XL2 inspection")
        };
        let post = serde_json::from_str::<OfflineXl2InspectResponse>(
            &self.post_inspection_receipt.response_body,
        )
        .context("decode post-heal XL2 inspection")?;
        ensure!(
            object_directory
                == &volume_relative_object_directory(
                    &selection.probe.bucket,
                    &selection.probe.object_key,
                )
                && bucket == &selection.probe.bucket
                && object_key == &selection.probe.object_key
                && post.layout.version_id == selection.probe.version_id
                && post.drive_uuid == selection.context.volume.rustfs_drive_uuid
                && post.selected_part.original_sha256 == mutation.original_sha256
                && post.selected_part.original_sha256 != mutation.mutated_sha256,
            "post-heal inspection does not prove the selected shard hash transition"
        );
        heal.validate(
            selection,
            corruption_closed_at_ms,
            self.post_inspection_receipt.completed_at_ms,
        )?;
        ensure!(
            self.fresh_mapping.source == ShardMappingSource::OfflineXl2Inspector
                && self
                    .fresh_mapping
                    .validated_mapping(&selection.membership, &selection.shape)?
                    .version_id
                    == selection.probe.version_id,
            "post-heal mapping is not fresh receipt-bound offline evidence"
        );
        self.post_heal_exact_quorum
            .require_expected_success(&self.context, &selection.probe)?;
        ensure!(
            self.post_heal_exact_quorum.cohort_sha256
                == selection
                    .exact_cohort
                    .sha256(&selection.shape, &selection.membership)?,
            "post-heal read did not use the sealed exact cohort"
        );
        self.final_version_set.validate(&selection.probe)?;
        ensure!(
            self.final_version_set.entries == selection.probe.version_set.entries
                && self.final_version_set.data_version_id
                    == selection.probe.version_set.data_version_id
                && self.final_version_set.delete_marker_version_id
                    == selection.probe.version_set.delete_marker_version_id,
            "post-heal version set or delete marker changed"
        );
        self.helper_cleanup.validate_for(&self.context)?;
        ensure!(
            self.post_inspection_receipt.completed_at_ms
                < self.post_heal_exact_quorum.started_at_ms
                && self.post_heal_exact_quorum.completed_at_ms
                    <= self.final_version_set.observed_at_ms
                && self.final_version_set.observed_at_ms <= self.completed_at_ms,
            "bitrot cleanup, post-inspection, and final exact-quorum read are out of order"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OnDiskBitrotWorkflowEvidence {
    pub schema_version: u8,
    pub identity: StorageRecoveryArtifactIdentity,
    pub selection_sha256: String,
    pub mutation_sha256: String,
    pub corruption_window_sha256: String,
    pub heal_sha256: String,
    pub cleanup_sha256: String,
    pub checker_report_sha256: String,
    pub post_write_report_sha256: String,
    pub diagnostic_logs: Option<DiagnosticBitrotLogEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BitrotEmergencyCleanupEvidence {
    pub attempted: bool,
    pub chaos_removed: bool,
    pub admin_heal_closed: bool,
    pub helper_closed: bool,
    pub mutation_lookup: Option<MutationJournalLookup>,
    pub cleanup_proof: Option<StorageRecoveryCleanupProof>,
    pub errors: Vec<String>,
    pub completed_at_ms: u64,
}

impl BitrotEmergencyCleanupEvidence {
    pub(crate) fn succeeded(&self) -> bool {
        self.attempted
            && self.chaos_removed
            && self.admin_heal_closed
            && self.helper_closed
            && self.errors.is_empty()
    }

    fn validate_for(&self, context: Option<&OwnedStorageContext>) -> Result<()> {
        ensure!(
            self.attempted && self.completed_at_ms > 0,
            "bitrot emergency cleanup was not attempted"
        );
        ensure!(
            self.errors.is_empty() == self.succeeded(),
            "bitrot emergency cleanup flags and errors disagree"
        );
        if let Some(context) = context {
            if let Some(lookup) = &self.mutation_lookup {
                lookup.validate_for(context, &lookup.operation_id, &lookup.operation)?;
                let cleanup_operation_id = match self.cleanup_proof.as_ref() {
                    Some(StorageRecoveryCleanupProof::BitrotRestored { restore_receipt })
                    | Some(StorageRecoveryCleanupProof::BitrotAlreadyRepaired {
                        restore_receipt,
                    }) => match &restore_receipt.operation {
                        StorageRecoveryHostOperation::RestoreShard {
                            mutation_operation_id,
                        } => Some(mutation_operation_id.as_str()),
                        _ => None,
                    },
                    Some(StorageRecoveryCleanupProof::BitrotVerifiedSuperseded {
                        verification_receipt,
                    }) => match &verification_receipt.operation {
                        StorageRecoveryHostOperation::VerifySupersededShard {
                            mutation_operation_id,
                            ..
                        } => Some(mutation_operation_id.as_str()),
                        _ => None,
                    },
                    _ => None,
                };
                ensure!(
                    cleanup_operation_id == Some(lookup.operation_id.as_str()),
                    "bitrot mutation lookup is not bound to its cleanup proof"
                );
            }
            if let Some(cleanup) = &self.cleanup_proof {
                cleanup.validate_for(context)?;
            }
        } else {
            ensure!(
                self.mutation_lookup.is_none() && self.cleanup_proof.is_none(),
                "bitrot cleanup proof lacks its owned context"
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BitrotFailureEvidence {
    pub schema_version: u8,
    pub run_id: String,
    pub case: StorageRecoveryCase,
    pub stage: String,
    pub primary_error: String,
    pub context: Option<Box<OwnedStorageContext>>,
    pub cleanup: BitrotEmergencyCleanupEvidence,
    pub observed_at_ms: u64,
}

impl BitrotFailureEvidence {
    pub(crate) fn validate(&self, run_id: &str, case_name: &str) -> Result<()> {
        ensure!(
            self.schema_version == BITROT_ARTIFACT_SCHEMA_VERSION
                && self.run_id == run_id
                && !self.primary_error.trim().is_empty()
                && self.observed_at_ms >= self.cleanup.completed_at_ms
                && matches!(
                    self.case,
                    StorageRecoveryCase::OnDiskBitrotAutomaticScanner
                        | StorageRecoveryCase::OnDiskBitrotAdminDeep
                )
                && matches!(
                    self.stage.as_str(),
                    "target-proof"
                        | "selection"
                        | "mutation"
                        | "corruption-window"
                        | "heal"
                        | "post-heal-verification"
                        | "cleanup"
                        | "helper-cleanup"
                        | "final-checker"
                ),
            "bitrot failure identity, stage, or primary error is invalid"
        );
        if let Some(context) = self.context.as_deref() {
            context.validate()?;
            ensure!(
                context.identity.run_id == self.run_id
                    && context.identity.case_name == case_name
                    && context.identity.scenario == "on-disk-bitrot"
                    && context.case == self.case,
                "bitrot failure context belongs to another run or case"
            );
        }
        self.cleanup.validate_for(self.context.as_deref())
    }

    pub(crate) fn validate_progress_failure(
        &self,
        progress: &[BitrotHealProgressSample],
    ) -> Result<()> {
        if let Some(last) = progress.last()
            && last.state == HealProgressState::Failed
        {
            let detail = last
                .failure_detail
                .as_deref()
                .context("failed bitrot heal progress lacks its failure detail")?;
            ensure!(
                self.stage == "heal" && self.primary_error.contains(detail),
                "bitrot primary error does not preserve the terminal heal failure"
            );
        }
        Ok(())
    }
}

pub struct OnDiskBitrotEvidenceSet<'a> {
    pub workflow: &'a OnDiskBitrotWorkflowEvidence,
    pub selection: &'a BitrotSelectionEvidence,
    pub mutation: &'a BitrotMutationEvidence,
    pub corruption_window: &'a BitrotCorruptionWindowProof,
    pub heal: &'a BitrotHealEvidence,
    pub cleanup: &'a BitrotCleanupEvidence,
    pub checker_report_body: &'a str,
    pub post_write_report_body: &'a str,
}

pub fn validate_on_disk_bitrot_evidence(evidence: &OnDiskBitrotEvidenceSet<'_>) -> Result<()> {
    let selection_response = evidence.selection.validate()?;
    let mutation_response = evidence.mutation.validate(evidence.selection)?;
    evidence
        .corruption_window
        .validate(evidence.selection, evidence.mutation)?;
    evidence.cleanup.validate(
        evidence.selection,
        &mutation_response,
        evidence.heal,
        evidence.corruption_window.closed_at_ms,
    )?;
    ensure!(
        evidence.workflow.schema_version == BITROT_ARTIFACT_SCHEMA_VERSION
            && evidence.workflow.identity == evidence.selection.identity
            && evidence.workflow.selection_sha256 == canonical_sha256(evidence.selection)?
            && evidence.workflow.mutation_sha256 == canonical_sha256(evidence.mutation)?
            && evidence.workflow.corruption_window_sha256
                == canonical_sha256(evidence.corruption_window)?
            && evidence.workflow.heal_sha256 == canonical_sha256(evidence.heal)?
            && evidence.workflow.cleanup_sha256 == canonical_sha256(evidence.cleanup)?
            && evidence.workflow.checker_report_sha256
                == sha256_bytes(evidence.checker_report_body.as_bytes())
            && evidence.workflow.post_write_report_sha256
                == sha256_bytes(evidence.post_write_report_body.as_bytes())
            && selection_response.selected_part.original_sha256
                == mutation_response.original_sha256,
        "bitrot workflow artifact digests or identities are not transitively bound"
    );
    validate_sha256(
        &evidence.workflow.checker_report_sha256,
        "bitrot checker report",
    )?;
    validate_sha256(
        &evidence.workflow.post_write_report_sha256,
        "bitrot post-write report",
    )?;
    if let Some(logs) = &evidence.workflow.diagnostic_logs {
        logs.validate_diagnostic_only()?;
    }
    Ok(())
}

/// Operator-reviewed binding for the one physical shard a planned bitrot run
/// may touch. The file contains no credentials and is capability-based rather
/// than tied to a RustFS release. All Kubernetes generations are re-read by the
/// runner; this document supplies only immutable identities and the closed
/// exact-quorum selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BitrotLiveTargetConfig {
    pub schema_version: u8,
    pub tenant_uid: String,
    pub volume: crate::fault::storage_recovery::StorageVolumeIdentity,
    pub host_generation: crate::fault::storage_recovery_runtime::HostGenerationIdentity,
    pub host_proof_body: String,
    pub host_lock_device_id: String,
    pub host_lock_inode: u64,
    pub helper_pod_name: String,
    pub helper_pod_uid: String,
    pub shape: ErasureSetShape,
    pub membership: ErasureSetMembership,
    pub member_pod_uids: BTreeMap<String, String>,
    pub unavailable_pods: Vec<String>,
    pub bucket: String,
    pub selected_part_number: u32,
    pub mutation_byte_offset: u64,
    pub lease_duration_seconds: u64,
    pub scanner_poll_interval_ms: u64,
    pub capability_ttl_ms: u64,
}

impl BitrotLiveTargetConfig {
    fn load(path: &Path) -> Result<(Self, String)> {
        ensure!(
            path.is_absolute()
                && path
                    .components()
                    .all(|component| !matches!(component, std::path::Component::ParentDir)),
            "storage-recovery target config path must be normalized and absolute"
        );
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("stat storage-recovery target config {}", path.display()))?;
        ensure!(
            metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
            "storage-recovery target config must be a regular non-symlink file"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            ensure!(
                metadata.mode() & 0o022 == 0,
                "storage-recovery target config must not be group/other writable"
            );
        }
        let canonical = fs::canonicalize(path)
            .with_context(|| format!("canonicalize target config {}", path.display()))?;
        ensure!(
            canonical == path,
            "storage-recovery target config path is not canonical"
        );
        let body = fs::read_to_string(path)
            .with_context(|| format!("read storage-recovery target config {}", path.display()))?;
        ensure!(
            body.len() <= 1024 * 1024,
            "storage-recovery target config is oversized"
        );
        let target = serde_json::from_str::<Self>(&body)
            .context("decode strict storage-recovery target config")?;
        Ok((target, body))
    }

    fn validate_static(&self, config: &FaultTestConfig) -> Result<()> {
        ensure!(
            self.schema_version == 1,
            "unsupported bitrot target config schema"
        );
        self.volume.validate()?;
        self.shape.validate()?;
        self.membership.validate(&self.shape)?;
        ensure!(
            self.volume.namespace == config.cluster.test_namespace
                && self.volume.tenant == config.cluster.tenant_name
                && self.volume.mount_path == config.rustfs_volume_path
                && self.volume.pool_index == self.shape.pool_index
                && self.volume.set_index == self.shape.set_index
                && self.host_generation.mount_namespace_id == self.volume.target_mount_namespace_id
                && self.host_generation.filesystem_uuid == self.volume.filesystem_uuid
                && self.host_generation.rustfs_drive_uuid == self.volume.rustfs_drive_uuid
                && !self.tenant_uid.trim().is_empty()
                && !self.helper_pod_name.trim().is_empty()
                && !self.helper_pod_uid.trim().is_empty(),
            "bitrot target config is bound to another Tenant, mount, or erasure set"
        );
        ensure!(
            self.host_generation
                .device_mapper_uuid
                .as_deref()
                .is_some_and(|uuid| !uuid.trim().is_empty()),
            "bitrot requires an exact device-mapper UUID"
        );
        validate_sha256(
            self.host_generation
                .device_mapper_table_sha256
                .as_deref()
                .context("bitrot requires an exact device-mapper table digest")?,
            "bitrot device-mapper table",
        )?;
        ensure!(
            sha256_bytes(self.host_proof_body.as_bytes()) == self.volume.host_storage_proof_sha256
                && !self.host_lock_device_id.trim().is_empty()
                && self.host_lock_inode > 0,
            "bitrot host proof or pre-created lock identity is invalid"
        );
        ensure!(
            self.shape.volumes_per_server == 1,
            "unqualified topology: exact-cohort bitrot requires one volume per server"
        );
        let requirements = self.shape.payload_quorum()?;
        ensure!(
            self.unavailable_pods.len() == usize::try_from(requirements.read_tolerance)?
                && !self.unavailable_pods.contains(&self.volume.pod),
            "unqualified topology: exact unavailable cohort does not equal payload read tolerance"
        );
        self.membership.require_selected_boundary(
            &self.shape,
            self.unavailable_pods.iter().map(String::as_str),
        )?;
        let members = self
            .membership
            .members
            .iter()
            .map(|member| member.pod_name.as_str())
            .collect::<BTreeSet<_>>();
        ensure!(
            self.member_pod_uids.len() == members.len()
                && self
                    .member_pod_uids
                    .keys()
                    .all(|name| members.contains(name.as_str()))
                && self
                    .member_pod_uids
                    .values()
                    .all(|uid| !uid.trim().is_empty())
                && self.membership.members.iter().any(|member| {
                    member.pod_name == self.volume.pod
                        && member.shard_ids.as_slice() == [self.volume.rustfs_drive_uuid.as_str()]
                }),
            "bitrot member Pod identities do not cover the exact one-drive-per-server set"
        );
        ensure!(
            !self.bucket.trim().is_empty()
                && self.bucket.len() <= 63
                && self
                    .bucket
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && self.selected_part_number > 0,
            "bitrot object identity is invalid"
        );
        ensure!(
            (5..=300).contains(&self.lease_duration_seconds)
                && self.scanner_poll_interval_ms > 0
                && self.scanner_poll_interval_ms <= 30_000
                && self.capability_ttl_ms >= self.scanner_poll_interval_ms
                && self.capability_ttl_ms <= 300_000,
            "bitrot Lease, scanner poll, or capability TTL is outside the closed bounds"
        );
        Ok(())
    }
}

#[derive(Debug)]
struct KubernetesTargetObservation {
    resource_versions: KubernetesResourceVersions,
    observed_at_ms: u64,
    target_proof_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum BitrotAdminHealStartState {
    NotStarted,
    Ambiguous {
        bucket: String,
        prefix: String,
        request_path: String,
        requested_at_ms: u64,
    },
    Owned {
        bucket: String,
        prefix: String,
        request_path: String,
        requested_at_ms: u64,
        acknowledged_at_ms: u64,
        client_token: String,
        start_time: String,
        reconciled_after_response_loss: bool,
    },
}

impl BitrotAdminHealStartState {
    fn ambiguous(bucket: &str, request_path: &str, requested_at_ms: u64) -> Self {
        Self::Ambiguous {
            bucket: bucket.to_string(),
            prefix: String::new(),
            request_path: request_path.to_string(),
            requested_at_ms,
        }
    }

    fn own_from_start(
        &mut self,
        start: &RawBitrotEvidenceReceipt,
        reconciled_after_response_loss: bool,
    ) -> Result<AdminHealStartBody> {
        start.validate("admin heal start")?;
        ensure!(
            start.api_revision == "v3/heal/start",
            "admin heal start used an unexpected API revision"
        );
        let (bucket, prefix, request_path, requested_at_ms) = match self {
            Self::Ambiguous {
                bucket,
                prefix,
                request_path,
                requested_at_ms,
            } => (
                bucket.clone(),
                prefix.clone(),
                request_path.clone(),
                *requested_at_ms,
            ),
            _ => bail!("admin heal start was not registered as ambiguous"),
        };
        ensure!(
            prefix.is_empty()
                && request_path == format!("/rustfs/admin/v3/heal/{bucket}")
                && start.started_at_ms >= requested_at_ms,
            "admin heal start escaped its exact bucket, prefix, or request interval"
        );
        let start_body = serde_json::from_str::<AdminHealStartBody>(&start.response_body)
            .context("decode owned admin heal start")?;
        ensure!(
            !start_body.client_token.trim().is_empty()
                && !start_body.client_address.trim().is_empty()
                && !start_body.start_time.trim().is_empty(),
            "owned admin heal start lacks token, address, or startTime"
        );
        let parsed_start = time::OffsetDateTime::parse(
            &start_body.start_time,
            &time::format_description::well_known::Rfc3339,
        )
        .context("parse admin heal startTime")?;
        let start_ms = u64::try_from(parsed_start.unix_timestamp_nanos() / 1_000_000)
            .context("admin heal startTime precedes the Unix epoch")?;
        ensure!(
            start_ms.saturating_add(2_000) >= requested_at_ms
                && start_ms <= start.completed_at_ms.saturating_add(2_000),
            "admin heal startTime is outside the registered request interval"
        );
        *self = Self::Owned {
            bucket,
            prefix,
            request_path,
            requested_at_ms,
            acknowledged_at_ms: start.completed_at_ms,
            client_token: start_body.client_token.clone(),
            start_time: start_body.start_time.clone(),
            reconciled_after_response_loss,
        };
        Ok(start_body)
    }

    fn validate_owned_status(
        &self,
        status: &RawBitrotEvidenceReceipt,
    ) -> Result<AdminHealStatusBody> {
        status.validate("admin heal status")?;
        ensure!(
            status.api_revision == "v3/heal/status",
            "admin heal status used an unexpected API revision"
        );
        let Self::Owned {
            acknowledged_at_ms,
            start_time,
            ..
        } = self
        else {
            bail!("admin heal status arrived before the start was owned")
        };
        let status_body = serde_json::from_str::<AdminHealStatusBody>(&status.response_body)
            .context("decode owned admin heal status")?;
        ensure!(
            status_body.settings.scan_mode == AdminHealScanMode::Deep
                && !status_body.start_time.trim().is_empty()
                && status.started_at_ms >= *acknowledged_at_ms,
            "owned admin heal status is not a Deep scan for the registered interval"
        );
        let parsed_start =
            time::OffsetDateTime::parse(start_time, &time::format_description::well_known::Rfc3339)
                .context("parse owned admin heal startTime")?;
        let parsed_status = time::OffsetDateTime::parse(
            &status_body.start_time,
            &time::format_description::well_known::Rfc3339,
        )
        .context("parse owned admin heal status startTime")?;
        let start_ms = parsed_start.unix_timestamp_nanos() / 1_000_000;
        let status_ms = parsed_status.unix_timestamp_nanos() / 1_000_000;
        ensure!(
            (start_ms - status_ms).abs() <= 2_000,
            "admin heal status belongs to another start interval"
        );
        Ok(status_body)
    }

    fn owned_token<'a>(&'a self, bucket: &str, request_path: &str) -> Result<Option<&'a str>> {
        match self {
            Self::NotStarted => Ok(None),
            Self::Ambiguous { .. } => {
                bail!("admin heal start ownership remains ambiguous; cleanup must fail closed")
            }
            Self::Owned {
                bucket: owned_bucket,
                prefix,
                request_path: owned_path,
                requested_at_ms,
                acknowledged_at_ms,
                client_token,
                start_time,
                reconciled_after_response_loss: _,
            } => {
                ensure!(
                    owned_bucket == bucket
                        && prefix.is_empty()
                        && owned_path == request_path
                        && *requested_at_ms > 0
                        && *acknowledged_at_ms >= *requested_at_ms
                        && !client_token.trim().is_empty()
                        && !start_time.trim().is_empty(),
                    "owned admin heal cleanup escaped its exact bucket and prefix"
                );
                Ok(Some(client_token))
            }
        }
    }
}

fn observe_exact_kubernetes_target(
    config: &FaultTestConfig,
    target: &BitrotLiveTargetConfig,
) -> Result<KubernetesTargetObservation> {
    let namespaced = Kubectl::new(&config.cluster).namespaced(&target.volume.namespace);
    let cluster = Kubectl::new(&config.cluster).cluster_scoped();
    let get = |kubectl: &Kubectl, kind: &str, name: &str| -> Result<Value> {
        let output = kubectl
            .command(["get", kind, name, "-o", "json"])
            .run_checked()
            .with_context(|| format!("read exact storage target {kind}/{name}"))?;
        serde_json::from_str(&output.stdout)
            .with_context(|| format!("decode exact storage target {kind}/{name}"))
    };
    let tenant = get(&namespaced, "tenant", &target.volume.tenant)?;
    let pod = get(&namespaced, "pod", &target.volume.pod)?;
    let pvc = get(
        &namespaced,
        "persistentvolumeclaim",
        &target.volume.persistent_volume_claim,
    )?;
    let pv = get(
        &cluster,
        "persistentvolume",
        &target.volume.persistent_volume,
    )?;
    let node = get(&cluster, "node", &target.volume.node)?;
    let helper = get(&namespaced, "pod", &target.helper_pod_name)?;
    let required = |value: &Value, pointer: &str, label: &str| -> Result<String> {
        value
            .pointer(pointer)
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(str::to_string)
            .with_context(|| format!("exact storage target lacks {label}"))
    };
    ensure!(
        required(&tenant, "/metadata/uid", "Tenant UID")? == target.tenant_uid
            && required(&pod, "/metadata/uid", "Pod UID")? == target.volume.pod_uid
            && required(&pod, "/spec/nodeName", "Pod node")? == target.volume.node
            && required(&pvc, "/metadata/uid", "PVC UID")?
                == target.volume.persistent_volume_claim_uid
            && required(&pvc, "/spec/volumeName", "PVC volume")? == target.volume.persistent_volume
            && required(&pv, "/metadata/uid", "PV UID")? == target.volume.persistent_volume_uid
            && required(&pv, "/spec/claimRef/uid", "PV claim UID")?
                == target.volume.persistent_volume_claim_uid
            && required(&node, "/metadata/uid", "node UID")? == target.volume.node_uid
            && required(&helper, "/metadata/uid", "helper Pod UID")? == target.helper_pod_uid,
        "storage target Kubernetes UID or binding drifted"
    );
    for (pod_name, expected_uid) in &target.member_pod_uids {
        let member = get(&namespaced, "pod", pod_name)?;
        ensure!(
            required(&member, "/metadata/uid", "member Pod UID")? == *expected_uid,
            "erasure-set member Pod {pod_name:?} generation drifted"
        );
        ensure!(
            member
                .pointer("/status/conditions")
                .and_then(Value::as_array)
                .is_some_and(|conditions| conditions.iter().any(|condition| {
                    condition.get("type").and_then(Value::as_str) == Some("Ready")
                        && condition.get("status").and_then(Value::as_str) == Some("True")
                })),
            "erasure-set member Pod {pod_name:?} is not Ready"
        );
    }
    let canonical = serde_json::to_vec(&[&tenant, &pod, &pvc, &pv, &node, &helper])?;
    let target_proof_sha256 = sha256_bytes(&canonical);
    ensure!(
        target_proof_sha256 == target.volume.target_proof_sha256,
        "storage target Kubernetes proof digest drifted"
    );
    Ok(KubernetesTargetObservation {
        resource_versions: KubernetesResourceVersions {
            tenant: required(
                &tenant,
                "/metadata/resourceVersion",
                "Tenant resourceVersion",
            )?,
            pod: required(&pod, "/metadata/resourceVersion", "Pod resourceVersion")?,
            persistent_volume_claim: required(
                &pvc,
                "/metadata/resourceVersion",
                "PVC resourceVersion",
            )?,
            persistent_volume: required(&pv, "/metadata/resourceVersion", "PV resourceVersion")?,
            node: required(&node, "/metadata/resourceVersion", "node resourceVersion")?,
            helper_pod: required(
                &helper,
                "/metadata/resourceVersion",
                "helper Pod resourceVersion",
            )?,
        },
        observed_at_ms: now_ms()?,
        target_proof_sha256,
    })
}

struct LiveOnDiskBitrotRuntime {
    config: FaultTestConfig,
    collector: ArtifactCollector,
    case_name: String,
    run_id: String,
    case: StorageRecoveryCase,
    target: BitrotLiveTargetConfig,
    target_config_sha256: String,
    deadline: RunDeadline,
    endpoint: String,
    _port_forward: PortForwardGuard,
    admin: RustfsAdminTransport,
    s3: S3WorkloadClient,
    history: Recorder,
    events: RunEventRecorder,
    workload_plan: WorkloadPlan,
    capability_cache: BitrotCapabilityCache,
    lease: Option<KubernetesStorageLeaseAdapter>,
    helper: Option<KubectlStorageRecoveryAttemptGuard>,
    current: Option<OwnedStorageContext>,
    active_chaos: Option<ChaosGuard>,
    selection: Option<BitrotSelectionEvidence>,
    mutation: Option<BitrotMutationEvidence>,
    pending_mutation: Option<(String, StorageRecoveryHostOperation)>,
    corruption: Option<BitrotCorruptionWindowProof>,
    heal: Option<BitrotHealEvidence>,
    cleanup: Option<BitrotCleanupEvidence>,
    pending_cleanup_proof: Option<StorageRecoveryCleanupProof>,
    baseline: Option<ExactCohortReadReceipt>,
    admin_heal: BitrotAdminHealStartState,
    heal_progress: Vec<BitrotHealProgressSample>,
    helper_finish_completed: bool,
}

impl LiveOnDiskBitrotRuntime {
    async fn new(
        config: &FaultTestConfig,
        collector: &ArtifactCollector,
        scenario: &FaultScenario,
        storage_plan: &StorageRecoveryExecutionPlan,
        run_id: &str,
        deadline: RunDeadline,
    ) -> Result<Self> {
        let target_path = config.storage_recovery_target_config.as_deref().context(
            "planned on-disk-bitrot requires RUSTFS_FAULT_TEST_STORAGE_RECOVERY_TARGET_CONFIG",
        )?;
        let (target, target_body) = BitrotLiveTargetConfig::load(target_path)?;
        target.validate_static(config)?;
        ensure!(
            config.qualify_planned_storage
                && config.storage_recovery_case == Some(storage_plan.case)
                && target.bucket.starts_with("s3chaos-bitrot-"),
            "planned bitrot live adapter lacks exact qualification or a dedicated bucket"
        );
        let case_dir = collector.case_dir(scenario.case_name);
        fs::create_dir_all(&case_dir)?;
        let port_spec = PortForwardSpec::tenant_io_on_available_port(
            target.volume.namespace.clone(),
            target.volume.tenant.clone(),
        )?;
        let endpoint = port_spec.local_base_url();
        let mut port_forward = port_spec.start(
            &Kubectl::new(&config.cluster),
            case_dir.join("bitrot-port-forward.log"),
        )?;
        port_forward.ensure_running()?;
        tokio::time::sleep(Duration::from_millis(250)).await;
        port_forward.ensure_running()?;
        let (access_key, secret_key) = resources::test_credentials();
        let s3 = S3WorkloadClient::new(
            endpoint.clone(),
            target.bucket.clone(),
            access_key,
            secret_key,
            config.request_timeout,
        )
        .await?;
        let admin = RustfsAdminTransport::new(
            &endpoint,
            "us-east-1",
            access_key,
            secret_key,
            None,
            "s3chaos-on-disk-bitrot",
        )?;
        let history = Recorder::create(
            case_dir.join("history.jsonl"),
            scenario.name.clone(),
            run_id,
        )?;
        let events = RunEventRecorder::create(
            case_dir.join("run-events.jsonl"),
            scenario.name.clone(),
            run_id,
        )?;
        let workload_plan = WorkloadPlan::seeded_with_profile(
            config.workload_seed.unwrap_or(0x6269_7472_6f74),
            scenario.object_count,
            config.workload.concurrency,
            config.workload_operation_mix,
            config.workload_payload_distribution.clone(),
            config.workload_hotspot,
        )?;
        let catalog = scenario_spec(&scenario.name)?;
        let run_spec = FaultRunSpec::resolved_execution(
            config,
            scenario,
            catalog,
            &ExecutionPlan::StorageRecovery(storage_plan.clone()),
            &workload_plan,
            run_id,
            &target.bucket,
        );
        collector.write_text(scenario.case_name, "run-spec.yaml", &run_spec.to_yaml()?)?;
        collector.write_text(scenario.case_name, "run-spec.json", &run_spec.to_json()?)?;
        collector.write_text(
            scenario.case_name,
            "run-metadata.json",
            &serde_json::to_string_pretty(&RunMetadata::from_case(
                config,
                scenario,
                catalog,
                &ExecutionPlan::StorageRecovery(storage_plan.clone()),
                &workload_plan,
                run_id,
                &target.bucket,
            ))?,
        )?;
        collector.write_text(
            scenario.case_name,
            "workload-plan.json",
            &serde_json::to_string_pretty(&WorkloadPlanArtifact {
                scenario: &scenario.name,
                run_id,
                plan: &workload_plan,
            })?,
        )?;
        events.record(
            "run",
            RunEventStatus::Started,
            "on-disk-bitrot run initialized",
            Some(serde_json::json!({
                "case": storage_plan.case,
                "targetConfigSha256": sha256_bytes(target_body.as_bytes()),
            })),
        )?;
        Ok(Self {
            config: config.clone(),
            collector: collector.clone(),
            case_name: scenario.case_name.to_string(),
            run_id: run_id.to_string(),
            case: storage_plan.case,
            target,
            target_config_sha256: sha256_bytes(target_body.as_bytes()),
            deadline,
            endpoint,
            _port_forward: port_forward,
            admin,
            s3,
            history,
            events,
            workload_plan,
            capability_cache: BitrotCapabilityCache::default(),
            lease: None,
            helper: None,
            current: None,
            active_chaos: None,
            selection: None,
            mutation: None,
            pending_mutation: None,
            corruption: None,
            heal: None,
            cleanup: None,
            pending_cleanup_proof: None,
            baseline: None,
            admin_heal: BitrotAdminHealStartState::NotStarted,
            heal_progress: Vec::new(),
            helper_finish_completed: false,
        })
    }

    fn persist_json(&self, name: &str, value: &impl Serialize) -> Result<String> {
        let body = serde_json::to_string_pretty(value)?;
        self.collector.write_text(&self.case_name, name, &body)?;
        Ok(body)
    }

    fn record_heal_progress(&mut self, sample: BitrotHealProgressSample) -> Result<()> {
        let state = sample.state;
        let failure_detail = sample.failure_detail.clone();
        let path = self
            .collector
            .case_dir(&self.case_name)
            .join(BITROT_HEAL_PROGRESS_ARTIFACT);
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("open bitrot heal progress {}", path.display()))?;
        serde_json::to_writer(&mut file, &sample)?;
        file.write_all(b"\n")?;
        file.flush()?;
        file.sync_data()?;
        self.heal_progress.push(sample);
        self.events.record(
            "heal-progress",
            match state {
                HealProgressState::Completed => RunEventStatus::Succeeded,
                HealProgressState::Failed => RunEventStatus::Failed,
                HealProgressState::Queued | HealProgressState::Running => RunEventStatus::Observed,
            },
            format!("bitrot heal status is {state:?}"),
            Some(serde_json::json!({
                "ordinal": self.heal_progress.len() - 1,
                "failureDetail": failure_detail,
            })),
        )
    }

    fn reset_heal_progress(&mut self) -> Result<()> {
        self.heal_progress.clear();
        self.collector
            .write_text(&self.case_name, BITROT_HEAL_PROGRESS_ARTIFACT, "")?;
        Ok(())
    }

    fn current(&self) -> Result<&OwnedStorageContext> {
        self.current
            .as_ref()
            .context("storage-recovery context has not been acquired")
    }

    fn helper_mut(&mut self) -> Result<&mut KubectlStorageRecoveryAttemptGuard> {
        self.helper
            .as_mut()
            .context("storage-recovery helper session is not active")
    }

    async fn renew_current(&mut self) -> Result<OwnedStorageContext> {
        let previous = self.current()?.clone();
        let observation = observe_exact_kubernetes_target(&self.config, &self.target)?;
        ensure!(
            observation.resource_versions == previous.resource_versions
                && observation.target_proof_sha256 == previous.volume.target_proof_sha256,
            "storage target Kubernetes generation drifted before Lease heartbeat"
        );
        let proof = self
            .lease
            .as_ref()
            .context("storage-recovery Lease adapter is absent")?
            .renew(&previous.exclusive_access.kubernetes_lease)
            .await?;
        let mut renewed = previous.clone();
        renewed.exclusive_access.kubernetes_lease = proof;
        renewed.observed_at_ms = observation.observed_at_ms.max(previous.observed_at_ms + 1);
        renewed.volume.observed_at_ms = renewed.observed_at_ms;
        renewed.validate()?;
        validate_renewed_context(&previous, &renewed)?;
        self.current = Some(renewed.clone());
        Ok(renewed)
    }

    fn cohort_sha256(&self) -> Result<String> {
        ExactCohortDefinition {
            member_pod_uids: self.target.member_pod_uids.clone(),
            unavailable_pods: self.target.unavailable_pods.clone(),
            target_drive_uuid: self.target.volume.rustfs_drive_uuid.clone(),
            volume_path: self.config.rustfs_volume_path.clone(),
        }
        .sha256(&self.target.shape, &self.target.membership)
    }

    fn apply_exact_quorum_chaos(&mut self, suffix: &str) -> Result<()> {
        ensure!(
            self.active_chaos.is_none(),
            "exact-quorum IOChaos is already active"
        );
        require_iochaos_crd(&self.config.cluster)?;
        let spec = IoChaosSpec::eio_on_rustfs_volume(
            &self.config.cluster,
            &self.config.chaos_namespace,
            &self.run_id,
            "on-disk-bitrot",
            &self.config.rustfs_volume_path,
            100,
            Duration::from_secs(300),
        )?
        .with_name_suffix(suffix)
        .with_exact_pods(self.target.unavailable_pods.clone())?;
        let manifest = spec.manifest();
        self.collector.write_text(
            &self.case_name,
            &format!("bitrot-exact-quorum{suffix}.yaml"),
            &manifest,
        )?;
        let guard = apply_iochaos(&self.config.cluster, &spec)?;
        guard.wait_active(self.config.cluster.timeout)?;
        self.validate_exact_chaos_snapshot(&guard)?;
        self.active_chaos = Some(guard);
        Ok(())
    }

    fn validate_exact_chaos_snapshot(&self, guard: &ChaosGuard) -> Result<()> {
        let raw = guard.json()?;
        let value: Value = serde_json::from_str(&raw).context("decode exact-quorum IOChaos")?;
        let selected = value
            .pointer("/spec/selector/pods")
            .and_then(Value::as_object)
            .and_then(|pods| pods.get(&self.target.volume.namespace))
            .and_then(Value::as_array)
            .context("exact-quorum IOChaos lacks its closed Pod selector")?
            .iter()
            .map(|pod| {
                pod.as_str()
                    .map(str::to_string)
                    .context("IOChaos Pod is not a string")
            })
            .collect::<Result<BTreeSet<_>>>()?;
        let expected = self
            .target
            .unavailable_pods
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let injected = value
            .pointer("/status/experiment/containerRecords")
            .and_then(Value::as_array)
            .context("exact-quorum IOChaos lacks controller records")?
            .iter()
            .map(|record| {
                ensure!(
                    record.get("phase").and_then(Value::as_str) == Some("Injected")
                        && record
                            .get("injectedCount")
                            .and_then(Value::as_u64)
                            .is_some_and(|count| count > 0),
                    "exact-quorum IOChaos controller record is not injected"
                );
                let id = record
                    .get("id")
                    .and_then(Value::as_str)
                    .context("exact-quorum IOChaos controller record lacks id")?;
                let qualified = iochaos_record_pod_id(id)?;
                qualified
                    .strip_prefix(&format!("{}/", self.target.volume.namespace))
                    .map(str::to_string)
                    .context("exact-quorum IOChaos record belongs to another namespace")
            })
            .collect::<Result<BTreeSet<_>>>()?;
        ensure!(
            selected == expected && injected == expected,
            "exact-quorum IOChaos intent or active controller cohort differs from the sealed Pod set"
        );
        self.collector.write_text(
            &self.case_name,
            &format!("{}-active.json", guard.name()),
            &raw,
        )?;
        Ok(())
    }

    fn remove_exact_quorum_chaos(&mut self) -> Result<()> {
        if let Some(mut guard) = self.active_chaos.take()
            && let Err(error) = guard.delete(self.config.cluster.timeout)
        {
            self.active_chaos = Some(guard);
            return Err(error);
        }
        Ok(())
    }

    fn raw_admin_receipt(
        api_revision: &str,
        started_at_ms: u64,
        completed_at_ms: u64,
        response: RustfsAdminResponse,
    ) -> Result<RawBitrotEvidenceReceipt> {
        ensure!(
            (200..300).contains(&response.status),
            "RustFS {api_revision} returned HTTP {} request_id={}",
            response.status,
            response.request_id.as_deref().unwrap_or("unknown")
        );
        let response_body = String::from_utf8(response.body)
            .with_context(|| format!("RustFS {api_revision} returned non-UTF-8 evidence"))?;
        Ok(RawBitrotEvidenceReceipt {
            api_revision: api_revision.to_string(),
            response_sha256: sha256_bytes(response_body.as_bytes()),
            response_body,
            started_at_ms,
            completed_at_ms,
        })
    }

    async fn automatic_scanner_evidence(
        &mut self,
        corruption_closed_at_ms: u64,
    ) -> Result<(RawBitrotEvidenceReceipt, Vec<BitrotHealProgressSample>)> {
        self.reset_heal_progress()?;
        loop {
            self.deadline.check()?;
            let _ = self.renew_current().await?;
            let started_at_ms = now_ms()?;
            let response = self
                .admin
                .request(
                    Method::GET,
                    "/rustfs/admin/v3/scanner/status",
                    &[],
                    Vec::new(),
                    None,
                )
                .await?;
            let completed_at_ms = now_ms()?.max(started_at_ms);
            let receipt = Self::raw_admin_receipt(
                "v3/scanner/status",
                started_at_ms,
                completed_at_ms,
                response,
            )?;
            let body = serde_json::from_str::<ScannerStatusBody>(&receipt.response_body)
                .context("decode live scanner status")?;
            let end_ms = body.metrics.last_cycle_end_unix_secs.saturating_mul(1_000);
            let duration_ms = (body.metrics.last_cycle_duration_seconds * 1_000.0)
                .round()
                .max(0.0) as u64;
            let completed = body.enabled
                && body.metrics.last_cycle_result == "completed"
                && body.metrics.last_cycle_heal_objects > 0
                && body.metrics.versions_scanned > 0
                && end_ms.saturating_sub(duration_ms) >= corruption_closed_at_ms;
            let failed = matches!(
                body.metrics.last_cycle_result.as_str(),
                "failed" | "stopped" | "canceled"
            ) && end_ms >= corruption_closed_at_ms;
            let state = if completed {
                HealProgressState::Completed
            } else if failed {
                HealProgressState::Failed
            } else {
                HealProgressState::Running
            };
            let failure_detail = failed.then(|| {
                format!(
                    "scanner cycle ended with result {} after corruption",
                    body.metrics.last_cycle_result
                )
            });
            self.record_heal_progress(BitrotHealProgressSample {
                schema_version: BITROT_ARTIFACT_SCHEMA_VERSION,
                source: BitrotHealProgressSource::AutomaticScanner,
                ordinal: u64::try_from(self.heal_progress.len())?,
                client_token_sha256: None,
                state,
                failure_detail: failure_detail.clone(),
                receipt: receipt.clone(),
            })?;
            if completed {
                return Ok((receipt, self.heal_progress.clone()));
            }
            if let Some(failure_detail) = failure_detail {
                bail!(failure_detail);
            }
            tokio::time::sleep(Duration::from_millis(self.target.scanner_poll_interval_ms)).await;
        }
    }

    async fn admin_deep_evidence(
        &mut self,
    ) -> Result<(
        RawBitrotEvidenceReceipt,
        RawBitrotEvidenceReceipt,
        Vec<BitrotHealProgressSample>,
    )> {
        self.reset_heal_progress()?;
        let path = format!("/rustfs/admin/v3/heal/{}", self.target.bucket);
        let request_body = serde_json::to_vec(&serde_json::json!({
            "recursive": true,
            "scanMode": 2
        }))?;
        let started_at_ms = now_ms()?;
        ensure!(
            matches!(self.admin_heal, BitrotAdminHealStartState::NotStarted),
            "admin heal ownership already exists"
        );
        self.admin_heal =
            BitrotAdminHealStartState::ambiguous(&self.target.bucket, &path, started_at_ms);
        let first = self
            .admin
            .request(
                Method::POST,
                &path,
                &[],
                request_body.clone(),
                Some("application/json"),
            )
            .await;
        let (response, reconciled_after_response_loss) = match first {
            Ok(response) => (response, false),
            Err(response_loss) => (
                self.admin
                    .request(
                        Method::POST,
                        &path,
                        &[],
                        request_body,
                        Some("application/json"),
                    )
                    .await
                    .with_context(|| {
                        format!(
                            "admin heal start remained ambiguous after exact-scope replay: {response_loss:#}"
                        )
                    })?,
                true,
            ),
        };
        let completed_at_ms = now_ms()?.max(started_at_ms);
        let start =
            Self::raw_admin_receipt("v3/heal/start", started_at_ms, completed_at_ms, response)?;
        let start_body = self
            .admin_heal
            .own_from_start(&start, reconciled_after_response_loss)?;
        let token = start_body.client_token.clone();
        self.persist_json(BITROT_ADMIN_HEAL_START_ARTIFACT, &start)?;
        self.events.record(
            "admin-heal",
            RunEventStatus::Started,
            "owned AdminDeep heal started",
            Some(serde_json::json!({
                "clientTokenSha256": sha256_bytes(start_body.client_token.as_bytes()),
                "startedAtMs": start.started_at_ms,
            })),
        )?;
        let status_started_at_ms = now_ms()?;
        let response = self
            .admin
            .request(
                Method::POST,
                &path,
                &[("clientToken", token.as_str())],
                Vec::new(),
                None,
            )
            .await
            .context("reconcile admin heal start with exact-scope status")?;
        let status_completed_at_ms = now_ms()?.max(status_started_at_ms);
        let mut status = Self::raw_admin_receipt(
            "v3/heal/status",
            status_started_at_ms,
            status_completed_at_ms,
            response,
        )?;
        loop {
            self.deadline.check()?;
            let body = self.admin_heal.validate_owned_status(&status)?;
            let state = match body.summary.as_str() {
                "finished" if body.failure_detail.is_empty() => HealProgressState::Completed,
                "failed" | "stopped" | "canceled" => HealProgressState::Failed,
                "finished" => HealProgressState::Failed,
                "running" => HealProgressState::Running,
                _ => HealProgressState::Failed,
            };
            let failure_detail = (state == HealProgressState::Failed).then(|| {
                if body.failure_detail.trim().is_empty() {
                    format!("admin heal ended in state {:?}", body.summary)
                } else {
                    body.failure_detail.clone()
                }
            });
            self.record_heal_progress(BitrotHealProgressSample {
                schema_version: BITROT_ARTIFACT_SCHEMA_VERSION,
                source: BitrotHealProgressSource::AdminDeep,
                ordinal: u64::try_from(self.heal_progress.len())?,
                client_token_sha256: Some(sha256_bytes(token.as_bytes())),
                state,
                failure_detail: failure_detail.clone(),
                receipt: status.clone(),
            })?;
            match state {
                HealProgressState::Completed => {
                    let progress = self.heal_progress.clone();
                    validate_heal_progress(
                        &progress,
                        BitrotHealProgressSource::AdminDeep,
                        Some(&token),
                    )?;
                    self.admin_heal = BitrotAdminHealStartState::NotStarted;
                    self.events.record(
                        "admin-heal",
                        RunEventStatus::Succeeded,
                        "owned AdminDeep heal reached a successful terminal status",
                        Some(serde_json::json!({
                            "progressSamples": progress.len(),
                        })),
                    )?;
                    return Ok((start, status, progress));
                }
                HealProgressState::Running | HealProgressState::Queued => {
                    tokio::time::sleep(Duration::from_millis(self.target.scanner_poll_interval_ms))
                        .await;
                    let _ = self.renew_current().await?;
                    let status_started_at_ms = now_ms()?;
                    let response = self
                        .admin
                        .request(
                            Method::POST,
                            &path,
                            &[("clientToken", token.as_str())],
                            Vec::new(),
                            None,
                        )
                        .await?;
                    let status_completed_at_ms = now_ms()?.max(status_started_at_ms);
                    status = Self::raw_admin_receipt(
                        "v3/heal/status",
                        status_started_at_ms,
                        status_completed_at_ms,
                        response,
                    )?;
                }
                HealProgressState::Failed => {
                    let failure_detail =
                        failure_detail.context("failed admin heal lacks a reason")?;
                    self.events.record(
                        "admin-heal",
                        RunEventStatus::Failed,
                        "owned AdminDeep heal reached a failed terminal status",
                        Some(serde_json::json!({
                            "failureDetail": failure_detail.clone(),
                        })),
                    )?;
                    bail!("owned admin heal failed: {failure_detail}")
                }
            }
        }
    }

    async fn cancel_owned_admin(&mut self) -> Result<()> {
        let path = format!("/rustfs/admin/v3/heal/{}", self.target.bucket);
        let Some(token) = self
            .admin_heal
            .owned_token(&self.target.bucket, &path)?
            .map(str::to_string)
        else {
            return Ok(());
        };
        let started_at_ms = now_ms()?;
        let response = self
            .admin
            .request(
                Method::POST,
                &path,
                &[("forceStop", "true"), ("clientToken", token.as_str())],
                Vec::new(),
                None,
            )
            .await?;
        let completed_at_ms = now_ms()?.max(started_at_ms);
        let receipt =
            Self::raw_admin_receipt("v3/heal/cancel", started_at_ms, completed_at_ms, response)?;
        let body = serde_json::from_str::<AdminHealStatusBody>(&receipt.response_body)
            .context("decode owned admin heal cancel status")?;
        ensure!(
            matches!(body.summary.as_str(), "stopped" | "finished"),
            "owned admin heal cancel did not return a terminal status"
        );
        self.admin_heal = BitrotAdminHealStartState::NotStarted;
        Ok(())
    }

    async fn perform_exact_read(
        &mut self,
        context: &OwnedStorageContext,
        probe: &ExplicitVersionProbe,
    ) -> Result<ExactCohortReadReceipt> {
        let observation = observe_exact_kubernetes_target(&self.config, &self.target)?;
        ensure!(
            observation.resource_versions == context.resource_versions
                && observation.target_proof_sha256 == context.volume.target_proof_sha256,
            "exact-quorum read target generation drifted"
        );
        let guard = self
            .active_chaos
            .as_ref()
            .context("exact-quorum read requires an active IOChaos cohort")?;
        self.validate_exact_chaos_snapshot(guard)?;
        let started_at_ms = now_ms()?;
        let recorded = self
            .s3
            .get_object_version_recorded_result(&probe.object_key, &probe.version_id, &self.history)
            .await?;
        let completed_at_ms = now_ms()?.max(started_at_ms);
        let result = recorded.result;
        let observed_sha256 = result.body.as_deref().map(sha256_bytes);
        let outcome = if result.outcome == OperationOutcome::Ok {
            if observed_sha256.as_deref() == Some(probe.expected_sha256.as_str()) {
                BitrotReadOutcome::ExpectedBytes
            } else {
                BitrotReadOutcome::UnexpectedBytes
            }
        } else {
            BitrotReadOutcome::CleanRejected
        };
        Ok(ExactCohortReadReceipt {
            operation_id: recorded.operation_id,
            context_sha256: context_sha256(context)?,
            cohort_sha256: self.cohort_sha256()?,
            bucket: probe.bucket.clone(),
            object_key: probe.object_key.clone(),
            version_id: probe.version_id.clone(),
            expected_sha256: probe.expected_sha256.clone(),
            observed_sha256,
            http_status: result.http_status,
            error: result.error.or_else(|| {
                (outcome == BitrotReadOutcome::CleanRejected)
                    .then(|| "exact-quorum read was rejected without an SDK detail".to_string())
            }),
            outcome,
            target_shard_required: true,
            started_at_ms,
            completed_at_ms,
        })
    }

    async fn emergency_cleanup_proof(
        &mut self,
        context: &OwnedStorageContext,
    ) -> Result<(StorageRecoveryCleanupProof, Option<MutationJournalLookup>)> {
        let (mutation_operation_id, mutation_lookup) = if let Some(mutation) = &self.mutation {
            (mutation.mutation_receipt.operation_id.clone(), None)
        } else if let Some((operation_id, operation)) = self.pending_mutation.clone() {
            let lookup = self
                .helper_mut()?
                .query_mutation(context, &operation_id, &operation)
                .await?;
            (operation_id, Some(lookup))
        } else {
            return Ok((
                StorageRecoveryCleanupProof::AbortedBeforeMutation {
                    observed_at_ms: now_ms()?.max(context.observed_at_ms),
                },
                None,
            ));
        };
        let operation = StorageRecoveryHostOperation::RestoreShard {
            mutation_operation_id,
        };
        let receipt = self.helper_mut()?.execute(context, &operation).await?;
        let response = serde_json::from_str::<OfflineShardRecoveryResponse>(&receipt.response_body)
            .context("decode emergency shard recovery")?;
        match response.outcome {
            crate::fault::storage_recovery_runtime::RestoreOutcome::Restored => Ok((
                StorageRecoveryCleanupProof::BitrotRestored {
                    restore_receipt: Box::new(receipt),
                },
                mutation_lookup,
            )),
            crate::fault::storage_recovery_runtime::RestoreOutcome::AlreadyRepaired => Ok((
                StorageRecoveryCleanupProof::BitrotAlreadyRepaired {
                    restore_receipt: Box::new(receipt),
                },
                mutation_lookup,
            )),
            outcome => bail!("emergency shard cleanup returned {outcome:?}"),
        }
    }

    async fn emergency_cleanup(&mut self) -> BitrotEmergencyCleanupEvidence {
        let mut errors = Vec::new();
        let mut mutation_lookup = None;
        let mut cleanup_proof = self
            .cleanup
            .as_ref()
            .map(|cleanup| cleanup.helper_cleanup.clone())
            .or_else(|| self.pending_cleanup_proof.clone());
        let mut helper_closed =
            self.helper.is_none() && (self.cleanup.is_none() || self.helper_finish_completed);
        if let Err(error) = self.remove_exact_quorum_chaos() {
            errors.push(format!("remove exact-quorum IOChaos: {error:#}"));
        }
        if let Err(error) = self.cancel_owned_admin().await {
            errors.push(format!("cancel owned admin heal: {error:#}"));
        }
        if self.helper.is_some() && self.current.is_some() {
            match self.renew_current().await {
                Ok(context) => {
                    let cleanup_result = if let Some(cleanup) = cleanup_proof.clone() {
                        Ok((cleanup, None))
                    } else {
                        self.emergency_cleanup_proof(&context).await
                    };
                    match cleanup_result {
                        Ok((cleanup, lookup)) => {
                            mutation_lookup = lookup;
                            cleanup_proof = Some(cleanup.clone());
                            if let Some(helper) = self.helper.take() {
                                match helper.finish(&context, &cleanup).await {
                                    Ok(()) => {
                                        self.helper_finish_completed = true;
                                        helper_closed = true;
                                    }
                                    Err(error) => {
                                        errors.push(format!("finish storage helper: {error:#}"));
                                    }
                                }
                            }
                        }
                        Err(error) => {
                            errors.push(format!("restore selected shard: {error:#}"));
                        }
                    }
                }
                Err(error) => {
                    errors.push(format!("renew cleanup Lease: {error:#}"));
                }
            }
        }
        BitrotEmergencyCleanupEvidence {
            attempted: true,
            chaos_removed: self.active_chaos.is_none(),
            admin_heal_closed: matches!(self.admin_heal, BitrotAdminHealStartState::NotStarted),
            helper_closed,
            mutation_lookup,
            cleanup_proof,
            errors,
            completed_at_ms: now_ms().unwrap_or_default(),
        }
    }

    fn failure_stage(&self) -> &'static str {
        if self.current.is_none() {
            "target-proof"
        } else if self.selection.is_none() {
            "selection"
        } else if self.pending_mutation.is_some() || self.mutation.is_none() {
            "mutation"
        } else if self.corruption.is_none() {
            "corruption-window"
        } else if self.heal.is_none() {
            if self
                .heal_progress
                .last()
                .is_some_and(|sample| sample.state == HealProgressState::Completed)
            {
                "post-heal-verification"
            } else {
                "heal"
            }
        } else if self.cleanup.is_none() {
            "cleanup"
        } else if !self.helper_finish_completed {
            "helper-cleanup"
        } else {
            "final-checker"
        }
    }
}

#[async_trait]
impl OnDiskBitrotRuntimePort for LiveOnDiskBitrotRuntime {
    async fn acquire(&mut self, case: StorageRecoveryCase) -> Result<OwnedStorageContext> {
        ensure!(case == self.case, "live bitrot adapter case drifted");
        let observation = observe_exact_kubernetes_target(&self.config, &self.target)?;
        let mut volume = self.target.volume.clone();
        volume.observed_at_ms = observation.observed_at_ms;
        let identity = StorageRecoveryArtifactIdentity {
            run_id: self.run_id.clone(),
            scenario: "on-disk-bitrot".to_string(),
            case_name: self.case_name.clone(),
            bucket: self.target.bucket.clone(),
        };
        let attempt_id = Uuid::new_v4().to_string();
        let placeholder_lease = crate::fault::storage_recovery_runtime::KubernetesLeaseProof {
            name: "placeholder".to_string(),
            uid: "placeholder".to_string(),
            resource_version: "placeholder".to_string(),
            holder_identity: "placeholder".to_string(),
            scope_sha256: "0".repeat(64),
            acquired_at_ms: 1,
            renew_at_ms: 1,
            expires_at_ms: u64::MAX,
        };
        let mut context = OwnedStorageContext {
            identity,
            case,
            attempt_id: attempt_id.clone(),
            cluster_context: self.config.cluster.context.clone(),
            tenant_uid: self.target.tenant_uid.clone(),
            scope_sha256: String::new(),
            volume,
            resource_versions: observation.resource_versions,
            host_generation: self.target.host_generation.clone(),
            exclusive_access: StorageRecoveryExclusiveAccess {
                kubernetes_lease: placeholder_lease,
                host_flock: HostFlockProof {
                    node: self.target.volume.node.clone(),
                    node_uid: self.target.volume.node_uid.clone(),
                    path: String::new(),
                    device_id: self.target.host_lock_device_id.clone(),
                    inode: self.target.host_lock_inode,
                    scope_sha256: String::new(),
                    acquired_at_ms: 1,
                },
            },
            helper_pod_name: self.target.helper_pod_name.clone(),
            helper_pod_uid: self.target.helper_pod_uid.clone(),
            observed_at_ms: observation.observed_at_ms,
        };
        context.scope_sha256 = storage_scope_sha256(&context);
        let client = client_for_context(&context.cluster_context)
            .await
            .context("build Kubernetes client for bitrot Lease")?;
        let lease = KubernetesStorageLeaseAdapter::new(
            client,
            &context.volume.namespace,
            &context.scope_sha256,
            &self.run_id,
            &attempt_id,
            Duration::from_secs(self.target.lease_duration_seconds),
        )?;
        let proof = lease.acquire().await?;
        let acquired_observed_at_ms = now_ms()?.max(proof.acquired_at_ms);
        context.volume.observed_at_ms = acquired_observed_at_ms;
        context.observed_at_ms = acquired_observed_at_ms;
        context.exclusive_access = StorageRecoveryExclusiveAccess {
            kubernetes_lease: proof,
            host_flock: HostFlockProof {
                node: context.volume.node.clone(),
                node_uid: context.volume.node_uid.clone(),
                path: format!(
                    "{}/storage-{}.lock",
                    crate::fault::storage_recovery_runtime::STORAGE_RECOVERY_HOST_LOCK_DIRECTORY,
                    context.scope_sha256
                ),
                device_id: self.target.host_lock_device_id.clone(),
                inode: self.target.host_lock_inode,
                scope_sha256: context.scope_sha256.clone(),
                acquired_at_ms: acquired_observed_at_ms,
            },
        };
        context.validate()?;
        let host = KubectlStorageRecoveryHostAdapter::new(
            &self.config.cluster,
            context.volume.namespace.clone(),
            context.helper_pod_name.clone(),
            self.config.request_timeout,
        )?;
        let helper = host.begin_attempt(&context).await?;
        self.lease = Some(lease);
        self.helper = Some(helper);
        self.current = Some(context.clone());
        let preflight = PreflightSummary::single_run(
            &self.config,
            "on-disk-bitrot",
            &self.run_id,
            vec![PreflightPhase::new(
                "target-proof",
                vec![PreflightCheck::passed(
                    "owned-storage-context",
                    "exact Kubernetes generations, Lease, helper flock, and one-volume-per-server cohort qualified",
                    ResponsibilityDomain::Harness,
                )],
            )],
        );
        self.persist_json("preflight-summary.json", &preflight)?;
        self.events.record(
            "target-proof",
            RunEventStatus::Succeeded,
            "owned storage target and exclusive guards acquired",
            Some(serde_json::json!({
                "attemptId": context.attempt_id,
                "scopeSha256": context.scope_sha256,
            })),
        )?;
        Ok(context)
    }

    async fn renew(&mut self, context: &OwnedStorageContext) -> Result<OwnedStorageContext> {
        ensure!(
            self.current()? == context,
            "Lease heartbeat was requested for a stale context"
        );
        self.renew_current().await
    }

    async fn qualify_capability(
        &mut self,
        context: &OwnedStorageContext,
    ) -> Result<BitrotCapabilityObservation> {
        ensure!(self.current()? == context, "capability context is stale");
        let started_at_ms = now_ms()?;
        let response = self
            .admin
            .request(Method::GET, "/rustfs/admin/v3/info", &[], Vec::new(), None)
            .await?;
        ensure!(
            (200..300).contains(&response.status),
            "RustFS capability request failed with HTTP {}",
            response.status
        );
        let response_body =
            String::from_utf8(response.body).context("capability body is not UTF-8")?;
        let observed_at_ms = now_ms()?.max(started_at_ms);
        let observation = BitrotCapabilityObservation {
            cluster_context: context.cluster_context.clone(),
            tenant_uid: context.tenant_uid.clone(),
            drive_uuid: context.volume.rustfs_drive_uuid.clone(),
            explicit_version_reads: true,
            offline_xl2_non_inline: true,
            observed_at_ms,
            expires_at_ms: observed_at_ms
                .checked_add(self.target.capability_ttl_ms)
                .context("bitrot capability expiry overflow")?,
            response_sha256: sha256_bytes(response_body.as_bytes()),
            response_body,
        };
        self.capability_cache.insert(observation.clone())?;
        Ok(observation)
    }

    async fn write_explicit_version_probe(
        &mut self,
        context: &OwnedStorageContext,
    ) -> Result<ExplicitVersionProbe> {
        ensure!(self.current()? == context, "probe context is stale");
        let capability = self.capability_cache.require(context, now_ms()?)?.clone();
        ensure!(
            self.s3.create_bucket(&self.history).await? == OperationOutcome::Ok,
            "dedicated bitrot bucket could not be created"
        );
        ensure!(
            self.s3.enable_bucket_versioning(&self.history).await? == OperationOutcome::Ok,
            "bitrot bucket versioning could not be enabled"
        );
        let object = ObjectSpec::prepare_seeded(&self.run_id, 0, 1024 * 1024, 0x6269_7472_6f74);
        let record = self.s3.put_object_record(&object, &self.history).await?;
        ensure!(
            record.outcome == OperationOutcome::Ok,
            "bitrot probe PUT failed"
        );
        let version_id = record
            .version_id
            .filter(|version| !version.is_empty() && version != "null")
            .context("bitrot probe PUT did not return an explicit versionId")?;
        let marker = self
            .s3
            .delete_marker_record(&object.spec.key, &self.history)
            .await?
            .context("bitrot probe DELETE did not confirm a versioned delete marker")?;
        ensure!(
            marker.outcome == OperationOutcome::Ok,
            "bitrot probe delete-marker creation failed"
        );
        let delete_marker_version_id = marker
            .version_id
            .filter(|version| !version.is_empty() && version != "null")
            .context("bitrot probe delete marker lacks an explicit versionId")?;
        let listed_versions = self
            .s3
            .list_object_versions(&object.spec.key, &self.history)
            .await?
            .context("bitrot probe ListObjectVersions did not complete")?;
        let version_set = BitrotVersionSetEvidence::from_listing(
            &self.target.bucket,
            &object.spec.key,
            &version_id,
            &delete_marker_version_id,
            &listed_versions,
            now_ms()?,
        )?;
        let probe = ExplicitVersionProbe {
            operation_id: record.id,
            bucket: self.target.bucket.clone(),
            object_key: object.spec.key,
            version_id: version_id.clone(),
            expected_sha256: object.spec.sha256,
            size_bytes: u64::try_from(object.spec.size_bytes)?,
            committed_at_ms: record.ended_at_ms,
            capability_sha256: capability.response_sha256.clone(),
            version_set,
        };
        probe.validate(&context.identity, &capability)?;
        Ok(probe)
    }

    async fn inspect(
        &mut self,
        context: &OwnedStorageContext,
        probe: &ExplicitVersionProbe,
    ) -> Result<BitrotSelectionEvidence> {
        ensure!(self.current()? == context, "inspection context is stale");
        self.capability_cache.require(context, now_ms()?)?;
        let observation = observe_exact_kubernetes_target(&self.config, &self.target)?;
        ensure!(
            observation.resource_versions == context.resource_versions,
            "storage target drifted before inspection"
        );
        let operation = StorageRecoveryHostOperation::InspectXlMeta {
            object_directory: volume_relative_object_directory(&probe.bucket, &probe.object_key),
            bucket: probe.bucket.clone(),
            object_key: probe.object_key.clone(),
            object_sha256: probe.expected_sha256.clone(),
            version_id: probe.version_id.clone(),
            selected_part_number: self.target.selected_part_number,
            expected_mount_device_id: context.host_generation.device_major_minor.clone(),
            expected_drive_uuid: context.volume.rustfs_drive_uuid.clone(),
        };
        let receipt = self.helper_mut()?.execute(context, &operation).await?;
        let mapping = offline_mapping(context, &receipt)?;
        let selection = BitrotSelectionEvidence {
            schema_version: BITROT_ARTIFACT_SCHEMA_VERSION,
            identity: context.identity.clone(),
            case: self.case,
            context: Box::new(context.clone()),
            capability: self.capability_cache.require(context, now_ms()?)?.clone(),
            probe: probe.clone(),
            shape: self.target.shape.clone(),
            membership: self.target.membership.clone(),
            exact_cohort: ExactCohortDefinition {
                member_pod_uids: self.target.member_pod_uids.clone(),
                unavailable_pods: self.target.unavailable_pods.clone(),
                target_drive_uuid: self.target.volume.rustfs_drive_uuid.clone(),
                volume_path: self.config.rustfs_volume_path.clone(),
            },
            mapping,
            inspection_receipt: Box::new(receipt),
        };
        selection.validate()?;
        self.persist_json(BITROT_SELECTION_ARTIFACT, &selection)?;
        self.selection = Some(selection.clone());
        Ok(selection)
    }

    async fn exact_quorum_read(
        &mut self,
        context: &OwnedStorageContext,
        probe: &ExplicitVersionProbe,
    ) -> Result<ExactCohortReadReceipt> {
        ensure!(
            self.current()? == context,
            "exact-quorum read context is stale"
        );
        if self.active_chaos.is_none() {
            self.apply_exact_quorum_chaos("-corruption")?;
        }
        let receipt = self.perform_exact_read(context, probe).await?;
        if let Some(baseline) = self.baseline.take() {
            let mutation = self
                .mutation
                .as_ref()
                .context("corruption read occurred before controlled mutation")?;
            let proof = BitrotCorruptionWindowProof {
                schema_version: BITROT_ARTIFACT_SCHEMA_VERSION,
                baseline,
                opened_at_ms: mutation.mutated_at_ms,
                closed_at_ms: receipt.completed_at_ms,
                corrupted: receipt.clone(),
            };
            self.persist_json(BITROT_CORRUPTION_WINDOW_ARTIFACT, &proof)?;
            self.corruption = Some(proof);
        } else {
            self.baseline = Some(receipt.clone());
        }
        Ok(receipt)
    }

    async fn mutate(
        &mut self,
        context: &OwnedStorageContext,
        inspection_operation_id: &str,
        part_number: u32,
    ) -> Result<StorageRecoveryOperationReceipt> {
        ensure!(self.current()? == context, "mutation context is stale");
        let observation = observe_exact_kubernetes_target(&self.config, &self.target)?;
        ensure!(
            observation.resource_versions == context.resource_versions,
            "storage target drifted immediately before mutation"
        );
        self.validate_exact_chaos_snapshot(
            self.active_chaos
                .as_ref()
                .context("controlled mutation requires the active exact cohort")?,
        )?;
        let operation = StorageRecoveryHostOperation::MutateShard {
            inspection_operation_id: inspection_operation_id.to_string(),
            part_number,
            byte_offset: self.target.mutation_byte_offset,
        };
        let operation_id = Uuid::new_v4().to_string();
        self.pending_mutation = Some((operation_id.clone(), operation.clone()));
        let receipt = self
            .helper_mut()?
            .execute_mutation_with_id(context, &operation_id, &operation)
            .await?;
        let evidence = BitrotMutationEvidence {
            schema_version: BITROT_ARTIFACT_SCHEMA_VERSION,
            selection_operation_id: inspection_operation_id.to_string(),
            mutated_at_ms: receipt.completed_at_ms,
            mutation_receipt: Box::new(receipt.clone()),
        };
        let selection = self
            .selection
            .as_ref()
            .context("mutation lacks selection evidence")?;
        evidence.validate(selection)?;
        self.history.mark_fault_active_at(receipt.completed_at_ms);
        let collector = self.collector.clone();
        let case_name = self.case_name.clone();
        retain_mutation_before_persist(
            &mut self.mutation,
            &mut self.pending_mutation,
            evidence,
            |evidence| {
                let body = serde_json::to_string_pretty(evidence)?;
                collector.write_text(&case_name, BITROT_MUTATION_ARTIFACT, &body)?;
                Ok(())
            },
        )?;
        Ok(receipt)
    }

    async fn heal_and_cleanup(
        &mut self,
        context: &OwnedStorageContext,
        probe: &ExplicitVersionProbe,
        mutation: &StorageRecoveryOperationReceipt,
        mode: HealMode,
    ) -> Result<(BitrotHealEvidence, BitrotCleanupEvidence)> {
        ensure!(self.current()? == context, "recovery context is stale");
        let corruption_closed_at_ms = self
            .corruption
            .as_ref()
            .context("recovery lacks corruption-window proof")?
            .closed_at_ms;
        self.remove_exact_quorum_chaos()?;
        self.history.mark_fault_ended_now();
        let heal = match mode {
            HealMode::AutomaticScanner => {
                let (status, progress) = self
                    .automatic_scanner_evidence(corruption_closed_at_ms)
                    .await?;
                BitrotHealEvidence::AutomaticScanner {
                    status,
                    progress,
                    no_admin_operation: true,
                    no_host_restore_before_post_inspect: true,
                }
            }
            HealMode::AdminDeep => {
                let (start, terminal_status, progress) = self.admin_deep_evidence().await?;
                BitrotHealEvidence::AdminDeep {
                    start,
                    progress,
                    terminal_status,
                    cancel: None,
                }
            }
            _ => bail!("on-disk-bitrot received a non-bitrot heal mode"),
        };
        let recovery_context = self.current()?.clone();
        let operation = StorageRecoveryHostOperation::InspectXlMeta {
            object_directory: volume_relative_object_directory(&probe.bucket, &probe.object_key),
            bucket: probe.bucket.clone(),
            object_key: probe.object_key.clone(),
            object_sha256: probe.expected_sha256.clone(),
            version_id: probe.version_id.clone(),
            selected_part_number: self.target.selected_part_number,
            expected_mount_device_id: recovery_context.host_generation.device_major_minor.clone(),
            expected_drive_uuid: recovery_context.volume.rustfs_drive_uuid.clone(),
        };
        let post_inspection = self
            .helper_mut()?
            .execute(&recovery_context, &operation)
            .await?;
        let post =
            serde_json::from_str::<OfflineXl2InspectResponse>(&post_inspection.response_body)?;
        let mutated =
            serde_json::from_str::<OfflineShardMutationResponse>(&mutation.response_body)?;
        ensure!(
            post.selected_part.original_sha256 == mutated.original_sha256
                && post.selected_part.original_sha256 != mutated.mutated_sha256,
            "heal source completed without repairing the selected shard"
        );
        let cleanup_operation = if post.selected_part.shard_inode == mutated.shard_inode {
            StorageRecoveryHostOperation::RestoreShard {
                mutation_operation_id: mutation.operation_id.clone(),
            }
        } else {
            StorageRecoveryHostOperation::VerifySupersededShard {
                mutation_operation_id: mutation.operation_id.clone(),
                post_inspection_operation_id: post_inspection.operation_id.clone(),
            }
        };
        let cleanup_receipt = self
            .helper_mut()?
            .execute(&recovery_context, &cleanup_operation)
            .await?;
        let helper_cleanup = match cleanup_operation {
            StorageRecoveryHostOperation::RestoreShard { .. } => {
                let response = serde_json::from_str::<OfflineShardRecoveryResponse>(
                    &cleanup_receipt.response_body,
                )?;
                match response.outcome {
                    crate::fault::storage_recovery_runtime::RestoreOutcome::Restored => {
                        StorageRecoveryCleanupProof::BitrotRestored {
                            restore_receipt: Box::new(cleanup_receipt),
                        }
                    }
                    crate::fault::storage_recovery_runtime::RestoreOutcome::AlreadyRepaired => {
                        StorageRecoveryCleanupProof::BitrotAlreadyRepaired {
                            restore_receipt: Box::new(cleanup_receipt),
                        }
                    }
                    _ => bail!("bitrot cleanup did not reach a releasable shard state"),
                }
            }
            StorageRecoveryHostOperation::VerifySupersededShard { .. } => {
                StorageRecoveryCleanupProof::BitrotVerifiedSuperseded {
                    verification_receipt: Box::new(cleanup_receipt),
                }
            }
            _ => unreachable!("cleanup operation is closed above"),
        };
        self.pending_cleanup_proof = Some(helper_cleanup.clone());
        let fresh_mapping = offline_mapping(&recovery_context, &post_inspection)?;
        self.persist_json(BITROT_HEAL_ARTIFACT, &heal)?;
        self.apply_exact_quorum_chaos("-post-heal")?;
        let final_read = self.perform_exact_read(&recovery_context, probe).await?;
        final_read.require_expected_success(&recovery_context, probe)?;
        self.remove_exact_quorum_chaos()?;
        let listed_versions = self
            .s3
            .list_object_versions(&probe.object_key, &self.history)
            .await?
            .context("post-heal ListObjectVersions did not complete")?;
        let final_version_set = BitrotVersionSetEvidence::from_listing(
            &probe.bucket,
            &probe.object_key,
            &probe.version_id,
            &probe.version_set.delete_marker_version_id,
            &listed_versions,
            now_ms()?,
        )?;
        let cleanup = BitrotCleanupEvidence {
            schema_version: BITROT_ARTIFACT_SCHEMA_VERSION,
            context: Box::new(recovery_context),
            post_inspection_receipt: Box::new(post_inspection),
            fresh_mapping,
            post_heal_exact_quorum: final_read,
            final_version_set,
            helper_cleanup,
            completed_at_ms: now_ms()?,
        };
        let selection = self.selection.as_ref().context("cleanup lacks selection")?;
        cleanup.validate(selection, &mutated, &heal, corruption_closed_at_ms)?;
        self.persist_json(BITROT_CLEANUP_ARTIFACT, &cleanup)?;
        self.heal = Some(heal.clone());
        self.cleanup = Some(cleanup.clone());
        self.pending_cleanup_proof = None;
        Ok((heal, cleanup))
    }

    async fn finish(
        &mut self,
        _context: &OwnedStorageContext,
        cleanup: &StorageRecoveryCleanupProof,
    ) -> Result<()> {
        let current = self.current()?.clone();
        ensure!(
            self.cleanup
                .as_ref()
                .map(|evidence| &evidence.helper_cleanup)
                == Some(cleanup),
            "finish cleanup proof differs from the validated workflow"
        );
        let helper = self.helper.take().context("finish lacks storage helper")?;
        helper.finish(&current, cleanup).await?;
        self.helper_finish_completed = true;
        Ok(())
    }
}

impl LiveOnDiskBitrotRuntime {
    async fn finalize_success_artifacts(&mut self) -> Result<()> {
        let current = self.current()?.clone();
        self.history
            .set_durability_cohort(DurabilityCohort::PostRecovery);
        let checker = checker::check_s3_history(
            &self.s3,
            &self.history,
            true,
            self.workload_plan.concurrency,
            true,
        )
        .await?;
        checker.require_success()?;
        let checker_body = self.persist_json("checker-report.json", &checker)?;
        let post_history = Recorder::create(
            self.collector
                .case_dir(&self.case_name)
                .join(POST_RECOVERY_WRITE_HISTORY_ARTIFACT),
            "on-disk-bitrot",
            &self.run_id,
        )?;
        let post_report = run_post_recovery_write_probe(&PostRecoveryWriteRequest {
            s3: &self.s3,
            history: &post_history,
            run_id: &self.run_id,
            scope: crate::fault::workload::WriteProbeScope::PostRecovery,
            seed: 0x706f_7374_6269_7472,
            object_count: post_recovery_object_count(self.workload_plan.object_count),
            concurrency: self.workload_plan.concurrency,
            deadline: self.deadline,
        })
        .await?;
        post_report.require_success()?;
        let post_body = self.persist_json(POST_RECOVERY_WRITE_REPORT_ARTIFACT, &post_report)?;
        let selection = self.selection.as_ref().context("finish lacks selection")?;
        let mutation = self.mutation.as_ref().context("finish lacks mutation")?;
        let corruption = self
            .corruption
            .as_ref()
            .context("finish lacks corruption proof")?;
        let heal = self.heal.as_ref().context("finish lacks heal evidence")?;
        let cleanup_evidence = self
            .cleanup
            .as_ref()
            .context("finish lacks cleanup evidence")?;
        let workflow = OnDiskBitrotWorkflowEvidence {
            schema_version: BITROT_ARTIFACT_SCHEMA_VERSION,
            identity: selection.identity.clone(),
            selection_sha256: canonical_sha256(selection)?,
            mutation_sha256: canonical_sha256(mutation)?,
            corruption_window_sha256: canonical_sha256(corruption)?,
            heal_sha256: canonical_sha256(heal)?,
            cleanup_sha256: canonical_sha256(cleanup_evidence)?,
            checker_report_sha256: sha256_bytes(checker_body.as_bytes()),
            post_write_report_sha256: sha256_bytes(post_body.as_bytes()),
            diagnostic_logs: None,
        };
        validate_on_disk_bitrot_evidence(&OnDiskBitrotEvidenceSet {
            workflow: &workflow,
            selection,
            mutation,
            corruption_window: corruption,
            heal,
            cleanup: cleanup_evidence,
            checker_report_body: &checker_body,
            post_write_report_body: &post_body,
        })?;
        self.persist_json(BITROT_WORKFLOW_ARTIFACT, &workflow)?;
        self.persist_json(
            "bitrot-live-target-binding.json",
            &serde_json::json!({
                "schemaVersion": 1,
                "targetConfigSha256": self.target_config_sha256,
                "endpoint": self.endpoint,
                "scopeSha256": current.scope_sha256,
                "attemptId": current.attempt_id,
            }),
        )?;
        self.events.record(
            "checker-final",
            RunEventStatus::Succeeded,
            "final checker and post-recovery write probe passed",
            None,
        )?;
        self.events.record(
            "run",
            RunEventStatus::Succeeded,
            "on-disk-bitrot completed with receipt-bound cleanup",
            None,
        )?;
        Ok(())
    }
}

fn offline_mapping(
    context: &OwnedStorageContext,
    receipt: &StorageRecoveryOperationReceipt,
) -> Result<VersionShardMappingObservation> {
    serde_json::from_str::<OfflineXl2InspectResponse>(&receipt.response_body)
        .context("decode receipt-bound offline mapping")?;
    Ok(VersionShardMappingObservation {
        schema_version: 1,
        identity: context.identity.clone(),
        observation_id: Uuid::new_v4().to_string(),
        source: ShardMappingSource::OfflineXl2Inspector,
        api_revision: OFFLINE_XL2_INSPECTOR_REVISION.to_string(),
        response_sha256: receipt.response_sha256.clone(),
        response_body: receipt.response_body.clone(),
        offline_evidence: Some(Box::new(OfflineVersionShardMappingEvidence {
            context: Box::new(context.clone()),
            inspection_receipt: Box::new(receipt.clone()),
        })),
        target_proof_sha256: context.volume.target_proof_sha256.clone(),
        observed_at_ms: receipt.completed_at_ms,
    })
}

#[async_trait]
pub trait OnDiskBitrotRuntimePort: Send {
    async fn acquire(&mut self, case: StorageRecoveryCase) -> Result<OwnedStorageContext>;
    async fn renew(&mut self, context: &OwnedStorageContext) -> Result<OwnedStorageContext>;
    async fn qualify_capability(
        &mut self,
        context: &OwnedStorageContext,
    ) -> Result<BitrotCapabilityObservation>;
    async fn write_explicit_version_probe(
        &mut self,
        context: &OwnedStorageContext,
    ) -> Result<ExplicitVersionProbe>;
    async fn inspect(
        &mut self,
        context: &OwnedStorageContext,
        probe: &ExplicitVersionProbe,
    ) -> Result<BitrotSelectionEvidence>;
    async fn exact_quorum_read(
        &mut self,
        context: &OwnedStorageContext,
        probe: &ExplicitVersionProbe,
    ) -> Result<ExactCohortReadReceipt>;
    async fn mutate(
        &mut self,
        context: &OwnedStorageContext,
        inspection_operation_id: &str,
        part_number: u32,
    ) -> Result<StorageRecoveryOperationReceipt>;
    async fn heal_and_cleanup(
        &mut self,
        context: &OwnedStorageContext,
        probe: &ExplicitVersionProbe,
        mutation: &StorageRecoveryOperationReceipt,
        mode: HealMode,
    ) -> Result<(BitrotHealEvidence, BitrotCleanupEvidence)>;
    async fn finish(
        &mut self,
        context: &OwnedStorageContext,
        cleanup: &StorageRecoveryCleanupProof,
    ) -> Result<()>;
}

/// Executes the production ordering through one closed runtime port. Every
/// implementation, including the live adapter, must pass through the same
/// receipt validators used by fake integration tests.
pub async fn execute_on_disk_bitrot(
    runtime: &mut dyn OnDiskBitrotRuntimePort,
    case: StorageRecoveryCase,
) -> Result<()> {
    ensure!(
        matches!(
            case,
            StorageRecoveryCase::OnDiskBitrotAutomaticScanner
                | StorageRecoveryCase::OnDiskBitrotAdminDeep
        ),
        "on-disk-bitrot driver received a case from another scenario"
    );
    let acquired = runtime.acquire(case).await?;
    let capability = runtime.qualify_capability(&acquired).await?;
    capability.validate_for(&acquired, capability.observed_at_ms)?;
    let probe = runtime.write_explicit_version_probe(&acquired).await?;
    probe.validate(&acquired.identity, &capability)?;
    let mutation_context = runtime.renew(&acquired).await?;
    validate_renewed_context(&acquired, &mutation_context)?;
    let selection = runtime.inspect(&mutation_context, &probe).await?;
    let inspected = selection.validate()?;
    let baseline = runtime.exact_quorum_read(&mutation_context, &probe).await?;
    baseline.require_expected_success(&mutation_context, &probe)?;
    ensure!(
        baseline.cohort_sha256
            == selection
                .exact_cohort
                .sha256(&selection.shape, &selection.membership)?,
        "baseline read did not use the sealed exact cohort"
    );
    let mutation = runtime
        .mutate(
            &mutation_context,
            &selection.inspection_receipt.operation_id,
            inspected.selected_part.part_number,
        )
        .await?;
    mutation.validate_for(&mutation_context, &mutation.operation)?;
    let corrupted = runtime.exact_quorum_read(&mutation_context, &probe).await?;
    match corrupted.classify_corruption_window(&mutation_context, &probe)? {
        CorruptionReadVerdict::CleanRejected => {}
        CorruptionReadVerdict::ProductFailure => {
            bail!("product failure: a successful corruption-window GET returned bad bytes")
        }
        CorruptionReadVerdict::HarnessUnqualified => {
            bail!("harness unqualified: a required corrupt shard returned clean 2xx bytes")
        }
    }
    let recovery_context = runtime.renew(&mutation_context).await?;
    validate_renewed_context(&mutation_context, &recovery_context)?;
    let (heal, cleanup) = runtime
        .heal_and_cleanup(
            &recovery_context,
            &probe,
            &mutation,
            case.heal_mode().context("bitrot case lacks a heal mode")?,
        )
        .await?;
    let mutation_response =
        serde_json::from_str::<OfflineShardMutationResponse>(&mutation.response_body)
            .context("decode runtime mutation receipt")?;
    heal.validate(
        &selection,
        corrupted.completed_at_ms,
        cleanup.post_inspection_receipt.completed_at_ms,
    )?;
    cleanup.validate(
        &selection,
        &mutation_response,
        &heal,
        corrupted.completed_at_ms,
    )?;
    runtime
        .finish(&recovery_context, &cleanup.helper_cleanup)
        .await
}

pub(crate) async fn run_on_disk_bitrot_case(
    config: &FaultTestConfig,
    collector: &ArtifactCollector,
    scenario: &FaultScenario,
    execution_plan: &ExecutionPlan,
    storage_plan: &StorageRecoveryExecutionPlan,
    run_id: &str,
    deadline: RunDeadline,
) -> Result<()> {
    ensure!(
        execution_plan.storage_recovery() == Some(storage_plan)
            && execution_plan.scenario() == scenario.name
            && execution_plan.case_name() == scenario.case_name,
        "bitrot runner received a mismatched typed execution plan"
    );
    let mut runtime =
        LiveOnDiskBitrotRuntime::new(config, collector, scenario, storage_plan, run_id, deadline)
            .await?;
    let workflow_result = deadline
        .run(execute_on_disk_bitrot(&mut runtime, storage_plan.case))
        .await;
    let result = match workflow_result {
        Ok(()) => runtime.finalize_success_artifacts().await,
        Err(error) => Err(error),
    };
    match result {
        Ok(()) => Ok(()),
        Err(primary) => {
            let stage = runtime.failure_stage().to_string();
            let primary_error = format!("{primary:#}");
            let cleanup = runtime.emergency_cleanup().await;
            let failure = BitrotFailureEvidence {
                schema_version: BITROT_ARTIFACT_SCHEMA_VERSION,
                run_id: run_id.to_string(),
                case: storage_plan.case,
                stage: stage.clone(),
                primary_error: primary_error.clone(),
                context: runtime.current.clone().map(Box::new),
                observed_at_ms: now_ms().unwrap_or_default(),
                cleanup: cleanup.clone(),
            };
            let persist_result = runtime.persist_json(BITROT_FAILURE_ARTIFACT, &failure);
            runtime
                .events
                .record(
                    "run",
                    RunEventStatus::Failed,
                    "on-disk-bitrot failed and emergency cleanup completed",
                    Some(serde_json::json!({
                        "stage": stage,
                        "primaryError": primary_error,
                        "cleanupSucceeded": cleanup.succeeded(),
                        "cleanupErrors": cleanup.errors.clone(),
                    })),
                )
                .ok();
            if let Err(error) = persist_result {
                return Err(primary.context(format!("persist bitrot failure evidence: {error:#}")));
            }
            if cleanup.succeeded() {
                Err(primary)
            } else {
                Err(primary.context(format!(
                    "on-disk-bitrot emergency cleanup also failed: {}",
                    cleanup.errors.join("; ")
                )))
            }
        }
    }
}

fn validate_renewed_context(
    previous: &OwnedStorageContext,
    current: &OwnedStorageContext,
) -> Result<()> {
    previous.validate()?;
    current.validate()?;
    ensure!(
        previous.identity == current.identity
            && previous.case == current.case
            && previous.attempt_id == current.attempt_id
            && previous.cluster_context == current.cluster_context
            && previous.tenant_uid == current.tenant_uid
            && previous.scope_sha256 == current.scope_sha256
            && same_storage_volume_generation(&previous.volume, &current.volume)
            && previous.host_generation == current.host_generation
            && previous.exclusive_access.host_flock == current.exclusive_access.host_flock
            && previous.exclusive_access.kubernetes_lease.uid
                == current.exclusive_access.kubernetes_lease.uid
            && previous.exclusive_access.kubernetes_lease.holder_identity
                == current.exclusive_access.kubernetes_lease.holder_identity
            && previous.exclusive_access.kubernetes_lease.acquired_at_ms
                == current.exclusive_access.kubernetes_lease.acquired_at_ms
            && previous.exclusive_access.kubernetes_lease.resource_version
                != current.exclusive_access.kubernetes_lease.resource_version
            && previous.exclusive_access.kubernetes_lease.renew_at_ms
                < current.exclusive_access.kubernetes_lease.renew_at_ms
            && previous.observed_at_ms < current.observed_at_ms,
        "storage-recovery heartbeat did not preserve attempt ownership and advance Lease context"
    );
    Ok(())
}

fn capability_key(cluster_context: &str, tenant_uid: &str, drive_uuid: &str) -> String {
    format!("{cluster_context}\0{tenant_uid}\0{drive_uuid}")
}

fn canonical_sha256(value: &impl Serialize) -> Result<String> {
    Ok(sha256_bytes(&serde_json::to_vec(value)?))
}

fn validate_sha256(value: &str, label: &str) -> Result<()> {
    ensure!(
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "{label} is not SHA-256 hex"
    );
    Ok(())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn now_ms() -> Result<u64> {
    u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())
        .context("system timestamp exceeds u64 milliseconds")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fault::{
        plan::{FaultInjectionParameters, FaultPlanOptions},
        quorum::ErasureSetMember,
        scenarios::{ON_DISK_BITROT_SCENARIO, scenario_spec},
        storage_recovery::StorageVolumeIdentity,
        storage_recovery_helper::{OfflineInspectedShard, OfflineShardRecoveryResponse},
        storage_recovery_runtime::{
            HostFlockProof, HostGenerationIdentity, KubernetesLeaseProof,
            KubernetesResourceVersions, StorageRecoveryExclusiveAccess, storage_scope_sha256,
        },
        xl2_inspector::{Xl2ObjectVersionLayout, inspect_xl_meta, test_inline_fixture},
    };

    const ORIGINAL: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const MUTATED: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const VERSION: &str = "01234567-89ab-cdef-0123-456789abcdef";
    const DELETE_MARKER_VERSION: &str = "11234567-89ab-cdef-0123-456789abcdef";
    const PATH: &str = "bucket/object/data-dir/part.1";

    fn context() -> OwnedStorageContext {
        let volume = StorageVolumeIdentity {
            target_proof_sha256: ORIGINAL.to_string(),
            host_storage_proof_sha256: ORIGINAL.to_string(),
            rustfs_deployment_id: "deployment-1".to_string(),
            namespace: "rustfs-system".to_string(),
            tenant: "tenant-1".to_string(),
            pod: "rustfs-0".to_string(),
            pod_uid: "pod-uid-1".to_string(),
            rustfs_container_id: "containerd://container-1".to_string(),
            volume_name: "data".to_string(),
            persistent_volume_claim: "data-rustfs-0".to_string(),
            persistent_volume_claim_uid: "pvc-uid-1".to_string(),
            persistent_volume: "pv-1".to_string(),
            persistent_volume_uid: "pv-uid-1".to_string(),
            node: "node-1".to_string(),
            node_uid: "node-uid-1".to_string(),
            storage_class: "local".to_string(),
            local_volume_path: "/var/lib/rustfs/data".to_string(),
            mount_path: "/data/rustfs0".to_string(),
            canonical_device: "/dev/mapper/rustfs0".to_string(),
            target_mount_namespace_id: "mnt:[1]".to_string(),
            filesystem_uuid: "fs-1".to_string(),
            rustfs_drive_uuid: "drive-1".to_string(),
            pool_index: 0,
            set_index: 0,
            observed_at_ms: 100,
        };
        let mut context = OwnedStorageContext {
            identity: StorageRecoveryArtifactIdentity {
                run_id: "run-1".to_string(),
                scenario: ON_DISK_BITROT_SCENARIO.to_string(),
                case_name: "fault_on_disk_bitrot_is_rejected_and_healed".to_string(),
                bucket: "bucket".to_string(),
            },
            case: StorageRecoveryCase::OnDiskBitrotAutomaticScanner,
            attempt_id: "attempt-1".to_string(),
            cluster_context: "real-cluster".to_string(),
            tenant_uid: "tenant-uid-1".to_string(),
            scope_sha256: String::new(),
            volume,
            resource_versions: KubernetesResourceVersions {
                tenant: "1".to_string(),
                pod: "2".to_string(),
                persistent_volume_claim: "3".to_string(),
                persistent_volume: "4".to_string(),
                node: "5".to_string(),
                helper_pod: "6".to_string(),
            },
            host_generation: HostGenerationIdentity {
                mount_id: "mount-1".to_string(),
                mount_namespace_id: "mnt:[1]".to_string(),
                device_major_minor: "259:0".to_string(),
                device_mapper_uuid: Some("dm-uuid-1".to_string()),
                device_mapper_table_sha256: Some(ORIGINAL.to_string()),
                filesystem_uuid: "fs-1".to_string(),
                rustfs_drive_uuid: "drive-1".to_string(),
            },
            exclusive_access: StorageRecoveryExclusiveAccess {
                kubernetes_lease: KubernetesLeaseProof {
                    name: String::new(),
                    uid: "lease-uid-1".to_string(),
                    resource_version: "10".to_string(),
                    holder_identity: "run-1/attempt-1".to_string(),
                    scope_sha256: String::new(),
                    acquired_at_ms: 90,
                    renew_at_ms: 95,
                    expires_at_ms: 1_000,
                },
                host_flock: HostFlockProof {
                    node: "node-1".to_string(),
                    node_uid: "node-uid-1".to_string(),
                    path: String::new(),
                    device_id: "8:1".to_string(),
                    inode: 42,
                    scope_sha256: String::new(),
                    acquired_at_ms: 96,
                },
            },
            helper_pod_name: "storage-helper".to_string(),
            helper_pod_uid: "helper-uid-1".to_string(),
            observed_at_ms: 100,
        };
        let scope = storage_scope_sha256(&context);
        context.scope_sha256 = scope.clone();
        context.exclusive_access.kubernetes_lease.name =
            format!("s3chaos-storage-{}", &scope[..20]);
        context.exclusive_access.kubernetes_lease.scope_sha256 = scope.clone();
        context.exclusive_access.host_flock.path =
            format!("/var/lock/s3chaos/storage-{scope}.lock");
        context.exclusive_access.host_flock.scope_sha256 = scope;
        context
    }

    fn renewed(previous: &OwnedStorageContext, observed_at_ms: u64) -> OwnedStorageContext {
        let mut current = previous.clone();
        current.exclusive_access.kubernetes_lease.resource_version =
            (observed_at_ms / 10).to_string();
        current.exclusive_access.kubernetes_lease.renew_at_ms = observed_at_ms - 1;
        current.exclusive_access.kubernetes_lease.expires_at_ms = observed_at_ms + 500;
        current.observed_at_ms = observed_at_ms;
        current
    }

    fn capability(context: &OwnedStorageContext) -> BitrotCapabilityObservation {
        let body = r#"{"explicitVersionReads":true,"offlineXl2NonInline":true}"#.to_string();
        BitrotCapabilityObservation {
            cluster_context: context.cluster_context.clone(),
            tenant_uid: context.tenant_uid.clone(),
            drive_uuid: context.volume.rustfs_drive_uuid.clone(),
            explicit_version_reads: true,
            offline_xl2_non_inline: true,
            observed_at_ms: 101,
            expires_at_ms: 500,
            response_sha256: sha256_bytes(body.as_bytes()),
            response_body: body,
        }
    }

    fn probe(capability: &BitrotCapabilityObservation) -> ExplicitVersionProbe {
        ExplicitVersionProbe {
            operation_id: "put-1".to_string(),
            bucket: "bucket".to_string(),
            object_key: "object".to_string(),
            version_id: VERSION.to_string(),
            expected_sha256: ORIGINAL.to_string(),
            size_bytes: MIN_NON_INLINE_PROBE_BYTES,
            committed_at_ms: 102,
            capability_sha256: capability.response_sha256.clone(),
            version_set: BitrotVersionSetEvidence {
                bucket: "bucket".to_string(),
                object_key: "object".to_string(),
                data_version_id: VERSION.to_string(),
                delete_marker_version_id: DELETE_MARKER_VERSION.to_string(),
                entries: vec![
                    BitrotVersionEntry {
                        key: "object".to_string(),
                        version_id: VERSION.to_string(),
                        is_latest: false,
                        is_delete_marker: false,
                    },
                    BitrotVersionEntry {
                        key: "object".to_string(),
                        version_id: DELETE_MARKER_VERSION.to_string(),
                        is_latest: true,
                        is_delete_marker: true,
                    },
                ],
                observed_at_ms: 103,
            },
        }
    }

    fn exact_cohort() -> ExactCohortDefinition {
        ExactCohortDefinition {
            member_pod_uids: BTreeMap::from([
                ("rustfs-0".to_string(), "pod-uid-1".to_string()),
                ("rustfs-1".to_string(), "pod-uid-2".to_string()),
            ]),
            unavailable_pods: vec!["rustfs-1".to_string()],
            target_drive_uuid: "drive-1".to_string(),
            volume_path: "/data/rustfs0".to_string(),
        }
    }

    fn shape() -> ErasureSetShape {
        ErasureSetShape {
            pool_index: 0,
            set_index: 0,
            server_count: 2,
            volumes_per_server: 1,
            total_shards: 2,
            payload_data_shards: 1,
            payload_parity_shards: 1,
        }
    }

    fn membership(shape: &ErasureSetShape) -> ErasureSetMembership {
        ErasureSetMembership::from_runtime(
            shape,
            vec![
                ErasureSetMember {
                    pod_name: "rustfs-0".to_string(),
                    server_endpoint: "http://rustfs-0:9000".to_string(),
                    shard_ids: vec!["drive-1".to_string()],
                },
                ErasureSetMember {
                    pod_name: "rustfs-1".to_string(),
                    server_endpoint: "http://rustfs-1:9000".to_string(),
                    shard_ids: vec!["drive-2".to_string()],
                },
            ],
        )
        .expect("membership")
    }

    fn inspect_response(hash: &str, inode: u64) -> OfflineXl2InspectResponse {
        OfflineXl2InspectResponse {
            mount_device_id: "259:0".to_string(),
            drive_uuid: "drive-1".to_string(),
            format_json_sha256: ORIGINAL.to_string(),
            xl_meta_sha256: ORIGINAL.to_string(),
            layout: Xl2ObjectVersionLayout {
                inspector_revision: OFFLINE_XL2_INSPECTOR_REVISION.to_string(),
                profile: Xl2FormatProfile::LATEST_RUSTFS,
                version_id: VERSION.to_string(),
                data_directory: "data-dir".to_string(),
                erasure_data_shards: 1,
                erasure_parity_shards: 1,
                erasure_index: 1,
                part_numbers: vec![1],
                part_sizes: vec![1024],
                relative_part_paths: vec![PATH.to_string()],
            },
            selected_part: OfflineInspectedShard {
                part_number: 1,
                relative_part_path: PATH.to_string(),
                shard_device_id: "259:0".to_string(),
                shard_inode: inode,
                shard_size_bytes: 1024,
                original_sha256: hash.to_string(),
            },
        }
    }

    fn receipt(
        context: &OwnedStorageContext,
        id: &str,
        operation: StorageRecoveryHostOperation,
        response_body: String,
        started_at_ms: u64,
        completed_at_ms: u64,
    ) -> StorageRecoveryOperationReceipt {
        StorageRecoveryOperationReceipt {
            operation_id: id.to_string(),
            operation,
            context_sha256: context_sha256(context).expect("context digest"),
            response_sha256: sha256_bytes(response_body.as_bytes()),
            response_body,
            started_at_ms,
            journal_persisted_at_ms: completed_at_ms - 1,
            completed_at_ms,
            journal_fsync_succeeded: true,
        }
    }

    fn selection(context: &OwnedStorageContext) -> BitrotSelectionEvidence {
        let capability = capability(context);
        let probe = probe(&capability);
        let operation = StorageRecoveryHostOperation::InspectXlMeta {
            object_directory: "bucket/object".to_string(),
            bucket: "bucket".to_string(),
            object_key: "object".to_string(),
            object_sha256: ORIGINAL.to_string(),
            version_id: VERSION.to_string(),
            selected_part_number: 1,
            expected_mount_device_id: "259:0".to_string(),
            expected_drive_uuid: "drive-1".to_string(),
        };
        let response_body =
            serde_json::to_string(&inspect_response(ORIGINAL, 42)).expect("inspect");
        let inspection = receipt(
            context,
            "11111111-1111-1111-1111-111111111111",
            operation,
            response_body.clone(),
            111,
            112,
        );
        let shape = shape();
        let membership = membership(&shape);
        let mapping = VersionShardMappingObservation {
            schema_version: 1,
            identity: context.identity.clone(),
            observation_id: "mapping-1".to_string(),
            source: ShardMappingSource::OfflineXl2Inspector,
            api_revision: OFFLINE_XL2_INSPECTOR_REVISION.to_string(),
            response_sha256: inspection.response_sha256.clone(),
            response_body,
            offline_evidence: Some(Box::new(OfflineVersionShardMappingEvidence {
                context: Box::new(context.clone()),
                inspection_receipt: Box::new(inspection.clone()),
            })),
            target_proof_sha256: ORIGINAL.to_string(),
            observed_at_ms: inspection.completed_at_ms,
        };
        BitrotSelectionEvidence {
            schema_version: BITROT_ARTIFACT_SCHEMA_VERSION,
            identity: context.identity.clone(),
            case: context.case,
            context: Box::new(context.clone()),
            capability,
            probe,
            shape,
            membership,
            exact_cohort: exact_cohort(),
            mapping,
            inspection_receipt: Box::new(inspection),
        }
    }

    fn exact_read(
        context: &OwnedStorageContext,
        probe: &ExplicitVersionProbe,
        operation_id: &str,
        started_at_ms: u64,
        outcome: BitrotReadOutcome,
    ) -> ExactCohortReadReceipt {
        let expected = outcome == BitrotReadOutcome::ExpectedBytes;
        let shape = shape();
        let membership = membership(&shape);
        ExactCohortReadReceipt {
            operation_id: operation_id.to_string(),
            context_sha256: context_sha256(context).expect("context digest"),
            cohort_sha256: exact_cohort()
                .sha256(&shape, &membership)
                .expect("cohort digest"),
            bucket: probe.bucket.clone(),
            object_key: probe.object_key.clone(),
            version_id: probe.version_id.clone(),
            expected_sha256: probe.expected_sha256.clone(),
            observed_sha256: expected.then(|| probe.expected_sha256.clone()),
            http_status: Some(if expected { 200 } else { 500 }),
            error: (!expected).then(|| "checksum mismatch".to_string()),
            outcome,
            target_shard_required: true,
            started_at_ms,
            completed_at_ms: started_at_ms + 1,
        }
    }

    fn evidence_set() -> (
        BitrotSelectionEvidence,
        BitrotMutationEvidence,
        BitrotCorruptionWindowProof,
        BitrotHealEvidence,
        BitrotCleanupEvidence,
        OnDiskBitrotWorkflowEvidence,
    ) {
        let selected_context = renewed(&context(), 110);
        let selection = selection(&selected_context);
        let mutation_body = serde_json::to_string(&OfflineShardMutationResponse {
            journal_operation_id: "22222222-2222-2222-2222-222222222222".to_string(),
            relative_part_path: PATH.to_string(),
            shard_device_id: "259:0".to_string(),
            shard_inode: 42,
            shard_size_bytes: 1024,
            byte_offset: 7,
            original_byte: 1,
            mutated_byte: 254,
            original_sha256: ORIGINAL.to_string(),
            mutated_sha256: MUTATED.to_string(),
        })
        .expect("mutation response");
        let mutation_receipt = receipt(
            &selected_context,
            "22222222-2222-2222-2222-222222222222",
            StorageRecoveryHostOperation::MutateShard {
                inspection_operation_id: selection.inspection_receipt.operation_id.clone(),
                part_number: 1,
                byte_offset: 7,
            },
            mutation_body,
            120,
            122,
        );
        let mutation = BitrotMutationEvidence {
            schema_version: BITROT_ARTIFACT_SCHEMA_VERSION,
            selection_operation_id: selection.inspection_receipt.operation_id.clone(),
            mutated_at_ms: mutation_receipt.completed_at_ms,
            mutation_receipt: Box::new(mutation_receipt.clone()),
        };
        let corruption = BitrotCorruptionWindowProof {
            schema_version: BITROT_ARTIFACT_SCHEMA_VERSION,
            baseline: exact_read(
                &selected_context,
                &selection.probe,
                "55555555-5555-5555-5555-555555555555",
                115,
                BitrotReadOutcome::ExpectedBytes,
            ),
            corrupted: exact_read(
                &selected_context,
                &selection.probe,
                "66666666-6666-6666-6666-666666666666",
                130,
                BitrotReadOutcome::CleanRejected,
            ),
            opened_at_ms: 122,
            closed_at_ms: 131,
        };
        let scanner_body = serde_json::to_string(&ScannerStatusBody {
            enabled: true,
            metrics: ScannerMetricsBody {
                last_cycle_end_unix_secs: 1,
                last_cycle_duration_seconds: 0.8,
                last_cycle_result: "completed".to_string(),
                last_cycle_heal_objects: 1,
                versions_scanned: 1,
            },
        })
        .expect("scanner status");
        let scanner_status = RawBitrotEvidenceReceipt {
            api_revision: "v3/background-heal/status".to_string(),
            response_sha256: sha256_bytes(scanner_body.as_bytes()),
            response_body: scanner_body,
            started_at_ms: 900,
            completed_at_ms: 1_000,
        };
        let heal = BitrotHealEvidence::AutomaticScanner {
            status: scanner_status.clone(),
            progress: vec![BitrotHealProgressSample {
                schema_version: BITROT_ARTIFACT_SCHEMA_VERSION,
                source: BitrotHealProgressSource::AutomaticScanner,
                ordinal: 0,
                client_token_sha256: None,
                state: HealProgressState::Completed,
                failure_detail: None,
                receipt: scanner_status,
            }],
            no_admin_operation: true,
            no_host_restore_before_post_inspect: true,
        };
        let recovery_context = renewed(&selected_context, 1_100);
        let post_body =
            serde_json::to_string(&inspect_response(ORIGINAL, 42)).expect("post inspect");
        let post_inspection = receipt(
            &recovery_context,
            "33333333-3333-3333-3333-333333333333",
            StorageRecoveryHostOperation::InspectXlMeta {
                object_directory: "bucket/object".to_string(),
                bucket: "bucket".to_string(),
                object_key: "object".to_string(),
                object_sha256: ORIGINAL.to_string(),
                version_id: VERSION.to_string(),
                selected_part_number: 1,
                expected_mount_device_id: "259:0".to_string(),
                expected_drive_uuid: "drive-1".to_string(),
            },
            post_body.clone(),
            1_200,
            1_202,
        );
        let fresh_mapping = VersionShardMappingObservation {
            schema_version: 1,
            identity: recovery_context.identity.clone(),
            observation_id: "mapping-2".to_string(),
            source: ShardMappingSource::OfflineXl2Inspector,
            api_revision: OFFLINE_XL2_INSPECTOR_REVISION.to_string(),
            response_sha256: post_inspection.response_sha256.clone(),
            response_body: post_body,
            offline_evidence: Some(Box::new(OfflineVersionShardMappingEvidence {
                context: Box::new(recovery_context.clone()),
                inspection_receipt: Box::new(post_inspection.clone()),
            })),
            target_proof_sha256: ORIGINAL.to_string(),
            observed_at_ms: 1_202,
        };
        let recovery_body = serde_json::to_string(&OfflineShardRecoveryResponse {
            mutation_operation_id: mutation_receipt.operation_id.clone(),
            outcome: crate::fault::storage_recovery_runtime::RestoreOutcome::AlreadyRepaired,
            observed_sha256: Some(ORIGINAL.to_string()),
        })
        .expect("recovery response");
        let restore_receipt = receipt(
            &recovery_context,
            "44444444-4444-4444-4444-444444444444",
            StorageRecoveryHostOperation::RestoreShard {
                mutation_operation_id: mutation_receipt.operation_id,
            },
            recovery_body,
            1_203,
            1_205,
        );
        let cleanup = BitrotCleanupEvidence {
            schema_version: BITROT_ARTIFACT_SCHEMA_VERSION,
            context: Box::new(recovery_context.clone()),
            post_inspection_receipt: Box::new(post_inspection),
            fresh_mapping,
            post_heal_exact_quorum: exact_read(
                &recovery_context,
                &selection.probe,
                "77777777-7777-7777-7777-777777777777",
                1_210,
                BitrotReadOutcome::ExpectedBytes,
            ),
            final_version_set: BitrotVersionSetEvidence {
                observed_at_ms: 1_212,
                ..selection.probe.version_set.clone()
            },
            helper_cleanup: StorageRecoveryCleanupProof::BitrotAlreadyRepaired {
                restore_receipt: Box::new(restore_receipt),
            },
            completed_at_ms: 1_213,
        };
        let workflow = OnDiskBitrotWorkflowEvidence {
            schema_version: BITROT_ARTIFACT_SCHEMA_VERSION,
            identity: selection.identity.clone(),
            selection_sha256: canonical_sha256(&selection).expect("selection digest"),
            mutation_sha256: canonical_sha256(&mutation).expect("mutation digest"),
            corruption_window_sha256: canonical_sha256(&corruption).expect("corruption digest"),
            heal_sha256: canonical_sha256(&heal).expect("heal digest"),
            cleanup_sha256: canonical_sha256(&cleanup).expect("cleanup digest"),
            checker_report_sha256: sha256_bytes(b"{}"),
            post_write_report_sha256: sha256_bytes(b"{}"),
            diagnostic_logs: None,
        };
        (selection, mutation, corruption, heal, cleanup, workflow)
    }

    #[test]
    fn capability_cache_is_exact_and_fail_closed() {
        let context = context();
        let observation = capability(&context);
        let mut cache = BitrotCapabilityCache::default();
        assert!(cache.require(&context, 101).is_err());
        cache.insert(observation).expect("qualified capability");
        cache.require(&context, 101).expect("cached capability");
        assert!(cache.require(&context, 500).is_err());
        let mut other = context;
        other.volume.rustfs_drive_uuid = "drive-2".to_string();
        assert!(cache.require(&other, 101).is_err());
    }

    #[test]
    fn corruption_window_classifies_bad_and_clean_2xx_distinctly() {
        let context = context();
        let capability = capability(&context);
        let probe = probe(&capability);
        let mut read = exact_read(
            &context,
            &probe,
            "88888888-8888-8888-8888-888888888888",
            120,
            BitrotReadOutcome::ExpectedBytes,
        );
        assert_eq!(
            read.classify_corruption_window(&context, &probe)
                .expect("classification"),
            CorruptionReadVerdict::HarnessUnqualified
        );
        read.outcome = BitrotReadOutcome::UnexpectedBytes;
        read.observed_sha256 = Some(MUTATED.to_string());
        assert_eq!(
            read.classify_corruption_window(&context, &probe)
                .expect("classification"),
            CorruptionReadVerdict::ProductFailure
        );
    }

    #[test]
    fn inspection_uses_the_bucket_key_below_the_exact_volume_root() {
        let selected_context = renewed(&context(), 110);
        let selection = selection(&selected_context);
        let StorageRecoveryHostOperation::InspectXlMeta {
            object_directory,
            bucket,
            object_key,
            ..
        } = &selection.inspection_receipt.operation
        else {
            panic!("selection must contain an XL2 inspection")
        };
        assert_eq!(object_directory, "bucket/object");
        assert_eq!(
            object_directory,
            &volume_relative_object_directory(bucket, object_key)
        );
        selection.validate().expect("standard volume-relative path");
    }

    #[test]
    fn selection_rejects_the_legacy_double_prefixed_object_root() {
        let selected_context = renewed(&context(), 110);
        let mut selection = selection(&selected_context);
        let StorageRecoveryHostOperation::InspectXlMeta {
            object_directory, ..
        } = &mut selection.inspection_receipt.operation
        else {
            panic!("selection must contain an XL2 inspection")
        };
        *object_directory = "legacy-root/bucket/object".to_string();

        let error = selection
            .validate()
            .expect_err("legacy double-prefixed object root must be rejected");
        assert!(
            error.to_string().contains("bitrot inspection is not bound"),
            "{error:#}"
        );
    }

    #[test]
    fn selection_rejects_a_mapping_from_an_untrusted_source() {
        let selected_context = renewed(&context(), 110);
        let mut selection = selection(&selected_context);
        selection.mapping.source = ShardMappingSource::RustfsDiagnosticApi;
        selection.mapping.api_revision = "v3/diagnostics/shards".to_string();
        selection.mapping.offline_evidence = None;
        assert!(selection.validate().is_err());
    }

    #[test]
    fn inline_version_cannot_supply_a_mutable_shard_path() {
        let error = inspect_xl_meta(&test_inline_fixture(VERSION), VERSION)
            .expect_err("inline version must not produce a physical shard mapping");
        assert!(error.to_string().contains("inline"));
    }

    #[test]
    fn mutation_requires_a_changed_readback_digest() {
        let (selection, mut mutation, ..) = evidence_set();
        let mut response = serde_json::from_str::<OfflineShardMutationResponse>(
            &mutation.mutation_receipt.response_body,
        )
        .expect("mutation response");
        response.mutated_sha256 = response.original_sha256.clone();
        mutation.mutation_receipt.response_body =
            serde_json::to_string(&response).expect("unchanged mutation response");
        mutation.mutation_receipt.response_sha256 =
            sha256_bytes(mutation.mutation_receipt.response_body.as_bytes());
        assert!(mutation.validate(&selection).is_err());
    }

    #[test]
    fn mutation_state_survives_artifact_persistence_failure() {
        let (_, mutation, ..) = evidence_set();
        let mut retained = None;
        let mut pending = Some((
            mutation.mutation_receipt.operation_id.clone(),
            mutation.mutation_receipt.operation.clone(),
        ));
        let error =
            retain_mutation_before_persist(&mut retained, &mut pending, mutation.clone(), |_| {
                bail!("artifact write failed")
            })
            .expect_err("artifact failure must remain visible");
        assert!(error.to_string().contains("artifact write failed"));
        assert_eq!(retained, Some(mutation));
        assert!(pending.is_some());
    }

    #[test]
    fn heal_evidence_rejects_a_non_converged_terminal_sample() {
        let (selection, _, corruption, mut heal, cleanup, _) = evidence_set();
        let BitrotHealEvidence::AutomaticScanner {
            status, progress, ..
        } = &mut heal
        else {
            panic!("automatic scanner fixture")
        };
        let mut body = serde_json::from_str::<ScannerStatusBody>(&status.response_body)
            .expect("scanner status");
        body.metrics.last_cycle_result = "running".to_string();
        let response_body = serde_json::to_string(&body).expect("running scanner status");
        status.response_body = response_body.clone();
        status.response_sha256 = sha256_bytes(response_body.as_bytes());
        progress[0].state = HealProgressState::Running;
        progress[0].receipt = status.clone();
        assert!(
            heal.validate(
                &selection,
                corruption.closed_at_ms,
                cleanup.post_inspection_receipt.completed_at_ms,
            )
            .is_err()
        );
    }

    #[test]
    fn force_read_must_require_the_repaired_target_shard() {
        let (selection, mutation, corruption, heal, mut cleanup, _) = evidence_set();
        cleanup.post_heal_exact_quorum.target_shard_required = false;
        let mutation = mutation.validate(&selection).expect("mutation evidence");
        assert!(
            cleanup
                .validate(&selection, &mutation, &heal, corruption.closed_at_ms)
                .is_err()
        );
    }

    #[test]
    fn artifact_read_receipts_must_bind_exact_history_get_ids() {
        let (selection, _, corruption, _, cleanup, _) = evidence_set();
        let receipts = [
            &corruption.baseline,
            &corruption.corrupted,
            &cleanup.post_heal_exact_quorum,
        ];
        let history = receipts
            .iter()
            .enumerate()
            .map(|(index, receipt)| OperationRecord {
                id: receipt.operation_id.clone(),
                scenario: "on-disk-bitrot".to_string(),
                run_id: Some("run-1".to_string()),
                kind: OperationKind::Get,
                bucket: receipt.bucket.clone(),
                key: Some(receipt.object_key.clone()),
                value_sha256: receipt.observed_sha256.clone(),
                size_bytes: receipt
                    .observed_sha256
                    .as_ref()
                    .map(|_| usize::try_from(selection.probe.size_bytes).expect("probe size")),
                version_id: Some(receipt.version_id.clone()),
                listed_keys: None,
                listed_versions: None,
                payload_ref: None,
                range: None,
                started_sequence: Some(u64::try_from(index * 2).expect("start sequence")),
                ended_sequence: Some(u64::try_from(index * 2 + 1).expect("end sequence")),
                started_at_ms: receipt.started_at_ms,
                ended_at_ms: receipt.completed_at_ms,
                outcome: if receipt.outcome == BitrotReadOutcome::CleanRejected {
                    OperationOutcome::Failed
                } else {
                    OperationOutcome::Ok
                },
                http_status: receipt.http_status,
                error: receipt.error.clone(),
                durability_cohort: Some(DurabilityCohort::FaultActive),
                fault_window_relation: None,
            })
            .collect::<Vec<_>>();
        for receipt in receipts {
            receipt
                .validate_against_history(&selection.probe, &history)
                .expect("receipt-bound history GET");
        }

        let mut tampered = corruption.baseline.clone();
        tampered.operation_id = "88888888-8888-8888-8888-888888888888".to_string();
        assert!(
            tampered
                .validate_against_history(&selection.probe, &history)
                .is_err()
        );
    }

    #[test]
    fn final_version_set_must_preserve_the_delete_marker() {
        let (selection, mutation, corruption, heal, mut cleanup, _) = evidence_set();
        cleanup
            .final_version_set
            .entries
            .retain(|entry| !entry.is_delete_marker);
        let mutation = mutation.validate(&selection).expect("mutation evidence");
        assert!(
            cleanup
                .validate(&selection, &mutation, &heal, corruption.closed_at_ms)
                .is_err()
        );
    }

    #[test]
    fn failed_heal_progress_requires_a_reason() {
        let response_body = r#"{"summary":"failed","detail":"drive remained corrupt","settings":{"scanMode":2},"items":[]}"#.to_string();
        let receipt = RawBitrotEvidenceReceipt {
            api_revision: "v3/heal/status".to_string(),
            response_sha256: sha256_bytes(response_body.as_bytes()),
            response_body,
            started_at_ms: 1,
            completed_at_ms: 2,
        };
        let mut progress = vec![BitrotHealProgressSample {
            schema_version: BITROT_ARTIFACT_SCHEMA_VERSION,
            source: BitrotHealProgressSource::AdminDeep,
            ordinal: 0,
            client_token_sha256: Some(sha256_bytes(b"token")),
            state: HealProgressState::Failed,
            failure_detail: None,
            receipt,
        }];
        assert!(
            validate_heal_progress(
                &progress,
                BitrotHealProgressSource::AdminDeep,
                Some("token"),
            )
            .is_err()
        );
        progress[0].failure_detail = Some("drive remained corrupt".to_string());
        validate_heal_progress(
            &progress,
            BitrotHealProgressSource::AdminDeep,
            Some("token"),
        )
        .expect("failure reason is retained");
    }

    #[test]
    fn incomplete_emergency_cleanup_is_reported_as_failed() {
        let evidence = BitrotEmergencyCleanupEvidence {
            attempted: true,
            chaos_removed: true,
            admin_heal_closed: true,
            helper_closed: false,
            mutation_lookup: None,
            cleanup_proof: None,
            errors: vec!["restore selected shard: device identity changed".to_string()],
            completed_at_ms: 10,
        };
        assert!(!evidence.succeeded());
        let body = serde_json::to_string(&evidence).expect("cleanup evidence");
        assert!(body.contains("device identity changed"));
    }

    #[test]
    fn failed_admin_terminal_status_forms_valid_failed_run_evidence() {
        let mut failed_context = context();
        failed_context.case = StorageRecoveryCase::OnDiskBitrotAdminDeep;
        let scope = storage_scope_sha256(&failed_context);
        failed_context.scope_sha256 = scope.clone();
        failed_context
            .exclusive_access
            .kubernetes_lease
            .scope_sha256 = scope.clone();
        failed_context.exclusive_access.kubernetes_lease.name =
            format!("s3chaos-storage-{}", &scope[..20]);
        failed_context.exclusive_access.host_flock.scope_sha256 = scope.clone();
        failed_context.exclusive_access.host_flock.path =
            format!("/var/lock/s3chaos/storage-{scope}.lock");
        let response_body = r#"{"summary":"failed","detail":"target shard remained corrupt","startTime":"1970-01-01T00:00:00Z","settings":{"scanMode":2},"items":[]}"#.to_string();
        let progress = vec![BitrotHealProgressSample {
            schema_version: BITROT_ARTIFACT_SCHEMA_VERSION,
            source: BitrotHealProgressSource::AdminDeep,
            ordinal: 0,
            client_token_sha256: Some(sha256_bytes(b"token-1")),
            state: HealProgressState::Failed,
            failure_detail: Some("target shard remained corrupt".to_string()),
            receipt: RawBitrotEvidenceReceipt {
                api_revision: "v3/heal/status".to_string(),
                response_sha256: sha256_bytes(response_body.as_bytes()),
                response_body,
                started_at_ms: 120,
                completed_at_ms: 121,
            },
        }];
        validate_heal_progress(
            &progress,
            BitrotHealProgressSource::AdminDeep,
            Some("token-1"),
        )
        .expect("failed AdminDeep status preserves its reason");

        let failure = BitrotFailureEvidence {
            schema_version: BITROT_ARTIFACT_SCHEMA_VERSION,
            run_id: "run-1".to_string(),
            case: StorageRecoveryCase::OnDiskBitrotAdminDeep,
            stage: "heal".to_string(),
            primary_error: "owned admin heal failed: target shard remained corrupt".to_string(),
            context: Some(Box::new(failed_context.clone())),
            cleanup: BitrotEmergencyCleanupEvidence {
                attempted: true,
                chaos_removed: true,
                admin_heal_closed: true,
                helper_closed: true,
                mutation_lookup: None,
                cleanup_proof: Some(StorageRecoveryCleanupProof::AbortedBeforeMutation {
                    observed_at_ms: 130,
                }),
                errors: Vec::new(),
                completed_at_ms: 131,
            },
            observed_at_ms: 132,
        };
        failure
            .validate("run-1", "fault_on_disk_bitrot_is_rejected_and_healed")
            .expect("terminal AdminDeep failure evidence");
        failure
            .validate_progress_failure(&progress)
            .expect("terminal AdminDeep reason is preserved by the primary error");
    }

    #[test]
    fn accepted_admin_start_is_owned_before_artifact_or_event_writes() {
        let path = "/rustfs/admin/v3/heal/s3chaos-bitrot-run-1";
        let start_body = r#"{"clientToken":"server-token-1","clientAddress":"127.0.0.1","startTime":"1970-01-01T00:00:01Z"}"#;
        let status_body = r#"{"summary":"running","startTime":"1970-01-01T00:00:01.4Z","settings":{"recursive":true,"scanMode":2},"items":[]}"#;
        let start = RawBitrotEvidenceReceipt {
            api_revision: "v3/heal/start".to_string(),
            response_sha256: sha256_bytes(start_body.as_bytes()),
            response_body: start_body.to_string(),
            started_at_ms: 1_000,
            completed_at_ms: 1_100,
        };
        let status = RawBitrotEvidenceReceipt {
            api_revision: "v3/heal/status".to_string(),
            response_sha256: sha256_bytes(status_body.as_bytes()),
            response_body: status_body.to_string(),
            started_at_ms: 1_100,
            completed_at_ms: 1_200,
        };
        let mut state = BitrotAdminHealStartState::ambiguous("s3chaos-bitrot-run-1", path, 1_000);
        assert_eq!(
            state
                .own_from_start(&start, true)
                .expect("accepted response owns the heal")
                .client_token,
            "server-token-1",
        );
        state
            .validate_owned_status(&status)
            .expect("exact status belongs to the owned heal");
        assert_eq!(
            state
                .owned_token("s3chaos-bitrot-run-1", path)
                .expect("owned exact token"),
            Some("server-token-1")
        );
        assert!(state.owned_token("s3chaos-bitrot-run-2", path).is_err());

        let mut ambiguous =
            BitrotAdminHealStartState::ambiguous("s3chaos-bitrot-run-1", path, 1_000);
        ambiguous
            .own_from_start(&start, true)
            .expect("accepted response owns the heal before persistence");
        let artifact_write: Result<()> = Err(anyhow::anyhow!("artifact write failed"));
        assert!(artifact_write.is_err());
        assert_eq!(
            ambiguous
                .owned_token("s3chaos-bitrot-run-1", path)
                .expect("cleanup retains the owned token"),
            Some("server-token-1")
        );
        let mut wrong_status = status.clone();
        wrong_status.response_body = status_body.replace("00:00:01.4Z", "00:00:20Z");
        wrong_status.response_sha256 = sha256_bytes(wrong_status.response_body.as_bytes());
        assert!(ambiguous.validate_owned_status(&wrong_status).is_err());

        let mut normal_status = status.clone();
        normal_status.response_body = status_body.replace("\"scanMode\":2", "\"scanMode\":1");
        normal_status.response_sha256 = sha256_bytes(normal_status.response_body.as_bytes());
        assert!(ambiguous.validate_owned_status(&normal_status).is_err());
    }

    #[test]
    fn admin_heal_drive_transition_requires_explicit_states_and_endpoint() {
        let mut item = AdminHealResultItem {
            bucket: "bucket".to_string(),
            object_key: "object".to_string(),
            version_id: VERSION.to_string(),
            before: AdminHealDriveSetBody {
                drives: vec![AdminHealDriveBody {
                    uuid: "drive-1".to_string(),
                    endpoint: "http://rustfs-0:9000/data".to_string(),
                    state: "corrupt".to_string(),
                }],
            },
            after: AdminHealDriveSetBody {
                drives: vec![AdminHealDriveBody {
                    uuid: "drive-1".to_string(),
                    endpoint: "http://rustfs-0:9000/data".to_string(),
                    state: "ok".to_string(),
                }],
            },
        };
        assert!(admin_item_repairs_exact_drive(&item, "drive-1"));

        item.before.drives[0].state.clear();
        assert!(!admin_item_repairs_exact_drive(&item, "drive-1"));
        item.before.drives[0].state = "corrupt".to_string();
        item.before.drives[0].endpoint.clear();
        item.after.drives[0].endpoint.clear();
        assert!(!admin_item_repairs_exact_drive(&item, "drive-1"));
    }

    #[test]
    fn admin_deep_evidence_binds_progress_and_the_exact_healed_drive() {
        let mut admin_context = context();
        admin_context.case = StorageRecoveryCase::OnDiskBitrotAdminDeep;
        let scope = storage_scope_sha256(&admin_context);
        admin_context.scope_sha256 = scope.clone();
        admin_context.exclusive_access.kubernetes_lease.scope_sha256 = scope.clone();
        admin_context.exclusive_access.kubernetes_lease.name =
            format!("s3chaos-storage-{}", &scope[..20]);
        admin_context.exclusive_access.host_flock.scope_sha256 = scope.clone();
        admin_context.exclusive_access.host_flock.path =
            format!("/var/lock/s3chaos/storage-{scope}.lock");
        let selection = selection(&renewed(&admin_context, 110));

        let start_body = r#"{"clientToken":"token-1","clientAddress":"127.0.0.1","startTime":"1970-01-01T00:00:00Z"}"#;
        let start = RawBitrotEvidenceReceipt {
            api_revision: "v3/heal/start".to_string(),
            response_sha256: sha256_bytes(start_body.as_bytes()),
            response_body: start_body.to_string(),
            started_at_ms: 140,
            completed_at_ms: 150,
        };
        let status_body = serde_json::to_string(&AdminHealStatusBody {
            summary: "finished".to_string(),
            failure_detail: String::new(),
            start_time: "1970-01-01T00:00:00Z".to_string(),
            settings: AdminHealSettingsBody {
                scan_mode: AdminHealScanMode::Deep,
            },
            items: vec![AdminHealResultItem {
                bucket: selection.probe.bucket.clone(),
                object_key: selection.probe.object_key.clone(),
                version_id: selection.probe.version_id.clone(),
                before: AdminHealDriveSetBody {
                    drives: vec![AdminHealDriveBody {
                        uuid: selection.context.volume.rustfs_drive_uuid.clone(),
                        endpoint: "http://rustfs-0:9000/data".to_string(),
                        state: "corrupt".to_string(),
                    }],
                },
                after: AdminHealDriveSetBody {
                    drives: vec![AdminHealDriveBody {
                        uuid: selection.context.volume.rustfs_drive_uuid.clone(),
                        endpoint: "http://rustfs-0:9000/data".to_string(),
                        state: "ok".to_string(),
                    }],
                },
            }],
        })
        .expect("admin heal status");
        let terminal_status = RawBitrotEvidenceReceipt {
            api_revision: "v3/heal/status".to_string(),
            response_sha256: sha256_bytes(status_body.as_bytes()),
            response_body: status_body,
            started_at_ms: 160,
            completed_at_ms: 170,
        };
        let heal = BitrotHealEvidence::AdminDeep {
            start,
            progress: vec![BitrotHealProgressSample {
                schema_version: BITROT_ARTIFACT_SCHEMA_VERSION,
                source: BitrotHealProgressSource::AdminDeep,
                ordinal: 0,
                client_token_sha256: Some(sha256_bytes(b"token-1")),
                state: HealProgressState::Completed,
                failure_detail: None,
                receipt: terminal_status.clone(),
            }],
            terminal_status,
            cancel: None,
        };
        heal.validate(&selection, 131, 180)
            .expect("exact AdminDeep heal evidence");
    }

    #[test]
    fn aggregate_rejects_unrepaired_shard_then_accepts_repair() {
        let (selection, mutation, corruption, heal, mut cleanup, mut workflow) = evidence_set();
        let mut post = serde_json::from_str::<OfflineXl2InspectResponse>(
            &cleanup.post_inspection_receipt.response_body,
        )
        .expect("post inspection");
        post.selected_part.original_sha256 = MUTATED.to_string();
        cleanup.post_inspection_receipt.response_body =
            serde_json::to_string(&post).expect("unrepaired response");
        cleanup.post_inspection_receipt.response_sha256 =
            sha256_bytes(cleanup.post_inspection_receipt.response_body.as_bytes());
        cleanup.fresh_mapping.response_body = cleanup.post_inspection_receipt.response_body.clone();
        cleanup.fresh_mapping.response_sha256 =
            cleanup.post_inspection_receipt.response_sha256.clone();
        cleanup.fresh_mapping.offline_evidence =
            Some(Box::new(OfflineVersionShardMappingEvidence {
                context: cleanup.context.clone(),
                inspection_receipt: cleanup.post_inspection_receipt.clone(),
            }));
        workflow.cleanup_sha256 = canonical_sha256(&cleanup).expect("cleanup digest");
        assert!(
            validate_on_disk_bitrot_evidence(&OnDiskBitrotEvidenceSet {
                workflow: &workflow,
                selection: &selection,
                mutation: &mutation,
                corruption_window: &corruption,
                heal: &heal,
                cleanup: &cleanup,
                checker_report_body: "{}",
                post_write_report_body: "{}",
            })
            .is_err(),
            "an exact-quorum success cannot hide an unrepaired physical shard"
        );

        let repaired = evidence_set();
        validate_on_disk_bitrot_evidence(&OnDiskBitrotEvidenceSet {
            workflow: &repaired.5,
            selection: &repaired.0,
            mutation: &repaired.1,
            corruption_window: &repaired.2,
            heal: &repaired.3,
            cleanup: &repaired.4,
            checker_report_body: "{}",
            post_write_report_body: "{}",
        })
        .expect("repaired bitrot evidence");
    }

    #[test]
    fn storage_plan_exposes_both_closed_bitrot_cases() {
        let catalog = scenario_spec(ON_DISK_BITROT_SCENARIO).expect("catalog");
        let scenario = FaultScenario {
            name: ON_DISK_BITROT_SCENARIO.to_string(),
            case_name: catalog.case_name,
            duration: std::time::Duration::from_secs(300),
            percent: 1,
            object_count: 8,
        };
        for case in [
            StorageRecoveryCase::OnDiskBitrotAutomaticScanner,
            StorageRecoveryCase::OnDiskBitrotAdminDeep,
        ] {
            let plan = ExecutionPlan::from_scenario_with_options(
                &scenario,
                catalog,
                FaultPlanOptions {
                    rustfs_volume_path: "/data/rustfs0".to_string(),
                    scenario_parameters: FaultInjectionParameters::Default,
                    storage_recovery_case: Some(case),
                },
            )
            .expect("storage plan");
            assert_eq!(plan.storage_recovery().map(|plan| plan.case), Some(case));
        }
    }

    struct FakeBitrotRuntime {
        acquired: OwnedStorageContext,
        selection: BitrotSelectionEvidence,
        mutation: StorageRecoveryOperationReceipt,
        reads: std::collections::VecDeque<ExactCohortReadReceipt>,
        heal: BitrotHealEvidence,
        cleanup: BitrotCleanupEvidence,
        renewals: usize,
        finished: bool,
        finish_error: Option<String>,
    }

    impl FakeBitrotRuntime {
        fn successful() -> Self {
            let (selection, mutation, corruption, heal, cleanup, _) = evidence_set();
            Self {
                acquired: context(),
                mutation: mutation.mutation_receipt.as_ref().clone(),
                reads: [corruption.baseline, corruption.corrupted].into(),
                selection,
                heal,
                cleanup,
                renewals: 0,
                finished: false,
                finish_error: None,
            }
        }
    }

    #[async_trait]
    impl OnDiskBitrotRuntimePort for FakeBitrotRuntime {
        async fn acquire(&mut self, _case: StorageRecoveryCase) -> Result<OwnedStorageContext> {
            Ok(self.acquired.clone())
        }

        async fn renew(&mut self, _context: &OwnedStorageContext) -> Result<OwnedStorageContext> {
            self.renewals += 1;
            Ok(if self.renewals == 1 {
                self.selection.context.as_ref().clone()
            } else {
                self.cleanup.context.as_ref().clone()
            })
        }

        async fn qualify_capability(
            &mut self,
            _context: &OwnedStorageContext,
        ) -> Result<BitrotCapabilityObservation> {
            Ok(capability(&self.acquired))
        }

        async fn write_explicit_version_probe(
            &mut self,
            _context: &OwnedStorageContext,
        ) -> Result<ExplicitVersionProbe> {
            Ok(self.selection.probe.clone())
        }

        async fn inspect(
            &mut self,
            _context: &OwnedStorageContext,
            _probe: &ExplicitVersionProbe,
        ) -> Result<BitrotSelectionEvidence> {
            Ok(self.selection.clone())
        }

        async fn exact_quorum_read(
            &mut self,
            _context: &OwnedStorageContext,
            _probe: &ExplicitVersionProbe,
        ) -> Result<ExactCohortReadReceipt> {
            self.reads.pop_front().context("fake read exhausted")
        }

        async fn mutate(
            &mut self,
            _context: &OwnedStorageContext,
            _inspection_operation_id: &str,
            _part_number: u32,
        ) -> Result<StorageRecoveryOperationReceipt> {
            Ok(self.mutation.clone())
        }

        async fn heal_and_cleanup(
            &mut self,
            _context: &OwnedStorageContext,
            _probe: &ExplicitVersionProbe,
            _mutation: &StorageRecoveryOperationReceipt,
            _mode: HealMode,
        ) -> Result<(BitrotHealEvidence, BitrotCleanupEvidence)> {
            Ok((self.heal.clone(), self.cleanup.clone()))
        }

        async fn finish(
            &mut self,
            _context: &OwnedStorageContext,
            _cleanup: &StorageRecoveryCleanupProof,
        ) -> Result<()> {
            if let Some(error) = &self.finish_error {
                bail!(error.clone());
            }
            self.finished = true;
            Ok(())
        }
    }

    #[tokio::test]
    async fn typed_executor_reaches_receipt_bound_repair_and_cleanup() {
        let mut runtime = FakeBitrotRuntime::successful();
        execute_on_disk_bitrot(
            &mut runtime,
            StorageRecoveryCase::OnDiskBitrotAutomaticScanner,
        )
        .await
        .expect("repaired execution");
        assert!(runtime.finished);
    }

    #[tokio::test]
    async fn typed_executor_rejects_clean_bytes_from_required_corrupt_shard() {
        let mut runtime = FakeBitrotRuntime::successful();
        let corrupt = runtime.reads.back_mut().expect("corruption read");
        corrupt.outcome = BitrotReadOutcome::ExpectedBytes;
        corrupt.http_status = Some(200);
        corrupt.observed_sha256 = Some(ORIGINAL.to_string());
        corrupt.error = None;
        let error = execute_on_disk_bitrot(
            &mut runtime,
            StorageRecoveryCase::OnDiskBitrotAutomaticScanner,
        )
        .await
        .expect_err("required corrupt shard must not read cleanly");
        assert!(error.to_string().contains("harness unqualified"));
        assert!(!runtime.finished);
    }

    #[tokio::test]
    async fn typed_executor_reports_helper_cleanup_failure() {
        let mut runtime = FakeBitrotRuntime::successful();
        runtime.finish_error = Some("helper cleanup receipt was rejected".to_string());
        let error = execute_on_disk_bitrot(
            &mut runtime,
            StorageRecoveryCase::OnDiskBitrotAutomaticScanner,
        )
        .await
        .expect_err("cleanup failure must fail the workflow");
        assert!(error.to_string().contains("cleanup receipt"));
        assert!(!runtime.finished);
    }
}
