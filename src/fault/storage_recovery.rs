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

//! Evidence contracts for RustFS storage-recovery scenarios.
//!
//! These types deliberately stop short of discovering RustFS's private
//! on-disk layout. A future runtime adapter may execute replacement, bitrot,
//! and stale-generation workflows only after RustFS supplies a stable mapping
//! hook and the adapter can populate these proofs from observed identities.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::fault::{
    history::{
        DurabilityCohort, FaultWindowRelation, OperationKind, OperationOutcome, OperationRecord,
    },
    quorum::{ErasureSetMembership, ErasureSetShape, PersistedVersionClass, QuorumRequirements},
};

pub const STORAGE_RECOVERY_PROOF_SCHEMA_VERSION: u8 = 1;
pub const DISK_GENERATION_PROOF_ARTIFACT: &str = "disk-generation-proof.json";
pub const SHARD_MUTATION_PROOF_ARTIFACT: &str = "shard-mutation-proof.json";
pub const HEAL_SUMMARY_ARTIFACT: &str = "heal-summary.json";
pub const HEAL_PROGRESS_ARTIFACT: &str = "heal-progress.jsonl";
pub const FORCE_READ_PROOF_ARTIFACT: &str = "force-read-proof.json";
pub const VERSION_SHARD_MAPPING_ARTIFACT: &str = "version-shard-mapping.json";
pub const DANGLING_CLEANUP_PROOF_ARTIFACT: &str = "dangling-cleanup-proof.json";
pub const SHARD_INVENTORY_BEFORE_ARTIFACT: &str = "shard-inventory-before.json";
pub const SHARD_INVENTORY_AFTER_ARTIFACT: &str = "shard-inventory-after.json";
const STORAGE_OBSERVATION_MAX_AGE_MS: u64 = 5_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageRecoveryArtifactIdentity {
    pub run_id: String,
    pub scenario: String,
    pub case_name: String,
    pub bucket: String,
}

impl StorageRecoveryArtifactIdentity {
    fn validate(&self) -> Result<()> {
        for (field, value) in [
            ("run id", self.run_id.as_str()),
            ("scenario", self.scenario.as_str()),
            ("case name", self.case_name.as_str()),
            ("bucket", self.bucket.as_str()),
        ] {
            ensure!(
                !value.trim().is_empty(),
                "storage recovery artifact {field} is empty"
            );
        }
        Ok(())
    }
}

/// Closed set of storage-recovery cases. These are variants of three catalog
/// families, not generic workflow steps or backend parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StorageRecoveryCase {
    FreshVolumeReplacementAutomaticReplacement,
    FreshVolumeReplacementAdminDeep,
    OnDiskBitrotAutomaticScanner,
    OnDiskBitrotAdminDeep,
    StaleDiskReturn,
}

impl StorageRecoveryCase {
    pub const ALL: [Self; 5] = [
        Self::FreshVolumeReplacementAutomaticReplacement,
        Self::FreshVolumeReplacementAdminDeep,
        Self::OnDiskBitrotAutomaticScanner,
        Self::OnDiskBitrotAdminDeep,
        Self::StaleDiskReturn,
    ];

    pub fn scenario(self) -> &'static str {
        match self {
            Self::FreshVolumeReplacementAutomaticReplacement
            | Self::FreshVolumeReplacementAdminDeep => "fresh-volume-replacement",
            Self::OnDiskBitrotAutomaticScanner | Self::OnDiskBitrotAdminDeep => "on-disk-bitrot",
            Self::StaleDiskReturn => "stale-disk-return-detect",
        }
    }

    pub fn heal_mode(self) -> Option<HealMode> {
        match self {
            Self::FreshVolumeReplacementAutomaticReplacement => {
                Some(HealMode::AutomaticReplacement)
            }
            Self::OnDiskBitrotAutomaticScanner => Some(HealMode::AutomaticScanner),
            Self::FreshVolumeReplacementAdminDeep | Self::OnDiskBitrotAdminDeep => {
                Some(HealMode::AdminDeep)
            }
            Self::StaleDiskReturn => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageVolumeIdentity {
    pub target_proof_sha256: String,
    pub host_storage_proof_sha256: String,
    pub rustfs_deployment_id: String,
    pub namespace: String,
    pub tenant: String,
    pub pod: String,
    pub pod_uid: String,
    pub volume_name: String,
    pub persistent_volume_claim: String,
    pub persistent_volume_claim_uid: String,
    pub persistent_volume: String,
    pub persistent_volume_uid: String,
    pub node: String,
    pub node_uid: String,
    pub mount_path: String,
    pub canonical_device: String,
    pub filesystem_uuid: String,
    pub rustfs_drive_uuid: String,
    pub pool_index: u32,
    pub set_index: u32,
    pub observed_at_ms: u64,
}

impl StorageVolumeIdentity {
    pub fn validate(&self) -> Result<()> {
        validate_sha256("target proof", &self.target_proof_sha256)?;
        validate_sha256("host-storage proof", &self.host_storage_proof_sha256)?;
        for (field, value) in [
            ("RustFS deployment id", self.rustfs_deployment_id.as_str()),
            ("namespace", self.namespace.as_str()),
            ("tenant", self.tenant.as_str()),
            ("Pod", self.pod.as_str()),
            ("Pod UID", self.pod_uid.as_str()),
            ("volume name", self.volume_name.as_str()),
            ("PVC", self.persistent_volume_claim.as_str()),
            ("PVC UID", self.persistent_volume_claim_uid.as_str()),
            ("PV", self.persistent_volume.as_str()),
            ("PV UID", self.persistent_volume_uid.as_str()),
            ("node", self.node.as_str()),
            ("node UID", self.node_uid.as_str()),
            ("canonical device", self.canonical_device.as_str()),
            ("filesystem UUID", self.filesystem_uuid.as_str()),
            ("RustFS drive UUID", self.rustfs_drive_uuid.as_str()),
        ] {
            ensure!(
                !value.trim().is_empty(),
                "storage identity {field} is empty"
            );
        }
        ensure!(
            self.mount_path.starts_with('/')
                && self.mount_path != "/"
                && !self.mount_path.split('/').any(|part| part == ".."),
            "storage identity mount path must be an absolute normalized non-root path"
        );
        ensure!(
            self.canonical_device.starts_with('/'),
            "storage identity canonical device must be absolute"
        );
        ensure!(
            self.observed_at_ms > 0,
            "storage identity observation timestamp must be positive"
        );
        Ok(())
    }

    fn same_logical_slot(&self, other: &Self) -> bool {
        self.rustfs_deployment_id == other.rustfs_deployment_id
            && self.namespace == other.namespace
            && self.tenant == other.tenant
            && self.volume_name == other.volume_name
            && self.persistent_volume_claim == other.persistent_volume_claim
            && self.mount_path == other.mount_path
            && self.pool_index == other.pool_index
            && self.set_index == other.set_index
    }

    fn same_storage_generation(&self, other: &Self) -> bool {
        self.persistent_volume_uid == other.persistent_volume_uid
            && self.canonical_device == other.canonical_device
            && self.filesystem_uuid == other.filesystem_uuid
            && self.rustfs_drive_uuid == other.rustfs_drive_uuid
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmptyVolumeObservation {
    pub observed_at_ms: u64,
    pub persistent_volume_uid: String,
    pub canonical_device: String,
    pub filesystem_uuid: String,
    pub rustfs_process_can_access_volume: bool,
    pub data_entries: Vec<String>,
    pub scan_response_sha256: String,
    pub scan_response_body: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmptyVolumeScanResponse {
    pub persistent_volume_uid: String,
    pub canonical_device: String,
    pub filesystem_uuid: String,
    pub rustfs_process_can_access_volume: bool,
    pub scan_started_at_ms: u64,
    pub scan_completed_at_ms: u64,
    pub exhaustive: bool,
    pub data_entries: Vec<String>,
}

impl EmptyVolumeObservation {
    fn validate(&self, replacement: &StorageVolumeIdentity) -> Result<()> {
        validate_sha256("empty-volume scan response", &self.scan_response_sha256)?;
        ensure!(
            self.scan_response_sha256 == sha256_bytes(self.scan_response_body.as_bytes()),
            "empty-volume scan response digest does not match its captured body"
        );
        let response = serde_json::from_str::<EmptyVolumeScanResponse>(&self.scan_response_body)
            .context("decode captured empty-volume scan response")?;
        ensure!(
            response.scan_started_at_ms > 0
                && response.scan_started_at_ms < response.scan_completed_at_ms
                && response.scan_completed_at_ms == self.observed_at_ms
                && self.observed_at_ms <= replacement.observed_at_ms,
            "empty-volume observation must precede the replacement identity observation"
        );
        ensure!(
            self.persistent_volume_uid == replacement.persistent_volume_uid
                && self.canonical_device == replacement.canonical_device
                && self.filesystem_uuid == replacement.filesystem_uuid,
            "empty-volume observation is not bound to the replacement storage generation"
        );
        ensure!(
            !self.rustfs_process_can_access_volume,
            "replacement emptiness must be observed before RustFS can access the volume"
        );
        ensure!(
            self.data_entries.is_empty(),
            "replacement volume contains data entries before RustFS adoption"
        );
        ensure!(
            response.persistent_volume_uid == self.persistent_volume_uid
                && response.canonical_device == self.canonical_device
                && response.filesystem_uuid == self.filesystem_uuid
                && response.rustfs_process_can_access_volume
                    == self.rustfs_process_can_access_volume
                && response.data_entries == self.data_entries
                && response.exhaustive,
            "empty-volume fields are not derived from one exhaustive host scan response"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FreshVolumeReplacementProof {
    pub schema_version: u8,
    pub identity: StorageRecoveryArtifactIdentity,
    pub original: StorageVolumeIdentity,
    pub replacement: StorageVolumeIdentity,
    pub empty_before_adoption: EmptyVolumeObservation,
}

impl FreshVolumeReplacementProof {
    pub fn prove(
        identity: StorageRecoveryArtifactIdentity,
        original: StorageVolumeIdentity,
        replacement: StorageVolumeIdentity,
        empty_before_adoption: EmptyVolumeObservation,
    ) -> Result<Self> {
        let proof = Self {
            schema_version: STORAGE_RECOVERY_PROOF_SCHEMA_VERSION,
            identity,
            original,
            replacement,
            empty_before_adoption,
        };
        proof.validate()?;
        Ok(proof)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == STORAGE_RECOVERY_PROOF_SCHEMA_VERSION,
            "unsupported disk-generation proof schema version {}",
            self.schema_version
        );
        self.identity.validate()?;
        ensure!(
            self.identity.scenario == "fresh-volume-replacement",
            "fresh replacement proof is bound to the wrong scenario"
        );
        self.original.validate()?;
        self.replacement.validate()?;
        ensure!(
            self.original.same_logical_slot(&self.replacement),
            "replacement does not occupy the original RustFS logical volume slot"
        );
        ensure!(
            self.replacement.observed_at_ms > self.original.observed_at_ms,
            "replacement identity must be observed after the original identity"
        );
        ensure!(
            self.original.persistent_volume_claim_uid
                != self.replacement.persistent_volume_claim_uid,
            "fresh replacement reused the original PVC generation"
        );
        ensure!(
            self.original.persistent_volume_uid != self.replacement.persistent_volume_uid
                && self.original.filesystem_uuid != self.replacement.filesystem_uuid
                && self.original.rustfs_drive_uuid != self.replacement.rustfs_drive_uuid,
            "fresh replacement must have new PV, filesystem, and RustFS drive generations"
        );
        self.empty_before_adoption.validate(&self.replacement)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StaleMutationKind {
    Overwrite,
    DeleteMarker,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommittedMutationEvidence {
    pub operation_id: String,
    pub kind: StaleMutationKind,
    pub object_key: String,
    pub version_id: String,
    pub acknowledged_at_ms: u64,
    pub absence_observation_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiskAbsenceObservation {
    pub observation_id: String,
    pub detachment_operation_id: String,
    pub persistent_volume_uid: String,
    pub canonical_device: String,
    pub filesystem_uuid: String,
    pub rustfs_drive_uuid: String,
    pub target_proof_sha256: String,
    pub host_storage_proof_sha256: String,
    pub watch_started_at_ms: u64,
    pub watch_ended_at_ms: u64,
    pub controller_watch_had_no_reattach_event: bool,
    pub node_watch_had_no_device_present_event: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StaleDiskReturnEvidence {
    pub detached_at_ms: u64,
    pub mutation_window_ended_at_ms: u64,
    pub returned_at_ms: u64,
    pub detachment_operation_id: String,
    pub reattachment_operation_id: String,
    pub absence_observations: Vec<DiskAbsenceObservation>,
    pub committed_mutations: Vec<CommittedMutationEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StaleDiskReturnProof {
    pub schema_version: u8,
    pub identity: StorageRecoveryArtifactIdentity,
    pub detached_generation: StorageVolumeIdentity,
    pub returned_generation: StorageVolumeIdentity,
    pub detached_at_ms: u64,
    pub mutation_window_ended_at_ms: u64,
    pub returned_at_ms: u64,
    pub detachment_operation_id: String,
    pub reattachment_operation_id: String,
    pub absence_observations: Vec<DiskAbsenceObservation>,
    pub committed_mutations: Vec<CommittedMutationEvidence>,
}

impl StaleDiskReturnProof {
    pub fn prove(
        identity: StorageRecoveryArtifactIdentity,
        detached_generation: StorageVolumeIdentity,
        returned_generation: StorageVolumeIdentity,
        evidence: StaleDiskReturnEvidence,
        history: &[OperationRecord],
    ) -> Result<Self> {
        let proof = Self {
            schema_version: STORAGE_RECOVERY_PROOF_SCHEMA_VERSION,
            identity,
            detached_generation,
            returned_generation,
            detached_at_ms: evidence.detached_at_ms,
            mutation_window_ended_at_ms: evidence.mutation_window_ended_at_ms,
            returned_at_ms: evidence.returned_at_ms,
            detachment_operation_id: evidence.detachment_operation_id,
            reattachment_operation_id: evidence.reattachment_operation_id,
            absence_observations: evidence.absence_observations,
            committed_mutations: evidence.committed_mutations,
        };
        proof.validate_against_history(history)?;
        Ok(proof)
    }

    pub fn validate_against_history(&self, history: &[OperationRecord]) -> Result<()> {
        ensure!(
            self.schema_version == STORAGE_RECOVERY_PROOF_SCHEMA_VERSION,
            "unsupported disk-generation proof schema version {}",
            self.schema_version
        );
        self.identity.validate()?;
        ensure!(
            self.identity.scenario == "stale-disk-return-detect",
            "stale-disk proof is bound to the wrong scenario"
        );
        self.detached_generation.validate()?;
        self.returned_generation.validate()?;
        ensure!(
            self.detached_generation
                .same_logical_slot(&self.returned_generation),
            "returned stale disk does not occupy its original logical volume slot"
        );
        ensure!(
            self.detached_generation
                .same_storage_generation(&self.returned_generation),
            "returned disk is not the detached storage generation"
        );
        ensure!(
            self.detached_at_ms >= self.detached_generation.observed_at_ms
                && self.detached_at_ms < self.mutation_window_ended_at_ms
                && self.mutation_window_ended_at_ms < self.returned_at_ms
                && self.returned_at_ms <= self.returned_generation.observed_at_ms,
            "stale-disk detach, mutation, return, and observation timestamps are not ordered"
        );
        ensure!(
            !self.detachment_operation_id.trim().is_empty()
                && !self.reattachment_operation_id.trim().is_empty()
                && self.detachment_operation_id != self.reattachment_operation_id,
            "stale-disk proof requires distinct detach and reattach operation identities"
        );
        ensure!(
            !self.absence_observations.is_empty(),
            "stale-disk proof has no runtime absence observations"
        );
        let mut absence_by_id = BTreeMap::new();
        for observation in &self.absence_observations {
            ensure!(
                !observation.observation_id.trim().is_empty()
                    && absence_by_id
                        .insert(observation.observation_id.as_str(), observation)
                        .is_none(),
                "stale-disk proof has an empty or duplicate absence observation id"
            );
            ensure!(
                observation.detachment_operation_id == self.detachment_operation_id
                    && observation.persistent_volume_uid
                        == self.detached_generation.persistent_volume_uid
                    && observation.canonical_device == self.detached_generation.canonical_device
                    && observation.filesystem_uuid == self.detached_generation.filesystem_uuid
                    && observation.rustfs_drive_uuid == self.detached_generation.rustfs_drive_uuid,
                "stale-disk absence observation is not bound to the detached generation and operation"
            );
            ensure!(
                observation.target_proof_sha256 == self.detached_generation.target_proof_sha256
                    && observation.host_storage_proof_sha256
                        == self.detached_generation.host_storage_proof_sha256,
                "stale-disk absence observation is not bound to the target and host-storage proofs"
            );
            ensure!(
                observation.watch_started_at_ms <= self.detached_at_ms
                    && observation.watch_ended_at_ms >= self.mutation_window_ended_at_ms
                    && observation.watch_ended_at_ms >= observation.watch_started_at_ms
                    && observation.controller_watch_had_no_reattach_event
                    && observation.node_watch_had_no_device_present_event,
                "stale-disk absence watch does not continuously prove controller and node absence across the mutation window"
            );
        }
        ensure!(
            !self.committed_mutations.is_empty(),
            "stale-disk proof has no committed mutations while the disk was absent"
        );
        let mut operation_ids = BTreeSet::new();
        let mut saw_overwrite = false;
        let mut saw_delete_marker = false;
        for mutation in &self.committed_mutations {
            ensure!(
                !mutation.operation_id.trim().is_empty()
                    && operation_ids.insert(mutation.operation_id.as_str())
                    && !mutation.object_key.trim().is_empty()
                    && !mutation.version_id.trim().is_empty()
                    && mutation.version_id != "null"
                    && !mutation.absence_observation_id.trim().is_empty(),
                "stale-disk committed mutation lacks a unique operation/object/version identity"
            );
            ensure!(
                mutation.acknowledged_at_ms > self.detached_at_ms
                    && mutation.acknowledged_at_ms <= self.mutation_window_ended_at_ms,
                "stale-disk mutation ACK falls outside the disk-absence window"
            );
            let absence = absence_by_id
                .get(mutation.absence_observation_id.as_str())
                .ok_or_else(|| {
                    anyhow::anyhow!("stale-disk mutation references an unknown absence observation")
                })?;
            ensure!(
                absence.watch_started_at_ms <= mutation.acknowledged_at_ms
                    && absence.watch_ended_at_ms >= mutation.acknowledged_at_ms,
                "stale-disk mutation ACK is not covered by a continuous disk-absence watch"
            );
            let matching_history = history
                .iter()
                .filter(|record| record.id == mutation.operation_id)
                .collect::<Vec<_>>();
            let [record] = matching_history.as_slice() else {
                anyhow::bail!("stale-disk mutation must match exactly one workload history record")
            };
            let kind_matches = match mutation.kind {
                StaleMutationKind::Overwrite => matches!(
                    record.kind,
                    OperationKind::Put | OperationKind::CompleteMultipartUpload
                ),
                StaleMutationKind::DeleteMarker => record.kind == OperationKind::Delete,
            };
            ensure!(
                record.run_id.as_deref() == Some(self.identity.run_id.as_str())
                    && record.scenario == self.identity.scenario
                    && record.bucket == self.identity.bucket
                    && kind_matches
                    && record.outcome == OperationOutcome::Ok
                    && record
                        .http_status
                        .is_some_and(|status| (200..300).contains(&status))
                    && record.key.as_deref() == Some(mutation.object_key.as_str())
                    && record.version_id.as_deref() == Some(mutation.version_id.as_str())
                    && valid_operation_interval(record)
                    && record.started_at_ms > self.detached_at_ms
                    && record.started_at_ms >= absence.watch_started_at_ms
                    && record.ended_at_ms <= absence.watch_ended_at_ms
                    && record.ended_at_ms == mutation.acknowledged_at_ms,
                "stale-disk mutation does not match a successful versioned request wholly executed during the proven absence window"
            );
            match mutation.kind {
                StaleMutationKind::Overwrite => saw_overwrite = true,
                StaleMutationKind::DeleteMarker => saw_delete_marker = true,
            }
        }
        ensure!(
            saw_overwrite && saw_delete_marker,
            "stale-disk proof requires both a committed overwrite and delete marker"
        );
        let history_mutation_ids = history
            .iter()
            .filter(|record| {
                record.run_id.as_deref() == Some(self.identity.run_id.as_str())
                    && record.scenario == self.identity.scenario
                    && record.bucket == self.identity.bucket
                    && matches!(
                        record.kind,
                        OperationKind::Put
                            | OperationKind::CompleteMultipartUpload
                            | OperationKind::Delete
                    )
                    && record.outcome == OperationOutcome::Ok
                    && valid_operation_interval(record)
                    && record.started_at_ms > self.detached_at_ms
                    && record.ended_at_ms > self.detached_at_ms
                    && record.ended_at_ms <= self.mutation_window_ended_at_ms
            })
            .map(|record| record.id.as_str())
            .collect::<BTreeSet<_>>();
        ensure!(
            history_mutation_ids == operation_ids,
            "stale-disk proof does not cover the exact successful mutation history from the disk-absence window"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ShardMappingSource {
    RustfsDiagnosticApi,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RustfsShardMutationMappingResponse {
    pub bucket: String,
    pub object_key: String,
    pub version_id: String,
    pub object_sha256: String,
    pub drive_uuid: String,
    pub shard_path: String,
    pub shard_device_id: String,
    pub shard_inode: u64,
    pub shard_size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShardRollbackObservation {
    pub shard_path: String,
    pub shard_device_id: String,
    pub shard_inode: u64,
    pub shard_size_bytes: u64,
    pub observed_sha256: String,
    pub observed_at_ms: u64,
    pub target_proof_sha256: String,
    pub host_storage_proof_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ShardPathResolutionMethod {
    Openat2BeneathNoSymlinksNoXdev,
    CanonicalizeOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Openat2PathResolutionReceipt {
    pub method: ShardPathResolutionMethod,
    pub requested_path: String,
    pub canonical_mount_path: String,
    pub mount_canonical_device: String,
    pub mount_filesystem_uuid: String,
    pub resolved_path: String,
    pub mount_device_id: String,
    pub returned_fd_device_id: String,
    pub returned_fd_inode: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShardPathContainmentProof {
    pub observed_at_ms: u64,
    pub resolver_evidence_sha256: String,
    pub resolver_response_body: String,
    pub target_proof_sha256: String,
    pub host_storage_proof_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShardMutationProof {
    pub schema_version: u8,
    pub identity: StorageRecoveryArtifactIdentity,
    pub mapping_source: ShardMappingSource,
    pub mapping_api_revision: String,
    pub mapping_response_sha256: String,
    pub mapping_response_body: String,
    pub object_key: String,
    pub version_id: String,
    pub expected_object_sha256: String,
    pub volume: StorageVolumeIdentity,
    pub shard_path: String,
    pub shard_device_id: String,
    pub shard_inode: u64,
    pub shard_size_bytes: u64,
    pub path_containment: ShardPathContainmentProof,
    pub byte_offset: u64,
    pub byte_length: u64,
    pub original_sha256: String,
    pub mutated_sha256: String,
    pub host_mutation_evidence: Option<ShardMutationHostEvidence>,
    pub rollback: ShardRollbackObservation,
    pub mapped_at_ms: u64,
    pub mutated_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShardMutationHostReceipt {
    pub shard_path: String,
    pub shard_device_id: String,
    pub shard_inode: u64,
    pub shard_size_bytes: u64,
    pub byte_offset: u64,
    pub byte_length: u64,
    pub original_sha256: String,
    pub mutated_sha256: String,
    pub rollback_sha256: String,
    pub original_observed_at_ms: u64,
    pub pwrite_completed_at_ms: u64,
    pub mutation_fsync_completed_at_ms: u64,
    pub mutation_fstat_observed_at_ms: u64,
    pub mutated_readback_at_ms: u64,
    pub rollback_pwrite_completed_at_ms: u64,
    pub rollback_fsync_completed_at_ms: u64,
    pub rollback_fstat_observed_at_ms: u64,
    pub rollback_readback_at_ms: u64,
    pub pwrite_bytes: u64,
    pub rollback_pwrite_bytes: u64,
    pub mutation_fsync_succeeded: bool,
    pub rollback_fsync_succeeded: bool,
    pub target_proof_sha256: String,
    pub host_storage_proof_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShardMutationHostEvidence {
    pub response_sha256: String,
    pub response_body: String,
}

impl ShardMutationProof {
    pub fn validate_against_history(&self, history: &[OperationRecord]) -> Result<()> {
        ensure!(
            self.schema_version == STORAGE_RECOVERY_PROOF_SCHEMA_VERSION,
            "unsupported shard-mutation proof schema version {}",
            self.schema_version
        );
        self.identity.validate()?;
        ensure!(
            self.identity.scenario == "on-disk-bitrot",
            "shard mutation proof is bound to the wrong scenario"
        );
        self.volume.validate()?;
        for (field, value) in [
            ("mapping API revision", self.mapping_api_revision.as_str()),
            ("object key", self.object_key.as_str()),
            ("version id", self.version_id.as_str()),
            ("shard device id", self.shard_device_id.as_str()),
        ] {
            ensure!(!value.trim().is_empty(), "shard mutation {field} is empty");
        }
        ensure!(
            self.version_id != "null",
            "shard mutation requires an explicit non-null object version"
        );
        for (field, value) in [
            ("expected object", self.expected_object_sha256.as_str()),
            ("original shard", self.original_sha256.as_str()),
            ("mutated shard", self.mutated_sha256.as_str()),
        ] {
            validate_sha256(field, value)?;
        }
        validate_sha256("shard mapping response", &self.mapping_response_sha256)?;
        ensure!(
            self.mapping_response_sha256 == sha256_bytes(self.mapping_response_body.as_bytes()),
            "shard mapping response digest does not match the captured RustFS response body"
        );
        let mapping_response =
            serde_json::from_str::<RustfsShardMutationMappingResponse>(&self.mapping_response_body)
                .context("decode captured RustFS shard mutation mapping response")?;
        ensure!(
            mapping_response.bucket == self.identity.bucket
                && mapping_response.object_key == self.object_key
                && mapping_response.version_id == self.version_id
                && mapping_response.object_sha256 == self.expected_object_sha256
                && mapping_response.drive_uuid == self.volume.rustfs_drive_uuid
                && mapping_response.shard_path == self.shard_path
                && mapping_response.shard_device_id == self.shard_device_id
                && mapping_response.shard_inode == self.shard_inode
                && mapping_response.shard_size_bytes == self.shard_size_bytes,
            "shard mutation fields do not match the captured RustFS mapping response"
        );
        validate_sha256("rollback shard", &self.rollback.observed_sha256)?;
        validate_sha256(
            "shard path resolver evidence",
            &self.path_containment.resolver_evidence_sha256,
        )?;
        ensure!(
            self.path_containment.resolver_evidence_sha256
                == sha256_bytes(self.path_containment.resolver_response_body.as_bytes()),
            "shard path resolver digest does not match the captured openat2 receipt"
        );
        let path_receipt = serde_json::from_str::<Openat2PathResolutionReceipt>(
            &self.path_containment.resolver_response_body,
        )
        .context("decode captured openat2 shard path receipt")?;
        ensure!(
            self.shard_path
                .starts_with(&format!("{}/", self.volume.mount_path))
                && !self.shard_path.split('/').any(|part| part == ".."),
            "mapped shard path must be a normalized descendant of the proven volume mount"
        );
        ensure!(
            path_receipt.method == ShardPathResolutionMethod::Openat2BeneathNoSymlinksNoXdev
                && path_receipt.requested_path == self.shard_path
                && path_receipt.canonical_mount_path == self.volume.mount_path
                && path_receipt.mount_canonical_device == self.volume.canonical_device
                && path_receipt.mount_filesystem_uuid == self.volume.filesystem_uuid
                && path_receipt.resolved_path == self.shard_path
                && path_receipt.mount_device_id == self.shard_device_id
                && path_receipt.returned_fd_device_id == self.shard_device_id
                && path_receipt.returned_fd_inode == self.shard_inode
                && self.path_containment.observed_at_ms >= self.mapped_at_ms
                && self.path_containment.observed_at_ms <= self.mutated_at_ms
                && self.path_containment.target_proof_sha256 == self.volume.target_proof_sha256
                && self.path_containment.host_storage_proof_sha256
                    == self.volume.host_storage_proof_sha256,
            "shard path was not opened beneath the proven mount with no symlinks or device crossing"
        );
        ensure!(
            self.byte_length > 0,
            "shard mutation byte length must be positive"
        );
        let byte_end = self
            .byte_offset
            .checked_add(self.byte_length)
            .ok_or_else(|| anyhow::anyhow!("shard mutation byte range overflows"))?;
        ensure!(
            self.shard_inode > 0 && self.shard_size_bytes > 0 && byte_end <= self.shard_size_bytes,
            "shard mutation range must fall inside the proven non-empty shard inode"
        );
        let host_evidence = self
            .host_mutation_evidence
            .as_ref()
            .context("shard mutation lacks a captured host-helper receipt")?;
        validate_sha256("host mutation receipt", &host_evidence.response_sha256)?;
        ensure!(
            host_evidence.response_sha256 == sha256_bytes(host_evidence.response_body.as_bytes()),
            "host mutation receipt digest does not match its captured body"
        );
        let host_receipt =
            serde_json::from_str::<ShardMutationHostReceipt>(&host_evidence.response_body)
                .context("decode captured shard-mutation host-helper receipt")?;
        for (field, value) in [
            (
                "receipt original shard",
                host_receipt.original_sha256.as_str(),
            ),
            (
                "receipt mutated shard",
                host_receipt.mutated_sha256.as_str(),
            ),
            (
                "receipt rollback shard",
                host_receipt.rollback_sha256.as_str(),
            ),
        ] {
            validate_sha256(field, value)?;
        }
        ensure!(
            host_receipt.shard_path == self.shard_path
                && host_receipt.shard_device_id == self.shard_device_id
                && host_receipt.shard_inode == self.shard_inode
                && host_receipt.shard_size_bytes == self.shard_size_bytes
                && host_receipt.byte_offset == self.byte_offset
                && host_receipt.byte_length == self.byte_length
                && host_receipt.pwrite_bytes == self.byte_length
                && host_receipt.rollback_pwrite_bytes == self.byte_length
                && host_receipt.original_sha256 == self.original_sha256
                && host_receipt.mutated_sha256 == self.mutated_sha256
                && host_receipt.rollback_sha256 == self.rollback.observed_sha256
                && host_receipt.target_proof_sha256 == self.volume.target_proof_sha256
                && host_receipt.host_storage_proof_sha256 == self.volume.host_storage_proof_sha256
                && host_receipt.mutation_fsync_succeeded
                && host_receipt.rollback_fsync_succeeded,
            "shard mutation fields are not derived from a successful host-helper receipt for the proven inode"
        );
        ensure!(
            host_receipt.original_observed_at_ms >= self.path_containment.observed_at_ms
                && host_receipt.original_observed_at_ms < host_receipt.pwrite_completed_at_ms
                && host_receipt.pwrite_completed_at_ms
                    <= host_receipt.mutation_fsync_completed_at_ms
                && host_receipt.mutation_fsync_completed_at_ms
                    <= host_receipt.mutation_fstat_observed_at_ms
                && host_receipt.mutation_fstat_observed_at_ms
                    <= host_receipt.mutated_readback_at_ms
                && host_receipt.mutated_readback_at_ms == self.mutated_at_ms
                && host_receipt.mutated_readback_at_ms
                    < host_receipt.rollback_pwrite_completed_at_ms
                && host_receipt.rollback_pwrite_completed_at_ms
                    <= host_receipt.rollback_fsync_completed_at_ms
                && host_receipt.rollback_fsync_completed_at_ms
                    <= host_receipt.rollback_fstat_observed_at_ms
                && host_receipt.rollback_fstat_observed_at_ms
                    <= host_receipt.rollback_readback_at_ms
                && host_receipt.rollback_readback_at_ms == self.rollback.observed_at_ms,
            "host-helper pwrite, fsync, fstat, readback, and rollback receipt is not strictly ordered"
        );
        ensure!(
            self.original_sha256 != self.mutated_sha256,
            "shard mutation did not change the shard hash"
        );
        ensure!(
            self.rollback.observed_sha256 == self.original_sha256
                && self.rollback.shard_path == self.shard_path
                && self.rollback.shard_device_id == self.shard_device_id
                && self.rollback.shard_inode == self.shard_inode
                && self.rollback.shard_size_bytes == self.shard_size_bytes
                && self.rollback.observed_at_ms > self.mutated_at_ms
                && self.rollback.target_proof_sha256 == self.volume.target_proof_sha256
                && self.rollback.host_storage_proof_sha256 == self.volume.host_storage_proof_sha256,
            "post-rollback observation does not prove restoration of the mutated shard and target"
        );
        ensure!(
            self.mapped_at_ms >= self.volume.observed_at_ms
                && self.mutated_at_ms >= self.mapped_at_ms
                && self.mutated_at_ms - self.mapped_at_ms <= STORAGE_OBSERVATION_MAX_AGE_MS,
            "shard mapping must be fresh and precede mutation"
        );
        let matching_history = history
            .iter()
            .filter(|record| {
                record.run_id.as_deref() == Some(self.identity.run_id.as_str())
                    && record.scenario == self.identity.scenario
                    && record.bucket == self.identity.bucket
                    && matches!(
                        record.kind,
                        OperationKind::Put | OperationKind::CompleteMultipartUpload
                    )
                    && record.outcome == OperationOutcome::Ok
                    && record
                        .http_status
                        .is_some_and(|status| (200..300).contains(&status))
                    && record.key.as_deref() == Some(self.object_key.as_str())
                    && record.version_id.as_deref() == Some(self.version_id.as_str())
                    && valid_operation_interval(record)
                    && record.ended_at_ms <= self.mapped_at_ms
            })
            .collect::<Vec<_>>();
        let [committed_write] = matching_history.as_slice() else {
            anyhow::bail!(
                "shard mapping must match exactly one committed object version identity in workload history"
            )
        };
        ensure!(
            committed_write.value_sha256.as_deref() == Some(self.expected_object_sha256.as_str()),
            "committed object version identity has a conflicting content hash"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HealMode {
    AutomaticReplacement,
    AutomaticScanner,
    AdminDeep,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum HealObserverIdentity {
    ReplacementTask { task_id: String, generation: u64 },
    ScannerStatus { status_cursor: String },
    AdminOperation { operation_id: String },
}

impl HealObserverIdentity {
    fn validate_for_mode(&self, mode: HealMode) -> Result<()> {
        match (mode, self) {
            (
                HealMode::AutomaticReplacement,
                Self::ReplacementTask {
                    task_id,
                    generation,
                },
            ) => ensure!(
                !task_id.trim().is_empty() && *generation > 0,
                "automatic replacement requires a task id and positive generation"
            ),
            (HealMode::AutomaticScanner, Self::ScannerStatus { status_cursor }) => ensure!(
                !status_cursor.trim().is_empty(),
                "automatic scanner requires a status cursor"
            ),
            (HealMode::AdminDeep, Self::AdminOperation { operation_id }) => ensure!(
                !operation_id.trim().is_empty(),
                "admin heal requires an operation id"
            ),
            _ => anyhow::bail!("heal observer kind does not match the selected heal mode"),
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HealProgressState {
    Queued,
    Running,
    Completed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HealProgressSample {
    pub schema_version: u8,
    pub identity: StorageRecoveryArtifactIdentity,
    pub observer: HealObserverIdentity,
    pub observed_at_ms: u64,
    pub state: HealProgressState,
    pub scanned: u64,
    pub repaired: u64,
    pub failed: u64,
    pub status_evidence: Option<HealStatusEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HealStatusEvidence {
    pub api_revision: String,
    pub response_sha256: String,
    pub response_body: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RustfsHealStatusResponse {
    pub observer: HealObserverIdentity,
    pub observed_at_ms: u64,
    pub state: HealProgressState,
    pub scanned: u64,
    pub repaired: u64,
    pub failed: u64,
    pub cluster_definitive: bool,
    pub target_drive_uuid: Option<String>,
    pub pool_index: u32,
    pub set_index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HealSummary {
    pub schema_version: u8,
    pub identity: StorageRecoveryArtifactIdentity,
    pub case: StorageRecoveryCase,
    pub observer: HealObserverIdentity,
    pub mode: HealMode,
    pub target_drive_uuid: Option<String>,
    pub pool_index: u32,
    pub set_index: u32,
    pub cluster_definitive: bool,
    pub started_at_ms: u64,
    pub completed_at_ms: u64,
    pub scanned: u64,
    pub repaired: u64,
    pub failed: u64,
    pub state: HealProgressState,
}

impl HealSummary {
    pub fn validate_progress(
        &self,
        samples: &[HealProgressSample],
        expected_target: Option<(&str, u32, u32)>,
    ) -> Result<()> {
        ensure!(
            self.schema_version == STORAGE_RECOVERY_PROOF_SCHEMA_VERSION,
            "unsupported heal-summary schema version {}",
            self.schema_version
        );
        self.identity.validate()?;
        ensure!(
            self.case.scenario() == self.identity.scenario
                && self.case.heal_mode() == Some(self.mode),
            "heal case, scenario identity, and mode do not identify the same qualified variant"
        );
        self.observer.validate_for_mode(self.mode)?;
        ensure!(
            self.cluster_definitive,
            "heal status must be reported by a cluster-definitive observer"
        );
        match (
            self.mode,
            expected_target,
            self.target_drive_uuid.as_deref(),
        ) {
            (
                HealMode::AutomaticReplacement | HealMode::AdminDeep,
                Some((expected_drive, expected_pool, expected_set)),
                Some(actual_drive),
            ) => ensure!(
                !expected_drive.trim().is_empty()
                    && actual_drive == expected_drive
                    && self.pool_index == expected_pool
                    && self.set_index == expected_set,
                "heal target does not match the replacement or mutation evidence"
            ),
            (HealMode::AutomaticScanner, None, None) => {}
            _ => anyhow::bail!(
                "heal mode has an incompatible target contract; replacement/admin heals are target-specific while scanner status is aggregate"
            ),
        }
        ensure!(
            self.started_at_ms > 0 && self.completed_at_ms >= self.started_at_ms,
            "heal summary timestamps are not ordered"
        );
        ensure!(
            self.state == HealProgressState::Completed && self.failed == 0,
            "heal did not reach a successful terminal state"
        );
        if self.mode != HealMode::AutomaticReplacement {
            ensure!(
                self.scanned > 0 && self.repaired > 0,
                "scanner/admin heal requires positive scanned and repaired counters"
            );
        }
        ensure!(!samples.is_empty(), "heal progress has no samples");

        let mut previous: Option<&HealProgressSample> = None;
        for sample in samples {
            ensure!(
                sample.schema_version == STORAGE_RECOVERY_PROOF_SCHEMA_VERSION
                    && sample.identity == self.identity,
                "heal progress identity or schema does not match the summary"
            );
            ensure!(
                sample.observer == self.observer,
                "heal progress observer identity does not match the summary"
            );
            let status_evidence = sample
                .status_evidence
                .as_ref()
                .context("heal progress sample lacks a captured RustFS status response")?;
            ensure!(
                !status_evidence.api_revision.trim().is_empty(),
                "heal progress status response lacks an API revision"
            );
            validate_sha256("heal status response", &status_evidence.response_sha256)?;
            ensure!(
                status_evidence.response_sha256
                    == sha256_bytes(status_evidence.response_body.as_bytes()),
                "heal status response digest does not match its captured body"
            );
            let response =
                serde_json::from_str::<RustfsHealStatusResponse>(&status_evidence.response_body)
                    .context("decode captured RustFS heal status response")?;
            ensure!(
                response.observer == sample.observer
                    && response.observed_at_ms == sample.observed_at_ms
                    && response.state == sample.state
                    && response.scanned == sample.scanned
                    && response.repaired == sample.repaired
                    && response.failed == sample.failed
                    && response.cluster_definitive == self.cluster_definitive
                    && response.target_drive_uuid == self.target_drive_uuid
                    && response.pool_index == self.pool_index
                    && response.set_index == self.set_index,
                "heal progress fields are not derived from the captured RustFS status response"
            );
            ensure!(
                sample.observed_at_ms >= self.started_at_ms
                    && sample.observed_at_ms <= self.completed_at_ms,
                "heal progress timestamp falls outside the operation window"
            );
            if let Some(previous) = previous {
                ensure!(
                    sample.observed_at_ms >= previous.observed_at_ms
                        && sample.scanned >= previous.scanned
                        && sample.repaired >= previous.repaired
                        && sample.failed >= previous.failed,
                    "heal progress timestamps and counters must be monotonic"
                );
                ensure!(
                    previous.state != HealProgressState::Completed
                        && previous.state != HealProgressState::Failed,
                    "heal progress contains samples after a terminal state"
                );
                ensure!(
                    heal_state_rank(sample.state) >= heal_state_rank(previous.state),
                    "heal progress state regressed"
                );
            }
            previous = Some(sample);
        }

        let last = samples.last().expect("non-empty checked above");
        ensure!(
            last.state == self.state
                && last.observed_at_ms == self.completed_at_ms
                && last.scanned == self.scanned
                && last.repaired == self.repaired
                && last.failed == self.failed,
            "heal summary does not match the terminal progress sample"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForcedReadProbe {
    pub operation_id: String,
    pub object_key: String,
    pub version_id: String,
    pub expected_sha256: String,
    pub observed_sha256: String,
    pub http_status: u16,
    pub observed_at_ms: u64,
    pub mapping_observation_id: String,
    pub active_fault_snapshot_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionShardMappingObservation {
    pub schema_version: u8,
    pub identity: StorageRecoveryArtifactIdentity,
    pub observation_id: String,
    pub source: ShardMappingSource,
    pub api_revision: String,
    pub response_sha256: String,
    pub response_body: String,
    pub target_proof_sha256: String,
    pub observed_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RustfsVersionShardMappingResponse {
    pub bucket: String,
    pub object_key: String,
    pub version_id: String,
    pub object_sha256: String,
    pub pool_index: u32,
    pub set_index: u32,
    pub shard_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnavailableShardObservation {
    pub pod_name: String,
    pub drive_uuid: String,
    pub pool_index: u32,
    pub set_index: u32,
    pub fault_resource_id: String,
    pub active_snapshot_id: String,
    pub target_proof_sha256: String,
    pub fault_evidence_sha256: String,
    pub active_from_ms: u64,
    pub active_until_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForceReadThroughProof {
    pub schema_version: u8,
    pub identity: StorageRecoveryArtifactIdentity,
    pub shape: ErasureSetShape,
    pub persisted_version_class: PersistedVersionClass,
    pub all_shard_ids: Vec<String>,
    pub repaired_shard_id: String,
    pub target_proof_sha256: String,
    pub fault_evidence_sha256: String,
    pub fault_evidence_body: Option<String>,
    pub unavailable_shards: Vec<UnavailableShardObservation>,
    pub fault_active_from_ms: u64,
    pub fault_active_until_ms: u64,
    pub probes: Vec<ForcedReadProbe>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StorageFaultPodIdentity {
    name: String,
    uid: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct StorageFaultStatusSnapshot {
    stage: String,
    resource_kind: Option<String>,
    resource_name: Option<String>,
    chaos_status: Option<serde_json::Value>,
    dm_status: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct StorageFaultEvidenceResponse {
    scenario: String,
    run_id: String,
    injected: bool,
    active_during_workload: bool,
    pods_at_fault_activation: Vec<StorageFaultPodIdentity>,
    pods_at_workload_snapshot: Vec<StorageFaultPodIdentity>,
    active_snapshots: Vec<StorageFaultStatusSnapshot>,
    workload_snapshots: Vec<StorageFaultStatusSnapshot>,
    fault_active_at_ms: Option<u64>,
    workload_started_at_ms: Option<u64>,
    workload_ended_at_ms: Option<u64>,
    fault_delete_started_at_ms: Option<u64>,
}

impl ForceReadThroughProof {
    pub fn validate_against_runtime(
        &self,
        membership: &ErasureSetMembership,
        target_selected_pods: &[String],
        fault_selected_pods: &[String],
        expected_repaired_shard_id: &str,
        history: &[OperationRecord],
        mapping_observations: &[VersionShardMappingObservation],
    ) -> Result<()> {
        ensure!(
            self.schema_version == STORAGE_RECOVERY_PROOF_SCHEMA_VERSION,
            "unsupported force-read proof schema version {}",
            self.schema_version
        );
        self.identity.validate()?;
        ensure!(
            matches!(
                self.identity.scenario.as_str(),
                "fresh-volume-replacement" | "on-disk-bitrot"
            ),
            "force-read proof is bound to a scenario without a repaired drive"
        );
        self.shape.validate()?;
        membership.validate(&self.shape)?;
        validate_sha256("target proof", &self.target_proof_sha256)?;
        validate_sha256("fault evidence", &self.fault_evidence_sha256)?;
        let (evidence_pods, evidence_snapshot_id, evidence_resource_id) =
            self.validate_fault_evidence()?;
        ensure!(
            self.persisted_version_class == PersistedVersionClass::DataObject,
            "force-read heal proof requires a data-bearing object version"
        );
        validate_unique_nonempty("erasure shard id", &self.all_shard_ids, true)?;
        ensure!(
            self.all_shard_ids.len() == usize::try_from(self.shape.total_shards)?,
            "force-read proof shard inventory does not match the erasure-set width"
        );
        let membership_shards = membership
            .members
            .iter()
            .flat_map(|member| member.shard_ids.iter())
            .collect::<BTreeSet<_>>();
        ensure!(
            self.all_shard_ids.iter().collect::<BTreeSet<_>>() == membership_shards,
            "force-read shard inventory does not match runtime erasure-set membership"
        );
        ensure!(
            !expected_repaired_shard_id.trim().is_empty()
                && self.repaired_shard_id == expected_repaired_shard_id
                && self.all_shard_ids.contains(&self.repaired_shard_id),
            "repaired shard does not match the replacement/mutation evidence or is outside the proven erasure set"
        );
        let unavailable_ids = self
            .unavailable_shards
            .iter()
            .map(|observation| observation.drive_uuid.clone())
            .collect::<Vec<_>>();
        validate_unique_nonempty("unavailable shard id", &unavailable_ids, true)?;
        let all = self.all_shard_ids.iter().collect::<BTreeSet<_>>();
        let unavailable = unavailable_ids.iter().collect::<BTreeSet<_>>();
        ensure!(
            unavailable.is_subset(&all) && !unavailable.contains(&self.repaired_shard_id),
            "force-read unavailable set is invalid or contains the repaired shard"
        );
        let quorum = QuorumRequirements::for_persisted_version(
            self.shape.total_shards,
            self.shape.payload_parity_shards,
            self.persisted_version_class,
        )?;
        ensure!(
            self.unavailable_shards.len() == usize::try_from(quorum.read_tolerance)?,
            "force-read proof must leave exactly read quorum online"
        );
        ensure!(
            self.fault_active_from_ms > 0
                && self.fault_active_until_ms >= self.fault_active_from_ms,
            "force-read fault-active window is invalid"
        );
        ensure!(
            !self.probes.is_empty(),
            "force-read proof contains no S3 reads"
        );
        let mut mappings_by_id = BTreeMap::new();
        let mut mapping_ids = BTreeSet::new();
        for mapping in mapping_observations {
            ensure!(
                mapping.schema_version == STORAGE_RECOVERY_PROOF_SCHEMA_VERSION
                    && mapping.identity == self.identity
                    && !mapping.observation_id.trim().is_empty()
                    && mapping_ids.insert(mapping.observation_id.as_str()),
                "version-shard mapping has a mismatched schema/identity or duplicate observation id"
            );
            ensure!(
                mapping.source == ShardMappingSource::RustfsDiagnosticApi
                    && !mapping.api_revision.trim().is_empty()
                    && mapping.target_proof_sha256 == self.target_proof_sha256
                    && mapping.observed_at_ms > 0
                    && mapping.observed_at_ms <= self.fault_active_from_ms
                    && self.fault_active_from_ms - mapping.observed_at_ms
                        <= STORAGE_OBSERVATION_MAX_AGE_MS,
                "version-shard mapping is not a fresh pre-fault RustFS diagnostic observation"
            );
            validate_sha256("version-shard mapping response", &mapping.response_sha256)?;
            ensure!(
                mapping.response_sha256 == sha256_bytes(mapping.response_body.as_bytes()),
                "version-shard mapping response digest does not match the captured RustFS response body"
            );
            validate_sha256(
                "version-shard mapping target proof",
                &mapping.target_proof_sha256,
            )?;
            let response =
                serde_json::from_str::<RustfsVersionShardMappingResponse>(&mapping.response_body)
                    .context("decode captured RustFS version-shard mapping response")?;
            ensure!(
                !response.object_key.trim().is_empty()
                    && !response.version_id.trim().is_empty()
                    && response.version_id != "null",
                "captured RustFS version-shard mapping response lacks object/version identity"
            );
            validate_sha256("version-shard mapping object", &response.object_sha256)?;
            validate_unique_nonempty("version-shard mapping shard id", &response.shard_ids, true)?;
            mappings_by_id.insert(mapping.observation_id.as_str(), (mapping, response));
        }
        let mut snapshot_ids = BTreeSet::new();
        let target_pods = target_selected_pods
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let reported_evidence_pods = fault_selected_pods.iter().cloned().collect::<BTreeSet<_>>();
        ensure!(
            target_pods.len() == target_selected_pods.len()
                && reported_evidence_pods.len() == fault_selected_pods.len()
                && target_pods == evidence_pods
                && reported_evidence_pods == evidence_pods,
            "target proof and active fault evidence select different Pods"
        );
        let selected_membership_shards = membership
            .members
            .iter()
            .filter(|member| target_pods.contains(member.pod_name.as_str()))
            .flat_map(|member| member.shard_ids.iter())
            .collect::<BTreeSet<_>>();
        let unavailable_pods = self
            .unavailable_shards
            .iter()
            .map(|observation| observation.pod_name.clone())
            .collect::<BTreeSet<_>>();
        ensure!(
            unavailable_pods == target_pods && selected_membership_shards == unavailable,
            "unavailable drives are not the shards owned by the Pods selected in target proof and active fault evidence"
        );
        for observation in &self.unavailable_shards {
            snapshot_ids.insert(observation.active_snapshot_id.as_str());
            let matching_members = membership
                .members
                .iter()
                .filter(|member| member.pod_name == observation.pod_name)
                .collect::<Vec<_>>();
            let [member] = matching_members.as_slice() else {
                anyhow::bail!(
                    "unavailable shard observation must match exactly one erasure-set member Pod"
                )
            };
            ensure!(
                !observation.pod_name.trim().is_empty()
                    && member.shard_ids.contains(&observation.drive_uuid)
                    && observation.pool_index == self.shape.pool_index
                    && observation.set_index == self.shape.set_index
                    && observation.fault_resource_id == evidence_resource_id
                    && observation.active_snapshot_id == evidence_snapshot_id
                    && observation.active_from_ms <= self.fault_active_from_ms
                    && observation.active_until_ms >= self.fault_active_until_ms
                    && observation.target_proof_sha256 == self.target_proof_sha256
                    && observation.fault_evidence_sha256 == self.fault_evidence_sha256,
                "unavailable shard is not bound to its owning Pod and a unique active fault spanning the force-read window in the repaired set"
            );
        }
        ensure!(
            snapshot_ids.len() == 1,
            "force-read unavailable shards were not proven active in one atomic snapshot"
        );
        let mut probe_operation_ids = BTreeSet::new();
        let mut used_mapping_ids = BTreeSet::new();
        for probe in &self.probes {
            ensure!(
                !probe.operation_id.trim().is_empty()
                    && probe_operation_ids.insert(probe.operation_id.as_str())
                    && !probe.object_key.trim().is_empty()
                    && !probe.version_id.trim().is_empty(),
                "force-read probe lacks object/version identity"
            );
            validate_sha256("force-read expected object", &probe.expected_sha256)?;
            validate_sha256("force-read observed object", &probe.observed_sha256)?;
            ensure!(
                (200..300).contains(&probe.http_status)
                    && probe.expected_sha256 == probe.observed_sha256,
                "force-read probe did not return the expected object bytes"
            );
            ensure!(
                probe.version_id != "null"
                    && !probe.mapping_observation_id.trim().is_empty()
                    && snapshot_ids.contains(probe.active_fault_snapshot_id.as_str()),
                "force-read probe lacks an authoritative mapping or active fault snapshot"
            );
            let (mapping, response) = mappings_by_id
                .get(probe.mapping_observation_id.as_str())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "force-read probe references an unknown version-shard mapping observation"
                    )
                })?;
            ensure!(
                used_mapping_ids.insert(mapping.observation_id.as_str())
                    && response.bucket == self.identity.bucket
                    && response.object_key == probe.object_key
                    && response.version_id == probe.version_id
                    && response.object_sha256 == probe.expected_sha256
                    && response.pool_index == self.shape.pool_index
                    && response.set_index == self.shape.set_index
                    && response.shard_ids.iter().collect::<BTreeSet<_>>() == all
                    && response.shard_ids.len() == self.all_shard_ids.len(),
                "force-read probe is not uniquely mapped by RustFS diagnostics to the repaired erasure set"
            );
            ensure!(
                probe.observed_at_ms >= self.fault_active_from_ms
                    && probe.observed_at_ms <= self.fault_active_until_ms,
                "force-read probe falls outside the exact-quorum fault-active window"
            );
            let committed_writes = history
                .iter()
                .filter(|record| {
                    record_matches_identity(record, &self.identity)
                        && is_object_commit(record.kind)
                        && record.outcome == OperationOutcome::Ok
                        && record
                            .http_status
                            .is_some_and(|status| (200..300).contains(&status))
                        && record.key.as_deref() == Some(probe.object_key.as_str())
                        && record.version_id.as_deref() == Some(probe.version_id.as_str())
                        && record.durability_cohort == Some(DurabilityCohort::PreFault)
                        && matches!(
                            record.fault_window_relation,
                            None | Some(FaultWindowRelation::BeforeFault)
                        )
                        && valid_operation_interval(record)
                        && record.ended_at_ms < self.fault_active_from_ms
                })
                .collect::<Vec<_>>();
            let [committed_write] = committed_writes.as_slice() else {
                anyhow::bail!(
                    "force-read probe must match exactly one successful pre-fault object version identity"
                )
            };
            ensure!(
                committed_write.value_sha256.as_deref() == Some(probe.expected_sha256.as_str()),
                "force-read object version identity has a conflicting committed content hash"
            );
            ensure!(
                mapping.observed_at_ms >= committed_write.ended_at_ms,
                "version-shard mapping was observed before the committed object version existed"
            );
            let matching_history = history
                .iter()
                .filter(|record| record.id == probe.operation_id)
                .collect::<Vec<_>>();
            let [record] = matching_history.as_slice() else {
                anyhow::bail!("force-read probe must match exactly one workload history record")
            };
            ensure!(
                record.run_id.as_deref() == Some(self.identity.run_id.as_str())
                    && record.scenario == self.identity.scenario
                    && record.bucket == self.identity.bucket
                    && record.kind == OperationKind::Get
                    && record.outcome == OperationOutcome::Ok
                    && record.durability_cohort == Some(DurabilityCohort::FaultActive)
                    && record.fault_window_relation == Some(FaultWindowRelation::DuringFault)
                    && record.http_status == Some(probe.http_status)
                    && record.key.as_deref() == Some(probe.object_key.as_str())
                    && record.version_id.as_deref() == Some(probe.version_id.as_str())
                    && record.value_sha256.as_deref() == Some(probe.observed_sha256.as_str())
                    && valid_operation_interval(record)
                    && record.started_at_ms >= self.fault_active_from_ms
                    && record.ended_at_ms <= self.fault_active_until_ms
                    && record.ended_at_ms == probe.observed_at_ms,
                "force-read probe does not match its successful versioned GET in workload history"
            );
        }
        ensure!(
            used_mapping_ids == mappings_by_id.keys().copied().collect::<BTreeSet<_>>(),
            "force-read proof does not consume the exact version-shard mapping evidence set"
        );
        Ok(())
    }

    fn validate_fault_evidence(&self) -> Result<(BTreeSet<String>, String, String)> {
        let body = self
            .fault_evidence_body
            .as_deref()
            .context("force-read proof lacks captured fault-evidence.json")?;
        ensure!(
            self.fault_evidence_sha256 == sha256_bytes(body.as_bytes()),
            "force-read fault-evidence digest does not match its captured body"
        );
        let evidence = serde_json::from_str::<StorageFaultEvidenceResponse>(body)
            .context("decode captured force-read fault evidence")?;
        ensure!(
            evidence.run_id == self.identity.run_id
                && evidence.scenario == self.identity.scenario
                && evidence.injected
                && evidence.active_during_workload,
            "force-read fault evidence is not the active fault from this scenario run"
        );
        let active_at = evidence
            .fault_active_at_ms
            .context("force-read fault evidence lacks activation time")?;
        let workload_started = evidence
            .workload_started_at_ms
            .context("force-read fault evidence lacks workload start time")?;
        let workload_ended = evidence
            .workload_ended_at_ms
            .context("force-read fault evidence lacks workload end time")?;
        let delete_started = evidence
            .fault_delete_started_at_ms
            .context("force-read fault evidence lacks fault-delete start time")?;
        ensure!(
            active_at == self.fault_active_from_ms
                && delete_started == self.fault_active_until_ms
                && active_at <= workload_started
                && workload_started <= workload_ended
                && workload_ended <= delete_started,
            "force-read window is not derived from the captured fault lifecycle"
        );
        let active_pods =
            unique_storage_fault_pods("activation", &evidence.pods_at_fault_activation)?;
        let workload_pods =
            unique_storage_fault_pods("workload", &evidence.pods_at_workload_snapshot)?;
        ensure!(
            !active_pods.is_empty() && active_pods == workload_pods,
            "force-read selected Pod identities changed while the fault was active"
        );
        let [active_snapshot] = evidence.active_snapshots.as_slice() else {
            anyhow::bail!("force-read fault evidence must contain one active snapshot")
        };
        let [workload_snapshot] = evidence.workload_snapshots.as_slice() else {
            anyhow::bail!("force-read fault evidence must contain one workload snapshot")
        };
        ensure!(
            active_snapshot.stage == "active"
                && workload_snapshot.stage == "after-workload"
                && active_snapshot.resource_kind == workload_snapshot.resource_kind
                && active_snapshot.resource_name == workload_snapshot.resource_name,
            "force-read fault snapshots do not identify one resource across the active window"
        );
        let resource_kind = active_snapshot
            .resource_kind
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .context("force-read active snapshot lacks a resource kind")?;
        ensure!(
            resource_kind == "iochaos",
            "force-read exact-quorum proof requires a RustFS volume IOChaos resource"
        );
        let name = active_snapshot
            .resource_name
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .context("force-read IOChaos snapshot lacks a resource name")?;
        validate_active_iochaos_snapshot(active_snapshot, name)?;
        validate_active_iochaos_snapshot(workload_snapshot, name)?;
        let resource_id = format!("{resource_kind}/{name}");
        let snapshot_id = sha256_bytes(&serde_json::to_vec(active_snapshot)?);
        Ok((
            active_pods.keys().cloned().collect(),
            snapshot_id,
            resource_id,
        ))
    }
}

fn validate_active_iochaos_snapshot(
    snapshot: &StorageFaultStatusSnapshot,
    expected_name: &str,
) -> Result<()> {
    ensure!(
        snapshot.dm_status.is_none(),
        "force-read IOChaos snapshot unexpectedly contains device-mapper status"
    );
    let resource = snapshot
        .chaos_status
        .as_ref()
        .context("force-read IOChaos snapshot lacks the captured resource")?;
    ensure!(
        resource
            .pointer("/metadata/name")
            .and_then(serde_json::Value::as_str)
            == Some(expected_name)
            && resource
                .pointer("/status/experiment/desiredPhase")
                .and_then(serde_json::Value::as_str)
                == Some("Run"),
        "force-read IOChaos snapshot does not identify the active resource"
    );
    let conditions = resource
        .pointer("/status/conditions")
        .and_then(serde_json::Value::as_array)
        .context("force-read IOChaos snapshot lacks status conditions")?;
    for (condition_type, expected_status) in [
        ("Selected", "True"),
        ("AllInjected", "True"),
        ("AllRecovered", "False"),
    ] {
        ensure!(
            conditions.iter().any(|condition| {
                condition.get("type").and_then(serde_json::Value::as_str) == Some(condition_type)
                    && condition.get("status").and_then(serde_json::Value::as_str)
                        == Some(expected_status)
            }),
            "force-read IOChaos snapshot lacks active {condition_type}={expected_status} status"
        );
    }
    Ok(())
}

fn unique_storage_fault_pods<'a>(
    stage: &str,
    pods: &'a [StorageFaultPodIdentity],
) -> Result<BTreeMap<String, &'a str>> {
    let mut identities = BTreeMap::new();
    for pod in pods {
        ensure!(
            !pod.name.trim().is_empty()
                && !pod.uid.trim().is_empty()
                && identities
                    .insert(pod.name.clone(), pod.uid.as_str())
                    .is_none(),
            "force-read {stage} fault evidence contains an empty or duplicate Pod identity"
        );
    }
    Ok(identities)
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShardInventoryEntry {
    pub fragment_id: String,
    pub bucket: String,
    pub object_key: String,
    pub version_id: String,
    pub drive_uuid: String,
    pub object_sha256: String,
    pub sha256: String,
    pub reference_state: FragmentReferenceState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FragmentReferenceState {
    ReferencedVersion,
    OrphanedUncommitted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ShardInventorySource {
    RustfsDiagnosticApi,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShardInventoryScanReceipt {
    pub snapshot_id: String,
    pub source: ShardInventorySource,
    pub api_revision: String,
    pub response_sha256: String,
    pub response_body: String,
    pub started_at_ms: u64,
    pub completed_at_ms: u64,
    pub observed_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RustfsShardInventoryResponse {
    pub bucket: String,
    pub drive_uuid: String,
    pub filesystem_uuid: String,
    pub start_cursor: Option<String>,
    pub end_cursor: String,
    pub exhausted: bool,
    pub total_count: usize,
    pub entries: Vec<ShardInventoryEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShardInventorySnapshot {
    pub schema_version: u8,
    pub identity: StorageRecoveryArtifactIdentity,
    pub receipt: ShardInventoryScanReceipt,
    pub volume: StorageVolumeIdentity,
    pub entry_count: usize,
    pub entries_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FragmentRecoverability {
    Committed,
    RecoverableUnknown,
    UncommittedDangling,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClassifiedVersionFragments {
    pub evidence_id: String,
    pub operation_id: Option<String>,
    pub object_key: String,
    pub version_id: String,
    pub recoverability: FragmentRecoverability,
    pub fragment_ids: Vec<String>,
}

impl ShardInventoryEntry {
    fn validate(&self) -> Result<()> {
        for (field, value) in [
            ("fragment id", self.fragment_id.as_str()),
            ("bucket", self.bucket.as_str()),
            ("object key", self.object_key.as_str()),
            ("version id", self.version_id.as_str()),
            ("drive UUID", self.drive_uuid.as_str()),
        ] {
            ensure!(!value.trim().is_empty(), "shard inventory {field} is empty");
        }
        validate_sha256("shard inventory object", &self.object_sha256)?;
        validate_sha256("shard inventory fragment", &self.sha256)
    }
}

impl ShardInventorySnapshot {
    pub fn from_complete_scan(
        identity: StorageRecoveryArtifactIdentity,
        volume: StorageVolumeIdentity,
        receipt: ShardInventoryScanReceipt,
    ) -> Result<Self> {
        let response = serde_json::from_str::<RustfsShardInventoryResponse>(&receipt.response_body)
            .context("decode captured RustFS shard-inventory response")?;
        let proof = Self {
            schema_version: STORAGE_RECOVERY_PROOF_SCHEMA_VERSION,
            identity,
            receipt,
            volume,
            entry_count: response.entries.len(),
            entries_sha256: inventory_entries_sha256(&response.entries)?,
        };
        proof.validate()?;
        Ok(proof)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == STORAGE_RECOVERY_PROOF_SCHEMA_VERSION,
            "unsupported shard-inventory schema version {}",
            self.schema_version
        );
        self.identity.validate()?;
        self.volume.validate()?;
        ensure!(
            !self.receipt.snapshot_id.trim().is_empty()
                && self.receipt.source == ShardInventorySource::RustfsDiagnosticApi
                && !self.receipt.api_revision.trim().is_empty()
                && self.receipt.started_at_ms > 0
                && self.receipt.started_at_ms < self.receipt.completed_at_ms
                && self.receipt.completed_at_ms == self.receipt.observed_at_ms
                && self.receipt.observed_at_ms >= self.volume.observed_at_ms,
            "shard inventory lacks a complete, ordered scan receipt"
        );
        validate_sha256(
            "shard inventory diagnostic response",
            &self.receipt.response_sha256,
        )?;
        ensure!(
            self.receipt.response_sha256 == sha256_bytes(self.receipt.response_body.as_bytes()),
            "shard inventory response digest does not match the captured RustFS response body"
        );
        let response = self.response()?;
        ensure!(
            response.bucket == self.identity.bucket
                && response.drive_uuid == self.volume.rustfs_drive_uuid
                && response.filesystem_uuid == self.volume.filesystem_uuid
                && response.start_cursor.is_none()
                && !response.end_cursor.trim().is_empty()
                && response.exhausted
                && response.total_count == response.entries.len(),
            "shard inventory response is not a complete server-scoped scan of the returned generation"
        );
        for entry in &response.entries {
            entry.validate()?;
            ensure!(
                entry.drive_uuid == self.volume.rustfs_drive_uuid
                    && entry.bucket == self.identity.bucket,
                "shard inventory entry is not located in the run bucket on the scanned drive"
            );
        }
        unique_fragments("shard-inventory", &response.entries)?;
        validate_sha256("shard inventory entries", &self.entries_sha256)?;
        ensure!(
            self.entry_count == response.entries.len()
                && self.entries_sha256 == inventory_entries_sha256(&response.entries)?,
            "shard inventory count or canonical entries digest does not match the complete scan"
        );
        Ok(())
    }

    fn response(&self) -> Result<RustfsShardInventoryResponse> {
        serde_json::from_str(&self.receipt.response_body)
            .context("decode captured RustFS shard-inventory response")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DanglingCleanupProof {
    pub schema_version: u8,
    pub identity: StorageRecoveryArtifactIdentity,
    pub returned_generation: StorageVolumeIdentity,
    pub before_inventory_snapshot_id: String,
    pub before_inventory_sha256: String,
    pub after_inventory_snapshot_id: String,
    pub after_inventory_sha256: String,
    pub cleanup_operation_id: String,
    pub writes_quiesced_at_ms: u64,
    pub started_at_ms: u64,
    pub completed_at_ms: u64,
    pub classified_versions: Vec<ClassifiedVersionFragments>,
}

impl DanglingCleanupProof {
    pub fn validate_against_stale_return(
        &self,
        stale_return: &StaleDiskReturnProof,
        before_inventory: &ShardInventorySnapshot,
        after_inventory: &ShardInventorySnapshot,
        history: &[OperationRecord],
    ) -> Result<()> {
        ensure!(
            self.schema_version == STORAGE_RECOVERY_PROOF_SCHEMA_VERSION,
            "unsupported dangling-cleanup proof schema version {}",
            self.schema_version
        );
        self.identity.validate()?;
        ensure!(
            self.identity.scenario == "stale-disk-return-detect",
            "dangling-cleanup proof is bound to the wrong scenario"
        );
        stale_return.validate_against_history(history)?;
        self.returned_generation.validate()?;
        ensure!(
            stale_return.identity == self.identity
                && stale_return.returned_generation == self.returned_generation,
            "dangling-cleanup proof is not bound to the validated stale-return generation"
        );
        ensure!(
            !self.cleanup_operation_id.trim().is_empty(),
            "dangling-cleanup operation id is empty"
        );
        before_inventory.validate()?;
        after_inventory.validate()?;
        let before_response = before_inventory.response()?;
        let after_response = after_inventory.response()?;
        ensure!(
            before_inventory.identity == self.identity
                && after_inventory.identity == self.identity
                && before_inventory.volume == self.returned_generation
                && after_inventory.volume == self.returned_generation
                && before_inventory.receipt.api_revision == after_inventory.receipt.api_revision,
            "dangling-cleanup inventories do not describe the validated returned stale generation"
        );
        ensure!(
            self.before_inventory_snapshot_id == before_inventory.receipt.snapshot_id
                && self.before_inventory_sha256 == before_inventory.entries_sha256
                && self.after_inventory_snapshot_id == after_inventory.receipt.snapshot_id
                && self.after_inventory_sha256 == after_inventory.entries_sha256
                && before_inventory.receipt.snapshot_id != after_inventory.receipt.snapshot_id
                && before_response.end_cursor != after_response.end_cursor,
            "dangling-cleanup proof does not reference two distinct complete inventory receipts"
        );
        validate_sha256(
            "pre-cleanup inventory reference",
            &self.before_inventory_sha256,
        )?;
        validate_sha256(
            "post-cleanup inventory reference",
            &self.after_inventory_sha256,
        )?;
        ensure!(
            self.writes_quiesced_at_ms > self.returned_generation.observed_at_ms
                && before_inventory.receipt.started_at_ms > self.writes_quiesced_at_ms
                && self.started_at_ms > before_inventory.receipt.completed_at_ms
                && self.started_at_ms - before_inventory.receipt.completed_at_ms
                    <= STORAGE_OBSERVATION_MAX_AGE_MS
                && self.completed_at_ms > self.started_at_ms
                && after_inventory.receipt.started_at_ms > self.completed_at_ms
                && after_inventory.receipt.completed_at_ms > after_inventory.receipt.started_at_ms
                && after_inventory.receipt.completed_at_ms - self.completed_at_ms
                    <= STORAGE_OBSERVATION_MAX_AGE_MS,
            "dangling-cleanup and complete inventory observations are not ordered after the stale return"
        );
        ensure!(
            history
                .iter()
                .filter(|record| {
                    record_matches_identity(record, &self.identity)
                        && is_object_mutation(record.kind)
                })
                .all(|record| {
                    valid_operation_interval(record)
                        && (record.ended_at_ms <= self.writes_quiesced_at_ms
                            || record.started_at_ms > after_inventory.receipt.completed_at_ms)
                }),
            "object mutation overlapped the quiesced inventory and dangling-cleanup window"
        );
        ensure!(
            !before_response.entries.is_empty(),
            "pre-cleanup shard inventory is empty"
        );
        let before = unique_fragments("pre-cleanup", &before_response.entries)?;
        let after = unique_fragments("post-cleanup", &after_response.entries)?;
        ensure!(
            !self.classified_versions.is_empty(),
            "dangling-cleanup validation requires fragment classifications"
        );
        let mut classified_fragment_ids = BTreeSet::new();
        let mut classified_versions = BTreeSet::new();
        let mut classification_evidence_ids = BTreeSet::new();
        let mut protected_operation_ids = BTreeSet::new();
        for version in &self.classified_versions {
            ensure!(
                !version.evidence_id.trim().is_empty()
                    && !version.object_key.trim().is_empty()
                    && !version.version_id.trim().is_empty()
                    && version.version_id != "null",
                "fragment classification has incomplete version identity"
            );
            ensure!(
                classification_evidence_ids.insert(version.evidence_id.as_str()),
                "fragment classification contains a duplicate evidence id"
            );
            ensure!(
                classified_versions
                    .insert((version.object_key.as_str(), version.version_id.as_str(),)),
                "fragment classification contains a duplicate object version"
            );
            validate_unique_nonempty("classified fragment id", &version.fragment_ids, true)?;
            let mut object_hashes = BTreeSet::new();
            let mut reference_states = BTreeSet::new();
            for fragment_id in &version.fragment_ids {
                ensure!(
                    classified_fragment_ids.insert(fragment_id.as_str()),
                    "version classifications reuse a fragment identity"
                );
                let Some(entry) = before.get(fragment_id) else {
                    anyhow::bail!(
                        "classified fragment {fragment_id:?} is absent from the pre-cleanup inventory"
                    )
                };
                ensure!(
                    entry.object_key == version.object_key
                        && entry.version_id == version.version_id,
                    "classified fragment does not match its inventory object/version identity"
                );
                object_hashes.insert(entry.object_sha256.as_str());
                reference_states.insert(entry.reference_state);
            }
            ensure!(
                object_hashes.len() == 1 && reference_states.len() == 1,
                "all fragments classified for one object version must carry one object hash and reference state"
            );
            let object_sha256 = object_hashes
                .first()
                .copied()
                .expect("non-empty fragment classification has one object hash");

            let operation = match version.operation_id.as_deref() {
                Some(operation_id) => {
                    ensure!(
                        !operation_id.trim().is_empty(),
                        "classified operation id is empty"
                    );
                    let matches = history
                        .iter()
                        .filter(|record| record.id == operation_id)
                        .collect::<Vec<_>>();
                    let [record] = matches.as_slice() else {
                        anyhow::bail!(
                            "classified version must match exactly one workload history operation"
                        )
                    };
                    ensure!(
                        record_matches_identity(record, &self.identity)
                            && is_object_commit(record.kind)
                            && valid_operation_interval(record)
                            && record.key.as_deref() == Some(version.object_key.as_str())
                            && record.value_sha256.as_deref() == Some(object_sha256)
                            && record.ended_at_ms <= self.writes_quiesced_at_ms,
                        "classified version is not bound to the matching pre-cleanup PUT or multipart completion"
                    );
                    Some(*record)
                }
                None => None,
            };

            match version.recoverability {
                FragmentRecoverability::Committed => {
                    let Some(record) = operation else {
                        anyhow::bail!("committed fragments require a workload operation")
                    };
                    ensure!(
                        reference_states.contains(&FragmentReferenceState::ReferencedVersion)
                            && record.outcome == OperationOutcome::Ok
                            && record
                                .http_status
                                .is_some_and(|status| (200..300).contains(&status))
                            && record.version_id.as_deref() == Some(version.version_id.as_str()),
                        "committed fragments are not backed by a successful versioned write"
                    );
                    ensure!(
                        protected_operation_ids.insert(record.id.as_str()),
                        "one committed/ambiguous operation backs multiple classifications"
                    );
                }
                FragmentRecoverability::RecoverableUnknown => {
                    let Some(record) = operation else {
                        anyhow::bail!("recoverable-unknown fragments require an ACK-loss operation")
                    };
                    let status_is_ambiguous = match record.outcome {
                        OperationOutcome::Timeout => record.http_status.is_none(),
                        OperationOutcome::Unknown => {
                            record.http_status.is_none_or(ambiguous_http_status)
                        }
                        OperationOutcome::Failed => {
                            record.http_status.is_none_or(ambiguous_http_status)
                        }
                        _ => false,
                    };
                    ensure!(
                        reference_states.contains(&FragmentReferenceState::ReferencedVersion)
                            && status_is_ambiguous
                            && record.version_id.as_deref().is_none_or(|version_id| {
                                version_id == "null" || version_id == version.version_id
                            }),
                        "recoverable-unknown fragments are not backed by an ambiguous write outcome"
                    );
                    if record
                        .version_id
                        .as_deref()
                        .is_none_or(|version_id| version_id == "null")
                    {
                        let possible_versions = before_response
                            .entries
                            .iter()
                            .filter(|entry| {
                                entry.object_key == version.object_key
                                    && entry.object_sha256 == object_sha256
                            })
                            .map(|entry| entry.version_id.as_str())
                            .collect::<BTreeSet<_>>();
                        ensure!(
                            possible_versions.len() == 1
                                && possible_versions.contains(version.version_id.as_str()),
                            "an ACK-loss write without a version id must map to exactly one inventory version"
                        );
                    }
                    ensure!(
                        protected_operation_ids.insert(record.id.as_str()),
                        "one committed/ambiguous operation backs multiple classifications"
                    );
                }
                FragmentRecoverability::UncommittedDangling => {
                    ensure!(
                        reference_states.contains(&FragmentReferenceState::OrphanedUncommitted),
                        "uncommitted-dangling fragments lack authoritative orphan classification"
                    );
                    if let Some(record) = operation {
                        ensure!(
                            record.outcome == OperationOutcome::Failed
                                && record.http_status.is_some_and(|status| {
                                    (400..500).contains(&status) && status != 408
                                })
                                && record.version_id.as_deref().is_none_or(|version_id| {
                                    version_id == "null" || version_id == version.version_id
                                }),
                            "uncommitted-dangling fragments are not backed by a failed write"
                        );
                    }
                }
            }
        }
        ensure!(
            self.classified_versions
                .iter()
                .any(|version| { version.recoverability == FragmentRecoverability::Committed })
                && self.classified_versions.iter().any(|version| {
                    version.recoverability == FragmentRecoverability::RecoverableUnknown
                })
                && self.classified_versions.iter().any(|version| {
                    version.recoverability == FragmentRecoverability::UncommittedDangling
                }),
            "ACK-loss cleanup must exercise committed, recoverable-unknown, and uncommitted-dangling versions"
        );
        ensure!(
            classified_fragment_ids
                == before
                    .keys()
                    .map(|fragment_id| fragment_id.as_str())
                    .collect::<BTreeSet<_>>(),
            "fragment classifications do not cover the complete pre-cleanup inventory"
        );
        let inventory_versions = before_response
            .entries
            .iter()
            .map(|entry| {
                (
                    entry.object_key.as_str(),
                    entry.version_id.as_str(),
                    entry.object_sha256.as_str(),
                )
            })
            .collect::<BTreeSet<_>>();
        let inventory_objects = before_response
            .entries
            .iter()
            .map(|entry| (entry.object_key.as_str(), entry.object_sha256.as_str()))
            .collect::<BTreeSet<_>>();
        let mut relevant_protected_operations = BTreeSet::new();
        for record in history.iter().filter(|record| {
            record_matches_identity(record, &self.identity)
                && is_object_commit(record.kind)
                && write_may_have_committed(record)
                && valid_operation_interval(record)
                && record.ended_at_ms <= self.writes_quiesced_at_ms
        }) {
            let key = record
                .key
                .as_deref()
                .context("a possibly committed write lacks an object key")?;
            let object_sha256 = record
                .value_sha256
                .as_deref()
                .context("a possibly committed write lacks a content hash")?;
            let matches_inventory = match record.version_id.as_deref() {
                Some(version_id) if version_id != "null" => {
                    inventory_versions.contains(&(key, version_id, object_sha256))
                }
                _ => inventory_objects.contains(&(key, object_sha256)),
            };
            if matches_inventory {
                ensure!(
                    relevant_protected_operations.insert(record.id.as_str()),
                    "workload history contains a duplicate relevant operation id"
                );
            }
        }
        ensure!(
            protected_operation_ids == relevant_protected_operations,
            "fragment classifications do not exactly cover successful and ambiguous writes represented in the inventory"
        );
        ensure!(
            after_response
                .entries
                .iter()
                .all(|entry| before.get(&entry.fragment_id) == Some(&entry)),
            "dangling cleanup changed or introduced a fragment instead of only removing one"
        );
        let mut removed_dangling = false;
        for version in &self.classified_versions {
            let protected = version.recoverability != FragmentRecoverability::UncommittedDangling;
            for fragment_id in &version.fragment_ids {
                let retained = after.get(fragment_id) == before.get(fragment_id);
                if protected {
                    ensure!(
                        retained,
                        "dangling cleanup removed a committed or recoverable-unknown fragment {fragment_id:?}"
                    );
                } else if !retained {
                    removed_dangling = true;
                }
            }
        }
        ensure!(
            removed_dangling,
            "dangling-cleanup case has no proven uncommitted-dangling fragment removal signal"
        );
        Ok(())
    }
}

fn is_object_commit(kind: OperationKind) -> bool {
    matches!(
        kind,
        OperationKind::Put | OperationKind::CompleteMultipartUpload
    )
}

fn is_object_mutation(kind: OperationKind) -> bool {
    matches!(
        kind,
        OperationKind::Put
            | OperationKind::Delete
            | OperationKind::CreateMultipartUpload
            | OperationKind::UploadPart
            | OperationKind::CompleteMultipartUpload
            | OperationKind::AbortMultipartUpload
    )
}

fn valid_operation_interval(record: &OperationRecord) -> bool {
    record.started_at_ms > 0 && record.started_at_ms <= record.ended_at_ms
}

fn ambiguous_http_status(status: u16) -> bool {
    status == 408 || (500..600).contains(&status)
}

fn write_may_have_committed(record: &OperationRecord) -> bool {
    match record.outcome {
        OperationOutcome::Ok | OperationOutcome::Timeout | OperationOutcome::Unknown => true,
        OperationOutcome::Failed => record.http_status.is_none_or(ambiguous_http_status),
        OperationOutcome::NotFound => false,
    }
}

fn record_matches_identity(
    record: &OperationRecord,
    identity: &StorageRecoveryArtifactIdentity,
) -> bool {
    record.run_id.as_deref() == Some(identity.run_id.as_str())
        && record.scenario == identity.scenario
        && record.bucket == identity.bucket
}

fn unique_fragments<'a>(
    label: &str,
    entries: &'a [ShardInventoryEntry],
) -> Result<BTreeMap<&'a String, &'a ShardInventoryEntry>> {
    let mut fragments = BTreeMap::new();
    for entry in entries {
        ensure!(
            fragments.insert(&entry.fragment_id, entry).is_none(),
            "{label} shard inventory contains duplicate fragment id {:?}",
            entry.fragment_id
        );
    }
    Ok(fragments)
}

fn inventory_entries_sha256(entries: &[ShardInventoryEntry]) -> Result<String> {
    let mut canonical = entries.to_vec();
    canonical.sort();
    let encoded = serde_json::to_vec(&canonical)?;
    Ok(sha256_bytes(&encoded))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn heal_state_rank(state: HealProgressState) -> u8 {
    match state {
        HealProgressState::Queued => 0,
        HealProgressState::Running => 1,
        HealProgressState::Completed | HealProgressState::Failed => 2,
    }
}

fn validate_unique_nonempty(label: &str, values: &[String], require_nonempty: bool) -> Result<()> {
    if require_nonempty {
        ensure!(!values.is_empty(), "{label} list is empty");
    }
    let mut unique = BTreeSet::new();
    for value in values {
        ensure!(
            !value.trim().is_empty() && unique.insert(value),
            "{label} list contains an empty or duplicate value"
        );
    }
    Ok(())
}

fn validate_sha256(label: &str, value: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{label} SHA-256 must be 64 lowercase hexadecimal characters"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fault::quorum::ErasureSetMember;

    const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const HASH_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn volume(generation: &str, observed_at_ms: u64) -> StorageVolumeIdentity {
        StorageVolumeIdentity {
            target_proof_sha256: HASH_A.to_string(),
            host_storage_proof_sha256: HASH_B.to_string(),
            rustfs_deployment_id: "deployment-1".to_string(),
            namespace: "fault-run".to_string(),
            tenant: "rustfs".to_string(),
            pod: "rustfs-0".to_string(),
            pod_uid: format!("pod-{generation}"),
            volume_name: "data-0".to_string(),
            persistent_volume_claim: "data-0-rustfs-0".to_string(),
            persistent_volume_claim_uid: format!("pvc-{generation}"),
            persistent_volume: format!("pv-{generation}"),
            persistent_volume_uid: format!("pv-uid-{generation}"),
            node: "worker-0".to_string(),
            node_uid: "node-0".to_string(),
            mount_path: "/data0".to_string(),
            canonical_device: format!("/dev/mapper/data-{generation}"),
            filesystem_uuid: format!("fs-{generation}"),
            rustfs_drive_uuid: format!("drive-{generation}"),
            pool_index: 0,
            set_index: 0,
            observed_at_ms,
        }
    }

    fn identity(scenario: &str) -> StorageRecoveryArtifactIdentity {
        StorageRecoveryArtifactIdentity {
            run_id: "run-1".to_string(),
            scenario: scenario.to_string(),
            case_name: format!("case-{scenario}"),
            bucket: "bucket-1".to_string(),
        }
    }

    fn empty_observation(
        replacement: &StorageVolumeIdentity,
        observed_at_ms: u64,
    ) -> EmptyVolumeObservation {
        let response = serde_json::to_string(&EmptyVolumeScanResponse {
            persistent_volume_uid: replacement.persistent_volume_uid.clone(),
            canonical_device: replacement.canonical_device.clone(),
            filesystem_uuid: replacement.filesystem_uuid.clone(),
            rustfs_process_can_access_volume: false,
            scan_started_at_ms: observed_at_ms - 1,
            scan_completed_at_ms: observed_at_ms,
            exhaustive: true,
            data_entries: vec![],
        })
        .expect("empty-volume scan response");
        EmptyVolumeObservation {
            observed_at_ms,
            persistent_volume_uid: replacement.persistent_volume_uid.clone(),
            canonical_device: replacement.canonical_device.clone(),
            filesystem_uuid: replacement.filesystem_uuid.clone(),
            rustfs_process_can_access_volume: false,
            data_entries: vec![],
            scan_response_sha256: sha256_bytes(response.as_bytes()),
            scan_response_body: response,
        }
    }

    fn absence_observation(
        generation: &StorageVolumeIdentity,
        observation_id: &str,
        watch_started_at_ms: u64,
    ) -> DiskAbsenceObservation {
        DiskAbsenceObservation {
            observation_id: observation_id.to_string(),
            detachment_operation_id: "detach-1".to_string(),
            persistent_volume_uid: generation.persistent_volume_uid.clone(),
            canonical_device: generation.canonical_device.clone(),
            filesystem_uuid: generation.filesystem_uuid.clone(),
            rustfs_drive_uuid: generation.rustfs_drive_uuid.clone(),
            target_proof_sha256: generation.target_proof_sha256.clone(),
            host_storage_proof_sha256: generation.host_storage_proof_sha256.clone(),
            watch_started_at_ms,
            watch_ended_at_ms: 400,
            controller_watch_had_no_reattach_event: true,
            node_watch_had_no_device_present_event: true,
        }
    }

    fn history_record(
        id: &str,
        scenario: &str,
        kind: OperationKind,
        key: &str,
        version_id: &str,
        value_sha256: Option<&str>,
        ended_at_ms: u64,
    ) -> OperationRecord {
        OperationRecord {
            id: id.to_string(),
            scenario: scenario.to_string(),
            run_id: Some("run-1".to_string()),
            kind,
            bucket: "bucket-1".to_string(),
            key: Some(key.to_string()),
            value_sha256: value_sha256.map(str::to_string),
            size_bytes: None,
            version_id: Some(version_id.to_string()),
            listed_keys: None,
            payload_ref: None,
            range: None,
            started_at_ms: ended_at_ms.saturating_sub(1),
            ended_at_ms,
            outcome: OperationOutcome::Ok,
            http_status: Some(200),
            error: None,
            durability_cohort: Some(DurabilityCohort::FaultActive),
            fault_window_relation: Some(FaultWindowRelation::DuringFault),
        }
    }

    fn stale_return_fixture() -> (StaleDiskReturnProof, Vec<OperationRecord>) {
        let original = volume("old", 100);
        let mut returned = original.clone();
        returned.pod_uid = "pod-returned".to_string();
        returned.observed_at_ms = 500;
        let history = vec![
            history_record(
                "stale-put",
                "stale-disk-return-detect",
                OperationKind::Put,
                "stale/key-a",
                "stale-version-a",
                Some(HASH_A),
                300,
            ),
            history_record(
                "stale-delete",
                "stale-disk-return-detect",
                OperationKind::Delete,
                "stale/key-b",
                "stale-version-b",
                None,
                350,
            ),
        ];
        let proof = StaleDiskReturnProof::prove(
            identity("stale-disk-return-detect"),
            original.clone(),
            returned,
            StaleDiskReturnEvidence {
                detached_at_ms: 200,
                mutation_window_ended_at_ms: 400,
                returned_at_ms: 450,
                detachment_operation_id: "detach-1".to_string(),
                reattachment_operation_id: "reattach-1".to_string(),
                absence_observations: vec![absence_observation(&original, "absence-watch", 190)],
                committed_mutations: vec![
                    CommittedMutationEvidence {
                        operation_id: "stale-put".to_string(),
                        kind: StaleMutationKind::Overwrite,
                        object_key: "stale/key-a".to_string(),
                        version_id: "stale-version-a".to_string(),
                        acknowledged_at_ms: 300,
                        absence_observation_id: "absence-watch".to_string(),
                    },
                    CommittedMutationEvidence {
                        operation_id: "stale-delete".to_string(),
                        kind: StaleMutationKind::DeleteMarker,
                        object_key: "stale/key-b".to_string(),
                        version_id: "stale-version-b".to_string(),
                        acknowledged_at_ms: 350,
                        absence_observation_id: "absence-watch".to_string(),
                    },
                ],
            },
            &history,
        )
        .expect("valid stale return fixture");
        (proof, history)
    }

    #[test]
    fn fresh_replacement_requires_new_empty_storage_in_the_same_slot() {
        let replacement = volume("new", 300);
        let proof = FreshVolumeReplacementProof::prove(
            identity("fresh-volume-replacement"),
            volume("old", 100),
            replacement.clone(),
            empty_observation(&replacement, 200),
        )
        .expect("valid replacement");

        assert_eq!(proof.replacement.rustfs_drive_uuid, "drive-new");

        let mut reused = volume("old", 300);
        reused.pod_uid = "pod-new".to_string();
        let reused_empty = empty_observation(&reused, 200);
        let error = FreshVolumeReplacementProof::prove(
            identity("fresh-volume-replacement"),
            volume("old", 100),
            reused,
            reused_empty,
        )
        .expect_err("same storage generation");
        assert!(error.to_string().contains("PVC generation"));

        let replacement = volume("new", 300);
        let mut unrelated_empty = empty_observation(&replacement, 200);
        unrelated_empty.filesystem_uuid = "fs-unrelated".to_string();
        assert!(
            FreshVolumeReplacementProof::prove(
                identity("fresh-volume-replacement"),
                volume("old", 100),
                replacement.clone(),
                unrelated_empty,
            )
            .is_err()
        );

        let mut fabricated_empty = empty_observation(&replacement, 200);
        let mut raw =
            serde_json::from_str::<EmptyVolumeScanResponse>(&fabricated_empty.scan_response_body)
                .expect("empty-volume scan response");
        raw.exhaustive = false;
        fabricated_empty.scan_response_body =
            serde_json::to_string(&raw).expect("empty-volume scan response");
        fabricated_empty.scan_response_sha256 =
            sha256_bytes(fabricated_empty.scan_response_body.as_bytes());
        assert!(
            FreshVolumeReplacementProof::prove(
                identity("fresh-volume-replacement"),
                volume("old", 100),
                replacement,
                fabricated_empty,
            )
            .is_err(),
            "a self-reported empty Vec cannot replace one exhaustive host scan"
        );
    }

    #[test]
    fn storage_recovery_case_matrix_has_five_distinct_qualified_variants() {
        assert_eq!(StorageRecoveryCase::ALL.len(), 5);
        assert_eq!(
            StorageRecoveryCase::ALL
                .iter()
                .filter(|case| case.scenario() == "fresh-volume-replacement")
                .count(),
            2
        );
        assert_eq!(
            StorageRecoveryCase::ALL
                .iter()
                .filter(|case| case.scenario() == "on-disk-bitrot")
                .count(),
            2
        );
        assert_eq!(StorageRecoveryCase::StaleDiskReturn.heal_mode(), None);
        assert_eq!(
            StorageRecoveryCase::FreshVolumeReplacementAutomaticReplacement.heal_mode(),
            Some(HealMode::AutomaticReplacement)
        );
    }

    #[test]
    fn fresh_replacement_rejects_emptiness_observed_after_adoption() {
        let replacement = volume("new", 300);
        let mut empty = empty_observation(&replacement, 200);
        empty.rustfs_process_can_access_volume = true;
        let error = FreshVolumeReplacementProof::prove(
            identity("fresh-volume-replacement"),
            volume("old", 100),
            replacement,
            empty,
        )
        .expect_err("RustFS already mounted replacement");
        assert!(error.to_string().contains("before RustFS can access"));
    }

    #[test]
    fn stale_return_requires_the_original_generation_and_commits_while_absent() {
        let original = volume("old", 100);
        let mut returned = original.clone();
        returned.pod_uid = "pod-returned".to_string();
        returned.observed_at_ms = 500;
        let absence = vec![absence_observation(&original, "absence-watch", 190)];
        let history = vec![
            history_record(
                "put-1",
                "stale-disk-return-detect",
                OperationKind::Put,
                "key-a",
                "version-a",
                Some(HASH_A),
                300,
            ),
            history_record(
                "mpu-2",
                "stale-disk-return-detect",
                OperationKind::CompleteMultipartUpload,
                "key-mpu",
                "version-mpu",
                Some(HASH_B),
                325,
            ),
            history_record(
                "delete-2",
                "stale-disk-return-detect",
                OperationKind::Delete,
                "key-b",
                "version-b",
                None,
                350,
            ),
        ];

        let proof = StaleDiskReturnProof::prove(
            identity("stale-disk-return-detect"),
            original.clone(),
            returned,
            StaleDiskReturnEvidence {
                detached_at_ms: 200,
                mutation_window_ended_at_ms: 400,
                returned_at_ms: 450,
                detachment_operation_id: "detach-1".to_string(),
                reattachment_operation_id: "reattach-1".to_string(),
                absence_observations: absence,
                committed_mutations: vec![
                    CommittedMutationEvidence {
                        operation_id: "put-1".to_string(),
                        kind: StaleMutationKind::Overwrite,
                        object_key: "key-a".to_string(),
                        version_id: "version-a".to_string(),
                        acknowledged_at_ms: 300,
                        absence_observation_id: "absence-watch".to_string(),
                    },
                    CommittedMutationEvidence {
                        operation_id: "mpu-2".to_string(),
                        kind: StaleMutationKind::Overwrite,
                        object_key: "key-mpu".to_string(),
                        version_id: "version-mpu".to_string(),
                        acknowledged_at_ms: 325,
                        absence_observation_id: "absence-watch".to_string(),
                    },
                    CommittedMutationEvidence {
                        operation_id: "delete-2".to_string(),
                        kind: StaleMutationKind::DeleteMarker,
                        object_key: "key-b".to_string(),
                        version_id: "version-b".to_string(),
                        acknowledged_at_ms: 350,
                        absence_observation_id: "absence-watch".to_string(),
                    },
                ],
            },
            &history,
        )
        .expect("valid stale return");

        let mut omitted_multipart = proof.clone();
        omitted_multipart
            .committed_mutations
            .retain(|mutation| mutation.operation_id != "mpu-2");
        assert!(
            omitted_multipart
                .validate_against_history(&history)
                .is_err(),
            "a successful multipart completion during absence must be covered exactly"
        );

        let mut started_while_attached = history.clone();
        started_while_attached[0].started_at_ms = 150;
        assert!(
            proof
                .validate_against_history(&started_while_attached)
                .is_err(),
            "a request started before detachment must not prove an absent-disk mutation"
        );

        let mut inverted_absence_mutation = history.clone();
        inverted_absence_mutation[0].started_at_ms = 301;
        assert!(
            proof
                .validate_against_history(&inverted_absence_mutation)
                .is_err(),
            "an inverted request interval cannot prove a mutation during disk absence"
        );

        let error = StaleDiskReturnProof::prove(
            identity("stale-disk-return-detect"),
            original,
            volume("new", 500),
            StaleDiskReturnEvidence {
                detached_at_ms: 200,
                mutation_window_ended_at_ms: 400,
                returned_at_ms: 450,
                detachment_operation_id: "detach-1".to_string(),
                reattachment_operation_id: "reattach-1".to_string(),
                absence_observations: vec![absence_observation(
                    &volume("old", 100),
                    "absence-watch",
                    190,
                )],
                committed_mutations: vec![CommittedMutationEvidence {
                    operation_id: "put-1".to_string(),
                    kind: StaleMutationKind::Overwrite,
                    object_key: "key-a".to_string(),
                    version_id: "version-a".to_string(),
                    acknowledged_at_ms: 300,
                    absence_observation_id: "absence-watch".to_string(),
                }],
            },
            &history[..1],
        )
        .expect_err("new disk is not the stale generation");
        assert!(error.to_string().contains("detached storage generation"));

        let mut reconnected = absence_observation(&volume("old", 100), "absence-watch", 190);
        reconnected.controller_watch_had_no_reattach_event = false;
        let history = vec![
            history_record(
                "put-1",
                "stale-disk-return-detect",
                OperationKind::Put,
                "key-a",
                "version-a",
                Some(HASH_A),
                300,
            ),
            history_record(
                "delete-2",
                "stale-disk-return-detect",
                OperationKind::Delete,
                "key-b",
                "version-b",
                None,
                350,
            ),
        ];
        let original = volume("old", 100);
        let mut returned = original.clone();
        returned.observed_at_ms = 500;
        assert!(
            StaleDiskReturnProof::prove(
                identity("stale-disk-return-detect"),
                original,
                returned,
                StaleDiskReturnEvidence {
                    detached_at_ms: 200,
                    mutation_window_ended_at_ms: 400,
                    returned_at_ms: 450,
                    detachment_operation_id: "detach-1".to_string(),
                    reattachment_operation_id: "reattach-1".to_string(),
                    absence_observations: vec![reconnected],
                    committed_mutations: vec![
                        CommittedMutationEvidence {
                            operation_id: "put-1".to_string(),
                            kind: StaleMutationKind::Overwrite,
                            object_key: "key-a".to_string(),
                            version_id: "version-a".to_string(),
                            acknowledged_at_ms: 300,
                            absence_observation_id: "absence-watch".to_string(),
                        },
                        CommittedMutationEvidence {
                            operation_id: "delete-2".to_string(),
                            kind: StaleMutationKind::DeleteMarker,
                            object_key: "key-b".to_string(),
                            version_id: "version-b".to_string(),
                            acknowledged_at_ms: 350,
                            absence_observation_id: "absence-watch".to_string(),
                        },
                    ],
                },
                &history,
            )
            .is_err()
        );
    }

    #[test]
    fn bitrot_proof_requires_stable_mapping_and_reversible_mutation() {
        let history = vec![history_record(
            "put-bitrot",
            "on-disk-bitrot",
            OperationKind::Put,
            "bitrot/key",
            "version-1",
            Some(HASH_A),
            90,
        )];
        let mapping_response = serde_json::to_string(&RustfsShardMutationMappingResponse {
            bucket: "bucket-1".to_string(),
            object_key: "bitrot/key".to_string(),
            version_id: "version-1".to_string(),
            object_sha256: HASH_A.to_string(),
            drive_uuid: "drive-old".to_string(),
            shard_path: "/data0/.rustfs/shard".to_string(),
            shard_device_id: "259:0".to_string(),
            shard_inode: 42,
            shard_size_bytes: 8192,
        })
        .expect("shard mapping response");
        let path_response = serde_json::to_string(&Openat2PathResolutionReceipt {
            method: ShardPathResolutionMethod::Openat2BeneathNoSymlinksNoXdev,
            requested_path: "/data0/.rustfs/shard".to_string(),
            canonical_mount_path: "/data0".to_string(),
            mount_canonical_device: "/dev/mapper/data-old".to_string(),
            mount_filesystem_uuid: "fs-old".to_string(),
            resolved_path: "/data0/.rustfs/shard".to_string(),
            mount_device_id: "259:0".to_string(),
            returned_fd_device_id: "259:0".to_string(),
            returned_fd_inode: 42,
        })
        .expect("openat2 path receipt");
        let host_mutation_response = serde_json::to_string(&ShardMutationHostReceipt {
            shard_path: "/data0/.rustfs/shard".to_string(),
            shard_device_id: "259:0".to_string(),
            shard_inode: 42,
            shard_size_bytes: 8192,
            byte_offset: 4096,
            byte_length: 1,
            original_sha256: HASH_A.to_string(),
            mutated_sha256: HASH_B.to_string(),
            rollback_sha256: HASH_A.to_string(),
            original_observed_at_ms: 200,
            pwrite_completed_at_ms: 201,
            mutation_fsync_completed_at_ms: 201,
            mutation_fstat_observed_at_ms: 201,
            mutated_readback_at_ms: 201,
            rollback_pwrite_completed_at_ms: 202,
            rollback_fsync_completed_at_ms: 202,
            rollback_fstat_observed_at_ms: 202,
            rollback_readback_at_ms: 202,
            pwrite_bytes: 1,
            rollback_pwrite_bytes: 1,
            mutation_fsync_succeeded: true,
            rollback_fsync_succeeded: true,
            target_proof_sha256: HASH_A.to_string(),
            host_storage_proof_sha256: HASH_B.to_string(),
        })
        .expect("host mutation receipt");
        let proof = ShardMutationProof {
            schema_version: STORAGE_RECOVERY_PROOF_SCHEMA_VERSION,
            identity: identity("on-disk-bitrot"),
            mapping_source: ShardMappingSource::RustfsDiagnosticApi,
            mapping_api_revision: "v1".to_string(),
            mapping_response_sha256: sha256_bytes(mapping_response.as_bytes()),
            mapping_response_body: mapping_response,
            object_key: "bitrot/key".to_string(),
            version_id: "version-1".to_string(),
            expected_object_sha256: HASH_A.to_string(),
            volume: volume("old", 100),
            shard_path: "/data0/.rustfs/shard".to_string(),
            shard_device_id: "259:0".to_string(),
            shard_inode: 42,
            shard_size_bytes: 8192,
            path_containment: ShardPathContainmentProof {
                observed_at_ms: 200,
                resolver_evidence_sha256: sha256_bytes(path_response.as_bytes()),
                resolver_response_body: path_response,
                target_proof_sha256: HASH_A.to_string(),
                host_storage_proof_sha256: HASH_B.to_string(),
            },
            byte_offset: 4096,
            byte_length: 1,
            original_sha256: HASH_A.to_string(),
            mutated_sha256: HASH_B.to_string(),
            host_mutation_evidence: Some(ShardMutationHostEvidence {
                response_sha256: sha256_bytes(host_mutation_response.as_bytes()),
                response_body: host_mutation_response,
            }),
            rollback: ShardRollbackObservation {
                shard_path: "/data0/.rustfs/shard".to_string(),
                shard_device_id: "259:0".to_string(),
                shard_inode: 42,
                shard_size_bytes: 8192,
                observed_sha256: HASH_A.to_string(),
                observed_at_ms: 202,
                target_proof_sha256: HASH_A.to_string(),
                host_storage_proof_sha256: HASH_B.to_string(),
            },
            mapped_at_ms: 200,
            mutated_at_ms: 201,
        };
        proof
            .validate_against_history(&history)
            .expect("valid bitrot proof");

        let mut inverted_commit = history.clone();
        inverted_commit[0].started_at_ms = 91;
        assert!(
            proof.validate_against_history(&inverted_commit).is_err(),
            "an inverted write interval cannot prove that the mapped shard version existed"
        );

        let mut null_version = proof.clone();
        null_version.version_id = "null".to_string();
        assert!(null_version.validate_against_history(&history).is_err());

        let mut out_of_bounds = proof.clone();
        out_of_bounds.byte_length = 8193;
        assert!(out_of_bounds.validate_against_history(&history).is_err());

        let mut false_rollback = proof.clone();
        false_rollback.rollback.observed_sha256 = HASH_B.to_string();
        assert!(false_rollback.validate_against_history(&history).is_err());

        let mut unsafe_resolution = proof.clone();
        let mut unsafe_receipt = serde_json::from_str::<Openat2PathResolutionReceipt>(
            &unsafe_resolution.path_containment.resolver_response_body,
        )
        .expect("openat2 path receipt");
        unsafe_receipt.method = ShardPathResolutionMethod::CanonicalizeOnly;
        unsafe_resolution.path_containment.resolver_response_body =
            serde_json::to_string(&unsafe_receipt).expect("openat2 path receipt");
        unsafe_resolution.path_containment.resolver_evidence_sha256 = sha256_bytes(
            unsafe_resolution
                .path_containment
                .resolver_response_body
                .as_bytes(),
        );
        assert!(
            unsafe_resolution
                .validate_against_history(&history)
                .is_err(),
            "a shard reached through a symlink or mount crossing must be rejected"
        );

        let mut no_host_receipt = proof.clone();
        no_host_receipt.host_mutation_evidence = None;
        assert!(
            no_host_receipt.validate_against_history(&history).is_err(),
            "serialized A/B/A hashes cannot substitute for a host-helper mutation receipt"
        );

        let mut no_persisted_mutation = proof.clone();
        let host_evidence = no_persisted_mutation
            .host_mutation_evidence
            .as_mut()
            .expect("host mutation evidence");
        let mut receipt =
            serde_json::from_str::<ShardMutationHostReceipt>(&host_evidence.response_body)
                .expect("host mutation receipt");
        receipt.mutation_fsync_succeeded = false;
        host_evidence.response_body =
            serde_json::to_string(&receipt).expect("host mutation receipt");
        host_evidence.response_sha256 = sha256_bytes(host_evidence.response_body.as_bytes());
        assert!(
            no_persisted_mutation
                .validate_against_history(&history)
                .is_err(),
            "a failed fsync cannot prove an on-disk bitrot mutation"
        );

        let mut conflicting_history = history.clone();
        conflicting_history.push(history_record(
            "put-bitrot-conflict",
            "on-disk-bitrot",
            OperationKind::Put,
            "bitrot/key",
            "version-1",
            Some(HASH_B),
            95,
        ));
        assert!(
            proof
                .validate_against_history(&conflicting_history)
                .is_err(),
            "one immutable version identity cannot have two committed content hashes"
        );

        let mut foreign_bucket = proof.clone();
        let mut mapping = serde_json::from_str::<RustfsShardMutationMappingResponse>(
            &foreign_bucket.mapping_response_body,
        )
        .expect("shard mapping response");
        mapping.bucket = "bucket-foreign".to_string();
        foreign_bucket.mapping_response_body =
            serde_json::to_string(&mapping).expect("shard mapping response");
        foreign_bucket.mapping_response_sha256 =
            sha256_bytes(foreign_bucket.mapping_response_body.as_bytes());
        assert!(
            foreign_bucket.validate_against_history(&history).is_err(),
            "a same-key mapping from another bucket cannot identify the mutated shard"
        );

        let mut inferred_path = proof;
        inferred_path.shard_path = "/tmp/guessed-shard".to_string();
        assert!(inferred_path.validate_against_history(&history).is_err());
    }

    #[test]
    fn heal_progress_must_be_monotonic_and_terminal() {
        let observer = HealObserverIdentity::AdminOperation {
            operation_id: "heal-1".to_string(),
        };
        let mut samples = vec![
            HealProgressSample {
                schema_version: STORAGE_RECOVERY_PROOF_SCHEMA_VERSION,
                identity: identity("fresh-volume-replacement"),
                observer: observer.clone(),
                observed_at_ms: 110,
                state: HealProgressState::Running,
                scanned: 10,
                repaired: 1,
                failed: 0,
                status_evidence: None,
            },
            HealProgressSample {
                schema_version: STORAGE_RECOVERY_PROOF_SCHEMA_VERSION,
                identity: identity("fresh-volume-replacement"),
                observer: observer.clone(),
                observed_at_ms: 200,
                state: HealProgressState::Completed,
                scanned: 20,
                repaired: 2,
                failed: 0,
                status_evidence: None,
            },
        ];
        for sample in &mut samples {
            let response = serde_json::to_string(&RustfsHealStatusResponse {
                observer: sample.observer.clone(),
                observed_at_ms: sample.observed_at_ms,
                state: sample.state,
                scanned: sample.scanned,
                repaired: sample.repaired,
                failed: sample.failed,
                cluster_definitive: true,
                target_drive_uuid: Some("drive-new".to_string()),
                pool_index: 0,
                set_index: 0,
            })
            .expect("heal status response");
            sample.status_evidence = Some(HealStatusEvidence {
                api_revision: "v1".to_string(),
                response_sha256: sha256_bytes(response.as_bytes()),
                response_body: response,
            });
        }
        let summary = HealSummary {
            schema_version: STORAGE_RECOVERY_PROOF_SCHEMA_VERSION,
            identity: identity("fresh-volume-replacement"),
            case: StorageRecoveryCase::FreshVolumeReplacementAdminDeep,
            observer,
            mode: HealMode::AdminDeep,
            target_drive_uuid: Some("drive-new".to_string()),
            pool_index: 0,
            set_index: 0,
            cluster_definitive: true,
            started_at_ms: 100,
            completed_at_ms: 200,
            scanned: 20,
            repaired: 2,
            failed: 0,
            state: HealProgressState::Completed,
        };
        summary
            .validate_progress(&samples, Some(("drive-new", 0, 0)))
            .expect("valid heal progress");

        let mut regressed = samples.clone();
        regressed[1].repaired = 0;
        assert!(
            summary
                .validate_progress(&regressed, Some(("drive-new", 0, 0)))
                .is_err()
        );

        assert!(
            summary
                .validate_progress(&samples, Some(("drive-unrelated", 0, 0)))
                .is_err()
        );
        let mut wrong_qualified_variant = summary.clone();
        wrong_qualified_variant.case =
            StorageRecoveryCase::FreshVolumeReplacementAutomaticReplacement;
        assert!(
            wrong_qualified_variant
                .validate_progress(&samples, Some(("drive-new", 0, 0)))
                .is_err()
        );
        let mut missing_status = samples.clone();
        missing_status[0].status_evidence = None;
        assert!(
            summary
                .validate_progress(&missing_status, Some(("drive-new", 0, 0)))
                .is_err(),
            "self-reported heal counters require a captured RustFS status response"
        );
        let mut forged_status = samples.clone();
        let evidence = forged_status[1]
            .status_evidence
            .as_mut()
            .expect("heal status evidence");
        let mut response =
            serde_json::from_str::<RustfsHealStatusResponse>(&evidence.response_body)
                .expect("heal status response");
        response.repaired = 99;
        evidence.response_body = serde_json::to_string(&response).expect("heal status response");
        evidence.response_sha256 = sha256_bytes(evidence.response_body.as_bytes());
        assert!(
            summary
                .validate_progress(&forged_status, Some(("drive-new", 0, 0)))
                .is_err(),
            "heal progress must be derived from the captured RustFS status body"
        );
        let mut no_op = summary.clone();
        no_op.scanned = 0;
        no_op.repaired = 0;
        let mut no_op_samples = samples;
        no_op_samples[0].scanned = 0;
        no_op_samples[0].repaired = 0;
        no_op_samples[1].scanned = 0;
        no_op_samples[1].repaired = 0;
        assert!(
            no_op
                .validate_progress(&no_op_samples, Some(("drive-new", 0, 0)))
                .is_err()
        );
    }

    #[test]
    fn force_read_leaves_exact_quorum_and_requires_repaired_shard() {
        let shape = ErasureSetShape {
            pool_index: 0,
            set_index: 0,
            server_count: 8,
            volumes_per_server: 1,
            total_shards: 8,
            payload_data_shards: 4,
            payload_parity_shards: 4,
        };
        let membership = ErasureSetMembership::from_runtime(
            &shape,
            (0..8)
                .map(|index| ErasureSetMember {
                    pod_name: format!("rustfs-{index}"),
                    server_endpoint: format!("http://rustfs-{index}:9000"),
                    shard_ids: vec![format!("drive-{index}")],
                })
                .collect(),
        )
        .expect("membership");
        let selected_pods = (0..4)
            .map(|index| format!("rustfs-{index}"))
            .collect::<Vec<_>>();
        let mut committed = history_record(
            "put-1",
            "fresh-volume-replacement",
            OperationKind::Put,
            "key",
            "version-1",
            Some(HASH_A),
            250,
        );
        committed.durability_cohort = Some(DurabilityCohort::PreFault);
        // Recorder cannot label BeforeFault until the future fault boundary is
        // known; the PreFault cohort plus the proof timestamp supplies it.
        committed.fault_window_relation = None;
        let history = vec![
            committed,
            history_record(
                "get-1",
                "fresh-volume-replacement",
                OperationKind::Get,
                "key",
                "version-1",
                Some(HASH_A),
                350,
            ),
        ];
        let mapping_response = serde_json::to_string(&RustfsVersionShardMappingResponse {
            bucket: "bucket-1".to_string(),
            object_key: "key".to_string(),
            version_id: "version-1".to_string(),
            object_sha256: HASH_A.to_string(),
            pool_index: 0,
            set_index: 0,
            shard_ids: (0..8).map(|index| format!("drive-{index}")).collect(),
        })
        .expect("mapping response");
        let mapping_observations = vec![VersionShardMappingObservation {
            schema_version: STORAGE_RECOVERY_PROOF_SCHEMA_VERSION,
            identity: identity("fresh-volume-replacement"),
            observation_id: "mapping-1".to_string(),
            source: ShardMappingSource::RustfsDiagnosticApi,
            api_revision: "v1".to_string(),
            response_sha256: sha256_bytes(mapping_response.as_bytes()),
            response_body: mapping_response,
            target_proof_sha256: HASH_A.to_string(),
            observed_at_ms: 299,
        }];
        let active_snapshot = StorageFaultStatusSnapshot {
            stage: "active".to_string(),
            resource_kind: Some("iochaos".to_string()),
            resource_name: Some("force-read-fault".to_string()),
            chaos_status: Some(serde_json::json!({
                "metadata": {"name": "force-read-fault"},
                "status": {
                    "conditions": [
                        {"type": "Selected", "status": "True"},
                        {"type": "AllInjected", "status": "True"},
                        {"type": "AllRecovered", "status": "False"}
                    ],
                    "experiment": {"desiredPhase": "Run"}
                }
            })),
            dm_status: None,
        };
        let workload_snapshot = StorageFaultStatusSnapshot {
            stage: "after-workload".to_string(),
            ..active_snapshot.clone()
        };
        let fault_snapshot_id =
            sha256_bytes(&serde_json::to_vec(&active_snapshot).expect("active fault snapshot"));
        let fault_evidence_body = serde_json::to_string(&StorageFaultEvidenceResponse {
            scenario: "fresh-volume-replacement".to_string(),
            run_id: "run-1".to_string(),
            injected: true,
            active_during_workload: true,
            pods_at_fault_activation: selected_pods
                .iter()
                .map(|name| StorageFaultPodIdentity {
                    name: name.clone(),
                    uid: format!("uid-{name}"),
                })
                .collect(),
            pods_at_workload_snapshot: selected_pods
                .iter()
                .map(|name| StorageFaultPodIdentity {
                    name: name.clone(),
                    uid: format!("uid-{name}"),
                })
                .collect(),
            active_snapshots: vec![active_snapshot],
            workload_snapshots: vec![workload_snapshot],
            fault_active_at_ms: Some(300),
            workload_started_at_ms: Some(300),
            workload_ended_at_ms: Some(400),
            fault_delete_started_at_ms: Some(400),
        })
        .expect("fault evidence");
        let fault_evidence_sha256 = sha256_bytes(fault_evidence_body.as_bytes());
        let proof = ForceReadThroughProof {
            schema_version: STORAGE_RECOVERY_PROOF_SCHEMA_VERSION,
            identity: identity("fresh-volume-replacement"),
            shape,
            persisted_version_class: PersistedVersionClass::DataObject,
            all_shard_ids: (0..8).map(|index| format!("drive-{index}")).collect(),
            repaired_shard_id: "drive-7".to_string(),
            target_proof_sha256: HASH_A.to_string(),
            fault_evidence_sha256: fault_evidence_sha256.clone(),
            fault_evidence_body: Some(fault_evidence_body),
            unavailable_shards: (0..4)
                .map(|index| UnavailableShardObservation {
                    pod_name: format!("rustfs-{index}"),
                    drive_uuid: format!("drive-{index}"),
                    pool_index: 0,
                    set_index: 0,
                    fault_resource_id: "iochaos/force-read-fault".to_string(),
                    active_snapshot_id: fault_snapshot_id.clone(),
                    target_proof_sha256: HASH_A.to_string(),
                    fault_evidence_sha256: fault_evidence_sha256.clone(),
                    active_from_ms: 290,
                    active_until_ms: 410,
                })
                .collect(),
            fault_active_from_ms: 300,
            fault_active_until_ms: 400,
            probes: vec![ForcedReadProbe {
                operation_id: "get-1".to_string(),
                object_key: "key".to_string(),
                version_id: "version-1".to_string(),
                expected_sha256: HASH_A.to_string(),
                observed_sha256: HASH_A.to_string(),
                http_status: 200,
                observed_at_ms: 350,
                mapping_observation_id: "mapping-1".to_string(),
                active_fault_snapshot_id: fault_snapshot_id,
            }],
        };
        proof
            .validate_against_runtime(
                &membership,
                &selected_pods,
                &selected_pods,
                "drive-7",
                &history,
                &mapping_observations,
            )
            .expect("valid forced read");

        let mut missing_fault_receipt = proof.clone();
        missing_fault_receipt.fault_evidence_body = None;
        assert!(
            missing_fault_receipt
                .validate_against_runtime(
                    &membership,
                    &selected_pods,
                    &selected_pods,
                    "drive-7",
                    &history,
                    &mapping_observations,
                )
                .is_err(),
            "Pod names and active timestamps cannot replace captured fault evidence"
        );

        let mut inactive_fault = proof.clone();
        let mut raw = serde_json::from_str::<StorageFaultEvidenceResponse>(
            inactive_fault
                .fault_evidence_body
                .as_deref()
                .expect("fault evidence"),
        )
        .expect("fault evidence");
        *raw.active_snapshots[0]
            .chaos_status
            .as_mut()
            .expect("IOChaos resource")
            .pointer_mut("/status/conditions/1/status")
            .expect("AllInjected condition") = serde_json::json!("False");
        let inactive_snapshot_id =
            sha256_bytes(&serde_json::to_vec(&raw.active_snapshots[0]).expect("active snapshot"));
        let body = serde_json::to_string(&raw).expect("fault evidence");
        inactive_fault.fault_evidence_sha256 = sha256_bytes(body.as_bytes());
        inactive_fault.fault_evidence_body = Some(body);
        for shard in &mut inactive_fault.unavailable_shards {
            shard.fault_evidence_sha256 = inactive_fault.fault_evidence_sha256.clone();
            shard.active_snapshot_id = inactive_snapshot_id.clone();
        }
        inactive_fault.probes[0].active_fault_snapshot_id = inactive_snapshot_id;
        assert!(
            inactive_fault
                .validate_against_runtime(
                    &membership,
                    &selected_pods,
                    &selected_pods,
                    "drive-7",
                    &history,
                    &mapping_observations,
                )
                .is_err(),
            "a self-consistent but inactive IOChaos snapshot cannot prove forced reading"
        );

        let mut wrong_mapping = mapping_observations.clone();
        let mut wrong_response = serde_json::from_str::<RustfsVersionShardMappingResponse>(
            &wrong_mapping[0].response_body,
        )
        .expect("mapping response");
        wrong_response.set_index = 1;
        wrong_mapping[0].response_body =
            serde_json::to_string(&wrong_response).expect("mapping response");
        wrong_mapping[0].response_sha256 = sha256_bytes(wrong_mapping[0].response_body.as_bytes());
        assert!(
            proof
                .validate_against_runtime(
                    &membership,
                    &selected_pods,
                    &selected_pods,
                    "drive-7",
                    &history,
                    &wrong_mapping,
                )
                .is_err(),
            "the probe cannot self-assert membership in the repaired erasure set"
        );

        let mut wrong_bucket_mapping = mapping_observations.clone();
        let mut response = serde_json::from_str::<RustfsVersionShardMappingResponse>(
            &wrong_bucket_mapping[0].response_body,
        )
        .expect("mapping response");
        response.bucket = "bucket-foreign".to_string();
        wrong_bucket_mapping[0].response_body =
            serde_json::to_string(&response).expect("mapping response");
        wrong_bucket_mapping[0].response_sha256 =
            sha256_bytes(wrong_bucket_mapping[0].response_body.as_bytes());
        assert!(
            proof
                .validate_against_runtime(
                    &membership,
                    &selected_pods,
                    &selected_pods,
                    "drive-7",
                    &history,
                    &wrong_bucket_mapping,
                )
                .is_err(),
            "a same-key mapping from another bucket cannot select force-read shards"
        );

        let mut conflicting_commits = history.clone();
        let mut conflicting = history_record(
            "put-2",
            "fresh-volume-replacement",
            OperationKind::Put,
            "key",
            "version-1",
            Some(HASH_B),
            260,
        );
        conflicting.durability_cohort = Some(DurabilityCohort::PreFault);
        conflicting.fault_window_relation = None;
        conflicting_commits.push(conflicting);
        assert!(
            proof
                .validate_against_runtime(
                    &membership,
                    &selected_pods,
                    &selected_pods,
                    "drive-7",
                    &conflicting_commits,
                    &mapping_observations,
                )
                .is_err(),
            "conflicting successful writes for one immutable version identity must fail closed"
        );

        let mut contradictory_commit_window = history.clone();
        contradictory_commit_window[0].durability_cohort = Some(DurabilityCohort::FaultActive);
        contradictory_commit_window[0].fault_window_relation =
            Some(FaultWindowRelation::DuringFault);
        assert!(
            proof
                .validate_against_runtime(
                    &membership,
                    &selected_pods,
                    &selected_pods,
                    "drive-7",
                    &contradictory_commit_window,
                    &mapping_observations,
                )
                .is_err(),
            "a timestamp alone must not override contradictory recorder fault-window evidence"
        );

        let mut inverted_commit_interval = history.clone();
        inverted_commit_interval[0].started_at_ms = 301;
        assert!(
            proof
                .validate_against_runtime(
                    &membership,
                    &selected_pods,
                    &selected_pods,
                    "drive-7",
                    &inverted_commit_interval,
                    &mapping_observations,
                )
                .is_err(),
            "an inverted PUT interval cannot be made pre-fault by forging only its end time"
        );

        let mut inverted_probe_interval = history.clone();
        inverted_probe_interval[1].started_at_ms = 351;
        assert!(
            proof
                .validate_against_runtime(
                    &membership,
                    &selected_pods,
                    &selected_pods,
                    "drive-7",
                    &inverted_probe_interval,
                    &mapping_observations,
                )
                .is_err(),
            "an inverted GET interval cannot prove a read during the active fault window"
        );

        let mut contradictory_probe_window = history.clone();
        contradictory_probe_window[1].durability_cohort = Some(DurabilityCohort::PreFault);
        contradictory_probe_window[1].fault_window_relation =
            Some(FaultWindowRelation::BeforeFault);
        assert!(
            proof
                .validate_against_runtime(
                    &membership,
                    &selected_pods,
                    &selected_pods,
                    "drive-7",
                    &contradictory_probe_window,
                    &mapping_observations,
                )
                .is_err(),
            "timestamps cannot make a recorder-labeled pre-fault GET prove exact-quorum reading"
        );

        let mut swapped_pod_drives = proof.clone();
        let first_drive = swapped_pod_drives.unavailable_shards[0].drive_uuid.clone();
        swapped_pod_drives.unavailable_shards[0].drive_uuid =
            swapped_pod_drives.unavailable_shards[1].drive_uuid.clone();
        swapped_pod_drives.unavailable_shards[1].drive_uuid = first_drive;
        assert!(
            swapped_pod_drives
                .validate_against_runtime(
                    &membership,
                    &selected_pods,
                    &selected_pods,
                    "drive-7",
                    &history,
                    &mapping_observations,
                )
                .is_err(),
            "unavailable drive identities must remain paired with their owning Pods"
        );

        let mut too_many_online = proof.clone();
        too_many_online.unavailable_shards.pop();
        assert!(
            too_many_online
                .validate_against_runtime(
                    &membership,
                    &selected_pods,
                    &selected_pods,
                    "drive-7",
                    &history,
                    &mapping_observations,
                )
                .is_err()
        );

        let mut repaired_offline = proof.clone();
        repaired_offline.unavailable_shards[0].drive_uuid = "drive-7".to_string();
        assert!(
            repaired_offline
                .validate_against_runtime(
                    &membership,
                    &selected_pods,
                    &selected_pods,
                    "drive-7",
                    &history,
                    &mapping_observations,
                )
                .is_err()
        );

        let wrong_evidence_pods = vec!["rustfs-4".to_string()];
        assert!(
            proof
                .validate_against_runtime(
                    &membership,
                    &selected_pods,
                    &wrong_evidence_pods,
                    "drive-7",
                    &history,
                    &mapping_observations,
                )
                .is_err()
        );

        let mut self_consistent_wrong_value = proof.clone();
        self_consistent_wrong_value.probes[0].expected_sha256 = HASH_B.to_string();
        self_consistent_wrong_value.probes[0].observed_sha256 = HASH_B.to_string();
        let mut wrong_history = history.clone();
        wrong_history[1].value_sha256 = Some(HASH_B.to_string());
        assert!(
            self_consistent_wrong_value
                .validate_against_runtime(
                    &membership,
                    &selected_pods,
                    &selected_pods,
                    "drive-7",
                    &wrong_history,
                    &mapping_observations,
                )
                .is_err()
        );
    }

    #[test]
    fn dangling_cleanup_cannot_remove_committed_fragments() {
        let (stale_return, mut history) = stale_return_fixture();
        let committed = ShardInventoryEntry {
            fragment_id: "fragment-committed".to_string(),
            bucket: "bucket-1".to_string(),
            object_key: "key".to_string(),
            version_id: "version-1".to_string(),
            drive_uuid: "drive-old".to_string(),
            object_sha256: HASH_A.to_string(),
            sha256: HASH_B.to_string(),
            reference_state: FragmentReferenceState::ReferencedVersion,
        };
        let dangling = ShardInventoryEntry {
            fragment_id: "fragment-dangling".to_string(),
            bucket: "bucket-1".to_string(),
            object_key: "key".to_string(),
            version_id: "unknown-write".to_string(),
            drive_uuid: "drive-old".to_string(),
            object_sha256: HASH_C.to_string(),
            sha256: HASH_B.to_string(),
            reference_state: FragmentReferenceState::OrphanedUncommitted,
        };
        let unknown = ShardInventoryEntry {
            fragment_id: "fragment-unknown".to_string(),
            bucket: "bucket-1".to_string(),
            object_key: "key".to_string(),
            version_id: "ack-lost-version".to_string(),
            drive_uuid: "drive-old".to_string(),
            object_sha256: HASH_B.to_string(),
            sha256: HASH_A.to_string(),
            reference_state: FragmentReferenceState::ReferencedVersion,
        };
        let mut ack_lost = history_record(
            "ack-loss-1",
            "stale-disk-return-detect",
            OperationKind::Put,
            "key",
            "null",
            Some(HASH_B),
            530,
        );
        ack_lost.version_id = None;
        ack_lost.outcome = OperationOutcome::Timeout;
        ack_lost.http_status = None;
        history.push(history_record(
            "put-1",
            "stale-disk-return-detect",
            OperationKind::Put,
            "key",
            "version-1",
            Some(HASH_A),
            520,
        ));
        history.push(ack_lost);
        let inventory = |snapshot_id: &str,
                         cursor: &str,
                         observed_at_ms: u64,
                         entries: Vec<ShardInventoryEntry>| {
            let response = serde_json::to_string(&RustfsShardInventoryResponse {
                bucket: "bucket-1".to_string(),
                drive_uuid: stale_return.returned_generation.rustfs_drive_uuid.clone(),
                filesystem_uuid: stale_return.returned_generation.filesystem_uuid.clone(),
                start_cursor: None,
                end_cursor: cursor.to_string(),
                exhausted: true,
                total_count: entries.len(),
                entries,
            })
            .expect("inventory response");
            ShardInventorySnapshot::from_complete_scan(
                identity("stale-disk-return-detect"),
                stale_return.returned_generation.clone(),
                ShardInventoryScanReceipt {
                    snapshot_id: snapshot_id.to_string(),
                    source: ShardInventorySource::RustfsDiagnosticApi,
                    api_revision: "v1".to_string(),
                    response_sha256: sha256_bytes(response.as_bytes()),
                    response_body: response,
                    started_at_ms: observed_at_ms - 5,
                    completed_at_ms: observed_at_ms,
                    observed_at_ms,
                },
            )
            .expect("complete shard inventory")
        };
        let before_inventory = inventory(
            "inventory-before",
            "cursor-before",
            550,
            vec![committed.clone(), unknown.clone(), dangling.clone()],
        );
        let after_inventory = inventory(
            "inventory-after",
            "cursor-after",
            710,
            vec![committed.clone(), unknown.clone()],
        );
        let proof = DanglingCleanupProof {
            schema_version: STORAGE_RECOVERY_PROOF_SCHEMA_VERSION,
            identity: identity("stale-disk-return-detect"),
            returned_generation: stale_return.returned_generation.clone(),
            before_inventory_snapshot_id: before_inventory.receipt.snapshot_id.clone(),
            before_inventory_sha256: before_inventory.entries_sha256.clone(),
            after_inventory_snapshot_id: after_inventory.receipt.snapshot_id.clone(),
            after_inventory_sha256: after_inventory.entries_sha256.clone(),
            cleanup_operation_id: "cleanup-1".to_string(),
            writes_quiesced_at_ms: 540,
            started_at_ms: 600,
            completed_at_ms: 700,
            classified_versions: vec![
                ClassifiedVersionFragments {
                    evidence_id: "put-1".to_string(),
                    operation_id: Some("put-1".to_string()),
                    object_key: committed.object_key.clone(),
                    version_id: committed.version_id.clone(),
                    recoverability: FragmentRecoverability::Committed,
                    fragment_ids: vec![committed.fragment_id.clone()],
                },
                ClassifiedVersionFragments {
                    evidence_id: "ack-loss-1".to_string(),
                    operation_id: Some("ack-loss-1".to_string()),
                    object_key: unknown.object_key.clone(),
                    version_id: unknown.version_id.clone(),
                    recoverability: FragmentRecoverability::RecoverableUnknown,
                    fragment_ids: vec![unknown.fragment_id.clone()],
                },
                ClassifiedVersionFragments {
                    evidence_id: "inventory-1".to_string(),
                    operation_id: None,
                    object_key: dangling.object_key.clone(),
                    version_id: dangling.version_id.clone(),
                    recoverability: FragmentRecoverability::UncommittedDangling,
                    fragment_ids: vec![dangling.fragment_id.clone()],
                },
            ],
        };
        proof
            .validate_against_stale_return(
                &stale_return,
                &before_inventory,
                &after_inventory,
                &history,
            )
            .expect("committed and recoverable-unknown fragments retained");

        let rejects_order = |candidate: &DanglingCleanupProof,
                             before: &ShardInventorySnapshot,
                             after: &ShardInventorySnapshot| {
            candidate
                .validate_against_stale_return(&stale_return, before, after, &history)
                .is_err()
        };
        let mut quiesce_at_return = proof.clone();
        quiesce_at_return.writes_quiesced_at_ms = stale_return.returned_generation.observed_at_ms;
        assert!(rejects_order(
            &quiesce_at_return,
            &before_inventory,
            &after_inventory
        ));
        let mut before_at_quiesce = before_inventory.clone();
        before_at_quiesce.receipt.started_at_ms = proof.writes_quiesced_at_ms;
        assert!(rejects_order(&proof, &before_at_quiesce, &after_inventory));
        let mut cleanup_at_before = proof.clone();
        cleanup_at_before.started_at_ms = before_inventory.receipt.completed_at_ms;
        assert!(rejects_order(
            &cleanup_at_before,
            &before_inventory,
            &after_inventory
        ));
        let mut completed_at_start = proof.clone();
        completed_at_start.completed_at_ms = completed_at_start.started_at_ms;
        assert!(rejects_order(
            &completed_at_start,
            &before_inventory,
            &after_inventory
        ));
        let mut after_at_complete = after_inventory.clone();
        after_at_complete.receipt.started_at_ms = proof.completed_at_ms;
        assert!(rejects_order(&proof, &before_inventory, &after_at_complete));

        let mut inverted_cleanup_history = history.clone();
        inverted_cleanup_history
            .iter_mut()
            .find(|record| record.id == "put-1")
            .expect("committed cleanup history")
            .started_at_ms = 601;
        assert!(
            proof
                .validate_against_stale_return(
                    &stale_return,
                    &before_inventory,
                    &after_inventory,
                    &inverted_cleanup_history,
                )
                .is_err(),
            "an inverted history interval cannot prove a fragment existed before cleanup"
        );

        let mut overlapping_write = history.clone();
        overlapping_write.push(history_record(
            "overlapping-put",
            "stale-disk-return-detect",
            OperationKind::Put,
            "key-overlap",
            "version-overlap",
            Some(HASH_C),
            650,
        ));
        assert!(
            proof
                .validate_against_stale_return(
                    &stale_return,
                    &before_inventory,
                    &after_inventory,
                    &overlapping_write,
                )
                .is_err(),
            "writes must be quiesced until the post-cleanup inventory is complete"
        );
        for kind in [
            OperationKind::Delete,
            OperationKind::UploadPart,
            OperationKind::AbortMultipartUpload,
        ] {
            let mut overlapping_mutation = history.clone();
            overlapping_mutation.push(history_record(
                "overlapping-mutation",
                "stale-disk-return-detect",
                kind,
                "key-overlap",
                "version-overlap",
                Some(HASH_C),
                650,
            ));
            assert!(
                proof
                    .validate_against_stale_return(
                        &stale_return,
                        &before_inventory,
                        &after_inventory,
                        &overlapping_mutation,
                    )
                    .is_err(),
                "{kind:?} must not overlap the quiesced cleanup window"
            );
        }

        let mut incomplete_scan = before_inventory.clone();
        let mut partial_response = incomplete_scan.response().expect("inventory response");
        partial_response.exhausted = false;
        incomplete_scan.receipt.response_body =
            serde_json::to_string(&partial_response).expect("inventory response");
        incomplete_scan.receipt.response_sha256 =
            sha256_bytes(incomplete_scan.receipt.response_body.as_bytes());
        assert!(
            proof
                .validate_against_stale_return(
                    &stale_return,
                    &incomplete_scan,
                    &after_inventory,
                    &history,
                )
                .is_err(),
            "a partial inventory response must not define the cleanup universe"
        );

        let mut truncated_scan = before_inventory.clone();
        let mut truncated_response = truncated_scan.response().expect("inventory response");
        truncated_response.entries.remove(0);
        truncated_scan.entry_count = truncated_response.entries.len();
        truncated_scan.entries_sha256 =
            inventory_entries_sha256(&truncated_response.entries).expect("inventory digest");
        truncated_scan.receipt.response_body =
            serde_json::to_string(&truncated_response).expect("inventory response");
        truncated_scan.receipt.response_sha256 =
            sha256_bytes(truncated_scan.receipt.response_body.as_bytes());
        let mut truncated_proof = proof.clone();
        truncated_proof.before_inventory_sha256 = truncated_scan.entries_sha256.clone();
        assert!(
            truncated_proof
                .validate_against_stale_return(
                    &stale_return,
                    &truncated_scan,
                    &after_inventory,
                    &history,
                )
                .is_err(),
            "recomputing local inventory fields cannot hide an entry omitted from the server total"
        );

        let missing_after = inventory(
            "inventory-missing-after",
            "cursor-missing-after",
            710,
            vec![committed],
        );
        let mut missing = proof.clone();
        missing.after_inventory_snapshot_id = missing_after.receipt.snapshot_id.clone();
        missing.after_inventory_sha256 = missing_after.entries_sha256.clone();
        let error = missing
            .validate_against_stale_return(
                &stale_return,
                &before_inventory,
                &missing_after,
                &history,
            )
            .expect_err("recoverable-unknown fragment was removed");
        assert!(error.to_string().contains("recoverable-unknown"));

        let mut incomplete = proof.clone();
        incomplete.classified_versions.pop();
        assert!(
            incomplete
                .validate_against_stale_return(
                    &stale_return,
                    &before_inventory,
                    &after_inventory,
                    &history,
                )
                .is_err()
        );

        let mut relabeled_unknown = proof.clone();
        relabeled_unknown.classified_versions[1].recoverability =
            FragmentRecoverability::UncommittedDangling;
        assert!(
            relabeled_unknown
                .validate_against_stale_return(
                    &stale_return,
                    &before_inventory,
                    &after_inventory,
                    &history,
                )
                .is_err()
        );

        let mut foreign_before = before_inventory.clone();
        let mut foreign_response = foreign_before.response().expect("inventory response");
        foreign_response.entries[0].drive_uuid = "drive-foreign".to_string();
        foreign_before.entries_sha256 =
            inventory_entries_sha256(&foreign_response.entries).expect("inventory digest");
        foreign_before.receipt.response_body =
            serde_json::to_string(&foreign_response).expect("inventory response");
        foreign_before.receipt.response_sha256 =
            sha256_bytes(foreign_before.receipt.response_body.as_bytes());
        let mut foreign_drive = proof.clone();
        foreign_drive.before_inventory_sha256 = foreign_before.entries_sha256.clone();
        assert!(
            foreign_drive
                .validate_against_stale_return(
                    &stale_return,
                    &foreign_before,
                    &after_inventory,
                    &history,
                )
                .is_err(),
            "inventory from a foreign drive must not prove stale-drive cleanup"
        );

        let mut foreign_bucket_inventory = before_inventory.clone();
        let mut foreign_bucket_response = foreign_bucket_inventory
            .response()
            .expect("inventory response");
        foreign_bucket_response.bucket = "bucket-foreign".to_string();
        for entry in &mut foreign_bucket_response.entries {
            entry.bucket = "bucket-foreign".to_string();
        }
        foreign_bucket_inventory.entries_sha256 =
            inventory_entries_sha256(&foreign_bucket_response.entries).expect("inventory digest");
        foreign_bucket_inventory.receipt.response_body =
            serde_json::to_string(&foreign_bucket_response).expect("inventory response");
        foreign_bucket_inventory.receipt.response_sha256 =
            sha256_bytes(foreign_bucket_inventory.receipt.response_body.as_bytes());
        let mut foreign_bucket_proof = proof.clone();
        foreign_bucket_proof.before_inventory_sha256 =
            foreign_bucket_inventory.entries_sha256.clone();
        assert!(
            foreign_bucket_proof
                .validate_against_stale_return(
                    &stale_return,
                    &foreign_bucket_inventory,
                    &after_inventory,
                    &history,
                )
                .is_err(),
            "same-key fragments from another bucket cannot enter this cleanup universe"
        );

        let mut definite_http_failure = history.clone();
        let ambiguous = definite_http_failure
            .iter_mut()
            .find(|record| record.id == "ack-loss-1")
            .expect("ACK-loss history record");
        ambiguous.outcome = OperationOutcome::Unknown;
        ambiguous.http_status = Some(400);
        assert!(
            proof
                .validate_against_stale_return(
                    &stale_return,
                    &before_inventory,
                    &after_inventory,
                    &definite_http_failure,
                )
                .is_err(),
            "a definite HTTP 4xx response must not be treated as ACK loss"
        );

        let mut server_error = history.clone();
        let ambiguous = server_error
            .iter_mut()
            .find(|record| record.id == "ack-loss-1")
            .expect("ACK-loss history record");
        ambiguous.outcome = OperationOutcome::Failed;
        ambiguous.http_status = Some(500);
        proof
            .validate_against_stale_return(
                &stale_return,
                &before_inventory,
                &after_inventory,
                &server_error,
            )
            .expect("a failed 5xx write remains recoverable-unknown and protected");

        let second_unknown = ShardInventoryEntry {
            fragment_id: "fragment-unknown-2".to_string(),
            version_id: "ack-lost-version-2".to_string(),
            reference_state: FragmentReferenceState::OrphanedUncommitted,
            ..unknown
        };
        let mut ambiguous_materialization = proof;
        let original_entries = before_inventory
            .response()
            .expect("inventory response")
            .entries;
        let ambiguous_before = inventory(
            "inventory-ambiguous",
            "cursor-ambiguous",
            550,
            vec![
                original_entries[0].clone(),
                original_entries[1].clone(),
                original_entries[2].clone(),
                second_unknown.clone(),
            ],
        );
        ambiguous_materialization.before_inventory_snapshot_id =
            ambiguous_before.receipt.snapshot_id.clone();
        ambiguous_materialization.before_inventory_sha256 = ambiguous_before.entries_sha256.clone();
        ambiguous_materialization
            .classified_versions
            .push(ClassifiedVersionFragments {
                evidence_id: "inventory-ambiguous-2".to_string(),
                operation_id: None,
                object_key: second_unknown.object_key.clone(),
                version_id: second_unknown.version_id.clone(),
                recoverability: FragmentRecoverability::UncommittedDangling,
                fragment_ids: vec![second_unknown.fragment_id],
            });
        assert!(
            ambiguous_materialization
                .validate_against_stale_return(
                    &stale_return,
                    &ambiguous_before,
                    &after_inventory,
                    &history,
                )
                .is_err(),
            "an unversioned ACK-loss operation must not select one of multiple inventory versions"
        );
    }
}
