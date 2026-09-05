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

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    fault::{
        backends::host::DmStatusSnapshot,
        checker::RecoveryStabilityClassification,
        config::FaultTestConfig,
        plan::{FaultPlan, FaultSelection},
        scenarios::{FaultScenario, FaultScenarioSpec},
        workload::WorkloadPlan,
    },
    framework::artifacts::ArtifactCollector,
};

const FAILURE_SUMMARY_SCHEMA_VERSION: u8 = 2;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct FaultStatusSnapshot {
    pub(crate) stage: String,
    pub(crate) resource_kind: Option<String>,
    pub(crate) resource_name: Option<String>,
    pub(crate) chaos_status: Option<serde_json::Value>,
    pub(crate) dm_status: Option<DmStatusSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct PodIdentity {
    pub(crate) name: String,
    pub(crate) uid: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct FaultEvidence {
    pub(crate) scenario: String,
    pub(crate) backend: String,
    pub(crate) target: String,
    pub(crate) injected: bool,
    pub(crate) active_during_workload: bool,
    pub(crate) recovered: bool,
    pub(crate) require_client_disruption: bool,
    pub(crate) client_disruptions: usize,
    pub(crate) workload_plan: WorkloadPlan,
    pub(crate) pods_before: Vec<PodIdentity>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) pods_at_fault_activation: Vec<PodIdentity>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) pods_at_workload_snapshot: Vec<PodIdentity>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) fixed_volume_targets_at_fault_activation: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) fixed_volume_targets_at_workload_snapshot: Vec<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) fixed_volume_containers_at_fault_activation: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) fixed_volume_containers_at_workload_snapshot: BTreeMap<String, String>,
    pub(crate) pods_after: Vec<PodIdentity>,
    pub(crate) active_snapshots: Vec<FaultStatusSnapshot>,
    pub(crate) workload_snapshots: Vec<FaultStatusSnapshot>,
    pub(crate) dm_recovery_snapshot: Option<DmStatusSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) fault_apply_started_at_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) fault_active_at_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) workload_started_at_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) workload_ended_at_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) fault_delete_started_at_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) recovery_started_at_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) recovery_ended_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RunMetadata {
    scenario: String,
    case_name: String,
    run_id: String,
    bucket: String,
    backend: String,
    target: String,
    context: String,
    namespace: String,
    tenant: String,
    storage_class: String,
    rustfs_image: String,
    artifacts_dir: String,
    fault_duration_seconds: u64,
    percent: Option<u8>,
    fault_selection: Vec<String>,
    fault_parameters: Vec<crate::fault::plan::FaultInjectionParameters>,
    workload_objects: usize,
    workload_concurrency: usize,
    workload_operation_mix: crate::fault::workload::WorkloadOperationMix,
    prefill_concurrency: usize,
    request_timeout_seconds: u64,
    recovery_stability_reread_seconds: u64,
    use_cluster_ip: bool,
    require_client_disruption: bool,
    chaos_namespace: String,
}

impl RunMetadata {
    pub(crate) fn from_case(
        config: &FaultTestConfig,
        scenario: &FaultScenario,
        spec: &FaultScenarioSpec,
        plan: &FaultPlan,
        workload_plan: &WorkloadPlan,
        run_id: &str,
        bucket: &str,
    ) -> Self {
        let require_client_disruption =
            config.require_client_disruption || spec.impact_policy.requires_client_disruption();
        Self {
            scenario: scenario.name.clone(),
            case_name: scenario.case_name.to_string(),
            run_id: run_id.to_string(),
            bucket: bucket.to_string(),
            backend: plan.backend_summary(),
            target: plan.target_summary(),
            context: config.cluster.context.clone(),
            namespace: config.cluster.test_namespace.clone(),
            tenant: config.cluster.tenant_name.clone(),
            storage_class: config.cluster.storage_class.clone(),
            rustfs_image: config.cluster.rustfs_image.clone(),
            artifacts_dir: config.cluster.artifacts_dir.display().to_string(),
            fault_duration_seconds: scenario.duration.as_secs(),
            percent: plan
                .faults()
                .iter()
                .find_map(|fault| match fault.selection() {
                    FaultSelection::Percent(percent) => Some(percent),
                    FaultSelection::FixedTargets(_) => None,
                }),
            fault_selection: plan
                .faults()
                .iter()
                .map(|fault| fault.selection().summary())
                .collect(),
            fault_parameters: plan
                .faults()
                .iter()
                .map(|fault| fault.parameters().clone())
                .collect(),
            workload_objects: workload_plan.object_count,
            workload_concurrency: workload_plan.concurrency,
            workload_operation_mix: workload_plan.operation_mix,
            prefill_concurrency: config.prefill_concurrency,
            request_timeout_seconds: config.request_timeout.as_secs(),
            recovery_stability_reread_seconds: config.recovery_stability_reread.as_secs(),
            use_cluster_ip: config.use_cluster_ip,
            require_client_disruption,
            chaos_namespace: config.chaos_namespace.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureVerdict {
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureSeverity {
    Degraded,
    FailAvailability,
    FailCorrectness,
    Infra,
    NeedsInvestigation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum FailurePhase {
    Preflight,
    Setup,
    FaultInjection,
    Workload,
    Recovery,
    Checker,
    Cleanup,
    Runner,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum ResponsibilityDomain {
    Product,
    Harness,
    Environment,
    FaultBackend,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataCorrectnessStatus {
    Passed,
    Failed,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AvailabilityStatus {
    RecoveredAfterTailLatency,
    CommittedObjectUnavailable,
    CommittedVersionUnavailable,
    ListUnavailableOrUnknown,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FailureClassification {
    RecoveryTailReadLatency,
    CommittedObjectUnavailable,
    CommittedVersionMissing,
    CommittedVersionUnavailable,
    VersionHashMismatch,
    DeleteMarkerMissing,
    DeletedObjectResurrected,
    DeleteMarkerLineageIncomplete,
    VersionIdMissingOnCommittedWrite,
    MultipartUploadLineageIncomplete,
    ListUnavailableOrUnknown,
    DataCorruption,
    AmbiguousWriteMaterialized,
    HarnessError,
    TestHarness,
    WorkloadExecutionError,
    ArtifactValidationFailed,
    CheckerExecutionError,
    PreflightFailed,
    HealthGuardFailed,
    FaultBackendUnavailable,
    FaultNotActive,
    FaultNotRecovered,
    Unknown,
    CheckerOrEnvironment,
    TestOrEnvironment,
    EnvironmentOrFaultBackend,
    ProductOrEnvironment,
    EnvironmentOrWorkload,
    WorkloadOrProduct,
    NoSignal,
}

impl FailureClassification {
    pub(crate) const ALL: [Self; 31] = [
        Self::RecoveryTailReadLatency,
        Self::CommittedObjectUnavailable,
        Self::CommittedVersionMissing,
        Self::CommittedVersionUnavailable,
        Self::VersionHashMismatch,
        Self::DeleteMarkerMissing,
        Self::DeletedObjectResurrected,
        Self::DeleteMarkerLineageIncomplete,
        Self::VersionIdMissingOnCommittedWrite,
        Self::MultipartUploadLineageIncomplete,
        Self::ListUnavailableOrUnknown,
        Self::DataCorruption,
        Self::AmbiguousWriteMaterialized,
        Self::HarnessError,
        Self::TestHarness,
        Self::WorkloadExecutionError,
        Self::ArtifactValidationFailed,
        Self::CheckerExecutionError,
        Self::PreflightFailed,
        Self::HealthGuardFailed,
        Self::FaultBackendUnavailable,
        Self::FaultNotActive,
        Self::FaultNotRecovered,
        Self::Unknown,
        Self::CheckerOrEnvironment,
        Self::TestOrEnvironment,
        Self::EnvironmentOrFaultBackend,
        Self::ProductOrEnvironment,
        Self::EnvironmentOrWorkload,
        Self::WorkloadOrProduct,
        Self::NoSignal,
    ];

    pub(crate) fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|classification| classification.as_str() == name)
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::RecoveryTailReadLatency => "recovery_tail_read_latency",
            Self::CommittedObjectUnavailable => "committed_object_unavailable",
            Self::CommittedVersionMissing => "committed_version_missing",
            Self::CommittedVersionUnavailable => "committed_version_unavailable",
            Self::VersionHashMismatch => "version_hash_mismatch",
            Self::DeleteMarkerMissing => "delete_marker_missing",
            Self::DeletedObjectResurrected => "deleted_object_resurrected",
            Self::DeleteMarkerLineageIncomplete => "delete_marker_lineage_incomplete",
            Self::VersionIdMissingOnCommittedWrite => "version_id_missing_on_committed_write",
            Self::MultipartUploadLineageIncomplete => "multipart_upload_lineage_incomplete",
            Self::ListUnavailableOrUnknown => "list_unavailable_or_unknown",
            Self::DataCorruption => "data_corruption",
            Self::AmbiguousWriteMaterialized => "ambiguous_write_materialized",
            Self::HarnessError => "harness_error",
            Self::TestHarness => "test_harness",
            Self::WorkloadExecutionError => "workload_execution_error",
            Self::ArtifactValidationFailed => "artifact_validation_failed",
            Self::CheckerExecutionError => "checker_execution_error",
            Self::PreflightFailed => "preflight_failed",
            Self::HealthGuardFailed => "health_guard_failed",
            Self::FaultBackendUnavailable => "fault_backend_unavailable",
            Self::FaultNotActive => "fault_not_active",
            Self::FaultNotRecovered => "fault_not_recovered",
            Self::Unknown => "unknown",
            Self::CheckerOrEnvironment => "checker_or_environment",
            Self::TestOrEnvironment => "test_or_environment",
            Self::EnvironmentOrFaultBackend => "environment_or_fault_backend",
            Self::ProductOrEnvironment => "product_or_environment",
            Self::EnvironmentOrWorkload => "environment_or_workload",
            Self::WorkloadOrProduct => "workload_or_product",
            Self::NoSignal => "no_signal",
        }
    }

    pub(crate) const fn is_s3_model(self) -> bool {
        matches!(
            self,
            Self::RecoveryTailReadLatency
                | Self::CommittedObjectUnavailable
                | Self::CommittedVersionMissing
                | Self::CommittedVersionUnavailable
                | Self::VersionHashMismatch
                | Self::DeleteMarkerMissing
                | Self::DeletedObjectResurrected
                | Self::DeleteMarkerLineageIncomplete
                | Self::VersionIdMissingOnCommittedWrite
                | Self::MultipartUploadLineageIncomplete
                | Self::ListUnavailableOrUnknown
                | Self::DataCorruption
                | Self::AmbiguousWriteMaterialized
        )
    }

    const fn responsibility_domain(self) -> ResponsibilityDomain {
        match self {
            Self::RecoveryTailReadLatency
            | Self::CommittedObjectUnavailable
            | Self::CommittedVersionMissing
            | Self::CommittedVersionUnavailable
            | Self::VersionHashMismatch
            | Self::DeleteMarkerMissing
            | Self::DeletedObjectResurrected
            | Self::DeleteMarkerLineageIncomplete
            | Self::VersionIdMissingOnCommittedWrite
            | Self::MultipartUploadLineageIncomplete
            | Self::ListUnavailableOrUnknown
            | Self::DataCorruption
            | Self::AmbiguousWriteMaterialized => ResponsibilityDomain::Product,
            Self::HarnessError
            | Self::TestHarness
            | Self::WorkloadExecutionError
            | Self::ArtifactValidationFailed
            | Self::CheckerExecutionError => ResponsibilityDomain::Harness,
            Self::PreflightFailed | Self::HealthGuardFailed => ResponsibilityDomain::Environment,
            Self::FaultBackendUnavailable | Self::FaultNotActive | Self::FaultNotRecovered => {
                ResponsibilityDomain::FaultBackend
            }
            Self::Unknown
            | Self::CheckerOrEnvironment
            | Self::TestOrEnvironment
            | Self::EnvironmentOrFaultBackend
            | Self::ProductOrEnvironment
            | Self::EnvironmentOrWorkload
            | Self::WorkloadOrProduct
            | Self::NoSignal => ResponsibilityDomain::Unknown,
        }
    }
}

impl From<RecoveryStabilityClassification> for FailureClassification {
    fn from(classification: RecoveryStabilityClassification) -> Self {
        match classification {
            RecoveryStabilityClassification::DataCorruption => Self::DataCorruption,
            RecoveryStabilityClassification::CommittedObjectUnavailable => {
                Self::CommittedObjectUnavailable
            }
            RecoveryStabilityClassification::CommittedVersionMissing => {
                Self::CommittedVersionMissing
            }
            RecoveryStabilityClassification::CommittedVersionUnavailable => {
                Self::CommittedVersionUnavailable
            }
            RecoveryStabilityClassification::VersionHashMismatch => Self::VersionHashMismatch,
            RecoveryStabilityClassification::DeleteMarkerMissing => Self::DeleteMarkerMissing,
            RecoveryStabilityClassification::DeletedObjectResurrected => {
                Self::DeletedObjectResurrected
            }
            RecoveryStabilityClassification::DeleteMarkerLineageIncomplete => {
                Self::DeleteMarkerLineageIncomplete
            }
            RecoveryStabilityClassification::VersionIdMissingOnCommittedWrite => {
                Self::VersionIdMissingOnCommittedWrite
            }
            RecoveryStabilityClassification::MultipartUploadLineageIncomplete => {
                Self::MultipartUploadLineageIncomplete
            }
            RecoveryStabilityClassification::ListUnavailableOrUnknown => {
                Self::ListUnavailableOrUnknown
            }
            RecoveryStabilityClassification::RecoveryTailReadLatency => {
                Self::RecoveryTailReadLatency
            }
            RecoveryStabilityClassification::AmbiguousWriteMaterialized => {
                Self::AmbiguousWriteMaterialized
            }
            RecoveryStabilityClassification::HarnessError => Self::HarnessError,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct FailureClassificationDetails {
    severity: FailureSeverity,
    data_correctness: DataCorrectnessStatus,
    availability: AvailabilityStatus,
    data_loss: Option<bool>,
    corruption: Option<bool>,
    recovered_within_window: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct FailureSummary {
    #[serde(default = "legacy_failure_summary_schema_version")]
    schema_version: u8,
    scenario: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    case_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    observed_at_ms: Option<u64>,
    stage: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    phase: Option<FailurePhase>,
    verdict: FailureVerdict,
    severity: FailureSeverity,
    classification: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    s3_model_classification: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    run_failure_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    responsibility_domain: Option<ResponsibilityDomain>,
    data_correctness: DataCorrectnessStatus,
    availability: AvailabilityStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    primary_evidence_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    evidence_classifications: Vec<String>,
    #[serde(default, skip_serializing_if = "is_zero")]
    final_list_warning_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    list_warnings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_loss: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    corruption: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    recovered_within_window: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    recovered_within_seconds: Option<u64>,
    message: String,
}

impl FailureSummary {
    pub(crate) fn new(
        scenario: impl Into<String>,
        stage: impl Into<String>,
        classification: impl AsRef<str>,
        message: impl Into<String>,
    ) -> Result<Self> {
        let stage = stage.into();
        let classification_name = classification.as_ref();
        let classification =
            FailureClassification::from_name(classification_name).with_context(|| {
                format!(
                    "failure classification {classification_name:?} is not in the writer allowlist"
                )
            })?;
        Ok(Self::from_classification(
            scenario,
            stage,
            classification,
            message,
        ))
    }

    pub(crate) fn from_checker(
        scenario: impl Into<String>,
        stage: impl Into<String>,
        classification: RecoveryStabilityClassification,
        message: impl Into<String>,
    ) -> Self {
        let classification = FailureClassification::from(classification);
        let mut summary =
            Self::from_classification(scenario, stage.into(), classification, message);
        summary.evidence_classifications = vec![classification.as_str().to_string()];
        summary
    }

    fn from_classification(
        scenario: impl Into<String>,
        stage: String,
        classification: FailureClassification,
        message: impl Into<String>,
    ) -> Self {
        let details = FailureClassificationDetails::from_classification(classification);
        let phase = FailurePhase::from_stage(&stage);
        let projection = FailureV2Projection::from_classification(classification);
        Self {
            schema_version: FAILURE_SUMMARY_SCHEMA_VERSION,
            scenario: scenario.into(),
            case_name: None,
            observed_at_ms: Some(now_ms()),
            stage: stage.clone(),
            phase: Some(phase),
            verdict: FailureVerdict::Failed,
            severity: details.severity,
            classification: classification.as_str().to_string(),
            s3_model_classification: projection.s3_model_classification,
            run_failure_reason: projection.run_failure_reason,
            responsibility_domain: Some(projection.responsibility_domain),
            data_correctness: details.data_correctness,
            availability: details.availability,
            primary_evidence_refs: primary_evidence_refs_for(&stage, phase),
            evidence_classifications: Vec::new(),
            final_list_warning_count: 0,
            list_warnings: Vec::new(),
            data_loss: details.data_loss,
            corruption: details.corruption,
            recovered_within_window: details.recovered_within_window,
            recovered_within_seconds: None,
            message: message.into(),
        }
    }

    fn with_case_name(mut self, case_name: &str) -> Self {
        if self.case_name.is_none() {
            self.case_name = Some(case_name.to_string());
        }
        self
    }

    fn with_artifact_context(
        mut self,
        collector: &ArtifactCollector,
        case_name: &str,
    ) -> Result<Self> {
        let case_dir = collector.case_dir(case_name);
        self.primary_evidence_refs = self
            .primary_evidence_refs
            .into_iter()
            .map(|artifact| case_dir.join(artifact))
            .filter(|path| path.is_file())
            .map(|path| {
                collector
                    .reference_path(&path)
                    .map(|relative| relative.display().to_string())
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(self)
    }

    pub(crate) fn with_recovered_within_seconds(mut self, seconds: Option<u64>) -> Self {
        self.recovered_within_seconds = seconds;
        self
    }

    pub(crate) fn with_evidence_classifications(
        mut self,
        classifications: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.evidence_classifications = classifications.into_iter().map(Into::into).collect();
        self.evidence_classifications.sort();
        self.evidence_classifications.dedup();
        self
    }

    pub(crate) fn with_list_warnings(
        mut self,
        final_list_warning_count: usize,
        warnings: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.final_list_warning_count = final_list_warning_count;
        self.list_warnings = warnings.into_iter().map(Into::into).collect();
        self.list_warnings.sort();
        self.list_warnings.dedup();
        self
    }

    pub(crate) fn severity(&self) -> FailureSeverity {
        self.severity
    }

    pub(crate) fn phase(&self) -> Option<FailurePhase> {
        self.phase
    }

    pub(crate) fn classification(&self) -> &str {
        &self.classification
    }

    pub(crate) fn s3_model_classification(&self) -> Option<&str> {
        self.s3_model_classification.as_deref()
    }

    pub(crate) fn run_failure_reason(&self) -> Option<&str> {
        self.run_failure_reason.as_deref()
    }

    pub(crate) fn responsibility_domain(&self) -> Option<ResponsibilityDomain> {
        self.responsibility_domain
    }

    pub(crate) fn primary_evidence_refs(&self) -> &[String] {
        &self.primary_evidence_refs
    }

    pub(crate) fn evidence_classifications(&self) -> &[String] {
        &self.evidence_classifications
    }
}

fn legacy_failure_summary_schema_version() -> u8 {
    1
}

fn is_zero(value: &usize) -> bool {
    *value == 0
}

#[derive(Debug, Clone)]
struct FailureV2Projection {
    s3_model_classification: Option<String>,
    run_failure_reason: Option<String>,
    responsibility_domain: ResponsibilityDomain,
}

impl FailureV2Projection {
    fn from_classification(classification: FailureClassification) -> Self {
        if classification.is_s3_model() {
            return Self {
                s3_model_classification: Some(classification.as_str().to_string()),
                run_failure_reason: None,
                responsibility_domain: ResponsibilityDomain::Product,
            };
        }

        Self {
            s3_model_classification: None,
            run_failure_reason: Some(classification.as_str().to_string()),
            responsibility_domain: classification.responsibility_domain(),
        }
    }
}

impl ResponsibilityDomain {
    pub(crate) fn from_classification(classification: &str) -> Self {
        FailureClassification::from_name(classification)
            .map(FailureClassification::responsibility_domain)
            .unwrap_or(Self::Unknown)
    }
}

impl FailurePhase {
    pub(crate) fn from_stage(stage: &str) -> Self {
        match stage {
            "scenario" | "fault-backend-preflight" | "fault-backend-pre-cleanup" => Self::Preflight,
            "fixture-prepare"
            | "tenant-ready-before-fault"
            | "pod-stability-before-fault"
            | "initial-s3-access"
            | "s3-endpoint"
            | "s3-client"
            | "bucket-create"
            | "prefill"
            | "pod-identity-before-fault" => Self::Setup,
            "fault-apply" | "wait-active" | "fault-snapshot-active" | "active-snapshot-failed" => {
                Self::FaultInjection
            }
            "s3-access-under-fault"
            | "warp-workload"
            | "mixed-workload"
            | "post-warp-s3-access"
            | "post-warp-port-forward-failed"
            | "fault-evidence"
            | "workload-no-fault-evidence"
            | "fault-still-active"
            | "workload-outlived-fault"
            | "fault-snapshot-after-workload"
            | "after-workload-snapshot-failed" => Self::Workload,
            "fault-delete" => Self::Cleanup,
            "tenant-recovery"
            | "pod-stability-after-recovery"
            | "s3-access-after-recovery"
            | "recommit-unconfirmed" => Self::Recovery,
            "checker-pre-recommit"
            | "checker-pre-recommit-verdict"
            | "checker-final"
            | "checker-verdict" => Self::Checker,
            _ if stage.contains("preflight") => Self::Preflight,
            _ if stage.starts_with("checker") || stage.ends_with("-verdict") => Self::Checker,
            _ if stage.contains("cleanup") || stage.ends_with("-delete") => Self::Cleanup,
            _ => Self::Runner,
        }
    }
}

fn primary_evidence_refs_for(stage: &str, phase: FailurePhase) -> Vec<String> {
    let mut refs = Vec::new();

    match phase {
        FailurePhase::Checker => {
            if stage == "checker-pre-recommit" {
                push_unique(&mut refs, "recovery-stability-report.json");
                push_unique(&mut refs, "checker-pre-recommit-error.txt");
            } else if stage.contains("pre-recommit") {
                push_unique(&mut refs, "recovery-stability-report.json");
                push_unique(&mut refs, "checker-pre-recommit-report.json");
            } else if stage == "checker-final" {
                push_unique(&mut refs, "checker-final-error.txt");
            } else {
                push_unique(&mut refs, "checker-report.json");
            }
            push_unique(&mut refs, "fault-evidence.json");
        }
        FailurePhase::Recovery if stage == "recommit-unconfirmed" => {
            push_unique(&mut refs, "fault-evidence.json");
        }
        FailurePhase::Preflight
        | FailurePhase::Setup
        | FailurePhase::FaultInjection
        | FailurePhase::Workload
        | FailurePhase::Recovery
        | FailurePhase::Cleanup
        | FailurePhase::Runner => {}
    }

    push_unique(&mut refs, "run-events.jsonl");
    refs.truncate(5);
    refs
}

fn push_unique(refs: &mut Vec<String>, artifact: &str) {
    if !refs.iter().any(|item| item == artifact) {
        refs.push(artifact.to_string());
    }
}

impl FailureClassificationDetails {
    fn from_classification(classification: FailureClassification) -> Self {
        match classification {
            FailureClassification::RecoveryTailReadLatency => Self {
                severity: FailureSeverity::Degraded,
                data_correctness: DataCorrectnessStatus::Passed,
                availability: AvailabilityStatus::RecoveredAfterTailLatency,
                data_loss: Some(false),
                corruption: Some(false),
                recovered_within_window: Some(true),
            },
            FailureClassification::CommittedObjectUnavailable => Self {
                severity: FailureSeverity::FailAvailability,
                data_correctness: DataCorrectnessStatus::Unknown,
                availability: AvailabilityStatus::CommittedObjectUnavailable,
                data_loss: None,
                corruption: Some(false),
                recovered_within_window: Some(false),
            },
            FailureClassification::CommittedVersionMissing => Self {
                severity: FailureSeverity::FailCorrectness,
                data_correctness: DataCorrectnessStatus::Failed,
                availability: AvailabilityStatus::Unknown,
                data_loss: Some(true),
                corruption: Some(false),
                recovered_within_window: Some(false),
            },
            FailureClassification::CommittedVersionUnavailable => Self {
                severity: FailureSeverity::FailAvailability,
                data_correctness: DataCorrectnessStatus::Unknown,
                availability: AvailabilityStatus::CommittedVersionUnavailable,
                data_loss: None,
                corruption: Some(false),
                recovered_within_window: Some(false),
            },
            FailureClassification::VersionHashMismatch
            | FailureClassification::DeleteMarkerMissing
            | FailureClassification::DeletedObjectResurrected => Self {
                severity: FailureSeverity::FailCorrectness,
                data_correctness: DataCorrectnessStatus::Failed,
                availability: AvailabilityStatus::Unknown,
                data_loss: Some(false),
                corruption: Some(true),
                recovered_within_window: None,
            },
            FailureClassification::DeleteMarkerLineageIncomplete
            | FailureClassification::VersionIdMissingOnCommittedWrite
            | FailureClassification::MultipartUploadLineageIncomplete => Self {
                severity: FailureSeverity::NeedsInvestigation,
                data_correctness: DataCorrectnessStatus::Unknown,
                availability: AvailabilityStatus::Unknown,
                data_loss: None,
                corruption: Some(false),
                recovered_within_window: None,
            },
            FailureClassification::ListUnavailableOrUnknown => Self {
                severity: FailureSeverity::FailAvailability,
                data_correctness: DataCorrectnessStatus::Unknown,
                availability: AvailabilityStatus::ListUnavailableOrUnknown,
                data_loss: None,
                corruption: Some(false),
                recovered_within_window: Some(false),
            },
            FailureClassification::DataCorruption => Self {
                severity: FailureSeverity::FailCorrectness,
                data_correctness: DataCorrectnessStatus::Failed,
                availability: AvailabilityStatus::Unknown,
                data_loss: None,
                corruption: Some(true),
                recovered_within_window: None,
            },
            FailureClassification::AmbiguousWriteMaterialized => Self {
                severity: FailureSeverity::NeedsInvestigation,
                data_correctness: DataCorrectnessStatus::Unknown,
                availability: AvailabilityStatus::Unknown,
                data_loss: None,
                corruption: Some(false),
                recovered_within_window: None,
            },
            FailureClassification::HarnessError
            | FailureClassification::TestHarness
            | FailureClassification::TestOrEnvironment
            | FailureClassification::EnvironmentOrFaultBackend => Self {
                severity: FailureSeverity::Infra,
                data_correctness: DataCorrectnessStatus::Unknown,
                availability: AvailabilityStatus::Unknown,
                data_loss: None,
                corruption: None,
                recovered_within_window: None,
            },
            FailureClassification::WorkloadExecutionError
            | FailureClassification::ArtifactValidationFailed
            | FailureClassification::CheckerExecutionError
            | FailureClassification::PreflightFailed
            | FailureClassification::HealthGuardFailed
            | FailureClassification::FaultBackendUnavailable
            | FailureClassification::FaultNotActive
            | FailureClassification::FaultNotRecovered
            | FailureClassification::Unknown
            | FailureClassification::CheckerOrEnvironment
            | FailureClassification::ProductOrEnvironment
            | FailureClassification::EnvironmentOrWorkload
            | FailureClassification::WorkloadOrProduct
            | FailureClassification::NoSignal => Self {
                severity: FailureSeverity::NeedsInvestigation,
                data_correctness: DataCorrectnessStatus::Unknown,
                availability: AvailabilityStatus::Unknown,
                data_loss: None,
                corruption: None,
                recovered_within_window: None,
            },
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub(crate) fn write_failure_summary(
    collector: &ArtifactCollector,
    case_name: &str,
    summary: FailureSummary,
) -> Result<()> {
    let summary = summary
        .with_case_name(case_name)
        .with_artifact_context(collector, case_name)?;
    collector.write_text(
        case_name,
        "failure-summary.json",
        &serde_json::to_string_pretty(&summary)?,
    )?;
    // Diagnostic contract check on the failure path: the strict validator only
    // runs on passing runs, so this is the only automated coverage a failed
    // run's summary gets. Warning-only — a contract violation must never mask
    // the run's original failure.
    let path = collector.case_dir(case_name).join("failure-summary.json");
    if let Err(violation) = crate::fault::artifact_validation::validate_written_failure_summary(
        collector.reference_root(),
        &path,
    ) {
        eprintln!(
            "warning: failure-summary.json violates the artifact contract (diagnostic validation): {violation:#}"
        );
    }
    Ok(())
}

pub(crate) fn write_failure_summary_if_absent(
    collector: &ArtifactCollector,
    case_name: &str,
    summary: FailureSummary,
) -> Result<()> {
    let path = collector.case_dir(case_name).join("failure-summary.json");
    if path.exists() {
        return Ok(());
    }
    write_failure_summary(collector, case_name, summary)
}

pub(crate) fn write_checker_error(
    collector: &ArtifactCollector,
    case_name: &str,
    artifact: &str,
    message: &str,
) -> Result<()> {
    collector.write_text(case_name, artifact, message)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        FailureClassification, FailurePhase, FailureSeverity, FailureSummary, ResponsibilityDomain,
        write_failure_summary,
    };
    use crate::{
        fault::checker::RecoveryStabilityClassification, framework::artifacts::ArtifactCollector,
    };
    use serde_json::json;
    use std::{collections::BTreeSet, fs};

    #[test]
    fn final_checker_summary_preserves_list_warning_count_and_samples() {
        let dir = tempfile::tempdir().expect("tempdir");
        let collector = ArtifactCollector::new(dir.path());
        for classification in [
            RecoveryStabilityClassification::ListUnavailableOrUnknown,
            RecoveryStabilityClassification::DataCorruption,
        ] {
            let case_name = classification.as_str();
            collector
                .write_text(case_name, "checker-report.json", "{}")
                .expect("checker evidence");
            let warnings = vec!["LIST warning b".to_string(), "LIST warning a".to_string()];
            write_failure_summary(
                &collector,
                case_name,
                FailureSummary::from_checker(
                    "io-eio",
                    "checker-verdict",
                    classification,
                    "LIST failed",
                )
                .with_list_warnings(3, warnings),
            )
            .expect("write summary");
            let path = collector.case_dir(case_name).join("failure-summary.json");
            let value: serde_json::Value =
                serde_json::from_slice(&fs::read(&path).expect("summary")).expect("json");
            assert_eq!(value["classification"], classification.as_str());
            assert_eq!(value["final_list_warning_count"], 3);
            assert_eq!(
                value["list_warnings"],
                json!(["LIST warning a", "LIST warning b"])
            );
            assert_eq!(
                value["primary_evidence_refs"],
                json!([format!("{case_name}/checker-report.json")])
            );
            crate::fault::artifact_validation::validate_written_failure_summary(dir.path(), &path)
                .expect("valid final summary");
        }
    }

    #[test]
    fn checker_classification_projects_to_s3_model_fields() {
        let summary = FailureSummary::from_checker(
            "io-eio",
            "checker-pre-recommit-verdict",
            RecoveryStabilityClassification::DataCorruption,
            "hash mismatch",
        );

        assert_eq!(summary.phase(), Some(FailurePhase::Checker));
        assert_eq!(summary.s3_model_classification(), Some("data_corruption"));
        assert_eq!(summary.run_failure_reason(), None);
        assert_eq!(
            summary.responsibility_domain(),
            Some(ResponsibilityDomain::Product)
        );

        let value = serde_json::to_value(&summary).expect("summary json");
        assert_eq!(value["schema_version"], json!(2));
        assert_eq!(value["phase"], json!("checker"));
        assert_eq!(value["classification"], json!("data_corruption"));
        assert_eq!(value["s3_model_classification"], json!("data_corruption"));
        assert!(value.get("run_failure_reason").is_none());
        assert_eq!(value["responsibility_domain"], json!("product"));
        assert_eq!(
            value["primary_evidence_refs"],
            json!([
                "recovery-stability-report.json",
                "checker-pre-recommit-report.json",
                "fault-evidence.json",
                "run-events.jsonl"
            ])
        );
    }

    #[test]
    fn typed_checker_classifications_project_to_stable_failure_fields() {
        let cases = [
            (
                RecoveryStabilityClassification::CommittedVersionMissing,
                "committed_version_missing",
                "fail_correctness",
                "failed",
                "unknown",
                Some(true),
                Some(false),
            ),
            (
                RecoveryStabilityClassification::CommittedVersionUnavailable,
                "committed_version_unavailable",
                "fail_availability",
                "unknown",
                "committed_version_unavailable",
                None,
                Some(false),
            ),
            (
                RecoveryStabilityClassification::VersionHashMismatch,
                "version_hash_mismatch",
                "fail_correctness",
                "failed",
                "unknown",
                Some(false),
                Some(true),
            ),
            (
                RecoveryStabilityClassification::DeleteMarkerMissing,
                "delete_marker_missing",
                "fail_correctness",
                "failed",
                "unknown",
                Some(false),
                Some(true),
            ),
            (
                RecoveryStabilityClassification::DeletedObjectResurrected,
                "deleted_object_resurrected",
                "fail_correctness",
                "failed",
                "unknown",
                Some(false),
                Some(true),
            ),
            (
                RecoveryStabilityClassification::DeleteMarkerLineageIncomplete,
                "delete_marker_lineage_incomplete",
                "needs_investigation",
                "unknown",
                "unknown",
                None,
                Some(false),
            ),
            (
                RecoveryStabilityClassification::VersionIdMissingOnCommittedWrite,
                "version_id_missing_on_committed_write",
                "needs_investigation",
                "unknown",
                "unknown",
                None,
                Some(false),
            ),
            (
                RecoveryStabilityClassification::MultipartUploadLineageIncomplete,
                "multipart_upload_lineage_incomplete",
                "needs_investigation",
                "unknown",
                "unknown",
                None,
                Some(false),
            ),
        ];

        for (classification, name, severity, correctness, availability, data_loss, corruption) in
            cases
        {
            let summary = FailureSummary::from_checker(
                "io-eio",
                "checker-verdict",
                classification,
                "checker failed",
            );
            let value = serde_json::to_value(summary).expect("summary json");
            assert_eq!(value["classification"], json!(name), "{name}");
            assert_eq!(value["s3_model_classification"], json!(name), "{name}");
            assert!(value.get("run_failure_reason").is_none(), "{name}");
            assert_eq!(value["severity"], json!(severity), "{name}");
            assert_eq!(value["data_correctness"], json!(correctness), "{name}");
            assert_eq!(value["availability"], json!(availability), "{name}");
            assert_eq!(
                value.get("data_loss").and_then(serde_json::Value::as_bool),
                data_loss,
                "{name}"
            );
            assert_eq!(
                value.get("corruption").and_then(serde_json::Value::as_bool),
                corruption,
                "{name}"
            );
        }
    }

    #[test]
    fn non_checker_failure_projects_to_run_failure_reason() {
        let summary = FailureSummary::new(
            "io-eio",
            "fault-backend-preflight",
            "environment_or_fault_backend",
            "missing chaos mesh",
        )
        .expect("known classification");

        assert_eq!(summary.phase(), Some(FailurePhase::Preflight));
        assert_eq!(summary.s3_model_classification(), None);
        assert_eq!(
            summary.run_failure_reason(),
            Some("environment_or_fault_backend")
        );
        assert_eq!(
            summary.responsibility_domain(),
            Some(ResponsibilityDomain::Unknown)
        );

        let value = serde_json::to_value(&summary).expect("summary json");
        assert_eq!(value["phase"], json!("preflight"));
        assert!(value.get("s3_model_classification").is_none());
        assert_eq!(
            value["run_failure_reason"],
            json!("environment_or_fault_backend")
        );
        assert_eq!(value["responsibility_domain"], json!("unknown"));
    }

    #[test]
    fn old_failure_summary_artifacts_remain_readable() {
        let old = json!({
            "scenario": "io-eio",
            "stage": "checker-pre-recommit-verdict",
            "verdict": "failed",
            "severity": "fail_correctness",
            "classification": "data_corruption",
            "data_correctness": "failed",
            "availability": "unknown",
            "message": "hash mismatch"
        });

        let summary: FailureSummary =
            serde_json::from_value(old).expect("old failure summary should deserialize");

        assert_eq!(summary.phase(), None);
        assert_eq!(summary.s3_model_classification(), None);
        assert_eq!(summary.run_failure_reason(), None);
        assert_eq!(summary.responsibility_domain(), None);
    }

    #[test]
    fn writer_fills_case_name_without_touching_call_sites() {
        let summary = FailureSummary::new("io-eio", "checker-verdict", "data_corruption", "bad")
            .expect("known classification")
            .with_case_name("fault_io_eio_preserves_committed_objects");
        let value = serde_json::to_value(&summary).expect("summary json");

        assert_eq!(
            value["case_name"],
            json!("fault_io_eio_preserves_committed_objects")
        );
    }

    #[test]
    fn writer_classification_allowlist_is_exhaustive_and_unique() {
        let expected = BTreeSet::from([
            "recovery_tail_read_latency",
            "committed_object_unavailable",
            "committed_version_missing",
            "committed_version_unavailable",
            "version_hash_mismatch",
            "delete_marker_missing",
            "deleted_object_resurrected",
            "delete_marker_lineage_incomplete",
            "version_id_missing_on_committed_write",
            "multipart_upload_lineage_incomplete",
            "list_unavailable_or_unknown",
            "data_corruption",
            "ambiguous_write_materialized",
            "harness_error",
            "test_harness",
            "workload_execution_error",
            "artifact_validation_failed",
            "checker_execution_error",
            "preflight_failed",
            "health_guard_failed",
            "fault_backend_unavailable",
            "fault_not_active",
            "fault_not_recovered",
            "unknown",
            "checker_or_environment",
            "test_or_environment",
            "environment_or_fault_backend",
            "product_or_environment",
            "environment_or_workload",
            "workload_or_product",
            "no_signal",
        ]);
        let mut names = BTreeSet::new();
        for classification in FailureClassification::ALL {
            let name = classification.as_str();
            assert!(names.insert(name), "duplicate classification {name}");
            let summary = FailureSummary::new("io-eio", "scenario", name, "failure")
                .expect("allowlisted classification");
            assert_eq!(summary.classification(), name);
            assert_eq!(
                summary.responsibility_domain(),
                Some(classification.responsibility_domain())
            );
            assert_eq!(
                summary.s3_model_classification().is_some(),
                classification.is_s3_model()
            );
            assert_eq!(
                summary.run_failure_reason().is_some(),
                !classification.is_s3_model()
            );
        }
        assert_eq!(names, expected);

        assert!(FailureSummary::new("io-eio", "checker", "data_corrupton", "typo").is_err());
    }

    #[test]
    fn writer_preserves_product_classification_severity() {
        for (classification, severity) in [
            ("recovery_tail_read_latency", FailureSeverity::Degraded),
            (
                "committed_object_unavailable",
                FailureSeverity::FailAvailability,
            ),
            (
                "committed_version_missing",
                FailureSeverity::FailCorrectness,
            ),
            (
                "committed_version_unavailable",
                FailureSeverity::FailAvailability,
            ),
            ("version_hash_mismatch", FailureSeverity::FailCorrectness),
            ("delete_marker_missing", FailureSeverity::FailCorrectness),
            (
                "deleted_object_resurrected",
                FailureSeverity::FailCorrectness,
            ),
            (
                "delete_marker_lineage_incomplete",
                FailureSeverity::NeedsInvestigation,
            ),
            (
                "version_id_missing_on_committed_write",
                FailureSeverity::NeedsInvestigation,
            ),
            (
                "multipart_upload_lineage_incomplete",
                FailureSeverity::NeedsInvestigation,
            ),
            (
                "list_unavailable_or_unknown",
                FailureSeverity::FailAvailability,
            ),
            ("data_corruption", FailureSeverity::FailCorrectness),
            (
                "ambiguous_write_materialized",
                FailureSeverity::NeedsInvestigation,
            ),
        ] {
            let summary = FailureSummary::new("io-eio", "checker", classification, "failure")
                .expect("allowlisted product classification");
            assert_eq!(summary.severity(), severity, "{classification}");
            assert_eq!(
                summary.responsibility_domain(),
                Some(ResponsibilityDomain::Product)
            );
        }
    }

    #[test]
    fn writer_emits_suite_root_relative_primary_evidence_without_self_reference() {
        let dir = tempfile::tempdir().expect("tempdir");
        let suite_root = dir.path().join("suite");
        let attempt_root = suite_root.join("001-io-eio-r1");
        let case_name = "fault_io_eio_preserves_committed_objects";
        let case_dir = attempt_root.join(case_name);
        fs::create_dir_all(&case_dir).expect("case dir");
        for artifact in [
            "recovery-stability-report.json",
            "checker-pre-recommit-report.json",
            "fault-evidence.json",
            "run-events.jsonl",
        ] {
            fs::write(case_dir.join(artifact), "{}").expect("evidence");
        }
        let collector = ArtifactCollector::with_reference_root(&attempt_root, &suite_root)
            .expect("collector roots");

        write_failure_summary(
            &collector,
            case_name,
            FailureSummary::new(
                "io-eio",
                "checker-pre-recommit-verdict",
                "data_corruption",
                "hash mismatch",
            )
            .expect("known classification"),
        )
        .expect("write failure summary");

        let raw = fs::read_to_string(case_dir.join("failure-summary.json")).expect("summary");
        let value: serde_json::Value = serde_json::from_str(&raw).expect("summary json");
        assert_eq!(
            value["primary_evidence_refs"],
            json!([
                format!("001-io-eio-r1/{case_name}/recovery-stability-report.json"),
                format!("001-io-eio-r1/{case_name}/checker-pre-recommit-report.json"),
                format!("001-io-eio-r1/{case_name}/fault-evidence.json"),
                format!("001-io-eio-r1/{case_name}/run-events.jsonl")
            ])
        );
        assert!(
            value["observed_at_ms"]
                .as_u64()
                .is_some_and(|value| value > 0)
        );
        assert!(
            value["primary_evidence_refs"]
                .as_array()
                .expect("refs")
                .iter()
                .all(|value| !value
                    .as_str()
                    .expect("ref")
                    .ends_with("failure-summary.json"))
        );
    }
}
