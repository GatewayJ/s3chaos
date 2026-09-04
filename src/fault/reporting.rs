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

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::{
    fault::{
        backends::host::DmStatusSnapshot,
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
    ListUnavailableOrUnknown,
    Unknown,
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
        classification: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        let classification = classification.into();
        let stage = stage.into();
        let details = FailureClassificationDetails::from_classification(&classification);
        let phase = FailurePhase::from_stage(&stage);
        let projection = FailureV2Projection::from_classification(&classification);
        Self {
            schema_version: FAILURE_SUMMARY_SCHEMA_VERSION,
            scenario: scenario.into(),
            case_name: None,
            stage: stage.clone(),
            phase: Some(phase),
            verdict: FailureVerdict::Failed,
            severity: details.severity,
            classification,
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
    fn from_classification(classification: &str) -> Self {
        if is_s3_model_classification(classification) {
            return Self {
                s3_model_classification: Some(classification.to_string()),
                run_failure_reason: None,
                responsibility_domain: ResponsibilityDomain::Product,
            };
        }

        Self {
            s3_model_classification: None,
            run_failure_reason: Some(classification.to_string()),
            responsibility_domain: ResponsibilityDomain::from_run_failure_reason(classification),
        }
    }
}

pub(crate) fn is_s3_model_classification(classification: &str) -> bool {
    matches!(
        classification,
        "recovery_tail_read_latency"
            | "committed_object_unavailable"
            | "list_unavailable_or_unknown"
            | "data_corruption"
            | "ambiguous_write_materialized"
    )
}

impl ResponsibilityDomain {
    pub(crate) fn from_classification(classification: &str) -> Self {
        if is_s3_model_classification(classification) {
            Self::Product
        } else {
            Self::from_run_failure_reason(classification)
        }
    }

    fn from_run_failure_reason(reason: &str) -> Self {
        match reason {
            "harness_error"
            | "test_harness"
            | "workload_execution_error"
            | "artifact_validation_failed"
            | "checker_execution_error" => Self::Harness,
            "preflight_failed" | "health_guard_failed" => Self::Environment,
            "fault_backend_unavailable" | "fault_not_active" | "fault_not_recovered" => {
                Self::FaultBackend
            }
            "unknown"
            | "checker_or_environment"
            | "test_or_environment"
            | "environment_or_fault_backend"
            | "product_or_environment"
            | "environment_or_workload"
            | "workload_or_product" => Self::Unknown,
            _ => Self::Unknown,
        }
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
    push_unique(&mut refs, "failure-summary.json");

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
    fn from_classification(classification: &str) -> Self {
        match classification {
            "recovery_tail_read_latency" => Self {
                severity: FailureSeverity::Degraded,
                data_correctness: DataCorrectnessStatus::Passed,
                availability: AvailabilityStatus::RecoveredAfterTailLatency,
                data_loss: Some(false),
                corruption: Some(false),
                recovered_within_window: Some(true),
            },
            "committed_object_unavailable" => Self {
                severity: FailureSeverity::FailAvailability,
                data_correctness: DataCorrectnessStatus::Unknown,
                availability: AvailabilityStatus::CommittedObjectUnavailable,
                data_loss: None,
                corruption: Some(false),
                recovered_within_window: Some(false),
            },
            "list_unavailable_or_unknown" => Self {
                severity: FailureSeverity::FailAvailability,
                data_correctness: DataCorrectnessStatus::Unknown,
                availability: AvailabilityStatus::ListUnavailableOrUnknown,
                data_loss: None,
                corruption: Some(false),
                recovered_within_window: Some(false),
            },
            "data_corruption" => Self {
                severity: FailureSeverity::FailCorrectness,
                data_correctness: DataCorrectnessStatus::Failed,
                availability: AvailabilityStatus::Unknown,
                data_loss: None,
                corruption: Some(true),
                recovered_within_window: None,
            },
            "ambiguous_write_materialized" => Self {
                severity: FailureSeverity::NeedsInvestigation,
                data_correctness: DataCorrectnessStatus::Unknown,
                availability: AvailabilityStatus::Unknown,
                data_loss: None,
                corruption: Some(false),
                recovered_within_window: None,
            },
            "harness_error"
            | "test_harness"
            | "test_or_environment"
            | "environment_or_fault_backend" => Self {
                severity: FailureSeverity::Infra,
                data_correctness: DataCorrectnessStatus::Unknown,
                availability: AvailabilityStatus::Unknown,
                data_loss: None,
                corruption: None,
                recovered_within_window: None,
            },
            _ => Self {
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

pub(crate) fn write_failure_summary(
    collector: &ArtifactCollector,
    case_name: &str,
    summary: FailureSummary,
) -> Result<()> {
    let summary = summary.with_case_name(case_name);
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
    if let Err(violation) =
        crate::fault::artifact_validation::validate_written_failure_summary(&path)
    {
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
    use super::{FailurePhase, FailureSummary, ResponsibilityDomain};
    use serde_json::json;

    #[test]
    fn checker_classification_projects_to_s3_model_fields() {
        let summary = FailureSummary::new(
            "io-eio",
            "checker-pre-recommit-verdict",
            "data_corruption",
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
                "failure-summary.json",
                "recovery-stability-report.json",
                "checker-pre-recommit-report.json",
                "fault-evidence.json",
                "run-events.jsonl"
            ])
        );
    }

    #[test]
    fn non_checker_failure_projects_to_run_failure_reason() {
        let summary = FailureSummary::new(
            "io-eio",
            "fault-backend-preflight",
            "environment_or_fault_backend",
            "missing chaos mesh",
        );

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
            .with_case_name("fault_io_eio_preserves_committed_objects");
        let value = serde_json::to_value(&summary).expect("summary json");

        assert_eq!(
            value["case_name"],
            json!("fault_io_eio_preserves_committed_objects")
        );
    }
}
