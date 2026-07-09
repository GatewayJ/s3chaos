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
    pub(crate) pods_after: Vec<PodIdentity>,
    pub(crate) active_snapshots: Vec<FaultStatusSnapshot>,
    pub(crate) workload_snapshots: Vec<FaultStatusSnapshot>,
    pub(crate) dm_recovery_snapshot: Option<DmStatusSnapshot>,
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
    scenario: String,
    stage: String,
    verdict: FailureVerdict,
    severity: FailureSeverity,
    classification: String,
    data_correctness: DataCorrectnessStatus,
    availability: AvailabilityStatus,
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
        let details = FailureClassificationDetails::from_classification(&classification);
        Self {
            scenario: scenario.into(),
            stage: stage.into(),
            verdict: FailureVerdict::Failed,
            severity: details.severity,
            classification,
            data_correctness: details.data_correctness,
            availability: details.availability,
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

    pub(crate) fn classification(&self) -> &str {
        &self.classification
    }

    pub(crate) fn evidence_classifications(&self) -> &[String] {
        &self.evidence_classifications
    }
}

fn is_zero(value: &usize) -> bool {
    *value == 0
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
    collector.write_text(
        case_name,
        "failure-summary.json",
        &serde_json::to_string_pretty(&summary)?,
    )?;
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
