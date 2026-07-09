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

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use crate::fault::{
    checker::RecoveryStabilityReport,
    checker::{CheckerReport, RecoveryStabilityClassification},
    config::{
        DEFAULT_RECOVERY_STABILITY_REREAD_SECONDS, DEFAULT_RUSTFS_POD_COUNT,
        DEFAULT_RUSTFS_POD_STABLE_WINDOW_SECONDS, DEFAULT_RUSTFS_VOLUME_PATH,
        DEFAULT_WORKLOAD_CONCURRENCY, DEFAULT_WORKLOAD_OBJECTS,
    },
    events::{RunEvent, RunEventStatus},
    reporting::{AvailabilityStatus, DataCorrectnessStatus, FailureSeverity, FailureVerdict},
    scenarios,
    spec::{
        FAULT_RUN_API_VERSION, FAULT_RUN_KIND, FaultRunArtifactSpec, FaultRunSpec,
        FaultRunTargetSpec,
    },
    workload::WorkloadPlan,
};

#[derive(Debug, Clone)]
pub struct ArtifactValidationOptions {
    pub scenario: String,
    pub artifact_root: PathBuf,
    pub expected_workload_objects: usize,
    pub expected_workload_concurrency: usize,
    pub expected_workload_versioning: bool,
    pub expected_rustfs_pod_count: usize,
    pub expected_stable_window_seconds: u64,
    pub expected_recovery_stability_reread_seconds: u64,
    pub expected_rustfs_volume_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ArtifactValidationReport {
    pub scenario: String,
    pub case_name: String,
    pub seed: u64,
    pub client_disruptions: usize,
    pub recommitted: usize,
    pub committed: usize,
    pub required_artifacts: Vec<String>,
}

impl ArtifactValidationReport {
    pub fn validation_summary_tsv_row(&self) -> String {
        format!(
            "{}\t{}\t0\t{}\t{}\t{}\t0\t0\t0\t0\ttrue",
            self.scenario, self.seed, self.client_disruptions, self.recommitted, self.committed
        )
    }
}

impl ArtifactValidationOptions {
    pub fn from_env(
        scenario: impl Into<String>,
        artifact_root: impl Into<PathBuf>,
    ) -> Result<Self> {
        Ok(Self {
            scenario: scenario.into(),
            artifact_root: artifact_root.into(),
            expected_workload_objects: env_usize(
                "RUSTFS_FAULT_TEST_WORKLOAD_OBJECTS",
                DEFAULT_WORKLOAD_OBJECTS,
            )?,
            expected_workload_concurrency: env_usize(
                "RUSTFS_FAULT_TEST_WORKLOAD_CONCURRENCY",
                DEFAULT_WORKLOAD_CONCURRENCY,
            )?,
            expected_workload_versioning: env_bool("RUSTFS_FAULT_TEST_WORKLOAD_VERSIONING")?,
            expected_rustfs_pod_count: env_usize(
                "RUSTFS_FAULT_TEST_RUSTFS_POD_COUNT",
                DEFAULT_RUSTFS_POD_COUNT,
            )?,
            expected_stable_window_seconds: env_u64(
                "RUSTFS_FAULT_TEST_RUSTFS_POD_STABLE_WINDOW_SECONDS",
                DEFAULT_RUSTFS_POD_STABLE_WINDOW_SECONDS,
            )?,
            expected_recovery_stability_reread_seconds: env_u64(
                "RUSTFS_FAULT_TEST_RECOVERY_STABILITY_REREAD_SECONDS",
                DEFAULT_RECOVERY_STABILITY_REREAD_SECONDS,
            )?,
            expected_rustfs_volume_path: env_string(
                "RUSTFS_FAULT_TEST_RUSTFS_VOLUME_PATH",
                DEFAULT_RUSTFS_VOLUME_PATH,
            ),
        })
    }
}

pub fn validate_fault_artifacts(
    options: &ArtifactValidationOptions,
) -> Result<ArtifactValidationReport> {
    let scenario_spec = scenarios::scenario_spec(&options.scenario)?;
    validate_conditional_recovery_stability_artifact(
        &options.artifact_root,
        scenario_spec.case_name,
    )?;
    let artifacts = locate_required_artifacts(&options.artifact_root, scenario_spec.case_name)?;

    let metadata_path = required(&artifacts, "run-metadata.json")?;
    ensure_json_field_present(
        metadata_path,
        "/recovery_stability_reread_seconds",
        "run-metadata.json recovery_stability_reread_seconds",
    )?;
    let metadata = read_json::<RunMetadataArtifact>(metadata_path)?;
    ensure!(
        metadata.scenario == options.scenario,
        "run-metadata.json scenario {:?} does not match selected scenario {:?}",
        metadata.scenario,
        options.scenario
    );
    ensure_nonempty(&metadata.run_id, "run-metadata.json run_id")?;
    ensure_nonempty(&metadata.rustfs_image, "run-metadata.json rustfs_image")?;
    ensure_nonempty(&metadata.storage_class, "run-metadata.json storage_class")?;
    ensure_nonempty(&metadata.context, "run-metadata.json context")?;
    ensure!(
        metadata.workload_objects == options.expected_workload_objects,
        "run-metadata.json workload_objects {} does not match expected {}",
        metadata.workload_objects,
        options.expected_workload_objects
    );
    ensure!(
        metadata.workload_concurrency == options.expected_workload_concurrency,
        "run-metadata.json workload_concurrency {} does not match expected {}",
        metadata.workload_concurrency,
        options.expected_workload_concurrency
    );
    ensure!(
        metadata.recovery_stability_reread_seconds
            == options.expected_recovery_stability_reread_seconds,
        "run-metadata.json recovery_stability_reread_seconds {} does not match expected {}",
        metadata.recovery_stability_reread_seconds,
        options.expected_recovery_stability_reread_seconds
    );

    let workload_plan = read_json::<WorkloadPlan>(required(&artifacts, "workload-plan.json")?)?;
    ensure!(
        workload_plan.object_count == options.expected_workload_objects,
        "workload-plan.json object_count {} does not match expected {}",
        workload_plan.object_count,
        options.expected_workload_objects
    );
    ensure!(
        workload_plan.concurrency == options.expected_workload_concurrency,
        "workload-plan.json concurrency {} does not match expected {}",
        workload_plan.concurrency,
        options.expected_workload_concurrency
    );

    let json_spec_path = required(&artifacts, "run-spec.json")?;
    let yaml_spec_path = required(&artifacts, "run-spec.yaml")?;
    ensure_json_field_present(
        json_spec_path,
        "/recovery/recovery_stability_reread_seconds",
        "run-spec.json recovery.recovery_stability_reread_seconds",
    )?;
    ensure_yaml_field_present(
        yaml_spec_path,
        "/recovery/recovery_stability_reread_seconds",
        "run-spec.yaml recovery.recovery_stability_reread_seconds",
    )?;
    let json_spec = read_json::<FaultRunSpec>(json_spec_path)?;
    let yaml_spec = read_yaml::<FaultRunSpec>(yaml_spec_path)?;
    ensure!(
        json_spec == yaml_spec,
        "run spec JSON and YAML artifacts do not describe the same contract"
    );
    validate_run_spec(&json_spec, options)?;

    let events = read_jsonl::<RunEvent>(required(&artifacts, "run-events.jsonl")?)?;
    ensure!(
        has_event(&events, "run", RunEventStatus::Started)
            && has_event(&events, "run", RunEventStatus::Succeeded)
            && has_event(&events, "checker-final", RunEventStatus::Succeeded),
        "run-events.jsonl is missing run started, run succeeded, or checker-final succeeded events"
    );

    let evidence =
        read_json::<FaultEvidenceArtifact>(required(&artifacts, "fault-evidence.json")?)?;
    ensure!(
        evidence.injected && evidence.active_during_workload && evidence.recovered,
        "fault-evidence.json must record injected=true, active_during_workload=true, recovered=true"
    );
    ensure!(
        !evidence.active_snapshots.is_empty() && !evidence.workload_snapshots.is_empty(),
        "fault-evidence.json must include active and workload fault snapshots"
    );

    let prechecker =
        read_json::<CheckerReport>(required(&artifacts, "checker-pre-recommit-report.json")?)?;
    validate_checker_report(
        "checker-pre-recommit-report.json",
        &prechecker,
        options.expected_workload_versioning,
    )?;
    let checker = read_json::<CheckerReport>(required(&artifacts, "checker-report.json")?)?;
    validate_checker_report(
        "checker-report.json",
        &checker,
        options.expected_workload_versioning,
    )?;

    let recommit =
        read_json::<RecommitReportArtifact>(required(&artifacts, "recommit-report.json")?)?;
    ensure!(
        recommit.attempted == recommit.committed
            && recommit.failed == 0
            && recommit.harness_errors == 0
            && recommit.attempts.len() == recommit.attempted,
        "recommit-report.json must have attempted == committed, failed == 0, harness_errors == 0, and attempts length matching attempted"
    );

    let summary =
        read_json::<WorkloadSummaryArtifact>(required(&artifacts, "workload-summary.json")?)?;
    ensure!(
        summary.seed == workload_plan.seed
            && summary.object_count == workload_plan.object_count
            && summary.concurrency == workload_plan.concurrency,
        "workload-summary.json does not match workload-plan.json seed/object_count/concurrency"
    );
    ensure!(
        summary.recommitted_after_recovery == recommit.committed,
        "workload-summary.json recommitted_after_recovery does not match recommit-report.json committed"
    );
    ensure!(
        summary.exercised_all_operation_families(),
        "workload-summary.json did not exercise every required S3 operation family"
    );

    Ok(ArtifactValidationReport {
        scenario: options.scenario.clone(),
        case_name: scenario_spec.case_name.to_string(),
        seed: workload_plan.seed,
        client_disruptions: evidence.client_disruptions,
        recommitted: recommit.committed,
        committed: checker.committed_puts,
        required_artifacts: FaultRunArtifactSpec::required_names(),
    })
}

fn validate_run_spec(spec: &FaultRunSpec, options: &ArtifactValidationOptions) -> Result<()> {
    ensure!(
        spec.api_version == FAULT_RUN_API_VERSION,
        "run-spec apiVersion {:?} does not match {FAULT_RUN_API_VERSION}",
        spec.api_version
    );
    ensure!(
        spec.kind == FAULT_RUN_KIND,
        "run-spec kind {:?} does not match {FAULT_RUN_KIND}",
        spec.kind
    );
    ensure!(
        spec.scenario.name == options.scenario,
        "run-spec scenario {:?} does not match selected scenario {:?}",
        spec.scenario.name,
        options.scenario
    );
    ensure!(
        spec.workload.object_count == options.expected_workload_objects,
        "run-spec workload.object_count {} does not match expected {}",
        spec.workload.object_count,
        options.expected_workload_objects
    );
    ensure!(
        spec.workload.concurrency == options.expected_workload_concurrency,
        "run-spec workload.concurrency {} does not match expected {}",
        spec.workload.concurrency,
        options.expected_workload_concurrency
    );
    ensure!(
        spec.workload.versioning == options.expected_workload_versioning,
        "run-spec workload.versioning {} does not match expected {}",
        spec.workload.versioning,
        options.expected_workload_versioning
    );
    ensure!(
        spec.recovery.expected_rustfs_pod_count == options.expected_rustfs_pod_count,
        "run-spec recovery.expected_rustfs_pod_count {} does not match expected {}",
        spec.recovery.expected_rustfs_pod_count,
        options.expected_rustfs_pod_count
    );
    ensure!(
        spec.recovery.stable_pod_window_seconds == options.expected_stable_window_seconds,
        "run-spec recovery.stable_pod_window_seconds {} does not match expected {}",
        spec.recovery.stable_pod_window_seconds,
        options.expected_stable_window_seconds
    );
    ensure!(
        spec.recovery.recovery_stability_reread_seconds
            == options.expected_recovery_stability_reread_seconds,
        "run-spec recovery.recovery_stability_reread_seconds {} does not match expected {}",
        spec.recovery.recovery_stability_reread_seconds,
        options.expected_recovery_stability_reread_seconds
    );
    ensure!(
        spec.artifacts.event_stream == "run-events.jsonl",
        "run-spec artifacts.event_stream must be run-events.jsonl"
    );
    for required in FaultRunArtifactSpec::required_names() {
        ensure!(
            spec.artifacts.required.contains(&required),
            "run-spec artifacts.required is missing {required}"
        );
    }
    ensure!(
        !spec.faults.is_empty(),
        "run-spec must contain at least one fault"
    );
    for fault in &spec.faults {
        ensure!(
            fault.fault_duration_seconds > 0,
            "run-spec fault {} has zero fault_duration_seconds",
            fault.name
        );
        ensure!(
            !fault.conflict_domain.is_empty(),
            "run-spec fault {} has empty conflict_domain",
            fault.name
        );
        ensure!(
            fault.selection.value > 0,
            "run-spec fault {} has zero selection value",
            fault.name
        );
        validate_run_spec_target(&fault.name, &fault.target, options)?;
    }
    Ok(())
}

fn validate_run_spec_target(
    fault_name: &str,
    target: &FaultRunTargetSpec,
    options: &ArtifactValidationOptions,
) -> Result<()> {
    if target.kind == "rustfs-volume" {
        ensure!(
            target.path.as_deref() == Some(options.expected_rustfs_volume_path.as_str()),
            "run-spec fault {fault_name} rustfs-volume path {:?} does not match expected {:?}",
            target.path,
            options.expected_rustfs_volume_path
        );
    } else {
        ensure!(
            target.path.is_none(),
            "run-spec fault {fault_name} non-volume target must not set path"
        );
    }
    Ok(())
}

fn validate_checker_report(
    name: &str,
    report: &CheckerReport,
    expected_versioning: bool,
) -> Result<()> {
    report
        .require_success()
        .with_context(|| format!("{name} did not pass"))?;
    ensure!(
        report.versioning_expected == expected_versioning,
        "{name} versioning_expected {} does not match expected {}",
        report.versioning_expected,
        expected_versioning
    );
    ensure!(
        report.missing_committed_objects.is_empty()
            && report.unavailable_committed_objects.is_empty()
            && report.unknown_committed_read_failures.is_empty()
            && report.hash_mismatches.is_empty()
            && report.successful_corrupted_reads.is_empty()
            && report.unexpected_visible_deleted_objects.is_empty()
            && report.unknown_writes_materialized.is_empty()
            && report.unknown_write_value_conflicts.is_empty()
            && report.final_list_warning_count == 0
            && report.list_warnings.is_empty()
            && report.committed_writes_missing_version_id_count == 0
            && report.missing_committed_versions.is_empty()
            && report.unavailable_committed_versions.is_empty()
            && report.version_hash_mismatches.is_empty()
            && report.missing_committed_delete_markers.is_empty()
            && report.resurrected_deleted_objects.is_empty()
            && report.tenant_recovered,
        "{name} contains a non-clean checker verdict"
    );
    Ok(())
}

fn locate_required_artifacts(root: &Path, case_name: &str) -> Result<BTreeMap<String, PathBuf>> {
    let mut artifacts = BTreeMap::new();
    for name in FaultRunArtifactSpec::required_names() {
        let path = locate_artifact(root, case_name, &name)
            .with_context(|| format!("locate required artifact {name} under {}", root.display()))?;
        artifacts.insert(name, path);
    }
    Ok(artifacts)
}

fn validate_conditional_recovery_stability_artifact(root: &Path, case_name: &str) -> Result<()> {
    let Some(events_path) = optional_artifact(root, case_name, "run-events.jsonl")? else {
        return Ok(());
    };
    let events = read_jsonl::<RunEvent>(&events_path)?;
    let should_validate = events.iter().any(|event| {
        (event.stage == "checker-pre-recommit" && event.status == RunEventStatus::Failed)
            || event.stage == "recovery-stability-reread"
    });
    if !should_validate {
        return Ok(());
    }

    let recovery_path = locate_artifact(root, case_name, "recovery-stability-report.json")
        .with_context(|| "locate conditional artifact recovery-stability-report.json")?;
    let failure_summary_path = locate_artifact(root, case_name, "failure-summary.json")
        .with_context(|| "locate conditional artifact failure-summary.json")?;
    let recovery = read_json::<RecoveryStabilityReport>(&recovery_path)?;
    validate_recovery_stability_report(&recovery)?;
    let failure_summary = read_json::<FailureSummaryArtifact>(&failure_summary_path)?;
    ensure!(
        failure_summary.classification == recovery.classification.as_str(),
        "failure-summary.json classification {:?} does not match recovery-stability-report.json classification {:?}",
        failure_summary.classification,
        recovery.classification.as_str()
    );
    ensure!(
        failure_summary.stage == "checker-pre-recommit"
            || failure_summary.stage == "checker-pre-recommit-verdict",
        "failure-summary.json stage {:?} is not a pre-recommit recovery-stability stage",
        failure_summary.stage
    );
    ensure!(
        !failure_summary.scenario.trim().is_empty() && !failure_summary.message.trim().is_empty(),
        "failure-summary.json must include non-empty scenario and message"
    );
    validate_recovery_failure_summary_fields(&failure_summary, &recovery)?;
    Ok(())
}

fn validate_recovery_failure_summary_fields(
    summary: &FailureSummaryArtifact,
    recovery: &RecoveryStabilityReport,
) -> Result<()> {
    ensure!(
        summary.verdict == FailureVerdict::Failed,
        "failure-summary.json verdict must be failed for recovery-stability failures"
    );
    ensure!(
        summary.evidence_classifications == recovery.evidence_classifications(),
        "failure-summary.json evidence_classifications {:?} do not match recovery-stability-report.json evidence classifications {:?}",
        summary.evidence_classifications,
        recovery.evidence_classifications()
    );
    match recovery.classification {
        RecoveryStabilityClassification::RecoveryTailReadLatency => {
            ensure!(
                summary.severity == FailureSeverity::Degraded
                    && summary.data_correctness == DataCorrectnessStatus::Passed
                    && summary.availability == AvailabilityStatus::RecoveredAfterTailLatency
                    && summary.data_loss == Some(false)
                    && summary.corruption == Some(false)
                    && summary.recovered_within_window == Some(true),
                "recovery_tail_read_latency failure-summary.json must describe degraded recovered-tail latency without data loss or corruption"
            );
            ensure!(
                summary.recovered_within_seconds == recovery.recovered_within_seconds
                    && summary.recovered_within_seconds.is_some(),
                "recovery_tail_read_latency failure-summary.json recovered_within_seconds must match recovery-stability-report.json"
            );
        }
        RecoveryStabilityClassification::CommittedObjectUnavailable => {
            ensure!(
                summary.severity == FailureSeverity::FailAvailability
                    && summary.data_correctness == DataCorrectnessStatus::Unknown
                    && summary.availability == AvailabilityStatus::CommittedObjectUnavailable
                    && summary.corruption == Some(false)
                    && summary.recovered_within_window == Some(false),
                "committed_object_unavailable failure-summary.json must describe an availability failure with unverified data correctness"
            );
        }
        RecoveryStabilityClassification::DataCorruption => {
            ensure!(
                summary.severity == FailureSeverity::FailCorrectness
                    && summary.data_correctness == DataCorrectnessStatus::Failed
                    && summary.corruption == Some(true),
                "data_corruption failure-summary.json must describe a correctness failure"
            );
        }
        RecoveryStabilityClassification::AmbiguousWriteMaterialized => {
            ensure!(
                summary.severity == FailureSeverity::NeedsInvestigation
                    && summary.data_correctness == DataCorrectnessStatus::Unknown
                    && summary.availability == AvailabilityStatus::Unknown
                    && summary.data_loss.is_none()
                    && summary.corruption == Some(false)
                    && summary.recovered_within_window.is_none()
                    && summary.recovered_within_seconds.is_none(),
                "ambiguous_write_materialized failure-summary.json must describe an explicit ambiguous-write result without proven corruption"
            );
        }
        RecoveryStabilityClassification::HarnessError => {
            ensure!(
                summary.severity == FailureSeverity::Infra
                    && summary.data_correctness == DataCorrectnessStatus::Unknown
                    && summary.availability == AvailabilityStatus::Unknown,
                "harness_error failure-summary.json must describe an infra/harness failure"
            );
        }
    }
    Ok(())
}

fn validate_recovery_stability_report(report: &RecoveryStabilityReport) -> Result<()> {
    ensure_sorted_unique(
        &report.reread_attempted_keys,
        "recovery-stability-report.json reread_attempted_keys",
    )?;
    ensure_sorted_unique(
        &report.reread_recovered_keys,
        "recovery-stability-report.json reread_recovered_keys",
    )?;
    ensure_sorted_unique(
        &report.still_unavailable_keys,
        "recovery-stability-report.json still_unavailable_keys",
    )?;
    ensure_sorted_unique(
        &report.data_corruption_evidence,
        "recovery-stability-report.json data_corruption_evidence",
    )?;
    ensure_sorted_unique(
        &report.ambiguous_write_evidence,
        "recovery-stability-report.json ambiguous_write_evidence",
    )?;
    match report.classification {
        RecoveryStabilityClassification::RecoveryTailReadLatency => {
            ensure!(
                !report.reread_attempted_keys.is_empty()
                    && report.reread_attempted_keys == report.reread_recovered_keys
                    && report.still_unavailable_keys.is_empty()
                    && report.hash_mismatches.is_empty()
                    && report.data_corruption_evidence.is_empty()
                    && report.ambiguous_write_evidence.is_empty()
                    && report.harness_errors.is_empty(),
                "recovery_tail_read_latency requires all attempted keys to be recovered without hard failures"
            );
        }
        RecoveryStabilityClassification::CommittedObjectUnavailable => {
            ensure!(
                !report.still_unavailable_keys.is_empty()
                    && report.hash_mismatches.is_empty()
                    && report.data_corruption_evidence.is_empty()
                    && report.harness_errors.is_empty(),
                "committed_object_unavailable requires still_unavailable_keys without higher-priority recovery failures"
            );
        }
        RecoveryStabilityClassification::DataCorruption => {
            ensure!(
                !report.hash_mismatches.is_empty() || !report.data_corruption_evidence.is_empty(),
                "data_corruption requires hash_mismatches or data_corruption_evidence"
            );
        }
        RecoveryStabilityClassification::AmbiguousWriteMaterialized => {
            ensure!(
                !report.ambiguous_write_evidence.is_empty()
                    && report.hash_mismatches.is_empty()
                    && report.data_corruption_evidence.is_empty()
                    && report.still_unavailable_keys.is_empty()
                    && report.harness_errors.is_empty(),
                "ambiguous_write_materialized requires only ambiguous_write_evidence without harder recovery failures"
            );
        }
        RecoveryStabilityClassification::HarnessError => {
            ensure!(
                !report.harness_errors.is_empty()
                    && report.hash_mismatches.is_empty()
                    && report.data_corruption_evidence.is_empty(),
                "harness_error requires harness_errors without data-corruption evidence"
            );
        }
    }
    Ok(())
}

fn ensure_sorted_unique(values: &[String], field: &str) -> Result<()> {
    for pair in values.windows(2) {
        ensure!(
            pair[0] < pair[1],
            "{field} must be sorted and contain no duplicates"
        );
    }
    Ok(())
}

fn locate_artifact(root: &Path, case_name: &str, name: &str) -> Result<PathBuf> {
    for candidate in [root.join(case_name).join(name), root.join(name)] {
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    recursive_find(root, name)?.with_context(|| format!("required artifact {name} is missing"))
}

fn optional_artifact(root: &Path, case_name: &str, name: &str) -> Result<Option<PathBuf>> {
    for candidate in [root.join(case_name).join(name), root.join(name)] {
        if candidate.is_file() {
            return Ok(Some(candidate));
        }
    }
    recursive_find(root, name)
}

fn recursive_find(root: &Path, name: &str) -> Result<Option<PathBuf>> {
    if !root.exists() {
        return Ok(None);
    }
    for entry in fs::read_dir(root).with_context(|| format!("read dir {}", root.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() && path.file_name().and_then(|file| file.to_str()) == Some(name) {
            return Ok(Some(path));
        }
        if path.is_dir()
            && let Some(found) = recursive_find(&path, name)?
        {
            return Ok(Some(found));
        }
    }
    Ok(None)
}

fn required<'a>(artifacts: &'a BTreeMap<String, PathBuf>, name: &str) -> Result<&'a Path> {
    artifacts
        .get(name)
        .map(PathBuf::as_path)
        .with_context(|| format!("{name} was not located"))
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parse json {}", path.display()))
}

fn read_yaml<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_yaml_ng::from_str(&raw).with_context(|| format!("parse yaml {}", path.display()))
}

fn ensure_json_field_present(path: &Path, pointer: &str, field: &str) -> Result<()> {
    let value = read_json::<Value>(path)?;
    ensure!(
        value.pointer(pointer).is_some(),
        "{field} must be explicitly present"
    );
    Ok(())
}

fn ensure_yaml_field_present(path: &Path, pointer: &str, field: &str) -> Result<()> {
    let value = read_yaml::<Value>(path)?;
    ensure!(
        value.pointer(pointer).is_some(),
        "{field} must be explicitly present"
    );
    Ok(())
}

fn read_jsonl<T: DeserializeOwned>(path: &Path) -> Result<Vec<T>> {
    let file = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut items = Vec::new();
    for (index, line) in reader.lines().enumerate() {
        let line = line.with_context(|| format!("read {} line {}", path.display(), index + 1))?;
        if line.trim().is_empty() {
            continue;
        }
        items.push(
            serde_json::from_str(&line)
                .with_context(|| format!("parse jsonl {} line {}", path.display(), index + 1))?,
        );
    }
    Ok(items)
}

fn has_event(events: &[RunEvent], stage: &str, status: RunEventStatus) -> bool {
    events
        .iter()
        .any(|event| event.stage == stage && event.status == status)
}

fn ensure_nonempty(value: &str, field: &str) -> Result<()> {
    ensure!(!value.trim().is_empty(), "{field} must not be empty");
    Ok(())
}

fn env_string(name: &str, default: &str) -> String {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| default.to_string())
}

fn env_usize(name: &str, default: usize) -> Result<usize> {
    let value = env_string(name, &default.to_string());
    value
        .parse::<usize>()
        .with_context(|| format!("{name} must be an unsigned integer"))
}

fn env_u64(name: &str, default: u64) -> Result<u64> {
    let value = env_string(name, &default.to_string());
    value
        .parse::<u64>()
        .with_context(|| format!("{name} must be an unsigned integer"))
}

fn env_bool(name: &str) -> Result<bool> {
    let Ok(value) = std::env::var(name) else {
        return Ok(false);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(false);
    }
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" => Ok(true),
        "0" | "false" | "no" => Ok(false),
        _ => bail!("{name} must be a boolean: 1/0, true/false, or yes/no"),
    }
}

#[derive(Debug, Deserialize)]
struct RunMetadataArtifact {
    scenario: String,
    run_id: String,
    context: String,
    storage_class: String,
    rustfs_image: String,
    workload_objects: usize,
    workload_concurrency: usize,
    #[serde(default = "default_recovery_stability_reread_seconds")]
    recovery_stability_reread_seconds: u64,
}

fn default_recovery_stability_reread_seconds() -> u64 {
    DEFAULT_RECOVERY_STABILITY_REREAD_SECONDS
}

#[derive(Debug, Deserialize)]
struct FaultEvidenceArtifact {
    injected: bool,
    active_during_workload: bool,
    recovered: bool,
    client_disruptions: usize,
    active_snapshots: Vec<Value>,
    workload_snapshots: Vec<Value>,
}

#[derive(Debug, Deserialize)]
struct RecommitReportArtifact {
    attempted: usize,
    committed: usize,
    failed: usize,
    harness_errors: usize,
    attempts: Vec<Value>,
}

#[derive(Debug, Deserialize)]
struct FailureSummaryArtifact {
    scenario: String,
    stage: String,
    verdict: FailureVerdict,
    severity: FailureSeverity,
    classification: String,
    data_correctness: DataCorrectnessStatus,
    availability: AvailabilityStatus,
    evidence_classifications: Vec<String>,
    data_loss: Option<bool>,
    corruption: Option<bool>,
    recovered_within_window: Option<bool>,
    recovered_within_seconds: Option<u64>,
    message: String,
}

#[derive(Debug, Deserialize)]
struct WorkloadSummaryArtifact {
    seed: u64,
    object_count: usize,
    concurrency: usize,
    recommitted_after_recovery: usize,
    puts: OutcomeCountsArtifact,
    gets: OutcomeCountsArtifact,
    deletes: OutcomeCountsArtifact,
    lists: OutcomeCountsArtifact,
    multipart_completes: OutcomeCountsArtifact,
    multipart_aborts: OutcomeCountsArtifact,
}

impl WorkloadSummaryArtifact {
    fn exercised_all_operation_families(&self) -> bool {
        self.puts.total() > 0
            && self.gets.total() > 0
            && self.deletes.total() > 0
            && self.lists.total() > 0
            && self.multipart_completes.total() > 0
            && self.multipart_aborts.total() > 0
    }
}

#[derive(Debug, Default, Deserialize)]
struct OutcomeCountsArtifact {
    ok: usize,
    not_found: usize,
    failed: usize,
    timeout: usize,
    unknown: usize,
}

impl OutcomeCountsArtifact {
    fn total(&self) -> usize {
        self.ok + self.not_found + self.failed + self.timeout + self.unknown
    }
}

#[cfg(test)]
mod tests {
    use super::{ArtifactValidationOptions, recursive_find, validate_fault_artifacts};
    use crate::fault::{
        spec::{FAULT_RUN_API_VERSION, FAULT_RUN_KIND, FaultRunArtifactSpec},
        workload::WorkloadPlan,
    };
    use serde_json::json;
    use std::fs;

    #[test]
    fn validates_successful_fault_artifacts() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_success_artifacts(dir.path(), "io-eio");
        let options = ArtifactValidationOptions {
            scenario: "io-eio".to_string(),
            artifact_root: dir.path().to_path_buf(),
            expected_workload_objects: 12,
            expected_workload_concurrency: 4,
            expected_workload_versioning: false,
            expected_rustfs_pod_count: 4,
            expected_stable_window_seconds: 60,
            expected_recovery_stability_reread_seconds: 60,
            expected_rustfs_volume_path: "/data/rustfs0".to_string(),
        };

        let report = validate_fault_artifacts(&options).expect("valid artifacts");

        assert_eq!(report.scenario, "io-eio");
        assert_eq!(
            report.validation_summary_tsv_row(),
            "io-eio\t42\t0\t2\t1\t7\t0\t0\t0\t0\ttrue"
        );
    }

    #[test]
    fn rejects_missing_required_artifact() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_success_artifacts(dir.path(), "io-eio");
        fs::remove_file(
            dir.path()
                .join("fault_io_eio_preserves_committed_objects")
                .join("checker-report.json"),
        )
        .expect("remove checker");
        let options = ArtifactValidationOptions {
            scenario: "io-eio".to_string(),
            artifact_root: dir.path().to_path_buf(),
            expected_workload_objects: 12,
            expected_workload_concurrency: 4,
            expected_workload_versioning: false,
            expected_rustfs_pod_count: 4,
            expected_stable_window_seconds: 60,
            expected_recovery_stability_reread_seconds: 60,
            expected_rustfs_volume_path: "/data/rustfs0".to_string(),
        };

        let error = validate_fault_artifacts(&options).expect_err("missing checker");

        assert!(error.to_string().contains("checker-report.json"));
    }

    #[test]
    fn rejects_missing_explicit_recovery_stability_reread_metadata() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_success_artifacts(dir.path(), "io-eio");
        let case_dir = dir.path().join("fault_io_eio_preserves_committed_objects");
        let metadata_path = case_dir.join("run-metadata.json");
        let mut metadata = serde_json::from_str::<serde_json::Value>(
            &fs::read_to_string(&metadata_path).expect("metadata"),
        )
        .expect("metadata json");
        metadata
            .as_object_mut()
            .expect("metadata object")
            .remove("recovery_stability_reread_seconds");
        fs::write(
            &metadata_path,
            serde_json::to_string_pretty(&metadata).expect("json"),
        )
        .expect("rewrite metadata");
        let options = ArtifactValidationOptions {
            scenario: "io-eio".to_string(),
            artifact_root: dir.path().to_path_buf(),
            expected_workload_objects: 12,
            expected_workload_concurrency: 4,
            expected_workload_versioning: false,
            expected_rustfs_pod_count: 4,
            expected_stable_window_seconds: 60,
            expected_recovery_stability_reread_seconds: 60,
            expected_rustfs_volume_path: "/data/rustfs0".to_string(),
        };

        let error = validate_fault_artifacts(&options).expect_err("missing metadata field");

        assert!(
            error
                .to_string()
                .contains("recovery_stability_reread_seconds")
        );
    }

    #[test]
    fn rejects_run_spec_when_versioning_expectation_mismatches() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_success_artifacts(dir.path(), "io-eio");
        let options = ArtifactValidationOptions {
            scenario: "io-eio".to_string(),
            artifact_root: dir.path().to_path_buf(),
            expected_workload_objects: 12,
            expected_workload_concurrency: 4,
            expected_workload_versioning: true,
            expected_rustfs_pod_count: 4,
            expected_stable_window_seconds: 60,
            expected_recovery_stability_reread_seconds: 60,
            expected_rustfs_volume_path: "/data/rustfs0".to_string(),
        };

        let error = validate_fault_artifacts(&options).expect_err("versioning mismatch");

        assert!(error.to_string().contains("run-spec workload.versioning"));
    }

    #[test]
    fn rejects_checker_report_when_versioning_expectation_mismatches() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_success_artifacts(dir.path(), "io-eio");
        let case_dir = dir.path().join("fault_io_eio_preserves_committed_objects");
        rewrite_run_spec_versioning(&case_dir, true);
        let options = ArtifactValidationOptions {
            scenario: "io-eio".to_string(),
            artifact_root: dir.path().to_path_buf(),
            expected_workload_objects: 12,
            expected_workload_concurrency: 4,
            expected_workload_versioning: true,
            expected_rustfs_pod_count: 4,
            expected_stable_window_seconds: 60,
            expected_recovery_stability_reread_seconds: 60,
            expected_rustfs_volume_path: "/data/rustfs0".to_string(),
        };

        let error = validate_fault_artifacts(&options).expect_err("checker versioning mismatch");

        assert!(
            error
                .to_string()
                .contains("checker-pre-recommit-report.json versioning_expected")
        );
    }

    #[test]
    fn rejects_clean_checker_report_with_ambiguous_write_evidence() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_success_artifacts(dir.path(), "io-eio");
        let case_dir = dir.path().join("fault_io_eio_preserves_committed_objects");
        let checker_path = case_dir.join("checker-pre-recommit-report.json");
        let mut checker: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&checker_path).expect("checker report"))
                .expect("checker json");
        checker["unknown_writes_materialized"] = json!(["k: op-2 materialized"]);
        write_json(&case_dir, "checker-pre-recommit-report.json", &checker);
        let options = ArtifactValidationOptions {
            scenario: "io-eio".to_string(),
            artifact_root: dir.path().to_path_buf(),
            expected_workload_objects: 12,
            expected_workload_concurrency: 4,
            expected_workload_versioning: false,
            expected_rustfs_pod_count: 4,
            expected_stable_window_seconds: 60,
            expected_recovery_stability_reread_seconds: 60,
            expected_rustfs_volume_path: "/data/rustfs0".to_string(),
        };

        let error = validate_fault_artifacts(&options).expect_err("ambiguous evidence mismatch");

        assert!(
            error
                .to_string()
                .contains("contains a non-clean checker verdict")
        );
    }

    #[test]
    fn rejects_mismatched_recovery_stability_failure_summary_classification() {
        let dir = tempfile::tempdir().expect("tempdir");
        let case_dir = dir.path().join("fault_io_eio_preserves_committed_objects");
        fs::create_dir_all(&case_dir).expect("case dir");
        fs::write(
            case_dir.join("run-events.jsonl"),
            [
                json!({"at_ms":1,"scenario":"io-eio","run_id":"run-1","stage":"checker-pre-recommit","status":"failed","message":"failed"}).to_string(),
                json!({"at_ms":2,"scenario":"io-eio","run_id":"run-1","stage":"recovery-stability-reread","status":"succeeded","message":"done"}).to_string(),
            ].join("\n"),
        )
        .expect("events");
        write_json(
            &case_dir,
            "recovery-stability-report.json",
            &json!({
                "immediate_passed": false,
                "reread_attempted_keys": ["k"],
                "reread_recovered_keys": ["k"],
                "still_unavailable_keys": [],
                "hash_mismatches": [],
                "data_corruption_evidence": [],
                "harness_errors": [],
                "max_recovery_seconds": 60,
                "classification": "recovery_tail_read_latency"
            }),
        );
        write_json(
            &case_dir,
            "failure-summary.json",
            &json!({
                "scenario": "io-eio",
                "stage": "checker-pre-recommit-verdict",
                "verdict": "failed",
                "severity": "fail_availability",
                "classification": "committed_object_unavailable",
                "evidence_classifications": ["recovery_tail_read_latency"],
                "data_correctness": "unknown",
                "availability": "committed_object_unavailable",
                "corruption": false,
                "recovered_within_window": false,
                "message": "immediate checker failed"
            }),
        );
        let options = ArtifactValidationOptions {
            scenario: "io-eio".to_string(),
            artifact_root: dir.path().to_path_buf(),
            expected_workload_objects: 12,
            expected_workload_concurrency: 4,
            expected_workload_versioning: false,
            expected_rustfs_pod_count: 4,
            expected_stable_window_seconds: 60,
            expected_recovery_stability_reread_seconds: 60,
            expected_rustfs_volume_path: "/data/rustfs0".to_string(),
        };

        let error = validate_fault_artifacts(&options).expect_err("classification mismatch");

        assert!(
            error
                .to_string()
                .contains("failure-summary.json classification")
        );
    }

    #[test]
    fn validates_recovery_tail_failure_summary_severity_fields() {
        let dir = tempfile::tempdir().expect("tempdir");
        let case_name = "fault_io_eio_preserves_committed_objects";
        let case_dir = dir.path().join(case_name);
        fs::create_dir_all(&case_dir).expect("case dir");
        fs::write(
            case_dir.join("run-events.jsonl"),
            [
                json!({"at_ms":1,"scenario":"io-eio","run_id":"run-1","stage":"checker-pre-recommit","status":"failed","message":"failed"}).to_string(),
                json!({"at_ms":2,"scenario":"io-eio","run_id":"run-1","stage":"recovery-stability-reread","status":"succeeded","message":"done"}).to_string(),
            ].join("\n"),
        )
        .expect("events");
        write_json(
            &case_dir,
            "recovery-stability-report.json",
            &json!({
                "immediate_passed": false,
                "reread_attempted_keys": ["k"],
                "reread_recovered_keys": ["k"],
                "still_unavailable_keys": [],
                "hash_mismatches": [],
                "data_corruption_evidence": [],
                "harness_errors": [],
                "max_recovery_seconds": 60,
                "recovered_within_seconds": 27,
                "classification": "recovery_tail_read_latency"
            }),
        );
        write_json(
            &case_dir,
            "failure-summary.json",
            &json!({
                "scenario": "io-eio",
                "stage": "checker-pre-recommit-verdict",
                "verdict": "failed",
                "severity": "degraded",
                "classification": "recovery_tail_read_latency",
                "evidence_classifications": ["recovery_tail_read_latency"],
                "data_correctness": "passed",
                "availability": "recovered_after_tail_latency",
                "data_loss": false,
                "corruption": false,
                "recovered_within_window": true,
                "recovered_within_seconds": 27,
                "message": "immediate checker failed"
            }),
        );

        super::validate_conditional_recovery_stability_artifact(dir.path(), case_name)
            .expect("valid recovery failure fields");
    }

    #[test]
    fn validates_ambiguous_write_failure_summary_severity_fields() {
        let dir = tempfile::tempdir().expect("tempdir");
        let case_name = "fault_io_eio_preserves_committed_objects";
        let case_dir = dir.path().join(case_name);
        fs::create_dir_all(&case_dir).expect("case dir");
        fs::write(
            case_dir.join("run-events.jsonl"),
            [
                json!({"at_ms":1,"scenario":"io-eio","run_id":"run-1","stage":"checker-pre-recommit","status":"failed","message":"failed"}).to_string(),
                json!({"at_ms":2,"scenario":"io-eio","run_id":"run-1","stage":"recovery-stability-reread","status":"succeeded","message":"done"}).to_string(),
            ].join("\n"),
        )
        .expect("events");
        write_json(
            &case_dir,
            "recovery-stability-report.json",
            &json!({
                "immediate_passed": false,
                "reread_attempted_keys": [],
                "reread_recovered_keys": [],
                "still_unavailable_keys": [],
                "hash_mismatches": [],
                "data_corruption_evidence": [],
                "ambiguous_write_evidence": ["ambiguous_write_materialized: k op-2"],
                "harness_errors": [],
                "max_recovery_seconds": 60,
                "classification": "ambiguous_write_materialized"
            }),
        );
        write_json(
            &case_dir,
            "failure-summary.json",
            &json!({
                "scenario": "io-eio",
                "stage": "checker-pre-recommit-verdict",
                "verdict": "failed",
                "severity": "needs_investigation",
                "classification": "ambiguous_write_materialized",
                "evidence_classifications": ["ambiguous_write_materialized"],
                "data_correctness": "unknown",
                "availability": "unknown",
                "corruption": false,
                "message": "immediate checker failed"
            }),
        );

        super::validate_conditional_recovery_stability_artifact(dir.path(), case_name)
            .expect("valid ambiguous write failure fields");
    }

    #[test]
    fn rejects_ambiguous_write_summary_with_proven_loss_fields() {
        let dir = tempfile::tempdir().expect("tempdir");
        let case_name = "fault_io_eio_preserves_committed_objects";
        let case_dir = dir.path().join(case_name);
        fs::create_dir_all(&case_dir).expect("case dir");
        fs::write(
            case_dir.join("run-events.jsonl"),
            [
                json!({"at_ms":1,"scenario":"io-eio","run_id":"run-1","stage":"checker-pre-recommit","status":"failed","message":"failed"}).to_string(),
                json!({"at_ms":2,"scenario":"io-eio","run_id":"run-1","stage":"recovery-stability-reread","status":"succeeded","message":"done"}).to_string(),
            ].join("\n"),
        )
        .expect("events");
        write_json(
            &case_dir,
            "recovery-stability-report.json",
            &json!({
                "immediate_passed": false,
                "reread_attempted_keys": [],
                "reread_recovered_keys": [],
                "still_unavailable_keys": [],
                "hash_mismatches": [],
                "data_corruption_evidence": [],
                "ambiguous_write_evidence": ["ambiguous_write_materialized: k op-2"],
                "harness_errors": [],
                "max_recovery_seconds": 60,
                "classification": "ambiguous_write_materialized"
            }),
        );
        write_json(
            &case_dir,
            "failure-summary.json",
            &json!({
                "scenario": "io-eio",
                "stage": "checker-pre-recommit-verdict",
                "verdict": "failed",
                "severity": "needs_investigation",
                "classification": "ambiguous_write_materialized",
                "evidence_classifications": ["ambiguous_write_materialized"],
                "data_correctness": "unknown",
                "availability": "unknown",
                "data_loss": true,
                "corruption": false,
                "recovered_within_window": false,
                "message": "immediate checker failed"
            }),
        );

        let error = super::validate_conditional_recovery_stability_artifact(dir.path(), case_name)
            .expect_err("ambiguous summary with loss fields");

        assert!(error.to_string().contains("without proven corruption"));
    }

    #[test]
    fn rejects_ambiguous_write_report_with_harder_recovery_evidence() {
        let dir = tempfile::tempdir().expect("tempdir");
        let case_name = "fault_io_eio_preserves_committed_objects";
        let case_dir = dir.path().join(case_name);
        fs::create_dir_all(&case_dir).expect("case dir");
        fs::write(
            case_dir.join("run-events.jsonl"),
            [
                json!({"at_ms":1,"scenario":"io-eio","run_id":"run-1","stage":"checker-pre-recommit","status":"failed","message":"failed"}).to_string(),
                json!({"at_ms":2,"scenario":"io-eio","run_id":"run-1","stage":"recovery-stability-reread","status":"succeeded","message":"done"}).to_string(),
            ].join("\n"),
        )
        .expect("events");
        write_json(
            &case_dir,
            "recovery-stability-report.json",
            &json!({
                "immediate_passed": false,
                "reread_attempted_keys": [],
                "reread_recovered_keys": [],
                "still_unavailable_keys": [],
                "hash_mismatches": ["k: expected old, got other"],
                "data_corruption_evidence": [],
                "ambiguous_write_evidence": ["ambiguous_write_materialized: k op-2"],
                "harness_errors": [],
                "max_recovery_seconds": 60,
                "classification": "ambiguous_write_materialized"
            }),
        );
        write_json(
            &case_dir,
            "failure-summary.json",
            &json!({
                "scenario": "io-eio",
                "stage": "checker-pre-recommit-verdict",
                "verdict": "failed",
                "severity": "needs_investigation",
                "classification": "ambiguous_write_materialized",
                "evidence_classifications": ["ambiguous_write_materialized", "data_corruption"],
                "data_correctness": "unknown",
                "availability": "unknown",
                "corruption": false,
                "message": "immediate checker failed"
            }),
        );

        let error = super::validate_conditional_recovery_stability_artifact(dir.path(), case_name)
            .expect_err("ambiguous report with hard evidence");

        assert!(
            error
                .to_string()
                .contains("without harder recovery failures")
        );
    }

    #[test]
    fn rejects_tail_latency_report_with_ambiguous_evidence() {
        let dir = tempfile::tempdir().expect("tempdir");
        let case_name = "fault_io_eio_preserves_committed_objects";
        let case_dir = dir.path().join(case_name);
        fs::create_dir_all(&case_dir).expect("case dir");
        fs::write(
            case_dir.join("run-events.jsonl"),
            [
                json!({"at_ms":1,"scenario":"io-eio","run_id":"run-1","stage":"checker-pre-recommit","status":"failed","message":"failed"}).to_string(),
                json!({"at_ms":2,"scenario":"io-eio","run_id":"run-1","stage":"recovery-stability-reread","status":"succeeded","message":"done"}).to_string(),
            ].join("\n"),
        )
        .expect("events");
        write_json(
            &case_dir,
            "recovery-stability-report.json",
            &json!({
                "immediate_passed": false,
                "reread_attempted_keys": ["k"],
                "reread_recovered_keys": ["k"],
                "still_unavailable_keys": [],
                "hash_mismatches": [],
                "data_corruption_evidence": [],
                "ambiguous_write_evidence": ["ambiguous_write_materialized: k op-2"],
                "harness_errors": [],
                "max_recovery_seconds": 60,
                "recovered_within_seconds": 27,
                "classification": "recovery_tail_read_latency"
            }),
        );
        write_json(
            &case_dir,
            "failure-summary.json",
            &json!({
                "scenario": "io-eio",
                "stage": "checker-pre-recommit-verdict",
                "verdict": "failed",
                "severity": "degraded",
                "classification": "recovery_tail_read_latency",
                "evidence_classifications": ["ambiguous_write_materialized", "recovery_tail_read_latency"],
                "data_correctness": "passed",
                "availability": "recovered_after_tail_latency",
                "data_loss": false,
                "corruption": false,
                "recovered_within_window": true,
                "recovered_within_seconds": 27,
                "message": "immediate checker failed"
            }),
        );

        let error = super::validate_conditional_recovery_stability_artifact(dir.path(), case_name)
            .expect_err("tail latency with ambiguous evidence");

        assert!(error.to_string().contains("without hard failures"));
    }

    #[test]
    fn rejects_availability_report_with_data_corruption_evidence() {
        let dir = tempfile::tempdir().expect("tempdir");
        let case_name = "fault_io_eio_preserves_committed_objects";
        let case_dir = dir.path().join(case_name);
        fs::create_dir_all(&case_dir).expect("case dir");
        fs::write(
            case_dir.join("run-events.jsonl"),
            [json!({"at_ms":1,"scenario":"io-eio","run_id":"run-1","stage":"checker-pre-recommit","status":"failed","message":"failed"}).to_string()].join("\n"),
        )
        .expect("events");
        write_json(
            &case_dir,
            "recovery-stability-report.json",
            &json!({
                "immediate_passed": false,
                "reread_attempted_keys": [],
                "reread_recovered_keys": [],
                "still_unavailable_keys": ["k"],
                "hash_mismatches": [],
                "data_corruption_evidence": ["unknown_write_value_conflict: k"],
                "ambiguous_write_evidence": [],
                "harness_errors": [],
                "max_recovery_seconds": 60,
                "classification": "committed_object_unavailable"
            }),
        );
        write_json(
            &case_dir,
            "failure-summary.json",
            &json!({
                "scenario": "io-eio",
                "stage": "checker-pre-recommit-verdict",
                "verdict": "failed",
                "severity": "fail_availability",
                "classification": "committed_object_unavailable",
                "evidence_classifications": ["committed_object_unavailable", "data_corruption"],
                "data_correctness": "unknown",
                "availability": "committed_object_unavailable",
                "corruption": false,
                "recovered_within_window": false,
                "message": "immediate checker failed"
            }),
        );

        let error = super::validate_conditional_recovery_stability_artifact(dir.path(), case_name)
            .expect_err("availability report with data evidence");

        assert!(
            error
                .to_string()
                .contains("without higher-priority recovery failures")
        );
    }

    fn write_success_artifacts(root: &std::path::Path, scenario: &str) {
        let case_dir = root.join("fault_io_eio_preserves_committed_objects");
        fs::create_dir_all(&case_dir).expect("case dir");
        let plan = WorkloadPlan::seeded(42, 12, 4);
        let run_spec = json!({
            "apiVersion": FAULT_RUN_API_VERSION,
            "kind": FAULT_RUN_KIND,
            "metadata": {"name": "fault_io_eio_preserves_committed_objects", "run_id": "run-1", "bucket": "bucket"},
            "cluster": {
                "context": "real-cluster",
                "namespace": "rustfs-fault-test",
                "tenant": "fault-test-tenant",
                "storage_class": "fast-csi",
                "rustfs_image": "rustfs:test",
                "chaos_namespace": "chaos-mesh",
                "use_cluster_ip": false
            },
            "scenario": {
                "name": scenario,
                "case_name": "fault_io_eio_preserves_committed_objects",
                "priority": "p0",
                "isolation": "fresh-tenant",
                "impact_policy": "client-disruption-required",
                "boundary": "rustfs-workload/fault-injection",
                "validation": "clean checker"
            },
            "workload": {
                "mode": "s3-mixed",
                "object_count": 12,
                "concurrency": 4,
                "prefill_concurrency": 4,
                "request_timeout_seconds": 30,
                "seed": 42,
                "plan": plan
            },
            "recovery": {
                "timeout_seconds": 300,
                "expected_rustfs_pod_count": 4,
                "stable_pod_window_seconds": 60,
                "recovery_stability_reread_seconds": 60,
                "recommit_unconfirmed_writes": true
            },
            "faults": [{
                "name": "io-eio-00-rustfs-volume-io-error",
                "kind": "rustfs-volume-io-error",
                "backend": "chaos-mesh-io-chaos",
                "target": {"kind": "rustfs-volume", "path": "/data/rustfs0"},
                "selection": {"kind": "percent", "value": 20},
                "fault_duration_seconds": 60,
                "observability": "chaos",
                "conflict_domain": "run-scoped IOChaos"
            }],
            "artifacts": {
                "required": FaultRunArtifactSpec::required_names(),
                "event_stream": "run-events.jsonl"
            }
        });
        write_json(&case_dir, "run-spec.json", &run_spec);
        fs::write(
            case_dir.join("run-spec.yaml"),
            serde_yaml_ng::to_string(&run_spec).expect("yaml"),
        )
        .expect("write yaml");
        fs::write(
            case_dir.join("run-events.jsonl"),
            [
                json!({"at_ms":1,"scenario":scenario,"run_id":"run-1","stage":"run","status":"started","message":"started"}).to_string(),
                json!({"at_ms":2,"scenario":scenario,"run_id":"run-1","stage":"checker-final","status":"succeeded","message":"checked"}).to_string(),
                json!({"at_ms":3,"scenario":scenario,"run_id":"run-1","stage":"run","status":"succeeded","message":"done"}).to_string(),
            ].join("\n"),
        ).expect("write events");
        write_json(
            &case_dir,
            "run-metadata.json",
            &json!({
                "scenario": scenario,
                "case_name": "fault_io_eio_preserves_committed_objects",
                "run_id": "run-1",
                "bucket": "bucket",
                "backend": "chaos-mesh-io-chaos",
                "target": "rustfs-volume",
                "context": "real-cluster",
                "namespace": "rustfs-fault-test",
                "tenant": "fault-test-tenant",
                "storage_class": "fast-csi",
                "rustfs_image": "rustfs:test",
                "artifacts_dir": root.display().to_string(),
                "fault_duration_seconds": 60,
                "percent": 20,
                "fault_selection": ["percent=20"],
                "workload_objects": 12,
                "workload_concurrency": 4,
                "prefill_concurrency": 4,
                "request_timeout_seconds": 30,
                "recovery_stability_reread_seconds": 60,
                "use_cluster_ip": false,
                "require_client_disruption": true,
                "chaos_namespace": "chaos-mesh"
            }),
        );
        write_json(&case_dir, "workload-plan.json", &json!(plan));
        fs::write(case_dir.join("history.jsonl"), "{}\n").expect("history");
        write_json(
            &case_dir,
            "workload-summary.json",
            &json!({
                "seed": 42,
                "object_count": 12,
                "concurrency": 4,
                "total_payload_bytes": 12582912,
                "puts": {"ok": 1, "not_found": 0, "failed": 0, "timeout": 0, "unknown": 0},
                "gets": {"ok": 1, "not_found": 0, "failed": 0, "timeout": 0, "unknown": 0},
                "deletes": {"ok": 1, "not_found": 0, "failed": 0, "timeout": 0, "unknown": 0},
                "lists": {"ok": 1, "not_found": 0, "failed": 0, "timeout": 0, "unknown": 0},
                "multipart_completes": {"ok": 1, "not_found": 0, "failed": 0, "timeout": 0, "unknown": 0},
                "multipart_aborts": {"ok": 1, "not_found": 0, "failed": 0, "timeout": 0, "unknown": 0},
                "recommitted_after_recovery": 1
            }),
        );
        write_json(
            &case_dir,
            "recommit-report.json",
            &json!({
                "attempted": 1,
                "committed": 1,
                "failed": 0,
                "harness_errors": 0,
                "attempts": [{"key": "k", "size_bytes": 1, "sha256": "s", "outcome": "ok", "verify_get_outcome": "ok", "http_status": 200, "error": null, "harness_error": null}]
            }),
        );
        let checker = json!({
            "scenario": scenario,
            "run_id": "run-1",
            "committed_puts": 7,
            "expected_live_objects": 7,
            "verified_live_objects": 7,
            "missing_committed_objects": [],
            "unavailable_committed_objects": [],
            "unknown_committed_read_failures": [],
            "hash_mismatches": [],
            "successful_corrupted_reads": [],
            "unexpected_visible_deleted_objects": [],
            "unknown_writes_materialized": [],
            "list_history_warning_count": 0,
            "final_list_warning_count": 0,
            "list_history_warnings": [],
            "list_warnings": [],
            "final_listed_objects": 7,
            "tenant_recovered": true,
            "passed": true
        });
        write_json(&case_dir, "checker-pre-recommit-report.json", &checker);
        write_json(&case_dir, "checker-report.json", &checker);
        write_json(
            &case_dir,
            "fault-evidence.json",
            &json!({
                "scenario": scenario,
                "backend": "chaos-mesh-io-chaos",
                "target": "rustfs-volume",
                "injected": true,
                "active_during_workload": true,
                "recovered": true,
                "client_disruptions": 2,
                "workload_plan": plan,
                "pods_before": [{"name": "p0", "uid": "u0"}],
                "pods_after": [{"name": "p0", "uid": "u0"}],
                "active_snapshots": [{"stage": "active"}],
                "workload_snapshots": [{"stage": "after-workload"}],
                "dm_recovery_snapshot": null
            }),
        );
    }

    fn write_json(dir: &std::path::Path, name: &str, value: &serde_json::Value) {
        fs::write(
            dir.join(name),
            serde_json::to_string_pretty(value).expect("json"),
        )
        .expect("write json");
    }

    fn rewrite_run_spec_versioning(case_dir: &std::path::Path, versioning: bool) {
        let json_path = case_dir.join("run-spec.json");
        let mut spec = serde_json::from_str::<serde_json::Value>(
            &fs::read_to_string(&json_path).expect("read run spec"),
        )
        .expect("parse run spec");
        spec["workload"]["versioning"] = json!(versioning);
        fs::write(
            &json_path,
            serde_json::to_string_pretty(&spec).expect("json"),
        )
        .expect("write run spec json");
        fs::write(
            case_dir.join("run-spec.yaml"),
            serde_yaml_ng::to_string(&spec).expect("yaml"),
        )
        .expect("write run spec yaml");
    }

    #[test]
    fn recursive_find_returns_none_for_missing_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("does-not-exist");

        assert_eq!(
            recursive_find(&missing, "checker-report.json").expect("find"),
            None
        );
    }

    #[test]
    fn recursive_find_returns_none_when_name_is_absent() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(dir.path().join("other.json"), "{}").expect("write");

        assert_eq!(
            recursive_find(dir.path(), "checker-report.json").expect("find"),
            None
        );
    }

    #[test]
    fn recursive_find_locates_a_nested_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let nested = dir.path().join("a").join("b");
        fs::create_dir_all(&nested).expect("mkdir");
        let target = nested.join("checker-report.json");
        fs::write(&target, "{}").expect("write");

        assert_eq!(
            recursive_find(dir.path(), "checker-report.json").expect("find"),
            Some(target)
        );
    }

    #[test]
    fn recursive_find_matches_by_exact_file_name_not_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        // A directory sharing the searched name must not be returned; only a
        // file with that exact name counts as a hit.
        fs::create_dir_all(dir.path().join("checker-report.json")).expect("mkdir");

        assert_eq!(
            recursive_find(dir.path(), "checker-report.json").expect("find"),
            None
        );
    }
}
