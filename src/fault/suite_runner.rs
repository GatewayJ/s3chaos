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

use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::fault::{
    artifact_validation::{
        ArtifactValidationOptions, ExpectedFailureArtifactReport,
        validate_expected_failure_artifacts, validate_fault_artifacts_and_write_report,
    },
    config::FaultTestConfig,
    reporting::{FailurePhase, FailureSeverity, FailureSummary, ResponsibilityDomain},
    runner::run_scenario_with_config_and_reference_root,
    suite::{FaultExpectedFailure, ResolvedFaultSuite},
    suite_plan::{
        attempt_minimum_required_duration, build_fault_suite_plan_expansion, suite_run_id,
    },
};

pub use crate::fault::suite_plan::{
    FAULT_SUITE_PLAN_API_VERSION, FAULT_SUITE_PLAN_KIND, FaultSuitePlan, FaultSuitePlanArtifacts,
    FaultSuitePlanAttempt, FaultSuitePlanBudgetImpact, FaultSuitePlanBudgets,
    FaultSuitePlanCluster, FaultSuitePlanFault, FaultSuitePlanPayloadClass,
    FaultSuitePlanSelection, FaultSuitePlanTarget, FaultSuitePlanWorkload,
    plan_fault_suite_from_yaml,
};

pub const FAULT_SUITE_RUN_API_VERSION: &str = "rustfs.com/s3chaos/v1alpha1";
pub const FAULT_SUITE_RUN_KIND: &str = "FaultSuiteRun";

#[derive(Debug, Clone)]
struct PlannedFaultSuiteAttempt {
    plan: FaultSuitePlanAttempt,
    config: FaultTestConfig,
}

#[derive(Debug, Clone)]
struct FaultSuiteExecutionPlan {
    suite: ResolvedFaultSuite,
    plan: FaultSuitePlan,
    attempts: Vec<PlannedFaultSuiteAttempt>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SuiteRunStatus {
    Running,
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SuiteAttemptStatus {
    Running,
    Succeeded,
    ExpectedFailure,
    Failed,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FaultSuiteRunSummary {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub suite: String,
    pub run_id: String,
    pub status: SuiteRunStatus,
    pub started_at_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended_at_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elapsed_seconds: Option<u64>,
    pub failures: Vec<FaultSuiteRunFailure>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_reason: Option<FaultSuiteStopReason>,
    pub stop_on_first_failure: bool,
    pub continue_on_severities: Vec<FailureSeverity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_duration_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_client_disruptions: Option<usize>,
    pub total_client_disruptions: usize,
    pub attempts: Vec<FaultSuiteRunAttempt>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FaultSuiteRunFailure {
    pub index: usize,
    pub kind: FaultSuiteRunFailureKind,
    pub reason: String,
    pub stopped_suite: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attempt_index: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scenario: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repetition: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<FailureSeverity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classification: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<FailurePhase>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s3_model_classification: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_failure_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub responsibility_domain: Option<ResponsibilityDomain>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_evidence_artifacts: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_classifications: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attempt_artifacts_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_summary: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FaultSuiteRunFailureKind {
    AttemptFailure,
    SuiteBudget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum FaultSuiteStopReason {
    Failure {
        #[serde(rename = "failureIndex")]
        failure_index: usize,
    },
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FaultSuiteRunAttempt {
    pub index: usize,
    pub scenario: String,
    pub repetition: usize,
    pub status: SuiteAttemptStatus,
    pub started_at_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended_at_ms: Option<u64>,
    pub artifacts_dir: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_failure: Option<FaultExpectedFailure>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_failure_matched: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seed: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_disruptions: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommitted: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub committed: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<FailureSeverity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classification: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<FailurePhase>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s3_model_classification: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_failure_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub responsibility_domain: Option<ResponsibilityDomain>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_classifications: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub async fn run_fault_suite_from_yaml(path: impl AsRef<Path>) -> Result<()> {
    let suite = crate::fault::suite::resolve_fault_suite_yaml(&path)?;
    let base_config = FaultTestConfig::from_env()?;
    base_config.require_destructive_enabled()?;
    let execution_plan = build_fault_suite_execution_plan(suite, base_config, suite_run_id())?;

    let suite_root = PathBuf::from(&execution_plan.plan.artifact_root);
    fs::create_dir_all(&suite_root)
        .with_context(|| format!("create suite artifact root {}", suite_root.display()))?;
    let summary_path = suite_root.join("suite-summary.json");
    let plan_path = suite_root.join("suite-plan.json");
    let started = Instant::now();
    let mut summary =
        FaultSuiteRunSummary::started(&execution_plan.suite, execution_plan.plan.run_id.clone());
    fs::write(&plan_path, execution_plan.plan.to_json()?)
        .with_context(|| format!("write suite plan {}", plan_path.display()))?;
    write_summary(&summary_path, &summary)?;

    eprintln!(
        "running destructive RustFS fault suite {} run_id={} artifacts={}",
        execution_plan.suite.metadata.name,
        execution_plan.plan.run_id,
        suite_root.display()
    );

    'suite: for planned in &execution_plan.attempts {
        if let Some(reason) = suite_duration_budget_failure(
            started.elapsed(),
            execution_plan.suite.budgets.max_duration_seconds,
            &planned.config,
            &planned.plan.scenario,
            planned.plan.repetition,
        ) {
            summary.record_suite_budget_failure(reason);
            write_summary(&summary_path, &summary)?;
            break 'suite;
        }

        let attempt_dir = Path::new(&planned.plan.artifacts.attempt_dir);
        let mut attempt = FaultSuiteRunAttempt::running(
            planned.plan.index,
            &planned.plan.scenario,
            planned.plan.repetition,
            attempt_dir,
            planned.plan.expected_failure.clone(),
        );
        write_attempt_started(&mut summary, &summary_path, attempt.clone())?;

        eprintln!(
            "suite attempt {} scenario={} repetition={} artifacts={}",
            planned.plan.index,
            planned.plan.scenario,
            planned.plan.repetition,
            attempt_dir.display()
        );

        let result =
            run_scenario_with_config_and_reference_root(planned.config.clone(), suite_root.clone())
                .await;
        let mut stop_after_attempt_failure = false;
        match result {
            Ok(()) => match validate_attempt_artifacts(&planned.config) {
                Ok(report) => {
                    let disruption_budget_failure =
                        summary.record_client_disruptions(report.client_disruptions);
                    attempt.succeed(
                        report.seed,
                        report.client_disruptions,
                        report.recommitted,
                        report.committed,
                    );
                    if planned.plan.expected_failure.is_some() {
                        let attempt_error = format!(
                            "scenario {} repetition {} succeeded, but the suite required the typed expected failure signal",
                            planned.plan.scenario, planned.plan.repetition
                        );
                        attempt.fail(attempt_error.clone(), None);
                        stop_after_attempt_failure = should_stop_after_attempt_failure(
                            &execution_plan.suite.budgets.continue_on_severities,
                            execution_plan.suite.budgets.stop_on_first_failure,
                            None,
                        );
                        summary.record_attempt_failure(
                            &attempt,
                            None,
                            None,
                            attempt_error,
                            stop_after_attempt_failure,
                        );
                    }
                    replace_last_attempt(&mut summary, attempt);
                    if enforce_disruption_budget(&mut summary, disruption_budget_failure) {
                        write_summary(&summary_path, &summary)?;
                        break 'suite;
                    }
                }
                Err(error) => {
                    let (attempt_error, failure_summary_artifact, forced_stop) =
                        artifact_validation_failure_details(
                            &planned.plan,
                            format!("artifact validation failed: {error}"),
                        );
                    attempt.fail(attempt_error.clone(), None);
                    let failure_message = format!(
                        "scenario {} repetition {} failed: {attempt_error}",
                        planned.plan.scenario, planned.plan.repetition
                    );
                    stop_after_attempt_failure = forced_stop;
                    summary.record_attempt_failure(
                        &attempt,
                        None,
                        failure_summary_artifact,
                        failure_message,
                        stop_after_attempt_failure,
                    );
                    replace_last_attempt(&mut summary, attempt);
                }
            },
            Err(error) => {
                let (attempt_error, failure_summary, failure_severity) =
                    attempt_failure_details(&planned.plan, error.to_string());
                let expected_failure_artifacts = planned.plan.expected_failure.as_ref().map(|_| {
                    validate_expected_failure_artifact_contract(
                        &suite_root,
                        &planned.plan,
                        failure_summary.as_ref(),
                        attempt.started_at_ms,
                        now_ms(),
                    )
                });
                let (expected_failure_mismatch, disruption_budget_failure) = match (
                    planned.plan.expected_failure.as_ref(),
                    expected_failure_artifacts.as_ref(),
                ) {
                    (Some(expected), Some(Ok(validation))) => {
                        let evaluation = evaluate_validated_expected_failure(
                            &mut summary,
                            &mut attempt,
                            expected,
                            validation,
                        );
                        (evaluation.mismatch, evaluation.disruption_budget_failure)
                    }
                    (Some(_), Some(Err(error))) => (Some(format!("{error:#}")), None),
                    _ => (None, None),
                };
                if planned.plan.expected_failure.is_some() && expected_failure_mismatch.is_none() {
                    let validation = expected_failure_artifacts
                        .as_ref()
                        .and_then(|result| result.as_ref().ok())
                        .expect("a matched expected failure has validated artifacts");
                    attempt.satisfy_expected_failure(
                        &validation.summary,
                        validation.failure_summary.clone(),
                        validation.client_disruptions,
                    );
                    replace_last_attempt(&mut summary, attempt);
                    if enforce_disruption_budget(&mut summary, disruption_budget_failure) {
                        write_summary(&summary_path, &summary)?;
                        break 'suite;
                    }
                    write_summary(&summary_path, &summary)?;
                    continue 'suite;
                }

                let attempt_error = match expected_failure_mismatch {
                    Some(mismatch) => {
                        format!("{attempt_error}; expected failure did not match: {mismatch}")
                    }
                    None => attempt_error,
                };
                attempt.fail(attempt_error.clone(), failure_summary.as_ref());
                let failure_message = format!(
                    "scenario {} repetition {} failed: {attempt_error}",
                    planned.plan.scenario, planned.plan.repetition
                );
                stop_after_attempt_failure = should_stop_after_attempt_failure(
                    &execution_plan.suite.budgets.continue_on_severities,
                    execution_plan.suite.budgets.stop_on_first_failure,
                    failure_severity,
                );
                summary.record_attempt_failure(
                    &attempt,
                    failure_summary.as_ref(),
                    attempt_failure_summary_artifact(&planned.plan),
                    failure_message,
                    stop_after_attempt_failure,
                );
                replace_last_attempt(&mut summary, attempt);
                if enforce_disruption_budget(&mut summary, disruption_budget_failure) {
                    write_summary(&summary_path, &summary)?;
                    break 'suite;
                }
            }
        }

        write_summary(&summary_path, &summary)?;
        if stop_after_attempt_failure {
            break 'suite;
        }
    }

    if summary.status == SuiteRunStatus::Running {
        summary.succeed();
    }
    summary.ended_at_ms = Some(now_ms());
    summary.elapsed_seconds = Some(started.elapsed().as_secs());
    write_summary(&summary_path, &summary)?;

    eprintln!("suite summary: {}", summary_path.display());
    if summary.status == SuiteRunStatus::Failed {
        bail!(
            "fault suite {} failed; summary: {}",
            execution_plan.suite.metadata.name,
            summary_path.display()
        );
    }

    Ok(())
}

fn build_fault_suite_execution_plan(
    suite: ResolvedFaultSuite,
    base_config: FaultTestConfig,
    run_id: String,
) -> Result<FaultSuiteExecutionPlan> {
    let expansion = build_fault_suite_plan_expansion(suite, base_config, run_id)?;
    let attempts = expansion
        .attempts
        .into_iter()
        .map(|attempt| PlannedFaultSuiteAttempt {
            plan: attempt.plan,
            config: attempt.config,
        })
        .collect();

    Ok(FaultSuiteExecutionPlan {
        suite: expansion.suite,
        plan: expansion.plan,
        attempts,
    })
}

fn suite_duration_budget_failure(
    elapsed: Duration,
    max_duration_seconds: Option<u64>,
    config: &FaultTestConfig,
    scenario: &str,
    repetition: usize,
) -> Option<String> {
    let max_duration_seconds = max_duration_seconds?;
    let max_duration = Duration::from_secs(max_duration_seconds);
    let remaining = match max_duration.checked_sub(elapsed) {
        Some(remaining) => remaining,
        None => {
            return Some(format!(
                "suite maxDuration budget {max_duration_seconds}s was reached before starting scenario {scenario} repetition {repetition}"
            ));
        }
    };
    let required = attempt_minimum_required_duration(config).unwrap_or(Duration::MAX);
    if remaining < required {
        return Some(format!(
            "suite maxDuration budget {max_duration_seconds}s leaves {}s, but scenario {scenario} repetition {repetition} needs at least {}s (fault duration {}s + recovery timeout {}s + recovery stability reread {}s)",
            remaining.as_secs(),
            required.as_secs(),
            config.duration.as_secs(),
            config.cluster.timeout.as_secs(),
            config.recovery_stability_reread.as_secs()
        ));
    }
    None
}

fn validate_attempt_artifacts(
    config: &FaultTestConfig,
) -> Result<crate::fault::artifact_validation::ArtifactValidationReport> {
    let options = ArtifactValidationOptions {
        scenario: config.scenario.clone(),
        artifact_root: config.cluster.artifacts_dir.clone(),
        expected_workload_objects: config.workload.object_count,
        expected_workload_concurrency: config.workload.concurrency,
        expected_workload_versioning: config.workload_versioning,
        expected_rustfs_pod_count: config.expected_rustfs_pod_count,
        expected_stable_window_seconds: config.rustfs_pod_stable_window.as_secs(),
        expected_recovery_stability_reread_seconds: config.recovery_stability_reread.as_secs(),
        expected_rustfs_volume_path: config.rustfs_volume_path.clone(),
    };
    validate_fault_artifacts_and_write_report(&options)
}

fn write_attempt_started(
    summary: &mut FaultSuiteRunSummary,
    path: &Path,
    attempt: FaultSuiteRunAttempt,
) -> Result<()> {
    summary.attempts.push(attempt);
    write_summary(path, summary)
}

fn replace_last_attempt(summary: &mut FaultSuiteRunSummary, attempt: FaultSuiteRunAttempt) {
    if let Some(last) = summary.attempts.last_mut() {
        *last = attempt;
    }
}

fn read_attempt_failure_summary(plan: &FaultSuitePlanAttempt) -> Result<Option<FailureSummary>> {
    let path = Path::new(&plan.artifacts.case_dir).join("failure-summary.json");
    if !path.is_file() {
        return Ok(None);
    }
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("read failure summary {}", path.display()))?;
    let summary = serde_json::from_str::<FailureSummary>(&raw)
        .with_context(|| format!("parse failure summary {}", path.display()))?;
    Ok(Some(summary))
}

fn validate_expected_failure_artifact_contract(
    suite_root: &Path,
    plan: &FaultSuitePlanAttempt,
    observed: Option<&FailureSummary>,
    attempt_started_at_ms: u64,
    evaluated_at_ms: u64,
) -> Result<ExpectedFailureArtifactReport> {
    observed.context("failure-summary.json is missing or unreadable")?;
    validate_expected_failure_artifacts(
        suite_root,
        Path::new(&plan.artifacts.case_dir),
        &plan.scenario,
        &plan.case_name,
        attempt_started_at_ms,
        evaluated_at_ms,
    )
    .context("failure-summary.json does not satisfy the artifact contract")
}

fn validate_expected_failure_match(
    expected: &FaultExpectedFailure,
    validation: &ExpectedFailureArtifactReport,
) -> Result<()> {
    expected.validate_observed(
        validation.summary.classification(),
        validation.summary.severity(),
        validation.summary.responsibility_domain(),
        validation.summary.primary_evidence_refs(),
    )
}

struct ValidatedExpectedFailureEvaluation {
    mismatch: Option<String>,
    disruption_budget_failure: Option<String>,
}

fn evaluate_validated_expected_failure(
    summary: &mut FaultSuiteRunSummary,
    attempt: &mut FaultSuiteRunAttempt,
    expected: &FaultExpectedFailure,
    validation: &ExpectedFailureArtifactReport,
) -> ValidatedExpectedFailureEvaluation {
    // Once the artifact contract is trusted, its safety signal is authoritative
    // even when the diagnostic expectation itself is wrong.
    let disruption_budget_failure =
        account_validated_failure_disruptions(summary, attempt, validation);
    let mismatch = validate_expected_failure_match(expected, validation)
        .err()
        .map(|error| format!("{error:#}"));
    ValidatedExpectedFailureEvaluation {
        mismatch,
        disruption_budget_failure,
    }
}

#[cfg(test)]
fn validate_expected_failure(
    suite_root: &Path,
    plan: &FaultSuitePlanAttempt,
    expected: &FaultExpectedFailure,
    observed: Option<&FailureSummary>,
    attempt_started_at_ms: u64,
    evaluated_at_ms: u64,
) -> Result<ExpectedFailureArtifactReport> {
    let validation = validate_expected_failure_artifact_contract(
        suite_root,
        plan,
        observed,
        attempt_started_at_ms,
        evaluated_at_ms,
    )?;
    validate_expected_failure_match(expected, &validation)?;
    Ok(validation)
}

fn account_validated_failure_disruptions(
    summary: &mut FaultSuiteRunSummary,
    attempt: &mut FaultSuiteRunAttempt,
    validation: &ExpectedFailureArtifactReport,
) -> Option<String> {
    attempt.client_disruptions = Some(validation.client_disruptions);
    summary.record_client_disruptions(validation.client_disruptions)
}

fn enforce_disruption_budget(
    summary: &mut FaultSuiteRunSummary,
    budget_failure: Option<String>,
) -> bool {
    if let Some(reason) = budget_failure {
        summary.record_suite_budget_failure(reason);
        true
    } else {
        false
    }
}

fn attempt_failure_details(
    plan: &FaultSuitePlanAttempt,
    base_error: String,
) -> (String, Option<FailureSummary>, Option<FailureSeverity>) {
    match read_attempt_failure_summary(plan) {
        Ok(summary) => {
            let severity = summary.as_ref().map(FailureSummary::severity);
            (base_error, summary, severity)
        }
        Err(error) => (
            format!("{base_error}; failure-summary.json could not be read: {error}"),
            None,
            None,
        ),
    }
}

fn artifact_validation_failure_details(
    plan: &FaultSuitePlanAttempt,
    base_error: String,
) -> (String, Option<String>, bool) {
    let (attempt_error, _, _) = attempt_failure_details(plan, base_error);
    (attempt_error, attempt_failure_summary_artifact(plan), true)
}

fn attempt_failure_summary_artifact(plan: &FaultSuitePlanAttempt) -> Option<String> {
    let path = Path::new(&plan.artifacts.case_dir).join("failure-summary.json");
    path.is_file().then(|| path.display().to_string())
}

fn primary_evidence_artifacts(
    summary: &FailureSummary,
    failure_summary_artifact: &str,
) -> Option<Vec<String>> {
    if summary.primary_evidence_refs().is_empty() {
        return None;
    }
    let legacy_base = Path::new(failure_summary_artifact)
        .parent()
        .unwrap_or_else(|| Path::new(""));
    Some(
        summary
            .primary_evidence_refs()
            .iter()
            .map(|evidence_ref| {
                let path = Path::new(evidence_ref);
                if path.components().count() == 1 {
                    legacy_base.join(path).display().to_string()
                } else {
                    evidence_ref.clone()
                }
            })
            .collect(),
    )
}

fn should_stop_after_attempt_failure(
    continue_on_severities: &[FailureSeverity],
    stop_on_first_failure: bool,
    severity: Option<FailureSeverity>,
) -> bool {
    if !stop_on_first_failure {
        return false;
    }
    match severity {
        Some(severity) => !continue_on_severities.contains(&severity),
        None => true,
    }
}

fn write_summary(path: &Path, summary: &FaultSuiteRunSummary) -> Result<()> {
    fs::write(path, serde_json::to_string_pretty(summary)?)
        .with_context(|| format!("write suite summary {}", path.display()))
}

impl FaultSuiteRunSummary {
    fn started(suite: &ResolvedFaultSuite, run_id: String) -> Self {
        Self {
            api_version: FAULT_SUITE_RUN_API_VERSION.to_string(),
            kind: FAULT_SUITE_RUN_KIND.to_string(),
            suite: suite.metadata.name.clone(),
            run_id,
            status: SuiteRunStatus::Running,
            started_at_ms: now_ms(),
            ended_at_ms: None,
            elapsed_seconds: None,
            failures: Vec::new(),
            stop_reason: None,
            stop_on_first_failure: suite.budgets.stop_on_first_failure,
            continue_on_severities: suite.budgets.continue_on_severities.clone(),
            max_duration_seconds: suite.budgets.max_duration_seconds,
            max_client_disruptions: suite.budgets.max_client_disruptions,
            total_client_disruptions: 0,
            attempts: Vec::new(),
        }
    }

    fn succeed(&mut self) {
        self.status = SuiteRunStatus::Succeeded;
    }

    fn record_client_disruptions(&mut self, disruptions: usize) -> Option<String> {
        self.total_client_disruptions += disruptions;
        self.max_client_disruptions
            .filter(|max| self.total_client_disruptions > *max)
            .map(|max| {
                format!(
                    "suite maxClientDisruptions budget {max} was exceeded with {} disruptions",
                    self.total_client_disruptions
                )
            })
    }

    fn record_suite_budget_failure(&mut self, reason: String) {
        self.record_failure(FaultSuiteRunFailure {
            index: 0,
            kind: FaultSuiteRunFailureKind::SuiteBudget,
            reason,
            stopped_suite: true,
            attempt_index: None,
            scenario: None,
            repetition: None,
            severity: None,
            classification: None,
            phase: None,
            s3_model_classification: None,
            run_failure_reason: None,
            responsibility_domain: None,
            primary_evidence_artifacts: None,
            evidence_classifications: None,
            attempt_artifacts_dir: None,
            failure_summary: None,
        });
    }

    fn record_attempt_failure(
        &mut self,
        attempt: &FaultSuiteRunAttempt,
        failure_summary: Option<&FailureSummary>,
        failure_summary_artifact: Option<String>,
        reason: String,
        stopped_suite: bool,
    ) {
        let primary_evidence_artifacts = failure_summary.and_then(|summary| {
            failure_summary_artifact
                .as_deref()
                .and_then(|artifact| primary_evidence_artifacts(summary, artifact))
        });
        self.record_failure(FaultSuiteRunFailure {
            index: 0,
            kind: FaultSuiteRunFailureKind::AttemptFailure,
            reason,
            stopped_suite,
            attempt_index: Some(attempt.index),
            scenario: Some(attempt.scenario.clone()),
            repetition: Some(attempt.repetition),
            severity: failure_summary.map(FailureSummary::severity),
            classification: failure_summary.map(|summary| summary.classification().to_string()),
            phase: failure_summary.and_then(FailureSummary::phase),
            s3_model_classification: failure_summary
                .and_then(FailureSummary::s3_model_classification)
                .map(ToString::to_string),
            run_failure_reason: failure_summary
                .and_then(FailureSummary::run_failure_reason)
                .map(ToString::to_string),
            responsibility_domain: failure_summary.and_then(FailureSummary::responsibility_domain),
            primary_evidence_artifacts,
            evidence_classifications: failure_summary.and_then(|summary| {
                (!summary.evidence_classifications().is_empty())
                    .then(|| summary.evidence_classifications().to_vec())
            }),
            attempt_artifacts_dir: Some(attempt.artifacts_dir.clone()),
            failure_summary: failure_summary_artifact,
        });
    }

    fn record_failure(&mut self, mut failure: FaultSuiteRunFailure) {
        self.status = SuiteRunStatus::Failed;
        failure.index = self.failures.len();
        if failure.stopped_suite && self.stop_reason.is_none() {
            self.stop_reason = Some(FaultSuiteStopReason::Failure {
                failure_index: failure.index,
            });
        }
        self.failures.push(failure);
    }
}

impl FaultSuiteRunAttempt {
    fn running(
        index: usize,
        scenario: &str,
        repetition: usize,
        artifacts_dir: &Path,
        expected_failure: Option<FaultExpectedFailure>,
    ) -> Self {
        Self {
            index,
            scenario: scenario.to_string(),
            repetition,
            status: SuiteAttemptStatus::Running,
            started_at_ms: now_ms(),
            ended_at_ms: None,
            artifacts_dir: artifacts_dir.display().to_string(),
            expected_failure,
            expected_failure_matched: None,
            failure_summary: None,
            seed: None,
            client_disruptions: None,
            recommitted: None,
            committed: None,
            severity: None,
            classification: None,
            phase: None,
            s3_model_classification: None,
            run_failure_reason: None,
            responsibility_domain: None,
            evidence_classifications: None,
            error: None,
        }
    }

    fn succeed(&mut self, seed: u64, disruptions: usize, recommitted: usize, committed: usize) {
        self.status = SuiteAttemptStatus::Succeeded;
        self.ended_at_ms = Some(now_ms());
        self.seed = Some(seed);
        self.client_disruptions = Some(disruptions);
        self.recommitted = Some(recommitted);
        self.committed = Some(committed);
    }

    fn fail(&mut self, error: String, failure_summary: Option<&FailureSummary>) {
        self.status = SuiteAttemptStatus::Failed;
        self.ended_at_ms = Some(now_ms());
        if self.expected_failure.is_some() {
            self.expected_failure_matched = Some(false);
        }
        if let Some(summary) = failure_summary {
            self.severity = Some(summary.severity());
            self.classification = Some(summary.classification().to_string());
            self.phase = summary.phase();
            self.s3_model_classification =
                summary.s3_model_classification().map(ToString::to_string);
            self.run_failure_reason = summary.run_failure_reason().map(ToString::to_string);
            self.responsibility_domain = summary.responsibility_domain();
            if !summary.evidence_classifications().is_empty() {
                self.evidence_classifications = Some(summary.evidence_classifications().to_vec());
            }
        }
        self.error = Some(error);
    }

    fn satisfy_expected_failure(
        &mut self,
        failure_summary: &FailureSummary,
        failure_summary_artifact: String,
        client_disruptions: usize,
    ) {
        self.status = SuiteAttemptStatus::ExpectedFailure;
        self.ended_at_ms = Some(now_ms());
        self.expected_failure_matched = Some(true);
        self.failure_summary = Some(failure_summary_artifact);
        self.client_disruptions = Some(client_disruptions);
        self.severity = Some(failure_summary.severity());
        self.classification = Some(failure_summary.classification().to_string());
        self.phase = failure_summary.phase();
        self.s3_model_classification = failure_summary
            .s3_model_classification()
            .map(ToString::to_string);
        self.run_failure_reason = failure_summary
            .run_failure_reason()
            .map(ToString::to_string);
        self.responsibility_domain = failure_summary.responsibility_domain();
        if !failure_summary.evidence_classifications().is_empty() {
            self.evidence_classifications =
                Some(failure_summary.evidence_classifications().to_vec());
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{
        FaultSuiteRunAttempt, FaultSuiteRunFailureKind, FaultSuiteRunSummary, FaultSuiteStopReason,
        SuiteAttemptStatus, SuiteRunStatus, artifact_validation_failure_details,
        attempt_failure_details, build_fault_suite_execution_plan, enforce_disruption_budget,
        evaluate_validated_expected_failure, should_stop_after_attempt_failure,
        suite_duration_budget_failure, validate_expected_failure,
        validate_expected_failure_artifact_contract, write_summary,
    };
    use crate::fault::artifact_validation::validate_expected_failure_artifacts;
    use crate::fault::{
        config::FaultTestConfig,
        plan::FaultInjectionParameters,
        reporting::{
            FailureClassification, FailurePhase, FailureSeverity, FailureSummary,
            ResponsibilityDomain,
        },
        suite::FaultSuite,
    };
    use serde_json::json;
    use std::{fs, path::Path, path::PathBuf, time::Duration};

    #[test]
    fn suite_plan_expands_attempts_artifacts_faults_and_budget() {
        let suite = serde_yaml_ng::from_str::<FaultSuite>(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: rustfs-smoke
budgets:
  maxDuration: 32m
  maxClientDisruptions: 10
  recoveryStableWindowSeconds: 30
scenarios:
  - name: io-eio
    repetitions: 2
    faultDuration: 10m
    percent: 35
    workload:
      objects: 64
      concurrency: 8
"#,
        )
        .expect("suite yaml")
        .resolve()
        .expect("resolved suite");
        let mut base = FaultTestConfig::for_test("real-cluster", "fast-csi");
        base.workload_seed = Some(100);
        base.cluster.artifacts_dir = PathBuf::from("target/fault-tests/artifacts");

        let execution = build_fault_suite_execution_plan(suite, base, "suite-fixed".to_string())
            .expect("suite execution plan");

        assert_eq!(execution.plan.kind, "FaultSuitePlan");
        assert_eq!(execution.plan.suite, "rustfs-smoke");
        assert_eq!(execution.plan.run_id, "suite-fixed");
        assert_eq!(execution.plan.suite_seed, 100);
        assert_eq!(execution.plan.budgets.max_duration_seconds, Some(1920));
        assert_eq!(
            execution.plan.budgets.continue_on_severities,
            vec![FailureSeverity::Degraded]
        );
        assert_eq!(execution.plan.budgets.minimum_required_seconds, 1920);
        assert!(execution.plan.requires_chaos_mesh);
        assert_eq!(
            execution.plan.required_crds,
            vec!["iochaos.chaos-mesh.org".to_string()]
        );
        assert_eq!(execution.plan.attempts.len(), 2);

        let first = &execution.plan.attempts[0];
        assert_eq!(first.index, 1);
        assert_eq!(first.scenario, "io-eio");
        assert_eq!(first.case_name, "fault_io_eio_preserves_committed_objects");
        assert_eq!(first.fault_duration_seconds, 600);
        assert_eq!(first.workload.objects, 64);
        assert_eq!(first.workload.concurrency, 8);
        assert_eq!(first.workload.profile, None);
        assert_eq!(first.workload.operation_mix.put, 1);
        assert_eq!(first.workload.seed, 100 ^ (1_u64 << 32) ^ 1);
        assert!(first.artifacts.attempt_dir.ends_with("001-io-eio-r1"));
        assert!(
            first
                .artifacts
                .case_dir
                .ends_with("001-io-eio-r1/fault_io_eio_preserves_committed_objects")
        );
        assert!(
            first
                .artifacts
                .required
                .contains(&"run-spec.json".to_string())
        );
        assert_eq!(first.budget.fault_duration_seconds, 600);
        assert_eq!(first.budget.recovery_stability_reread_seconds, 60);
        assert_eq!(first.budget.minimum_required_seconds, 960);
        assert_eq!(first.budget.remaining_before_seconds, Some(1920));
        assert_eq!(first.budget.remaining_after_minimum_seconds, Some(960));

        let fault = &first.faults[0];
        assert_eq!(fault.kind, "rustfs_volume_io_error");
        assert_eq!(fault.backend, "chaos-mesh-io-chaos");
        assert_eq!(fault.parameters, FaultInjectionParameters::Default);
        assert_eq!(fault.target.kind, "rustfs-volume");
        assert_eq!(fault.target.path.as_deref(), Some("/data/rustfs0"));
        assert_eq!(fault.selection.kind, "percent");
        assert_eq!(fault.selection.value, 35);
        assert_eq!(
            execution.attempts[0].config.cluster.artifacts_dir,
            PathBuf::from("target/fault-tests/artifacts/rustfs-smoke/suite-fixed/001-io-eio-r1")
        );
    }

    #[test]
    fn suite_plan_carries_typed_params_and_operation_weights() {
        let suite = serde_yaml_ng::from_str::<FaultSuite>(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: rustfs-smoke
scenarios:
  - name: network-delay
    faultDuration: 8m
    params:
      kind: networkDelay
      latency: 350ms
      jitter: 75ms
      correlationPercent: 15
    workload:
      objects: 72
      concurrency: 9
      operationWeights:
        put: 2
        overwrite: 1
        get: 3
        list: 1
        delete: 1
        multipart: 1
      payloadDistribution:
        - sizeBytes: 1024
          weight: 1
        - sizeBytes: 4096
          weight: 3
      hotspot:
        objectPercent: 10
        operationPercent: 70
"#,
        )
        .expect("suite yaml")
        .resolve()
        .expect("resolved suite");
        let mut base = FaultTestConfig::for_test("real-cluster", "fast-csi");
        base.workload_seed = Some(100);

        let execution = build_fault_suite_execution_plan(suite, base, "suite-fixed".to_string())
            .expect("suite execution plan");

        let attempt = &execution.plan.attempts[0];
        assert_eq!(attempt.workload.objects, 72);
        assert_eq!(attempt.workload.concurrency, 9);
        assert_eq!(attempt.workload.operation_mix.put, 2);
        assert_eq!(attempt.workload.operation_mix.get, 3);
        assert_eq!(attempt.workload.payload_distribution[0].object_count, 18);
        assert_eq!(attempt.workload.payload_distribution[1].object_count, 54);
        assert_eq!(
            attempt.workload.hotspot.expect("hotspot").operation_percent,
            70
        );
        assert_eq!(
            attempt.faults[0].parameters,
            FaultInjectionParameters::NetworkDelay {
                latency: "350ms".to_string(),
                jitter: "75ms".to_string(),
                correlation_percent: 15,
            }
        );
        assert_eq!(
            execution.attempts[0].config.scenario_parameters,
            attempt.faults[0].parameters
        );
        assert_eq!(execution.attempts[0].config.workload_operation_mix.get, 3);
        assert!(
            execution.attempts[0]
                .config
                .workload_payload_distribution
                .is_some()
        );
        assert_eq!(
            execution.attempts[0]
                .config
                .workload_hotspot
                .expect("hotspot")
                .object_percent,
            10
        );
    }

    #[test]
    fn suite_plan_applies_reusable_workload_profile() {
        let suite = serde_yaml_ng::from_str::<FaultSuite>(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: rustfs-smoke
workloadProfiles:
  long-read:
    objects: 96
    concurrency: 12
    operationWeights:
      put: 2
      overwrite: 1
      get: 4
      list: 1
      delete: 1
      multipart: 1
    payloadDistribution:
      - sizeBytes: 1024
        weight: 1
      - sizeBytes: 4096
        weight: 1
    hotspot:
      objectPercent: 20
      operationPercent: 80
scenarios:
  - name: io-eio
    faultDuration: 20m
    workloadProfile: long-read
"#,
        )
        .expect("suite yaml")
        .resolve()
        .expect("resolved suite");
        let mut base = FaultTestConfig::for_test("real-cluster", "fast-csi");
        base.workload_seed = Some(100);

        let execution = build_fault_suite_execution_plan(suite, base, "suite-fixed".to_string())
            .expect("suite execution plan");

        let attempt = &execution.plan.attempts[0];
        assert_eq!(attempt.workload.objects, 96);
        assert_eq!(attempt.workload.concurrency, 12);
        assert_eq!(attempt.workload.profile.as_deref(), Some("long-read"));
        assert_eq!(attempt.fault_duration_seconds, 1200);
        assert_eq!(attempt.workload.operation_mix.get, 4);
        assert_eq!(attempt.workload.payload_distribution[0].object_count, 48);
        assert_eq!(attempt.workload.payload_distribution[1].object_count, 48);
        assert_eq!(
            attempt.workload.hotspot.expect("hotspot").operation_percent,
            80
        );

        let config = &execution.attempts[0].config;
        assert_eq!(config.workload.object_count, 96);
        assert_eq!(config.workload.concurrency, 12);
        assert_eq!(config.workload_operation_mix.get, 4);
        assert_eq!(config.workload_hotspot.expect("hotspot").object_percent, 20);
    }

    #[test]
    fn suite_plan_rejects_impossible_max_duration_before_execution() {
        let suite = serde_yaml_ng::from_str::<FaultSuite>(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: rustfs-smoke
budgets:
  maxDuration: 10m
scenarios:
  - name: io-eio
    faultDuration: 10m
"#,
        )
        .expect("suite yaml")
        .resolve()
        .expect("resolved suite");
        let mut base = FaultTestConfig::for_test("real-cluster", "fast-csi");
        base.workload_seed = Some(100);

        let error = build_fault_suite_execution_plan(suite, base, "suite-fixed".to_string())
            .expect_err("budget should fail before execution");

        assert!(error.to_string().contains("cannot cover planned scenario"));
    }

    #[test]
    fn suite_duration_budget_requires_room_for_attempt_and_recovery() {
        let mut config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        config.duration = Duration::from_secs(600);
        config.cluster.timeout = Duration::from_secs(300);

        assert!(
            suite_duration_budget_failure(
                Duration::from_secs(240),
                Some(1_200),
                &config,
                "io-eio",
                1
            )
            .is_none()
        );

        let error = suite_duration_budget_failure(
            Duration::from_secs(241),
            Some(1_200),
            &config,
            "io-eio",
            1,
        )
        .expect("budget should fail");
        assert!(error.contains("needs at least 960s"));

        assert!(
            suite_duration_budget_failure(Duration::from_secs(10_000), None, &config, "io-eio", 1)
                .is_none()
        );
    }

    #[test]
    fn stop_policy_continues_only_configured_severities() {
        assert!(!should_stop_after_attempt_failure(
            &[FailureSeverity::Degraded],
            true,
            Some(FailureSeverity::Degraded)
        ));
        assert!(should_stop_after_attempt_failure(
            &[FailureSeverity::Degraded],
            true,
            Some(FailureSeverity::FailCorrectness)
        ));
        assert!(should_stop_after_attempt_failure(
            &[FailureSeverity::Degraded],
            true,
            None
        ));
        assert!(!should_stop_after_attempt_failure(
            &[],
            false,
            Some(FailureSeverity::FailCorrectness)
        ));
    }

    #[test]
    fn suite_summary_records_failure_history_and_terminal_stop_reason() {
        let suite = single_scenario_suite();
        let mut summary = FaultSuiteRunSummary::started(&suite, "suite-fixed".to_string());

        let degraded = FailureSummary::new(
            "io-eio",
            "checker-pre-recommit-verdict",
            "recovery_tail_read_latency",
            "tail latency",
        )
        .expect("known classification")
        .with_recovered_within_seconds(Some(27));
        let mut first_attempt =
            FaultSuiteRunAttempt::running(1, "io-eio", 1, Path::new("attempts/0001"), None);
        first_attempt.fail("tail latency".to_string(), Some(&degraded));
        summary.record_attempt_failure(
            &first_attempt,
            Some(&degraded),
            Some("attempts/0001/failure-summary.json".to_string()),
            "scenario io-eio repetition 1 failed: tail latency".to_string(),
            false,
        );

        assert_eq!(summary.status, SuiteRunStatus::Failed);
        assert_eq!(summary.stop_reason, None);
        assert_eq!(summary.failures.len(), 1);
        assert_eq!(
            summary.failures[0].kind,
            FaultSuiteRunFailureKind::AttemptFailure
        );
        assert!(!summary.failures[0].stopped_suite);

        let hard_failure = FailureSummary::new(
            "network-delay",
            "checker-pre-recommit-verdict",
            "data_corruption",
            "hash mismatch",
        )
        .expect("known classification")
        .with_evidence_classifications(["ambiguous_write_materialized", "data_corruption"]);
        let mut second_attempt =
            FaultSuiteRunAttempt::running(2, "network-delay", 1, Path::new("attempts/0002"), None);
        second_attempt.fail("hash mismatch".to_string(), Some(&hard_failure));
        assert_eq!(
            second_attempt.evidence_classifications.as_deref(),
            Some(
                &[
                    "ambiguous_write_materialized".to_string(),
                    "data_corruption".to_string()
                ][..]
            )
        );
        summary.record_attempt_failure(
            &second_attempt,
            Some(&hard_failure),
            Some("attempts/0002/failure-summary.json".to_string()),
            "scenario network-delay repetition 1 failed: hash mismatch".to_string(),
            true,
        );

        assert_eq!(
            summary.stop_reason,
            Some(FaultSuiteStopReason::Failure { failure_index: 1 })
        );
        assert_eq!(summary.failures.len(), 2);
        assert!(summary.failures[1].stopped_suite);
        assert_eq!(
            summary.failures[1].severity,
            Some(FailureSeverity::FailCorrectness)
        );
        assert_eq!(
            summary.failures[1].classification.as_deref(),
            Some("data_corruption")
        );
        assert_eq!(summary.failures[1].phase, Some(FailurePhase::Checker));
        assert_eq!(
            summary.failures[1].s3_model_classification.as_deref(),
            Some("data_corruption")
        );
        assert_eq!(summary.failures[1].run_failure_reason, None);
        assert_eq!(
            summary.failures[1].responsibility_domain,
            Some(ResponsibilityDomain::Product)
        );
        assert_eq!(
            summary.failures[1].primary_evidence_artifacts.as_deref(),
            Some(
                &[
                    "attempts/0002/recovery-stability-report.json".to_string(),
                    "attempts/0002/checker-pre-recommit-report.json".to_string(),
                    "attempts/0002/fault-evidence.json".to_string(),
                    "attempts/0002/run-events.jsonl".to_string()
                ][..]
            )
        );
        assert_eq!(
            summary.failures[1].evidence_classifications.as_deref(),
            Some(
                &[
                    "ambiguous_write_materialized".to_string(),
                    "data_corruption".to_string()
                ][..]
            )
        );

        let value = serde_json::to_value(&summary).expect("summary json");
        assert!(value.get("failureReason").is_none());
        assert_eq!(value["stopReason"]["type"], "failure");
        assert_eq!(value["stopReason"]["failureIndex"], 1);
        assert_eq!(value["failures"][0]["stoppedSuite"], false);
        assert_eq!(
            value["failures"][0]["failureSummary"],
            "attempts/0001/failure-summary.json"
        );
        assert_eq!(
            value["failures"][1]["evidenceClassifications"],
            serde_json::json!(["ambiguous_write_materialized", "data_corruption"])
        );
        assert_eq!(value["failures"][1]["phase"], "checker");
        assert_eq!(
            value["failures"][1]["s3ModelClassification"],
            "data_corruption"
        );
        assert_eq!(value["failures"][1]["responsibilityDomain"], "product");
        assert_eq!(
            value["failures"][1]["primaryEvidenceArtifacts"],
            serde_json::json!([
                "attempts/0002/recovery-stability-report.json",
                "attempts/0002/checker-pre-recommit-report.json",
                "attempts/0002/fault-evidence.json",
                "attempts/0002/run-events.jsonl"
            ])
        );
        assert!(value["failures"][1].get("runFailureReason").is_none());
    }

    #[test]
    fn attempt_failure_details_reads_summary_for_severity_policy() {
        let dir = tempfile::tempdir().expect("tempdir");
        let suite = single_scenario_suite();
        let mut base = FaultTestConfig::for_test("real-cluster", "fast-csi");
        base.workload_seed = Some(100);
        base.cluster.artifacts_dir = dir.path().to_path_buf();
        let execution = build_fault_suite_execution_plan(suite, base, "suite-fixed".to_string())
            .expect("suite execution plan");
        let planned = &execution.plan.attempts[0];
        fs::create_dir_all(&planned.artifacts.case_dir).expect("case dir");
        write_failure_summary(
            Path::new(&planned.artifacts.case_dir),
            json!({
                "scenario": "io-eio",
                "stage": "checker-pre-recommit-verdict",
                "verdict": "failed",
                "severity": "degraded",
                "classification": "recovery_tail_read_latency",
                "data_correctness": "passed",
                "availability": "recovered_after_tail_latency",
                "data_loss": false,
                "corruption": false,
                "recovered_within_window": true,
                "recovered_within_seconds": 27,
                "message": "tail latency"
            }),
        );

        let (attempt_error, summary, severity) =
            attempt_failure_details(planned, "scenario failed".to_string());

        assert_eq!(attempt_error, "scenario failed");
        assert_eq!(severity, Some(FailureSeverity::Degraded));
        assert!(!should_stop_after_attempt_failure(
            &[FailureSeverity::Degraded],
            true,
            severity
        ));
        let mut attempt = FaultSuiteRunAttempt::running(
            planned.index,
            &planned.scenario,
            planned.repetition,
            Path::new(&planned.artifacts.attempt_dir),
            None,
        );
        attempt.fail(attempt_error, summary.as_ref());
        assert_eq!(attempt.severity, Some(FailureSeverity::Degraded));
        assert_eq!(
            attempt.classification.as_deref(),
            Some("recovery_tail_read_latency")
        );

        write_failure_summary(
            Path::new(&planned.artifacts.case_dir),
            json!({
                "scenario": "io-eio",
                "stage": "checker-pre-recommit-verdict",
                "verdict": "failed",
                "severity": "fail_correctness",
                "classification": "data_corruption",
                "data_correctness": "failed",
                "availability": "unknown",
                "corruption": true,
                "message": "hash mismatch"
            }),
        );
        let (_, _, severity) = attempt_failure_details(planned, "scenario failed".to_string());

        assert_eq!(severity, Some(FailureSeverity::FailCorrectness));
        assert!(should_stop_after_attempt_failure(
            &[FailureSeverity::Degraded],
            true,
            severity
        ));
    }

    #[test]
    fn artifact_validation_failure_ignores_degraded_summary_for_stop_policy() {
        let dir = tempfile::tempdir().expect("tempdir");
        let suite = single_scenario_suite();
        let mut base = FaultTestConfig::for_test("real-cluster", "fast-csi");
        base.workload_seed = Some(100);
        base.cluster.artifacts_dir = dir.path().to_path_buf();
        let execution = build_fault_suite_execution_plan(suite, base, "suite-fixed".to_string())
            .expect("suite execution plan");
        let planned = &execution.plan.attempts[0];
        fs::create_dir_all(&planned.artifacts.case_dir).expect("case dir");
        write_failure_summary(
            Path::new(&planned.artifacts.case_dir),
            json!({
                "scenario": "io-eio",
                "stage": "checker-pre-recommit-verdict",
                "verdict": "failed",
                "severity": "degraded",
                "classification": "recovery_tail_read_latency",
                "data_correctness": "passed",
                "availability": "recovered_after_tail_latency",
                "data_loss": false,
                "corruption": false,
                "recovered_within_window": true,
                "recovered_within_seconds": 27,
                "message": "tail latency"
            }),
        );

        let (attempt_error, failure_summary_artifact, forced_stop) =
            artifact_validation_failure_details(planned, "artifact validation failed".to_string());

        assert_eq!(attempt_error, "artifact validation failed");
        assert!(failure_summary_artifact.is_some());
        assert!(forced_stop);
        let artifact = failure_summary_artifact.clone();
        let mut attempt = FaultSuiteRunAttempt::running(
            planned.index,
            &planned.scenario,
            planned.repetition,
            Path::new(&planned.artifacts.attempt_dir),
            None,
        );
        attempt.fail(attempt_error, None);
        assert_eq!(attempt.severity, None);
        assert_eq!(attempt.classification, None);

        let mut summary =
            FaultSuiteRunSummary::started(&execution.suite, "suite-fixed".to_string());
        summary.record_attempt_failure(
            &attempt,
            None,
            artifact,
            format!(
                "scenario {} repetition {} failed: artifact validation failed",
                planned.scenario, planned.repetition
            ),
            forced_stop,
        );
        assert_eq!(
            summary.stop_reason,
            Some(FaultSuiteStopReason::Failure { failure_index: 0 })
        );
        assert!(summary.failures[0].stopped_suite);
        assert_eq!(summary.failures[0].severity, None);
        assert!(summary.failures[0].failure_summary.is_some());
    }

    #[test]
    fn attempt_failure_details_surfaces_malformed_summary() {
        let dir = tempfile::tempdir().expect("tempdir");
        let suite = single_scenario_suite();
        let mut base = FaultTestConfig::for_test("real-cluster", "fast-csi");
        base.workload_seed = Some(100);
        base.cluster.artifacts_dir = dir.path().to_path_buf();
        let execution = build_fault_suite_execution_plan(suite, base, "suite-fixed".to_string())
            .expect("suite execution plan");
        let planned = &execution.plan.attempts[0];
        fs::create_dir_all(&planned.artifacts.case_dir).expect("case dir");
        fs::write(
            Path::new(&planned.artifacts.case_dir).join("failure-summary.json"),
            "{not json",
        )
        .expect("write malformed summary");

        let (attempt_error, summary, severity) =
            attempt_failure_details(planned, "scenario failed".to_string());

        assert!(summary.is_none());
        assert_eq!(severity, None);
        assert!(
            attempt_error.contains("failure-summary.json could not be read"),
            "{attempt_error}"
        );
        assert!(should_stop_after_attempt_failure(
            &[FailureSeverity::Degraded],
            true,
            severity
        ));
    }

    #[test]
    fn typed_expected_failure_requires_valid_summary_and_evidence() {
        let dir = tempfile::tempdir().expect("tempdir");
        let suite = expected_failure_suite();
        let mut base = FaultTestConfig::for_test("real-cluster", "fast-csi");
        base.workload_seed = Some(100);
        base.cluster.artifacts_dir = dir.path().to_path_buf();
        let execution = build_fault_suite_execution_plan(suite, base, "suite-fixed".to_string())
            .expect("suite execution plan");
        let planned = &execution.plan.attempts[0];
        let case_dir = Path::new(&planned.artifacts.case_dir);
        fs::create_dir_all(case_dir).expect("case dir");
        let suite_root = dir.path().join("rustfs-smoke/suite-fixed");
        let failure_summary_json = write_expected_failure_artifacts(&suite_root, planned, 1);
        let observed = serde_json::from_value::<FailureSummary>(failure_summary_json.clone())
            .expect("failure summary");
        let expected = planned.expected_failure.as_ref().expect("expected failure");

        let validation =
            validate_expected_failure(&suite_root, planned, expected, Some(&observed), 10, 100)
                .expect("matched expected failure");
        let mut attempt = FaultSuiteRunAttempt::running(
            planned.index,
            &planned.scenario,
            planned.repetition,
            Path::new(&planned.artifacts.attempt_dir),
            Some(expected.clone()),
        );
        attempt.satisfy_expected_failure(
            &observed,
            validation.failure_summary.clone(),
            validation.client_disruptions,
        );

        assert_eq!(attempt.status, SuiteAttemptStatus::ExpectedFailure);
        assert_eq!(attempt.expected_failure_matched, Some(true));
        assert_eq!(attempt.client_disruptions, Some(1));
        assert_eq!(
            attempt.failure_summary.as_deref(),
            Some(validation.failure_summary.as_str())
        );
        let mut run_summary =
            FaultSuiteRunSummary::started(&execution.suite, "suite-fixed".to_string());
        run_summary.max_client_disruptions = Some(1);
        assert_eq!(run_summary.record_client_disruptions(1), None);
        run_summary.attempts.push(attempt);
        run_summary.succeed();
        assert_eq!(run_summary.status, SuiteRunStatus::Succeeded);
        assert!(run_summary.failures.is_empty());
        let suite_summary_json = serde_json::to_value(&run_summary).expect("suite summary json");
        assert_eq!(
            suite_summary_json["attempts"][0]["status"],
            "expected-failure"
        );
        assert_eq!(
            suite_summary_json["attempts"][0]["expectedFailureMatched"],
            true
        );
        assert_eq!(suite_summary_json["totalClientDisruptions"], 1);

        let mut mismatched_expected = expected.clone();
        mismatched_expected.classification = FailureClassification::CommittedObjectUnavailable;
        mismatched_expected.severity = FailureSeverity::FailAvailability;
        let validation = validate_expected_failure_artifact_contract(
            &suite_root,
            planned,
            Some(&observed),
            10,
            100,
        )
        .expect("strict artifact validation remains independent of typed matching");
        let mut budget_summary =
            FaultSuiteRunSummary::started(&execution.suite, "suite-budget".to_string());
        budget_summary.max_client_disruptions = Some(0);
        let mut mismatched_attempt = FaultSuiteRunAttempt::running(
            planned.index,
            &planned.scenario,
            planned.repetition,
            Path::new(&planned.artifacts.attempt_dir),
            Some(mismatched_expected.clone()),
        );
        let evaluation = evaluate_validated_expected_failure(
            &mut budget_summary,
            &mut mismatched_attempt,
            &mismatched_expected,
            &validation,
        );
        assert!(evaluation.mismatch.is_some(), "fixture must mismatch");
        assert!(
            evaluation.disruption_budget_failure.is_some(),
            "mismatch cannot bypass max=0"
        );
        assert_eq!(budget_summary.total_client_disruptions, 1);
        assert_eq!(mismatched_attempt.client_disruptions, Some(1));
        let must_stop =
            enforce_disruption_budget(&mut budget_summary, evaluation.disruption_budget_failure);
        assert!(
            must_stop,
            "the runner must stop before scheduling another destructive attempt"
        );
        assert_eq!(budget_summary.status, SuiteRunStatus::Failed);
        assert!(matches!(
            budget_summary.stop_reason,
            Some(FaultSuiteStopReason::Failure { .. })
        ));
        let mismatch_summary_path = dir.path().join("mismatch-suite-summary.json");
        write_summary(&mismatch_summary_path, &budget_summary).expect("write suite summary");
        let persisted = serde_json::from_str::<serde_json::Value>(
            &fs::read_to_string(mismatch_summary_path).expect("read suite summary"),
        )
        .expect("suite summary json");
        assert_eq!(persisted["totalClientDisruptions"], 1);
        assert_eq!(persisted["status"], "failed");

        let checker_path = case_dir.join("checker-report.json");
        let mut clean_checker = expected_failure_checker_report(&planned.scenario);
        clean_checker["hash_mismatches"] = json!([]);
        clean_checker["passed"] = json!(true);
        fs::write(
            &checker_path,
            serde_json::to_string(&clean_checker).expect("checker json"),
        )
        .expect("write clean checker");
        let error =
            validate_expected_failure(&suite_root, planned, expected, Some(&observed), 10, 100)
                .expect_err("a passing checker without corruption cannot prove data corruption");
        assert!(format!("{error:#}").contains("passed"));

        let mut legacy_summary = failure_summary_json.clone();
        legacy_summary["schema_version"] = json!(1);
        write_failure_summary(case_dir, legacy_summary.clone());
        fs::remove_file(case_dir.join("fault-evidence.json")).expect("remove evidence");
        let legacy_observed =
            serde_json::from_value::<FailureSummary>(legacy_summary).expect("legacy summary");
        let error = validate_expected_failure(
            &suite_root,
            planned,
            expected,
            Some(&legacy_observed),
            10,
            100,
        )
        .expect_err("legacy summary and missing evidence cannot match");
        assert!(format!("{error:#}").contains("schema_version 2"));

        let mut wrong_scenario = write_expected_failure_artifacts(&suite_root, planned, 1);
        wrong_scenario["scenario"] = json!("network-delay");
        write_failure_summary(case_dir, wrong_scenario);
        let error =
            validate_expected_failure(&suite_root, planned, expected, Some(&observed), 10, 100)
                .expect_err("wrong scenario cannot match");
        assert!(format!("{error:#}").contains("does not match current attempt"));

        let mut cross_attempt = write_expected_failure_artifacts(&suite_root, planned, 1);
        let other_case = suite_root.join("002-io-eio-r2").join(&planned.case_name);
        fs::create_dir_all(&other_case).expect("other case");
        fs::copy(
            case_dir.join("fault-evidence.json"),
            other_case.join("fault-evidence.json"),
        )
        .expect("copy cross-attempt evidence");
        cross_attempt["primary_evidence_refs"][1] = json!(
            other_case
                .join("fault-evidence.json")
                .strip_prefix(&suite_root)
                .expect("relative evidence")
                .display()
                .to_string()
        );
        write_failure_summary(case_dir, cross_attempt);
        let error =
            validate_expected_failure(&suite_root, planned, expected, Some(&observed), 10, 100)
                .expect_err("cross-attempt evidence cannot match");
        assert!(format!("{error:#}").contains("current case directory"));

        write_expected_failure_artifacts(&suite_root, planned, 1);
        let fault_evidence_path = case_dir.join("fault-evidence.json");
        let mut fault_evidence: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&fault_evidence_path).expect("read fault evidence"),
        )
        .expect("fault evidence json");
        fault_evidence
            .as_object_mut()
            .expect("fault evidence object")
            .remove("client_disruptions");
        fs::write(
            &fault_evidence_path,
            serde_json::to_string(&fault_evidence).expect("fault evidence json"),
        )
        .expect("write fault evidence");
        let error =
            validate_expected_failure(&suite_root, planned, expected, Some(&observed), 10, 100)
                .expect_err("missing disruption count cannot match");
        assert!(format!("{error:#}").contains("client_disruptions"));

        let error = validate_expected_failure(&suite_root, planned, expected, None, 10, 100)
            .expect_err("missing signal cannot match");
        assert!(error.to_string().contains("missing or unreadable"));
    }

    #[test]
    fn expected_failure_signal_accepts_each_supported_checker_classification() {
        let dir = tempfile::tempdir().expect("tempdir");
        let suite = expected_failure_suite();
        let mut base = FaultTestConfig::for_test("real-cluster", "fast-csi");
        base.workload_seed = Some(100);
        base.cluster.artifacts_dir = dir.path().to_path_buf();
        let execution = build_fault_suite_execution_plan(suite, base, "suite-fixed".to_string())
            .expect("suite execution plan");
        let planned = &execution.plan.attempts[0];
        let suite_root = dir.path().join("rustfs-smoke/suite-fixed");
        let case_dir = Path::new(&planned.artifacts.case_dir);

        for (classification, severity, correctness, availability, signal, value) in [
            (
                "data_corruption",
                "fail_correctness",
                "failed",
                "unknown",
                "hash_mismatches",
                json!(["k: hash mismatch"]),
            ),
            (
                "ambiguous_write_materialized",
                "needs_investigation",
                "unknown",
                "unknown",
                "unknown_writes_materialized",
                json!(["k: ambiguous write materialized"]),
            ),
            (
                "committed_object_unavailable",
                "fail_availability",
                "unknown",
                "committed_object_unavailable",
                "unavailable_committed_objects",
                json!(["k"]),
            ),
            (
                "list_unavailable_or_unknown",
                "fail_availability",
                "unknown",
                "list_unavailable_or_unknown",
                "list_warnings",
                json!(["LIST prefix fault-test/ did not complete"]),
            ),
        ] {
            let mut summary = write_expected_failure_artifacts(&suite_root, planned, 1);
            summary["classification"] = json!(classification);
            summary["s3_model_classification"] = json!(classification);
            summary["severity"] = json!(severity);
            summary["data_correctness"] = json!(correctness);
            summary["availability"] = json!(availability);
            summary["corruption"] = json!(classification == "data_corruption");
            if matches!(
                classification,
                "committed_object_unavailable" | "list_unavailable_or_unknown"
            ) {
                summary["recovered_within_window"] = json!(false);
            }
            write_failure_summary(case_dir, summary);

            let mut checker = expected_failure_checker_report(&planned.scenario);
            checker["hash_mismatches"] = json!([]);
            checker[signal] = value;
            if classification == "list_unavailable_or_unknown" {
                checker["final_list_warning_count"] = json!(1);
            }
            fs::write(
                case_dir.join("checker-report.json"),
                serde_json::to_string(&checker).expect("checker json"),
            )
            .expect("write checker report");

            validate_expected_failure_artifacts(
                &suite_root,
                case_dir,
                &planned.scenario,
                &planned.case_name,
                10,
                100,
            )
            .unwrap_or_else(|error| panic!("{classification} evidence rejected: {error:#}"));
        }
    }

    #[test]
    fn expected_failure_signal_accepts_recovery_tail_evidence() {
        let dir = tempfile::tempdir().expect("tempdir");
        let suite = expected_failure_suite();
        let mut base = FaultTestConfig::for_test("real-cluster", "fast-csi");
        base.workload_seed = Some(100);
        base.cluster.artifacts_dir = dir.path().to_path_buf();
        let execution = build_fault_suite_execution_plan(suite, base, "suite-fixed".to_string())
            .expect("suite execution plan");
        let planned = &execution.plan.attempts[0];
        let suite_root = dir.path().join("rustfs-smoke/suite-fixed");
        let case_dir = Path::new(&planned.artifacts.case_dir);
        let mut summary = write_expected_failure_artifacts(&suite_root, planned, 1);
        let relative_case = case_dir.strip_prefix(&suite_root).expect("relative case");
        let evidence_ref = |name: &str| relative_case.join(name).display().to_string();

        let mut checker = expected_failure_checker_report(&planned.scenario);
        checker["hash_mismatches"] = json!([]);
        checker["unavailable_committed_objects"] =
            json!(["k: outcome=Timeout status=200 error=\"get body read timed out\""]);
        fs::write(
            case_dir.join("checker-pre-recommit-report.json"),
            serde_json::to_string(&checker).expect("checker json"),
        )
        .expect("write checker report");
        let mut recovery = json!({
            "immediate_passed": false,
            "reread_attempted_keys": ["k"],
            "reread_recovered_keys": ["k"],
            "still_unavailable_keys": [],
            "hash_mismatches": [],
            "data_corruption_evidence": [],
            "ambiguous_write_evidence": [],
            "final_list_warning_count": 0,
            "list_warnings": [],
            "harness_errors": [],
            "max_recovery_seconds": 60,
            "recovered_within_seconds": 27,
            "classification": "recovery_tail_read_latency"
        });
        fs::write(
            case_dir.join("recovery-stability-report.json"),
            serde_json::to_string(&recovery).expect("recovery json"),
        )
        .expect("write recovery report");
        summary["stage"] = json!("checker-pre-recommit-verdict");
        summary["classification"] = json!("recovery_tail_read_latency");
        summary["s3_model_classification"] = json!("recovery_tail_read_latency");
        summary["severity"] = json!("degraded");
        summary["data_correctness"] = json!("passed");
        summary["availability"] = json!("recovered_after_tail_latency");
        summary["data_loss"] = json!(false);
        summary["corruption"] = json!(false);
        summary["recovered_within_window"] = json!(true);
        summary["recovered_within_seconds"] = json!(27);
        summary["evidence_classifications"] = json!(["recovery_tail_read_latency"]);
        summary["primary_evidence_refs"] = json!([
            evidence_ref("recovery-stability-report.json"),
            evidence_ref("checker-pre-recommit-report.json"),
            evidence_ref("fault-evidence.json"),
            evidence_ref("run-events.jsonl")
        ]);
        write_failure_summary(case_dir, summary);

        validate_expected_failure_artifacts(
            &suite_root,
            case_dir,
            &planned.scenario,
            &planned.case_name,
            10,
            100,
        )
        .expect("recovery-tail evidence");

        recovery["reread_attempted_keys"] = json!(["other"]);
        recovery["reread_recovered_keys"] = json!(["other"]);
        fs::write(
            case_dir.join("recovery-stability-report.json"),
            serde_json::to_string(&recovery).expect("recovery json"),
        )
        .expect("write recovery report with mismatched key identity");
        let error = validate_expected_failure_artifacts(
            &suite_root,
            case_dir,
            &planned.scenario,
            &planned.case_name,
            10,
            100,
        )
        .expect_err("same-count recovery evidence for another key must be rejected");
        assert!(format!("{error:#}").contains("committed_object_unavailable"));

        recovery["reread_attempted_keys"] = json!(["k"]);
        recovery["reread_recovered_keys"] = json!(["k"]);

        let list_warning = "LIST prefix fault-test/ did not complete";
        checker["final_list_warning_count"] = json!(1);
        checker["list_warnings"] = json!([list_warning]);
        fs::write(
            case_dir.join("checker-pre-recommit-report.json"),
            serde_json::to_string(&checker).expect("checker json"),
        )
        .expect("write checker report with LIST warning");
        recovery["final_list_warning_count"] = json!(1);
        recovery["list_warnings"] = json!([list_warning]);
        fs::write(
            case_dir.join("recovery-stability-report.json"),
            serde_json::to_string(&recovery).expect("recovery json"),
        )
        .expect("write forged tail recovery report");
        let error = validate_expected_failure_artifacts(
            &suite_root,
            case_dir,
            &planned.scenario,
            &planned.case_name,
            10,
            100,
        )
        .expect_err("LIST warning must outrank recovered read-tail evidence");
        assert!(format!("{error:#}").contains("list_unavailable_or_unknown"));
    }

    #[test]
    fn client_disruption_budget_is_checked_for_every_accounted_attempt() {
        let suite = single_scenario_suite();
        let mut summary = FaultSuiteRunSummary::started(&suite, "suite-fixed".to_string());
        summary.max_client_disruptions = Some(0);
        assert_eq!(
            summary.record_client_disruptions(1).as_deref(),
            Some("suite maxClientDisruptions budget 0 was exceeded with 1 disruptions")
        );

        let mut summary = FaultSuiteRunSummary::started(&suite, "suite-fixed".to_string());
        summary.max_client_disruptions = Some(1);
        assert_eq!(summary.record_client_disruptions(1), None);
        assert!(summary.record_client_disruptions(1).is_some());
        assert_eq!(summary.total_client_disruptions, 2);
    }

    fn single_scenario_suite() -> crate::fault::suite::ResolvedFaultSuite {
        serde_yaml_ng::from_str::<FaultSuite>(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: rustfs-smoke
scenarios:
  - name: io-eio
    faultDuration: 10m
"#,
        )
        .expect("suite yaml")
        .resolve()
        .expect("resolved suite")
    }

    fn expected_failure_suite() -> crate::fault::suite::ResolvedFaultSuite {
        serde_yaml_ng::from_str::<FaultSuite>(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: rustfs-smoke
scenarios:
  - name: io-eio
    expectedFailure:
      classification: data_corruption
      severity: fail_correctness
      responsibilityDomain: product
      evidenceRefs:
        - checker-report.json
        - fault-evidence.json
        - run-events.jsonl
"#,
        )
        .expect("suite yaml")
        .resolve()
        .expect("resolved suite")
    }

    fn write_failure_summary(case_dir: &Path, summary: serde_json::Value) {
        fs::write(
            case_dir.join("failure-summary.json"),
            serde_json::to_string_pretty(&summary).expect("json"),
        )
        .expect("write failure summary");
    }

    fn write_expected_failure_artifacts(
        suite_root: &Path,
        planned: &crate::fault::suite_plan::FaultSuitePlanAttempt,
        client_disruptions: usize,
    ) -> serde_json::Value {
        let case_dir = Path::new(&planned.artifacts.case_dir);
        fs::create_dir_all(case_dir).expect("case dir");
        fs::write(
            case_dir.join("run-spec.json"),
            serde_json::to_string(&json!({
                "metadata": {"name": planned.case_name, "run_id": "run-1"},
                "scenario": {"name": planned.scenario, "case_name": planned.case_name}
            }))
            .expect("run spec json"),
        )
        .expect("run spec");
        fs::write(
            case_dir.join("checker-report.json"),
            serde_json::to_string(&expected_failure_checker_report(&planned.scenario))
                .expect("checker json"),
        )
        .expect("checker report");
        fs::write(
            case_dir.join("fault-evidence.json"),
            serde_json::to_string(&json!({
                "scenario": planned.scenario,
                "injected": true,
                "active_during_workload": true,
                "recovered": true,
                "require_client_disruption": false,
                "client_disruptions": client_disruptions,
                "pods_before": [],
                "pods_after": [],
                "active_snapshots": [{}],
                "workload_snapshots": [{}],
                "fault_apply_started_at_ms": 20,
                "fault_active_at_ms": 30,
                "workload_started_at_ms": 40,
                "workload_ended_at_ms": 50,
                "fault_delete_started_at_ms": 60,
                "recovery_started_at_ms": 70,
                "recovery_ended_at_ms": 80
            }))
            .expect("evidence json"),
        )
        .expect("fault evidence");
        fs::write(
            case_dir.join("run-events.jsonl"),
            [
                json!({"at_ms": 10, "scenario": planned.scenario, "run_id": "run-1", "stage": "run", "status": "started", "message": "started"}).to_string(),
                json!({"at_ms": 90, "scenario": planned.scenario, "run_id": "run-1", "stage": "run", "status": "failed", "message": "failed"}).to_string(),
            ]
            .join("\n"),
        )
        .expect("run events");
        let relative_case = case_dir.strip_prefix(suite_root).expect("relative case");
        let evidence_ref = |name: &str| relative_case.join(name).display().to_string();
        let summary = json!({
            "schema_version": 2,
            "scenario": planned.scenario,
            "case_name": planned.case_name,
            "observed_at_ms": 85,
            "stage": "checker-verdict",
            "phase": "checker",
            "verdict": "failed",
            "severity": "fail_correctness",
            "classification": "data_corruption",
            "s3_model_classification": "data_corruption",
            "responsibility_domain": "product",
            "data_correctness": "failed",
            "availability": "unknown",
            "primary_evidence_refs": [
                evidence_ref("checker-report.json"),
                evidence_ref("fault-evidence.json"),
                evidence_ref("run-events.jsonl")
            ],
            "corruption": true,
            "message": "hash mismatch"
        });
        write_failure_summary(case_dir, summary.clone());
        summary
    }

    fn expected_failure_checker_report(scenario: &str) -> serde_json::Value {
        json!({
            "scenario": scenario,
            "run_id": "run-1",
            "committed_puts": 1,
            "expected_live_objects": 1,
            "verified_live_objects": 1,
            "missing_committed_objects": [],
            "unavailable_committed_objects": [],
            "unknown_committed_read_failures": [],
            "hash_mismatches": ["k: hash mismatch"],
            "successful_corrupted_reads": [],
            "unexpected_visible_deleted_objects": [],
            "list_history_warning_count": 0,
            "final_list_warning_count": 0,
            "list_history_warnings": [],
            "list_warnings": [],
            "final_listed_objects": 1,
            "tenant_recovered": true,
            "passed": false
        })
    }
}
