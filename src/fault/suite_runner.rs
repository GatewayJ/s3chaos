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
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::fault::{
    artifact_validation::{ArtifactValidationOptions, validate_fault_artifacts},
    config::{FaultTestConfig, FaultWorkloadProfile, default_percent_for_scenario},
    runner::run_scenario_with_config,
    suite::{ResolvedFaultSuite, ResolvedFaultSuiteScenario, resolve_fault_suite_yaml},
};

pub const FAULT_SUITE_RUN_API_VERSION: &str = "rustfs.com/s3chaos/v1alpha1";
pub const FAULT_SUITE_RUN_KIND: &str = "FaultSuiteRun";

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
    pub stop_on_first_failure: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_duration_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_client_disruptions: Option<usize>,
    pub total_client_disruptions: usize,
    pub attempts: Vec<FaultSuiteRunAttempt>,
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
    pub seed: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_disruptions: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommitted: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub committed: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub async fn run_fault_suite_from_yaml(path: impl AsRef<Path>) -> Result<()> {
    let suite = resolve_fault_suite_yaml(&path)?;
    let base_config = FaultTestConfig::from_env()?;
    base_config.require_destructive_enabled()?;
    validate_suite_runtime_contract(&suite, &base_config)?;

    let run_id = format!("suite-{}", Uuid::new_v4());
    let suite_root = suite_run_root(&base_config, &suite, &run_id);
    fs::create_dir_all(&suite_root)
        .with_context(|| format!("create suite artifact root {}", suite_root.display()))?;
    let summary_path = suite_root.join("suite-summary.json");
    let started = Instant::now();
    let mut summary = FaultSuiteRunSummary::started(&suite, run_id.clone());
    write_summary(&summary_path, &summary)?;

    eprintln!(
        "running destructive RustFS fault suite {} run_id={} artifacts={}",
        suite.metadata.name,
        run_id,
        suite_root.display()
    );

    let mut attempt_index = 0usize;
    'suite: for scenario in &suite.scenarios {
        for repetition in 1..=scenario.repetitions {
            let next_attempt_index = attempt_index + 1;
            let attempt_dir = suite_root.join(format!(
                "{next_attempt_index:03}-{}-r{repetition}",
                scenario.name
            ));
            let config = scenario_config(
                &base_config,
                &suite,
                scenario,
                repetition,
                next_attempt_index,
                &attempt_dir,
            )?;
            if let Some(reason) = suite_duration_budget_failure(
                started.elapsed(),
                suite.budgets.max_duration_seconds,
                &config,
                &scenario.name,
                repetition,
            ) {
                summary.fail(reason);
                write_summary(&summary_path, &summary)?;
                break 'suite;
            }

            attempt_index = next_attempt_index;
            let mut attempt =
                FaultSuiteRunAttempt::running(attempt_index, scenario, repetition, &attempt_dir);
            write_attempt_started(&mut summary, &summary_path, attempt.clone())?;

            eprintln!(
                "suite attempt {} scenario={} repetition={} artifacts={}",
                attempt_index,
                scenario.name,
                repetition,
                attempt_dir.display()
            );

            let result = run_scenario_with_config(config.clone()).await;
            match result {
                Ok(()) => match validate_attempt_artifacts(&config) {
                    Ok(report) => {
                        summary.total_client_disruptions += report.client_disruptions;
                        attempt.succeed(
                            report.seed,
                            report.client_disruptions,
                            report.recommitted,
                            report.committed,
                        );
                        replace_last_attempt(&mut summary, attempt);
                        if let Some(max_disruptions) = suite.budgets.max_client_disruptions
                            && summary.total_client_disruptions > max_disruptions
                        {
                            summary.fail(format!(
                                "suite maxClientDisruptions budget {max_disruptions} was exceeded with {} disruptions",
                                summary.total_client_disruptions
                            ));
                            write_summary(&summary_path, &summary)?;
                            break 'suite;
                        }
                    }
                    Err(error) => {
                        attempt.fail(format!("artifact validation failed: {error}"));
                        replace_last_attempt(&mut summary, attempt);
                        summary.fail(format!(
                            "scenario {} repetition {} artifact validation failed: {error}",
                            scenario.name, repetition
                        ));
                    }
                },
                Err(error) => {
                    attempt.fail(error.to_string());
                    replace_last_attempt(&mut summary, attempt);
                    summary.fail(format!(
                        "scenario {} repetition {} failed: {error}",
                        scenario.name, repetition
                    ));
                }
            }

            write_summary(&summary_path, &summary)?;
            if summary.status == SuiteRunStatus::Failed && suite.budgets.stop_on_first_failure {
                break 'suite;
            }
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
            suite.metadata.name,
            summary_path.display()
        );
    }

    Ok(())
}

fn scenario_config(
    base: &FaultTestConfig,
    suite: &ResolvedFaultSuite,
    scenario: &ResolvedFaultSuiteScenario,
    repetition: usize,
    attempt_index: usize,
    attempt_dir: &Path,
) -> Result<FaultTestConfig> {
    let mut config = base.clone();
    config.scenario = scenario.name.clone();
    if let Some(duration_seconds) = scenario.duration_seconds {
        config.duration = Duration::from_secs(duration_seconds);
    }
    if let Some(percent) = scenario.percent {
        config.percent = percent;
        config.percent_overridden = true;
    } else if !base.percent_overridden {
        config.percent = default_percent_for_scenario(&scenario.name);
        config.percent_overridden = false;
    }
    if let Some(workload) = &scenario.workload {
        let object_count = workload.objects.unwrap_or(config.workload.object_count);
        let concurrency = workload.concurrency.unwrap_or(config.workload.concurrency);
        config.workload = FaultWorkloadProfile::new(object_count, concurrency)?;
        config.prefill_concurrency = config
            .prefill_concurrency
            .min(config.workload.concurrency)
            .min(config.workload.object_count)
            .max(1);
    }
    if let Some(stable_window_seconds) = suite.budgets.recovery_stable_window_seconds {
        config.rustfs_pod_stable_window = Duration::from_secs(stable_window_seconds);
        ensure!(
            config.rustfs_pod_stable_window < config.cluster.timeout,
            "suite budgets.recoveryStableWindowSeconds must be less than RUSTFS_FAULT_TEST_TIMEOUT_SECONDS"
        );
    }
    config.workload_seed = attempt_seed(base.workload_seed, attempt_index, repetition);
    config.cluster.artifacts_dir = attempt_dir.to_path_buf();
    Ok(config)
}

fn validate_suite_runtime_contract(
    suite: &ResolvedFaultSuite,
    base_config: &FaultTestConfig,
) -> Result<()> {
    if let Some(stable_window_seconds) = suite.budgets.recovery_stable_window_seconds {
        ensure!(
            Duration::from_secs(stable_window_seconds) < base_config.cluster.timeout,
            "suite budgets.recoveryStableWindowSeconds must be less than RUSTFS_FAULT_TEST_TIMEOUT_SECONDS"
        );
    }
    Ok(())
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
    let required = config
        .duration
        .checked_add(config.cluster.timeout)
        .unwrap_or(Duration::MAX);
    if remaining < required {
        return Some(format!(
            "suite maxDuration budget {max_duration_seconds}s leaves {}s, but scenario {scenario} repetition {repetition} needs at least {}s (duration {}s + recovery timeout {}s)",
            remaining.as_secs(),
            required.as_secs(),
            config.duration.as_secs(),
            config.cluster.timeout.as_secs()
        ));
    }
    None
}

fn attempt_seed(base_seed: Option<u64>, attempt_index: usize, repetition: usize) -> Option<u64> {
    base_seed.map(|seed| seed ^ ((attempt_index as u64) << 32) ^ repetition as u64)
}

fn validate_attempt_artifacts(
    config: &FaultTestConfig,
) -> Result<crate::fault::artifact_validation::ArtifactValidationReport> {
    let options = ArtifactValidationOptions {
        scenario: config.scenario.clone(),
        artifact_root: config.cluster.artifacts_dir.clone(),
        expected_workload_objects: config.workload.object_count,
        expected_workload_concurrency: config.workload.concurrency,
        expected_rustfs_pod_count: config.expected_rustfs_pod_count,
        expected_stable_window_seconds: config.rustfs_pod_stable_window.as_secs(),
        expected_rustfs_volume_path: config.rustfs_volume_path.clone(),
    };
    validate_fault_artifacts(&options)
}

fn suite_run_root(config: &FaultTestConfig, suite: &ResolvedFaultSuite, run_id: &str) -> PathBuf {
    config
        .cluster
        .artifacts_dir
        .join(&suite.metadata.name)
        .join(run_id)
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
            failure_reason: None,
            stop_on_first_failure: suite.budgets.stop_on_first_failure,
            max_duration_seconds: suite.budgets.max_duration_seconds,
            max_client_disruptions: suite.budgets.max_client_disruptions,
            total_client_disruptions: 0,
            attempts: Vec::new(),
        }
    }

    fn succeed(&mut self) {
        self.status = SuiteRunStatus::Succeeded;
    }

    fn fail(&mut self, reason: String) {
        self.status = SuiteRunStatus::Failed;
        if self.failure_reason.is_none() {
            self.failure_reason = Some(reason);
        }
    }
}

impl FaultSuiteRunAttempt {
    fn running(
        index: usize,
        scenario: &ResolvedFaultSuiteScenario,
        repetition: usize,
        artifacts_dir: &Path,
    ) -> Self {
        Self {
            index,
            scenario: scenario.name.clone(),
            repetition,
            status: SuiteAttemptStatus::Running,
            started_at_ms: now_ms(),
            ended_at_ms: None,
            artifacts_dir: artifacts_dir.display().to_string(),
            seed: None,
            client_disruptions: None,
            recommitted: None,
            committed: None,
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

    fn fail(&mut self, error: String) {
        self.status = SuiteAttemptStatus::Failed;
        self.ended_at_ms = Some(now_ms());
        self.error = Some(error);
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
        attempt_seed, scenario_config, suite_duration_budget_failure,
        validate_suite_runtime_contract,
    };
    use crate::fault::{config::FaultTestConfig, suite::FaultSuite};
    use std::time::Duration;

    #[test]
    fn scenario_config_applies_suite_overrides_and_unique_artifacts() {
        let suite = serde_yaml_ng::from_str::<FaultSuite>(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: rustfs-smoke
budgets:
  recoveryStableWindowSeconds: 30
scenarios:
  - name: io-eio
    duration: 10m
    percent: 35
    workload:
      objects: 64
      concurrency: 8
"#,
        )
        .expect("suite yaml")
        .resolve()
        .expect("resolved suite");
        let base = FaultTestConfig::for_test("real-cluster", "fast-csi");
        let attempt_dir = std::path::PathBuf::from("target/fault-tests/suite/attempt-1");

        let config = scenario_config(&base, &suite, &suite.scenarios[0], 1, 1, &attempt_dir)
            .expect("scenario config");

        assert_eq!(config.scenario, "io-eio");
        assert_eq!(config.duration, Duration::from_secs(600));
        assert_eq!(config.percent, 35);
        assert!(config.percent_overridden);
        assert_eq!(config.workload.object_count, 64);
        assert_eq!(config.workload.concurrency, 8);
        assert_eq!(config.prefill_concurrency, 8);
        assert_eq!(config.rustfs_pod_stable_window, Duration::from_secs(30));
        assert_eq!(config.cluster.artifacts_dir, attempt_dir);
    }

    #[test]
    fn scenario_config_uses_per_scenario_default_percent_without_global_override() {
        let suite = serde_yaml_ng::from_str::<FaultSuite>(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: rustfs-smoke
scenarios:
  - name: disk-full
"#,
        )
        .expect("suite yaml")
        .resolve()
        .expect("resolved suite");
        let base = FaultTestConfig::for_test("real-cluster", "fast-csi");

        let config = scenario_config(
            &base,
            &suite,
            &suite.scenarios[0],
            1,
            1,
            std::path::Path::new("target/fault-tests/suite/disk-full"),
        )
        .expect("scenario config");

        assert_eq!(config.percent, 100);
        assert!(!config.percent_overridden);
    }

    #[test]
    fn attempt_seed_keeps_repetitions_distinct_when_seed_is_fixed() {
        assert_ne!(attempt_seed(Some(42), 1, 1), attempt_seed(Some(42), 2, 1));
        assert_eq!(attempt_seed(None, 1, 1), None);
    }

    #[test]
    fn suite_duration_budget_requires_room_for_attempt_and_recovery() {
        let mut config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        config.duration = Duration::from_secs(600);
        config.cluster.timeout = Duration::from_secs(300);

        assert!(
            suite_duration_budget_failure(
                Duration::from_secs(300),
                Some(1_200),
                &config,
                "io-eio",
                1
            )
            .is_none()
        );

        let error = suite_duration_budget_failure(
            Duration::from_secs(301),
            Some(1_200),
            &config,
            "io-eio",
            1,
        )
        .expect("budget should fail");
        assert!(error.contains("needs at least 900s"));

        assert!(
            suite_duration_budget_failure(Duration::from_secs(10_000), None, &config, "io-eio", 1)
                .is_none()
        );
    }

    #[test]
    fn suite_runtime_contract_rejects_stable_window_that_matches_timeout_before_run_starts() {
        let suite = serde_yaml_ng::from_str::<FaultSuite>(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: rustfs-smoke
budgets:
  recoveryStableWindowSeconds: 300
scenarios:
  - name: io-eio
"#,
        )
        .expect("suite yaml")
        .resolve()
        .expect("resolved suite");
        let base = FaultTestConfig::for_test("real-cluster", "fast-csi");

        let error = validate_suite_runtime_contract(&suite, &base).expect_err("runtime contract");

        assert!(
            error
                .to_string()
                .contains("recoveryStableWindowSeconds must be less")
        );
    }
}
