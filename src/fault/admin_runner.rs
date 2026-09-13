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

use anyhow::{Context, Result, anyhow, bail, ensure};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::fault::{
    config::FaultTestConfig,
    plan::{AdminExecutionPlan, ExecutionPlan},
    scenarios::FaultScenario,
    shutdown::RunDeadline,
};
use crate::framework::artifacts::ArtifactCollector;

pub(crate) const ADMIN_WORKFLOW_ARTIFACT: &str = "admin-workflow.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminWorkflowObservation {
    Running,
    Completed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminCancelOutcome {
    CanceledOwnedOperation,
    NoOwnedOperation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum AdminWorkflowPhaseStatus {
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AdminWorkflowPhaseEvidence {
    pub phase: String,
    pub status: AdminWorkflowPhaseStatus,
    pub started_at_ms: u64,
    pub ended_at_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AdminWorkflowEvidence {
    pub schema_version: u8,
    pub scenario: String,
    pub run_id: String,
    pub phases: Vec<AdminWorkflowPhaseEvidence>,
    pub completed: bool,
    pub cancel_attempted: bool,
    pub cleanup_succeeded: bool,
}

impl AdminWorkflowEvidence {
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1,
            "admin workflow schema is unsupported"
        );
        ensure!(
            !self.scenario.trim().is_empty() && !self.run_id.trim().is_empty(),
            "admin workflow evidence lacks scenario or run identity"
        );
        ensure!(
            !self.phases.is_empty(),
            "admin workflow has no phase evidence"
        );
        ensure!(
            self.phases.iter().all(|phase| {
                !phase.phase.trim().is_empty()
                    && phase.started_at_ms > 0
                    && phase.started_at_ms <= phase.ended_at_ms
                    && (phase.status == AdminWorkflowPhaseStatus::Failed) == phase.error.is_some()
            }),
            "admin workflow contains an invalid phase receipt"
        );
        ensure!(
            self.phases
                .windows(2)
                .all(|pair| pair[0].ended_at_ms <= pair[1].started_at_ms),
            "admin workflow phase receipts are not monotonic"
        );
        let phase_names = self
            .phases
            .iter()
            .map(|phase| phase.phase.as_str())
            .collect::<Vec<_>>();
        ensure!(
            phase_names[0] == "start",
            "admin workflow must start with start"
        );
        ensure!(
            phase_names.last() == Some(&"cleanup"),
            "admin workflow must end with cleanup"
        );
        ensure!(
            self.cleanup_succeeded
                == self.phases.last().is_some_and(|phase| {
                    phase.phase == "cleanup" && phase.status == AdminWorkflowPhaseStatus::Succeeded
                }),
            "admin workflow cleanup summary contradicts its receipt"
        );
        if self.completed {
            ensure!(
                phase_names == ["start", "operation-workload-overlap", "verify", "cleanup"]
                    && self
                        .phases
                        .iter()
                        .all(|phase| phase.status == AdminWorkflowPhaseStatus::Succeeded)
                    && !self.cancel_attempted,
                "completed admin workflow has a failed, canceled, or missing phase"
            );
        } else {
            ensure!(
                self.phases
                    .iter()
                    .any(|phase| phase.status == AdminWorkflowPhaseStatus::Failed),
                "incomplete admin workflow must preserve a failed phase receipt"
            );
        }
        Ok(())
    }
}

pub(crate) struct AdminWorkflowExecution {
    pub(crate) evidence: AdminWorkflowEvidence,
    pub(crate) error: Option<anyhow::Error>,
}

#[async_trait]
pub(crate) trait AdminCaseDriver: Send + Sync {
    /// Starts the typed RustFS admin operation and retains its raw receipt.
    async fn start(&self) -> Result<()>;

    /// Polls once and classifies only this scenario's terminal semantics.
    async fn observe(&self) -> Result<AdminWorkflowObservation>;

    /// Runs the finite, run-owned S3 workload after admin start.
    async fn run_workload(&self) -> Result<()>;

    /// Proves interval overlap from run-owned operation/status and S3
    /// receipts when the operation reaches terminal state before the runner
    /// observes a `Running` sample.
    async fn verify_completed_overlap(&self) -> Result<()> {
        bail!("admin operation completed before overlap with the workload was observed")
    }

    /// Verifies scenario-specific admin receipts and the committed S3 model.
    async fn verify(&self) -> Result<()>;

    /// Reconciles a possibly ambiguous start and stops or cancels only an
    /// operation proven to belong to this attempt.
    ///
    /// The runner invokes this hook after every failed phase, including a
    /// failed or timed-out `start`: an accepted request may lose its response.
    /// Drivers must return [`AdminCancelOutcome::NoOwnedOperation`] when no
    /// attempt-owned operation can be proven instead of touching ambient work.
    async fn cancel(&self) -> Result<AdminCancelOutcome>;

    /// Restores non-destructive runner resources and flushes pending evidence.
    async fn cleanup(&self) -> Result<()>;
}

pub(crate) async fn execute_admin_workflow<D: AdminCaseDriver + ?Sized>(
    scenario: &str,
    run_id: &str,
    driver: &D,
    deadline: RunDeadline,
    poll_interval: Duration,
    operation_timeout: Duration,
    recovery_timeout: Duration,
) -> AdminWorkflowExecution {
    let mut evidence = AdminWorkflowEvidence {
        schema_version: 1,
        scenario: scenario.to_string(),
        run_id: run_id.to_string(),
        phases: Vec::new(),
        completed: false,
        cancel_attempted: false,
        cleanup_succeeded: false,
    };
    let operation_deadline = tokio::time::Instant::now()
        .checked_add(operation_timeout)
        .filter(|_| !operation_timeout.is_zero());
    let mut primary = match operation_deadline {
        Some(operation_deadline) if !poll_interval.is_zero() && !recovery_timeout.is_zero() => {
            run_phase(
                &mut evidence,
                "start",
                run_operation_phase(deadline, operation_deadline, "start", driver.start()),
            )
            .await
        }
        _ => {
            run_phase(&mut evidence, "start", async {
                bail!(
                    "admin workflow poll interval, operation timeout, and recovery timeout must be positive"
                )
            })
            .await
        }
    };
    if primary.is_none()
        && let Some(operation_deadline) = operation_deadline
    {
        let (workload_started_tx, workload_started_rx) = tokio::sync::oneshot::channel();
        let workload = async {
            let _ = workload_started_tx.send(());
            driver.run_workload().await
        };
        let operation = async {
            workload_started_rx
                .await
                .map_err(|_| anyhow!("admin workload ended before overlap observation began"))?;
            wait_for_admin_completion(driver, deadline, operation_deadline, poll_interval).await
        };
        let overlap = async {
            let (_, observed_running) = tokio::try_join!(
                run_operation_phase(deadline, operation_deadline, "workload", workload),
                operation,
            )?;
            if !observed_running {
                run_operation_phase(
                    deadline,
                    operation_deadline,
                    "completed-operation overlap proof",
                    driver.verify_completed_overlap(),
                )
                .await?;
            }
            Ok(())
        };
        primary = run_phase(&mut evidence, "operation-workload-overlap", overlap).await;
    }

    if primary.is_none()
        && let Some(operation_deadline) = operation_deadline
    {
        primary = run_phase(
            &mut evidence,
            "verify",
            run_operation_phase(deadline, operation_deadline, "verify", driver.verify()),
        )
        .await;
    }

    if primary.is_some() {
        let cancel = tokio::time::timeout(recovery_timeout, driver.cancel())
            .await
            .map_err(|_| anyhow!("admin cancellation exceeded {recovery_timeout:?}"))
            .and_then(|result| result);
        evidence.cancel_attempted = !matches!(cancel, Ok(AdminCancelOutcome::NoOwnedOperation));
        if let Some(cancel_error) =
            run_phase(&mut evidence, "cancel", async { cancel.map(|_| ()) }).await
        {
            let original = primary.take().expect("failure requires a primary error");
            primary =
                Some(original.context(format!("admin cancellation also failed: {cancel_error:#}")));
        }
    }

    let cleanup = tokio::time::timeout(recovery_timeout, driver.cleanup())
        .await
        .map_err(|_| anyhow!("admin cleanup exceeded {recovery_timeout:?}"))
        .and_then(|result| result);
    if let Some(cleanup_error) = run_phase(&mut evidence, "cleanup", async { cleanup }).await {
        primary = Some(match primary {
            Some(original) => {
                original.context(format!("admin cleanup also failed: {cleanup_error:#}"))
            }
            None => cleanup_error,
        });
    } else {
        evidence.cleanup_succeeded = true;
    }
    evidence.completed = primary.is_none();

    AdminWorkflowExecution {
        evidence,
        error: primary,
    }
}

pub(crate) fn persist_admin_workflow(
    collector: &ArtifactCollector,
    case_name: &str,
    execution: AdminWorkflowExecution,
) -> Result<()> {
    let AdminWorkflowExecution {
        evidence,
        error: primary,
    } = execution;
    let serialized =
        serde_json::to_string_pretty(&evidence).context("serialize admin workflow evidence")?;
    let persisted = collector
        .write_text(case_name, ADMIN_WORKFLOW_ARTIFACT, &serialized)
        .context("persist admin workflow evidence")
        .and_then(|_| {
            evidence
                .validate()
                .context("validate admin workflow evidence")
        });

    match (primary, persisted) {
        (None, Ok(())) => Ok(()),
        (Some(primary), Ok(())) => Err(primary),
        (None, Err(artifact_error)) => Err(artifact_error),
        (Some(primary), Err(artifact_error)) => Err(primary.context(format!(
            "admin workflow evidence persistence also failed: {artifact_error:#}"
        ))),
    }
}

async fn wait_for_admin_completion<D: AdminCaseDriver + ?Sized>(
    driver: &D,
    deadline: RunDeadline,
    operation_deadline: tokio::time::Instant,
    poll_interval: Duration,
) -> Result<bool> {
    let mut observed_running = false;
    loop {
        match run_operation_phase(
            deadline,
            operation_deadline,
            "status observation",
            driver.observe(),
        )
        .await?
        {
            AdminWorkflowObservation::Running => {
                observed_running = true;
                run_operation_phase(
                    deadline,
                    operation_deadline,
                    "status poll interval",
                    async {
                        tokio::time::sleep(poll_interval).await;
                        Ok(())
                    },
                )
                .await?;
            }
            AdminWorkflowObservation::Completed => {
                return Ok(observed_running);
            }
        }
    }
}

async fn run_operation_phase<F, T>(
    deadline: RunDeadline,
    operation_deadline: tokio::time::Instant,
    phase: &str,
    operation: F,
) -> Result<T>
where
    F: std::future::Future<Output = Result<T>>,
{
    let remaining = operation_deadline.saturating_duration_since(tokio::time::Instant::now());
    ensure!(
        !remaining.is_zero(),
        "admin operation timeout reached before {phase}"
    );
    let timeout = deadline.bounded_timeout(remaining)?;
    let result = tokio::time::timeout(timeout, operation)
        .await
        .map_err(|_| anyhow!("admin operation timeout reached during {phase}"))??;
    deadline.check()?;
    ensure!(
        tokio::time::Instant::now() < operation_deadline,
        "admin operation timeout reached during {phase}"
    );
    Ok(result)
}

async fn run_phase<F>(
    evidence: &mut AdminWorkflowEvidence,
    phase: &str,
    operation: F,
) -> Option<anyhow::Error>
where
    F: std::future::Future<Output = Result<()>>,
{
    let started_at_ms = now_ms();
    let result = operation.await;
    let ended_at_ms = now_ms().max(started_at_ms);
    let (status, error) = match &result {
        Ok(()) => (AdminWorkflowPhaseStatus::Succeeded, None),
        Err(error) => (AdminWorkflowPhaseStatus::Failed, Some(format!("{error:#}"))),
    };
    evidence.phases.push(AdminWorkflowPhaseEvidence {
        phase: phase.to_string(),
        status,
        started_at_ms,
        ended_at_ms,
        error,
    });
    result.err()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(1)
        .max(1)
}

/// Typed dispatch hook. Catalog entries remain Planned in this foundation;
/// concrete scenario PRs replace this fail-closed branch with a case driver.
pub(crate) async fn run_admin_case(
    config: &FaultTestConfig,
    collector: &ArtifactCollector,
    scenario: &FaultScenario,
    execution_plan: &ExecutionPlan,
    admin_plan: &AdminExecutionPlan,
    run_id: &str,
    deadline: RunDeadline,
) -> Result<()> {
    ensure!(
        execution_plan.admin() == Some(admin_plan)
            && execution_plan.scenario() == scenario.name
            && execution_plan.case_name() == scenario.case_name,
        "admin runner received a mismatched typed execution plan"
    );
    let driver = concrete_admin_case_driver(config, collector, scenario, admin_plan, run_id)?;
    let execution = execute_admin_workflow(
        &scenario.name,
        run_id,
        driver.as_ref(),
        deadline,
        Duration::from_secs(5),
        admin_plan.operation_timeout,
        config.cluster.timeout,
    )
    .await;
    persist_admin_workflow(collector, scenario.case_name, execution)
}

fn concrete_admin_case_driver(
    _config: &FaultTestConfig,
    _collector: &ArtifactCollector,
    _scenario: &FaultScenario,
    admin_plan: &AdminExecutionPlan,
    _run_id: &str,
) -> Result<Box<dyn AdminCaseDriver>> {
    bail!(
        "admin scenario {:?} has a typed execution plan but no concrete case driver; keep it Planned until its scenario implementation is live-qualified",
        admin_plan.scenario
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct FakeDriver {
        calls: Arc<Mutex<Vec<&'static str>>>,
        fail: Option<&'static str>,
        observations: Mutex<Vec<AdminWorkflowObservation>>,
    }

    impl FakeDriver {
        fn with_fail(fail: &'static str) -> Self {
            Self {
                fail: Some(fail),
                ..Self::default()
            }
        }

        fn call(&self, name: &'static str) -> Result<()> {
            self.calls.lock().expect("calls").push(name);
            if self.fail == Some(name) {
                bail!("{name} failed")
            }
            Ok(())
        }
    }

    #[async_trait]
    impl AdminCaseDriver for FakeDriver {
        async fn start(&self) -> Result<()> {
            self.call("start")
        }

        async fn observe(&self) -> Result<AdminWorkflowObservation> {
            self.call("observe")?;
            Ok(self
                .observations
                .lock()
                .expect("observations")
                .pop()
                .unwrap_or(AdminWorkflowObservation::Completed))
        }

        async fn run_workload(&self) -> Result<()> {
            self.call("workload")
        }

        async fn verify(&self) -> Result<()> {
            self.call("verify")
        }

        async fn cancel(&self) -> Result<AdminCancelOutcome> {
            self.call("cancel")?;
            Ok(AdminCancelOutcome::CanceledOwnedOperation)
        }

        async fn cleanup(&self) -> Result<()> {
            self.call("cleanup")
        }
    }

    #[tokio::test]
    async fn successful_workflow_overlaps_workload_and_operation() {
        let driver = FakeDriver {
            observations: Mutex::new(vec![
                AdminWorkflowObservation::Completed,
                AdminWorkflowObservation::Running,
            ]),
            ..FakeDriver::default()
        };
        let execution = execute_admin_workflow(
            "admin-rebalance",
            "run-1",
            &driver,
            RunDeadline::default(),
            Duration::from_millis(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .await;

        assert!(execution.error.is_none());
        execution.evidence.validate().expect("valid evidence");
        let calls = driver.calls.lock().expect("calls");
        assert_eq!(calls[0], "start");
        assert!(calls.contains(&"workload"));
        assert!(calls.contains(&"observe"));
        assert_eq!(calls[calls.len() - 2..], ["verify", "cleanup"]);
    }

    #[tokio::test]
    async fn workflow_rejects_operation_completed_before_observed_overlap() {
        let driver = FakeDriver {
            observations: Mutex::new(vec![AdminWorkflowObservation::Completed]),
            ..FakeDriver::default()
        };
        let execution = execute_admin_workflow(
            "admin-rebalance",
            "run-1",
            &driver,
            RunDeadline::default(),
            Duration::from_millis(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .await;

        let error = execution.error.expect("missing overlap must fail");
        assert!(
            error
                .to_string()
                .contains("completed before overlap with the workload was observed"),
            "{error:#}"
        );
        assert!(execution.evidence.cancel_attempted);
        assert!(execution.evidence.cleanup_succeeded);
    }

    #[tokio::test]
    async fn workflow_accepts_receipt_proof_for_fast_completed_operation() {
        struct ReceiptOverlapDriver(FakeDriver);

        #[async_trait]
        impl AdminCaseDriver for ReceiptOverlapDriver {
            async fn start(&self) -> Result<()> {
                self.0.start().await
            }
            async fn observe(&self) -> Result<AdminWorkflowObservation> {
                self.0.observe().await
            }
            async fn run_workload(&self) -> Result<()> {
                self.0.run_workload().await
            }
            async fn verify_completed_overlap(&self) -> Result<()> {
                self.0.call("verify-overlap")
            }
            async fn verify(&self) -> Result<()> {
                self.0.verify().await
            }
            async fn cancel(&self) -> Result<AdminCancelOutcome> {
                self.0.cancel().await
            }
            async fn cleanup(&self) -> Result<()> {
                self.0.cleanup().await
            }
        }

        let driver = ReceiptOverlapDriver(FakeDriver {
            observations: Mutex::new(vec![AdminWorkflowObservation::Completed]),
            ..FakeDriver::default()
        });
        let execution = execute_admin_workflow(
            "admin-rebalance",
            "run-1",
            &driver,
            RunDeadline::default(),
            Duration::from_millis(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .await;

        assert!(execution.error.is_none());
        let calls = driver.0.calls.lock().expect("calls");
        assert!(calls.contains(&"verify-overlap"));
    }

    #[tokio::test]
    async fn primary_error_survives_cancel_and_cleanup_failures() {
        struct FailingCleanupDriver(FakeDriver);

        #[async_trait]
        impl AdminCaseDriver for FailingCleanupDriver {
            async fn start(&self) -> Result<()> {
                self.0.start().await
            }
            async fn observe(&self) -> Result<AdminWorkflowObservation> {
                self.0.observe().await
            }
            async fn run_workload(&self) -> Result<()> {
                bail!("workload failed")
            }
            async fn verify(&self) -> Result<()> {
                self.0.verify().await
            }
            async fn cancel(&self) -> Result<AdminCancelOutcome> {
                bail!("cancel failed")
            }
            async fn cleanup(&self) -> Result<()> {
                bail!("cleanup failed")
            }
        }

        let driver = FailingCleanupDriver(FakeDriver::default());
        let execution = execute_admin_workflow(
            "admin-decommission",
            "run-2",
            &driver,
            RunDeadline::default(),
            Duration::from_millis(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .await;
        let error = format!("{:#}", execution.error.expect("workflow failure"));

        assert!(error.contains("workload failed"));
        assert!(error.contains("cancellation also failed"));
        assert!(error.contains("cleanup also failed"));
        assert!(execution.evidence.cancel_attempted);
        assert!(!execution.evidence.completed);
        execution
            .evidence
            .validate()
            .expect("valid failure evidence");
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_is_canceled_and_cleanup_is_still_bounded() {
        use std::future::pending;

        struct PendingDriver(FakeDriver);

        #[async_trait]
        impl AdminCaseDriver for PendingDriver {
            async fn start(&self) -> Result<()> {
                self.0.start().await
            }
            async fn observe(&self) -> Result<AdminWorkflowObservation> {
                pending().await
            }
            async fn run_workload(&self) -> Result<()> {
                pending().await
            }
            async fn verify(&self) -> Result<()> {
                self.0.verify().await
            }
            async fn cancel(&self) -> Result<AdminCancelOutcome> {
                self.0.cancel().await
            }
            async fn cleanup(&self) -> Result<()> {
                self.0.cleanup().await
            }
        }

        let driver = PendingDriver(FakeDriver::default());
        let execution = execute_admin_workflow(
            "admin-rebalance",
            "run-3",
            &driver,
            RunDeadline::new(Some(1)).expect("deadline"),
            Duration::from_millis(10),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .await;

        assert!(execution.error.is_some());
        assert!(execution.evidence.cancel_attempted);
        assert!(execution.evidence.cleanup_succeeded);
        let calls = driver.0.calls.lock().expect("calls");
        assert!(calls.contains(&"cancel"));
        assert_eq!(calls.last(), Some(&"cleanup"));
    }

    #[tokio::test]
    async fn start_failure_never_runs_workload_or_verification() {
        let driver = FakeDriver::with_fail("start");
        let execution = execute_admin_workflow(
            "admin-rebalance",
            "run-4",
            &driver,
            RunDeadline::default(),
            Duration::from_millis(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .await;

        assert!(execution.error.is_some());
        let calls = driver.calls.lock().expect("calls");
        assert_eq!(&*calls, &["start", "cancel", "cleanup"]);
        assert!(execution.evidence.cancel_attempted);
    }

    #[tokio::test]
    async fn failed_start_cannot_cancel_without_an_owned_operation() {
        struct NoOwnedOperationDriver(FakeDriver);

        #[async_trait]
        impl AdminCaseDriver for NoOwnedOperationDriver {
            async fn start(&self) -> Result<()> {
                self.0.call("start")?;
                bail!("start response was not accepted")
            }
            async fn observe(&self) -> Result<AdminWorkflowObservation> {
                unreachable!("observe must not run after start failure")
            }
            async fn run_workload(&self) -> Result<()> {
                unreachable!("workload must not run after start failure")
            }
            async fn verify(&self) -> Result<()> {
                unreachable!("verify must not run after start failure")
            }
            async fn cancel(&self) -> Result<AdminCancelOutcome> {
                self.0.call("cancel")?;
                Ok(AdminCancelOutcome::NoOwnedOperation)
            }
            async fn cleanup(&self) -> Result<()> {
                self.0.cleanup().await
            }
        }

        let driver = NoOwnedOperationDriver(FakeDriver::default());
        let execution = execute_admin_workflow(
            "admin-rebalance",
            "run-5",
            &driver,
            RunDeadline::default(),
            Duration::from_millis(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .await;

        assert!(execution.error.is_some());
        assert!(!execution.evidence.cancel_attempted);
        assert_eq!(
            &*driver.0.calls.lock().expect("calls"),
            &["start", "cancel", "cleanup"]
        );
    }
}
