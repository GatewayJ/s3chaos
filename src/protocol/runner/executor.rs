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
use async_trait::async_trait;
use futures::future::join_all;

use crate::protocol::{
    cases::ProtocolCaseExecution, reporting::ProtocolCleanupReport,
    runner::cleanup::ProtocolExecutionCleanup, suite_plan::ProtocolSuitePlanCase,
};

#[async_trait]
pub(crate) trait ProtocolCaseLifecycle: Sync {
    async fn run_case(
        &self,
        case: &ProtocolSuitePlanCase,
    ) -> Result<(ProtocolCaseExecution, ProtocolCleanupReport)>;
}

#[async_trait]
pub(crate) trait ProtocolShutdownSignal: Sync {
    async fn wait(&self) -> Result<()>;
}

pub(crate) trait ProtocolClock: Sync {
    fn now_millis(&self) -> u128;
}

#[async_trait]
pub(crate) trait ProtocolTimeoutPolicy: Sync {
    async fn wait_for_case(&self, case_id: &str, started_at_millis: u128) -> Result<()>;
    async fn wait_for_suite(
        &self,
        suite_started_at_millis: u128,
        elapsed_millis: u128,
    ) -> Result<()>;
}

pub(crate) struct ExecutedProtocolCase {
    pub(crate) execution: ProtocolCaseExecution,
    pub(crate) cleanup: ProtocolCleanupReport,
}

pub(crate) struct ProtocolSuiteExecution {
    pub(crate) cases: Vec<ExecutedProtocolCase>,
    pub(crate) fallback_cleanup: ProtocolCleanupReport,
}

#[derive(Clone, Copy)]
enum ExecutionControl {
    Shutdown,
    SuiteTimeout,
}

enum CaseControl {
    Completed(Box<Result<(ProtocolCaseExecution, ProtocolCleanupReport)>>),
    TimedOut(Result<()>),
}

/// Runs the planned waves and owns stop/cleanup sequencing.
///
/// This use case depends only on lifecycle, cleanup, shutdown, clock, and
/// timeout ports.
/// Concrete AWS, Admin, Keycloak, and filesystem implementations are wired by
/// the outer runtime composition root.
pub(crate) struct ProtocolSuiteExecutor<'a, C, L, S> {
    case_lifecycle: &'a C,
    cleanup: &'a L,
    shutdown: &'a S,
    clock: &'a dyn ProtocolClock,
    timeout: &'a dyn ProtocolTimeoutPolicy,
    api_version: &'a str,
}

impl<'a, C, L, S> ProtocolSuiteExecutor<'a, C, L, S>
where
    C: ProtocolCaseLifecycle,
    L: ProtocolExecutionCleanup,
    S: ProtocolShutdownSignal,
{
    pub(crate) fn new(
        case_lifecycle: &'a C,
        cleanup: &'a L,
        shutdown: &'a S,
        clock: &'a dyn ProtocolClock,
        timeout: &'a dyn ProtocolTimeoutPolicy,
        api_version: &'a str,
    ) -> Self {
        Self {
            case_lifecycle,
            cleanup,
            shutdown,
            clock,
            timeout,
            api_version,
        }
    }

    pub(crate) async fn execute(
        &self,
        selected_cases: &[ProtocolSuitePlanCase],
        cleanup_state: &mut L::RunState,
        preflight_failure: Option<&str>,
    ) -> Result<ProtocolSuiteExecution> {
        let mut cases = Vec::with_capacity(selected_cases.len());
        let mut stop_reason = None;

        if let Some(reason) = preflight_failure {
            cases.extend(selected_cases.iter().map(|case| ExecutedProtocolCase {
                execution: ProtocolCaseExecution::preflight_failed(&case.id, reason),
                cleanup: ProtocolCleanupReport::empty(self.api_version),
            }));
        } else {
            let suite_started_at_millis = self.clock.now_millis();
            let wave_count = selected_cases
                .iter()
                .map(|case| case.wave_index)
                .max()
                .map_or(0, |wave| wave + 1);
            for wave_index in 0..wave_count {
                let wave = selected_cases
                    .iter()
                    .filter(|case| case.wave_index == wave_index)
                    .collect::<Vec<_>>();
                if let Some(reason) = &stop_reason {
                    cases.extend(wave.iter().map(|case| ExecutedProtocolCase {
                        execution: ProtocolCaseExecution::not_run(&case.id, reason),
                        cleanup: ProtocolCleanupReport::empty(self.api_version),
                    }));
                    continue;
                }

                let futures = wave.iter().map(|case| async move {
                    let started_at_millis = self.clock.now_millis();
                    tokio::select! {
                        result = self.case_lifecycle.run_case(case) => {
                            CaseControl::Completed(Box::new(result))
                        }
                        timeout = self.timeout.wait_for_case(&case.id, started_at_millis) => {
                            CaseControl::TimedOut(timeout)
                        }
                    }
                });
                let elapsed_millis = self
                    .clock
                    .now_millis()
                    .saturating_sub(suite_started_at_millis);
                let wave_result = tokio::select! {
                    biased;
                    signal = self.shutdown.wait() => Err((ExecutionControl::Shutdown, signal)),
                    timeout = self.timeout.wait_for_suite(suite_started_at_millis, elapsed_millis) => {
                        Err((ExecutionControl::SuiteTimeout, timeout))
                    },
                    results = join_all(futures) => Ok(results),
                };
                match wave_result {
                    Ok(results) => {
                        for (case, result) in wave.into_iter().zip(results) {
                            let (execution, cleanup) = match result {
                                CaseControl::Completed(result) => match *result {
                                    Ok(completed) => completed,
                                    Err(error) => {
                                        let cleanup = self
                                            .cleanup
                                            .cleanup_case_registry_if_present(&case.id)
                                            .await;
                                        (
                                            ProtocolCaseExecution::harness_failed(
                                                &case.id,
                                                format!("protocol case runner failed: {error}"),
                                            ),
                                            cleanup,
                                        )
                                    }
                                },
                                CaseControl::TimedOut(outcome) => {
                                    let execution = match outcome {
                                        Ok(()) => ProtocolCaseExecution::case_timed_out(&case.id),
                                        Err(error) => ProtocolCaseExecution::harness_failed(
                                            &case.id,
                                            format!(
                                                "protocol case timeout handler failed: {error}"
                                            ),
                                        ),
                                    };
                                    let cleanup = self
                                        .cleanup
                                        .cleanup_case_registry_if_present(&case.id)
                                        .await;
                                    if stop_reason.is_none() {
                                        stop_reason = Some(format!(
                                            "case {} timed out; later waves were not started",
                                            case.id
                                        ));
                                    }
                                    (execution, cleanup)
                                }
                            };
                            if !cleanup.succeeded && stop_reason.is_none() {
                                stop_reason = Some(format!(
                                    "case {} cleanup failed; later waves were not started",
                                    execution.report.case_id
                                ));
                            }
                            cases.push(ExecutedProtocolCase { execution, cleanup });
                        }
                    }
                    Err((control, outcome)) => {
                        stop_reason = Some(match (control, outcome) {
                            (ExecutionControl::Shutdown, Ok(())) => {
                                "protocol suite interrupted; cleanup requested".to_string()
                            }
                            (ExecutionControl::Shutdown, Err(error)) => {
                                format!("protocol signal handler failed: {error}")
                            }
                            (ExecutionControl::SuiteTimeout, Ok(())) => {
                                "protocol suite budget exhausted; cleanup requested".to_string()
                            }
                            (ExecutionControl::SuiteTimeout, Err(error)) => {
                                format!("protocol suite timeout handler failed: {error}")
                            }
                        });
                        for case in wave {
                            let cleanup = self
                                .cleanup
                                .cleanup_case_registry_if_present(&case.id)
                                .await;
                            cases.push(ExecutedProtocolCase {
                                execution: match control {
                                    ExecutionControl::Shutdown => {
                                        ProtocolCaseExecution::interrupted(&case.id)
                                    }
                                    ExecutionControl::SuiteTimeout => {
                                        ProtocolCaseExecution::suite_timed_out(&case.id)
                                    }
                                },
                                cleanup,
                            });
                        }
                    }
                }
            }
        }

        let fallback_cleanup = self
            .cleanup
            .cleanup_suite_registries(selected_cases, cleanup_state)
            .await;
        Ok(ProtocolSuiteExecution {
            cases,
            fallback_cleanup,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ProtocolCaseLifecycle, ProtocolClock, ProtocolShutdownSignal, ProtocolSuiteExecutor,
        ProtocolTimeoutPolicy,
    };
    use crate::protocol::{
        cases::ProtocolCaseExecution, reporting::ProtocolCleanupReport,
        runner::cleanup::ProtocolExecutionCleanup, suite_plan::ProtocolSuitePlanCase,
    };
    use anyhow::Result;
    use async_trait::async_trait;
    use std::{
        collections::BTreeSet,
        future::pending,
        sync::{
            Arc, Mutex,
            atomic::{AtomicU64, Ordering},
        },
    };

    struct FakeLifecycle {
        invoked: Arc<Mutex<Vec<String>>>,
        cleanup_failures: BTreeSet<String>,
        never_completes: bool,
    }

    #[async_trait]
    impl ProtocolCaseLifecycle for FakeLifecycle {
        async fn run_case(
            &self,
            case: &ProtocolSuitePlanCase,
        ) -> Result<(ProtocolCaseExecution, ProtocolCleanupReport)> {
            self.invoked
                .lock()
                .expect("invocations")
                .push(case.id.clone());
            if self.never_completes {
                pending::<()>().await;
            }
            let mut cleanup = ProtocolCleanupReport::empty("rustfs.com/s3chaos/v1alpha1");
            cleanup.succeeded = !self.cleanup_failures.contains(&case.id);
            Ok((ProtocolCaseExecution::interrupted(&case.id), cleanup))
        }
    }

    #[derive(Default)]
    struct FakeCleanup {
        interrupted: Arc<Mutex<Vec<String>>>,
        suite_calls: Arc<Mutex<usize>>,
        case_cleanup_failures: BTreeSet<String>,
    }

    #[async_trait]
    impl ProtocolExecutionCleanup for FakeCleanup {
        type RunState = ();

        async fn cleanup_case_registry_if_present(&self, case_id: &str) -> ProtocolCleanupReport {
            self.interrupted
                .lock()
                .expect("interrupted")
                .push(case_id.to_string());
            let mut report = ProtocolCleanupReport::empty("rustfs.com/s3chaos/v1alpha1");
            report.succeeded = !self.case_cleanup_failures.contains(case_id);
            report
        }

        async fn cleanup_suite_registries(
            &self,
            _cases: &[ProtocolSuitePlanCase],
            _run_state: &mut Self::RunState,
        ) -> ProtocolCleanupReport {
            *self.suite_calls.lock().expect("suite calls") += 1;
            ProtocolCleanupReport::empty("rustfs.com/s3chaos/v1alpha1")
        }
    }

    struct NeverShutdown;

    #[async_trait]
    impl ProtocolShutdownSignal for NeverShutdown {
        async fn wait(&self) -> Result<()> {
            pending().await
        }
    }

    struct ImmediateShutdown;

    #[async_trait]
    impl ProtocolShutdownSignal for ImmediateShutdown {
        async fn wait(&self) -> Result<()> {
            Ok(())
        }
    }

    struct FakeClock(AtomicU64);

    impl ProtocolClock for FakeClock {
        fn now_millis(&self) -> u128 {
            self.0.fetch_add(1, Ordering::SeqCst).into()
        }
    }

    struct NeverTimeout;

    #[async_trait]
    impl ProtocolTimeoutPolicy for NeverTimeout {
        async fn wait_for_case(&self, _case_id: &str, _started_at_millis: u128) -> Result<()> {
            pending().await
        }

        async fn wait_for_suite(
            &self,
            _suite_started_at_millis: u128,
            _elapsed_millis: u128,
        ) -> Result<()> {
            pending().await
        }
    }

    #[derive(Default)]
    struct ImmediateCaseTimeout(Arc<Mutex<Vec<(String, u128)>>>);

    #[async_trait]
    impl ProtocolTimeoutPolicy for ImmediateCaseTimeout {
        async fn wait_for_case(&self, case_id: &str, started_at_millis: u128) -> Result<()> {
            self.0
                .lock()
                .expect("timeout calls")
                .push((case_id.to_string(), started_at_millis));
            Ok(())
        }

        async fn wait_for_suite(
            &self,
            _suite_started_at_millis: u128,
            _elapsed_millis: u128,
        ) -> Result<()> {
            pending().await
        }
    }

    struct ImmediateSuiteTimeout;

    #[async_trait]
    impl ProtocolTimeoutPolicy for ImmediateSuiteTimeout {
        async fn wait_for_case(&self, _case_id: &str, _started_at_millis: u128) -> Result<()> {
            pending().await
        }

        async fn wait_for_suite(
            &self,
            _suite_started_at_millis: u128,
            _elapsed_millis: u128,
        ) -> Result<()> {
            Ok(())
        }
    }

    fn planned_case(id: &str, wave_index: usize) -> ProtocolSuitePlanCase {
        ProtocolSuitePlanCase {
            id: id.to_string(),
            domain: crate::protocol::catalog::ProtocolDomain::Other,
            group: "test".to_string(),
            tags: Vec::new(),
            requires: Vec::new(),
            isolation: "case".to_string(),
            serial: false,
            worker_index: 0,
            wave_index,
            locks: Vec::new(),
            artifact_dir: format!("cases/{id}"),
            contract: None,
        }
    }

    #[tokio::test]
    async fn cleanup_failure_stops_later_waves_and_always_runs_fallback_cleanup() {
        let invoked = Arc::new(Mutex::new(Vec::new()));
        let lifecycle = FakeLifecycle {
            invoked: invoked.clone(),
            cleanup_failures: BTreeSet::from(["first".to_string()]),
            never_completes: false,
        };
        let cleanup = FakeCleanup::default();
        let clock = FakeClock(AtomicU64::new(10));
        let mut cleanup_state = ();
        let cases = [planned_case("first", 0), planned_case("second", 1)];
        let executor = ProtocolSuiteExecutor::new(
            &lifecycle,
            &cleanup,
            &NeverShutdown,
            &clock,
            &NeverTimeout,
            "rustfs.com/s3chaos/v1alpha1",
        );

        let result = executor
            .execute(&cases, &mut cleanup_state, None)
            .await
            .expect("execution");

        assert_eq!(*invoked.lock().expect("invocations"), vec!["first"]);
        assert_eq!(result.cases.len(), 2);
        assert_eq!(
            result.cases[1].execution.report.failure_phase.as_deref(),
            Some("not-run")
        );
        assert_eq!(*cleanup.suite_calls.lock().expect("suite calls"), 1);
    }

    #[tokio::test]
    async fn injected_shutdown_cancels_wave_and_cleans_each_registry() {
        let lifecycle = FakeLifecycle {
            invoked: Arc::new(Mutex::new(Vec::new())),
            cleanup_failures: BTreeSet::new(),
            never_completes: true,
        };
        let cleanup = FakeCleanup::default();
        let clock = FakeClock(AtomicU64::new(10));
        let mut cleanup_state = ();
        let cases = [planned_case("first", 0), planned_case("second", 0)];
        let executor = ProtocolSuiteExecutor::new(
            &lifecycle,
            &cleanup,
            &ImmediateShutdown,
            &clock,
            &NeverTimeout,
            "rustfs.com/s3chaos/v1alpha1",
        );

        let result = executor
            .execute(&cases, &mut cleanup_state, None)
            .await
            .expect("execution");

        assert_eq!(result.cases.len(), 2);
        assert!(
            result.cases.iter().all(|case| {
                case.execution.report.failure_phase.as_deref() == Some("interrupted")
            })
        );
        assert_eq!(
            *cleanup.interrupted.lock().expect("interrupted"),
            vec!["first", "second"]
        );
        assert!(result.fallback_cleanup.succeeded);
    }

    #[tokio::test]
    async fn injected_clock_and_timeout_use_safe_interruption_cleanup_path() {
        let lifecycle = FakeLifecycle {
            invoked: Arc::new(Mutex::new(Vec::new())),
            cleanup_failures: BTreeSet::new(),
            never_completes: true,
        };
        let cleanup = FakeCleanup::default();
        let timeout = ImmediateCaseTimeout::default();
        let clock = FakeClock(AtomicU64::new(42));
        let mut cleanup_state = ();
        let cases = [planned_case("first", 0), planned_case("second", 0)];
        let executor = ProtocolSuiteExecutor::new(
            &lifecycle,
            &cleanup,
            &NeverShutdown,
            &clock,
            &timeout,
            "rustfs.com/s3chaos/v1alpha1",
        );

        let result = executor
            .execute(&cases, &mut cleanup_state, None)
            .await
            .expect("execution");

        assert_eq!(
            timeout
                .0
                .lock()
                .expect("timeout calls")
                .iter()
                .map(|(case_id, _)| case_id.as_str())
                .collect::<Vec<_>>(),
            vec!["first", "second"]
        );
        assert_eq!(
            *cleanup.interrupted.lock().expect("interrupted"),
            vec!["first", "second"]
        );
        assert_eq!(result.cases.len(), 2);
        assert!(result.cases.iter().all(|case| {
            case.execution.report.failure_phase.as_deref() == Some("case-timeout")
        }));
        assert!(result.fallback_cleanup.succeeded);
    }

    #[tokio::test]
    async fn suite_budget_stops_new_waves_and_cleans_active_registries() {
        let invoked = Arc::new(Mutex::new(Vec::new()));
        let lifecycle = FakeLifecycle {
            invoked: invoked.clone(),
            cleanup_failures: BTreeSet::new(),
            never_completes: true,
        };
        let cleanup = FakeCleanup::default();
        let clock = FakeClock(AtomicU64::new(100));
        let mut cleanup_state = ();
        let cases = [planned_case("active", 0), planned_case("later", 1)];
        let executor = ProtocolSuiteExecutor::new(
            &lifecycle,
            &cleanup,
            &NeverShutdown,
            &clock,
            &ImmediateSuiteTimeout,
            "rustfs.com/s3chaos/v1alpha1",
        );

        let result = executor
            .execute(&cases, &mut cleanup_state, None)
            .await
            .expect("execution");

        assert_eq!(*invoked.lock().expect("invocations"), Vec::<String>::new());
        assert_eq!(result.cases.len(), 2);
        assert_eq!(
            result.cases[0].execution.report.failure_phase.as_deref(),
            Some("suite-timeout")
        );
        assert_eq!(
            result.cases[1].execution.report.failure_phase.as_deref(),
            Some("not-run")
        );
        assert_eq!(
            *cleanup.interrupted.lock().expect("interrupted"),
            vec!["active"]
        );
    }

    #[tokio::test]
    async fn case_timeout_remains_primary_when_cleanup_also_fails() {
        let lifecycle = FakeLifecycle {
            invoked: Arc::new(Mutex::new(Vec::new())),
            cleanup_failures: BTreeSet::new(),
            never_completes: true,
        };
        let cleanup = FakeCleanup {
            case_cleanup_failures: BTreeSet::from(["timed-out".to_string()]),
            ..FakeCleanup::default()
        };
        let clock = FakeClock(AtomicU64::new(10));
        let timeout = ImmediateCaseTimeout::default();
        let mut cleanup_state = ();
        let cases = [planned_case("timed-out", 0)];
        let executor = ProtocolSuiteExecutor::new(
            &lifecycle,
            &cleanup,
            &NeverShutdown,
            &clock,
            &timeout,
            "rustfs.com/s3chaos/v1alpha1",
        );

        let result = executor
            .execute(&cases, &mut cleanup_state, None)
            .await
            .expect("execution");

        assert_eq!(
            result.cases[0].execution.report.failure_phase.as_deref(),
            Some("case-timeout")
        );
        assert!(!result.cases[0].cleanup.succeeded);
    }
}
