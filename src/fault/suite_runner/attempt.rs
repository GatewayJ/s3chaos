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

use super::*;

pub(super) fn evaluate_attempt_result(
    planned: &PlannedFaultSuiteAttempt,
    suite: &ResolvedFaultSuite,
    summary: &mut FaultSuiteRunSummary,
    suite_root: &Path,
    attempt: FaultSuiteRunAttempt,
    result: Result<()>,
) -> Result<bool> {
    match result {
        Ok(()) => evaluate_completed_attempt(planned, suite, summary, suite_root, attempt),
        Err(error) => evaluate_failed_attempt(planned, suite, summary, suite_root, attempt, error),
    }
}

fn evaluate_completed_attempt(
    planned: &PlannedFaultSuiteAttempt,
    suite: &ResolvedFaultSuite,
    summary: &mut FaultSuiteRunSummary,
    suite_root: &Path,
    mut attempt: FaultSuiteRunAttempt,
) -> Result<bool> {
    let mut stop_after_attempt_failure = false;
    match validate_attempt_artifacts(&planned.config, &attempt.run_id) {
        Ok(report) => {
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
                let safety_failure = evaluate_failed_attempt_safety(
                    summary,
                    &mut attempt,
                    suite_root,
                    &planned.plan,
                    now_ms(),
                    Some(report.client_disruptions),
                );
                stop_after_attempt_failure = safety_failure.is_some()
                    || should_stop_after_attempt_failure(
                        &suite.budgets.continue_on_severities,
                        suite.budgets.stop_on_first_failure,
                        None,
                    );
                summary.record_attempt_failure(
                    &attempt,
                    None,
                    None,
                    attempt_error,
                    stop_after_attempt_failure,
                );
                replace_last_attempt(summary, attempt);
                if enforce_disruption_budget(summary, safety_failure) {
                    return Ok(true);
                }
            } else {
                let disruption_budget_failure =
                    summary.record_client_disruptions(report.client_disruptions)?;
                replace_last_attempt(summary, attempt);
                if enforce_disruption_budget(summary, disruption_budget_failure) {
                    return Ok(true);
                }
            }
        }
        Err(error) => {
            let (attempt_error, failure_summary_artifact, forced_stop) =
                artifact_validation_failure_details(
                    &planned.plan,
                    format!("artifact validation failed: {error}"),
                );
            attempt.fail(attempt_error.clone(), None);
            let safety_failure = evaluate_failed_attempt_safety(
                summary,
                &mut attempt,
                suite_root,
                &planned.plan,
                now_ms(),
                None,
            );
            let failure_message = format!(
                "scenario {} repetition {} failed: {attempt_error}",
                planned.plan.scenario, planned.plan.repetition
            );
            stop_after_attempt_failure = forced_stop || safety_failure.is_some();
            summary.record_attempt_failure(
                &attempt,
                None,
                failure_summary_artifact,
                failure_message,
                stop_after_attempt_failure,
            );
            replace_last_attempt(summary, attempt);
            if enforce_disruption_budget(summary, safety_failure) {
                return Ok(true);
            }
        }
    }
    Ok(stop_after_attempt_failure)
}

fn evaluate_failed_attempt(
    planned: &PlannedFaultSuiteAttempt,
    suite: &ResolvedFaultSuite,
    summary: &mut FaultSuiteRunSummary,
    suite_root: &Path,
    mut attempt: FaultSuiteRunAttempt,
    error: anyhow::Error,
) -> Result<bool> {
    let evaluated_at_ms = now_ms();
    let (attempt_error, failure_summary, failure_severity) =
        attempt_failure_details(&planned.plan, error.to_string());
    let expected_failure_artifacts = planned.plan.expected_failure.as_ref().map(|_| {
        validate_expected_failure_artifact_contract(
            suite_root,
            &planned.plan,
            failure_summary.as_ref(),
            attempt.started_at_ms,
            evaluated_at_ms,
        )
    });
    let expected_failure_mismatch = match (
        planned.plan.expected_failure.as_ref(),
        expected_failure_artifacts.as_ref(),
    ) {
        (Some(expected), Some(Ok(validation))) => {
            evaluate_validated_expected_failure(expected, validation).mismatch
        }
        (Some(_), Some(Err(error))) => Some(format!("{error:#}")),
        _ => None,
    };
    let trusted_disruptions = expected_failure_artifacts
        .as_ref()
        .and_then(|result| result.as_ref().ok())
        .map(|validation| validation.client_disruptions);
    let safety_failure = evaluate_failed_attempt_safety(
        summary,
        &mut attempt,
        suite_root,
        &planned.plan,
        evaluated_at_ms,
        trusted_disruptions,
    );
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
        replace_last_attempt(summary, attempt);
        if enforce_disruption_budget(summary, safety_failure) {
            return Ok(true);
        }
        return Ok(false);
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
    let stop_after_attempt_failure = safety_failure.is_some()
        || should_stop_after_attempt_failure(
            &suite.budgets.continue_on_severities,
            suite.budgets.stop_on_first_failure,
            failure_severity,
        );
    summary.record_attempt_failure(
        &attempt,
        failure_summary.as_ref(),
        attempt_failure_summary_artifact(&planned.plan),
        failure_message,
        stop_after_attempt_failure,
    );
    replace_last_attempt(summary, attempt);
    if enforce_disruption_budget(summary, safety_failure) {
        return Ok(true);
    }
    Ok(stop_after_attempt_failure)
}
