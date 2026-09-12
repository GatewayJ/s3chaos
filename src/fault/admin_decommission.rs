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

//! Scenario-owned sequencing and S3 overlap evidence for admin decommission.
//!
//! Fixture staging remains owned by the shared admin workflow layer. This
//! module starts only after that layer has proven the named, populated source
//! pool and the empty survivor pool for one run-owned Tenant.

use anyhow::{Context, Result, ensure};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    error::Error,
    fmt,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::Mutex as AsyncMutex,
    time::{Instant, sleep, timeout},
};

use crate::fault::{
    admin_runner::{
        AdminCancelOutcome, AdminCaseDriver, AdminWorkflowObservation,
        persist_then_cleanup_admin_fixture,
    },
    admin_topology::{
        ADMIN_OPERATION_ARTIFACT, ADMIN_OPERATION_PROGRESS_ARTIFACT, ADMIN_TOPOLOGY_PROOF_ARTIFACT,
        AdminAttemptIdentity, AdminAttemptWindow, AdminCall, AdminOperationEvidence,
        AdminOperationProgressSample, AdminPoolSnapshot, AdminRequestEvidence,
        AdminTopologyBuildContext, AdminTopologyPort, AdminTopologyProof, DecommissionPoolStatus,
        RustfsAdminTopologyAdapter, decommission_progress_sample,
        validate_admin_operation_progress, validate_admin_pre_start_snapshot,
        validate_decommission_control_call,
    },
    checker::{self, CheckerReport},
    config::FaultTestConfig,
    events::RunEventStatus,
    fixture::{
        ADMIN_FIXTURE_ARTIFACT, AdminFixtureEvidence, AdminFixturePhase, AdminFixturePlan,
        apply_admin_tenant_stage, capture_admin_fixture_observation,
        reset_owned_admin_tenant_resources, reset_tenant_resources,
    },
    history::{OperationKind, OperationOutcome, OperationRecord, validate_history_scope_and_order},
    plan::AdminExecutionPlan,
    pods::rustfs_pod_identities,
    preflight::{PreflightCheck, PreflightPhase, PreflightSummary},
    recovery_health::{RECOVERY_HEALTH_ARTIFACT, RecoveryHealthBaseline},
    reporting::ResponsibilityDomain,
    runner::{
        FaultRunContext, POST_RECOVERY_SEED_SALT, ensure_s3_access, initialize_fault_run,
        observe_recovery_health, s3_access, tenant_port_forward, wait_for_ready_tenant,
        wait_for_stable_rustfs_pods, wait_for_tenant_s3,
    },
    scenarios::{ADMIN_DECOMMISSION_SCENARIO, FaultScenario},
    shutdown::RunDeadline,
    workload::execution::{
        MixedWorkloadRequest, MixedWorkloadResult, POST_RECOVERY_WRITE_HISTORY_ARTIFACT,
        POST_RECOVERY_WRITE_REPORT_ARTIFACT, PostRecoveryWriteRequest, post_recovery_object_count,
        prefill_objects, recommit_unconfirmed_objects, run_mixed_workload,
        run_post_recovery_write_probe,
    },
    workload::{ObjectSpec, S3WorkloadClient},
};
use crate::framework::{artifacts::ArtifactCollector, port_forward::PortForwardGuard, resources};

const START_PATH: &str = "/rustfs/admin/v3/pools/decommission";
const STATUS_PATH: &str = "/rustfs/admin/v3/decommission/status";
const CANCEL_PATH: &str = "/rustfs/admin/v3/pools/cancel";
const CLEAR_PATH: &str = "/rustfs/admin/v3/pools/clear";

pub const ADMIN_DECOMMISSION_OVERLAP_ARTIFACT: &str = "admin-decommission-overlap.json";
pub const ADMIN_DECOMMISSION_TRANSCRIPT_ARTIFACT: &str = "admin-decommission-transcript.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdminDecommissionLimits {
    pub poll_interval: Duration,
    pub operation_timeout: Duration,
    pub cancel_timeout: Duration,
}

impl AdminDecommissionLimits {
    pub fn validate(self) -> Result<()> {
        ensure!(
            !self.poll_interval.is_zero()
                && !self.operation_timeout.is_zero()
                && !self.cancel_timeout.is_zero()
                && self.poll_interval <= self.operation_timeout
                && self.poll_interval <= self.cancel_timeout,
            "admin decommission polling and operation/cancel deadlines must be positive and ordered"
        );
        Ok(())
    }
}

#[async_trait]
pub trait AdminDecommissionAttemptPort: AdminTopologyPort {
    /// Capture Tenant GET, runtime binding, and pools/list evidence in order.
    async fn capture_pool_snapshot(
        &self,
        run_id: &str,
        case_name: &str,
    ) -> Result<AdminPoolSnapshot>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminDecommissionWorkloadReceipt {
    pub started_at_ms: u64,
    pub ended_at_ms: u64,
    pub first_event_sequence: u64,
    pub last_event_sequence: u64,
    /// Complete recorder contents at workload completion.
    pub history: Vec<OperationRecord>,
}

#[async_trait]
pub trait AdminDecommissionWorkload: Send + Sync {
    /// Run exactly one finite, byte-budgeted mixed workload.
    async fn run_bounded(&self) -> Result<AdminDecommissionWorkloadReceipt>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminDecommissionOverlapEvidence {
    #[serde(flatten)]
    pub attempt: AdminAttemptIdentity,
    pub operation_id: String,
    pub target_pool_id: usize,
    pub target_pool_expression: String,
    pub decommission_started_at_ms: u64,
    pub decommission_completed_at_ms: u64,
    pub workload_started_at_ms: u64,
    pub workload_ended_at_ms: u64,
    pub workload_first_event_sequence: u64,
    pub workload_last_event_sequence: u64,
    pub workload_operation_ids: Vec<String>,
    pub overlapping_operation_ids: Vec<String>,
    pub overlapping_status_request_ids: Vec<String>,
}

impl AdminDecommissionOverlapEvidence {
    pub fn from_history(
        operation: &AdminOperationEvidence,
        progress: &[AdminOperationProgressSample],
        workload: &AdminDecommissionWorkloadReceipt,
    ) -> Result<Self> {
        let (decommission_started_at_ms, decommission_completed_at_ms) =
            decommission_window(operation)?;
        let records = workload_records(workload)?;
        let target_pool_id = operation
            .target_pool_id
            .context("decommission operation lacks a target pool ID")?;
        let target_pool_expression = operation
            .target_pool_expression
            .clone()
            .context("decommission operation lacks a target pool expression")?;
        let evidence = Self {
            attempt: operation.attempt.clone(),
            operation_id: operation.operation_id.clone(),
            target_pool_id,
            target_pool_expression,
            decommission_started_at_ms,
            decommission_completed_at_ms,
            workload_started_at_ms: workload.started_at_ms,
            workload_ended_at_ms: workload.ended_at_ms,
            workload_first_event_sequence: workload.first_event_sequence,
            workload_last_event_sequence: workload.last_event_sequence,
            workload_operation_ids: records.iter().map(|record| record.id.clone()).collect(),
            overlapping_operation_ids: records
                .iter()
                .filter(|record| {
                    intervals_overlap(
                        record.started_at_ms,
                        record.ended_at_ms,
                        decommission_started_at_ms,
                        decommission_completed_at_ms,
                    )
                })
                .map(|record| record.id.clone())
                .collect(),
            overlapping_status_request_ids: overlapping_status_request_ids(
                operation,
                progress,
                workload.started_at_ms,
                workload.ended_at_ms,
            )?,
        };
        evidence.validate(operation, progress, &workload.history)?;
        Ok(evidence)
    }

    pub fn validate(
        &self,
        operation: &AdminOperationEvidence,
        progress: &[AdminOperationProgressSample],
        history: &[OperationRecord],
    ) -> Result<()> {
        ensure!(
            operation.scenario == ADMIN_DECOMMISSION_SCENARIO
                && self.attempt == operation.attempt
                && self.operation_id == operation.operation_id
                && operation.target_pool_id == Some(self.target_pool_id)
                && operation.target_pool_expression.as_deref()
                    == Some(self.target_pool_expression.as_str()),
            "decommission overlap identity does not match the admin operation and exact target"
        );
        ensure!(
            !history.is_empty()
                && history.iter().all(|record| {
                    record.scenario == ADMIN_DECOMMISSION_SCENARIO
                        && record.run_id.as_deref() == Some(operation.attempt.run_id.as_str())
                }),
            "decommission overlap history does not belong to the current attempt"
        );
        let (started_at_ms, completed_at_ms) = decommission_window(operation)?;
        ensure!(
            self.decommission_started_at_ms == started_at_ms
                && self.decommission_completed_at_ms == completed_at_ms
                && self.workload_started_at_ms <= self.workload_ended_at_ms
                && intervals_overlap(
                    self.workload_started_at_ms,
                    self.workload_ended_at_ms,
                    started_at_ms,
                    completed_at_ms,
                ),
            "bounded S3 workload did not intersect the observed decommission window"
        );
        let receipt = AdminDecommissionWorkloadReceipt {
            started_at_ms: self.workload_started_at_ms,
            ended_at_ms: self.workload_ended_at_ms,
            first_event_sequence: self.workload_first_event_sequence,
            last_event_sequence: self.workload_last_event_sequence,
            history: history.to_vec(),
        };
        let records = workload_records(&receipt)?;
        ensure!(
            records
                .iter()
                .map(|record| record.id.as_str())
                .eq(self.workload_operation_ids.iter().map(String::as_str)),
            "decommission overlap operation IDs do not match the workload history slice"
        );
        let overlapping_ids = records
            .iter()
            .filter(|record| {
                intervals_overlap(
                    record.started_at_ms,
                    record.ended_at_ms,
                    started_at_ms,
                    completed_at_ms,
                )
            })
            .map(|record| record.id.as_str())
            .collect::<Vec<_>>();
        ensure!(
            !overlapping_ids.is_empty()
                && overlapping_ids
                    .iter()
                    .copied()
                    .eq(self.overlapping_operation_ids.iter().map(String::as_str)),
            "no complete S3 operation interval overlaps the observed decommission window"
        );
        let status_ids = overlapping_status_request_ids(
            operation,
            progress,
            self.workload_started_at_ms,
            self.workload_ended_at_ms,
        )?;
        ensure!(
            !status_ids.is_empty()
                && status_ids
                    .iter()
                    .eq(self.overlapping_status_request_ids.iter()),
            "decommission has no status request receipt intersecting the workload"
        );
        validate_workload_families(history, records)?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct AdminDecommissionExecution {
    pub proof: AdminTopologyProof,
    pub operation: AdminOperationEvidence,
    pub progress: Vec<AdminOperationProgressSample>,
    pub overlap: AdminDecommissionOverlapEvidence,
    pub attempt_window: AdminAttemptWindow,
    workload_history: Vec<OperationRecord>,
}

impl AdminDecommissionExecution {
    pub fn write_artifacts(&self, collector: &ArtifactCollector) -> Result<()> {
        self.proof.require_satisfied()?;
        self.operation.require_success(self.attempt_window)?;
        validate_admin_operation_progress(&self.operation, &self.progress, self.attempt_window)?;
        self.overlap
            .validate(&self.operation, &self.progress, &self.workload_history)
            .context("validate decommission overlap before artifact write")?;
        let case_name = &self.operation.attempt.case_name;
        collector.write_text(
            case_name,
            ADMIN_TOPOLOGY_PROOF_ARTIFACT,
            &serde_json::to_string_pretty(&self.proof)?,
        )?;
        collector.write_text(
            case_name,
            ADMIN_OPERATION_ARTIFACT,
            &serde_json::to_string_pretty(&self.operation)?,
        )?;
        let progress = self
            .progress
            .iter()
            .map(serde_json::to_string)
            .collect::<std::result::Result<Vec<_>, _>>()?
            .join("\n");
        collector.write_text(
            case_name,
            ADMIN_OPERATION_PROGRESS_ARTIFACT,
            &format!("{progress}\n"),
        )?;
        collector.write_text(
            case_name,
            ADMIN_DECOMMISSION_OVERLAP_ARTIFACT,
            &serde_json::to_string_pretty(&self.overlap)?,
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminDecommissionTranscript {
    pub operation_id: Option<String>,
    pub requests: Vec<AdminRequestEvidence>,
    pub progress: Vec<AdminOperationProgressSample>,
}

#[derive(Debug)]
pub struct AdminDecommissionExecutionError {
    primary: anyhow::Error,
    cleanup_error: Option<anyhow::Error>,
    transcript: AdminDecommissionTranscript,
}

impl AdminDecommissionExecutionError {
    pub fn primary_error(&self) -> &anyhow::Error {
        &self.primary
    }

    pub fn cleanup_error(&self) -> Option<&anyhow::Error> {
        self.cleanup_error.as_ref()
    }

    pub fn transcript(&self) -> &AdminDecommissionTranscript {
        &self.transcript
    }
}

impl fmt::Display for AdminDecommissionExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:#}", self.primary)?;
        if let Some(cleanup_error) = &self.cleanup_error {
            write!(
                formatter,
                "; decommission cleanup also failed: {cleanup_error:#}"
            )?;
        }
        Ok(())
    }
}

impl Error for AdminDecommissionExecutionError {}

struct TerminalDecommission {
    status: DecommissionPoolStatus,
}

/// Execute the scenario-specific operation phase after fixture staging.
pub async fn run_admin_decommission<P, W>(
    port: &P,
    workload: &W,
    proof: AdminTopologyProof,
    attempt_started_at_ms: u64,
    limits: AdminDecommissionLimits,
) -> std::result::Result<AdminDecommissionExecution, AdminDecommissionExecutionError>
where
    P: AdminDecommissionAttemptPort,
    W: AdminDecommissionWorkload,
{
    let transcript = Arc::new(Mutex::new(AdminDecommissionTranscript::default()));
    let result = run_admin_decommission_inner(
        port,
        workload,
        proof.clone(),
        attempt_started_at_ms,
        limits,
        Arc::clone(&transcript),
    )
    .await;
    match result {
        Ok(execution) => Ok(execution),
        Err(primary) => {
            let operation_id = transcript_state(&transcript).operation_id;
            let cleanup_error = if let Some(operation_id) = operation_id {
                cancel_owned_decommission(port, &proof, &operation_id, limits, &transcript)
                    .await
                    .err()
            } else {
                None
            };
            Err(AdminDecommissionExecutionError {
                primary,
                cleanup_error,
                transcript: transcript_state(&transcript),
            })
        }
    }
}

async fn run_admin_decommission_inner<P, W>(
    port: &P,
    workload: &W,
    proof: AdminTopologyProof,
    attempt_started_at_ms: u64,
    limits: AdminDecommissionLimits,
    transcript: Arc<Mutex<AdminDecommissionTranscript>>,
) -> Result<AdminDecommissionExecution>
where
    P: AdminDecommissionAttemptPort,
    W: AdminDecommissionWorkload,
{
    limits.validate()?;
    proof.require_satisfied()?;
    let target_pool_id = proof
        .target_pool_id
        .context("admin-decommission proof lacks a target pool ID")?;
    let target_expression = proof
        .target_pool_expression
        .as_deref()
        .context("admin-decommission proof lacks a target pool expression")?;
    ensure!(
        proof.scenario == ADMIN_DECOMMISSION_SCENARIO
            && proof.tenant_pools.len() == 2
            && proof.runtime_pools.len() == 2
            && proof.target_used_bytes > 0,
        "admin-decommission requires a populated exact target in a run-owned two-pool topology"
    );
    ensure!(
        attempt_started_at_ms > 0 && attempt_started_at_ms <= now_ms(),
        "admin-decommission attempt start time is invalid"
    );

    let pools_before = port
        .capture_pool_snapshot(&proof.attempt.run_id, &proof.attempt.case_name)
        .await
        .context("capture fresh pre-start decommission pool snapshot")?;
    validate_admin_pre_start_snapshot(&proof, &pools_before, now_ms())
        .context("revalidate exact decommission target and capacity immediately before start")?;
    let start_call = port
        .start_decommission(target_pool_id, target_expression)
        .await
        .context("start RustFS pool decommission")?;
    lock_transcript(&transcript)
        .requests
        .push(start_call.request.clone());
    validate_decommission_control_call(&proof, START_PATH, &start_call)?;

    let poll = poll_decommission(port, &proof, limits, Arc::clone(&transcript));
    let workload_run = workload.run_bounded();
    tokio::pin!(poll);
    tokio::pin!(workload_run);

    let (workload_receipt, terminal) = tokio::select! {
        workload_result = &mut workload_run => {
            let receipt = workload_result.context("bounded admin-decommission workload failed")?;
            let terminal = poll.await?;
            (receipt, terminal)
        }
        poll_result = &mut poll => {
            let terminal = poll_result?;
            let receipt = workload_run.await.context("bounded admin-decommission workload failed")?;
            (receipt, terminal)
        }
    };

    let pools_after = port
        .capture_pool_snapshot(&proof.attempt.run_id, &proof.attempt.case_name)
        .await
        .context("capture post-terminal decommission pool snapshot")?;
    let state = transcript_state(&transcript);
    let operation = AdminOperationEvidence::from_decommission(
        &proof,
        pools_before,
        terminal.status,
        state.requests,
        pools_after,
    )?;
    let attempt_window = AdminAttemptWindow {
        started_at_ms: attempt_started_at_ms,
        evaluated_at_ms: now_ms(),
    };
    operation.require_success(attempt_window)?;
    validate_admin_operation_progress(&operation, &state.progress, attempt_window)?;
    let overlap = AdminDecommissionOverlapEvidence::from_history(
        &operation,
        &state.progress,
        &workload_receipt,
    )?;

    Ok(AdminDecommissionExecution {
        proof: proof.clone(),
        operation,
        progress: state.progress,
        overlap,
        attempt_window,
        workload_history: workload_receipt.history,
    })
}

async fn poll_decommission<P: AdminTopologyPort>(
    port: &P,
    proof: &AdminTopologyProof,
    limits: AdminDecommissionLimits,
    transcript: Arc<Mutex<AdminDecommissionTranscript>>,
) -> Result<TerminalDecommission> {
    let target_pool_id = proof.target_pool_id.context("missing target pool ID")?;
    let target_expression = proof
        .target_pool_expression
        .as_deref()
        .context("missing target pool expression")?;
    let deadline = Instant::now() + limits.operation_timeout;
    let mut calls = Vec::<AdminCall<DecommissionPoolStatus>>::new();

    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .context("timed out waiting for RustFS decommission completion")?;
        let call = timeout(
            remaining,
            port.decommission_status(target_pool_id, target_expression),
        )
        .await
        .context("timed out reading RustFS decommission status")??;
        lock_transcript(&transcript)
            .requests
            .push(call.request.clone());
        calls.push(call);

        let candidate_id = operation_id_from_status(proof, &calls[calls.len() - 1])?;
        let operation_id = {
            let mut state = lock_transcript(&transcript);
            match (&state.operation_id, candidate_id) {
                (Some(current), Some(candidate)) => {
                    ensure!(
                        current == &candidate,
                        "decommission status changed operation identity while polling"
                    );
                }
                (None, Some(candidate)) => state.operation_id = Some(candidate),
                _ => {}
            }
            state.operation_id.clone()
        };

        let sample = if let Some(operation_id) = operation_id {
            let progress = calls
                .iter()
                .map(|call| decommission_progress_sample(proof, &operation_id, call))
                .collect::<Result<Vec<_>>>()?;
            let sample = progress
                .last()
                .cloned()
                .context("decommission progress reconstruction was empty")?;
            lock_transcript(&transcript).progress = progress;
            sample
        } else {
            let sample = decommission_progress_sample(
                proof,
                "unbound-queued-operation",
                &calls[calls.len() - 1],
            )?;
            ensure!(
                sample.state.eq_ignore_ascii_case("queued")
                    && !sample.completed
                    && !sample.failed
                    && !sample.canceled_or_stopped,
                "decommission reached a non-queued state without a stable operation identity"
            );
            sample
        };
        if is_terminal_state(&sample.state) {
            return Ok(TerminalDecommission {
                status: calls
                    .last()
                    .expect("current status call exists")
                    .value
                    .clone(),
            });
        }

        let remaining = deadline
            .checked_duration_since(Instant::now())
            .context("timed out waiting for RustFS decommission completion")?;
        sleep(limits.poll_interval.min(remaining)).await;
    }
}

fn operation_id_from_status(
    proof: &AdminTopologyProof,
    call: &AdminCall<DecommissionPoolStatus>,
) -> Result<Option<String>> {
    let target_pool_id = proof.target_pool_id.context("missing target pool ID")?;
    let start_time = call
        .value
        .decommission
        .as_ref()
        .and_then(|progress| progress.start_time.as_deref())
        .filter(|value| !value.trim().is_empty());
    let operation_id =
        start_time.map(|start_time| format!("decommission:{target_pool_id}:{start_time}"));
    let validation_id = operation_id
        .as_deref()
        .unwrap_or("unbound-queued-operation");
    decommission_progress_sample(proof, validation_id, call)?;
    Ok(operation_id)
}

async fn cancel_owned_decommission<P: AdminTopologyPort>(
    port: &P,
    proof: &AdminTopologyProof,
    operation_id: &str,
    limits: AdminDecommissionLimits,
    transcript: &Arc<Mutex<AdminDecommissionTranscript>>,
) -> Result<()> {
    let target_pool_id = proof.target_pool_id.context("missing target pool ID")?;
    let target_expression = proof
        .target_pool_expression
        .as_deref()
        .context("missing target pool expression")?;
    let deadline = Instant::now() + limits.cancel_timeout;
    let status = timeout(
        limits.cancel_timeout,
        port.decommission_status(target_pool_id, target_expression),
    )
    .await
    .context("timed out proving decommission ownership before cancel")??;
    record_status_sample(proof, operation_id, &status, transcript)?;

    if status_is_successful_completion(&status.value) {
        return Ok(());
    }
    if is_terminal_status(&status.value) {
        return clear_terminal_decommission(
            port,
            proof,
            operation_id,
            status,
            deadline,
            transcript,
        )
        .await;
    }

    let remaining = deadline
        .checked_duration_since(Instant::now())
        .context("decommission cancel deadline elapsed before cancel request")?;
    let cancel = timeout(
        remaining,
        port.cancel_decommission(target_pool_id, target_expression),
    )
    .await
    .context("timed out canceling owned RustFS decommission")??;
    lock_transcript(transcript)
        .requests
        .push(cancel.request.clone());
    validate_decommission_control_call(proof, CANCEL_PATH, &cancel)?;

    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .context("timed out waiting for canceled RustFS decommission")?;
        let status = timeout(
            remaining,
            port.decommission_status(target_pool_id, target_expression),
        )
        .await
        .context("timed out reading RustFS decommission status after cancel")??;
        record_status_sample(proof, operation_id, &status, transcript)?;
        if status_is_successful_completion(&status.value) {
            return Ok(());
        }
        if is_terminal_status(&status.value) {
            return clear_terminal_decommission(
                port,
                proof,
                operation_id,
                status,
                deadline,
                transcript,
            )
            .await;
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .context("timed out waiting for canceled RustFS decommission")?;
        sleep(limits.poll_interval.min(remaining)).await;
    }
}

async fn clear_terminal_decommission<P: AdminTopologyPort>(
    port: &P,
    proof: &AdminTopologyProof,
    operation_id: &str,
    terminal: AdminCall<DecommissionPoolStatus>,
    deadline: Instant,
    transcript: &Arc<Mutex<AdminDecommissionTranscript>>,
) -> Result<()> {
    validate_clearable_terminal(&terminal.value)?;
    let target_pool_id = proof.target_pool_id.context("missing target pool ID")?;
    let target_expression = proof
        .target_pool_expression
        .as_deref()
        .context("missing target pool expression")?;
    ensure!(
        operation_id_from_status(proof, &terminal)?.as_deref() == Some(operation_id),
        "refusing to clear decommission for a different operation identity"
    );
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .context("decommission cleanup deadline elapsed before clear")?;
    let clear = timeout(
        remaining,
        port.clear_decommission(target_pool_id, target_expression),
    )
    .await
    .context("timed out clearing terminal RustFS decommission metadata")??;
    lock_transcript(transcript)
        .requests
        .push(clear.request.clone());
    validate_decommission_control_call(proof, CLEAR_PATH, &clear)?;
    Ok(())
}

fn validate_clearable_terminal(status: &DecommissionPoolStatus) -> Result<()> {
    let progress = status
        .decommission
        .as_ref()
        .context("terminal decommission status lacks progress before clear")?;
    ensure!(
        is_terminal_status(status)
            && !progress.complete
            && (progress.failed || progress.canceled)
            && progress.unresolved_entries.is_empty(),
        "refusing to clear decommission outside a failed/canceled terminal state with no unresolved entries"
    );
    Ok(())
}

fn record_status_sample(
    proof: &AdminTopologyProof,
    operation_id: &str,
    call: &AdminCall<DecommissionPoolStatus>,
    transcript: &Arc<Mutex<AdminDecommissionTranscript>>,
) -> Result<()> {
    lock_transcript(transcript)
        .requests
        .push(call.request.clone());
    ensure!(
        operation_id_from_status(proof, call)?.as_deref() == Some(operation_id),
        "decommission status does not match the owned operation identity"
    );
    let sample = decommission_progress_sample(proof, operation_id, call)?;
    lock_transcript(transcript).progress.push(sample);
    Ok(())
}

fn is_terminal_state(state: &str) -> bool {
    matches!(
        state.to_ascii_lowercase().as_str(),
        "complete" | "failed" | "canceled"
    )
}

fn is_terminal_status(status: &DecommissionPoolStatus) -> bool {
    is_terminal_state(&status.status)
}

fn status_is_successful_completion(status: &DecommissionPoolStatus) -> bool {
    status.status.eq_ignore_ascii_case("complete")
        && status.pool_status.eq_ignore_ascii_case("decommissioned")
        && status.decommission.as_ref().is_some_and(|progress| {
            progress.complete
                && !progress.queued
                && !progress.failed
                && !progress.canceled
                && progress.unresolved_entries.is_empty()
                && (progress.objects_decommissioned > 0 || progress.bytes_decommissioned > 0)
        })
}

pub fn validate_admin_decommission_evidence(
    operation: &AdminOperationEvidence,
    progress: &[AdminOperationProgressSample],
    overlap: &AdminDecommissionOverlapEvidence,
    history: &[OperationRecord],
    checker: &CheckerReport,
) -> Result<()> {
    overlap.validate(operation, progress, history)?;
    ensure!(
        checker.scenario == ADMIN_DECOMMISSION_SCENARIO
            && checker.run_id == operation.attempt.run_id,
        "final checker identity does not match the admin-decommission attempt"
    );
    checker.require_success()?;
    ensure!(
        checker.versioning_expected
            && checker.expected_committed_versions > 0
            && checker.expected_committed_versions == checker.verified_committed_versions
            && !checker.operation_cohorts.is_empty(),
        "final checker did not prove the complete committed versioned workload"
    );
    checker::validate_checker_audit_against_history(checker, history)
        .context("admin-decommission checker audit does not match history.jsonl")?;
    let audit = checker
        .audit
        .as_ref()
        .context("admin-decommission checker lacks a history-bound audit")?;
    ensure!(
        audit.history_prefix_record_count + audit.history_suffix_record_count == history.len()
            && audit.list_object_versions_completed == Some(true)
            && audit.data_version_checks.len() == checker.expected_committed_versions
            && !audit.delete_marker_checks.is_empty()
            && audit
                .delete_marker_checks
                .iter()
                .all(|marker| marker.visible_in_list_object_versions),
        "final checker did not cover every committed data version and delete marker"
    );
    Ok(())
}

fn workload_records(receipt: &AdminDecommissionWorkloadReceipt) -> Result<Vec<&OperationRecord>> {
    ensure!(
        receipt.started_at_ms > 0
            && receipt.started_at_ms <= receipt.ended_at_ms
            && receipt.first_event_sequence > 0
            && receipt.first_event_sequence <= receipt.last_event_sequence,
        "bounded workload receipt has an invalid time or recorder sequence window"
    );
    let first = receipt
        .history
        .first()
        .context("bounded workload receipt has empty history")?;
    let run_id = first
        .run_id
        .as_deref()
        .context("bounded workload receipt history lacks a run ID")?;
    validate_history_scope_and_order(&receipt.history, &first.scenario, run_id, &first.bucket)?;
    let mut records = Vec::new();
    for record in &receipt.history {
        let started = record
            .started_sequence
            .context("bounded workload history record lacks a start sequence")?;
        let ended = record
            .ended_sequence
            .context("bounded workload history record lacks an end sequence")?;
        let starts_in =
            (receipt.first_event_sequence..=receipt.last_event_sequence).contains(&started);
        let ends_in = (receipt.first_event_sequence..=receipt.last_event_sequence).contains(&ended);
        ensure!(
            starts_in == ends_in,
            "an S3 operation crosses the bounded workload recorder sequence boundary"
        );
        if starts_in {
            ensure!(
                record.started_at_ms >= receipt.started_at_ms
                    && record.ended_at_ms <= receipt.ended_at_ms,
                "an S3 operation falls outside the bounded workload time window"
            );
            records.push(record);
        }
    }
    ensure!(
        !records.is_empty(),
        "bounded decommission workload is empty"
    );
    ensure!(
        records
            .iter()
            .filter_map(|record| record.started_sequence)
            .min()
            == Some(receipt.first_event_sequence)
            && records
                .iter()
                .filter_map(|record| record.ended_sequence)
                .max()
                == Some(receipt.last_event_sequence),
        "bounded workload sequence window is not exactly covered by history"
    );
    Ok(records)
}

fn validate_workload_families(
    history: &[OperationRecord],
    workload: Vec<&OperationRecord>,
) -> Result<()> {
    let successful_versioned_mutation = |record: &OperationRecord| {
        record.outcome == OperationOutcome::Ok
            && record
                .version_id
                .as_deref()
                .is_some_and(|version| !version.is_empty() && version != "null")
    };
    let puts = workload
        .iter()
        .filter(|record| record.kind == OperationKind::Put)
        .filter(|record| successful_versioned_mutation(record))
        .copied()
        .collect::<Vec<_>>();
    let earlier_data_version = |put: &OperationRecord| {
        let start = put.started_sequence.unwrap_or_default();
        history.iter().any(|record| {
            record.key == put.key
                && record.outcome == OperationOutcome::Ok
                && matches!(
                    record.kind,
                    OperationKind::Put | OperationKind::CompleteMultipartUpload
                )
                && record.ended_sequence.is_some_and(|ended| ended < start)
        })
    };
    ensure!(
        puts.iter().any(|record| !earlier_data_version(record)),
        "bounded decommission workload has no successful ordinary PUT"
    );
    ensure!(
        puts.iter().any(|record| earlier_data_version(record)),
        "bounded decommission workload has no successful overwrite"
    );
    ensure!(
        history.iter().any(|record| {
            record.kind == OperationKind::Put
                && record.outcome == OperationOutcome::Ok
                && record.size_bytes == Some(0)
                && record
                    .version_id
                    .as_deref()
                    .is_some_and(|version| !version.is_empty() && version != "null")
        }),
        "versioned decommission history has no committed zero-byte object"
    );
    ensure!(
        workload.iter().any(|record| {
            record.kind == OperationKind::Delete && successful_versioned_mutation(record)
        }),
        "bounded decommission workload has no committed delete marker"
    );
    ensure!(
        workload.iter().any(|record| {
            record.kind == OperationKind::CompleteMultipartUpload
                && successful_versioned_mutation(record)
        }) && workload.iter().any(|record| {
            record.kind == OperationKind::AbortMultipartUpload
                && record.outcome == OperationOutcome::Ok
        }),
        "bounded decommission workload lacks successful multipart completion or abort activity"
    );
    ensure!(
        history.iter().any(|record| {
            record.kind == OperationKind::PutBucketVersioning
                && record.outcome == OperationOutcome::Ok
        }),
        "admin-decommission history does not prove bucket versioning was enabled"
    );
    ensure!(
        history.iter().all(|record| {
            !matches!(
                record.kind,
                OperationKind::Put | OperationKind::Delete | OperationKind::CompleteMultipartUpload
            ) || record.outcome != OperationOutcome::Ok
                || record
                    .version_id
                    .as_deref()
                    .is_some_and(|version| !version.is_empty() && version != "null")
        }),
        "a successful admin-decommission mutation lacks an immutable version ID"
    );
    Ok(())
}

fn decommission_window(operation: &AdminOperationEvidence) -> Result<(u64, u64)> {
    ensure!(
        operation.scenario == ADMIN_DECOMMISSION_SCENARIO,
        "operation is not admin-decommission"
    );
    let start = operation
        .requests
        .iter()
        .find(|request| request.method == "POST" && request.path == START_PATH)
        .context("admin-decommission operation lacks its start receipt")?;
    let terminal = operation
        .requests
        .iter()
        .rev()
        .find(|request| request.method == "GET" && request.path == STATUS_PATH)
        .context("admin-decommission operation lacks its terminal status receipt")?;
    ensure!(
        start.observed_at_ms <= terminal.observed_at_ms,
        "admin-decommission operation receipt times are inverted"
    );
    Ok((start.observed_at_ms, terminal.observed_at_ms))
}

fn overlapping_status_request_ids(
    operation: &AdminOperationEvidence,
    progress: &[AdminOperationProgressSample],
    workload_started_at_ms: u64,
    workload_ended_at_ms: u64,
) -> Result<Vec<String>> {
    let progress_ids = progress
        .iter()
        .map(|sample| sample.status_request_id.as_str())
        .collect::<BTreeSet<_>>();
    operation
        .requests
        .iter()
        .filter(|request| {
            request.method == "GET"
                && request.path == STATUS_PATH
                && intervals_overlap(
                    request.started_at_ms,
                    request.observed_at_ms,
                    workload_started_at_ms,
                    workload_ended_at_ms,
                )
        })
        .map(|request| {
            request
                .request_id
                .clone()
                .filter(|request_id| progress_ids.contains(request_id.as_str()))
                .context("overlapping decommission status request lacks its progress sample")
        })
        .collect()
}

fn intervals_overlap(first_start: u64, first_end: u64, second_start: u64, second_end: u64) -> bool {
    first_start <= second_end && second_start <= first_end
}

fn lock_transcript(
    transcript: &Arc<Mutex<AdminDecommissionTranscript>>,
) -> std::sync::MutexGuard<'_, AdminDecommissionTranscript> {
    transcript
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn transcript_state(
    transcript: &Arc<Mutex<AdminDecommissionTranscript>>,
) -> AdminDecommissionTranscript {
    lock_transcript(transcript).clone()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

#[async_trait]
impl AdminDecommissionAttemptPort for RustfsAdminTopologyAdapter {
    async fn capture_pool_snapshot(
        &self,
        run_id: &str,
        case_name: &str,
    ) -> Result<AdminPoolSnapshot> {
        RustfsAdminTopologyAdapter::capture_pool_snapshot(self, run_id, case_name).await
    }
}

struct LiveDecommissionState {
    context: Option<FaultRunContext>,
    s3: Option<S3WorkloadClient>,
    s3_port_forward: Option<PortForwardGuard>,
    s3_endpoint: Option<String>,
    admin: Option<Arc<RustfsAdminTopologyAdapter>>,
    proof: Option<AdminTopologyProof>,
    pools_before: Option<AdminPoolSnapshot>,
    terminal: Option<DecommissionPoolStatus>,
    status_calls: Vec<AdminCall<DecommissionPoolStatus>>,
    fixture: AdminFixtureEvidence,
    prefilled: Vec<ObjectSpec>,
    workload: Option<MixedWorkloadResult>,
    workload_receipt: Option<AdminDecommissionWorkloadReceipt>,
    health_baseline: Option<RecoveryHealthBaseline>,
    verified: bool,
}

pub(crate) struct LiveAdminDecommissionDriver {
    config: FaultTestConfig,
    collector: ArtifactCollector,
    scenario: FaultScenario,
    plan: AdminExecutionPlan,
    run_id: String,
    deadline: RunDeadline,
    transcript: Arc<Mutex<AdminDecommissionTranscript>>,
    state: AsyncMutex<LiveDecommissionState>,
}

impl LiveAdminDecommissionDriver {
    pub(crate) fn new(
        config: &FaultTestConfig,
        collector: &ArtifactCollector,
        scenario: &FaultScenario,
        plan: &AdminExecutionPlan,
        run_id: &str,
        deadline: RunDeadline,
    ) -> Result<Self> {
        ensure!(
            scenario.name == ADMIN_DECOMMISSION_SCENARIO
                && plan.scenario == scenario.name
                && plan.case_name == scenario.case_name,
            "live decommission driver requires the canonical admin-decommission plan"
        );
        let fixture_plan =
            AdminFixturePlan::for_scenario(&scenario.name, config.expected_rustfs_pod_count)?;
        Ok(Self {
            config: config.clone(),
            collector: collector.clone(),
            scenario: scenario.clone(),
            plan: plan.clone(),
            run_id: run_id.to_string(),
            deadline,
            transcript: Arc::new(Mutex::new(AdminDecommissionTranscript::default())),
            state: AsyncMutex::new(LiveDecommissionState {
                context: None,
                s3: None,
                s3_port_forward: None,
                s3_endpoint: None,
                admin: None,
                proof: None,
                pools_before: None,
                terminal: None,
                status_calls: Vec::new(),
                fixture: AdminFixtureEvidence {
                    schema_version: 1,
                    scenario: scenario.name.clone(),
                    run_id: run_id.to_string(),
                    tenant: config.cluster.tenant_name.clone(),
                    plan: fixture_plan,
                    observations: Vec::new(),
                },
                prefilled: Vec::new(),
                workload: None,
                workload_receipt: None,
                health_baseline: None,
                verified: false,
            }),
        })
    }

    async fn start_inner(&self) -> Result<()> {
        let execution_plan = crate::fault::plan::ExecutionPlan::Admin(self.plan.clone());
        let context = initialize_fault_run(
            &self.config,
            &self.collector,
            &self.scenario,
            &execution_plan,
            &self.run_id,
        )?;
        let mut state = self.state.lock().await;
        state.context = Some(context);
        self.write_fixture(&state.fixture)?;

        reset_tenant_resources(&self.config.cluster)
            .context("reset fault-test Tenant before admin decommission")?;
        apply_admin_tenant_stage(
            &self.config.cluster,
            &state.fixture.plan,
            false,
            &self.run_id,
        )
        .context("apply decommission source-pool Tenant")?;
        wait_for_ready_tenant(&self.config.cluster)
            .await
            .context("wait for decommission source-pool Tenant")?;
        wait_for_stable_rustfs_pods(
            &self.config.cluster,
            state.fixture.plan.servers_per_pool,
            self.config.rustfs_pod_stable_window,
        )
        .await
        .context("wait for stable decommission source pool")?;
        state
            .fixture
            .observations
            .push(capture_admin_fixture_observation(
                &self.config.cluster,
                AdminFixturePhase::PrimaryReady,
                None,
            )?);
        self.write_fixture(&state.fixture)?;

        let (endpoint, mut s3_port_forward) = s3_access(&self.config)?;
        ensure_s3_access(&mut s3_port_forward, &self.config.cluster, &endpoint).await?;
        let (access_key, secret_key) = resources::test_credentials();
        let s3 = S3WorkloadClient::new(
            &endpoint,
            &state.context.as_ref().expect("context initialized").bucket,
            access_key,
            secret_key,
            self.config.request_timeout,
        )
        .await?;
        let history = &state.context.as_ref().expect("context initialized").history;
        ensure!(
            s3.create_bucket(history).await? == OperationOutcome::Ok,
            "admin decommission workload bucket creation failed"
        );
        ensure!(
            self.config.workload_versioning,
            "admin decommission requires a versioned workload"
        );
        ensure!(
            s3.enable_bucket_versioning(history).await? == OperationOutcome::Ok,
            "admin decommission workload bucket versioning failed"
        );
        let prefilled = prefill_objects(
            &s3,
            history,
            &self.run_id,
            &state
                .context
                .as_ref()
                .expect("context initialized")
                .workload_plan,
            self.scenario.prefill_count(),
            self.config.prefill_concurrency,
            self.config.workload_directory_marker_percent,
        )
        .await
        .context("prefill the exact decommission target pool")?;
        sleep(Duration::from_millis(1)).await;
        state
            .fixture
            .observations
            .push(capture_admin_fixture_observation(
                &self.config.cluster,
                AdminFixturePhase::PrefillComplete,
                Some(prefilled.len()),
            )?);
        self.write_fixture(&state.fixture)?;

        apply_admin_tenant_stage(
            &self.config.cluster,
            &state.fixture.plan,
            true,
            &self.run_id,
        )
        .context("append the decommission survivor pool")?;
        sleep(Duration::from_millis(1)).await;
        state
            .fixture
            .observations
            .push(capture_admin_fixture_observation(
                &self.config.cluster,
                AdminFixturePhase::ExpansionApplied,
                None,
            )?);
        self.write_fixture(&state.fixture)?;
        wait_for_ready_tenant(&self.config.cluster)
            .await
            .context("wait for expanded decommission Tenant")?;
        let expanded_pod_count = state
            .fixture
            .plan
            .servers_per_pool
            .checked_mul(2)
            .context("expanded admin Tenant pod count overflowed")?;
        wait_for_stable_rustfs_pods(
            &self.config.cluster,
            expanded_pod_count,
            self.config.rustfs_pod_stable_window,
        )
        .await
        .context("wait for stable two-pool decommission Tenant")?;
        ensure_s3_access(&mut s3_port_forward, &self.config.cluster, &endpoint)
            .await
            .context("restore S3 access after decommission Tenant expansion")?;
        sleep(Duration::from_millis(1)).await;
        state
            .fixture
            .observations
            .push(capture_admin_fixture_observation(
                &self.config.cluster,
                AdminFixturePhase::TopologyStable,
                None,
            )?);
        state.fixture.validate_complete()?;
        self.write_fixture(&state.fixture)?;

        let layout =
            crate::rustfs::read_erasure_layout(&endpoint, "us-east-1", access_key, secret_key)
                .await
                .context("capture healthy two-pool RustFS layout")?;
        let health_baseline = RecoveryHealthBaseline::from_layout(&layout, now_ms())
            .context("two-pool RustFS layout is not healthy before decommission")?;
        let context = state.context.as_ref().expect("context initialized");
        context.events.record(
            "recovery-health-baseline",
            RunEventStatus::Succeeded,
            "healthy two-pool RustFS baseline captured before decommission",
            Some(serde_json::to_value(&health_baseline)?),
        )?;

        let (admin_endpoint, mut admin_forward) = tenant_port_forward(&self.config.cluster)?;
        wait_for_tenant_s3(
            &mut admin_forward,
            &admin_endpoint,
            self.config.cluster.timeout,
        )
        .await?;
        let adapter = Arc::new(
            RustfsAdminTopologyAdapter::connect(admin_forward, "us-east-1", access_key, secret_key)
                .await
                .context("connect fresh RustFS admin topology adapter")?,
        );
        let pools_before = AdminDecommissionAttemptPort::capture_pool_snapshot(
            adapter.as_ref(),
            &self.run_id,
            self.scenario.case_name,
        )
        .await
        .context("capture fresh pre-start decommission pool snapshot")?;
        let tenant = serde_json::from_str(&pools_before.tenant_get.response_body)
            .context("decode authenticated Tenant receipt for topology proof")?;
        let topology_context = AdminTopologyBuildContext::new(
            &self.run_id,
            self.scenario.case_name,
            &context.workload_plan,
            pools_before.runtime.clone(),
        )?;
        let proof = AdminTopologyProof::build(
            &self.plan.topology,
            &self.scenario.name,
            &tenant,
            pools_before.pools.clone(),
            &topology_context,
        )?;
        ensure!(
            proof.target_used_bytes > 0,
            "decommission target pool has no real data movement to perform"
        );
        validate_admin_pre_start_snapshot(&proof, &pools_before, now_ms())
            .context("recheck exact decommission target and capacity immediately before start")?;
        let preflight = PreflightSummary::single_run(
            &self.config,
            &self.scenario.name,
            &self.run_id,
            vec![PreflightPhase::new(
                "admin-topology",
                vec![PreflightCheck::passed(
                    "owned_two_pool_target",
                    "fresh Tenant, deployment, exact populated target, idle peers, and survivor capacity were rechecked immediately before decommission",
                    ResponsibilityDomain::Harness,
                )],
            )],
        );
        self.collector.write_text(
            self.scenario.case_name,
            "preflight-summary.json",
            &serde_json::to_string_pretty(&preflight)?,
        )?;

        let target_pool_id = proof
            .target_pool_id
            .context("admin-decommission proof lacks a target pool ID")?;
        let target_expression = proof
            .target_pool_expression
            .as_deref()
            .context("admin-decommission proof lacks a target pool expression")?;
        let start = adapter
            .start_decommission(target_pool_id, target_expression)
            .await
            .context("start exact RustFS pool decommission")?;
        validate_decommission_control_call(&proof, START_PATH, &start)?;
        lock_transcript(&self.transcript)
            .requests
            .push(start.request);

        state.s3 = Some(s3);
        state.s3_port_forward = s3_port_forward;
        state.s3_endpoint = Some(endpoint);
        state.admin = Some(adapter);
        state.proof = Some(proof);
        state.pools_before = Some(pools_before);
        state.prefilled = prefilled;
        state.health_baseline = Some(health_baseline);
        self.write_transcript()?;
        Ok(())
    }

    async fn observe_inner(&self) -> Result<AdminWorkflowObservation> {
        let (adapter, proof) = {
            let state = self.state.lock().await;
            (
                state
                    .admin
                    .clone()
                    .context("decommission adapter is not ready")?,
                state
                    .proof
                    .clone()
                    .context("decommission proof is not ready")?,
            )
        };
        let target_pool_id = proof.target_pool_id.context("missing target pool ID")?;
        let target_expression = proof
            .target_pool_expression
            .as_deref()
            .context("missing target pool expression")?;
        let call = adapter
            .decommission_status(target_pool_id, target_expression)
            .await?;
        lock_transcript(&self.transcript)
            .requests
            .push(call.request.clone());

        let candidate_id = operation_id_from_status(&proof, &call)?;
        let operation_id = {
            let mut transcript = lock_transcript(&self.transcript);
            match (&transcript.operation_id, candidate_id) {
                (Some(current), Some(candidate)) => ensure!(
                    current == &candidate,
                    "decommission status changed operation identity while polling"
                ),
                (None, Some(candidate)) => transcript.operation_id = Some(candidate),
                _ => {}
            }
            transcript.operation_id.clone()
        };

        let mut state = self.state.lock().await;
        state.status_calls.push(call.clone());
        let sample = if let Some(operation_id) = operation_id {
            let progress = state
                .status_calls
                .iter()
                .map(|call| decommission_progress_sample(&proof, &operation_id, call))
                .collect::<Result<Vec<_>>>()?;
            let sample = progress
                .last()
                .cloned()
                .context("decommission progress reconstruction was empty")?;
            lock_transcript(&self.transcript).progress = progress;
            sample
        } else {
            let sample = decommission_progress_sample(&proof, "unbound-queued-operation", &call)?;
            ensure!(
                sample.state.eq_ignore_ascii_case("queued")
                    && !sample.completed
                    && !sample.failed
                    && !sample.canceled_or_stopped,
                "decommission reached a non-queued state without a stable operation identity"
            );
            sample
        };
        self.write_transcript()?;
        if is_terminal_state(&sample.state) {
            state.terminal = Some(call.value);
            ensure!(
                sample.completed && !sample.failed && !sample.canceled_or_stopped,
                "RustFS decommission reached an unsuccessful terminal state"
            );
            Ok(AdminWorkflowObservation::Completed)
        } else {
            Ok(AdminWorkflowObservation::Running)
        }
    }

    async fn run_workload_inner(&self) -> Result<()> {
        let (s3, history, plan, prefilled, events) = {
            let state = self.state.lock().await;
            let context = state
                .context
                .as_ref()
                .context("decommission run is not initialized")?;
            (
                state
                    .s3
                    .clone()
                    .context("decommission S3 client is not ready")?,
                context.history.clone(),
                context.workload_plan.clone(),
                state.prefilled.clone(),
                context.events.clone(),
            )
        };
        events.record(
            "mixed-workload",
            RunEventStatus::Started,
            "running bounded versioned S3 workload during RustFS decommission",
            Some(serde_json::json!({
                "object_count": self.scenario.mixed_workload_count(),
                "concurrency": plan.concurrency,
            })),
        )?;
        let first_event_sequence = history.next_event_sequence();
        let started_at_ms = now_ms();
        let workload = run_mixed_workload(&MixedWorkloadRequest {
            s3: &s3,
            history: &history,
            scenario: &self.scenario.name,
            run_id: &self.run_id,
            plan: &plan,
            prefilled: &prefilled,
            start_index: self.scenario.prefill_count(),
            count: self.scenario.mixed_workload_count(),
            ranged_get_percent: self.config.workload_ranged_get_percent,
            staged_multipart_uploads: None,
            deadline: self.deadline,
        })
        .await?;
        let ended_at_ms = now_ms();
        let last_event_sequence = history
            .next_event_sequence()
            .checked_sub(1)
            .context("bounded decommission workload recorded no completed operation")?;
        let receipt = AdminDecommissionWorkloadReceipt {
            started_at_ms,
            ended_at_ms,
            first_event_sequence,
            last_event_sequence,
            history: history.records(),
        };
        workload_records(&receipt)?;
        events.record(
            "mixed-workload",
            RunEventStatus::Succeeded,
            "bounded S3 workload completed during RustFS decommission",
            Some(serde_json::json!({ "disruptions": workload.summary.disrupted() })),
        )?;
        self.collector.write_text(
            self.scenario.case_name,
            "workload-summary.json",
            &serde_json::to_string_pretty(&workload.summary)?,
        )?;
        let mut state = self.state.lock().await;
        state.workload = Some(workload);
        state.workload_receipt = Some(receipt);
        Ok(())
    }

    async fn verify_inner(&self) -> Result<()> {
        let (
            adapter,
            proof,
            pools_before,
            terminal,
            workload_receipt,
            s3,
            endpoint,
            baseline,
            history,
            workload_plan,
            events,
            mut workload,
            attempt_started_at_ms,
        ) = {
            let mut state = self.state.lock().await;
            let context = state
                .context
                .as_ref()
                .context("decommission run is not initialized")?;
            (
                state
                    .admin
                    .clone()
                    .context("decommission adapter is not ready")?,
                state
                    .proof
                    .clone()
                    .context("decommission proof is not ready")?,
                state
                    .pools_before
                    .clone()
                    .context("decommission pre-start snapshot is missing")?,
                state
                    .terminal
                    .clone()
                    .context("decommission terminal receipt is missing")?,
                state
                    .workload_receipt
                    .clone()
                    .context("decommission workload receipt is missing")?,
                state
                    .s3
                    .clone()
                    .context("decommission S3 client is not ready")?,
                state
                    .s3_endpoint
                    .clone()
                    .context("decommission S3 endpoint is missing")?,
                state
                    .health_baseline
                    .clone()
                    .context("decommission health baseline is missing")?,
                context.history.clone(),
                context.workload_plan.clone(),
                context.events.clone(),
                state
                    .workload
                    .take()
                    .context("decommission workload result is missing")?,
                state
                    .fixture
                    .observations
                    .first()
                    .map(|observation| observation.observed_at_ms)
                    .context("decommission fixture has no initial observation")?,
            )
        };
        let pools_after = AdminDecommissionAttemptPort::capture_pool_snapshot(
            adapter.as_ref(),
            &self.run_id,
            self.scenario.case_name,
        )
        .await
        .context("capture post-terminal decommission pool snapshot")?;
        let transcript = transcript_state(&self.transcript);
        let attempt_window = AdminAttemptWindow {
            started_at_ms: attempt_started_at_ms,
            evaluated_at_ms: now_ms(),
        };
        let operation = AdminOperationEvidence::from_decommission(
            &proof,
            pools_before,
            terminal,
            transcript.requests,
            pools_after,
        )?;
        operation.require_success(attempt_window)?;
        validate_admin_operation_progress(&operation, &transcript.progress, attempt_window)?;
        let overlap = AdminDecommissionOverlapEvidence::from_history(
            &operation,
            &transcript.progress,
            &workload_receipt,
        )?;
        let execution = AdminDecommissionExecution {
            proof,
            operation,
            progress: transcript.progress,
            overlap,
            attempt_window,
            workload_history: workload_receipt.history,
        };
        execution.write_artifacts(&self.collector)?;

        wait_for_stable_rustfs_pods(
            &self.config.cluster,
            self.config
                .expected_rustfs_pod_count
                .checked_mul(2)
                .context("expanded admin Tenant pod count overflowed")?,
            self.config.rustfs_pod_stable_window,
        )
        .await?;
        let pods = rustfs_pod_identities(&self.config.cluster)?;
        events.record(
            "recovery-health",
            RunEventStatus::Started,
            "validating RustFS health after decommission",
            None,
        )?;
        let report = self
            .deadline
            .run(observe_recovery_health(
                &self.config.cluster,
                &endpoint,
                &baseline,
                &pods,
                &self.scenario.name,
                &self.run_id,
                &|report| {
                    self.collector
                        .write_text(
                            self.scenario.case_name,
                            RECOVERY_HEALTH_ARTIFACT,
                            &serde_json::to_string_pretty(report)?,
                        )
                        .map(|_| ())
                },
            ))
            .await?;
        self.collector.write_text(
            self.scenario.case_name,
            RECOVERY_HEALTH_ARTIFACT,
            &serde_json::to_string_pretty(&report)?,
        )?;
        report.require_success()?;
        events.record(
            "recovery-health",
            RunEventStatus::Succeeded,
            "RustFS health remained stable after decommission",
            None,
        )?;

        self.run_post_recovery_probe(&s3, &workload_plan, &events)
            .await?;
        workload.seal_recommit_candidates(&s3, &history)?;
        self.collector.write_text(
            self.scenario.case_name,
            "workload-summary.json",
            &serde_json::to_string_pretty(&workload.summary)?,
        )?;
        let prechecker =
            checker::check_s3_history(&s3, &history, true, workload_plan.concurrency, true).await?;
        self.collector.write_text(
            self.scenario.case_name,
            "checker-pre-recommit-report.json",
            &serde_json::to_string_pretty(&prechecker)?,
        )?;
        prechecker.require_success()?;

        let recommit = recommit_unconfirmed_objects(
            &s3,
            &history,
            &workload.unconfirmed_puts,
            workload_plan.concurrency,
            self.deadline,
        )
        .await;
        self.collector.write_text(
            self.scenario.case_name,
            "recommit-report.json",
            &serde_json::to_string_pretty(&recommit)?,
        )?;
        ensure!(!recommit.has_failures(), "{}", recommit.failure_message());
        workload.summary.recommitted_after_recovery = recommit.committed;
        self.collector.write_text(
            self.scenario.case_name,
            "workload-summary.json",
            &serde_json::to_string_pretty(&workload.summary)?,
        )?;

        events.record(
            "checker-final",
            RunEventStatus::Started,
            "checking the final versioned object model after decommission",
            None,
        )?;
        let checker =
            checker::check_s3_history(&s3, &history, true, workload_plan.concurrency, true).await?;
        self.collector.write_text(
            self.scenario.case_name,
            "checker-report.json",
            &serde_json::to_string_pretty(&checker)?,
        )?;
        checker.require_success()?;
        validate_admin_decommission_evidence(
            &execution.operation,
            &execution.progress,
            &execution.overlap,
            &history.records(),
            &checker,
        )?;
        events.record(
            "checker-final",
            RunEventStatus::Succeeded,
            "final decommission object model check passed",
            None,
        )?;
        self.state.lock().await.verified = true;
        Ok(())
    }

    async fn run_post_recovery_probe(
        &self,
        s3: &S3WorkloadClient,
        workload_plan: &crate::fault::workload::WorkloadPlan,
        events: &crate::fault::events::RunEventRecorder,
    ) -> Result<()> {
        let history = crate::fault::history::Recorder::create(
            self.collector
                .case_dir(self.scenario.case_name)
                .join(POST_RECOVERY_WRITE_HISTORY_ARTIFACT),
            &self.scenario.name,
            &self.run_id,
        )?;
        let object_count = post_recovery_object_count(workload_plan.object_count);
        events.record(
            "post-recovery-write",
            RunEventStatus::Started,
            "probing fresh writes after decommission",
            Some(serde_json::json!({ "objects": object_count })),
        )?;
        let report = run_post_recovery_write_probe(&PostRecoveryWriteRequest {
            s3,
            history: &history,
            run_id: &self.run_id,
            seed: workload_plan.seed ^ POST_RECOVERY_SEED_SALT,
            object_count,
            concurrency: workload_plan.concurrency,
            deadline: self.deadline,
        })
        .await?;
        self.collector.write_text(
            self.scenario.case_name,
            POST_RECOVERY_WRITE_REPORT_ARTIFACT,
            &serde_json::to_string_pretty(&report)?,
        )?;
        report.require_success()?;
        events.record(
            "post-recovery-write",
            RunEventStatus::Succeeded,
            "fresh writes succeeded after decommission",
            None,
        )?;
        Ok(())
    }

    fn write_fixture(&self, fixture: &AdminFixtureEvidence) -> Result<()> {
        self.collector.write_text(
            self.scenario.case_name,
            ADMIN_FIXTURE_ARTIFACT,
            &serde_json::to_string_pretty(fixture)?,
        )?;
        Ok(())
    }

    fn write_transcript(&self) -> Result<()> {
        self.collector.write_text(
            self.scenario.case_name,
            ADMIN_DECOMMISSION_TRANSCRIPT_ARTIFACT,
            &serde_json::to_string_pretty(&transcript_state(&self.transcript))?,
        )?;
        Ok(())
    }

    async fn preserve_evidence(&self, result: Result<()>) -> Result<()> {
        let fixture = self.state.lock().await.fixture.clone();
        combine_primary_and_secondary(
            result,
            self.write_fixture(&fixture)
                .and_then(|_| self.write_transcript()),
            "persist decommission transcript",
        )
    }
}

#[async_trait(?Send)]
impl AdminCaseDriver for LiveAdminDecommissionDriver {
    async fn start(&self) -> Result<()> {
        let result = self.start_inner().await;
        self.preserve_evidence(result).await
    }

    async fn observe(&self) -> Result<AdminWorkflowObservation> {
        let result = self.observe_inner().await;
        match result {
            Ok(observation) => Ok(observation),
            Err(error) => self
                .preserve_evidence(Err(error))
                .await
                .and(Ok(AdminWorkflowObservation::Running)),
        }
    }

    async fn run_workload(&self) -> Result<()> {
        let result = self.run_workload_inner().await;
        self.preserve_evidence(result).await
    }

    async fn verify(&self) -> Result<()> {
        let result = self.verify_inner().await;
        self.preserve_evidence(result).await
    }

    async fn cancel(&self) -> Result<AdminCancelOutcome> {
        let (adapter, proof, operation_id) = {
            let state = self.state.lock().await;
            let Some(operation_id) = transcript_state(&self.transcript).operation_id else {
                return Ok(AdminCancelOutcome::NoOwnedOperation);
            };
            (
                state
                    .admin
                    .clone()
                    .context("decommission adapter is not ready")?,
                state
                    .proof
                    .clone()
                    .context("decommission proof is not ready")?,
                operation_id,
            )
        };
        let result = cancel_owned_decommission(
            adapter.as_ref(),
            &proof,
            &operation_id,
            AdminDecommissionLimits {
                poll_interval: Duration::from_secs(5),
                operation_timeout: self.plan.operation_timeout,
                cancel_timeout: self.config.cluster.timeout,
            },
            &self.transcript,
        )
        .await;
        combine_primary_and_secondary(
            result,
            self.write_transcript(),
            "persist decommission cancel transcript",
        )?;
        let changed_operation = transcript_state(&self.transcript)
            .requests
            .iter()
            .any(|request| request.path == CANCEL_PATH || request.path == CLEAR_PATH);
        Ok(if changed_operation {
            AdminCancelOutcome::CanceledOwnedOperation
        } else {
            AdminCancelOutcome::NoOwnedOperation
        })
    }

    async fn cleanup(&self) -> Result<()> {
        let (fixture, events, verified, admin, s3, s3_port_forward) = {
            let mut state = self.state.lock().await;
            (
                state.fixture.clone(),
                state.context.as_ref().map(|context| context.events.clone()),
                state.verified,
                state.admin.take(),
                state.s3.take(),
                state.s3_port_forward.take(),
            )
        };
        let cluster = self.config.cluster.clone();
        let run_id = self.run_id.clone();
        persist_then_cleanup_admin_fixture(
            || {
                self.write_fixture(&fixture)?;
                self.write_transcript()?;
                if let Some(events) = &events {
                    events.record(
                        "run",
                        if verified {
                            RunEventStatus::Succeeded
                        } else {
                            RunEventStatus::Failed
                        },
                        if verified {
                            "admin decommission run completed successfully"
                        } else {
                            "admin decommission run ended before successful verification"
                        },
                        None,
                    )?;
                }
                Ok(())
            },
            move || {
                drop(admin);
                drop(s3);
                drop(s3_port_forward);
                reset_owned_admin_tenant_resources(&cluster, &run_id)
                    .context("clean up run-owned staged admin Tenant")
            },
        )
        .await
    }
}

fn combine_primary_and_secondary(
    primary: Result<()>,
    secondary: Result<()>,
    secondary_label: &str,
) -> Result<()> {
    match (primary, secondary) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(primary), Err(secondary)) => {
            Err(primary.context(format!("{secondary_label} also failed: {secondary:#}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn record(
        id: &str,
        kind: OperationKind,
        key: Option<&str>,
        size: Option<usize>,
        version: Option<&str>,
        sequence: u64,
    ) -> OperationRecord {
        OperationRecord {
            id: id.to_string(),
            scenario: ADMIN_DECOMMISSION_SCENARIO.to_string(),
            run_id: Some("run-decommission".to_string()),
            kind,
            bucket: "bucket".to_string(),
            key: key.map(str::to_string),
            value_sha256: size.map(|_| "hash".to_string()),
            size_bytes: size,
            version_id: version.map(str::to_string),
            listed_keys: None,
            listed_versions: None,
            payload_ref: None,
            range: None,
            started_sequence: Some(sequence),
            ended_sequence: Some(sequence + 1),
            started_at_ms: 100 + sequence,
            ended_at_ms: 101 + sequence,
            outcome: OperationOutcome::Ok,
            http_status: Some(200),
            error: None,
            durability_cohort: None,
            fault_window_relation: None,
        }
    }

    fn versioned_history() -> Vec<OperationRecord> {
        vec![
            record(
                "versioning",
                OperationKind::PutBucketVersioning,
                None,
                None,
                None,
                1,
            ),
            record(
                "seed",
                OperationKind::Put,
                Some("hot"),
                Some(4),
                Some("v1"),
                3,
            ),
            record(
                "zero",
                OperationKind::Put,
                Some("zero/"),
                Some(0),
                Some("v2"),
                5,
            ),
            record(
                "put",
                OperationKind::Put,
                Some("new"),
                Some(4),
                Some("v3"),
                7,
            ),
            record(
                "overwrite",
                OperationKind::Put,
                Some("hot"),
                Some(4),
                Some("v4"),
                9,
            ),
            record(
                "delete",
                OperationKind::Delete,
                Some("hot"),
                None,
                Some("v5"),
                11,
            ),
            record(
                "multipart",
                OperationKind::CompleteMultipartUpload,
                Some("large"),
                Some(8),
                Some("v6"),
                13,
            ),
            record(
                "abort",
                OperationKind::AbortMultipartUpload,
                Some("aborted"),
                None,
                None,
                15,
            ),
        ]
    }

    fn terminal_status(state: &str, failed: bool, canceled: bool) -> DecommissionPoolStatus {
        DecommissionPoolStatus {
            id: 1,
            expression: "pool-1".to_string(),
            status: state.to_string(),
            pool_status: "active".to_string(),
            decommission: Some(crate::fault::admin_topology::DecommissionProgress {
                start_time: Some("2026-09-12T00:00:00Z".to_string()),
                failed,
                canceled,
                ..Default::default()
            }),
        }
    }

    #[test]
    fn bounded_workload_requires_every_versioned_mutation_family() {
        let history = versioned_history();
        let receipt = AdminDecommissionWorkloadReceipt {
            started_at_ms: 107,
            ended_at_ms: 117,
            first_event_sequence: 7,
            last_event_sequence: 16,
            history: history.clone(),
        };
        let records = workload_records(&receipt).expect("bounded workload records");
        validate_workload_families(&history, records).expect("complete versioned workload");

        for omitted in ["put", "overwrite", "delete", "multipart", "abort"] {
            let mut incomplete = history.clone();
            incomplete.retain(|record| record.id != omitted);
            for (index, record) in incomplete.iter_mut().enumerate() {
                record.started_sequence = Some(index as u64 * 2 + 1);
                record.ended_sequence = Some(index as u64 * 2 + 2);
            }
            let selected = incomplete
                .iter()
                .filter(|record| !matches!(record.id.as_str(), "versioning" | "seed" | "zero"))
                .collect();
            assert!(
                validate_workload_families(&incomplete, selected).is_err(),
                "missing {omitted} must fail closed"
            );
        }
    }

    #[test]
    fn workload_receipt_requires_exact_recorder_boundaries() {
        let history = versioned_history();
        let valid = AdminDecommissionWorkloadReceipt {
            started_at_ms: 107,
            ended_at_ms: 117,
            first_event_sequence: 7,
            last_event_sequence: 16,
            history,
        };
        assert_eq!(workload_records(&valid).expect("valid receipt").len(), 5);

        let mut crossing = valid;
        crossing.first_event_sequence = 8;
        assert!(workload_records(&crossing).is_err());
    }

    #[test]
    fn versioned_workload_rejects_missing_zero_byte_or_version_id() {
        let mut no_zero = versioned_history();
        no_zero[2].size_bytes = Some(1);
        let selected = no_zero.iter().skip(3).collect();
        assert!(validate_workload_families(&no_zero, selected).is_err());

        let mut missing_version = versioned_history();
        missing_version[4].version_id = None;
        let selected = missing_version.iter().skip(3).collect();
        assert!(validate_workload_families(&missing_version, selected).is_err());
    }

    #[test]
    fn quick_completion_accepts_real_interval_overlap() {
        assert!(intervals_overlap(100, 110, 105, 106));
        assert!(!intervals_overlap(107, 110, 100, 106));
    }

    #[test]
    fn clear_requires_failed_or_canceled_terminal_without_unresolved_entries() {
        assert!(validate_clearable_terminal(&terminal_status("failed", true, false)).is_ok());
        assert!(validate_clearable_terminal(&terminal_status("canceled", false, true)).is_ok());
        assert!(validate_clearable_terminal(&terminal_status("running", true, false)).is_err());

        let mut unresolved = terminal_status("failed", true, false);
        unresolved
            .decommission
            .as_mut()
            .expect("progress")
            .unresolved_entries
            .push(json!({"bucket": "bucket"}));
        assert!(validate_clearable_terminal(&unresolved).is_err());
    }

    #[test]
    fn limits_reject_unbounded_or_slower_polling() {
        assert!(
            AdminDecommissionLimits {
                poll_interval: Duration::ZERO,
                operation_timeout: Duration::from_secs(1),
                cancel_timeout: Duration::from_secs(1),
            }
            .validate()
            .is_err()
        );
        assert!(
            AdminDecommissionLimits {
                poll_interval: Duration::from_secs(2),
                operation_timeout: Duration::from_secs(1),
                cancel_timeout: Duration::from_secs(3),
            }
            .validate()
            .is_err()
        );
    }
}
