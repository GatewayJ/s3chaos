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

//! Scenario-owned sequencing and S3 overlap evidence for admin rebalance.
//!
//! Fixture staging remains owned by the shared admin workflow layer. This
//! module starts only after that layer has produced a run-owned, two-pool
//! topology proof and exposes one narrow snapshot hook for that integration.

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
use tokio::time::{Instant, sleep, timeout};

use crate::fault::{
    admin_topology::{
        ADMIN_OPERATION_ARTIFACT, ADMIN_OPERATION_PROGRESS_ARTIFACT, ADMIN_TOPOLOGY_PROOF_ARTIFACT,
        AdminAttemptIdentity, AdminAttemptWindow, AdminOperationEvidence,
        AdminOperationProgressSample, AdminPoolSnapshot, AdminRequestEvidence, AdminTopologyPort,
        AdminTopologyProof, RebalanceStart, RebalanceStatus, rebalance_progress_sample,
        validate_admin_operation_progress, validate_admin_pre_start_snapshot,
    },
    checker::{self, CheckerReport},
    history::{OperationKind, OperationOutcome, OperationRecord, validate_history_scope_and_order},
    scenarios::ADMIN_REBALANCE_SCENARIO,
};
use crate::framework::artifacts::ArtifactCollector;

pub const ADMIN_REBALANCE_OVERLAP_ARTIFACT: &str = "admin-rebalance-overlap.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdminRebalanceLimits {
    pub poll_interval: Duration,
    pub operation_timeout: Duration,
    pub stop_timeout: Duration,
}

impl AdminRebalanceLimits {
    pub fn validate(self) -> Result<()> {
        ensure!(
            !self.poll_interval.is_zero()
                && !self.operation_timeout.is_zero()
                && !self.stop_timeout.is_zero()
                && self.poll_interval <= self.operation_timeout
                && self.poll_interval <= self.stop_timeout,
            "admin rebalance polling and operation/stop deadlines must be positive and ordered"
        );
        Ok(())
    }
}

#[async_trait]
pub trait AdminRebalanceAttemptPort: AdminTopologyPort {
    /// Capture a Tenant GET, runtime binding, and pools/list receipt in that
    /// order. The shared workflow implementation owns the Kubernetes access.
    async fn capture_pool_snapshot(&self) -> Result<AdminPoolSnapshot>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminRebalanceWorkloadReceipt {
    pub started_at_ms: u64,
    pub ended_at_ms: u64,
    pub first_event_sequence: u64,
    pub last_event_sequence: u64,
    /// Complete recorder contents at workload completion. The overlap artifact
    /// stores only IDs; the offline validator authenticates them against the
    /// final history and checker audit.
    pub history: Vec<OperationRecord>,
}

#[async_trait]
pub trait AdminRebalanceWorkload: Send + Sync {
    /// Run exactly one finite, byte-budgeted mixed workload. Implementations
    /// must return an error for a partial harness execution.
    async fn run_bounded(&self) -> Result<AdminRebalanceWorkloadReceipt>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminRebalanceOverlapEvidence {
    #[serde(flatten)]
    pub attempt: AdminAttemptIdentity,
    pub operation_id: String,
    pub rebalance_started_at_ms: u64,
    pub rebalance_completed_at_ms: u64,
    pub workload_started_at_ms: u64,
    pub workload_ended_at_ms: u64,
    pub workload_first_event_sequence: u64,
    pub workload_last_event_sequence: u64,
    pub workload_operation_ids: Vec<String>,
    pub overlapping_operation_ids: Vec<String>,
    pub overlapping_status_request_ids: Vec<String>,
}

impl AdminRebalanceOverlapEvidence {
    pub fn from_history(
        operation: &AdminOperationEvidence,
        progress: &[AdminOperationProgressSample],
        workload: &AdminRebalanceWorkloadReceipt,
    ) -> Result<Self> {
        let (rebalance_started_at_ms, rebalance_completed_at_ms) = rebalance_window(operation)?;
        let workload_records = workload_records(workload)?;
        let overlapping_status_request_ids = overlapping_status_request_ids(
            operation,
            progress,
            workload.started_at_ms,
            workload.ended_at_ms,
        )?;
        let overlapping_operation_ids = workload_records
            .iter()
            .filter(|record| {
                record.started_at_ms <= rebalance_completed_at_ms
                    && record.ended_at_ms >= rebalance_started_at_ms
            })
            .map(|record| record.id.clone())
            .collect();
        let evidence = Self {
            attempt: operation.attempt.clone(),
            operation_id: operation.operation_id.clone(),
            rebalance_started_at_ms,
            rebalance_completed_at_ms,
            workload_started_at_ms: workload.started_at_ms,
            workload_ended_at_ms: workload.ended_at_ms,
            workload_first_event_sequence: workload.first_event_sequence,
            workload_last_event_sequence: workload.last_event_sequence,
            workload_operation_ids: workload_records
                .iter()
                .map(|record| record.id.clone())
                .collect(),
            overlapping_operation_ids,
            overlapping_status_request_ids,
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
            operation.scenario == ADMIN_REBALANCE_SCENARIO
                && self.attempt == operation.attempt
                && self.operation_id == operation.operation_id,
            "rebalance overlap identity does not match the admin operation"
        );
        ensure!(
            !history.is_empty()
                && history.iter().all(|record| {
                    record.scenario == ADMIN_REBALANCE_SCENARIO
                        && record.run_id.as_deref() == Some(operation.attempt.run_id.as_str())
                }),
            "rebalance overlap history does not belong to the current scenario attempt"
        );
        let (rebalance_started_at_ms, rebalance_completed_at_ms) = rebalance_window(operation)?;
        ensure!(
            self.rebalance_started_at_ms == rebalance_started_at_ms
                && self.rebalance_completed_at_ms == rebalance_completed_at_ms
                && self.workload_started_at_ms <= self.workload_ended_at_ms
                && self.workload_started_at_ms <= self.rebalance_completed_at_ms
                && self.workload_ended_at_ms >= self.rebalance_started_at_ms,
            "bounded S3 workload did not intersect the observed rebalance window"
        );
        let receipt = AdminRebalanceWorkloadReceipt {
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
            "rebalance overlap operation IDs do not match the authenticated workload history slice"
        );
        let overlapping_operation_ids = records
            .iter()
            .filter(|record| {
                record.started_at_ms <= self.rebalance_completed_at_ms
                    && record.ended_at_ms >= self.rebalance_started_at_ms
            })
            .map(|record| record.id.as_str())
            .collect::<Vec<_>>();
        ensure!(
            !overlapping_operation_ids.is_empty()
                && overlapping_operation_ids
                    .iter()
                    .copied()
                    .eq(self.overlapping_operation_ids.iter().map(String::as_str)),
            "no complete S3 operation interval overlaps the observed rebalance window"
        );
        let status_request_ids = overlapping_status_request_ids(
            operation,
            progress,
            self.workload_started_at_ms,
            self.workload_ended_at_ms,
        )?;
        ensure!(
            !status_request_ids.is_empty()
                && status_request_ids
                    .iter()
                    .eq(self.overlapping_status_request_ids.iter()),
            "rebalance has no status request receipt intersecting the workload"
        );
        validate_workload_families(history, records)?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct AdminRebalanceExecution {
    pub proof: AdminTopologyProof,
    pub operation: AdminOperationEvidence,
    pub progress: Vec<AdminOperationProgressSample>,
    pub overlap: AdminRebalanceOverlapEvidence,
    pub attempt_window: AdminAttemptWindow,
    workload_history: Vec<OperationRecord>,
}

impl AdminRebalanceExecution {
    pub fn write_artifacts(&self, collector: &ArtifactCollector) -> Result<()> {
        self.proof.require_satisfied()?;
        self.operation.require_success(self.attempt_window)?;
        validate_admin_operation_progress(&self.operation, &self.progress, self.attempt_window)?;
        self.overlap
            .validate(&self.operation, &self.progress, &self.workload_history)
            .context("validate rebalance overlap before artifact write")?;
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
            ADMIN_REBALANCE_OVERLAP_ARTIFACT,
            &serde_json::to_string_pretty(&self.overlap)?,
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct AdminRebalanceTranscript {
    pub operation_id: Option<String>,
    pub requests: Vec<AdminRequestEvidence>,
    pub progress: Vec<AdminOperationProgressSample>,
}

#[derive(Debug)]
pub struct AdminRebalanceExecutionError {
    primary: anyhow::Error,
    stop_error: Option<anyhow::Error>,
    transcript: AdminRebalanceTranscript,
}

impl AdminRebalanceExecutionError {
    pub fn primary_error(&self) -> &anyhow::Error {
        &self.primary
    }

    pub fn stop_error(&self) -> Option<&anyhow::Error> {
        self.stop_error.as_ref()
    }

    pub fn transcript(&self) -> &AdminRebalanceTranscript {
        &self.transcript
    }
}

impl fmt::Display for AdminRebalanceExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:#}", self.primary)?;
        if let Some(stop_error) = &self.stop_error {
            write!(formatter, "; rebalance stop also failed: {stop_error:#}")?;
        }
        Ok(())
    }
}

impl Error for AdminRebalanceExecutionError {}

struct TerminalRebalance {
    start: RebalanceStart,
    status: RebalanceStatus,
}

/// Execute the scenario-specific operation phase after the shared staged-pool
/// fixture has produced its topology proof.
pub async fn run_admin_rebalance<P, W>(
    port: &P,
    workload: &W,
    proof: AdminTopologyProof,
    attempt_started_at_ms: u64,
    limits: AdminRebalanceLimits,
) -> std::result::Result<AdminRebalanceExecution, AdminRebalanceExecutionError>
where
    P: AdminRebalanceAttemptPort,
    W: AdminRebalanceWorkload,
{
    let transcript = Arc::new(Mutex::new(AdminRebalanceTranscript::default()));
    let result = run_admin_rebalance_inner(
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
            let stop_error = if let Some(operation_id) = operation_id {
                stop_owned_rebalance(port, &proof, &operation_id, limits, &transcript)
                    .await
                    .err()
            } else {
                None
            };
            Err(AdminRebalanceExecutionError {
                primary,
                stop_error,
                transcript: transcript_state(&transcript),
            })
        }
    }
}

async fn run_admin_rebalance_inner<P, W>(
    port: &P,
    workload: &W,
    proof: AdminTopologyProof,
    attempt_started_at_ms: u64,
    limits: AdminRebalanceLimits,
    transcript: Arc<Mutex<AdminRebalanceTranscript>>,
) -> Result<AdminRebalanceExecution>
where
    P: AdminRebalanceAttemptPort,
    W: AdminRebalanceWorkload,
{
    limits.validate()?;
    proof.require_satisfied()?;
    ensure!(
        proof.scenario == ADMIN_REBALANCE_SCENARIO
            && proof.tenant_pools.len() == 2
            && proof.runtime_pools.len() == 2,
        "admin-rebalance requires one run-owned topology proof with exactly two pools"
    );
    ensure!(
        attempt_started_at_ms > 0 && attempt_started_at_ms <= now_ms(),
        "admin-rebalance attempt start time is invalid"
    );

    let pools_before = port
        .capture_pool_snapshot()
        .await
        .context("capture fresh pre-start rebalance pool snapshot")?;
    validate_admin_pre_start_snapshot(&proof, &pools_before, now_ms())
        .context("revalidate rebalance topology immediately before start")?;
    let start_call = port
        .start_rebalance()
        .await
        .context("start RustFS rebalance")?;
    ensure!(
        !start_call.value.id.trim().is_empty(),
        "RustFS rebalance start response has no operation ID"
    );
    {
        let mut state = lock_transcript(&transcript);
        state.operation_id = Some(start_call.value.id.clone());
        state.requests.push(start_call.request.clone());
    }

    let poll = poll_rebalance(
        port,
        &proof,
        start_call.value.clone(),
        limits,
        Arc::clone(&transcript),
    );
    let workload_run = workload.run_bounded();
    tokio::pin!(poll);
    tokio::pin!(workload_run);

    let (workload_receipt, terminal) = tokio::select! {
        workload_result = &mut workload_run => {
            let receipt = workload_result.context("bounded admin-rebalance workload failed")?;
            let terminal = poll.await?;
            (receipt, terminal)
        }
        poll_result = &mut poll => {
            let terminal = poll_result?;
            let receipt = workload_run.await.context("bounded admin-rebalance workload failed")?;
            (receipt, terminal)
        }
    };

    let pools_after = port
        .capture_pool_snapshot()
        .await
        .context("capture post-terminal rebalance pool snapshot")?;
    let state = transcript_state(&transcript);
    let operation = AdminOperationEvidence::from_rebalance(
        &proof,
        pools_before,
        &terminal.start,
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
    let overlap = AdminRebalanceOverlapEvidence::from_history(
        &operation,
        &state.progress,
        &workload_receipt,
    )?;

    Ok(AdminRebalanceExecution {
        proof: proof.clone(),
        operation,
        progress: state.progress,
        overlap,
        attempt_window,
        workload_history: workload_receipt.history,
    })
}

async fn poll_rebalance<P: AdminTopologyPort>(
    port: &P,
    proof: &AdminTopologyProof,
    start: RebalanceStart,
    limits: AdminRebalanceLimits,
    transcript: Arc<Mutex<AdminRebalanceTranscript>>,
) -> Result<TerminalRebalance> {
    let deadline = Instant::now() + limits.operation_timeout;
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .context("timed out waiting for RustFS rebalance completion")?;
        let call = timeout(remaining, port.rebalance_status())
            .await
            .context("timed out reading RustFS rebalance status")??;
        {
            lock_transcript(&transcript)
                .requests
                .push(call.request.clone());
        }
        let sample = rebalance_progress_sample(proof, &start.id, &call)?;
        let terminal = sample.completed || sample.failed || sample.canceled_or_stopped;
        lock_transcript(&transcript).progress.push(sample);
        if terminal {
            return Ok(TerminalRebalance {
                start,
                status: call.value,
            });
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .context("timed out waiting for RustFS rebalance completion")?;
        sleep(limits.poll_interval.min(remaining)).await;
    }
}

async fn stop_owned_rebalance<P: AdminTopologyPort>(
    port: &P,
    proof: &AdminTopologyProof,
    operation_id: &str,
    limits: AdminRebalanceLimits,
    transcript: &Arc<Mutex<AdminRebalanceTranscript>>,
) -> Result<()> {
    let deadline = Instant::now() + limits.stop_timeout;
    let status = timeout(limits.stop_timeout, port.rebalance_status())
        .await
        .context("timed out proving rebalance ownership before stop")??;
    lock_transcript(transcript)
        .requests
        .push(status.request.clone());
    let sample = rebalance_progress_sample(proof, operation_id, &status)
        .context("refusing to stop a rebalance not owned by this attempt")?;
    let terminal = sample.completed || sample.failed || sample.canceled_or_stopped;
    lock_transcript(transcript).progress.push(sample);
    if terminal {
        return Ok(());
    }

    let remaining = deadline
        .checked_duration_since(Instant::now())
        .context("rebalance stop deadline elapsed before stop request")?;
    let stop = timeout(remaining, port.stop_rebalance())
        .await
        .context("timed out stopping owned RustFS rebalance")??;
    lock_transcript(transcript)
        .requests
        .push(stop.request.clone());

    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .context("timed out waiting for stopped RustFS rebalance")?;
        let status = timeout(remaining, port.rebalance_status())
            .await
            .context("timed out reading RustFS rebalance status after stop")??;
        lock_transcript(transcript)
            .requests
            .push(status.request.clone());
        let sample = rebalance_progress_sample(proof, operation_id, &status)?;
        let terminal = sample.completed || sample.failed || sample.canceled_or_stopped;
        lock_transcript(transcript).progress.push(sample);
        if terminal {
            return Ok(());
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .context("timed out waiting for stopped RustFS rebalance")?;
        sleep(limits.poll_interval.min(remaining)).await;
    }
}

pub fn validate_admin_rebalance_evidence(
    operation: &AdminOperationEvidence,
    progress: &[AdminOperationProgressSample],
    overlap: &AdminRebalanceOverlapEvidence,
    history: &[OperationRecord],
    checker: &CheckerReport,
) -> Result<()> {
    overlap.validate(operation, progress, history)?;
    ensure!(
        checker.scenario == ADMIN_REBALANCE_SCENARIO && checker.run_id == operation.attempt.run_id,
        "final checker identity does not match the admin-rebalance attempt"
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
        .context("admin-rebalance checker audit does not match history.jsonl")?;
    let audit = checker
        .audit
        .as_ref()
        .context("admin-rebalance checker lacks a history-bound audit")?;
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

fn workload_records(receipt: &AdminRebalanceWorkloadReceipt) -> Result<Vec<&OperationRecord>> {
    ensure!(
        receipt.started_at_ms > 0
            && receipt.started_at_ms <= receipt.ended_at_ms
            && receipt.first_event_sequence > 0
            && receipt.first_event_sequence <= receipt.last_event_sequence,
        "bounded workload receipt has an invalid time or recorder sequence window"
    );
    let bucket = receipt
        .history
        .first()
        .map(|record| record.bucket.as_str())
        .context("bounded workload receipt has empty history")?;
    let scenario = receipt
        .history
        .first()
        .map(|record| record.scenario.as_str())
        .expect("non-empty checked above");
    let run_id = receipt
        .history
        .first()
        .and_then(|record| record.run_id.as_deref())
        .context("bounded workload receipt history lacks a run ID")?;
    validate_history_scope_and_order(&receipt.history, scenario, run_id, bucket)?;
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
    ensure!(!records.is_empty(), "bounded rebalance workload is empty");
    let observed_first_sequence = records
        .iter()
        .filter_map(|record| record.started_sequence)
        .min();
    let observed_last_sequence = records
        .iter()
        .filter_map(|record| record.ended_sequence)
        .max();
    ensure!(
        observed_first_sequence == Some(receipt.first_event_sequence)
            && observed_last_sequence == Some(receipt.last_event_sequence),
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
    let put_records = workload
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
        put_records
            .iter()
            .any(|record| !earlier_data_version(record)),
        "bounded rebalance workload has no successful ordinary PUT"
    );
    ensure!(
        put_records
            .iter()
            .any(|record| earlier_data_version(record)),
        "bounded rebalance workload has no successful overwrite"
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
        "versioned rebalance workload has no committed zero-byte object"
    );
    ensure!(
        workload.iter().any(|record| {
            record.kind == OperationKind::Delete && successful_versioned_mutation(record)
        }),
        "bounded rebalance workload has no committed delete marker"
    );
    ensure!(
        workload.iter().any(|record| {
            record.kind == OperationKind::CompleteMultipartUpload
                && successful_versioned_mutation(record)
        }) && workload.iter().any(|record| {
            record.kind == OperationKind::AbortMultipartUpload
                && record.outcome == OperationOutcome::Ok
        }),
        "bounded rebalance workload lacks successful multipart completion or abort activity"
    );
    ensure!(
        history.iter().any(|record| {
            record.kind == OperationKind::PutBucketVersioning
                && record.outcome == OperationOutcome::Ok
        }),
        "admin-rebalance history does not prove bucket versioning was enabled"
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
        "a successful admin-rebalance mutation lacks an immutable version ID"
    );
    Ok(())
}

fn rebalance_window(operation: &AdminOperationEvidence) -> Result<(u64, u64)> {
    ensure!(
        operation.scenario == ADMIN_REBALANCE_SCENARIO,
        "operation is not admin-rebalance"
    );
    let start = operation
        .requests
        .iter()
        .find(|request| {
            request.method == "POST" && request.path == "/rustfs/admin/v3/rebalance/start"
        })
        .context("admin-rebalance operation lacks its start receipt")?;
    let terminal = operation
        .requests
        .iter()
        .rev()
        .find(|request| {
            request.method == "GET" && request.path == "/rustfs/admin/v3/rebalance/status"
        })
        .context("admin-rebalance operation lacks its terminal status receipt")?;
    ensure!(
        start.observed_at_ms <= terminal.observed_at_ms,
        "admin-rebalance operation receipt times are inverted"
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
    let request_ids = operation
        .requests
        .iter()
        .filter(|request| {
            request.method == "GET"
                && request.path == "/rustfs/admin/v3/rebalance/status"
                && request.started_at_ms <= workload_ended_at_ms
                && request.observed_at_ms >= workload_started_at_ms
        })
        .map(|request| {
            request
                .request_id
                .clone()
                .filter(|request_id| progress_ids.contains(request_id.as_str()))
                .context("overlapping rebalance status request lacks its progress sample")
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(request_ids)
}

fn lock_transcript(
    transcript: &Arc<Mutex<AdminRebalanceTranscript>>,
) -> std::sync::MutexGuard<'_, AdminRebalanceTranscript> {
    transcript
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn transcript_state(transcript: &Arc<Mutex<AdminRebalanceTranscript>>) -> AdminRebalanceTranscript {
    lock_transcript(transcript).clone()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
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
            scenario: ADMIN_REBALANCE_SCENARIO.to_string(),
            run_id: Some("run-rebalance".to_string()),
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

    #[test]
    fn bounded_workload_requires_every_versioned_mutation_family() {
        let history = versioned_history();
        let receipt = AdminRebalanceWorkloadReceipt {
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
    fn bounded_workload_rejects_missing_zero_byte_or_version_id() {
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
    fn workload_receipt_requires_exact_recorder_boundaries() {
        let history = versioned_history();
        let valid = AdminRebalanceWorkloadReceipt {
            started_at_ms: 107,
            ended_at_ms: 117,
            first_event_sequence: 7,
            last_event_sequence: 16,
            history: history.clone(),
        };
        assert_eq!(workload_records(&valid).expect("valid receipt").len(), 5);

        let mut crossing = valid;
        crossing.first_event_sequence = 8;
        assert!(workload_records(&crossing).is_err());
    }

    #[test]
    fn limits_reject_unbounded_or_slower_polling() {
        assert!(
            AdminRebalanceLimits {
                poll_interval: Duration::ZERO,
                operation_timeout: Duration::from_secs(1),
                stop_timeout: Duration::from_secs(1),
            }
            .validate()
            .is_err()
        );
        assert!(
            AdminRebalanceLimits {
                poll_interval: Duration::from_secs(2),
                operation_timeout: Duration::from_secs(1),
                stop_timeout: Duration::from_secs(3),
            }
            .validate()
            .is_err()
        );
    }
}
