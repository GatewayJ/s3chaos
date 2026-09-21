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

#[cfg(test)]
use std::sync::Arc;
use std::{
    collections::BTreeMap,
    panic::{AssertUnwindSafe, catch_unwind},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, ensure};
use futures::future::join_all;
use serde::{Deserialize, Serialize};

use crate::{
    fault::{
        backends::chaos_mesh::iochaos_record_pod_id,
        preflight::TargetProof,
        quorum::{QuorumVolumeBinding, QuorumVolumeTargetProof},
        reporting::FaultStatusSnapshot,
        workload::sha256_hex,
    },
    framework::{
        artifacts::ArtifactCollector, command::CommandOutput, config::ClusterTestConfig,
        kubectl::Kubectl,
    },
};

use super::now_ms;

const ACTIVATION_SCHEMA_VERSION: u8 = 1;
const RUSTFS_CONTAINER: &str = "rustfs";
const CANARY_SCRIPT: &str = r#"export LC_ALL=C
target=$1
(umask 077; printf 's3chaos-quorum-canary\n' > "$target")
status=$?
if [ "$status" -eq 0 ]; then
    rm -f -- "$target"
fi
exit "$status""#;
const CLEANUP_SCRIPT: &str = r#"target=$1
rm -f -- "$target""#;
const CLEANUP_FAILURE_ARTIFACT: &str = "quorum-canary-cleanup-error.txt";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum QuorumCanaryOutcome {
    NotRun,
    IoErrorObserved,
    WriteSucceeded,
    UnexpectedFailure,
    TransportFailure,
    TimedOut,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum QuorumCanaryCleanupOutcome {
    Removed,
    Failed,
    TimedOut,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum QuorumActivationDisposition {
    RunTypedOracle,
    SkipTypedOracleAndRecover,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct QuorumCanaryCleanupEvidence {
    pub(crate) started_at_ms: u64,
    pub(crate) completed_at_ms: u64,
    pub(crate) outcome: QuorumCanaryCleanupOutcome,
    pub(crate) exit_code: Option<i32>,
    pub(crate) stderr: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct QuorumFaultActivationTargetEvidence {
    pub(crate) pod_name: String,
    pub(crate) pod_uid: String,
    pub(crate) container_id: String,
    pub(crate) persistent_volume_claim: String,
    pub(crate) persistent_volume: String,
    pub(crate) mount_path: String,
    pub(crate) drive_uuid: String,
    pub(crate) controller_record_id: String,
    pub(crate) canary_path: String,
    pub(crate) started_at_ms: u64,
    pub(crate) completed_at_ms: u64,
    pub(crate) outcome: QuorumCanaryOutcome,
    pub(crate) exit_code: Option<i32>,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) cleanup: Option<QuorumCanaryCleanupEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct QuorumFaultActivationEvidence {
    pub(crate) schema_version: u8,
    pub(crate) scenario: String,
    pub(crate) run_id: String,
    pub(crate) backend: String,
    pub(crate) iochaos_resource_name: String,
    pub(crate) iochaos_snapshot_sha256: String,
    pub(crate) volume_path: String,
    pub(crate) expected_targets: u32,
    pub(crate) controller_records: usize,
    pub(crate) started_at_ms: u64,
    pub(crate) completed_at_ms: u64,
    pub(crate) qualified: bool,
    pub(crate) failure_reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) cleanup_failure_reason: Option<String>,
    pub(crate) targets: Vec<QuorumFaultActivationTargetEvidence>,
}

impl QuorumFaultActivationEvidence {
    pub(super) fn disposition(&self) -> QuorumActivationDisposition {
        if self.qualified {
            QuorumActivationDisposition::RunTypedOracle
        } else {
            QuorumActivationDisposition::SkipTypedOracleAndRecover
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == ACTIVATION_SCHEMA_VERSION,
            "quorum activation evidence uses an unsupported schema version"
        );
        ensure!(
            !self.scenario.trim().is_empty()
                && !self.run_id.trim().is_empty()
                && self.backend == "chaos-mesh-iochaos"
                && self.volume_path.starts_with('/')
                && self.expected_targets > 0
                && self.started_at_ms > 0
                && self.started_at_ms <= self.completed_at_ms,
            "quorum activation evidence identity or timing is invalid"
        );
        if self.qualified {
            ensure!(
                !self.iochaos_resource_name.trim().is_empty()
                    && self.iochaos_snapshot_sha256.len() == 64,
                "qualified quorum activation evidence lacks its IOChaos identity"
            );
        }
        ensure!(
            self.targets.iter().all(|target| {
                !target.pod_name.trim().is_empty()
                    && !target.pod_uid.trim().is_empty()
                    && !target.container_id.trim().is_empty()
                    && !target.persistent_volume_claim.trim().is_empty()
                    && !target.persistent_volume.trim().is_empty()
                    && target.mount_path == self.volume_path
                    && !target.drive_uuid.trim().is_empty()
                    && !target.controller_record_id.trim().is_empty()
                    && target
                        .canary_path
                        .starts_with(&format!("{}/", self.volume_path.trim_end_matches('/')))
                    && target.started_at_ms >= self.started_at_ms
                    && target.started_at_ms <= target.completed_at_ms
                    && target.completed_at_ms <= self.completed_at_ms
            }),
            "quorum activation target identity, path, or timing is invalid"
        );
        for values in [
            self.targets
                .iter()
                .map(|target| target.pod_name.as_str())
                .collect::<Vec<_>>(),
            self.targets
                .iter()
                .map(|target| target.pod_uid.as_str())
                .collect(),
            self.targets
                .iter()
                .map(|target| target.container_id.as_str())
                .collect(),
            self.targets
                .iter()
                .map(|target| target.persistent_volume_claim.as_str())
                .collect(),
            self.targets
                .iter()
                .map(|target| target.persistent_volume.as_str())
                .collect(),
            self.targets
                .iter()
                .map(|target| target.drive_uuid.as_str())
                .collect(),
            self.targets
                .iter()
                .map(|target| target.controller_record_id.as_str())
                .collect(),
            self.targets
                .iter()
                .map(|target| target.canary_path.as_str())
                .collect(),
        ] {
            ensure!(
                values
                    .iter()
                    .copied()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    == values.len(),
                "quorum activation evidence contains duplicate target identities"
            );
        }
        let independently_proven = self.targets.len() == usize::try_from(self.expected_targets)?
            && self.controller_records == usize::try_from(self.expected_targets)?
            && self
                .targets
                .iter()
                .all(|target| target.outcome == QuorumCanaryOutcome::IoErrorObserved);
        ensure!(
            self.qualified == (self.failure_reasons.is_empty() && independently_proven),
            "quorum activation qualification is inconsistent with its controller and canary evidence"
        );
        ensure!(
            self.cleanup_failure_reason
                .as_deref()
                .is_none_or(|reason| !reason.trim().is_empty()),
            "quorum activation cleanup failure reason is empty"
        );
        for target in &self.targets {
            match target.outcome {
                QuorumCanaryOutcome::NotRun => ensure!(
                    target.exit_code.is_none(),
                    "quorum activation canary pending result contains a remote exit code"
                ),
                QuorumCanaryOutcome::IoErrorObserved => ensure!(
                    target.exit_code.is_some_and(|code| code != 0) && io_error_text(&target.stderr),
                    "quorum activation canary claims EIO without an EIO process result"
                ),
                QuorumCanaryOutcome::WriteSucceeded => ensure!(
                    target.exit_code == Some(0),
                    "quorum activation canary claims success with a failed process result"
                ),
                QuorumCanaryOutcome::UnexpectedFailure => ensure!(
                    target.exit_code.is_some_and(|code| code != 0)
                        && !io_error_text(&target.stderr),
                    "quorum activation canary unexpected failure result is inconsistent"
                ),
                QuorumCanaryOutcome::TransportFailure | QuorumCanaryOutcome::TimedOut => ensure!(
                    target.exit_code.is_none(),
                    "quorum activation canary transport result contains a remote exit code"
                ),
            }
        }
        Ok(())
    }

    pub(super) fn failure_reason(&self) -> Option<String> {
        (!self.qualified).then(|| {
            if self.failure_reasons.is_empty() {
                "fault activation was not independently proven".to_string()
            } else {
                self.failure_reasons.join("; ")
            }
        })
    }

    pub(super) fn selected_record_ids(&self) -> std::collections::BTreeSet<String> {
        self.targets
            .iter()
            .map(|target| target.controller_record_id.clone())
            .collect()
    }

    pub(super) fn selected_containers(&self) -> BTreeMap<String, String> {
        self.targets
            .iter()
            .map(|target| (target.pod_name.clone(), target.container_id.clone()))
            .collect()
    }
}

#[cfg(test)]
type TestCleanupRunner =
    Arc<dyn Fn(&mut QuorumFaultActivationEvidence, Duration) -> Result<()> + Send + Sync + 'static>;

#[derive(Clone)]
enum CleanupBackend {
    Kubernetes(Box<ClusterTestConfig>),
    #[cfg(test)]
    Test(TestCleanupRunner),
}

impl CleanupBackend {
    fn run(&self, evidence: &mut QuorumFaultActivationEvidence, timeout: Duration) -> Result<()> {
        match self {
            Self::Kubernetes(cluster) => {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .context("create quorum canary cleanup runtime")?;
                runtime.block_on(cleanup_quorum_canaries(cluster, evidence, timeout))
            }
            #[cfg(test)]
            Self::Test(runner) => runner(evidence, timeout),
        }
    }
}

#[derive(Clone)]
struct QuorumCanaryCleanupTask {
    backend: CleanupBackend,
    collector: ArtifactCollector,
    case_name: String,
    timeout: Duration,
}

struct QuorumCanaryCleanupCompletion {
    evidence: QuorumFaultActivationEvidence,
    failure: Option<String>,
}

impl QuorumCanaryCleanupTask {
    fn persist_completion(
        self,
        mut evidence: QuorumFaultActivationEvidence,
        cleanup_failure: Option<String>,
    ) -> QuorumCanaryCleanupCompletion {
        evidence.cleanup_failure_reason = cleanup_failure.clone();
        let persistence = serde_json::to_string_pretty(&evidence)
            .context("encode quorum activation evidence after canary cleanup")
            .and_then(|body| {
                self.collector
                    .write_text(
                        &self.case_name,
                        crate::fault::quorum::QUORUM_FAULT_ACTIVATION_ARTIFACT,
                        &body,
                    )
                    .map(|_| ())
            });
        let persistence_failure = persistence.err().map(|error| error.to_string());
        let failure = match (cleanup_failure, persistence_failure) {
            (Some(cleanup), Some(persistence)) => Some(format!(
                "{cleanup}; persist quorum activation cleanup evidence: {persistence}"
            )),
            (Some(cleanup), None) => Some(cleanup),
            (None, Some(persistence)) => Some(format!(
                "persist quorum activation cleanup evidence: {persistence}"
            )),
            (None, None) => None,
        };
        if let Some(failure) = failure.as_deref() {
            let _ = self
                .collector
                .write_text(&self.case_name, CLEANUP_FAILURE_ARTIFACT, failure);
        }
        QuorumCanaryCleanupCompletion { evidence, failure }
    }

    fn execute_on_worker(
        self,
        mut evidence: QuorumFaultActivationEvidence,
    ) -> QuorumCanaryCleanupCompletion {
        let cleanup = catch_unwind(AssertUnwindSafe(|| {
            self.backend.run(&mut evidence, self.timeout)
        }))
        .map_err(|_| anyhow!("quorum activation canary cleanup panicked"))
        .and_then(|result| result);
        let cleanup_failure = cleanup.err().map(|error| error.to_string());
        self.persist_completion(evidence, cleanup_failure)
    }

    fn execute(self, evidence: QuorumFaultActivationEvidence) -> QuorumCanaryCleanupCompletion {
        let fallback_task = self.clone();
        let fallback_evidence = evidence.clone();
        // The worker owns its runtime so cancellation and runtime shutdown do
        // not interrupt the final Kubernetes cleanup attempt.
        match std::thread::Builder::new()
            .name("s3chaos-quorum-canary-cleanup".to_string())
            .spawn(move || self.execute_on_worker(evidence))
        {
            Ok(worker) => worker.join().unwrap_or_else(|_| {
                fallback_task.persist_completion(
                    fallback_evidence,
                    Some("quorum activation canary cleanup worker panicked".to_string()),
                )
            }),
            Err(error) => fallback_task.persist_completion(
                fallback_evidence,
                Some(format!(
                    "start quorum activation canary cleanup worker: {error}"
                )),
            ),
        }
    }
}

pub(super) struct QuorumCanaryCleanupGuard {
    task: Option<QuorumCanaryCleanupTask>,
    evidence: Option<QuorumFaultActivationEvidence>,
    cleanup_finished: bool,
}

impl QuorumCanaryCleanupGuard {
    pub(super) fn new(
        cluster: &ClusterTestConfig,
        collector: &ArtifactCollector,
        case_name: &str,
        timeout: Duration,
        evidence: QuorumFaultActivationEvidence,
    ) -> Self {
        Self {
            task: Some(QuorumCanaryCleanupTask {
                backend: CleanupBackend::Kubernetes(Box::new(cluster.clone())),
                collector: collector.clone(),
                case_name: case_name.to_string(),
                timeout,
            }),
            evidence: Some(evidence),
            cleanup_finished: false,
        }
    }

    pub(super) fn evidence(&self) -> &QuorumFaultActivationEvidence {
        self.evidence
            .as_ref()
            .expect("quorum activation evidence is available outside cleanup")
    }

    fn replace_evidence(&mut self, evidence: QuorumFaultActivationEvidence) {
        assert!(
            !self.cleanup_finished && self.evidence.is_some(),
            "quorum activation evidence can only change before cleanup"
        );
        self.evidence = Some(evidence);
    }

    pub(super) async fn cleanup(&mut self) -> Result<()> {
        if self.cleanup_finished {
            return Ok(());
        }
        let task = self
            .task
            .take()
            .context("quorum canary cleanup task is missing")?;
        let fallback_task = task.clone();
        let evidence = self
            .evidence
            .take()
            .context("quorum activation evidence is missing")?;
        let fallback_evidence = evidence.clone();
        let completion = match tokio::task::spawn_blocking(move || task.execute(evidence)).await {
            Ok(completion) => completion,
            Err(error) => {
                self.task = Some(fallback_task);
                self.evidence = Some(fallback_evidence);
                return Err(error).context("join quorum canary cleanup task");
            }
        };
        self.evidence = Some(completion.evidence);
        self.cleanup_finished = true;
        match completion.failure {
            Some(failure) => Err(anyhow!(failure)),
            None => Ok(()),
        }
    }

    #[cfg(test)]
    fn for_test(
        collector: &ArtifactCollector,
        case_name: &str,
        evidence: QuorumFaultActivationEvidence,
        runner: TestCleanupRunner,
    ) -> Self {
        Self {
            task: Some(QuorumCanaryCleanupTask {
                backend: CleanupBackend::Test(runner),
                collector: collector.clone(),
                case_name: case_name.to_string(),
                timeout: Duration::from_secs(1),
            }),
            evidence: Some(evidence),
            cleanup_finished: false,
        }
    }
}

impl Drop for QuorumCanaryCleanupGuard {
    fn drop(&mut self) {
        if self.cleanup_finished {
            return;
        }
        let (Some(task), Some(evidence)) = (self.task.take(), self.evidence.take()) else {
            return;
        };
        let _ = task.execute(evidence);
    }
}

fn volume_quorum_proof(target_proof: &TargetProof) -> Result<&QuorumVolumeTargetProof> {
    target_proof
        .faults
        .iter()
        .find_map(|fault| fault.erasure_set.as_ref())
        .and_then(|proof| proof.volume_quorum.as_ref())
        .context("runtime quorum target proof has no volume bindings")
}

fn injected_controller_records(snapshot: &serde_json::Value) -> Result<Vec<String>> {
    let records = snapshot
        .pointer("/status/experiment/containerRecords")
        .and_then(serde_json::Value::as_array)
        .context("IOChaos activation snapshot has no controller records")?;
    Ok(records
        .iter()
        .filter(|record| {
            record
                .get("selectorKey")
                .and_then(serde_json::Value::as_str)
                == Some(".")
                && record.get("phase").and_then(serde_json::Value::as_str) == Some("Injected")
                && record
                    .get("injectedCount")
                    .and_then(serde_json::Value::as_u64)
                    .is_some_and(|count| count > 0)
        })
        .filter_map(|record| record.get("id").and_then(serde_json::Value::as_str))
        .map(str::to_string)
        .collect())
}

fn io_error_text(stderr: &str) -> bool {
    let stderr = stderr.to_ascii_lowercase();
    stderr.contains("input/output error")
        || stderr.contains("i/o error")
        || stderr.contains("os error 5")
        || stderr.contains("errno 5")
}

fn io_error_observed(output: &CommandOutput) -> bool {
    if output.code == Some(0) {
        return false;
    }
    io_error_text(&output.stderr)
}

fn canary_path(binding: &QuorumVolumeBinding, run_id: &str) -> String {
    let suffix = run_id
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .take(20)
        .collect::<String>()
        .to_ascii_lowercase();
    format!(
        "{}/.s3chaos-quorum-{}-{}",
        binding.mount_path.trim_end_matches('/'),
        suffix,
        binding.pod_name
    )
}

async fn run_canary(
    cluster: &ClusterTestConfig,
    run_id: &str,
    binding: QuorumVolumeBinding,
    controller_record_id: String,
    timeout: Duration,
) -> QuorumFaultActivationTargetEvidence {
    let path = canary_path(&binding, run_id);
    let started_at_ms = now_ms();
    let result = Kubectl::new(cluster)
        .namespaced(&cluster.test_namespace)
        .command([
            "exec",
            &binding.pod_name,
            "-c",
            RUSTFS_CONTAINER,
            "--",
            "/bin/sh",
            "-c",
            CANARY_SCRIPT,
            "s3chaos-quorum-canary",
            &path,
        ])
        .run_bounded(timeout)
        .await;
    let completed_at_ms = now_ms();
    let (outcome, exit_code, stdout, stderr) = match result {
        Ok(output) if io_error_observed(&output) => (
            QuorumCanaryOutcome::IoErrorObserved,
            output.code,
            output.stdout,
            output.stderr,
        ),
        Ok(output) if output.code == Some(0) => (
            QuorumCanaryOutcome::WriteSucceeded,
            output.code,
            output.stdout,
            output.stderr,
        ),
        Ok(output) if output.code.is_none() => (
            QuorumCanaryOutcome::TransportFailure,
            None,
            output.stdout,
            output.stderr,
        ),
        Ok(output) => (
            QuorumCanaryOutcome::UnexpectedFailure,
            output.code,
            output.stdout,
            output.stderr,
        ),
        Err(error) if error.to_string().contains("timed out") => (
            QuorumCanaryOutcome::TimedOut,
            None,
            String::new(),
            error.to_string(),
        ),
        Err(error) => (
            QuorumCanaryOutcome::TransportFailure,
            None,
            String::new(),
            error.to_string(),
        ),
    };
    QuorumFaultActivationTargetEvidence {
        pod_name: binding.pod_name,
        pod_uid: binding.pod_uid,
        container_id: binding.container_id,
        persistent_volume_claim: binding.persistent_volume_claim,
        persistent_volume: binding.persistent_volume,
        mount_path: binding.mount_path,
        drive_uuid: binding.drive_uuid,
        controller_record_id,
        canary_path: path,
        started_at_ms,
        completed_at_ms,
        outcome,
        exit_code,
        stdout,
        stderr,
        cleanup: None,
    }
}

pub(super) struct QuorumFaultActivationPlan {
    attempts: Vec<(QuorumVolumeBinding, String)>,
    failure_reasons: Vec<String>,
}

pub(super) fn prepare_quorum_fault_activation(
    scenario: &str,
    run_id: &str,
    target_proof: &TargetProof,
    active_snapshots: &[FaultStatusSnapshot],
    controller_validation_error: Option<String>,
) -> (QuorumFaultActivationEvidence, QuorumFaultActivationPlan) {
    let started_at_ms = now_ms();
    let mut failure_reasons = controller_validation_error.into_iter().collect::<Vec<_>>();
    let snapshot = active_snapshots.first();
    let resource = snapshot.and_then(|snapshot| snapshot.chaos_status.as_ref());
    let iochaos_resource_name = snapshot
        .and_then(|snapshot| snapshot.resource_name.clone())
        .unwrap_or_default();
    let iochaos_snapshot_sha256 = resource
        .and_then(|resource| serde_json::to_vec(resource).ok())
        .map(|encoded| sha256_hex(&encoded))
        .unwrap_or_default();
    let proof = volume_quorum_proof(target_proof);
    let (expected_targets, volume_path, bindings) = match proof {
        Ok(proof) => (
            proof.target_count,
            proof
                .candidates
                .first()
                .map(|binding| binding.mount_path.clone())
                .unwrap_or_default(),
            proof
                .candidates
                .iter()
                .cloned()
                .map(|binding| (binding.pod_name.clone(), binding))
                .collect::<BTreeMap<_, _>>(),
        ),
        Err(error) => {
            failure_reasons.push(error.to_string());
            (0, String::new(), BTreeMap::new())
        }
    };
    let records = match resource.and_then(|resource| injected_controller_records(resource).ok()) {
        Some(records) => records,
        None => {
            failure_reasons.push(
                "IOChaos activation snapshot has no usable injected controller records".to_string(),
            );
            Vec::new()
        }
    };
    let controller_records = records.len();
    let unique_records = records
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    if unique_records.len() != records.len() {
        failure_reasons
            .push("IOChaos activation snapshot contains duplicate controller records".to_string());
    }
    let mut attempts = Vec::new();
    for record_id in unique_records {
        let binding = iochaos_record_pod_id(&record_id)
            .ok()
            .and_then(|pod_id| pod_id.rsplit_once('/').map(|(_, pod)| pod.to_string()))
            .and_then(|pod| bindings.get(&pod).cloned());
        match binding {
            Some(binding) => attempts.push((binding, record_id)),
            None => failure_reasons.push(format!(
                "IOChaos controller record {record_id:?} does not resolve to a proven quorum volume"
            )),
        }
    }
    if attempts.len() != usize::try_from(expected_targets).unwrap_or(usize::MAX) {
        failure_reasons.push(format!(
            "IOChaos independently exercised {} targets, expected {expected_targets}",
            attempts.len()
        ));
    }
    failure_reasons.sort();
    failure_reasons.dedup();
    let mut targets = attempts
        .iter()
        .map(
            |(binding, controller_record_id)| QuorumFaultActivationTargetEvidence {
                pod_name: binding.pod_name.clone(),
                pod_uid: binding.pod_uid.clone(),
                container_id: binding.container_id.clone(),
                persistent_volume_claim: binding.persistent_volume_claim.clone(),
                persistent_volume: binding.persistent_volume.clone(),
                mount_path: binding.mount_path.clone(),
                drive_uuid: binding.drive_uuid.clone(),
                controller_record_id: controller_record_id.clone(),
                canary_path: canary_path(binding, run_id),
                started_at_ms,
                completed_at_ms: started_at_ms,
                outcome: QuorumCanaryOutcome::NotRun,
                exit_code: None,
                stdout: String::new(),
                stderr: "canary execution did not complete".to_string(),
                cleanup: None,
            },
        )
        .collect::<Vec<_>>();
    targets.sort_by(|left, right| left.pod_name.cmp(&right.pod_name));
    let mut pending_failure_reasons = failure_reasons.clone();
    pending_failure_reasons.push("quorum activation canary execution did not complete".to_string());
    let evidence = QuorumFaultActivationEvidence {
        schema_version: ACTIVATION_SCHEMA_VERSION,
        scenario: scenario.to_string(),
        run_id: run_id.to_string(),
        backend: "chaos-mesh-iochaos".to_string(),
        iochaos_resource_name,
        iochaos_snapshot_sha256,
        volume_path,
        expected_targets,
        controller_records,
        started_at_ms,
        completed_at_ms: started_at_ms,
        qualified: false,
        failure_reasons: pending_failure_reasons,
        cleanup_failure_reason: None,
        targets,
    };
    (
        evidence,
        QuorumFaultActivationPlan {
            attempts,
            failure_reasons,
        },
    )
}

pub(super) async fn qualify_prepared_quorum_fault_activation(
    cluster: &ClusterTestConfig,
    run_id: &str,
    activation: &mut QuorumCanaryCleanupGuard,
    plan: QuorumFaultActivationPlan,
    timeout: Duration,
) {
    let futures = plan
        .attempts
        .into_iter()
        .map(|(binding, record_id)| run_canary(cluster, run_id, binding, record_id, timeout));
    let mut targets = join_all(futures).await;
    targets.sort_by(|left, right| left.pod_name.cmp(&right.pod_name));
    let mut failure_reasons = plan.failure_reasons;
    for target in &targets {
        if target.outcome != QuorumCanaryOutcome::IoErrorObserved {
            failure_reasons.push(format!(
                "canary for Pod {:?} did not observe EIO: {:?}",
                target.pod_name, target.outcome
            ));
        }
    }
    failure_reasons.sort();
    failure_reasons.dedup();
    let completed_at_ms = now_ms();
    let mut evidence = activation.evidence().clone();
    let qualified = failure_reasons.is_empty()
        && targets.len() == usize::try_from(evidence.expected_targets).unwrap_or(usize::MAX)
        && evidence.controller_records
            == usize::try_from(evidence.expected_targets).unwrap_or(usize::MAX)
        && targets
            .iter()
            .all(|target| target.outcome == QuorumCanaryOutcome::IoErrorObserved);
    evidence.completed_at_ms = completed_at_ms;
    evidence.qualified = qualified;
    evidence.failure_reasons = failure_reasons;
    evidence.targets = targets;
    activation.replace_evidence(evidence);
}

pub(super) async fn cleanup_quorum_canaries(
    cluster: &ClusterTestConfig,
    evidence: &mut QuorumFaultActivationEvidence,
    timeout: Duration,
) -> Result<()> {
    let futures = evidence.targets.iter().map(|target| {
        let command = Kubectl::new(cluster)
            .namespaced(&cluster.test_namespace)
            .command([
                "exec",
                &target.pod_name,
                "-c",
                RUSTFS_CONTAINER,
                "--",
                "/bin/sh",
                "-c",
                CLEANUP_SCRIPT,
                "s3chaos-quorum-canary-cleanup",
                &target.canary_path,
            ]);
        async move {
            let started_at_ms = now_ms();
            let result = command.run_bounded(timeout).await;
            let completed_at_ms = now_ms();
            match result {
                Ok(output) => QuorumCanaryCleanupEvidence {
                    started_at_ms,
                    completed_at_ms,
                    outcome: if output.code == Some(0) {
                        QuorumCanaryCleanupOutcome::Removed
                    } else {
                        QuorumCanaryCleanupOutcome::Failed
                    },
                    exit_code: output.code,
                    stderr: output.stderr,
                },
                Err(error) => QuorumCanaryCleanupEvidence {
                    started_at_ms,
                    completed_at_ms,
                    outcome: if error.to_string().contains("timed out") {
                        QuorumCanaryCleanupOutcome::TimedOut
                    } else {
                        QuorumCanaryCleanupOutcome::Failed
                    },
                    exit_code: None,
                    stderr: error.to_string(),
                },
            }
        }
    });
    let cleanups = join_all(futures).await;
    for (target, cleanup) in evidence.targets.iter_mut().zip(cleanups) {
        target.cleanup = Some(cleanup);
    }
    let failures = evidence
        .targets
        .iter()
        .filter(|target| {
            target
                .cleanup
                .as_ref()
                .is_none_or(|cleanup| cleanup.outcome != QuorumCanaryCleanupOutcome::Removed)
        })
        .map(|target| target.pod_name.clone())
        .collect::<Vec<_>>();
    ensure!(
        failures.is_empty(),
        "failed to remove quorum activation canaries from Pods: {}",
        failures.join(", ")
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    };

    fn target(index: usize, outcome: QuorumCanaryOutcome) -> QuorumFaultActivationTargetEvidence {
        QuorumFaultActivationTargetEvidence {
            pod_name: format!("rustfs-{index}"),
            pod_uid: format!("pod-uid-{index}"),
            container_id: format!("containerd://container-{index}"),
            persistent_volume_claim: format!("data-rustfs-{index}"),
            persistent_volume: format!("pv-{index}"),
            mount_path: "/data/rustfs0".to_string(),
            drive_uuid: format!("drive-{index}"),
            controller_record_id: format!("faults/rustfs-{index}/rustfs"),
            canary_path: format!("/data/rustfs0/.s3chaos-quorum-run-rustfs-{index}"),
            started_at_ms: 110 + index as u64,
            completed_at_ms: 120 + index as u64,
            outcome,
            exit_code: Some(1),
            stdout: String::new(),
            stderr: "sh: write error: Input/output error".to_string(),
            cleanup: None,
        }
    }

    fn evidence(
        expected_targets: u32,
        targets: Vec<QuorumFaultActivationTargetEvidence>,
        failure_reasons: Vec<String>,
    ) -> QuorumFaultActivationEvidence {
        let qualified = failure_reasons.is_empty()
            && targets.len() == expected_targets as usize
            && targets
                .iter()
                .all(|target| target.outcome == QuorumCanaryOutcome::IoErrorObserved);
        QuorumFaultActivationEvidence {
            schema_version: ACTIVATION_SCHEMA_VERSION,
            scenario: "quorum-p-io-fault".to_string(),
            run_id: "run-1".to_string(),
            backend: "chaos-mesh-iochaos".to_string(),
            iochaos_resource_name: "s3chaos-run-1".to_string(),
            iochaos_snapshot_sha256: "a".repeat(64),
            volume_path: "/data/rustfs0".to_string(),
            expected_targets,
            controller_records: targets.len(),
            started_at_ms: 100,
            completed_at_ms: 200,
            qualified,
            failure_reasons,
            cleanup_failure_reason: None,
            targets,
        }
    }

    fn mark_cleanup(
        evidence: &mut QuorumFaultActivationEvidence,
        outcome: QuorumCanaryCleanupOutcome,
        exit_code: Option<i32>,
        stderr: &str,
    ) {
        for target in &mut evidence.targets {
            target.cleanup = Some(QuorumCanaryCleanupEvidence {
                started_at_ms: 210,
                completed_at_ms: 220,
                outcome,
                exit_code,
                stderr: stderr.to_string(),
            });
        }
    }

    #[test]
    fn complete_independent_eio_evidence_qualifies_activation() {
        let evidence = evidence(
            2,
            vec![
                target(0, QuorumCanaryOutcome::IoErrorObserved),
                target(1, QuorumCanaryOutcome::IoErrorObserved),
            ],
            Vec::new(),
        );

        evidence.validate().expect("qualified activation evidence");
        assert!(evidence.qualified);
        assert!(evidence.failure_reason().is_none());
    }

    #[test]
    fn partial_activation_is_unqualified_with_an_explicit_reason() {
        let evidence = evidence(
            2,
            vec![target(0, QuorumCanaryOutcome::IoErrorObserved)],
            vec!["IOChaos independently exercised 1 targets, expected 2".to_string()],
        );

        evidence
            .validate()
            .expect("diagnostic evidence remains valid");
        assert!(!evidence.qualified);
        assert_eq!(
            evidence.disposition(),
            QuorumActivationDisposition::SkipTypedOracleAndRecover
        );
        assert!(evidence.failure_reason().unwrap().contains("expected 2"));
    }

    #[test]
    fn write_success_cannot_prove_fault_activation() {
        let mut evidence = evidence(
            1,
            vec![target(0, QuorumCanaryOutcome::WriteSucceeded)],
            vec!["canary did not observe EIO".to_string()],
        );
        evidence.targets[0].exit_code = Some(0);
        evidence.targets[0].stderr.clear();

        evidence
            .validate()
            .expect("diagnostic evidence remains valid");
        assert!(!evidence.qualified);
    }

    #[test]
    fn timed_out_canary_cannot_prove_fault_activation() {
        let mut evidence = evidence(
            1,
            vec![target(0, QuorumCanaryOutcome::TimedOut)],
            vec!["canary timed out".to_string()],
        );
        evidence.targets[0].exit_code = None;
        evidence.targets[0].stderr = "command timed out".to_string();

        evidence
            .validate()
            .expect("diagnostic evidence remains valid");
        assert!(!evidence.qualified);
    }

    #[test]
    fn qualification_rejects_a_success_claim_with_partial_targets() {
        let mut evidence = evidence(
            2,
            vec![target(0, QuorumCanaryOutcome::IoErrorObserved)],
            vec!["partial".to_string()],
        );
        evidence.qualified = true;

        assert!(evidence.validate().is_err());
    }

    #[test]
    fn unqualified_activation_skips_the_oracle_and_continues_recovery() {
        let mut evidence = evidence(
            1,
            vec![target(0, QuorumCanaryOutcome::WriteSucceeded)],
            vec!["canary did not observe EIO".to_string()],
        );
        evidence.targets[0].exit_code = Some(0);
        evidence.targets[0].stderr.clear();

        assert_eq!(
            evidence.disposition(),
            QuorumActivationDisposition::SkipTypedOracleAndRecover
        );
    }

    #[test]
    fn qualified_activation_runs_the_typed_oracle() {
        let evidence = evidence(
            1,
            vec![target(0, QuorumCanaryOutcome::IoErrorObserved)],
            Vec::new(),
        );

        assert_eq!(
            evidence.disposition(),
            QuorumActivationDisposition::RunTypedOracle
        );
    }

    #[test]
    fn stage_failure_keeps_the_primary_error_and_persists_cleanup_failure() {
        let dir = tempfile::tempdir().expect("artifact dir");
        let collector = ArtifactCollector::new(dir.path());
        let attempts = Arc::new(AtomicUsize::new(0));
        let runner_attempts = Arc::clone(&attempts);
        let runner: TestCleanupRunner = Arc::new(move |evidence, _| {
            runner_attempts.fetch_add(1, Ordering::SeqCst);
            mark_cleanup(
                evidence,
                QuorumCanaryCleanupOutcome::Failed,
                Some(1),
                "forced cleanup failure",
            );
            Err(anyhow!("forced cleanup failure"))
        });
        let guard = QuorumCanaryCleanupGuard::for_test(
            &collector,
            "quorum-case",
            evidence(
                1,
                vec![target(0, QuorumCanaryOutcome::IoErrorObserved)],
                Vec::new(),
            ),
            runner,
        );

        let primary = {
            let _guard = guard;
            Err::<(), _>(anyhow!("typed workload failed"))
        }
        .expect_err("stage error");

        assert_eq!(primary.to_string(), "typed workload failed");
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        let artifact = std::fs::read_to_string(
            collector
                .case_dir("quorum-case")
                .join(crate::fault::quorum::QUORUM_FAULT_ACTIVATION_ARTIFACT),
        )
        .expect("cleanup artifact");
        let persisted: QuorumFaultActivationEvidence =
            serde_json::from_str(&artifact).expect("cleanup evidence");
        assert_eq!(
            persisted.cleanup_failure_reason.as_deref(),
            Some("forced cleanup failure")
        );
        assert_eq!(
            persisted.targets[0]
                .cleanup
                .as_ref()
                .expect("target cleanup")
                .outcome,
            QuorumCanaryCleanupOutcome::Failed
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_cleanup_future_finishes_once_and_persists_evidence() {
        let dir = tempfile::tempdir().expect("artifact dir");
        let collector = ArtifactCollector::new(dir.path());
        let attempts = Arc::new(AtomicUsize::new(0));
        let runner_attempts = Arc::clone(&attempts);
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let release_rx = Arc::new(Mutex::new(release_rx));
        let runner_release = Arc::clone(&release_rx);
        let runner: TestCleanupRunner = Arc::new(move |evidence, _| {
            runner_attempts.fetch_add(1, Ordering::SeqCst);
            started_tx.send(()).expect("signal cleanup start");
            runner_release
                .lock()
                .expect("release receiver")
                .recv_timeout(Duration::from_secs(5))
                .expect("release cleanup");
            mark_cleanup(evidence, QuorumCanaryCleanupOutcome::Removed, Some(0), "");
            Ok(())
        });
        let guard = QuorumCanaryCleanupGuard::for_test(
            &collector,
            "quorum-case",
            evidence(
                1,
                vec![target(0, QuorumCanaryOutcome::IoErrorObserved)],
                Vec::new(),
            ),
            runner,
        );
        let cleanup = tokio::spawn(async move {
            let mut guard = guard;
            guard.cleanup().await
        });
        tokio::task::spawn_blocking(move || {
            started_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("cleanup started")
        })
        .await
        .expect("wait for cleanup start");

        cleanup.abort();
        let _ = cleanup.await;
        release_tx.send(()).expect("release cleanup worker");

        let artifact_path = collector
            .case_dir("quorum-case")
            .join(crate::fault::quorum::QUORUM_FAULT_ACTIVATION_ARTIFACT);
        tokio::time::timeout(Duration::from_secs(5), async {
            while !artifact_path.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("cleanup artifact deadline");
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        let artifact = std::fs::read_to_string(artifact_path).expect("cleanup artifact");
        let persisted: QuorumFaultActivationEvidence =
            serde_json::from_str(&artifact).expect("cleanup evidence");
        assert!(persisted.cleanup_failure_reason.is_none());
        assert_eq!(
            persisted.targets[0]
                .cleanup
                .as_ref()
                .expect("target cleanup")
                .outcome,
            QuorumCanaryCleanupOutcome::Removed
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_fault_stage_drops_the_guard_and_persists_cleanup() {
        let dir = tempfile::tempdir().expect("artifact dir");
        let collector = ArtifactCollector::new(dir.path());
        let attempts = Arc::new(AtomicUsize::new(0));
        let runner_attempts = Arc::clone(&attempts);
        let runner: TestCleanupRunner = Arc::new(move |evidence, _| {
            runner_attempts.fetch_add(1, Ordering::SeqCst);
            mark_cleanup(evidence, QuorumCanaryCleanupOutcome::Removed, Some(0), "");
            Ok(())
        });
        let guard = QuorumCanaryCleanupGuard::for_test(
            &collector,
            "quorum-case",
            evidence(
                1,
                vec![target(0, QuorumCanaryOutcome::IoErrorObserved)],
                Vec::new(),
            ),
            runner,
        );
        let (stage_started_tx, stage_started_rx) = mpsc::channel();
        let stage = tokio::spawn(async move {
            let _guard = guard;
            stage_started_tx.send(()).expect("stage started");
            std::future::pending::<()>().await;
        });
        tokio::task::spawn_blocking(move || {
            stage_started_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("fault stage started")
        })
        .await
        .expect("wait for fault stage");

        stage.abort();
        let _ = stage.await;

        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        let artifact = std::fs::read_to_string(
            collector
                .case_dir("quorum-case")
                .join(crate::fault::quorum::QUORUM_FAULT_ACTIVATION_ARTIFACT),
        )
        .expect("cleanup artifact");
        let persisted: QuorumFaultActivationEvidence =
            serde_json::from_str(&artifact).expect("cleanup evidence");
        assert!(persisted.cleanup_failure_reason.is_none());
        assert_eq!(
            persisted.targets[0]
                .cleanup
                .as_ref()
                .expect("target cleanup")
                .outcome,
            QuorumCanaryCleanupOutcome::Removed
        );
    }
}
