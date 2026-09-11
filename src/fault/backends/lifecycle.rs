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

//! kubectl-driven Kubernetes lifecycle backend: graceful single-Pod restart,
//! ordered rolling restart, and StatefulSet cold restart.
//!
//! The fault-test Tenant's StatefulSet is owned by the RustFS operator, which
//! reconciles `spec.replicas` and the Pod template (including annotations)
//! back to the Tenant spec whenever they differ. `kubectl rollout restart`
//! (a template annotation) and a bare `kubectl scale` would therefore be
//! reverted mid-operation. The operator-safe primitive is deleting Pods with
//! their default grace period: the StatefulSet controller recreates each Pod
//! with a new UID and the operator sees nothing to reconcile. Rolling restart
//! is driven Pod by Pod from the highest ordinal down, waiting for every
//! replacement to become Ready first, which is what the controller does for a
//! rollout. Cold restart must hold the outage across the workload, so it pauses
//! the operator (scales its Deployment to zero, an explicit opt-in through
//! `RUSTFS_FAULT_TEST_OPERATOR_DEPLOYMENT`), scales the StatefulSet to zero,
//! and restores both afterwards; every `spec.replicas` sample taken meanwhile
//! is recorded so a reverted scale-down cannot pass as a held outage.
//!
//! Every deleted Pod's final container state is captured from a streaming
//! `kubectl get --watch` plus status polls, because the Pod object disappears
//! right after the container exits and a replacement Pod carries no
//! `lastState` for it. The grace-timeout rule lives in `evidence.rs`.

pub mod evidence;
pub mod kube;

use anyhow::{Context, Result, bail, ensure};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Child;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{JoinHandle, sleep};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::{
    fault::{
        config::FaultTestConfig,
        fault_artifacts::FaultFailureArtifactSource,
        fault_lifecycle::{AppliedFault, ClassifiedFaultFailure, FaultLifecyclePort},
        plan::{FaultInjection, FaultKind},
        preflight::{TargetStatefulSetPodProof, TargetStatefulSetProof},
        reporting::FaultStatusSnapshot,
        scenarios::FaultScenario,
    },
    framework::{artifacts::ArtifactCollector, config::ClusterTestConfig, kubectl::Kubectl},
};
use evidence::{
    LifecycleOperation, LifecyclePodStatus, LifecycleStatusSnapshot, OperatorPauseEvidence,
    OutageEvidence, POD_LIFECYCLE_EVIDENCE_ARTIFACT, PodLifecycleEvidence, PodTerminationEvidence,
    ReplicaObservation, StatefulSetIdentity, TerminationClassification,
    TerminationClassificationInput, classify_termination,
};
use kube::{
    ObservedPod, ObservedStatefulSet, auth_can_i_command, delete_pod_default_grace_command,
    final_pod_states, get_deployment_command, get_statefulset_command, list_rustfs_pods_command,
    parse_deployment, parse_pod_list, parse_statefulset, parse_watch_stream,
    require_single_statefulset_owner, run_json, scale_deployment_command,
    scale_statefulset_command, watch_rustfs_pods_command,
};

const POLL_INTERVAL: Duration = Duration::from_millis(250);
const REPLICA_SAMPLE_INTERVAL_MS: u64 = 5_000;
pub const POD_LIFECYCLE_WATCH_ARTIFACT: &str = "pod-lifecycle-watch.json";
pub const OPERATOR_DEPLOYMENT_ENV: &str = "RUSTFS_FAULT_TEST_OPERATOR_DEPLOYMENT";

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

/// Static backend preflight. The fixture may not exist yet, so this checks
/// only what a lifecycle operation needs from the kube context itself: the
/// RBAC verbs it will use, and for cold restarts the operator pause target.
pub(in crate::fault) fn require_backend(config: &FaultTestConfig, kind: FaultKind) -> Result<()> {
    let operation = LifecycleOperation::from_kind(kind)?;
    let cluster = &config.cluster;
    let test_namespace = cluster.test_namespace.as_str();
    let mut required = vec![
        (test_namespace, "get", "pods"),
        (test_namespace, "list", "pods"),
        (test_namespace, "watch", "pods"),
        (test_namespace, "delete", "pods"),
        (test_namespace, "get", "statefulsets"),
    ];
    if operation == LifecycleOperation::ColdRestart {
        let deployment = config.operator_deployment.as_deref().with_context(|| {
            format!(
                "cluster-cold-restart holds the outage by pausing the RustFS operator; set {OPERATOR_DEPLOYMENT_ENV} to the operator Deployment name in namespace {:?}",
                cluster.operator_namespace
            )
        })?;
        ensure!(
            !deployment.trim().is_empty(),
            "{OPERATOR_DEPLOYMENT_ENV} must not be empty"
        );
        required.extend([
            (test_namespace, "patch", "statefulsets"),
            (cluster.operator_namespace.as_str(), "get", "deployments"),
            (cluster.operator_namespace.as_str(), "patch", "deployments"),
        ]);
    }
    require_permissions(cluster, &required)
}

fn require_permissions(cluster: &ClusterTestConfig, required: &[(&str, &str, &str)]) -> Result<()> {
    let mut denied = Vec::new();
    for (namespace, verb, resource) in required {
        let command = auth_can_i_command(cluster, namespace, verb, resource);
        let output = command.run()?;
        if output.stdout.trim() != "yes" {
            denied.push(format!(
                "{verb} {resource} in {namespace} ({})",
                if output.stderr.trim().is_empty() {
                    output.stdout.trim().to_string()
                } else {
                    output.stderr.trim().to_string()
                }
            ));
        }
    }
    ensure!(
        denied.is_empty(),
        "the kube context lacks permissions the Kubernetes lifecycle backend needs: {}",
        denied.join("; ")
    );
    Ok(())
}

pub(in crate::fault) struct StatefulSetObservation {
    pub(in crate::fault) statefulset: ObservedStatefulSet,
    pub(in crate::fault) pods: Vec<ObservedPod>,
    pub(in crate::fault) observed_at_ms: u64,
}

fn observe_pods(cluster: &ClusterTestConfig) -> Result<Vec<ObservedPod>> {
    parse_pod_list(&run_json(&list_rustfs_pods_command(cluster))?)
}

fn observe_statefulset(cluster: &ClusterTestConfig, name: &str) -> Result<ObservedStatefulSet> {
    parse_statefulset(&run_json(&get_statefulset_command(cluster, name))?)
}

/// Bind the current tenant Pods to exactly one Ready StatefulSet. Rejects
/// Deployments, mixed owners, missing Pods, and Pods that disagree with the
/// template's grace period, so every later step acts on a proven topology.
pub(in crate::fault) fn observe_statefulset_topology(
    cluster: &ClusterTestConfig,
    expected_pods: usize,
) -> Result<StatefulSetObservation> {
    let observed_at_ms = now_ms();
    let pods = observe_pods(cluster)?;
    ensure!(
        pods.len() == expected_pods,
        "expected {expected_pods} RustFS Pods for the lifecycle scenario, found {}",
        pods.len()
    );
    let owner = require_single_statefulset_owner(&pods)?;
    let statefulset = observe_statefulset(cluster, &owner.name)?;
    ensure!(
        statefulset.identity.uid == owner.uid,
        "StatefulSet {} uid {} does not match the Pods' controller uid {}",
        owner.name,
        statefulset.identity.uid,
        owner.uid
    );
    ensure!(
        statefulset.identity.namespace == cluster.test_namespace,
        "StatefulSet {} lives in namespace {:?}, not the fault-test namespace {:?}",
        owner.name,
        statefulset.identity.namespace,
        cluster.test_namespace
    );
    ensure!(
        usize::try_from(statefulset.spec_replicas).ok() == Some(expected_pods),
        "StatefulSet {} declares {} replicas but the scenario expects {expected_pods} Pods",
        owner.name,
        statefulset.spec_replicas
    );
    let mut ordinals = std::collections::BTreeSet::new();
    for pod in &pods {
        ensure!(
            pod.phase == "Running" && pod.ready && !pod.terminating,
            "Pod {} is not Running and Ready before the lifecycle operation (phase={}, ready={}, terminating={})",
            pod.name,
            pod.phase,
            pod.ready,
            pod.terminating
        );
        let ordinal = pod
            .ordinal
            .with_context(|| format!("Pod {} has no StatefulSet ordinal suffix", pod.name))?;
        ensure!(
            pod.name == format!("{}-{ordinal}", owner.name) && ordinals.insert(ordinal),
            "Pod {} is not a unique ordinal member of StatefulSet {}",
            pod.name,
            owner.name
        );
        ensure!(
            pod.termination_grace_period_seconds
                == statefulset.identity.termination_grace_period_seconds,
            "Pod {} grace period {}s differs from the StatefulSet template {}s",
            pod.name,
            pod.termination_grace_period_seconds,
            statefulset.identity.termination_grace_period_seconds
        );
    }
    Ok(StatefulSetObservation {
        statefulset,
        pods,
        observed_at_ms,
    })
}

/// Target-proof evidence: the live StatefulSet identity and its owned Pods.
pub(in crate::fault) fn prove_statefulset_ownership(
    cluster: &ClusterTestConfig,
    expected_pods: usize,
) -> Result<TargetStatefulSetProof> {
    let observation = observe_statefulset_topology(cluster, expected_pods)?;
    let identity = observation.statefulset.identity;
    Ok(TargetStatefulSetProof {
        name: identity.name,
        uid: identity.uid,
        namespace: identity.namespace,
        replicas: identity.replicas,
        pod_management_policy: identity.pod_management_policy,
        update_strategy: identity.update_strategy,
        pvc_retention_when_scaled: identity.pvc_retention_when_scaled,
        pvc_retention_when_deleted: identity.pvc_retention_when_deleted,
        termination_grace_period_seconds: identity.termination_grace_period_seconds,
        current_revision: identity.current_revision,
        update_revision: identity.update_revision,
        owned_pods: observation
            .pods
            .iter()
            .map(|pod| TargetStatefulSetPodProof {
                name: pod.name.clone(),
                uid: pod.uid.clone(),
                ordinal: pod.ordinal.unwrap_or_default(),
                restart_count: pod.restart_count,
            })
            .collect(),
        observed_at_ms: observation.observed_at_ms,
    })
}

pub(in crate::fault) struct FaultApplyRequest<'a> {
    pub(in crate::fault) config: &'a FaultTestConfig,
    pub(in crate::fault) collector: &'a ArtifactCollector,
    pub(in crate::fault) scenario: &'a FaultScenario,
    pub(in crate::fault) injection: &'a FaultInjection,
    pub(in crate::fault) run_id: &'a str,
}

/// Per-target restart bookkeeping shared between the handle and, for rolling
/// restarts, the worker thread.
#[derive(Default)]
struct LifecycleState {
    targets: Vec<PodTerminationEvidence>,
    outage: Option<OutageEvidence>,
    last_replica_sample_at_ms: u64,
}

impl LifecycleState {
    fn begin_target(&mut self, pod: &ObservedPod, delete_requested_at_ms: u64, deferred: bool) {
        self.targets.push(PodTerminationEvidence {
            pod_name: pod.name.clone(),
            ordinal: pod.ordinal.unwrap_or_default(),
            old_uid: pod.uid.clone(),
            restart_count_before: pod.restart_count,
            termination_grace_period_seconds: pod.termination_grace_period_seconds,
            delete_requested_at_ms,
            deletion_timestamp: None,
            deletion_grace_period_seconds: None,
            sigterm_requested_at_ms: None,
            terminated: None,
            observation_source: None,
            termination_duration_ms: None,
            old_uid_gone_at_ms: None,
            new_uid: None,
            restart_count_after: None,
            replacement_ready_at_ms: None,
            classification: TerminationClassification::Unobserved,
            restarted_after_workload: deferred,
        });
    }

    /// Fold one Pod listing into every open target: deletion metadata and the
    /// container's terminated state while the old Pod still exists, then the
    /// replacement's identity and readiness once it is gone.
    fn absorb(&mut self, pods: &[ObservedPod], observed_at_ms: u64) {
        for target in &mut self.targets {
            if target.replacement_ready_at_ms.is_some() {
                continue;
            }
            match pods.iter().find(|pod| pod.uid == target.old_uid) {
                Some(old) => {
                    if old.deletion_timestamp.is_some() && target.deletion_timestamp.is_none() {
                        target.deletion_timestamp = old.deletion_timestamp.clone();
                        target.deletion_grace_period_seconds = old.deletion_grace_period_seconds;
                        target.sigterm_requested_at_ms = old.sigterm_requested_at_ms();
                    }
                    if target.terminated.is_none()
                        && let Some(terminated) = &old.rustfs_terminated
                    {
                        target.terminated = Some(terminated.clone());
                        target.observation_source = Some("poll".to_string());
                    }
                }
                None => {
                    if target.old_uid_gone_at_ms.is_none() {
                        target.old_uid_gone_at_ms = Some(observed_at_ms);
                    }
                    if let Some(replacement) = pods
                        .iter()
                        .find(|pod| pod.name == target.pod_name && pod.uid != target.old_uid)
                    {
                        target.new_uid = Some(replacement.uid.clone());
                        target.restart_count_after = Some(replacement.restart_count);
                        if replacement.ready && !replacement.terminating {
                            target.replacement_ready_at_ms = Some(observed_at_ms);
                        }
                    }
                }
            }
        }
    }

    fn absorb_watch(&mut self, states: &BTreeMap<String, ObservedPod>) {
        for target in &mut self.targets {
            let Some(old) = states.get(&target.old_uid) else {
                continue;
            };
            if target.deletion_timestamp.is_none() && old.deletion_timestamp.is_some() {
                target.deletion_timestamp = old.deletion_timestamp.clone();
                target.deletion_grace_period_seconds = old.deletion_grace_period_seconds;
                target.sigterm_requested_at_ms = old.sigterm_requested_at_ms();
            }
            if target.terminated.is_none()
                && let Some(terminated) = &old.rustfs_terminated
            {
                target.terminated = Some(terminated.clone());
                target.observation_source = Some("watch".to_string());
            }
        }
    }

    fn classify_all(&mut self) {
        for target in &mut self.targets {
            let classified = classify_termination(&TerminationClassificationInput {
                grace_period_seconds: target.termination_grace_period_seconds,
                sigterm_reference_at_ms: target.sigterm_reference_at_ms(),
                terminated: target.terminated.as_ref(),
            });
            target.classification = classified.classification;
            target.termination_duration_ms = classified.duration_ms;
        }
    }

    fn target(&self, name: &str) -> Option<&PodTerminationEvidence> {
        self.targets.iter().find(|target| target.pod_name == name)
    }

    fn any_gone(&self) -> bool {
        self.targets
            .iter()
            .any(|target| target.old_uid_gone_at_ms.is_some())
    }

    fn all_gone(&self) -> bool {
        !self.targets.is_empty()
            && self
                .targets
                .iter()
                .all(|target| target.old_uid_gone_at_ms.is_some())
    }

    fn all_replacements_ready(&self) -> bool {
        !self.targets.is_empty()
            && self
                .targets
                .iter()
                .all(|target| target.replacement_ready_at_ms.is_some())
    }

    fn record_replica_sample(&mut self, spec_replicas: i64, pods: usize, observed_at_ms: u64) {
        let Some(outage) = &mut self.outage else {
            return;
        };
        let changed = outage
            .replica_observations
            .last()
            .is_none_or(|last| last.spec_replicas != spec_replicas || last.pods != pods);
        if changed || observed_at_ms >= self.last_replica_sample_at_ms + REPLICA_SAMPLE_INTERVAL_MS
        {
            outage.replica_observations.push(ReplicaObservation {
                observed_at_ms,
                spec_replicas,
                pods,
            });
            self.last_replica_sample_at_ms = observed_at_ms;
        }
    }
}

type SharedState = Arc<Mutex<LifecycleState>>;

fn lock_state(state: &SharedState) -> std::sync::MutexGuard<'_, LifecycleState> {
    state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Background `kubectl get --watch` capturing every Pod change to a file.
struct PodWatch {
    child: Child,
    log_path: PathBuf,
}

impl PodWatch {
    fn start(cluster: &ClusterTestConfig, log_path: PathBuf) -> Result<Self> {
        let child = watch_rustfs_pods_command(cluster).spawn_background_with_log(&log_path)?;
        Ok(Self { child, log_path })
    }

    fn finish(mut self) -> Result<BTreeMap<String, ObservedPod>> {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let raw = std::fs::read_to_string(&self.log_path)
            .with_context(|| format!("read Pod watch log {}", self.log_path.display()))?;
        let stream = parse_watch_stream(&raw);
        if stream.truncated {
            eprintln!(
                "warning: Pod lifecycle watch stream {} ended with unparsable output; relying on the parsed prefix and status polls",
                self.log_path.display()
            );
        }
        Ok(final_pod_states(&stream.objects))
    }
}

impl Drop for PodWatch {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Scale the RustFS operator Deployment to zero so it cannot reconcile the
/// StatefulSet replica count back while the outage is held.
struct OperatorPause {
    cluster: ClusterTestConfig,
    evidence: OperatorPauseEvidence,
    resumed: bool,
}

impl OperatorPause {
    fn pause(cluster: &ClusterTestConfig, deployment: &str, timeout: Duration) -> Result<Self> {
        let namespace = cluster.operator_namespace.clone();
        let observed = parse_deployment(&run_json(&get_deployment_command(
            cluster, &namespace, deployment,
        ))?)
        .with_context(|| format!("read operator Deployment {namespace}/{deployment}"))?;
        let replicas_before = u32::try_from(observed.spec_replicas)
            .ok()
            .filter(|replicas| *replicas > 0)
            .with_context(|| {
                format!(
                    "operator Deployment {namespace}/{deployment} has {} replicas; refusing to pause an operator that is not running",
                    observed.spec_replicas
                )
            })?;
        let pause_requested_at_ms = now_ms();
        scale_deployment_command(cluster, &namespace, deployment, 0)?.run_checked()?;
        let mut pause = Self {
            cluster: cluster.clone(),
            evidence: OperatorPauseEvidence {
                namespace: namespace.clone(),
                deployment: deployment.to_string(),
                replicas_before,
                pause_requested_at_ms,
                operator_pods_gone_at_ms: None,
                resume_requested_at_ms: None,
                resumed_at_ms: None,
            },
            resumed: false,
        };
        let deadline = Instant::now() + timeout;
        loop {
            let observed = parse_deployment(&run_json(&get_deployment_command(
                cluster, &namespace, deployment,
            ))?)?;
            if observed.spec_replicas == 0 && observed.status_replicas == 0 {
                pause.evidence.operator_pods_gone_at_ms = Some(now_ms());
                return Ok(pause);
            }
            if Instant::now() >= deadline {
                let error = anyhow::anyhow!(
                    "operator Deployment {namespace}/{deployment} still reports {} Pod(s) {timeout:?} after scaling to zero",
                    observed.status_replicas
                );
                pause.resume(timeout).ok();
                return Err(error);
            }
            sleep(POLL_INTERVAL);
        }
    }

    fn resume(&mut self, timeout: Duration) -> Result<()> {
        if self.resumed {
            return Ok(());
        }
        let namespace = self.evidence.namespace.clone();
        let deployment = self.evidence.deployment.clone();
        let replicas = self.evidence.replicas_before;
        self.evidence.resume_requested_at_ms = Some(now_ms());
        scale_deployment_command(&self.cluster, &namespace, &deployment, replicas)?
            .run_checked()?;
        // The scale request is durable even if availability is slow; treat the
        // operator as resumed from here so Drop does not repeat the request.
        self.resumed = true;
        let deadline = Instant::now() + timeout;
        loop {
            let observed = parse_deployment(&run_json(&get_deployment_command(
                &self.cluster,
                &namespace,
                &deployment,
            ))?)?;
            if observed.available_replicas >= i64::from(replicas) {
                self.evidence.resumed_at_ms = Some(now_ms());
                return Ok(());
            }
            ensure!(
                Instant::now() < deadline,
                "operator Deployment {namespace}/{deployment} did not become available again within {timeout:?} (available={}, wanted={replicas})",
                observed.available_replicas
            );
            sleep(POLL_INTERVAL);
        }
    }
}

impl Drop for OperatorPause {
    fn drop(&mut self) {
        if self.resumed {
            return;
        }
        match scale_deployment_command(
            &self.cluster,
            &self.evidence.namespace,
            &self.evidence.deployment,
            self.evidence.replicas_before,
        )
        .and_then(|command| command.run_checked())
        {
            Ok(_) => eprintln!(
                "warning: resumed operator Deployment {}/{} during cleanup",
                self.evidence.namespace, self.evidence.deployment
            ),
            Err(error) => eprintln!(
                "warning: failed to resume operator Deployment {}/{} during cleanup; scale it back to {} replicas manually: {error:#}",
                self.evidence.namespace, self.evidence.deployment, self.evidence.replicas_before
            ),
        }
    }
}

/// Issue the graceful delete and register the target.
fn initiate_pod_delete(
    cluster: &ClusterTestConfig,
    state: &SharedState,
    pod: &ObservedPod,
    deferred: bool,
) -> Result<()> {
    let command = delete_pod_default_grace_command(cluster, &pod.name, &pod.uid)?;
    let delete_requested_at_ms = now_ms();
    lock_state(state).begin_target(pod, delete_requested_at_ms, deferred);
    command
        .run_checked()
        .with_context(|| format!("graceful delete of Pod {} (uid {})", pod.name, pod.uid))?;
    Ok(())
}

fn poll_targets(cluster: &ClusterTestConfig, state: &SharedState) -> Result<Vec<ObservedPod>> {
    let pods = observe_pods(cluster)?;
    lock_state(state).absorb(&pods, now_ms());
    Ok(pods)
}

fn wait_until(
    cluster: &ClusterTestConfig,
    state: &SharedState,
    timeout: Duration,
    cancel: Option<&AtomicBool>,
    description: &str,
    mut condition: impl FnMut(&LifecycleState) -> bool,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if cancel.is_some_and(|flag| flag.load(Ordering::SeqCst)) {
            bail!("cancelled while waiting for {description}");
        }
        poll_targets(cluster, state)?;
        if condition(&lock_state(state)) {
            return Ok(());
        }
        ensure!(
            Instant::now() < deadline,
            "timed out after {timeout:?} waiting for {description}"
        );
        sleep(POLL_INTERVAL);
    }
}

/// Delete one Pod gracefully and wait for its replacement to become Ready.
fn restart_pod_blocking(
    cluster: &ClusterTestConfig,
    state: &SharedState,
    pod: &ObservedPod,
    timeout: Duration,
    cancel: Option<&AtomicBool>,
    deferred: bool,
) -> Result<()> {
    initiate_pod_delete(cluster, state, pod, deferred)?;
    let name = pod.name.clone();
    wait_until(
        cluster,
        state,
        timeout,
        cancel,
        &format!("Pod {name} (uid {}) to terminate", pod.uid),
        |state| {
            state
                .target(&name)
                .is_some_and(|target| target.old_uid_gone_at_ms.is_some())
        },
    )?;
    wait_until(
        cluster,
        state,
        timeout,
        cancel,
        &format!("replacement of Pod {name} to become Ready"),
        |state| {
            state
                .target(&name)
                .is_some_and(|target| target.replacement_ready_at_ms.is_some())
        },
    )
}

#[derive(Default)]
struct RollingProgress {
    error: Option<String>,
    finished: bool,
}

struct RollingWorker {
    handle: Option<JoinHandle<()>>,
    cancel: Arc<AtomicBool>,
    progress: Arc<Mutex<RollingProgress>>,
}

impl RollingWorker {
    fn spawn(
        cluster: ClusterTestConfig,
        state: SharedState,
        pods: Vec<ObservedPod>,
        timeout: Duration,
    ) -> Self {
        let cancel = Arc::new(AtomicBool::new(false));
        let progress = Arc::new(Mutex::new(RollingProgress::default()));
        let worker_cancel = Arc::clone(&cancel);
        let worker_progress = Arc::clone(&progress);
        let handle = std::thread::spawn(move || {
            let outcome = pods.iter().try_for_each(|pod| {
                restart_pod_blocking(
                    &cluster,
                    &state,
                    pod,
                    timeout,
                    Some(worker_cancel.as_ref()),
                    false,
                )
            });
            let mut progress = worker_progress
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Err(error) = outcome {
                progress.error = Some(format!("{error:#}"));
            }
            progress.finished = true;
        });
        Self {
            handle: Some(handle),
            cancel,
            progress,
        }
    }

    fn snapshot(&self) -> (bool, Option<String>) {
        let progress = self
            .progress
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (progress.finished, progress.error.clone())
    }

    fn require_healthy(&self) -> Result<()> {
        if let (_, Some(error)) = self.snapshot() {
            bail!("rolling restart worker failed: {error}");
        }
        Ok(())
    }

    fn wait_finished(&mut self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            let (finished, error) = self.snapshot();
            if let Some(error) = error {
                bail!("rolling restart worker failed: {error}");
            }
            if finished {
                if let Some(handle) = self.handle.take() {
                    let _ = handle.join();
                }
                return Ok(());
            }
            ensure!(
                Instant::now() < deadline,
                "rolling restart did not finish within {timeout:?}"
            );
            sleep(POLL_INTERVAL);
        }
    }
}

impl Drop for RollingWorker {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

struct LifecycleFaultHandle {
    operation: LifecycleOperation,
    cluster: ClusterTestConfig,
    scenario: String,
    run_id: String,
    case_dir: PathBuf,
    statefulset: StatefulSetIdentity,
    expected_pods: usize,
    started_at_ms: u64,
    state: SharedState,
    /// Pods restarted while the workload runs; the runner pins its
    /// availability endpoint to a Pod outside this set.
    target_pods_during_workload: Vec<String>,
    deferred: Option<ObservedPod>,
    watch: Option<PodWatch>,
    worker: Option<RollingWorker>,
    operator_pause: Option<OperatorPause>,
    scaled_up: bool,
    evidence: Option<PodLifecycleEvidence>,
}

pub(in crate::fault) fn apply_fault(request: &FaultApplyRequest<'_>) -> Result<AppliedFault> {
    let config = request.config;
    let cluster = &config.cluster;
    let operation = LifecycleOperation::from_kind(request.injection.kind())?;
    let expected_pods = config.expected_rustfs_pod_count;
    let observation = observe_statefulset_topology(cluster, expected_pods)?;
    let case_dir = request.collector.case_dir(request.scenario.case_name);
    std::fs::create_dir_all(&case_dir)
        .with_context(|| format!("create case dir {}", case_dir.display()))?;
    let watch = PodWatch::start(cluster, case_dir.join(POD_LIFECYCLE_WATCH_ARTIFACT))?;
    let state: SharedState = Arc::new(Mutex::new(LifecycleState::default()));
    let mut handle = LifecycleFaultHandle {
        operation,
        cluster: cluster.clone(),
        scenario: request.scenario.name.clone(),
        run_id: request.run_id.to_string(),
        case_dir,
        statefulset: observation.statefulset.identity.clone(),
        expected_pods,
        started_at_ms: now_ms(),
        state: Arc::clone(&state),
        target_pods_during_workload: Vec::new(),
        deferred: None,
        watch: Some(watch),
        worker: None,
        operator_pause: None,
        scaled_up: false,
        evidence: None,
    };
    let pods = observation.pods;
    match operation {
        LifecycleOperation::GracefulPodRestart => {
            // Deterministic choice: the highest ordinal. The runner's survivor
            // selection picks the lexicographically smallest Pod name, which
            // this never targets.
            let target = pods
                .iter()
                .max_by_key(|pod| pod.ordinal)
                .context("no RustFS Pod to restart")?;
            handle.target_pods_during_workload = vec![target.name.clone()];
            initiate_pod_delete(cluster, &state, target, false)?;
        }
        LifecycleOperation::RollingRestart => {
            // A kubectl port-forward stays attached to the Pod it started on,
            // so with a port-forward endpoint the Pod the runner pins for the
            // availability contract (the smallest name) is restarted after the
            // workload instead of under it. A ClusterIP endpoint balances
            // across ready Pods and needs no deferral.
            let deferred = (!config.use_cluster_ip)
                .then(|| pods.iter().min_by(|a, b| a.name.cmp(&b.name)).cloned())
                .flatten();
            let mut during = pods
                .iter()
                .filter(|pod| deferred.as_ref().is_none_or(|d| d.uid != pod.uid))
                .cloned()
                .collect::<Vec<_>>();
            during.sort_by_key(|pod| std::cmp::Reverse(pod.ordinal));
            ensure!(
                !during.is_empty(),
                "rolling restart needs at least one Pod to restart under the workload"
            );
            handle.target_pods_during_workload =
                during.iter().map(|pod| pod.name.clone()).collect();
            handle.deferred = deferred;
            handle.worker = Some(RollingWorker::spawn(
                cluster.clone(),
                Arc::clone(&state),
                during,
                cluster.timeout,
            ));
        }
        LifecycleOperation::ColdRestart => {
            ensure!(
                observation
                    .statefulset
                    .identity
                    .pvc_retention_when_scaled
                    .as_deref()
                    .is_none_or(|policy| policy == "Retain"),
                "StatefulSet {} persistentVolumeClaimRetentionPolicy.whenScaled={:?} would delete data on scale-down; refusing the cold restart",
                observation.statefulset.identity.name,
                observation.statefulset.identity.pvc_retention_when_scaled
            );
            let deployment = config.operator_deployment.as_deref().with_context(|| {
                format!("cluster-cold-restart requires {OPERATOR_DEPLOYMENT_ENV}")
            })?;
            handle.operator_pause =
                Some(OperatorPause::pause(cluster, deployment, cluster.timeout)?);
            handle.target_pods_during_workload = pods.iter().map(|pod| pod.name.clone()).collect();
            let scale_down_requested_at_ms = now_ms();
            {
                let mut state = lock_state(&state);
                state.outage = Some(OutageEvidence {
                    scale_down_requested_at_ms,
                    all_pods_terminated_at_ms: None,
                    replica_observations: Vec::new(),
                    scale_up_requested_at_ms: None,
                    all_pods_ready_at_ms: None,
                });
                for pod in &pods {
                    state.begin_target(pod, scale_down_requested_at_ms, false);
                }
            }
            scale_statefulset_command(cluster, &observation.statefulset.identity.name, 0)?
                .run_checked()
                .context("scale the RustFS StatefulSet to zero")?;
        }
    }
    Ok(Box::new(handle))
}

impl LifecycleFaultHandle {
    /// One outage poll: fold Pod states in and prove `spec.replicas` is still
    /// zero. Any other value means an external controller fought the
    /// scale-down; the outage the scenario claims did not happen.
    fn sample_outage(&self) -> Result<(i64, usize)> {
        let pods = poll_targets(&self.cluster, &self.state)?;
        let statefulset = observe_statefulset(&self.cluster, &self.statefulset.name)?;
        let observed_at_ms = now_ms();
        let mut state = lock_state(&self.state);
        state.record_replica_sample(statefulset.spec_replicas, pods.len(), observed_at_ms);
        ensure!(
            statefulset.spec_replicas == 0,
            "StatefulSet {} spec.replicas is {} while the cold-restart outage should be held at zero; an external controller reverted the scale-down",
            self.statefulset.name,
            statefulset.spec_replicas
        );
        ensure!(
            statefulset.identity.uid == self.statefulset.uid,
            "StatefulSet {} uid changed from {} to {} during the outage",
            self.statefulset.name,
            self.statefulset.uid,
            statefulset.identity.uid
        );
        Ok((statefulset.spec_replicas, pods.len()))
    }

    fn require_outage_held(&self, stage: &str) -> Result<()> {
        let (_, pods) = self.sample_outage()?;
        ensure!(
            pods == 0,
            "{pods} RustFS Pod(s) exist at stage {stage:?} while the cold-restart outage should be held"
        );
        Ok(())
    }

    fn wait_outage(&self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            let (_, pods) = self.sample_outage()?;
            if pods == 0 && lock_state(&self.state).all_gone() {
                let mut state = lock_state(&self.state);
                if let Some(outage) = &mut state.outage
                    && outage.all_pods_terminated_at_ms.is_none()
                {
                    outage.all_pods_terminated_at_ms = Some(now_ms());
                }
                return Ok(());
            }
            ensure!(
                Instant::now() < deadline,
                "timed out after {timeout:?} waiting for every RustFS Pod to terminate ({pods} remaining)"
            );
            sleep(POLL_INTERVAL);
        }
    }

    fn scale_back_up(&mut self, timeout: Duration) -> Result<()> {
        let replicas = u32::try_from(self.expected_pods)?;
        {
            let mut state = lock_state(&self.state);
            if let Some(outage) = &mut state.outage {
                outage.scale_up_requested_at_ms = Some(now_ms());
            }
        }
        scale_statefulset_command(&self.cluster, &self.statefulset.name, replicas)?
            .run_checked()
            .context("scale the RustFS StatefulSet back up")?;
        self.scaled_up = true;
        wait_until(
            &self.cluster,
            &self.state,
            timeout,
            None,
            "every replacement RustFS Pod to become Ready after the cold restart",
            LifecycleState::all_replacements_ready,
        )?;
        let mut state = lock_state(&self.state);
        if let Some(outage) = &mut state.outage {
            outage.all_pods_ready_at_ms = Some(now_ms());
        }
        Ok(())
    }

    fn remove_inner(&mut self, timeout: Duration) -> Result<()> {
        match self.operation {
            LifecycleOperation::GracefulPodRestart => {
                let name = self.target_pods_during_workload[0].clone();
                wait_until(
                    &self.cluster,
                    &self.state,
                    timeout,
                    None,
                    &format!("replacement of Pod {name} to become Ready"),
                    |state| {
                        state
                            .target(&name)
                            .is_some_and(|target| target.replacement_ready_at_ms.is_some())
                    },
                )
            }
            LifecycleOperation::RollingRestart => {
                let targets = u32::try_from(self.target_pods_during_workload.len())?;
                if let Some(worker) = &mut self.worker {
                    worker.wait_finished(timeout.saturating_mul(targets.max(1)))?;
                }
                if let Some(deferred) = self.deferred.clone() {
                    restart_pod_blocking(
                        &self.cluster,
                        &self.state,
                        &deferred,
                        timeout,
                        None,
                        true,
                    )?;
                }
                Ok(())
            }
            LifecycleOperation::ColdRestart => {
                self.require_outage_held("fault-delete")?;
                self.scale_back_up(timeout)?;
                if let Some(pause) = &mut self.operator_pause {
                    pause.resume(timeout)?;
                }
                Ok(())
            }
        }
    }

    /// Stop the watch, merge its final Pod states with the polled samples,
    /// classify every termination, and persist the artifact.
    fn finalize_evidence(&mut self) -> Result<PodLifecycleEvidence> {
        if let Some(evidence) = &self.evidence {
            return Ok(evidence.clone());
        }
        if let Some(watch) = self.watch.take() {
            match watch.finish() {
                Ok(states) => lock_state(&self.state).absorb_watch(&states),
                Err(error) => {
                    eprintln!("warning: Pod lifecycle watch could not be read: {error:#}")
                }
            }
        }
        let statefulset_uid_after = observe_statefulset(&self.cluster, &self.statefulset.name)
            .map(|statefulset| statefulset.identity.uid)
            .ok();
        let (targets, outage) = {
            let mut state = lock_state(&self.state);
            state.classify_all();
            (state.targets.clone(), state.outage.clone())
        };
        let evidence = PodLifecycleEvidence {
            scenario: self.scenario.clone(),
            run_id: self.run_id.clone(),
            operation: self.operation,
            statefulset: self.statefulset.clone(),
            statefulset_uid_after,
            operator_pause: self
                .operator_pause
                .as_ref()
                .map(|pause| pause.evidence.clone()),
            targets,
            outage,
            started_at_ms: self.started_at_ms,
            completed_at_ms: now_ms(),
            violations: Vec::new(),
            passed: false,
        }
        .finalize();
        std::fs::write(
            self.case_dir.join(POD_LIFECYCLE_EVIDENCE_ARTIFACT),
            serde_json::to_string_pretty(&evidence)?,
        )
        .with_context(|| format!("write {POD_LIFECYCLE_EVIDENCE_ARTIFACT}"))?;
        self.evidence = Some(evidence.clone());
        Ok(evidence)
    }

    fn status_snapshot(&self, stage: &str) -> Result<FaultStatusSnapshot> {
        let pods = observe_pods(&self.cluster)?;
        let statefulset = observe_statefulset(&self.cluster, &self.statefulset.name)?;
        Ok(FaultStatusSnapshot {
            stage: stage.to_string(),
            resource_kind: Some("statefulset".to_string()),
            resource_name: Some(self.statefulset.name.clone()),
            chaos_status: None,
            dm_status: None,
            lifecycle_status: Some(LifecycleStatusSnapshot {
                operation: self.operation,
                statefulset_name: statefulset.identity.name,
                statefulset_uid: statefulset.identity.uid,
                spec_replicas: statefulset.spec_replicas,
                ready_replicas: statefulset.ready_replicas,
                target_pods: self.target_pods_during_workload.clone(),
                pods: pods
                    .iter()
                    .map(|pod| LifecyclePodStatus {
                        name: pod.name.clone(),
                        uid: pod.uid.clone(),
                        ready: pod.ready,
                        terminating: pod.terminating,
                        restart_count: pod.restart_count,
                    })
                    .collect(),
                observed_at_ms: now_ms(),
            }),
        })
    }
}

impl FaultLifecyclePort for LifecycleFaultHandle {
    fn wait_active(&self, timeout: Duration) -> Result<()> {
        match self.operation {
            LifecycleOperation::GracefulPodRestart => {
                let name = self.target_pods_during_workload[0].clone();
                wait_until(
                    &self.cluster,
                    &self.state,
                    timeout,
                    None,
                    &format!("Pod {name} to terminate after its graceful delete"),
                    |state| {
                        state
                            .target(&name)
                            .is_some_and(|target| target.old_uid_gone_at_ms.is_some())
                    },
                )
            }
            LifecycleOperation::RollingRestart => {
                let deadline = Instant::now() + timeout;
                loop {
                    if let Some(worker) = &self.worker {
                        worker.require_healthy()?;
                    }
                    if lock_state(&self.state).any_gone() {
                        return Ok(());
                    }
                    ensure!(
                        Instant::now() < deadline,
                        "timed out after {timeout:?} waiting for the first rolling-restart Pod to terminate"
                    );
                    sleep(POLL_INTERVAL);
                }
            }
            LifecycleOperation::ColdRestart => self.wait_outage(timeout),
        }
    }

    /// Lifecycle operations are not held states (except the cold-restart
    /// outage): a restart that already completed is still the fault under
    /// test, so this only proves the operation was started and has not failed.
    fn ensure_active(&self, stage: &str) -> Result<()> {
        match self.operation {
            LifecycleOperation::GracefulPodRestart => {
                let name = &self.target_pods_during_workload[0];
                ensure!(
                    lock_state(&self.state)
                        .target(name)
                        .is_some_and(|target| target.old_uid_gone_at_ms.is_some()),
                    "graceful restart of Pod {name} was not observed at stage {stage:?}"
                );
                Ok(())
            }
            LifecycleOperation::RollingRestart => self
                .worker
                .as_ref()
                .context("rolling restart worker is missing")?
                .require_healthy(),
            LifecycleOperation::ColdRestart => self.require_outage_held(stage),
        }
    }

    fn delete(&mut self, timeout: Duration) -> Result<()> {
        let removal = self.remove_inner(timeout);
        let evidence = self.finalize_evidence();
        removal?;
        let evidence = evidence?;
        if let Err(error) = evidence.require_success() {
            return Err(ClassifiedFaultFailure {
                classification: evidence.failure_classification(),
                message: format!("{error:#}"),
            }
            .into());
        }
        Ok(())
    }

    fn snapshot(&self, stage: &str) -> Result<FaultStatusSnapshot> {
        self.status_snapshot(stage)
    }

    fn failure_artifacts(&self) -> Option<&dyn FaultFailureArtifactSource> {
        Some(self)
    }
}

impl FaultFailureArtifactSource for LifecycleFaultHandle {
    fn collect_failure_artifacts(
        &self,
        collector: &ArtifactCollector,
        case_name: &str,
        suffix: &str,
    ) -> Result<()> {
        let kubectl = Kubectl::new(&self.cluster).namespaced(&self.cluster.test_namespace);
        for (file, command) in [
            (
                format!("statefulset-{suffix}.yaml"),
                kubectl.command([
                    "get",
                    "statefulset",
                    self.statefulset.name.as_str(),
                    "-o",
                    "yaml",
                ]),
            ),
            (
                format!("rustfs-pods-{suffix}.yaml"),
                kubectl.command([
                    "get",
                    "pod",
                    "-l",
                    kube::rustfs_tenant_selector(&self.cluster).as_str(),
                    "-o",
                    "yaml",
                ]),
            ),
            (
                format!("namespace-events-{suffix}.txt"),
                kubectl.command(["get", "events", "--sort-by=.lastTimestamp"]),
            ),
        ] {
            super::runtime::capture_command_artifact(collector, case_name, &file, command)?;
        }
        if let Some(evidence) = &self.evidence {
            collector.write_text(
                case_name,
                &format!("pod-lifecycle-evidence-{suffix}.json"),
                &serde_json::to_string_pretty(evidence)?,
            )?;
        }
        Ok(())
    }
}

impl Drop for LifecycleFaultHandle {
    fn drop(&mut self) {
        // Stop the worker before touching shared state; its Drop cancels it.
        self.worker.take();
        if self.operation == LifecycleOperation::ColdRestart && !self.scaled_up {
            match u32::try_from(self.expected_pods)
                .map_err(anyhow::Error::from)
                .and_then(|replicas| {
                    scale_statefulset_command(&self.cluster, &self.statefulset.name, replicas)
                })
                .and_then(|command| command.run_checked())
            {
                Ok(_) => eprintln!(
                    "warning: scaled StatefulSet {} back to {} replicas during cleanup",
                    self.statefulset.name, self.expected_pods
                ),
                Err(error) => eprintln!(
                    "warning: failed to scale StatefulSet {} back up during cleanup: {error:#}",
                    self.statefulset.name
                ),
            }
        }
        // OperatorPause resumes the operator in its own Drop.
    }
}

#[cfg(test)]
mod tests {
    use super::{LifecycleState, evidence::OutageEvidence, kube::ObservedPod};
    use crate::fault::backends::lifecycle::evidence::{
        ContainerTermination, TerminationClassification,
    };

    fn pod(name: &str, uid: &str, ready: bool) -> ObservedPod {
        ObservedPod {
            name: name.to_string(),
            uid: uid.to_string(),
            ordinal: super::kube::pod_ordinal(name),
            phase: "Running".to_string(),
            ready,
            terminating: false,
            deletion_timestamp: None,
            deletion_grace_period_seconds: None,
            termination_grace_period_seconds: 30,
            restart_count: 0,
            owner: None,
            rustfs_terminated: None,
        }
    }

    #[test]
    fn state_tracks_deletion_termination_and_replacement_readiness() {
        let mut state = LifecycleState::default();
        let old = pod("rustfs-3", "old-3", true);
        state.begin_target(&old, 1_000, false);

        let mut terminating = old.clone();
        terminating.terminating = true;
        terminating.deletion_timestamp = Some("2026-09-11T10:05:30Z".to_string());
        terminating.deletion_grace_period_seconds = Some(30);
        state.absorb(&[terminating.clone()], 2_000);
        assert_eq!(
            state.targets[0].sigterm_requested_at_ms,
            Some(super::evidence::parse_rfc3339_ms("2026-09-11T10:05:00Z").unwrap())
        );
        assert!(state.targets[0].terminated.is_none());

        let mut exited = terminating.clone();
        exited.rustfs_terminated = Some(ContainerTermination {
            exit_code: 0,
            signal: None,
            reason: Some("Completed".to_string()),
            message: None,
            started_at: None,
            finished_at: Some("2026-09-11T10:05:05Z".to_string()),
            container_id: None,
        });
        state.absorb(&[exited], 3_000);
        assert_eq!(state.targets[0].observation_source.as_deref(), Some("poll"));
        assert!(!state.any_gone());

        state.absorb(&[], 4_000);
        assert_eq!(state.targets[0].old_uid_gone_at_ms, Some(4_000));
        assert!(state.any_gone() && state.all_gone());
        assert!(!state.all_replacements_ready());

        let mut replacement = pod("rustfs-3", "new-3", false);
        replacement.restart_count = 1;
        state.absorb(&[replacement.clone()], 5_000);
        assert_eq!(state.targets[0].new_uid.as_deref(), Some("new-3"));
        assert_eq!(state.targets[0].restart_count_after, Some(1));
        assert!(state.targets[0].replacement_ready_at_ms.is_none());
        replacement.ready = true;
        state.absorb(&[replacement], 6_000);
        assert_eq!(state.targets[0].replacement_ready_at_ms, Some(6_000));
        assert!(state.all_replacements_ready());

        state.classify_all();
        assert_eq!(
            state.targets[0].classification,
            TerminationClassification::GracefulExit
        );
        assert_eq!(state.targets[0].termination_duration_ms, Some(5_000));
    }

    #[test]
    fn watch_states_fill_in_terminations_the_polls_missed() {
        let mut state = LifecycleState::default();
        let old = pod("rustfs-0", "old-0", true);
        state.begin_target(&old, 1_000, false);
        state.absorb(&[], 2_000);
        assert!(state.targets[0].terminated.is_none());
        let mut final_state = old.clone();
        final_state.deletion_timestamp = Some("2026-09-11T10:05:30Z".to_string());
        final_state.deletion_grace_period_seconds = Some(30);
        final_state.rustfs_terminated = Some(ContainerTermination {
            exit_code: 137,
            signal: Some(9),
            reason: Some("Error".to_string()),
            message: None,
            started_at: None,
            finished_at: Some("2026-09-11T10:05:30Z".to_string()),
            container_id: None,
        });
        state.absorb_watch(&[(old.uid.clone(), final_state)].into_iter().collect());
        assert_eq!(
            state.targets[0].observation_source.as_deref(),
            Some("watch")
        );
        state.classify_all();
        assert_eq!(
            state.targets[0].classification,
            TerminationClassification::KilledOnGraceTimeout
        );
        assert_eq!(state.targets[0].termination_duration_ms, Some(30_000));
    }

    #[test]
    fn replica_samples_are_recorded_on_change_and_periodically() {
        let mut state = LifecycleState {
            outage: Some(OutageEvidence {
                scale_down_requested_at_ms: 0,
                all_pods_terminated_at_ms: None,
                replica_observations: Vec::new(),
                scale_up_requested_at_ms: None,
                all_pods_ready_at_ms: None,
            }),
            ..LifecycleState::default()
        };
        state.record_replica_sample(0, 4, 1_000);
        state.record_replica_sample(0, 4, 1_500);
        state.record_replica_sample(0, 3, 2_000);
        state.record_replica_sample(0, 3, 7_500);
        state.record_replica_sample(4, 3, 7_600);
        let outage = state.outage.as_ref().unwrap();
        assert_eq!(outage.replica_observations.len(), 4);
        assert!(!outage.held_at_zero());
    }
}
