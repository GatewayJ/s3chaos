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
//! writes it with server-side apply (no force) and treats `spec.replicas`
//! and the Pod template annotations as its own fields. A `kubectl scale` or
//! `kubectl rollout restart` makes `kubectl-scale`/`kubectl-rollout` a
//! co-owner of those fields, so the operator's next apply conflicts (HTTP
//! 409, Tenant status `StatefulSetApplyFailed`) instead of converging, and the
//! harness would be racing an operator that keeps failing its reconcile. The
//! operator-safe primitive is deleting Pods with their default grace period:
//! the StatefulSet controller recreates each Pod with a new UID and nothing
//! the operator manages changes. Rolling restart is driven Pod by Pod from the
//! highest ordinal down, waiting for every replacement to become Ready first,
//! which is what the controller does for a rollout. Cold restart must hold
//! the outage across the workload, so it pauses the operator (scales its
//! Deployment to zero, an explicit opt-in through
//! `RUSTFS_FAULT_TEST_OPERATOR_DEPLOYMENT`), records the pause as annotations
//! on that Deployment so `fault-cleanup` can undo it even if the harness dies,
//! scales the StatefulSet to zero, and restores both afterwards. The scale
//! leaves `kubectl-scale` as a co-owner of the fixture StatefulSet's
//! `spec.replicas`, which is why the cold restart only runs on a fresh
//! Tenant fixture that the next run recreates.
//!
//! Every deleted Pod's final container state is captured from a streaming
//! `kubectl get --watch` plus status polls, because the Pod object disappears
//! right after the container exits and a replacement Pod carries no
//! `lastState` for it. The grace-timeout rule lives in `evidence.rs`.
//!
//! Load during shutdown: the single-Pod and rolling restarts consider the
//! fault active as soon as the graceful delete is accepted, so RustFS receives
//! SIGTERM while the workload runs (with a port-forward endpoint the client is
//! pinned to the smallest-name Pod, which the rolling restart therefore
//! restarts after the workload). The cold restart drains every Pod before the
//! workload starts because its contract is the held total outage, not a
//! loaded shutdown.

pub(in crate::fault) mod evidence;
pub(in crate::fault) mod kube;

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
        pods::rustfs_tenant_selector,
        preflight::{TargetStatefulSetPodProof, TargetStatefulSetProof},
        reporting::FaultStatusSnapshot,
        scenarios::{FaultIsolation, FaultScenario, scenario_spec},
    },
    framework::{artifacts::ArtifactCollector, config::ClusterTestConfig, kubectl::Kubectl},
};
use evidence::{
    ContainerTermination, LifecycleOperation, LifecyclePodStatus, LifecycleStatusSnapshot,
    OperatorPauseEvidence, OutageEvidence, POD_LIFECYCLE_EVIDENCE_ARTIFACT, PodLifecycleEvidence,
    PodTerminationEvidence, ReplicaObservation, StatefulSetIdentity, TerminationClassification,
    TerminationClassificationInput, classify_termination,
};
use kube::{
    GracefulDeletion, OPERATOR_PAUSE_REPLICAS_ANNOTATION, OPERATOR_PAUSE_RUN_ANNOTATION,
    ObservedDeployment, ObservedPod, ObservedStatefulSet, WatchedPod, annotate_deployment_command,
    auth_can_i_command, delete_pod_default_grace_command, final_pod_states, get_deployment_command,
    get_statefulset_command, list_deployments_command, list_pods_by_selector_command,
    list_rustfs_pods_command, parse_deployment, parse_pod_list, parse_statefulset,
    parse_watch_stream, remove_deployment_annotations_command, require_single_statefulset_owner,
    required_permissions, run_json, scale_deployment_command, scale_statefulset_command,
    verify_operator_identity, watch_rustfs_pods_command,
};

const POLL_INTERVAL: Duration = Duration::from_millis(250);
const REPLICA_SAMPLE_INTERVAL_MS: u64 = 5_000;
pub const POD_LIFECYCLE_WATCH_ARTIFACT: &str = "pod-lifecycle-watch.json";
pub const POD_LIFECYCLE_WATCH_STDERR_ARTIFACT: &str = "pod-lifecycle-watch.stderr.log";
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
    if operation == LifecycleOperation::Cold {
        let deployment = config.operator_deployment.as_deref().with_context(|| {
            format!(
                "cluster-cold-restart holds the outage by pausing the RustFS operator; set {OPERATOR_DEPLOYMENT_ENV} to the operator Deployment name in namespace {:?}",
                cluster.operator_namespace
            )
        })?;
        kube::ensure_dns1123_subdomain(deployment, OPERATOR_DEPLOYMENT_ENV)?;
    }
    let mut denied = Vec::new();
    for check in required_permissions(
        operation,
        &cluster.test_namespace,
        &cluster.operator_namespace,
    ) {
        let output = auth_can_i_command(cluster, &check)?.run()?;
        if output.stdout.trim() != "yes" {
            denied.push(format!(
                "{} {}{} in {} ({})",
                check.verb,
                check.resource,
                check
                    .subresource
                    .map(|subresource| format!("/{subresource}"))
                    .unwrap_or_default(),
                check.namespace,
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

/// `fault-cleanup` path: undo any operator pause a previous run left behind
/// (harness killed before its Drop ran). The record lives on the Deployment
/// itself, so no artifact context is needed; an unreadable record fails
/// closed instead of guessing.
pub(in crate::fault) fn restore_paused_operators(config: &FaultTestConfig) -> Result<Vec<String>> {
    let cluster = &config.cluster;
    let deployments = run_json(&list_deployments_command(
        cluster,
        &cluster.operator_namespace,
    )?)?;
    let mut restored = Vec::new();
    for item in deployments
        .pointer("/items")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
    {
        let deployment = parse_deployment(item)?;
        let Some(replicas) = deployment.paused_replicas()? else {
            continue;
        };
        kube::ensure_dns1123_subdomain(&deployment.name, "paused Deployment name")?;
        eprintln!(
            "restoring operator Deployment {}/{} left paused by a previous run to {replicas} replicas",
            cluster.operator_namespace, deployment.name
        );
        resume_deployment(
            cluster,
            &cluster.operator_namespace,
            &deployment.name,
            replicas,
            cluster.timeout,
        )?;
        restored.push(deployment.name);
    }
    Ok(restored)
}

fn resume_deployment(
    cluster: &ClusterTestConfig,
    namespace: &str,
    deployment: &str,
    replicas: u32,
    timeout: Duration,
) -> Result<u64> {
    scale_deployment_command(cluster, namespace, deployment, replicas)?.run_checked()?;
    let deadline = Instant::now() + timeout;
    loop {
        let observed = observe_deployment(cluster, namespace, deployment)?;
        if observed.available_replicas >= i64::from(replicas) {
            break;
        }
        ensure!(
            Instant::now() < deadline,
            "operator Deployment {namespace}/{deployment} did not become available again within {timeout:?} (available={}, wanted={replicas})",
            observed.available_replicas
        );
        sleep(POLL_INTERVAL);
    }
    remove_deployment_annotations_command(
        cluster,
        namespace,
        deployment,
        &[
            OPERATOR_PAUSE_REPLICAS_ANNOTATION,
            OPERATOR_PAUSE_RUN_ANNOTATION,
        ],
    )?
    .run_checked()?;
    Ok(now_ms())
}

pub(in crate::fault) struct StatefulSetObservation {
    pub(in crate::fault) statefulset: ObservedStatefulSet,
    pub(in crate::fault) pods: Vec<ObservedPod>,
    pub(in crate::fault) observed_at_ms: u64,
}

fn observe_pods(cluster: &ClusterTestConfig) -> Result<Vec<ObservedPod>> {
    parse_pod_list(&run_json(&list_rustfs_pods_command(cluster)?)?)
}

fn observe_statefulset(cluster: &ClusterTestConfig, name: &str) -> Result<ObservedStatefulSet> {
    parse_statefulset(&run_json(&get_statefulset_command(cluster, name)?)?)
}

fn observe_deployment(
    cluster: &ClusterTestConfig,
    namespace: &str,
    name: &str,
) -> Result<ObservedDeployment> {
    parse_deployment(&run_json(&get_deployment_command(
        cluster, namespace, name,
    )?)?)
    .with_context(|| format!("read Deployment {namespace}/{name}"))
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
        ensure!(
            pod.ordinal.is_some_and(|ordinal| ordinals.insert(ordinal)),
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

/// Which Pods restart under the workload and which one (if any) is deferred
/// until after it. A kubectl port-forward stays attached to the Pod it
/// started on, so with a port-forward endpoint the Pod the runner pins for
/// the availability contract (the lexicographically smallest name, matching
/// the runner's survivor choice) is restarted after the workload. A ClusterIP
/// endpoint balances across ready Pods and needs no deferral.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::fault) struct TargetPlan {
    pub(in crate::fault) during: Vec<ObservedPod>,
    pub(in crate::fault) deferred: Option<ObservedPod>,
}

pub(in crate::fault) fn plan_targets(
    pods: &[ObservedPod],
    operation: LifecycleOperation,
    use_cluster_ip: bool,
) -> Result<TargetPlan> {
    ensure!(!pods.is_empty(), "no RustFS Pod to restart");
    match operation {
        LifecycleOperation::GracefulPod => {
            // Deterministic choice: the highest ordinal, which the runner's
            // survivor selection (smallest name) never picks.
            let target = pods
                .iter()
                .max_by_key(|pod| pod.ordinal)
                .cloned()
                .expect("non-empty");
            Ok(TargetPlan {
                during: vec![target],
                deferred: None,
            })
        }
        LifecycleOperation::Rolling => {
            let deferred = (!use_cluster_ip)
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
                "rolling restart needs at least one Pod to restart under the workload; a single-Pod Tenant behind a port-forward cannot be rolled"
            );
            Ok(TargetPlan { during, deferred })
        }
        LifecycleOperation::Cold => Ok(TargetPlan {
            during: pods.to_vec(),
            deferred: None,
        }),
    }
}

/// The verdict of a completed removal: a removal error is still reported,
/// but when the evidence already explains it (a replacement that never came
/// back, a container that was SIGKILLed) the evidence's classification wins
/// so the run is not misattributed to the environment.
pub(in crate::fault) fn removal_verdict(
    removal: Result<()>,
    evidence: &PodLifecycleEvidence,
) -> Result<()> {
    match (removal, evidence.require_success()) {
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(evidence_error)) => Err(ClassifiedFaultFailure {
            classification: evidence.failure_classification(),
            message: format!("{evidence_error:#}"),
        }
        .into()),
        (Err(removal_error), Err(evidence_error)) => Err(ClassifiedFaultFailure {
            classification: evidence.failure_classification(),
            message: format!("{removal_error:#}; evidence: {evidence_error:#}"),
        }
        .into()),
        (Err(removal_error), Ok(())) => Err(removal_error),
    }
}

pub(in crate::fault) struct FaultApplyRequest<'a> {
    pub(in crate::fault) config: &'a FaultTestConfig,
    pub(in crate::fault) collector: &'a ArtifactCollector,
    pub(in crate::fault) scenario: &'a FaultScenario,
    pub(in crate::fault) injection: &'a FaultInjection,
    pub(in crate::fault) run_id: &'a str,
}

/// Fold one observation of the old Pod into its target: the graceful
/// deletion metadata once, and the container's terminated state once.
fn fold_old_pod(
    target: &mut PodTerminationEvidence,
    deletion: Option<&GracefulDeletion>,
    terminated: Option<&ContainerTermination>,
    source: &str,
) {
    if target.deletion_timestamp.is_none()
        && let Some(deletion) = deletion
    {
        target.deletion_timestamp = Some(deletion.deletion_timestamp.clone());
        target.deletion_grace_period_seconds = Some(deletion.deletion_grace_period_seconds);
        target.sigterm_requested_at_ms = deletion.sigterm_requested_at_ms();
    }
    if target.terminated.is_none()
        && let Some(terminated) = terminated
    {
        target.terminated = Some(terminated.clone());
        target.observation_source = Some(source.to_string());
    }
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
                Some(old) => fold_old_pod(
                    target,
                    old.graceful_deletion().as_ref(),
                    old.rustfs_terminated.as_ref(),
                    "poll",
                ),
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

    fn absorb_watch(&mut self, states: &BTreeMap<String, WatchedPod>) {
        for target in &mut self.targets {
            if let Some(old) = states.get(&target.old_uid) {
                fold_old_pod(
                    target,
                    old.graceful_deletion.as_ref(),
                    old.terminated.as_ref(),
                    "watch",
                );
            }
        }
    }

    fn classify_all(&mut self) {
        for target in &mut self.targets {
            let classified = classify_termination(&TerminationClassificationInput {
                grace_period_seconds: target.termination_grace_period_seconds,
                sigterm_reference_at_ms: target.sigterm_requested_at_ms,
                terminated: target.terminated.as_ref(),
            });
            target.classification = classified.classification;
            target.termination_duration_ms = classified.duration_ms;
        }
    }

    fn target(&self, name: &str) -> Option<&PodTerminationEvidence> {
        self.targets.iter().find(|target| target.pod_name == name)
    }

    /// The API server accepted the graceful delete (or the Pod is already
    /// gone): SIGTERM is on its way while the workload keeps running.
    fn delete_accepted(target: &PodTerminationEvidence) -> bool {
        target.deletion_timestamp.is_some() || target.old_uid_gone_at_ms.is_some()
    }

    fn any_delete_accepted(&self) -> bool {
        self.targets.iter().any(Self::delete_accepted)
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

/// Background `kubectl get --watch` capturing every Pod change to a file;
/// kubectl's own stderr goes to a separate file so a warning line can never
/// truncate the JSON stream.
struct PodWatch {
    child: Child,
    log_path: PathBuf,
}

impl PodWatch {
    fn start(cluster: &ClusterTestConfig, log_path: PathBuf, stderr_path: PathBuf) -> Result<Self> {
        let child = watch_rustfs_pods_command(cluster)?
            .spawn_background_with_logs(&log_path, &stderr_path)?;
        Ok(Self { child, log_path })
    }

    fn finish(mut self) -> Result<BTreeMap<String, WatchedPod>> {
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

/// Scale the RustFS operator Deployment to zero so it cannot apply the
/// StatefulSet while the outage is held. The pause is recorded on the
/// Deployment (`OPERATOR_PAUSE_*` annotations) before the scale so
/// `restore_paused_operators` can undo it without this process.
struct OperatorPause {
    cluster: ClusterTestConfig,
    evidence: OperatorPauseEvidence,
    resumed: bool,
}

impl OperatorPause {
    fn pause(
        cluster: &ClusterTestConfig,
        deployment: &str,
        image_match: &str,
        run_id: &str,
        timeout: Duration,
    ) -> Result<Self> {
        let namespace = cluster.operator_namespace.clone();
        let observed = observe_deployment(cluster, &namespace, deployment)?;
        let (image, identity_matched_by) = verify_operator_identity(&observed, image_match)?;
        ensure!(
            observed.paused_replicas()?.is_none(),
            "operator Deployment {namespace}/{deployment} still carries a pause record from a previous run; run fault-cleanup first"
        );
        let replicas_before = u32::try_from(observed.spec_replicas)
            .ok()
            .filter(|replicas| *replicas > 0)
            .with_context(|| {
                format!(
                    "operator Deployment {namespace}/{deployment} has {} replicas; refusing to pause an operator that is not running",
                    observed.spec_replicas
                )
            })?;
        ensure!(
            !observed.selector.is_empty(),
            "operator Deployment {namespace}/{deployment} has no selector to watch its Pods by"
        );
        annotate_deployment_command(
            cluster,
            &namespace,
            deployment,
            &[
                (
                    OPERATOR_PAUSE_REPLICAS_ANNOTATION,
                    replicas_before.to_string(),
                ),
                (OPERATOR_PAUSE_RUN_ANNOTATION, run_id.to_string()),
            ],
        )?
        .run_checked()
        .context("record the operator pause on its Deployment")?;
        let pause_requested_at_ms = now_ms();
        let mut pause = Self {
            cluster: cluster.clone(),
            evidence: OperatorPauseEvidence {
                namespace: namespace.clone(),
                deployment: deployment.to_string(),
                image,
                identity_matched_by,
                replicas_before,
                pause_requested_at_ms,
                operator_pods_gone_at_ms: None,
                resume_requested_at_ms: None,
                resumed_at_ms: None,
            },
            resumed: false,
        };
        if let Err(error) = scale_deployment_command(cluster, &namespace, deployment, 0)
            .and_then(|command| command.run_checked())
        {
            pause.resume(timeout).ok();
            return Err(error);
        }
        // Wait for the operator Pods themselves to be gone, terminating ones
        // included: a terminating operator can still write until it exits.
        let deadline = Instant::now() + timeout;
        loop {
            let pods = run_json(&list_pods_by_selector_command(
                cluster,
                &namespace,
                &observed.selector,
            )?)?;
            let remaining = pods
                .pointer("/items")
                .and_then(serde_json::Value::as_array)
                .map_or(0, Vec::len);
            if remaining == 0 {
                pause.evidence.operator_pods_gone_at_ms = Some(now_ms());
                return Ok(pause);
            }
            if Instant::now() >= deadline {
                let error = anyhow::anyhow!(
                    "operator Deployment {namespace}/{deployment} still has {remaining} Pod(s) {timeout:?} after scaling to zero"
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
        self.evidence.resume_requested_at_ms = Some(now_ms());
        // The scale request is durable even if availability is slow; treat the
        // operator as resumed from here so Drop does not repeat the request.
        self.resumed = true;
        let resumed_at_ms = resume_deployment(
            &self.cluster,
            &self.evidence.namespace,
            &self.evidence.deployment,
            self.evidence.replicas_before,
            timeout,
        )?;
        self.evidence.resumed_at_ms = Some(resumed_at_ms);
        Ok(())
    }
}

impl Drop for OperatorPause {
    fn drop(&mut self) {
        if self.resumed {
            return;
        }
        // Best effort only: if this fails the annotations stay on the
        // Deployment and `fault-cleanup` restores it.
        match scale_deployment_command(
            &self.cluster,
            &self.evidence.namespace,
            &self.evidence.deployment,
            self.evidence.replicas_before,
        )
        .and_then(|command| command.run_checked())
        .and_then(|_| {
            remove_deployment_annotations_command(
                &self.cluster,
                &self.evidence.namespace,
                &self.evidence.deployment,
                &[
                    OPERATOR_PAUSE_REPLICAS_ANNOTATION,
                    OPERATOR_PAUSE_RUN_ANNOTATION,
                ],
            )?
            .run_checked()
        }) {
            Ok(_) => eprintln!(
                "warning: resumed operator Deployment {}/{} during cleanup",
                self.evidence.namespace, self.evidence.deployment
            ),
            Err(error) => eprintln!(
                "warning: failed to resume operator Deployment {}/{} during cleanup; run fault-cleanup or scale it back to {} replicas manually: {error:#}",
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

fn wait_for_target(
    cluster: &ClusterTestConfig,
    state: &SharedState,
    timeout: Duration,
    cancel: Option<&AtomicBool>,
    name: &str,
    description: &str,
    condition: fn(&PodTerminationEvidence) -> bool,
) -> Result<()> {
    wait_until(cluster, state, timeout, cancel, description, |state| {
        state.target(name).is_some_and(condition)
    })
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
    wait_for_target(
        cluster,
        state,
        timeout,
        cancel,
        &pod.name,
        &format!("Pod {} (uid {}) to terminate", pod.name, pod.uid),
        |target| target.old_uid_gone_at_ms.is_some(),
    )?;
    wait_for_target(
        cluster,
        state,
        timeout,
        cancel,
        &pod.name,
        &format!("replacement of Pod {} to become Ready", pod.name),
        |target| target.replacement_ready_at_ms.is_some(),
    )
}

struct RollingWorker {
    handle: Option<JoinHandle<Result<()>>>,
    cancel: Arc<AtomicBool>,
    outcome: Option<Result<()>>,
}

impl RollingWorker {
    fn spawn(
        cluster: ClusterTestConfig,
        state: SharedState,
        pods: Vec<ObservedPod>,
        timeout: Duration,
    ) -> Self {
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);
        let handle = std::thread::spawn(move || {
            pods.iter().try_for_each(|pod| {
                restart_pod_blocking(
                    &cluster,
                    &state,
                    pod,
                    timeout,
                    Some(worker_cancel.as_ref()),
                    false,
                )
            })
        });
        Self {
            handle: Some(handle),
            cancel,
            outcome: None,
        }
    }

    /// Collect the thread's result once it has finished; a panic is an error
    /// like any other so it can never pass silently.
    fn poll(&mut self) -> Option<&Result<()>> {
        if self.outcome.is_none()
            && let Some(handle) = &self.handle
            && handle.is_finished()
        {
            let outcome = match self.handle.take().expect("handle present").join() {
                Ok(result) => result,
                Err(panic) => Err(anyhow::anyhow!(
                    "rolling restart worker panicked: {}",
                    panic
                        .downcast_ref::<String>()
                        .cloned()
                        .or_else(|| panic.downcast_ref::<&str>().map(|s| (*s).to_string()))
                        .unwrap_or_else(|| "non-string panic payload".to_string())
                )),
            };
            self.outcome = Some(outcome);
        }
        self.outcome.as_ref()
    }

    fn require_healthy(&mut self) -> Result<()> {
        if let Some(Err(error)) = self.poll() {
            bail!("rolling restart worker failed: {error:#}");
        }
        Ok(())
    }

    fn wait_finished(&mut self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            match self.poll() {
                Some(Ok(())) => return Ok(()),
                Some(Err(error)) => bail!("rolling restart worker failed: {error:#}"),
                None => {}
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
    worker: Mutex<Option<RollingWorker>>,
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
    let watch = PodWatch::start(
        cluster,
        case_dir.join(POD_LIFECYCLE_WATCH_ARTIFACT),
        case_dir.join(POD_LIFECYCLE_WATCH_STDERR_ARTIFACT),
    )?;
    let state: SharedState = Arc::new(Mutex::new(LifecycleState::default()));
    let plan = plan_targets(&observation.pods, operation, config.use_cluster_ip)?;
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
        target_pods_during_workload: plan.during.iter().map(|pod| pod.name.clone()).collect(),
        deferred: plan.deferred,
        watch: Some(watch),
        worker: Mutex::new(None),
        operator_pause: None,
        scaled_up: false,
        evidence: None,
    };
    match operation {
        LifecycleOperation::GracefulPod => {
            initiate_pod_delete(cluster, &state, &plan.during[0], false)?;
        }
        LifecycleOperation::Rolling => {
            handle.worker = Mutex::new(Some(RollingWorker::spawn(
                cluster.clone(),
                Arc::clone(&state),
                plan.during,
                cluster.timeout,
            )));
        }
        LifecycleOperation::Cold => {
            // The scale leaves kubectl-scale co-owning spec.replicas of the
            // fixture StatefulSet; only a fixture the next run recreates may
            // carry that residue.
            let isolation = scenario_spec(&request.scenario.name)?.isolation;
            ensure!(
                isolation == FaultIsolation::FreshTenant,
                "cold restart requires a fresh Tenant fixture (scenario isolation is {:?}); kubectl scale leaves the StatefulSet spec.replicas co-owned by kubectl-scale",
                isolation
            );
            observation
                .statefulset
                .identity
                .require_cold_restart_eligible()?;
            let deployment = config.operator_deployment.as_deref().with_context(|| {
                format!("cluster-cold-restart requires {OPERATOR_DEPLOYMENT_ENV}")
            })?;
            handle.operator_pause = Some(OperatorPause::pause(
                cluster,
                deployment,
                &config.operator_image_match,
                request.run_id,
                cluster.timeout,
            )?);
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
                for pod in &plan.during {
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
    fn with_worker<T>(&self, f: impl FnOnce(&mut RollingWorker) -> Result<T>) -> Result<T> {
        let mut worker = self
            .worker
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        f(worker
            .as_mut()
            .context("rolling restart worker is missing")?)
    }

    /// One outage poll: fold Pod states in and prove `spec.replicas` is still
    /// zero. Any other value means something else wrote the scale; the outage
    /// the scenario claims did not happen.
    fn sample_outage(&self) -> Result<(i64, usize)> {
        let pods = poll_targets(&self.cluster, &self.state)?;
        let statefulset = observe_statefulset(&self.cluster, &self.statefulset.name)?;
        let observed_at_ms = now_ms();
        let mut state = lock_state(&self.state);
        state.record_replica_sample(statefulset.spec_replicas, pods.len(), observed_at_ms);
        ensure!(
            statefulset.spec_replicas == 0,
            "StatefulSet {} spec.replicas is {} while the cold-restart outage should be held at zero; something else wrote the scale",
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
            LifecycleOperation::GracefulPod => {
                let name = self.target_pods_during_workload[0].clone();
                wait_for_target(
                    &self.cluster,
                    &self.state,
                    timeout,
                    None,
                    &name,
                    &format!("Pod {name} to terminate"),
                    |target| target.old_uid_gone_at_ms.is_some(),
                )?;
                wait_for_target(
                    &self.cluster,
                    &self.state,
                    timeout,
                    None,
                    &name,
                    &format!("replacement of Pod {name} to become Ready"),
                    |target| target.replacement_ready_at_ms.is_some(),
                )
            }
            LifecycleOperation::Rolling => {
                let targets = u32::try_from(self.target_pods_during_workload.len())?;
                self.with_worker(|worker| {
                    worker.wait_finished(timeout.saturating_mul(targets.max(1)))
                })?;
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
            LifecycleOperation::Cold => {
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
    /// Active means the shutdown is under way, not finished: the single-Pod
    /// and rolling restarts return as soon as the API server accepted the
    /// graceful delete so SIGTERM lands while the workload runs; the cold
    /// restart waits for every Pod to be gone because its contract is the
    /// held outage.
    fn wait_active(&self, timeout: Duration) -> Result<()> {
        match self.operation {
            LifecycleOperation::GracefulPod => {
                let name = self.target_pods_during_workload[0].clone();
                wait_for_target(
                    &self.cluster,
                    &self.state,
                    timeout,
                    None,
                    &name,
                    &format!("the graceful delete of Pod {name} to be accepted"),
                    LifecycleState::delete_accepted,
                )
            }
            LifecycleOperation::Rolling => {
                let deadline = Instant::now() + timeout;
                loop {
                    self.with_worker(RollingWorker::require_healthy)?;
                    if lock_state(&self.state).any_delete_accepted() {
                        return Ok(());
                    }
                    ensure!(
                        Instant::now() < deadline,
                        "timed out after {timeout:?} waiting for the first rolling-restart delete to be accepted"
                    );
                    sleep(POLL_INTERVAL);
                }
            }
            LifecycleOperation::Cold => self.wait_outage(timeout),
        }
    }

    /// Lifecycle operations are not held states (except the cold-restart
    /// outage): a restart that already completed is still the fault under
    /// test, so this only proves the operation was started and has not failed.
    fn ensure_active(&self, stage: &str) -> Result<()> {
        match self.operation {
            LifecycleOperation::GracefulPod => {
                let name = &self.target_pods_during_workload[0];
                ensure!(
                    lock_state(&self.state)
                        .target(name)
                        .is_some_and(LifecycleState::delete_accepted),
                    "graceful delete of Pod {name} was not accepted at stage {stage:?}"
                );
                Ok(())
            }
            LifecycleOperation::Rolling => self.with_worker(RollingWorker::require_healthy),
            LifecycleOperation::Cold => self.require_outage_held(stage),
        }
    }

    fn delete(&mut self, timeout: Duration) -> Result<()> {
        let removal = self.remove_inner(timeout);
        let evidence = self.finalize_evidence()?;
        removal_verdict(removal, &evidence)
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
                    rustfs_tenant_selector(&self.cluster).as_str(),
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
        self.worker
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if self.operation == LifecycleOperation::Cold && !self.scaled_up {
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
    use super::{
        LifecycleState,
        evidence::{
            ContainerTermination, LifecycleOperation, OutageEvidence, PodLifecycleEvidence,
            StatefulSetIdentity, TerminationClassification,
        },
        kube::{GracefulDeletion, ObservedPod, WatchedPod},
        plan_targets, removal_verdict,
    };
    use crate::fault::fault_lifecycle::removal_failure_classification;

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

    fn exited(exit_code: i64, finished_at: &str) -> ContainerTermination {
        ContainerTermination {
            exit_code,
            signal: (exit_code == 137).then_some(9),
            reason: Some(if exit_code == 0 { "Completed" } else { "Error" }.to_string()),
            message: None,
            started_at: None,
            finished_at: Some(finished_at.to_string()),
            container_id: None,
        }
    }

    #[test]
    fn state_tracks_deletion_termination_and_replacement_readiness() {
        let mut state = LifecycleState::default();
        let old = pod("rustfs-3", "old-3", true);
        state.begin_target(&old, 1_000, false);
        assert!(!state.any_delete_accepted());

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
        assert!(state.any_delete_accepted(), "SIGTERM is under way");
        assert!(!state.all_gone());

        let mut exited_pod = terminating.clone();
        exited_pod.rustfs_terminated = Some(exited(0, "2026-09-11T10:05:05Z"));
        state.absorb(&[exited_pod.clone()], 3_000);
        assert_eq!(state.targets[0].observation_source.as_deref(), Some("poll"));

        // kubelet's final grace-0 rewrite must not replace the graceful
        // deletion metadata already captured.
        let mut final_delete = exited_pod;
        final_delete.deletion_timestamp = Some("2026-09-11T10:05:06Z".to_string());
        final_delete.deletion_grace_period_seconds = Some(0);
        state.absorb(&[final_delete], 3_500);
        assert_eq!(state.targets[0].deletion_grace_period_seconds, Some(30));

        state.absorb(&[], 4_000);
        assert_eq!(state.targets[0].old_uid_gone_at_ms, Some(4_000));
        assert!(state.all_gone());
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
        // Only a grace-0 final document was polled: no SIGTERM reference yet.
        let mut final_delete = old.clone();
        final_delete.deletion_timestamp = Some("2026-09-11T10:05:31Z".to_string());
        final_delete.deletion_grace_period_seconds = Some(0);
        state.absorb(&[final_delete], 1_500);
        state.absorb(&[], 2_000);
        assert!(state.targets[0].terminated.is_none());
        assert!(state.targets[0].deletion_timestamp.is_none());
        let watched = WatchedPod {
            last: old.clone(),
            graceful_deletion: Some(GracefulDeletion {
                deletion_timestamp: "2026-09-11T10:05:30Z".to_string(),
                deletion_grace_period_seconds: 30,
            }),
            terminated: Some(exited(137, "2026-09-11T10:05:30Z")),
        };
        state.absorb_watch(&[(old.uid.clone(), watched)].into_iter().collect());
        assert_eq!(
            state.targets[0].observation_source.as_deref(),
            Some("watch")
        );
        assert_eq!(state.targets[0].deletion_grace_period_seconds, Some(30));
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

    #[test]
    fn target_plan_orders_ordinals_and_defers_the_pinned_pod_only_for_port_forwards() {
        let pods = (0..4)
            .map(|ordinal| {
                pod(
                    &format!("tenant-primary-{ordinal}"),
                    &format!("u{ordinal}"),
                    true,
                )
            })
            .collect::<Vec<_>>();
        let names =
            |plan: &[ObservedPod]| plan.iter().map(|pod| pod.name.clone()).collect::<Vec<_>>();
        let port_forward = plan_targets(&pods, LifecycleOperation::Rolling, false).unwrap();
        assert_eq!(
            names(&port_forward.during),
            ["tenant-primary-3", "tenant-primary-2", "tenant-primary-1"]
        );
        assert_eq!(
            port_forward.deferred.map(|pod| pod.name).as_deref(),
            Some("tenant-primary-0")
        );
        let cluster_ip = plan_targets(&pods, LifecycleOperation::Rolling, true).unwrap();
        assert_eq!(
            names(&cluster_ip.during),
            [
                "tenant-primary-3",
                "tenant-primary-2",
                "tenant-primary-1",
                "tenant-primary-0"
            ]
        );
        assert!(cluster_ip.deferred.is_none());
        let single = plan_targets(&pods, LifecycleOperation::GracefulPod, false).unwrap();
        assert_eq!(names(&single.during), ["tenant-primary-3"]);
        assert!(single.deferred.is_none());
        let cold = plan_targets(&pods, LifecycleOperation::Cold, false).unwrap();
        assert_eq!(cold.during.len(), 4);
        assert!(cold.deferred.is_none());
        // A single Pod behind a port-forward has nothing to roll under load.
        let error = plan_targets(&pods[..1], LifecycleOperation::Rolling, false)
            .expect_err("nothing to restart under the workload");
        assert!(error.to_string().contains("cannot be rolled"), "{error}");
        assert!(
            plan_targets(&pods[..1], LifecycleOperation::Rolling, true)
                .unwrap()
                .deferred
                .is_none()
        );
        assert!(plan_targets(&[], LifecycleOperation::GracefulPod, false).is_err());
    }

    fn passing_evidence(replacement_ready: bool) -> PodLifecycleEvidence {
        evidence_with_exit(replacement_ready, 0, "2026-09-11T10:05:02Z")
    }

    fn evidence_with_exit(
        replacement_ready: bool,
        exit_code: i64,
        finished_at: &str,
    ) -> PodLifecycleEvidence {
        let sigterm = super::evidence::parse_rfc3339_ms("2026-09-11T10:05:00Z").unwrap();
        let mut state = LifecycleState::default();
        let old = pod("rustfs-1", "old-1", true);
        state.begin_target(&old, sigterm - 100, false);
        let mut terminating = old;
        terminating.deletion_timestamp = Some("2026-09-11T10:05:30Z".to_string());
        terminating.deletion_grace_period_seconds = Some(30);
        terminating.rustfs_terminated = Some(exited(exit_code, finished_at));
        state.absorb(&[terminating], sigterm + 1_000);
        state.absorb(&[], sigterm + 3_000);
        let mut replacement = pod("rustfs-1", "new-1", replacement_ready);
        replacement.restart_count = 0;
        state.absorb(&[replacement], sigterm + 20_000);
        state.classify_all();
        PodLifecycleEvidence {
            scenario: "pod-graceful-restart-one".to_string(),
            run_id: "run-1".to_string(),
            operation: LifecycleOperation::GracefulPod,
            statefulset: StatefulSetIdentity {
                name: "tenant".to_string(),
                uid: "sts".to_string(),
                namespace: "ns".to_string(),
                replicas: 1,
                pod_management_policy: Some("Parallel".to_string()),
                update_strategy: None,
                pvc_retention_when_scaled: None,
                pvc_retention_when_deleted: None,
                termination_grace_period_seconds: 30,
                current_revision: None,
                update_revision: None,
            },
            statefulset_uid_after: Some("sts".to_string()),
            operator_pause: None,
            targets: state.targets,
            outage: None,
            started_at_ms: sigterm - 500,
            completed_at_ms: sigterm + 30_000,
            violations: Vec::new(),
            passed: false,
        }
        .finalize()
    }

    #[test]
    fn removal_verdict_prefers_the_evidence_classification_over_a_wait_timeout() {
        let clean = passing_evidence(true);
        assert!(clean.passed, "{:?}", clean.violations);
        removal_verdict(Ok(()), &clean).expect("clean restart");
        // A removal error with clean evidence stays an environment error.
        let error = removal_verdict(Err(anyhow::anyhow!("kubectl timed out")), &clean)
            .expect_err("removal error");
        assert_eq!(
            removal_failure_classification(&error),
            "environment_or_fault_backend"
        );
        // A replacement that never became Ready surfaces as the product /
        // environment classification even though the removal timed out.
        let never_ready = passing_evidence(false);
        assert!(!never_ready.passed);
        let error = removal_verdict(
            Err(anyhow::anyhow!(
                "timed out after 300s waiting for replacement of Pod rustfs-1 to become Ready"
            )),
            &never_ready,
        )
        .expect_err("never ready");
        assert_eq!(
            removal_failure_classification(&error),
            "product_or_environment"
        );
        assert!(
            error.to_string().contains("timed out")
                && error.to_string().contains("never became Ready"),
            "{error:#}"
        );
        // Failing evidence without a removal error is classified the same way.
        let error = removal_verdict(Ok(()), &never_ready).expect_err("never ready");
        assert_eq!(
            removal_failure_classification(&error),
            "product_or_environment"
        );
        // A grace timeout wins over everything.
        let killed = evidence_with_exit(true, 137, "2026-09-11T10:05:30Z");
        assert_eq!(
            killed.targets[0].classification,
            TerminationClassification::KilledOnGraceTimeout
        );
        let error = removal_verdict(Ok(()), &killed).expect_err("SIGKILL at grace expiry");
        assert_eq!(
            removal_failure_classification(&error),
            "graceful_shutdown_failed"
        );
    }
}
