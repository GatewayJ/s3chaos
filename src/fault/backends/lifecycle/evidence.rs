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

//! Typed evidence for kubectl-driven Pod lifecycle faults: what was
//! restarted, how each RustFS container left, and whether the exit was
//! graceful. Everything here is pure so the classification rule and the
//! artifact contract are unit-testable without a cluster.

use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::fault::plan::FaultKind;

pub const POD_LIFECYCLE_EVIDENCE_ARTIFACT: &str = "pod-lifecycle-evidence.json";
/// Kubernetes default when the Pod spec omits `terminationGracePeriodSeconds`.
pub const DEFAULT_TERMINATION_GRACE_PERIOD_SECONDS: u64 = 30;
/// Kubernetes object timestamps are RFC 3339 with second precision, so any
/// comparison between them tolerates one second of rounding.
pub const TIMESTAMP_TOLERANCE_MS: u64 = 1_000;
/// Failure classification for a RustFS container that did not leave cleanly
/// on SIGTERM within its grace period; a product defect, not an environment
/// problem.
pub const GRACEFUL_SHUTDOWN_FAILED_CLASSIFICATION: &str = "graceful_shutdown_failed";
/// Failure classification for a replacement Pod that never became Ready or
/// restarted its container while starting (rustfs/rustfs#6573 family): the
/// product could not come back, but node pressure or image pulls can produce
/// the same symptom, so the domain stays shared.
pub const REPLACEMENT_NOT_READY_CLASSIFICATION: &str = "product_or_environment";
const HARNESS_CLASSIFICATION: &str = "test_or_environment";

/// The restart shapes; serialized names keep the `-restart` suffix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LifecycleOperation {
    /// Delete one Pod with its default grace period; the StatefulSet
    /// controller recreates it.
    #[serde(rename = "graceful-pod-restart")]
    GracefulPod,
    /// Delete every Pod one at a time from the highest ordinal down, waiting
    /// for each replacement to become Ready before the next deletion.
    #[serde(rename = "rolling-restart")]
    Rolling,
    /// Scale the StatefulSet to zero, hold the outage, and scale it back.
    #[serde(rename = "cold-restart")]
    Cold,
}

impl LifecycleOperation {
    pub fn from_kind(kind: FaultKind) -> Result<Self> {
        match kind {
            FaultKind::RustfsServerPodGracefulRestart => Ok(Self::GracefulPod),
            FaultKind::RustfsServerRollingRestart => Ok(Self::Rolling),
            FaultKind::RustfsServerColdRestart => Ok(Self::Cold),
            other => bail!(
                "fault kind {} is not a Kubernetes lifecycle operation",
                other.as_str()
            ),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::GracefulPod => "graceful-pod-restart",
            Self::Rolling => "rolling-restart",
            Self::Cold => "cold-restart",
        }
    }

    pub fn restarts_every_pod(self) -> bool {
        matches!(self, Self::Rolling | Self::Cold)
    }
}

/// The StatefulSet that owns the fault-test RustFS Pods, as observed
/// immediately before the lifecycle operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatefulSetIdentity {
    pub name: String,
    pub uid: String,
    pub namespace: String,
    pub replicas: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pod_management_policy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_strategy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pvc_retention_when_scaled: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pvc_retention_when_deleted: Option<String>,
    pub termination_grace_period_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_revision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_revision: Option<String>,
}

impl StatefulSetIdentity {
    /// A cold restart scales to zero and back: the claims must survive the
    /// scale-down, and every replacement must be created at once because
    /// RustFS readiness needs its peers (under `OrderedReady` ordinal 1 is
    /// never created while ordinal 0 waits for it, wedging the Tenant).
    pub fn require_cold_restart_eligible(&self) -> Result<()> {
        ensure!(
            self.pvc_retention_when_scaled
                .as_deref()
                .is_none_or(|policy| policy == "Retain"),
            "StatefulSet {} persistentVolumeClaimRetentionPolicy.whenScaled={:?} would delete data on scale-down; refusing the cold restart",
            self.name,
            self.pvc_retention_when_scaled
        );
        ensure!(
            self.pod_management_policy.as_deref() == Some("Parallel"),
            "StatefulSet {} podManagementPolicy is {:?}; a cold restart requires Parallel so every RustFS Pod is recreated at once",
            self.name,
            self.pod_management_policy
        );
        Ok(())
    }
}

/// Final `state.terminated` of the RustFS container in a deleted Pod.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContainerTermination {
    pub exit_code: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_id: Option<String>,
}

/// How the RustFS container left when its Pod was deleted.
///
/// Rule (inputs: effective grace period G, SIGTERM reference time T taken
/// from the graceful delete's `deletionTimestamp - deletionGracePeriodSeconds`,
/// final terminated state with exit code E, signal S, reason R, finishedAt F;
/// duration D = F - T, tolerance 1s for second-granular timestamps):
///
/// - no terminated state or no SIGTERM reference observed -> `unobserved`
///   (harness failure);
/// - R == "OOMKilled" -> `oom_killed`;
/// - E == 0 and D <= G + 1s -> `graceful_exit` (the only PASS);
/// - E == 0 and D > G + 1s -> `inconsistent_timing` (kubelet would have
///   SIGKILLed at G, so the timestamps contradict each other; harness failure);
/// - E == 137 or S == 9 (SIGKILL) and D + 1s >= G -> `killed_on_grace_timeout`
///   (RustFS ignored SIGTERM for the whole grace period; product failure);
/// - E == 137 or S == 9 and D + 1s < G -> `killed_before_grace_expired` (an
///   external kill; not attributable to the shutdown path);
/// - E == 143 or S == 15 -> `terminated_by_signal_default` (no SIGTERM
///   handler, the default action killed the process; product failure);
/// - any other E -> `error_exit` (product failure).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminationClassification {
    GracefulExit,
    KilledOnGraceTimeout,
    KilledBeforeGraceExpired,
    OomKilled,
    TerminatedBySignalDefault,
    ErrorExit,
    InconsistentTiming,
    Unobserved,
}

impl TerminationClassification {
    pub fn is_graceful(self) -> bool {
        matches!(self, Self::GracefulExit)
    }

    /// Failure classification the run records when this outcome is observed.
    pub fn failure_classification(self) -> &'static str {
        match self {
            Self::GracefulExit => unreachable!("graceful exits do not fail the run"),
            Self::KilledOnGraceTimeout | Self::TerminatedBySignalDefault | Self::ErrorExit => {
                GRACEFUL_SHUTDOWN_FAILED_CLASSIFICATION
            }
            Self::KilledBeforeGraceExpired | Self::OomKilled => "product_or_environment",
            Self::InconsistentTiming | Self::Unobserved => HARNESS_CLASSIFICATION,
        }
    }
}

pub struct TerminationClassificationInput<'a> {
    pub grace_period_seconds: u64,
    pub sigterm_reference_at_ms: Option<u64>,
    pub terminated: Option<&'a ContainerTermination>,
}

pub struct ClassifiedTermination {
    pub classification: TerminationClassification,
    pub duration_ms: Option<u64>,
}

const UNOBSERVED: ClassifiedTermination = ClassifiedTermination {
    classification: TerminationClassification::Unobserved,
    duration_ms: None,
};

pub fn classify_termination(input: &TerminationClassificationInput<'_>) -> ClassifiedTermination {
    let (Some(terminated), Some(sigterm_at_ms)) = (input.terminated, input.sigterm_reference_at_ms)
    else {
        return UNOBSERVED;
    };
    let Some(finished_at_ms) = terminated
        .finished_at
        .as_deref()
        .and_then(|value| parse_rfc3339_ms(value).ok())
    else {
        return UNOBSERVED;
    };
    if finished_at_ms + TIMESTAMP_TOLERANCE_MS < sigterm_at_ms {
        return ClassifiedTermination {
            classification: TerminationClassification::InconsistentTiming,
            duration_ms: None,
        };
    }
    let duration_ms = finished_at_ms.saturating_sub(sigterm_at_ms);
    let grace_ms = input.grace_period_seconds.saturating_mul(1_000);
    let reason = terminated.reason.as_deref().unwrap_or_default();
    let sigkill = terminated.exit_code == 137 || terminated.signal == Some(9);
    let sigterm_default = terminated.exit_code == 143 || terminated.signal == Some(15);
    let classification = if reason == "OOMKilled" {
        TerminationClassification::OomKilled
    } else if terminated.exit_code == 0 {
        if duration_ms <= grace_ms + TIMESTAMP_TOLERANCE_MS {
            TerminationClassification::GracefulExit
        } else {
            TerminationClassification::InconsistentTiming
        }
    } else if sigkill {
        if duration_ms + TIMESTAMP_TOLERANCE_MS >= grace_ms {
            TerminationClassification::KilledOnGraceTimeout
        } else {
            TerminationClassification::KilledBeforeGraceExpired
        }
    } else if sigterm_default {
        TerminationClassification::TerminatedBySignalDefault
    } else {
        TerminationClassification::ErrorExit
    };
    ClassifiedTermination {
        classification,
        duration_ms: Some(duration_ms),
    }
}

/// Parse an RFC 3339 timestamp as Unix epoch milliseconds.
pub fn parse_rfc3339_ms(value: &str) -> Result<u64> {
    let parsed =
        time::OffsetDateTime::parse(value.trim(), &time::format_description::well_known::Rfc3339)
            .map_err(|error| anyhow::anyhow!("parse timestamp {value:?}: {error}"))?;
    let millis = parsed.unix_timestamp_nanos() / 1_000_000;
    u64::try_from(millis).map_err(|_| anyhow::anyhow!("timestamp {value:?} predates the epoch"))
}

/// A held total outage serves nothing: a family that answered a request
/// (2xx or 404) or that was never attempted is a contract violation.
pub fn total_outage_violation(
    family: &str,
    ok: usize,
    not_found: usize,
    total: usize,
) -> Option<String> {
    if total == 0 {
        return Some(format!(
            "cold-restart outage evidence is incomplete: {family} was never attempted while the StatefulSet was scaled to zero"
        ));
    }
    (ok > 0 || not_found > 0).then(|| {
        format!(
            "cold-restart outage was not total: {family} answered {ok} request(s) with success and {not_found} with 404 while no RustFS Pod should exist"
        )
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PodTerminationEvidence {
    pub pod_name: String,
    pub ordinal: u32,
    pub old_uid: String,
    pub restart_count_before: u64,
    pub termination_grace_period_seconds: u64,
    /// Harness clock when the delete request was issued.
    pub delete_requested_at_ms: u64,
    /// From the graceful delete (the first observation with a positive
    /// `deletionGracePeriodSeconds`); kubelet's final delete rewrites both to
    /// now/0 and is ignored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deletion_timestamp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deletion_grace_period_seconds: Option<i64>,
    /// `deletionTimestamp - deletionGracePeriodSeconds`: the API server
    /// accepted the graceful delete and kubelet sends SIGTERM from here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sigterm_requested_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminated: Option<ContainerTermination>,
    /// `"watch"` when the final state came from the streaming Pod watch,
    /// `"poll"` when a status poll caught it before the Pod object vanished.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub termination_duration_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_uid_gone_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_uid: Option<String>,
    /// RustFS container restarts of the replacement Pod when it became Ready
    /// (or was last seen); anything above zero is a crash-looping start.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restart_count_after: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement_ready_at_ms: Option<u64>,
    pub classification: TerminationClassification,
    /// The Pod that served the pinned port-forward is restarted after the
    /// workload so the client keeps one stable server; see the backend docs.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub restarted_after_workload: bool,
}

impl PodTerminationEvidence {
    pub fn violations(&self) -> Vec<String> {
        let mut violations = Vec::new();
        let pod = &self.pod_name;
        if !self.classification.is_graceful() {
            violations.push(format!(
                "Pod {pod} (uid {}) did not exit gracefully: {:?}{}",
                self.old_uid,
                self.classification,
                self.terminated
                    .as_ref()
                    .map(|terminated| format!(
                        " exit_code={} signal={:?} reason={:?}",
                        terminated.exit_code, terminated.signal, terminated.reason
                    ))
                    .unwrap_or_default()
            ));
        }
        let expected = classify_termination(&TerminationClassificationInput {
            grace_period_seconds: self.termination_grace_period_seconds,
            sigterm_reference_at_ms: self.sigterm_requested_at_ms,
            terminated: self.terminated.as_ref(),
        });
        if expected.classification != self.classification
            || expected.duration_ms != self.termination_duration_ms
        {
            violations.push(format!(
                "Pod {pod} classification {:?}/{:?} does not follow from its terminated state ({:?}/{:?})",
                self.classification,
                self.termination_duration_ms,
                expected.classification,
                expected.duration_ms
            ));
        }
        match self.deletion_grace_period_seconds {
            None => violations.push(format!(
                "Pod {pod} graceful deletion timestamp was never observed"
            )),
            Some(grace)
                if u64::try_from(grace).ok() != Some(self.termination_grace_period_seconds) =>
            {
                violations.push(format!(
                    "Pod {pod} was deleted with grace {grace}s instead of its spec terminationGracePeriodSeconds {}",
                    self.termination_grace_period_seconds
                ));
            }
            Some(_) => {}
        }
        if self.deletion_timestamp.is_none() || self.sigterm_requested_at_ms.is_none() {
            violations.push(format!(
                "Pod {pod} has no SIGTERM reference derived from its deletion timestamp"
            ));
        }
        match &self.new_uid {
            Some(new_uid) if new_uid == &self.old_uid => {
                violations.push(format!("Pod {pod} replacement uid equals the deleted uid"));
            }
            Some(_) => {}
            None => violations.push(format!("Pod {pod} has no replacement uid")),
        }
        if self.replacement_ready_at_ms.is_none() {
            violations.push(format!("Pod {pod} replacement never became Ready"));
        }
        if self.old_uid_gone_at_ms.is_none() {
            violations.push(format!("Pod {pod} old uid was never observed gone"));
        }
        // A replacement that crash-looped while starting (restart under load,
        // rustfs/rustfs#6573) must not pass as a clean restart.
        match self.restart_count_after {
            Some(0) => {}
            Some(count) => violations.push(format!(
                "Pod {pod} replacement container restarted {count} time(s) before Ready"
            )),
            None => violations.push(format!("Pod {pod} replacement restart count unknown")),
        }
        violations
    }

    /// The failure classification this target contributes, if it failed.
    pub fn failure_classification(&self) -> Option<&'static str> {
        if !self.classification.is_graceful() {
            return Some(self.classification.failure_classification());
        }
        let replacement_failed = self.replacement_ready_at_ms.is_none()
            || self.restart_count_after.is_none_or(|count| count > 0);
        if replacement_failed {
            return Some(REPLACEMENT_NOT_READY_CLASSIFICATION);
        }
        (!self.violations().is_empty()).then_some(HARNESS_CLASSIFICATION)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperatorPauseEvidence {
    pub namespace: String,
    pub deployment: String,
    /// Container image that identified the Deployment as the RustFS operator.
    pub image: String,
    /// `"image"` or `"label"`: which identity rule matched.
    pub identity_matched_by: String,
    pub replicas_before: u32,
    pub pause_requested_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_pods_gone_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume_requested_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resumed_at_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplicaObservation {
    pub observed_at_ms: u64,
    pub spec_replicas: i64,
    pub pods: usize,
}

/// The held outage of a cold restart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OutageEvidence {
    pub scale_down_requested_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub all_pods_terminated_at_ms: Option<u64>,
    /// Every `spec.replicas` sample taken while the outage was supposed to be
    /// held; any non-zero sample means something else wrote the scale and the
    /// outage was not what the scenario claims.
    #[serde(default)]
    pub replica_observations: Vec<ReplicaObservation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scale_up_requested_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub all_pods_ready_at_ms: Option<u64>,
}

impl OutageEvidence {
    pub fn held_at_zero(&self) -> bool {
        !self.replica_observations.is_empty()
            && self
                .replica_observations
                .iter()
                .all(|observation| observation.spec_replicas == 0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PodLifecycleEvidence {
    pub scenario: String,
    pub run_id: String,
    pub operation: LifecycleOperation,
    pub statefulset: StatefulSetIdentity,
    /// The StatefulSet UID after the operation; it must not change, a new
    /// UID means the workload was recreated rather than restarted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statefulset_uid_after: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_pause: Option<OperatorPauseEvidence>,
    pub targets: Vec<PodTerminationEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outage: Option<OutageEvidence>,
    pub started_at_ms: u64,
    pub completed_at_ms: u64,
    #[serde(default)]
    pub violations: Vec<String>,
    pub passed: bool,
}

impl PodLifecycleEvidence {
    /// Every way the recorded evidence falls short of a clean restart,
    /// recomputed from content so a hand-edited `passed` cannot claim it.
    pub fn compute_violations(&self) -> Vec<String> {
        let mut violations = Vec::new();
        if self.statefulset.uid.trim().is_empty() {
            violations.push("StatefulSet UID is empty".to_string());
        }
        match &self.statefulset_uid_after {
            Some(after) if after != &self.statefulset.uid => violations.push(format!(
                "StatefulSet UID changed from {} to {after}",
                self.statefulset.uid
            )),
            Some(_) => {}
            None => violations
                .push("StatefulSet UID was not re-observed after the operation".to_string()),
        }
        if self.targets.is_empty() {
            violations.push("no Pod was restarted".to_string());
        }
        match self.operation {
            LifecycleOperation::GracefulPod => {
                if self.targets.len() != 1 {
                    violations.push(format!(
                        "graceful Pod restart must target exactly one Pod, got {}",
                        self.targets.len()
                    ));
                }
            }
            LifecycleOperation::Rolling | LifecycleOperation::Cold => {
                if self.targets.len() != usize::try_from(self.statefulset.replicas).unwrap_or(0) {
                    violations.push(format!(
                        "{} must restart every one of {} Pods, got {}",
                        self.operation.as_str(),
                        self.statefulset.replicas,
                        self.targets.len()
                    ));
                }
            }
        }
        let names = self
            .targets
            .iter()
            .map(|target| target.pod_name.as_str())
            .collect::<BTreeSet<_>>();
        if names.len() != self.targets.len() {
            violations.push("restart targets contain duplicate Pod names".to_string());
        }
        for target in &self.targets {
            violations.extend(target.violations());
            if target.termination_grace_period_seconds
                != self.statefulset.termination_grace_period_seconds
            {
                violations.push(format!(
                    "Pod {} grace period {}s differs from the StatefulSet template {}s",
                    target.pod_name,
                    target.termination_grace_period_seconds,
                    self.statefulset.termination_grace_period_seconds
                ));
            }
            if target.delete_requested_at_ms < self.started_at_ms
                || target
                    .replacement_ready_at_ms
                    .is_some_and(|ready| ready > self.completed_at_ms)
            {
                violations.push(format!(
                    "Pod {} restart lies outside the operation window",
                    target.pod_name
                ));
            }
        }
        let deferred = self
            .targets
            .iter()
            .filter(|target| target.restarted_after_workload)
            .count();
        if deferred > 1 || (deferred == 1 && self.operation != LifecycleOperation::Rolling) {
            violations.push(format!(
                "{deferred} Pod(s) marked restarted-after-workload; only a rolling restart may defer exactly one"
            ));
        }
        match (self.operation, &self.outage) {
            (LifecycleOperation::Cold, None) => {
                violations.push("cold restart recorded no outage evidence".to_string());
            }
            (LifecycleOperation::Cold, Some(outage)) => {
                if !outage.held_at_zero() {
                    violations.push(
                        "StatefulSet spec.replicas was not held at zero for the whole outage"
                            .to_string(),
                    );
                }
                if outage.all_pods_terminated_at_ms.is_none() {
                    violations.push("cold restart never observed every Pod gone".to_string());
                }
                if outage.scale_up_requested_at_ms.is_none()
                    || outage.all_pods_ready_at_ms.is_none()
                {
                    violations.push("cold restart did not record the scale-up".to_string());
                }
                if let (Some(terminated), Some(scaled_up)) = (
                    outage.all_pods_terminated_at_ms,
                    outage.scale_up_requested_at_ms,
                ) && terminated > scaled_up
                {
                    violations.push("cold restart scaled up before every Pod was gone".to_string());
                }
                match &self.operator_pause {
                    Some(pause) if pause.resumed_at_ms.is_none() => {
                        violations.push("operator was paused but never resumed".to_string());
                    }
                    Some(_) => {}
                    None => violations.push(
                        "cold restart requires the operator pause that keeps the StatefulSet at zero replicas"
                            .to_string(),
                    ),
                }
                if let Err(error) = self.statefulset.require_cold_restart_eligible() {
                    violations.push(error.to_string());
                }
            }
            (_, Some(_)) => {
                violations.push("only a cold restart records outage evidence".to_string());
            }
            (_, None) => {}
        }
        if self.started_at_ms == 0 || self.started_at_ms > self.completed_at_ms {
            violations.push("operation window is invalid".to_string());
        }
        violations.sort();
        violations.dedup();
        violations
    }

    pub fn finalize(mut self) -> Self {
        self.violations = self.compute_violations();
        self.passed = self.violations.is_empty();
        self
    }

    pub fn require_success(&self) -> Result<()> {
        let recomputed = self.compute_violations();
        ensure!(
            self.passed && self.violations.is_empty() && recomputed.is_empty(),
            "{POD_LIFECYCLE_EVIDENCE_ARTIFACT} for scenario {} run {} did not pass: {}",
            self.scenario,
            self.run_id,
            if recomputed.is_empty() {
                "report content contradicts its passed verdict".to_string()
            } else {
                recomputed.join("; ")
            }
        );
        Ok(())
    }

    /// The failure classification a failed operation records. Precedence:
    /// a container that did not leave cleanly (`graceful_shutdown_failed`),
    /// then a replacement that could not come back
    /// (`product_or_environment`), then structural evidence problems
    /// (`test_or_environment`).
    pub fn failure_classification(&self) -> &'static str {
        let mut classification = HARNESS_CLASSIFICATION;
        for candidate in self
            .targets
            .iter()
            .filter_map(PodTerminationEvidence::failure_classification)
        {
            if candidate == GRACEFUL_SHUTDOWN_FAILED_CLASSIFICATION {
                return candidate;
            }
            if candidate == REPLACEMENT_NOT_READY_CLASSIFICATION {
                classification = candidate;
            }
        }
        classification
    }

    /// Cross-check against the run's Pod identities and fault window as
    /// recorded in `fault-evidence.json`.
    pub fn validate_against_run(&self, run: &LifecycleRunContext<'_>) -> Result<()> {
        self.require_success()?;
        let expected_operation = LifecycleOperation::from_kind(run.kind)?;
        ensure!(
            self.operation == expected_operation,
            "{POD_LIFECYCLE_EVIDENCE_ARTIFACT} operation {:?} does not match the scenario fault kind {}",
            self.operation,
            run.kind.as_str()
        );
        ensure!(
            usize::try_from(self.statefulset.replicas).ok() == Some(run.pods_before.len()),
            "{POD_LIFECYCLE_EVIDENCE_ARTIFACT} StatefulSet replicas {} do not match {} proven Pods",
            self.statefulset.replicas,
            run.pods_before.len()
        );
        let before_names = run
            .pods_before
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<BTreeSet<_>>();
        let after_names = run
            .pods_after
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<BTreeSet<_>>();
        ensure!(
            before_names == after_names,
            "StatefulSet Pod names changed across the restart: before={before_names:?} after={after_names:?}"
        );
        let target_names = self
            .targets
            .iter()
            .map(|target| target.pod_name.as_str())
            .collect::<BTreeSet<_>>();
        if self.operation.restarts_every_pod() {
            ensure!(
                target_names == before_names,
                "{POD_LIFECYCLE_EVIDENCE_ARTIFACT} targets {target_names:?} do not cover every proven Pod {before_names:?}"
            );
        } else {
            ensure!(
                target_names.is_subset(&before_names),
                "{POD_LIFECYCLE_EVIDENCE_ARTIFACT} target {target_names:?} is not a proven Pod"
            );
        }
        for target in &self.targets {
            let before_uid = run
                .pods_before
                .iter()
                .find(|(name, _)| name == &target.pod_name)
                .map(|(_, uid)| uid.as_str());
            ensure!(
                before_uid == Some(target.old_uid.as_str()),
                "{POD_LIFECYCLE_EVIDENCE_ARTIFACT} Pod {} old uid {} does not match the proven pre-fault uid {:?}",
                target.pod_name,
                target.old_uid,
                before_uid
            );
            let after_uid = run
                .pods_after
                .iter()
                .find(|(name, _)| name == &target.pod_name)
                .map(|(_, uid)| uid.as_str());
            ensure!(
                after_uid.is_some() && after_uid == target.new_uid.as_deref(),
                "{POD_LIFECYCLE_EVIDENCE_ARTIFACT} Pod {} replacement uid {:?} does not match the recovered Pod uid {:?}",
                target.pod_name,
                target.new_uid,
                after_uid
            );
            ensure!(
                target.delete_requested_at_ms >= run.fault_apply_started_at_ms
                    && target
                        .replacement_ready_at_ms
                        .is_some_and(|ready| ready <= run.recovery_ended_at_ms),
                "{POD_LIFECYCLE_EVIDENCE_ARTIFACT} Pod {} restart lies outside the fault window",
                target.pod_name
            );
            if target.restarted_after_workload {
                ensure!(
                    target.delete_requested_at_ms >= run.workload_ended_at_ms,
                    "{POD_LIFECYCLE_EVIDENCE_ARTIFACT} Pod {} is marked restarted-after-workload but was deleted during the workload",
                    target.pod_name
                );
                ensure!(
                    run.served_by_pod == Some(target.pod_name.as_str()),
                    "{POD_LIFECYCLE_EVIDENCE_ARTIFACT} deferred Pod {} is not the Pod that served the availability endpoint ({:?})",
                    target.pod_name,
                    run.served_by_pod
                );
            }
        }
        // Pods that were not restarted must keep their identity; otherwise
        // something outside the scenario restarted them.
        for (name, uid) in run.pods_before {
            if !target_names.contains(name.as_str()) {
                let after_uid = run
                    .pods_after
                    .iter()
                    .find(|(after_name, _)| after_name == name)
                    .map(|(_, uid)| uid.as_str());
                ensure!(
                    after_uid == Some(uid.as_str()),
                    "Pod {name} was not a restart target but its uid changed from {uid} to {after_uid:?}"
                );
            }
        }
        if let Some(served) = run.served_by_pod
            && self.operation == LifecycleOperation::Rolling
        {
            ensure!(
                self.targets
                    .iter()
                    .any(|target| target.pod_name == served && target.restarted_after_workload),
                "rolling restart served the availability endpoint from Pod {served} but did not defer its restart until after the workload"
            );
        }
        if let Some(outage) = &self.outage {
            let terminated = outage.all_pods_terminated_at_ms.ok_or_else(|| {
                anyhow::anyhow!("outage evidence lacks all_pods_terminated_at_ms")
            })?;
            let scaled_up = outage
                .scale_up_requested_at_ms
                .ok_or_else(|| anyhow::anyhow!("outage evidence lacks scale_up_requested_at_ms"))?;
            ensure!(
                terminated <= run.fault_active_at_ms
                    && run.fault_active_at_ms <= run.workload_started_at_ms
                    && run.workload_ended_at_ms <= scaled_up,
                "cold restart outage [{terminated}, {scaled_up}] does not enclose the workload window [{}, {}] with the fault active at {}",
                run.workload_started_at_ms,
                run.workload_ended_at_ms,
                run.fault_active_at_ms
            );
        }
        Ok(())
    }
}

/// Run facts the lifecycle artifact is checked against.
pub struct LifecycleRunContext<'a> {
    pub kind: FaultKind,
    pub pods_before: &'a [(String, String)],
    pub pods_after: &'a [(String, String)],
    pub fault_apply_started_at_ms: u64,
    pub fault_active_at_ms: u64,
    pub workload_started_at_ms: u64,
    pub workload_ended_at_ms: u64,
    pub recovery_ended_at_ms: u64,
    pub served_by_pod: Option<&'a str>,
}

/// One Pod as seen in a lifecycle status snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LifecyclePodStatus {
    pub name: String,
    pub uid: String,
    pub ready: bool,
    pub terminating: bool,
    pub restart_count: u64,
}

/// Fault status snapshot payload for lifecycle faults; the runner reads
/// `target_pods` to pin the availability endpoint to a surviving Pod.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleStatusSnapshot {
    pub operation: LifecycleOperation,
    pub statefulset_name: String,
    pub statefulset_uid: String,
    pub spec_replicas: i64,
    pub ready_replicas: i64,
    /// Pods the operation restarts while the workload runs.
    pub target_pods: Vec<String>,
    pub pods: Vec<LifecyclePodStatus>,
    pub observed_at_ms: u64,
}

/// JSON pointer to `target_pods` inside a serialized `FaultStatusSnapshot`
/// (`lifecycle_status` is a plain field; the payload is camelCase).
pub const SNAPSHOT_TARGET_PODS_POINTER: &str = "/lifecycle_status/targetPods";

#[cfg(test)]
mod tests {
    use super::{
        ContainerTermination, LifecycleOperation, LifecycleRunContext, OperatorPauseEvidence,
        OutageEvidence, PodLifecycleEvidence, PodTerminationEvidence, ReplicaObservation,
        StatefulSetIdentity, TerminationClassification, TerminationClassificationInput,
        classify_termination, parse_rfc3339_ms, total_outage_violation,
    };
    use crate::fault::plan::FaultKind;

    fn terminated(exit_code: i64, finished_at: &str) -> ContainerTermination {
        ContainerTermination {
            exit_code,
            signal: None,
            reason: Some(if exit_code == 0 { "Completed" } else { "Error" }.to_string()),
            message: None,
            started_at: Some("2026-09-11T10:00:00Z".to_string()),
            finished_at: Some(finished_at.to_string()),
            container_id: Some("containerd://old".to_string()),
        }
    }

    const SIGTERM_AT: &str = "2026-09-11T10:05:00Z";

    fn sigterm_ms() -> u64 {
        parse_rfc3339_ms(SIGTERM_AT).expect("sigterm")
    }

    fn classify(
        grace: u64,
        terminated_state: Option<&ContainerTermination>,
    ) -> (TerminationClassification, Option<u64>) {
        let result = classify_termination(&TerminationClassificationInput {
            grace_period_seconds: grace,
            sigterm_reference_at_ms: Some(sigterm_ms()),
            terminated: terminated_state,
        });
        (result.classification, result.duration_ms)
    }

    #[test]
    fn clean_exit_within_grace_is_graceful() {
        assert_eq!(
            classify(30, Some(&terminated(0, "2026-09-11T10:05:07Z"))),
            (TerminationClassification::GracefulExit, Some(7_000))
        );
        // Exactly at the grace boundary plus the one-second rounding.
        assert_eq!(
            classify(30, Some(&terminated(0, "2026-09-11T10:05:31Z"))).0,
            TerminationClassification::GracefulExit
        );
        assert_eq!(
            classify(30, Some(&terminated(0, "2026-09-11T10:05:32Z"))).0,
            TerminationClassification::InconsistentTiming
        );
        // Sub-second exits that finish before the second-granular SIGTERM
        // reference stay graceful within the tolerance.
        assert_eq!(
            classify(30, Some(&terminated(0, "2026-09-11T10:04:59.500Z"))),
            (TerminationClassification::GracefulExit, Some(0))
        );
    }

    #[test]
    fn sigkill_at_grace_expiry_is_a_grace_timeout() {
        assert_eq!(
            classify(30, Some(&terminated(137, "2026-09-11T10:05:30Z"))),
            (
                TerminationClassification::KilledOnGraceTimeout,
                Some(30_000)
            )
        );
        assert_eq!(
            classify(30, Some(&terminated(137, "2026-09-11T10:05:29Z"))).0,
            TerminationClassification::KilledOnGraceTimeout
        );
        // Two seconds early is outside the rounding tolerance: an external kill.
        assert_eq!(
            classify(30, Some(&terminated(137, "2026-09-11T10:05:28Z"))).0,
            TerminationClassification::KilledBeforeGraceExpired
        );
        assert_eq!(
            classify(30, Some(&terminated(137, "2026-09-11T10:05:10Z"))).0,
            TerminationClassification::KilledBeforeGraceExpired
        );
        let mut signalled = terminated(0, "2026-09-11T10:05:30Z");
        signalled.signal = Some(9);
        signalled.exit_code = 137;
        assert_eq!(
            classify(30, Some(&signalled)).0,
            TerminationClassification::KilledOnGraceTimeout
        );
        assert_eq!(
            TerminationClassification::KilledOnGraceTimeout.failure_classification(),
            "graceful_shutdown_failed"
        );
        assert_eq!(
            TerminationClassification::KilledBeforeGraceExpired.failure_classification(),
            "product_or_environment"
        );
    }

    #[test]
    fn other_exits_are_classified_and_missing_state_is_unobserved() {
        assert_eq!(
            classify(30, Some(&terminated(143, "2026-09-11T10:05:00Z"))).0,
            TerminationClassification::TerminatedBySignalDefault
        );
        // Signal 15 reported with a foreign exit code is still the default
        // SIGTERM action.
        let mut signalled = terminated(1, "2026-09-11T10:05:00Z");
        signalled.signal = Some(15);
        assert_eq!(
            classify(30, Some(&signalled)).0,
            TerminationClassification::TerminatedBySignalDefault
        );
        assert_eq!(
            classify(30, Some(&terminated(1, "2026-09-11T10:05:02Z"))).0,
            TerminationClassification::ErrorExit
        );
        // OOMKilled wins even when the runtime reports exit code 0.
        let mut oom = terminated(0, "2026-09-11T10:05:03Z");
        oom.reason = Some("OOMKilled".to_string());
        assert_eq!(
            classify(30, Some(&oom)).0,
            TerminationClassification::OomKilled
        );
        assert_eq!(
            classify(30, None),
            (TerminationClassification::Unobserved, None)
        );
        assert_eq!(
            classify(30, Some(&terminated(0, "2026-09-11T10:04:50Z"))).0,
            TerminationClassification::InconsistentTiming
        );
        let mut no_finish = terminated(0, "2026-09-11T10:05:01Z");
        no_finish.finished_at = None;
        assert_eq!(
            classify(30, Some(&no_finish)).0,
            TerminationClassification::Unobserved
        );
        // Without a SIGTERM reference nothing can be classified.
        let no_reference = classify_termination(&TerminationClassificationInput {
            grace_period_seconds: 30,
            sigterm_reference_at_ms: None,
            terminated: Some(&terminated(0, "2026-09-11T10:05:01Z")),
        });
        assert_eq!(
            no_reference.classification,
            TerminationClassification::Unobserved
        );
    }

    fn target(name: &str, ordinal: u32, deferred: bool) -> PodTerminationEvidence {
        let delete_requested_at_ms = sigterm_ms() - 200;
        PodTerminationEvidence {
            pod_name: name.to_string(),
            ordinal,
            old_uid: format!("old-{ordinal}"),
            restart_count_before: 0,
            termination_grace_period_seconds: 30,
            delete_requested_at_ms,
            deletion_timestamp: Some("2026-09-11T10:05:30Z".to_string()),
            deletion_grace_period_seconds: Some(30),
            sigterm_requested_at_ms: Some(sigterm_ms()),
            terminated: Some(terminated(0, "2026-09-11T10:05:07Z")),
            observation_source: Some("watch".to_string()),
            termination_duration_ms: Some(7_000),
            old_uid_gone_at_ms: Some(delete_requested_at_ms + 9_000),
            new_uid: Some(format!("new-{ordinal}")),
            restart_count_after: Some(0),
            replacement_ready_at_ms: Some(delete_requested_at_ms + 40_000),
            classification: TerminationClassification::GracefulExit,
            restarted_after_workload: deferred,
        }
    }

    fn statefulset() -> StatefulSetIdentity {
        StatefulSetIdentity {
            name: "tenant-primary".to_string(),
            uid: "sts-uid".to_string(),
            namespace: "rustfs-fault-test".to_string(),
            replicas: 2,
            pod_management_policy: Some("Parallel".to_string()),
            update_strategy: Some("RollingUpdate".to_string()),
            pvc_retention_when_scaled: Some("Retain".to_string()),
            pvc_retention_when_deleted: Some("Retain".to_string()),
            termination_grace_period_seconds: 30,
            current_revision: Some("rev-1".to_string()),
            update_revision: Some("rev-1".to_string()),
        }
    }

    fn evidence(
        operation: LifecycleOperation,
        targets: Vec<PodTerminationEvidence>,
    ) -> PodLifecycleEvidence {
        let started_at_ms = sigterm_ms() - 1_000;
        PodLifecycleEvidence {
            scenario: "pod-graceful-restart-one".to_string(),
            run_id: "run-1".to_string(),
            operation,
            statefulset: statefulset(),
            statefulset_uid_after: Some("sts-uid".to_string()),
            operator_pause: None,
            targets,
            outage: None,
            started_at_ms,
            completed_at_ms: started_at_ms + 600_000,
            violations: Vec::new(),
            passed: false,
        }
        .finalize()
    }

    fn pods(prefix: &str) -> Vec<(String, String)> {
        vec![
            ("rustfs-0".to_string(), format!("{prefix}-0")),
            ("rustfs-1".to_string(), format!("{prefix}-1")),
        ]
    }

    fn run_context<'a>(
        kind: FaultKind,
        before: &'a [(String, String)],
        after: &'a [(String, String)],
        served_by_pod: Option<&'a str>,
    ) -> LifecycleRunContext<'a> {
        let base = sigterm_ms();
        LifecycleRunContext {
            kind,
            pods_before: before,
            pods_after: after,
            fault_apply_started_at_ms: base - 2_000,
            fault_active_at_ms: base + 10_000,
            workload_started_at_ms: base + 11_000,
            workload_ended_at_ms: base + 100_000,
            recovery_ended_at_ms: base + 500_000,
            served_by_pod,
        }
    }

    #[test]
    fn graceful_single_restart_passes_and_binds_to_run_identities() {
        let report = evidence(
            LifecycleOperation::GracefulPod,
            vec![target("rustfs-1", 1, false)],
        );
        assert!(report.passed, "{:?}", report.violations);
        let before = pods("old");
        let mut after = pods("old");
        after[1].1 = "new-1".to_string();
        report
            .validate_against_run(&run_context(
                FaultKind::RustfsServerPodGracefulRestart,
                &before,
                &after,
                Some("rustfs-0"),
            ))
            .expect("bound to run");

        // The untouched Pod must keep its identity.
        let mut after_both = after.clone();
        after_both[0].1 = "new-0".to_string();
        let error = report
            .validate_against_run(&run_context(
                FaultKind::RustfsServerPodGracefulRestart,
                &before,
                &after_both,
                Some("rustfs-0"),
            ))
            .expect_err("untouched Pod changed uid");
        assert!(
            error.to_string().contains("was not a restart target"),
            "{error}"
        );

        // A stale old uid cannot pass.
        let mut wrong_before = before.clone();
        wrong_before[1].1 = "other".to_string();
        let error = report
            .validate_against_run(&run_context(
                FaultKind::RustfsServerPodGracefulRestart,
                &wrong_before,
                &after,
                None,
            ))
            .expect_err("stale old uid");
        assert!(error.to_string().contains("old uid"), "{error}");
        // The operation must match the scenario's fault kind.
        let error = report
            .validate_against_run(&run_context(
                FaultKind::RustfsServerRollingRestart,
                &before,
                &after,
                None,
            ))
            .expect_err("kind mismatch");
        assert!(
            error
                .to_string()
                .contains("does not match the scenario fault kind"),
            "{error}"
        );
    }

    #[test]
    fn grace_timeout_or_crashlooping_replacement_fails_the_evidence() {
        let mut killed = target("rustfs-1", 1, false);
        killed.terminated = Some(terminated(137, "2026-09-11T10:05:30Z"));
        killed.termination_duration_ms = Some(30_000);
        killed.classification = TerminationClassification::KilledOnGraceTimeout;
        let report = evidence(LifecycleOperation::GracefulPod, vec![killed]);
        assert!(!report.passed);
        assert!(report.require_success().is_err());
        assert_eq!(report.failure_classification(), "graceful_shutdown_failed");

        // A passed flag with a classification that contradicts the terminated
        // state is rejected on recomputation.
        let mut forged = evidence(
            LifecycleOperation::GracefulPod,
            vec![target("rustfs-1", 1, false)],
        );
        forged.targets[0].terminated = Some(terminated(137, "2026-09-11T10:05:30Z"));
        assert!(forged.passed);
        let error = forged.require_success().expect_err("forged classification");
        assert!(error.to_string().contains("does not follow"), "{error}");

        // A replacement that crash-looped or never came back is a product
        // (or environment) failure, not a harness problem.
        let mut crashlooping = target("rustfs-1", 1, false);
        crashlooping.restart_count_after = Some(2);
        let report = evidence(LifecycleOperation::GracefulPod, vec![crashlooping]);
        assert!(
            report
                .violations
                .iter()
                .any(|v| v.contains("restarted 2 time"))
        );
        assert_eq!(report.failure_classification(), "product_or_environment");
        let mut never_ready = target("rustfs-1", 1, false);
        never_ready.replacement_ready_at_ms = None;
        never_ready.restart_count_after = None;
        let report = evidence(LifecycleOperation::GracefulPod, vec![never_ready]);
        assert!(
            report
                .violations
                .iter()
                .any(|v| v.contains("never became Ready"))
        );
        assert_eq!(report.failure_classification(), "product_or_environment");
        // A grace timeout outranks a replacement failure on another target.
        let mut killed = target("rustfs-0", 0, false);
        killed.terminated = Some(terminated(137, "2026-09-11T10:05:30Z"));
        killed.termination_duration_ms = Some(30_000);
        killed.classification = TerminationClassification::KilledOnGraceTimeout;
        let mut never_ready = target("rustfs-1", 1, false);
        never_ready.replacement_ready_at_ms = None;
        let report = evidence(LifecycleOperation::Rolling, vec![never_ready, killed]);
        assert_eq!(report.failure_classification(), "graceful_shutdown_failed");

        let mut unobserved = target("rustfs-1", 1, false);
        unobserved.terminated = None;
        unobserved.termination_duration_ms = None;
        unobserved.classification = TerminationClassification::Unobserved;
        let report = evidence(LifecycleOperation::GracefulPod, vec![unobserved]);
        assert!(!report.passed);
        assert_eq!(report.failure_classification(), "test_or_environment");

        let mut short_grace = target("rustfs-1", 1, false);
        short_grace.deletion_grace_period_seconds = Some(0);
        let report = evidence(LifecycleOperation::GracefulPod, vec![short_grace]);
        assert!(
            report
                .violations
                .iter()
                .any(|v| v.contains("instead of its spec"))
        );

        // Missing deletion metadata is a violation, never a silent fallback.
        let mut no_deletion = target("rustfs-1", 1, false);
        no_deletion.deletion_timestamp = None;
        no_deletion.deletion_grace_period_seconds = None;
        no_deletion.sigterm_requested_at_ms = None;
        no_deletion.termination_duration_ms = None;
        no_deletion.classification = TerminationClassification::Unobserved;
        let report = evidence(LifecycleOperation::GracefulPod, vec![no_deletion]);
        assert!(
            report
                .violations
                .iter()
                .any(|v| v.contains("deletion timestamp was never observed"))
        );
    }

    #[test]
    fn target_violations_cover_identity_and_restart_count_gaps() {
        let mut same_uid = target("rustfs-1", 1, false);
        same_uid.new_uid = Some(same_uid.old_uid.clone());
        assert!(
            same_uid
                .violations()
                .iter()
                .any(|v| v.contains("equals the deleted uid"))
        );
        let mut no_uid = target("rustfs-1", 1, false);
        no_uid.new_uid = None;
        assert!(
            no_uid
                .violations()
                .iter()
                .any(|v| v.contains("no replacement uid"))
        );
        let mut unknown_restarts = target("rustfs-1", 1, false);
        unknown_restarts.restart_count_after = None;
        assert!(
            unknown_restarts
                .violations()
                .iter()
                .any(|v| v.contains("restart count unknown"))
        );
        assert_eq!(
            unknown_restarts.failure_classification(),
            Some("product_or_environment")
        );
        let mut never_gone = target("rustfs-1", 1, false);
        never_gone.old_uid_gone_at_ms = None;
        assert!(
            never_gone
                .violations()
                .iter()
                .any(|v| v.contains("never observed gone"))
        );
        assert_eq!(
            never_gone.failure_classification(),
            Some("test_or_environment")
        );
        assert_eq!(target("rustfs-1", 1, false).failure_classification(), None);
    }

    #[test]
    fn structural_violations_are_reported_individually() {
        let base = evidence(
            LifecycleOperation::GracefulPod,
            vec![target("rustfs-1", 1, false)],
        );
        let mut no_after = base.clone();
        no_after.statefulset_uid_after = None;
        assert!(
            no_after
                .compute_violations()
                .iter()
                .any(|v| v.contains("not re-observed"))
        );
        let mut changed = base.clone();
        changed.statefulset_uid_after = Some("sts-new".to_string());
        assert!(
            changed
                .compute_violations()
                .iter()
                .any(|v| v.contains("UID changed"))
        );
        let mut duplicate = base.clone();
        duplicate.targets.push(target("rustfs-1", 1, false));
        assert!(
            duplicate
                .compute_violations()
                .iter()
                .any(|v| v.contains("duplicate Pod names"))
        );
        let mut early = base.clone();
        early.targets[0].delete_requested_at_ms = early.started_at_ms - 1;
        assert!(
            early
                .compute_violations()
                .iter()
                .any(|v| v.contains("outside the operation window"))
        );
        let mut deferred = base.clone();
        deferred.targets[0].restarted_after_workload = true;
        assert!(
            deferred
                .compute_violations()
                .iter()
                .any(|v| v.contains("only a rolling restart may defer"))
        );
        let mut outage = base.clone();
        outage.outage = Some(OutageEvidence {
            scale_down_requested_at_ms: 1,
            all_pods_terminated_at_ms: None,
            replica_observations: Vec::new(),
            scale_up_requested_at_ms: None,
            all_pods_ready_at_ms: None,
        });
        assert!(
            outage
                .compute_violations()
                .iter()
                .any(|v| v.contains("only a cold restart records outage"))
        );
        let mut window = base.clone();
        window.started_at_ms = 0;
        assert!(
            window
                .compute_violations()
                .iter()
                .any(|v| v.contains("operation window is invalid"))
        );
        let mut empty = base;
        empty.targets.clear();
        assert!(
            empty
                .compute_violations()
                .iter()
                .any(|v| v.contains("no Pod was restarted"))
        );
    }

    #[test]
    fn rolling_restart_must_cover_every_pod_and_defer_the_served_pod() {
        let before = pods("old");
        let after = pods("new");
        let complete = evidence(
            LifecycleOperation::Rolling,
            vec![target("rustfs-1", 1, false), target("rustfs-0", 0, true)],
        );
        assert!(complete.passed, "{:?}", complete.violations);
        let mut deferred_late = complete.clone();
        deferred_late.targets[1].delete_requested_at_ms = sigterm_ms() + 200_000;
        deferred_late.targets[1].replacement_ready_at_ms = Some(sigterm_ms() + 260_000);
        deferred_late
            .validate_against_run(&run_context(
                FaultKind::RustfsServerRollingRestart,
                &before,
                &after,
                Some("rustfs-0"),
            ))
            .expect("deferred served Pod");
        // Deferring the Pod that did not serve the endpoint is rejected.
        let error = deferred_late
            .validate_against_run(&run_context(
                FaultKind::RustfsServerRollingRestart,
                &before,
                &after,
                Some("rustfs-1"),
            ))
            .expect_err("wrong deferred Pod");
        assert!(
            error.to_string().contains("is not the Pod that served"),
            "{error}"
        );
        // Deleting the deferred Pod during the workload is rejected.
        let error = complete
            .validate_against_run(&run_context(
                FaultKind::RustfsServerRollingRestart,
                &before,
                &after,
                Some("rustfs-0"),
            ))
            .expect_err("deferred Pod deleted under workload");
        assert!(
            error
                .to_string()
                .contains("was deleted during the workload"),
            "{error}"
        );
        // ClusterIP runs defer nothing.
        let all_during = evidence(
            LifecycleOperation::Rolling,
            vec![target("rustfs-1", 1, false), target("rustfs-0", 0, false)],
        );
        all_during
            .validate_against_run(&run_context(
                FaultKind::RustfsServerRollingRestart,
                &before,
                &after,
                None,
            ))
            .expect("cluster ip rolling restart");
        let error = all_during
            .validate_against_run(&run_context(
                FaultKind::RustfsServerRollingRestart,
                &before,
                &after,
                Some("rustfs-0"),
            ))
            .expect_err("pinned endpoint without deferral");
        assert!(
            error.to_string().contains("did not defer its restart"),
            "{error}"
        );
        let partial = evidence(
            LifecycleOperation::Rolling,
            vec![target("rustfs-1", 1, false)],
        );
        assert!(!partial.passed);
        assert!(
            partial
                .violations
                .iter()
                .any(|v| v.contains("every one of 2 Pods"))
        );
    }

    fn cold_restart_report() -> PodLifecycleEvidence {
        let base = sigterm_ms();
        let mut report = evidence(
            LifecycleOperation::Cold,
            vec![target("rustfs-1", 1, false), target("rustfs-0", 0, false)],
        );
        report.outage = Some(OutageEvidence {
            scale_down_requested_at_ms: base - 500,
            all_pods_terminated_at_ms: Some(base + 9_000),
            replica_observations: vec![
                ReplicaObservation {
                    observed_at_ms: base,
                    spec_replicas: 0,
                    pods: 2,
                },
                ReplicaObservation {
                    observed_at_ms: base + 9_000,
                    spec_replicas: 0,
                    pods: 0,
                },
            ],
            scale_up_requested_at_ms: Some(base + 120_000),
            all_pods_ready_at_ms: Some(base + 200_000),
        });
        report.operator_pause = Some(OperatorPauseEvidence {
            namespace: "rustfs-system".to_string(),
            deployment: "rustfs-operator".to_string(),
            image: "docker.io/rustfs/operator:1.0.0".to_string(),
            identity_matched_by: "image".to_string(),
            replicas_before: 1,
            pause_requested_at_ms: base - 5_000,
            operator_pods_gone_at_ms: Some(base - 2_000),
            resume_requested_at_ms: Some(base + 200_500),
            resumed_at_ms: Some(base + 210_000),
        });
        for target in &mut report.targets {
            target.replacement_ready_at_ms = Some(base + 200_000);
        }
        report.finalize()
    }

    #[test]
    fn cold_restart_requires_a_held_outage_and_operator_pause() {
        let base = sigterm_ms();
        let unheld = evidence(
            LifecycleOperation::Cold,
            vec![target("rustfs-1", 1, false), target("rustfs-0", 0, false)],
        );
        assert!(
            unheld
                .violations
                .iter()
                .any(|v| v.contains("recorded no outage evidence"))
        );
        let report = cold_restart_report();
        assert!(report.passed, "{:?}", report.violations);
        let before = pods("old");
        let after = pods("new");
        report
            .validate_against_run(&run_context(
                FaultKind::RustfsServerColdRestart,
                &before,
                &after,
                None,
            ))
            .expect("held outage");

        let mut fought = report.clone();
        fought.outage.as_mut().unwrap().replica_observations[1].spec_replicas = 2;
        let fought = fought.finalize();
        assert!(
            fought
                .violations
                .iter()
                .any(|v| v.contains("not held at zero"))
        );

        let mut unpaused = report.clone();
        unpaused.operator_pause = None;
        assert!(
            unpaused
                .finalize()
                .violations
                .iter()
                .any(|v| v.contains("requires the operator pause"))
        );
        let mut unresumed = report.clone();
        unresumed.operator_pause.as_mut().unwrap().resumed_at_ms = None;
        assert!(
            unresumed
                .finalize()
                .violations
                .iter()
                .any(|v| v.contains("never resumed"))
        );

        let mut deleting_pvcs = report.clone();
        deleting_pvcs.statefulset.pvc_retention_when_scaled = Some("Delete".to_string());
        assert!(
            deleting_pvcs
                .finalize()
                .violations
                .iter()
                .any(|v| v.contains("whenScaled"))
        );
        let mut ordered = report.clone();
        ordered.statefulset.pod_management_policy = Some("OrderedReady".to_string());
        assert!(ordered.statefulset.require_cold_restart_eligible().is_err());
        assert!(
            ordered
                .finalize()
                .violations
                .iter()
                .any(|v| v.contains("requires Parallel"))
        );
        let mut scaled_early = report.clone();
        scaled_early
            .outage
            .as_mut()
            .unwrap()
            .scale_up_requested_at_ms = Some(base + 8_000);
        assert!(
            scaled_early
                .finalize()
                .violations
                .iter()
                .any(|v| v.contains("scaled up before every Pod was gone"))
        );

        // The workload must lie entirely inside the outage.
        let mut context = run_context(FaultKind::RustfsServerColdRestart, &before, &after, None);
        context.workload_ended_at_ms = base + 130_000;
        let error = report
            .validate_against_run(&context)
            .expect_err("workload outlived the outage");
        assert!(error.to_string().contains("does not enclose"), "{error}");
    }

    #[test]
    fn total_outage_predicate_flags_any_served_or_unattempted_family() {
        assert_eq!(total_outage_violation("gets", 0, 0, 12), None);
        assert!(
            total_outage_violation("deletes", 0, 1, 5)
                .expect("404 counts as served")
                .contains("1 with 404")
        );
        assert!(
            total_outage_violation("multipart_aborts", 2, 0, 2)
                .expect("success counts as served")
                .contains("2 request(s) with success")
        );
        assert!(
            total_outage_violation("lists", 0, 0, 0)
                .expect("unattempted family")
                .contains("never attempted")
        );
    }

    #[test]
    fn rfc3339_parsing_handles_fractional_seconds() {
        assert_eq!(
            parse_rfc3339_ms("2026-09-11T10:05:00Z").expect("ts") % 1000,
            0
        );
        assert_eq!(
            parse_rfc3339_ms("2026-09-11T10:05:00.250Z").expect("ts")
                - parse_rfc3339_ms("2026-09-11T10:05:00Z").expect("ts"),
            250
        );
        assert!(parse_rfc3339_ms("yesterday").is_err());
    }
}
