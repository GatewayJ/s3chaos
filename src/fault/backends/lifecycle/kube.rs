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

//! kubectl command rendering and Kubernetes object parsing for the lifecycle
//! backend. Rendering and parsing are pure so the exact commands and the
//! fields read from Pod/StatefulSet/Deployment objects are unit-tested.

use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;
use std::collections::BTreeMap;

use super::evidence::{
    ContainerTermination, DEFAULT_TERMINATION_GRACE_PERIOD_SECONDS, StatefulSetIdentity,
    parse_rfc3339_ms,
};
use crate::framework::{command::CommandSpec, config::ClusterTestConfig, kubectl::Kubectl};

pub const RUSTFS_CONTAINER_NAME: &str = "rustfs";

pub fn rustfs_tenant_selector(cluster: &ClusterTestConfig) -> String {
    format!("rustfs.tenant={}", cluster.tenant_name)
}

/// StatefulSet Pods are named `<statefulset>-<ordinal>`.
pub fn pod_ordinal(name: &str) -> Option<u32> {
    let (_, ordinal) = name.rsplit_once('-')?;
    ordinal.parse().ok()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodOwner {
    pub kind: String,
    pub name: String,
    pub uid: String,
    pub controller: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedPod {
    pub name: String,
    pub uid: String,
    pub ordinal: Option<u32>,
    pub phase: String,
    pub ready: bool,
    pub terminating: bool,
    pub deletion_timestamp: Option<String>,
    pub deletion_grace_period_seconds: Option<i64>,
    pub termination_grace_period_seconds: u64,
    pub restart_count: u64,
    pub owner: Option<PodOwner>,
    pub rustfs_terminated: Option<ContainerTermination>,
}

impl ObservedPod {
    /// `deletionTimestamp - deletionGracePeriodSeconds`: when the API server
    /// accepted the graceful delete, i.e. the earliest SIGTERM time.
    pub fn sigterm_requested_at_ms(&self) -> Option<u64> {
        let deletion = parse_rfc3339_ms(self.deletion_timestamp.as_deref()?).ok()?;
        let grace = u64::try_from(self.deletion_grace_period_seconds?).ok()?;
        Some(deletion.saturating_sub(grace.saturating_mul(1_000)))
    }
}

fn rustfs_container_status(pod: &Value) -> Option<&Value> {
    let statuses = pod
        .pointer("/status/containerStatuses")
        .and_then(Value::as_array)?;
    statuses
        .iter()
        .find(|status| status.get("name").and_then(Value::as_str) == Some(RUSTFS_CONTAINER_NAME))
        .or_else(|| (statuses.len() == 1).then(|| &statuses[0]))
}

pub fn parse_pod(pod: &Value) -> Result<ObservedPod> {
    let metadata = pod.get("metadata").context("Pod has no metadata")?;
    let name = metadata
        .get("name")
        .and_then(Value::as_str)
        .context("Pod has no metadata.name")?
        .to_string();
    let uid = metadata
        .get("uid")
        .and_then(Value::as_str)
        .context("Pod has no metadata.uid")?
        .to_string();
    let deletion_timestamp = metadata
        .get("deletionTimestamp")
        .and_then(Value::as_str)
        .map(str::to_string);
    let deletion_grace_period_seconds = metadata
        .get("deletionGracePeriodSeconds")
        .and_then(Value::as_i64);
    let termination_grace_period_seconds = pod
        .pointer("/spec/terminationGracePeriodSeconds")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_TERMINATION_GRACE_PERIOD_SECONDS);
    let phase = pod
        .pointer("/status/phase")
        .and_then(Value::as_str)
        .unwrap_or("Unknown")
        .to_string();
    let ready = pod
        .pointer("/status/conditions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|condition| {
            condition.get("type").and_then(Value::as_str) == Some("Ready")
                && condition.get("status").and_then(Value::as_str) == Some("True")
        });
    let restart_count = pod
        .pointer("/status/containerStatuses")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|status| status.get("restartCount"))
        .filter_map(Value::as_u64)
        .sum();
    let owner = metadata
        .get("ownerReferences")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|reference| reference.get("controller").and_then(Value::as_bool) == Some(true))
        .map(|reference| PodOwner {
            kind: reference
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            name: reference
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            uid: reference
                .get("uid")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            controller: true,
        });
    let rustfs_terminated = rustfs_container_status(pod).and_then(|status| {
        let terminated = status.pointer("/state/terminated")?;
        Some(ContainerTermination {
            exit_code: terminated.get("exitCode").and_then(Value::as_i64)?,
            signal: terminated.get("signal").and_then(Value::as_i64),
            reason: terminated
                .get("reason")
                .and_then(Value::as_str)
                .map(str::to_string),
            message: terminated
                .get("message")
                .and_then(Value::as_str)
                .map(str::to_string),
            started_at: terminated
                .get("startedAt")
                .and_then(Value::as_str)
                .map(str::to_string),
            finished_at: terminated
                .get("finishedAt")
                .and_then(Value::as_str)
                .map(str::to_string),
            container_id: status
                .get("containerID")
                .or_else(|| terminated.get("containerID"))
                .and_then(Value::as_str)
                .map(str::to_string),
        })
    });
    Ok(ObservedPod {
        ordinal: pod_ordinal(&name),
        name,
        uid,
        phase,
        ready,
        terminating: deletion_timestamp.is_some(),
        deletion_timestamp,
        deletion_grace_period_seconds,
        termination_grace_period_seconds,
        restart_count,
        owner,
        rustfs_terminated,
    })
}

pub fn parse_pod_list(value: &Value) -> Result<Vec<ObservedPod>> {
    let items = value
        .pointer("/items")
        .and_then(Value::as_array)
        .context("Pod list has no items array")?;
    let mut pods = items.iter().map(parse_pod).collect::<Result<Vec<_>>>()?;
    pods.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(pods)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedStatefulSet {
    pub identity: StatefulSetIdentity,
    pub spec_replicas: i64,
    pub status_replicas: i64,
    pub ready_replicas: i64,
}

pub fn parse_statefulset(value: &Value) -> Result<ObservedStatefulSet> {
    let metadata = value
        .get("metadata")
        .context("StatefulSet has no metadata")?;
    let name = metadata
        .get("name")
        .and_then(Value::as_str)
        .context("StatefulSet has no metadata.name")?
        .to_string();
    let uid = metadata
        .get("uid")
        .and_then(Value::as_str)
        .context("StatefulSet has no metadata.uid")?
        .to_string();
    let namespace = metadata
        .get("namespace")
        .and_then(Value::as_str)
        .context("StatefulSet has no metadata.namespace")?
        .to_string();
    let spec_replicas = value
        .pointer("/spec/replicas")
        .and_then(Value::as_i64)
        .context("StatefulSet has no spec.replicas")?;
    let string_at = |pointer: &str| {
        value
            .pointer(pointer)
            .and_then(Value::as_str)
            .map(str::to_string)
    };
    let termination_grace_period_seconds = value
        .pointer("/spec/template/spec/terminationGracePeriodSeconds")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_TERMINATION_GRACE_PERIOD_SECONDS);
    Ok(ObservedStatefulSet {
        identity: StatefulSetIdentity {
            name,
            uid,
            namespace,
            replicas: u32::try_from(spec_replicas.max(0)).unwrap_or(u32::MAX),
            pod_management_policy: string_at("/spec/podManagementPolicy"),
            update_strategy: string_at("/spec/updateStrategy/type"),
            pvc_retention_when_scaled: string_at(
                "/spec/persistentVolumeClaimRetentionPolicy/whenScaled",
            ),
            pvc_retention_when_deleted: string_at(
                "/spec/persistentVolumeClaimRetentionPolicy/whenDeleted",
            ),
            termination_grace_period_seconds,
            current_revision: string_at("/status/currentRevision"),
            update_revision: string_at("/status/updateRevision"),
        },
        spec_replicas,
        status_replicas: value
            .pointer("/status/replicas")
            .and_then(Value::as_i64)
            .unwrap_or(0),
        ready_replicas: value
            .pointer("/status/readyReplicas")
            .and_then(Value::as_i64)
            .unwrap_or(0),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedDeployment {
    pub name: String,
    pub spec_replicas: i64,
    pub status_replicas: i64,
    pub available_replicas: i64,
}

pub fn parse_deployment(value: &Value) -> Result<ObservedDeployment> {
    Ok(ObservedDeployment {
        name: value
            .pointer("/metadata/name")
            .and_then(Value::as_str)
            .context("Deployment has no metadata.name")?
            .to_string(),
        spec_replicas: value
            .pointer("/spec/replicas")
            .and_then(Value::as_i64)
            .unwrap_or(1),
        status_replicas: value
            .pointer("/status/replicas")
            .and_then(Value::as_i64)
            .unwrap_or(0),
        available_replicas: value
            .pointer("/status/availableReplicas")
            .and_then(Value::as_i64)
            .unwrap_or(0),
    })
}

pub fn list_rustfs_pods_command(cluster: &ClusterTestConfig) -> CommandSpec {
    Kubectl::new(cluster)
        .namespaced(&cluster.test_namespace)
        .command([
            "get",
            "pod",
            "-l",
            rustfs_tenant_selector(cluster).as_str(),
            "-o",
            "json",
        ])
}

/// Streams every change to the tenant Pods as concatenated JSON objects; the
/// final state of a deleted Pod (its container exit code) is only reliably
/// visible in this stream because the Pod object disappears right after.
pub fn watch_rustfs_pods_command(cluster: &ClusterTestConfig) -> CommandSpec {
    Kubectl::new(cluster)
        .namespaced(&cluster.test_namespace)
        .command([
            "get",
            "pod",
            "-l",
            rustfs_tenant_selector(cluster).as_str(),
            "-o",
            "json",
            "--watch",
        ])
}

pub fn get_statefulset_command(cluster: &ClusterTestConfig, name: &str) -> CommandSpec {
    Kubectl::new(cluster)
        .namespaced(&cluster.test_namespace)
        .command(["get", "statefulset", name, "-o", "json"])
}

pub fn get_deployment_command(
    cluster: &ClusterTestConfig,
    namespace: &str,
    name: &str,
) -> CommandSpec {
    Kubectl::new(cluster)
        .namespaced(namespace)
        .command(["get", "deployment", name, "-o", "json"])
}

fn ensure_api_path_safe(value: &str, what: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.chars().all(|ch| ch.is_ascii_lowercase()
                || ch.is_ascii_digit()
                || matches!(ch, '.' | '-')),
        "{what} {value:?} is not safe for the Kubernetes API path"
    );
    Ok(())
}

/// Graceful delete with the Pod's own `terminationGracePeriodSeconds`: the
/// request body deliberately carries no `gracePeriodSeconds`, and the UID
/// precondition guarantees the delete cannot hit a replacement Pod.
pub fn delete_pod_default_grace_command(
    cluster: &ClusterTestConfig,
    pod: &str,
    pod_uid: &str,
) -> Result<CommandSpec> {
    ensure_api_path_safe(pod, "target Pod name")?;
    ensure!(!pod_uid.trim().is_empty(), "target Pod UID is empty");
    let uri = format!("/api/v1/namespaces/{}/pods/{pod}", cluster.test_namespace);
    let delete_options = serde_json::json!({
        "apiVersion": "v1",
        "kind": "DeleteOptions",
        "propagationPolicy": "Background",
        "preconditions": {"uid": pod_uid},
    });
    Ok(Kubectl::new(cluster)
        .command(["delete", "--raw", uri.as_str(), "-f", "-"])
        .stdin(serde_json::to_string(&delete_options)?))
}

pub fn scale_statefulset_command(
    cluster: &ClusterTestConfig,
    name: &str,
    replicas: u32,
) -> Result<CommandSpec> {
    ensure_api_path_safe(name, "StatefulSet name")?;
    Ok(Kubectl::new(cluster)
        .namespaced(&cluster.test_namespace)
        .command([
            "scale",
            "statefulset",
            name,
            &format!("--replicas={replicas}"),
        ]))
}

pub fn scale_deployment_command(
    cluster: &ClusterTestConfig,
    namespace: &str,
    name: &str,
    replicas: u32,
) -> Result<CommandSpec> {
    ensure_api_path_safe(name, "Deployment name")?;
    ensure_api_path_safe(namespace, "Deployment namespace")?;
    Ok(Kubectl::new(cluster).namespaced(namespace).command([
        "scale",
        "deployment",
        name,
        &format!("--replicas={replicas}"),
    ]))
}

pub fn auth_can_i_command(
    cluster: &ClusterTestConfig,
    namespace: &str,
    verb: &str,
    resource: &str,
) -> CommandSpec {
    Kubectl::new(cluster)
        .namespaced(namespace)
        .command(["auth", "can-i", verb, resource])
}

pub fn run_json(command: &CommandSpec) -> Result<Value> {
    let output = command.run_checked()?;
    serde_json::from_str(&output.stdout)
        .with_context(|| format!("parse JSON from {}", command.display()))
}

/// Split the concatenated JSON documents `kubectl get --watch -o json`
/// writes; a `List` (the initial listing on some kubectl versions) is
/// flattened into its items. Trailing garbage (a broken watch's stderr
/// lines) ends the stream and is reported as `truncated`.
pub struct WatchStream {
    pub objects: Vec<Value>,
    pub truncated: bool,
}

pub fn parse_watch_stream(raw: &str) -> WatchStream {
    let mut objects = Vec::new();
    let mut truncated = false;
    for document in serde_json::Deserializer::from_str(raw).into_iter::<Value>() {
        match document {
            Ok(value) if value.get("kind").and_then(Value::as_str) == Some("List") => {
                objects.extend(
                    value
                        .get("items")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .cloned(),
                );
            }
            Ok(value) => objects.push(value),
            Err(_) => {
                truncated = true;
                break;
            }
        }
    }
    WatchStream { objects, truncated }
}

/// The last observed state per Pod UID, preferring the latest document that
/// carries the RustFS container's terminated state over a later one without
/// it.
pub fn final_pod_states(objects: &[Value]) -> BTreeMap<String, ObservedPod> {
    let mut states = BTreeMap::<String, ObservedPod>::new();
    for value in objects {
        let Ok(pod) = parse_pod(value) else {
            continue;
        };
        match states.get(&pod.uid) {
            Some(existing)
                if existing.rustfs_terminated.is_some() && pod.rustfs_terminated.is_none() => {}
            _ => {
                states.insert(pod.uid.clone(), pod);
            }
        }
    }
    states
}

/// Group the tenant Pods by controller owner and require exactly one
/// controlling StatefulSet.
pub fn require_single_statefulset_owner(pods: &[ObservedPod]) -> Result<PodOwner> {
    ensure!(!pods.is_empty(), "no RustFS Pods to inspect for ownership");
    let mut owners = BTreeMap::<String, PodOwner>::new();
    for pod in pods {
        let owner = pod.owner.clone().with_context(|| {
            format!(
                "Pod {} has no controlling owner; lifecycle scenarios require StatefulSet-managed RustFS Pods",
                pod.name
            )
        })?;
        ensure!(
            owner.kind == "StatefulSet",
            "Pod {} is controlled by a {} ({}), not a StatefulSet; lifecycle scenarios reject non-StatefulSet deployments",
            pod.name,
            owner.kind,
            owner.name
        );
        owners.insert(owner.uid.clone(), owner);
    }
    if owners.len() != 1 {
        bail!(
            "RustFS Pods are owned by {} StatefulSets ({}); lifecycle scenarios require exactly one",
            owners.len(),
            owners
                .values()
                .map(|owner| owner.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    Ok(owners.into_values().next().expect("one owner"))
}

#[cfg(test)]
mod tests {
    use super::{
        auth_can_i_command, delete_pod_default_grace_command, final_pod_states,
        get_statefulset_command, parse_deployment, parse_pod, parse_pod_list, parse_statefulset,
        parse_watch_stream, pod_ordinal, require_single_statefulset_owner,
        scale_deployment_command, scale_statefulset_command, watch_rustfs_pods_command,
    };
    use crate::fault::config::FaultTestConfig;
    use serde_json::json;

    fn cluster() -> crate::framework::config::ClusterTestConfig {
        FaultTestConfig::for_test("real-cluster", "fast-csi").cluster
    }

    fn pod_json(name: &str, uid: &str, terminated: Option<serde_json::Value>) -> serde_json::Value {
        let mut status = json!({
            "name": "rustfs",
            "containerID": "containerd://abc",
            "restartCount": 1,
            "ready": terminated.is_none(),
            "state": {"running": {"startedAt": "2026-09-11T10:00:00Z"}}
        });
        if let Some(terminated) = terminated {
            status["state"] = json!({"terminated": terminated});
        }
        json!({
            "metadata": {
                "name": name,
                "uid": uid,
                "namespace": "rustfs-fault-test",
                "deletionTimestamp": terminated_present(&status).then_some("2026-09-11T10:05:30Z"),
                "deletionGracePeriodSeconds": terminated_present(&status).then_some(30),
                "ownerReferences": [{
                    "apiVersion": "apps/v1",
                    "kind": "StatefulSet",
                    "name": "fault-test-tenant-primary",
                    "uid": "sts-uid",
                    "controller": true
                }]
            },
            "spec": {"terminationGracePeriodSeconds": 30, "containers": [{"name": "rustfs"}]},
            "status": {
                "phase": "Running",
                "conditions": [{"type": "Ready", "status": if terminated_present(&status) {"False"} else {"True"}}],
                "containerStatuses": [
                    {"name": "sidecar", "restartCount": 2, "ready": true, "state": {"running": {}}},
                    status
                ]
            }
        })
    }

    fn terminated_present(status: &serde_json::Value) -> bool {
        status.pointer("/state/terminated").is_some()
    }

    #[test]
    fn pod_parsing_reads_identity_owner_grace_and_terminated_state() {
        let running =
            parse_pod(&pod_json("fault-test-tenant-primary-3", "uid-3", None)).expect("pod");
        assert_eq!(running.ordinal, Some(3));
        assert!(running.ready && !running.terminating);
        assert_eq!(running.restart_count, 3);
        assert_eq!(running.termination_grace_period_seconds, 30);
        assert_eq!(
            running.owner.as_ref().map(|owner| owner.uid.as_str()),
            Some("sts-uid")
        );
        assert!(running.rustfs_terminated.is_none());
        assert_eq!(running.sigterm_requested_at_ms(), None);

        let exited = parse_pod(&pod_json(
            "fault-test-tenant-primary-3",
            "uid-3",
            Some(json!({
                "exitCode": 0,
                "reason": "Completed",
                "startedAt": "2026-09-11T10:00:00Z",
                "finishedAt": "2026-09-11T10:05:04Z",
                "containerID": "containerd://abc"
            })),
        ))
        .expect("pod");
        assert!(exited.terminating);
        let terminated = exited.rustfs_terminated.as_ref().expect("terminated");
        assert_eq!(terminated.exit_code, 0);
        assert_eq!(
            terminated.finished_at.as_deref(),
            Some("2026-09-11T10:05:04Z")
        );
        // deletionTimestamp 10:05:30 minus the 30s grace is the SIGTERM time.
        assert_eq!(
            exited.sigterm_requested_at_ms(),
            Some(super::parse_rfc3339_ms("2026-09-11T10:05:00Z").expect("ts"))
        );

        let list = parse_pod_list(&json!({"items": [
            pod_json("fault-test-tenant-primary-1", "uid-1", None),
            pod_json("fault-test-tenant-primary-0", "uid-0", None)
        ]}))
        .expect("list");
        assert_eq!(
            list.iter().map(|pod| pod.ordinal).collect::<Vec<_>>(),
            [Some(0), Some(1)]
        );
        assert_eq!(pod_ordinal("tenant-primary-12"), Some(12));
        assert_eq!(pod_ordinal("tenant"), None);
        assert!(parse_pod(&json!({"metadata": {"name": "x"}})).is_err());
    }

    #[test]
    fn statefulset_ownership_requires_exactly_one_controlling_statefulset() {
        let pods = parse_pod_list(&json!({"items": [
            pod_json("fault-test-tenant-primary-0", "uid-0", None),
            pod_json("fault-test-tenant-primary-1", "uid-1", None)
        ]}))
        .expect("list");
        let owner = require_single_statefulset_owner(&pods).expect("owner");
        assert_eq!(owner.name, "fault-test-tenant-primary");

        let mut deployment_owned = pod_json("fault-test-tenant-primary-1", "uid-1", None);
        deployment_owned["metadata"]["ownerReferences"][0]["kind"] = json!("ReplicaSet");
        let pods = parse_pod_list(&json!({"items": [
            pod_json("fault-test-tenant-primary-0", "uid-0", None),
            deployment_owned
        ]}))
        .expect("list");
        let error = require_single_statefulset_owner(&pods).expect_err("ReplicaSet owner");
        assert!(error.to_string().contains("not a StatefulSet"), "{error}");

        let mut other_sts = pod_json("other-0", "uid-9", None);
        other_sts["metadata"]["ownerReferences"][0]["uid"] = json!("sts-other");
        let pods = parse_pod_list(&json!({"items": [
            pod_json("fault-test-tenant-primary-0", "uid-0", None),
            other_sts
        ]}))
        .expect("list");
        assert!(require_single_statefulset_owner(&pods).is_err());

        let mut orphan = pod_json("fault-test-tenant-primary-0", "uid-0", None);
        orphan["metadata"]["ownerReferences"] = json!([]);
        assert!(require_single_statefulset_owner(&[parse_pod(&orphan).expect("pod")]).is_err());
        assert!(require_single_statefulset_owner(&[]).is_err());
    }

    #[test]
    fn statefulset_and_deployment_parsing_read_scale_and_retention_fields() {
        let sts = parse_statefulset(&json!({
            "metadata": {"name": "fault-test-tenant-primary", "uid": "sts-uid", "namespace": "rustfs-fault-test"},
            "spec": {
                "replicas": 4,
                "podManagementPolicy": "Parallel",
                "updateStrategy": {"type": "RollingUpdate"},
                "persistentVolumeClaimRetentionPolicy": {"whenScaled": "Retain", "whenDeleted": "Retain"},
                "template": {"spec": {"terminationGracePeriodSeconds": 45}}
            },
            "status": {"replicas": 4, "readyReplicas": 3, "currentRevision": "a", "updateRevision": "a"}
        }))
        .expect("statefulset");
        assert_eq!(sts.identity.replicas, 4);
        assert_eq!(sts.identity.termination_grace_period_seconds, 45);
        assert_eq!(
            sts.identity.pvc_retention_when_scaled.as_deref(),
            Some("Retain")
        );
        assert_eq!(sts.ready_replicas, 3);
        let minimal = parse_statefulset(&json!({
            "metadata": {"name": "s", "uid": "u", "namespace": "n"},
            "spec": {"replicas": 0}
        }))
        .expect("minimal");
        assert_eq!(minimal.identity.termination_grace_period_seconds, 30);
        assert_eq!(minimal.status_replicas, 0);
        assert!(
            parse_statefulset(&json!({"metadata": {"name": "s", "uid": "u", "namespace": "n"}}))
                .is_err()
        );

        let deployment = parse_deployment(&json!({
            "metadata": {"name": "rustfs-operator"},
            "spec": {"replicas": 2},
            "status": {"replicas": 2, "availableReplicas": 2}
        }))
        .expect("deployment");
        assert_eq!(deployment.spec_replicas, 2);
        assert_eq!(deployment.available_replicas, 2);
        let scaled_to_zero = parse_deployment(
            &json!({"metadata": {"name": "op"}, "spec": {"replicas": 0}, "status": {}}),
        )
        .expect("deployment");
        assert_eq!(scaled_to_zero.status_replicas, 0);
    }

    #[test]
    fn commands_render_default_grace_delete_scale_and_watch() {
        let cluster = cluster();
        let delete =
            delete_pod_default_grace_command(&cluster, "fault-test-tenant-primary-3", "uid-3")
                .expect("delete");
        assert_eq!(
            delete.display(),
            "kubectl --context real-cluster delete --raw /api/v1/namespaces/rustfs-fault-test/pods/fault-test-tenant-primary-3 -f -"
        );
        let body: serde_json::Value =
            serde_json::from_str(delete.stdin.as_deref().expect("stdin")).expect("json");
        assert_eq!(body["preconditions"]["uid"], json!("uid-3"));
        assert!(
            body.get("gracePeriodSeconds").is_none(),
            "a default-grace delete must not override terminationGracePeriodSeconds"
        );
        assert!(delete_pod_default_grace_command(&cluster, "Bad/Name", "uid").is_err());
        assert!(delete_pod_default_grace_command(&cluster, "pod-0", " ").is_err());

        assert_eq!(
            scale_statefulset_command(&cluster, "fault-test-tenant-primary", 0)
                .expect("scale")
                .display(),
            "kubectl --context real-cluster -n rustfs-fault-test scale statefulset fault-test-tenant-primary --replicas=0"
        );
        assert_eq!(
            scale_deployment_command(&cluster, "rustfs-system", "rustfs-operator", 1)
                .expect("scale")
                .display(),
            "kubectl --context real-cluster -n rustfs-system scale deployment rustfs-operator --replicas=1"
        );
        assert!(scale_statefulset_command(&cluster, "", 1).is_err());
        assert_eq!(
            watch_rustfs_pods_command(&cluster).display(),
            "kubectl --context real-cluster -n rustfs-fault-test get pod -l rustfs.tenant=fault-test-tenant -o json --watch"
        );
        assert_eq!(
            get_statefulset_command(&cluster, "fault-test-tenant-primary").display(),
            "kubectl --context real-cluster -n rustfs-fault-test get statefulset fault-test-tenant-primary -o json"
        );
        assert_eq!(
            auth_can_i_command(&cluster, "rustfs-fault-test", "delete", "pods").display(),
            "kubectl --context real-cluster -n rustfs-fault-test auth can-i delete pods"
        );
    }

    #[test]
    fn watch_stream_parsing_keeps_the_terminated_state_per_uid() {
        let running = pod_json("fault-test-tenant-primary-3", "uid-3", None);
        let exited = pod_json(
            "fault-test-tenant-primary-3",
            "uid-3",
            Some(
                json!({"exitCode": 0, "reason": "Completed", "finishedAt": "2026-09-11T10:05:04Z"}),
            ),
        );
        let mut deleted_without_state = exited.clone();
        deleted_without_state["status"]["containerStatuses"] = json!([]);
        let replacement = pod_json("fault-test-tenant-primary-3", "uid-3-new", None);
        let raw = format!(
            "{}\n{}\n{}\n{}\n{}\nError from server: watch closed\n",
            json!({"kind": "List", "items": [running.clone()]}),
            serde_json::to_string_pretty(&running).unwrap(),
            serde_json::to_string_pretty(&exited).unwrap(),
            serde_json::to_string_pretty(&deleted_without_state).unwrap(),
            serde_json::to_string_pretty(&replacement).unwrap(),
        );
        let stream = parse_watch_stream(&raw);
        assert_eq!(stream.objects.len(), 5);
        assert!(stream.truncated);
        let states = final_pod_states(&stream.objects);
        assert_eq!(states.len(), 2);
        let old = &states["uid-3"];
        assert_eq!(old.rustfs_terminated.as_ref().map(|t| t.exit_code), Some(0));
        assert!(states["uid-3-new"].rustfs_terminated.is_none());
        let clean = parse_watch_stream("");
        assert!(clean.objects.is_empty() && !clean.truncated);
    }
}
