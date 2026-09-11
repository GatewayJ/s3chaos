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
//! Every name that reaches an argv or an API path is validated as a DNS-1123
//! subdomain first: object names come from the cluster (owner references,
//! Deployment listings) and must never be able to smuggle a kubectl flag.

use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;
use std::collections::BTreeMap;

use super::evidence::{
    ContainerTermination, DEFAULT_TERMINATION_GRACE_PERIOD_SECONDS, LifecycleOperation,
    StatefulSetIdentity, parse_rfc3339_ms,
};
use crate::fault::pods::{pod_is_ready, rustfs_tenant_selector};
use crate::framework::{command::CommandSpec, config::ClusterTestConfig, kubectl::Kubectl};

pub const RUSTFS_CONTAINER_NAME: &str = "rustfs";
/// Bounded API calls so a hung API server cannot block the rolling worker
/// (and the handle's Drop, which joins it) forever. The Pod watch is exempt.
pub const REQUEST_TIMEOUT_FLAG: &str = "--request-timeout=30s";
/// Durable record of a paused operator, written on the Deployment itself so
/// a cleanup with no artifact context can find and undo the pause.
pub const OPERATOR_PAUSE_REPLICAS_ANNOTATION: &str = "s3chaos.rustfs.com/operator-paused-replicas";
pub const OPERATOR_PAUSE_RUN_ANNOTATION: &str = "s3chaos.rustfs.com/operator-paused-run";
pub const OPERATOR_NAME_LABEL: &str = "app.kubernetes.io/name";
pub const OPERATOR_NAME_LABEL_VALUE: &str = "rustfs-operator";

/// DNS-1123 subdomain: lowercase alphanumerics, `-` and `.`, starting and
/// ending alphanumeric, at most 253 characters. Rejects `.`, `..`, a leading
/// `-` (a flag), and anything with a path separator or whitespace.
pub fn ensure_dns1123_subdomain(value: &str, what: &str) -> Result<()> {
    let valid = !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label
                    .chars()
                    .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        });
    ensure!(
        valid,
        "{what} {value:?} is not a valid DNS-1123 subdomain and is not safe for kubectl arguments"
    );
    Ok(())
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
}

/// The graceful delete's metadata. Only an observation with a positive
/// `deletionGracePeriodSeconds` counts: kubelet's final delete rewrites
/// `deletionTimestamp` to now and the grace to zero (apiserver
/// `BeforeDelete`), which says nothing about when SIGTERM was sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GracefulDeletion {
    pub deletion_timestamp: String,
    pub deletion_grace_period_seconds: i64,
}

impl GracefulDeletion {
    /// `deletionTimestamp - deletionGracePeriodSeconds`: when the API server
    /// accepted the graceful delete, i.e. the earliest SIGTERM time.
    pub fn sigterm_requested_at_ms(&self) -> Option<u64> {
        let deletion = parse_rfc3339_ms(&self.deletion_timestamp).ok()?;
        let grace = u64::try_from(self.deletion_grace_period_seconds).ok()?;
        Some(deletion.saturating_sub(grace.saturating_mul(1_000)))
    }
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
    /// Restarts of the RustFS container only; sidecars do not count.
    pub restart_count: u64,
    pub owner: Option<PodOwner>,
    pub rustfs_terminated: Option<ContainerTermination>,
}

impl ObservedPod {
    pub fn graceful_deletion(&self) -> Option<GracefulDeletion> {
        let grace = self.deletion_grace_period_seconds?;
        let deletion_timestamp = self.deletion_timestamp.clone()?;
        (grace > 0).then_some(GracefulDeletion {
            deletion_timestamp,
            deletion_grace_period_seconds: grace,
        })
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
    let rustfs = rustfs_container_status(pod);
    let restart_count = rustfs
        .and_then(|status| status.get("restartCount"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let owner = metadata
        .get("ownerReferences")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|reference| reference.get("controller").and_then(Value::as_bool) == Some(true))
        .map(|reference| {
            let field = |key: &str| {
                reference
                    .get(key)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string()
            };
            PodOwner {
                kind: field("kind"),
                name: field("name"),
                uid: field("uid"),
            }
        });
    let rustfs_terminated = rustfs.and_then(|status| {
        let terminated = status.pointer("/state/terminated")?;
        let text = |key: &str| {
            terminated
                .get(key)
                .and_then(Value::as_str)
                .map(str::to_string)
        };
        Some(ContainerTermination {
            exit_code: terminated.get("exitCode").and_then(Value::as_i64)?,
            signal: terminated.get("signal").and_then(Value::as_i64),
            reason: text("reason"),
            message: text("message"),
            started_at: text("startedAt"),
            finished_at: text("finishedAt"),
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
        ready: pod_is_ready(pod),
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
    let required = |key: &str| {
        metadata
            .get(key)
            .and_then(Value::as_str)
            .with_context(|| format!("StatefulSet has no metadata.{key}"))
            .map(str::to_string)
    };
    let name = required("name")?;
    let uid = required("uid")?;
    let namespace = required("namespace")?;
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
    pub selector: BTreeMap<String, String>,
    pub images: Vec<String>,
    pub template_labels: BTreeMap<String, String>,
    pub annotations: BTreeMap<String, String>,
}

fn string_map(value: Option<&Value>) -> BTreeMap<String, String> {
    value
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter_map(|(key, value)| Some((key.clone(), value.as_str()?.to_string())))
        .collect()
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
        selector: string_map(value.pointer("/spec/selector/matchLabels")),
        images: value
            .pointer("/spec/template/spec/containers")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|container| container.get("image").and_then(Value::as_str))
            .map(str::to_string)
            .collect(),
        template_labels: string_map(value.pointer("/spec/template/metadata/labels")),
        annotations: string_map(value.pointer("/metadata/annotations")),
    })
}

impl ObservedDeployment {
    /// The replica count recorded by a previous, unfinished pause; a present
    /// but unparsable record is an error, never silently ignored.
    pub fn paused_replicas(&self) -> Result<Option<u32>> {
        let Some(raw) = self.annotations.get(OPERATOR_PAUSE_REPLICAS_ANNOTATION) else {
            return Ok(None);
        };
        let replicas = raw.trim().parse::<u32>().with_context(|| {
            format!(
                "Deployment {} carries an unreadable pause record {OPERATOR_PAUSE_REPLICAS_ANNOTATION}={raw:?}; restore the operator manually and remove the annotation",
                self.name
            )
        })?;
        ensure!(
            replicas > 0,
            "Deployment {} pause record {OPERATOR_PAUSE_REPLICAS_ANNOTATION}={raw:?} is zero; restore the operator manually and remove the annotation",
            self.name
        );
        Ok(Some(replicas))
    }
}

/// Prove a Deployment is the RustFS operator before pausing it: a container
/// image containing `image_match`, or the canonical name label.
pub fn verify_operator_identity(
    deployment: &ObservedDeployment,
    image_match: &str,
) -> Result<(String, String)> {
    ensure!(
        !image_match.trim().is_empty(),
        "operator image match must not be empty"
    );
    if let Some(image) = deployment
        .images
        .iter()
        .find(|image| image.contains(image_match))
    {
        return Ok((image.clone(), "image".to_string()));
    }
    if deployment
        .template_labels
        .get(OPERATOR_NAME_LABEL)
        .map(String::as_str)
        == Some(OPERATOR_NAME_LABEL_VALUE)
    {
        return Ok((
            deployment.images.first().cloned().unwrap_or_default(),
            "label".to_string(),
        ));
    }
    bail!(
        "Deployment {} does not look like the RustFS operator: no container image contains {image_match:?} and the {OPERATOR_NAME_LABEL} label is not {OPERATOR_NAME_LABEL_VALUE:?} (images: {:?}); refusing to pause it",
        deployment.name,
        deployment.images
    )
}

fn kubectl(cluster: &ClusterTestConfig, namespace: &str) -> Result<Kubectl> {
    ensure_dns1123_subdomain(namespace, "namespace")?;
    Ok(Kubectl::new(cluster).namespaced(namespace))
}

pub fn list_rustfs_pods_command(cluster: &ClusterTestConfig) -> Result<CommandSpec> {
    Ok(kubectl(cluster, &cluster.test_namespace)?
        .command([
            "get",
            "pod",
            "-l",
            rustfs_tenant_selector(cluster).as_str(),
            "-o",
            "json",
        ])
        .arg(REQUEST_TIMEOUT_FLAG))
}

/// Streams every change to the tenant Pods as concatenated JSON objects; the
/// final state of a deleted Pod (its container exit code) is only reliably
/// visible in this stream because the Pod object disappears right after.
pub fn watch_rustfs_pods_command(cluster: &ClusterTestConfig) -> Result<CommandSpec> {
    Ok(kubectl(cluster, &cluster.test_namespace)?.command([
        "get",
        "pod",
        "-l",
        rustfs_tenant_selector(cluster).as_str(),
        "-o",
        "json",
        "--watch",
    ]))
}

pub fn get_statefulset_command(cluster: &ClusterTestConfig, name: &str) -> Result<CommandSpec> {
    ensure_dns1123_subdomain(name, "StatefulSet name")?;
    Ok(kubectl(cluster, &cluster.test_namespace)?
        .command(["get", "statefulset", name, "-o", "json"])
        .arg(REQUEST_TIMEOUT_FLAG))
}

pub fn get_deployment_command(
    cluster: &ClusterTestConfig,
    namespace: &str,
    name: &str,
) -> Result<CommandSpec> {
    ensure_dns1123_subdomain(name, "Deployment name")?;
    Ok(kubectl(cluster, namespace)?
        .command(["get", "deployment", name, "-o", "json"])
        .arg(REQUEST_TIMEOUT_FLAG))
}

pub fn list_deployments_command(
    cluster: &ClusterTestConfig,
    namespace: &str,
) -> Result<CommandSpec> {
    Ok(kubectl(cluster, namespace)?
        .command(["get", "deployment", "-o", "json"])
        .arg(REQUEST_TIMEOUT_FLAG))
}

pub fn list_pods_by_selector_command(
    cluster: &ClusterTestConfig,
    namespace: &str,
    selector: &BTreeMap<String, String>,
) -> Result<CommandSpec> {
    ensure!(!selector.is_empty(), "Pod selector must not be empty");
    let selector = selector
        .iter()
        .map(|(key, value)| {
            ensure!(
                !key.starts_with('-') && !value.starts_with('-') && !key.is_empty(),
                "Pod selector label {key:?}={value:?} is not safe for kubectl arguments"
            );
            Ok(format!("{key}={value}"))
        })
        .collect::<Result<Vec<_>>>()?
        .join(",");
    Ok(kubectl(cluster, namespace)?
        .command(["get", "pod", "-l", selector.as_str(), "-o", "json"])
        .arg(REQUEST_TIMEOUT_FLAG))
}

/// Graceful delete with the Pod's own `terminationGracePeriodSeconds`: the
/// request body deliberately carries no `gracePeriodSeconds`, and the UID
/// precondition guarantees the delete cannot hit a replacement Pod.
pub fn delete_pod_default_grace_command(
    cluster: &ClusterTestConfig,
    pod: &str,
    pod_uid: &str,
) -> Result<CommandSpec> {
    ensure_dns1123_subdomain(&cluster.test_namespace, "namespace")?;
    ensure_dns1123_subdomain(pod, "target Pod name")?;
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
        .arg(REQUEST_TIMEOUT_FLAG)
        .stdin(serde_json::to_string(&delete_options)?))
}

pub fn scale_statefulset_command(
    cluster: &ClusterTestConfig,
    name: &str,
    replicas: u32,
) -> Result<CommandSpec> {
    ensure_dns1123_subdomain(name, "StatefulSet name")?;
    Ok(kubectl(cluster, &cluster.test_namespace)?
        .command([
            "scale",
            "statefulset",
            name,
            &format!("--replicas={replicas}"),
        ])
        .arg(REQUEST_TIMEOUT_FLAG))
}

pub fn scale_deployment_command(
    cluster: &ClusterTestConfig,
    namespace: &str,
    name: &str,
    replicas: u32,
) -> Result<CommandSpec> {
    ensure_dns1123_subdomain(name, "Deployment name")?;
    Ok(kubectl(cluster, namespace)?
        .command([
            "scale",
            "deployment",
            name,
            &format!("--replicas={replicas}"),
        ])
        .arg(REQUEST_TIMEOUT_FLAG))
}

pub fn annotate_deployment_command(
    cluster: &ClusterTestConfig,
    namespace: &str,
    name: &str,
    annotations: &[(&str, String)],
) -> Result<CommandSpec> {
    ensure_dns1123_subdomain(name, "Deployment name")?;
    ensure!(!annotations.is_empty(), "no annotations to write");
    let mut args = vec![
        "annotate".to_string(),
        "deployment".to_string(),
        name.to_string(),
        "--overwrite".to_string(),
    ];
    for (key, value) in annotations {
        ensure!(
            !value.starts_with('-') && !value.contains(['\n', '=']),
            "annotation value {value:?} is not safe for kubectl arguments"
        );
        args.push(format!("{key}={value}"));
    }
    Ok(kubectl(cluster, namespace)?
        .command(args)
        .arg(REQUEST_TIMEOUT_FLAG))
}

pub fn remove_deployment_annotations_command(
    cluster: &ClusterTestConfig,
    namespace: &str,
    name: &str,
    keys: &[&str],
) -> Result<CommandSpec> {
    ensure_dns1123_subdomain(name, "Deployment name")?;
    ensure!(!keys.is_empty(), "no annotations to remove");
    let mut args = vec![
        "annotate".to_string(),
        "deployment".to_string(),
        name.to_string(),
    ];
    args.extend(keys.iter().map(|key| format!("{key}-")));
    Ok(kubectl(cluster, namespace)?
        .command(args)
        .arg(REQUEST_TIMEOUT_FLAG))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionCheck {
    pub namespace: String,
    pub verb: &'static str,
    pub resource: &'static str,
    pub subresource: Option<&'static str>,
}

/// RBAC the operation needs. `kubectl scale` patches the `scale`
/// subresource, so that is what is checked, not the parent resource.
pub fn required_permissions(
    operation: LifecycleOperation,
    test_namespace: &str,
    operator_namespace: &str,
) -> Vec<PermissionCheck> {
    let check = |namespace: &str, verb, resource, subresource| PermissionCheck {
        namespace: namespace.to_string(),
        verb,
        resource,
        subresource,
    };
    let mut required = vec![
        check(test_namespace, "get", "pods", None),
        check(test_namespace, "list", "pods", None),
        check(test_namespace, "watch", "pods", None),
        check(test_namespace, "delete", "pods", None),
        check(test_namespace, "get", "statefulsets", None),
    ];
    if operation == LifecycleOperation::Cold {
        required.extend([
            check(test_namespace, "patch", "statefulsets", Some("scale")),
            check(operator_namespace, "get", "deployments", None),
            check(operator_namespace, "list", "deployments", None),
            check(operator_namespace, "list", "pods", None),
            check(operator_namespace, "patch", "deployments", None),
            check(operator_namespace, "patch", "deployments", Some("scale")),
        ]);
    }
    required
}

pub fn auth_can_i_command(
    cluster: &ClusterTestConfig,
    check: &PermissionCheck,
) -> Result<CommandSpec> {
    let mut command =
        kubectl(cluster, &check.namespace)?.command(["auth", "can-i", check.verb, check.resource]);
    if let Some(subresource) = check.subresource {
        command = command.arg(format!("--subresource={subresource}"));
    }
    Ok(command.arg(REQUEST_TIMEOUT_FLAG))
}

pub fn run_json(command: &CommandSpec) -> Result<Value> {
    let output = command.run_checked()?;
    serde_json::from_str(&output.stdout)
        .with_context(|| format!("parse JSON from {}", command.display()))
}

/// Split the concatenated JSON documents `kubectl get --watch -o json`
/// writes; a `List` (the initial listing on some kubectl versions) is
/// flattened into its items. Trailing garbage ends the stream and is
/// reported as `truncated`.
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

/// One Pod UID as the watch saw it: the graceful deletion metadata from the
/// FIRST document that carried it (kubelet's final DELETED document rewrites
/// it to now/0) and the container's terminated state from the LAST document
/// that carried one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchedPod {
    pub last: ObservedPod,
    pub graceful_deletion: Option<GracefulDeletion>,
    pub terminated: Option<ContainerTermination>,
}

pub fn final_pod_states(objects: &[Value]) -> BTreeMap<String, WatchedPod> {
    let mut states = BTreeMap::<String, WatchedPod>::new();
    for value in objects {
        let Ok(pod) = parse_pod(value) else {
            continue;
        };
        let graceful_deletion = pod.graceful_deletion();
        let terminated = pod.rustfs_terminated.clone();
        let entry = states.entry(pod.uid.clone()).or_insert_with(|| WatchedPod {
            last: pod.clone(),
            graceful_deletion: None,
            terminated: None,
        });
        entry.last = pod;
        if entry.graceful_deletion.is_none() {
            entry.graceful_deletion = graceful_deletion;
        }
        if terminated.is_some() {
            entry.terminated = terminated;
        }
    }
    states
}

/// Require exactly one controlling StatefulSet across the tenant Pods, with
/// an owner name that is safe to pass to kubectl and that every Pod name is
/// derived from.
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
        ensure_dns1123_subdomain(&owner.name, "StatefulSet owner name")?;
        ensure!(
            !owner.uid.trim().is_empty(),
            "Pod {} owner reference has no uid",
            pod.name
        );
        ensure!(
            pod.ordinal
                .is_some_and(|ordinal| pod.name == format!("{}-{ordinal}", owner.name)),
            "Pod {} is not named after its owning StatefulSet {}",
            pod.name,
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
        LifecycleOperation, OPERATOR_PAUSE_REPLICAS_ANNOTATION, PermissionCheck,
        annotate_deployment_command, auth_can_i_command, delete_pod_default_grace_command,
        ensure_dns1123_subdomain, final_pod_states, get_deployment_command,
        get_statefulset_command, list_pods_by_selector_command, parse_deployment, parse_pod,
        parse_pod_list, parse_statefulset, parse_watch_stream, pod_ordinal,
        remove_deployment_annotations_command, require_single_statefulset_owner,
        required_permissions, scale_deployment_command, scale_statefulset_command,
        verify_operator_identity, watch_rustfs_pods_command,
    };
    use crate::fault::config::FaultTestConfig;
    use serde_json::json;
    use std::collections::BTreeMap;

    fn cluster() -> crate::framework::config::ClusterTestConfig {
        FaultTestConfig::for_test("real-cluster", "fast-csi").cluster
    }

    fn pod_json(name: &str, uid: &str, terminated: Option<serde_json::Value>) -> serde_json::Value {
        let deleting = terminated.is_some();
        let mut status = json!({
            "name": "rustfs",
            "containerID": "containerd://abc",
            "restartCount": 1,
            "ready": !deleting,
            "state": {"running": {"startedAt": "2026-09-11T10:00:00Z"}}
        });
        if let Some(terminated) = terminated {
            status["state"] = json!({"terminated": terminated});
        }
        let mut metadata = json!({
            "name": name,
            "uid": uid,
            "namespace": "rustfs-fault-test",
        });
        if deleting {
            metadata["deletionTimestamp"] = json!("2026-09-11T10:05:30Z");
            metadata["deletionGracePeriodSeconds"] = json!(30);
        }
        metadata["ownerReferences"] = json!([{
                    "apiVersion": "apps/v1",
                    "kind": "StatefulSet",
                    "name": "fault-test-tenant-primary",
                    "uid": "sts-uid",
                    "controller": true
        }]);
        json!({
            "metadata": metadata,
            "spec": {"terminationGracePeriodSeconds": 30, "containers": [{"name": "rustfs"}]},
            "status": {
                "phase": "Running",
                "conditions": [{"type": "Ready", "status": if deleting {"False"} else {"True"}}],
                "containerStatuses": [
                    {"name": "sidecar", "restartCount": 2, "ready": true, "state": {"running": {}}},
                    status
                ]
            }
        })
    }

    #[test]
    fn pod_parsing_reads_identity_owner_grace_and_terminated_state() {
        let running =
            parse_pod(&pod_json("fault-test-tenant-primary-3", "uid-3", None)).expect("pod");
        assert_eq!(running.ordinal, Some(3));
        assert!(running.ready && !running.terminating);
        assert_eq!(running.restart_count, 1, "sidecar restarts do not count");
        assert_eq!(running.termination_grace_period_seconds, 30);
        assert_eq!(
            running.owner.as_ref().map(|owner| owner.uid.as_str()),
            Some("sts-uid")
        );
        assert!(running.rustfs_terminated.is_none());
        assert!(running.graceful_deletion().is_none());

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
            exited
                .graceful_deletion()
                .expect("graceful")
                .sigterm_requested_at_ms(),
            Some(super::parse_rfc3339_ms("2026-09-11T10:05:00Z").expect("ts"))
        );

        // Fallbacks: no container statuses, no grace, no owner, no phase.
        let bare = parse_pod(&json!({"metadata": {"name": "solo", "uid": "u"}, "spec": {}}))
            .expect("bare pod");
        assert_eq!(bare.restart_count, 0);
        assert_eq!(bare.termination_grace_period_seconds, 30);
        assert!(bare.owner.is_none() && !bare.ready && bare.ordinal.is_none());
        assert_eq!(bare.phase, "Unknown");
        // A single unnamed container is used when no container is named rustfs.
        let single = parse_pod(&json!({
            "metadata": {"name": "solo-0", "uid": "u"},
            "status": {"containerStatuses": [{"name": "server", "restartCount": 4}]}
        }))
        .expect("single container");
        assert_eq!(single.restart_count, 4);

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
    fn statefulset_ownership_requires_exactly_one_safe_controlling_statefulset() {
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
        other_sts["metadata"]["ownerReferences"][0]["name"] = json!("other");
        let pods = parse_pod_list(&json!({"items": [
            pod_json("fault-test-tenant-primary-0", "uid-0", None),
            other_sts
        ]}))
        .expect("list");
        let error = require_single_statefulset_owner(&pods).expect_err("two owners");
        assert!(error.to_string().contains("2 StatefulSets"), "{error}");

        // An owner name that is a kubectl flag never reaches argv.
        let mut injected = pod_json("fault-test-tenant-primary-0", "uid-0", None);
        injected["metadata"]["ownerReferences"][0]["name"] = json!("--server=http://attacker");
        let error = require_single_statefulset_owner(&[parse_pod(&injected).expect("pod")])
            .expect_err("flag-shaped owner");
        assert!(error.to_string().contains("DNS-1123"), "{error}");
        // The Pod must be named after its owner.
        let mut mismatched = pod_json("fault-test-tenant-primary-0", "uid-0", None);
        mismatched["metadata"]["ownerReferences"][0]["name"] = json!("elsewhere");
        let error = require_single_statefulset_owner(&[parse_pod(&mismatched).expect("pod")])
            .expect_err("owner name mismatch");
        assert!(error.to_string().contains("not named after"), "{error}");
        let mut no_uid = pod_json("fault-test-tenant-primary-0", "uid-0", None);
        no_uid["metadata"]["ownerReferences"][0]["uid"] = json!("");
        assert!(require_single_statefulset_owner(&[parse_pod(&no_uid).expect("pod")]).is_err());

        let mut orphan = pod_json("fault-test-tenant-primary-0", "uid-0", None);
        orphan["metadata"]["ownerReferences"] = json!([]);
        assert!(require_single_statefulset_owner(&[parse_pod(&orphan).expect("pod")]).is_err());
        assert!(require_single_statefulset_owner(&[]).is_err());
    }

    #[test]
    fn dns1123_validation_rejects_flags_dots_and_paths() {
        ensure_dns1123_subdomain("fault-test-tenant-primary", "name").expect("valid");
        ensure_dns1123_subdomain("a.b-c.d", "name").expect("valid subdomain");
        for bad in [
            "",
            ".",
            "..",
            "-leading",
            "trailing-",
            "--server=http://attacker",
            "Upper",
            "with space",
            "a/b",
            "a..b",
            "a_b",
        ] {
            assert!(
                ensure_dns1123_subdomain(bad, "name").is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn statefulset_and_deployment_parsing_read_scale_identity_and_retention_fields() {
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
            "metadata": {"name": "rustfs-operator", "annotations": {OPERATOR_PAUSE_REPLICAS_ANNOTATION: "2"}},
            "spec": {
                "replicas": 2,
                "selector": {"matchLabels": {"app.kubernetes.io/name": "rustfs-operator"}},
                "template": {
                    "metadata": {"labels": {"app.kubernetes.io/name": "rustfs-operator"}},
                    "spec": {"containers": [{"name": "operator", "image": "docker.io/rustfs/operator:1.0.0"}]}
                }
            },
            "status": {"replicas": 2, "availableReplicas": 2}
        }))
        .expect("deployment");
        assert_eq!(deployment.spec_replicas, 2);
        assert_eq!(deployment.available_replicas, 2);
        assert_eq!(
            deployment.selector,
            BTreeMap::from([(
                "app.kubernetes.io/name".to_string(),
                "rustfs-operator".to_string()
            )])
        );
        assert_eq!(deployment.paused_replicas().expect("record"), Some(2));
        assert_eq!(
            verify_operator_identity(&deployment, "rustfs/operator").expect("identity"),
            (
                "docker.io/rustfs/operator:1.0.0".to_string(),
                "image".to_string()
            )
        );
        assert_eq!(
            verify_operator_identity(&deployment, "no-such-image")
                .expect("label fallback")
                .1,
            "label"
        );
        let scaled_to_zero = parse_deployment(
            &json!({"metadata": {"name": "op"}, "spec": {"replicas": 0}, "status": {}}),
        )
        .expect("deployment");
        assert_eq!(scaled_to_zero.status_replicas, 0);
        assert_eq!(scaled_to_zero.paused_replicas().expect("no record"), None);
        let error = verify_operator_identity(&scaled_to_zero, "rustfs/operator")
            .expect_err("not the operator");
        assert!(error.to_string().contains("refusing to pause"), "{error}");
        let unreadable = parse_deployment(
            &json!({"metadata": {"name": "op", "annotations": {OPERATOR_PAUSE_REPLICAS_ANNOTATION: "many"}}}),
        )
        .expect("deployment");
        let error = unreadable.paused_replicas().expect_err("unreadable record");
        assert!(
            error.to_string().contains("unreadable pause record"),
            "{error}"
        );
        let zero = parse_deployment(
            &json!({"metadata": {"name": "op", "annotations": {OPERATOR_PAUSE_REPLICAS_ANNOTATION: "0"}}}),
        )
        .expect("deployment");
        assert!(zero.paused_replicas().is_err());
    }

    #[test]
    fn commands_render_default_grace_delete_scale_annotate_and_watch() {
        let cluster = cluster();
        let delete =
            delete_pod_default_grace_command(&cluster, "fault-test-tenant-primary-3", "uid-3")
                .expect("delete");
        assert_eq!(
            delete.display(),
            "kubectl --context real-cluster delete --raw /api/v1/namespaces/rustfs-fault-test/pods/fault-test-tenant-primary-3 -f - --request-timeout=30s"
        );
        let body: serde_json::Value =
            serde_json::from_str(delete.stdin.as_deref().expect("stdin")).expect("json");
        assert_eq!(body["preconditions"]["uid"], json!("uid-3"));
        assert!(
            body.get("gracePeriodSeconds").is_none(),
            "a default-grace delete must not override terminationGracePeriodSeconds"
        );
        assert!(delete_pod_default_grace_command(&cluster, "Bad/Name", "uid").is_err());
        assert!(delete_pod_default_grace_command(&cluster, "..", "uid").is_err());
        assert!(delete_pod_default_grace_command(&cluster, "pod-0", " ").is_err());
        let mut bad_namespace = cluster.clone();
        bad_namespace.test_namespace = "../kube-system".to_string();
        assert!(delete_pod_default_grace_command(&bad_namespace, "pod-0", "uid").is_err());
        assert!(list_rustfs_pods_command_is_err(&bad_namespace));

        assert_eq!(
            scale_statefulset_command(&cluster, "fault-test-tenant-primary", 0)
                .expect("scale")
                .display(),
            "kubectl --context real-cluster -n rustfs-fault-test scale statefulset fault-test-tenant-primary --replicas=0 --request-timeout=30s"
        );
        assert_eq!(
            scale_deployment_command(&cluster, "rustfs-system", "rustfs-operator", 1)
                .expect("scale")
                .display(),
            "kubectl --context real-cluster -n rustfs-system scale deployment rustfs-operator --replicas=1 --request-timeout=30s"
        );
        assert!(scale_statefulset_command(&cluster, "", 1).is_err());
        assert!(scale_statefulset_command(&cluster, "-n", 1).is_err());
        assert!(get_statefulset_command(&cluster, "--server=x").is_err());
        assert!(get_deployment_command(&cluster, "rustfs-system", "-x").is_err());
        assert!(get_deployment_command(&cluster, "-n", "op").is_err());
        assert_eq!(
            get_statefulset_command(&cluster, "fault-test-tenant-primary")
                .expect("get")
                .display(),
            "kubectl --context real-cluster -n rustfs-fault-test get statefulset fault-test-tenant-primary -o json --request-timeout=30s"
        );
        assert_eq!(
            watch_rustfs_pods_command(&cluster)
                .expect("watch")
                .display(),
            "kubectl --context real-cluster -n rustfs-fault-test get pod -l rustfs.tenant=fault-test-tenant -o json --watch"
        );
        assert_eq!(
            annotate_deployment_command(
                &cluster,
                "rustfs-system",
                "rustfs-operator",
                &[
                    (OPERATOR_PAUSE_REPLICAS_ANNOTATION, "1".to_string()),
                    (super::OPERATOR_PAUSE_RUN_ANNOTATION, "run-1".to_string()),
                ],
            )
            .expect("annotate")
            .display(),
            "kubectl --context real-cluster -n rustfs-system annotate deployment rustfs-operator --overwrite s3chaos.rustfs.com/operator-paused-replicas=1 s3chaos.rustfs.com/operator-paused-run=run-1 --request-timeout=30s"
        );
        assert!(
            annotate_deployment_command(
                &cluster,
                "rustfs-system",
                "rustfs-operator",
                &[(OPERATOR_PAUSE_REPLICAS_ANNOTATION, "-1".to_string())],
            )
            .is_err()
        );
        assert_eq!(
            remove_deployment_annotations_command(
                &cluster,
                "rustfs-system",
                "rustfs-operator",
                &[OPERATOR_PAUSE_REPLICAS_ANNOTATION],
            )
            .expect("remove")
            .display(),
            "kubectl --context real-cluster -n rustfs-system annotate deployment rustfs-operator s3chaos.rustfs.com/operator-paused-replicas- --request-timeout=30s"
        );
        assert_eq!(
            list_pods_by_selector_command(
                &cluster,
                "rustfs-system",
                &BTreeMap::from([("app".to_string(), "operator".to_string())]),
            )
            .expect("list")
            .display(),
            "kubectl --context real-cluster -n rustfs-system get pod -l app=operator -o json --request-timeout=30s"
        );
        assert!(
            list_pods_by_selector_command(&cluster, "rustfs-system", &BTreeMap::new()).is_err()
        );
    }

    fn list_rustfs_pods_command_is_err(
        cluster: &crate::framework::config::ClusterTestConfig,
    ) -> bool {
        super::list_rustfs_pods_command(cluster).is_err()
    }

    #[test]
    fn rbac_checks_cover_the_scale_subresource_for_cold_restarts() {
        let cluster = cluster();
        let basic = required_permissions(
            LifecycleOperation::GracefulPod,
            "rustfs-fault-test",
            "rustfs-system",
        );
        assert_eq!(
            basic
                .iter()
                .map(|check| format!("{}:{} {}", check.namespace, check.verb, check.resource))
                .collect::<Vec<_>>(),
            [
                "rustfs-fault-test:get pods",
                "rustfs-fault-test:list pods",
                "rustfs-fault-test:watch pods",
                "rustfs-fault-test:delete pods",
                "rustfs-fault-test:get statefulsets",
            ]
        );
        assert!(basic.iter().all(|check| check.subresource.is_none()));
        assert_eq!(
            required_permissions(
                LifecycleOperation::Rolling,
                "rustfs-fault-test",
                "rustfs-system"
            ),
            basic
        );
        let cold = required_permissions(
            LifecycleOperation::Cold,
            "rustfs-fault-test",
            "rustfs-system",
        );
        assert!(cold.contains(&PermissionCheck {
            namespace: "rustfs-fault-test".to_string(),
            verb: "patch",
            resource: "statefulsets",
            subresource: Some("scale"),
        }));
        assert!(cold.contains(&PermissionCheck {
            namespace: "rustfs-system".to_string(),
            verb: "patch",
            resource: "deployments",
            subresource: Some("scale"),
        }));
        assert!(cold.contains(&PermissionCheck {
            namespace: "rustfs-system".to_string(),
            verb: "list",
            resource: "pods",
            subresource: None,
        }));
        assert_eq!(
            auth_can_i_command(&cluster, &cold[5])
                .expect("command")
                .display(),
            "kubectl --context real-cluster -n rustfs-fault-test auth can-i patch statefulsets --subresource=scale --request-timeout=30s"
        );
        assert_eq!(
            auth_can_i_command(&cluster, &basic[3])
                .expect("command")
                .display(),
            "kubectl --context real-cluster -n rustfs-fault-test auth can-i delete pods --request-timeout=30s"
        );
    }

    #[test]
    fn watch_stream_keeps_first_graceful_deletion_and_last_terminated_state() {
        let running = pod_json("fault-test-tenant-primary-3", "uid-3", None);
        // MODIFIED: the API server accepted the graceful delete (grace 30).
        let mut deleting = running.clone();
        deleting["metadata"]["deletionTimestamp"] = json!("2026-09-11T10:05:30Z");
        deleting["metadata"]["deletionGracePeriodSeconds"] = json!(30);
        // MODIFIED: the container exited one second after SIGTERM.
        let exited = pod_json(
            "fault-test-tenant-primary-3",
            "uid-3",
            Some(
                json!({"exitCode": 0, "reason": "Completed", "finishedAt": "2026-09-11T10:05:01Z"}),
            ),
        );
        // DELETED: kubelet's final delete rewrites the metadata to now/0.
        let mut deleted = exited.clone();
        deleted["metadata"]["deletionTimestamp"] = json!("2026-09-11T10:05:02Z");
        deleted["metadata"]["deletionGracePeriodSeconds"] = json!(0);
        let replacement = pod_json("fault-test-tenant-primary-3", "uid-3-new", None);
        let raw = format!(
            "{}\n{}\n{}\n{}\n{}\n{}\nError from server: watch closed\n",
            json!({"kind": "List", "items": [running.clone()]}),
            serde_json::to_string_pretty(&running).unwrap(),
            serde_json::to_string_pretty(&deleting).unwrap(),
            serde_json::to_string_pretty(&exited).unwrap(),
            serde_json::to_string_pretty(&deleted).unwrap(),
            serde_json::to_string_pretty(&replacement).unwrap(),
        );
        let stream = parse_watch_stream(&raw);
        assert_eq!(stream.objects.len(), 6);
        assert!(stream.truncated);
        let states = final_pod_states(&stream.objects);
        assert_eq!(states.len(), 2);
        let old = &states["uid-3"];
        let deletion = old.graceful_deletion.as_ref().expect("graceful deletion");
        assert_eq!(deletion.deletion_grace_period_seconds, 30);
        assert_eq!(deletion.deletion_timestamp, "2026-09-11T10:05:30Z");
        assert_eq!(
            deletion.sigterm_requested_at_ms(),
            Some(super::parse_rfc3339_ms("2026-09-11T10:05:00Z").unwrap())
        );
        assert_eq!(old.terminated.as_ref().map(|t| t.exit_code), Some(0));
        assert_eq!(
            old.last.deletion_grace_period_seconds,
            Some(0),
            "the last document is the DELETED one"
        );
        assert!(states["uid-3-new"].terminated.is_none());
        assert!(states["uid-3-new"].graceful_deletion.is_none());

        // A stream that only ever saw the final grace-0 document yields no
        // graceful deletion, which the evidence layer reports as a violation.
        let only_final = final_pod_states(&[deleted]);
        assert!(only_final["uid-3"].graceful_deletion.is_none());
        assert!(only_final["uid-3"].terminated.is_some());

        let clean = parse_watch_stream("");
        assert!(clean.objects.is_empty() && !clean.truncated);
    }
}
