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

use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::thread::sleep;
use std::time::{Duration, Instant};

use crate::{
    fault::{
        preflight::{
            TargetPersistentVolumeClaimProof, TargetPersistentVolumeProof, TargetResolvedPodProof,
            TargetVolumeMountProof,
        },
        reporting::PodIdentity,
    },
    framework::{config::ClusterTestConfig, kubectl::Kubectl},
};

pub(crate) struct RustfsTargetInventory {
    pub identities: Vec<PodIdentity>,
    pub pod_proofs: Vec<TargetResolvedPodProof>,
}

pub(crate) fn rustfs_pod_identities(config: &ClusterTestConfig) -> Result<Vec<PodIdentity>> {
    let pods = rustfs_pods_json(config)?;
    let selector = rustfs_tenant_selector(config);
    let items = pod_items(&pods)?;
    pod_identities_from_items(items, &selector, &config.test_namespace)
}

pub(crate) fn rustfs_target_inventory(
    config: &ClusterTestConfig,
    include_volume_bindings: bool,
) -> Result<RustfsTargetInventory> {
    let pods = rustfs_pods_json(config)?;
    let selector = rustfs_tenant_selector(config);
    let items = pod_items(&pods)?;
    let identities = pod_identities_from_items(items, &selector, &config.test_namespace)?;
    let volume_maps = if include_volume_bindings {
        Some((pvc_map(config)?, pv_map(config)?))
    } else {
        None
    };
    let pod_proofs = items
        .iter()
        .filter_map(|item| match &volume_maps {
            Some((pvcs, pvs)) => target_pod_proof(item, Some(pvcs), Some(pvs)),
            None => target_pod_proof(item, None, None),
        })
        .collect();

    Ok(RustfsTargetInventory {
        identities,
        pod_proofs,
    })
}

fn rustfs_pods_json(config: &ClusterTestConfig) -> Result<Value> {
    let selector = format!("rustfs.tenant={}", config.tenant_name);
    let output = Kubectl::new(config)
        .namespaced(&config.test_namespace)
        .command(["get", "pod", "-l", &selector, "-o", "json"])
        .run_checked()?;
    serde_json::from_str::<Value>(&output.stdout).context("parse RustFS pod list json")
}

fn pod_items(value: &Value) -> Result<&[Value]> {
    value
        .pointer("/items")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .context("RustFS pod list did not contain an items array")
}

fn pod_identities_from_items(
    items: &[Value],
    selector: &str,
    namespace: &str,
) -> Result<Vec<PodIdentity>> {
    let pods = items
        .iter()
        .filter_map(|item| {
            let metadata = item.get("metadata")?;
            Some(PodIdentity {
                name: metadata.get("name")?.as_str()?.to_string(),
                uid: metadata.get("uid")?.as_str()?.to_string(),
            })
        })
        .collect::<Vec<_>>();
    ensure!(
        !pods.is_empty(),
        "no RustFS pods found for selector {selector} in namespace {namespace}",
    );
    Ok(pods)
}

fn rustfs_tenant_selector(config: &ClusterTestConfig) -> String {
    format!("rustfs.tenant={}", config.tenant_name)
}

fn pvc_map(config: &ClusterTestConfig) -> Result<BTreeMap<String, Value>> {
    let output = Kubectl::new(config)
        .namespaced(&config.test_namespace)
        .command(["get", "pvc", "-o", "json"])
        .run_checked()?;
    let value = serde_json::from_str::<Value>(&output.stdout).context("parse PVC list json")?;
    Ok(items_by_metadata_name(&value))
}

fn pv_map(config: &ClusterTestConfig) -> Result<BTreeMap<String, Value>> {
    let output = Kubectl::new(config)
        .command(["get", "pv", "-o", "json"])
        .run_checked()?;
    let value = serde_json::from_str::<Value>(&output.stdout).context("parse PV list json")?;
    Ok(items_by_metadata_name(&value))
}

fn items_by_metadata_name(value: &Value) -> BTreeMap<String, Value> {
    value
        .pointer("/items")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| {
            let name = item.pointer("/metadata/name").and_then(Value::as_str)?;
            Some((name.to_string(), item.clone()))
        })
        .collect()
}

fn target_pod_proof(
    pod: &Value,
    pvcs: Option<&BTreeMap<String, Value>>,
    pvs: Option<&BTreeMap<String, Value>>,
) -> Option<TargetResolvedPodProof> {
    let metadata = pod.get("metadata")?;
    let name = metadata.get("name")?.as_str()?.to_string();
    let uid = metadata.get("uid")?.as_str()?.to_string();
    let mut proof = TargetResolvedPodProof::new(name, uid).with_ready(pod_is_ready(pod));
    if let Some(node) = pod.pointer("/spec/nodeName").and_then(Value::as_str) {
        proof = proof.with_node(node);
    }
    let claims = match (pvcs, pvs) {
        (Some(pvcs), Some(pvs)) => persistent_volume_claim_names(pod)
            .into_iter()
            .map(|claim| target_pvc_proof(&claim, pvcs, pvs))
            .collect(),
        _ => Vec::new(),
    };
    let volume_mounts = match (pvcs, pvs) {
        (Some(_), Some(_)) => target_volume_mounts(pod),
        _ => Vec::new(),
    };
    Some(
        proof
            .with_persistent_volume_claims(claims)
            .with_volume_mounts(volume_mounts),
    )
}

fn pod_is_ready(pod: &Value) -> bool {
    pod.pointer("/metadata/deletionTimestamp").is_none()
        && pod
            .pointer("/status/conditions")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .any(|condition| {
                condition.get("type").and_then(Value::as_str) == Some("Ready")
                    && condition.get("status").and_then(Value::as_str) == Some("True")
            })
}

fn persistent_volume_claim_names(pod: &Value) -> Vec<String> {
    let mut claims = pod
        .pointer("/spec/volumes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|volume| {
            volume
                .pointer("/persistentVolumeClaim/claimName")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect::<Vec<_>>();
    claims.sort();
    claims.dedup();
    claims
}

fn target_volume_mounts(pod: &Value) -> Vec<TargetVolumeMountProof> {
    let volume_claims = pod
        .pointer("/spec/volumes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|volume| {
            let name = volume.get("name").and_then(Value::as_str)?;
            let claim = volume
                .pointer("/persistentVolumeClaim/claimName")
                .and_then(Value::as_str)
                .map(str::to_string);
            Some((name.to_string(), claim))
        })
        .collect::<BTreeMap<_, _>>();
    let mut mounts = pod
        .pointer("/spec/containers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .flat_map(|container| {
            let container_name = container
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            container
                .get("volumeMounts")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|mount| {
                    let volume_name = mount.get("name").and_then(Value::as_str)?;
                    let mount_path = mount.get("mountPath").and_then(Value::as_str)?;
                    Some(TargetVolumeMountProof {
                        container_name: container_name.clone(),
                        mount_path: mount_path.to_string(),
                        volume_name: volume_name.to_string(),
                        persistent_volume_claim: volume_claims.get(volume_name).cloned().flatten(),
                    })
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    mounts.sort_by(|left, right| {
        left.container_name
            .cmp(&right.container_name)
            .then_with(|| left.mount_path.cmp(&right.mount_path))
            .then_with(|| left.volume_name.cmp(&right.volume_name))
    });
    mounts
}

fn target_pvc_proof(
    claim: &str,
    pvcs: &BTreeMap<String, Value>,
    pvs: &BTreeMap<String, Value>,
) -> TargetPersistentVolumeClaimProof {
    let pvc = pvcs.get(claim);
    let volume_name = pvc
        .and_then(|value| value.pointer("/spec/volumeName"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let storage_class = pvc
        .and_then(|value| value.pointer("/spec/storageClassName"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let persistent_volume = volume_name
        .as_deref()
        .and_then(|volume| pvs.get(volume).map(|pv| target_pv_proof(volume, pv)));

    TargetPersistentVolumeClaimProof {
        name: claim.to_string(),
        volume_name,
        storage_class,
        persistent_volume,
    }
}

fn target_pv_proof(name: &str, pv: &Value) -> TargetPersistentVolumeProof {
    TargetPersistentVolumeProof {
        name: name.to_string(),
        source: pv_source(pv).map(str::to_string),
        node: pv_node_affinity_hostname(pv),
        device_or_path: pv_device_or_path(pv),
    }
}

fn pv_source(pv: &Value) -> Option<&'static str> {
    if pv.pointer("/spec/local/path").is_some() {
        Some("local")
    } else if pv.pointer("/spec/hostPath/path").is_some() {
        Some("host-path")
    } else if pv.pointer("/spec/csi/volumeHandle").is_some() {
        Some("csi")
    } else {
        None
    }
}

fn pv_node_affinity_hostname(pv: &Value) -> Option<String> {
    pv.pointer("/spec/nodeAffinity/required/nodeSelectorTerms")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|term| term.get("matchExpressions").and_then(Value::as_array))
        .flatten()
        .find_map(|expression| {
            if expression.get("key").and_then(Value::as_str) != Some("kubernetes.io/hostname")
                || expression.get("operator").and_then(Value::as_str) != Some("In")
            {
                return None;
            }
            expression
                .get("values")
                .and_then(Value::as_array)?
                .iter()
                .find_map(|value| value.as_str().map(str::to_string))
        })
}

fn pv_device_or_path(pv: &Value) -> Option<String> {
    pv.pointer("/spec/local/path")
        .or_else(|| pv.pointer("/spec/hostPath/path"))
        .or_else(|| pv.pointer("/spec/csi/volumeHandle"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

pub(crate) fn wait_for_rustfs_pod_replacement(
    config: &ClusterTestConfig,
    before: &[PodIdentity],
    timeout: Duration,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    let mut last_snapshot = Vec::new();
    let mut last_error = "not checked yet".to_string();

    loop {
        if Instant::now() >= deadline {
            bail!(
                "timed out waiting for PodChaos to replace a RustFS pod after {timeout:?}\nbefore: {before:?}\nlast: {last_snapshot:?}\nlast error: {last_error}",
            );
        }

        match rustfs_pod_identities(config) {
            Ok(current) => {
                if pod_replacement_observed(before, &current) {
                    return Ok(());
                }
                last_snapshot = current;
                last_error = "none".to_string();
            }
            Err(error) => {
                last_error = error.to_string();
            }
        }

        sleep(Duration::from_secs(1));
    }
}

pub(crate) fn wait_for_rustfs_pod_deletion(
    config: &ClusterTestConfig,
    before: &[PodIdentity],
    timeout: Duration,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    let mut last_snapshot = Vec::new();
    let mut last_error = "not checked yet".to_string();

    loop {
        if Instant::now() >= deadline {
            bail!(
                "timed out waiting for PodChaos to delete a RustFS pod after {timeout:?}\nbefore: {before:?}\nlast: {last_snapshot:?}\nlast error: {last_error}",
            );
        }

        match rustfs_pod_identities(config) {
            Ok(current) => {
                if pod_deletion_observed(before, &current) {
                    return Ok(());
                }
                last_snapshot = current;
                last_error = "none".to_string();
            }
            Err(error) => {
                last_error = error.to_string();
            }
        }

        sleep(Duration::from_millis(250));
    }
}

pub(crate) fn pod_deletion_observed(before: &[PodIdentity], current: &[PodIdentity]) -> bool {
    let current_uids = current
        .iter()
        .map(|pod| pod.uid.as_str())
        .collect::<BTreeSet<_>>();
    !before.is_empty()
        && before
            .iter()
            .any(|pod| !current_uids.contains(pod.uid.as_str()))
}

pub(crate) fn pod_replacement_observed(before: &[PodIdentity], current: &[PodIdentity]) -> bool {
    if before.is_empty() || current.is_empty() {
        return false;
    }

    let before_uids = before
        .iter()
        .map(|pod| pod.uid.as_str())
        .collect::<BTreeSet<_>>();
    let current_uids = current
        .iter()
        .map(|pod| pod.uid.as_str())
        .collect::<BTreeSet<_>>();
    let old_uid_removed = before_uids.iter().any(|uid| !current_uids.contains(uid));
    let new_uid_added = current_uids.iter().any(|uid| !before_uids.contains(uid));

    old_uid_removed && new_uid_added
}

#[cfg(test)]
mod tests {
    use super::{
        items_by_metadata_name, persistent_volume_claim_names, pod_deletion_observed,
        pod_replacement_observed, target_pod_proof,
    };
    use crate::fault::{preflight::target_pod_has_fixed_volume, reporting::PodIdentity};
    use serde_json::json;

    #[test]
    fn pod_replacement_requires_old_uid_removed_and_new_uid_added() {
        let before = vec![
            PodIdentity {
                name: "rustfs-0".to_string(),
                uid: "uid-a".to_string(),
            },
            PodIdentity {
                name: "rustfs-1".to_string(),
                uid: "uid-b".to_string(),
            },
        ];

        assert!(!pod_replacement_observed(&before, &before));
        assert!(!pod_replacement_observed(&before, &before[..1]));
        assert!(!pod_deletion_observed(&before, &before));
        assert!(pod_deletion_observed(&before, &before[..1]));
        assert!(pod_replacement_observed(
            &before,
            &[
                PodIdentity {
                    name: "rustfs-0".to_string(),
                    uid: "uid-c".to_string(),
                },
                before[1].clone(),
            ],
        ));
    }

    #[test]
    fn target_pod_proof_links_pod_pvc_pv_node_and_path() {
        let pod = json!({
            "metadata": {"name": "rustfs-0", "uid": "uid-a"},
            "spec": {
                "nodeName": "node-a",
                "containers": [{
                    "name": "rustfs",
                    "volumeMounts": [{"name": "data", "mountPath": "/data/rustfs0"}]
                }],
                "volumes": [{
                    "name": "data",
                    "persistentVolumeClaim": {"claimName": "data-rustfs-0"}
                }]
            },
            "status": {"conditions": [{"type": "Ready", "status": "True"}]}
        });
        let pvc_list = json!({
            "items": [{
                "metadata": {"name": "data-rustfs-0"},
                "spec": {
                    "volumeName": "pv-a",
                    "storageClassName": "fast-local"
                }
            }]
        });
        let pv_list = json!({
            "items": [{
                "metadata": {"name": "pv-a"},
                "spec": {
                    "local": {"path": "/mnt/rustfs0"},
                    "nodeAffinity": {
                        "required": {
                            "nodeSelectorTerms": [{
                                "matchExpressions": [{
                                    "key": "kubernetes.io/hostname",
                                    "operator": "In",
                                    "values": ["node-a"]
                                }]
                            }]
                        }
                    }
                }
            }]
        });
        let pvcs = items_by_metadata_name(&pvc_list);
        let pvs = items_by_metadata_name(&pv_list);

        let proof = target_pod_proof(&pod, Some(&pvcs), Some(&pvs)).expect("proof");

        assert_eq!(persistent_volume_claim_names(&pod), vec!["data-rustfs-0"]);
        assert!(proof.ready);
        assert_eq!(proof.node.as_deref(), Some("node-a"));
        assert_eq!(proof.persistent_volume_claims.len(), 1);
        let claim = &proof.persistent_volume_claims[0];
        assert_eq!(claim.volume_name.as_deref(), Some("pv-a"));
        let pv = claim.persistent_volume.as_ref().expect("pv");
        assert_eq!(pv.source.as_deref(), Some("local"));
        assert_eq!(pv.node.as_deref(), Some("node-a"));
        assert_eq!(pv.device_or_path.as_deref(), Some("/mnt/rustfs0"));
        assert!(target_pod_has_fixed_volume(&proof, "/data/rustfs0"));
    }

    #[test]
    fn unrelated_pvc_does_not_prove_empty_dir_volume_target() {
        let pod = json!({
            "metadata": {"name": "rustfs-0", "uid": "uid-a"},
            "spec": {
                "nodeName": "node-a",
                "containers": [{
                    "name": "rustfs",
                    "volumeMounts": [
                        {"name": "data", "mountPath": "/data/rustfs0"},
                        {"name": "logs", "mountPath": "/var/log/rustfs"}
                    ]
                }],
                "volumes": [
                    {"name": "data", "emptyDir": {}},
                    {"name": "logs", "persistentVolumeClaim": {"claimName": "logs-rustfs-0"}}
                ]
            },
            "status": {"conditions": [{"type": "Ready", "status": "True"}]}
        });
        let pvc_list = json!({
            "items": [{
                "metadata": {"name": "logs-rustfs-0"},
                "spec": {"volumeName": "pv-logs", "storageClassName": "fast-csi"}
            }]
        });
        let pv_list = json!({
            "items": [{
                "metadata": {"name": "pv-logs"},
                "spec": {"csi": {"volumeHandle": "logs-handle"}}
            }]
        });

        let proof = target_pod_proof(
            &pod,
            Some(&items_by_metadata_name(&pvc_list)),
            Some(&items_by_metadata_name(&pv_list)),
        )
        .expect("proof");

        assert_eq!(proof.persistent_volume_claims.len(), 1);
        assert!(
            !target_pod_has_fixed_volume(&proof, "/data/rustfs0"),
            "an unrelated logs PVC must not prove the emptyDir data mount"
        );
    }

    #[test]
    fn target_pod_proof_can_skip_volume_binding_enrichment() {
        let pod = json!({
            "metadata": {"name": "rustfs-0", "uid": "uid-a"},
            "spec": {
                "nodeName": "node-a",
                "volumes": [{
                    "name": "data",
                    "persistentVolumeClaim": {"claimName": "data-rustfs-0"}
                }]
            }
        });

        let proof = target_pod_proof(&pod, None, None).expect("proof");

        assert_eq!(proof.name, "rustfs-0");
        assert_eq!(proof.node.as_deref(), Some("node-a"));
        assert!(proof.persistent_volume_claims.is_empty());
    }
}
