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

use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const HOST_STORAGE_PROOF_SCHEMA_VERSION: u8 = 1;
pub const HOST_STORAGE_PROOF_ARTIFACT: &str = "host-storage-proof.json";
pub const HOST_STORAGE_CLEANUP_ARTIFACT: &str = "host-storage-post-cleanup.json";
pub const HOST_STORAGE_PROOF_MAX_AGE_MS: u64 = 60_000;

const DM_FLAKEY_KIND: &str = "rustfs_block_device_flakey";
const DM_DROP_WRITES_KIND: &str = "rustfs_block_device_drop_writes_crash";
const DM_CRASH_TAINT_KEY: &str = "s3chaos.rustfs.com/dm-crash";
const READ_ONLY_PREFLIGHT_SCOPE: &str = "read-only Kubernetes and host metadata observation plus proof artifact write; no disk, PV, PVC, object, or power mutation";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HostStorageProofStatus {
    Satisfied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostStorageAllowlist {
    pub nodes: Vec<String>,
    pub devices: Vec<String>,
    pub persistent_volumes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostStorageMutationIntent {
    pub scenario: String,
    pub fault_name: String,
    pub fault_kind: String,
    pub run_id: String,
    pub context: String,
    pub namespace: String,
    pub tenant: String,
    pub observer_namespace: String,
    pub observer_pod: String,
    pub backend_specific_destructive_opt_in: bool,
    pub allowlist: HostStorageAllowlist,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostStorageTargetObservation {
    pub node: String,
    pub pod: String,
    pub pod_uid: String,
    pub persistent_volume_claim: String,
    pub persistent_volume: String,
    pub persistent_volume_path: String,
    pub mapper_name: String,
    pub logical_device: String,
    pub canonical_device: String,
    pub mount_source: String,
    pub mount_canonical_source: String,
    pub filesystem: String,
    pub recovery_table: String,
    pub observed_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostStorageProvenTarget {
    pub node: String,
    pub pod: String,
    pub pod_uid: String,
    pub persistent_volume_claim: String,
    pub persistent_volume: String,
    pub persistent_volume_path: String,
    pub mapper_name: String,
    pub logical_device: String,
    pub canonical_device: String,
    pub mount_source: String,
    pub mount_canonical_source: String,
    pub filesystem: String,
    pub recovery_table_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceMapperRollbackContract {
    pub mapper_name: String,
    pub suspend_mode: String,
    pub recovery_table_sha256: String,
    pub resume_without_udev_sync: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostStorageQuarantineContract {
    pub node: String,
    pub taint_key: String,
    pub effect: String,
    pub required_on_rollback_failure: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostStoragePostCleanupContract {
    pub require_recovery_table_match: bool,
    pub require_mount_device_match: bool,
    pub require_filesystem_mounted: bool,
    pub require_quarantine_absent: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostStorageRecoveryContract {
    pub rollback: DeviceMapperRollbackContract,
    pub quarantine: HostStorageQuarantineContract,
    pub post_cleanup: HostStoragePostCleanupContract,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostStorageMutationProof {
    pub schema_version: u8,
    pub status: HostStorageProofStatus,
    pub generated_at_ms: u64,
    pub scenario: String,
    pub fault_name: String,
    pub fault_kind: String,
    pub run_id: String,
    pub context: String,
    pub namespace: String,
    pub tenant: String,
    pub observer_namespace: String,
    pub observer_pod: String,
    pub backend: String,
    pub backend_specific_destructive_opt_in: bool,
    pub preflight_side_effects: String,
    pub allowlist: HostStorageAllowlist,
    pub target: HostStorageProvenTarget,
    pub recovery: HostStorageRecoveryContract,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostStoragePostCleanupObservation {
    pub schema_version: u8,
    pub scenario: String,
    pub fault_name: String,
    pub run_id: String,
    pub observed_at_ms: u64,
    pub node: String,
    pub persistent_volume: String,
    pub mapper_name: String,
    pub logical_device: String,
    pub canonical_device: String,
    pub mount_canonical_source: String,
    pub filesystem_mounted: bool,
    pub node_quarantined: bool,
    pub recovery_table_sha256: String,
}

impl HostStorageMutationProof {
    pub fn prove_device_mapper(
        intent: HostStorageMutationIntent,
        observation: HostStorageTargetObservation,
    ) -> Result<Self> {
        ensure!(
            intent.backend_specific_destructive_opt_in,
            "device-mapper mutation requires RUSTFS_FAULT_TEST_DEVICE_MAPPER_DESTRUCTIVE=1"
        );
        ensure_supported_dm_kind(&intent.fault_kind)?;
        validate_observation(&observation)?;
        require_exact_singleton("host node", &intent.allowlist.nodes, &observation.node)?;
        require_exact_singleton(
            "host device",
            &intent.allowlist.devices,
            &observation.logical_device,
        )?;
        require_exact_singleton(
            "PersistentVolume",
            &intent.allowlist.persistent_volumes,
            &observation.persistent_volume,
        )?;

        let recovery_table_sha256 = normalized_dm_table_sha256(&observation.recovery_table)?;
        let target = HostStorageProvenTarget {
            node: observation.node,
            pod: observation.pod,
            pod_uid: observation.pod_uid,
            persistent_volume_claim: observation.persistent_volume_claim,
            persistent_volume: observation.persistent_volume,
            persistent_volume_path: observation.persistent_volume_path,
            mapper_name: observation.mapper_name,
            logical_device: observation.logical_device,
            canonical_device: observation.canonical_device,
            mount_source: observation.mount_source,
            mount_canonical_source: observation.mount_canonical_source,
            filesystem: observation.filesystem,
            recovery_table_sha256: recovery_table_sha256.clone(),
        };
        let recovery =
            canonical_recovery_contract(&intent.fault_kind, &target, recovery_table_sha256)?;
        let proof = Self {
            schema_version: HOST_STORAGE_PROOF_SCHEMA_VERSION,
            status: HostStorageProofStatus::Satisfied,
            generated_at_ms: observation.observed_at_ms,
            scenario: intent.scenario,
            fault_name: intent.fault_name,
            fault_kind: intent.fault_kind,
            run_id: intent.run_id,
            context: intent.context,
            namespace: intent.namespace,
            tenant: intent.tenant,
            observer_namespace: intent.observer_namespace,
            observer_pod: intent.observer_pod,
            backend: "device-mapper".to_string(),
            backend_specific_destructive_opt_in: true,
            preflight_side_effects: READ_ONLY_PREFLIGHT_SCOPE.to_string(),
            allowlist: intent.allowlist,
            target,
            recovery,
        };
        proof.validate()?;
        Ok(proof)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == HOST_STORAGE_PROOF_SCHEMA_VERSION,
            "unsupported host-storage proof schema version {}",
            self.schema_version
        );
        ensure!(self.status == HostStorageProofStatus::Satisfied);
        ensure!(
            self.backend == "device-mapper" && self.backend_specific_destructive_opt_in,
            "host-storage proof lacks the device-mapper destructive opt-in"
        );
        ensure!(
            self.preflight_side_effects == READ_ONLY_PREFLIGHT_SCOPE,
            "host-storage proof does not declare the side-effect-free preflight scope"
        );
        for (label, value) in [
            ("scenario", self.scenario.as_str()),
            ("fault name", self.fault_name.as_str()),
            ("run id", self.run_id.as_str()),
            ("context", self.context.as_str()),
            ("namespace", self.namespace.as_str()),
            ("tenant", self.tenant.as_str()),
            ("observer namespace", self.observer_namespace.as_str()),
            ("observer Pod", self.observer_pod.as_str()),
        ] {
            ensure!(
                !value.trim().is_empty(),
                "host-storage proof {label} is empty"
            );
        }
        ensure!(
            self.observer_namespace != self.namespace,
            "host observer must be outside the disposable fault Tenant namespace"
        );
        ensure_supported_dm_kind(&self.fault_kind)?;
        validate_proven_target(&self.target)?;
        require_exact_singleton("host node", &self.allowlist.nodes, &self.target.node)?;
        require_exact_singleton(
            "host device",
            &self.allowlist.devices,
            &self.target.logical_device,
        )?;
        require_exact_singleton(
            "PersistentVolume",
            &self.allowlist.persistent_volumes,
            &self.target.persistent_volume,
        )?;
        ensure!(
            self.recovery
                == canonical_recovery_contract(
                    &self.fault_kind,
                    &self.target,
                    self.target.recovery_table_sha256.clone(),
                )?,
            "host-storage recovery/quarantine/cleanup contract is not canonical"
        );
        Ok(())
    }

    pub fn require_fresh_at(&self, fault_apply_started_at_ms: u64) -> Result<()> {
        ensure!(
            self.generated_at_ms > 0 && self.generated_at_ms <= fault_apply_started_at_ms,
            "host-storage proof timestamp is after fault apply or is missing"
        );
        ensure!(
            fault_apply_started_at_ms - self.generated_at_ms <= HOST_STORAGE_PROOF_MAX_AGE_MS,
            "host-storage proof is older than {}ms at fault apply",
            HOST_STORAGE_PROOF_MAX_AGE_MS
        );
        Ok(())
    }

    pub fn require_apply_observation(
        &self,
        observation: &HostStorageTargetObservation,
    ) -> Result<()> {
        validate_observation(observation)?;
        ensure!(
            self.target.node == observation.node
                && self.target.pod == observation.pod
                && self.target.pod_uid == observation.pod_uid
                && self.target.persistent_volume_claim == observation.persistent_volume_claim
                && self.target.persistent_volume == observation.persistent_volume
                && self.target.persistent_volume_path == observation.persistent_volume_path
                && self.target.mapper_name == observation.mapper_name
                && self.target.logical_device == observation.logical_device
                && self.target.canonical_device == observation.canonical_device
                && self.target.mount_source == observation.mount_source
                && self.target.mount_canonical_source == observation.mount_canonical_source
                && self.target.filesystem == observation.filesystem
                && self.target.recovery_table_sha256
                    == normalized_dm_table_sha256(&observation.recovery_table)?,
            "device-mapper target changed between host-storage preflight and fault apply"
        );
        Ok(())
    }

    pub fn validate_post_cleanup(
        &self,
        observation: &HostStoragePostCleanupObservation,
    ) -> Result<()> {
        ensure!(observation.schema_version == 1);
        ensure!(
            observation.scenario == self.scenario
                && observation.fault_name == self.fault_name
                && observation.run_id == self.run_id
                && observation.node == self.target.node
                && observation.persistent_volume == self.target.persistent_volume
                && observation.mapper_name == self.target.mapper_name
                && observation.logical_device == self.target.logical_device
                && observation.canonical_device == self.target.canonical_device
                && observation.mount_canonical_source == self.target.mount_canonical_source,
            "post-cleanup host-storage observation does not match its preflight proof"
        );
        ensure!(
            observation.observed_at_ms >= self.generated_at_ms,
            "post-cleanup host-storage observation predates preflight"
        );
        ensure!(
            observation.recovery_table_sha256 == self.target.recovery_table_sha256,
            "post-cleanup device-mapper table does not match the preflight recovery table"
        );
        ensure!(
            observation.filesystem_mounted && !observation.node_quarantined,
            "post-cleanup observation must prove the filesystem is mounted and node quarantine is absent"
        );
        Ok(())
    }
}

pub fn normalized_dm_table_sha256(table: &str) -> Result<String> {
    let normalized = table.split_whitespace().collect::<Vec<_>>().join(" ");
    ensure!(
        !normalized.is_empty(),
        "device-mapper recovery table is empty"
    );
    Ok(format!("{:x}", Sha256::digest(normalized.as_bytes())))
}

fn validate_observation(observation: &HostStorageTargetObservation) -> Result<()> {
    for (label, value) in [
        ("node", observation.node.as_str()),
        ("pod", observation.pod.as_str()),
        ("pod UID", observation.pod_uid.as_str()),
        ("PVC", observation.persistent_volume_claim.as_str()),
        ("PV", observation.persistent_volume.as_str()),
        ("PV path", observation.persistent_volume_path.as_str()),
        ("mapper name", observation.mapper_name.as_str()),
        ("logical device", observation.logical_device.as_str()),
        ("canonical device", observation.canonical_device.as_str()),
        ("mount source", observation.mount_source.as_str()),
        (
            "canonical mount source",
            observation.mount_canonical_source.as_str(),
        ),
        ("filesystem", observation.filesystem.as_str()),
        ("recovery table", observation.recovery_table.as_str()),
    ] {
        ensure!(
            !value.trim().is_empty(),
            "observed host-storage {label} is empty"
        );
    }
    ensure!(
        observation.logical_device == format!("/dev/mapper/{}", observation.mapper_name),
        "logical device does not match the device-mapper target name"
    );
    ensure!(
        observation.canonical_device == observation.mount_canonical_source,
        "mounted device does not resolve to the selected device-mapper target"
    );
    ensure!(
        observation.observed_at_ms > 0,
        "host-storage observation timestamp is missing"
    );
    Ok(())
}

fn validate_proven_target(target: &HostStorageProvenTarget) -> Result<()> {
    ensure!(
        target.logical_device == format!("/dev/mapper/{}", target.mapper_name)
            && target.canonical_device == target.mount_canonical_source,
        "host-storage proven device identity is inconsistent"
    );
    for (label, value) in [
        ("node", target.node.as_str()),
        ("pod", target.pod.as_str()),
        ("pod UID", target.pod_uid.as_str()),
        ("PVC", target.persistent_volume_claim.as_str()),
        ("PV", target.persistent_volume.as_str()),
        ("PV path", target.persistent_volume_path.as_str()),
        ("mapper name", target.mapper_name.as_str()),
        ("logical device", target.logical_device.as_str()),
        ("canonical device", target.canonical_device.as_str()),
        ("mount source", target.mount_source.as_str()),
        ("filesystem", target.filesystem.as_str()),
        ("recovery table hash", target.recovery_table_sha256.as_str()),
    ] {
        ensure!(
            !value.trim().is_empty(),
            "proven host-storage {label} is empty"
        );
    }
    Ok(())
}

fn canonical_recovery_contract(
    fault_kind: &str,
    target: &HostStorageProvenTarget,
    recovery_table_sha256: String,
) -> Result<HostStorageRecoveryContract> {
    let suspend_mode = match fault_kind {
        DM_FLAKEY_KIND => "noflush",
        DM_DROP_WRITES_KIND => "nolockfs",
        other => bail!("fault kind {other:?} is not a host-storage mutation"),
    };
    Ok(HostStorageRecoveryContract {
        rollback: DeviceMapperRollbackContract {
            mapper_name: target.mapper_name.clone(),
            suspend_mode: suspend_mode.to_string(),
            recovery_table_sha256,
            resume_without_udev_sync: true,
        },
        quarantine: HostStorageQuarantineContract {
            node: target.node.clone(),
            taint_key: DM_CRASH_TAINT_KEY.to_string(),
            effect: "NoSchedule".to_string(),
            required_on_rollback_failure: true,
        },
        post_cleanup: HostStoragePostCleanupContract {
            require_recovery_table_match: true,
            require_mount_device_match: true,
            require_filesystem_mounted: true,
            require_quarantine_absent: true,
        },
    })
}

fn ensure_supported_dm_kind(fault_kind: &str) -> Result<()> {
    match fault_kind {
        DM_FLAKEY_KIND | DM_DROP_WRITES_KIND => Ok(()),
        other => bail!("fault kind {other:?} is not a supported device-mapper mutation"),
    }
}

fn require_exact_singleton(label: &str, allowlist: &[String], observed: &str) -> Result<()> {
    let values = allowlist
        .iter()
        .map(|value| value.trim())
        .collect::<BTreeSet<_>>();
    ensure!(
        allowlist.len() == 1 && values.len() == 1 && values.contains(observed),
        "{label} allowlist must contain exactly the observed target {observed:?}; configured={allowlist:?}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        HostStorageAllowlist, HostStorageMutationIntent, HostStorageMutationProof,
        HostStoragePostCleanupObservation, HostStorageTargetObservation,
    };

    fn observation() -> HostStorageTargetObservation {
        HostStorageTargetObservation {
            node: "worker-a".to_string(),
            pod: "rustfs-0".to_string(),
            pod_uid: "uid-0".to_string(),
            persistent_volume_claim: "data-rustfs-0".to_string(),
            persistent_volume: "pv-a".to_string(),
            persistent_volume_path: "/data/rustfs-fault/dm-volume".to_string(),
            mapper_name: "rustfs-fault-dm".to_string(),
            logical_device: "/dev/mapper/rustfs-fault-dm".to_string(),
            canonical_device: "/dev/dm-0".to_string(),
            mount_source: "/dev/mapper/rustfs-fault-dm".to_string(),
            mount_canonical_source: "/dev/dm-0".to_string(),
            filesystem: "ext4".to_string(),
            recovery_table: "0 1024 linear /dev/loop0 0".to_string(),
            observed_at_ms: 1,
        }
    }

    fn intent() -> HostStorageMutationIntent {
        HostStorageMutationIntent {
            scenario: "dm-flakey".to_string(),
            fault_name: "dm-flakey-00-rustfs_block_device_flakey".to_string(),
            fault_kind: "rustfs_block_device_flakey".to_string(),
            run_id: "run-1".to_string(),
            context: "lab".to_string(),
            namespace: "rustfs-fault-test".to_string(),
            tenant: "fault-test-tenant".to_string(),
            observer_namespace: "rustfs-fault-observers".to_string(),
            observer_pod: "observer-worker-a".to_string(),
            backend_specific_destructive_opt_in: true,
            allowlist: HostStorageAllowlist {
                nodes: vec!["worker-a".to_string()],
                devices: vec!["/dev/mapper/rustfs-fault-dm".to_string()],
                persistent_volumes: vec!["pv-a".to_string()],
            },
        }
    }

    #[test]
    fn exact_allowlists_and_cleanup_contract_produce_a_valid_proof() {
        let proof = HostStorageMutationProof::prove_device_mapper(intent(), observation())
            .expect("host-storage proof");
        proof.validate().expect("valid proof");
        proof.require_fresh_at(60_001).expect("bounded age");

        proof
            .validate_post_cleanup(&HostStoragePostCleanupObservation {
                schema_version: 1,
                scenario: proof.scenario.clone(),
                fault_name: proof.fault_name.clone(),
                run_id: proof.run_id.clone(),
                observed_at_ms: 2,
                node: proof.target.node.clone(),
                persistent_volume: proof.target.persistent_volume.clone(),
                mapper_name: proof.target.mapper_name.clone(),
                logical_device: proof.target.logical_device.clone(),
                canonical_device: proof.target.canonical_device.clone(),
                mount_canonical_source: proof.target.mount_canonical_source.clone(),
                filesystem_mounted: true,
                node_quarantined: false,
                recovery_table_sha256: proof.target.recovery_table_sha256.clone(),
            })
            .expect("cleanup proof");
    }

    #[test]
    fn proof_fails_closed_without_backend_opt_in_or_exact_allowlists() {
        let mut disabled = intent();
        disabled.backend_specific_destructive_opt_in = false;
        assert!(HostStorageMutationProof::prove_device_mapper(disabled, observation()).is_err());

        let mut broad = intent();
        broad.allowlist.nodes.push("worker-b".to_string());
        assert!(HostStorageMutationProof::prove_device_mapper(broad, observation()).is_err());

        let mut wrong_device = intent();
        wrong_device.allowlist.devices = vec!["/dev/mapper/other".to_string()];
        assert!(
            HostStorageMutationProof::prove_device_mapper(wrong_device, observation()).is_err()
        );
    }

    #[test]
    fn proof_and_cleanup_tampering_is_rejected() {
        let proof = HostStorageMutationProof::prove_device_mapper(intent(), observation())
            .expect("host-storage proof");
        let mut tampered = proof.clone();
        tampered.recovery.rollback.mapper_name = "other".to_string();
        assert!(tampered.validate().is_err());

        let mut changed = observation();
        changed.persistent_volume = "pv-b".to_string();
        assert!(proof.require_apply_observation(&changed).is_err());

        let cleanup = HostStoragePostCleanupObservation {
            schema_version: 1,
            scenario: proof.scenario.clone(),
            fault_name: proof.fault_name.clone(),
            run_id: proof.run_id.clone(),
            observed_at_ms: 2,
            node: proof.target.node.clone(),
            persistent_volume: proof.target.persistent_volume.clone(),
            mapper_name: proof.target.mapper_name.clone(),
            logical_device: proof.target.logical_device.clone(),
            canonical_device: proof.target.canonical_device.clone(),
            mount_canonical_source: proof.target.mount_canonical_source.clone(),
            filesystem_mounted: true,
            node_quarantined: true,
            recovery_table_sha256: proof.target.recovery_table_sha256.clone(),
        };
        assert!(proof.validate_post_cleanup(&cleanup).is_err());
    }
}
