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

//! Runtime boundary for destructive storage-recovery workflows.
//!
//! The scenario runners own sequencing. This module owns the narrower trust
//! boundary: a run-owned Kubernetes generation, its two exclusive locks, the
//! immediately-current observation required before mutation, and the closed
//! set of operations an adapter may perform.

use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    fault::storage_recovery::{
        HealMode, StorageRecoveryArtifactIdentity, StorageRecoveryCase, StorageVolumeIdentity,
    },
    framework::{command::CommandSpec, config::ClusterTestConfig, kubectl::Kubectl},
};

pub const STORAGE_RECOVERY_HOST_LOCK_DIRECTORY: &str = "/var/lock/s3chaos";
pub const STORAGE_RECOVERY_HELPER_PROGRAM: &str = "/usr/local/bin/s3chaos-storage-helper";
pub const STORAGE_RECOVERY_CONTEXT_MAX_AGE_MS: u64 = 5_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KubernetesResourceVersions {
    pub tenant: String,
    pub pod: String,
    pub persistent_volume_claim: String,
    pub persistent_volume: String,
    pub node: String,
    pub helper_pod: String,
}

impl KubernetesResourceVersions {
    fn validate(&self) -> Result<()> {
        for (field, value) in [
            ("Tenant", self.tenant.as_str()),
            ("Pod", self.pod.as_str()),
            ("PVC", self.persistent_volume_claim.as_str()),
            ("PV", self.persistent_volume.as_str()),
            ("node", self.node.as_str()),
            ("helper Pod", self.helper_pod.as_str()),
        ] {
            ensure!(
                !value.trim().is_empty(),
                "storage-recovery {field} resourceVersion is empty"
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KubernetesLeaseProof {
    pub name: String,
    pub uid: String,
    pub resource_version: String,
    pub holder_identity: String,
    pub scope_sha256: String,
    pub acquired_at_ms: u64,
    pub renew_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostFlockProof {
    pub node: String,
    pub node_uid: String,
    pub path: String,
    pub device_id: String,
    pub inode: u64,
    pub scope_sha256: String,
    pub acquired_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageRecoveryExclusiveAccess {
    pub kubernetes_lease: KubernetesLeaseProof,
    pub host_flock: HostFlockProof,
}

impl StorageRecoveryExclusiveAccess {
    fn validate_for(
        &self,
        run_id: &str,
        attempt_id: &str,
        volume: &StorageVolumeIdentity,
        scope_sha256: &str,
        observed_at_ms: u64,
    ) -> Result<()> {
        let expected_holder = format!("{run_id}/{attempt_id}");
        let expected_lease_name = format!("s3chaos-storage-{}", &scope_sha256[..20]);
        let expected_lock_path =
            format!("{STORAGE_RECOVERY_HOST_LOCK_DIRECTORY}/storage-{scope_sha256}.lock");
        ensure!(
            self.kubernetes_lease.name == expected_lease_name
                && !self.kubernetes_lease.uid.trim().is_empty()
                && !self.kubernetes_lease.resource_version.trim().is_empty()
                && self.kubernetes_lease.holder_identity == expected_holder
                && self.kubernetes_lease.scope_sha256 == scope_sha256
                && self.kubernetes_lease.acquired_at_ms > 0
                && self.kubernetes_lease.renew_at_ms >= self.kubernetes_lease.acquired_at_ms
                && self.kubernetes_lease.expires_at_ms > observed_at_ms,
            "storage-recovery Kubernetes Lease is not current and run-owned"
        );
        ensure!(
            self.host_flock.node == volume.node
                && self.host_flock.node_uid == volume.node_uid
                && self.host_flock.path == expected_lock_path
                && !self.host_flock.device_id.trim().is_empty()
                && self.host_flock.inode > 0
                && self.host_flock.scope_sha256 == scope_sha256
                && self.host_flock.acquired_at_ms >= self.kubernetes_lease.acquired_at_ms
                && self.host_flock.acquired_at_ms <= observed_at_ms,
            "storage-recovery host flock is not bound to the target node and fixed lock path"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnedStorageContext {
    pub identity: StorageRecoveryArtifactIdentity,
    pub case: StorageRecoveryCase,
    pub attempt_id: String,
    pub cluster_context: String,
    pub tenant_uid: String,
    pub scope_sha256: String,
    pub volume: StorageVolumeIdentity,
    pub resource_versions: KubernetesResourceVersions,
    pub host_generation: HostGenerationIdentity,
    pub exclusive_access: StorageRecoveryExclusiveAccess,
    pub helper_pod_name: String,
    pub helper_pod_uid: String,
    pub observed_at_ms: u64,
}

impl OwnedStorageContext {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.identity.scenario == self.case.scenario(),
            "storage-recovery case is bound to the wrong scenario"
        );
        ensure!(
            !self.identity.run_id.trim().is_empty()
                && !self.identity.case_name.trim().is_empty()
                && !self.identity.bucket.trim().is_empty()
                && !self.attempt_id.trim().is_empty()
                && !self.cluster_context.trim().is_empty()
                && !self.tenant_uid.trim().is_empty()
                && !self.helper_pod_name.trim().is_empty()
                && !self.helper_pod_uid.trim().is_empty()
                && self.observed_at_ms > 0,
            "storage-recovery context has an empty identity or timestamp"
        );
        self.volume.validate()?;
        ensure!(
            self.volume.observed_at_ms <= self.observed_at_ms
                && self.observed_at_ms - self.volume.observed_at_ms
                    <= STORAGE_RECOVERY_CONTEXT_MAX_AGE_MS,
            "storage-recovery context does not contain a fresh volume identity"
        );
        self.resource_versions.validate()?;
        self.host_generation.validate_for(&self.volume)?;
        validate_sha256(&self.scope_sha256)?;
        ensure!(
            self.scope_sha256 == storage_scope_sha256(self),
            "storage-recovery scope digest does not match cluster/Tenant/volume identity"
        );
        self.exclusive_access.validate_for(
            &self.identity.run_id,
            &self.attempt_id,
            &self.volume,
            &self.scope_sha256,
            self.observed_at_ms,
        )
    }

    /// Revalidates every mutable Kubernetes/host identity immediately before a
    /// destructive operation. A replacement result must be captured as a new
    /// context after the operation; generation drift is never accepted here.
    pub fn require_current(&self, current: &CurrentStorageObservation) -> Result<()> {
        self.validate()?;
        current.validate()?;
        ensure!(
            current.observed_at_ms >= self.observed_at_ms
                && current.observed_at_ms - self.observed_at_ms
                    <= STORAGE_RECOVERY_CONTEXT_MAX_AGE_MS,
            "storage-recovery pre-mutation observation is stale"
        );
        ensure!(
            current.volume == self.volume
                && current.resource_versions == self.resource_versions
                && current.cluster_context == self.cluster_context
                && current.tenant_uid == self.tenant_uid
                && current.scope_sha256 == self.scope_sha256
                && current.host_generation == self.host_generation
                && current.helper_pod_name == self.helper_pod_name
                && current.helper_pod_uid == self.helper_pod_uid
                && current.kubernetes_lease_uid == self.exclusive_access.kubernetes_lease.uid
                && current.kubernetes_lease_resource_version
                    == self.exclusive_access.kubernetes_lease.resource_version
                && current.kubernetes_lease_holder
                    == self.exclusive_access.kubernetes_lease.holder_identity
                && current.host_lock_device_id == self.exclusive_access.host_flock.device_id
                && current.host_lock_inode == self.exclusive_access.host_flock.inode,
            "storage-recovery identity or exclusive access drifted before mutation"
        );
        ensure!(
            current.observed_at_ms < self.exclusive_access.kubernetes_lease.expires_at_ms,
            "storage-recovery Kubernetes Lease expired before mutation"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CurrentStorageObservation {
    pub cluster_context: String,
    pub tenant_uid: String,
    pub scope_sha256: String,
    pub volume: StorageVolumeIdentity,
    pub resource_versions: KubernetesResourceVersions,
    pub host_generation: HostGenerationIdentity,
    pub helper_pod_name: String,
    pub helper_pod_uid: String,
    pub kubernetes_lease_uid: String,
    pub kubernetes_lease_resource_version: String,
    pub kubernetes_lease_holder: String,
    pub host_lock_device_id: String,
    pub host_lock_inode: u64,
    pub observed_at_ms: u64,
}

impl CurrentStorageObservation {
    fn validate(&self) -> Result<()> {
        self.volume.validate()?;
        self.resource_versions.validate()?;
        self.host_generation.validate_for(&self.volume)?;
        validate_sha256(&self.scope_sha256)?;
        for (field, value) in [
            ("cluster context", self.cluster_context.as_str()),
            ("Tenant UID", self.tenant_uid.as_str()),
            ("helper Pod name", self.helper_pod_name.as_str()),
            ("helper Pod UID", self.helper_pod_uid.as_str()),
            ("Kubernetes Lease UID", self.kubernetes_lease_uid.as_str()),
            (
                "Kubernetes Lease resourceVersion",
                self.kubernetes_lease_resource_version.as_str(),
            ),
            (
                "Kubernetes Lease holder",
                self.kubernetes_lease_holder.as_str(),
            ),
            ("host lock device", self.host_lock_device_id.as_str()),
        ] {
            ensure!(!value.trim().is_empty(), "current {field} is empty");
        }
        ensure!(
            self.host_lock_inode > 0 && self.observed_at_ms >= self.volume.observed_at_ms,
            "current storage observation has an invalid lock inode or timestamp"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostGenerationIdentity {
    pub mount_id: String,
    pub mount_namespace_id: String,
    pub device_major_minor: String,
    pub device_mapper_uuid: String,
    pub device_mapper_table_sha256: String,
    pub filesystem_uuid: String,
    pub rustfs_drive_uuid: String,
}

impl HostGenerationIdentity {
    fn validate_for(&self, volume: &StorageVolumeIdentity) -> Result<()> {
        for (field, value) in [
            ("mount id", self.mount_id.as_str()),
            ("mount namespace id", self.mount_namespace_id.as_str()),
            ("device major:minor", self.device_major_minor.as_str()),
            ("device-mapper UUID", self.device_mapper_uuid.as_str()),
            (
                "device-mapper table digest",
                self.device_mapper_table_sha256.as_str(),
            ),
            ("filesystem UUID", self.filesystem_uuid.as_str()),
            ("RustFS drive UUID", self.rustfs_drive_uuid.as_str()),
        ] {
            ensure!(
                !value.trim().is_empty(),
                "storage-recovery {field} is empty"
            );
        }
        validate_sha256(&self.device_mapper_table_sha256)?;
        ensure!(
            self.mount_namespace_id == volume.target_mount_namespace_id
                && self.filesystem_uuid == volume.filesystem_uuid
                && self.rustfs_drive_uuid == volume.rustfs_drive_uuid,
            "host generation does not match the proven RustFS volume"
        );
        let Some((major, minor)) = self.device_major_minor.split_once(':') else {
            bail!("storage-recovery device major:minor is malformed")
        };
        ensure!(
            major.parse::<u32>().is_ok() && minor.parse::<u32>().is_ok(),
            "storage-recovery device major:minor is malformed"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum StorageRecoveryHostOperation {
    InspectXlMeta {
        object_directory: String,
        version_id: String,
        expected_mount_device_id: String,
        expected_drive_uuid: String,
    },
    MutateShard {
        relative_part_path: String,
        shard_device_id: String,
        shard_inode: u64,
        shard_size_bytes: u64,
        byte_offset: u64,
        original_sha256: String,
    },
    PrepareFreshVolume {
        replacement_persistent_volume: String,
        replacement_persistent_volume_claim: String,
    },
    DetachDeviceMapper {
        mapping_name: String,
        recovery_table_sha256: String,
    },
    ReattachDeviceMapper {
        mapping_name: String,
        recovery_table_sha256: String,
    },
}

impl StorageRecoveryHostOperation {
    pub fn is_destructive(&self) -> bool {
        !matches!(self, Self::InspectXlMeta { .. })
    }

    pub fn validate(&self) -> Result<()> {
        match self {
            Self::InspectXlMeta {
                object_directory,
                version_id,
                expected_mount_device_id,
                expected_drive_uuid,
            } => {
                validate_relative_path("object directory", object_directory)?;
                validate_explicit_version(version_id)?;
                ensure!(
                    !expected_mount_device_id.trim().is_empty()
                        && !expected_drive_uuid.trim().is_empty(),
                    "offline XL2 inspection must bind the opened root and format.json drive identity"
                );
                Ok(())
            }
            Self::MutateShard {
                relative_part_path,
                shard_device_id,
                shard_inode,
                shard_size_bytes,
                byte_offset,
                original_sha256,
            } => {
                validate_relative_path("shard", relative_part_path)?;
                ensure!(
                    relative_part_path.rsplit('/').next().is_some_and(|name| {
                        name.strip_prefix("part.").is_some_and(|part| {
                            !part.is_empty() && part.chars().all(|c| c.is_ascii_digit())
                        })
                    }),
                    "storage-recovery mutation target must be an exact part.N path"
                );
                ensure!(
                    !shard_device_id.trim().is_empty()
                        && *shard_inode > 0
                        && *shard_size_bytes > 0
                        && *byte_offset < *shard_size_bytes,
                    "storage-recovery shard identity or mutation offset is invalid"
                );
                validate_sha256(original_sha256)
            }
            Self::PrepareFreshVolume {
                replacement_persistent_volume,
                replacement_persistent_volume_claim,
            } => {
                ensure!(
                    !replacement_persistent_volume.trim().is_empty()
                        && !replacement_persistent_volume_claim.trim().is_empty(),
                    "fresh-volume replacement PVC/PV identity is empty"
                );
                Ok(())
            }
            Self::DetachDeviceMapper {
                mapping_name,
                recovery_table_sha256,
            }
            | Self::ReattachDeviceMapper {
                mapping_name,
                recovery_table_sha256,
            } => {
                ensure!(
                    !mapping_name.trim().is_empty()
                        && mapping_name
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')),
                    "device-mapper operation has an unsafe mapping name"
                );
                validate_sha256(recovery_table_sha256)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RestoreOutcome {
    Restored,
    Quarantined,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageRecoveryOperationReceipt {
    pub operation_id: String,
    pub operation: StorageRecoveryHostOperation,
    pub context_sha256: String,
    pub response_sha256: String,
    pub response_body: String,
    pub started_at_ms: u64,
    pub completed_at_ms: u64,
    pub journal_persisted_at_ms: u64,
    pub journal_fsync_succeeded: bool,
}

impl StorageRecoveryOperationReceipt {
    pub fn validate_for(
        &self,
        context: &OwnedStorageContext,
        operation: &StorageRecoveryHostOperation,
    ) -> Result<()> {
        ensure!(
            !self.operation_id.trim().is_empty() && self.operation == *operation,
            "storage-recovery receipt has the wrong operation identity"
        );
        let expected_context_sha256 = context_sha256(context)?;
        validate_sha256(&self.context_sha256)?;
        validate_sha256(&self.response_sha256)?;
        ensure!(
            self.context_sha256 == expected_context_sha256
                && self.response_sha256 == sha256_bytes(self.response_body.as_bytes()),
            "storage-recovery receipt digest does not match its context or raw response"
        );
        ensure!(
            self.started_at_ms >= context.observed_at_ms
                && self.started_at_ms <= self.journal_persisted_at_ms
                && self.journal_persisted_at_ms <= self.completed_at_ms
                && self.journal_fsync_succeeded,
            "storage-recovery receipt is not durably persisted and ordered"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HealObservationReceipt {
    pub mode: HealMode,
    pub context_sha256: String,
    pub response_sha256: String,
    pub response_body: String,
    pub started_at_ms: u64,
    pub observed_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExactQuorumReadReceipt {
    pub context_sha256: String,
    pub mapping_artifact_sha256: String,
    pub response_sha256: String,
    pub response_body: String,
    pub fault_active_from_ms: u64,
    pub completed_at_ms: u64,
    pub fault_active_until_ms: u64,
}

#[async_trait]
pub trait StorageRecoveryRuntimePort: Send {
    async fn acquire(&mut self, case: StorageRecoveryCase) -> Result<OwnedStorageContext>;

    async fn observe_current(
        &mut self,
        context: &OwnedStorageContext,
    ) -> Result<CurrentStorageObservation>;

    async fn execute_host_operation(
        &mut self,
        context: &OwnedStorageContext,
        operation: &StorageRecoveryHostOperation,
    ) -> Result<StorageRecoveryOperationReceipt>;

    async fn observe_heal(
        &mut self,
        context: &OwnedStorageContext,
        mode: HealMode,
    ) -> Result<HealObservationReceipt>;

    async fn force_read_exact_quorum(
        &mut self,
        context: &OwnedStorageContext,
        mapping_artifact: &str,
    ) -> Result<ExactQuorumReadReceipt>;

    async fn restore_or_quarantine(
        &mut self,
        context: &OwnedStorageContext,
    ) -> Result<RestoreOutcome>;
}

pub async fn execute_checked_host_operation(
    runtime: &mut dyn StorageRecoveryRuntimePort,
    context: &OwnedStorageContext,
    operation: &StorageRecoveryHostOperation,
) -> Result<StorageRecoveryOperationReceipt> {
    operation.validate()?;
    let current = runtime.observe_current(context).await?;
    context.require_current(&current)?;
    let receipt = runtime.execute_host_operation(context, operation).await?;
    receipt.validate_for(context, operation)?;
    Ok(receipt)
}

pub fn storage_scope_sha256(context: &OwnedStorageContext) -> String {
    let mut hasher = Sha256::new();
    for value in [
        context.cluster_context.as_str(),
        context.volume.namespace.as_str(),
        context.tenant_uid.as_str(),
        context.volume.persistent_volume_uid.as_str(),
        context.volume.node_uid.as_str(),
        context.volume.canonical_device.as_str(),
        context.volume.filesystem_uuid.as_str(),
    ] {
        hasher.update(value.as_bytes());
        hasher.update([0]);
    }
    hex::encode(hasher.finalize())
}

pub fn context_sha256(context: &OwnedStorageContext) -> Result<String> {
    Ok(sha256_bytes(
        serde_json::to_vec(context)
            .context("encode storage-recovery context for digest")?
            .as_slice(),
    ))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct StorageHelperInvocation<'a> {
    context: &'a OwnedStorageContext,
    operation: &'a StorageRecoveryHostOperation,
}

/// Concrete, bounded transport for the privileged storage helper. The command
/// is a direct `kubectl exec` of one fixed program with a typed JSON request on
/// stdin; neither the adapter nor the helper protocol exposes a shell or an
/// arbitrary argv surface.
pub struct KubectlStorageRecoveryHostAdapter {
    kubectl: Kubectl,
    namespace: String,
    helper_pod: String,
    timeout: Duration,
}

impl KubectlStorageRecoveryHostAdapter {
    pub fn new(
        cluster: &ClusterTestConfig,
        namespace: impl Into<String>,
        helper_pod: impl Into<String>,
        timeout: Duration,
    ) -> Result<Self> {
        let namespace = namespace.into();
        let helper_pod = helper_pod.into();
        ensure!(
            valid_kubernetes_name(&namespace) && valid_kubernetes_name(&helper_pod),
            "storage-recovery helper namespace or Pod name is invalid"
        );
        ensure!(
            !timeout.is_zero(),
            "storage-recovery helper timeout is zero"
        );
        Ok(Self {
            kubectl: Kubectl::new(cluster).namespaced(&namespace),
            namespace,
            helper_pod,
            timeout,
        })
    }

    fn command(
        &self,
        context: &OwnedStorageContext,
        operation: &StorageRecoveryHostOperation,
    ) -> Result<CommandSpec> {
        context.validate()?;
        operation.validate()?;
        ensure!(
            context.cluster_context == self.kubectl.context()
                && context.volume.namespace == self.namespace
                && context.helper_pod_name == self.helper_pod,
            "storage-recovery helper adapter is bound to another context, namespace, or Pod"
        );
        let request = serde_json::to_string(&StorageHelperInvocation { context, operation })
            .context("encode storage-recovery helper invocation")?;
        Ok(self
            .kubectl
            .command([
                "exec",
                self.helper_pod.as_str(),
                "--",
                STORAGE_RECOVERY_HELPER_PROGRAM,
                "execute",
            ])
            .stdin(request))
    }

    pub async fn execute(
        &self,
        context: &OwnedStorageContext,
        operation: &StorageRecoveryHostOperation,
    ) -> Result<StorageRecoveryOperationReceipt> {
        let output = self
            .command(context, operation)?
            .run_bounded(self.timeout)
            .await
            .context("execute typed storage-recovery host helper")?;
        ensure!(
            output.code == Some(0),
            "storage-recovery host helper failed: exit={:?}, stderr={}",
            output.code,
            output.stderr
        );
        let receipt = serde_json::from_str::<StorageRecoveryOperationReceipt>(&output.stdout)
            .context("decode storage-recovery host-helper receipt")?;
        receipt.validate_for(context, operation)?;
        Ok(receipt)
    }
}

fn valid_kubernetes_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
        })
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

fn validate_relative_path(label: &str, path: &str) -> Result<()> {
    ensure!(
        !path.is_empty()
            && !path.starts_with('/')
            && !path.ends_with('/')
            && !path.chars().any(char::is_whitespace)
            && path
                .split('/')
                .all(|component| !component.is_empty() && component != "." && component != ".."),
        "storage-recovery {label} must be a normalized relative path"
    );
    Ok(())
}

fn validate_explicit_version(version_id: &str) -> Result<()> {
    if version_id.trim().is_empty() || version_id == "null" {
        bail!("storage-recovery requires an explicit non-null version id")
    }
    uuid::Uuid::parse_str(version_id)
        .map(|_| ())
        .map_err(|error| anyhow::anyhow!("invalid storage-recovery version id: {error}"))
}

fn validate_sha256(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "storage-recovery digest must be a SHA-256 hex string"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn volume() -> StorageVolumeIdentity {
        StorageVolumeIdentity {
            target_proof_sha256: HASH.to_string(),
            host_storage_proof_sha256: HASH.to_string(),
            rustfs_deployment_id: "deployment-1".to_string(),
            namespace: "rustfs-system".to_string(),
            tenant: "tenant-1".to_string(),
            pod: "rustfs-0".to_string(),
            pod_uid: "pod-uid-1".to_string(),
            rustfs_container_id: "containerd://container-1".to_string(),
            volume_name: "data".to_string(),
            persistent_volume_claim: "data-rustfs-0".to_string(),
            persistent_volume_claim_uid: "pvc-uid-1".to_string(),
            persistent_volume: "pv-1".to_string(),
            persistent_volume_uid: "pv-uid-1".to_string(),
            node: "node-1".to_string(),
            node_uid: "node-uid-1".to_string(),
            storage_class: "local".to_string(),
            local_volume_path: "/var/lib/rustfs-1".to_string(),
            mount_path: "/data".to_string(),
            canonical_device: "/dev/mapper/rustfs-1".to_string(),
            target_mount_namespace_id: "mnt:[1]".to_string(),
            filesystem_uuid: "fs-1".to_string(),
            rustfs_drive_uuid: "drive-1".to_string(),
            pool_index: 0,
            set_index: 0,
            observed_at_ms: 100,
        }
    }

    fn versions() -> KubernetesResourceVersions {
        KubernetesResourceVersions {
            tenant: "10".to_string(),
            pod: "11".to_string(),
            persistent_volume_claim: "12".to_string(),
            persistent_volume: "13".to_string(),
            node: "14".to_string(),
            helper_pod: "15".to_string(),
        }
    }

    fn context() -> OwnedStorageContext {
        let mut context = OwnedStorageContext {
            identity: StorageRecoveryArtifactIdentity {
                run_id: "run-1".to_string(),
                scenario: "on-disk-bitrot".to_string(),
                case_name: "automatic-scanner".to_string(),
                bucket: "bucket-1".to_string(),
            },
            case: StorageRecoveryCase::OnDiskBitrotAutomaticScanner,
            attempt_id: "attempt-1".to_string(),
            cluster_context: "kind-s3chaos".to_string(),
            tenant_uid: "tenant-uid-1".to_string(),
            scope_sha256: String::new(),
            volume: volume(),
            resource_versions: versions(),
            host_generation: HostGenerationIdentity {
                mount_id: "mount-1".to_string(),
                mount_namespace_id: "mnt:[1]".to_string(),
                device_major_minor: "259:0".to_string(),
                device_mapper_uuid: "dm-uuid-1".to_string(),
                device_mapper_table_sha256: HASH.to_string(),
                filesystem_uuid: "fs-1".to_string(),
                rustfs_drive_uuid: "drive-1".to_string(),
            },
            exclusive_access: StorageRecoveryExclusiveAccess {
                kubernetes_lease: KubernetesLeaseProof {
                    name: String::new(),
                    uid: "lease-uid-1".to_string(),
                    resource_version: "20".to_string(),
                    holder_identity: "run-1/attempt-1".to_string(),
                    scope_sha256: String::new(),
                    acquired_at_ms: 100,
                    renew_at_ms: 105,
                    expires_at_ms: 1_000,
                },
                host_flock: HostFlockProof {
                    node: "node-1".to_string(),
                    node_uid: "node-uid-1".to_string(),
                    path: String::new(),
                    device_id: "8:1".to_string(),
                    inode: 42,
                    scope_sha256: String::new(),
                    acquired_at_ms: 106,
                },
            },
            helper_pod_name: "s3chaos-storage-helper".to_string(),
            helper_pod_uid: "helper-uid-1".to_string(),
            observed_at_ms: 110,
        };
        let scope = storage_scope_sha256(&context);
        context.scope_sha256 = scope.clone();
        context.exclusive_access.kubernetes_lease.name =
            format!("s3chaos-storage-{}", &scope[..20]);
        context.exclusive_access.kubernetes_lease.scope_sha256 = scope.clone();
        context.exclusive_access.host_flock.path =
            format!("{STORAGE_RECOVERY_HOST_LOCK_DIRECTORY}/storage-{scope}.lock");
        context.exclusive_access.host_flock.scope_sha256 = scope;
        context
    }

    fn current(context: &OwnedStorageContext) -> CurrentStorageObservation {
        CurrentStorageObservation {
            cluster_context: context.cluster_context.clone(),
            tenant_uid: context.tenant_uid.clone(),
            scope_sha256: context.scope_sha256.clone(),
            volume: context.volume.clone(),
            resource_versions: context.resource_versions.clone(),
            host_generation: context.host_generation.clone(),
            helper_pod_name: context.helper_pod_name.clone(),
            helper_pod_uid: context.helper_pod_uid.clone(),
            kubernetes_lease_uid: context.exclusive_access.kubernetes_lease.uid.clone(),
            kubernetes_lease_resource_version: context
                .exclusive_access
                .kubernetes_lease
                .resource_version
                .clone(),
            kubernetes_lease_holder: context
                .exclusive_access
                .kubernetes_lease
                .holder_identity
                .clone(),
            host_lock_device_id: context.exclusive_access.host_flock.device_id.clone(),
            host_lock_inode: context.exclusive_access.host_flock.inode,
            observed_at_ms: 111,
        }
    }

    #[test]
    fn owned_context_rejects_generation_and_lock_drift() {
        let context = context();
        context
            .require_current(&current(&context))
            .expect("matching current identity");

        let mut drifted_generation = current(&context);
        drifted_generation.volume.persistent_volume_uid = "other-pv-uid".to_string();
        assert!(context.require_current(&drifted_generation).is_err());

        let mut restarted_helper = current(&context);
        restarted_helper.helper_pod_uid = "other-helper".to_string();
        assert!(context.require_current(&restarted_helper).is_err());

        let mut replaced_lock = current(&context);
        replaced_lock.host_lock_inode += 1;
        assert!(context.require_current(&replaced_lock).is_err());

        let mut remounted = current(&context);
        remounted.host_generation.mount_id = "mount-2".to_string();
        assert!(context.require_current(&remounted).is_err());

        let mut changed_table = current(&context);
        changed_table.host_generation.device_mapper_table_sha256 =
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_string();
        assert!(context.require_current(&changed_table).is_err());
    }

    #[test]
    fn owned_context_rejects_expired_or_cross_run_lease() {
        let mut cross_run = context();
        cross_run.exclusive_access.kubernetes_lease.holder_identity =
            "other-run/attempt-1".to_string();
        assert!(cross_run.validate().is_err());

        let mut expired = context();
        expired.exclusive_access.kubernetes_lease.expires_at_ms = expired.observed_at_ms;
        assert!(expired.validate().is_err());

        let mut other_tenant = context();
        other_tenant.tenant_uid = "tenant-uid-2".to_string();
        assert!(other_tenant.validate().is_err());
    }

    #[test]
    fn host_operations_are_closed_and_reject_unsafe_paths() {
        StorageRecoveryHostOperation::InspectXlMeta {
            object_directory: "bucket/object".to_string(),
            version_id: "01234567-89ab-cdef-0123-456789abcdef".to_string(),
            expected_mount_device_id: "259:0".to_string(),
            expected_drive_uuid: "drive-1".to_string(),
        }
        .validate()
        .expect("read-only inspection");

        for path in [
            "/data/part.1",
            "../part.1",
            "data/link/../part.1",
            "data/blob",
        ] {
            let operation = StorageRecoveryHostOperation::MutateShard {
                relative_part_path: path.to_string(),
                shard_device_id: "8:1".to_string(),
                shard_inode: 42,
                shard_size_bytes: 1024,
                byte_offset: 0,
                original_sha256: HASH.to_string(),
            };
            assert!(operation.validate().is_err(), "unsafe mutation path {path}");
        }
    }

    struct FakeRuntime {
        current: CurrentStorageObservation,
        observations: usize,
    }

    #[async_trait]
    impl StorageRecoveryRuntimePort for FakeRuntime {
        async fn acquire(&mut self, _case: StorageRecoveryCase) -> Result<OwnedStorageContext> {
            unreachable!()
        }

        async fn observe_current(
            &mut self,
            _context: &OwnedStorageContext,
        ) -> Result<CurrentStorageObservation> {
            self.observations += 1;
            Ok(self.current.clone())
        }

        async fn execute_host_operation(
            &mut self,
            context: &OwnedStorageContext,
            operation: &StorageRecoveryHostOperation,
        ) -> Result<StorageRecoveryOperationReceipt> {
            let response_body = "{}".to_string();
            Ok(StorageRecoveryOperationReceipt {
                operation_id: "operation-1".to_string(),
                operation: operation.clone(),
                context_sha256: context_sha256(context)?,
                response_sha256: sha256_bytes(response_body.as_bytes()),
                response_body,
                started_at_ms: 120,
                completed_at_ms: 121,
                journal_persisted_at_ms: 120,
                journal_fsync_succeeded: true,
            })
        }

        async fn observe_heal(
            &mut self,
            _context: &OwnedStorageContext,
            _mode: HealMode,
        ) -> Result<HealObservationReceipt> {
            unreachable!()
        }

        async fn force_read_exact_quorum(
            &mut self,
            _context: &OwnedStorageContext,
            _mapping_artifact: &str,
        ) -> Result<ExactQuorumReadReceipt> {
            unreachable!()
        }

        async fn restore_or_quarantine(
            &mut self,
            _context: &OwnedStorageContext,
        ) -> Result<RestoreOutcome> {
            unreachable!()
        }
    }

    #[tokio::test]
    async fn destructive_operation_requires_immediate_revalidation() {
        let context = context();
        let mut runtime = FakeRuntime {
            current: current(&context),
            observations: 0,
        };
        let destructive = StorageRecoveryHostOperation::MutateShard {
            relative_part_path: "bucket/object/data-dir/part.1".to_string(),
            shard_device_id: "8:1".to_string(),
            shard_inode: 42,
            shard_size_bytes: 1024,
            byte_offset: 0,
            original_sha256: HASH.to_string(),
        };
        execute_checked_host_operation(&mut runtime, &context, &destructive)
            .await
            .expect("checked operation");
        assert_eq!(runtime.observations, 1);

        let inspection = StorageRecoveryHostOperation::InspectXlMeta {
            object_directory: "bucket/object".to_string(),
            version_id: "01234567-89ab-cdef-0123-456789abcdef".to_string(),
            expected_mount_device_id: "259:0".to_string(),
            expected_drive_uuid: "drive-1".to_string(),
        };
        execute_checked_host_operation(&mut runtime, &context, &inspection)
            .await
            .expect("read-only inspection");
        assert_eq!(runtime.observations, 2);
    }

    #[test]
    fn receipt_must_be_durable_and_bound_to_exact_context() {
        let context = context();
        let operation = StorageRecoveryHostOperation::MutateShard {
            relative_part_path: "bucket/object/data-dir/part.1".to_string(),
            shard_device_id: "259:0".to_string(),
            shard_inode: 42,
            shard_size_bytes: 1024,
            byte_offset: 0,
            original_sha256: HASH.to_string(),
        };
        let response_body = "{}".to_string();
        let mut receipt = StorageRecoveryOperationReceipt {
            operation_id: "operation-1".to_string(),
            operation: operation.clone(),
            context_sha256: context_sha256(&context).expect("context digest"),
            response_sha256: sha256_bytes(response_body.as_bytes()),
            response_body,
            started_at_ms: 120,
            completed_at_ms: 122,
            journal_persisted_at_ms: 121,
            journal_fsync_succeeded: true,
        };
        receipt
            .validate_for(&context, &operation)
            .expect("durable exact receipt");

        receipt.journal_fsync_succeeded = false;
        assert!(receipt.validate_for(&context, &operation).is_err());
        receipt.journal_fsync_succeeded = true;
        receipt.context_sha256 = HASH.to_string();
        assert!(receipt.validate_for(&context, &operation).is_err());
    }

    #[test]
    fn kubectl_helper_adapter_exposes_no_shell_or_arbitrary_argv() {
        let context = context();
        let cluster = crate::framework::config::E2eConfig::defaults().cluster;
        let adapter = KubectlStorageRecoveryHostAdapter::new(
            &cluster,
            "rustfs-system",
            "s3chaos-storage-helper",
            Duration::from_secs(5),
        )
        .expect("adapter");
        let operation = StorageRecoveryHostOperation::InspectXlMeta {
            object_directory: "bucket/object".to_string(),
            version_id: "01234567-89ab-cdef-0123-456789abcdef".to_string(),
            expected_mount_device_id: "259:0".to_string(),
            expected_drive_uuid: "drive-1".to_string(),
        };
        let command = adapter
            .command(&context, &operation)
            .expect("typed command");

        assert_eq!(
            command.args[4..],
            [
                "exec",
                "s3chaos-storage-helper",
                "--",
                STORAGE_RECOVERY_HELPER_PROGRAM,
                "execute",
            ]
        );
        assert!(
            !command
                .args
                .iter()
                .any(|arg| matches!(arg.as_str(), "sh" | "bash" | "-c"))
        );
        assert!(
            command
                .stdin
                .as_deref()
                .is_some_and(|body| body.contains("inspect-xl-meta") && !body.contains("argv"))
        );
    }
}
