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

//! Kubernetes Lease adapter for exclusive storage-recovery ownership.

use std::{collections::BTreeMap, time::Duration};

use anyhow::{Context, Result, bail, ensure};
use k8s_openapi::{
    api::coordination::v1::{Lease, LeaseSpec},
    apimachinery::pkg::apis::meta::v1::{MicroTime, ObjectMeta},
    chrono::{TimeZone, Utc},
};
use kube::{
    Api, Client, ResourceExt,
    api::{DeleteParams, PostParams, Preconditions},
};
use serde::{Deserialize, Serialize};

use crate::fault::storage_recovery::{StorageRecoveryCase, StorageVolumeIdentity};
use crate::fault::storage_recovery_runtime::{
    HostGenerationIdentity, KubernetesLeaseProof, OwnedStorageContext,
    StorageRecoveryHostOperation, StorageRecoveryOperationReceipt, storage_lease_name,
};

const SCOPE_ANNOTATION: &str = "s3chaos.rustfs.com/storage-scope-sha256";
const MIN_LEASE_DURATION_SECONDS: u64 = 5;
const MAX_LEASE_DURATION_SECONDS: u64 = 300;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum StorageRecoveryCleanupProof {
    AbortedBeforeMutation {
        observed_at_ms: u64,
    },
    BitrotRestored {
        restore_receipt: Box<StorageRecoveryOperationReceipt>,
    },
    BitrotAlreadyRepaired {
        restore_receipt: Box<StorageRecoveryOperationReceipt>,
    },
    BitrotVerifiedSuperseded {
        verification_receipt: Box<StorageRecoveryOperationReceipt>,
    },
    BitrotQuarantined {
        restore_receipt: Box<StorageRecoveryOperationReceipt>,
    },
    StaleDiskReattached {
        reattach_receipt: Box<StorageRecoveryOperationReceipt>,
        reattach_context: Box<OwnedStorageContext>,
        post_reattach_generation: Box<HostGenerationIdentity>,
        observed_at_ms: u64,
    },
    FreshVolumeCommitted {
        prepare_receipt: Box<StorageRecoveryOperationReceipt>,
        replacement_volume: Box<StorageVolumeIdentity>,
        old_device_absence_sha256: String,
        observed_at_ms: u64,
    },
}

impl StorageRecoveryCleanupProof {
    pub fn validate_for(&self, context: &OwnedStorageContext) -> Result<()> {
        match self {
            Self::AbortedBeforeMutation { observed_at_ms } => {
                ensure!(
                    matches!(
                        context.case,
                        StorageRecoveryCase::FreshVolumeReplacementAutomaticReplacement
                            | StorageRecoveryCase::FreshVolumeReplacementAdminDeep
                            | StorageRecoveryCase::OnDiskBitrotAutomaticScanner
                            | StorageRecoveryCase::OnDiskBitrotAdminDeep
                            | StorageRecoveryCase::StaleDiskReturn
                    ) && *observed_at_ms
                        >= context.exclusive_access.kubernetes_lease.acquired_at_ms,
                    "pre-mutation abort proof is not a supported storage Lease-generation proof"
                );
                Ok(())
            }
            Self::BitrotRestored { restore_receipt }
            | Self::BitrotAlreadyRepaired { restore_receipt }
            | Self::BitrotQuarantined {
                restore_receipt, ..
            } => {
                ensure!(
                    matches!(
                        context.case,
                        StorageRecoveryCase::OnDiskBitrotAutomaticScanner
                            | StorageRecoveryCase::OnDiskBitrotAdminDeep
                    ),
                    "bitrot cleanup proof is bound to another recovery case"
                );
                validate_receipt_operation(
                    context,
                    restore_receipt,
                    |operation| {
                        matches!(operation, StorageRecoveryHostOperation::RestoreShard { .. })
                    },
                    "shard restoration",
                )?;
                let response: serde_json::Value =
                    serde_json::from_str(&restore_receipt.response_body)
                        .context("decode shard cleanup response")?;
                let expected = match self {
                    Self::BitrotRestored { .. } => "restored",
                    Self::BitrotAlreadyRepaired { .. } => "already-repaired",
                    Self::BitrotQuarantined { .. } => "quarantined",
                    _ => unreachable!("matched a restore-receipt bitrot cleanup"),
                };
                ensure!(
                    response.get("outcome").and_then(serde_json::Value::as_str) == Some(expected),
                    "shard cleanup response does not prove the declared terminal state"
                );
                if matches!(self, Self::BitrotQuarantined { .. }) {
                    bail!(
                        "quarantined shard is durable evidence, not successful cleanup; explicit repair acknowledgement is required"
                    )
                }
                Ok(())
            }
            Self::BitrotVerifiedSuperseded {
                verification_receipt,
            } => {
                ensure!(
                    matches!(
                        context.case,
                        StorageRecoveryCase::OnDiskBitrotAutomaticScanner
                            | StorageRecoveryCase::OnDiskBitrotAdminDeep
                    ),
                    "bitrot superseded cleanup proof is bound to another recovery case"
                );
                validate_receipt_operation(
                    context,
                    verification_receipt,
                    |operation| {
                        matches!(
                            operation,
                            StorageRecoveryHostOperation::VerifySupersededShard { .. }
                        )
                    },
                    "superseded-shard verification",
                )?;
                let response: serde_json::Value =
                    serde_json::from_str(&verification_receipt.response_body)
                        .context("decode superseded-shard cleanup response")?;
                ensure!(
                    response.get("outcome").and_then(serde_json::Value::as_str)
                        == Some("verified-superseded"),
                    "superseded-shard cleanup response has the wrong terminal state"
                );
                Ok(())
            }
            Self::StaleDiskReattached {
                reattach_receipt,
                reattach_context,
                post_reattach_generation,
                observed_at_ms,
            } => {
                ensure!(
                    context.case == StorageRecoveryCase::StaleDiskReturn,
                    "stale-disk cleanup proof is bound to another recovery case"
                );
                validate_receipt_operation(
                    reattach_context,
                    reattach_receipt,
                    |operation| {
                        matches!(
                            operation,
                            StorageRecoveryHostOperation::ReattachDeviceMapper { .. }
                        )
                    },
                    "device-mapper reattach",
                )?;
                ensure!(
                    reattach_context.identity == context.identity
                        && reattach_context.case == context.case
                        && reattach_context.attempt_id == context.attempt_id
                        && reattach_context.cluster_context == context.cluster_context
                        && reattach_context.tenant_uid == context.tenant_uid
                        && reattach_context.scope_sha256 == context.scope_sha256
                        && crate::fault::storage_recovery_runtime::same_storage_volume_generation(
                            &reattach_context.volume,
                            &context.volume,
                        )
                        && reattach_context.resource_versions == context.resource_versions
                        && reattach_context.host_generation == context.host_generation
                        && reattach_context.exclusive_access.host_flock
                            == context.exclusive_access.host_flock
                        && reattach_context.exclusive_access.kubernetes_lease.uid
                            == context.exclusive_access.kubernetes_lease.uid
                        && reattach_context
                            .exclusive_access
                            .kubernetes_lease
                            .acquired_at_ms
                            == context.exclusive_access.kubernetes_lease.acquired_at_ms
                        && reattach_context
                            .exclusive_access
                            .kubernetes_lease
                            .holder_identity
                            == context.exclusive_access.kubernetes_lease.holder_identity
                        && reattach_context
                            .exclusive_access
                            .kubernetes_lease
                            .renew_at_ms
                            <= context.exclusive_access.kubernetes_lease.renew_at_ms
                        && post_reattach_generation.as_ref() == &context.host_generation
                        && *observed_at_ms >= reattach_receipt.completed_at_ms,
                    "stale-disk cleanup does not prove the expected reattached generation"
                );
                Ok(())
            }
            Self::FreshVolumeCommitted {
                prepare_receipt,
                replacement_volume,
                old_device_absence_sha256,
                observed_at_ms,
            } => {
                ensure!(
                    matches!(
                        context.case,
                        StorageRecoveryCase::FreshVolumeReplacementAutomaticReplacement
                            | StorageRecoveryCase::FreshVolumeReplacementAdminDeep
                    ),
                    "fresh-volume cleanup proof is bound to another recovery case"
                );
                validate_receipt_operation(
                    context,
                    prepare_receipt,
                    |operation| {
                        matches!(
                            operation,
                            StorageRecoveryHostOperation::PrepareFreshVolume { .. }
                        )
                    },
                    "fresh-volume preparation",
                )?;
                replacement_volume.validate()?;
                let StorageRecoveryHostOperation::PrepareFreshVolume {
                    replacement_persistent_volume,
                    replacement_persistent_volume_claim,
                } = &prepare_receipt.operation
                else {
                    unreachable!("operation was checked above")
                };
                validate_sha256(old_device_absence_sha256)?;
                ensure!(
                    replacement_volume.rustfs_deployment_id == context.volume.rustfs_deployment_id
                        && replacement_volume.namespace == context.volume.namespace
                        && replacement_volume.tenant == context.volume.tenant
                        && replacement_volume.volume_name == context.volume.volume_name
                        && replacement_volume.persistent_volume == *replacement_persistent_volume
                        && replacement_volume.persistent_volume_claim
                            == *replacement_persistent_volume_claim
                        && replacement_volume.persistent_volume_uid
                            != context.volume.persistent_volume_uid
                        && replacement_volume.rustfs_drive_uuid != context.volume.rustfs_drive_uuid
                        && replacement_volume.canonical_device != context.volume.canonical_device
                        && *observed_at_ms >= prepare_receipt.completed_at_ms,
                    "fresh-volume cleanup does not prove replacement ownership and old-device absence"
                );
                Ok(())
            }
        }
    }

    fn completed_at_ms(&self) -> u64 {
        match self {
            Self::AbortedBeforeMutation { observed_at_ms } => *observed_at_ms,
            Self::BitrotRestored { restore_receipt }
            | Self::BitrotAlreadyRepaired { restore_receipt }
            | Self::BitrotQuarantined {
                restore_receipt, ..
            } => restore_receipt.completed_at_ms,
            Self::BitrotVerifiedSuperseded {
                verification_receipt,
            } => verification_receipt.completed_at_ms,
            Self::StaleDiskReattached { observed_at_ms, .. }
            | Self::FreshVolumeCommitted { observed_at_ms, .. } => *observed_at_ms,
        }
    }
}

fn validate_receipt_operation(
    context: &OwnedStorageContext,
    receipt: &StorageRecoveryOperationReceipt,
    expected: impl FnOnce(&StorageRecoveryHostOperation) -> bool,
    label: &str,
) -> Result<()> {
    receipt.validate_for(context, &receipt.operation)?;
    ensure!(
        expected(&receipt.operation),
        "cleanup proof is not a {label} receipt"
    );
    Ok(())
}

fn validate_sha256(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "cleanup proof digest is not SHA-256 hex"
    );
    Ok(())
}

pub struct KubernetesStorageLeaseAdapter {
    api: Api<Lease>,
    name: String,
    scope_sha256: String,
    holder_identity: String,
    duration_seconds: i32,
}

impl KubernetesStorageLeaseAdapter {
    pub fn new(
        client: Client,
        namespace: &str,
        scope_sha256: &str,
        run_id: &str,
        attempt_id: &str,
        duration: Duration,
    ) -> Result<Self> {
        ensure!(
            !namespace.trim().is_empty()
                && !run_id.trim().is_empty()
                && !attempt_id.trim().is_empty(),
            "storage-recovery Lease identity is empty"
        );
        let holder_identity = format!("{run_id}/{attempt_id}");
        ensure!(
            holder_identity.len() <= 128
                && holder_identity
                    .chars()
                    .all(|character| !character.is_control() && !character.is_whitespace()),
            "storage-recovery Lease holder identity is invalid"
        );
        let duration_seconds = duration.as_secs();
        ensure!(
            (MIN_LEASE_DURATION_SECONDS..=MAX_LEASE_DURATION_SECONDS).contains(&duration_seconds)
                && duration.subsec_nanos() == 0,
            "storage-recovery Lease duration must be an integral 5..=300 seconds"
        );
        Ok(Self {
            api: Api::namespaced(client, namespace),
            name: storage_lease_name(scope_sha256)?,
            scope_sha256: scope_sha256.to_string(),
            holder_identity,
            duration_seconds: i32::try_from(duration_seconds)?,
        })
    }

    pub async fn acquire(&self) -> Result<KubernetesLeaseProof> {
        for _ in 0..3 {
            let now_ms = now_ms()?;
            let Some(existing) = self
                .api
                .get_opt(&self.name)
                .await
                .context("read storage-recovery Kubernetes Lease")?
            else {
                let lease = self.lease(None, now_ms, now_ms, 0)?;
                match self.api.create(&PostParams::default(), &lease).await {
                    Ok(created) => return self.proof(&created),
                    Err(kube::Error::Api(response)) if response.code == 409 => continue,
                    Err(error) => {
                        return Err(error).context("create storage-recovery Kubernetes Lease");
                    }
                }
            };
            let decision =
                acquisition_decision(&existing, &self.scope_sha256, &self.holder_identity, now_ms)?;
            let (acquired_at_ms, transitions) = match decision {
                AcquisitionDecision::Renew {
                    acquired_at_ms,
                    transitions,
                } => (acquired_at_ms, transitions),
                AcquisitionDecision::TakeOver { transitions } => (now_ms, transitions),
                AcquisitionDecision::Contended {
                    holder,
                    expires_at_ms,
                } => {
                    bail!(
                        "storage-recovery Kubernetes Lease is held by {holder:?} until {expires_at_ms}"
                    )
                }
            };
            let lease = self.lease(
                existing.metadata.resource_version.clone(),
                acquired_at_ms,
                now_ms,
                transitions,
            )?;
            match self
                .api
                .replace(&self.name, &PostParams::default(), &lease)
                .await
            {
                Ok(replaced) => return self.proof(&replaced),
                Err(kube::Error::Api(response)) if response.code == 409 => continue,
                Err(error) => {
                    return Err(error).context("replace storage-recovery Kubernetes Lease");
                }
            }
        }
        bail!("storage-recovery Kubernetes Lease changed during three acquisition attempts")
    }

    pub async fn renew(&self, proof: &KubernetesLeaseProof) -> Result<KubernetesLeaseProof> {
        self.validate_proof_identity(proof)?;
        let now_ms = now_ms()?;
        ensure!(
            now_ms < proof.expires_at_ms,
            "storage-recovery Kubernetes Lease expired before renewal"
        );
        let existing = self
            .api
            .get(&self.name)
            .await
            .context("read storage-recovery Kubernetes Lease for renewal")?;
        ensure!(
            existing.uid().as_deref() == Some(proof.uid.as_str())
                && existing.resource_version().as_deref() == Some(proof.resource_version.as_str()),
            "storage-recovery Kubernetes Lease generation drifted before renewal"
        );
        let decision =
            acquisition_decision(&existing, &self.scope_sha256, &self.holder_identity, now_ms)?;
        let AcquisitionDecision::Renew {
            acquired_at_ms,
            transitions,
        } = decision
        else {
            bail!("storage-recovery Kubernetes Lease is no longer renewable by this holder")
        };
        let renewed = self
            .api
            .replace(
                &self.name,
                &PostParams::default(),
                &self.lease(
                    existing.metadata.resource_version,
                    acquired_at_ms,
                    now_ms,
                    transitions,
                )?,
            )
            .await
            .context("renew storage-recovery Kubernetes Lease")?;
        self.proof(&renewed)
    }

    pub async fn release(
        &self,
        context: &OwnedStorageContext,
        proof: &KubernetesLeaseProof,
        cleanup: &StorageRecoveryCleanupProof,
    ) -> Result<()> {
        context.validate()?;
        cleanup.validate_for(context)?;
        self.validate_proof_identity(proof)?;
        ensure!(
            context.scope_sha256 == self.scope_sha256
                && context.exclusive_access.kubernetes_lease == *proof
                && cleanup.completed_at_ms() >= proof.acquired_at_ms,
            "storage-recovery cleanup proof is not bound to this Lease generation"
        );
        let current = self
            .api
            .get(&self.name)
            .await
            .context("re-read storage-recovery Kubernetes Lease before release")?;
        validate_current_lease(&current, proof, &self.scope_sha256, now_ms()?)?;
        self.api
            .delete(
                &self.name,
                &DeleteParams {
                    preconditions: Some(Preconditions {
                        resource_version: Some(proof.resource_version.clone()),
                        uid: Some(proof.uid.clone()),
                    }),
                    ..DeleteParams::default()
                },
            )
            .await
            .context("release storage-recovery Kubernetes Lease")?;
        Ok(())
    }

    fn lease(
        &self,
        resource_version: Option<String>,
        acquired_at_ms: u64,
        renew_at_ms: u64,
        transitions: i32,
    ) -> Result<Lease> {
        Ok(Lease {
            metadata: ObjectMeta {
                name: Some(self.name.clone()),
                resource_version,
                annotations: Some(BTreeMap::from([(
                    SCOPE_ANNOTATION.to_string(),
                    self.scope_sha256.clone(),
                )])),
                ..ObjectMeta::default()
            },
            spec: Some(LeaseSpec {
                acquire_time: Some(micro_time(acquired_at_ms)?),
                holder_identity: Some(self.holder_identity.clone()),
                lease_duration_seconds: Some(self.duration_seconds),
                lease_transitions: Some(transitions),
                renew_time: Some(micro_time(renew_at_ms)?),
            }),
        })
    }

    fn proof(&self, lease: &Lease) -> Result<KubernetesLeaseProof> {
        validate_scope(lease, &self.scope_sha256)?;
        let spec = lease.spec.as_ref().context("Kubernetes Lease lacks spec")?;
        ensure!(
            spec.holder_identity.as_deref() == Some(self.holder_identity.as_str())
                && spec.lease_duration_seconds == Some(self.duration_seconds),
            "Kubernetes Lease response is not owned by the expected holder"
        );
        let acquired_at_ms = timestamp_ms(
            spec.acquire_time
                .as_ref()
                .context("Kubernetes Lease lacks acquireTime")?,
        )?;
        let renew_at_ms = timestamp_ms(
            spec.renew_time
                .as_ref()
                .context("Kubernetes Lease lacks renewTime")?,
        )?;
        Ok(KubernetesLeaseProof {
            name: self.name.clone(),
            uid: lease.uid().context("Kubernetes Lease response lacks UID")?,
            resource_version: lease
                .resource_version()
                .context("Kubernetes Lease response lacks resourceVersion")?,
            holder_identity: self.holder_identity.clone(),
            scope_sha256: self.scope_sha256.clone(),
            acquired_at_ms,
            renew_at_ms,
            expires_at_ms: expiry_ms(renew_at_ms, self.duration_seconds)?,
        })
    }

    fn validate_proof_identity(&self, proof: &KubernetesLeaseProof) -> Result<()> {
        ensure!(
            proof.name == self.name
                && proof.scope_sha256 == self.scope_sha256
                && proof.holder_identity == self.holder_identity
                && !proof.uid.trim().is_empty()
                && !proof.resource_version.trim().is_empty(),
            "storage-recovery Kubernetes Lease proof belongs to another owner or scope"
        );
        Ok(())
    }
}

pub async fn require_current_lease(client: Client, context: &OwnedStorageContext) -> Result<()> {
    context.validate()?;
    let api: Api<Lease> = Api::namespaced(client, &context.volume.namespace);
    let lease = api
        .get(&context.exclusive_access.kubernetes_lease.name)
        .await
        .context("re-read storage-recovery Kubernetes Lease")?;
    validate_current_lease(
        &lease,
        &context.exclusive_access.kubernetes_lease,
        &context.scope_sha256,
        now_ms()?,
    )
}

pub async fn release_owned_lease(
    client: Client,
    context: &OwnedStorageContext,
    cleanup: &StorageRecoveryCleanupProof,
) -> Result<()> {
    context.validate()?;
    cleanup.validate_for(context)?;
    let proof = &context.exclusive_access.kubernetes_lease;
    let api: Api<Lease> = Api::namespaced(client, &context.volume.namespace);
    let current = api
        .get(&proof.name)
        .await
        .context("re-read storage-recovery Kubernetes Lease before release")?;
    validate_current_lease(&current, proof, &context.scope_sha256, now_ms()?)?;
    ensure!(
        cleanup.completed_at_ms() >= proof.acquired_at_ms,
        "storage-recovery cleanup predates the Lease generation"
    );
    api.delete(
        &proof.name,
        &DeleteParams {
            preconditions: Some(Preconditions {
                resource_version: Some(proof.resource_version.clone()),
                uid: Some(proof.uid.clone()),
            }),
            ..DeleteParams::default()
        },
    )
    .await
    .context("release storage-recovery Kubernetes Lease")?;
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum AcquisitionDecision {
    Renew {
        acquired_at_ms: u64,
        transitions: i32,
    },
    TakeOver {
        transitions: i32,
    },
    Contended {
        holder: String,
        expires_at_ms: u64,
    },
}

fn acquisition_decision(
    lease: &Lease,
    scope_sha256: &str,
    holder_identity: &str,
    now_ms: u64,
) -> Result<AcquisitionDecision> {
    validate_scope(lease, scope_sha256)?;
    let spec = lease.spec.as_ref().context("Kubernetes Lease lacks spec")?;
    let holder = spec
        .holder_identity
        .as_deref()
        .context("Kubernetes Lease lacks holderIdentity")?;
    let duration_seconds = spec
        .lease_duration_seconds
        .context("Kubernetes Lease lacks leaseDurationSeconds")?;
    ensure!(duration_seconds > 0, "Kubernetes Lease duration is invalid");
    let renew_at_ms = timestamp_ms(
        spec.renew_time
            .as_ref()
            .or(spec.acquire_time.as_ref())
            .context("Kubernetes Lease lacks renewTime and acquireTime")?,
    )?;
    let expires_at_ms = expiry_ms(renew_at_ms, duration_seconds)?;
    let transitions = spec.lease_transitions.unwrap_or_default();
    ensure!(transitions >= 0, "Kubernetes Lease transitions are invalid");
    if holder == holder_identity {
        return Ok(AcquisitionDecision::Renew {
            acquired_at_ms: timestamp_ms(
                spec.acquire_time
                    .as_ref()
                    .context("owned Kubernetes Lease lacks acquireTime")?,
            )?,
            transitions,
        });
    }
    if now_ms < expires_at_ms {
        return Ok(AcquisitionDecision::Contended {
            holder: holder.to_string(),
            expires_at_ms,
        });
    }
    Ok(AcquisitionDecision::TakeOver {
        transitions: transitions
            .checked_add(1)
            .context("Kubernetes Lease transition count overflow")?,
    })
}

fn validate_current_lease(
    lease: &Lease,
    proof: &KubernetesLeaseProof,
    scope_sha256: &str,
    now_ms: u64,
) -> Result<()> {
    validate_scope(lease, scope_sha256)?;
    let spec = lease.spec.as_ref().context("Kubernetes Lease lacks spec")?;
    let acquired_at_ms = timestamp_ms(
        spec.acquire_time
            .as_ref()
            .context("Kubernetes Lease lacks acquireTime")?,
    )?;
    let renew_at_ms = timestamp_ms(
        spec.renew_time
            .as_ref()
            .context("Kubernetes Lease lacks renewTime")?,
    )?;
    let expires_at_ms = expiry_ms(
        renew_at_ms,
        spec.lease_duration_seconds
            .context("Kubernetes Lease lacks leaseDurationSeconds")?,
    )?;
    ensure!(
        lease.uid().as_deref() == Some(proof.uid.as_str())
            && lease.resource_version().as_deref() == Some(proof.resource_version.as_str())
            && spec.holder_identity.as_deref() == Some(proof.holder_identity.as_str())
            && acquired_at_ms == proof.acquired_at_ms
            && renew_at_ms == proof.renew_at_ms
            && expires_at_ms == proof.expires_at_ms
            && now_ms < expires_at_ms,
        "storage-recovery Kubernetes Lease ownership, generation, or expiry drifted"
    );
    Ok(())
}

fn validate_scope(lease: &Lease, expected_scope_sha256: &str) -> Result<()> {
    ensure!(
        lease
            .metadata
            .annotations
            .as_ref()
            .and_then(|annotations| annotations.get(SCOPE_ANNOTATION))
            .is_some_and(|scope| scope == expected_scope_sha256),
        "Kubernetes Lease scope annotation does not match the storage target"
    );
    Ok(())
}

fn micro_time(timestamp_ms: u64) -> Result<MicroTime> {
    let timestamp_ms = i64::try_from(timestamp_ms)?;
    Ok(MicroTime(
        Utc.timestamp_millis_opt(timestamp_ms)
            .single()
            .context("storage-recovery Lease timestamp is invalid")?,
    ))
}

fn timestamp_ms(timestamp: &MicroTime) -> Result<u64> {
    u64::try_from(timestamp.0.timestamp_millis())
        .context("storage-recovery Lease timestamp precedes the Unix epoch")
}

fn expiry_ms(renew_at_ms: u64, duration_seconds: i32) -> Result<u64> {
    let duration_ms = u64::try_from(duration_seconds)?
        .checked_mul(1_000)
        .context("storage-recovery Lease duration overflow")?;
    renew_at_ms
        .checked_add(duration_ms)
        .context("storage-recovery Lease expiry overflow")
}

fn now_ms() -> Result<u64> {
    use std::time::{SystemTime, UNIX_EPOCH};

    u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())
        .context("system timestamp exceeds u64 milliseconds")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCOPE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn lease(holder: &str, renew_at_ms: u64, duration_seconds: i32) -> Lease {
        Lease {
            metadata: ObjectMeta {
                uid: Some("lease-uid".to_string()),
                resource_version: Some("20".to_string()),
                annotations: Some(BTreeMap::from([(
                    SCOPE_ANNOTATION.to_string(),
                    SCOPE.to_string(),
                )])),
                ..ObjectMeta::default()
            },
            spec: Some(LeaseSpec {
                acquire_time: Some(micro_time(renew_at_ms - 1_000).expect("acquire time")),
                holder_identity: Some(holder.to_string()),
                lease_duration_seconds: Some(duration_seconds),
                lease_transitions: Some(2),
                renew_time: Some(micro_time(renew_at_ms).expect("renew time")),
            }),
        }
    }

    #[test]
    fn active_foreign_lease_is_contended() {
        assert_eq!(
            acquisition_decision(&lease("other", 10_000, 30), SCOPE, "run/attempt", 39_999)
                .expect("decision"),
            AcquisitionDecision::Contended {
                holder: "other".to_string(),
                expires_at_ms: 40_000,
            }
        );
    }

    #[test]
    fn expired_foreign_lease_can_be_taken_over_with_transition() {
        assert_eq!(
            acquisition_decision(&lease("other", 10_000, 30), SCOPE, "run/attempt", 40_000)
                .expect("decision"),
            AcquisitionDecision::TakeOver { transitions: 3 }
        );
    }

    #[test]
    fn scope_mismatch_fails_closed() {
        let error = acquisition_decision(
            &lease("other", 10_000, 30),
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "run/attempt",
            40_000,
        )
        .expect_err("scope mismatch");
        assert!(error.to_string().contains("scope annotation"));
    }

    #[test]
    fn lost_or_renewed_lease_rejects_next_operation() {
        let proof = KubernetesLeaseProof {
            name: storage_lease_name(SCOPE).expect("name"),
            uid: "lease-uid".to_string(),
            resource_version: "20".to_string(),
            holder_identity: "run/attempt".to_string(),
            scope_sha256: SCOPE.to_string(),
            acquired_at_ms: 9_000,
            renew_at_ms: 10_000,
            expires_at_ms: 40_000,
        };
        validate_current_lease(&lease("run/attempt", 10_000, 30), &proof, SCOPE, 39_999)
            .expect("current lease");

        let mut stolen = lease("other", 11_000, 30);
        stolen.metadata.resource_version = Some("21".to_string());
        let error = validate_current_lease(&stolen, &proof, SCOPE, 11_001)
            .expect_err("lost Lease must fail closed");
        assert!(error.to_string().contains("ownership"), "{error:#}");

        let error =
            validate_current_lease(&lease("run/attempt", 10_000, 30), &proof, SCOPE, 40_000)
                .expect_err("expired Lease must fail closed");
        assert!(error.to_string().contains("expiry"), "{error:#}");
    }
}
