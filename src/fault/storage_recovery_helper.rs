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

//! Privileged storage helper implementation.
//!
//! The helper has two fixed mount roots and one typed JSON protocol. It never
//! accepts a command or argv. Every target below the volume root is opened with
//! `openat2` containment, and the exclusive flock remains held for the entire
//! helper process operation.

use std::{
    ffi::CString,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    mem::size_of,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{fs::MetadataExt, prelude::FileExt},
    },
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::fault::{
    storage_recovery_lease::StorageRecoveryCleanupProof,
    storage_recovery_runtime::{
        OwnedStorageContext, STORAGE_RECOVERY_HOST_LOCK_DIRECTORY, StorageHelperInvocation,
        StorageRecoveryHostOperation, StorageRecoveryOperationReceipt, context_sha256,
    },
    xl2_inspector::{inspect_xl_meta, validate_format_json_drive},
};

pub const STORAGE_HELPER_VOLUME_ROOT: &str = "/target";
pub const STORAGE_HELPER_JOURNAL_ROOT: &str = "/journal";
const FORMAT_JSON_PATH: &str = ".rustfs.sys/format.json";
const MAX_FORMAT_JSON_BYTES: usize = 1024 * 1024;
const MAX_XL_META_BYTES: usize = 16 * 1024 * 1024;
const MAX_JOURNAL_BYTES: usize = 1024 * 1024;
const MUTATION_XOR_MASK: u8 = 0xff;

const RESOLVE_NO_XDEV: u64 = 0x01;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;
const STORAGE_RESOLVE_FLAGS: u64 = RESOLVE_NO_XDEV | RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH;

#[derive(Debug, Clone)]
pub struct StorageHelperRoots {
    pub volume: PathBuf,
    pub journal: PathBuf,
    pub lock: PathBuf,
}

impl Default for StorageHelperRoots {
    fn default() -> Self {
        Self {
            volume: PathBuf::from(STORAGE_HELPER_VOLUME_ROOT),
            journal: PathBuf::from(STORAGE_HELPER_JOURNAL_ROOT),
            lock: PathBuf::from(STORAGE_RECOVERY_HOST_LOCK_DIRECTORY),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum StorageHelperSessionRequest {
    Begin {
        context: Box<OwnedStorageContext>,
    },
    Execute {
        invocation: Box<StorageHelperInvocation>,
    },
    Finish {
        context: Box<OwnedStorageContext>,
        cleanup: Box<StorageRecoveryCleanupProof>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum StorageHelperSessionResponse {
    Ready {
        scope_sha256: String,
    },
    Receipt {
        receipt: Box<StorageRecoveryOperationReceipt>,
    },
    Error {
        message: String,
    },
    Finished {
        scope_sha256: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum JournalState {
    Completed,
    Prepared,
    Mutated,
    Restored,
    Quarantined,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MutationJournal {
    schema_version: u8,
    operation_id: String,
    context_sha256: String,
    scope_sha256: String,
    #[serde(default)]
    holder_identity: String,
    operation: StorageRecoveryHostOperation,
    state: JournalState,
    relative_part_path: Option<String>,
    shard_device_id: Option<String>,
    shard_inode: Option<u64>,
    shard_size_bytes: Option<u64>,
    byte_offset: Option<u64>,
    original_byte: Option<u8>,
    mutated_byte: Option<u8>,
    original_sha256: Option<String>,
    mutated_sha256: Option<String>,
    reason: Option<String>,
    #[serde(default)]
    response_body: Option<String>,
    #[serde(default)]
    response_sha256: Option<String>,
    updated_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OfflineXl2InspectResponse {
    pub mount_device_id: String,
    pub drive_uuid: String,
    pub format_json_sha256: String,
    pub xl_meta_sha256: String,
    pub layout: crate::fault::xl2_inspector::Xl2ObjectVersionLayout,
    pub selected_part: OfflineInspectedShard,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OfflineInspectedShard {
    pub part_number: u32,
    pub relative_part_path: String,
    pub shard_device_id: String,
    pub shard_inode: u64,
    pub shard_size_bytes: u64,
    pub original_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MutationResponse {
    journal_operation_id: String,
    relative_part_path: String,
    shard_device_id: String,
    shard_inode: u64,
    shard_size_bytes: u64,
    byte_offset: u64,
    original_byte: u8,
    mutated_byte: u8,
    original_sha256: String,
    mutated_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct RestoreResponse {
    mutation_operation_id: String,
    outcome: crate::fault::storage_recovery_runtime::RestoreOutcome,
    observed_sha256: Option<String>,
}

pub struct StorageHelperSession {
    owner: OwnedStorageContext,
    volume_root: File,
    journal_root: File,
    _lock: File,
}

impl StorageHelperSession {
    pub fn begin_default(context: OwnedStorageContext) -> Result<Self> {
        Self::begin(context, &StorageHelperRoots::default())
    }

    pub fn begin(context: OwnedStorageContext, roots: &StorageHelperRoots) -> Result<Self> {
        context.validate()?;
        ensure!(
            now_ms()? < context.exclusive_access.kubernetes_lease.expires_at_ms,
            "storage-recovery Kubernetes Lease expired before helper session"
        );
        let lock_root = open_directory(&roots.lock, "storage helper lock root")?;
        let lock_name = format!("storage-{}.lock", context.scope_sha256);
        let lock = open_beneath(
            &lock_root,
            &lock_name,
            libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC,
            0o600,
        )?;
        acquire_flock(&lock)?;
        let lock_metadata = lock.metadata().context("stat storage helper flock")?;
        ensure!(
            device_id(&lock_metadata) == context.exclusive_access.host_flock.device_id
                && lock_metadata.ino() == context.exclusive_access.host_flock.inode,
            "storage helper flock identity differs from the owned context"
        );
        let volume_root = open_directory(&roots.volume, "storage helper volume root")?;
        let volume_metadata = volume_root
            .metadata()
            .context("stat storage helper volume root")?;
        ensure!(
            device_id(&volume_metadata) == context.host_generation.device_major_minor,
            "storage helper volume root device differs from the owned context"
        );
        let journal_root = open_directory(&roots.journal, "storage helper journal root")?;
        ensure_no_unresolved_journals(&journal_root, &context)?;
        Ok(Self {
            owner: context,
            volume_root,
            journal_root,
            _lock: lock,
        })
    }

    pub fn execute(
        &mut self,
        invocation: StorageHelperInvocation,
    ) -> Result<StorageRecoveryOperationReceipt> {
        validate_session_context(&self.owner, &invocation.context)?;
        invocation.operation.validate()?;
        let started_at_ms = now_ms()?;
        match &invocation.operation {
            StorageRecoveryHostOperation::InspectXlMeta {
                object_directory,
                bucket,
                object_key,
                object_sha256,
                version_id,
                selected_part_number,
                expected_mount_device_id,
                expected_drive_uuid,
            } => inspect(
                &invocation.context,
                &self.volume_root,
                &self.journal_root,
                object_directory,
                bucket,
                object_key,
                object_sha256,
                version_id,
                *selected_part_number,
                expected_mount_device_id,
                expected_drive_uuid,
                started_at_ms,
            ),
            StorageRecoveryHostOperation::MutateShard { .. } => mutate(
                &invocation.context,
                &self.volume_root,
                &self.journal_root,
                &invocation.operation,
                started_at_ms,
            ),
            StorageRecoveryHostOperation::RestoreShard {
                mutation_operation_id,
            } => restore(
                &invocation.context,
                &self.volume_root,
                &self.journal_root,
                &invocation.operation,
                mutation_operation_id,
                started_at_ms,
            ),
            StorageRecoveryHostOperation::PrepareFreshVolume { .. }
            | StorageRecoveryHostOperation::DetachDeviceMapper { .. }
            | StorageRecoveryHostOperation::ReattachDeviceMapper { .. } => {
                bail!("unqualified: operation has no safe storage-helper implementation")
            }
        }
    }

    pub fn finish(
        &self,
        context: &OwnedStorageContext,
        cleanup: &StorageRecoveryCleanupProof,
    ) -> Result<()> {
        validate_session_context(&self.owner, context)?;
        cleanup.validate_for(context)
    }
}

fn validate_session_context(
    owner: &OwnedStorageContext,
    current: &OwnedStorageContext,
) -> Result<()> {
    current.validate()?;
    ensure!(
        owner.identity == current.identity
            && owner.case == current.case
            && owner.attempt_id == current.attempt_id
            && owner.cluster_context == current.cluster_context
            && owner.tenant_uid == current.tenant_uid
            && owner.scope_sha256 == current.scope_sha256
            && owner.volume == current.volume
            && owner.resource_versions == current.resource_versions
            && owner.host_generation == current.host_generation
            && owner.exclusive_access.host_flock == current.exclusive_access.host_flock
            && owner.exclusive_access.kubernetes_lease.name
                == current.exclusive_access.kubernetes_lease.name
            && owner.exclusive_access.kubernetes_lease.uid
                == current.exclusive_access.kubernetes_lease.uid
            && owner.exclusive_access.kubernetes_lease.holder_identity
                == current.exclusive_access.kubernetes_lease.holder_identity
            && owner.exclusive_access.kubernetes_lease.scope_sha256
                == current.exclusive_access.kubernetes_lease.scope_sha256
            && owner.exclusive_access.kubernetes_lease.acquired_at_ms
                == current.exclusive_access.kubernetes_lease.acquired_at_ms
            && current.exclusive_access.kubernetes_lease.renew_at_ms
                >= owner.exclusive_access.kubernetes_lease.renew_at_ms
            && owner.helper_pod_name == current.helper_pod_name
            && owner.helper_pod_uid == current.helper_pod_uid,
        "storage helper session ownership or physical target changed"
    );
    ensure!(
        current.exclusive_access.kubernetes_lease.expires_at_ms > now_ms()?,
        "storage helper session Lease snapshot expired"
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn inspect(
    context: &OwnedStorageContext,
    volume_root: &File,
    journal_root: &File,
    object_directory: &str,
    bucket: &str,
    object_key: &str,
    object_sha256: &str,
    version_id: &str,
    selected_part_number: u32,
    expected_mount_device_id: &str,
    expected_drive_uuid: &str,
    started_at_ms: u64,
) -> Result<StorageRecoveryOperationReceipt> {
    ensure!(
        expected_mount_device_id == context.host_generation.device_major_minor
            && expected_drive_uuid == context.volume.rustfs_drive_uuid,
        "offline inspection target differs from the owned context"
    );
    ensure!(
        bucket == context.identity.bucket && !object_key.trim().is_empty(),
        "offline inspection object identity differs from the owned context"
    );
    let format_file = open_beneath(
        volume_root,
        FORMAT_JSON_PATH,
        libc::O_RDONLY | libc::O_CLOEXEC,
        0,
    )?;
    let format_bytes = read_limited(&format_file, MAX_FORMAT_JSON_BYTES, "format.json")?;
    validate_format_json_drive(
        &format_bytes,
        &context.volume.rustfs_deployment_id,
        expected_drive_uuid,
    )?;
    let xl_meta_path = format!("{object_directory}/xl.meta");
    let xl_meta_file = open_beneath(
        volume_root,
        &xl_meta_path,
        libc::O_RDONLY | libc::O_CLOEXEC,
        0,
    )?;
    let xl_meta_metadata = xl_meta_file.metadata().context("stat contained xl.meta")?;
    ensure!(
        device_id(&xl_meta_metadata) == expected_mount_device_id,
        "contained xl.meta crossed the proven volume device"
    );
    let xl_meta = read_limited(&xl_meta_file, MAX_XL_META_BYTES, "xl.meta")?;
    let layout = inspect_xl_meta(&xl_meta, version_id)?;
    let selected_index = layout
        .part_numbers
        .iter()
        .position(|part| *part == selected_part_number)
        .context("selected part number is absent from XL2 metadata")?;
    let relative_part_path = layout
        .relative_part_paths
        .get(selected_index)
        .context("selected XL2 part path is absent")?
        .clone();
    let part = open_beneath(
        volume_root,
        &relative_part_path,
        libc::O_RDONLY | libc::O_CLOEXEC,
        0,
    )?;
    let part_metadata = part.metadata().context("stat inspected shard")?;
    ensure!(part_metadata.len() > 0, "selected shard is empty");
    validate_part_identity(
        &part,
        expected_mount_device_id,
        part_metadata.ino(),
        part_metadata.len(),
    )?;
    let response = OfflineXl2InspectResponse {
        mount_device_id: expected_mount_device_id.to_string(),
        drive_uuid: expected_drive_uuid.to_string(),
        format_json_sha256: sha256_bytes(&format_bytes),
        xl_meta_sha256: sha256_bytes(&xl_meta),
        layout,
        selected_part: OfflineInspectedShard {
            part_number: selected_part_number,
            relative_part_path,
            shard_device_id: device_id(&part_metadata),
            shard_inode: part_metadata.ino(),
            shard_size_bytes: part_metadata.len(),
            original_sha256: hash_file(&part, None)?,
        },
    };
    completed_receipt(
        context,
        journal_root,
        StorageRecoveryHostOperation::InspectXlMeta {
            object_directory: object_directory.to_string(),
            bucket: bucket.to_string(),
            object_key: object_key.to_string(),
            object_sha256: object_sha256.to_string(),
            version_id: version_id.to_string(),
            selected_part_number,
            expected_mount_device_id: expected_mount_device_id.to_string(),
            expected_drive_uuid: expected_drive_uuid.to_string(),
        },
        &response,
        started_at_ms,
    )
}

fn mutate(
    context: &OwnedStorageContext,
    volume_root: &File,
    journal_root: &File,
    operation: &StorageRecoveryHostOperation,
    started_at_ms: u64,
) -> Result<StorageRecoveryOperationReceipt> {
    let StorageRecoveryHostOperation::MutateShard {
        inspection_operation_id,
        part_number,
        byte_offset,
    } = operation
    else {
        unreachable!("mutate receives only MutateShard")
    };
    let inspection = load_journal(journal_root, inspection_operation_id)?;
    inspection.operation.validate()?;
    ensure!(
        inspection.schema_version == 1
            && inspection.operation_id == *inspection_operation_id
            && inspection.context_sha256 == context_sha256(context)?
            && inspection.scope_sha256 == context.scope_sha256
            && inspection.holder_identity
                == context.exclusive_access.kubernetes_lease.holder_identity
            && inspection.state == JournalState::Completed,
        "shard mutation inspection receipt is absent, unresolved, or belongs to another context"
    );
    let StorageRecoveryHostOperation::InspectXlMeta {
        selected_part_number,
        ..
    } = &inspection.operation
    else {
        bail!("shard mutation source journal is not an XL2 inspection")
    };
    let inspection_body = required(&inspection.response_body, "inspection response body")?;
    ensure!(
        inspection
            .response_sha256
            .as_deref()
            .is_some_and(|digest| digest == sha256_bytes(inspection_body.as_bytes())),
        "shard mutation inspection response is not durably digest-bound"
    );
    let inspected: OfflineXl2InspectResponse =
        serde_json::from_str(inspection_body).context("decode sealed XL2 inspection response")?;
    let shard = &inspected.selected_part;
    ensure!(
        *selected_part_number == *part_number
            && shard.part_number == *part_number
            && inspected
                .layout
                .part_numbers
                .iter()
                .position(|number| number == part_number)
                .and_then(|index| inspected.layout.relative_part_paths.get(index))
                == Some(&shard.relative_part_path)
            && shard
                .relative_part_path
                .ends_with(&format!("/part.{part_number}"))
            && shard.shard_device_id == context.host_generation.device_major_minor
            && *byte_offset < shard.shard_size_bytes,
        "shard mutation does not match the selected part in the sealed inspection receipt"
    );
    let part = open_beneath(
        volume_root,
        &shard.relative_part_path,
        libc::O_RDWR | libc::O_CLOEXEC,
        0,
    )?;
    validate_part_identity(
        &part,
        &shard.shard_device_id,
        shard.shard_inode,
        shard.shard_size_bytes,
    )?;
    let observed_original = hash_file(&part, None)?;
    ensure!(
        observed_original == shard.original_sha256,
        "shard hash drifted before mutation"
    );
    let mut original = [0_u8; 1];
    ensure!(
        part.read_at(&mut original, *byte_offset)? == 1,
        "short read at shard mutation offset"
    );
    let mutated = original[0] ^ MUTATION_XOR_MASK;
    let expected_mutated_sha256 = hash_file(&part, Some((*byte_offset, mutated)))?;
    ensure!(
        expected_mutated_sha256 != observed_original,
        "controlled shard mutation would not change the shard digest"
    );

    let operation_id = Uuid::new_v4().to_string();
    let prepared_at_ms = now_ms()?;
    let mut journal = MutationJournal {
        schema_version: 1,
        operation_id: operation_id.clone(),
        context_sha256: context_sha256(context)?,
        scope_sha256: context.scope_sha256.clone(),
        holder_identity: context
            .exclusive_access
            .kubernetes_lease
            .holder_identity
            .clone(),
        operation: operation.clone(),
        state: JournalState::Prepared,
        relative_part_path: Some(shard.relative_part_path.clone()),
        shard_device_id: Some(shard.shard_device_id.clone()),
        shard_inode: Some(shard.shard_inode),
        shard_size_bytes: Some(shard.shard_size_bytes),
        byte_offset: Some(*byte_offset),
        original_byte: Some(original[0]),
        mutated_byte: Some(mutated),
        original_sha256: Some(observed_original.clone()),
        mutated_sha256: Some(expected_mutated_sha256.clone()),
        reason: None,
        response_body: None,
        response_sha256: None,
        updated_at_ms: prepared_at_ms,
    };
    persist_journal(journal_root, &journal)?;

    ensure!(
        part.write_at(&[mutated], *byte_offset)? == 1,
        "short pwrite during shard mutation"
    );
    part.sync_all().context("fsync mutated shard")?;
    validate_part_identity(
        &part,
        &shard.shard_device_id,
        shard.shard_inode,
        shard.shard_size_bytes,
    )?;
    let mut readback = [0_u8; 1];
    ensure!(
        part.read_at(&mut readback, *byte_offset)? == 1 && readback[0] == mutated,
        "mutated shard byte did not survive fsync/readback"
    );
    let mutated_sha256 = hash_file(&part, None)?;
    ensure!(
        mutated_sha256 == expected_mutated_sha256,
        "mutated shard digest differs from the precomputed controlled mutation"
    );
    let response = MutationResponse {
        journal_operation_id: operation_id.clone(),
        relative_part_path: shard.relative_part_path.clone(),
        shard_device_id: shard.shard_device_id.clone(),
        shard_inode: shard.shard_inode,
        shard_size_bytes: shard.shard_size_bytes,
        byte_offset: *byte_offset,
        original_byte: original[0],
        mutated_byte: mutated,
        original_sha256: observed_original,
        mutated_sha256,
    };
    let response_body = serde_json::to_string(&response)?;
    journal.state = JournalState::Mutated;
    let persisted_at_ms = persist_response(journal_root, &mut journal, &response_body)?;
    receipt(
        context,
        operation.clone(),
        operation_id,
        response_body,
        started_at_ms,
        persisted_at_ms,
    )
}

fn restore(
    context: &OwnedStorageContext,
    volume_root: &File,
    journal_root: &File,
    operation: &StorageRecoveryHostOperation,
    mutation_operation_id: &str,
    started_at_ms: u64,
) -> Result<StorageRecoveryOperationReceipt> {
    let mut journal = load_journal(journal_root, mutation_operation_id)?;
    ensure!(
        journal.schema_version == 1
            && journal.operation_id == mutation_operation_id
            && journal.context_sha256 == context_sha256(context)?
            && journal.scope_sha256 == context.scope_sha256
            && matches!(
                journal.state,
                JournalState::Prepared | JournalState::Mutated
            ),
        "mutation journal is not recoverable by this exact context"
    );
    let path = required(&journal.relative_part_path, "journal shard path")?;
    let expected_device = required(&journal.shard_device_id, "journal shard device")?;
    let expected_inode = journal.shard_inode.context("journal lacks shard inode")?;
    let expected_size = journal
        .shard_size_bytes
        .context("journal lacks shard size")?;
    let offset = journal.byte_offset.context("journal lacks byte offset")?;
    let original_byte = journal
        .original_byte
        .context("journal lacks original byte")?;
    let mutated_byte = journal.mutated_byte.context("journal lacks mutated byte")?;
    let original_sha256 = required(&journal.original_sha256, "journal original digest")?;
    let mutated_sha256 = required(&journal.mutated_sha256, "journal mutated digest")?;

    let part = open_beneath(volume_root, path, libc::O_RDWR | libc::O_CLOEXEC, 0)?;
    if let Err(error) =
        validate_part_identity(&part, expected_device, expected_inode, expected_size)
    {
        quarantine(
            journal_root,
            &mut journal,
            format!("identity mismatch: {error:#}"),
        )?;
        return quarantined_receipt(
            context,
            journal_root,
            operation,
            mutation_operation_id,
            None,
            started_at_ms,
        );
    }
    let current_sha256 = hash_file(&part, None)?;
    if current_sha256 == original_sha256 {
        journal.state = JournalState::Restored;
    } else if current_sha256 == mutated_sha256 {
        let mut current = [0_u8; 1];
        ensure!(
            part.read_at(&mut current, offset)? == 1,
            "short restore read"
        );
        if current[0] != mutated_byte {
            quarantine(
                journal_root,
                &mut journal,
                "mutation byte does not match journal".to_string(),
            )?;
            return quarantined_receipt(
                context,
                journal_root,
                operation,
                mutation_operation_id,
                Some(current_sha256),
                started_at_ms,
            );
        }
        ensure!(
            part.write_at(&[original_byte], offset)? == 1,
            "short restore pwrite"
        );
        part.sync_all().context("fsync restored shard")?;
        validate_part_identity(&part, expected_device, expected_inode, expected_size)?;
        let restored_sha256 = hash_file(&part, None)?;
        if restored_sha256 != original_sha256 {
            quarantine(
                journal_root,
                &mut journal,
                "post-restore digest differs from the original".to_string(),
            )?;
            return quarantined_receipt(
                context,
                journal_root,
                operation,
                mutation_operation_id,
                Some(restored_sha256),
                started_at_ms,
            );
        }
        journal.state = JournalState::Restored;
    } else {
        quarantine(
            journal_root,
            &mut journal,
            "shard digest matches neither original nor controlled mutation".to_string(),
        )?;
        return quarantined_receipt(
            context,
            journal_root,
            operation,
            mutation_operation_id,
            Some(current_sha256),
            started_at_ms,
        );
    }

    let response = RestoreResponse {
        mutation_operation_id: mutation_operation_id.to_string(),
        outcome: crate::fault::storage_recovery_runtime::RestoreOutcome::Restored,
        observed_sha256: Some(original_sha256.to_string()),
    };
    journal.updated_at_ms = now_ms()?;
    persist_journal(journal_root, &journal)?;
    completed_receipt(
        context,
        journal_root,
        operation.clone(),
        &response,
        started_at_ms,
    )
}

#[allow(clippy::too_many_arguments)]
fn quarantined_receipt(
    context: &OwnedStorageContext,
    journal_root: &File,
    operation: &StorageRecoveryHostOperation,
    mutation_operation_id: &str,
    observed_sha256: Option<String>,
    started_at_ms: u64,
) -> Result<StorageRecoveryOperationReceipt> {
    let response = RestoreResponse {
        mutation_operation_id: mutation_operation_id.to_string(),
        outcome: crate::fault::storage_recovery_runtime::RestoreOutcome::Quarantined,
        observed_sha256,
    };
    completed_receipt(
        context,
        journal_root,
        operation.clone(),
        &response,
        started_at_ms,
    )
}

fn quarantine(journal_root: &File, journal: &mut MutationJournal, reason: String) -> Result<()> {
    journal.state = JournalState::Quarantined;
    journal.reason = Some(reason);
    journal.updated_at_ms = now_ms()?;
    persist_journal(journal_root, journal)
}

fn persist_response(
    journal_root: &File,
    journal: &mut MutationJournal,
    response_body: &str,
) -> Result<u64> {
    journal.response_body = Some(response_body.to_string());
    journal.response_sha256 = Some(sha256_bytes(response_body.as_bytes()));
    journal.updated_at_ms = now_ms()?;
    persist_journal(journal_root, journal)?;
    Ok(journal.updated_at_ms)
}

fn completed_receipt(
    context: &OwnedStorageContext,
    journal_root: &File,
    operation: StorageRecoveryHostOperation,
    response: &impl Serialize,
    started_at_ms: u64,
) -> Result<StorageRecoveryOperationReceipt> {
    let operation_id = Uuid::new_v4().to_string();
    let persisted_at_ms = now_ms()?;
    let journal = MutationJournal {
        schema_version: 1,
        operation_id: operation_id.clone(),
        context_sha256: context_sha256(context)?,
        scope_sha256: context.scope_sha256.clone(),
        holder_identity: context
            .exclusive_access
            .kubernetes_lease
            .holder_identity
            .clone(),
        operation: operation.clone(),
        state: JournalState::Completed,
        relative_part_path: None,
        shard_device_id: None,
        shard_inode: None,
        shard_size_bytes: None,
        byte_offset: None,
        original_byte: None,
        mutated_byte: None,
        original_sha256: None,
        mutated_sha256: None,
        reason: None,
        response_body: Some(serde_json::to_string(response)?),
        response_sha256: None,
        updated_at_ms: persisted_at_ms,
    };
    let mut journal = journal;
    let response_body = journal
        .response_body
        .clone()
        .context("completed response")?;
    journal.response_sha256 = Some(sha256_bytes(response_body.as_bytes()));
    persist_journal(journal_root, &journal)?;
    receipt(
        context,
        operation,
        operation_id,
        response_body,
        started_at_ms,
        persisted_at_ms,
    )
}

fn receipt(
    context: &OwnedStorageContext,
    operation: StorageRecoveryHostOperation,
    operation_id: String,
    response_body: String,
    started_at_ms: u64,
    journal_persisted_at_ms: u64,
) -> Result<StorageRecoveryOperationReceipt> {
    let completed_at_ms = now_ms()?;
    let receipt = StorageRecoveryOperationReceipt {
        operation_id,
        operation,
        context_sha256: context_sha256(context)?,
        response_sha256: sha256_bytes(response_body.as_bytes()),
        response_body,
        started_at_ms,
        completed_at_ms,
        journal_persisted_at_ms,
        journal_fsync_succeeded: true,
    };
    receipt.validate_for(context, &receipt.operation)?;
    Ok(receipt)
}

fn validate_part_identity(
    file: &File,
    expected_device: &str,
    expected_inode: u64,
    expected_size: u64,
) -> Result<()> {
    let metadata = file.metadata().context("fstat contained shard")?;
    ensure!(metadata.is_file(), "contained shard is not a regular file");
    ensure!(
        metadata.nlink() == 1,
        "contained shard has multiple hard links"
    );
    ensure!(
        device_id(&metadata) == expected_device
            && metadata.ino() == expected_inode
            && metadata.len() == expected_size,
        "contained shard device/inode/size differs from the mapping receipt"
    );
    Ok(())
}

fn hash_file(file: &File, substitute: Option<(u64, u8)>) -> Result<String> {
    let mut reader = file.try_clone().context("clone shard fd for hashing")?;
    reader.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut offset = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        if let Some((target, byte)) = substitute
            && target >= offset
            && target < offset + count as u64
        {
            buffer[usize::try_from(target - offset)?] = byte;
        }
        hasher.update(&buffer[..count]);
        offset += count as u64;
    }
    Ok(hex::encode(hasher.finalize()))
}

fn open_directory(path: &Path, label: &str) -> Result<File> {
    let path = CString::new(path.as_os_str().as_encoded_bytes())
        .with_context(|| format!("{label} contains NUL"))?;
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("open {label}"));
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

fn open_beneath(root: &File, relative: &str, flags: i32, mode: u32) -> Result<File> {
    ensure!(
        !relative.is_empty()
            && !relative.starts_with('/')
            && relative
                .split('/')
                .all(|component| !component.is_empty() && component != "." && component != ".."),
        "storage helper path is not normalized and relative"
    );
    let path = CString::new(relative).context("storage helper path contains NUL")?;
    let how = OpenHow {
        flags: flags as u64,
        mode: u64::from(mode),
        resolve: STORAGE_RESOLVE_FLAGS,
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root.as_raw_fd(),
            path.as_ptr(),
            &how,
            size_of::<OpenHow>(),
        )
    } as i32;
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("open contained storage path {relative:?}"));
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn acquire_flock(file: &File) -> Result<()> {
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result != 0 {
        return Err(std::io::Error::last_os_error())
            .context("acquire exclusive storage helper flock");
    }
    Ok(())
}

fn persist_journal(root: &File, journal: &MutationJournal) -> Result<()> {
    let final_name = journal_name(&journal.operation_id)?;
    let temporary_name = format!(".{final_name}.{}.tmp", std::process::id());
    let mut temporary = open_beneath(
        root,
        &temporary_name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
        0o600,
    )?;
    let old = CString::new(temporary_name.clone())?;
    let write_result = (|| -> Result<()> {
        let body = serde_json::to_vec(journal)?;
        temporary.write_all(&body)?;
        temporary
            .sync_all()
            .context("fsync storage mutation journal")
    })();
    drop(temporary);
    if let Err(error) = write_result {
        let _ = unsafe { libc::unlinkat(root.as_raw_fd(), old.as_ptr(), 0) };
        return Err(error).context("persist storage mutation journal temporary file");
    }
    let new = CString::new(final_name.clone())?;
    let result = unsafe {
        libc::renameat(
            root.as_raw_fd(),
            old.as_ptr(),
            root.as_raw_fd(),
            new.as_ptr(),
        )
    };
    if result != 0 {
        let _ = unsafe { libc::unlinkat(root.as_raw_fd(), old.as_ptr(), 0) };
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("publish storage journal {final_name}"));
    }
    root.sync_all().context("fsync storage journal directory")
}

fn load_journal(root: &File, operation_id: &str) -> Result<MutationJournal> {
    let name = journal_name(operation_id)?;
    let file = open_beneath(root, &name, libc::O_RDONLY | libc::O_CLOEXEC, 0)?;
    serde_json::from_slice(&read_limited(&file, MAX_JOURNAL_BYTES, "mutation journal")?)
        .context("decode mutation journal")
}

fn ensure_no_unresolved_journals(journal_root: &File, context: &OwnedStorageContext) -> Result<()> {
    let directory = format!("/proc/self/fd/{}", journal_root.as_raw_fd());
    for entry in std::fs::read_dir(&directory)
        .with_context(|| format!("scan pre-opened storage journal directory {directory}"))?
    {
        let entry = entry.context("read storage journal directory entry")?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("storage journal has a non-UTF-8 filename"))?;
        let Some(operation_id) = name
            .strip_prefix("mutation-")
            .and_then(|name| name.strip_suffix(".json"))
        else {
            continue;
        };
        let journal = load_journal(journal_root, operation_id)
            .with_context(|| format!("validate existing storage journal {name}"))?;
        if journal.scope_sha256 != context.scope_sha256 {
            continue;
        }
        ensure!(
            journal.schema_version == 1,
            "existing storage journal has an unsupported schema"
        );
        match journal.state {
            JournalState::Completed | JournalState::Restored => {}
            JournalState::Prepared | JournalState::Mutated
                if journal.holder_identity
                    == context.exclusive_access.kubernetes_lease.holder_identity => {}
            JournalState::Prepared | JournalState::Mutated => {
                bail!(
                    "unresolved storage mutation belongs to another attempt; explicit recovery is required"
                )
            }
            JournalState::Quarantined => {
                bail!(
                    "quarantined storage mutation requires explicit repair acknowledgement before a new session"
                )
            }
        }
    }
    Ok(())
}

fn journal_name(operation_id: &str) -> Result<String> {
    let id = Uuid::parse_str(operation_id).context("journal operation id is not a UUID")?;
    Ok(format!("mutation-{id}.json"))
}

fn read_limited(file: &File, limit: usize, label: &str) -> Result<Vec<u8>> {
    let metadata = file.metadata().with_context(|| format!("stat {label}"))?;
    ensure!(metadata.is_file(), "{label} is not a regular file");
    let length = usize::try_from(metadata.len()).context("file length overflow")?;
    ensure!(
        length > 0 && length <= limit,
        "{label} is empty or oversized"
    );
    let mut reader = file.try_clone()?;
    let mut body = Vec::with_capacity(length);
    Read::by_ref(&mut reader)
        .take(u64::try_from(limit)? + 1)
        .read_to_end(&mut body)?;
    ensure!(
        body.len() == length && body.len() <= limit,
        "{label} changed while it was read"
    );
    Ok(body)
}

fn required<'a>(value: &'a Option<String>, label: &str) -> Result<&'a str> {
    value
        .as_deref()
        .with_context(|| format!("{label} is absent"))
}

fn device_id(metadata: &std::fs::Metadata) -> String {
    let device = metadata.dev();
    let major = libc::major(device);
    let minor = libc::minor(device);
    format!("{major}:{minor}")
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn now_ms() -> Result<u64> {
    u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())
        .context("system timestamp exceeds u64 milliseconds")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fault::storage_recovery_runtime::*;
    use std::{fs, os::unix::fs::symlink};
    use tempfile::TempDir;

    const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn execute(
        invocation: StorageHelperInvocation,
        roots: &StorageHelperRoots,
    ) -> Result<StorageRecoveryOperationReceipt> {
        StorageHelperSession::begin(invocation.context.clone(), roots)?.execute(invocation)
    }

    fn test_roots() -> (TempDir, StorageHelperRoots) {
        let temporary = tempfile::tempdir().expect("temporary roots");
        for name in ["volume", "journal", "lock"] {
            fs::create_dir(temporary.path().join(name)).expect("helper root");
        }
        let roots = StorageHelperRoots {
            volume: temporary.path().join("volume"),
            journal: temporary.path().join("journal"),
            lock: temporary.path().join("lock"),
        };
        (temporary, roots)
    }

    fn context_for(roots: &StorageHelperRoots) -> OwnedStorageContext {
        let volume_metadata = fs::metadata(&roots.volume).expect("volume metadata");
        let device = device_id(&volume_metadata);
        let mut context = OwnedStorageContext {
            identity: crate::fault::storage_recovery::StorageRecoveryArtifactIdentity {
                run_id: "run-1".to_string(),
                scenario: "on-disk-bitrot".to_string(),
                case_name: "automatic-scanner".to_string(),
                bucket: "bucket-1".to_string(),
            },
            case: crate::fault::storage_recovery::StorageRecoveryCase::OnDiskBitrotAutomaticScanner,
            attempt_id: "attempt-1".to_string(),
            cluster_context: "kind-s3chaos".to_string(),
            tenant_uid: "tenant-uid-1".to_string(),
            scope_sha256: String::new(),
            volume: crate::fault::storage_recovery::StorageVolumeIdentity {
                target_proof_sha256: HASH.to_string(),
                host_storage_proof_sha256: HASH.to_string(),
                rustfs_deployment_id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".to_string(),
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
                rustfs_drive_uuid: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb".to_string(),
                pool_index: 0,
                set_index: 0,
                observed_at_ms: now_ms().expect("now") - 100,
            },
            resource_versions: KubernetesResourceVersions {
                tenant: "10".to_string(),
                pod: "11".to_string(),
                persistent_volume_claim: "12".to_string(),
                persistent_volume: "13".to_string(),
                node: "14".to_string(),
                helper_pod: "15".to_string(),
            },
            host_generation: HostGenerationIdentity {
                mount_id: "mount-1".to_string(),
                mount_namespace_id: "mnt:[1]".to_string(),
                device_major_minor: device,
                device_mapper_uuid: "dm-uuid-1".to_string(),
                device_mapper_table_sha256: HASH.to_string(),
                filesystem_uuid: "fs-1".to_string(),
                rustfs_drive_uuid: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb".to_string(),
            },
            exclusive_access: StorageRecoveryExclusiveAccess {
                kubernetes_lease: KubernetesLeaseProof {
                    name: String::new(),
                    uid: "lease-uid-1".to_string(),
                    resource_version: "20".to_string(),
                    holder_identity: "run-1/attempt-1".to_string(),
                    scope_sha256: String::new(),
                    acquired_at_ms: now_ms().expect("now") - 100,
                    renew_at_ms: now_ms().expect("now") - 50,
                    expires_at_ms: now_ms().expect("now") + 60_000,
                },
                host_flock: HostFlockProof {
                    node: "node-1".to_string(),
                    node_uid: "node-uid-1".to_string(),
                    path: String::new(),
                    device_id: String::new(),
                    inode: 0,
                    scope_sha256: String::new(),
                    acquired_at_ms: now_ms().expect("now") - 25,
                },
            },
            helper_pod_name: "s3chaos-storage-helper".to_string(),
            helper_pod_uid: "helper-uid-1".to_string(),
            observed_at_ms: now_ms().expect("now"),
        };
        let scope = storage_scope_sha256(&context);
        let lock_path = roots.lock.join(format!("storage-{scope}.lock"));
        File::create(&lock_path).expect("lock file");
        let lock_metadata = fs::metadata(lock_path).expect("lock metadata");
        context.scope_sha256 = scope.clone();
        context.exclusive_access.kubernetes_lease.name =
            format!("s3chaos-storage-{}", &scope[..20]);
        context.exclusive_access.kubernetes_lease.scope_sha256 = scope.clone();
        context.exclusive_access.host_flock.path =
            format!("{STORAGE_RECOVERY_HOST_LOCK_DIRECTORY}/storage-{scope}.lock");
        context.exclusive_access.host_flock.device_id = device_id(&lock_metadata);
        context.exclusive_access.host_flock.inode = lock_metadata.ino();
        context.exclusive_access.host_flock.scope_sha256 = scope;
        context
    }

    fn mutation(
        context: &OwnedStorageContext,
        roots: &StorageHelperRoots,
        path: &str,
    ) -> StorageRecoveryHostOperation {
        let metadata = fs::metadata(path).expect("part metadata");
        let body = fs::read(path).expect("part body");
        let relative_part_path = "bucket/object/data-dir/part.1".to_string();
        let inspection = completed_receipt(
            context,
            &open_directory(&roots.journal, "journal root").expect("journal root"),
            StorageRecoveryHostOperation::InspectXlMeta {
                object_directory: "bucket/object".to_string(),
                bucket: "bucket-1".to_string(),
                object_key: "object".to_string(),
                object_sha256: HASH.to_string(),
                version_id: "01234567-89ab-cdef-0123-456789abcdef".to_string(),
                selected_part_number: 1,
                expected_mount_device_id: context.host_generation.device_major_minor.clone(),
                expected_drive_uuid: context.volume.rustfs_drive_uuid.clone(),
            },
            &OfflineXl2InspectResponse {
                mount_device_id: context.host_generation.device_major_minor.clone(),
                drive_uuid: context.volume.rustfs_drive_uuid.clone(),
                format_json_sha256: HASH.to_string(),
                xl_meta_sha256: HASH.to_string(),
                layout: crate::fault::xl2_inspector::Xl2ObjectVersionLayout {
                    inspector_revision: crate::fault::xl2_inspector::OFFLINE_XL2_INSPECTOR_REVISION
                        .to_string(),
                    profile: crate::fault::xl2_inspector::Xl2FormatProfile::SUPPORTED,
                    version_id: "01234567-89ab-cdef-0123-456789abcdef".to_string(),
                    data_directory: "data-dir".to_string(),
                    erasure_data_shards: 1,
                    erasure_parity_shards: 1,
                    erasure_index: 1,
                    part_numbers: vec![1],
                    part_sizes: vec![metadata.len()],
                    relative_part_paths: vec![relative_part_path.clone()],
                },
                selected_part: OfflineInspectedShard {
                    part_number: 1,
                    relative_part_path,
                    shard_device_id: context.host_generation.device_major_minor.clone(),
                    shard_inode: metadata.ino(),
                    shard_size_bytes: metadata.len(),
                    original_sha256: sha256_bytes(&body),
                },
            },
            now_ms().expect("now"),
        )
        .expect("sealed inspection receipt");
        StorageRecoveryHostOperation::MutateShard {
            inspection_operation_id: inspection.operation_id,
            part_number: 1,
            byte_offset: 1,
        }
    }

    #[test]
    fn controlled_mutation_is_durable_and_compare_restores() {
        let (_temporary, roots) = test_roots();
        let part_path = roots.volume.join("bucket/object/data-dir/part.1");
        let other_part_path = roots.volume.join("bucket/object/data-dir/part.2");
        fs::create_dir_all(part_path.parent().expect("part parent")).expect("part parent");
        fs::write(&part_path, b"original shard payload").expect("part");
        fs::write(&other_part_path, b"other shard payload").expect("other part");
        let context = context_for(&roots);
        let operation = mutation(&context, &roots, part_path.to_str().expect("part path"));
        let mut session = StorageHelperSession::begin(context.clone(), &roots).expect("session");
        let mutated = session
            .execute(StorageHelperInvocation {
                context: context.clone(),
                operation,
            })
            .expect("mutate shard");
        let journal_root = open_directory(&roots.journal, "journal root").expect("journal root");
        let mutation_journal =
            load_journal(&journal_root, &mutated.operation_id).expect("mutation journal");
        assert_eq!(
            mutation_journal.response_body.as_deref(),
            Some(mutated.response_body.as_str())
        );
        assert_eq!(
            mutation_journal.response_sha256.as_deref(),
            Some(mutated.response_sha256.as_str())
        );
        assert_ne!(
            fs::read(&part_path).expect("mutated part"),
            b"original shard payload"
        );
        assert_eq!(
            fs::read(&other_part_path).expect("other part"),
            b"other shard payload",
            "a receipt-derived mutation must not touch another part on the same volume"
        );

        let restored = session
            .execute(StorageHelperInvocation {
                context: context.clone(),
                operation: StorageRecoveryHostOperation::RestoreShard {
                    mutation_operation_id: mutated.operation_id,
                },
            })
            .expect("restore shard");
        let restore_journal =
            load_journal(&journal_root, &restored.operation_id).expect("restore receipt journal");
        assert_eq!(restore_journal.operation, restored.operation);
        assert_eq!(
            restore_journal.response_sha256.as_deref(),
            Some(restored.response_sha256.as_str())
        );
        let cleanup = StorageRecoveryCleanupProof::BitrotRestored {
            restore_receipt: Box::new(restored),
        };
        session.finish(&context, &cleanup).expect("finish session");
        assert_eq!(
            fs::read(part_path).expect("restored part"),
            b"original shard payload"
        );
        assert_eq!(
            fs::read(other_part_path).expect("other part"),
            b"other shard payload"
        );
    }

    #[test]
    fn mutation_requires_the_exact_sealed_inspection_and_part() {
        let (_temporary, roots) = test_roots();
        let part_path = roots.volume.join("bucket/object/data-dir/part.1");
        let other_part_path = roots.volume.join("bucket/object/data-dir/part.2");
        fs::create_dir_all(part_path.parent().expect("part parent")).expect("part parent");
        fs::write(&part_path, b"original shard payload").expect("part");
        fs::write(&other_part_path, b"other shard payload").expect("other part");
        let context = context_for(&roots);

        let mut wrong_inspection =
            mutation(&context, &roots, part_path.to_str().expect("part path"));
        let StorageRecoveryHostOperation::MutateShard {
            inspection_operation_id,
            ..
        } = &mut wrong_inspection
        else {
            unreachable!("test operation is a mutation")
        };
        *inspection_operation_id = Uuid::new_v4().to_string();
        assert!(
            execute(
                StorageHelperInvocation {
                    context: context.clone(),
                    operation: wrong_inspection,
                },
                &roots,
            )
            .is_err(),
            "an unknown inspection id must fail closed"
        );

        let mut switched_part = mutation(&context, &roots, part_path.to_str().expect("part path"));
        let StorageRecoveryHostOperation::MutateShard { part_number, .. } = &mut switched_part
        else {
            unreachable!("test operation is a mutation")
        };
        *part_number = 2;
        assert!(
            execute(
                StorageHelperInvocation {
                    context,
                    operation: switched_part,
                },
                &roots,
            )
            .is_err(),
            "a controller-selected part different from the sealed inspection must fail closed"
        );
        assert_eq!(
            fs::read(part_path).expect("selected part"),
            b"original shard payload"
        );
        assert_eq!(
            fs::read(other_part_path).expect("other part"),
            b"other shard payload"
        );
    }

    #[test]
    fn prepared_journal_recovers_after_helper_dies_post_mutation() {
        let (_temporary, roots) = test_roots();
        let part_path = roots.volume.join("bucket/object/data-dir/part.1");
        fs::create_dir_all(part_path.parent().expect("part parent")).expect("part parent");
        fs::write(&part_path, b"original shard payload").expect("part");
        let context = context_for(&roots);
        let operation = mutation(&context, &roots, part_path.to_str().expect("part path"));
        let StorageRecoveryHostOperation::MutateShard { byte_offset, .. } = operation.clone()
        else {
            unreachable!("test operation is a mutation")
        };
        let relative_part_path = "bucket/object/data-dir/part.1".to_string();
        let shard_metadata = fs::metadata(&part_path).expect("part metadata");
        let shard_device_id = context.host_generation.device_major_minor.clone();
        let shard_inode = shard_metadata.ino();
        let shard_size_bytes = shard_metadata.len();
        let original_sha256 = sha256_bytes(&fs::read(&part_path).expect("part"));
        let root = open_directory(&roots.volume, "volume root").expect("volume root");
        let part = open_beneath(&root, &relative_part_path, libc::O_RDWR, 0).expect("part fd");
        let mut original = [0_u8; 1];
        part.read_at(&mut original, byte_offset)
            .expect("read original");
        let mutated_byte = original[0] ^ MUTATION_XOR_MASK;
        let mutated_sha256 = hash_file(&part, Some((byte_offset, mutated_byte))).expect("hash");
        let operation_id = Uuid::new_v4().to_string();
        let journal = MutationJournal {
            schema_version: 1,
            operation_id: operation_id.clone(),
            context_sha256: context_sha256(&context).expect("context digest"),
            scope_sha256: context.scope_sha256.clone(),
            holder_identity: context
                .exclusive_access
                .kubernetes_lease
                .holder_identity
                .clone(),
            operation,
            state: JournalState::Prepared,
            relative_part_path: Some(relative_part_path),
            shard_device_id: Some(shard_device_id),
            shard_inode: Some(shard_inode),
            shard_size_bytes: Some(shard_size_bytes),
            byte_offset: Some(byte_offset),
            original_byte: Some(original[0]),
            mutated_byte: Some(mutated_byte),
            original_sha256: Some(original_sha256),
            mutated_sha256: Some(mutated_sha256),
            reason: None,
            response_body: None,
            response_sha256: None,
            updated_at_ms: now_ms().expect("now"),
        };
        let journal_root = open_directory(&roots.journal, "journal root").expect("journal root");
        persist_journal(&journal_root, &journal).expect("prepared journal");
        part.write_at(&[mutated_byte], byte_offset)
            .expect("simulate mutation before helper death");
        part.sync_all().expect("durable simulated mutation");
        drop(part);

        execute(
            StorageHelperInvocation {
                context: context.clone(),
                operation: StorageRecoveryHostOperation::RestoreShard {
                    mutation_operation_id: operation_id,
                },
            },
            &roots,
        )
        .expect("restore prepared journal");
        assert_eq!(
            fs::read(part_path).expect("restored part"),
            b"original shard payload"
        );
    }

    #[test]
    fn partial_published_journal_is_rejected_without_touching_shard() {
        let (_temporary, roots) = test_roots();
        let part_path = roots.volume.join("bucket/object/data-dir/part.1");
        fs::create_dir_all(part_path.parent().expect("part parent")).expect("part parent");
        fs::write(&part_path, b"original shard payload").expect("part");
        let context = context_for(&roots);
        let operation_id = Uuid::new_v4().to_string();
        fs::write(
            roots.journal.join(format!("mutation-{operation_id}.json")),
            b"{\"schemaVersion\":1",
        )
        .expect("partial journal");

        assert!(
            execute(
                StorageHelperInvocation {
                    context,
                    operation: StorageRecoveryHostOperation::RestoreShard {
                        mutation_operation_id: operation_id,
                    },
                },
                &roots,
            )
            .is_err()
        );
        assert_eq!(
            fs::read(part_path).expect("untouched part"),
            b"original shard payload"
        );
    }

    #[test]
    fn path_escape_and_symlink_are_rejected_by_openat2() {
        let (_temporary, roots) = test_roots();
        fs::write(roots.volume.join("outside"), b"outside").expect("outside");
        symlink("outside", roots.volume.join("link")).expect("symlink");
        let root = open_directory(&roots.volume, "test root").expect("root");

        assert!(open_beneath(&root, "../outside", libc::O_RDONLY, 0).is_err());
        assert!(open_beneath(&root, "link", libc::O_RDONLY, 0).is_err());
        let system_root = open_directory(Path::new("/"), "system root").expect("system root");
        assert!(
            open_beneath(&system_root, "proc/version", libc::O_RDONLY, 0).is_err(),
            "openat2 must reject crossing from / into the /proc mount"
        );
        assert_eq!(
            STORAGE_RESOLVE_FLAGS,
            RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV
        );
    }

    #[test]
    fn second_attempt_cannot_acquire_host_lock_during_session() {
        let (_temporary, roots) = test_roots();
        let context = context_for(&roots);
        let _first = StorageHelperSession::begin(context.clone(), &roots).expect("first session");

        let error = StorageHelperSession::begin(context, &roots)
            .err()
            .expect("second session must not acquire flock");
        assert!(error.to_string().contains("flock"), "{error:#}");
    }

    #[test]
    fn unresolved_mutation_blocks_lease_takeover_by_new_attempt() {
        let (_temporary, roots) = test_roots();
        let part_path = roots.volume.join("bucket/object/data-dir/part.1");
        fs::create_dir_all(part_path.parent().expect("part parent")).expect("part parent");
        fs::write(&part_path, b"original shard payload").expect("part");
        let context = context_for(&roots);
        let operation = mutation(&context, &roots, part_path.to_str().expect("part path"));
        let mut first = StorageHelperSession::begin(context.clone(), &roots).expect("first");
        first
            .execute(StorageHelperInvocation {
                context: context.clone(),
                operation,
            })
            .expect("mutation");
        drop(first);

        let mut next_attempt = context;
        next_attempt.identity.run_id = "run-2".to_string();
        next_attempt.attempt_id = "attempt-2".to_string();
        next_attempt
            .exclusive_access
            .kubernetes_lease
            .holder_identity = "run-2/attempt-2".to_string();
        let error = StorageHelperSession::begin(next_attempt, &roots)
            .err()
            .expect("new attempt must not inherit unresolved mutation");
        assert!(error.to_string().contains("another attempt"), "{error:#}");
    }

    #[test]
    fn inode_drift_and_independent_change_quarantine_restore() {
        let (_temporary, roots) = test_roots();
        let part_path = roots.volume.join("bucket/object/data-dir/part.1");
        fs::create_dir_all(part_path.parent().expect("part parent")).expect("part parent");
        fs::write(&part_path, b"original shard payload").expect("part");
        let context = context_for(&roots);
        let operation = mutation(&context, &roots, part_path.to_str().expect("part path"));
        let mutated = execute(
            StorageHelperInvocation {
                context: context.clone(),
                operation,
            },
            &roots,
        )
        .expect("mutate shard");

        fs::remove_file(&part_path).expect("remove old inode");
        fs::write(&part_path, b"independent replacement").expect("replacement inode");
        let receipt = execute(
            StorageHelperInvocation {
                context: context.clone(),
                operation: StorageRecoveryHostOperation::RestoreShard {
                    mutation_operation_id: mutated.operation_id.clone(),
                },
            },
            &roots,
        )
        .expect("durable quarantine receipt");
        assert!(
            receipt
                .response_body
                .contains("\"outcome\":\"quarantined\"")
        );
        StorageRecoveryCleanupProof::BitrotQuarantined {
            restore_receipt: Box::new(receipt),
        }
        .validate_for(&context)
        .expect_err("quarantine must not release attempt ownership");
        let journal = load_journal(
            &open_directory(&roots.journal, "journal root").expect("journal root"),
            &mutated.operation_id,
        )
        .expect("quarantine journal");
        assert_eq!(journal.state, JournalState::Quarantined);

        let mut next_attempt = context;
        next_attempt.identity.run_id = "run-2".to_string();
        next_attempt.attempt_id = "attempt-2".to_string();
        next_attempt
            .exclusive_access
            .kubernetes_lease
            .holder_identity = "run-2/attempt-2".to_string();
        let error = StorageHelperSession::begin(next_attempt, &roots)
            .err()
            .expect("quarantine must fence a new attempt after Lease takeover");
        assert!(
            error.to_string().contains("repair acknowledgement"),
            "{error:#}"
        );
    }
}
