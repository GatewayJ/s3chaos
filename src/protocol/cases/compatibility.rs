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

use anyhow::{Context, Result, anyhow, ensure};

use crate::protocol::{
    authorization::{
        ProtocolActorSource, ProtocolAuthorizationDimensions, ProtocolGrantSource,
        ProtocolPolicyEffect,
    },
    cases::{
        CaseContext, ProtocolCaseExecution,
        authz::{expect_error_class, expect_eventual_ok, expect_eventual_value},
    },
    catalog::{
        COMPAT_BUCKET_HEAD, COMPAT_BUCKET_LIST_CREATE_DELETE, COMPAT_LIST_OBJECTS_BASIC,
        COMPAT_MULTI_OBJECT_DELETE, COMPAT_MULTIPART_UPLOAD_SMALL, COMPAT_OBJECT_COPY_SAME_BUCKET,
        COMPAT_OBJECT_PUT_GET_DELETE, COMPAT_VERSIONING_HEAD_REMOVAL,
        PUBLIC_ACCESS_BLOCK_ROUND_TRIP,
    },
    fixture::{
        naming::ProtocolResourceNamer,
        registry::{ResourceHandle, ResourceKind, ResourceRegistry, ResourceState},
    },
    ports::{ProtocolCompletedPart, ProtocolPublicAccessBlock, ProtocolS3Error, ProtocolS3Port},
    reporting::ProtocolAssertionClass,
};

pub(crate) async fn run_compatibility_case(
    case_id: &str,
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    s3: &impl ProtocolS3Port,
) -> ProtocolCaseExecution {
    let mut context = CaseContext::new(
        case_id,
        ProtocolAuthorizationDimensions {
            actor_source: ProtocolActorSource::Admin,
            grant_source: ProtocolGrantSource::AdminCredential,
            policy_effect: ProtocolPolicyEffect::Allow,
        },
    );
    let result = match case_id {
        COMPAT_BUCKET_HEAD => run_bucket_head(case_id, namer, registry, s3, &mut context).await,
        COMPAT_BUCKET_LIST_CREATE_DELETE => {
            run_bucket_list_create_delete(case_id, namer, registry, s3, &mut context).await
        }
        COMPAT_LIST_OBJECTS_BASIC => {
            run_list_objects_basic(case_id, namer, registry, s3, &mut context).await
        }
        COMPAT_MULTI_OBJECT_DELETE => {
            run_multi_object_delete(case_id, namer, registry, s3, &mut context).await
        }
        COMPAT_MULTIPART_UPLOAD_SMALL => {
            run_multipart_upload_small(case_id, namer, registry, s3, &mut context).await
        }
        COMPAT_OBJECT_COPY_SAME_BUCKET => {
            run_object_copy_same_bucket(case_id, namer, registry, s3, &mut context).await
        }
        COMPAT_OBJECT_PUT_GET_DELETE => {
            run_object_put_get_delete(case_id, namer, registry, s3, &mut context).await
        }
        COMPAT_VERSIONING_HEAD_REMOVAL => {
            run_versioning_head_removal(case_id, namer, registry, s3, &mut context).await
        }
        PUBLIC_ACCESS_BLOCK_ROUND_TRIP => {
            run_public_access_block_round_trip(case_id, namer, registry, s3, &mut context).await
        }
        _ => Err(anyhow!("unsupported compatibility case {case_id}")),
    };
    context.finish(result)
}

async fn run_bucket_head(
    case_id: &str,
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    s3: &impl ProtocolS3Port,
    context: &mut CaseContext,
) -> Result<()> {
    let bucket = namer.bucket(case_id, 0)?;
    create_bucket(case_id, &bucket, registry, s3).await?;
    context.current_phase = "assertion".to_string();
    expect_eventual_ok(context, "admin", "head-bucket", &bucket, None, || {
        s3.head_bucket(&bucket)
    })
    .await
}

async fn run_bucket_list_create_delete(
    case_id: &str,
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    s3: &impl ProtocolS3Port,
    context: &mut CaseContext,
) -> Result<()> {
    let bucket = namer.bucket(case_id, 0)?;
    context.current_phase = "assertion".to_string();
    let before = expect_eventual_value(
        context,
        "admin",
        "list-buckets-before-create",
        &bucket,
        None,
        || s3.list_buckets_with_prefix(&bucket),
    )
    .await?;
    ensure!(
        before.is_empty(),
        "bucket unexpectedly existed before create"
    );

    context.current_phase = "setup".to_string();
    create_bucket(case_id, &bucket, registry, s3).await?;
    context.current_phase = "assertion".to_string();
    let after = expect_eventual_value(
        context,
        "admin",
        "list-buckets-after-create",
        &bucket,
        None,
        || s3.list_buckets_with_prefix(&bucket),
    )
    .await?;
    ensure!(
        after == [bucket.as_str()],
        "created bucket was not listed exactly once"
    );
    let listing =
        expect_eventual_value(context, "admin", "list-empty-bucket", &bucket, None, || {
            s3.list_objects_v2_summary(&bucket)
        })
        .await?;
    ensure!(
        listing.keys.is_empty() && listing.key_count == 0,
        "new bucket returned objects or a non-zero KeyCount"
    );
    Ok(())
}

async fn run_object_put_get_delete(
    case_id: &str,
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    s3: &impl ProtocolS3Port,
    context: &mut CaseContext,
) -> Result<()> {
    let bucket = namer.bucket(case_id, 0)?;
    let bucket_handle = create_bucket(case_id, &bucket, registry, s3).await?;
    let key = format!("cases/{case_id}/object");
    let object_handle = register_object_prefix(case_id, &bucket, &bucket_handle, registry)?;
    context.current_phase = "assertion".to_string();
    expect_eventual_ok(context, "admin", "put-object", &bucket, Some(&key), || {
        s3.put_object(&bucket, &key, b"bar")
    })
    .await?;
    registry.transition(&object_handle.id, ResourceState::Created, None)?;
    let body = expect_eventual_value(context, "admin", "get-object", &bucket, Some(&key), || {
        s3.get_object(&bucket, &key)
    })
    .await?;
    ensure!(
        body == b"bar",
        "object body changed after initial round trip"
    );
    expect_eventual_ok(
        context,
        "admin",
        "update-object",
        &bucket,
        Some(&key),
        || s3.put_object(&bucket, &key, b"soup"),
    )
    .await?;
    let updated = expect_eventual_value(
        context,
        "admin",
        "get-object-after-update",
        &bucket,
        Some(&key),
        || s3.get_object(&bucket, &key),
    )
    .await?;
    ensure!(
        updated == b"soup",
        "object update was not visible to a later read"
    );
    expect_eventual_ok(
        context,
        "admin",
        "delete-object",
        &bucket,
        Some(&key),
        || s3.delete_object(&bucket, &key),
    )
    .await?;
    expect_error_class(
        context,
        "admin",
        "get-object-after-delete",
        &bucket,
        ProtocolAssertionClass::NoSuchKey,
        || async { s3.get_object(&bucket, &key).await.map(|_| ()) },
    )
    .await
}

async fn run_list_objects_basic(
    case_id: &str,
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    s3: &impl ProtocolS3Port,
    context: &mut CaseContext,
) -> Result<()> {
    let bucket = namer.bucket(case_id, 0)?;
    let bucket_handle = create_bucket(case_id, &bucket, registry, s3).await?;
    let object_handle = register_object_prefix(case_id, &bucket, &bucket_handle, registry)?;
    let keys = (0..5)
        .map(|index| format!("cases/{case_id}/{index}"))
        .collect::<Vec<_>>();
    context.current_phase = "assertion".to_string();
    for key in &keys {
        expect_eventual_ok(
            context,
            "admin",
            "put-list-fixture",
            &bucket,
            Some(key),
            || s3.put_object(&bucket, key, key.as_bytes()),
        )
        .await?;
    }
    registry.transition(&object_handle.id, ResourceState::Created, None)?;
    let mut listing = expect_eventual_value(
        context,
        "admin",
        "list-objects-with-key-count",
        &bucket,
        None,
        || s3.list_objects_v2_summary(&bucket),
    )
    .await?;
    listing.keys.sort();
    ensure!(
        listing.key_count == 5,
        "ListObjectsV2 returned KeyCount={} instead of 5",
        listing.key_count
    );
    ensure!(
        listing.keys == keys,
        "ListObjectsV2 returned an unexpected key set"
    );
    Ok(())
}

async fn run_object_copy_same_bucket(
    case_id: &str,
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    s3: &impl ProtocolS3Port,
    context: &mut CaseContext,
) -> Result<()> {
    let bucket = namer.bucket(case_id, 0)?;
    let bucket_handle = create_bucket(case_id, &bucket, registry, s3).await?;
    let object_handle = register_object_prefix(case_id, &bucket, &bucket_handle, registry)?;
    let source = format!("cases/{case_id}/foo123bar");
    let destination = format!("cases/{case_id}/bar321foo");
    context.current_phase = "assertion".to_string();
    expect_eventual_ok(
        context,
        "admin",
        "put-copy-source",
        &bucket,
        Some(&source),
        || s3.put_object(&bucket, &source, b"foo"),
    )
    .await?;
    expect_eventual_ok(
        context,
        "admin",
        "copy-object-same-bucket",
        &bucket,
        Some(&destination),
        || s3.copy_object(&bucket, &source, &destination),
    )
    .await?;
    registry.transition(&object_handle.id, ResourceState::Created, None)?;
    let copied = expect_eventual_value(
        context,
        "admin",
        "get-copied-object",
        &bucket,
        Some(&destination),
        || s3.get_object(&bucket, &destination),
    )
    .await?;
    ensure!(copied == b"foo", "same-bucket copy changed the object body");
    Ok(())
}

async fn run_multi_object_delete(
    case_id: &str,
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    s3: &impl ProtocolS3Port,
    context: &mut CaseContext,
) -> Result<()> {
    let bucket = namer.bucket(case_id, 0)?;
    let bucket_handle = create_bucket(case_id, &bucket, registry, s3).await?;
    let object_handle = register_object_prefix(case_id, &bucket, &bucket_handle, registry)?;
    let keys = (0..3)
        .map(|index| format!("cases/{case_id}/key{index}"))
        .collect::<Vec<_>>();
    context.current_phase = "assertion".to_string();
    for key in &keys {
        expect_eventual_ok(
            context,
            "admin",
            "put-delete-fixture",
            &bucket,
            Some(key),
            || s3.put_object(&bucket, key, key.as_bytes()),
        )
        .await?;
    }
    registry.transition(&object_handle.id, ResourceState::Created, None)?;
    for operation in ["delete-objects", "delete-objects-idempotent-retry"] {
        let mut deleted = expect_eventual_value(context, "admin", operation, &bucket, None, || {
            s3.delete_objects(&bucket, &keys)
        })
        .await?;
        deleted.sort();
        ensure!(
            deleted == keys,
            "{operation} did not report every requested key"
        );
        ensure!(
            s3.list_objects(&bucket).await?.is_empty(),
            "{operation} left objects in the bucket"
        );
    }
    Ok(())
}

async fn run_multipart_upload_small(
    case_id: &str,
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    s3: &impl ProtocolS3Port,
    context: &mut CaseContext,
) -> Result<()> {
    let bucket = namer.bucket(case_id, 0)?;
    let bucket_handle = create_bucket(case_id, &bucket, registry, s3).await?;
    let key = format!("cases/{case_id}/mymultipart");
    let object_handle = register_object_prefix(case_id, &bucket, &bucket_handle, registry)?;
    let upload_handle =
        registry.plan_multipart_upload(&bucket, &key, case_id, vec![bucket_handle.id.clone()])?;
    registry.transition(&upload_handle.id, ResourceState::Creating, None)?;
    let upload_id = s3.create_multipart_upload(&bucket, &key).await?;
    registry.set_multipart_upload_id(&upload_handle.id, &upload_id)?;
    registry.transition(&upload_handle.id, ResourceState::Created, None)?;
    let etag = s3.upload_part(&bucket, &key, &upload_id, 1, b"x").await?;
    let parts = [ProtocolCompletedPart {
        part_number: 1,
        etag,
    }];
    context.current_phase = "assertion".to_string();
    expect_eventual_ok(
        context,
        "admin",
        "complete-multipart-upload",
        &bucket,
        Some(&key),
        || s3.complete_multipart_upload(&bucket, &key, &upload_id, &parts),
    )
    .await?;
    expect_eventual_ok(
        context,
        "admin",
        "complete-multipart-upload-idempotent-retry",
        &bucket,
        Some(&key),
        || s3.complete_multipart_upload(&bucket, &key, &upload_id, &parts),
    )
    .await?;
    registry.transition(&upload_handle.id, ResourceState::CleanupAttempted, None)?;
    registry.transition(&upload_handle.id, ResourceState::Cleaned, None)?;
    registry.transition(&object_handle.id, ResourceState::Created, None)?;
    let body = expect_eventual_value(
        context,
        "admin",
        "get-completed-multipart-object",
        &bucket,
        Some(&key),
        || s3.get_object(&bucket, &key),
    )
    .await?;
    ensure!(
        body == b"x",
        "completed multipart object body was incorrect"
    );
    Ok(())
}

async fn run_versioning_head_removal(
    case_id: &str,
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    s3: &impl ProtocolS3Port,
    context: &mut CaseContext,
) -> Result<()> {
    registry.set_versioned_cleanup(true)?;
    let bucket = namer.bucket(case_id, 0)?;
    let bucket_handle = create_bucket(case_id, &bucket, registry, s3).await?;
    context.current_phase = "assertion".to_string();
    expect_eventual_ok(
        context,
        "admin",
        "enable-bucket-versioning",
        &bucket,
        None,
        || s3.put_bucket_versioning(&bucket, true),
    )
    .await?;
    let key = format!("cases/{case_id}/testobj");
    let object_handle = register_object_prefix(case_id, &bucket, &bucket_handle, registry)?;
    for index in 0..5 {
        s3.put_object(&bucket, &key, format!("version-{index}").as_bytes())
            .await?;
    }
    registry.transition(&object_handle.id, ResourceState::Created, None)?;
    let versions = s3
        .list_object_versions(&bucket)
        .await?
        .into_iter()
        .filter(|version| version.key == key && !version.delete_marker)
        .collect::<Vec<_>>();
    ensure!(versions.len() == 5, "expected five object versions");
    let mut latest_version_id = None;
    for version in &versions {
        if s3
            .get_object_version(&bucket, &key, &version.version_id)
            .await?
            == b"version-4"
        {
            latest_version_id = Some(version.version_id.clone());
        }
    }
    let latest_version_id = latest_version_id.context("latest object version was not found")?;
    s3.delete_object_version(&bucket, &key, &latest_version_id)
        .await?;
    ensure!(
        s3.get_object(&bucket, &key).await? == b"version-3",
        "deleting the latest version did not expose its predecessor"
    );
    s3.delete_object(&bucket, &key).await?;
    let after_delete = s3.list_object_versions(&bucket).await?;
    ensure!(
        after_delete
            .iter()
            .filter(|version| version.key == key && !version.delete_marker)
            .count()
            == 4,
        "version delete changed the remaining version count"
    );
    ensure!(
        after_delete
            .iter()
            .filter(|version| version.key == key && version.delete_marker)
            .count()
            == 1,
        "deleting the current object did not create exactly one delete marker"
    );
    Ok(())
}

async fn run_public_access_block_round_trip(
    case_id: &str,
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    s3: &impl ProtocolS3Port,
    context: &mut CaseContext,
) -> Result<()> {
    let bucket = namer.bucket(case_id, 0)?;
    let bucket_handle = create_bucket(case_id, &bucket, registry, s3).await?;
    let configuration = ProtocolPublicAccessBlock {
        block_public_acls: true,
        ignore_public_acls: true,
        block_public_policy: true,
        restrict_public_buckets: false,
    };
    let handle = registry.plan(
        ResourceKind::PublicAccessBlock,
        &bucket,
        case_id,
        vec![bucket_handle.id],
    )?;
    registry.transition(&handle.id, ResourceState::Creating, None)?;
    s3.put_public_access_block(&bucket, configuration).await?;
    registry.transition(&handle.id, ResourceState::Created, None)?;
    context.current_phase = "assertion".to_string();
    let actual = expect_eventual_value(
        context,
        "admin",
        "get-public-access-block",
        &bucket,
        None,
        || s3.get_public_access_block(&bucket),
    )
    .await?;
    ensure!(
        actual == configuration,
        "public access block changed during round trip"
    );
    s3.delete_public_access_block(&bucket).await?;
    expect_error_class(
        context,
        "admin",
        "get-public-access-block-after-delete",
        &bucket,
        ProtocolAssertionClass::NoSuchPublicAccessBlockConfiguration,
        || async { s3.get_public_access_block(&bucket).await.map(|_| ()) },
    )
    .await?;
    registry.transition(&handle.id, ResourceState::CleanupAttempted, None)?;
    registry.transition(&handle.id, ResourceState::Cleaned, None)?;
    Ok(())
}

async fn create_bucket(
    case_id: &str,
    bucket: &str,
    registry: &mut ResourceRegistry,
    s3: &impl ProtocolS3Port,
) -> Result<ResourceHandle> {
    let handle = registry.plan(ResourceKind::Bucket, bucket, case_id, Vec::new())?;
    registry.transition(&handle.id, ResourceState::Creating, None)?;
    match s3.create_bucket(bucket).await {
        Ok(()) => registry.transition(&handle.id, ResourceState::Created, None)?,
        Err(error) => return fail_resource(registry, &handle, "create bucket", error),
    }
    Ok(handle)
}

fn register_object_prefix(
    case_id: &str,
    bucket: &str,
    bucket_handle: &ResourceHandle,
    registry: &mut ResourceRegistry,
) -> Result<ResourceHandle> {
    let handle = registry.plan_object_prefix(
        bucket,
        format!("cases/{case_id}/"),
        case_id,
        vec![bucket_handle.id.clone()],
    )?;
    registry.transition(&handle.id, ResourceState::Creating, None)?;
    Ok(handle)
}

fn fail_resource<T>(
    registry: &mut ResourceRegistry,
    handle: &ResourceHandle,
    operation: &str,
    error: ProtocolS3Error,
) -> Result<T> {
    let message = format!("{operation} failed: {error}");
    registry.transition(&handle.id, ResourceState::Failed, Some(message.clone()))?;
    Err(anyhow!(message))
}

#[cfg(test)]
mod tests {
    use super::run_compatibility_case;
    use crate::protocol::{
        catalog::{
            COMPAT_BUCKET_HEAD, COMPAT_BUCKET_LIST_CREATE_DELETE, COMPAT_LIST_OBJECTS_BASIC,
            COMPAT_MULTI_OBJECT_DELETE, COMPAT_MULTIPART_UPLOAD_SMALL,
            COMPAT_OBJECT_COPY_SAME_BUCKET, COMPAT_OBJECT_PUT_GET_DELETE,
            COMPAT_VERSIONING_HEAD_REMOVAL, PUBLIC_ACCESS_BLOCK_ROUND_TRIP,
        },
        fixture::{
            cleanup::cleanup_registered_resources, naming::ProtocolResourceNamer,
            registry::ResourceRegistry,
        },
        ports::{
            ProtocolAdminError, ProtocolAdminPort, ProtocolCompletedPart, ProtocolObjectVersion,
            ProtocolPublicAccessBlock, ProtocolS3Error, ProtocolS3Port, ProtocolServerInfo,
        },
        reporting::ProtocolCaseStatus,
        suite_plan::TargetFingerprint,
    };
    use async_trait::async_trait;
    use std::{
        collections::{BTreeMap, BTreeSet},
        sync::{Arc, Mutex},
    };

    #[derive(Default)]
    struct State {
        buckets: BTreeSet<String>,
        objects: BTreeMap<(String, String), Vec<u8>>,
        versioned_buckets: BTreeSet<String>,
        versions: BTreeMap<(String, String), Vec<StoredVersion>>,
        public_access_blocks: BTreeMap<String, ProtocolPublicAccessBlock>,
        multipart_uploads: BTreeMap<(String, String, String), BTreeMap<i32, Vec<u8>>>,
        completed_uploads: BTreeSet<(String, String, String)>,
        next_id: usize,
    }

    #[derive(Clone)]
    struct StoredVersion {
        id: String,
        body: Vec<u8>,
        delete_marker: bool,
    }

    #[derive(Clone)]
    struct FakeS3(Arc<Mutex<State>>);

    struct UnusedAdmin;

    #[async_trait]
    impl ProtocolAdminPort for UnusedAdmin {
        async fn server_info(&self) -> std::result::Result<ProtocolServerInfo, ProtocolAdminError> {
            unreachable!()
        }

        async fn users_with_prefix(
            &self,
            _prefix: &str,
        ) -> std::result::Result<Vec<String>, ProtocolAdminError> {
            unreachable!()
        }

        async fn create_user(
            &self,
            _credential: &crate::protocol::credentials::ActorCredential,
        ) -> std::result::Result<(), ProtocolAdminError> {
            unreachable!()
        }

        async fn remove_user(
            &self,
            _access_key: &str,
        ) -> std::result::Result<(), ProtocolAdminError> {
            unreachable!()
        }
    }

    #[async_trait]
    impl ProtocolS3Port for FakeS3 {
        async fn list_buckets_with_prefix(
            &self,
            prefix: &str,
        ) -> std::result::Result<Vec<String>, ProtocolS3Error> {
            Ok(self
                .0
                .lock()
                .expect("state")
                .buckets
                .iter()
                .filter(|bucket| bucket.starts_with(prefix))
                .cloned()
                .collect())
        }

        async fn create_bucket(&self, bucket: &str) -> std::result::Result<(), ProtocolS3Error> {
            self.0
                .lock()
                .expect("state")
                .buckets
                .insert(bucket.to_string());
            Ok(())
        }

        async fn delete_bucket(&self, bucket: &str) -> std::result::Result<(), ProtocolS3Error> {
            let mut state = self.0.lock().expect("state");
            state.buckets.remove(bucket);
            state.versioned_buckets.remove(bucket);
            state.public_access_blocks.remove(bucket);
            state
                .multipart_uploads
                .retain(|(upload_bucket, _, _), _| upload_bucket != bucket);
            state
                .completed_uploads
                .retain(|(upload_bucket, _, _)| upload_bucket != bucket);
            state
                .versions
                .retain(|(version_bucket, _), _| version_bucket != bucket);
            Ok(())
        }

        async fn head_bucket(&self, bucket: &str) -> std::result::Result<(), ProtocolS3Error> {
            if self.0.lock().expect("state").buckets.contains(bucket) {
                Ok(())
            } else {
                Err(ProtocolS3Error {
                    code: "NoSuchBucket".to_string(),
                    status: Some(404),
                    request_id: Some("fake".to_string()),
                })
            }
        }

        async fn put_bucket_policy(
            &self,
            _bucket: &str,
            _policy: &str,
        ) -> std::result::Result<(), ProtocolS3Error> {
            Ok(())
        }

        async fn delete_bucket_policy(
            &self,
            _bucket: &str,
        ) -> std::result::Result<(), ProtocolS3Error> {
            Ok(())
        }

        async fn list_objects(
            &self,
            bucket: &str,
        ) -> std::result::Result<Vec<String>, ProtocolS3Error> {
            Ok(self
                .0
                .lock()
                .expect("state")
                .objects
                .keys()
                .filter(|(object_bucket, _)| object_bucket == bucket)
                .map(|(_, key)| key.clone())
                .collect())
        }

        async fn put_object(
            &self,
            bucket: &str,
            key: &str,
            body: &[u8],
        ) -> std::result::Result<(), ProtocolS3Error> {
            let mut state = self.0.lock().expect("state");
            if state.versioned_buckets.contains(bucket) {
                state.next_id += 1;
                let version_id = format!("version-{}", state.next_id);
                state
                    .versions
                    .entry((bucket.to_string(), key.to_string()))
                    .or_default()
                    .push(StoredVersion {
                        id: version_id,
                        body: body.to_vec(),
                        delete_marker: false,
                    });
            }
            state
                .objects
                .insert((bucket.to_string(), key.to_string()), body.to_vec());
            Ok(())
        }

        async fn get_object(
            &self,
            bucket: &str,
            key: &str,
        ) -> std::result::Result<Vec<u8>, ProtocolS3Error> {
            self.0
                .lock()
                .expect("state")
                .objects
                .get(&(bucket.to_string(), key.to_string()))
                .cloned()
                .ok_or_else(no_such_key)
        }

        async fn delete_object(
            &self,
            bucket: &str,
            key: &str,
        ) -> std::result::Result<(), ProtocolS3Error> {
            let mut state = self.0.lock().expect("state");
            if state.versioned_buckets.contains(bucket) {
                state.next_id += 1;
                let version_id = format!("version-{}", state.next_id);
                state
                    .versions
                    .entry((bucket.to_string(), key.to_string()))
                    .or_default()
                    .push(StoredVersion {
                        id: version_id,
                        body: Vec::new(),
                        delete_marker: true,
                    });
            }
            state.objects.remove(&(bucket.to_string(), key.to_string()));
            Ok(())
        }

        async fn copy_object(
            &self,
            bucket: &str,
            source_key: &str,
            destination_key: &str,
        ) -> std::result::Result<(), ProtocolS3Error> {
            let body = self.get_object(bucket, source_key).await?;
            self.put_object(bucket, destination_key, &body).await
        }

        async fn delete_objects(
            &self,
            bucket: &str,
            keys: &[String],
        ) -> std::result::Result<Vec<String>, ProtocolS3Error> {
            for key in keys {
                self.delete_object(bucket, key).await?;
            }
            Ok(keys.to_vec())
        }

        async fn create_multipart_upload(
            &self,
            bucket: &str,
            key: &str,
        ) -> std::result::Result<String, ProtocolS3Error> {
            let mut state = self.0.lock().expect("state");
            state.next_id += 1;
            let upload_id = format!("upload-{}", state.next_id);
            state.multipart_uploads.insert(
                (bucket.to_string(), key.to_string(), upload_id.clone()),
                BTreeMap::new(),
            );
            Ok(upload_id)
        }

        async fn upload_part(
            &self,
            bucket: &str,
            key: &str,
            upload_id: &str,
            part_number: i32,
            body: &[u8],
        ) -> std::result::Result<String, ProtocolS3Error> {
            self.0
                .lock()
                .expect("state")
                .multipart_uploads
                .get_mut(&(bucket.to_string(), key.to_string(), upload_id.to_string()))
                .ok_or_else(no_such_upload)?
                .insert(part_number, body.to_vec());
            Ok(format!("etag-{part_number}"))
        }

        async fn complete_multipart_upload(
            &self,
            bucket: &str,
            key: &str,
            upload_id: &str,
            parts: &[ProtocolCompletedPart],
        ) -> std::result::Result<(), ProtocolS3Error> {
            let coordinates = (bucket.to_string(), key.to_string(), upload_id.to_string());
            let mut state = self.0.lock().expect("state");
            if state.completed_uploads.contains(&coordinates) {
                return Ok(());
            }
            let uploaded = state
                .multipart_uploads
                .remove(&coordinates)
                .ok_or_else(no_such_upload)?;
            let mut body = Vec::new();
            for part in parts {
                body.extend(uploaded.get(&part.part_number).ok_or_else(no_such_upload)?);
            }
            state
                .objects
                .insert((bucket.to_string(), key.to_string()), body);
            state.completed_uploads.insert(coordinates);
            Ok(())
        }

        async fn abort_multipart_upload(
            &self,
            bucket: &str,
            key: &str,
            upload_id: &str,
        ) -> std::result::Result<(), ProtocolS3Error> {
            self.0.lock().expect("state").multipart_uploads.remove(&(
                bucket.to_string(),
                key.to_string(),
                upload_id.to_string(),
            ));
            Ok(())
        }

        async fn list_multipart_uploads(
            &self,
            bucket: &str,
            key: &str,
        ) -> std::result::Result<Vec<String>, ProtocolS3Error> {
            Ok(self
                .0
                .lock()
                .expect("state")
                .multipart_uploads
                .keys()
                .filter(|(candidate_bucket, candidate_key, _)| {
                    candidate_bucket == bucket && candidate_key == key
                })
                .map(|(_, _, upload_id)| upload_id.clone())
                .collect())
        }

        async fn put_bucket_versioning(
            &self,
            bucket: &str,
            enabled: bool,
        ) -> std::result::Result<(), ProtocolS3Error> {
            let mut state = self.0.lock().expect("state");
            if enabled {
                state.versioned_buckets.insert(bucket.to_string());
            } else {
                state.versioned_buckets.remove(bucket);
            }
            Ok(())
        }

        async fn list_object_versions(
            &self,
            bucket: &str,
        ) -> std::result::Result<Vec<ProtocolObjectVersion>, ProtocolS3Error> {
            Ok(self
                .0
                .lock()
                .expect("state")
                .versions
                .iter()
                .filter(|((version_bucket, _), _)| version_bucket == bucket)
                .flat_map(|((_, key), versions)| {
                    versions.iter().map(|version| ProtocolObjectVersion {
                        key: key.clone(),
                        version_id: version.id.clone(),
                        delete_marker: version.delete_marker,
                    })
                })
                .collect())
        }

        async fn get_object_version(
            &self,
            bucket: &str,
            key: &str,
            version_id: &str,
        ) -> std::result::Result<Vec<u8>, ProtocolS3Error> {
            self.0
                .lock()
                .expect("state")
                .versions
                .get(&(bucket.to_string(), key.to_string()))
                .and_then(|versions| versions.iter().find(|version| version.id == version_id))
                .filter(|version| !version.delete_marker)
                .map(|version| version.body.clone())
                .ok_or_else(no_such_key)
        }

        async fn delete_object_version(
            &self,
            bucket: &str,
            key: &str,
            version_id: &str,
        ) -> std::result::Result<(), ProtocolS3Error> {
            let coordinates = (bucket.to_string(), key.to_string());
            let mut state = self.0.lock().expect("state");
            let current = {
                let versions = state.versions.entry(coordinates.clone()).or_default();
                versions.retain(|version| version.id != version_id);
                versions.last().cloned()
            };
            match current {
                Some(version) if !version.delete_marker => {
                    state.objects.insert(coordinates, version.body);
                }
                _ => {
                    state.objects.remove(&coordinates);
                }
            }
            Ok(())
        }

        async fn put_public_access_block(
            &self,
            bucket: &str,
            configuration: ProtocolPublicAccessBlock,
        ) -> std::result::Result<(), ProtocolS3Error> {
            self.0
                .lock()
                .expect("state")
                .public_access_blocks
                .insert(bucket.to_string(), configuration);
            Ok(())
        }

        async fn get_public_access_block(
            &self,
            bucket: &str,
        ) -> std::result::Result<ProtocolPublicAccessBlock, ProtocolS3Error> {
            self.0
                .lock()
                .expect("state")
                .public_access_blocks
                .get(bucket)
                .copied()
                .ok_or_else(|| ProtocolS3Error {
                    code: "NoSuchPublicAccessBlockConfiguration".to_string(),
                    status: Some(404),
                    request_id: Some("fake".to_string()),
                })
        }

        async fn delete_public_access_block(
            &self,
            bucket: &str,
        ) -> std::result::Result<(), ProtocolS3Error> {
            self.0
                .lock()
                .expect("state")
                .public_access_blocks
                .remove(bucket);
            Ok(())
        }
    }

    fn no_such_key() -> ProtocolS3Error {
        ProtocolS3Error {
            code: "NoSuchKey".to_string(),
            status: Some(404),
            request_id: Some("fake".to_string()),
        }
    }

    fn no_such_upload() -> ProtocolS3Error {
        ProtocolS3Error {
            code: "NoSuchUpload".to_string(),
            status: Some(404),
            request_id: Some("fake".to_string()),
        }
    }

    #[tokio::test]
    async fn every_native_compatibility_case_passes_and_cleans() {
        for case_id in [
            COMPAT_BUCKET_HEAD,
            COMPAT_BUCKET_LIST_CREATE_DELETE,
            COMPAT_LIST_OBJECTS_BASIC,
            COMPAT_MULTI_OBJECT_DELETE,
            COMPAT_MULTIPART_UPLOAD_SMALL,
            COMPAT_OBJECT_COPY_SAME_BUCKET,
            COMPAT_OBJECT_PUT_GET_DELETE,
            COMPAT_VERSIONING_HEAD_REMOVAL,
            PUBLIC_ACCESS_BLOCK_ROUND_TRIP,
        ] {
            let state = Arc::new(Mutex::new(State::default()));
            let s3 = FakeS3(state.clone());
            let dir = tempfile::tempdir().expect("tempdir");
            let fingerprint = TargetFingerprint::new(
                "http://127.0.0.1:9000",
                "us-east-1",
                "deployment",
                None,
                None,
            )
            .expect("fingerprint");
            let mut registry =
                ResourceRegistry::create(dir.path(), "run", fingerprint).expect("registry");
            let namer = ProtocolResourceNamer::new("s3c", "s3chaos", "run").expect("namer");
            let execution = run_compatibility_case(case_id, &namer, &mut registry, &s3).await;
            assert_eq!(
                execution.report.status,
                ProtocolCaseStatus::Passed,
                "{case_id}"
            );
            let cleanup = cleanup_registered_resources(&mut registry, &UnusedAdmin, &s3).await;
            assert!(cleanup.succeeded, "{case_id}");
            let current = state.lock().expect("state");
            assert!(current.buckets.is_empty(), "{case_id}");
            assert!(current.objects.is_empty(), "{case_id}");
            assert!(current.versions.is_empty(), "{case_id}");
            assert!(current.multipart_uploads.is_empty(), "{case_id}");
            assert!(current.public_access_blocks.is_empty(), "{case_id}");
        }
    }
}
