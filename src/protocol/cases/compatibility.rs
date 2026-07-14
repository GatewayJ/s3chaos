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

use anyhow::{Result, anyhow, ensure};

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
        COMPAT_BUCKET_LIST_CREATE_DELETE, COMPAT_LIST_OBJECTS_BASIC, COMPAT_OBJECT_PUT_GET_DELETE,
    },
    fixture::{
        naming::ProtocolResourceNamer,
        registry::{ResourceHandle, ResourceKind, ResourceRegistry, ResourceState},
    },
    ports::{ProtocolS3Error, ProtocolS3Port},
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
        COMPAT_BUCKET_LIST_CREATE_DELETE => {
            run_bucket_list_create_delete(case_id, namer, registry, s3, &mut context).await
        }
        COMPAT_LIST_OBJECTS_BASIC => {
            run_list_objects_basic(case_id, namer, registry, s3, &mut context).await
        }
        COMPAT_OBJECT_PUT_GET_DELETE => {
            run_object_put_get_delete(case_id, namer, registry, s3, &mut context).await
        }
        _ => Err(anyhow!("unsupported compatibility case {case_id}")),
    };
    context.finish(result)
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
        after == [bucket],
        "created bucket was not listed exactly once"
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
        s3.put_object(&bucket, &key, b"compatibility-object")
    })
    .await?;
    registry.transition(&object_handle.id, ResourceState::Created, None)?;
    let body = expect_eventual_value(context, "admin", "get-object", &bucket, Some(&key), || {
        s3.get_object(&bucket, &key)
    })
    .await?;
    ensure!(
        body == b"compatibility-object",
        "object body changed after round trip"
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
    let keys = [
        format!("cases/{case_id}/alpha"),
        format!("cases/{case_id}/beta"),
    ];
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
    let mut actual = expect_eventual_value(context, "admin", "list-objects", &bucket, None, || {
        s3.list_objects(&bucket)
    })
    .await?;
    actual.sort();
    ensure!(
        actual == keys,
        "ListObjectsV2 returned an unexpected key set"
    );
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
            COMPAT_BUCKET_LIST_CREATE_DELETE, COMPAT_LIST_OBJECTS_BASIC,
            COMPAT_OBJECT_PUT_GET_DELETE,
        },
        fixture::{
            cleanup::cleanup_registered_resources, naming::ProtocolResourceNamer,
            registry::ResourceRegistry,
        },
        ports::{
            ProtocolAdminError, ProtocolAdminPort, ProtocolObjectVersion, ProtocolS3Error,
            ProtocolS3Port, ProtocolServerInfo,
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
            self.0.lock().expect("state").buckets.remove(bucket);
            Ok(())
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
            self.0
                .lock()
                .expect("state")
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
            self.0
                .lock()
                .expect("state")
                .objects
                .remove(&(bucket.to_string(), key.to_string()));
            Ok(())
        }

        async fn list_object_versions(
            &self,
            _bucket: &str,
        ) -> std::result::Result<Vec<ProtocolObjectVersion>, ProtocolS3Error> {
            Ok(Vec::new())
        }

        async fn delete_object_version(
            &self,
            bucket: &str,
            key: &str,
            _version_id: &str,
        ) -> std::result::Result<(), ProtocolS3Error> {
            self.delete_object(bucket, key).await
        }
    }

    fn no_such_key() -> ProtocolS3Error {
        ProtocolS3Error {
            code: "NoSuchKey".to_string(),
            status: Some(404),
            request_id: Some("fake".to_string()),
        }
    }

    #[tokio::test]
    async fn every_native_compatibility_case_passes_and_cleans() {
        for case_id in [
            COMPAT_BUCKET_LIST_CREATE_DELETE,
            COMPAT_LIST_OBJECTS_BASIC,
            COMPAT_OBJECT_PUT_GET_DELETE,
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
        }
    }
}
