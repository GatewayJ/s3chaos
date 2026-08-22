use super::run_compatibility_case;
use crate::protocol::{
    catalog::{
        COMPAT_BUCKET_HEAD, COMPAT_BUCKET_LIST_CREATE_DELETE, COMPAT_LIST_OBJECTS_BASIC,
        COMPAT_MULTI_OBJECT_DELETE, COMPAT_MULTIPART_UPLOAD_SMALL, COMPAT_OBJECT_COPY_SAME_BUCKET,
        COMPAT_OBJECT_PUT_GET_DELETE, COMPAT_VERSIONING_HEAD_REMOVAL,
        PUBLIC_ACCESS_BLOCK_ROUND_TRIP,
    },
    fixture::{
        cleanup::cleanup_registered_resources, naming::ProtocolResourceNamer,
        registry::ResourceRegistry,
    },
    ports::{
        ExclusiveBucketOwnership, ProtocolAdminCleanupPort, ProtocolAdminError,
        ProtocolBucketConfigPort, ProtocolBucketPort, ProtocolCompletedPart,
        ProtocolListObjectsResult, ProtocolListingPort, ProtocolMultipartPort, ProtocolObjectPort,
        ProtocolObjectVersion, ProtocolPublicAccessBlock, ProtocolS3CleanupPort, ProtocolS3Error,
        ProtocolVersioningPort,
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
    fail_bucket_creation: bool,
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
impl ProtocolAdminCleanupPort for UnusedAdmin {
    async fn users_with_prefix(
        &self,
        _prefix: &str,
    ) -> std::result::Result<Vec<String>, ProtocolAdminError> {
        unreachable!()
    }

    async fn remove_user(&self, _access_key: &str) -> std::result::Result<(), ProtocolAdminError> {
        unreachable!()
    }

    async fn groups_with_prefix(&self, _prefix: &str) -> Result<Vec<String>, ProtocolAdminError> {
        unreachable!()
    }
    async fn group_contains_member(
        &self,
        _group: &str,
        _member: &str,
    ) -> Result<bool, ProtocolAdminError> {
        unreachable!()
    }
    async fn update_group_members(
        &self,
        _group: &str,
        _members: &[String],
        _remove: bool,
    ) -> Result<(), ProtocolAdminError> {
        unreachable!()
    }
    async fn remove_group(&self, _group: &str) -> Result<(), ProtocolAdminError> {
        unreachable!()
    }
    async fn policies_with_prefix(&self, _prefix: &str) -> Result<Vec<String>, ProtocolAdminError> {
        unreachable!()
    }
    async fn remove_policy(&self, _name: &str) -> Result<(), ProtocolAdminError> {
        unreachable!()
    }
    async fn detach_policy(
        &self,
        _policy: &str,
        _principal: &str,
        _is_group: bool,
    ) -> Result<(), ProtocolAdminError> {
        unreachable!()
    }
    async fn policy_attached(
        &self,
        _policy: &str,
        _principal: &str,
        _is_group: bool,
    ) -> Result<bool, ProtocolAdminError> {
        unreachable!()
    }
    async fn revoke_sts_sessions_for_provider(
        &self,
        _parent_access_key: &str,
        _provider: &str,
    ) -> Result<(), ProtocolAdminError> {
        unreachable!()
    }
    async fn sts_sessions_with_parent_for_provider(
        &self,
        _parent_access_key: &str,
        _provider: &str,
    ) -> Result<Vec<String>, ProtocolAdminError> {
        unreachable!()
    }
}

impl FakeS3 {
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
        let mut state = self.0.lock().expect("state");
        if state.fail_bucket_creation {
            return Err(ProtocolS3Error {
                code: "InternalError".to_string(),
                status: Some(500),
                request_id: Some("fake".to_string()),
            });
        }
        state.buckets.insert(bucket.to_string());
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

#[async_trait]
impl ProtocolBucketPort for FakeS3 {
    async fn list_buckets_with_prefix(&self, prefix: &str) -> Result<Vec<String>, ProtocolS3Error> {
        FakeS3::list_buckets_with_prefix(self, prefix).await
    }
    async fn create_bucket(&self, bucket: &str) -> Result<(), ProtocolS3Error> {
        FakeS3::create_bucket(self, bucket).await
    }
    async fn delete_bucket(&self, bucket: &str) -> Result<(), ProtocolS3Error> {
        FakeS3::delete_bucket(self, bucket).await
    }
    async fn head_bucket(&self, bucket: &str) -> Result<(), ProtocolS3Error> {
        FakeS3::head_bucket(self, bucket).await
    }
}

#[async_trait]
impl ProtocolListingPort for FakeS3 {
    async fn list_objects(&self, bucket: &str) -> Result<Vec<String>, ProtocolS3Error> {
        FakeS3::list_objects(self, bucket).await
    }
    async fn list_objects_v2_summary(
        &self,
        bucket: &str,
    ) -> Result<ProtocolListObjectsResult, ProtocolS3Error> {
        let keys = FakeS3::list_objects(self, bucket).await?;
        Ok(ProtocolListObjectsResult {
            key_count: keys.len(),
            keys,
        })
    }
}

#[async_trait]
impl ProtocolObjectPort for FakeS3 {
    async fn put_object(
        &self,
        bucket: &str,
        key: &str,
        body: &[u8],
    ) -> Result<(), ProtocolS3Error> {
        FakeS3::put_object(self, bucket, key, body).await
    }
    async fn get_object(&self, bucket: &str, key: &str) -> Result<Vec<u8>, ProtocolS3Error> {
        FakeS3::get_object(self, bucket, key).await
    }
    async fn delete_object(&self, bucket: &str, key: &str) -> Result<(), ProtocolS3Error> {
        FakeS3::delete_object(self, bucket, key).await
    }
    async fn copy_object(
        &self,
        bucket: &str,
        source_key: &str,
        destination_key: &str,
    ) -> Result<(), ProtocolS3Error> {
        FakeS3::copy_object(self, bucket, source_key, destination_key).await
    }
    async fn delete_objects(
        &self,
        bucket: &str,
        keys: &[String],
    ) -> Result<Vec<String>, ProtocolS3Error> {
        FakeS3::delete_objects(self, bucket, keys).await
    }
}

#[async_trait]
impl ProtocolMultipartPort for FakeS3 {
    async fn create_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<String, ProtocolS3Error> {
        FakeS3::create_multipart_upload(self, bucket, key).await
    }
    async fn upload_part(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        part_number: i32,
        body: &[u8],
    ) -> Result<String, ProtocolS3Error> {
        FakeS3::upload_part(self, bucket, key, upload_id, part_number, body).await
    }
    async fn complete_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        parts: &[ProtocolCompletedPart],
    ) -> Result<(), ProtocolS3Error> {
        FakeS3::complete_multipart_upload(self, bucket, key, upload_id, parts).await
    }
    async fn abort_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
    ) -> Result<(), ProtocolS3Error> {
        FakeS3::abort_multipart_upload(self, bucket, key, upload_id).await
    }
    async fn list_multipart_uploads(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Vec<String>, ProtocolS3Error> {
        FakeS3::list_multipart_uploads(self, bucket, key).await
    }
}

#[async_trait]
impl ProtocolVersioningPort for FakeS3 {
    async fn put_bucket_versioning(
        &self,
        bucket: &str,
        enabled: bool,
    ) -> Result<(), ProtocolS3Error> {
        FakeS3::put_bucket_versioning(self, bucket, enabled).await
    }
    async fn get_object_version(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> Result<Vec<u8>, ProtocolS3Error> {
        FakeS3::get_object_version(self, bucket, key, version_id).await
    }
    async fn list_object_versions(
        &self,
        bucket: &str,
    ) -> Result<Vec<ProtocolObjectVersion>, ProtocolS3Error> {
        FakeS3::list_object_versions(self, bucket).await
    }
    async fn delete_object_version(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> Result<(), ProtocolS3Error> {
        FakeS3::delete_object_version(self, bucket, key, version_id).await
    }
}

#[async_trait]
impl ProtocolBucketConfigPort for FakeS3 {
    async fn put_public_access_block(
        &self,
        bucket: &str,
        configuration: ProtocolPublicAccessBlock,
    ) -> Result<(), ProtocolS3Error> {
        FakeS3::put_public_access_block(self, bucket, configuration).await
    }
    async fn get_public_access_block(
        &self,
        bucket: &str,
    ) -> Result<ProtocolPublicAccessBlock, ProtocolS3Error> {
        FakeS3::get_public_access_block(self, bucket).await
    }
    async fn delete_public_access_block(&self, bucket: &str) -> Result<(), ProtocolS3Error> {
        FakeS3::delete_public_access_block(self, bucket).await
    }
}

#[async_trait]
impl ProtocolS3CleanupPort for FakeS3 {
    async fn cleanup_bucket_names(&self, prefix: &str) -> Result<Vec<String>, ProtocolS3Error> {
        FakeS3::list_buckets_with_prefix(self, prefix).await
    }
    async fn cleanup_exclusive_bucket(
        &self,
        ownership: ExclusiveBucketOwnership<'_>,
        include_versions: bool,
    ) -> Result<(), ProtocolS3Error> {
        let bucket = ownership.bucket();
        if include_versions {
            for version in FakeS3::list_object_versions(self, bucket).await? {
                FakeS3::delete_object_version(self, bucket, &version.key, &version.version_id)
                    .await?;
            }
        }
        for key in FakeS3::list_objects(self, bucket).await? {
            FakeS3::delete_object(self, bucket, &key).await?;
        }
        FakeS3::delete_bucket(self, bucket).await
    }
    async fn cleanup_object_prefix(
        &self,
        bucket: &str,
        prefix: &str,
        include_versions: bool,
    ) -> Result<(), ProtocolS3Error> {
        if include_versions {
            for version in FakeS3::list_object_versions(self, bucket)
                .await?
                .into_iter()
                .filter(|version| version.key.starts_with(prefix))
            {
                FakeS3::delete_object_version(self, bucket, &version.key, &version.version_id)
                    .await?;
            }
        }
        for key in FakeS3::list_objects(self, bucket)
            .await?
            .into_iter()
            .filter(|key| key.starts_with(prefix))
        {
            FakeS3::delete_object(self, bucket, &key).await?;
        }
        Ok(())
    }
    async fn cleanup_object_prefix_exists(
        &self,
        bucket: &str,
        prefix: &str,
        include_versions: bool,
    ) -> Result<bool, ProtocolS3Error> {
        if FakeS3::list_objects(self, bucket)
            .await?
            .iter()
            .any(|key| key.starts_with(prefix))
        {
            return Ok(true);
        }
        Ok(include_versions
            && FakeS3::list_object_versions(self, bucket)
                .await?
                .iter()
                .any(|version| version.key.starts_with(prefix)))
    }
    async fn cleanup_abort_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
    ) -> Result<(), ProtocolS3Error> {
        FakeS3::abort_multipart_upload(self, bucket, key, upload_id).await
    }
    async fn cleanup_multipart_upload_exists(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
    ) -> Result<bool, ProtocolS3Error> {
        Ok(FakeS3::list_multipart_uploads(self, bucket, key)
            .await?
            .iter()
            .any(|candidate| candidate == upload_id))
    }
    async fn cleanup_delete_bucket_policy(&self, _bucket: &str) -> Result<(), ProtocolS3Error> {
        Ok(())
    }
    async fn cleanup_bucket_policy_exists(&self, _bucket: &str) -> Result<bool, ProtocolS3Error> {
        Ok(false)
    }
    async fn cleanup_delete_public_access_block(
        &self,
        bucket: &str,
    ) -> Result<(), ProtocolS3Error> {
        FakeS3::delete_public_access_block(self, bucket).await
    }
    async fn cleanup_public_access_block_exists(
        &self,
        bucket: &str,
    ) -> Result<bool, ProtocolS3Error> {
        Ok(self
            .0
            .lock()
            .expect("state")
            .public_access_blocks
            .contains_key(bucket))
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

#[tokio::test]
async fn setup_failure_is_reported_and_registered_resource_is_cleaned() {
    let state = Arc::new(Mutex::new(State {
        fail_bucket_creation: true,
        ..State::default()
    }));
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
    let mut registry = ResourceRegistry::create(dir.path(), "run", fingerprint).expect("registry");
    let namer = ProtocolResourceNamer::new("s3c", "s3chaos", "run").expect("namer");

    let execution = run_compatibility_case(COMPAT_BUCKET_HEAD, &namer, &mut registry, &s3).await;
    assert_eq!(execution.report.status, ProtocolCaseStatus::Failed);
    assert_eq!(execution.report.failure_phase.as_deref(), Some("setup"));

    let cleanup = cleanup_registered_resources(&mut registry, &UnusedAdmin, &s3).await;
    assert!(cleanup.succeeded);
    assert!(state.lock().expect("state").buckets.is_empty());
}
