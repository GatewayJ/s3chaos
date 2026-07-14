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

use std::fmt;
use std::time::Duration;

use crate::protocol::{
    fixture::registry::{ResourceHandle, ResourceKind, ResourceRegistry, ResourceState},
    ports::{ProtocolAdminError, ProtocolAdminPort, ProtocolS3Error, ProtocolS3Port},
    reporting::{ProtocolCleanupAttempt, ProtocolCleanupReport},
};

pub(crate) async fn cleanup_registered_resources(
    registry: &mut ResourceRegistry,
    admin: &impl ProtocolAdminPort,
    s3: &impl ProtocolS3Port,
) -> ProtocolCleanupReport {
    let mut resources = match registry.cleanup_order() {
        Ok(resources) => resources,
        Err(error) => {
            let leftovers = registry
                .pending_cleanup()
                .map(|resource| resource.id.clone())
                .collect();
            return ProtocolCleanupReport {
                api_version: registry.api_version.clone(),
                kind: "ProtocolCleanupReport".to_string(),
                attempts: vec![ProtocolCleanupAttempt {
                    resource_id: "registry".to_string(),
                    resource_kind: "registry".to_string(),
                    resource_name: registry.path().display().to_string(),
                    retry_count: 0,
                    succeeded: false,
                    error: Some(error.to_string()),
                }],
                leftovers,
                succeeded: false,
            };
        }
    };
    for resource in &mut resources {
        if resource.kind == ResourceKind::StsSession && resource.principal.is_none() {
            resource.principal = resource.depends_on.iter().find_map(|dependency| {
                registry
                    .resources
                    .iter()
                    .find(|candidate| {
                        candidate.id == *dependency && candidate.kind == ResourceKind::IamUser
                    })
                    .map(|parent| parent.name.clone())
            });
        }
    }
    let mut attempts = Vec::new();
    let versioned_cleanup = registry.versioned_cleanup;

    for resource in resources {
        let start_result = if resource.state == ResourceState::CleanupAttempted {
            Ok(())
        } else {
            registry.transition(&resource.id, ResourceState::CleanupAttempted, None)
        };
        let cleanup_result =
            cleanup_resource_with_retry(&resource, admin, s3, versioned_cleanup).await;
        let state = if cleanup_result.is_ok() {
            ResourceState::Cleaned
        } else {
            ResourceState::Failed
        };
        let cleanup_error = cleanup_result
            .as_ref()
            .err()
            .map(|failure| failure.error.to_string());
        let finish_result = if start_result.is_ok() {
            registry.transition(&resource.id, state, cleanup_error.clone())
        } else {
            Ok(())
        };
        let errors = [
            start_result
                .err()
                .map(|error| format!("record cleanup start: {error}")),
            cleanup_error,
            finish_result
                .err()
                .map(|error| format!("record cleanup result: {error}")),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        let succeeded = errors.is_empty();
        attempts.push(ProtocolCleanupAttempt {
            resource_id: resource.id,
            resource_kind: resource.kind.as_str().to_string(),
            resource_name: resource.name,
            retry_count: cleanup_result
                .as_ref()
                .map(|success| success.retry_count)
                .unwrap_or_else(|failure| failure.retry_count),
            succeeded,
            error: (!errors.is_empty()).then(|| errors.join("; ")),
        });
    }

    let leftovers = registry
        .pending_cleanup()
        .map(|resource| resource.id.clone())
        .collect::<Vec<_>>();
    ProtocolCleanupReport {
        api_version: registry.api_version.clone(),
        kind: "ProtocolCleanupReport".to_string(),
        attempts,
        succeeded: leftovers.is_empty(),
        leftovers,
    }
}

const CLEANUP_MUTATION_MAX_ATTEMPTS: usize = 4;
const CLEANUP_VERIFY_MAX_ATTEMPTS: usize = 8;
#[cfg(not(test))]
const CLEANUP_RETRY_BASE: Duration = Duration::from_millis(100);
#[cfg(test)]
const CLEANUP_RETRY_BASE: Duration = Duration::from_millis(1);

struct CleanupSuccess {
    retry_count: usize,
}

struct CleanupFailure {
    retry_count: usize,
    error: CleanupError,
}

async fn cleanup_resource_with_retry(
    resource: &ResourceHandle,
    admin: &impl ProtocolAdminPort,
    s3: &impl ProtocolS3Port,
    versioned_cleanup: bool,
) -> std::result::Result<CleanupSuccess, CleanupFailure> {
    let mut retry_count = 0;
    let mut mutation_attempt = 0;
    loop {
        mutation_attempt += 1;
        match cleanup_resource(resource, admin, s3, versioned_cleanup).await {
            Ok(()) => break,
            Err(error) if error.is_not_found_for(resource.kind) => break,
            Err(error)
                if error.is_transient() && mutation_attempt < CLEANUP_MUTATION_MAX_ATTEMPTS =>
            {
                let multiplier = 1u32 << (mutation_attempt - 1);
                tokio::time::sleep(CLEANUP_RETRY_BASE * multiplier).await;
                retry_count += 1;
            }
            Err(error) => {
                return Err(CleanupFailure { retry_count, error });
            }
        }
    }

    let mut verify_attempt = 0;
    loop {
        verify_attempt += 1;
        match verify_resource_absent(resource, admin, s3, versioned_cleanup).await {
            Ok(()) => return Ok(CleanupSuccess { retry_count }),
            Err(error) if error.is_transient() && verify_attempt < CLEANUP_VERIFY_MAX_ATTEMPTS => {
                let multiplier = 1u32 << (verify_attempt - 1);
                tokio::time::sleep(CLEANUP_RETRY_BASE * multiplier).await;
                retry_count += 1;
            }
            Err(error) => return Err(CleanupFailure { retry_count, error }),
        }
    }
}

async fn verify_resource_absent(
    resource: &ResourceHandle,
    admin: &impl ProtocolAdminPort,
    s3: &impl ProtocolS3Port,
    versioned_cleanup: bool,
) -> std::result::Result<(), CleanupError> {
    match resource.kind {
        ResourceKind::Bucket => verify_exact_absence(
            resource,
            s3.list_buckets_with_prefix(&resource.name)
                .await
                .map_err(CleanupError::S3)?,
        ),
        ResourceKind::BucketPolicy => match s3.get_bucket_policy(&resource.name).await {
            Err(error) if matches!(error.code.as_str(), "NoSuchBucketPolicy" | "NoSuchBucket") => {
                Ok(())
            }
            Err(error) => Err(CleanupError::S3(error)),
            Ok(_) => Err(CleanupError::NotConverged(format!(
                "bucket policy {} is still visible after deletion",
                resource.name
            ))),
        },
        ResourceKind::ObjectPrefix => {
            let bucket = resource.bucket.as_deref().ok_or_else(|| {
                CleanupError::Contract("object prefix resource omitted bucket".to_string())
            })?;
            let prefix = resource.key_prefix.as_deref().ok_or_else(|| {
                CleanupError::Contract("object prefix resource omitted key prefix".to_string())
            })?;
            let current = s3.list_objects(bucket).await.map_err(CleanupError::S3)?;
            let versions = if versioned_cleanup {
                s3.list_object_versions(bucket)
                    .await
                    .map_err(CleanupError::S3)?
            } else {
                Vec::new()
            };
            if current.iter().any(|key| key.starts_with(prefix))
                || versions
                    .iter()
                    .any(|version| version.key.starts_with(prefix))
            {
                Err(CleanupError::NotConverged(format!(
                    "object prefix {bucket}/{prefix} is still visible after cleanup"
                )))
            } else {
                Ok(())
            }
        }
        ResourceKind::IamUser => {
            verify_admin_absence(resource, admin.users_with_prefix(&resource.name).await)
        }
        ResourceKind::IamPolicy => {
            verify_admin_absence(resource, admin.policies_with_prefix(&resource.name).await)
        }
        ResourceKind::IamGroup => {
            verify_admin_absence(resource, admin.groups_with_prefix(&resource.name).await)
        }
        ResourceKind::IamPolicyAttachment => {
            let policy = resource.policy.as_deref().ok_or_else(|| {
                CleanupError::Contract("IAM policy attachment omitted policy".to_string())
            })?;
            let principal = resource.principal.as_deref().ok_or_else(|| {
                CleanupError::Contract("IAM policy attachment omitted principal".to_string())
            })?;
            let is_group = resource.is_group.ok_or_else(|| {
                CleanupError::Contract("IAM policy attachment omitted principal kind".to_string())
            })?;
            match admin.policy_attached(policy, principal, is_group).await {
                Ok(false) => Ok(()),
                Ok(true) => Err(CleanupError::NotConverged(format!(
                    "IAM policy {policy} is still attached to {principal}"
                ))),
                Err(error) => Err(CleanupError::Admin(error)),
            }
        }
        ResourceKind::IamGroupMembership => {
            let group = resource.group.as_deref().ok_or_else(|| {
                CleanupError::Contract("IAM group membership omitted group".to_string())
            })?;
            let member = resource.member.as_deref().ok_or_else(|| {
                CleanupError::Contract("IAM group membership omitted member".to_string())
            })?;
            match admin.group_contains_member(group, member).await {
                Ok(false) => Ok(()),
                Ok(true) => Err(CleanupError::NotConverged(format!(
                    "IAM user {member} is still a member of group {group}"
                ))),
                Err(error) => Err(CleanupError::Admin(error)),
            }
        }
        ResourceKind::StsSession => {
            let parent = resource.principal.as_deref().ok_or_else(|| {
                CleanupError::Contract("STS session omitted parent access key".to_string())
            })?;
            match admin.sts_sessions_with_parent(parent).await {
                Ok(sessions) if sessions.is_empty() => Ok(()),
                Ok(sessions) => Err(CleanupError::NotConverged(format!(
                    "{} STS session(s) remain for parent {parent}",
                    sessions.len()
                ))),
                Err(error) => Err(CleanupError::Admin(error)),
            }
        }
    }
}

fn verify_admin_absence(
    resource: &ResourceHandle,
    result: std::result::Result<Vec<String>, ProtocolAdminError>,
) -> std::result::Result<(), CleanupError> {
    match result {
        Ok(names) => verify_exact_absence(resource, names),
        Err(error) => Err(CleanupError::Admin(error)),
    }
}

fn verify_exact_absence(
    resource: &ResourceHandle,
    names: Vec<String>,
) -> std::result::Result<(), CleanupError> {
    if names.iter().any(|name| name == &resource.name) {
        Err(CleanupError::NotConverged(format!(
            "{} {} is still visible after deletion",
            resource.kind.as_str(),
            resource.name
        )))
    } else {
        Ok(())
    }
}

async fn cleanup_resource(
    resource: &ResourceHandle,
    admin: &impl ProtocolAdminPort,
    s3: &impl ProtocolS3Port,
    versioned_cleanup: bool,
) -> std::result::Result<(), CleanupError> {
    match resource.kind {
        ResourceKind::BucketPolicy => s3
            .delete_bucket_policy(&resource.name)
            .await
            .map_err(CleanupError::S3),
        ResourceKind::ObjectPrefix => {
            let bucket = resource.bucket.as_deref().ok_or_else(|| {
                CleanupError::Contract("object prefix resource omitted bucket".to_string())
            })?;
            s3.empty_bucket(bucket, versioned_cleanup)
                .await
                .map_err(CleanupError::S3)
        }
        ResourceKind::Bucket => {
            s3.empty_bucket(&resource.name, versioned_cleanup)
                .await
                .map_err(CleanupError::S3)?;
            s3.delete_bucket(&resource.name)
                .await
                .map_err(CleanupError::S3)
        }
        ResourceKind::IamPolicyAttachment => {
            let policy = resource.policy.as_deref().ok_or_else(|| {
                CleanupError::Contract("IAM policy attachment omitted policy".to_string())
            })?;
            let principal = resource.principal.as_deref().ok_or_else(|| {
                CleanupError::Contract("IAM policy attachment omitted principal".to_string())
            })?;
            let is_group = resource.is_group.ok_or_else(|| {
                CleanupError::Contract("IAM policy attachment omitted principal kind".to_string())
            })?;
            admin
                .detach_policy(policy, principal, is_group)
                .await
                .map_err(CleanupError::Admin)
        }
        ResourceKind::IamGroupMembership => {
            let group = resource.group.as_deref().ok_or_else(|| {
                CleanupError::Contract("IAM group membership omitted group".to_string())
            })?;
            let member = resource.member.as_deref().ok_or_else(|| {
                CleanupError::Contract("IAM group membership omitted member".to_string())
            })?;
            admin
                .update_group_members(group, &[member.to_string()], true)
                .await
                .map_err(CleanupError::Admin)
        }
        ResourceKind::IamPolicy => admin
            .remove_policy(&resource.name)
            .await
            .map_err(CleanupError::Admin),
        ResourceKind::IamGroup => admin
            .remove_group(&resource.name)
            .await
            .map_err(CleanupError::Admin),
        ResourceKind::IamUser => admin
            .remove_user(&resource.name)
            .await
            .map_err(CleanupError::Admin),
        ResourceKind::StsSession => {
            let parent = resource.principal.as_deref().ok_or_else(|| {
                CleanupError::Contract("STS session omitted parent access key".to_string())
            })?;
            admin
                .revoke_sts_sessions(parent)
                .await
                .map_err(CleanupError::Admin)
        }
    }
}

enum CleanupError {
    S3(ProtocolS3Error),
    Admin(ProtocolAdminError),
    Contract(String),
    NotConverged(String),
}

impl CleanupError {
    fn is_not_found_for(&self, kind: ResourceKind) -> bool {
        match (kind, self) {
            (ResourceKind::BucketPolicy, Self::S3(error)) => {
                matches!(error.code.as_str(), "NoSuchBucketPolicy" | "NoSuchBucket")
            }
            (ResourceKind::Bucket, Self::S3(error)) => error.code == "NoSuchBucket",
            (ResourceKind::ObjectPrefix, Self::S3(error)) => {
                matches!(error.code.as_str(), "NoSuchBucket" | "NoSuchKey")
            }
            (ResourceKind::IamUser, Self::Admin(error)) => {
                matches!(error.code.as_str(), "NoSuchUser" | "NoSuchEntity")
            }
            (ResourceKind::IamPolicy, Self::Admin(error)) => {
                matches!(error.code.as_str(), "NoSuchPolicy" | "NoSuchEntity")
            }
            (ResourceKind::IamGroup, Self::Admin(error)) => {
                matches!(error.code.as_str(), "NoSuchGroup" | "NoSuchEntity")
            }
            (
                ResourceKind::IamPolicyAttachment | ResourceKind::IamGroupMembership,
                Self::Admin(error),
            ) => matches!(
                error.code.as_str(),
                "NoSuchUser" | "NoSuchGroup" | "NoSuchPolicy" | "NoSuchEntity"
            ),
            (ResourceKind::StsSession, Self::Admin(error)) => {
                matches!(error.code.as_str(), "NoSuchUser" | "NoSuchEntity")
            }
            _ => false,
        }
    }

    fn is_transient(&self) -> bool {
        match self {
            Self::S3(error) => error.is_transient(),
            Self::Admin(error) => error.is_transient(),
            Self::Contract(_) => false,
            Self::NotConverged(_) => true,
        }
    }
}

impl fmt::Display for CleanupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::S3(error) => write!(
                formatter,
                "S3 cleanup failed: code={} status={} request_id={}",
                error.code,
                error
                    .status
                    .map(|status| status.to_string())
                    .unwrap_or_else(|| "unknown".to_string()),
                error.request_id.as_deref().unwrap_or("unknown")
            ),
            Self::Admin(error) => error.fmt(formatter),
            Self::Contract(message) => formatter.write_str(message),
            Self::NotConverged(message) => formatter.write_str(message),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::cleanup_registered_resources;
    use crate::protocol::{
        credentials::ActorCredential,
        fixture::registry::{ResourceKind, ResourceRegistry, ResourceState},
        ports::{
            ProtocolAdminError, ProtocolAdminPort, ProtocolObjectVersion, ProtocolS3Error,
            ProtocolS3Port, ProtocolServerInfo,
        },
        suite_plan::TargetFingerprint,
    };
    use async_trait::async_trait;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    #[derive(Clone, Default)]
    struct FakeAdmin;

    #[derive(Clone, Default)]
    struct EventuallyConsistentAdmin {
        attachment_visibility: Arc<AtomicUsize>,
        membership_visibility: Arc<AtomicUsize>,
        session_visibility: Arc<AtomicUsize>,
    }

    #[derive(Clone, Default)]
    struct FakeS3 {
        calls: Arc<Mutex<Vec<String>>>,
        policy_failures: Arc<AtomicUsize>,
        policy_readback_error: Arc<Mutex<Option<ProtocolS3Error>>>,
        bucket_visibility: Arc<AtomicUsize>,
        version_list_calls: Arc<AtomicUsize>,
        versions: Arc<Mutex<Vec<ProtocolObjectVersion>>>,
        objects: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl ProtocolAdminPort for FakeAdmin {
        async fn server_info(&self) -> std::result::Result<ProtocolServerInfo, ProtocolAdminError> {
            Ok(ProtocolServerInfo {
                deployment_id: "deployment".to_string(),
                mode: None,
                region: None,
            })
        }

        async fn users_with_prefix(
            &self,
            _prefix: &str,
        ) -> std::result::Result<Vec<String>, ProtocolAdminError> {
            Ok(Vec::new())
        }

        async fn create_user(
            &self,
            _credential: &ActorCredential,
        ) -> std::result::Result<(), ProtocolAdminError> {
            Ok(())
        }

        async fn remove_user(
            &self,
            _access_key: &str,
        ) -> std::result::Result<(), ProtocolAdminError> {
            Ok(())
        }
    }

    #[async_trait]
    impl ProtocolAdminPort for EventuallyConsistentAdmin {
        async fn server_info(&self) -> std::result::Result<ProtocolServerInfo, ProtocolAdminError> {
            Ok(ProtocolServerInfo {
                deployment_id: "deployment".to_string(),
                mode: None,
                region: None,
            })
        }

        async fn users_with_prefix(
            &self,
            _prefix: &str,
        ) -> std::result::Result<Vec<String>, ProtocolAdminError> {
            Ok(Vec::new())
        }

        async fn create_user(
            &self,
            _credential: &ActorCredential,
        ) -> std::result::Result<(), ProtocolAdminError> {
            Ok(())
        }

        async fn remove_user(
            &self,
            _access_key: &str,
        ) -> std::result::Result<(), ProtocolAdminError> {
            Ok(())
        }

        async fn detach_policy(
            &self,
            _policy: &str,
            _principal: &str,
            _is_group: bool,
        ) -> std::result::Result<(), ProtocolAdminError> {
            Ok(())
        }

        async fn update_group_members(
            &self,
            _group: &str,
            _members: &[String],
            _remove: bool,
        ) -> std::result::Result<(), ProtocolAdminError> {
            Ok(())
        }

        async fn revoke_sts_sessions(
            &self,
            _parent_access_key: &str,
        ) -> std::result::Result<(), ProtocolAdminError> {
            Ok(())
        }

        async fn policy_attached(
            &self,
            _policy: &str,
            _principal: &str,
            _is_group: bool,
        ) -> std::result::Result<bool, ProtocolAdminError> {
            Ok(self
                .attachment_visibility
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok())
        }

        async fn group_contains_member(
            &self,
            _group: &str,
            _member: &str,
        ) -> std::result::Result<bool, ProtocolAdminError> {
            Ok(self
                .membership_visibility
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok())
        }

        async fn sts_sessions_with_parent(
            &self,
            _parent_access_key: &str,
        ) -> std::result::Result<Vec<String>, ProtocolAdminError> {
            if self
                .session_visibility
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok()
            {
                Ok(vec!["session".to_string()])
            } else {
                Ok(Vec::new())
            }
        }
    }

    #[async_trait]
    impl ProtocolS3Port for FakeS3 {
        async fn list_buckets_with_prefix(
            &self,
            prefix: &str,
        ) -> std::result::Result<Vec<String>, ProtocolS3Error> {
            if self
                .bucket_visibility
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok()
            {
                Ok(vec![prefix.to_string()])
            } else {
                Ok(Vec::new())
            }
        }

        async fn create_bucket(&self, _bucket: &str) -> std::result::Result<(), ProtocolS3Error> {
            Ok(())
        }

        async fn delete_bucket(&self, bucket: &str) -> std::result::Result<(), ProtocolS3Error> {
            self.calls
                .lock()
                .expect("calls")
                .push(format!("delete-bucket:{bucket}"));
            Ok(())
        }

        async fn put_bucket_policy(
            &self,
            _bucket: &str,
            _policy: &str,
        ) -> std::result::Result<(), ProtocolS3Error> {
            Ok(())
        }

        async fn get_bucket_policy(
            &self,
            _bucket: &str,
        ) -> std::result::Result<String, ProtocolS3Error> {
            if let Some(error) = self
                .policy_readback_error
                .lock()
                .expect("policy readback")
                .clone()
            {
                return Err(error);
            }
            Err(ProtocolS3Error {
                code: "NoSuchBucketPolicy".to_string(),
                status: Some(404),
                request_id: None,
            })
        }

        async fn delete_bucket_policy(
            &self,
            bucket: &str,
        ) -> std::result::Result<(), ProtocolS3Error> {
            self.calls
                .lock()
                .expect("calls")
                .push(format!("delete-policy:{bucket}"));
            if self
                .policy_failures
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok()
            {
                return Err(transient_error());
            }
            Ok(())
        }

        async fn list_objects(
            &self,
            _bucket: &str,
        ) -> std::result::Result<Vec<String>, ProtocolS3Error> {
            Ok(self.objects.lock().expect("objects").clone())
        }

        async fn put_object(
            &self,
            _bucket: &str,
            _key: &str,
            _body: &[u8],
        ) -> std::result::Result<(), ProtocolS3Error> {
            Ok(())
        }

        async fn get_object(
            &self,
            _bucket: &str,
            _key: &str,
        ) -> std::result::Result<Vec<u8>, ProtocolS3Error> {
            Ok(Vec::new())
        }

        async fn delete_object(
            &self,
            _bucket: &str,
            key: &str,
        ) -> std::result::Result<(), ProtocolS3Error> {
            self.calls
                .lock()
                .expect("calls")
                .push(format!("delete-object:{key}"));
            self.objects
                .lock()
                .expect("objects")
                .retain(|item| item != key);
            Ok(())
        }

        async fn list_object_versions(
            &self,
            _bucket: &str,
        ) -> std::result::Result<Vec<ProtocolObjectVersion>, ProtocolS3Error> {
            self.version_list_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.versions.lock().expect("versions").clone())
        }

        async fn delete_object_version(
            &self,
            _bucket: &str,
            key: &str,
            version_id: &str,
        ) -> std::result::Result<(), ProtocolS3Error> {
            self.calls
                .lock()
                .expect("calls")
                .push(format!("delete-version:{key}:{version_id}"));
            self.versions
                .lock()
                .expect("versions")
                .retain(|version| version.key != key || version.version_id != version_id);
            Ok(())
        }
    }

    fn transient_error() -> ProtocolS3Error {
        ProtocolS3Error {
            code: "ServiceUnavailable".to_string(),
            status: Some(503),
            request_id: Some("request".to_string()),
        }
    }

    fn fingerprint() -> TargetFingerprint {
        TargetFingerprint::new(
            "http://127.0.0.1:9000",
            "us-east-1",
            "deployment",
            None,
            None,
        )
        .expect("fingerprint")
    }

    #[tokio::test]
    async fn retries_only_transient_cleanup_failures() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut registry =
            ResourceRegistry::create(dir.path(), "run", fingerprint()).expect("registry");
        let policy = registry
            .plan(ResourceKind::BucketPolicy, "bucket", "case", Vec::new())
            .expect("policy");
        registry
            .transition(&policy.id, ResourceState::Creating, None)
            .expect("creating");
        registry
            .transition(&policy.id, ResourceState::Created, None)
            .expect("created");
        let s3 = FakeS3 {
            policy_failures: Arc::new(AtomicUsize::new(2)),
            ..FakeS3::default()
        };

        let report = cleanup_registered_resources(&mut registry, &FakeAdmin, &s3).await;
        assert!(report.succeeded);
        assert_eq!(report.attempts[0].retry_count, 2);
        assert_eq!(s3.calls.lock().expect("calls").len(), 3);
    }

    #[tokio::test]
    async fn empties_versions_delete_markers_and_current_objects_before_bucket() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut registry =
            ResourceRegistry::create(dir.path(), "run", fingerprint()).expect("registry");
        registry
            .set_versioned_cleanup(true)
            .expect("enable versioned cleanup");
        let bucket = registry
            .plan(ResourceKind::Bucket, "bucket", "case", Vec::new())
            .expect("bucket");
        registry
            .transition(&bucket.id, ResourceState::Creating, None)
            .expect("creating");
        registry
            .transition(&bucket.id, ResourceState::Created, None)
            .expect("created");
        let s3 = FakeS3 {
            versions: Arc::new(Mutex::new(vec![
                ProtocolObjectVersion {
                    key: "key".to_string(),
                    version_id: "v1".to_string(),
                    delete_marker: false,
                },
                ProtocolObjectVersion {
                    key: "key".to_string(),
                    version_id: "marker".to_string(),
                    delete_marker: true,
                },
            ])),
            objects: Arc::new(Mutex::new(vec!["current".to_string()])),
            ..FakeS3::default()
        };

        let report = cleanup_registered_resources(&mut registry, &FakeAdmin, &s3).await;
        assert!(report.succeeded);
        assert_eq!(
            *s3.calls.lock().expect("calls"),
            vec![
                "delete-version:key:v1",
                "delete-version:key:marker",
                "delete-object:current",
                "delete-bucket:bucket",
            ]
        );
    }

    #[tokio::test]
    async fn retries_when_a_deleted_resource_remains_visible() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut registry =
            ResourceRegistry::create(dir.path(), "run", fingerprint()).expect("registry");
        let bucket = registry
            .plan(ResourceKind::Bucket, "bucket", "case", Vec::new())
            .expect("bucket");
        registry
            .transition(&bucket.id, ResourceState::Creating, None)
            .expect("creating");
        registry
            .transition(&bucket.id, ResourceState::Created, None)
            .expect("created");
        let s3 = FakeS3 {
            bucket_visibility: Arc::new(AtomicUsize::new(2)),
            ..FakeS3::default()
        };

        let report = cleanup_registered_resources(&mut registry, &FakeAdmin, &s3).await;

        assert!(report.succeeded);
        assert_eq!(report.attempts[0].retry_count, 2);
        assert_eq!(
            s3.calls
                .lock()
                .expect("calls")
                .iter()
                .filter(|call| call.as_str() == "delete-bucket:bucket")
                .count(),
            1
        );
        assert_eq!(s3.version_list_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn unknown_http_404_does_not_prove_bucket_policy_absence() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut registry =
            ResourceRegistry::create(dir.path(), "run", fingerprint()).expect("registry");
        let policy = registry
            .plan(ResourceKind::BucketPolicy, "bucket", "case", Vec::new())
            .expect("policy");
        registry
            .transition(&policy.id, ResourceState::Creating, None)
            .expect("creating");
        registry
            .transition(&policy.id, ResourceState::Created, None)
            .expect("created");
        let s3 = FakeS3 {
            policy_readback_error: Arc::new(Mutex::new(Some(ProtocolS3Error {
                code: "RouteNotFound".to_string(),
                status: Some(404),
                request_id: None,
            }))),
            ..FakeS3::default()
        };

        let report = cleanup_registered_resources(&mut registry, &FakeAdmin, &s3).await;

        assert!(!report.succeeded);
        assert_eq!(report.leftovers, vec![policy.id]);
        assert!(
            report.attempts[0]
                .error
                .as_deref()
                .is_some_and(|error| error.contains("RouteNotFound"))
        );
    }

    #[tokio::test]
    async fn relationship_cleanup_waits_for_live_readback_convergence() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut registry =
            ResourceRegistry::create(dir.path(), "run", fingerprint()).expect("registry");
        let attachment = registry
            .plan_policy_attachment("policy", "user", false, "case", Vec::new())
            .expect("attachment");
        let membership = registry
            .plan_group_membership("group", "user", "case", Vec::new())
            .expect("membership");
        let session = registry
            .plan_sts_session("user", "case", Vec::new())
            .expect("session");
        for handle in [&attachment, &membership, &session] {
            registry
                .transition(&handle.id, ResourceState::Creating, None)
                .expect("creating");
            registry
                .transition(&handle.id, ResourceState::Created, None)
                .expect("created");
        }
        let admin = EventuallyConsistentAdmin {
            attachment_visibility: Arc::new(AtomicUsize::new(2)),
            membership_visibility: Arc::new(AtomicUsize::new(2)),
            session_visibility: Arc::new(AtomicUsize::new(2)),
        };

        let report = cleanup_registered_resources(&mut registry, &admin, &FakeS3::default()).await;

        assert!(report.succeeded, "{report:?}");
        assert!(
            report
                .attempts
                .iter()
                .all(|attempt| attempt.retry_count == 2)
        );
        assert!(registry.pending_cleanup().next().is_none());
    }
}
