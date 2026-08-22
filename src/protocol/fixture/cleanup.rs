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
    ports::{
        ExclusiveBucketOwnership, ProtocolAdminCleanupPort, ProtocolAdminError,
        ProtocolExternalIdentityError, ProtocolExternalIdentityPort, ProtocolS3CleanupPort,
        ProtocolS3Error,
    },
    reporting::{ProtocolCleanupAttempt, ProtocolCleanupReport},
};

pub(crate) async fn cleanup_registered_resources(
    registry: &mut ResourceRegistry,
    admin: &impl ProtocolAdminCleanupPort,
    s3: &impl ProtocolS3CleanupPort,
) -> ProtocolCleanupReport {
    cleanup_registered_resources_with_external(registry, admin, s3, None).await
}

pub(crate) async fn cleanup_registered_resources_with_external(
    registry: &mut ResourceRegistry,
    admin: &impl ProtocolAdminCleanupPort,
    s3: &impl ProtocolS3CleanupPort,
    external_identity: Option<&dyn ProtocolExternalIdentityPort>,
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
            cleanup_resource_with_retry(&resource, admin, s3, external_identity, versioned_cleanup)
                .await;
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
    admin: &impl ProtocolAdminCleanupPort,
    s3: &impl ProtocolS3CleanupPort,
    external_identity: Option<&dyn ProtocolExternalIdentityPort>,
    versioned_cleanup: bool,
) -> std::result::Result<CleanupSuccess, CleanupFailure> {
    let mut retry_count = 0;
    let mut mutation_attempt = 0;
    loop {
        mutation_attempt += 1;
        match cleanup_resource(resource, admin, s3, external_identity, versioned_cleanup).await {
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
        match verify_resource_absent(resource, admin, s3, external_identity, versioned_cleanup)
            .await
        {
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
    admin: &impl ProtocolAdminCleanupPort,
    s3: &impl ProtocolS3CleanupPort,
    external_identity: Option<&dyn ProtocolExternalIdentityPort>,
    versioned_cleanup: bool,
) -> std::result::Result<(), CleanupError> {
    match resource.kind {
        ResourceKind::Bucket => verify_exact_absence(
            resource,
            s3.cleanup_bucket_names(&resource.name)
                .await
                .map_err(CleanupError::S3)?,
        ),
        ResourceKind::BucketPolicy => match s3
            .cleanup_bucket_policy_exists(&resource.name)
            .await
            .map_err(CleanupError::S3)?
        {
            false => Ok(()),
            true => Err(CleanupError::NotConverged(format!(
                "bucket policy {} is still visible after deletion",
                resource.name
            ))),
        },
        ResourceKind::PublicAccessBlock => match s3
            .cleanup_public_access_block_exists(&resource.name)
            .await
            .map_err(CleanupError::S3)?
        {
            false => Ok(()),
            true => Err(CleanupError::NotConverged(format!(
                "public access block {} is still visible after deletion",
                resource.name
            ))),
        },
        ResourceKind::ExternalIdentitySubject => {
            let provider = external_identity.ok_or_else(|| {
                CleanupError::Contract("external identity cleanup port is unavailable".to_string())
            })?;
            verify_external_identity(resource, provider)?;
            match provider.subject_exists(&resource.name).await {
                Ok(false) => Ok(()),
                Ok(true) => Err(CleanupError::NotConverged(format!(
                    "external identity subject {} is still visible after deletion",
                    resource.name
                ))),
                Err(error) => Err(CleanupError::ExternalIdentity(error)),
            }
        }
        ResourceKind::MultipartUpload => {
            let bucket = resource.bucket.as_deref().ok_or_else(|| {
                CleanupError::Contract("multipart upload resource omitted bucket".to_string())
            })?;
            let key = resource.key_prefix.as_deref().ok_or_else(|| {
                CleanupError::Contract("multipart upload resource omitted object key".to_string())
            })?;
            let upload_id = multipart_upload_id(resource)?;
            let exists = s3
                .cleanup_multipart_upload_exists(bucket, key, upload_id)
                .await
                .map_err(CleanupError::S3)?;
            if !exists {
                Ok(())
            } else {
                Err(CleanupError::NotConverged(format!(
                    "multipart upload {upload_id} remains for {bucket}/{key}",
                )))
            }
        }
        ResourceKind::ObjectPrefix => {
            let bucket = resource.bucket.as_deref().ok_or_else(|| {
                CleanupError::Contract("object prefix resource omitted bucket".to_string())
            })?;
            let prefix = resource.key_prefix.as_deref().ok_or_else(|| {
                CleanupError::Contract("object prefix resource omitted key prefix".to_string())
            })?;
            if s3
                .cleanup_object_prefix_exists(bucket, prefix, versioned_cleanup)
                .await
                .map_err(CleanupError::S3)?
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
            let provider = resource.identity_provider.as_deref().unwrap_or("builtin");
            match admin
                .sts_sessions_with_parent_for_provider(parent, provider)
                .await
            {
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
    admin: &impl ProtocolAdminCleanupPort,
    s3: &impl ProtocolS3CleanupPort,
    external_identity: Option<&dyn ProtocolExternalIdentityPort>,
    versioned_cleanup: bool,
) -> std::result::Result<(), CleanupError> {
    match resource.kind {
        ResourceKind::BucketPolicy => s3
            .cleanup_delete_bucket_policy(&resource.name)
            .await
            .map_err(CleanupError::S3),
        ResourceKind::PublicAccessBlock => s3
            .cleanup_delete_public_access_block(&resource.name)
            .await
            .map_err(CleanupError::S3),
        ResourceKind::MultipartUpload => {
            let bucket = resource.bucket.as_deref().ok_or_else(|| {
                CleanupError::Contract("multipart upload resource omitted bucket".to_string())
            })?;
            let key = resource.key_prefix.as_deref().ok_or_else(|| {
                CleanupError::Contract("multipart upload resource omitted object key".to_string())
            })?;
            let upload_id = multipart_upload_id(resource)?;
            s3.cleanup_abort_multipart_upload(bucket, key, upload_id)
                .await
                .map_err(CleanupError::S3)
        }
        ResourceKind::ExternalIdentitySubject => {
            let provider = external_identity.ok_or_else(|| {
                CleanupError::Contract("external identity cleanup port is unavailable".to_string())
            })?;
            verify_external_identity(resource, provider)?;
            provider
                .delete_subject(&resource.name)
                .await
                .map_err(CleanupError::ExternalIdentity)
        }
        ResourceKind::ObjectPrefix => {
            let bucket = resource.bucket.as_deref().ok_or_else(|| {
                CleanupError::Contract("object prefix resource omitted bucket".to_string())
            })?;
            let prefix = resource.key_prefix.as_deref().ok_or_else(|| {
                CleanupError::Contract("object prefix resource omitted key prefix".to_string())
            })?;
            s3.cleanup_object_prefix(bucket, prefix, versioned_cleanup)
                .await
                .map_err(CleanupError::S3)
        }
        ResourceKind::Bucket => s3
            .cleanup_exclusive_bucket(
                ExclusiveBucketOwnership::registry_owned(&resource.name),
                versioned_cleanup,
            )
            .await
            .map_err(CleanupError::S3),
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
            let provider = resource.identity_provider.as_deref().unwrap_or("builtin");
            admin
                .revoke_sts_sessions_for_provider(parent, provider)
                .await
                .map_err(CleanupError::Admin)
        }
    }
}

fn multipart_upload_id(resource: &ResourceHandle) -> std::result::Result<&str, CleanupError> {
    resource.upload_id.as_deref().ok_or_else(|| {
        CleanupError::Contract(format!(
            "multipart upload {} omitted uploadId; refusing unscoped cleanup",
            resource.name
        ))
    })
}

fn verify_external_identity(
    resource: &ResourceHandle,
    provider: &dyn ProtocolExternalIdentityPort,
) -> std::result::Result<(), CleanupError> {
    let expected = resource.external_identity.as_ref().ok_or_else(|| {
        CleanupError::Contract("external identity subject omitted provider coordinates".to_string())
    })?;
    let actual = provider.coordinates();
    if expected != &actual {
        return Err(CleanupError::Contract(format!(
            "external identity coordinates mismatch: registry={expected:?} adapter={actual:?}"
        )));
    }
    Ok(())
}

enum CleanupError {
    S3(ProtocolS3Error),
    Admin(ProtocolAdminError),
    ExternalIdentity(ProtocolExternalIdentityError),
    Contract(String),
    NotConverged(String),
}

impl CleanupError {
    fn is_not_found_for(&self, kind: ResourceKind) -> bool {
        match (kind, self) {
            (ResourceKind::BucketPolicy, Self::S3(error)) => {
                matches!(error.code.as_str(), "NoSuchBucketPolicy" | "NoSuchBucket")
            }
            (ResourceKind::PublicAccessBlock, Self::S3(error)) => matches!(
                error.code.as_str(),
                "NoSuchPublicAccessBlockConfiguration" | "NoSuchBucket"
            ),
            (ResourceKind::ExternalIdentitySubject, Self::ExternalIdentity(error)) => {
                error.code == "NoSuchExternalIdentitySubject"
            }
            (ResourceKind::Bucket, Self::S3(error)) => error.code == "NoSuchBucket",
            (ResourceKind::ObjectPrefix, Self::S3(error)) => {
                matches!(error.code.as_str(), "NoSuchBucket" | "NoSuchKey")
            }
            (ResourceKind::MultipartUpload, Self::S3(error)) => {
                matches!(error.code.as_str(), "NoSuchBucket" | "NoSuchUpload")
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
            Self::ExternalIdentity(error) => error.is_transient(),
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
            Self::ExternalIdentity(error) => error.fmt(formatter),
            Self::Contract(message) => formatter.write_str(message),
            Self::NotConverged(message) => formatter.write_str(message),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{cleanup_registered_resources, cleanup_registered_resources_with_external};
    use crate::protocol::{
        credentials::{ExternalIdentityCredential, WebIdentityToken},
        fixture::registry::{ResourceKind, ResourceRegistry, ResourceState},
        ports::{
            ExclusiveBucketOwnership, ProtocolAdminCleanupPort, ProtocolAdminError,
            ProtocolExternalIdentityCoordinates, ProtocolExternalIdentityError,
            ProtocolExternalIdentityPort, ProtocolExternalIdentityProviderInfo,
            ProtocolObjectVersion, ProtocolS3CleanupPort, ProtocolS3Error,
        },
        suite_plan::TargetFingerprint,
    };
    use async_trait::async_trait;
    use std::{
        collections::{BTreeMap, BTreeSet},
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
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
        multipart_uploads: Arc<Mutex<Vec<(String, String, String)>>>,
    }

    #[derive(Clone)]
    struct FakeExternalIdentity {
        subjects: Arc<Mutex<BTreeSet<String>>>,
        coordinates: ProtocolExternalIdentityCoordinates,
    }

    #[async_trait]
    impl ProtocolExternalIdentityPort for FakeExternalIdentity {
        fn coordinates(&self) -> ProtocolExternalIdentityCoordinates {
            self.coordinates.clone()
        }

        fn policy_claim(&self) -> &str {
            "policy"
        }

        async fn provider_info(
            &self,
        ) -> std::result::Result<ProtocolExternalIdentityProviderInfo, ProtocolExternalIdentityError>
        {
            Err(ProtocolExternalIdentityError::protocol("unused"))
        }

        async fn create_subject(
            &self,
            _credential: &ExternalIdentityCredential,
            _claims: &BTreeMap<String, Vec<String>>,
        ) -> std::result::Result<(), ProtocolExternalIdentityError> {
            Err(ProtocolExternalIdentityError::protocol("unused"))
        }

        async fn issue_id_token(
            &self,
            _credential: &ExternalIdentityCredential,
        ) -> std::result::Result<WebIdentityToken, ProtocolExternalIdentityError> {
            Err(ProtocolExternalIdentityError::protocol("unused"))
        }

        async fn subject_exists(
            &self,
            username: &str,
        ) -> std::result::Result<bool, ProtocolExternalIdentityError> {
            Ok(self.subjects.lock().expect("subjects").contains(username))
        }

        async fn delete_subject(
            &self,
            username: &str,
        ) -> std::result::Result<(), ProtocolExternalIdentityError> {
            self.subjects.lock().expect("subjects").remove(username);
            Ok(())
        }
    }

    #[async_trait]
    impl ProtocolAdminCleanupPort for FakeAdmin {
        async fn users_with_prefix(
            &self,
            _prefix: &str,
        ) -> std::result::Result<Vec<String>, ProtocolAdminError> {
            Ok(Vec::new())
        }

        async fn remove_user(
            &self,
            _access_key: &str,
        ) -> std::result::Result<(), ProtocolAdminError> {
            Ok(())
        }

        async fn groups_with_prefix(
            &self,
            _prefix: &str,
        ) -> std::result::Result<Vec<String>, ProtocolAdminError> {
            Ok(Vec::new())
        }

        async fn group_contains_member(
            &self,
            _group: &str,
            _member: &str,
        ) -> std::result::Result<bool, ProtocolAdminError> {
            Ok(false)
        }

        async fn update_group_members(
            &self,
            _group: &str,
            _members: &[String],
            _remove: bool,
        ) -> std::result::Result<(), ProtocolAdminError> {
            Ok(())
        }

        async fn remove_group(&self, _group: &str) -> std::result::Result<(), ProtocolAdminError> {
            Ok(())
        }

        async fn policies_with_prefix(
            &self,
            _prefix: &str,
        ) -> std::result::Result<Vec<String>, ProtocolAdminError> {
            Ok(Vec::new())
        }

        async fn remove_policy(&self, _name: &str) -> std::result::Result<(), ProtocolAdminError> {
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

        async fn policy_attached(
            &self,
            _policy: &str,
            _principal: &str,
            _is_group: bool,
        ) -> std::result::Result<bool, ProtocolAdminError> {
            Ok(false)
        }

        async fn revoke_sts_sessions_for_provider(
            &self,
            _parent_access_key: &str,
            _provider: &str,
        ) -> std::result::Result<(), ProtocolAdminError> {
            Ok(())
        }

        async fn sts_sessions_with_parent_for_provider(
            &self,
            _parent_access_key: &str,
            _provider: &str,
        ) -> std::result::Result<Vec<String>, ProtocolAdminError> {
            Ok(Vec::new())
        }
    }

    #[async_trait]
    impl ProtocolAdminCleanupPort for EventuallyConsistentAdmin {
        async fn users_with_prefix(
            &self,
            _prefix: &str,
        ) -> std::result::Result<Vec<String>, ProtocolAdminError> {
            Ok(Vec::new())
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

        async fn revoke_sts_sessions_for_provider(
            &self,
            _parent_access_key: &str,
            _provider: &str,
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

        async fn sts_sessions_with_parent_for_provider(
            &self,
            _parent_access_key: &str,
            _provider: &str,
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

        async fn groups_with_prefix(
            &self,
            _prefix: &str,
        ) -> std::result::Result<Vec<String>, ProtocolAdminError> {
            Ok(Vec::new())
        }

        async fn remove_group(&self, _group: &str) -> std::result::Result<(), ProtocolAdminError> {
            Ok(())
        }

        async fn policies_with_prefix(
            &self,
            _prefix: &str,
        ) -> std::result::Result<Vec<String>, ProtocolAdminError> {
            Ok(Vec::new())
        }

        async fn remove_policy(&self, _name: &str) -> std::result::Result<(), ProtocolAdminError> {
            Ok(())
        }
    }

    #[async_trait]
    impl ProtocolS3CleanupPort for FakeS3 {
        async fn cleanup_bucket_names(
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

        async fn cleanup_exclusive_bucket(
            &self,
            ownership: ExclusiveBucketOwnership<'_>,
            include_versions: bool,
        ) -> std::result::Result<(), ProtocolS3Error> {
            if include_versions {
                let versions = self.versions.lock().expect("versions").clone();
                for version in versions {
                    self.calls.lock().expect("calls").push(format!(
                        "delete-version:{}:{}",
                        version.key, version.version_id
                    ));
                    self.versions.lock().expect("versions").retain(|candidate| {
                        candidate.key != version.key || candidate.version_id != version.version_id
                    });
                }
            }
            let objects = self.objects.lock().expect("objects").clone();
            for key in objects {
                self.calls
                    .lock()
                    .expect("calls")
                    .push(format!("delete-object:{key}"));
            }
            self.objects.lock().expect("objects").clear();
            self.calls
                .lock()
                .expect("calls")
                .push(format!("delete-bucket:{}", ownership.bucket()));
            Ok(())
        }

        async fn cleanup_object_prefix(
            &self,
            _bucket: &str,
            prefix: &str,
            include_versions: bool,
        ) -> std::result::Result<(), ProtocolS3Error> {
            if include_versions {
                let owned = self
                    .versions
                    .lock()
                    .expect("versions")
                    .iter()
                    .filter(|version| version.key.starts_with(prefix))
                    .cloned()
                    .collect::<Vec<_>>();
                for version in owned {
                    self.calls.lock().expect("calls").push(format!(
                        "delete-version:{}:{}",
                        version.key, version.version_id
                    ));
                    self.versions.lock().expect("versions").retain(|candidate| {
                        candidate.key != version.key || candidate.version_id != version.version_id
                    });
                }
            }
            let owned = self
                .objects
                .lock()
                .expect("objects")
                .iter()
                .filter(|key| key.starts_with(prefix))
                .cloned()
                .collect::<Vec<_>>();
            for key in owned {
                self.calls
                    .lock()
                    .expect("calls")
                    .push(format!("delete-object:{key}"));
                self.objects
                    .lock()
                    .expect("objects")
                    .retain(|candidate| candidate != &key);
            }
            Ok(())
        }

        async fn cleanup_object_prefix_exists(
            &self,
            _bucket: &str,
            prefix: &str,
            include_versions: bool,
        ) -> std::result::Result<bool, ProtocolS3Error> {
            if self
                .objects
                .lock()
                .expect("objects")
                .iter()
                .any(|key| key.starts_with(prefix))
            {
                return Ok(true);
            }
            Ok(include_versions
                && self
                    .versions
                    .lock()
                    .expect("versions")
                    .iter()
                    .any(|version| version.key.starts_with(prefix)))
        }

        async fn cleanup_abort_multipart_upload(
            &self,
            bucket: &str,
            key: &str,
            upload_id: &str,
        ) -> std::result::Result<(), ProtocolS3Error> {
            self.calls
                .lock()
                .expect("calls")
                .push(format!("abort-multipart:{bucket}:{key}:{upload_id}"));
            self.multipart_uploads
                .lock()
                .expect("multipart uploads")
                .retain(|upload| {
                    upload != &(bucket.to_string(), key.to_string(), upload_id.to_string())
                });
            Ok(())
        }

        async fn cleanup_multipart_upload_exists(
            &self,
            bucket: &str,
            key: &str,
            upload_id: &str,
        ) -> std::result::Result<bool, ProtocolS3Error> {
            Ok(self
                .multipart_uploads
                .lock()
                .expect("multipart uploads")
                .iter()
                .any(|upload| upload.0 == bucket && upload.1 == key && upload.2 == upload_id))
        }

        async fn cleanup_delete_bucket_policy(
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

        async fn cleanup_bucket_policy_exists(
            &self,
            _bucket: &str,
        ) -> std::result::Result<bool, ProtocolS3Error> {
            if let Some(error) = self
                .policy_readback_error
                .lock()
                .expect("policy readback")
                .clone()
            {
                return Err(error);
            }
            Ok(false)
        }

        async fn cleanup_delete_public_access_block(
            &self,
            _bucket: &str,
        ) -> std::result::Result<(), ProtocolS3Error> {
            Ok(())
        }

        async fn cleanup_public_access_block_exists(
            &self,
            _bucket: &str,
        ) -> std::result::Result<bool, ProtocolS3Error> {
            Ok(false)
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
    async fn recorded_multipart_upload_is_aborted_and_verified_by_upload_id() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut registry =
            ResourceRegistry::create(dir.path(), "run", fingerprint()).expect("registry");
        let upload = registry
            .plan_multipart_upload("bucket", "cases/case/object", "case", Vec::new())
            .expect("multipart upload");
        registry
            .transition(&upload.id, ResourceState::Creating, None)
            .expect("creating multipart upload");
        registry
            .set_multipart_upload_id(&upload.id, "upload-1")
            .expect("record upload id");
        registry
            .transition(&upload.id, ResourceState::Created, None)
            .expect("created multipart upload");
        let s3 = FakeS3 {
            multipart_uploads: Arc::new(Mutex::new(vec![
                (
                    "bucket".to_string(),
                    "cases/case/object".to_string(),
                    "upload-1".to_string(),
                ),
                (
                    "bucket".to_string(),
                    "cases/case/object".to_string(),
                    "foreign-upload".to_string(),
                ),
            ])),
            ..FakeS3::default()
        };

        let report = cleanup_registered_resources(&mut registry, &FakeAdmin, &s3).await;

        assert!(report.succeeded, "{report:?}");
        assert!(registry.pending_cleanup().next().is_none());
        assert_eq!(
            *s3.multipart_uploads.lock().expect("uploads"),
            vec![(
                "bucket".to_string(),
                "cases/case/object".to_string(),
                "foreign-upload".to_string(),
            )]
        );
        assert_eq!(
            *s3.calls.lock().expect("calls"),
            vec!["abort-multipart:bucket:cases/case/object:upload-1"]
        );
    }

    #[tokio::test]
    async fn multipart_without_upload_id_refuses_unscoped_cleanup() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut registry =
            ResourceRegistry::create(dir.path(), "run", fingerprint()).expect("registry");
        let upload = registry
            .plan_multipart_upload("bucket", "shared/key", "case", Vec::new())
            .expect("multipart upload");
        registry
            .transition(&upload.id, ResourceState::Creating, None)
            .expect("creating multipart upload");
        let s3 = FakeS3 {
            multipart_uploads: Arc::new(Mutex::new(vec![(
                "bucket".to_string(),
                "shared/key".to_string(),
                "foreign-upload".to_string(),
            )])),
            ..FakeS3::default()
        };

        let report = cleanup_registered_resources(&mut registry, &FakeAdmin, &s3).await;

        assert!(!report.succeeded);
        assert!(
            report.attempts[0]
                .error
                .as_deref()
                .is_some_and(|error| error.contains("refusing unscoped cleanup"))
        );
        assert_eq!(s3.multipart_uploads.lock().expect("uploads").len(), 1);
        assert!(s3.calls.lock().expect("calls").is_empty());
    }

    #[tokio::test]
    async fn shared_bucket_prefix_cleanup_preserves_foreign_objects_and_versions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut registry =
            ResourceRegistry::create(dir.path(), "run", fingerprint()).expect("registry");
        registry
            .set_versioned_cleanup(true)
            .expect("enable versioned cleanup");
        let prefix = registry
            .plan_object_prefix("shared", "cases/owned/", "case", Vec::new())
            .expect("object prefix");
        registry
            .transition(&prefix.id, ResourceState::Creating, None)
            .expect("creating prefix");
        registry
            .transition(&prefix.id, ResourceState::Created, None)
            .expect("created prefix");
        let s3 = FakeS3 {
            objects: Arc::new(Mutex::new(vec![
                "cases/owned/current".to_string(),
                "foreign/current".to_string(),
            ])),
            versions: Arc::new(Mutex::new(vec![
                ProtocolObjectVersion {
                    key: "cases/owned/version".to_string(),
                    version_id: "v1".to_string(),
                    delete_marker: false,
                },
                ProtocolObjectVersion {
                    key: "cases/owned/marker".to_string(),
                    version_id: "m1".to_string(),
                    delete_marker: true,
                },
                ProtocolObjectVersion {
                    key: "foreign/version".to_string(),
                    version_id: "foreign-v1".to_string(),
                    delete_marker: false,
                },
                ProtocolObjectVersion {
                    key: "foreign/marker".to_string(),
                    version_id: "foreign-m1".to_string(),
                    delete_marker: true,
                },
            ])),
            ..FakeS3::default()
        };

        let report = cleanup_registered_resources(&mut registry, &FakeAdmin, &s3).await;

        assert!(report.succeeded, "{report:?}");
        assert_eq!(
            *s3.objects.lock().expect("objects"),
            vec!["foreign/current"]
        );
        assert_eq!(
            *s3.versions.lock().expect("versions"),
            vec![
                ProtocolObjectVersion {
                    key: "foreign/version".to_string(),
                    version_id: "foreign-v1".to_string(),
                    delete_marker: false,
                },
                ProtocolObjectVersion {
                    key: "foreign/marker".to_string(),
                    version_id: "foreign-m1".to_string(),
                    delete_marker: true,
                },
            ]
        );
        assert!(
            !s3.calls
                .lock()
                .expect("calls")
                .iter()
                .any(|call| call == "delete-bucket:shared")
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

    #[tokio::test]
    async fn external_identity_cleanup_uses_the_registered_coordinates() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut registry =
            ResourceRegistry::create(dir.path(), "run", fingerprint()).expect("registry");
        let coordinates = external_identity_coordinates();
        let subject = registry
            .plan_external_identity_subject("oidc-user", coordinates.clone(), "case", Vec::new())
            .expect("subject");
        registry
            .transition(&subject.id, ResourceState::Creating, None)
            .expect("creating");
        registry
            .transition(&subject.id, ResourceState::Created, None)
            .expect("created");
        let external = FakeExternalIdentity {
            subjects: Arc::new(Mutex::new(BTreeSet::from(["oidc-user".to_string()]))),
            coordinates,
        };

        let report = cleanup_registered_resources_with_external(
            &mut registry,
            &FakeAdmin,
            &FakeS3::default(),
            Some(&external),
        )
        .await;

        assert!(report.succeeded, "{report:?}");
        assert!(external.subjects.lock().expect("subjects").is_empty());
    }

    #[tokio::test]
    async fn external_identity_cleanup_refuses_a_different_subject_namespace() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut registry =
            ResourceRegistry::create(dir.path(), "run", fingerprint()).expect("registry");
        let subject = registry
            .plan_external_identity_subject(
                "oidc-user",
                external_identity_coordinates(),
                "case",
                Vec::new(),
            )
            .expect("subject");
        registry
            .transition(&subject.id, ResourceState::Creating, None)
            .expect("creating");
        registry
            .transition(&subject.id, ResourceState::Created, None)
            .expect("created");
        let subjects = Arc::new(Mutex::new(BTreeSet::from(["oidc-user".to_string()])));
        let external = FakeExternalIdentity {
            subjects: subjects.clone(),
            coordinates: ProtocolExternalIdentityCoordinates {
                subject_namespace: "https://other.example/admin/realms/ci/users".to_string(),
                ..external_identity_coordinates()
            },
        };

        let report = cleanup_registered_resources_with_external(
            &mut registry,
            &FakeAdmin,
            &FakeS3::default(),
            Some(&external),
        )
        .await;

        assert!(!report.succeeded);
        assert!(subjects.lock().expect("subjects").contains("oidc-user"));
    }

    fn external_identity_coordinates() -> ProtocolExternalIdentityCoordinates {
        ProtocolExternalIdentityCoordinates {
            provider: "keycloak".to_string(),
            profile: "keycloak-ci".to_string(),
            issuer: "https://idp.example/realms/ci".to_string(),
            subject_namespace: "https://idp.example/admin/realms/ci/users".to_string(),
        }
    }
}
