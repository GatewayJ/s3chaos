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

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt};

use crate::protocol::credentials::{ActorCredential, ExternalIdentityCredential, WebIdentityToken};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolServerInfo {
    pub deployment_id: String,
    pub mode: Option<String>,
    pub region: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolS3Error {
    pub code: String,
    pub status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

impl ProtocolS3Error {
    pub fn is_access_denied(&self) -> bool {
        matches!(self.code.as_str(), "AccessDenied" | "Forbidden")
    }

    pub fn is_transient(&self) -> bool {
        self.status
            .is_some_and(|status| status == 408 || status == 429 || status >= 500)
            || matches!(
                self.code.as_str(),
                "Timeout"
                    | "DispatchFailure"
                    | "ResponseError"
                    | "InternalError"
                    | "RequestTimeout"
                    | "ServiceUnavailable"
                    | "SlowDown"
            )
    }
}

impl fmt::Display for ProtocolS3Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "S3 request failed: code={} status={} request_id={}",
            self.code,
            self.status
                .map(|status| status.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            self.request_id.as_deref().unwrap_or("unknown")
        )
    }
}

impl std::error::Error for ProtocolS3Error {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolAdminError {
    pub code: String,
    pub status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    pub transient: bool,
}

impl ProtocolAdminError {
    pub fn service(code: impl Into<String>, status: u16, request_id: Option<String>) -> Self {
        Self {
            code: code.into(),
            status: Some(status),
            request_id,
            transient: status == 408 || status == 429 || status >= 500,
        }
    }

    pub fn transport(code: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            status: None,
            request_id: None,
            transient: true,
        }
    }

    pub fn protocol(code: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            status: None,
            request_id: None,
            transient: false,
        }
    }

    pub fn is_not_found(&self) -> bool {
        matches!(
            self.code.as_str(),
            "NoSuchUser" | "NoSuchGroup" | "NoSuchPolicy" | "NoSuchEntity"
        )
    }

    pub fn is_transient(&self) -> bool {
        self.transient
    }
}

impl fmt::Display for ProtocolAdminError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "admin request failed: code={} status={} request_id={}",
            self.code,
            self.status
                .map(|status| status.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            self.request_id.as_deref().unwrap_or("unknown")
        )
    }
}

impl std::error::Error for ProtocolAdminError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolObjectVersion {
    pub key: String,
    pub version_id: String,
    pub delete_marker: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolListObjectsResult {
    pub keys: Vec<String>,
    pub key_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolCompletedPart {
    pub part_number: i32,
    pub etag: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolPublicAccessBlock {
    pub block_public_acls: bool,
    pub ignore_public_acls: bool,
    pub block_public_policy: bool,
    pub restrict_public_buckets: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolAssumeRoleRequest {
    pub duration_seconds: u32,
    pub session_policy: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ProtocolWebIdentityRequest {
    pub duration_seconds: u32,
    pub session_policy: Option<String>,
    pub token: WebIdentityToken,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolStsError {
    pub code: String,
    pub status: Option<u16>,
    pub request_id: Option<String>,
}

impl fmt::Display for ProtocolStsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "STS request failed: code={} status={} request_id={}",
            self.code,
            self.status
                .map(|status| status.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            self.request_id.as_deref().unwrap_or("unknown")
        )
    }
}

impl std::error::Error for ProtocolStsError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolExternalIdentityError {
    pub code: String,
    pub status: Option<u16>,
    pub transient: bool,
}

impl ProtocolExternalIdentityError {
    pub fn service(code: impl Into<String>, status: u16) -> Self {
        Self {
            code: code.into(),
            status: Some(status),
            transient: status == 408 || status == 429 || status >= 500,
        }
    }

    pub fn transport(code: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            status: None,
            transient: true,
        }
    }

    pub fn protocol(code: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            status: None,
            transient: false,
        }
    }

    pub fn is_transient(&self) -> bool {
        self.transient
    }
}

impl fmt::Display for ProtocolExternalIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "external identity request failed: code={} status={}",
            self.code,
            self.status
                .map(|status| status.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        )
    }
}

impl std::error::Error for ProtocolExternalIdentityError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolExternalIdentityProviderInfo {
    pub provider: String,
    pub profile: String,
    pub issuer: String,
    pub policy_claim: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolExternalIdentityCoordinates {
    pub provider: String,
    pub profile: String,
    pub issuer: String,
    pub subject_namespace: String,
}

#[async_trait]
pub trait ProtocolStsPort: Send + Sync {
    async fn assume_role(
        &self,
        parent: &ActorCredential,
        request: &ProtocolAssumeRoleRequest,
        source_resource_id: &str,
    ) -> std::result::Result<ActorCredential, ProtocolStsError>;
}

#[async_trait]
pub trait ProtocolWebIdentityStsPort: Send + Sync {
    fn cleanup_parent(
        &self,
        token: &WebIdentityToken,
    ) -> std::result::Result<String, ProtocolStsError>;

    async fn assume_role_with_web_identity(
        &self,
        request: &ProtocolWebIdentityRequest,
        source_resource_id: &str,
    ) -> std::result::Result<ActorCredential, ProtocolStsError>;
}

#[async_trait]
pub trait ProtocolExternalIdentityPort: Send + Sync {
    fn coordinates(&self) -> ProtocolExternalIdentityCoordinates;
    fn policy_claim(&self) -> &str;

    async fn provider_info(
        &self,
    ) -> std::result::Result<ProtocolExternalIdentityProviderInfo, ProtocolExternalIdentityError>;
    async fn create_subject(
        &self,
        credential: &ExternalIdentityCredential,
        claims: &BTreeMap<String, Vec<String>>,
    ) -> std::result::Result<(), ProtocolExternalIdentityError>;
    async fn issue_id_token(
        &self,
        credential: &ExternalIdentityCredential,
    ) -> std::result::Result<WebIdentityToken, ProtocolExternalIdentityError>;
    async fn subject_exists(
        &self,
        username: &str,
    ) -> std::result::Result<bool, ProtocolExternalIdentityError>;
    async fn delete_subject(
        &self,
        username: &str,
    ) -> std::result::Result<(), ProtocolExternalIdentityError>;
}

/// Bucket lifecycle operations used by protocol cases and fixtures.
#[async_trait]
pub trait ProtocolBucketPort: Send + Sync {
    async fn list_buckets_with_prefix(
        &self,
        prefix: &str,
    ) -> std::result::Result<Vec<String>, ProtocolS3Error>;
    async fn create_bucket(&self, bucket: &str) -> Result<(), ProtocolS3Error>;
    async fn delete_bucket(&self, bucket: &str) -> Result<(), ProtocolS3Error>;
    async fn head_bucket(&self, bucket: &str) -> Result<(), ProtocolS3Error>;
}

/// Object data-plane operations. Listing is intentionally a separate role.
#[async_trait]
pub trait ProtocolObjectPort: Send + Sync {
    async fn put_object(&self, bucket: &str, key: &str, body: &[u8])
    -> Result<(), ProtocolS3Error>;
    async fn get_object(&self, bucket: &str, key: &str) -> Result<Vec<u8>, ProtocolS3Error>;
    async fn delete_object(&self, bucket: &str, key: &str) -> Result<(), ProtocolS3Error>;
    async fn copy_object(
        &self,
        bucket: &str,
        source_key: &str,
        destination_key: &str,
    ) -> Result<(), ProtocolS3Error>;
    async fn delete_objects(
        &self,
        bucket: &str,
        keys: &[String],
    ) -> Result<Vec<String>, ProtocolS3Error>;
}

#[async_trait]
pub trait ProtocolListingPort: Send + Sync {
    async fn list_objects(&self, bucket: &str) -> Result<Vec<String>, ProtocolS3Error>;
    async fn list_objects_v2_summary(
        &self,
        bucket: &str,
    ) -> Result<ProtocolListObjectsResult, ProtocolS3Error>;
}

#[async_trait]
pub trait ProtocolMultipartPort: Send + Sync {
    async fn create_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<String, ProtocolS3Error>;
    async fn upload_part(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        part_number: i32,
        body: &[u8],
    ) -> Result<String, ProtocolS3Error>;
    async fn complete_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        parts: &[ProtocolCompletedPart],
    ) -> Result<(), ProtocolS3Error>;
    async fn abort_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
    ) -> Result<(), ProtocolS3Error>;
    async fn list_multipart_uploads(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Vec<String>, ProtocolS3Error>;
}

#[async_trait]
pub trait ProtocolVersioningPort: Send + Sync {
    async fn put_bucket_versioning(
        &self,
        bucket: &str,
        enabled: bool,
    ) -> Result<(), ProtocolS3Error>;
    async fn get_object_version(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> Result<Vec<u8>, ProtocolS3Error>;
    async fn list_object_versions(
        &self,
        bucket: &str,
    ) -> Result<Vec<ProtocolObjectVersion>, ProtocolS3Error>;
    async fn delete_object_version(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> Result<(), ProtocolS3Error>;
}

#[async_trait]
pub trait ProtocolBucketConfigPort: Send + Sync {
    async fn put_public_access_block(
        &self,
        bucket: &str,
        configuration: ProtocolPublicAccessBlock,
    ) -> Result<(), ProtocolS3Error>;
    async fn get_public_access_block(
        &self,
        bucket: &str,
    ) -> Result<ProtocolPublicAccessBlock, ProtocolS3Error>;
    async fn delete_public_access_block(&self, bucket: &str) -> Result<(), ProtocolS3Error>;
}

#[async_trait]
pub trait ProtocolAuthorizationPort: Send + Sync {
    async fn put_bucket_policy(&self, bucket: &str, policy: &str) -> Result<(), ProtocolS3Error>;
    async fn get_bucket_policy(&self, bucket: &str) -> Result<String, ProtocolS3Error>;
    async fn delete_bucket_policy(&self, bucket: &str) -> Result<(), ProtocolS3Error>;
}

/// Proof that whole-bucket cleanup is allowed for a registry-owned bucket.
///
/// The constructor is crate-private so shared-bucket cleanup callers cannot accidentally pass a
/// plain bucket name to a destructive whole-bucket operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExclusiveBucketOwnership<'a> {
    bucket: &'a str,
}

impl<'a> ExclusiveBucketOwnership<'a> {
    pub(crate) fn registry_owned(bucket: &'a str) -> Self {
        Self { bucket }
    }

    pub fn bucket(self) -> &'a str {
        self.bucket
    }
}

/// Cleanup-only S3 boundary. Shared resources are addressed by exact prefix or upload ID, while
/// whole-bucket deletion requires [`ExclusiveBucketOwnership`].
#[async_trait]
pub trait ProtocolS3CleanupPort: Send + Sync {
    async fn cleanup_bucket_names(&self, prefix: &str) -> Result<Vec<String>, ProtocolS3Error>;
    async fn cleanup_exclusive_bucket(
        &self,
        ownership: ExclusiveBucketOwnership<'_>,
        include_versions: bool,
    ) -> Result<(), ProtocolS3Error>;
    async fn cleanup_object_prefix(
        &self,
        bucket: &str,
        prefix: &str,
        include_versions: bool,
    ) -> Result<(), ProtocolS3Error>;
    async fn cleanup_object_prefix_exists(
        &self,
        bucket: &str,
        prefix: &str,
        include_versions: bool,
    ) -> Result<bool, ProtocolS3Error>;
    async fn cleanup_abort_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
    ) -> Result<(), ProtocolS3Error>;
    async fn cleanup_multipart_upload_exists(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
    ) -> Result<bool, ProtocolS3Error>;
    async fn cleanup_delete_bucket_policy(&self, bucket: &str) -> Result<(), ProtocolS3Error>;
    async fn cleanup_bucket_policy_exists(&self, bucket: &str) -> Result<bool, ProtocolS3Error>;
    async fn cleanup_delete_public_access_block(&self, bucket: &str)
    -> Result<(), ProtocolS3Error>;
    async fn cleanup_public_access_block_exists(
        &self,
        bucket: &str,
    ) -> Result<bool, ProtocolS3Error>;
}

#[async_trait]
pub trait ProtocolAdminServerPort: Send + Sync {
    async fn server_info(&self) -> std::result::Result<ProtocolServerInfo, ProtocolAdminError>;
}

#[async_trait]
pub trait ProtocolIdentityAdminPort: Send + Sync {
    async fn users_with_prefix(
        &self,
        prefix: &str,
    ) -> std::result::Result<Vec<String>, ProtocolAdminError>;
    async fn create_user(
        &self,
        credential: &ActorCredential,
    ) -> std::result::Result<(), ProtocolAdminError>;
    async fn remove_user(&self, access_key: &str) -> std::result::Result<(), ProtocolAdminError>;
}

#[async_trait]
pub trait ProtocolGroupAdminPort: Send + Sync {
    async fn groups_with_prefix(
        &self,
        prefix: &str,
    ) -> std::result::Result<Vec<String>, ProtocolAdminError>;
    async fn group_contains_member(
        &self,
        group: &str,
        member: &str,
    ) -> std::result::Result<bool, ProtocolAdminError>;
    async fn update_group_members(
        &self,
        group: &str,
        members: &[String],
        remove: bool,
    ) -> std::result::Result<(), ProtocolAdminError>;
    async fn remove_group(&self, group: &str) -> std::result::Result<(), ProtocolAdminError>;
}

#[async_trait]
pub trait ProtocolPolicyAdminPort: Send + Sync {
    async fn policies_with_prefix(
        &self,
        prefix: &str,
    ) -> std::result::Result<Vec<String>, ProtocolAdminError>;
    async fn create_policy(
        &self,
        name: &str,
        document: &str,
    ) -> std::result::Result<(), ProtocolAdminError>;
    async fn remove_policy(&self, name: &str) -> std::result::Result<(), ProtocolAdminError>;
    async fn attach_policy(
        &self,
        policy: &str,
        principal: &str,
        is_group: bool,
    ) -> std::result::Result<(), ProtocolAdminError>;
    async fn detach_policy(
        &self,
        policy: &str,
        principal: &str,
        is_group: bool,
    ) -> std::result::Result<(), ProtocolAdminError>;
    async fn policy_attached(
        &self,
        policy: &str,
        principal: &str,
        is_group: bool,
    ) -> std::result::Result<bool, ProtocolAdminError>;
}

#[async_trait]
pub trait ProtocolSessionAdminPort: Send + Sync {
    async fn revoke_sts_sessions_for_provider(
        &self,
        parent_access_key: &str,
        provider: &str,
    ) -> std::result::Result<(), ProtocolAdminError>;
    async fn sts_sessions_with_parent_for_provider(
        &self,
        parent_access_key: &str,
        provider: &str,
    ) -> std::result::Result<Vec<String>, ProtocolAdminError>;
}

/// Cleanup-only admin boundary. It is intentionally independent from case roles so a cleanup fake
/// never has to implement unrelated create or authorization operations.
#[async_trait]
pub trait ProtocolAdminCleanupPort: Send + Sync {
    async fn users_with_prefix(
        &self,
        prefix: &str,
    ) -> std::result::Result<Vec<String>, ProtocolAdminError>;
    async fn remove_user(&self, access_key: &str) -> std::result::Result<(), ProtocolAdminError>;
    async fn groups_with_prefix(
        &self,
        prefix: &str,
    ) -> std::result::Result<Vec<String>, ProtocolAdminError>;
    async fn group_contains_member(
        &self,
        group: &str,
        member: &str,
    ) -> std::result::Result<bool, ProtocolAdminError>;
    async fn update_group_members(
        &self,
        group: &str,
        members: &[String],
        remove: bool,
    ) -> std::result::Result<(), ProtocolAdminError>;
    async fn remove_group(&self, group: &str) -> std::result::Result<(), ProtocolAdminError>;
    async fn policies_with_prefix(
        &self,
        prefix: &str,
    ) -> std::result::Result<Vec<String>, ProtocolAdminError>;
    async fn remove_policy(&self, name: &str) -> std::result::Result<(), ProtocolAdminError>;
    async fn detach_policy(
        &self,
        policy: &str,
        principal: &str,
        is_group: bool,
    ) -> std::result::Result<(), ProtocolAdminError>;
    async fn policy_attached(
        &self,
        policy: &str,
        principal: &str,
        is_group: bool,
    ) -> std::result::Result<bool, ProtocolAdminError>;
    async fn revoke_sts_sessions_for_provider(
        &self,
        parent_access_key: &str,
        provider: &str,
    ) -> std::result::Result<(), ProtocolAdminError>;
    async fn sts_sessions_with_parent_for_provider(
        &self,
        parent_access_key: &str,
        provider: &str,
    ) -> std::result::Result<Vec<String>, ProtocolAdminError>;
}

/// Role bundle used only at the case dispatch boundary. Individual cases immediately narrow this
/// bundle to the roles declared in their own signatures.
pub trait ProtocolAdminCasePorts:
    ProtocolIdentityAdminPort
    + ProtocolGroupAdminPort
    + ProtocolPolicyAdminPort
    + ProtocolSessionAdminPort
{
}

impl<T> ProtocolAdminCasePorts for T where
    T: ProtocolIdentityAdminPort
        + ProtocolGroupAdminPort
        + ProtocolPolicyAdminPort
        + ProtocolSessionAdminPort
{
}

/// Role bundle used only at the case dispatch boundary. Domain cases immediately narrow this
/// bundle to the roles declared in their own signatures.
pub trait ProtocolS3CasePorts:
    ProtocolBucketPort
    + ProtocolObjectPort
    + ProtocolListingPort
    + ProtocolMultipartPort
    + ProtocolVersioningPort
    + ProtocolBucketConfigPort
    + ProtocolAuthorizationPort
{
}

/// Roles shared by native compatibility cases. Authorization is excluded because these cases run
/// with the administrative actor and do not exercise bucket-policy behavior.
pub trait ProtocolS3CompatibilityPorts:
    ProtocolBucketPort
    + ProtocolObjectPort
    + ProtocolListingPort
    + ProtocolMultipartPort
    + ProtocolVersioningPort
    + ProtocolBucketConfigPort
{
}

/// S3 capabilities exercised by preflight. Multipart is deliberately excluded because the probe
/// does not create uploads.
pub trait ProtocolS3PreflightPorts:
    ProtocolBucketPort
    + ProtocolObjectPort
    + ProtocolListingPort
    + ProtocolVersioningPort
    + ProtocolBucketConfigPort
    + ProtocolAuthorizationPort
    + ProtocolS3CleanupPort
{
}

impl<T> ProtocolS3PreflightPorts for T where
    T: ProtocolBucketPort
        + ProtocolObjectPort
        + ProtocolListingPort
        + ProtocolVersioningPort
        + ProtocolBucketConfigPort
        + ProtocolAuthorizationPort
        + ProtocolS3CleanupPort
{
}

impl<T> ProtocolS3CompatibilityPorts for T where
    T: ProtocolBucketPort
        + ProtocolObjectPort
        + ProtocolListingPort
        + ProtocolMultipartPort
        + ProtocolVersioningPort
        + ProtocolBucketConfigPort
{
}

impl<T> ProtocolS3CasePorts for T where
    T: ProtocolBucketPort
        + ProtocolObjectPort
        + ProtocolListingPort
        + ProtocolMultipartPort
        + ProtocolVersioningPort
        + ProtocolBucketConfigPort
        + ProtocolAuthorizationPort
{
}

pub trait ProtocolAdminRuntimePorts: ProtocolAdminServerPort + ProtocolAdminCasePorts {}

impl<T> ProtocolAdminRuntimePorts for T where T: ProtocolAdminServerPort + ProtocolAdminCasePorts {}

#[async_trait]
pub trait ActorS3ClientFactory: Send + Sync {
    type Client: ProtocolListingPort + ProtocolObjectPort;

    async fn for_actor(&self, credential: &ActorCredential) -> anyhow::Result<Self::Client>;
}
