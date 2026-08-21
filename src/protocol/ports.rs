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

#[async_trait]
pub trait ProtocolAdminPort: Send + Sync {
    async fn server_info(&self) -> std::result::Result<ProtocolServerInfo, ProtocolAdminError>;
    async fn users_with_prefix(
        &self,
        prefix: &str,
    ) -> std::result::Result<Vec<String>, ProtocolAdminError>;
    async fn create_user(
        &self,
        credential: &ActorCredential,
    ) -> std::result::Result<(), ProtocolAdminError>;
    async fn remove_user(&self, access_key: &str) -> std::result::Result<(), ProtocolAdminError>;

    async fn revoke_sts_sessions(
        &self,
        _parent_access_key: &str,
    ) -> std::result::Result<(), ProtocolAdminError> {
        Err(ProtocolAdminError::protocol("RevokeStsSessionsUnsupported"))
    }

    async fn revoke_sts_sessions_for_provider(
        &self,
        parent_access_key: &str,
        provider: &str,
    ) -> std::result::Result<(), ProtocolAdminError> {
        if provider == "builtin" {
            self.revoke_sts_sessions(parent_access_key).await
        } else {
            Err(ProtocolAdminError::protocol(
                "RevokeStsSessionsForProviderUnsupported",
            ))
        }
    }

    async fn policy_attached(
        &self,
        _policy: &str,
        _principal: &str,
        _is_group: bool,
    ) -> std::result::Result<bool, ProtocolAdminError> {
        Err(ProtocolAdminError::protocol(
            "PolicyAttachmentReadbackUnsupported",
        ))
    }

    async fn group_contains_member(
        &self,
        _group: &str,
        _member: &str,
    ) -> std::result::Result<bool, ProtocolAdminError> {
        Err(ProtocolAdminError::protocol(
            "GroupMembershipReadbackUnsupported",
        ))
    }

    async fn sts_sessions_with_parent(
        &self,
        _parent_access_key: &str,
    ) -> std::result::Result<Vec<String>, ProtocolAdminError> {
        Err(ProtocolAdminError::protocol("ListStsSessionsUnsupported"))
    }

    async fn sts_sessions_with_parent_for_provider(
        &self,
        parent_access_key: &str,
        provider: &str,
    ) -> std::result::Result<Vec<String>, ProtocolAdminError> {
        if provider == "builtin" {
            self.sts_sessions_with_parent(parent_access_key).await
        } else {
            Err(ProtocolAdminError::protocol(
                "ListStsSessionsForProviderUnsupported",
            ))
        }
    }

    async fn policies_with_prefix(
        &self,
        _prefix: &str,
    ) -> std::result::Result<Vec<String>, ProtocolAdminError> {
        Err(ProtocolAdminError::protocol("ListPoliciesUnsupported"))
    }

    async fn groups_with_prefix(
        &self,
        _prefix: &str,
    ) -> std::result::Result<Vec<String>, ProtocolAdminError> {
        Err(ProtocolAdminError::protocol("ListGroupsUnsupported"))
    }

    async fn create_policy(
        &self,
        _name: &str,
        _document: &str,
    ) -> std::result::Result<(), ProtocolAdminError> {
        Err(ProtocolAdminError::protocol("CreatePolicyUnsupported"))
    }

    async fn remove_policy(&self, _name: &str) -> std::result::Result<(), ProtocolAdminError> {
        Err(ProtocolAdminError::protocol("RemovePolicyUnsupported"))
    }

    async fn attach_policy(
        &self,
        _policy: &str,
        _principal: &str,
        _is_group: bool,
    ) -> std::result::Result<(), ProtocolAdminError> {
        Err(ProtocolAdminError::protocol("AttachPolicyUnsupported"))
    }

    async fn detach_policy(
        &self,
        _policy: &str,
        _principal: &str,
        _is_group: bool,
    ) -> std::result::Result<(), ProtocolAdminError> {
        Err(ProtocolAdminError::protocol("DetachPolicyUnsupported"))
    }

    async fn update_group_members(
        &self,
        _group: &str,
        _members: &[String],
        _remove: bool,
    ) -> std::result::Result<(), ProtocolAdminError> {
        Err(ProtocolAdminError::protocol(
            "UpdateGroupMembersUnsupported",
        ))
    }

    async fn remove_group(&self, _group: &str) -> std::result::Result<(), ProtocolAdminError> {
        Err(ProtocolAdminError::protocol("RemoveGroupUnsupported"))
    }
}

#[async_trait]
pub trait ProtocolS3Port: Send + Sync {
    async fn list_buckets_with_prefix(
        &self,
        prefix: &str,
    ) -> std::result::Result<Vec<String>, ProtocolS3Error>;
    async fn create_bucket(&self, bucket: &str) -> Result<(), ProtocolS3Error>;
    async fn delete_bucket(&self, bucket: &str) -> Result<(), ProtocolS3Error>;
    async fn head_bucket(&self, _bucket: &str) -> Result<(), ProtocolS3Error> {
        Err(unsupported_s3_operation("HeadBucketUnsupported"))
    }
    async fn put_bucket_policy(&self, bucket: &str, policy: &str) -> Result<(), ProtocolS3Error>;
    async fn get_bucket_policy(&self, _bucket: &str) -> Result<String, ProtocolS3Error> {
        Err(ProtocolS3Error {
            code: "GetBucketPolicyUnsupported".to_string(),
            status: None,
            request_id: None,
        })
    }
    async fn delete_bucket_policy(&self, bucket: &str) -> Result<(), ProtocolS3Error>;
    async fn list_objects(&self, bucket: &str) -> Result<Vec<String>, ProtocolS3Error>;
    async fn list_objects_v2_summary(
        &self,
        bucket: &str,
    ) -> Result<ProtocolListObjectsResult, ProtocolS3Error> {
        let keys = self.list_objects(bucket).await?;
        let key_count = keys.len();
        Ok(ProtocolListObjectsResult { keys, key_count })
    }
    async fn put_object(&self, bucket: &str, key: &str, body: &[u8])
    -> Result<(), ProtocolS3Error>;
    async fn get_object(&self, bucket: &str, key: &str) -> Result<Vec<u8>, ProtocolS3Error>;
    async fn delete_object(&self, bucket: &str, key: &str) -> Result<(), ProtocolS3Error>;
    async fn copy_object(
        &self,
        _bucket: &str,
        _source_key: &str,
        _destination_key: &str,
    ) -> Result<(), ProtocolS3Error> {
        Err(unsupported_s3_operation("CopyObjectUnsupported"))
    }
    async fn delete_objects(
        &self,
        _bucket: &str,
        _keys: &[String],
    ) -> Result<Vec<String>, ProtocolS3Error> {
        Err(unsupported_s3_operation("DeleteObjectsUnsupported"))
    }
    async fn create_multipart_upload(
        &self,
        _bucket: &str,
        _key: &str,
    ) -> Result<String, ProtocolS3Error> {
        Err(unsupported_s3_operation("CreateMultipartUploadUnsupported"))
    }
    async fn upload_part(
        &self,
        _bucket: &str,
        _key: &str,
        _upload_id: &str,
        _part_number: i32,
        _body: &[u8],
    ) -> Result<String, ProtocolS3Error> {
        Err(unsupported_s3_operation("UploadPartUnsupported"))
    }
    async fn complete_multipart_upload(
        &self,
        _bucket: &str,
        _key: &str,
        _upload_id: &str,
        _parts: &[ProtocolCompletedPart],
    ) -> Result<(), ProtocolS3Error> {
        Err(unsupported_s3_operation(
            "CompleteMultipartUploadUnsupported",
        ))
    }
    async fn abort_multipart_upload(
        &self,
        _bucket: &str,
        _key: &str,
        _upload_id: &str,
    ) -> Result<(), ProtocolS3Error> {
        Err(unsupported_s3_operation("AbortMultipartUploadUnsupported"))
    }
    async fn list_multipart_uploads(
        &self,
        _bucket: &str,
        _key: &str,
    ) -> Result<Vec<String>, ProtocolS3Error> {
        Err(unsupported_s3_operation("ListMultipartUploadsUnsupported"))
    }
    async fn put_bucket_versioning(
        &self,
        _bucket: &str,
        _enabled: bool,
    ) -> Result<(), ProtocolS3Error> {
        Err(unsupported_s3_operation("PutBucketVersioningUnsupported"))
    }
    async fn get_object_version(
        &self,
        _bucket: &str,
        _key: &str,
        _version_id: &str,
    ) -> Result<Vec<u8>, ProtocolS3Error> {
        Err(unsupported_s3_operation("GetObjectVersionUnsupported"))
    }
    async fn put_public_access_block(
        &self,
        _bucket: &str,
        _configuration: ProtocolPublicAccessBlock,
    ) -> Result<(), ProtocolS3Error> {
        Err(unsupported_s3_operation("PutPublicAccessBlockUnsupported"))
    }
    async fn get_public_access_block(
        &self,
        _bucket: &str,
    ) -> Result<ProtocolPublicAccessBlock, ProtocolS3Error> {
        Err(unsupported_s3_operation("GetPublicAccessBlockUnsupported"))
    }
    async fn delete_public_access_block(&self, _bucket: &str) -> Result<(), ProtocolS3Error> {
        Err(unsupported_s3_operation(
            "DeletePublicAccessBlockUnsupported",
        ))
    }
    async fn empty_bucket(
        &self,
        bucket: &str,
        include_versions: bool,
    ) -> Result<(), ProtocolS3Error> {
        if include_versions {
            for version in self.list_object_versions(bucket).await? {
                self.delete_object_version(bucket, &version.key, &version.version_id)
                    .await?;
            }
        }
        for key in self.list_objects(bucket).await? {
            self.delete_object(bucket, &key).await?;
        }
        Ok(())
    }
    async fn list_object_versions(
        &self,
        bucket: &str,
    ) -> std::result::Result<Vec<ProtocolObjectVersion>, ProtocolS3Error>;
    async fn delete_object_version(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> std::result::Result<(), ProtocolS3Error>;
}

fn unsupported_s3_operation(code: &str) -> ProtocolS3Error {
    ProtocolS3Error {
        code: code.to_string(),
        status: None,
        request_id: None,
    }
}

#[async_trait]
pub trait ActorS3ClientFactory: Send + Sync {
    type Client: ProtocolS3Port;

    async fn for_actor(&self, credential: &ActorCredential) -> anyhow::Result<Self::Client>;
}
