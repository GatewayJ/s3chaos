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
use std::fmt;

use crate::protocol::credentials::ActorCredential;

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

    pub fn is_not_found(&self) -> bool {
        self.status == Some(404)
            || matches!(
                self.code.as_str(),
                "NoSuchBucket" | "NoSuchBucketPolicy" | "NoSuchKey" | "NotFound"
            )
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
        self.status == Some(404)
            || matches!(
                self.code.as_str(),
                "NoSuchUser" | "NoSuchGroup" | "NoSuchPolicy" | "NoSuchEntity" | "NotFound"
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
pub struct ProtocolAssumeRoleRequest {
    pub duration_seconds: u32,
    pub session_policy: Option<String>,
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
    async fn put_object(&self, bucket: &str, key: &str, body: &[u8])
    -> Result<(), ProtocolS3Error>;
    async fn get_object(&self, bucket: &str, key: &str) -> Result<Vec<u8>, ProtocolS3Error>;
    async fn delete_object(&self, bucket: &str, key: &str) -> Result<(), ProtocolS3Error>;
    async fn empty_bucket(&self, bucket: &str) -> Result<(), ProtocolS3Error> {
        for version in self.list_object_versions(bucket).await? {
            self.delete_object_version(bucket, &version.key, &version.version_id)
                .await?;
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
    async fn enable_bucket_versioning(
        &self,
        bucket: &str,
    ) -> std::result::Result<(), ProtocolS3Error>;
}

#[async_trait]
pub trait ActorS3ClientFactory: Send + Sync {
    type Client: ProtocolS3Port;

    async fn for_actor(&self, credential: &ActorCredential) -> anyhow::Result<Self::Client>;
}
