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

use anyhow::Result;
use aws_config::BehaviorVersion;
use aws_credential_types::Credentials;
use aws_sdk_s3::{
    Client,
    config::Region,
    error::{ProvideErrorMetadata, SdkError},
    primitives::ByteStream,
    types::{BucketVersioningStatus, VersioningConfiguration},
};
use std::fmt::Debug;

use crate::protocol::{
    credentials::{ActorCredential, AdminCredentials},
    ports::{ActorS3ClientFactory, ProtocolObjectVersion, ProtocolS3Error, ProtocolS3Port},
};

#[derive(Debug, Clone)]
pub struct ProtocolS3Client {
    client: Client,
}

#[derive(Debug, Clone)]
pub struct AwsS3ClientFactory {
    endpoint: String,
    region: String,
}

impl AwsS3ClientFactory {
    pub fn new(endpoint: impl Into<String>, region: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            region: region.into(),
        }
    }
}

impl ProtocolS3Client {
    pub async fn for_admin(
        endpoint: &str,
        region: &str,
        credentials: &AdminCredentials,
    ) -> Result<Self> {
        Self::new(
            endpoint,
            region,
            credentials.access_key(),
            credentials.secret_key(),
            credentials.session_token(),
            "s3chaos-protocol-admin-env",
        )
        .await
    }

    pub async fn for_actor(
        endpoint: &str,
        region: &str,
        credential: &ActorCredential,
    ) -> Result<Self> {
        Self::new(
            endpoint,
            region,
            credential.access_key(),
            credential.secret_key(),
            credential.session_token(),
            "s3chaos-protocol-generated-actor",
        )
        .await
    }

    async fn new(
        endpoint: &str,
        region: &str,
        access_key: &str,
        secret_key: &str,
        session_token: Option<&str>,
        provider_name: &'static str,
    ) -> Result<Self> {
        let credentials = Credentials::new(
            access_key,
            secret_key,
            session_token.map(str::to_string),
            None,
            provider_name,
        );
        let shared = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(region.to_string()))
            .credentials_provider(credentials)
            .endpoint_url(endpoint)
            .load()
            .await;
        let config = aws_sdk_s3::config::Builder::from(&shared)
            .force_path_style(true)
            .build();
        Ok(Self {
            client: Client::from_conf(config),
        })
    }

    pub async fn list_buckets_with_prefix(
        &self,
        prefix: &str,
    ) -> std::result::Result<Vec<String>, ProtocolS3Error> {
        let output = self
            .client
            .list_buckets()
            .send()
            .await
            .map_err(|error| protocol_s3_error(&error))?;
        Ok(output
            .buckets()
            .iter()
            .filter_map(|bucket| bucket.name())
            .filter(|name| name.starts_with(prefix))
            .map(str::to_string)
            .collect())
    }

    pub async fn create_bucket(&self, bucket: &str) -> Result<(), ProtocolS3Error> {
        self.client
            .create_bucket()
            .bucket(bucket)
            .send()
            .await
            .map_err(|error| protocol_s3_error(&error))?;
        Ok(())
    }

    pub async fn delete_bucket(&self, bucket: &str) -> Result<(), ProtocolS3Error> {
        self.client
            .delete_bucket()
            .bucket(bucket)
            .send()
            .await
            .map_err(|error| protocol_s3_error(&error))?;
        Ok(())
    }

    pub async fn put_bucket_policy(
        &self,
        bucket: &str,
        policy: &str,
    ) -> Result<(), ProtocolS3Error> {
        self.client
            .put_bucket_policy()
            .bucket(bucket)
            .policy(policy)
            .send()
            .await
            .map_err(|error| protocol_s3_error(&error))?;
        Ok(())
    }

    pub async fn get_bucket_policy(&self, bucket: &str) -> Result<String, ProtocolS3Error> {
        self.client
            .get_bucket_policy()
            .bucket(bucket)
            .send()
            .await
            .map_err(|error| protocol_s3_error(&error))?
            .policy()
            .map(str::to_string)
            .ok_or_else(|| ProtocolS3Error {
                code: "MissingBucketPolicyBody".to_string(),
                status: Some(200),
                request_id: None,
            })
    }

    pub async fn delete_bucket_policy(&self, bucket: &str) -> Result<(), ProtocolS3Error> {
        self.client
            .delete_bucket_policy()
            .bucket(bucket)
            .send()
            .await
            .map_err(|error| protocol_s3_error(&error))?;
        Ok(())
    }

    pub async fn list_objects(&self, bucket: &str) -> Result<Vec<String>, ProtocolS3Error> {
        let mut continuation = None;
        let mut keys = Vec::new();
        loop {
            let output = self
                .client
                .list_objects_v2()
                .bucket(bucket)
                .set_continuation_token(continuation)
                .send()
                .await
                .map_err(|error| protocol_s3_error(&error))?;
            keys.extend(
                output
                    .contents()
                    .iter()
                    .filter_map(|object| object.key().map(str::to_string)),
            );
            if !output.is_truncated().unwrap_or(false) {
                break;
            }
            continuation = output.next_continuation_token().map(str::to_string);
            if continuation.is_none() {
                break;
            }
        }
        Ok(keys)
    }

    pub async fn put_object(
        &self,
        bucket: &str,
        key: &str,
        body: &[u8],
    ) -> Result<(), ProtocolS3Error> {
        self.client
            .put_object()
            .bucket(bucket)
            .key(key)
            .body(ByteStream::from(body.to_vec()))
            .send()
            .await
            .map_err(|error| protocol_s3_error(&error))?;
        Ok(())
    }

    pub async fn get_object(&self, bucket: &str, key: &str) -> Result<Vec<u8>, ProtocolS3Error> {
        let output = self
            .client
            .get_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await
            .map_err(|error| protocol_s3_error(&error))?;
        output
            .body
            .collect()
            .await
            .map(|body| body.into_bytes().to_vec())
            .map_err(|_| ProtocolS3Error {
                code: "ResponseBodyError".to_string(),
                status: Some(200),
                request_id: None,
            })
    }

    pub async fn delete_object(&self, bucket: &str, key: &str) -> Result<(), ProtocolS3Error> {
        self.client
            .delete_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await
            .map_err(|error| protocol_s3_error(&error))?;
        Ok(())
    }

    pub async fn list_object_versions(
        &self,
        bucket: &str,
    ) -> std::result::Result<Vec<ProtocolObjectVersion>, ProtocolS3Error> {
        let mut key_marker = None;
        let mut version_id_marker = None;
        let mut entries = Vec::new();
        loop {
            let output = self
                .client
                .list_object_versions()
                .bucket(bucket)
                .set_key_marker(key_marker)
                .set_version_id_marker(version_id_marker)
                .send()
                .await
                .map_err(|error| protocol_s3_error(&error))?;
            for version in output.versions() {
                let Some(key) = version.key() else {
                    return Err(invalid_version_listing());
                };
                let Some(version_id) = version.version_id() else {
                    return Err(invalid_version_listing());
                };
                entries.push(ProtocolObjectVersion {
                    key: key.to_string(),
                    version_id: version_id.to_string(),
                    delete_marker: false,
                });
            }
            for marker in output.delete_markers() {
                let Some(key) = marker.key() else {
                    return Err(invalid_version_listing());
                };
                let Some(version_id) = marker.version_id() else {
                    return Err(invalid_version_listing());
                };
                entries.push(ProtocolObjectVersion {
                    key: key.to_string(),
                    version_id: version_id.to_string(),
                    delete_marker: true,
                });
            }
            if !output.is_truncated().unwrap_or(false) {
                break;
            }
            key_marker = output.next_key_marker().map(str::to_string);
            version_id_marker = output.next_version_id_marker().map(str::to_string);
            if key_marker.is_none() && version_id_marker.is_none() {
                return Err(invalid_version_listing());
            }
        }
        Ok(entries)
    }

    pub async fn delete_object_version(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> std::result::Result<(), ProtocolS3Error> {
        self.client
            .delete_object()
            .bucket(bucket)
            .key(key)
            .version_id(version_id)
            .send()
            .await
            .map_err(|error| protocol_s3_error(&error))?;
        Ok(())
    }

    pub async fn enable_bucket_versioning(
        &self,
        bucket: &str,
    ) -> std::result::Result<(), ProtocolS3Error> {
        self.client
            .put_bucket_versioning()
            .bucket(bucket)
            .versioning_configuration(
                VersioningConfiguration::builder()
                    .status(BucketVersioningStatus::Enabled)
                    .build(),
            )
            .send()
            .await
            .map_err(|error| protocol_s3_error(&error))?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl ProtocolS3Port for ProtocolS3Client {
    async fn list_buckets_with_prefix(
        &self,
        prefix: &str,
    ) -> std::result::Result<Vec<String>, ProtocolS3Error> {
        ProtocolS3Client::list_buckets_with_prefix(self, prefix).await
    }

    async fn create_bucket(&self, bucket: &str) -> Result<(), ProtocolS3Error> {
        ProtocolS3Client::create_bucket(self, bucket).await
    }

    async fn delete_bucket(&self, bucket: &str) -> Result<(), ProtocolS3Error> {
        ProtocolS3Client::delete_bucket(self, bucket).await
    }

    async fn put_bucket_policy(&self, bucket: &str, policy: &str) -> Result<(), ProtocolS3Error> {
        ProtocolS3Client::put_bucket_policy(self, bucket, policy).await
    }

    async fn get_bucket_policy(&self, bucket: &str) -> Result<String, ProtocolS3Error> {
        ProtocolS3Client::get_bucket_policy(self, bucket).await
    }

    async fn delete_bucket_policy(&self, bucket: &str) -> Result<(), ProtocolS3Error> {
        ProtocolS3Client::delete_bucket_policy(self, bucket).await
    }

    async fn list_objects(&self, bucket: &str) -> Result<Vec<String>, ProtocolS3Error> {
        ProtocolS3Client::list_objects(self, bucket).await
    }

    async fn put_object(
        &self,
        bucket: &str,
        key: &str,
        body: &[u8],
    ) -> Result<(), ProtocolS3Error> {
        ProtocolS3Client::put_object(self, bucket, key, body).await
    }

    async fn get_object(&self, bucket: &str, key: &str) -> Result<Vec<u8>, ProtocolS3Error> {
        ProtocolS3Client::get_object(self, bucket, key).await
    }

    async fn delete_object(&self, bucket: &str, key: &str) -> Result<(), ProtocolS3Error> {
        ProtocolS3Client::delete_object(self, bucket, key).await
    }

    async fn list_object_versions(
        &self,
        bucket: &str,
    ) -> std::result::Result<Vec<ProtocolObjectVersion>, ProtocolS3Error> {
        ProtocolS3Client::list_object_versions(self, bucket).await
    }

    async fn delete_object_version(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> std::result::Result<(), ProtocolS3Error> {
        ProtocolS3Client::delete_object_version(self, bucket, key, version_id).await
    }

    async fn enable_bucket_versioning(
        &self,
        bucket: &str,
    ) -> std::result::Result<(), ProtocolS3Error> {
        ProtocolS3Client::enable_bucket_versioning(self, bucket).await
    }
}

#[async_trait::async_trait]
impl ActorS3ClientFactory for AwsS3ClientFactory {
    type Client = ProtocolS3Client;

    async fn for_actor(&self, credential: &ActorCredential) -> Result<Self::Client> {
        ProtocolS3Client::for_actor(&self.endpoint, &self.region, credential).await
    }
}

fn protocol_s3_error<E>(error: &SdkError<E>) -> ProtocolS3Error
where
    E: ProvideErrorMetadata + Debug,
{
    let code = error
        .as_service_error()
        .and_then(ProvideErrorMetadata::code)
        .unwrap_or(match error {
            SdkError::TimeoutError(_) => "Timeout",
            SdkError::DispatchFailure(_) => "DispatchFailure",
            SdkError::ResponseError(_) => "ResponseError",
            SdkError::ConstructionFailure(_) => "ConstructionFailure",
            _ => "S3RequestFailed",
        })
        .to_string();
    let (status, request_id) = match error {
        SdkError::ServiceError(context) => (
            Some(context.raw().status().as_u16()),
            context
                .raw()
                .headers()
                .get("x-amz-request-id")
                .map(str::to_string),
        ),
        SdkError::ResponseError(context) => (
            Some(context.raw().status().as_u16()),
            context
                .raw()
                .headers()
                .get("x-amz-request-id")
                .map(str::to_string),
        ),
        _ => (None, None),
    };
    ProtocolS3Error {
        code,
        status,
        request_id,
    }
}

fn invalid_version_listing() -> ProtocolS3Error {
    ProtocolS3Error {
        code: "InvalidVersionListing".to_string(),
        status: Some(200),
        request_id: None,
    }
}

#[cfg(test)]
mod tests {
    use super::ProtocolS3Error;

    #[test]
    fn access_denied_requires_an_authorization_error_code() {
        assert!(
            ProtocolS3Error {
                code: "AccessDenied".to_string(),
                status: None,
                request_id: None,
            }
            .is_access_denied()
        );
        assert!(
            ProtocolS3Error {
                code: "Forbidden".to_string(),
                status: Some(403),
                request_id: None,
            }
            .is_access_denied()
        );
        for code in ["InvalidToken", "ExpiredToken", "SignatureDoesNotMatch"] {
            assert!(
                !ProtocolS3Error {
                    code: code.to_string(),
                    status: Some(403),
                    request_id: None,
                }
                .is_access_denied(),
                "{code} must not satisfy an authorization assertion"
            );
        }
    }
}
