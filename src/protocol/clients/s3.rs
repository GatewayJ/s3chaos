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
    config::{
        ConfigBag, Intercept, Region, RuntimeComponents,
        interceptors::BeforeTransmitInterceptorContextMut, timeout::TimeoutConfig,
    },
    error::{BoxError, ProvideErrorMetadata, SdkError},
    primitives::ByteStream,
    types::{
        BucketVersioningStatus, CompletedMultipartUpload, CompletedPart as AwsCompletedPart,
        Delete, ObjectIdentifier, PublicAccessBlockConfiguration,
    },
};
use std::{fmt::Debug, time::Duration};

use crate::protocol::{
    credentials::{ActorCredential, AdminCredentials},
    ports::{
        ActorS3ClientFactory, ExclusiveBucketOwnership, ProtocolAuthorizationPort,
        ProtocolBucketConfigPort, ProtocolBucketPort, ProtocolCompletedPart,
        ProtocolListObjectsResult, ProtocolListingPort, ProtocolMultipartPort, ProtocolObjectPort,
        ProtocolObjectVersion, ProtocolPublicAccessBlock, ProtocolRequestShape,
        ProtocolS3CleanupPort, ProtocolS3Error, ProtocolVersioningPort,
    },
};

#[derive(Debug, Clone)]
pub struct ProtocolS3Client {
    client: Client,
}

#[derive(Debug, Clone)]
pub struct AwsS3ClientFactory {
    endpoint: String,
    region: String,
    admin: AdminCredentials,
}

impl AwsS3ClientFactory {
    pub fn new(
        endpoint: impl Into<String>,
        region: impl Into<String>,
        admin: AdminCredentials,
    ) -> Self {
        Self {
            endpoint: endpoint.into(),
            region: region.into(),
            admin,
        }
    }
}

/// Adds the case's extra headers before signing, so they travel inside the SigV4 signed-header
/// set the way a first-party client (for example the RustFS Console) sends them.
#[derive(Debug)]
struct RequestShapeInterceptor {
    shape: ProtocolRequestShape,
}

impl Intercept for RequestShapeInterceptor {
    fn name(&self) -> &'static str {
        "S3ChaosRequestShape"
    }

    fn modify_before_signing(
        &self,
        context: &mut BeforeTransmitInterceptorContextMut<'_>,
        _runtime_components: &RuntimeComponents,
        _cfg: &mut ConfigBag,
    ) -> std::result::Result<(), BoxError> {
        let headers = context.request_mut().headers_mut();
        for (name, value) in &self.shape.extra_headers {
            headers.try_insert(name.clone(), value.clone())?;
        }
        Ok(())
    }
}

impl ProtocolS3Client {
    pub async fn for_admin(
        endpoint: &str,
        region: &str,
        credentials: &AdminCredentials,
    ) -> Result<Self> {
        Self::for_admin_with_shape(
            endpoint,
            region,
            credentials,
            &ProtocolRequestShape::default(),
        )
        .await
    }

    pub async fn for_admin_with_shape(
        endpoint: &str,
        region: &str,
        credentials: &AdminCredentials,
        shape: &ProtocolRequestShape,
    ) -> Result<Self> {
        Self::new(
            endpoint,
            region,
            credentials.access_key(),
            credentials.secret_key(),
            credentials.session_token(),
            "s3chaos-protocol-admin-env",
            shape,
        )
        .await
    }

    pub async fn for_actor(
        endpoint: &str,
        region: &str,
        credential: &ActorCredential,
    ) -> Result<Self> {
        Self::for_actor_with_shape(
            endpoint,
            region,
            credential,
            &ProtocolRequestShape::default(),
        )
        .await
    }

    pub async fn for_actor_with_shape(
        endpoint: &str,
        region: &str,
        credential: &ActorCredential,
        shape: &ProtocolRequestShape,
    ) -> Result<Self> {
        Self::new(
            endpoint,
            region,
            credential.access_key(),
            credential.secret_key(),
            credential.session_token(),
            "s3chaos-protocol-generated-actor",
            shape,
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
        shape: &ProtocolRequestShape,
    ) -> Result<Self> {
        shape.validate()?;
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
        let mut builder = aws_sdk_s3::config::Builder::from(&shared)
            .force_path_style(true)
            .timeout_config(
                TimeoutConfig::builder()
                    .operation_timeout(Duration::from_secs(15))
                    .operation_attempt_timeout(Duration::from_secs(10))
                    .build(),
            );
        if !shape.extra_headers.is_empty() {
            builder = builder.interceptor(RequestShapeInterceptor {
                shape: shape.clone(),
            });
        }
        Ok(Self {
            client: Client::from_conf(builder.build()),
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

    pub async fn head_bucket(&self, bucket: &str) -> Result<(), ProtocolS3Error> {
        self.client
            .head_bucket()
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
        Ok(self.list_objects_v2_summary(bucket).await?.keys)
    }

    pub async fn list_objects_v2_summary(
        &self,
        bucket: &str,
    ) -> Result<ProtocolListObjectsResult, ProtocolS3Error> {
        let mut continuation = None;
        let mut keys = Vec::new();
        let mut key_count = 0usize;
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
            let page_key_count = output.key_count().ok_or_else(|| ProtocolS3Error {
                code: "MissingListObjectsV2KeyCount".to_string(),
                status: Some(200),
                request_id: None,
            })?;
            let page_key_count = usize::try_from(page_key_count).map_err(|_| ProtocolS3Error {
                code: "InvalidListObjectsV2KeyCount".to_string(),
                status: Some(200),
                request_id: None,
            })?;
            key_count = key_count
                .checked_add(page_key_count)
                .ok_or_else(|| ProtocolS3Error {
                    code: "InvalidListObjectsV2KeyCount".to_string(),
                    status: Some(200),
                    request_id: None,
                })?;
            if !output.is_truncated().unwrap_or(false) {
                break;
            }
            continuation = output.next_continuation_token().map(str::to_string);
            if continuation.is_none() {
                break;
            }
        }
        Ok(ProtocolListObjectsResult { keys, key_count })
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

    pub async fn copy_object(
        &self,
        bucket: &str,
        source_key: &str,
        destination_key: &str,
    ) -> Result<(), ProtocolS3Error> {
        self.client
            .copy_object()
            .bucket(bucket)
            .key(destination_key)
            .copy_source(format!("{bucket}/{source_key}"))
            .send()
            .await
            .map_err(|error| protocol_s3_error(&error))?;
        Ok(())
    }

    pub async fn delete_objects(
        &self,
        bucket: &str,
        keys: &[String],
    ) -> Result<Vec<String>, ProtocolS3Error> {
        let objects = keys
            .iter()
            .map(|key| {
                ObjectIdentifier::builder()
                    .key(key)
                    .build()
                    .map_err(|_| local_s3_error("BuildObjectIdentifier"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let delete = Delete::builder()
            .set_objects(Some(objects))
            .build()
            .map_err(|_| local_s3_error("BuildDeleteObjectsRequest"))?;
        let output = self
            .client
            .delete_objects()
            .bucket(bucket)
            .delete(delete)
            .send()
            .await
            .map_err(|error| protocol_s3_error(&error))?;
        if let Some(error) = output.errors().first() {
            return Err(ProtocolS3Error {
                code: error
                    .code()
                    .unwrap_or("DeleteObjectsEntryFailed")
                    .to_string(),
                status: Some(200),
                request_id: None,
            });
        }
        Ok(output
            .deleted()
            .iter()
            .filter_map(|deleted| deleted.key().map(str::to_string))
            .collect())
    }

    pub async fn create_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<String, ProtocolS3Error> {
        self.client
            .create_multipart_upload()
            .bucket(bucket)
            .key(key)
            .send()
            .await
            .map_err(|error| protocol_s3_error(&error))?
            .upload_id()
            .map(str::to_string)
            .ok_or_else(|| local_s3_error("MissingMultipartUploadId"))
    }

    pub async fn upload_part(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        part_number: i32,
        body: &[u8],
    ) -> Result<String, ProtocolS3Error> {
        self.client
            .upload_part()
            .bucket(bucket)
            .key(key)
            .upload_id(upload_id)
            .part_number(part_number)
            .body(ByteStream::from(body.to_vec()))
            .send()
            .await
            .map_err(|error| protocol_s3_error(&error))?
            .e_tag()
            .map(str::to_string)
            .ok_or_else(|| local_s3_error("MissingMultipartPartEtag"))
    }

    pub async fn complete_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        parts: &[ProtocolCompletedPart],
    ) -> Result<(), ProtocolS3Error> {
        let parts = parts
            .iter()
            .map(|part| {
                AwsCompletedPart::builder()
                    .part_number(part.part_number)
                    .e_tag(&part.etag)
                    .build()
            })
            .collect::<Vec<_>>();
        let upload = CompletedMultipartUpload::builder()
            .set_parts(Some(parts))
            .build();
        self.client
            .complete_multipart_upload()
            .bucket(bucket)
            .key(key)
            .upload_id(upload_id)
            .multipart_upload(upload)
            .send()
            .await
            .map_err(|error| protocol_s3_error(&error))?;
        Ok(())
    }

    pub async fn abort_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
    ) -> Result<(), ProtocolS3Error> {
        self.client
            .abort_multipart_upload()
            .bucket(bucket)
            .key(key)
            .upload_id(upload_id)
            .send()
            .await
            .map_err(|error| protocol_s3_error(&error))?;
        Ok(())
    }

    pub async fn list_multipart_uploads(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Vec<String>, ProtocolS3Error> {
        let mut key_marker = None;
        let mut upload_id_marker = None;
        let mut upload_ids = Vec::new();
        loop {
            let output = self
                .client
                .list_multipart_uploads()
                .bucket(bucket)
                .prefix(key)
                .set_key_marker(key_marker)
                .set_upload_id_marker(upload_id_marker)
                .send()
                .await
                .map_err(|error| protocol_s3_error(&error))?;
            upload_ids.extend(output.uploads().iter().filter_map(|upload| {
                (upload.key() == Some(key))
                    .then(|| upload.upload_id().map(str::to_string))
                    .flatten()
            }));
            if !output.is_truncated().unwrap_or(false) {
                break;
            }
            key_marker = output.next_key_marker().map(str::to_string);
            upload_id_marker = output.next_upload_id_marker().map(str::to_string);
            if key_marker.is_none() && upload_id_marker.is_none() {
                return Err(local_s3_error("InvalidMultipartUploadListing"));
            }
        }
        Ok(upload_ids)
    }

    pub async fn put_bucket_versioning(
        &self,
        bucket: &str,
        enabled: bool,
    ) -> Result<(), ProtocolS3Error> {
        self.client
            .put_bucket_versioning()
            .bucket(bucket)
            .versioning_configuration(
                aws_sdk_s3::types::VersioningConfiguration::builder()
                    .status(if enabled {
                        BucketVersioningStatus::Enabled
                    } else {
                        BucketVersioningStatus::Suspended
                    })
                    .build(),
            )
            .send()
            .await
            .map_err(|error| protocol_s3_error(&error))?;
        Ok(())
    }

    pub async fn get_object_version(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> Result<Vec<u8>, ProtocolS3Error> {
        let output = self
            .client
            .get_object()
            .bucket(bucket)
            .key(key)
            .version_id(version_id)
            .send()
            .await
            .map_err(|error| protocol_s3_error(&error))?;
        output
            .body
            .collect()
            .await
            .map(|body| body.into_bytes().to_vec())
            .map_err(|_| local_s3_error("ResponseBodyError"))
    }

    pub async fn put_public_access_block(
        &self,
        bucket: &str,
        configuration: ProtocolPublicAccessBlock,
    ) -> Result<(), ProtocolS3Error> {
        let configuration = PublicAccessBlockConfiguration::builder()
            .block_public_acls(configuration.block_public_acls)
            .ignore_public_acls(configuration.ignore_public_acls)
            .block_public_policy(configuration.block_public_policy)
            .restrict_public_buckets(configuration.restrict_public_buckets)
            .build();
        self.client
            .put_public_access_block()
            .bucket(bucket)
            .public_access_block_configuration(configuration)
            .send()
            .await
            .map_err(|error| protocol_s3_error(&error))?;
        Ok(())
    }

    pub async fn get_public_access_block(
        &self,
        bucket: &str,
    ) -> Result<ProtocolPublicAccessBlock, ProtocolS3Error> {
        let output = self
            .client
            .get_public_access_block()
            .bucket(bucket)
            .send()
            .await
            .map_err(|error| protocol_s3_error(&error))?;
        let configuration = output
            .public_access_block_configuration()
            .ok_or_else(|| local_s3_error("MissingPublicAccessBlockConfiguration"))?;
        Ok(ProtocolPublicAccessBlock {
            block_public_acls: configuration.block_public_acls().unwrap_or(false),
            ignore_public_acls: configuration.ignore_public_acls().unwrap_or(false),
            block_public_policy: configuration.block_public_policy().unwrap_or(false),
            restrict_public_buckets: configuration.restrict_public_buckets().unwrap_or(false),
        })
    }

    pub async fn delete_public_access_block(&self, bucket: &str) -> Result<(), ProtocolS3Error> {
        self.client
            .delete_public_access_block()
            .bucket(bucket)
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
}

#[async_trait::async_trait]
impl ProtocolBucketPort for ProtocolS3Client {
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

    async fn head_bucket(&self, bucket: &str) -> Result<(), ProtocolS3Error> {
        ProtocolS3Client::head_bucket(self, bucket).await
    }
}

#[async_trait::async_trait]
impl ProtocolAuthorizationPort for ProtocolS3Client {
    async fn put_bucket_policy(&self, bucket: &str, policy: &str) -> Result<(), ProtocolS3Error> {
        ProtocolS3Client::put_bucket_policy(self, bucket, policy).await
    }

    async fn get_bucket_policy(&self, bucket: &str) -> Result<String, ProtocolS3Error> {
        ProtocolS3Client::get_bucket_policy(self, bucket).await
    }

    async fn delete_bucket_policy(&self, bucket: &str) -> Result<(), ProtocolS3Error> {
        ProtocolS3Client::delete_bucket_policy(self, bucket).await
    }
}

#[async_trait::async_trait]
impl ProtocolListingPort for ProtocolS3Client {
    async fn list_objects(&self, bucket: &str) -> Result<Vec<String>, ProtocolS3Error> {
        ProtocolS3Client::list_objects(self, bucket).await
    }

    async fn list_objects_v2_summary(
        &self,
        bucket: &str,
    ) -> Result<ProtocolListObjectsResult, ProtocolS3Error> {
        ProtocolS3Client::list_objects_v2_summary(self, bucket).await
    }
}

#[async_trait::async_trait]
impl ProtocolObjectPort for ProtocolS3Client {
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

    async fn copy_object(
        &self,
        bucket: &str,
        source_key: &str,
        destination_key: &str,
    ) -> Result<(), ProtocolS3Error> {
        ProtocolS3Client::copy_object(self, bucket, source_key, destination_key).await
    }

    async fn delete_objects(
        &self,
        bucket: &str,
        keys: &[String],
    ) -> Result<Vec<String>, ProtocolS3Error> {
        ProtocolS3Client::delete_objects(self, bucket, keys).await
    }
}

#[async_trait::async_trait]
impl ProtocolMultipartPort for ProtocolS3Client {
    async fn create_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<String, ProtocolS3Error> {
        ProtocolS3Client::create_multipart_upload(self, bucket, key).await
    }

    async fn upload_part(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        part_number: i32,
        body: &[u8],
    ) -> Result<String, ProtocolS3Error> {
        ProtocolS3Client::upload_part(self, bucket, key, upload_id, part_number, body).await
    }

    async fn complete_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        parts: &[ProtocolCompletedPart],
    ) -> Result<(), ProtocolS3Error> {
        ProtocolS3Client::complete_multipart_upload(self, bucket, key, upload_id, parts).await
    }

    async fn abort_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
    ) -> Result<(), ProtocolS3Error> {
        ProtocolS3Client::abort_multipart_upload(self, bucket, key, upload_id).await
    }

    async fn list_multipart_uploads(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Vec<String>, ProtocolS3Error> {
        ProtocolS3Client::list_multipart_uploads(self, bucket, key).await
    }
}

#[async_trait::async_trait]
impl ProtocolVersioningPort for ProtocolS3Client {
    async fn put_bucket_versioning(
        &self,
        bucket: &str,
        enabled: bool,
    ) -> Result<(), ProtocolS3Error> {
        ProtocolS3Client::put_bucket_versioning(self, bucket, enabled).await
    }

    async fn get_object_version(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> Result<Vec<u8>, ProtocolS3Error> {
        ProtocolS3Client::get_object_version(self, bucket, key, version_id).await
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
}

#[async_trait::async_trait]
impl ProtocolBucketConfigPort for ProtocolS3Client {
    async fn put_public_access_block(
        &self,
        bucket: &str,
        configuration: ProtocolPublicAccessBlock,
    ) -> Result<(), ProtocolS3Error> {
        ProtocolS3Client::put_public_access_block(self, bucket, configuration).await
    }

    async fn get_public_access_block(
        &self,
        bucket: &str,
    ) -> Result<ProtocolPublicAccessBlock, ProtocolS3Error> {
        ProtocolS3Client::get_public_access_block(self, bucket).await
    }

    async fn delete_public_access_block(&self, bucket: &str) -> Result<(), ProtocolS3Error> {
        ProtocolS3Client::delete_public_access_block(self, bucket).await
    }
}

#[async_trait::async_trait]
impl ProtocolS3CleanupPort for ProtocolS3Client {
    async fn cleanup_bucket_names(&self, prefix: &str) -> Result<Vec<String>, ProtocolS3Error> {
        ProtocolS3Client::list_buckets_with_prefix(self, prefix).await
    }

    async fn cleanup_exclusive_bucket(
        &self,
        ownership: ExclusiveBucketOwnership<'_>,
        include_versions: bool,
    ) -> Result<(), ProtocolS3Error> {
        let bucket = ownership.bucket();
        if include_versions {
            for version in ProtocolS3Client::list_object_versions(self, bucket).await? {
                ProtocolS3Client::delete_object_version(
                    self,
                    bucket,
                    &version.key,
                    &version.version_id,
                )
                .await?;
            }
        }
        for key in ProtocolS3Client::list_objects(self, bucket).await? {
            ProtocolS3Client::delete_object(self, bucket, &key).await?;
        }
        ProtocolBucketPort::delete_bucket(self, bucket).await
    }

    async fn cleanup_object_prefix(
        &self,
        bucket: &str,
        prefix: &str,
        include_versions: bool,
    ) -> Result<(), ProtocolS3Error> {
        if include_versions {
            for version in ProtocolS3Client::list_object_versions(self, bucket)
                .await?
                .into_iter()
                .filter(|version| version.key.starts_with(prefix))
            {
                ProtocolS3Client::delete_object_version(
                    self,
                    bucket,
                    &version.key,
                    &version.version_id,
                )
                .await?;
            }
        }
        for key in ProtocolS3Client::list_objects(self, bucket)
            .await?
            .into_iter()
            .filter(|key| key.starts_with(prefix))
        {
            ProtocolS3Client::delete_object(self, bucket, &key).await?;
        }
        Ok(())
    }

    async fn cleanup_object_prefix_exists(
        &self,
        bucket: &str,
        prefix: &str,
        include_versions: bool,
    ) -> Result<bool, ProtocolS3Error> {
        if ProtocolS3Client::list_objects(self, bucket)
            .await?
            .iter()
            .any(|key| key.starts_with(prefix))
        {
            return Ok(true);
        }
        if !include_versions {
            return Ok(false);
        }
        Ok(ProtocolS3Client::list_object_versions(self, bucket)
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
        ProtocolMultipartPort::abort_multipart_upload(self, bucket, key, upload_id).await
    }

    async fn cleanup_multipart_upload_exists(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
    ) -> Result<bool, ProtocolS3Error> {
        Ok(
            ProtocolMultipartPort::list_multipart_uploads(self, bucket, key)
                .await?
                .iter()
                .any(|candidate| candidate == upload_id),
        )
    }

    async fn cleanup_delete_bucket_policy(&self, bucket: &str) -> Result<(), ProtocolS3Error> {
        ProtocolS3Client::delete_bucket_policy(self, bucket).await
    }

    async fn cleanup_bucket_policy_exists(&self, bucket: &str) -> Result<bool, ProtocolS3Error> {
        match ProtocolS3Client::get_bucket_policy(self, bucket).await {
            Ok(_) => Ok(true),
            Err(error) if matches!(error.code.as_str(), "NoSuchBucketPolicy" | "NoSuchBucket") => {
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }

    async fn cleanup_delete_public_access_block(
        &self,
        bucket: &str,
    ) -> Result<(), ProtocolS3Error> {
        ProtocolS3Client::delete_public_access_block(self, bucket).await
    }

    async fn cleanup_public_access_block_exists(
        &self,
        bucket: &str,
    ) -> Result<bool, ProtocolS3Error> {
        match ProtocolS3Client::get_public_access_block(self, bucket).await {
            Ok(_) => Ok(true),
            Err(error)
                if matches!(
                    error.code.as_str(),
                    "NoSuchPublicAccessBlockConfiguration" | "NoSuchBucket"
                ) =>
            {
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }
}

#[async_trait::async_trait]
impl ActorS3ClientFactory for AwsS3ClientFactory {
    type Client = ProtocolS3Client;

    async fn for_actor(&self, credential: &ActorCredential) -> Result<Self::Client> {
        ProtocolS3Client::for_actor(&self.endpoint, &self.region, credential).await
    }

    async fn for_actor_with_shape(
        &self,
        credential: &ActorCredential,
        shape: &ProtocolRequestShape,
    ) -> Result<Self::Client> {
        ProtocolS3Client::for_actor_with_shape(&self.endpoint, &self.region, credential, shape)
            .await
    }

    async fn for_admin_with_shape(&self, shape: &ProtocolRequestShape) -> Result<Self::Client> {
        ProtocolS3Client::for_admin_with_shape(&self.endpoint, &self.region, &self.admin, shape)
            .await
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

fn local_s3_error(code: &str) -> ProtocolS3Error {
    ProtocolS3Error {
        code: code.to_string(),
        status: None,
        request_id: None,
    }
}

#[cfg(test)]
mod tests {
    use super::{ProtocolS3Client, ProtocolS3Error};
    use crate::protocol::{credentials::ActorCredential, ports::ProtocolRequestShape};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    /// Accepts one HTTP/1.1 request, returns its head, and answers 204 so the SDK treats the
    /// exchange as a completed DeleteObject.
    async fn capture_one_request(listener: TcpListener) -> String {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut raw = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let read = socket.read(&mut chunk).await.expect("read request");
            assert!(read > 0, "client closed before sending a request head");
            raw.extend_from_slice(&chunk[..read]);
            if raw.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        socket
            .write_all(b"HTTP/1.1 204 No Content\r\nconnection: close\r\ncontent-length: 0\r\n\r\n")
            .await
            .expect("write response");
        socket.shutdown().await.expect("shutdown");
        String::from_utf8(raw).expect("ascii request head")
    }

    #[tokio::test]
    async fn request_shape_headers_reach_the_wire_inside_the_signed_header_set() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
        let capture = tokio::spawn(capture_one_request(listener));
        let credential =
            ActorCredential::generated("actor", "shaped-user", "resource-1").expect("credential");
        let shape =
            ProtocolRequestShape::with_header("X-Rustfs-Force-Delete", "true").expect("shape");
        let client =
            ProtocolS3Client::for_actor_with_shape(&endpoint, "us-east-1", &credential, &shape)
                .await
                .expect("client");

        client
            .delete_object("bucket", "prefix/")
            .await
            .expect("204 completes DeleteObject");

        let head = capture.await.expect("capture task");
        let mut lines = head.lines();
        let request_line = lines.next().expect("request line");
        assert!(
            request_line.starts_with("DELETE /bucket/prefix/?x-id=DeleteObject HTTP/1.1")
                || request_line.starts_with("DELETE /bucket/prefix/ HTTP/1.1"),
            "{request_line}"
        );
        let headers = lines
            .map(|line| line.split_once(':').unwrap_or((line, "")))
            .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_string()))
            .collect::<Vec<_>>();
        assert!(
            headers
                .iter()
                .any(|(name, value)| name == "x-rustfs-force-delete" && value == "true"),
            "force-delete header missing from wire request: {head}"
        );
        let authorization = headers
            .iter()
            .find(|(name, _)| name == "authorization")
            .map(|(_, value)| value.as_str())
            .expect("SigV4 authorization header");
        let signed = authorization
            .split("SignedHeaders=")
            .nth(1)
            .and_then(|rest| rest.split(',').next())
            .expect("SignedHeaders list");
        assert!(
            signed
                .split(';')
                .any(|name| name == "x-rustfs-force-delete"),
            "force-delete header is not signed: {authorization}"
        );
    }

    #[tokio::test]
    async fn plain_clients_never_emit_request_shape_headers() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
        let capture = tokio::spawn(capture_one_request(listener));
        let credential =
            ActorCredential::generated("actor", "plain-user", "resource-1").expect("credential");
        let client = ProtocolS3Client::for_actor(&endpoint, "us-east-1", &credential)
            .await
            .expect("client");

        client
            .delete_object("bucket", "key")
            .await
            .expect("204 completes DeleteObject");

        let head = capture.await.expect("capture task").to_ascii_lowercase();
        assert!(!head.contains("x-rustfs-force-delete"), "{head}");
        assert!(!head.contains("x-minio-force-delete"), "{head}");
    }

    #[tokio::test]
    async fn invalid_request_shape_is_rejected_before_any_request() {
        let credential =
            ActorCredential::generated("actor", "shaped-user", "resource-1").expect("credential");
        let shape = ProtocolRequestShape {
            extra_headers: [("authorization".to_string(), "forged".to_string())].into(),
        };
        assert!(
            ProtocolS3Client::for_actor_with_shape(
                "http://127.0.0.1:9",
                "us-east-1",
                &credential,
                &shape
            )
            .await
            .is_err()
        );
    }

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
