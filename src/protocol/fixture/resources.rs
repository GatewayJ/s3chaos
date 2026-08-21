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

use anyhow::{Result, anyhow};

use crate::protocol::{
    credentials::ActorCredential,
    fixture::{
        naming::ProtocolResourceNamer,
        registry::{ResourceHandle, ResourceKind, ResourceRegistry, ResourceState},
    },
    ports::{
        ActorS3ClientFactory, ProtocolBucketConfigPort, ProtocolBucketPort,
        ProtocolIdentityAdminPort, ProtocolMultipartPort, ProtocolPolicyAdminPort,
        ProtocolPublicAccessBlock,
    },
};

pub(crate) struct S3BucketFixture {
    handle: ResourceHandle,
}

pub(crate) struct ObjectPrefixFixture {
    handle: ResourceHandle,
}

pub(crate) struct MultipartUploadFixture {
    handle: ResourceHandle,
    pub(crate) upload_id: String,
}

pub(crate) struct PublicAccessBlockFixture {
    handle: ResourceHandle,
}

pub(crate) async fn create_s3_bucket(
    case_id: &str,
    bucket: &str,
    registry: &mut ResourceRegistry,
    s3: &impl ProtocolBucketPort,
) -> Result<S3BucketFixture> {
    let handle = registry.plan(ResourceKind::Bucket, bucket, case_id, Vec::new())?;
    transition_external(registry, &handle, "create bucket", s3.create_bucket(bucket)).await?;
    Ok(S3BucketFixture { handle })
}

pub(crate) fn plan_object_prefix(
    case_id: &str,
    bucket: &str,
    bucket_fixture: &S3BucketFixture,
    registry: &mut ResourceRegistry,
) -> Result<ObjectPrefixFixture> {
    let handle = registry.plan_object_prefix(
        bucket,
        format!("cases/{case_id}/"),
        case_id,
        vec![bucket_fixture.handle.id.clone()],
    )?;
    registry.transition(&handle.id, ResourceState::Creating, None)?;
    Ok(ObjectPrefixFixture { handle })
}

pub(crate) fn mark_object_prefix_created(
    registry: &mut ResourceRegistry,
    fixture: &ObjectPrefixFixture,
) -> Result<()> {
    registry.transition(&fixture.handle.id, ResourceState::Created, None)
}

pub(crate) fn enable_versioned_cleanup(registry: &mut ResourceRegistry) -> Result<()> {
    registry.set_versioned_cleanup(true)
}

pub(crate) async fn create_multipart_upload(
    case_id: &str,
    bucket: &str,
    key: &str,
    bucket_fixture: &S3BucketFixture,
    registry: &mut ResourceRegistry,
    s3: &impl ProtocolMultipartPort,
) -> Result<MultipartUploadFixture> {
    let handle = registry.plan_multipart_upload(
        bucket,
        key,
        case_id,
        vec![bucket_fixture.handle.id.clone()],
    )?;
    registry.transition(&handle.id, ResourceState::Creating, None)?;
    let upload_id = match s3.create_multipart_upload(bucket, key).await {
        Ok(upload_id) => upload_id,
        Err(error) => {
            return fail_resource(registry, &handle, "create multipart upload", error);
        }
    };
    // Persist the remote identifier before marking the resource created so replay cleanup can
    // still abort an upload if the process stops between these two registry writes.
    registry.set_multipart_upload_id(&handle.id, &upload_id)?;
    registry.transition(&handle.id, ResourceState::Created, None)?;
    Ok(MultipartUploadFixture { handle, upload_id })
}

pub(crate) fn mark_multipart_upload_completed(
    registry: &mut ResourceRegistry,
    fixture: &MultipartUploadFixture,
) -> Result<()> {
    registry.transition(&fixture.handle.id, ResourceState::CleanupAttempted, None)?;
    registry.transition(&fixture.handle.id, ResourceState::Cleaned, None)
}

pub(crate) async fn create_public_access_block(
    case_id: &str,
    bucket: &str,
    configuration: ProtocolPublicAccessBlock,
    bucket_fixture: &S3BucketFixture,
    registry: &mut ResourceRegistry,
    s3: &impl ProtocolBucketConfigPort,
) -> Result<PublicAccessBlockFixture> {
    let handle = registry.plan(
        ResourceKind::PublicAccessBlock,
        bucket,
        case_id,
        vec![bucket_fixture.handle.id.clone()],
    )?;
    transition_external(
        registry,
        &handle,
        "create public access block",
        s3.put_public_access_block(bucket, configuration),
    )
    .await?;
    Ok(PublicAccessBlockFixture { handle })
}

pub(crate) async fn delete_public_access_block(
    bucket: &str,
    fixture: &PublicAccessBlockFixture,
    registry: &mut ResourceRegistry,
    s3: &impl ProtocolBucketConfigPort,
) -> Result<()> {
    s3.delete_public_access_block(bucket).await?;
    registry.transition(&fixture.handle.id, ResourceState::CleanupAttempted, None)?;
    registry.transition(&fixture.handle.id, ResourceState::Cleaned, None)
}

fn fail_resource<T, E>(
    registry: &mut ResourceRegistry,
    handle: &ResourceHandle,
    action: &str,
    error: E,
) -> Result<T>
where
    E: std::fmt::Display,
{
    let message = format!("{action} failed: {error}");
    registry.transition(&handle.id, ResourceState::Failed, Some(message.clone()))?;
    Err(anyhow!(message))
}

pub(crate) struct IamFixture<C> {
    pub(crate) user_handle_id: String,
    pub(crate) bucket_handle_id: String,
    pub(crate) user: String,
    pub(crate) bucket: String,
    pub(crate) actor: ActorCredential,
    pub(crate) actor_s3: C,
}

pub(crate) async fn setup_user_bucket<F>(
    case_id: &str,
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    admin: &impl ProtocolIdentityAdminPort,
    admin_s3: &impl ProtocolBucketPort,
    actor_clients: &F,
) -> Result<IamFixture<F::Client>>
where
    F: ActorS3ClientFactory,
{
    let user = namer.iam_user(case_id, 0)?;
    let user_handle = registry.plan(ResourceKind::IamUser, &user, case_id, Vec::new())?;
    let actor = ActorCredential::generated("iam-user", &user, &user_handle.id)?;
    transition_external(
        registry,
        &user_handle,
        "create IAM user",
        admin.create_user(&actor),
    )
    .await?;
    let actor_s3 = actor_clients.for_actor(&actor).await?;

    let bucket = namer.bucket(case_id, 0)?;
    let bucket_handle = registry.plan(ResourceKind::Bucket, &bucket, case_id, Vec::new())?;
    transition_external(
        registry,
        &bucket_handle,
        "create bucket",
        admin_s3.create_bucket(&bucket),
    )
    .await?;
    Ok(IamFixture {
        user_handle_id: user_handle.id,
        bucket_handle_id: bucket_handle.id,
        user,
        bucket,
        actor,
        actor_s3,
    })
}

pub(crate) struct PolicyGrant<'a> {
    pub(crate) document: &'a str,
    pub(crate) principal: &'a str,
    pub(crate) is_group: bool,
    pub(crate) principal_dependency: &'a str,
}

pub(crate) async fn create_and_attach_policy(
    case_id: &str,
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    admin: &impl ProtocolPolicyAdminPort,
    grant: PolicyGrant<'_>,
) -> Result<(ResourceHandle, ResourceHandle)> {
    let policy = namer.iam_policy(case_id, 0)?;
    let policy_handle = registry.plan(ResourceKind::IamPolicy, &policy, case_id, Vec::new())?;
    transition_external(
        registry,
        &policy_handle,
        "create IAM policy",
        admin.create_policy(&policy, grant.document),
    )
    .await?;
    let attachment = registry.plan_policy_attachment(
        &policy,
        grant.principal,
        grant.is_group,
        case_id,
        vec![
            policy_handle.id.clone(),
            grant.principal_dependency.to_string(),
        ],
    )?;
    transition_external(
        registry,
        &attachment,
        "attach IAM policy",
        admin.attach_policy(&policy, grant.principal, grant.is_group),
    )
    .await?;
    Ok((policy_handle, attachment))
}

pub(crate) async fn transition_external<E, F>(
    registry: &mut ResourceRegistry,
    handle: &ResourceHandle,
    action: &str,
    operation: F,
) -> Result<()>
where
    E: std::fmt::Display,
    F: std::future::Future<Output = std::result::Result<(), E>>,
{
    registry.transition(&handle.id, ResourceState::Creating, None)?;
    match operation.await {
        Ok(()) => registry.transition(&handle.id, ResourceState::Created, None),
        Err(error) => {
            let message = format!("{action} failed: {error}");
            registry.transition(&handle.id, ResourceState::Failed, Some(message.clone()))?;
            Err(anyhow!(message))
        }
    }
}
