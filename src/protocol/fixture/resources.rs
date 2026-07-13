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
    ports::{ActorS3ClientFactory, ProtocolAdminPort, ProtocolS3Port},
};

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
    admin: &impl ProtocolAdminPort,
    admin_s3: &impl ProtocolS3Port,
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
    admin: &impl ProtocolAdminPort,
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
