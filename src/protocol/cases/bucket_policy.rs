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

use anyhow::{Result, anyhow, bail, ensure};
use serde_json::json;

use crate::protocol::{
    authorization::{
        ProtocolActorSource, ProtocolAuthorizationDimensions, ProtocolGrantSource,
        ProtocolPolicyEffect,
    },
    cases::{
        CaseContext, ProtocolCaseExecution,
        authz::{
            expect_access_denied, expect_error_class, expect_eventual_access_denied,
            expect_eventual_ok, expect_eventual_value,
        },
    },
    catalog::{
        BUCKET_POLICY_AUTHENTICATED_USER_RW, BUCKET_POLICY_DELETE_RESTORES_PRIVATE,
        BUCKET_POLICY_EXPLICIT_DENY_OVERRIDES_ALLOW, BUCKET_POLICY_MALFORMED_POLICY_REJECTED,
        BUCKET_POLICY_PREFIX_SCOPE,
    },
    credentials::ActorCredential,
    fixture::{
        naming::ProtocolResourceNamer,
        registry::{ResourceKind, ResourceRegistry, ResourceState},
    },
    ports::{ActorS3ClientFactory, ProtocolAdminPort, ProtocolS3Error, ProtocolS3Port},
    reporting::ProtocolAssertionClass,
};

pub(crate) async fn run_bucket_policy_case<F>(
    case_id: &str,
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    admin: &impl ProtocolAdminPort,
    admin_s3: &impl ProtocolS3Port,
    actor_clients: &F,
) -> ProtocolCaseExecution
where
    F: ActorS3ClientFactory,
{
    let mut context = CaseContext::new(case_id, bucket_policy_dimensions(case_id));
    let result = match case_id {
        BUCKET_POLICY_AUTHENTICATED_USER_RW => {
            run_authenticated_user_rw(
                namer,
                registry,
                admin,
                admin_s3,
                actor_clients,
                &mut context,
            )
            .await
        }
        BUCKET_POLICY_PREFIX_SCOPE => {
            run_prefix_scope(
                namer,
                registry,
                admin,
                admin_s3,
                actor_clients,
                &mut context,
            )
            .await
        }
        BUCKET_POLICY_EXPLICIT_DENY_OVERRIDES_ALLOW => {
            run_explicit_deny(
                namer,
                registry,
                admin,
                admin_s3,
                actor_clients,
                &mut context,
            )
            .await
        }
        BUCKET_POLICY_DELETE_RESTORES_PRIVATE => {
            run_delete_restores_private(
                namer,
                registry,
                admin,
                admin_s3,
                actor_clients,
                &mut context,
            )
            .await
        }
        BUCKET_POLICY_MALFORMED_POLICY_REJECTED => {
            run_malformed_policy_rejected(
                namer,
                registry,
                admin,
                admin_s3,
                actor_clients,
                &mut context,
            )
            .await
        }
        _ => Err(anyhow!("unsupported bucket-policy case {case_id}")),
    };
    context.finish(result)
}

fn bucket_policy_dimensions(case_id: &str) -> ProtocolAuthorizationDimensions {
    let policy_effect = match case_id {
        BUCKET_POLICY_EXPLICIT_DENY_OVERRIDES_ALLOW => ProtocolPolicyEffect::ExplicitDeny,
        BUCKET_POLICY_DELETE_RESTORES_PRIVATE => ProtocolPolicyEffect::DeletePolicy,
        BUCKET_POLICY_MALFORMED_POLICY_REJECTED => ProtocolPolicyEffect::Malformed,
        _ => ProtocolPolicyEffect::Allow,
    };
    ProtocolAuthorizationDimensions {
        actor_source: ProtocolActorSource::IamUser,
        grant_source: ProtocolGrantSource::BucketPolicy,
        policy_effect,
    }
}

async fn run_authenticated_user_rw<F>(
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    admin: &impl ProtocolAdminPort,
    admin_s3: &impl ProtocolS3Port,
    actor_clients: &F,
    context: &mut CaseContext,
) -> Result<()>
where
    F: ActorS3ClientFactory,
{
    let case_id = BUCKET_POLICY_AUTHENTICATED_USER_RW;
    let actor_user = namer.iam_user(case_id, 0)?;
    let unrelated_user = namer.iam_user(case_id, 1)?;
    let bucket = namer.bucket(case_id, 0)?;
    let object_key = format!("cases/{case_id}/actor/object-1");
    let object_body = b"s3chaos-protocol-bucket-policy-smoke";

    let actor_handle = registry.plan(ResourceKind::IamUser, &actor_user, case_id, Vec::new())?;
    let actor = ActorCredential::generated("authorized-user", &actor_user, &actor_handle.id)?;
    create_user(registry, &actor_handle.id, admin, &actor).await?;
    context.add_actor(actor);

    let unrelated_handle =
        registry.plan(ResourceKind::IamUser, &unrelated_user, case_id, Vec::new())?;
    let unrelated =
        ActorCredential::generated("unrelated-user", &unrelated_user, &unrelated_handle.id)?;
    create_user(registry, &unrelated_handle.id, admin, &unrelated).await?;
    context.add_actor(unrelated);

    let bucket_handle = registry.plan(ResourceKind::Bucket, &bucket, case_id, Vec::new())?;
    registry.transition(&bucket_handle.id, ResourceState::Creating, None)?;
    match admin_s3.create_bucket(&bucket).await {
        Ok(()) => registry.transition(&bucket_handle.id, ResourceState::Created, None)?,
        Err(error) => {
            let message = format_s3_error("create bucket", &error);
            registry.transition(
                &bucket_handle.id,
                ResourceState::Failed,
                Some(message.clone()),
            )?;
            bail!(message);
        }
    }

    let actor_s3 = actor_clients.for_actor(&context.actors[0]).await?;
    let unrelated_s3 = actor_clients.for_actor(&context.actors[1]).await?;

    context.current_phase = "assertion".to_string();
    expect_access_denied(
        context,
        "authorized-user",
        "list-objects-before-policy",
        &bucket,
        None,
        || async { actor_s3.list_objects(&bucket).await.map(|_| ()) },
    )
    .await?;
    expect_access_denied(
        context,
        "authorized-user",
        "put-object-before-policy",
        &bucket,
        Some(&object_key),
        || async { actor_s3.put_object(&bucket, &object_key, object_body).await },
    )
    .await?;

    context.current_phase = "propagation".to_string();
    let policy_handle = registry.plan(
        ResourceKind::BucketPolicy,
        &bucket,
        case_id,
        vec![bucket_handle.id.clone(), actor_handle.id.clone()],
    )?;
    registry.transition(&policy_handle.id, ResourceState::Creating, None)?;
    let policy = bucket_policy(&bucket, context.actors[0].access_key())?;
    match admin_s3.put_bucket_policy(&bucket, &policy).await {
        Ok(()) => registry.transition(&policy_handle.id, ResourceState::Created, None)?,
        Err(error) => {
            let message = format_s3_error("put bucket policy", &error);
            registry.transition(
                &policy_handle.id,
                ResourceState::Failed,
                Some(message.clone()),
            )?;
            bail!(message);
        }
    }

    expect_eventual_ok(
        context,
        "authorized-user",
        "list-objects-after-policy",
        &bucket,
        None,
        || async { actor_s3.list_objects(&bucket).await.map(|_| ()) },
    )
    .await?;

    context.current_phase = "assertion".to_string();
    let object_handle = registry.plan_object_prefix(
        &bucket,
        format!("cases/{case_id}/"),
        case_id,
        vec![bucket_handle.id.clone()],
    )?;
    registry.transition(&object_handle.id, ResourceState::Creating, None)?;
    expect_eventual_ok(
        context,
        "authorized-user",
        "put-object-after-policy",
        &bucket,
        Some(&object_key),
        || async { actor_s3.put_object(&bucket, &object_key, object_body).await },
    )
    .await?;
    registry.transition(&object_handle.id, ResourceState::Created, None)?;

    let read = expect_eventual_value(
        context,
        "authorized-user",
        "get-object-after-policy",
        &bucket,
        Some(&object_key),
        || async { actor_s3.get_object(&bucket, &object_key).await },
    )
    .await?;
    ensure!(read == object_body, "get-object returned unexpected body");

    expect_access_denied(
        context,
        "unrelated-user",
        "list-objects-without-grant",
        &bucket,
        None,
        || async { unrelated_s3.list_objects(&bucket).await.map(|_| ()) },
    )
    .await?;

    expect_eventual_ok(
        context,
        "authorized-user",
        "delete-object-after-policy",
        &bucket,
        Some(&object_key),
        || async { actor_s3.delete_object(&bucket, &object_key).await },
    )
    .await?;
    Ok(())
}

struct SingleActorFixture<C> {
    actor_handle_id: String,
    bucket_handle_id: String,
    bucket: String,
    actor_s3: C,
}

async fn setup_single_actor<F>(
    case_id: &str,
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    admin: &impl ProtocolAdminPort,
    admin_s3: &impl ProtocolS3Port,
    actor_clients: &F,
    context: &mut CaseContext,
) -> Result<SingleActorFixture<F::Client>>
where
    F: ActorS3ClientFactory,
{
    let actor_user = namer.iam_user(case_id, 0)?;
    let actor_handle = registry.plan(ResourceKind::IamUser, &actor_user, case_id, Vec::new())?;
    let actor = ActorCredential::generated("authorized-user", &actor_user, &actor_handle.id)?;
    create_user(registry, &actor_handle.id, admin, &actor).await?;
    let actor_s3 = actor_clients.for_actor(&actor).await?;
    context.add_actor(actor);

    let bucket = namer.bucket(case_id, 0)?;
    let bucket_handle = registry.plan(ResourceKind::Bucket, &bucket, case_id, Vec::new())?;
    create_bucket(registry, &bucket_handle.id, admin_s3, &bucket).await?;
    Ok(SingleActorFixture {
        actor_handle_id: actor_handle.id,
        bucket_handle_id: bucket_handle.id,
        bucket,
        actor_s3,
    })
}

async fn run_prefix_scope<F>(
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    admin: &impl ProtocolAdminPort,
    admin_s3: &impl ProtocolS3Port,
    actor_clients: &F,
    context: &mut CaseContext,
) -> Result<()>
where
    F: ActorS3ClientFactory,
{
    let case_id = BUCKET_POLICY_PREFIX_SCOPE;
    let fixture = setup_single_actor(
        case_id,
        namer,
        registry,
        admin,
        admin_s3,
        actor_clients,
        context,
    )
    .await?;
    let allowed_prefix = format!("cases/{case_id}/allowed/");
    let denied_prefix = format!("cases/{case_id}/denied/");
    let allowed_key = format!("{allowed_prefix}object-1");
    let denied_key = format!("{denied_prefix}object-1");
    let policy = prefix_policy(
        &fixture.bucket,
        context.actors[0].access_key(),
        &allowed_prefix,
    )?;
    put_registered_policy(case_id, registry, admin_s3, &fixture, &policy).await?;

    let objects = registry.plan_object_prefix(
        &fixture.bucket,
        format!("cases/{case_id}/"),
        case_id,
        vec![fixture.bucket_handle_id.clone()],
    )?;
    registry.transition(&objects.id, ResourceState::Creating, None)?;
    context.current_phase = "propagation".to_string();
    expect_eventual_ok(
        context,
        "authorized-user",
        "put-object-inside-allowed-prefix",
        &fixture.bucket,
        Some(&allowed_key),
        || async {
            fixture
                .actor_s3
                .put_object(&fixture.bucket, &allowed_key, b"allowed")
                .await
        },
    )
    .await?;
    registry.transition(&objects.id, ResourceState::Created, None)?;
    context.current_phase = "assertion".to_string();
    expect_access_denied(
        context,
        "authorized-user",
        "put-object-outside-allowed-prefix",
        &fixture.bucket,
        Some(&denied_key),
        || async {
            fixture
                .actor_s3
                .put_object(&fixture.bucket, &denied_key, b"denied")
                .await
        },
    )
    .await
}

async fn run_explicit_deny<F>(
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    admin: &impl ProtocolAdminPort,
    admin_s3: &impl ProtocolS3Port,
    actor_clients: &F,
    context: &mut CaseContext,
) -> Result<()>
where
    F: ActorS3ClientFactory,
{
    let case_id = BUCKET_POLICY_EXPLICIT_DENY_OVERRIDES_ALLOW;
    let fixture = setup_single_actor(
        case_id,
        namer,
        registry,
        admin,
        admin_s3,
        actor_clients,
        context,
    )
    .await?;
    let allowed_key = format!("cases/{case_id}/allowed/object-1");
    let denied_key = format!("cases/{case_id}/denied/object-1");
    let policy = explicit_deny_policy(
        &fixture.bucket,
        context.actors[0].access_key(),
        &format!("cases/{case_id}/denied/*"),
    )?;
    put_registered_policy(case_id, registry, admin_s3, &fixture, &policy).await?;
    let objects = registry.plan_object_prefix(
        &fixture.bucket,
        format!("cases/{case_id}/"),
        case_id,
        vec![fixture.bucket_handle_id.clone()],
    )?;
    registry.transition(&objects.id, ResourceState::Creating, None)?;
    context.current_phase = "propagation".to_string();
    expect_eventual_ok(
        context,
        "authorized-user",
        "put-object-covered-by-allow",
        &fixture.bucket,
        Some(&allowed_key),
        || async {
            fixture
                .actor_s3
                .put_object(&fixture.bucket, &allowed_key, b"allowed")
                .await
        },
    )
    .await?;
    registry.transition(&objects.id, ResourceState::Created, None)?;
    context.current_phase = "assertion".to_string();
    expect_access_denied(
        context,
        "authorized-user",
        "put-object-covered-by-explicit-deny",
        &fixture.bucket,
        Some(&denied_key),
        || async {
            fixture
                .actor_s3
                .put_object(&fixture.bucket, &denied_key, b"denied")
                .await
        },
    )
    .await
}

async fn run_delete_restores_private<F>(
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    admin: &impl ProtocolAdminPort,
    admin_s3: &impl ProtocolS3Port,
    actor_clients: &F,
    context: &mut CaseContext,
) -> Result<()>
where
    F: ActorS3ClientFactory,
{
    let case_id = BUCKET_POLICY_DELETE_RESTORES_PRIVATE;
    let fixture = setup_single_actor(
        case_id,
        namer,
        registry,
        admin,
        admin_s3,
        actor_clients,
        context,
    )
    .await?;
    let policy = bucket_policy(&fixture.bucket, context.actors[0].access_key())?;
    let policy_handle =
        put_registered_policy(case_id, registry, admin_s3, &fixture, &policy).await?;
    context.current_phase = "propagation".to_string();
    expect_eventual_ok(
        context,
        "authorized-user",
        "list-objects-before-policy-delete",
        &fixture.bucket,
        None,
        || async {
            fixture
                .actor_s3
                .list_objects(&fixture.bucket)
                .await
                .map(|_| ())
        },
    )
    .await?;
    registry.transition(&policy_handle.id, ResourceState::CleanupAttempted, None)?;
    admin_s3
        .delete_bucket_policy(&fixture.bucket)
        .await
        .map_err(|error| anyhow!(format_s3_error("delete bucket policy", &error)))?;
    registry.transition(&policy_handle.id, ResourceState::Cleaned, None)?;
    expect_eventual_access_denied(
        context,
        "authorized-user",
        "list-objects-after-policy-delete",
        &fixture.bucket,
        None,
        || async {
            fixture
                .actor_s3
                .list_objects(&fixture.bucket)
                .await
                .map(|_| ())
        },
    )
    .await
}

async fn run_malformed_policy_rejected<F>(
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    admin: &impl ProtocolAdminPort,
    admin_s3: &impl ProtocolS3Port,
    actor_clients: &F,
    context: &mut CaseContext,
) -> Result<()>
where
    F: ActorS3ClientFactory,
{
    let case_id = BUCKET_POLICY_MALFORMED_POLICY_REJECTED;
    let fixture = setup_single_actor(
        case_id,
        namer,
        registry,
        admin,
        admin_s3,
        actor_clients,
        context,
    )
    .await?;
    let policy_handle = registry.plan(
        ResourceKind::BucketPolicy,
        &fixture.bucket,
        case_id,
        vec![
            fixture.bucket_handle_id.clone(),
            fixture.actor_handle_id.clone(),
        ],
    )?;
    registry.transition(&policy_handle.id, ResourceState::Creating, None)?;
    context.current_phase = "assertion".to_string();
    context.dimensions.actor_source = ProtocolActorSource::Admin;
    let result = expect_error_class(
        context,
        "admin",
        "put-malformed-bucket-policy",
        &fixture.bucket,
        ProtocolAssertionClass::MalformedPolicy,
        || async {
            admin_s3
                .put_bucket_policy(
                    &fixture.bucket,
                    r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*"}]}"#,
                )
                .await
        },
    )
    .await;
    match &result {
        Ok(()) => registry.transition(
            &policy_handle.id,
            ResourceState::Failed,
            Some("malformed policy rejected; cleanup verifies no partial state".to_string()),
        )?,
        Err(error) => registry.transition(
            &policy_handle.id,
            ResourceState::Failed,
            Some(error.to_string()),
        )?,
    }
    result?;
    context.dimensions.actor_source = ProtocolActorSource::IamUser;
    expect_access_denied(
        context,
        "authorized-user",
        "list-objects-after-malformed-policy",
        &fixture.bucket,
        None,
        || async {
            fixture
                .actor_s3
                .list_objects(&fixture.bucket)
                .await
                .map(|_| ())
        },
    )
    .await
}

async fn create_bucket(
    registry: &mut ResourceRegistry,
    handle_id: &str,
    s3: &impl ProtocolS3Port,
    bucket: &str,
) -> Result<()> {
    registry.transition(handle_id, ResourceState::Creating, None)?;
    match s3.create_bucket(bucket).await {
        Ok(()) => registry.transition(handle_id, ResourceState::Created, None),
        Err(error) => {
            let message = format_s3_error("create bucket", &error);
            registry.transition(handle_id, ResourceState::Failed, Some(message.clone()))?;
            Err(anyhow!(message))
        }
    }
}

async fn put_registered_policy<C>(
    case_id: &str,
    registry: &mut ResourceRegistry,
    admin_s3: &impl ProtocolS3Port,
    fixture: &SingleActorFixture<C>,
    policy: &str,
) -> Result<crate::protocol::fixture::registry::ResourceHandle> {
    let handle = registry.plan(
        ResourceKind::BucketPolicy,
        &fixture.bucket,
        case_id,
        vec![
            fixture.bucket_handle_id.clone(),
            fixture.actor_handle_id.clone(),
        ],
    )?;
    registry.transition(&handle.id, ResourceState::Creating, None)?;
    match admin_s3.put_bucket_policy(&fixture.bucket, policy).await {
        Ok(()) => {
            registry.transition(&handle.id, ResourceState::Created, None)?;
            Ok(handle)
        }
        Err(error) => {
            let message = format_s3_error("put bucket policy", &error);
            registry.transition(&handle.id, ResourceState::Failed, Some(message.clone()))?;
            Err(anyhow!(message))
        }
    }
}

async fn create_user(
    registry: &mut ResourceRegistry,
    handle_id: &str,
    admin: &impl ProtocolAdminPort,
    credential: &ActorCredential,
) -> Result<()> {
    registry.transition(handle_id, ResourceState::Creating, None)?;
    match admin.create_user(credential).await {
        Ok(()) => registry.transition(handle_id, ResourceState::Created, None),
        Err(error) => {
            let message = format!("create IAM user failed: {error}");
            registry.transition(handle_id, ResourceState::Failed, Some(message.clone()))?;
            Err(anyhow!(message))
        }
    }
}

fn bucket_policy(bucket: &str, principal: &str) -> Result<String> {
    Ok(serde_json::to_string(&json!({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowBucketListing",
                "Effect": "Allow",
                "Principal": {"AWS": principal},
                "Action": ["s3:ListBucket"],
                "Resource": [format!("arn:aws:s3:::{bucket}")]
            },
            {
                "Sid": "AllowObjectReadWrite",
                "Effect": "Allow",
                "Principal": {"AWS": principal},
                "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                "Resource": [format!("arn:aws:s3:::{bucket}/*")]
            }
        ]
    }))?)
}

fn prefix_policy(bucket: &str, principal: &str, prefix: &str) -> Result<String> {
    Ok(serde_json::to_string(&json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowObjectWritesUnderPrefix",
            "Effect": "Allow",
            "Principal": {"AWS": principal},
            "Action": ["s3:PutObject", "s3:GetObject", "s3:DeleteObject"],
            "Resource": [format!("arn:aws:s3:::{bucket}/{prefix}*")]
        }]
    }))?)
}

fn explicit_deny_policy(bucket: &str, principal: &str, denied_pattern: &str) -> Result<String> {
    Ok(serde_json::to_string(&json!({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowAllObjectWrites",
                "Effect": "Allow",
                "Principal": {"AWS": principal},
                "Action": ["s3:PutObject"],
                "Resource": [format!("arn:aws:s3:::{bucket}/*")]
            },
            {
                "Sid": "DenyProtectedPrefixWrites",
                "Effect": "Deny",
                "Principal": {"AWS": principal},
                "Action": ["s3:PutObject"],
                "Resource": [format!("arn:aws:s3:::{bucket}/{denied_pattern}")]
            }
        ]
    }))?)
}

fn format_s3_error(action: &str, error: &ProtocolS3Error) -> String {
    format!(
        "{action} failed: code={} status={:?} request_id={:?}",
        error.code, error.status, error.request_id
    )
}

#[cfg(test)]
mod tests {
    use super::{bucket_policy, run_bucket_policy_case};
    use crate::protocol::{
        credentials::ActorCredential,
        fixture::{
            cleanup::cleanup_registered_resources,
            naming::ProtocolResourceNamer,
            registry::{ResourceKind, ResourceRegistry, ResourceState},
        },
        ports::{
            ActorS3ClientFactory, ProtocolAdminError, ProtocolAdminPort, ProtocolObjectVersion,
            ProtocolS3Error, ProtocolS3Port, ProtocolServerInfo,
        },
        reporting::ProtocolCaseStatus,
        suite_plan::TargetFingerprint,
    };
    use anyhow::Result;
    use async_trait::async_trait;
    use std::{
        collections::{BTreeMap, BTreeSet},
        sync::{Arc, Mutex},
    };

    #[derive(Debug, Default)]
    struct FakeTargetState {
        users: BTreeSet<String>,
        buckets: BTreeSet<String>,
        policies: BTreeMap<String, serde_json::Value>,
        objects: BTreeMap<(String, String), Vec<u8>>,
        fail_authorized_operations: bool,
        fail_bucket_create: bool,
    }

    #[derive(Debug, Clone)]
    struct FakeAdmin {
        state: Arc<Mutex<FakeTargetState>>,
    }

    #[derive(Debug, Clone)]
    struct FakeS3 {
        state: Arc<Mutex<FakeTargetState>>,
        actor: Option<String>,
    }

    #[derive(Debug, Clone)]
    struct FakeActorFactory {
        state: Arc<Mutex<FakeTargetState>>,
    }

    #[async_trait]
    impl ProtocolAdminPort for FakeAdmin {
        async fn server_info(&self) -> std::result::Result<ProtocolServerInfo, ProtocolAdminError> {
            Ok(ProtocolServerInfo {
                deployment_id: "fake-deployment".to_string(),
                mode: Some("test".to_string()),
                region: Some("us-east-1".to_string()),
            })
        }

        async fn users_with_prefix(
            &self,
            prefix: &str,
        ) -> std::result::Result<Vec<String>, ProtocolAdminError> {
            Ok(self
                .state
                .lock()
                .expect("state")
                .users
                .iter()
                .filter(|user| user.starts_with(prefix))
                .cloned()
                .collect())
        }

        async fn create_user(
            &self,
            credential: &ActorCredential,
        ) -> std::result::Result<(), ProtocolAdminError> {
            self.state
                .lock()
                .expect("state")
                .users
                .insert(credential.access_key().to_string());
            Ok(())
        }

        async fn remove_user(
            &self,
            access_key: &str,
        ) -> std::result::Result<(), ProtocolAdminError> {
            self.state.lock().expect("state").users.remove(access_key);
            Ok(())
        }
    }

    #[async_trait]
    impl ProtocolS3Port for FakeS3 {
        async fn list_buckets_with_prefix(
            &self,
            prefix: &str,
        ) -> std::result::Result<Vec<String>, ProtocolS3Error> {
            Ok(self
                .state
                .lock()
                .expect("state")
                .buckets
                .iter()
                .filter(|bucket| bucket.starts_with(prefix))
                .cloned()
                .collect())
        }

        async fn create_bucket(&self, bucket: &str) -> std::result::Result<(), ProtocolS3Error> {
            if self.state.lock().expect("state").fail_bucket_create {
                return Err(ProtocolS3Error {
                    code: "InjectedSetupFailure".to_string(),
                    status: Some(500),
                    request_id: Some("fake-request".to_string()),
                });
            }
            self.state
                .lock()
                .expect("state")
                .buckets
                .insert(bucket.to_string());
            Ok(())
        }

        async fn delete_bucket(&self, bucket: &str) -> std::result::Result<(), ProtocolS3Error> {
            self.state.lock().expect("state").buckets.remove(bucket);
            Ok(())
        }

        async fn put_bucket_policy(
            &self,
            bucket: &str,
            policy: &str,
        ) -> std::result::Result<(), ProtocolS3Error> {
            let policy: serde_json::Value =
                serde_json::from_str(policy).map_err(|_| ProtocolS3Error {
                    code: "MalformedPolicy".to_string(),
                    status: Some(400),
                    request_id: Some("fake-request".to_string()),
                })?;
            let valid_statements = policy["Statement"].as_array().is_some_and(|statements| {
                !statements.is_empty()
                    && statements.iter().all(|statement| {
                        statement.get("Action").is_some() && statement.get("Resource").is_some()
                    })
            });
            if !valid_statements {
                return Err(ProtocolS3Error {
                    code: "MalformedPolicy".to_string(),
                    status: Some(400),
                    request_id: Some("fake-request".to_string()),
                });
            }
            self.state
                .lock()
                .expect("state")
                .policies
                .insert(bucket.to_string(), policy);
            Ok(())
        }

        async fn delete_bucket_policy(
            &self,
            bucket: &str,
        ) -> std::result::Result<(), ProtocolS3Error> {
            self.state.lock().expect("state").policies.remove(bucket);
            Ok(())
        }

        async fn list_objects(
            &self,
            bucket: &str,
        ) -> std::result::Result<Vec<String>, ProtocolS3Error> {
            self.authorize("s3:ListBucket", bucket, None)?;
            Ok(self
                .state
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
            self.authorize("s3:PutObject", bucket, Some(key))?;
            self.state
                .lock()
                .expect("state")
                .objects
                .insert((bucket.to_string(), key.to_string()), body.to_vec());
            Ok(())
        }

        async fn get_object(
            &self,
            bucket: &str,
            key: &str,
        ) -> std::result::Result<Vec<u8>, ProtocolS3Error> {
            self.authorize("s3:GetObject", bucket, Some(key))?;
            self.state
                .lock()
                .expect("state")
                .objects
                .get(&(bucket.to_string(), key.to_string()))
                .cloned()
                .ok_or_else(not_found)
        }

        async fn delete_object(
            &self,
            bucket: &str,
            key: &str,
        ) -> std::result::Result<(), ProtocolS3Error> {
            self.authorize("s3:DeleteObject", bucket, Some(key))?;
            self.state
                .lock()
                .expect("state")
                .objects
                .remove(&(bucket.to_string(), key.to_string()));
            Ok(())
        }

        async fn list_object_versions(
            &self,
            _bucket: &str,
        ) -> std::result::Result<Vec<ProtocolObjectVersion>, ProtocolS3Error> {
            Ok(Vec::new())
        }

        async fn delete_object_version(
            &self,
            bucket: &str,
            key: &str,
            _version_id: &str,
        ) -> std::result::Result<(), ProtocolS3Error> {
            self.state
                .lock()
                .expect("state")
                .objects
                .remove(&(bucket.to_string(), key.to_string()));
            Ok(())
        }

        async fn enable_bucket_versioning(
            &self,
            _bucket: &str,
        ) -> std::result::Result<(), ProtocolS3Error> {
            Ok(())
        }
    }

    impl FakeS3 {
        fn authorize(
            &self,
            action: &str,
            bucket: &str,
            key: Option<&str>,
        ) -> std::result::Result<(), ProtocolS3Error> {
            let state = self.state.lock().expect("state");
            let Some(actor) = self.actor.as_deref() else {
                return Ok(());
            };
            let Some(policy) = state.policies.get(bucket) else {
                return Err(access_denied());
            };
            if state.fail_authorized_operations {
                let principal_matches = policy["Statement"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|statement| statement["Principal"]["AWS"].as_str() == Some(actor));
                if principal_matches {
                    return Err(ProtocolS3Error {
                        code: "InjectedFailure".to_string(),
                        status: Some(500),
                        request_id: Some("fake-request".to_string()),
                    });
                }
            }
            let resource = key.map_or_else(
                || format!("arn:aws:s3:::{bucket}"),
                |key| format!("arn:aws:s3:::{bucket}/{key}"),
            );
            let mut allowed = false;
            for statement in policy["Statement"].as_array().into_iter().flatten() {
                if statement["Principal"]["AWS"].as_str() != Some(actor)
                    || !array_contains(&statement["Action"], action)
                    || !array_matches_resource(&statement["Resource"], &resource)
                {
                    continue;
                }
                match statement["Effect"].as_str() {
                    Some("Deny") => return Err(access_denied()),
                    Some("Allow") => allowed = true,
                    _ => {}
                }
            }
            if allowed {
                Ok(())
            } else {
                Err(access_denied())
            }
        }
    }

    fn array_contains(value: &serde_json::Value, expected: &str) -> bool {
        value
            .as_array()
            .into_iter()
            .flatten()
            .any(|value| value.as_str() == Some(expected))
    }

    fn array_matches_resource(value: &serde_json::Value, resource: &str) -> bool {
        value
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_str)
            .any(|pattern| {
                pattern
                    .strip_suffix('*')
                    .map_or(pattern == resource, |prefix| resource.starts_with(prefix))
            })
    }

    #[async_trait]
    impl ActorS3ClientFactory for FakeActorFactory {
        type Client = FakeS3;

        async fn for_actor(&self, credential: &ActorCredential) -> Result<Self::Client> {
            Ok(FakeS3 {
                state: self.state.clone(),
                actor: Some(credential.access_key().to_string()),
            })
        }
    }

    fn access_denied() -> ProtocolS3Error {
        ProtocolS3Error {
            code: "AccessDenied".to_string(),
            status: Some(403),
            request_id: Some("fake-request".to_string()),
        }
    }

    fn not_found() -> ProtocolS3Error {
        ProtocolS3Error {
            code: "NoSuchKey".to_string(),
            status: Some(404),
            request_id: Some("fake-request".to_string()),
        }
    }

    #[test]
    fn bucket_policy_scopes_principal_and_bucket() {
        let policy = bucket_policy("bucket", "generated-user").expect("policy");
        let value: serde_json::Value = serde_json::from_str(&policy).expect("json");
        assert_eq!(value["Statement"][0]["Principal"]["AWS"], "generated-user");
        assert_eq!(
            value["Statement"][1]["Resource"][0],
            "arn:aws:s3:::bucket/*"
        );
    }

    #[tokio::test]
    async fn case_closes_resources_after_success() {
        let (status, failure_phase, cleanup_succeeded, state_empty) = run_fake_case(
            crate::protocol::catalog::BUCKET_POLICY_AUTHENTICATED_USER_RW,
            false,
            false,
        )
        .await;
        assert_eq!(status, ProtocolCaseStatus::Passed);
        assert_eq!(failure_phase, None);
        assert!(cleanup_succeeded);
        assert!(state_empty);
    }

    #[tokio::test]
    async fn assertion_failure_still_closes_resources() {
        let (status, failure_phase, cleanup_succeeded, state_empty) = run_fake_case(
            crate::protocol::catalog::BUCKET_POLICY_AUTHENTICATED_USER_RW,
            true,
            false,
        )
        .await;
        assert_eq!(status, ProtocolCaseStatus::Failed);
        assert_eq!(failure_phase.as_deref(), Some("propagation"));
        assert!(cleanup_succeeded);
        assert!(state_empty);
    }

    #[tokio::test]
    async fn setup_failure_still_closes_planned_resources() {
        let (status, failure_phase, cleanup_succeeded, state_empty) = run_fake_case(
            crate::protocol::catalog::BUCKET_POLICY_PREFIX_SCOPE,
            false,
            true,
        )
        .await;
        assert_eq!(status, ProtocolCaseStatus::Failed);
        assert_eq!(failure_phase.as_deref(), Some("setup"));
        assert!(cleanup_succeeded);
        assert!(state_empty);
    }

    #[tokio::test]
    async fn every_bucket_policy_case_passes_and_cleans_resources() {
        for case_id in [
            crate::protocol::catalog::BUCKET_POLICY_AUTHENTICATED_USER_RW,
            crate::protocol::catalog::BUCKET_POLICY_DELETE_RESTORES_PRIVATE,
            crate::protocol::catalog::BUCKET_POLICY_EXPLICIT_DENY_OVERRIDES_ALLOW,
            crate::protocol::catalog::BUCKET_POLICY_MALFORMED_POLICY_REJECTED,
            crate::protocol::catalog::BUCKET_POLICY_PREFIX_SCOPE,
        ] {
            let (status, failure_phase, cleanup_succeeded, state_empty) =
                run_fake_case(case_id, false, false).await;
            assert_eq!(status, ProtocolCaseStatus::Passed, "case {case_id}");
            assert_eq!(failure_phase, None, "case {case_id}");
            assert!(cleanup_succeeded, "case {case_id}");
            assert!(state_empty, "case {case_id}");
        }
    }

    #[tokio::test]
    async fn neighboring_authz_cases_do_not_share_grants_or_cleanup_scope() {
        let state = Arc::new(Mutex::new(FakeTargetState::default()));
        let admin = FakeAdmin {
            state: state.clone(),
        };
        let admin_s3 = FakeS3 {
            state: state.clone(),
            actor: None,
        };
        let factory = FakeActorFactory {
            state: state.clone(),
        };
        let first_dir = tempfile::tempdir().expect("first tempdir");
        let second_dir = tempfile::tempdir().expect("second tempdir");
        let fingerprint = TargetFingerprint::new(
            "http://127.0.0.1:9000",
            "us-east-1",
            "fake-deployment",
            None,
            None,
        )
        .expect("fingerprint");
        let mut first_registry =
            ResourceRegistry::create(first_dir.path(), "run", fingerprint.clone())
                .expect("first registry");
        let mut second_registry = ResourceRegistry::create(second_dir.path(), "run", fingerprint)
            .expect("second registry");
        let namer = ProtocolResourceNamer::new("s3c", "s3chaos", "run").expect("namer");
        let first_namer = namer.for_worker(0);
        let second_namer = namer.for_worker(1);

        let (first, second) = tokio::join!(
            run_bucket_policy_case(
                crate::protocol::catalog::BUCKET_POLICY_AUTHENTICATED_USER_RW,
                &first_namer,
                &mut first_registry,
                &admin,
                &admin_s3,
                &factory,
            ),
            run_bucket_policy_case(
                crate::protocol::catalog::BUCKET_POLICY_PREFIX_SCOPE,
                &second_namer,
                &mut second_registry,
                &admin,
                &admin_s3,
                &factory,
            )
        );
        assert_eq!(first.report.status, ProtocolCaseStatus::Passed);
        assert_eq!(second.report.status, ProtocolCaseStatus::Passed);

        let second_names = second_registry
            .resources
            .iter()
            .map(|resource| (resource.kind, resource.name.clone()))
            .collect::<Vec<_>>();
        let first_cleanup =
            cleanup_registered_resources(&mut first_registry, &admin, &admin_s3).await;
        assert!(first_cleanup.succeeded);
        {
            let current = state.lock().expect("state");
            for (kind, name) in &second_names {
                match kind {
                    ResourceKind::Bucket => assert!(current.buckets.contains(name)),
                    ResourceKind::BucketPolicy => assert!(current.policies.contains_key(name)),
                    ResourceKind::IamUser => assert!(current.users.contains(name)),
                    ResourceKind::ObjectPrefix => {}
                    other => panic!("unexpected bucket-policy resource {other:?}"),
                }
            }
        }

        let second_cleanup =
            cleanup_registered_resources(&mut second_registry, &admin, &admin_s3).await;
        assert!(second_cleanup.succeeded);
        let current = state.lock().expect("state");
        assert!(current.users.is_empty());
        assert!(current.buckets.is_empty());
        assert!(current.policies.is_empty());
        assert!(current.objects.is_empty());
    }

    #[tokio::test]
    async fn parallel_cleanup_keeps_case_registries_independent() {
        let state = Arc::new(Mutex::new(FakeTargetState::default()));
        let admin = FakeAdmin {
            state: state.clone(),
        };
        let admin_s3 = FakeS3 {
            state: state.clone(),
            actor: None,
        };
        let first_dir = tempfile::tempdir().expect("first tempdir");
        let second_dir = tempfile::tempdir().expect("second tempdir");
        let fingerprint = TargetFingerprint::new(
            "http://127.0.0.1:9000",
            "us-east-1",
            "fake-deployment",
            None,
            None,
        )
        .expect("fingerprint");
        let mut first_registry =
            ResourceRegistry::create(first_dir.path(), "run", fingerprint.clone())
                .expect("first registry");
        let mut second_registry = ResourceRegistry::create(second_dir.path(), "run", fingerprint)
            .expect("second registry");
        register_cleanup_fixture(&mut first_registry, &state, "first");
        register_cleanup_fixture(&mut second_registry, &state, "second");

        let (first, second) = tokio::join!(
            cleanup_registered_resources(&mut first_registry, &admin, &admin_s3),
            cleanup_registered_resources(&mut second_registry, &admin, &admin_s3)
        );
        assert!(first.succeeded);
        assert!(second.succeeded);
        assert!(first_registry.pending_cleanup().next().is_none());
        assert!(second_registry.pending_cleanup().next().is_none());
        let current = state.lock().expect("state");
        assert!(current.users.is_empty());
        assert!(current.buckets.is_empty());
        assert!(current.policies.is_empty());
    }

    fn register_cleanup_fixture(
        registry: &mut ResourceRegistry,
        state: &Arc<Mutex<FakeTargetState>>,
        suffix: &str,
    ) {
        let user_name = format!("user-{suffix}");
        let bucket_name = format!("bucket-{suffix}");
        let user = registry
            .plan(ResourceKind::IamUser, &user_name, suffix, Vec::new())
            .expect("user plan");
        registry
            .transition(&user.id, ResourceState::Creating, None)
            .expect("user creating");
        registry
            .transition(&user.id, ResourceState::Created, None)
            .expect("user created");
        let bucket = registry
            .plan(ResourceKind::Bucket, &bucket_name, suffix, Vec::new())
            .expect("bucket plan");
        registry
            .transition(&bucket.id, ResourceState::Creating, None)
            .expect("bucket creating");
        registry
            .transition(&bucket.id, ResourceState::Created, None)
            .expect("bucket created");
        let policy = registry
            .plan(
                ResourceKind::BucketPolicy,
                &bucket_name,
                suffix,
                vec![bucket.id.clone(), user.id],
            )
            .expect("policy plan");
        registry
            .transition(&policy.id, ResourceState::Creating, None)
            .expect("policy creating");
        registry
            .transition(&policy.id, ResourceState::Created, None)
            .expect("policy created");

        let mut current = state.lock().expect("state");
        current.users.insert(user_name);
        current.buckets.insert(bucket_name.clone());
        current
            .policies
            .insert(bucket_name, serde_json::json!({"Statement": []}));
    }

    async fn run_fake_case(
        case_id: &str,
        fail_authorized_operations: bool,
        fail_bucket_create: bool,
    ) -> (ProtocolCaseStatus, Option<String>, bool, bool) {
        let state = Arc::new(Mutex::new(FakeTargetState {
            fail_authorized_operations,
            fail_bucket_create,
            ..FakeTargetState::default()
        }));
        let admin = FakeAdmin {
            state: state.clone(),
        };
        let admin_s3 = FakeS3 {
            state: state.clone(),
            actor: None,
        };
        let factory = FakeActorFactory {
            state: state.clone(),
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let fingerprint = TargetFingerprint::new(
            "http://127.0.0.1:9000",
            "us-east-1",
            "fake-deployment",
            None,
            None,
        )
        .expect("fingerprint");
        let mut registry =
            ResourceRegistry::create(dir.path(), "run", fingerprint).expect("registry");
        let namer = ProtocolResourceNamer::new("s3c", "s3chaos", "run").expect("namer");

        let execution =
            run_bucket_policy_case(case_id, &namer, &mut registry, &admin, &admin_s3, &factory)
                .await;
        let cleanup = cleanup_registered_resources(&mut registry, &admin, &admin_s3).await;
        let state = state.lock().expect("state");
        let state_empty = state.users.is_empty()
            && state.buckets.is_empty()
            && state.policies.is_empty()
            && state.objects.is_empty()
            && registry.pending_cleanup().next().is_none();
        (
            execution.report.status,
            execution.report.failure_phase,
            cleanup.succeeded,
            state_empty,
        )
    }
}
