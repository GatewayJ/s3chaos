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
use serde_json::json;
use std::time::Duration;

use crate::protocol::{
    authorization::{
        ProtocolActorSource, ProtocolAuthorizationDimensions, ProtocolGrantSource,
        ProtocolPolicyEffect,
    },
    cases::{
        CaseContext, ProtocolCaseExecution,
        authz::{expect_access_denied, expect_error_class, expect_eventual_ok},
    },
    catalog::{
        STS_ASSUME_ROLE_BASIC, STS_EXPIRED_TOKEN_DENIED, STS_SESSION_POLICY_DENY_PUT,
        STS_SESSION_POLICY_NARROWS_ROLE,
    },
    fixture::{
        naming::ProtocolResourceNamer,
        registry::{ResourceRegistry, ResourceState},
        resources::{IamFixture, PolicyGrant, create_and_attach_policy, setup_user_bucket},
    },
    ports::{
        ActorS3ClientFactory, ProtocolAssumeRoleRequest, ProtocolBucketPort,
        ProtocolIdentityAdminPort, ProtocolListingPort, ProtocolObjectPort,
        ProtocolPolicyAdminPort, ProtocolStsPort,
    },
    reporting::ProtocolAssertionClass,
};

#[cfg(not(test))]
const EXPIRING_SESSION_DURATION_SECONDS: u32 = 900;
#[cfg(test)]
const EXPIRING_SESSION_DURATION_SECONDS: u32 = 1;
#[cfg(not(test))]
const EXPIRATION_GRACE: Duration = Duration::from_secs(5);
#[cfg(test)]
const EXPIRATION_GRACE: Duration = Duration::from_millis(1);

pub(crate) async fn run_sts_case<F>(
    case_id: &str,
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    admin: &(impl ProtocolIdentityAdminPort + ProtocolPolicyAdminPort),
    admin_s3: &(impl ProtocolBucketPort + ProtocolObjectPort),
    sts: &impl ProtocolStsPort,
    actor_clients: &F,
) -> ProtocolCaseExecution
where
    F: ActorS3ClientFactory,
{
    let mut context = CaseContext::new(case_id, sts_dimensions(case_id));
    let result = match case_id {
        STS_ASSUME_ROLE_BASIC => {
            run_basic(
                namer,
                registry,
                admin,
                admin_s3,
                sts,
                actor_clients,
                &mut context,
            )
            .await
        }
        STS_SESSION_POLICY_NARROWS_ROLE => {
            run_narrowing(
                namer,
                registry,
                admin,
                admin_s3,
                sts,
                actor_clients,
                &mut context,
            )
            .await
        }
        STS_SESSION_POLICY_DENY_PUT => {
            run_deny_put(
                namer,
                registry,
                admin,
                admin_s3,
                sts,
                actor_clients,
                &mut context,
            )
            .await
        }
        STS_EXPIRED_TOKEN_DENIED => {
            run_expired_token(
                namer,
                registry,
                admin,
                admin_s3,
                sts,
                actor_clients,
                &mut context,
            )
            .await
        }
        _ => Err(anyhow!("unsupported STS case {case_id}")),
    };
    context.finish(result)
}

fn sts_dimensions(case_id: &str) -> ProtocolAuthorizationDimensions {
    if case_id == STS_ASSUME_ROLE_BASIC {
        ProtocolAuthorizationDimensions {
            actor_source: ProtocolActorSource::AssumedRole,
            grant_source: ProtocolGrantSource::ManagedPolicy,
            policy_effect: ProtocolPolicyEffect::Allow,
        }
    } else {
        ProtocolAuthorizationDimensions {
            actor_source: ProtocolActorSource::StsSession,
            grant_source: ProtocolGrantSource::SessionPolicy,
            policy_effect: ProtocolPolicyEffect::Allow,
        }
    }
}

async fn run_expired_token<F>(
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    admin: &(impl ProtocolIdentityAdminPort + ProtocolPolicyAdminPort),
    admin_s3: &(impl ProtocolBucketPort + ProtocolObjectPort),
    sts: &impl ProtocolStsPort,
    actor_clients: &F,
    context: &mut CaseContext,
) -> Result<()>
where
    F: ActorS3ClientFactory,
{
    let case_id = STS_EXPIRED_TOKEN_DENIED;
    let (fixture, session_s3) = setup_sts_fixture(
        case_id,
        registry,
        StsFixtureServices {
            namer,
            admin,
            admin_s3,
            sts,
            actor_clients,
        },
        context,
        SessionPolicySpec::None,
        EXPIRING_SESSION_DURATION_SECONDS,
    )
    .await?;
    context.current_phase = "expiration-wait".to_string();
    tokio::time::sleep(
        Duration::from_secs(EXPIRING_SESSION_DURATION_SECONDS as u64) + EXPIRATION_GRACE,
    )
    .await;
    context.current_phase = "assertion".to_string();
    expect_error_class(
        context,
        "sts-session",
        "list-bucket-with-expired-token",
        &fixture.bucket,
        ProtocolAssertionClass::ExpiredToken,
        || async { session_s3.list_objects(&fixture.bucket).await.map(|_| ()) },
    )
    .await
}

async fn run_basic<F>(
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    admin: &(impl ProtocolIdentityAdminPort + ProtocolPolicyAdminPort),
    admin_s3: &(impl ProtocolBucketPort + ProtocolObjectPort),
    sts: &impl ProtocolStsPort,
    actor_clients: &F,
    context: &mut CaseContext,
) -> Result<()>
where
    F: ActorS3ClientFactory,
{
    let case_id = STS_ASSUME_ROLE_BASIC;
    let (fixture, session_s3) = setup_sts_fixture(
        case_id,
        registry,
        StsFixtureServices {
            namer,
            admin,
            admin_s3,
            sts,
            actor_clients,
        },
        context,
        SessionPolicySpec::None,
        900,
    )
    .await?;
    let prefix = format!("cases/{case_id}/");
    let key = format!("{prefix}object");
    let objects = registry.plan_object_prefix(
        &fixture.bucket,
        &prefix,
        case_id,
        vec![fixture.bucket_handle_id.clone()],
    )?;
    registry.transition(&objects.id, ResourceState::Creating, None)?;
    context.current_phase = "propagation".to_string();
    expect_eventual_ok(
        context,
        "sts-session",
        "put-object-with-assumed-role",
        &fixture.bucket,
        Some(&key),
        || async {
            session_s3
                .put_object(&fixture.bucket, &key, b"sts-basic")
                .await
        },
    )
    .await?;
    registry.transition(&objects.id, ResourceState::Created, None)?;
    expect_eventual_ok(
        context,
        "sts-session",
        "get-object-with-assumed-role",
        &fixture.bucket,
        Some(&key),
        || async {
            session_s3
                .get_object(&fixture.bucket, &key)
                .await
                .map(|_| ())
        },
    )
    .await
}

async fn run_narrowing<F>(
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    admin: &(impl ProtocolIdentityAdminPort + ProtocolPolicyAdminPort),
    admin_s3: &(impl ProtocolBucketPort + ProtocolObjectPort),
    sts: &impl ProtocolStsPort,
    actor_clients: &F,
    context: &mut CaseContext,
) -> Result<()>
where
    F: ActorS3ClientFactory,
{
    let case_id = STS_SESSION_POLICY_NARROWS_ROLE;
    let allowed_prefix = format!("cases/{case_id}/allowed/");
    let (fixture, session_s3) = setup_sts_fixture(
        case_id,
        registry,
        StsFixtureServices {
            namer,
            admin,
            admin_s3,
            sts,
            actor_clients,
        },
        context,
        SessionPolicySpec::WritePrefix(&allowed_prefix),
        900,
    )
    .await?;
    let case_prefix = format!("cases/{case_id}/");
    let objects = registry.plan_object_prefix(
        &fixture.bucket,
        &case_prefix,
        case_id,
        vec![fixture.bucket_handle_id.clone()],
    )?;
    registry.transition(&objects.id, ResourceState::Creating, None)?;
    let allowed_key = format!("{allowed_prefix}object");
    context.current_phase = "propagation".to_string();
    expect_eventual_ok(
        context,
        "sts-session",
        "put-object-inside-session-policy-prefix",
        &fixture.bucket,
        Some(&allowed_key),
        || async {
            session_s3
                .put_object(&fixture.bucket, &allowed_key, b"allowed")
                .await
        },
    )
    .await?;
    registry.transition(&objects.id, ResourceState::Created, None)?;
    context.current_phase = "assertion".to_string();
    let denied_key = format!("{case_prefix}outside/object");
    expect_access_denied(
        context,
        "sts-session",
        "put-object-outside-session-policy-prefix",
        &fixture.bucket,
        Some(&denied_key),
        || async {
            session_s3
                .put_object(&fixture.bucket, &denied_key, b"denied")
                .await
        },
    )
    .await
}

async fn run_deny_put<F>(
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    admin: &(impl ProtocolIdentityAdminPort + ProtocolPolicyAdminPort),
    admin_s3: &(impl ProtocolBucketPort + ProtocolObjectPort),
    sts: &impl ProtocolStsPort,
    actor_clients: &F,
    context: &mut CaseContext,
) -> Result<()>
where
    F: ActorS3ClientFactory,
{
    let case_id = STS_SESSION_POLICY_DENY_PUT;
    let (fixture, session_s3) = setup_sts_fixture(
        case_id,
        registry,
        StsFixtureServices {
            namer,
            admin,
            admin_s3,
            sts,
            actor_clients,
        },
        context,
        SessionPolicySpec::ReadOnly,
        900,
    )
    .await?;
    let prefix = format!("cases/{case_id}/");
    let key = format!("{prefix}seed");
    let objects = registry.plan_object_prefix(
        &fixture.bucket,
        &prefix,
        case_id,
        vec![fixture.bucket_handle_id.clone()],
    )?;
    registry.transition(&objects.id, ResourceState::Creating, None)?;
    admin_s3.put_object(&fixture.bucket, &key, b"seed").await?;
    registry.transition(&objects.id, ResourceState::Created, None)?;
    context.current_phase = "propagation".to_string();
    expect_eventual_ok(
        context,
        "sts-session",
        "get-object-allowed-by-session-policy",
        &fixture.bucket,
        Some(&key),
        || async {
            session_s3
                .get_object(&fixture.bucket, &key)
                .await
                .map(|_| ())
        },
    )
    .await?;
    context.current_phase = "assertion".to_string();
    let denied_key = format!("{prefix}denied");
    expect_access_denied(
        context,
        "sts-session",
        "put-object-denied-by-session-policy",
        &fixture.bucket,
        Some(&denied_key),
        || async {
            session_s3
                .put_object(&fixture.bucket, &denied_key, b"denied")
                .await
        },
    )
    .await
}

enum SessionPolicySpec<'a> {
    None,
    WritePrefix(&'a str),
    ReadOnly,
}

struct StsFixtureServices<'a, A, S, T, F> {
    namer: &'a ProtocolResourceNamer,
    admin: &'a A,
    admin_s3: &'a S,
    sts: &'a T,
    actor_clients: &'a F,
}

async fn setup_sts_fixture<A, S, T, F>(
    case_id: &str,
    registry: &mut ResourceRegistry,
    services: StsFixtureServices<'_, A, S, T, F>,
    context: &mut CaseContext,
    session_policy_spec: SessionPolicySpec<'_>,
    duration_seconds: u32,
) -> Result<(IamFixture<F::Client>, F::Client)>
where
    A: ProtocolIdentityAdminPort + ProtocolPolicyAdminPort,
    S: ProtocolBucketPort,
    T: ProtocolStsPort,
    F: ActorS3ClientFactory,
{
    let fixture = setup_user_bucket(
        case_id,
        services.namer,
        registry,
        services.admin,
        services.admin_s3,
        services.actor_clients,
    )
    .await?;
    context.add_actor(fixture.actor.clone());
    let parent_policy = parent_policy(&fixture.bucket)?;
    let (_, attachment) = create_and_attach_policy(
        case_id,
        services.namer,
        registry,
        services.admin,
        PolicyGrant {
            document: &parent_policy,
            principal: &fixture.user,
            is_group: false,
            principal_dependency: &fixture.user_handle_id,
        },
    )
    .await?;
    let session_policy = match session_policy_spec {
        SessionPolicySpec::None => None,
        SessionPolicySpec::WritePrefix(prefix) => {
            Some(session_write_policy(&fixture.bucket, prefix)?)
        }
        SessionPolicySpec::ReadOnly => Some(session_read_policy(&fixture.bucket)?),
    };
    let session_handle = registry.plan_sts_session(
        &fixture.user,
        case_id,
        vec![fixture.user_handle_id.clone(), attachment.id],
    )?;
    registry.transition(&session_handle.id, ResourceState::Creating, None)?;
    let session = match services
        .sts
        .assume_role(
            &fixture.actor,
            &ProtocolAssumeRoleRequest {
                duration_seconds,
                session_policy,
            },
            &session_handle.id,
        )
        .await
    {
        Ok(session) => session,
        Err(error) => {
            let message = format!("AssumeRole failed: {error}");
            registry.transition(
                &session_handle.id,
                ResourceState::Failed,
                Some(message.clone()),
            )?;
            return Err(anyhow!(message));
        }
    };
    registry.transition(&session_handle.id, ResourceState::Created, None)?;
    context.add_actor(session.clone());
    let session_s3 = services.actor_clients.for_actor(&session).await?;
    Ok((fixture, session_s3))
}

fn parent_policy(bucket: &str) -> Result<String> {
    Ok(serde_json::to_string(&json!({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["sts:AssumeRole"]
            },
            {
                "Effect": "Allow",
                "Action": ["s3:ListBucket"],
                "Resource": [format!("arn:aws:s3:::{bucket}")]
            },
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                "Resource": [format!("arn:aws:s3:::{bucket}/*")]
            }
        ]
    }))?)
}

fn session_write_policy(bucket: &str, prefix: &str) -> Result<String> {
    Ok(serde_json::to_string(&json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:PutObject"],
            "Resource": [format!("arn:aws:s3:::{bucket}/{prefix}*")]
        }]
    }))?)
}

fn session_read_policy(bucket: &str) -> Result<String> {
    Ok(serde_json::to_string(&json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": [format!("arn:aws:s3:::{bucket}/*")]
        }]
    }))?)
}

#[cfg(test)]
mod tests {
    use super::{
        EXPIRING_SESSION_DURATION_SECONDS, parent_policy, run_sts_case, session_read_policy,
        session_write_policy,
    };
    use crate::protocol::{
        catalog::{
            STS_ASSUME_ROLE_BASIC, STS_EXPIRED_TOKEN_DENIED, STS_SESSION_POLICY_DENY_PUT,
            STS_SESSION_POLICY_NARROWS_ROLE,
        },
        credentials::ActorCredential,
        fixture::{
            cleanup::cleanup_registered_resources, naming::ProtocolResourceNamer,
            registry::ResourceRegistry,
        },
        ports::{
            ActorS3ClientFactory, ExclusiveBucketOwnership, ProtocolAdminCleanupPort,
            ProtocolAdminError, ProtocolAssumeRoleRequest, ProtocolBucketPort,
            ProtocolIdentityAdminPort, ProtocolListObjectsResult, ProtocolListingPort,
            ProtocolObjectPort, ProtocolPolicyAdminPort, ProtocolS3CleanupPort, ProtocolS3Error,
            ProtocolSessionAdminPort, ProtocolStsError, ProtocolStsPort,
        },
        reporting::ProtocolCaseStatus,
        suite_plan::TargetFingerprint,
    };
    use anyhow::Result;
    use async_trait::async_trait;
    use std::{
        collections::{BTreeMap, BTreeSet},
        fs,
        sync::{Arc, Mutex},
        time::Instant,
    };

    #[test]
    fn sts_parent_and_session_policies_are_scoped() {
        let parent = parent_policy("bucket").expect("parent");
        assert!(parent.contains("sts:AssumeRole"));
        let narrow = session_write_policy("bucket", "allowed/").expect("session");
        assert!(narrow.contains("arn:aws:s3:::bucket/allowed/*"));
        let read = session_read_policy("bucket").expect("read");
        assert!(read.contains("s3:GetObject"));
        assert!(!read.contains("s3:PutObject"));
    }

    #[derive(Clone)]
    struct SessionInfo {
        parent: String,
        policy: Option<serde_json::Value>,
        expires_at: Option<Instant>,
    }

    #[derive(Default)]
    struct State {
        users: BTreeSet<String>,
        policies: BTreeMap<String, serde_json::Value>,
        user_policies: BTreeMap<String, BTreeSet<String>>,
        sessions: BTreeMap<String, SessionInfo>,
        buckets: BTreeSet<String>,
        objects: BTreeMap<(String, String), Vec<u8>>,
        next_session: usize,
    }

    #[derive(Clone)]
    struct FakeAdmin(Arc<Mutex<State>>);

    #[derive(Clone)]
    struct FakeSts(Arc<Mutex<State>>);

    #[derive(Clone)]
    struct FakeS3 {
        state: Arc<Mutex<State>>,
        actor: Option<String>,
    }

    #[derive(Clone)]
    struct FakeActorFactory(Arc<Mutex<State>>);

    impl FakeAdmin {
        async fn users_with_prefix(
            &self,
            prefix: &str,
        ) -> std::result::Result<Vec<String>, ProtocolAdminError> {
            Ok(self
                .0
                .lock()
                .expect("state")
                .users
                .iter()
                .filter(|name| name.starts_with(prefix))
                .cloned()
                .collect())
        }

        async fn policies_with_prefix(
            &self,
            prefix: &str,
        ) -> std::result::Result<Vec<String>, ProtocolAdminError> {
            Ok(self
                .0
                .lock()
                .expect("state")
                .policies
                .keys()
                .filter(|name| name.starts_with(prefix))
                .cloned()
                .collect())
        }

        async fn create_user(
            &self,
            credential: &ActorCredential,
        ) -> std::result::Result<(), ProtocolAdminError> {
            self.0
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
            let mut state = self.0.lock().expect("state");
            state.users.remove(access_key);
            state.sessions.remove(access_key);
            state.user_policies.remove(access_key);
            Ok(())
        }

        async fn revoke_sts_sessions(
            &self,
            parent_access_key: &str,
        ) -> std::result::Result<(), ProtocolAdminError> {
            self.0
                .lock()
                .expect("state")
                .sessions
                .retain(|_, session| session.parent != parent_access_key);
            Ok(())
        }

        async fn sts_sessions_with_parent(
            &self,
            parent_access_key: &str,
        ) -> std::result::Result<Vec<String>, ProtocolAdminError> {
            Ok(self
                .0
                .lock()
                .expect("state")
                .sessions
                .iter()
                .filter(|(_, session)| session.parent == parent_access_key)
                .map(|(access_key, _)| access_key.clone())
                .collect())
        }

        async fn create_policy(
            &self,
            name: &str,
            document: &str,
        ) -> std::result::Result<(), ProtocolAdminError> {
            let policy = serde_json::from_str(document)
                .map_err(|_| ProtocolAdminError::protocol("MalformedPolicy"))?;
            self.0
                .lock()
                .expect("state")
                .policies
                .insert(name.to_string(), policy);
            Ok(())
        }

        async fn remove_policy(&self, name: &str) -> std::result::Result<(), ProtocolAdminError> {
            self.0.lock().expect("state").policies.remove(name);
            Ok(())
        }

        async fn attach_policy(
            &self,
            policy: &str,
            principal: &str,
            _is_group: bool,
        ) -> std::result::Result<(), ProtocolAdminError> {
            self.0
                .lock()
                .expect("state")
                .user_policies
                .entry(principal.to_string())
                .or_default()
                .insert(policy.to_string());
            Ok(())
        }

        async fn detach_policy(
            &self,
            policy: &str,
            principal: &str,
            _is_group: bool,
        ) -> std::result::Result<(), ProtocolAdminError> {
            let mut state = self.0.lock().expect("state");
            if let Some(policies) = state.user_policies.get_mut(principal) {
                policies.remove(policy);
                if policies.is_empty() {
                    state.user_policies.remove(principal);
                }
            }
            Ok(())
        }

        async fn policy_attached(
            &self,
            policy: &str,
            principal: &str,
            _is_group: bool,
        ) -> std::result::Result<bool, ProtocolAdminError> {
            Ok(self
                .0
                .lock()
                .expect("state")
                .user_policies
                .get(principal)
                .is_some_and(|policies| policies.contains(policy)))
        }
    }

    #[async_trait]
    impl ProtocolIdentityAdminPort for FakeAdmin {
        async fn users_with_prefix(&self, prefix: &str) -> Result<Vec<String>, ProtocolAdminError> {
            FakeAdmin::users_with_prefix(self, prefix).await
        }
        async fn create_user(
            &self,
            credential: &ActorCredential,
        ) -> Result<(), ProtocolAdminError> {
            FakeAdmin::create_user(self, credential).await
        }
        async fn remove_user(&self, access_key: &str) -> Result<(), ProtocolAdminError> {
            FakeAdmin::remove_user(self, access_key).await
        }
    }

    #[async_trait]
    impl ProtocolPolicyAdminPort for FakeAdmin {
        async fn policies_with_prefix(
            &self,
            prefix: &str,
        ) -> Result<Vec<String>, ProtocolAdminError> {
            FakeAdmin::policies_with_prefix(self, prefix).await
        }
        async fn create_policy(
            &self,
            name: &str,
            document: &str,
        ) -> Result<(), ProtocolAdminError> {
            FakeAdmin::create_policy(self, name, document).await
        }
        async fn remove_policy(&self, name: &str) -> Result<(), ProtocolAdminError> {
            FakeAdmin::remove_policy(self, name).await
        }
        async fn attach_policy(
            &self,
            policy: &str,
            principal: &str,
            is_group: bool,
        ) -> Result<(), ProtocolAdminError> {
            FakeAdmin::attach_policy(self, policy, principal, is_group).await
        }
        async fn detach_policy(
            &self,
            policy: &str,
            principal: &str,
            is_group: bool,
        ) -> Result<(), ProtocolAdminError> {
            FakeAdmin::detach_policy(self, policy, principal, is_group).await
        }
        async fn policy_attached(
            &self,
            policy: &str,
            principal: &str,
            is_group: bool,
        ) -> Result<bool, ProtocolAdminError> {
            FakeAdmin::policy_attached(self, policy, principal, is_group).await
        }
    }

    #[async_trait]
    impl ProtocolSessionAdminPort for FakeAdmin {
        async fn revoke_sts_sessions_for_provider(
            &self,
            parent_access_key: &str,
            _provider: &str,
        ) -> Result<(), ProtocolAdminError> {
            FakeAdmin::revoke_sts_sessions(self, parent_access_key).await
        }
        async fn sts_sessions_with_parent_for_provider(
            &self,
            parent_access_key: &str,
            _provider: &str,
        ) -> Result<Vec<String>, ProtocolAdminError> {
            FakeAdmin::sts_sessions_with_parent(self, parent_access_key).await
        }
    }

    #[async_trait]
    impl ProtocolAdminCleanupPort for FakeAdmin {
        async fn users_with_prefix(&self, prefix: &str) -> Result<Vec<String>, ProtocolAdminError> {
            FakeAdmin::users_with_prefix(self, prefix).await
        }
        async fn remove_user(&self, access_key: &str) -> Result<(), ProtocolAdminError> {
            FakeAdmin::remove_user(self, access_key).await
        }
        async fn groups_with_prefix(
            &self,
            _prefix: &str,
        ) -> Result<Vec<String>, ProtocolAdminError> {
            Ok(Vec::new())
        }
        async fn group_contains_member(
            &self,
            _group: &str,
            _member: &str,
        ) -> Result<bool, ProtocolAdminError> {
            Ok(false)
        }
        async fn update_group_members(
            &self,
            _group: &str,
            _members: &[String],
            _remove: bool,
        ) -> Result<(), ProtocolAdminError> {
            Ok(())
        }
        async fn remove_group(&self, _group: &str) -> Result<(), ProtocolAdminError> {
            Ok(())
        }
        async fn policies_with_prefix(
            &self,
            prefix: &str,
        ) -> Result<Vec<String>, ProtocolAdminError> {
            FakeAdmin::policies_with_prefix(self, prefix).await
        }
        async fn remove_policy(&self, name: &str) -> Result<(), ProtocolAdminError> {
            FakeAdmin::remove_policy(self, name).await
        }
        async fn detach_policy(
            &self,
            policy: &str,
            principal: &str,
            is_group: bool,
        ) -> Result<(), ProtocolAdminError> {
            FakeAdmin::detach_policy(self, policy, principal, is_group).await
        }
        async fn policy_attached(
            &self,
            policy: &str,
            principal: &str,
            is_group: bool,
        ) -> Result<bool, ProtocolAdminError> {
            FakeAdmin::policy_attached(self, policy, principal, is_group).await
        }
        async fn revoke_sts_sessions_for_provider(
            &self,
            parent_access_key: &str,
            _provider: &str,
        ) -> Result<(), ProtocolAdminError> {
            FakeAdmin::revoke_sts_sessions(self, parent_access_key).await
        }
        async fn sts_sessions_with_parent_for_provider(
            &self,
            parent_access_key: &str,
            _provider: &str,
        ) -> Result<Vec<String>, ProtocolAdminError> {
            FakeAdmin::sts_sessions_with_parent(self, parent_access_key).await
        }
    }

    #[async_trait]
    impl ProtocolStsPort for FakeSts {
        async fn assume_role(
            &self,
            parent: &ActorCredential,
            request: &ProtocolAssumeRoleRequest,
            source_resource_id: &str,
        ) -> std::result::Result<ActorCredential, ProtocolStsError> {
            let mut state = self.0.lock().expect("state");
            let parent_name = parent.access_key().to_string();
            let can_assume = state
                .user_policies
                .get(&parent_name)
                .into_iter()
                .flatten()
                .filter_map(|name| state.policies.get(name))
                .any(|policy| policy_allows(policy, "sts:AssumeRole", "*"));
            if !can_assume {
                return Err(sts_access_denied());
            }
            state.next_session += 1;
            let access_key = format!("temp-session-{}", state.next_session);
            let policy = request
                .session_policy
                .as_deref()
                .map(serde_json::from_str)
                .transpose()
                .map_err(|_| ProtocolStsError {
                    code: "InvalidPolicy".to_string(),
                    status: Some(400),
                    request_id: Some("fake".to_string()),
                })?;
            state.sessions.insert(
                access_key.clone(),
                SessionInfo {
                    parent: parent_name,
                    policy,
                    expires_at: (request.duration_seconds == EXPIRING_SESSION_DURATION_SECONDS)
                        .then(Instant::now),
                },
            );
            ActorCredential::temporary(
                "sts-session",
                access_key,
                "temporary-secret",
                "temporary-session-token",
                source_resource_id,
                "2099-01-01T00:00:00Z",
            )
            .map_err(|_| ProtocolStsError {
                code: "CredentialError".to_string(),
                status: None,
                request_id: None,
            })
        }
    }

    impl FakeS3 {
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
                .filter(|name| name.starts_with(prefix))
                .cloned()
                .collect())
        }

        async fn create_bucket(&self, bucket: &str) -> std::result::Result<(), ProtocolS3Error> {
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

        async fn delete_bucket_policy(
            &self,
            _bucket: &str,
        ) -> std::result::Result<(), ProtocolS3Error> {
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
                .filter(|(current, _)| current == bucket)
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
                .ok_or_else(s3_not_found)
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
    }

    #[async_trait]
    impl ProtocolBucketPort for FakeS3 {
        async fn list_buckets_with_prefix(
            &self,
            prefix: &str,
        ) -> Result<Vec<String>, ProtocolS3Error> {
            FakeS3::list_buckets_with_prefix(self, prefix).await
        }
        async fn create_bucket(&self, bucket: &str) -> Result<(), ProtocolS3Error> {
            FakeS3::create_bucket(self, bucket).await
        }
        async fn delete_bucket(&self, bucket: &str) -> Result<(), ProtocolS3Error> {
            FakeS3::delete_bucket(self, bucket).await
        }
        async fn head_bucket(&self, bucket: &str) -> Result<(), ProtocolS3Error> {
            self.state
                .lock()
                .expect("state")
                .buckets
                .contains(bucket)
                .then_some(())
                .ok_or_else(s3_not_found)
        }
    }

    #[async_trait]
    impl ProtocolListingPort for FakeS3 {
        async fn list_objects(&self, bucket: &str) -> Result<Vec<String>, ProtocolS3Error> {
            FakeS3::list_objects(self, bucket).await
        }
        async fn list_objects_v2_summary(
            &self,
            bucket: &str,
        ) -> Result<ProtocolListObjectsResult, ProtocolS3Error> {
            let keys = FakeS3::list_objects(self, bucket).await?;
            Ok(ProtocolListObjectsResult {
                key_count: keys.len(),
                keys,
            })
        }
    }

    #[async_trait]
    impl ProtocolObjectPort for FakeS3 {
        async fn put_object(
            &self,
            bucket: &str,
            key: &str,
            body: &[u8],
        ) -> Result<(), ProtocolS3Error> {
            FakeS3::put_object(self, bucket, key, body).await
        }
        async fn get_object(&self, bucket: &str, key: &str) -> Result<Vec<u8>, ProtocolS3Error> {
            FakeS3::get_object(self, bucket, key).await
        }
        async fn delete_object(&self, bucket: &str, key: &str) -> Result<(), ProtocolS3Error> {
            FakeS3::delete_object(self, bucket, key).await
        }
        async fn copy_object(
            &self,
            bucket: &str,
            source_key: &str,
            destination_key: &str,
        ) -> Result<(), ProtocolS3Error> {
            let body = FakeS3::get_object(self, bucket, source_key).await?;
            FakeS3::put_object(self, bucket, destination_key, &body).await
        }
        async fn delete_objects(
            &self,
            bucket: &str,
            keys: &[String],
        ) -> Result<Vec<String>, ProtocolS3Error> {
            for key in keys {
                FakeS3::delete_object(self, bucket, key).await?;
            }
            Ok(Vec::new())
        }
    }

    #[async_trait]
    impl ProtocolS3CleanupPort for FakeS3 {
        async fn cleanup_bucket_names(&self, prefix: &str) -> Result<Vec<String>, ProtocolS3Error> {
            FakeS3::list_buckets_with_prefix(self, prefix).await
        }
        async fn cleanup_exclusive_bucket(
            &self,
            ownership: ExclusiveBucketOwnership<'_>,
            _include_versions: bool,
        ) -> Result<(), ProtocolS3Error> {
            let bucket = ownership.bucket();
            self.state
                .lock()
                .expect("state")
                .objects
                .retain(|(candidate, _), _| candidate != bucket);
            FakeS3::delete_bucket(self, bucket).await
        }
        async fn cleanup_object_prefix(
            &self,
            bucket: &str,
            prefix: &str,
            _include_versions: bool,
        ) -> Result<(), ProtocolS3Error> {
            self.state
                .lock()
                .expect("state")
                .objects
                .retain(|(candidate, key), _| candidate != bucket || !key.starts_with(prefix));
            Ok(())
        }
        async fn cleanup_object_prefix_exists(
            &self,
            bucket: &str,
            prefix: &str,
            _include_versions: bool,
        ) -> Result<bool, ProtocolS3Error> {
            Ok(self
                .state
                .lock()
                .expect("state")
                .objects
                .keys()
                .any(|(candidate, key)| candidate == bucket && key.starts_with(prefix)))
        }
        async fn cleanup_abort_multipart_upload(
            &self,
            _bucket: &str,
            _key: &str,
            _upload_id: &str,
        ) -> Result<(), ProtocolS3Error> {
            Ok(())
        }
        async fn cleanup_multipart_upload_exists(
            &self,
            _bucket: &str,
            _key: &str,
            _upload_id: &str,
        ) -> Result<bool, ProtocolS3Error> {
            Ok(false)
        }
        async fn cleanup_delete_bucket_policy(&self, bucket: &str) -> Result<(), ProtocolS3Error> {
            FakeS3::delete_bucket_policy(self, bucket).await
        }
        async fn cleanup_bucket_policy_exists(
            &self,
            _bucket: &str,
        ) -> Result<bool, ProtocolS3Error> {
            Ok(false)
        }
        async fn cleanup_delete_public_access_block(
            &self,
            _bucket: &str,
        ) -> Result<(), ProtocolS3Error> {
            Ok(())
        }
        async fn cleanup_public_access_block_exists(
            &self,
            _bucket: &str,
        ) -> Result<bool, ProtocolS3Error> {
            Ok(false)
        }
    }

    impl FakeS3 {
        fn authorize(
            &self,
            action: &str,
            bucket: &str,
            key: Option<&str>,
        ) -> std::result::Result<(), ProtocolS3Error> {
            let Some(actor) = self.actor.as_deref() else {
                return Ok(());
            };
            let state = self.state.lock().expect("state");
            let session = state.sessions.get(actor);
            if session.is_some_and(|session| {
                session
                    .expires_at
                    .is_some_and(|expires_at| Instant::now() >= expires_at)
            }) {
                return Err(s3_expired_token());
            }
            let principal = session.map_or(actor, |session| session.parent.as_str());
            let resource = key.map_or_else(
                || format!("arn:aws:s3:::{bucket}"),
                |key| format!("arn:aws:s3:::{bucket}/{key}"),
            );
            let base_allowed = state
                .user_policies
                .get(principal)
                .into_iter()
                .flatten()
                .filter_map(|name| state.policies.get(name))
                .any(|policy| policy_allows(policy, action, &resource));
            if !base_allowed {
                return Err(s3_access_denied());
            }
            if let Some(policy) = session.and_then(|session| session.policy.as_ref())
                && !policy_allows(policy, action, &resource)
            {
                return Err(s3_access_denied());
            }
            Ok(())
        }
    }

    #[async_trait]
    impl ActorS3ClientFactory for FakeActorFactory {
        type Client = FakeS3;

        async fn for_actor(&self, credential: &ActorCredential) -> Result<Self::Client> {
            Ok(FakeS3 {
                state: self.0.clone(),
                actor: Some(credential.access_key().to_string()),
            })
        }
    }

    #[tokio::test]
    async fn every_sts_case_passes_intersection_rules_and_cleans_sessions() {
        for case_id in [
            STS_ASSUME_ROLE_BASIC,
            STS_EXPIRED_TOKEN_DENIED,
            STS_SESSION_POLICY_DENY_PUT,
            STS_SESSION_POLICY_NARROWS_ROLE,
        ] {
            let state = Arc::new(Mutex::new(State::default()));
            let admin = FakeAdmin(state.clone());
            let sts = FakeSts(state.clone());
            let admin_s3 = FakeS3 {
                state: state.clone(),
                actor: None,
            };
            let factory = FakeActorFactory(state.clone());
            let dir = tempfile::tempdir().expect("tempdir");
            let fingerprint =
                TargetFingerprint::new("http://127.0.0.1:9000", "us-east-1", "fake", None, None)
                    .expect("fingerprint");
            let mut registry =
                ResourceRegistry::create(dir.path(), "run", fingerprint).expect("registry");
            let namer = ProtocolResourceNamer::new("s3c", "s3chaos", "run").expect("namer");
            let execution = run_sts_case(
                case_id,
                &namer,
                &mut registry,
                &admin,
                &admin_s3,
                &sts,
                &factory,
            )
            .await;
            assert!(
                execution
                    .forbidden_secrets
                    .iter()
                    .any(|secret| secret == "temp-session-1"),
                "temporary STS access key must be scanned as forbidden material"
            );
            let persisted_registry = fs::read_to_string(registry.path()).expect("read registry");
            assert!(!persisted_registry.contains("temp-session-1"));
            let cleanup = cleanup_registered_resources(&mut registry, &admin, &admin_s3).await;
            assert_eq!(
                execution.report.status,
                ProtocolCaseStatus::Passed,
                "{case_id}"
            );
            assert!(cleanup.succeeded, "{case_id}: {cleanup:?}");
            assert!(registry.pending_cleanup().next().is_none(), "{case_id}");
            let state = state.lock().expect("state");
            assert!(state.users.is_empty(), "{case_id}");
            assert!(state.sessions.is_empty(), "{case_id}");
            assert!(state.policies.is_empty(), "{case_id}");
            assert!(state.user_policies.is_empty(), "{case_id}");
            assert!(state.buckets.is_empty(), "{case_id}");
            assert!(state.objects.is_empty(), "{case_id}");
        }
    }

    fn policy_allows(policy: &serde_json::Value, action: &str, resource: &str) -> bool {
        let mut allowed = false;
        for statement in policy["Statement"].as_array().into_iter().flatten() {
            if !array_contains(&statement["Action"], action)
                || !(statement.get("Resource").is_none() && !action.starts_with("s3:")
                    || array_matches(&statement["Resource"], resource))
            {
                continue;
            }
            match statement["Effect"].as_str() {
                Some("Deny") => return false,
                Some("Allow") => allowed = true,
                _ => {}
            }
        }
        allowed
    }

    fn array_contains(value: &serde_json::Value, expected: &str) -> bool {
        value
            .as_array()
            .into_iter()
            .flatten()
            .any(|value| value.as_str() == Some(expected))
    }

    fn array_matches(value: &serde_json::Value, resource: &str) -> bool {
        value
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_str)
            .any(|pattern| {
                pattern == "*"
                    || pattern
                        .strip_suffix('*')
                        .map_or(pattern == resource, |prefix| resource.starts_with(prefix))
            })
    }

    fn sts_access_denied() -> ProtocolStsError {
        ProtocolStsError {
            code: "AccessDenied".to_string(),
            status: Some(403),
            request_id: Some("fake".to_string()),
        }
    }

    fn s3_access_denied() -> ProtocolS3Error {
        ProtocolS3Error {
            code: "AccessDenied".to_string(),
            status: Some(403),
            request_id: Some("fake".to_string()),
        }
    }

    fn s3_expired_token() -> ProtocolS3Error {
        ProtocolS3Error {
            code: "ExpiredToken".to_string(),
            status: Some(403),
            request_id: Some("fake".to_string()),
        }
    }

    fn s3_not_found() -> ProtocolS3Error {
        ProtocolS3Error {
            code: "NoSuchKey".to_string(),
            status: Some(404),
            request_id: Some("fake".to_string()),
        }
    }
}
