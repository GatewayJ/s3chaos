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

use crate::protocol::{
    authorization::{
        ProtocolActorSource, ProtocolAuthorizationDimensions, ProtocolGrantSource,
        ProtocolPolicyEffect,
    },
    cases::{
        CaseContext, ProtocolCaseExecution,
        authz::{expect_access_denied, expect_eventual_ok},
        iam::{PolicyGrant, create_and_attach_policy, setup_user_bucket},
    },
    catalog::{
        STS_ASSUME_ROLE_BASIC, STS_SESSION_POLICY_DENY_PUT, STS_SESSION_POLICY_NARROWS_ROLE,
    },
    fixture::{
        naming::ProtocolResourceNamer,
        registry::{ResourceRegistry, ResourceState},
    },
    ports::{
        ActorS3ClientFactory, ProtocolAdminPort, ProtocolAssumeRoleRequest, ProtocolS3Port,
        ProtocolStsPort,
    },
};

pub(crate) async fn run_sts_case<F>(
    case_id: &str,
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    admin: &impl ProtocolAdminPort,
    admin_s3: &impl ProtocolS3Port,
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

async fn run_basic<F>(
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    admin: &impl ProtocolAdminPort,
    admin_s3: &impl ProtocolS3Port,
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
    admin: &impl ProtocolAdminPort,
    admin_s3: &impl ProtocolS3Port,
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
    admin: &impl ProtocolAdminPort,
    admin_s3: &impl ProtocolS3Port,
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
) -> Result<(
    crate::protocol::cases::iam::IamFixture<F::Client>,
    F::Client,
)>
where
    A: ProtocolAdminPort,
    S: ProtocolS3Port,
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
        context,
    )
    .await?;
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
            &context.actors[0],
            &ProtocolAssumeRoleRequest {
                duration_seconds: 900,
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
    registry.bind_external_name(&session_handle.id, session.access_key())?;
    registry.transition(&session_handle.id, ResourceState::Created, None)?;
    let session_s3 = services.actor_clients.for_actor(&session).await?;
    context.add_actor(session);
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
    use super::{parent_policy, run_sts_case, session_read_policy, session_write_policy};
    use crate::protocol::{
        catalog::{
            STS_ASSUME_ROLE_BASIC, STS_SESSION_POLICY_DENY_PUT, STS_SESSION_POLICY_NARROWS_ROLE,
        },
        credentials::ActorCredential,
        fixture::{
            cleanup::cleanup_registered_resources, naming::ProtocolResourceNamer,
            registry::ResourceRegistry,
        },
        ports::{
            ActorS3ClientFactory, ProtocolAdminError, ProtocolAdminPort, ProtocolAssumeRoleRequest,
            ProtocolObjectVersion, ProtocolS3Error, ProtocolS3Port, ProtocolServerInfo,
            ProtocolStsError, ProtocolStsPort,
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

    #[async_trait]
    impl ProtocolAdminPort for FakeAdmin {
        async fn server_info(&self) -> std::result::Result<ProtocolServerInfo, ProtocolAdminError> {
            Ok(ProtocolServerInfo {
                deployment_id: "fake".to_string(),
                mode: None,
                region: None,
            })
        }

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

        async fn put_bucket_policy(
            &self,
            _bucket: &str,
            _policy: &str,
        ) -> std::result::Result<(), ProtocolS3Error> {
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
            let Some(actor) = self.actor.as_deref() else {
                return Ok(());
            };
            let state = self.state.lock().expect("state");
            let session = state.sessions.get(actor);
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

    fn s3_not_found() -> ProtocolS3Error {
        ProtocolS3Error {
            code: "NoSuchKey".to_string(),
            status: Some(404),
            request_id: Some("fake".to_string()),
        }
    }
}
