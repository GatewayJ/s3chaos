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

use anyhow::{Result, anyhow, ensure};
use serde_json::json;
use std::collections::BTreeMap;

use crate::protocol::{
    authorization::{
        ProtocolActorSource, ProtocolAuthorizationDimensions, ProtocolGrantSource,
        ProtocolPolicyEffect,
    },
    cases::{
        CaseContext, ProtocolCaseExecution,
        authz::{expect_access_denied, expect_eventual_ok},
    },
    catalog::OIDC_WEB_IDENTITY_BASIC,
    credentials::ExternalIdentityCredential,
    fixture::{
        naming::ProtocolResourceNamer,
        registry::{ResourceKind, ResourceRegistry, ResourceState},
        resources::transition_external,
    },
    ports::{
        ActorS3ClientFactory, ProtocolBucketPort, ProtocolExternalIdentityPort,
        ProtocolListingPort, ProtocolObjectPort, ProtocolPolicyAdminPort,
        ProtocolWebIdentityRequest, ProtocolWebIdentityStsPort,
    },
};

pub(crate) struct OidcCaseServices<'a, A, S, F> {
    pub(crate) namer: &'a ProtocolResourceNamer,
    pub(crate) admin: &'a A,
    pub(crate) admin_s3: &'a S,
    pub(crate) external_identity: &'a dyn ProtocolExternalIdentityPort,
    pub(crate) web_identity_sts: &'a dyn ProtocolWebIdentityStsPort,
    pub(crate) actor_clients: &'a F,
}

pub(crate) async fn run_oidc_case<A, S, F>(
    case_id: &str,
    registry: &mut ResourceRegistry,
    services: OidcCaseServices<'_, A, S, F>,
) -> ProtocolCaseExecution
where
    A: ProtocolPolicyAdminPort,
    S: ProtocolBucketPort + ProtocolObjectPort,
    F: ActorS3ClientFactory,
{
    let mut context = CaseContext::new(
        case_id,
        ProtocolAuthorizationDimensions {
            actor_source: ProtocolActorSource::WebIdentity,
            grant_source: ProtocolGrantSource::OidcClaim,
            policy_effect: ProtocolPolicyEffect::Allow,
        },
    );
    let result = if case_id == OIDC_WEB_IDENTITY_BASIC {
        run_basic(registry, &services, &mut context).await
    } else {
        Err(anyhow!("unsupported OIDC case {case_id}"))
    };
    context.finish(result)
}

async fn run_basic<A, S, F>(
    registry: &mut ResourceRegistry,
    services: &OidcCaseServices<'_, A, S, F>,
    context: &mut CaseContext,
) -> Result<()>
where
    A: ProtocolPolicyAdminPort,
    S: ProtocolBucketPort + ProtocolObjectPort,
    F: ActorS3ClientFactory,
{
    let case_id = OIDC_WEB_IDENTITY_BASIC;
    let bucket = services.namer.bucket(case_id, 0)?;
    let bucket_handle = registry.plan(ResourceKind::Bucket, &bucket, case_id, Vec::new())?;
    transition_external(
        registry,
        &bucket_handle,
        "create OIDC target bucket",
        services.admin_s3.create_bucket(&bucket),
    )
    .await?;

    let unrelated_bucket = services.namer.bucket(case_id, 1)?;
    let unrelated_bucket_handle =
        registry.plan(ResourceKind::Bucket, &unrelated_bucket, case_id, Vec::new())?;
    transition_external(
        registry,
        &unrelated_bucket_handle,
        "create OIDC isolation bucket",
        services.admin_s3.create_bucket(&unrelated_bucket),
    )
    .await?;

    let prefix = format!("cases/{case_id}/");
    let key = format!("{prefix}seed-object");
    let objects =
        registry.plan_object_prefix(&bucket, &prefix, case_id, vec![bucket_handle.id.clone()])?;
    transition_external(
        registry,
        &objects,
        "seed OIDC target object",
        services.admin_s3.put_object(&bucket, &key, b"oidc-seed"),
    )
    .await?;

    let policy_name = services.namer.iam_policy(case_id, 0)?;
    let policy_handle = registry.plan(
        ResourceKind::IamPolicy,
        &policy_name,
        case_id,
        vec![bucket_handle.id.clone()],
    )?;
    let policy = readonly_policy(&bucket)?;
    transition_external(
        registry,
        &policy_handle,
        "create OIDC claim policy",
        services.admin.create_policy(&policy_name, &policy),
    )
    .await?;

    let username = services.namer.iam_user(case_id, 0)?;
    let subject_handle = registry.plan_external_identity_subject(
        &username,
        services.external_identity.coordinates(),
        case_id,
        vec![policy_handle.id.clone()],
    )?;
    let subject = ExternalIdentityCredential::generated(&username, &subject_handle.id)?;
    context.add_forbidden_secret(subject.password().to_string());
    let claims = BTreeMap::from([(
        services.external_identity.policy_claim().to_string(),
        vec![policy_name],
    )]);
    transition_external(
        registry,
        &subject_handle,
        "create Keycloak test subject",
        services.external_identity.create_subject(&subject, &claims),
    )
    .await?;

    context.current_phase = "token-exchange".to_string();
    let token = services.external_identity.issue_id_token(&subject).await?;
    context.add_forbidden_secret(token.expose().to_string());
    let cleanup_parent = services.web_identity_sts.cleanup_parent(&token)?;
    let session_handle = registry.plan_sts_session_for_provider(
        cleanup_parent,
        "openid",
        case_id,
        vec![subject_handle.id, policy_handle.id],
    )?;
    registry.transition(&session_handle.id, ResourceState::Creating, None)?;
    let session = match services
        .web_identity_sts
        .assume_role_with_web_identity(
            &ProtocolWebIdentityRequest {
                duration_seconds: 900,
                session_policy: None,
                token,
            },
            &session_handle.id,
        )
        .await
    {
        Ok(session) => session,
        Err(error) => {
            let message = format!("AssumeRoleWithWebIdentity failed: {error}");
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

    context.current_phase = "propagation".to_string();
    expect_eventual_ok(
        context,
        "web-identity",
        "list-bucket-with-oidc-policy-claim",
        &bucket,
        None,
        || async { session_s3.list_objects(&bucket).await.map(|_| ()) },
    )
    .await?;
    expect_eventual_ok(
        context,
        "web-identity",
        "get-object-with-oidc-policy-claim",
        &bucket,
        Some(&key),
        || async { session_s3.get_object(&bucket, &key).await.map(|_| ()) },
    )
    .await?;

    context.current_phase = "assertion".to_string();
    expect_access_denied(
        context,
        "web-identity",
        "put-object-denied-by-oidc-readonly-policy",
        &bucket,
        Some("denied-write"),
        || async {
            session_s3
                .put_object(&bucket, "denied-write", b"denied")
                .await
        },
    )
    .await?;
    expect_access_denied(
        context,
        "web-identity",
        "list-unrelated-bucket-denied",
        &unrelated_bucket,
        None,
        || async { session_s3.list_objects(&unrelated_bucket).await },
    )
    .await?;
    ensure!(
        services.external_identity.subject_exists(&username).await?,
        "Keycloak test subject disappeared before cleanup"
    );
    Ok(())
}

fn readonly_policy(bucket: &str) -> Result<String> {
    Ok(serde_json::to_string(&json!({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:ListBucket"],
                "Resource": [format!("arn:aws:s3:::{bucket}")]
            },
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": [format!("arn:aws:s3:::{bucket}/*")]
            }
        ]
    }))?)
}

#[cfg(test)]
mod tests {
    use super::{OidcCaseServices, run_oidc_case};
    use crate::protocol::{
        catalog::OIDC_WEB_IDENTITY_BASIC,
        credentials::{ActorCredential, ExternalIdentityCredential, WebIdentityToken},
        fixture::{
            naming::ProtocolResourceNamer,
            registry::{ResourceKind, ResourceRegistry},
        },
        ports::{
            ActorS3ClientFactory, ProtocolAdminError, ProtocolBucketPort,
            ProtocolExternalIdentityCoordinates, ProtocolExternalIdentityError,
            ProtocolExternalIdentityPort, ProtocolExternalIdentityProviderInfo,
            ProtocolListObjectsResult, ProtocolListingPort, ProtocolObjectPort,
            ProtocolPolicyAdminPort, ProtocolS3Error, ProtocolStsError, ProtocolWebIdentityRequest,
            ProtocolWebIdentityStsPort,
        },
        reporting::ProtocolCaseStatus,
        suite_plan::TargetFingerprint,
    };
    use async_trait::async_trait;
    use std::{
        collections::{BTreeMap, BTreeSet},
        sync::{Arc, Mutex},
    };

    #[derive(Default)]
    struct State {
        buckets: BTreeMap<String, BTreeMap<String, Vec<u8>>>,
        target_bucket: Option<String>,
        policies: BTreeSet<String>,
        subjects: BTreeSet<String>,
    }

    #[derive(Clone, Default)]
    struct FakeAdmin {
        state: Arc<Mutex<State>>,
    }

    #[derive(Clone)]
    struct FakeS3 {
        state: Arc<Mutex<State>>,
        actor: bool,
    }

    #[derive(Clone)]
    struct FakeExternalIdentity {
        state: Arc<Mutex<State>>,
    }

    #[derive(Clone, Default)]
    struct FakeWebIdentitySts;

    #[derive(Clone)]
    struct FakeActorClients {
        state: Arc<Mutex<State>>,
    }

    #[async_trait]
    impl ProtocolPolicyAdminPort for FakeAdmin {
        async fn policies_with_prefix(
            &self,
            prefix: &str,
        ) -> std::result::Result<Vec<String>, ProtocolAdminError> {
            Ok(self
                .state
                .lock()
                .expect("state")
                .policies
                .iter()
                .filter(|name| name.starts_with(prefix))
                .cloned()
                .collect())
        }
        async fn create_policy(
            &self,
            name: &str,
            _document: &str,
        ) -> std::result::Result<(), ProtocolAdminError> {
            self.state
                .lock()
                .expect("state")
                .policies
                .insert(name.to_string());
            Ok(())
        }

        async fn remove_policy(&self, name: &str) -> Result<(), ProtocolAdminError> {
            self.state.lock().expect("state").policies.remove(name);
            Ok(())
        }

        async fn attach_policy(
            &self,
            _policy: &str,
            _principal: &str,
            _is_group: bool,
        ) -> Result<(), ProtocolAdminError> {
            Ok(())
        }
        async fn detach_policy(
            &self,
            _policy: &str,
            _principal: &str,
            _is_group: bool,
        ) -> Result<(), ProtocolAdminError> {
            Ok(())
        }
        async fn policy_attached(
            &self,
            _policy: &str,
            _principal: &str,
            _is_group: bool,
        ) -> Result<bool, ProtocolAdminError> {
            Ok(false)
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
                .keys()
                .filter(|bucket| bucket.starts_with(prefix))
                .cloned()
                .collect())
        }

        async fn create_bucket(&self, bucket: &str) -> std::result::Result<(), ProtocolS3Error> {
            let mut state = self.state.lock().expect("state");
            state.buckets.insert(bucket.to_string(), BTreeMap::new());
            if state.target_bucket.is_none() {
                state.target_bucket = Some(bucket.to_string());
            }
            Ok(())
        }

        async fn delete_bucket(&self, bucket: &str) -> std::result::Result<(), ProtocolS3Error> {
            self.state.lock().expect("state").buckets.remove(bucket);
            Ok(())
        }

        async fn list_objects(
            &self,
            bucket: &str,
        ) -> std::result::Result<Vec<String>, ProtocolS3Error> {
            let state = self.state.lock().expect("state");
            if self.actor && state.target_bucket.as_deref() != Some(bucket) {
                return Err(access_denied());
            }
            Ok(state
                .buckets
                .get(bucket)
                .map(|objects| objects.keys().cloned().collect())
                .unwrap_or_default())
        }

        async fn put_object(
            &self,
            bucket: &str,
            key: &str,
            body: &[u8],
        ) -> std::result::Result<(), ProtocolS3Error> {
            if self.actor {
                return Err(access_denied());
            }
            self.state
                .lock()
                .expect("state")
                .buckets
                .get_mut(bucket)
                .expect("bucket")
                .insert(key.to_string(), body.to_vec());
            Ok(())
        }

        async fn get_object(
            &self,
            bucket: &str,
            key: &str,
        ) -> std::result::Result<Vec<u8>, ProtocolS3Error> {
            let state = self.state.lock().expect("state");
            if self.actor && state.target_bucket.as_deref() != Some(bucket) {
                return Err(access_denied());
            }
            state
                .buckets
                .get(bucket)
                .and_then(|objects| objects.get(key))
                .cloned()
                .ok_or_else(|| ProtocolS3Error {
                    code: "NoSuchKey".to_string(),
                    status: Some(404),
                    request_id: None,
                })
        }

        async fn delete_object(
            &self,
            bucket: &str,
            key: &str,
        ) -> std::result::Result<(), ProtocolS3Error> {
            if let Some(objects) = self.state.lock().expect("state").buckets.get_mut(bucket) {
                objects.remove(key);
            }
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
                .contains_key(bucket)
                .then_some(())
                .ok_or_else(|| ProtocolS3Error {
                    code: "NoSuchBucket".to_string(),
                    status: Some(404),
                    request_id: None,
                })
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
    impl ProtocolExternalIdentityPort for FakeExternalIdentity {
        fn coordinates(&self) -> ProtocolExternalIdentityCoordinates {
            ProtocolExternalIdentityCoordinates {
                provider: "keycloak".to_string(),
                profile: "keycloak-ci".to_string(),
                issuer: "https://idp.example/realms/ci".to_string(),
                subject_namespace: "https://idp.example/admin/realms/ci/users".to_string(),
            }
        }

        fn policy_claim(&self) -> &str {
            "policy"
        }

        async fn provider_info(
            &self,
        ) -> std::result::Result<ProtocolExternalIdentityProviderInfo, ProtocolExternalIdentityError>
        {
            Ok(ProtocolExternalIdentityProviderInfo {
                provider: "keycloak".to_string(),
                profile: "keycloak-ci".to_string(),
                issuer: "https://idp.example/realms/ci".to_string(),
                policy_claim: "policy".to_string(),
            })
        }

        async fn create_subject(
            &self,
            credential: &ExternalIdentityCredential,
            claims: &BTreeMap<String, Vec<String>>,
        ) -> std::result::Result<(), ProtocolExternalIdentityError> {
            if !claims.contains_key("policy") {
                return Err(ProtocolExternalIdentityError::protocol(
                    "MissingPolicyClaim",
                ));
            }
            self.state
                .lock()
                .expect("state")
                .subjects
                .insert(credential.username.clone());
            Ok(())
        }

        async fn issue_id_token(
            &self,
            _credential: &ExternalIdentityCredential,
        ) -> std::result::Result<WebIdentityToken, ProtocolExternalIdentityError> {
            WebIdentityToken::new("header.payload.signature")
                .map_err(|_| ProtocolExternalIdentityError::protocol("InvalidToken"))
        }

        async fn subject_exists(
            &self,
            username: &str,
        ) -> std::result::Result<bool, ProtocolExternalIdentityError> {
            Ok(self
                .state
                .lock()
                .expect("state")
                .subjects
                .contains(username))
        }

        async fn delete_subject(
            &self,
            username: &str,
        ) -> std::result::Result<(), ProtocolExternalIdentityError> {
            self.state.lock().expect("state").subjects.remove(username);
            Ok(())
        }
    }

    #[async_trait]
    impl ProtocolWebIdentityStsPort for FakeWebIdentitySts {
        fn cleanup_parent(
            &self,
            _token: &WebIdentityToken,
        ) -> std::result::Result<String, ProtocolStsError> {
            Ok("virtual-openid-parent".to_string())
        }

        async fn assume_role_with_web_identity(
            &self,
            _request: &ProtocolWebIdentityRequest,
            source_resource_id: &str,
        ) -> std::result::Result<ActorCredential, ProtocolStsError> {
            ActorCredential::temporary_for_phase(
                "web-identity-session",
                "temporary-access",
                "temporary-secret",
                "temporary-token",
                source_resource_id,
                "2099-01-01T00:00:00Z",
                "sts-assume-role-with-web-identity",
            )
            .map_err(|_| ProtocolStsError {
                code: "InvalidCredentials".to_string(),
                status: None,
                request_id: None,
            })
        }
    }

    #[async_trait]
    impl ActorS3ClientFactory for FakeActorClients {
        type Client = FakeS3;

        async fn for_actor(&self, _credential: &ActorCredential) -> anyhow::Result<Self::Client> {
            Ok(FakeS3 {
                state: self.state.clone(),
                actor: true,
            })
        }
    }

    fn access_denied() -> ProtocolS3Error {
        ProtocolS3Error {
            code: "AccessDenied".to_string(),
            status: Some(403),
            request_id: None,
        }
    }

    #[tokio::test]
    async fn basic_case_records_external_cleanup_coordinates_and_authorization_boundaries() {
        let state = Arc::new(Mutex::new(State::default()));
        let admin = FakeAdmin {
            state: state.clone(),
        };
        let admin_s3 = FakeS3 {
            state: state.clone(),
            actor: false,
        };
        let external_identity = FakeExternalIdentity {
            state: state.clone(),
        };
        let actor_clients = FakeActorClients { state };
        let namer = ProtocolResourceNamer::new("s3c", "s3chaos", "run").expect("namer");
        let fingerprint = TargetFingerprint::new(
            "http://127.0.0.1:9000",
            "us-east-1",
            "deployment",
            None,
            None,
        )
        .expect("fingerprint");
        let dir = tempfile::tempdir().expect("tempdir");
        let mut registry =
            ResourceRegistry::create(dir.path(), "run", fingerprint).expect("registry");

        let execution = run_oidc_case(
            OIDC_WEB_IDENTITY_BASIC,
            &mut registry,
            OidcCaseServices {
                namer: &namer,
                admin: &admin,
                admin_s3: &admin_s3,
                external_identity: &external_identity,
                web_identity_sts: &FakeWebIdentitySts,
                actor_clients: &actor_clients,
            },
        )
        .await;

        assert_eq!(execution.report.status, ProtocolCaseStatus::Passed);
        assert_eq!(execution.report.assertions.len(), 4);
        assert!(!execution.forbidden_secrets.is_empty());
        let subject = registry
            .resources
            .iter()
            .find(|resource| resource.kind == ResourceKind::ExternalIdentitySubject)
            .expect("external subject");
        let external_identity = subject.external_identity.as_ref().expect("coordinates");
        assert_eq!(external_identity.profile, "keycloak-ci");
        assert_eq!(external_identity.issuer, "https://idp.example/realms/ci");
        let session = registry
            .resources
            .iter()
            .find(|resource| resource.kind == ResourceKind::StsSession)
            .expect("STS session");
        assert_eq!(session.principal.as_deref(), Some("virtual-openid-parent"));
        assert_eq!(session.identity_provider.as_deref(), Some("openid"));
    }
}
