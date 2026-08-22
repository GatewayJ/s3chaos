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
        authz::{expect_access_denied, expect_eventual_access_denied, expect_eventual_ok},
    },
    catalog::{
        IAM_EXPLICIT_DENY_OVERRIDES_ALLOW, IAM_GROUP_POLICY, IAM_USER_MANAGED_POLICY_DETACH,
        IAM_USER_MANAGED_POLICY_READONLY,
    },
    fixture::{
        naming::ProtocolResourceNamer,
        registry::{ResourceHandle, ResourceKind, ResourceRegistry, ResourceState},
        resources::{
            PolicyGrant, create_and_attach_policy, setup_user_bucket, transition_external,
        },
    },
    ports::{
        ActorS3ClientFactory, ProtocolBucketPort, ProtocolGroupAdminPort,
        ProtocolIdentityAdminPort, ProtocolListingPort, ProtocolObjectPort,
        ProtocolPolicyAdminPort,
    },
};

pub(crate) async fn run_iam_case<F>(
    case_id: &str,
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    admin: &(impl ProtocolGroupAdminPort + ProtocolIdentityAdminPort + ProtocolPolicyAdminPort),
    admin_s3: &(impl ProtocolBucketPort + ProtocolObjectPort),
    actor_clients: &F,
) -> ProtocolCaseExecution
where
    F: ActorS3ClientFactory,
{
    let mut context = CaseContext::new(case_id, iam_dimensions(case_id));
    let result = match case_id {
        IAM_USER_MANAGED_POLICY_READONLY => {
            run_user_readonly(
                namer,
                registry,
                admin,
                admin_s3,
                actor_clients,
                &mut context,
            )
            .await
        }
        IAM_USER_MANAGED_POLICY_DETACH => {
            run_managed_policy_detach(
                namer,
                registry,
                admin,
                admin_s3,
                actor_clients,
                &mut context,
            )
            .await
        }
        IAM_GROUP_POLICY => {
            run_group_policy(
                namer,
                registry,
                admin,
                admin_s3,
                actor_clients,
                &mut context,
            )
            .await
        }
        IAM_EXPLICIT_DENY_OVERRIDES_ALLOW => {
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
        _ => Err(anyhow!("unsupported IAM case {case_id}")),
    };
    context.finish(result)
}

fn iam_dimensions(case_id: &str) -> ProtocolAuthorizationDimensions {
    match case_id {
        IAM_USER_MANAGED_POLICY_READONLY => ProtocolAuthorizationDimensions {
            actor_source: ProtocolActorSource::IamUser,
            grant_source: ProtocolGrantSource::ManagedPolicy,
            policy_effect: ProtocolPolicyEffect::Allow,
        },
        IAM_USER_MANAGED_POLICY_DETACH => ProtocolAuthorizationDimensions {
            actor_source: ProtocolActorSource::IamUser,
            grant_source: ProtocolGrantSource::ManagedPolicy,
            policy_effect: ProtocolPolicyEffect::Detach,
        },
        IAM_GROUP_POLICY => ProtocolAuthorizationDimensions {
            actor_source: ProtocolActorSource::GroupMemberUser,
            grant_source: ProtocolGrantSource::GroupPolicy,
            policy_effect: ProtocolPolicyEffect::Allow,
        },
        IAM_EXPLICIT_DENY_OVERRIDES_ALLOW => ProtocolAuthorizationDimensions {
            actor_source: ProtocolActorSource::IamUser,
            grant_source: ProtocolGrantSource::ManagedPolicy,
            policy_effect: ProtocolPolicyEffect::ExplicitDeny,
        },
        _ => ProtocolAuthorizationDimensions {
            actor_source: ProtocolActorSource::IamUser,
            grant_source: ProtocolGrantSource::ManagedPolicy,
            policy_effect: ProtocolPolicyEffect::Allow,
        },
    }
}

async fn run_user_readonly<F>(
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    admin: &(impl ProtocolIdentityAdminPort + ProtocolPolicyAdminPort),
    admin_s3: &(impl ProtocolBucketPort + ProtocolObjectPort),
    actor_clients: &F,
    context: &mut CaseContext,
) -> Result<()>
where
    F: ActorS3ClientFactory,
{
    let case_id = IAM_USER_MANAGED_POLICY_READONLY;
    let fixture =
        setup_user_bucket(case_id, namer, registry, admin, admin_s3, actor_clients).await?;
    context.add_actor(fixture.actor.clone());
    let key = format!("cases/{case_id}/seed-object");
    let objects = registry.plan_object_prefix(
        &fixture.bucket,
        format!("cases/{case_id}/"),
        case_id,
        vec![fixture.bucket_handle_id.clone()],
    )?;
    transition_external(
        registry,
        &objects,
        "seed object",
        admin_s3.put_object(&fixture.bucket, &key, b"seed"),
    )
    .await?;
    let policy = readonly_policy(&fixture.bucket)?;
    create_and_attach_policy(
        case_id,
        namer,
        registry,
        admin,
        PolicyGrant {
            document: &policy,
            principal: &fixture.user,
            is_group: false,
            principal_dependency: &fixture.user_handle_id,
        },
    )
    .await?;
    context.current_phase = "propagation".to_string();
    expect_eventual_ok(
        context,
        "iam-user",
        "list-bucket-with-readonly-policy",
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
    expect_eventual_ok(
        context,
        "iam-user",
        "get-object-with-readonly-policy",
        &fixture.bucket,
        Some(&key),
        || async {
            fixture
                .actor_s3
                .get_object(&fixture.bucket, &key)
                .await
                .map(|_| ())
        },
    )
    .await?;
    context.current_phase = "assertion".to_string();
    expect_access_denied(
        context,
        "iam-user",
        "put-object-with-readonly-policy",
        &fixture.bucket,
        Some("denied-write"),
        || async {
            fixture
                .actor_s3
                .put_object(&fixture.bucket, "denied-write", b"denied")
                .await
        },
    )
    .await?;
    expect_access_denied(
        context,
        "iam-user",
        "delete-object-with-readonly-policy",
        &fixture.bucket,
        Some(&key),
        || async { fixture.actor_s3.delete_object(&fixture.bucket, &key).await },
    )
    .await
}

async fn run_managed_policy_detach<F>(
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    admin: &(impl ProtocolIdentityAdminPort + ProtocolPolicyAdminPort),
    admin_s3: &impl ProtocolBucketPort,
    actor_clients: &F,
    context: &mut CaseContext,
) -> Result<()>
where
    F: ActorS3ClientFactory,
{
    let case_id = IAM_USER_MANAGED_POLICY_DETACH;
    let fixture =
        setup_user_bucket(case_id, namer, registry, admin, admin_s3, actor_clients).await?;
    context.add_actor(fixture.actor.clone());
    let policy = object_write_policy(&fixture.bucket, None)?;
    let (policy_handle, attachment) = create_and_attach_policy(
        case_id,
        namer,
        registry,
        admin,
        PolicyGrant {
            document: &policy,
            principal: &fixture.user,
            is_group: false,
            principal_dependency: &fixture.user_handle_id,
        },
    )
    .await?;
    let prefix = format!("cases/{case_id}/");
    let objects = registry.plan_object_prefix(
        &fixture.bucket,
        &prefix,
        case_id,
        vec![fixture.bucket_handle_id.clone()],
    )?;
    registry.transition(&objects.id, ResourceState::Creating, None)?;
    context.current_phase = "propagation".to_string();
    let allowed_key = format!("{prefix}before-detach");
    expect_eventual_ok(
        context,
        "iam-user",
        "put-object-before-managed-policy-detach",
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
    clean_attachment(
        registry,
        admin,
        &attachment,
        &policy_handle.name,
        &fixture.user,
        false,
    )
    .await?;
    let denied_key = format!("{prefix}after-detach");
    expect_eventual_access_denied(
        context,
        "iam-user",
        "put-object-after-managed-policy-detach",
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

async fn run_group_policy<F>(
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    admin: &(impl ProtocolGroupAdminPort + ProtocolIdentityAdminPort + ProtocolPolicyAdminPort),
    admin_s3: &impl ProtocolBucketPort,
    actor_clients: &F,
    context: &mut CaseContext,
) -> Result<()>
where
    F: ActorS3ClientFactory,
{
    let case_id = IAM_GROUP_POLICY;
    let fixture =
        setup_user_bucket(case_id, namer, registry, admin, admin_s3, actor_clients).await?;
    context.add_actor(fixture.actor.clone());
    let group = namer.iam_group(case_id, 0)?;
    let group_handle = registry.plan(ResourceKind::IamGroup, &group, case_id, Vec::new())?;
    registry.transition(&group_handle.id, ResourceState::Creating, None)?;
    let membership = registry.plan_group_membership(
        &group,
        &fixture.user,
        case_id,
        vec![group_handle.id.clone(), fixture.user_handle_id.clone()],
    )?;
    registry.transition(&membership.id, ResourceState::Creating, None)?;
    match admin
        .update_group_members(&group, std::slice::from_ref(&fixture.user), false)
        .await
    {
        Ok(()) => {
            registry.transition(&group_handle.id, ResourceState::Created, None)?;
            registry.transition(&membership.id, ResourceState::Created, None)?;
        }
        Err(error) => {
            let message = format!("create IAM group membership failed: {error}");
            registry.transition(
                &group_handle.id,
                ResourceState::Failed,
                Some(message.clone()),
            )?;
            registry.transition(&membership.id, ResourceState::Failed, Some(message.clone()))?;
            return Err(anyhow!(message));
        }
    }
    let policy = object_write_policy(&fixture.bucket, None)?;
    let (policy_handle, attachment) = create_and_attach_policy(
        case_id,
        namer,
        registry,
        admin,
        PolicyGrant {
            document: &policy,
            principal: &group,
            is_group: true,
            principal_dependency: &group_handle.id,
        },
    )
    .await?;
    let key = format!("cases/{case_id}/group-grant");
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
        "iam-user",
        "put-object-with-group-policy",
        &fixture.bucket,
        Some(&key),
        || async {
            fixture
                .actor_s3
                .put_object(&fixture.bucket, &key, b"allowed")
                .await
        },
    )
    .await?;
    registry.transition(&objects.id, ResourceState::Created, None)?;
    clean_membership(registry, admin, &membership, &group, &fixture.user).await?;
    let denied_key = format!("cases/{case_id}/after-membership-remove");
    expect_eventual_access_denied(
        context,
        "iam-user",
        "put-object-after-group-membership-remove",
        &fixture.bucket,
        Some(&denied_key),
        || async {
            fixture
                .actor_s3
                .put_object(&fixture.bucket, &denied_key, b"denied")
                .await
        },
    )
    .await?;
    // These remain registered for the normal dependency-ordered cleanup.
    let _ = (policy_handle, attachment);
    Ok(())
}

async fn run_explicit_deny<F>(
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    admin: &(impl ProtocolIdentityAdminPort + ProtocolPolicyAdminPort),
    admin_s3: &impl ProtocolBucketPort,
    actor_clients: &F,
    context: &mut CaseContext,
) -> Result<()>
where
    F: ActorS3ClientFactory,
{
    let case_id = IAM_EXPLICIT_DENY_OVERRIDES_ALLOW;
    let fixture =
        setup_user_bucket(case_id, namer, registry, admin, admin_s3, actor_clients).await?;
    context.add_actor(fixture.actor.clone());
    let denied_prefix = format!("cases/{case_id}/denied/");
    let policy = object_write_policy(&fixture.bucket, Some(&denied_prefix))?;
    create_and_attach_policy(
        case_id,
        namer,
        registry,
        admin,
        PolicyGrant {
            document: &policy,
            principal: &fixture.user,
            is_group: false,
            principal_dependency: &fixture.user_handle_id,
        },
    )
    .await?;
    let objects = registry.plan_object_prefix(
        &fixture.bucket,
        format!("cases/{case_id}/"),
        case_id,
        vec![fixture.bucket_handle_id.clone()],
    )?;
    registry.transition(&objects.id, ResourceState::Creating, None)?;
    let allowed_key = format!("cases/{case_id}/allowed/object");
    context.current_phase = "propagation".to_string();
    expect_eventual_ok(
        context,
        "iam-user",
        "put-object-covered-by-iam-allow",
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
    let denied_key = format!("{denied_prefix}object");
    expect_access_denied(
        context,
        "iam-user",
        "put-object-covered-by-iam-explicit-deny",
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

async fn clean_attachment(
    registry: &mut ResourceRegistry,
    admin: &impl ProtocolPolicyAdminPort,
    handle: &ResourceHandle,
    policy: &str,
    principal: &str,
    is_group: bool,
) -> Result<()> {
    registry.transition(&handle.id, ResourceState::CleanupAttempted, None)?;
    match admin.detach_policy(policy, principal, is_group).await {
        Ok(()) => registry.transition(&handle.id, ResourceState::Cleaned, None),
        Err(error) => {
            let message = format!("detach IAM policy failed: {error}");
            registry.transition(&handle.id, ResourceState::Failed, Some(message.clone()))?;
            Err(anyhow!(message))
        }
    }
}

async fn clean_membership(
    registry: &mut ResourceRegistry,
    admin: &impl ProtocolGroupAdminPort,
    handle: &ResourceHandle,
    group: &str,
    member: &str,
) -> Result<()> {
    registry.transition(&handle.id, ResourceState::CleanupAttempted, None)?;
    match admin
        .update_group_members(group, &[member.to_string()], true)
        .await
    {
        Ok(()) => registry.transition(&handle.id, ResourceState::Cleaned, None),
        Err(error) => {
            let message = format!("remove IAM group member failed: {error}");
            registry.transition(&handle.id, ResourceState::Failed, Some(message.clone()))?;
            Err(anyhow!(message))
        }
    }
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

fn object_write_policy(bucket: &str, denied_prefix: Option<&str>) -> Result<String> {
    let mut statements = vec![json!({
        "Effect": "Allow",
        "Action": ["s3:PutObject"],
        "Resource": [format!("arn:aws:s3:::{bucket}/*")]
    })];
    if let Some(prefix) = denied_prefix {
        statements.push(json!({
            "Effect": "Deny",
            "Action": ["s3:PutObject"],
            "Resource": [format!("arn:aws:s3:::{bucket}/{prefix}*")]
        }));
    }
    Ok(serde_json::to_string(&json!({
        "Version": "2012-10-17",
        "Statement": statements,
    }))?)
}

#[cfg(test)]
mod tests {
    use super::{iam_dimensions, object_write_policy, readonly_policy, run_iam_case};
    use crate::protocol::{
        catalog::{
            IAM_EXPLICIT_DENY_OVERRIDES_ALLOW, IAM_GROUP_POLICY, IAM_USER_MANAGED_POLICY_DETACH,
            IAM_USER_MANAGED_POLICY_READONLY,
        },
        credentials::ActorCredential,
        fixture::{
            cleanup::cleanup_registered_resources, naming::ProtocolResourceNamer,
            registry::ResourceRegistry,
        },
        ports::{
            ActorS3ClientFactory, ExclusiveBucketOwnership, ProtocolAdminCleanupPort,
            ProtocolAdminError, ProtocolBucketPort, ProtocolGroupAdminPort,
            ProtocolIdentityAdminPort, ProtocolListObjectsResult, ProtocolListingPort,
            ProtocolObjectPort, ProtocolPolicyAdminPort, ProtocolS3CleanupPort, ProtocolS3Error,
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
    fn iam_policy_documents_scope_actions_and_explicit_deny() {
        let readonly: serde_json::Value =
            serde_json::from_str(&readonly_policy("bucket").expect("policy")).expect("json");
        assert_eq!(readonly["Statement"][0]["Action"][0], "s3:ListBucket");
        let deny: serde_json::Value =
            serde_json::from_str(&object_write_policy("bucket", Some("denied/")).expect("policy"))
                .expect("json");
        assert_eq!(deny["Statement"][1]["Effect"], "Deny");
        assert_eq!(
            deny["Statement"][1]["Resource"][0],
            "arn:aws:s3:::bucket/denied/*"
        );
    }

    #[derive(Default)]
    struct State {
        users: BTreeSet<String>,
        buckets: BTreeSet<String>,
        policies: BTreeMap<String, serde_json::Value>,
        user_policies: BTreeMap<String, BTreeSet<String>>,
        group_policies: BTreeMap<String, BTreeSet<String>>,
        group_members: BTreeMap<String, BTreeSet<String>>,
        objects: BTreeMap<(String, String), Vec<u8>>,
    }

    #[derive(Clone)]
    struct FakeAdmin(Arc<Mutex<State>>);

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

        async fn groups_with_prefix(
            &self,
            prefix: &str,
        ) -> std::result::Result<Vec<String>, ProtocolAdminError> {
            Ok(self
                .0
                .lock()
                .expect("state")
                .group_members
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
            state.user_policies.remove(access_key);
            for members in state.group_members.values_mut() {
                members.remove(access_key);
            }
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
            is_group: bool,
        ) -> std::result::Result<(), ProtocolAdminError> {
            let mut state = self.0.lock().expect("state");
            let mappings = if is_group {
                &mut state.group_policies
            } else {
                &mut state.user_policies
            };
            mappings
                .entry(principal.to_string())
                .or_default()
                .insert(policy.to_string());
            Ok(())
        }

        async fn detach_policy(
            &self,
            policy: &str,
            principal: &str,
            is_group: bool,
        ) -> std::result::Result<(), ProtocolAdminError> {
            let mut state = self.0.lock().expect("state");
            let mappings = if is_group {
                &mut state.group_policies
            } else {
                &mut state.user_policies
            };
            if let Some(policies) = mappings.get_mut(principal) {
                policies.remove(policy);
                if policies.is_empty() {
                    mappings.remove(principal);
                }
            }
            Ok(())
        }

        async fn policy_attached(
            &self,
            policy: &str,
            principal: &str,
            is_group: bool,
        ) -> std::result::Result<bool, ProtocolAdminError> {
            let state = self.0.lock().expect("state");
            let mappings = if is_group {
                &state.group_policies
            } else {
                &state.user_policies
            };
            Ok(mappings
                .get(principal)
                .is_some_and(|policies| policies.contains(policy)))
        }

        async fn group_contains_member(
            &self,
            group: &str,
            member: &str,
        ) -> std::result::Result<bool, ProtocolAdminError> {
            Ok(self
                .0
                .lock()
                .expect("state")
                .group_members
                .get(group)
                .is_some_and(|members| members.contains(member)))
        }

        async fn update_group_members(
            &self,
            group: &str,
            members: &[String],
            remove: bool,
        ) -> std::result::Result<(), ProtocolAdminError> {
            let mut state = self.0.lock().expect("state");
            let current = state.group_members.entry(group.to_string()).or_default();
            for member in members {
                if remove {
                    current.remove(member);
                } else {
                    current.insert(member.clone());
                }
            }
            Ok(())
        }

        async fn remove_group(&self, group: &str) -> std::result::Result<(), ProtocolAdminError> {
            let mut state = self.0.lock().expect("state");
            state.group_members.remove(group);
            state.group_policies.remove(group);
            Ok(())
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
    impl ProtocolGroupAdminPort for FakeAdmin {
        async fn groups_with_prefix(
            &self,
            prefix: &str,
        ) -> Result<Vec<String>, ProtocolAdminError> {
            FakeAdmin::groups_with_prefix(self, prefix).await
        }
        async fn group_contains_member(
            &self,
            group: &str,
            member: &str,
        ) -> Result<bool, ProtocolAdminError> {
            FakeAdmin::group_contains_member(self, group, member).await
        }
        async fn update_group_members(
            &self,
            group: &str,
            members: &[String],
            remove: bool,
        ) -> Result<(), ProtocolAdminError> {
            FakeAdmin::update_group_members(self, group, members, remove).await
        }
        async fn remove_group(&self, group: &str) -> Result<(), ProtocolAdminError> {
            FakeAdmin::remove_group(self, group).await
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
            prefix: &str,
        ) -> Result<Vec<String>, ProtocolAdminError> {
            FakeAdmin::groups_with_prefix(self, prefix).await
        }
        async fn group_contains_member(
            &self,
            group: &str,
            member: &str,
        ) -> Result<bool, ProtocolAdminError> {
            FakeAdmin::group_contains_member(self, group, member).await
        }
        async fn update_group_members(
            &self,
            group: &str,
            members: &[String],
            remove: bool,
        ) -> Result<(), ProtocolAdminError> {
            FakeAdmin::update_group_members(self, group, members, remove).await
        }
        async fn remove_group(&self, group: &str) -> Result<(), ProtocolAdminError> {
            FakeAdmin::remove_group(self, group).await
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
            _parent_access_key: &str,
            _provider: &str,
        ) -> Result<(), ProtocolAdminError> {
            Ok(())
        }
        async fn sts_sessions_with_parent_for_provider(
            &self,
            _parent_access_key: &str,
            _provider: &str,
        ) -> Result<Vec<String>, ProtocolAdminError> {
            Ok(Vec::new())
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
                .ok_or_else(not_found)
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
            let mut names = state
                .user_policies
                .get(actor)
                .into_iter()
                .flatten()
                .cloned()
                .collect::<BTreeSet<_>>();
            for (group, members) in &state.group_members {
                if members.contains(actor) {
                    names.extend(
                        state
                            .group_policies
                            .get(group)
                            .into_iter()
                            .flatten()
                            .cloned(),
                    );
                }
            }
            let resource = key.map_or_else(
                || format!("arn:aws:s3:::{bucket}"),
                |key| format!("arn:aws:s3:::{bucket}/{key}"),
            );
            let mut allowed = false;
            for policy in names.iter().filter_map(|name| state.policies.get(name)) {
                for statement in policy["Statement"].as_array().into_iter().flatten() {
                    if !contains(&statement["Action"], action)
                        || !matches_resource(&statement["Resource"], &resource)
                    {
                        continue;
                    }
                    match statement["Effect"].as_str() {
                        Some("Deny") => return Err(access_denied()),
                        Some("Allow") => allowed = true,
                        _ => {}
                    }
                }
            }
            if allowed {
                Ok(())
            } else {
                Err(access_denied())
            }
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
    async fn every_iam_case_passes_and_dependency_cleanup_is_complete() {
        for case_id in [
            IAM_EXPLICIT_DENY_OVERRIDES_ALLOW,
            IAM_GROUP_POLICY,
            IAM_USER_MANAGED_POLICY_READONLY,
            IAM_USER_MANAGED_POLICY_DETACH,
        ] {
            let state = Arc::new(Mutex::new(State::default()));
            let admin = FakeAdmin(state.clone());
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
            let execution =
                run_iam_case(case_id, &namer, &mut registry, &admin, &admin_s3, &factory).await;
            let cleanup = cleanup_registered_resources(&mut registry, &admin, &admin_s3).await;
            assert_eq!(
                execution.report.status,
                ProtocolCaseStatus::Passed,
                "{case_id}"
            );
            let dimensions = iam_dimensions(case_id);
            assert!(execution.report.assertions.iter().all(|assertion| {
                assertion.actor_source == dimensions.actor_source
                    && assertion.grant_source == dimensions.grant_source
                    && assertion.policy_effect == dimensions.policy_effect
            }));
            assert!(cleanup.succeeded, "{case_id}: {cleanup:?}");
            assert!(registry.pending_cleanup().next().is_none(), "{case_id}");
            let state = state.lock().expect("state");
            assert!(state.users.is_empty(), "{case_id}");
            assert!(state.buckets.is_empty(), "{case_id}");
            assert!(state.policies.is_empty(), "{case_id}");
            assert!(state.user_policies.is_empty(), "{case_id}");
            assert!(state.group_policies.is_empty(), "{case_id}");
            assert!(state.group_members.is_empty(), "{case_id}");
            assert!(state.objects.is_empty(), "{case_id}");
        }
    }

    fn contains(value: &serde_json::Value, expected: &str) -> bool {
        value
            .as_array()
            .into_iter()
            .flatten()
            .any(|value| value.as_str() == Some(expected))
    }

    fn matches_resource(value: &serde_json::Value, resource: &str) -> bool {
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

    fn access_denied() -> ProtocolS3Error {
        ProtocolS3Error {
            code: "AccessDenied".to_string(),
            status: Some(403),
            request_id: Some("fake".to_string()),
        }
    }

    fn not_found() -> ProtocolS3Error {
        ProtocolS3Error {
            code: "NoSuchKey".to_string(),
            status: Some(404),
            request_id: Some("fake".to_string()),
        }
    }
}
