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
use serde::{Deserialize, Serialize};

use crate::protocol::{
    credentials::ActorCredential,
    fixture::{
        cleanup::cleanup_registered_resources,
        naming::ProtocolResourceNamer,
        registry::{ResourceKind, ResourceRegistry, ResourceState},
    },
    ports::{ProtocolAdminPort, ProtocolAssumeRoleRequest, ProtocolS3Port, ProtocolStsPort},
    reporting::ProtocolCleanupReport,
    suite::ResolvedProtocolSuite,
    suite_plan::{
        ProtocolMutatingProbeStatus, ProtocolMutatingProbeSummary, ProtocolSuitePlanPreflight,
        TargetFingerprint,
    },
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolPreflightSummary {
    pub api_version: String,
    pub kind: String,
    pub target_fingerprint: TargetFingerprint,
    pub endpoint_reachable: bool,
    pub admin_api_reachable: bool,
    pub selected_cases: Vec<String>,
    pub stale_resources: ProtocolStaleResourceScan,
    pub mutating_permission_probe: ProtocolMutatingProbeSummary,
}

impl From<&ProtocolPreflightSummary> for ProtocolSuitePlanPreflight {
    fn from(summary: &ProtocolPreflightSummary) -> Self {
        Self {
            endpoint_reachable: summary.endpoint_reachable,
            admin_api_reachable: summary.admin_api_reachable,
            stale_buckets: summary.stale_resources.buckets.clone(),
            stale_identities: summary.stale_resources.identities.clone(),
            stale_resource_policy: summary.stale_resources.policy.clone(),
            mutating_permission_probe: summary.mutating_permission_probe.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolStaleResourceScan {
    pub bucket_prefix: String,
    pub identity_prefix: String,
    pub buckets: Vec<String>,
    pub identities: Vec<String>,
    pub policy: String,
}

pub async fn preflight_protocol_suite(
    suite: &ResolvedProtocolSuite,
    endpoint: &str,
    admin: &impl ProtocolAdminPort,
    s3: &impl ProtocolS3Port,
    stale_resource_policy: &str,
) -> Result<ProtocolPreflightSummary> {
    ensure!(
        matches!(stale_resource_policy, "fail" | "warn-local-debug"),
        "unsupported stale resource policy {stale_resource_policy}"
    );
    let server_info = admin.server_info().await?;
    let fingerprint = TargetFingerprint::new(
        endpoint,
        &suite.target.region,
        server_info.deployment_id,
        server_info.mode,
        server_info.region,
    )?;
    let bucket_prefix = suite.target.ownership.resource_prefixes.bucket.clone();
    let identity_prefix = suite.target.ownership.resource_prefixes.identity.clone();
    let buckets = s3.list_buckets_with_prefix(&bucket_prefix).await?;
    let mut identities = admin.users_with_prefix(&identity_prefix).await?;
    let requires_iam = suite
        .cases
        .iter()
        .any(|case| case.requires.contains(&"iam"));
    if requires_iam {
        identities.extend(admin.policies_with_prefix(&identity_prefix).await?);
        identities.extend(admin.groups_with_prefix(&identity_prefix).await?);
    }
    identities.sort();
    identities.dedup();

    Ok(ProtocolPreflightSummary {
        api_version: suite.api_version.clone(),
        kind: "ProtocolPreflightSummary".to_string(),
        target_fingerprint: fingerprint,
        endpoint_reachable: true,
        admin_api_reachable: true,
        selected_cases: suite.cases.iter().map(|case| case.id.to_string()).collect(),
        stale_resources: ProtocolStaleResourceScan {
            bucket_prefix,
            identity_prefix,
            buckets,
            identities,
            policy: stale_resource_policy.to_string(),
        },
        mutating_permission_probe: ProtocolMutatingProbeSummary::not_run(),
    })
}

pub fn enforce_stale_resource_policy(summary: &ProtocolPreflightSummary) -> Result<()> {
    let stale = !summary.stale_resources.buckets.is_empty()
        || !summary.stale_resources.identities.is_empty();
    if stale && summary.stale_resources.policy == "fail" {
        bail!(
            "protocol preflight found stale resources: {} bucket(s), {} identity resource(s); clean the owning artifact registry before running",
            summary.stale_resources.buckets.len(),
            summary.stale_resources.identities.len()
        );
    }
    Ok(())
}

pub struct ProtocolMutatingProbeExecution {
    pub summary: ProtocolMutatingProbeSummary,
    pub cleanup: ProtocolCleanupReport,
    pub forbidden_secrets: Vec<String>,
}

pub async fn run_mutating_permission_probe(
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    admin: &impl ProtocolAdminPort,
    s3: &impl ProtocolS3Port,
    sts: Option<&dyn ProtocolStsPort>,
    requires_iam: bool,
    requires_sts: bool,
) -> ProtocolMutatingProbeExecution {
    let case_id = "preflight-permission-probe";
    let mut forbidden_secrets = Vec::new();
    let result = run_probe_resources(
        case_id,
        namer,
        registry,
        admin,
        s3,
        ProbeCapabilities {
            sts,
            requires_iam,
            requires_sts,
        },
        &mut forbidden_secrets,
    )
    .await;
    let cleanup = cleanup_registered_resources(registry, admin, s3).await;
    let (status, version_count, delete_marker_count, error) = match result {
        Ok((versions, markers)) if cleanup.succeeded => {
            (ProtocolMutatingProbeStatus::Passed, versions, markers, None)
        }
        Ok((versions, markers)) => (
            ProtocolMutatingProbeStatus::Failed,
            versions,
            markers,
            Some("preflight probe cleanup left registered resources".to_string()),
        ),
        Err(error) => (
            ProtocolMutatingProbeStatus::Failed,
            0,
            0,
            Some(error.to_string()),
        ),
    };
    ProtocolMutatingProbeExecution {
        summary: ProtocolMutatingProbeSummary {
            status,
            synthetic_case_id: case_id.to_string(),
            version_count,
            delete_marker_count,
            cleanup_succeeded: cleanup.succeeded,
            cleanup_report: Some("preflight-cleanup-report.json".to_string()),
            error,
        },
        cleanup,
        forbidden_secrets,
    }
}

pub async fn cleanup_interrupted_mutating_permission_probe(
    registry: &mut ResourceRegistry,
    admin: &impl ProtocolAdminPort,
    s3: &impl ProtocolS3Port,
    reason: impl Into<String>,
) -> ProtocolMutatingProbeExecution {
    let cleanup = cleanup_registered_resources(registry, admin, s3).await;
    ProtocolMutatingProbeExecution {
        summary: ProtocolMutatingProbeSummary {
            status: ProtocolMutatingProbeStatus::Failed,
            synthetic_case_id: "preflight-permission-probe".to_string(),
            version_count: 0,
            delete_marker_count: 0,
            cleanup_succeeded: cleanup.succeeded,
            cleanup_report: Some("preflight-cleanup-report.json".to_string()),
            error: Some(reason.into()),
        },
        cleanup,
        forbidden_secrets: Vec::new(),
    }
}

struct ProbeCapabilities<'a> {
    sts: Option<&'a dyn ProtocolStsPort>,
    requires_iam: bool,
    requires_sts: bool,
}

async fn run_probe_resources(
    case_id: &str,
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    admin: &impl ProtocolAdminPort,
    s3: &impl ProtocolS3Port,
    capabilities: ProbeCapabilities<'_>,
    forbidden_secrets: &mut Vec<String>,
) -> Result<(usize, usize)> {
    ensure!(
        !capabilities.requires_sts || capabilities.requires_iam,
        "STS preflight requires IAM preflight resources"
    );
    let user_name = namer.iam_user(case_id, 0)?;
    let user_handle = registry.plan_for_phase(
        ResourceKind::IamUser,
        &user_name,
        case_id,
        Vec::new(),
        "preflight",
    )?;
    let user = ActorCredential::generated("preflight-user", &user_name, &user_handle.id)?;
    forbidden_secrets.push(user.secret_key().to_string());
    if let Some(token) = user.session_token() {
        forbidden_secrets.push(token.to_string());
    }
    registry.transition(&user_handle.id, ResourceState::Creating, None)?;
    admin.create_user(&user).await?;
    registry.transition(&user_handle.id, ResourceState::Created, None)?;

    let bucket = namer.bucket(case_id, 0)?;
    let bucket_handle = registry.plan_for_phase(
        ResourceKind::Bucket,
        &bucket,
        case_id,
        Vec::new(),
        "preflight",
    )?;
    registry.transition(&bucket_handle.id, ResourceState::Creating, None)?;
    s3.create_bucket(&bucket).await?;
    registry.transition(&bucket_handle.id, ResourceState::Created, None)?;

    let policy_handle = registry.plan_for_phase(
        ResourceKind::BucketPolicy,
        &bucket,
        case_id,
        vec![bucket_handle.id.clone(), user_handle.id.clone()],
        "preflight",
    )?;
    registry.transition(&policy_handle.id, ResourceState::Creating, None)?;
    let policy = serde_json::to_string(&serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": user_name},
            "Action": ["s3:ListBucket"],
            "Resource": [format!("arn:aws:s3:::{bucket}")]
        }]
    }))?;
    s3.put_bucket_policy(&bucket, &policy).await?;
    registry.transition(&policy_handle.id, ResourceState::Created, None)?;

    if capabilities.requires_iam {
        let iam_policy_name = namer.iam_policy(case_id, 0)?;
        let iam_policy_handle = registry.plan_for_phase(
            ResourceKind::IamPolicy,
            &iam_policy_name,
            case_id,
            Vec::new(),
            "preflight",
        )?;
        registry.transition(&iam_policy_handle.id, ResourceState::Creating, None)?;
        let iam_policy = serde_json::to_string(&serde_json::json!({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:ListBucket"],
                    "Resource": [format!("arn:aws:s3:::{bucket}")]
                },
                {
                    "Effect": "Allow",
                    "Action": ["sts:AssumeRole"]
                }
            ]
        }))?;
        admin.create_policy(&iam_policy_name, &iam_policy).await?;
        registry.transition(&iam_policy_handle.id, ResourceState::Created, None)?;

        let user_attachment = registry.plan_policy_attachment_for_phase(
            &iam_policy_name,
            &user_name,
            false,
            case_id,
            vec![iam_policy_handle.id.clone(), user_handle.id.clone()],
            "preflight",
        )?;
        registry.transition(&user_attachment.id, ResourceState::Creating, None)?;
        admin
            .attach_policy(&iam_policy_name, &user_name, false)
            .await?;
        registry.transition(&user_attachment.id, ResourceState::Created, None)?;

        if capabilities.requires_sts {
            let sts = capabilities
                .sts
                .ok_or_else(|| anyhow!("STS preflight port is unavailable"))?;
            let session_handle = registry.plan_sts_session_for_phase(
                &user_name,
                case_id,
                vec![user_handle.id.clone(), user_attachment.id.clone()],
                "preflight",
            )?;
            registry.transition(&session_handle.id, ResourceState::Creating, None)?;
            let session = sts
                .assume_role(
                    &user,
                    &ProtocolAssumeRoleRequest {
                        duration_seconds: 900,
                        session_policy: None,
                    },
                    &session_handle.id,
                )
                .await?;
            registry.bind_external_name(&session_handle.id, session.access_key())?;
            registry.transition(&session_handle.id, ResourceState::Created, None)?;
            forbidden_secrets.push(session.secret_key().to_string());
            if let Some(token) = session.session_token() {
                forbidden_secrets.push(token.to_string());
            }
        }

        let group_name = namer.iam_group(case_id, 0)?;
        let group_handle = registry.plan_for_phase(
            ResourceKind::IamGroup,
            &group_name,
            case_id,
            Vec::new(),
            "preflight",
        )?;
        registry.transition(&group_handle.id, ResourceState::Creating, None)?;
        let membership = registry.plan_group_membership_for_phase(
            &group_name,
            &user_name,
            case_id,
            vec![group_handle.id.clone(), user_handle.id.clone()],
            "preflight",
        )?;
        registry.transition(&membership.id, ResourceState::Creating, None)?;
        admin
            .update_group_members(&group_name, std::slice::from_ref(&user_name), false)
            .await?;
        registry.transition(&group_handle.id, ResourceState::Created, None)?;
        registry.transition(&membership.id, ResourceState::Created, None)?;

        let group_attachment = registry.plan_policy_attachment_for_phase(
            &iam_policy_name,
            &group_name,
            true,
            case_id,
            vec![iam_policy_handle.id, group_handle.id],
            "preflight",
        )?;
        registry.transition(&group_attachment.id, ResourceState::Creating, None)?;
        admin
            .attach_policy(&iam_policy_name, &group_name, true)
            .await?;
        registry.transition(&group_attachment.id, ResourceState::Created, None)?;
    }

    let prefix = format!("cases/{case_id}/");
    let object_handle = registry.plan_object_prefix_for_phase(
        &bucket,
        &prefix,
        case_id,
        vec![bucket_handle.id],
        "preflight",
    )?;
    registry.transition(&object_handle.id, ResourceState::Creating, None)?;
    s3.enable_bucket_versioning(&bucket).await?;
    let key = format!("{prefix}versioned-object");
    s3.put_object(&bucket, &key, b"preflight-versioned-object")
        .await?;
    s3.delete_object(&bucket, &key).await?;
    let versions = s3.list_object_versions(&bucket).await?;
    let delete_marker_count = versions.iter().filter(|entry| entry.delete_marker).count();
    ensure!(
        versions.iter().any(|entry| !entry.delete_marker),
        "versioning preflight did not observe an object version"
    );
    ensure!(
        delete_marker_count > 0,
        "versioning preflight did not observe a delete marker"
    );
    registry.transition(&object_handle.id, ResourceState::Created, None)?;
    Ok((versions.len(), delete_marker_count))
}

#[cfg(test)]
mod tests {
    use super::{
        cleanup_interrupted_mutating_permission_probe, enforce_stale_resource_policy,
        run_mutating_permission_probe,
    };
    use crate::protocol::{
        credentials::ActorCredential,
        fixture::{
            naming::ProtocolResourceNamer,
            registry::{ResourceKind, ResourceRegistry, ResourceState},
        },
        ports::{
            ProtocolAdminError, ProtocolAdminPort, ProtocolAssumeRoleRequest,
            ProtocolObjectVersion, ProtocolS3Error, ProtocolS3Port, ProtocolServerInfo,
            ProtocolStsError, ProtocolStsPort,
        },
        preflight::{ProtocolPreflightSummary, ProtocolStaleResourceScan},
        suite_plan::{
            ProtocolMutatingProbeStatus, ProtocolMutatingProbeSummary, TargetFingerprint,
        },
    };
    use async_trait::async_trait;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct State {
        users: Vec<String>,
        buckets: Vec<String>,
        versions: Vec<ProtocolObjectVersion>,
        policy_present: bool,
        fail_policy_put: bool,
        iam_policies: Vec<String>,
        iam_groups: Vec<String>,
        iam_attachments: Vec<(String, String, bool)>,
        iam_memberships: Vec<(String, String)>,
        sts_sessions: Vec<(String, String)>,
    }

    #[derive(Clone)]
    struct FakeAdmin(Arc<Mutex<State>>);

    #[derive(Clone)]
    struct FakeS3(Arc<Mutex<State>>);

    #[derive(Clone)]
    struct FakeSts(Arc<Mutex<State>>);

    #[async_trait]
    impl ProtocolStsPort for FakeSts {
        async fn assume_role(
            &self,
            parent: &ActorCredential,
            _request: &ProtocolAssumeRoleRequest,
            source_resource_id: &str,
        ) -> std::result::Result<ActorCredential, ProtocolStsError> {
            let access_key = "preflight-temp-session";
            let mut state = self.0.lock().expect("state");
            state.users.push(access_key.to_string());
            state
                .sts_sessions
                .push((parent.access_key().to_string(), access_key.to_string()));
            ActorCredential::temporary(
                "preflight-sts-session",
                access_key,
                "temporary-secret",
                "temporary-token",
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
    impl ProtocolAdminPort for FakeAdmin {
        async fn server_info(&self) -> std::result::Result<ProtocolServerInfo, ProtocolAdminError> {
            Ok(ProtocolServerInfo {
                deployment_id: "deployment".to_string(),
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
                .filter(|user| user.starts_with(prefix))
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
                .push(credential.access_key().to_string());
            Ok(())
        }

        async fn remove_user(
            &self,
            access_key: &str,
        ) -> std::result::Result<(), ProtocolAdminError> {
            self.0
                .lock()
                .expect("state")
                .users
                .retain(|user| user != access_key);
            Ok(())
        }

        async fn revoke_sts_sessions(
            &self,
            parent_access_key: &str,
        ) -> std::result::Result<(), ProtocolAdminError> {
            let mut state = self.0.lock().expect("state");
            let revoked = state
                .sts_sessions
                .iter()
                .filter(|(parent, _)| parent == parent_access_key)
                .map(|(_, session)| session.clone())
                .collect::<Vec<_>>();
            state
                .sts_sessions
                .retain(|(parent, _)| parent != parent_access_key);
            state.users.retain(|user| !revoked.contains(user));
            Ok(())
        }

        async fn create_policy(
            &self,
            name: &str,
            _document: &str,
        ) -> std::result::Result<(), ProtocolAdminError> {
            self.0
                .lock()
                .expect("state")
                .iam_policies
                .push(name.to_string());
            Ok(())
        }

        async fn remove_policy(&self, name: &str) -> std::result::Result<(), ProtocolAdminError> {
            self.0
                .lock()
                .expect("state")
                .iam_policies
                .retain(|policy| policy != name);
            Ok(())
        }

        async fn attach_policy(
            &self,
            policy: &str,
            principal: &str,
            is_group: bool,
        ) -> std::result::Result<(), ProtocolAdminError> {
            self.0.lock().expect("state").iam_attachments.push((
                policy.to_string(),
                principal.to_string(),
                is_group,
            ));
            Ok(())
        }

        async fn detach_policy(
            &self,
            policy: &str,
            principal: &str,
            is_group: bool,
        ) -> std::result::Result<(), ProtocolAdminError> {
            self.0
                .lock()
                .expect("state")
                .iam_attachments
                .retain(|current| {
                    current.0 != policy || current.1 != principal || current.2 != is_group
                });
            Ok(())
        }

        async fn update_group_members(
            &self,
            group: &str,
            members: &[String],
            remove: bool,
        ) -> std::result::Result<(), ProtocolAdminError> {
            let mut state = self.0.lock().expect("state");
            if !remove && !state.iam_groups.iter().any(|current| current == group) {
                state.iam_groups.push(group.to_string());
            }
            for member in members {
                let relation = (group.to_string(), member.clone());
                if remove {
                    state.iam_memberships.retain(|current| current != &relation);
                } else {
                    state.iam_memberships.push(relation);
                }
            }
            Ok(())
        }

        async fn remove_group(&self, group: &str) -> std::result::Result<(), ProtocolAdminError> {
            self.0
                .lock()
                .expect("state")
                .iam_groups
                .retain(|current| current != group);
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
                .0
                .lock()
                .expect("state")
                .buckets
                .iter()
                .filter(|bucket| bucket.starts_with(prefix))
                .cloned()
                .collect())
        }

        async fn create_bucket(&self, bucket: &str) -> std::result::Result<(), ProtocolS3Error> {
            self.0
                .lock()
                .expect("state")
                .buckets
                .push(bucket.to_string());
            Ok(())
        }

        async fn delete_bucket(&self, bucket: &str) -> std::result::Result<(), ProtocolS3Error> {
            self.0
                .lock()
                .expect("state")
                .buckets
                .retain(|current| current != bucket);
            Ok(())
        }

        async fn put_bucket_policy(
            &self,
            _bucket: &str,
            _policy: &str,
        ) -> std::result::Result<(), ProtocolS3Error> {
            let mut state = self.0.lock().expect("state");
            if state.fail_policy_put {
                return Err(ProtocolS3Error {
                    code: "AccessDenied".to_string(),
                    status: Some(403),
                    request_id: None,
                });
            }
            state.policy_present = true;
            Ok(())
        }

        async fn delete_bucket_policy(
            &self,
            _bucket: &str,
        ) -> std::result::Result<(), ProtocolS3Error> {
            self.0.lock().expect("state").policy_present = false;
            Ok(())
        }

        async fn list_objects(
            &self,
            _bucket: &str,
        ) -> std::result::Result<Vec<String>, ProtocolS3Error> {
            Ok(Vec::new())
        }

        async fn put_object(
            &self,
            _bucket: &str,
            key: &str,
            _body: &[u8],
        ) -> std::result::Result<(), ProtocolS3Error> {
            self.0
                .lock()
                .expect("state")
                .versions
                .push(ProtocolObjectVersion {
                    key: key.to_string(),
                    version_id: "v1".to_string(),
                    delete_marker: false,
                });
            Ok(())
        }

        async fn get_object(
            &self,
            _bucket: &str,
            _key: &str,
        ) -> std::result::Result<Vec<u8>, ProtocolS3Error> {
            Ok(Vec::new())
        }

        async fn delete_object(
            &self,
            _bucket: &str,
            key: &str,
        ) -> std::result::Result<(), ProtocolS3Error> {
            self.0
                .lock()
                .expect("state")
                .versions
                .push(ProtocolObjectVersion {
                    key: key.to_string(),
                    version_id: "marker".to_string(),
                    delete_marker: true,
                });
            Ok(())
        }

        async fn list_object_versions(
            &self,
            _bucket: &str,
        ) -> std::result::Result<Vec<ProtocolObjectVersion>, ProtocolS3Error> {
            Ok(self.0.lock().expect("state").versions.clone())
        }

        async fn delete_object_version(
            &self,
            _bucket: &str,
            key: &str,
            version_id: &str,
        ) -> std::result::Result<(), ProtocolS3Error> {
            self.0
                .lock()
                .expect("state")
                .versions
                .retain(|version| version.key != key || version.version_id != version_id);
            Ok(())
        }

        async fn enable_bucket_versioning(
            &self,
            _bucket: &str,
        ) -> std::result::Result<(), ProtocolS3Error> {
            Ok(())
        }
    }

    fn fingerprint() -> TargetFingerprint {
        TargetFingerprint::new(
            "http://127.0.0.1:9000",
            "us-east-1",
            "deployment",
            None,
            None,
        )
        .expect("fingerprint")
    }

    #[tokio::test]
    async fn mutating_probe_verifies_versions_and_cleans_every_resource() {
        let state = Arc::new(Mutex::new(State::default()));
        let dir = tempfile::tempdir().expect("tempdir");
        let mut registry =
            ResourceRegistry::create(dir.path(), "run", fingerprint()).expect("registry");
        let namer = ProtocolResourceNamer::new("s3c", "s3chaos", "run").expect("namer");
        let execution = run_mutating_permission_probe(
            &namer,
            &mut registry,
            &FakeAdmin(state.clone()),
            &FakeS3(state.clone()),
            Some(&FakeSts(state.clone())),
            true,
            true,
        )
        .await;

        assert_eq!(
            execution.summary.status,
            ProtocolMutatingProbeStatus::Passed
        );
        assert_eq!(execution.summary.version_count, 2);
        assert_eq!(execution.summary.delete_marker_count, 1);
        assert!(execution.cleanup.succeeded);
        assert!(registry.pending_cleanup().next().is_none());
        assert!(
            registry
                .resources
                .iter()
                .all(|resource| resource.owner_phase == "preflight")
        );
        let state = state.lock().expect("state");
        assert!(state.users.is_empty());
        assert!(state.buckets.is_empty());
        assert!(state.versions.is_empty());
        assert!(!state.policy_present);
        assert!(state.iam_policies.is_empty());
        assert!(state.iam_groups.is_empty());
        assert!(
            state.iam_attachments.is_empty(),
            "leftover attachments: {:?}",
            state.iam_attachments
        );
        assert!(state.iam_memberships.is_empty());
    }

    #[tokio::test]
    async fn mutating_probe_failure_still_runs_registry_cleanup() {
        let state = Arc::new(Mutex::new(State {
            fail_policy_put: true,
            ..State::default()
        }));
        let dir = tempfile::tempdir().expect("tempdir");
        let mut registry =
            ResourceRegistry::create(dir.path(), "run", fingerprint()).expect("registry");
        let namer = ProtocolResourceNamer::new("s3c", "s3chaos", "run").expect("namer");
        let execution = run_mutating_permission_probe(
            &namer,
            &mut registry,
            &FakeAdmin(state.clone()),
            &FakeS3(state.clone()),
            None,
            false,
            false,
        )
        .await;

        assert_eq!(
            execution.summary.status,
            ProtocolMutatingProbeStatus::Failed
        );
        assert!(execution.cleanup.succeeded);
        assert!(registry.pending_cleanup().next().is_none());
        let state = state.lock().expect("state");
        assert!(state.users.is_empty());
        assert!(state.buckets.is_empty());
    }

    #[tokio::test]
    async fn interrupted_probe_replays_registry_cleanup() {
        let state = Arc::new(Mutex::new(State {
            users: vec!["s3chaos-interrupted".to_string()],
            buckets: vec!["s3c-interrupted".to_string()],
            ..State::default()
        }));
        let dir = tempfile::tempdir().expect("tempdir");
        let mut registry =
            ResourceRegistry::create(dir.path(), "run", fingerprint()).expect("registry");
        let user = registry
            .plan_for_phase(
                ResourceKind::IamUser,
                "s3chaos-interrupted",
                "preflight-permission-probe",
                Vec::new(),
                "preflight",
            )
            .expect("plan user");
        registry
            .transition(&user.id, ResourceState::Creating, None)
            .expect("start user");
        registry
            .transition(&user.id, ResourceState::Created, None)
            .expect("create user");
        let bucket = registry
            .plan_for_phase(
                ResourceKind::Bucket,
                "s3c-interrupted",
                "preflight-permission-probe",
                Vec::new(),
                "preflight",
            )
            .expect("plan bucket");
        registry
            .transition(&bucket.id, ResourceState::Creating, None)
            .expect("start bucket");
        registry
            .transition(&bucket.id, ResourceState::Created, None)
            .expect("create bucket");

        let execution = cleanup_interrupted_mutating_permission_probe(
            &mut registry,
            &FakeAdmin(state.clone()),
            &FakeS3(state.clone()),
            "forced interruption",
        )
        .await;

        assert_eq!(
            execution.summary.status,
            ProtocolMutatingProbeStatus::Failed
        );
        assert!(execution.summary.cleanup_succeeded);
        assert!(execution.cleanup.succeeded);
        assert!(registry.pending_cleanup().next().is_none());
        let state = state.lock().expect("state");
        assert!(state.users.is_empty());
        assert!(state.buckets.is_empty());
    }

    #[test]
    fn stale_resources_fail_closed_by_default() {
        let summary = ProtocolPreflightSummary {
            api_version: "rustfs.com/s3chaos/v1alpha1".to_string(),
            kind: "ProtocolPreflightSummary".to_string(),
            target_fingerprint: fingerprint(),
            endpoint_reachable: true,
            admin_api_reachable: true,
            selected_cases: Vec::new(),
            stale_resources: ProtocolStaleResourceScan {
                bucket_prefix: "s3c".to_string(),
                identity_prefix: "s3chaos".to_string(),
                buckets: vec!["s3c-stale".to_string()],
                identities: Vec::new(),
                policy: "fail".to_string(),
            },
            mutating_permission_probe: ProtocolMutatingProbeSummary::not_run(),
        };
        assert!(enforce_stale_resource_policy(&summary).is_err());
    }
}
