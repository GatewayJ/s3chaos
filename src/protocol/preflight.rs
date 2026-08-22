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

use anyhow::{Context, Result, anyhow, bail, ensure};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::protocol::{
    catalog::{
        ProtocolCapability, ProtocolCapabilityCheck, ProtocolCapabilitySource,
        ProtocolCapabilityState,
    },
    credentials::ActorCredential,
    fixture::{
        cleanup::cleanup_registered_resources,
        naming::ProtocolResourceNamer,
        registry::{ResourceKind, ResourceRegistry, ResourceState},
    },
    ports::{
        ProtocolAdminCleanupPort, ProtocolAdminRuntimePorts, ProtocolAssumeRoleRequest,
        ProtocolExternalIdentityPort, ProtocolExternalIdentityProviderInfo, ProtocolGroupAdminPort,
        ProtocolIdentityAdminPort, ProtocolPolicyAdminPort, ProtocolPublicAccessBlock,
        ProtocolS3CleanupPort, ProtocolS3PreflightPorts, ProtocolStsPort,
    },
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_identity: Option<ProtocolExternalIdentityProviderInfo>,
    pub selected_cases: Vec<String>,
    pub capability_matrix: Vec<ProtocolCapabilityCheck>,
    pub stale_resources: ProtocolStaleResourceScan,
    pub mutating_permission_probe: ProtocolMutatingProbeSummary,
}

pub fn capability_failures(summary: &ProtocolPreflightSummary) -> Vec<&ProtocolCapabilityCheck> {
    summary
        .capability_matrix
        .iter()
        .filter(|check| check.state == ProtocolCapabilityState::Fail)
        .collect()
}

impl From<&ProtocolPreflightSummary> for ProtocolSuitePlanPreflight {
    fn from(summary: &ProtocolPreflightSummary) -> Self {
        Self {
            endpoint_reachable: summary.endpoint_reachable,
            admin_api_reachable: summary.admin_api_reachable,
            external_identity: summary.external_identity.clone(),
            capability_matrix: summary.capability_matrix.clone(),
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

pub async fn preflight_protocol_suite_with_external(
    suite: &ResolvedProtocolSuite,
    endpoint: &str,
    admin: &(impl ProtocolAdminRuntimePorts + ProtocolAdminCleanupPort),
    s3: &impl ProtocolS3PreflightPorts,
    external_identity: Option<&dyn ProtocolExternalIdentityPort>,
    external_identity_configuration_error: Option<&str>,
    stale_resource_policy: &str,
) -> Result<ProtocolPreflightSummary> {
    ensure!(
        matches!(stale_resource_policy, "fail" | "warn-local-debug"),
        "unsupported stale resource policy {stale_resource_policy}"
    );
    let requires_admin_api = suite
        .cases
        .iter()
        .any(|case| case.has_capability(ProtocolCapability::AdminApi));
    let mut failures = BTreeMap::<ProtocolCapability, String>::new();
    let server_info = match admin.server_info().await {
        Ok(info) => Some(info),
        Err(error) => {
            if requires_admin_api {
                failures.insert(ProtocolCapability::AdminApi, error.to_string());
            }
            None
        }
    };
    let admin_api_reachable = server_info.is_some();
    let requires_external_identity = suite
        .cases
        .iter()
        .any(|case| case.has_capability(ProtocolCapability::ExternalIdp));
    let mut external_missing = false;
    let external_identity = if requires_external_identity {
        if let Some(error) = external_identity_configuration_error {
            failures.insert(ProtocolCapability::ExternalIdp, error.to_string());
            None
        } else if let Some(provider) = external_identity {
            match provider.provider_info().await {
                Ok(info) => Some(info),
                Err(error) => {
                    failures.insert(ProtocolCapability::ExternalIdp, error.to_string());
                    None
                }
            }
        } else {
            external_missing = true;
            None
        }
    } else {
        None
    };
    let fingerprint = if let Some(server_info) = server_info {
        TargetFingerprint::new(
            endpoint,
            &suite.target.region,
            server_info.deployment_id,
            server_info.mode,
            server_info.region,
        )?
    } else {
        TargetFingerprint::new(
            endpoint,
            &suite.target.region,
            format!("s3-endpoint:{endpoint}"),
            None,
            None,
        )?
    };
    let bucket_prefix = suite.target.ownership.resource_prefixes.bucket.clone();
    let identity_prefix = suite.target.ownership.resource_prefixes.identity.clone();
    let buckets = match s3.list_buckets_with_prefix(&bucket_prefix).await {
        Ok(buckets) => buckets,
        Err(error) => {
            failures.insert(ProtocolCapability::S3, error.to_string());
            Vec::new()
        }
    };
    let requires_iam = suite
        .cases
        .iter()
        .any(|case| case.has_capability(ProtocolCapability::Iam));
    let requires_iam_group = suite
        .cases
        .iter()
        .any(|case| case.has_capability(ProtocolCapability::IamGroup));
    let requires_identity = suite
        .cases
        .iter()
        .any(|case| case.has_capability(ProtocolCapability::Identity));
    let mut identities = Vec::new();
    if requires_identity || requires_iam {
        match ProtocolIdentityAdminPort::users_with_prefix(admin, &identity_prefix).await {
            Ok(users) => identities.extend(users),
            Err(error) => {
                record_user_scan_failure(
                    &mut failures,
                    requires_identity,
                    requires_iam,
                    error.to_string(),
                );
            }
        }
    }
    if requires_iam {
        match ProtocolPolicyAdminPort::policies_with_prefix(admin, &identity_prefix).await {
            Ok(policies) => identities.extend(policies),
            Err(error) => {
                failures.insert(ProtocolCapability::Iam, error.to_string());
            }
        }
    }
    if requires_iam_group {
        match ProtocolGroupAdminPort::groups_with_prefix(admin, &identity_prefix).await {
            Ok(groups) => identities.extend(groups),
            Err(error) => {
                failures.insert(ProtocolCapability::IamGroup, error.to_string());
            }
        }
    }
    identities.sort();
    identities.dedup();

    let required = suite
        .cases
        .iter()
        .flat_map(|case| case.capabilities.iter().copied())
        .collect::<BTreeSet<_>>();
    let capability_matrix = required
        .into_iter()
        .map(|capability| capability_check(capability, &failures, external_missing))
        .collect();

    Ok(ProtocolPreflightSummary {
        api_version: suite.api_version.clone(),
        kind: "ProtocolPreflightSummary".to_string(),
        target_fingerprint: fingerprint,
        endpoint_reachable: true,
        admin_api_reachable,
        external_identity,
        selected_cases: suite.cases.iter().map(|case| case.id.to_string()).collect(),
        capability_matrix,
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

fn capability_check(
    capability: ProtocolCapability,
    failures: &BTreeMap<ProtocolCapability, String>,
    external_missing: bool,
) -> ProtocolCapabilityCheck {
    let source = if capability == ProtocolCapability::ExternalIdp {
        ProtocolCapabilitySource::External
    } else {
        ProtocolCapabilitySource::BuiltIn
    };
    let (state, reason) = if let Some(error) = failures.get(&capability) {
        (
            ProtocolCapabilityState::Fail,
            format!("capability probe failed: {error}"),
        )
    } else if capability == ProtocolCapability::ExternalIdp && external_missing {
        (
            ProtocolCapabilityState::Skip,
            "optional external identity provider is not configured".to_string(),
        )
    } else if matches!(
        capability,
        ProtocolCapability::Kms | ProtocolCapability::Sns
    ) {
        (
            ProtocolCapabilityState::Fail,
            "required built-in capability has no registered protocol adapter".to_string(),
        )
    } else {
        (
            ProtocolCapabilityState::Pass,
            "required adapter is available; destructive permissions are verified by the mutating preflight probe"
                .to_string(),
        )
    };
    ProtocolCapabilityCheck {
        capability,
        source,
        state,
        reason,
    }
}

fn record_user_scan_failure(
    failures: &mut BTreeMap<ProtocolCapability, String>,
    requires_identity: bool,
    requires_iam: bool,
    error: String,
) {
    if requires_identity {
        failures.insert(ProtocolCapability::Identity, error.clone());
    }
    if requires_iam {
        failures.insert(ProtocolCapability::Iam, error);
    }
}

#[derive(Debug)]
pub(crate) struct ProtocolMutatingProbeExecution {
    pub summary: ProtocolMutatingProbeSummary,
    pub cleanup: ProtocolCleanupReport,
    pub forbidden_secrets: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ProtocolProbeCapabilities {
    pub bucket_policy: bool,
    pub iam: bool,
    pub iam_group: bool,
    pub assume_role: bool,
    pub versioning: bool,
    pub public_access_block: bool,
}

impl ProtocolProbeCapabilities {
    pub fn from_suite(suite: &ResolvedProtocolSuite) -> Self {
        let requires = |capability| {
            suite
                .cases
                .iter()
                .any(|case| case.has_capability(capability))
        };
        Self {
            bucket_policy: requires(ProtocolCapability::BucketPolicy),
            iam: requires(ProtocolCapability::Iam),
            iam_group: requires(ProtocolCapability::IamGroup),
            assume_role: requires(ProtocolCapability::StsAssumeRole),
            versioning: requires(ProtocolCapability::Versioning),
            public_access_block: requires(ProtocolCapability::PublicAccessBlock),
        }
    }
}

pub(crate) async fn run_mutating_permission_probe(
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    admin: &(impl ProtocolAdminRuntimePorts + ProtocolAdminCleanupPort),
    s3: &impl ProtocolS3PreflightPorts,
    sts: Option<&dyn ProtocolStsPort>,
    capabilities: ProtocolProbeCapabilities,
) -> ProtocolMutatingProbeExecution {
    let case_id = "preflight-permission-probe";
    let mut forbidden_secrets = Vec::new();
    let result = run_probe_resources(
        namer,
        registry,
        admin,
        s3,
        sts,
        capabilities,
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

pub(crate) async fn cleanup_interrupted_mutating_permission_probe(
    registry: &mut ResourceRegistry,
    admin: &impl ProtocolAdminCleanupPort,
    s3: &impl ProtocolS3CleanupPort,
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

async fn run_probe_resources(
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    admin: &(impl ProtocolAdminRuntimePorts + ProtocolAdminCleanupPort),
    s3: &impl ProtocolS3PreflightPorts,
    sts: Option<&dyn ProtocolStsPort>,
    capabilities: ProtocolProbeCapabilities,
    forbidden_secrets: &mut Vec<String>,
) -> Result<(usize, usize)> {
    let case_id = "preflight-permission-probe";
    registry.set_versioned_cleanup(capabilities.versioning)?;
    ensure!(
        !capabilities.assume_role || capabilities.iam,
        "AssumeRole preflight requires IAM"
    );
    let requires_identity = capabilities.bucket_policy || capabilities.iam;
    let (user_name, user_handle, user) = if requires_identity {
        let user_name = namer.iam_user(case_id, 0)?;
        let user_handle = registry.plan_for_phase(
            ResourceKind::IamUser,
            user_name.as_str(),
            case_id,
            Vec::new(),
            "preflight",
        )?;
        let user = ActorCredential::generated("preflight-user", &user_name, &user_handle.id)?;
        forbidden_secrets.push(user.secret_key().to_string());
        registry.transition(&user_handle.id, ResourceState::Creating, None)?;
        admin.create_user(&user).await?;
        registry.transition(&user_handle.id, ResourceState::Created, None)?;
        (Some(user_name), Some(user_handle), Some(user))
    } else {
        (None, None, None)
    };

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

    if capabilities.versioning {
        s3.put_bucket_versioning(&bucket, true).await?;
    }

    if capabilities.public_access_block {
        let public_access_block_handle = registry.plan_for_phase(
            ResourceKind::PublicAccessBlock,
            &bucket,
            case_id,
            vec![bucket_handle.id.clone()],
            "preflight",
        )?;
        registry.transition(
            &public_access_block_handle.id,
            ResourceState::Creating,
            None,
        )?;
        let configuration = ProtocolPublicAccessBlock {
            block_public_acls: true,
            ignore_public_acls: true,
            block_public_policy: true,
            restrict_public_buckets: true,
        };
        s3.put_public_access_block(&bucket, configuration).await?;
        ensure!(
            s3.get_public_access_block(&bucket).await? == configuration,
            "S3 preflight public access block round-trip changed the configuration"
        );
        registry.transition(&public_access_block_handle.id, ResourceState::Created, None)?;
    }

    if capabilities.bucket_policy {
        let user_name = user_name
            .as_deref()
            .context("bucket-policy probe omitted IAM user")?;
        let user_handle = user_handle
            .as_ref()
            .context("bucket-policy probe omitted IAM user handle")?;
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
    }

    if capabilities.iam {
        let user_name = user_name.as_ref().context("IAM probe omitted IAM user")?;
        let user_handle = user_handle
            .as_ref()
            .context("IAM probe omitted IAM user handle")?;
        let user = user.as_ref().context("IAM probe omitted IAM credentials")?;
        let iam_policy_name = namer.iam_policy(case_id, 0)?;
        let iam_policy_handle = registry.plan_for_phase(
            ResourceKind::IamPolicy,
            &iam_policy_name,
            case_id,
            Vec::new(),
            "preflight",
        )?;
        registry.transition(&iam_policy_handle.id, ResourceState::Creating, None)?;
        let mut statements = vec![serde_json::json!({
            "Effect": "Allow",
            "Action": ["s3:ListBucket"],
            "Resource": [format!("arn:aws:s3:::{bucket}")]
        })];
        if capabilities.assume_role {
            statements.push(serde_json::json!({
                "Effect": "Allow",
                "Action": ["sts:AssumeRole"]
            }));
        }
        let iam_policy = serde_json::to_string(&serde_json::json!({
            "Version": "2012-10-17",
            "Statement": statements
        }))?;
        admin.create_policy(&iam_policy_name, &iam_policy).await?;
        registry.transition(&iam_policy_handle.id, ResourceState::Created, None)?;

        let user_attachment = registry.plan_policy_attachment_for_phase(
            &iam_policy_name,
            user_name.as_str(),
            false,
            case_id,
            vec![iam_policy_handle.id.clone(), user_handle.id.clone()],
            "preflight",
        )?;
        registry.transition(&user_attachment.id, ResourceState::Creating, None)?;
        admin
            .attach_policy(&iam_policy_name, user_name, false)
            .await?;
        registry.transition(&user_attachment.id, ResourceState::Created, None)?;

        if capabilities.assume_role {
            let sts = sts.ok_or_else(|| anyhow!("STS preflight port is unavailable"))?;
            let session_handle = registry.plan_sts_session_for_phase(
                user_name.as_str(),
                case_id,
                vec![user_handle.id.clone(), user_attachment.id.clone()],
                "preflight",
            )?;
            registry.transition(&session_handle.id, ResourceState::Creating, None)?;
            let session = sts
                .assume_role(
                    user,
                    &ProtocolAssumeRoleRequest {
                        duration_seconds: 900,
                        session_policy: None,
                    },
                    &session_handle.id,
                )
                .await?;
            registry.transition(&session_handle.id, ResourceState::Created, None)?;
            forbidden_secrets.push(session.access_key().to_string());
            forbidden_secrets.push(session.secret_key().to_string());
            if let Some(token) = session.session_token() {
                forbidden_secrets.push(token.to_string());
            }
        }

        if capabilities.iam_group {
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
                user_name.as_str(),
                case_id,
                vec![group_handle.id.clone(), user_handle.id.clone()],
                "preflight",
            )?;
            registry.transition(&membership.id, ResourceState::Creating, None)?;
            ProtocolGroupAdminPort::update_group_members(
                admin,
                &group_name,
                std::slice::from_ref(user_name),
                false,
            )
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
    let key = format!("{prefix}object");
    s3.put_object(&bucket, &key, b"preflight-object").await?;
    if capabilities.versioning {
        s3.put_object(&bucket, &key, b"preflight-object").await?;
    }
    ensure!(
        s3.get_object(&bucket, &key).await? == b"preflight-object",
        "S3 preflight object round-trip changed the payload"
    );
    ensure!(
        s3.list_objects(&bucket)
            .await?
            .iter()
            .any(|entry| entry == &key),
        "S3 preflight did not list the created object"
    );
    s3.delete_object(&bucket, &key).await?;
    registry.transition(&object_handle.id, ResourceState::Created, None)?;
    let versions = if capabilities.versioning {
        s3.list_object_versions(&bucket).await?
    } else {
        Vec::new()
    };
    let version_count = versions.iter().filter(|entry| !entry.delete_marker).count();
    let delete_marker_count = versions.iter().filter(|entry| entry.delete_marker).count();
    if capabilities.versioning {
        ensure!(
            version_count >= 2 && delete_marker_count >= 1,
            "S3 preflight versioning did not preserve two versions and a delete marker"
        );
    }
    Ok((version_count, delete_marker_count))
}

#[cfg(test)]
mod tests {
    use super::{
        ProtocolProbeCapabilities, capability_check, cleanup_interrupted_mutating_permission_probe,
        enforce_stale_resource_policy, record_user_scan_failure, run_mutating_permission_probe,
    };
    use crate::protocol::{
        catalog::{ProtocolCapability, ProtocolCapabilitySource, ProtocolCapabilityState},
        credentials::ActorCredential,
        fixture::{
            naming::ProtocolResourceNamer,
            registry::{ResourceKind, ResourceRegistry, ResourceState},
        },
        ports::{
            ExclusiveBucketOwnership, ProtocolAdminCleanupPort, ProtocolAdminError,
            ProtocolAdminServerPort, ProtocolAssumeRoleRequest, ProtocolAuthorizationPort,
            ProtocolBucketConfigPort, ProtocolBucketPort, ProtocolGroupAdminPort,
            ProtocolIdentityAdminPort, ProtocolListObjectsResult, ProtocolListingPort,
            ProtocolObjectPort, ProtocolObjectVersion, ProtocolPolicyAdminPort,
            ProtocolPublicAccessBlock, ProtocolS3CleanupPort, ProtocolS3Error, ProtocolServerInfo,
            ProtocolSessionAdminPort, ProtocolStsError, ProtocolStsPort, ProtocolVersioningPort,
        },
        preflight::{ProtocolPreflightSummary, ProtocolStaleResourceScan},
        suite_plan::{
            ProtocolMutatingProbeStatus, ProtocolMutatingProbeSummary, TargetFingerprint,
        },
    };
    use async_trait::async_trait;
    use std::{
        collections::BTreeMap,
        sync::{Arc, Mutex},
    };

    #[test]
    fn iam_user_scan_failure_marks_the_required_iam_capability_failed() {
        let mut failures = BTreeMap::new();
        record_user_scan_failure(&mut failures, false, true, "user scan failed".to_string());

        let check = capability_check(ProtocolCapability::Iam, &failures, false);
        assert_eq!(check.state, ProtocolCapabilityState::Fail);
        assert!(check.reason.contains("user scan failed"));
        assert!(!failures.contains_key(&ProtocolCapability::Identity));
    }

    #[derive(Default)]
    struct State {
        users: Vec<String>,
        buckets: Vec<String>,
        versions: Vec<ProtocolObjectVersion>,
        policy_present: bool,
        fail_policy_put: bool,
        iam_policies: Vec<String>,
        iam_policy_documents: Vec<String>,
        iam_groups: Vec<String>,
        iam_attachments: Vec<(String, String, bool)>,
        iam_memberships: Vec<(String, String)>,
        sts_sessions: Vec<(String, String)>,
        versioning_enable_count: usize,
        versioning_enabled: bool,
        public_access_block: Option<ProtocolPublicAccessBlock>,
        group_mutation_count: usize,
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

    impl FakeAdmin {
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

        async fn policies_with_prefix(
            &self,
            prefix: &str,
        ) -> std::result::Result<Vec<String>, ProtocolAdminError> {
            Ok(self
                .0
                .lock()
                .expect("state")
                .iam_policies
                .iter()
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
                .iam_groups
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

        async fn policy_attached(
            &self,
            policy: &str,
            principal: &str,
            is_group: bool,
        ) -> std::result::Result<bool, ProtocolAdminError> {
            Ok(self
                .0
                .lock()
                .expect("state")
                .iam_attachments
                .iter()
                .any(|item| item == &(policy.to_string(), principal.to_string(), is_group)))
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
                .iam_memberships
                .iter()
                .any(|item| item == &(group.to_string(), member.to_string())))
        }

        async fn sts_sessions_with_parent(
            &self,
            parent_access_key: &str,
        ) -> std::result::Result<Vec<String>, ProtocolAdminError> {
            Ok(self
                .0
                .lock()
                .expect("state")
                .sts_sessions
                .iter()
                .filter(|(parent, _)| parent == parent_access_key)
                .map(|(_, session)| session.clone())
                .collect())
        }

        async fn create_policy(
            &self,
            name: &str,
            document: &str,
        ) -> std::result::Result<(), ProtocolAdminError> {
            let mut state = self.0.lock().expect("state");
            state.iam_policies.push(name.to_string());
            state.iam_policy_documents.push(document.to_string());
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
            let mut state = self.0.lock().expect("state");
            if is_group {
                state.group_mutation_count += 1;
            }
            state
                .iam_attachments
                .push((policy.to_string(), principal.to_string(), is_group));
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
            state.group_mutation_count += 1;
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
    impl ProtocolAdminServerPort for FakeAdmin {
        async fn server_info(&self) -> Result<ProtocolServerInfo, ProtocolAdminError> {
            FakeAdmin::server_info(self).await
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

    impl FakeS3 {
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

        async fn get_bucket_policy(
            &self,
            _bucket: &str,
        ) -> std::result::Result<String, ProtocolS3Error> {
            if self.0.lock().expect("state").policy_present {
                Ok("{}".to_string())
            } else {
                Err(ProtocolS3Error {
                    code: "NoSuchBucketPolicy".to_string(),
                    status: Some(404),
                    request_id: None,
                })
            }
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
            Ok(self
                .0
                .lock()
                .expect("state")
                .versions
                .iter()
                .filter(|entry| !entry.delete_marker)
                .map(|entry| entry.key.clone())
                .collect())
        }

        async fn put_object(
            &self,
            _bucket: &str,
            key: &str,
            _body: &[u8],
        ) -> std::result::Result<(), ProtocolS3Error> {
            let mut state = self.0.lock().expect("state");
            let version_id = format!("v{}", state.versions.len() + 1);
            if !state.versioning_enabled {
                state.versions.retain(|version| version.key != key);
            }
            state.versions.push(ProtocolObjectVersion {
                key: key.to_string(),
                version_id,
                delete_marker: false,
            });
            Ok(())
        }

        async fn get_object(
            &self,
            _bucket: &str,
            _key: &str,
        ) -> std::result::Result<Vec<u8>, ProtocolS3Error> {
            Ok(b"preflight-object".to_vec())
        }

        async fn delete_object(
            &self,
            _bucket: &str,
            key: &str,
        ) -> std::result::Result<(), ProtocolS3Error> {
            let mut state = self.0.lock().expect("state");
            if state.versioning_enabled {
                let version_id = format!("d{}", state.versions.len() + 1);
                state.versions.push(ProtocolObjectVersion {
                    key: key.to_string(),
                    version_id,
                    delete_marker: true,
                });
            } else {
                state.versions.retain(|version| version.key != key);
            }
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

        async fn put_bucket_versioning(
            &self,
            _bucket: &str,
            enabled: bool,
        ) -> std::result::Result<(), ProtocolS3Error> {
            let mut state = self.0.lock().expect("state");
            state.versioning_enabled = enabled;
            state.versioning_enable_count += usize::from(enabled);
            Ok(())
        }

        async fn put_public_access_block(
            &self,
            _bucket: &str,
            configuration: ProtocolPublicAccessBlock,
        ) -> std::result::Result<(), ProtocolS3Error> {
            self.0.lock().expect("state").public_access_block = Some(configuration);
            Ok(())
        }

        async fn get_public_access_block(
            &self,
            _bucket: &str,
        ) -> std::result::Result<ProtocolPublicAccessBlock, ProtocolS3Error> {
            self.0
                .lock()
                .expect("state")
                .public_access_block
                .ok_or_else(|| ProtocolS3Error {
                    code: "NoSuchPublicAccessBlockConfiguration".to_string(),
                    status: Some(404),
                    request_id: None,
                })
        }

        async fn delete_public_access_block(
            &self,
            _bucket: &str,
        ) -> std::result::Result<(), ProtocolS3Error> {
            self.0.lock().expect("state").public_access_block = None;
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
            self.0
                .lock()
                .expect("state")
                .buckets
                .iter()
                .any(|candidate| candidate == bucket)
                .then_some(())
                .ok_or_else(|| ProtocolS3Error {
                    code: "NoSuchBucket".to_string(),
                    status: Some(404),
                    request_id: None,
                })
        }
    }

    #[async_trait]
    impl ProtocolAuthorizationPort for FakeS3 {
        async fn put_bucket_policy(
            &self,
            bucket: &str,
            policy: &str,
        ) -> Result<(), ProtocolS3Error> {
            FakeS3::put_bucket_policy(self, bucket, policy).await
        }
        async fn get_bucket_policy(&self, bucket: &str) -> Result<String, ProtocolS3Error> {
            FakeS3::get_bucket_policy(self, bucket).await
        }
        async fn delete_bucket_policy(&self, bucket: &str) -> Result<(), ProtocolS3Error> {
            FakeS3::delete_bucket_policy(self, bucket).await
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
    impl ProtocolVersioningPort for FakeS3 {
        async fn put_bucket_versioning(
            &self,
            bucket: &str,
            enabled: bool,
        ) -> Result<(), ProtocolS3Error> {
            FakeS3::put_bucket_versioning(self, bucket, enabled).await
        }
        async fn get_object_version(
            &self,
            bucket: &str,
            key: &str,
            version_id: &str,
        ) -> Result<Vec<u8>, ProtocolS3Error> {
            if self
                .0
                .lock()
                .expect("state")
                .versions
                .iter()
                .any(|version| {
                    version.key == key && version.version_id == version_id && !version.delete_marker
                })
            {
                FakeS3::get_object(self, bucket, key).await
            } else {
                Err(ProtocolS3Error {
                    code: "NoSuchVersion".to_string(),
                    status: Some(404),
                    request_id: None,
                })
            }
        }
        async fn list_object_versions(
            &self,
            bucket: &str,
        ) -> Result<Vec<ProtocolObjectVersion>, ProtocolS3Error> {
            FakeS3::list_object_versions(self, bucket).await
        }
        async fn delete_object_version(
            &self,
            bucket: &str,
            key: &str,
            version_id: &str,
        ) -> Result<(), ProtocolS3Error> {
            FakeS3::delete_object_version(self, bucket, key, version_id).await
        }
    }

    #[async_trait]
    impl ProtocolBucketConfigPort for FakeS3 {
        async fn put_public_access_block(
            &self,
            bucket: &str,
            configuration: ProtocolPublicAccessBlock,
        ) -> Result<(), ProtocolS3Error> {
            FakeS3::put_public_access_block(self, bucket, configuration).await
        }
        async fn get_public_access_block(
            &self,
            bucket: &str,
        ) -> Result<ProtocolPublicAccessBlock, ProtocolS3Error> {
            FakeS3::get_public_access_block(self, bucket).await
        }
        async fn delete_public_access_block(&self, bucket: &str) -> Result<(), ProtocolS3Error> {
            FakeS3::delete_public_access_block(self, bucket).await
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
            include_versions: bool,
        ) -> Result<(), ProtocolS3Error> {
            let bucket = ownership.bucket();
            if include_versions {
                for version in FakeS3::list_object_versions(self, bucket).await? {
                    FakeS3::delete_object_version(self, bucket, &version.key, &version.version_id)
                        .await?;
                }
            }
            for key in FakeS3::list_objects(self, bucket).await? {
                FakeS3::delete_object(self, bucket, &key).await?;
            }
            FakeS3::delete_bucket(self, bucket).await
        }
        async fn cleanup_object_prefix(
            &self,
            bucket: &str,
            prefix: &str,
            include_versions: bool,
        ) -> Result<(), ProtocolS3Error> {
            if include_versions {
                for version in FakeS3::list_object_versions(self, bucket)
                    .await?
                    .into_iter()
                    .filter(|version| version.key.starts_with(prefix))
                {
                    FakeS3::delete_object_version(self, bucket, &version.key, &version.version_id)
                        .await?;
                }
            }
            for key in FakeS3::list_objects(self, bucket)
                .await?
                .into_iter()
                .filter(|key| key.starts_with(prefix))
            {
                FakeS3::delete_object(self, bucket, &key).await?;
            }
            Ok(())
        }
        async fn cleanup_object_prefix_exists(
            &self,
            bucket: &str,
            prefix: &str,
            include_versions: bool,
        ) -> Result<bool, ProtocolS3Error> {
            if FakeS3::list_objects(self, bucket)
                .await?
                .iter()
                .any(|key| key.starts_with(prefix))
            {
                return Ok(true);
            }
            Ok(include_versions
                && FakeS3::list_object_versions(self, bucket)
                    .await?
                    .iter()
                    .any(|version| version.key.starts_with(prefix)))
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
            bucket: &str,
        ) -> Result<bool, ProtocolS3Error> {
            Ok(FakeS3::get_bucket_policy(self, bucket).await.is_ok())
        }
        async fn cleanup_delete_public_access_block(
            &self,
            bucket: &str,
        ) -> Result<(), ProtocolS3Error> {
            FakeS3::delete_public_access_block(self, bucket).await
        }
        async fn cleanup_public_access_block_exists(
            &self,
            bucket: &str,
        ) -> Result<bool, ProtocolS3Error> {
            Ok(FakeS3::get_public_access_block(self, bucket).await.is_ok())
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
    async fn full_mutating_probe_covers_selected_capabilities_and_cleans_every_resource() {
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
            ProtocolProbeCapabilities {
                bucket_policy: true,
                iam: true,
                iam_group: true,
                assume_role: true,
                versioning: true,
                public_access_block: true,
            },
        )
        .await;

        assert_eq!(
            execution.summary.status,
            ProtocolMutatingProbeStatus::Passed,
            "{execution:?}"
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
        assert_eq!(state.versioning_enable_count, 1);
        assert!(state.public_access_block.is_none());
    }

    #[tokio::test]
    async fn s3_only_mutating_probe_skips_policy_iam_sts_and_versioning() {
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
            ProtocolProbeCapabilities::default(),
        )
        .await;

        assert_eq!(
            execution.summary.status,
            ProtocolMutatingProbeStatus::Passed,
            "{execution:?}"
        );
        assert!(execution.cleanup.succeeded);
        assert!(registry.pending_cleanup().next().is_none());
        let state = state.lock().expect("state");
        assert!(state.users.is_empty());
        assert!(state.buckets.is_empty());
        assert!(!state.policy_present);
        assert!(state.iam_policies.is_empty());
        assert!(state.iam_groups.is_empty());
        assert!(state.sts_sessions.is_empty());
        assert_eq!(state.versioning_enable_count, 0);
    }

    #[tokio::test]
    async fn iam_only_probe_does_not_require_sts_or_group_apis() {
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
            None,
            ProtocolProbeCapabilities {
                bucket_policy: false,
                iam: true,
                iam_group: false,
                assume_role: false,
                versioning: false,
                public_access_block: false,
            },
        )
        .await;

        assert_eq!(
            execution.summary.status,
            ProtocolMutatingProbeStatus::Passed,
            "{execution:?}"
        );
        assert!(execution.cleanup.succeeded);
        let state = state.lock().expect("state");
        assert_eq!(state.group_mutation_count, 0);
        assert!(state.iam_groups.is_empty());
        assert!(state.iam_memberships.is_empty());
        assert!(
            state
                .iam_policy_documents
                .iter()
                .all(|document| !document.contains("sts:AssumeRole"))
        );
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
            external_identity: None,
            selected_cases: Vec::new(),
            capability_matrix: Vec::new(),
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

    #[test]
    fn capability_matrix_distinguishes_missing_external_and_required_builtin() {
        let external = capability_check(ProtocolCapability::ExternalIdp, &BTreeMap::new(), true);
        assert_eq!(external.source, ProtocolCapabilitySource::External);
        assert_eq!(external.state, ProtocolCapabilityState::Skip);

        let kms = capability_check(ProtocolCapability::Kms, &BTreeMap::new(), false);
        assert_eq!(kms.source, ProtocolCapabilitySource::BuiltIn);
        assert_eq!(kms.state, ProtocolCapabilityState::Fail);

        let mut failures = BTreeMap::new();
        failures.insert(
            ProtocolCapability::ExternalIdp,
            "invalid issuer".to_string(),
        );
        let broken = capability_check(ProtocolCapability::ExternalIdp, &failures, false);
        assert_eq!(broken.state, ProtocolCapabilityState::Fail);
        assert!(broken.reason.contains("invalid issuer"));

        let s3 = capability_check(ProtocolCapability::S3, &BTreeMap::new(), false);
        assert_eq!(s3.state, ProtocolCapabilityState::Pass);
    }
}
