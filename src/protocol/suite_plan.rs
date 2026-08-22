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

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use uuid::Uuid;

use crate::protocol::{
    catalog::{
        ProtocolCapability, ProtocolCase, ProtocolCleanupScope, ProtocolDomain, ProtocolExecutor,
        ProtocolExpectedOutcome, ProtocolLockRequirement, ProtocolResourceOwnership,
    },
    ports::ProtocolExternalIdentityProviderInfo,
    scheduler::{ProtocolLock, plan_protocol_schedule},
    suite::{ProtocolCleanupPolicy, ProtocolExecutionTimeouts, ResolvedProtocolSuite},
};

pub const PROTOCOL_SUITE_PLAN_KIND: &str = "ProtocolSuitePlan";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TargetFingerprint {
    pub endpoint: String,
    pub region: String,
    pub deployment_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reported_region: Option<String>,
    pub sha256: String,
}

impl TargetFingerprint {
    pub fn new(
        endpoint: impl Into<String>,
        region: impl Into<String>,
        deployment_id: impl Into<String>,
        server_mode: Option<String>,
        reported_region: Option<String>,
    ) -> Result<Self> {
        let endpoint = normalize_endpoint(endpoint.into())?;
        let region = region.into();
        let deployment_id = deployment_id.into();
        ensure!(
            !deployment_id.trim().is_empty(),
            "target deployment id is missing"
        );
        let canonical = format!(
            "{endpoint}\n{region}\n{deployment_id}\n{}\n{}",
            server_mode.as_deref().unwrap_or_default(),
            reported_region.as_deref().unwrap_or_default()
        );
        let sha256 = hex::encode(Sha256::digest(canonical.as_bytes()));
        Ok(Self {
            endpoint,
            region,
            deployment_id,
            server_mode,
            reported_region,
            sha256,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolSuitePlan {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub suite: String,
    pub run_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_revision: Option<String>,
    pub artifact_root: String,
    pub target: ProtocolSuitePlanTarget,
    pub preflight: ProtocolSuitePlanPreflight,
    pub execution: ProtocolSuitePlanExecution,
    pub cases: Vec<ProtocolSuitePlanCase>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolSuitePlanPreflight {
    pub endpoint_reachable: bool,
    pub admin_api_reachable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_identity: Option<ProtocolExternalIdentityProviderInfo>,
    pub stale_buckets: Vec<String>,
    pub stale_identities: Vec<String>,
    pub stale_resource_policy: String,
    pub mutating_permission_probe: ProtocolMutatingProbeSummary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtocolMutatingProbeStatus {
    NotRun,
    Passed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolMutatingProbeSummary {
    pub status: ProtocolMutatingProbeStatus,
    pub synthetic_case_id: String,
    pub version_count: usize,
    pub delete_marker_count: usize,
    pub cleanup_succeeded: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cleanup_report: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ProtocolMutatingProbeSummary {
    pub fn not_run() -> Self {
        Self {
            status: ProtocolMutatingProbeStatus::NotRun,
            synthetic_case_id: "preflight-permission-probe".to_string(),
            version_count: 0,
            delete_marker_count: 0,
            cleanup_succeeded: true,
            cleanup_report: None,
            error: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolSuitePlanTarget {
    pub fingerprint: TargetFingerprint,
    pub credential_provider: String,
    pub admin_profile: String,
    pub ownership_mode: String,
    pub bucket_prefix: String,
    pub identity_prefix: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_identity_profile: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolSuitePlanExecution {
    pub parallelism: usize,
    pub cleanup: ProtocolCleanupPolicy,
    pub timeouts: ProtocolExecutionTimeouts,
    pub eventual_consistency: ProtocolEventualConsistencyPolicy,
    pub cleanup_retry: ProtocolCleanupRetryPolicy,
    pub product_case_retry: ProtocolProductCaseRetryPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolEventualConsistencyPolicy {
    pub deadline_millis: u64,
    pub interval_millis: u64,
}

impl Default for ProtocolEventualConsistencyPolicy {
    fn default() -> Self {
        Self {
            deadline_millis: 15_000,
            interval_millis: 500,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolCleanupRetryPolicy {
    pub mutation_max_attempts: usize,
    pub verification_max_attempts: usize,
    pub initial_backoff_millis: u64,
}

impl Default for ProtocolCleanupRetryPolicy {
    fn default() -> Self {
        Self::STANDARD
    }
}

impl ProtocolCleanupRetryPolicy {
    pub const STANDARD: Self = Self {
        mutation_max_attempts: 4,
        verification_max_attempts: 8,
        initial_backoff_millis: 100,
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtocolProductCaseRetryPolicy {
    Never,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolSuitePlanCase {
    pub id: String,
    pub domain: ProtocolDomain,
    pub group: String,
    pub tags: Vec<String>,
    pub requires: Vec<String>,
    pub isolation: String,
    pub serial: bool,
    pub worker_index: usize,
    pub wave_index: usize,
    pub locks: Vec<ProtocolLock>,
    pub artifact_dir: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract: Option<ProtocolSuitePlanCaseContract>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolSuitePlanCaseContract {
    pub variant_id: String,
    pub executor: ProtocolExecutor,
    pub capabilities: Vec<ProtocolCapability>,
    pub lock_requirements: Vec<ProtocolLockRequirement>,
    pub ownership: Vec<ProtocolResourceOwnership>,
    pub cleanup_scopes: Vec<ProtocolCleanupScope>,
    pub variants: Vec<ProtocolSuitePlanVariant>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolSuitePlanVariant {
    pub id: String,
    pub expected: ProtocolSuitePlanExpectedOutcome,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
pub enum ProtocolSuitePlanExpectedOutcome {
    Success,
    S3Error {
        http_status: u16,
        error_code: String,
    },
    Transport {
        outcome: String,
    },
    ExpectedDivergence {
        issue: String,
    },
}

impl ProtocolSuitePlanCaseContract {
    fn from_case(case: &ProtocolCase) -> Self {
        Self {
            variant_id: case.default_variant().id.to_string(),
            executor: case.executor,
            capabilities: case.capabilities.to_vec(),
            lock_requirements: case.lock_requirements.to_vec(),
            ownership: case.ownership.to_vec(),
            cleanup_scopes: case.cleanup_scopes.to_vec(),
            variants: case
                .variants
                .iter()
                .map(|variant| ProtocolSuitePlanVariant {
                    id: variant.id.to_string(),
                    expected: ProtocolSuitePlanExpectedOutcome::from(variant.expected),
                })
                .collect(),
        }
    }
}

impl From<ProtocolExpectedOutcome> for ProtocolSuitePlanExpectedOutcome {
    fn from(outcome: ProtocolExpectedOutcome) -> Self {
        match outcome {
            ProtocolExpectedOutcome::Success => Self::Success,
            ProtocolExpectedOutcome::S3Error {
                http_status,
                error_code,
            } => Self::S3Error {
                http_status,
                error_code: error_code.to_string(),
            },
            ProtocolExpectedOutcome::Transport { outcome } => Self::Transport {
                outcome: outcome.to_string(),
            },
            ProtocolExpectedOutcome::ExpectedDivergence { issue } => Self::ExpectedDivergence {
                issue: issue.to_string(),
            },
        }
    }
}

impl ProtocolSuitePlan {
    pub fn build(
        suite: &ResolvedProtocolSuite,
        fingerprint: TargetFingerprint,
        preflight: ProtocolSuitePlanPreflight,
        artifact_base: impl AsRef<Path>,
        run_id: impl Into<String>,
    ) -> Result<Self> {
        let run_id = run_id.into();
        ensure!(!run_id.is_empty(), "run id must not be empty");
        let artifact_root = artifact_base
            .as_ref()
            .join(&suite.metadata.name)
            .join(&run_id);
        let schedule = plan_protocol_schedule(&suite.cases, suite.execution.parallelism)?;
        let scheduled = schedule
            .into_iter()
            .enumerate()
            .flat_map(|(wave_index, wave)| {
                wave.into_iter()
                    .map(move |scheduled| (wave_index, scheduled))
            })
            .collect::<Vec<_>>();
        let cases = suite
            .cases
            .iter()
            .map(|case| {
                let (wave_index, scheduled) = scheduled
                    .iter()
                    .find(|(_, scheduled)| scheduled.case_id == case.id.as_str())
                    .expect("every selected case is scheduled");
                ProtocolSuitePlanCase {
                    id: case.id.to_string(),
                    domain: case.domain,
                    group: case.group.to_string(),
                    tags: case.tags.iter().map(|tag| (*tag).to_string()).collect(),
                    requires: case.capabilities.iter().map(ToString::to_string).collect(),
                    isolation: "case".to_string(),
                    serial: case.serial,
                    worker_index: scheduled.worker_index,
                    wave_index: *wave_index,
                    locks: scheduled.locks.clone(),
                    artifact_dir: artifact_root
                        .join("cases")
                        .join(case.id.as_str())
                        .display()
                        .to_string(),
                    contract: Some(ProtocolSuitePlanCaseContract::from_case(case)),
                }
            })
            .collect();

        Ok(Self {
            api_version: suite.api_version.clone(),
            kind: PROTOCOL_SUITE_PLAN_KIND.to_string(),
            suite: suite.metadata.name.clone(),
            run_id,
            source_revision: std::env::var("S3CHAOS_SOURCE_REVISION")
                .ok()
                .or_else(|| std::env::var("GITHUB_SHA").ok())
                .filter(|revision| !revision.trim().is_empty()),
            artifact_root: artifact_root.display().to_string(),
            target: ProtocolSuitePlanTarget {
                fingerprint,
                credential_provider: "env".to_string(),
                admin_profile: suite.target.credentials.admin_profile.clone(),
                ownership_mode: "dedicated-tenant".to_string(),
                bucket_prefix: suite.target.ownership.resource_prefixes.bucket.clone(),
                identity_prefix: suite.target.ownership.resource_prefixes.identity.clone(),
                external_identity_profile: suite
                    .target
                    .external_identity
                    .as_ref()
                    .map(|external| external.profile.clone()),
            },
            preflight,
            execution: ProtocolSuitePlanExecution {
                parallelism: suite.execution.parallelism,
                cleanup: suite.execution.cleanup,
                timeouts: suite.execution.timeouts,
                eventual_consistency: ProtocolEventualConsistencyPolicy::default(),
                cleanup_retry: ProtocolCleanupRetryPolicy::default(),
                product_case_retry: ProtocolProductCaseRetryPolicy::Never,
            },
            cases,
        })
    }

    pub fn generated(
        suite: &ResolvedProtocolSuite,
        fingerprint: TargetFingerprint,
        preflight: ProtocolSuitePlanPreflight,
        artifact_base: impl AsRef<Path>,
    ) -> Result<Self> {
        Self::build(
            suite,
            fingerprint,
            preflight,
            artifact_base,
            format!("protocol-{}", Uuid::new_v4()),
        )
    }

    pub fn artifact_root(&self) -> PathBuf {
        PathBuf::from(&self.artifact_root)
    }

    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}

fn normalize_endpoint(endpoint: String) -> Result<String> {
    let mut url = reqwest::Url::parse(&endpoint)
        .with_context(|| format!("parse protocol target endpoint {endpoint}"))?;
    ensure!(
        matches!(url.scheme(), "http" | "https"),
        "target endpoint must use http or https"
    );
    ensure!(
        url.username().is_empty() && url.password().is_none(),
        "target endpoint must not contain credentials"
    );
    url.set_query(None);
    url.set_fragment(None);
    let normalized = url.as_str().trim_end_matches('/').to_string();
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::{
        ProtocolCleanupRetryPolicy, ProtocolEventualConsistencyPolicy,
        ProtocolProductCaseRetryPolicy, ProtocolSuitePlanCaseContract, TargetFingerprint,
    };
    use crate::protocol::catalog::{
        BUCKET_POLICY_MALFORMED_POLICY_REJECTED, ProtocolCapability, ProtocolCleanupScope,
        protocol_case,
    };

    #[test]
    fn fingerprint_normalizes_endpoint_and_is_stable() {
        let first = TargetFingerprint::new(
            "http://127.0.0.1:9000/",
            "us-east-1",
            "deployment-1",
            Some("distributed".to_string()),
            Some("us-east-1".to_string()),
        )
        .expect("fingerprint");
        let second = TargetFingerprint::new(
            "http://127.0.0.1:9000",
            "us-east-1",
            "deployment-1",
            Some("distributed".to_string()),
            Some("us-east-1".to_string()),
        )
        .expect("fingerprint");
        assert_eq!(first, second);
        assert_eq!(first.sha256.len(), 64);
    }

    #[test]
    fn plan_contract_serializes_typed_descriptor_without_changing_requires() {
        let case = protocol_case(BUCKET_POLICY_MALFORMED_POLICY_REJECTED).expect("case");
        let contract = ProtocolSuitePlanCaseContract::from_case(case);
        assert_eq!(contract.variant_id, "default");
        assert!(
            contract
                .capabilities
                .contains(&ProtocolCapability::BucketPolicy)
        );
        assert!(
            contract
                .cleanup_scopes
                .contains(&ProtocolCleanupScope::BucketPolicy)
        );
        let json = serde_json::to_value(contract).expect("contract JSON");
        assert_eq!(json["variants"][0]["expected"]["kind"], "s3-error");
        assert_eq!(
            json["variants"][0]["expected"]["errorCode"],
            "MalformedPolicy"
        );
    }

    #[test]
    fn runtime_safety_policy_is_explicit_and_bounded() {
        let eventual = ProtocolEventualConsistencyPolicy::default();
        assert_eq!(eventual.deadline_millis, 15_000);
        assert_eq!(eventual.interval_millis, 500);

        let cleanup = ProtocolCleanupRetryPolicy::default();
        assert_eq!(cleanup.mutation_max_attempts, 4);
        assert_eq!(cleanup.verification_max_attempts, 8);
        assert_eq!(cleanup.initial_backoff_millis, 100);

        assert_eq!(
            serde_json::to_value(ProtocolProductCaseRetryPolicy::Never)
                .expect("product retry policy"),
            "never"
        );
    }
}
