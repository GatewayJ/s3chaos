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
    scheduler::{ProtocolLock, plan_protocol_schedule},
    suite::{ProtocolCleanupPolicy, ResolvedProtocolSuite},
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolSuitePlanExecution {
    pub parallelism: usize,
    pub cleanup: ProtocolCleanupPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolSuitePlanCase {
    pub id: String,
    pub group: String,
    pub tags: Vec<String>,
    pub requires: Vec<String>,
    pub isolation: String,
    pub serial: bool,
    pub worker_index: usize,
    pub wave_index: usize,
    pub locks: Vec<ProtocolLock>,
    pub artifact_dir: String,
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
                    .find(|(_, scheduled)| scheduled.case_id == case.id)
                    .expect("every selected case is scheduled");
                ProtocolSuitePlanCase {
                    id: case.id.to_string(),
                    group: case.group.to_string(),
                    tags: case.tags.iter().map(|tag| (*tag).to_string()).collect(),
                    requires: case
                        .requires
                        .iter()
                        .map(|requirement| (*requirement).to_string())
                        .collect(),
                    isolation: "case".to_string(),
                    serial: case.serial,
                    worker_index: scheduled.worker_index,
                    wave_index: *wave_index,
                    locks: scheduled.locks.clone(),
                    artifact_dir: artifact_root
                        .join("cases")
                        .join(case.id)
                        .display()
                        .to_string(),
                }
            })
            .collect();

        Ok(Self {
            api_version: suite.api_version.clone(),
            kind: PROTOCOL_SUITE_PLAN_KIND.to_string(),
            suite: suite.metadata.name.clone(),
            run_id,
            artifact_root: artifact_root.display().to_string(),
            target: ProtocolSuitePlanTarget {
                fingerprint,
                credential_provider: "env".to_string(),
                admin_profile: suite.target.credentials.admin_profile.clone(),
                ownership_mode: "dedicated-tenant".to_string(),
                bucket_prefix: suite.target.ownership.resource_prefixes.bucket.clone(),
                identity_prefix: suite.target.ownership.resource_prefixes.identity.clone(),
            },
            preflight,
            execution: ProtocolSuitePlanExecution {
                parallelism: suite.execution.parallelism,
                cleanup: suite.execution.cleanup,
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
    use super::TargetFingerprint;

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
}
