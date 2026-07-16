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

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use crate::protocol::catalog::{ProtocolCase, protocol_case, protocol_case_catalog};

pub const PROTOCOL_SUITE_API_VERSION: &str = "rustfs.com/s3chaos/v1alpha1";
pub const PROTOCOL_SUITE_KIND: &str = "ProtocolSuite";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolSuite {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub metadata: ProtocolSuiteMetadata,
    pub selector: ProtocolSuiteSelector,
    pub execution: ProtocolSuiteExecution,
    pub target: ProtocolSuiteTarget,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolSuiteMetadata {
    pub name: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolSuiteSelector {
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub cases: Vec<String>,
    #[serde(default)]
    pub exclude_cases: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolSuiteExecution {
    pub parallelism: usize,
    pub default_isolation: ProtocolSuiteIsolation,
    pub cleanup: ProtocolCleanupPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtocolSuiteIsolation {
    Case,
    Group,
    Suite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtocolCleanupPolicy {
    Always,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolSuiteTarget {
    pub endpoint: String,
    pub region: String,
    pub credentials: ProtocolSuiteCredentials,
    pub ownership: ProtocolSuiteOwnership,
    pub safety: ProtocolSuiteSafety,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolSuiteCredentials {
    pub admin_profile: String,
    pub provider: ProtocolCredentialProviderKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtocolCredentialProviderKind {
    Env,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolSuiteOwnership {
    pub mode: ProtocolOwnershipMode,
    #[serde(rename = "resourcePrefixes")]
    pub resource_prefixes: ProtocolResourcePrefixes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtocolOwnershipMode {
    DedicatedTenant,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolResourcePrefixes {
    pub bucket: String,
    pub identity: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolSuiteSafety {
    pub dedicated_target: ProtocolDedicatedTargetMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtocolDedicatedTargetMode {
    Required,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedProtocolSuite {
    pub api_version: String,
    pub kind: String,
    pub metadata: ProtocolSuiteMetadata,
    pub execution: ProtocolSuiteExecution,
    pub target: ProtocolSuiteTarget,
    pub cases: Vec<&'static ProtocolCase>,
}

impl ProtocolSuite {
    pub fn from_yaml_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        serde_yaml_ng::from_str(&raw)
            .with_context(|| format!("parse protocol suite yaml {}", path.display()))
    }

    pub fn resolve(&self) -> Result<ResolvedProtocolSuite> {
        ensure!(
            self.api_version == PROTOCOL_SUITE_API_VERSION,
            "unsupported ProtocolSuite apiVersion {}; expected {PROTOCOL_SUITE_API_VERSION}",
            self.api_version
        );
        ensure!(
            self.kind == PROTOCOL_SUITE_KIND,
            "unsupported protocol suite kind {}; expected {PROTOCOL_SUITE_KIND}",
            self.kind
        );
        validate_dns_label("metadata.name", &self.metadata.name, 63)?;
        ensure!(
            (1..=32).contains(&self.execution.parallelism),
            "execution.parallelism must be between 1 and 32"
        );
        ensure!(
            self.execution.default_isolation == ProtocolSuiteIsolation::Case,
            "execution.defaultIsolation must be case in Phase 1"
        );
        ensure!(
            !self.target.endpoint.trim().is_empty(),
            "target.endpoint is required"
        );
        if !self.target.endpoint.contains("${") {
            resolve_protocol_endpoint(&self.target.endpoint)?;
        }
        ensure!(
            !self.target.region.trim().is_empty(),
            "target.region is required"
        );
        ensure!(
            !self.target.credentials.admin_profile.trim().is_empty(),
            "target.credentials.adminProfile is required"
        );
        validate_dns_label(
            "target.ownership.resourcePrefixes.bucket",
            &self.target.ownership.resource_prefixes.bucket,
            20,
        )?;
        validate_identity_prefix(&self.target.ownership.resource_prefixes.identity)?;

        let cases = resolve_cases(&self.selector)?;
        ensure!(
            !cases.is_empty(),
            "ProtocolSuite must select at least one case"
        );
        if self.execution.parallelism > 1 {
            for case in &cases {
                ensure!(
                    !case.serial && case.tags.contains(&"parallel-safe"),
                    "protocol case {} is not parallel-safe; run it with parallelism 1",
                    case.id
                );
            }
        }
        Ok(ResolvedProtocolSuite {
            api_version: self.api_version.clone(),
            kind: self.kind.clone(),
            metadata: self.metadata.clone(),
            execution: self.execution.clone(),
            target: self.target.clone(),
            cases,
        })
    }
}

impl ResolvedProtocolSuite {
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}

fn resolve_cases(selector: &ProtocolSuiteSelector) -> Result<Vec<&'static ProtocolCase>> {
    let catalog = protocol_case_catalog();
    let groups = catalog
        .iter()
        .map(|case| case.group)
        .collect::<BTreeSet<_>>();
    let tags = catalog
        .iter()
        .flat_map(|case| case.tags.iter().copied())
        .collect::<BTreeSet<_>>();

    for group in &selector.groups {
        ensure!(
            groups.contains(group.as_str()),
            "unknown protocol group {group}"
        );
    }
    for tag in &selector.tags {
        ensure!(tags.contains(tag.as_str()), "unknown protocol tag {tag}");
    }
    for case_id in selector.cases.iter().chain(&selector.exclude_cases) {
        ensure!(
            protocol_case(case_id).is_some(),
            "unknown protocol case {case_id}"
        );
    }

    let has_filters = !selector.groups.is_empty() || !selector.tags.is_empty();
    let mut selected = if has_filters || selector.cases.is_empty() {
        catalog
            .iter()
            .filter(|case| {
                (selector.groups.is_empty()
                    || selector.groups.iter().any(|group| group == case.group))
                    && selector
                        .tags
                        .iter()
                        .all(|tag| case.tags.contains(&tag.as_str()))
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    for case_id in &selector.cases {
        let case = protocol_case(case_id).expect("case ids validated");
        if !selected.iter().any(|selected| selected.id == case.id) {
            selected.push(case);
        }
    }
    selected.retain(|case| !selector.exclude_cases.iter().any(|id| id == case.id));
    selected.sort_by_key(|case| case.id);
    Ok(selected)
}

fn validate_dns_label(field: &str, value: &str, max_len: usize) -> Result<()> {
    ensure!(!value.is_empty(), "{field} must not be empty");
    ensure!(
        value.len() <= max_len,
        "{field} must be at most {max_len} characters"
    );
    ensure!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'),
        "{field} must contain only lowercase letters, digits, and hyphens"
    );
    ensure!(
        !value.starts_with('-') && !value.ends_with('-'),
        "{field} must not start or end with a hyphen"
    );
    Ok(())
}

fn validate_identity_prefix(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty(),
        "target.ownership.resourcePrefixes.identity must not be empty"
    );
    ensure!(
        value.len() <= 20,
        "target.ownership.resourcePrefixes.identity must be at most 20 characters"
    );
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(byte, b'+' | b'=' | b',' | b'.' | b'@' | b'_' | b'-')
    }) {
        bail!("target.ownership.resourcePrefixes.identity contains unsupported IAM characters");
    }
    Ok(())
}

pub fn resolve_protocol_suite_yaml(path: impl AsRef<Path>) -> Result<ResolvedProtocolSuite> {
    ProtocolSuite::from_yaml_path(path)?.resolve()
}

pub fn resolve_protocol_endpoint(expression: &str) -> Result<String> {
    let resolved = if let Some(variable) = expression
        .strip_prefix("${")
        .and_then(|value| value.strip_suffix('}'))
    {
        ensure!(
            !variable.is_empty()
                && variable
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'),
            "target.endpoint contains an invalid environment variable expression"
        );
        std::env::var(variable)
            .with_context(|| format!("target.endpoint requires environment variable {variable}"))?
    } else {
        ensure!(
            !expression.contains("${"),
            "target.endpoint supports only a single complete environment variable expression"
        );
        expression.to_string()
    };
    let url = reqwest::Url::parse(&resolved)
        .with_context(|| format!("parse protocol target endpoint {resolved}"))?;
    ensure!(
        matches!(url.scheme(), "http" | "https"),
        "target.endpoint must use http or https"
    );
    ensure!(
        url.username().is_empty() && url.password().is_none(),
        "target.endpoint must not contain credentials"
    );
    ensure!(
        url.path() == "/" && url.query().is_none() && url.fragment().is_none(),
        "target.endpoint must be an origin without path, query, or fragment"
    );
    Ok(resolved.trim_end_matches('/').to_string())
}

pub fn protocol_suite_template_yaml() -> &'static str {
    r#"apiVersion: rustfs.com/s3chaos/v1alpha1
kind: ProtocolSuite
metadata:
  name: rustfs-authz-smoke
selector:
  groups:
    - bucket-policy
  tags:
    - smoke
execution:
  parallelism: 1
  defaultIsolation: case
  cleanup: always
target:
  endpoint: ${RUSTFS_PROTOCOL_TEST_ENDPOINT}
  region: us-east-1
  credentials:
    adminProfile: root
    provider: env
  ownership:
    mode: dedicated-tenant
    resourcePrefixes:
      bucket: s3c
      identity: s3chaos
  safety:
    dedicatedTarget: required
"#
}

#[cfg(test)]
mod tests {
    use super::{ProtocolSuite, protocol_suite_template_yaml, resolve_protocol_endpoint};

    #[test]
    fn template_round_trips_and_selects_smoke_case() {
        let suite: ProtocolSuite =
            serde_yaml_ng::from_str(protocol_suite_template_yaml()).expect("template");
        let resolved = suite.resolve().expect("resolved suite");
        assert_eq!(resolved.cases.len(), 1);
        assert_eq!(resolved.cases[0].id, "bucket-policy-authenticated-user-rw");
    }

    #[test]
    fn bucket_policy_group_selects_every_parallel_safe_case_without_smoke_filter() {
        let yaml = protocol_suite_template_yaml().replace("  tags:\n    - smoke\n", "");
        let suite: ProtocolSuite = serde_yaml_ng::from_str(&yaml).expect("suite");
        let resolved = suite.resolve().expect("resolved suite");
        assert_eq!(resolved.cases.len(), 5);
        assert!(
            resolved
                .cases
                .iter()
                .all(|case| { !case.serial && case.tags.contains(&"parallel-safe") })
        );
        assert!(
            resolved
                .cases
                .windows(2)
                .all(|cases| cases[0].id < cases[1].id)
        );
    }

    #[test]
    fn rejects_unknown_fields_invalid_parallelism_and_serial_case_selection() {
        let typo = protocol_suite_template_yaml().replace("parallelism: 1", "paralellism: 1");
        assert!(serde_yaml_ng::from_str::<ProtocolSuite>(&typo).is_err());

        let parallel = protocol_suite_template_yaml().replace("parallelism: 1", "parallelism: 2");
        let suite = serde_yaml_ng::from_str::<ProtocolSuite>(&parallel).expect("parse");
        assert!(suite.resolve().is_ok());

        let serial = parallel.replace(
            "  groups:\n    - bucket-policy\n  tags:\n    - smoke\n",
            "  cases:\n    - iam-group-policy\n",
        );
        let suite = serde_yaml_ng::from_str::<ProtocolSuite>(&serial).expect("serial parse");
        assert!(suite.resolve().is_err());

        let zero = protocol_suite_template_yaml().replace("parallelism: 1", "parallelism: 0");
        let suite = serde_yaml_ng::from_str::<ProtocolSuite>(&zero).expect("zero parse");
        assert!(suite.resolve().is_err());
    }

    #[test]
    fn endpoint_rejects_partial_or_unsafe_interpolation() {
        assert!(resolve_protocol_endpoint("http://${HOST}:9000").is_err());
        assert!(resolve_protocol_endpoint("${lowercase}").is_err());
        assert_eq!(
            resolve_protocol_endpoint("http://127.0.0.1:9000").expect("literal"),
            "http://127.0.0.1:9000"
        );
        assert!(resolve_protocol_endpoint("http://user:pass@127.0.0.1:9000").is_err());
        assert!(resolve_protocol_endpoint("http://127.0.0.1:9000/path").is_err());
    }
}
