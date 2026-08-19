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

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::protocol::catalog::{protocol_case, protocol_case_catalog};

pub const S3TESTS_REVISION: &str = "5522d1c351f75bc00ae0f64f742f3f095f5939d9";
const S3TESTS_SOURCE_INDEX: &str =
    include_str!("../../protocol/compatibility/s3tests-source-index.txt");
const NATIVE_PROFILE: &str = include_str!("../../protocol/compatibility/native-profile.yaml");

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CompatibilityStatus {
    Implemented,
    Unimplemented,
    Excluded,
    ExpectedDivergence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CompatibilityDisposition {
    Fail,
    Skip,
    Warn,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompatibilityEntry {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_case: Option<String>,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracking: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub review_condition: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disposition: Option<CompatibilityDisposition>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompatibilityManifest {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub status: CompatibilityStatus,
    pub source: String,
    pub source_revision: String,
    pub entries: Vec<CompatibilityEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeCompatibilityProfile {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub name: String,
    pub source: String,
    pub source_revision: String,
    pub native_cases: Vec<String>,
    pub operations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompatibilityCatalog {
    pub source: String,
    pub source_revision: String,
    pub source_case_count: usize,
    pub native_profile: NativeCompatibilityProfile,
    pub manifests: Vec<CompatibilityManifest>,
}

pub fn compatibility_catalog() -> Result<CompatibilityCatalog> {
    let source_cases = source_case_ids()?;
    let mut manifests = [
        include_str!("../../protocol/compatibility/implemented.yaml"),
        include_str!("../../protocol/compatibility/unimplemented.yaml"),
        include_str!("../../protocol/compatibility/excluded.yaml"),
        include_str!("../../protocol/compatibility/expected_divergence.yaml"),
    ]
    .into_iter()
    .map(serde_yaml_ng::from_str::<CompatibilityManifest>)
    .collect::<std::result::Result<Vec<_>, _>>()?;
    canonicalize_explicit_entries(&mut manifests, &source_cases)?;
    synthesize_unimplemented_entries(&mut manifests, &source_cases)?;
    validate_manifests(&manifests, &source_cases)?;
    let native_profile = serde_yaml_ng::from_str::<NativeCompatibilityProfile>(NATIVE_PROFILE)?;
    validate_native_profile(&native_profile, &manifests)?;
    Ok(CompatibilityCatalog {
        source: "ceph/s3-tests".to_string(),
        source_revision: S3TESTS_REVISION.to_string(),
        source_case_count: source_cases.len(),
        native_profile,
        manifests,
    })
}

fn validate_native_profile(
    profile: &NativeCompatibilityProfile,
    manifests: &[CompatibilityManifest],
) -> Result<()> {
    ensure!(
        profile.api_version == "rustfs.com/s3chaos/v1alpha1"
            && profile.kind == "ProtocolNativeCompatibilityProfile",
        "invalid native compatibility profile contract"
    );
    ensure!(
        profile.source == "ceph/s3-tests" && profile.source_revision == S3TESTS_REVISION,
        "native compatibility profile is not pinned to ceph/s3-tests {S3TESTS_REVISION}"
    );
    ensure!(
        !profile.name.trim().is_empty(),
        "native compatibility profile name is empty"
    );
    let native_cases = profile
        .native_cases
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    ensure!(
        native_cases.len() == profile.native_cases.len(),
        "native compatibility profile contains duplicate cases"
    );
    let catalog_cases = protocol_case_catalog()
        .iter()
        .filter(|case| case.tags.contains(&"compatibility"))
        .map(|case| case.id.to_string())
        .collect::<BTreeSet<_>>();
    ensure!(
        native_cases == catalog_cases,
        "native compatibility profile does not exactly cover compatibility-tagged native cases"
    );
    let implemented_cases = manifests
        .iter()
        .find(|manifest| manifest.status == CompatibilityStatus::Implemented)
        .into_iter()
        .flat_map(|manifest| manifest.entries.iter())
        .filter_map(|entry| entry.native_case.clone())
        .collect::<BTreeSet<_>>();
    ensure!(
        native_cases == implemented_cases,
        "native compatibility profile and implemented ceph/s3-tests mappings differ"
    );
    let operations = profile.operations.iter().cloned().collect::<BTreeSet<_>>();
    ensure!(
        operations.len() == profile.operations.len()
            && operations
                .iter()
                .all(|operation| !operation.trim().is_empty()),
        "native compatibility profile contains empty or duplicate operations"
    );
    Ok(())
}

pub fn compatibility_catalog_json() -> Result<String> {
    Ok(serde_json::to_string_pretty(&compatibility_catalog()?)?)
}

fn source_case_ids() -> Result<BTreeSet<String>> {
    let mut ids = BTreeSet::new();
    for line in S3TESTS_SOURCE_INDEX.lines() {
        let id = line.trim();
        if id.is_empty() || id.starts_with('#') {
            continue;
        }
        ensure!(
            id.starts_with("s3tests/functional/") && id.contains(".py::test_"),
            "invalid ceph/s3-tests source case id {id}"
        );
        ensure!(ids.insert(id.to_string()), "duplicate source case id {id}");
    }
    ensure!(
        ids.len() >= 900,
        "ceph/s3-tests source index is suspiciously small: {} cases",
        ids.len()
    );
    Ok(ids)
}

fn canonicalize_explicit_entries(
    manifests: &mut [CompatibilityManifest],
    source_cases: &BTreeSet<String>,
) -> Result<()> {
    for manifest in manifests {
        for entry in &mut manifest.entries {
            entry.id = canonical_source_case_id(&entry.id, source_cases)?;
        }
        manifest
            .entries
            .sort_by(|left, right| left.id.cmp(&right.id));
    }
    Ok(())
}

fn canonical_source_case_id(id: &str, source_cases: &BTreeSet<String>) -> Result<String> {
    if source_cases.contains(id) {
        return Ok(id.to_string());
    }
    let suffix = format!("::{id}");
    let matches = source_cases
        .iter()
        .filter(|source_id| source_id.ends_with(&suffix))
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1,
        "compatibility case id {id} resolved to {} source cases; use a full pytest node id",
        matches.len()
    );
    Ok(matches[0].to_string())
}

fn synthesize_unimplemented_entries(
    manifests: &mut [CompatibilityManifest],
    source_cases: &BTreeSet<String>,
) -> Result<()> {
    let explicit = manifests
        .iter()
        .flat_map(|manifest| manifest.entries.iter().map(|entry| entry.id.clone()))
        .collect::<BTreeSet<_>>();
    let unimplemented = manifests
        .iter_mut()
        .find(|manifest| manifest.status == CompatibilityStatus::Unimplemented)
        .ok_or_else(|| anyhow::anyhow!("unimplemented compatibility manifest is missing"))?;
    unimplemented.entries.extend(
        source_cases
            .difference(&explicit)
            .map(|id| CompatibilityEntry {
                id: id.clone(),
                native_case: None,
                reason: "Not implemented by the native s3chaos compatibility harness.".to_string(),
                tracking: None,
                review_condition: None,
                disposition: None,
            }),
    );
    unimplemented
        .entries
        .sort_by(|left, right| left.id.cmp(&right.id));
    Ok(())
}

fn validate_manifests(
    manifests: &[CompatibilityManifest],
    source_cases: &BTreeSet<String>,
) -> Result<()> {
    ensure!(
        manifests.len() == 4,
        "exactly four compatibility manifests are required"
    );
    let expected_statuses = [
        CompatibilityStatus::Implemented,
        CompatibilityStatus::Unimplemented,
        CompatibilityStatus::Excluded,
        CompatibilityStatus::ExpectedDivergence,
    ];
    let mut statuses = BTreeSet::new();
    let mut ids = BTreeSet::new();
    for manifest in manifests {
        ensure!(
            manifest.api_version == "rustfs.com/s3chaos/v1alpha1"
                && manifest.kind == "ProtocolCompatibilityStatus",
            "invalid compatibility manifest contract"
        );
        ensure!(
            manifest.source == "ceph/s3-tests",
            "unsupported compatibility source"
        );
        ensure!(
            manifest.source_revision == S3TESTS_REVISION,
            "compatibility source revision is not pinned to {S3TESTS_REVISION}"
        );
        ensure!(
            statuses.insert(manifest.status),
            "duplicate compatibility status manifest"
        );
        for entry in &manifest.entries {
            ensure!(
                !entry.id.trim().is_empty(),
                "compatibility case id is empty"
            );
            ensure!(
                source_cases.contains(&entry.id),
                "compatibility case {} is absent from the pinned source index",
                entry.id
            );
            ensure!(
                ids.insert(entry.id.clone()),
                "compatibility case {} has multiple statuses",
                entry.id
            );
            ensure!(
                !entry.reason.trim().is_empty(),
                "compatibility case {} has no reason",
                entry.id
            );
            match manifest.status {
                CompatibilityStatus::Implemented => {
                    let native_case = entry.native_case.as_deref().ok_or_else(|| {
                        anyhow::anyhow!(
                            "implemented compatibility case {} has no native case",
                            entry.id
                        )
                    })?;
                    let case = protocol_case(native_case).ok_or_else(|| {
                        anyhow::anyhow!(
                            "compatibility case {} maps to unknown native case {native_case}",
                            entry.id
                        )
                    })?;
                    ensure!(
                        case.tags.contains(&"compatibility"),
                        "native case {native_case} is not compatibility-tagged"
                    );
                }
                CompatibilityStatus::ExpectedDivergence => {
                    ensure!(
                        entry
                            .tracking
                            .as_deref()
                            .is_some_and(|value| !value.trim().is_empty()),
                        "expected divergence {} has no tracking issue or PR",
                        entry.id
                    );
                    ensure!(
                        entry
                            .review_condition
                            .as_deref()
                            .is_some_and(|value| !value.trim().is_empty()),
                        "expected divergence {} has no review condition",
                        entry.id
                    );
                    ensure!(
                        entry.disposition.is_some(),
                        "expected divergence {} has no disposition",
                        entry.id
                    );
                }
                CompatibilityStatus::Unimplemented | CompatibilityStatus::Excluded => {
                    ensure!(
                        entry.native_case.is_none(),
                        "non-implemented compatibility case {} must not map to a native case",
                        entry.id
                    );
                }
            }
        }
    }
    ensure!(
        expected_statuses
            .into_iter()
            .all(|status| statuses.contains(&status)),
        "compatibility status manifests are incomplete"
    );
    ensure!(
        ids == *source_cases,
        "compatibility status coverage is incomplete: classified {} of {} source cases",
        ids.len(),
        source_cases.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{CompatibilityStatus, S3TESTS_REVISION, compatibility_catalog};

    #[test]
    fn embedded_status_lists_are_disjoint_pinned_and_resolvable() {
        let catalog = compatibility_catalog().expect("compatibility catalog");
        assert_eq!(catalog.source_revision, S3TESTS_REVISION);
        assert_eq!(catalog.source_case_count, 976);
        assert_eq!(catalog.native_profile.native_cases.len(), 9);
        assert_eq!(catalog.native_profile.operations.len(), 21);
        assert_eq!(catalog.manifests.len(), 4);
        let implemented = catalog
            .manifests
            .iter()
            .find(|manifest| manifest.status == CompatibilityStatus::Implemented)
            .expect("implemented manifest");
        assert_eq!(implemented.entries.len(), 9);
        assert_eq!(
            catalog
                .manifests
                .iter()
                .map(|manifest| manifest.entries.len())
                .sum::<usize>(),
            catalog.source_case_count
        );
    }
}
