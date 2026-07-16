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

use crate::protocol::catalog::protocol_case;

pub const S3TESTS_REVISION: &str = "5522d1c351f75bc00ae0f64f742f3f095f5939d9";

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompatibilityCatalog {
    pub source: String,
    pub source_revision: String,
    pub manifests: Vec<CompatibilityManifest>,
}

pub fn compatibility_catalog() -> Result<CompatibilityCatalog> {
    let manifests = [
        include_str!("../../protocol/compatibility/implemented.yaml"),
        include_str!("../../protocol/compatibility/unimplemented.yaml"),
        include_str!("../../protocol/compatibility/excluded.yaml"),
        include_str!("../../protocol/compatibility/expected_divergence.yaml"),
    ]
    .into_iter()
    .map(serde_yaml_ng::from_str::<CompatibilityManifest>)
    .collect::<std::result::Result<Vec<_>, _>>()?;
    validate_manifests(&manifests)?;
    Ok(CompatibilityCatalog {
        source: "ceph/s3-tests".to_string(),
        source_revision: S3TESTS_REVISION.to_string(),
        manifests,
    })
}

pub fn compatibility_catalog_json() -> Result<String> {
    Ok(serde_json::to_string_pretty(&compatibility_catalog()?)?)
}

fn validate_manifests(manifests: &[CompatibilityManifest]) -> Result<()> {
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
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{CompatibilityStatus, S3TESTS_REVISION, compatibility_catalog};

    #[test]
    fn embedded_status_lists_are_disjoint_pinned_and_resolvable() {
        let catalog = compatibility_catalog().expect("compatibility catalog");
        assert_eq!(catalog.source_revision, S3TESTS_REVISION);
        assert_eq!(catalog.manifests.len(), 4);
        let implemented = catalog
            .manifests
            .iter()
            .find(|manifest| manifest.status == CompatibilityStatus::Implemented)
            .expect("implemented manifest");
        assert_eq!(implemented.entries.len(), 3);
    }
}
