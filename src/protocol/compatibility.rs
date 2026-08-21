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
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

use crate::protocol::catalog::{ProtocolDomain, protocol_case, protocol_case_catalog};

pub const S3TESTS_REVISION: &str = "5522d1c351f75bc00ae0f64f742f3f095f5939d9";
pub const COMPATIBILITY_COVERAGE_FILE: &str = "compatibility-coverage.json";

const S3TESTS_SOURCE_INDEX: &str =
    include_str!("../../protocol/compatibility/s3tests-source-index.txt");
const IMPLEMENTED: &str = include_str!("../../protocol/compatibility/implemented.yaml");
const UNIMPLEMENTED: &str = include_str!("../../protocol/compatibility/unimplemented.yaml");
const EXCLUDED: &str = include_str!("../../protocol/compatibility/excluded.yaml");
const EXPECTED_DIVERGENCE: &str =
    include_str!("../../protocol/compatibility/expected_divergence.yaml");
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CompatibilityMappingKind {
    ExactOneToOne,
    TableDrivenManyToOne,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompatibilityEntry {
    pub id: String,
    pub domain: ProtocolDomain,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_case: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mapping: Option<CompatibilityMappingKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rustfs_behavior: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_behavior: Option<String>,
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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawCompatibilityEntry {
    id: String,
    #[serde(default)]
    native_case: Option<String>,
    #[serde(default)]
    mapping: Option<CompatibilityMappingKind>,
    #[serde(default)]
    variant: Option<String>,
    reason: String,
    #[serde(default)]
    rustfs_behavior: Option<String>,
    #[serde(default)]
    expected_behavior: Option<String>,
    #[serde(default)]
    tracking: Option<String>,
    #[serde(default)]
    review_condition: Option<String>,
    #[serde(default)]
    disposition: Option<CompatibilityDisposition>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawCompatibilityManifest {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kind: String,
    status: CompatibilityStatus,
    source: String,
    source_revision: String,
    entries: Vec<RawCompatibilityEntry>,
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
    pub source_case_count: usize,
    pub source_index_sha256: String,
    pub native_cases: Vec<String>,
    pub operations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompatibilitySourceDrift {
    pub clean: bool,
    pub expected_revision: String,
    pub actual_revision: String,
    pub expected_case_count: usize,
    pub actual_case_count: usize,
    pub expected_index_sha256: String,
    pub actual_index_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompatibilityCatalog {
    pub source: String,
    pub source_revision: String,
    pub source_case_count: usize,
    pub source_index_sha256: String,
    pub source_drift: CompatibilitySourceDrift,
    pub native_profile: NativeCompatibilityProfile,
    pub manifests: Vec<CompatibilityManifest>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CompatibilityLiveStatus {
    NotRun,
    Passed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompatibilityCoverageCounts {
    pub source_cases: usize,
    pub implemented: usize,
    pub unimplemented: usize,
    pub excluded: usize,
    pub expected_divergence: usize,
    pub native_encoded: usize,
    pub native_live_passed: usize,
    pub native_live_failed: usize,
    pub native_not_run: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompatibilityDomainCoverage {
    pub domain: ProtocolDomain,
    #[serde(flatten)]
    pub counts: CompatibilityCoverageCounts,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompatibilityReference {
    pub id: String,
    pub domain: ProtocolDomain,
    pub mapping: CompatibilityMappingKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeCaseCoverage {
    pub id: String,
    pub domain: ProtocolDomain,
    pub encoded: bool,
    pub live_status: CompatibilityLiveStatus,
    pub references: Vec<CompatibilityReference>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompatibilityCoverageReport {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub source: String,
    pub source_revision: String,
    pub source_case_count: usize,
    pub source_index_sha256: String,
    pub source_drift: CompatibilitySourceDrift,
    pub native_profile: NativeCompatibilityProfile,
    pub summary: CompatibilityCoverageCounts,
    pub domains: Vec<CompatibilityDomainCoverage>,
    pub native_cases: Vec<NativeCaseCoverage>,
    pub manifests: Vec<CompatibilityManifest>,
}

#[derive(Debug)]
struct SourceIndex {
    revision: String,
    ids: BTreeSet<String>,
    sha256: String,
}

pub fn compatibility_catalog() -> Result<CompatibilityCatalog> {
    build_compatibility_catalog(
        S3TESTS_SOURCE_INDEX,
        [IMPLEMENTED, UNIMPLEMENTED, EXCLUDED, EXPECTED_DIVERGENCE],
        NATIVE_PROFILE,
    )
}

fn build_compatibility_catalog(
    source_index: &str,
    raw_manifests: [&str; 4],
    native_profile: &str,
) -> Result<CompatibilityCatalog> {
    let source_index = parse_source_index(source_index)?;
    ensure!(
        source_index.ids.len() >= 900,
        "ceph/s3-tests source index is suspiciously small: {} cases",
        source_index.ids.len()
    );
    let mut manifests = raw_manifests
        .into_iter()
        .map(serde_yaml_ng::from_str::<RawCompatibilityManifest>)
        .map(|manifest| manifest.map(normalize_manifest))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    canonicalize_explicit_entries(&mut manifests, &source_index.ids)?;
    synthesize_unimplemented_entries(&mut manifests, &source_index.ids)?;
    validate_manifests(&manifests, &source_index.ids)?;
    let native_profile = serde_yaml_ng::from_str::<NativeCompatibilityProfile>(native_profile)?;
    let source_drift = validate_native_profile(&native_profile, &manifests, &source_index)?;
    Ok(CompatibilityCatalog {
        source: "ceph/s3-tests".to_string(),
        source_revision: S3TESTS_REVISION.to_string(),
        source_case_count: source_index.ids.len(),
        source_index_sha256: source_index.sha256,
        source_drift,
        native_profile,
        manifests,
    })
}

fn normalize_manifest(raw: RawCompatibilityManifest) -> CompatibilityManifest {
    CompatibilityManifest {
        api_version: raw.api_version,
        kind: raw.kind,
        status: raw.status,
        source: raw.source,
        source_revision: raw.source_revision,
        entries: raw
            .entries
            .into_iter()
            .map(|entry| CompatibilityEntry {
                domain: source_case_domain(&entry.id),
                id: entry.id,
                native_case: entry.native_case,
                mapping: entry.mapping,
                variant: entry.variant,
                reason: entry.reason,
                rustfs_behavior: entry.rustfs_behavior,
                expected_behavior: entry.expected_behavior,
                tracking: entry.tracking,
                review_condition: entry.review_condition,
                disposition: entry.disposition,
            })
            .collect(),
    }
}

fn validate_native_profile(
    profile: &NativeCompatibilityProfile,
    manifests: &[CompatibilityManifest],
    source_index: &SourceIndex,
) -> Result<CompatibilitySourceDrift> {
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
        source_index.revision == S3TESTS_REVISION,
        "ceph/s3-tests revision drift: expected {S3TESTS_REVISION}, source index declares {}",
        source_index.revision
    );
    ensure!(
        profile.source_case_count == source_index.ids.len()
            && profile.source_index_sha256 == source_index.sha256,
        "ceph/s3-tests node-set drift: expected count={} sha256={}, actual count={} sha256={}",
        profile.source_case_count,
        profile.source_index_sha256,
        source_index.ids.len(),
        source_index.sha256
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
    Ok(CompatibilitySourceDrift {
        clean: true,
        expected_revision: S3TESTS_REVISION.to_string(),
        actual_revision: source_index.revision.clone(),
        expected_case_count: profile.source_case_count,
        actual_case_count: source_index.ids.len(),
        expected_index_sha256: profile.source_index_sha256.clone(),
        actual_index_sha256: source_index.sha256.clone(),
    })
}

pub fn compatibility_catalog_json() -> Result<String> {
    Ok(serde_json::to_string_pretty(
        &compatibility_coverage_report(&BTreeMap::new())?,
    )?)
}

pub fn compatibility_coverage_report(
    live_results: &BTreeMap<String, CompatibilityLiveStatus>,
) -> Result<CompatibilityCoverageReport> {
    let catalog = compatibility_catalog()?;
    let native_case_ids = catalog
        .native_profile
        .native_cases
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    ensure!(
        live_results.keys().all(|id| native_case_ids.contains(id)),
        "live compatibility results contain a case outside the native compatibility profile"
    );

    let implemented = catalog
        .manifests
        .iter()
        .find(|manifest| manifest.status == CompatibilityStatus::Implemented)
        .expect("validated implemented manifest");
    let mut references_by_native = BTreeMap::<String, Vec<CompatibilityReference>>::new();
    for entry in &implemented.entries {
        references_by_native
            .entry(entry.native_case.clone().expect("validated native case"))
            .or_default()
            .push(CompatibilityReference {
                id: entry.id.clone(),
                domain: entry.domain,
                mapping: entry.mapping.expect("validated mapping"),
                variant: entry.variant.clone(),
            });
    }

    let native_cases = catalog
        .native_profile
        .native_cases
        .iter()
        .map(|id| {
            let case = protocol_case(id).expect("validated native compatibility case");
            NativeCaseCoverage {
                id: id.clone(),
                domain: case.domain,
                encoded: true,
                live_status: live_results
                    .get(id)
                    .copied()
                    .unwrap_or(CompatibilityLiveStatus::NotRun),
                references: references_by_native.remove(id).unwrap_or_default(),
            }
        })
        .collect::<Vec<_>>();

    let summary = coverage_counts(
        catalog.manifests.iter().flat_map(|manifest| {
            manifest
                .entries
                .iter()
                .map(move |entry| (manifest.status, entry))
        }),
        native_cases.iter(),
    );
    let domains = all_domains()
        .into_iter()
        .map(|domain| CompatibilityDomainCoverage {
            domain,
            counts: coverage_counts(
                catalog.manifests.iter().flat_map(|manifest| {
                    manifest
                        .entries
                        .iter()
                        .filter(move |entry| entry.domain == domain)
                        .map(move |entry| (manifest.status, entry))
                }),
                native_cases.iter().filter(|case| case.domain == domain),
            ),
        })
        .filter(|coverage| coverage.counts.source_cases > 0 || coverage.counts.native_encoded > 0)
        .collect();

    Ok(CompatibilityCoverageReport {
        api_version: "rustfs.com/s3chaos/v1alpha1".to_string(),
        kind: "ProtocolCompatibilityCoverageReport".to_string(),
        source: catalog.source,
        source_revision: catalog.source_revision,
        source_case_count: catalog.source_case_count,
        source_index_sha256: catalog.source_index_sha256,
        source_drift: catalog.source_drift,
        native_profile: catalog.native_profile,
        summary,
        domains,
        native_cases,
        manifests: catalog.manifests,
    })
}

fn coverage_counts<'a>(
    source_entries: impl Iterator<Item = (CompatibilityStatus, &'a CompatibilityEntry)>,
    native_cases: impl Iterator<Item = &'a NativeCaseCoverage>,
) -> CompatibilityCoverageCounts {
    let mut counts = CompatibilityCoverageCounts {
        source_cases: 0,
        implemented: 0,
        unimplemented: 0,
        excluded: 0,
        expected_divergence: 0,
        native_encoded: 0,
        native_live_passed: 0,
        native_live_failed: 0,
        native_not_run: 0,
    };
    for (status, _) in source_entries {
        counts.source_cases += 1;
        match status {
            CompatibilityStatus::Implemented => counts.implemented += 1,
            CompatibilityStatus::Unimplemented => counts.unimplemented += 1,
            CompatibilityStatus::Excluded => counts.excluded += 1,
            CompatibilityStatus::ExpectedDivergence => counts.expected_divergence += 1,
        }
    }
    for case in native_cases {
        counts.native_encoded += usize::from(case.encoded);
        match case.live_status {
            CompatibilityLiveStatus::NotRun => counts.native_not_run += 1,
            CompatibilityLiveStatus::Passed => counts.native_live_passed += 1,
            CompatibilityLiveStatus::Failed => counts.native_live_failed += 1,
        }
    }
    counts
}

fn parse_source_index(raw: &str) -> Result<SourceIndex> {
    let mut revision = None;
    let mut ids = BTreeSet::new();
    for line in raw.lines() {
        let line = line.trim();
        if let Some(value) = line.strip_prefix("# sourceRevision:") {
            ensure!(revision.is_none(), "duplicate sourceRevision header");
            revision = Some(value.trim().to_string());
            continue;
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        ensure!(
            line.starts_with("s3tests/functional/") && line.contains(".py::test_"),
            "invalid ceph/s3-tests source case id {line}"
        );
        ensure!(
            ids.insert(line.to_string()),
            "duplicate source case id {line}"
        );
    }
    let revision = revision.ok_or_else(|| anyhow::anyhow!("sourceRevision header is missing"))?;
    let mut hasher = Sha256::new();
    for id in &ids {
        hasher.update(id.as_bytes());
        hasher.update(b"\n");
    }
    Ok(SourceIndex {
        revision,
        ids,
        sha256: hex::encode(hasher.finalize()),
    })
}

fn canonicalize_explicit_entries(
    manifests: &mut [CompatibilityManifest],
    source_cases: &BTreeSet<String>,
) -> Result<()> {
    for manifest in manifests {
        for entry in &mut manifest.entries {
            entry.id = canonical_source_case_id(&entry.id, source_cases)?;
            entry.domain = source_case_domain(&entry.id);
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
                domain: source_case_domain(id),
                native_case: None,
                mapping: None,
                variant: None,
                reason: "Not implemented by the native s3chaos compatibility harness.".to_string(),
                rustfs_behavior: None,
                expected_behavior: None,
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
    let mut implemented_by_native = BTreeMap::<String, Vec<&CompatibilityEntry>>::new();
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
                    ensure!(
                        entry.mapping.is_some(),
                        "implemented compatibility case {} has no mapping kind",
                        entry.id
                    );
                    implemented_by_native
                        .entry(native_case.to_string())
                        .or_default()
                        .push(entry);
                }
                CompatibilityStatus::ExpectedDivergence => {
                    ensure!(
                        entry.native_case.is_none()
                            && entry.mapping.is_none()
                            && entry.variant.is_none(),
                        "expected divergence {} must not map to a native case",
                        entry.id
                    );
                    ensure!(
                        non_empty(&entry.rustfs_behavior),
                        "expected divergence {} has no RustFS behavior",
                        entry.id
                    );
                    ensure!(
                        non_empty(&entry.expected_behavior),
                        "expected divergence {} has no expected S3 behavior",
                        entry.id
                    );
                    ensure!(
                        non_empty(&entry.tracking),
                        "expected divergence {} has no tracking issue or PR",
                        entry.id
                    );
                    ensure!(
                        non_empty(&entry.review_condition),
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
                        entry.native_case.is_none()
                            && entry.mapping.is_none()
                            && entry.variant.is_none(),
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
    validate_mapping_groups(&implemented_by_native)
}

fn validate_mapping_groups(mappings: &BTreeMap<String, Vec<&CompatibilityEntry>>) -> Result<()> {
    for (native_case, entries) in mappings {
        if entries.len() == 1 {
            ensure!(
                entries[0].mapping == Some(CompatibilityMappingKind::ExactOneToOne)
                    && entries[0].variant.is_none(),
                "native case {native_case} must use an exact-one-to-one mapping without a variant"
            );
            continue;
        }
        let mut variants = BTreeSet::new();
        for entry in entries {
            ensure!(
                entry.mapping == Some(CompatibilityMappingKind::TableDrivenManyToOne),
                "native case {native_case} has multiple references but is not table-driven-many-to-one"
            );
            let variant = entry
                .variant
                .as_deref()
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| {
                    anyhow::anyhow!("table-driven mapping {} has no variant", entry.id)
                })?;
            ensure!(
                variants.insert(variant),
                "native case {native_case} contains duplicate mapping variant {variant}"
            );
        }
    }
    Ok(())
}

fn non_empty(value: &Option<String>) -> bool {
    value
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
}

fn source_case_domain(id: &str) -> ProtocolDomain {
    let lower = id.to_ascii_lowercase();
    if lower.contains("/test_iam.py::") {
        return ProtocolDomain::Iam;
    }
    if lower.contains("/test_sts.py::") {
        return ProtocolDomain::Sts;
    }
    if lower.contains("/test_s3select.py::") {
        return ProtocolDomain::S3Select;
    }
    if lower.contains("/test_sns.py::") {
        return ProtocolDomain::Notification;
    }
    if lower.contains("/test_headers.py::") {
        return ProtocolDomain::RequestValidation;
    }
    if lower.contains("/test_s3control.py::") {
        return ProtocolDomain::BucketConfig;
    }
    if lower.contains("100_continue") {
        ProtocolDomain::RequestValidation
    } else if contains_any(&lower, &["multipart", "upload_part", "uploadpart"]) {
        ProtocolDomain::Multipart
    } else if lower.contains("version")
        || lower.contains("delete_marker")
        || lower.contains("noncur")
    {
        ProtocolDomain::Versioning
    } else if contains_any(
        &lower,
        &[
            "lifecycle",
            "cors",
            "tagging",
            "_tag_",
            "logging",
            "public_block",
            "public_access",
            "website",
            "request_payment",
            "ownership",
            "replication",
        ],
    ) {
        ProtocolDomain::BucketConfig
    } else if contains_any(
        &lower,
        &[
            "encryption",
            "encrypted_",
            "sse_",
            "kms",
            "checksum",
            "md5",
            "object_lock",
            "retention",
            "legal_hold",
        ],
    ) {
        ProtocolDomain::IntegrityEncryption
    } else if contains_any(
        &lower,
        &[
            "policy",
            "_acl",
            "authenticated",
            "anonymous",
            "authorization",
            "presign",
            "signature",
        ],
    ) {
        ProtocolDomain::Authorization
    } else if contains_any(
        &lower,
        &[
            "list_",
            "_list",
            "delimiter",
            "prefix",
            "marker",
            "continuation",
            "encoding",
            "key_count",
        ],
    ) {
        ProtocolDomain::Listing
    } else if contains_any(&lower, &["copy", "multi_object_delete", "delete_objects"]) {
        ProtocolDomain::CopyDelete
    } else if lower.contains("bucket") {
        ProtocolDomain::Bucket
    } else if contains_any(
        &lower,
        &[
            "object",
            "key",
            "range",
            "conditional",
            "atomic",
            "put_",
            "get_",
            "delete_",
            "read_through",
        ],
    ) {
        ProtocolDomain::Object
    } else {
        ProtocolDomain::Other
    }
}

fn contains_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}

fn all_domains() -> [ProtocolDomain; 15] {
    [
        ProtocolDomain::Bucket,
        ProtocolDomain::Object,
        ProtocolDomain::Listing,
        ProtocolDomain::CopyDelete,
        ProtocolDomain::Multipart,
        ProtocolDomain::Versioning,
        ProtocolDomain::BucketConfig,
        ProtocolDomain::IntegrityEncryption,
        ProtocolDomain::Authorization,
        ProtocolDomain::Iam,
        ProtocolDomain::Sts,
        ProtocolDomain::S3Select,
        ProtocolDomain::Notification,
        ProtocolDomain::RequestValidation,
        ProtocolDomain::Other,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_catalog_is_complete_and_reports_domains() {
        let catalog = compatibility_catalog().expect("compatibility catalog");
        assert_eq!(catalog.source_revision, S3TESTS_REVISION);
        assert_eq!(catalog.source_case_count, 976);
        assert!(catalog.source_drift.clean);
        assert_eq!(catalog.native_profile.native_cases.len(), 9);
        assert_eq!(catalog.native_profile.operations.len(), 21);
        let report = compatibility_coverage_report(&BTreeMap::new()).expect("coverage report");
        assert_eq!(report.summary.source_cases, 976);
        assert_eq!(report.summary.implemented, 10);
        assert_eq!(report.summary.unimplemented, 964);
        assert_eq!(report.summary.excluded, 2);
        assert_eq!(report.summary.native_encoded, 9);
        assert_eq!(report.summary.native_not_run, 9);
        assert_eq!(
            report
                .domains
                .iter()
                .map(|coverage| coverage.counts.source_cases)
                .sum::<usize>(),
            report.summary.source_cases
        );
        assert_eq!(
            report
                .domains
                .iter()
                .map(|coverage| coverage.counts.native_encoded)
                .sum::<usize>(),
            report.summary.native_encoded
        );
        assert!(
            report
                .domains
                .iter()
                .any(|coverage| coverage.domain == ProtocolDomain::Iam)
        );
        assert!(
            report
                .domains
                .iter()
                .any(|coverage| coverage.domain == ProtocolDomain::Multipart)
        );
    }

    #[test]
    fn exact_and_table_driven_mappings_are_auditable() {
        let catalog = compatibility_catalog().expect("compatibility catalog");
        let implemented = catalog
            .manifests
            .iter()
            .find(|manifest| manifest.status == CompatibilityStatus::Implemented)
            .expect("implemented manifest");
        let bucket_lifecycle = implemented
            .entries
            .iter()
            .filter(|entry| {
                entry.native_case.as_deref() == Some("compat-bucket-list-create-delete")
            })
            .collect::<Vec<_>>();
        assert_eq!(bucket_lifecycle.len(), 2);
        assert!(bucket_lifecycle.iter().all(|entry| {
            entry.mapping == Some(CompatibilityMappingKind::TableDrivenManyToOne)
                && entry.variant.is_some()
        }));
        assert!(implemented.entries.iter().any(|entry| {
            entry.mapping == Some(CompatibilityMappingKind::ExactOneToOne)
                && entry.variant.is_none()
        }));
    }

    #[test]
    fn duplicate_and_unknown_references_fail_validation() {
        let mut catalog = compatibility_catalog().expect("compatibility catalog");
        let duplicate = catalog.manifests[0].entries[0].clone();
        catalog.manifests[1].entries.push(duplicate);
        let source = parse_source_index(S3TESTS_SOURCE_INDEX).expect("source index");
        let error = validate_manifests(&catalog.manifests, &source.ids).unwrap_err();
        assert!(error.to_string().contains("multiple statuses"));

        let error = canonical_source_case_id("test_does_not_exist", &source.ids).unwrap_err();
        assert!(error.to_string().contains("resolved to 0 source cases"));
    }

    #[test]
    fn missing_native_case_and_duplicate_variant_fail_validation() {
        let source = parse_source_index(S3TESTS_SOURCE_INDEX).expect("source index");
        let mut catalog = compatibility_catalog().expect("compatibility catalog");
        catalog.manifests[0].entries[0].native_case = Some("missing-case".to_string());
        let error = validate_manifests(&catalog.manifests, &source.ids).unwrap_err();
        assert!(error.to_string().contains("unknown native case"));

        let mut catalog = compatibility_catalog().expect("compatibility catalog");
        let entries = &mut catalog.manifests[0].entries;
        let mut table_entries = entries
            .iter_mut()
            .filter(|entry| {
                entry.native_case.as_deref() == Some("compat-bucket-list-create-delete")
            })
            .collect::<Vec<_>>();
        let duplicate = table_entries[0].variant.clone();
        table_entries[1].variant = duplicate;
        let error = validate_manifests(&catalog.manifests, &source.ids).unwrap_err();
        assert!(error.to_string().contains("duplicate mapping variant"));
    }

    #[test]
    fn expected_divergence_requires_both_behaviors() {
        let source = parse_source_index(S3TESTS_SOURCE_INDEX).expect("source index");
        let mut catalog = compatibility_catalog().expect("compatibility catalog");
        let mut entry = catalog.manifests[1]
            .entries
            .pop()
            .expect("unimplemented entry");
        entry.tracking = Some("https://github.com/rustfs/rustfs/issues/1".to_string());
        entry.review_condition = Some("Review after the issue closes.".to_string());
        entry.disposition = Some(CompatibilityDisposition::Warn);
        catalog.manifests[3].entries.push(entry);
        let error = validate_manifests(&catalog.manifests, &source.ids).unwrap_err();
        assert!(error.to_string().contains("no RustFS behavior"));
    }

    #[test]
    fn source_revision_and_node_set_drift_report_expected_and_actual() {
        let changed_revision = S3TESTS_SOURCE_INDEX.replace(S3TESTS_REVISION, "deadbeef");
        let error = build_compatibility_catalog(
            &changed_revision,
            [IMPLEMENTED, UNIMPLEMENTED, EXCLUDED, EXPECTED_DIVERGENCE],
            NATIVE_PROFILE,
        )
        .unwrap_err();
        assert!(error.to_string().contains("revision drift"));
        assert!(error.to_string().contains("deadbeef"));

        let mut lines = S3TESTS_SOURCE_INDEX.lines().collect::<Vec<_>>();
        lines.pop();
        let changed_nodes = format!("{}\n", lines.join("\n"));
        let error = build_compatibility_catalog(
            &changed_nodes,
            [IMPLEMENTED, UNIMPLEMENTED, EXCLUDED, EXPECTED_DIVERGENCE],
            NATIVE_PROFILE,
        )
        .unwrap_err();
        assert!(error.to_string().contains("node-set drift"));
        assert!(error.to_string().contains("expected count=976"));
        assert!(error.to_string().contains("actual count=975"));
    }

    #[test]
    fn live_results_are_separate_from_encoded_coverage() {
        let mut live = BTreeMap::new();
        live.insert(
            "compat-bucket-head".to_string(),
            CompatibilityLiveStatus::Passed,
        );
        live.insert(
            "compat-list-objects-basic".to_string(),
            CompatibilityLiveStatus::Failed,
        );
        let report = compatibility_coverage_report(&live).expect("live report");
        assert_eq!(report.summary.native_encoded, 9);
        assert_eq!(report.summary.native_live_passed, 1);
        assert_eq!(report.summary.native_live_failed, 1);
        assert_eq!(report.summary.native_not_run, 7);
    }
}
