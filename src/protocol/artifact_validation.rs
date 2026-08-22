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
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Component, Path};

use crate::protocol::{
    catalog::protocol_case,
    compatibility::{
        COMPATIBILITY_COVERAGE_FILE, CompatibilityCoverageReport, compatibility_coverage_report,
        compatibility_live_status,
    },
    fixture::registry::{RESOURCE_REGISTRY_FILE, ResourceRegistry},
    preflight::ProtocolPreflightSummary,
    reporting::{
        PROTOCOL_JUNIT_FILE, ProtocolArtifactValidationReport, ProtocolCaseReport,
        ProtocolCaseStatus, ProtocolCleanupReport, ProtocolFailureSummary, ProtocolSuiteSummary,
        protocol_junit_xml,
    },
    runner::artifacts::ProtocolArtifactWriter,
    suite_plan::{ProtocolSuitePlan, ProtocolSuitePlanCaseContract},
};

pub const PROTOCOL_ARTIFACT_VALIDATION_REPORT: &str = "protocol-artifact-validation-report.json";
const MAX_FILES: usize = 10_000;
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

pub fn validate_protocol_artifacts_and_write_report(
    root: impl AsRef<Path>,
    forbidden_material: &[String],
) -> Result<ProtocolArtifactValidationReport> {
    let root = root.as_ref();
    let mut checked_files = 0;
    let validation = validate_contract(root, forbidden_material, &mut checked_files);
    let errors = validation
        .as_ref()
        .err()
        .map(|error| vec![error.to_string()])
        .unwrap_or_default();
    let report = ProtocolArtifactValidationReport {
        api_version: "rustfs.com/s3chaos/v1alpha1".to_string(),
        kind: "ProtocolArtifactValidationReport".to_string(),
        artifact_root: root.display().to_string(),
        valid: validation.is_ok(),
        checked_files,
        errors,
    };
    ProtocolArtifactWriter::file(root).write_json(PROTOCOL_ARTIFACT_VALIDATION_REPORT, &report)?;
    if let Err(error) = validation {
        bail!(
            "protocol artifact validation failed: {error}; report: {}",
            root.join(PROTOCOL_ARTIFACT_VALIDATION_REPORT).display()
        );
    }
    Ok(report)
}

fn validate_contract(
    root: &Path,
    forbidden_material: &[String],
    checked_files: &mut usize,
) -> Result<()> {
    ensure!(root.is_dir(), "protocol artifact root is not a directory");
    ensure!(
        !root
            .components()
            .any(|component| component.as_os_str() == "fault-tests"),
        "protocol artifacts must not be written under a fault-tests directory"
    );
    for name in [
        "protocol-suite.yaml",
        "protocol-suite-plan.json",
        "preflight-summary.json",
        RESOURCE_REGISTRY_FILE,
        "cleanup-report.json",
        COMPATIBILITY_COVERAGE_FILE,
        PROTOCOL_JUNIT_FILE,
        "protocol-suite-summary.json",
    ] {
        ensure!(
            root.join(name).is_file(),
            "required protocol artifact {name} is missing"
        );
    }

    let plan: ProtocolSuitePlan = read_json(&root.join("protocol-suite-plan.json"))?;
    let preflight: ProtocolPreflightSummary = read_json(&root.join("preflight-summary.json"))?;
    let registry = ResourceRegistry::load(root)?;
    let cleanup: ProtocolCleanupReport = read_json(&root.join("cleanup-report.json"))?;
    let compatibility: CompatibilityCoverageReport =
        read_json(&root.join(COMPATIBILITY_COVERAGE_FILE))?;
    let summary: ProtocolSuiteSummary = read_json(&root.join("protocol-suite-summary.json"))?;
    ensure!(
        Path::new(&plan.artifact_root) == root,
        "protocol plan artifact root does not match the validated directory"
    );
    ensure!(
        plan.target.fingerprint == preflight.target_fingerprint
            && plan.target.fingerprint == registry.target_fingerprint,
        "protocol target fingerprint differs across plan, preflight, and registry"
    );
    ensure!(
        plan.run_id == registry.run_id && plan.run_id == summary.run_id,
        "protocol run id differs across plan, registry, and summary"
    );
    ensure!(
        summary.plan == "protocol-suite-plan.json"
            && summary.preflight == "preflight-summary.json"
            && summary.registry == RESOURCE_REGISTRY_FILE
            && summary.cleanup == "cleanup-report.json"
            && summary.compatibility_coverage == COMPATIBILITY_COVERAGE_FILE,
        "protocol suite summary contains invalid artifact references"
    );

    let selected_cases = plan
        .cases
        .iter()
        .map(|case| case.id.clone())
        .collect::<Vec<_>>();
    ensure!(
        selected_cases == preflight.selected_cases,
        "protocol selected cases differ between plan and preflight"
    );
    ensure!(
        summary.case_reports.len() == selected_cases.len(),
        "protocol suite summary case report count differs from the plan"
    );
    let mut case_reports = Vec::new();
    let mut case_cleanups = Vec::new();
    for (planned_case, report_path) in plan.cases.iter().zip(&summary.case_reports) {
        let case_id = &planned_case.id;
        let report_path = safe_relative_path(report_path)?;
        let report: ProtocolCaseReport = read_json(&root.join(report_path))?;
        ensure!(
            &report.case_id == case_id,
            "case report id {} does not match planned case {case_id}",
            report.case_id
        );
        let expected_variant = planned_case
            .contract
            .as_ref()
            .map(|contract| contract.variant_id.as_str())
            .unwrap_or(crate::protocol::catalog::DEFAULT_PROTOCOL_VARIANT);
        ensure!(
            report.variant_id == expected_variant,
            "case report variant {} does not match planned case {case_id} variant {expected_variant}",
            report.variant_id
        );
        let case_dir = report_path
            .parent()
            .context("case report artifact has no parent directory")?;
        let cleanup_path = root.join(case_dir).join("cleanup-report.json");
        let case_registry_path = root.join(case_dir).join(RESOURCE_REGISTRY_FILE);
        let history_path = root.join(case_dir).join("operation-history.jsonl");
        let history =
            read_json_lines::<crate::protocol::reporting::ProtocolAssertion>(&history_path)?;
        ensure!(
            history == report.assertions,
            "case {case_id} operation history differs from its case report assertions"
        );
        let case_cleanup = read_json::<ProtocolCleanupReport>(&cleanup_path)?;
        if planned_case.contract.is_some() {
            ensure!(
                case_registry_path.is_file(),
                "case {case_id} typed plan is missing its resource registry"
            );
        }
        if case_registry_path.is_file() {
            let case_registry = ResourceRegistry::load_path(&case_registry_path)?;
            ensure!(
                case_registry.run_id == plan.run_id
                    && case_registry.target_fingerprint == plan.target.fingerprint,
                "case {case_id} registry ownership differs from the suite"
            );
            if let Some(planned_contract) = &planned_case.contract {
                validate_registry_contract(case_id, planned_contract, &case_registry)?;
            }
            if case_cleanup.succeeded {
                ensure!(
                    case_registry.pending_cleanup().next().is_none(),
                    "case {case_id} cleanup succeeded while its registry has leftovers"
                );
            }
        }
        case_cleanups.push(case_cleanup);
        case_reports.push(report);
    }
    let junit_cases = case_reports
        .iter()
        .zip(&case_cleanups)
        .map(|(report, cleanup)| (report, cleanup.succeeded))
        .collect::<Vec<_>>();
    let expected_junit = protocol_junit_xml(&summary.suite, &junit_cases, cleanup.succeeded);
    let actual_junit = fs::read_to_string(root.join(PROTOCOL_JUNIT_FILE))
        .with_context(|| format!("read protocol artifact {PROTOCOL_JUNIT_FILE}"))?;
    ensure!(
        actual_junit == expected_junit,
        "protocol JUnit report does not match planned case/variant results"
    );
    let expected_status = if case_reports
        .iter()
        .all(|report| report.status == ProtocolCaseStatus::Passed)
        && case_cleanups.iter().all(|cleanup| cleanup.succeeded)
        && cleanup.succeeded
    {
        ProtocolCaseStatus::Passed
    } else {
        ProtocolCaseStatus::Failed
    };
    ensure!(
        summary.status == expected_status,
        "protocol suite summary status does not match case and cleanup reports"
    );
    let live_compatibility = case_reports
        .iter()
        .zip(&case_cleanups)
        .filter(|(report, _)| {
            protocol_case(&report.case_id).is_some_and(|case| case.tags.contains(&"compatibility"))
        })
        .map(|(report, cleanup)| {
            (
                report.case_id.clone(),
                compatibility_live_status(
                    report.status,
                    report.failure_phase.as_deref(),
                    cleanup.succeeded,
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();
    ensure!(
        compatibility == compatibility_coverage_report(&live_compatibility)?,
        "compatibility coverage report does not match native case results"
    );
    if cleanup.succeeded {
        ensure!(
            registry.pending_cleanup().next().is_none(),
            "cleanup report succeeded while registry still contains pending resources"
        );
    }
    match &summary.failure_summary {
        Some(path) => {
            ensure!(
                summary.status == ProtocolCaseStatus::Failed,
                "passing protocol suite must not reference a failure summary"
            );
            let path = safe_relative_path(path)?;
            let _: ProtocolFailureSummary = read_json(&root.join(path))?;
        }
        None => ensure!(
            summary.status == ProtocolCaseStatus::Passed,
            "failed protocol suite must reference a failure summary"
        ),
    }

    scan_files(root, checked_files, &mut |path, contents| {
        for secret in forbidden_material {
            if secret.len() >= 4 && contents.contains(secret) {
                bail!(
                    "protocol artifact {} contains forbidden credential material",
                    path.display()
                );
            }
        }
        match path.extension().and_then(|extension| extension.to_str()) {
            Some("json") => {
                let value: Value = serde_json::from_str(contents)
                    .with_context(|| format!("parse protocol JSON artifact {}", path.display()))?;
                reject_sensitive_fields(path, &value)?;
            }
            Some("jsonl") => {
                for (index, line) in contents.lines().enumerate() {
                    if line.trim().is_empty() {
                        continue;
                    }
                    let value: Value = serde_json::from_str(line).with_context(|| {
                        format!(
                            "parse protocol JSONL artifact {} line {}",
                            path.display(),
                            index + 1
                        )
                    })?;
                    reject_sensitive_fields(path, &value)?;
                }
            }
            _ => {}
        }
        Ok(())
    })
}

fn reject_sensitive_fields(path: &Path, value: &Value) -> Result<()> {
    match value {
        Value::Object(fields) => {
            for (name, value) in fields {
                let normalized = name
                    .chars()
                    .filter(|character| character.is_ascii_alphanumeric())
                    .flat_map(char::to_lowercase)
                    .collect::<String>();
                ensure!(
                    !matches!(
                        normalized.as_str(),
                        "accesskey"
                            | "adminaccesskey"
                            | "secretkey"
                            | "secretaccesskey"
                            | "sessiontoken"
                            | "rawcredentials"
                    ),
                    "protocol artifact {} contains forbidden credential field {name}",
                    path.display()
                );
                reject_sensitive_fields(path, value)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                reject_sensitive_fields(path, value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_registry_contract(
    case_id: &str,
    planned: &ProtocolSuitePlanCaseContract,
    registry: &ResourceRegistry,
) -> Result<()> {
    let recorded = registry
        .contract
        .as_ref()
        .with_context(|| format!("case {case_id} registry omitted its typed contract"))?;
    ensure!(
        recorded.case_id == case_id,
        "case {case_id} registry contract records owner {}",
        recorded.case_id
    );
    ensure!(
        recorded.variant_id == planned.variant_id,
        "case {case_id} registry variant {} differs from planned variant {}",
        recorded.variant_id,
        planned.variant_id
    );
    ensure!(
        recorded.ownership == planned.ownership,
        "case {case_id} registry ownership differs from the planned contract"
    );
    ensure!(
        recorded.cleanup_scopes == planned.cleanup_scopes,
        "case {case_id} registry cleanup scopes differ from the planned contract"
    );
    ensure!(
        recorded.lock_requirements == planned.lock_requirements,
        "case {case_id} registry lock requirements differ from the planned contract"
    );
    Ok(())
}

fn safe_relative_path(path: &str) -> Result<&Path> {
    let path = Path::new(path);
    ensure!(!path.is_absolute(), "artifact reference must be relative");
    ensure!(
        path.components()
            .all(|component| matches!(component, Component::Normal(_))),
        "artifact reference contains unsafe path components"
    );
    Ok(path)
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("read protocol JSON artifact {}", path.display()))?;
    serde_json::from_str(&raw)
        .with_context(|| format!("parse protocol JSON artifact {}", path.display()))
}

fn read_json_lines<T: DeserializeOwned>(path: &Path) -> Result<Vec<T>> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("read protocol JSONL artifact {}", path.display()))?;
    raw.lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(index, line)| {
            serde_json::from_str(line).with_context(|| {
                format!(
                    "parse protocol JSONL artifact {} line {}",
                    path.display(),
                    index + 1
                )
            })
        })
        .collect()
}

fn scan_files(
    root: &Path,
    checked_files: &mut usize,
    visitor: &mut impl FnMut(&Path, &str) -> Result<()>,
) -> Result<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        ensure!(
            !file_type.is_symlink(),
            "protocol artifact tree must not contain symlinks"
        );
        if file_type.is_dir() {
            scan_files(&entry.path(), checked_files, visitor)?;
        } else if file_type.is_file() {
            *checked_files += 1;
            ensure!(
                *checked_files <= MAX_FILES,
                "protocol artifact tree exceeds {MAX_FILES} files"
            );
            ensure!(
                entry.metadata()?.len() <= MAX_FILE_BYTES,
                "protocol artifact {} exceeds {} bytes",
                entry.path().display(),
                MAX_FILE_BYTES
            );
            let contents = fs::read_to_string(entry.path())
                .with_context(|| format!("read protocol artifact {}", entry.path().display()))?;
            visitor(&entry.path(), &contents)?;
        }
    }
    Ok(())
}
