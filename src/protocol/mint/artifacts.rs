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

use std::{fmt::Write as _, fs, path::Path};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{
    API_VERSION, MintCompatibilityStatus, MintDiagnostic, MintDiagnosticCode, MintEvaluation,
    MintExecutionStatus, MintFunctionResult, MintFunctionStatus, MintGateStatus,
    MintInfrastructureFailure, MintInventory, MintKnownFailures, MintProfile, MintResultCounts,
    MintRunObservation, evaluate_mint_run,
};
use crate::protocol::runner::artifacts::ProtocolArtifactWriter;

const MINT_PROFILE_FILE: &str = "mint-profile.json";
const MINT_INVENTORY_FILE: &str = "mint-inventory.json";
const MINT_KNOWN_FAILURES_FILE: &str = "mint-known-failures.json";
const MINT_RESULTS_FILE: &str = "mint-results.json";
const MINT_SUMMARY_FILE: &str = "mint-summary.json";
const MINT_JUNIT_FILE: &str = "mint-junit.xml";
const MINT_STDOUT_FILE: &str = "stdout.log";
const MINT_STDERR_FILE: &str = "stderr.log";
const MINT_LOG_FILE: &str = "log.json";
const MINT_REDACTED_LOG_FILE: &str = "log.redacted.json";
const MINT_CONTAINER_EXIT_CODE_FILE: &str = "container-exit-code.txt";
const MINT_GATE_EXIT_CODE_FILE: &str = "exit-code.txt";
const MINT_CREDENTIAL_SCAN_FILE: &str = "mint-credential-scan.json";
pub const MINT_ARTIFACT_VALIDATION_FILE: &str = "mint-artifact-validation.json";
const REDACTION: &[u8] = b"[REDACTED]";
const MAX_ARTIFACT_FILES: usize = 1_000;
const MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct MintCapturedRun<'a> {
    pub container_started: bool,
    pub container_exit_code: Option<i32>,
    pub infrastructure_failure: Option<MintInfrastructureFailure>,
    pub log: Option<&'a [u8]>,
    pub stdout: &'a [u8],
    pub stderr: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MintObservationReport {
    container_started: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    container_exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    infrastructure_failure: Option<MintInfrastructureFailure>,
    log_collected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MintResultsReport {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kind: String,
    evaluated_at: String,
    observation: MintObservationReport,
    evaluation: MintEvaluation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MintArtifactReferences {
    profile: String,
    inventory: String,
    known_failures: String,
    results: String,
    junit: String,
    stdout: String,
    stderr: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    log: Option<String>,
    container_exit_code: String,
    gate_exit_code: String,
    credential_scan: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MintSummaryReport {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kind: String,
    evaluated_at: String,
    profile: MintProfile,
    observation: MintObservationReport,
    execution_status: MintExecutionStatus,
    compatibility_status: MintCompatibilityStatus,
    gate_status: MintGateStatus,
    counts: MintResultCounts,
    diagnostics: Vec<MintDiagnostic>,
    artifacts: MintArtifactReferences,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MintCredentialScanFile {
    source: String,
    published_as: String,
    redacted: bool,
    original_published: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MintCredentialScanReport {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kind: String,
    detected: bool,
    files: Vec<MintCredentialScanFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MintArtifactValidationReport {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub artifact_root: String,
    pub valid: bool,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct MintArtifactPublication {
    pub evaluation: MintEvaluation,
    pub gate_exit_code: i32,
    pub terminal_summary: String,
}

pub fn write_mint_artifacts(
    artifact_root: impl AsRef<Path>,
    profile: &MintProfile,
    inventory: &MintInventory,
    known_failures: &MintKnownFailures,
    captured: MintCapturedRun<'_>,
    evaluated_at: &str,
    forbidden_material: &[String],
) -> Result<MintArtifactPublication> {
    validate_timestamp(evaluated_at)?;
    let evaluation_date = evaluated_at
        .get(..10)
        .context("Mint evaluation timestamp has no calendar date")?;
    let observation = MintObservationReport {
        container_started: captured.container_started,
        container_exit_code: captured.container_exit_code,
        infrastructure_failure: captured.infrastructure_failure,
        log_collected: captured.log.is_some(),
    };
    let evaluation = evaluate_mint_run(
        profile,
        inventory,
        known_failures,
        MintRunObservation {
            container_started: captured.container_started,
            exit_code: captured.container_exit_code,
            log: captured.log,
            infrastructure_failure: captured.infrastructure_failure,
        },
        evaluation_date,
    )?;
    let gate_exit_code = i32::from(evaluation.gate_status == MintGateStatus::Failed);

    let patterns = forbidden_patterns(forbidden_material);
    let (stdout, stdout_redacted) = redact_bytes(captured.stdout, &patterns);
    let (stderr, stderr_redacted) = redact_bytes(captured.stderr, &patterns);
    let (published_log, log_path, log_redacted) = match captured.log {
        Some(log) => {
            let (contents, redacted) = redact_bytes(log, &patterns);
            let path = if redacted {
                MINT_REDACTED_LOG_FILE
            } else {
                MINT_LOG_FILE
            };
            (Some(contents), Some(path.to_string()), redacted)
        }
        None => (None, None, false),
    };
    let credential_scan = MintCredentialScanReport {
        api_version: API_VERSION.to_string(),
        kind: "MintCredentialScanReport".to_string(),
        detected: stdout_redacted || stderr_redacted || log_redacted,
        files: [
            Some(MintCredentialScanFile {
                source: "stdout".to_string(),
                published_as: MINT_STDOUT_FILE.to_string(),
                redacted: stdout_redacted,
                original_published: !stdout_redacted,
            }),
            Some(MintCredentialScanFile {
                source: "stderr".to_string(),
                published_as: MINT_STDERR_FILE.to_string(),
                redacted: stderr_redacted,
                original_published: !stderr_redacted,
            }),
            log_path.as_ref().map(|path| MintCredentialScanFile {
                source: "log.json".to_string(),
                published_as: path.clone(),
                redacted: log_redacted,
                original_published: !log_redacted,
            }),
        ]
        .into_iter()
        .flatten()
        .collect(),
    };
    let artifact_references = MintArtifactReferences {
        profile: MINT_PROFILE_FILE.to_string(),
        inventory: MINT_INVENTORY_FILE.to_string(),
        known_failures: MINT_KNOWN_FAILURES_FILE.to_string(),
        results: MINT_RESULTS_FILE.to_string(),
        junit: MINT_JUNIT_FILE.to_string(),
        stdout: MINT_STDOUT_FILE.to_string(),
        stderr: MINT_STDERR_FILE.to_string(),
        log: log_path,
        container_exit_code: MINT_CONTAINER_EXIT_CODE_FILE.to_string(),
        gate_exit_code: MINT_GATE_EXIT_CODE_FILE.to_string(),
        credential_scan: MINT_CREDENTIAL_SCAN_FILE.to_string(),
    };
    let results = MintResultsReport {
        api_version: API_VERSION.to_string(),
        kind: "MintResultsReport".to_string(),
        evaluated_at: evaluated_at.to_string(),
        observation: observation.clone(),
        evaluation: evaluation.clone(),
    };
    let summary = MintSummaryReport {
        api_version: API_VERSION.to_string(),
        kind: "MintSummaryReport".to_string(),
        evaluated_at: evaluated_at.to_string(),
        profile: profile.clone(),
        observation,
        execution_status: evaluation.execution_status,
        compatibility_status: evaluation.compatibility_status,
        gate_status: evaluation.gate_status,
        counts: evaluation.counts,
        diagnostics: evaluation.diagnostics.clone(),
        artifacts: artifact_references,
    };
    let junit = mint_junit_xml(&evaluation);
    let terminal_summary = mint_terminal_summary(&evaluation);

    ensure_generated_artifact_safe(MINT_PROFILE_FILE, profile, &patterns)?;
    ensure_generated_artifact_safe(MINT_INVENTORY_FILE, inventory, &patterns)?;
    ensure_generated_artifact_safe(MINT_KNOWN_FAILURES_FILE, known_failures, &patterns)?;
    ensure_generated_artifact_safe(MINT_RESULTS_FILE, &results, &patterns)?;
    ensure_generated_artifact_safe(MINT_SUMMARY_FILE, &summary, &patterns)?;
    ensure_bytes_safe(MINT_JUNIT_FILE, junit.as_bytes(), &patterns)?;
    ensure_bytes_safe("terminal summary", terminal_summary.as_bytes(), &patterns)?;
    ensure_bytes_safe(MINT_STDOUT_FILE, &stdout, &patterns)?;
    ensure_bytes_safe(MINT_STDERR_FILE, &stderr, &patterns)?;
    if let (Some(path), Some(contents)) = (&summary.artifacts.log, &published_log) {
        ensure_bytes_safe(path, contents, &patterns)?;
    }

    let artifact_root = artifact_root.as_ref();
    ensure_unused_artifact_root(artifact_root)?;
    fs::create_dir_all(artifact_root)
        .with_context(|| format!("create Mint artifact root {}", artifact_root.display()))?;
    let writer = ProtocolArtifactWriter::file(artifact_root);
    writer.write_json(MINT_PROFILE_FILE, profile)?;
    writer.write_json(MINT_INVENTORY_FILE, inventory)?;
    writer.write_json(MINT_KNOWN_FAILURES_FILE, known_failures)?;
    writer.write_json(MINT_RESULTS_FILE, &results)?;
    writer.write_json(MINT_SUMMARY_FILE, &summary)?;
    writer.write_text(MINT_JUNIT_FILE, &junit)?;
    writer.write_bytes(MINT_STDOUT_FILE, &stdout)?;
    writer.write_bytes(MINT_STDERR_FILE, &stderr)?;
    if let (Some(path), Some(contents)) = (&summary.artifacts.log, &published_log) {
        writer.write_bytes(path, contents)?;
    }
    writer.write_text(
        MINT_CONTAINER_EXIT_CODE_FILE,
        &format_optional_exit_code(captured.container_exit_code),
    )?;
    writer.write_text(MINT_GATE_EXIT_CODE_FILE, &format!("{gate_exit_code}\n"))?;
    writer.write_json(MINT_CREDENTIAL_SCAN_FILE, &credential_scan)?;
    validate_mint_artifacts_and_write_report(artifact_root, forbidden_material)?;

    Ok(MintArtifactPublication {
        evaluation,
        gate_exit_code,
        terminal_summary,
    })
}

pub fn validate_mint_artifacts_and_write_report(
    artifact_root: impl AsRef<Path>,
    forbidden_material: &[String],
) -> Result<MintArtifactValidationReport> {
    let artifact_root = artifact_root.as_ref();
    ensure_safe_artifact_root(artifact_root)?;
    let validation = validate_mint_artifacts(artifact_root, forbidden_material);
    let errors = validation
        .as_ref()
        .err()
        .map(|error| vec![error.to_string()])
        .unwrap_or_default();
    let report = MintArtifactValidationReport {
        api_version: API_VERSION.to_string(),
        kind: "MintArtifactValidationReport".to_string(),
        artifact_root: artifact_root.display().to_string(),
        valid: validation.is_ok(),
        errors,
    };
    ensure_generated_artifact_safe(
        MINT_ARTIFACT_VALIDATION_FILE,
        &report,
        &forbidden_patterns(forbidden_material),
    )?;
    ProtocolArtifactWriter::file(artifact_root)
        .write_json(MINT_ARTIFACT_VALIDATION_FILE, &report)?;
    if let Err(error) = validation {
        bail!(
            "Mint artifact validation failed: {error}; report: {}",
            artifact_root.join(MINT_ARTIFACT_VALIDATION_FILE).display()
        );
    }
    Ok(report)
}

fn validate_mint_artifacts(artifact_root: &Path, forbidden_material: &[String]) -> Result<()> {
    ensure_safe_artifact_root(artifact_root)?;
    let patterns = forbidden_patterns(forbidden_material);
    let mut checked_files = 0;
    scan_artifact_tree(artifact_root, artifact_root, &patterns, &mut checked_files)?;
    for required in [
        MINT_PROFILE_FILE,
        MINT_INVENTORY_FILE,
        MINT_KNOWN_FAILURES_FILE,
        MINT_RESULTS_FILE,
        MINT_SUMMARY_FILE,
        MINT_JUNIT_FILE,
        MINT_STDOUT_FILE,
        MINT_STDERR_FILE,
        MINT_CONTAINER_EXIT_CODE_FILE,
        MINT_GATE_EXIT_CODE_FILE,
        MINT_CREDENTIAL_SCAN_FILE,
    ] {
        ensure!(
            artifact_root.join(required).is_file(),
            "required Mint artifact {required} is missing"
        );
    }

    let profile: MintProfile = read_json(&artifact_root.join(MINT_PROFILE_FILE))?;
    let inventory: MintInventory = read_json(&artifact_root.join(MINT_INVENTORY_FILE))?;
    let known_failures: MintKnownFailures =
        read_json(&artifact_root.join(MINT_KNOWN_FAILURES_FILE))?;
    let results: MintResultsReport = read_json(&artifact_root.join(MINT_RESULTS_FILE))?;
    let summary: MintSummaryReport = read_json(&artifact_root.join(MINT_SUMMARY_FILE))?;
    let credential_scan: MintCredentialScanReport =
        read_json(&artifact_root.join(MINT_CREDENTIAL_SCAN_FILE))?;
    validate_timestamp(&results.evaluated_at)?;
    ensure!(
        summary.api_version == API_VERSION
            && summary.kind == "MintSummaryReport"
            && results.api_version == API_VERSION
            && results.kind == "MintResultsReport",
        "invalid Mint report headers"
    );
    ensure!(
        results.evaluated_at == summary.evaluated_at
            && results.observation == summary.observation
            && results.evaluation.profile == profile
            && summary.profile == profile
            && summary.execution_status == results.evaluation.execution_status
            && summary.compatibility_status == results.evaluation.compatibility_status
            && summary.gate_status == results.evaluation.gate_status
            && summary.counts == results.evaluation.counts
            && summary.diagnostics == results.evaluation.diagnostics,
        "Mint JSON reports disagree"
    );
    ensure!(
        summary.artifacts
            == MintArtifactReferences {
                profile: MINT_PROFILE_FILE.to_string(),
                inventory: MINT_INVENTORY_FILE.to_string(),
                known_failures: MINT_KNOWN_FAILURES_FILE.to_string(),
                results: MINT_RESULTS_FILE.to_string(),
                junit: MINT_JUNIT_FILE.to_string(),
                stdout: MINT_STDOUT_FILE.to_string(),
                stderr: MINT_STDERR_FILE.to_string(),
                log: summary.artifacts.log.clone(),
                container_exit_code: MINT_CONTAINER_EXIT_CODE_FILE.to_string(),
                gate_exit_code: MINT_GATE_EXIT_CODE_FILE.to_string(),
                credential_scan: MINT_CREDENTIAL_SCAN_FILE.to_string(),
            },
        "Mint summary contains invalid artifact references"
    );
    ensure!(
        matches!(
            summary.artifacts.log.as_deref(),
            None | Some(MINT_LOG_FILE) | Some(MINT_REDACTED_LOG_FILE)
        ),
        "Mint summary contains an invalid log artifact reference"
    );
    let log = summary
        .artifacts
        .log
        .as_ref()
        .map(|path| {
            fs::read(artifact_root.join(path))
                .with_context(|| format!("read Mint log artifact {path}"))
        })
        .transpose()?;
    ensure!(
        log.is_some() == results.observation.log_collected,
        "Mint log collection state differs from artifact references"
    );
    let evaluation_date = results
        .evaluated_at
        .get(..10)
        .context("Mint evaluation timestamp has no calendar date")?;
    let expected = evaluate_mint_run(
        &profile,
        &inventory,
        &known_failures,
        MintRunObservation {
            container_started: results.observation.container_started,
            exit_code: results.observation.container_exit_code,
            log: log.as_deref(),
            infrastructure_failure: results.observation.infrastructure_failure,
        },
        evaluation_date,
    )?;
    ensure!(
        results.evaluation == expected,
        "Mint results do not match the captured run and pinned contracts"
    );
    let expected_junit = mint_junit_xml(&results.evaluation);
    let actual_junit = fs::read_to_string(artifact_root.join(MINT_JUNIT_FILE))
        .context("read Mint JUnit artifact")?;
    ensure!(
        actual_junit == expected_junit,
        "Mint JUnit report disagrees"
    );
    let expected_gate_exit = i32::from(results.evaluation.gate_status == MintGateStatus::Failed);
    ensure!(
        fs::read_to_string(artifact_root.join(MINT_GATE_EXIT_CODE_FILE))?
            == format!("{expected_gate_exit}\n"),
        "Mint gate exit code disagrees with gate status"
    );
    ensure!(
        fs::read_to_string(artifact_root.join(MINT_CONTAINER_EXIT_CODE_FILE))?
            == format_optional_exit_code(results.observation.container_exit_code),
        "Mint container exit code artifact disagrees with the run observation"
    );
    ensure!(
        credential_scan.api_version == API_VERSION
            && credential_scan.kind == "MintCredentialScanReport",
        "invalid Mint credential scan report header"
    );
    let stdout = fs::read(artifact_root.join(MINT_STDOUT_FILE))?;
    let stderr = fs::read(artifact_root.join(MINT_STDERR_FILE))?;
    let expected_scan_files = [
        Some(expected_scan_file(
            "stdout",
            MINT_STDOUT_FILE,
            &stdout,
            None,
        )),
        Some(expected_scan_file(
            "stderr",
            MINT_STDERR_FILE,
            &stderr,
            None,
        )),
        summary.artifacts.log.as_deref().map(|path| {
            expected_scan_file(
                "log.json",
                path,
                log.as_deref().unwrap_or_default(),
                Some(path == MINT_REDACTED_LOG_FILE),
            )
        }),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    ensure!(
        credential_scan.files == expected_scan_files
            && credential_scan.detected == expected_scan_files.iter().any(|file| file.redacted),
        "Mint credential scan report disagrees with published captures"
    );
    Ok(())
}

fn ensure_safe_artifact_root(artifact_root: &Path) -> Result<()> {
    let root_metadata = fs::symlink_metadata(artifact_root)
        .with_context(|| format!("inspect Mint artifact root {}", artifact_root.display()))?;
    ensure!(
        root_metadata.file_type().is_dir() && !root_metadata.file_type().is_symlink(),
        "Mint artifact root must be a directory, not a symlink"
    );
    Ok(())
}

fn expected_scan_file(
    source: &str,
    published_as: &str,
    contents: &[u8],
    known_redacted: Option<bool>,
) -> MintCredentialScanFile {
    let redacted = known_redacted.unwrap_or_else(|| contains_subslice(contents, REDACTION));
    MintCredentialScanFile {
        source: source.to_string(),
        published_as: published_as.to_string(),
        redacted,
        original_published: !redacted,
    }
}

fn scan_artifact_tree(
    root: &Path,
    directory: &Path,
    patterns: &[Vec<u8>],
    checked_files: &mut usize,
) -> Result<()> {
    for entry in fs::read_dir(directory)
        .with_context(|| format!("scan Mint artifact directory {}", directory.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        ensure!(
            !file_type.is_symlink(),
            "Mint artifact tree contains a symlink: {}",
            path.display()
        );
        if file_type.is_dir() {
            scan_artifact_tree(root, &path, patterns, checked_files)?;
            continue;
        }
        ensure!(
            file_type.is_file(),
            "Mint artifact tree contains a non-file entry: {}",
            path.display()
        );
        *checked_files += 1;
        ensure!(
            *checked_files <= MAX_ARTIFACT_FILES,
            "Mint artifact tree exceeds {MAX_ARTIFACT_FILES} files"
        );
        let metadata = entry.metadata()?;
        ensure!(
            metadata.len() <= MAX_ARTIFACT_BYTES,
            "Mint artifact {} exceeds the {} byte limit",
            path.display(),
            MAX_ARTIFACT_BYTES
        );
        let contents =
            fs::read(&path).with_context(|| format!("read Mint artifact {}", path.display()))?;
        let relative = path
            .strip_prefix(root)
            .context("Mint artifact escaped its root")?;
        ensure_bytes_safe(&relative.display().to_string(), &contents, patterns)?;
    }
    Ok(())
}

fn ensure_unused_artifact_root(root: &Path) -> Result<()> {
    if !root.exists() {
        return Ok(());
    }
    ensure!(
        root.is_dir(),
        "Mint artifact root exists and is not a directory"
    );
    ensure!(
        fs::read_dir(root)?.next().is_none(),
        "Mint artifact root must be empty to prevent evidence overwrite"
    );
    Ok(())
}

fn validate_timestamp(value: &str) -> Result<()> {
    OffsetDateTime::parse(value, &Rfc3339)
        .with_context(|| format!("parse Mint evaluation timestamp {value:?} as RFC3339"))?;
    Ok(())
}

fn forbidden_patterns(forbidden_material: &[String]) -> Vec<Vec<u8>> {
    let mut patterns = forbidden_material
        .iter()
        .filter(|value| !value.is_empty())
        .flat_map(|value| {
            let encoded = serde_json::to_string(value).expect("serialize credential pattern");
            [
                value.as_bytes().to_vec(),
                encoded.as_bytes()[1..encoded.len() - 1].to_vec(),
            ]
        })
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    patterns.sort_by(|left, right| right.len().cmp(&left.len()).then_with(|| left.cmp(right)));
    patterns.dedup();
    patterns
}

fn redact_bytes(contents: &[u8], patterns: &[Vec<u8>]) -> (Vec<u8>, bool) {
    let mut output = Vec::with_capacity(contents.len());
    let mut index = 0;
    let mut redacted = false;
    while index < contents.len() {
        if let Some(pattern) = patterns
            .iter()
            .find(|pattern| contents[index..].starts_with(pattern))
        {
            output.extend_from_slice(REDACTION);
            index += pattern.len();
            redacted = true;
        } else {
            output.push(contents[index]);
            index += 1;
        }
    }
    (output, redacted)
}

fn ensure_generated_artifact_safe(
    path: &str,
    value: &impl Serialize,
    patterns: &[Vec<u8>],
) -> Result<()> {
    ensure_bytes_safe(path, &serde_json::to_vec(value)?, patterns)
}

fn ensure_bytes_safe(path: &str, contents: &[u8], patterns: &[Vec<u8>]) -> Result<()> {
    ensure!(
        !patterns
            .iter()
            .any(|pattern| contains_subslice(contents, pattern)),
        "refuse to publish Mint artifact {path} because it contains credential material"
    );
    Ok(())
}

fn contains_subslice(contents: &[u8], pattern: &[u8]) -> bool {
    !pattern.is_empty()
        && contents
            .windows(pattern.len())
            .any(|window| window == pattern)
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let contents =
        fs::read(path).with_context(|| format!("read Mint artifact {}", path.display()))?;
    serde_json::from_slice(&contents)
        .with_context(|| format!("parse Mint JSON artifact {}", path.display()))
}

fn format_optional_exit_code(exit_code: Option<i32>) -> String {
    match exit_code {
        Some(exit_code) => format!("{exit_code}\n"),
        None => "missing\n".to_string(),
    }
}

fn mint_terminal_summary(evaluation: &MintEvaluation) -> String {
    let mut summary = String::new();
    writeln!(
        summary,
        "Mint {}: gate={} execution={} compatibility={}",
        evaluation.profile.name,
        gate_status(evaluation.gate_status),
        execution_status(evaluation.execution_status),
        compatibility_status(evaluation.compatibility_status)
    )
    .expect("write to String");
    writeln!(
        summary,
        "functions: total={} passed={} failed={} known-failed={} na={} not-run={}",
        evaluation.counts.total,
        evaluation.counts.passed,
        evaluation.counts.failed,
        evaluation.counts.known_failed,
        evaluation.counts.not_applicable,
        evaluation.counts.not_run
    )
    .expect("write to String");
    for diagnostic in &evaluation.diagnostics {
        writeln!(
            summary,
            "diagnostic: {}{}{}",
            diagnostic_code(diagnostic.code),
            diagnostic
                .suite
                .as_deref()
                .map(|suite| format!(" suite={suite}"))
                .unwrap_or_default(),
            diagnostic
                .function
                .as_deref()
                .map(|function| format!(" function={function}"))
                .unwrap_or_default()
        )
        .expect("write to String");
    }
    summary
}

fn mint_junit_xml(evaluation: &MintEvaluation) -> String {
    let diagnostic_case = usize::from(!evaluation.diagnostics.is_empty());
    let failures = evaluation
        .results
        .iter()
        .filter(|result| {
            matches!(
                result.status,
                MintFunctionStatus::Failed | MintFunctionStatus::NotRun
            )
        })
        .count()
        + diagnostic_case;
    let skipped = evaluation
        .results
        .iter()
        .filter(|result| {
            matches!(
                result.status,
                MintFunctionStatus::KnownFailed | MintFunctionStatus::NotApplicable
            )
        })
        .count();
    let mut xml = String::new();
    writeln!(xml, r#"<?xml version="1.0" encoding="UTF-8"?>"#).expect("write to String");
    writeln!(
        xml,
        r#"<testsuite name="{}" tests="{}" failures="{}" skipped="{}">"#,
        escape_xml(&evaluation.profile.name),
        evaluation.results.len() + diagnostic_case,
        failures,
        skipped
    )
    .expect("write to String");
    writeln!(xml, "  <properties>").expect("write to String");
    write_junit_property(
        &mut xml,
        "executionStatus",
        execution_status(evaluation.execution_status),
    );
    write_junit_property(
        &mut xml,
        "compatibilityStatus",
        compatibility_status(evaluation.compatibility_status),
    );
    write_junit_property(&mut xml, "gateStatus", gate_status(evaluation.gate_status));
    write_junit_property(&mut xml, "image", &evaluation.profile.image);
    write_junit_property(&mut xml, "platform", &evaluation.profile.platform);
    write_junit_property(
        &mut xml,
        "targetFingerprint",
        &evaluation.profile.target_fingerprint,
    );
    writeln!(xml, "  </properties>").expect("write to String");
    for result in &evaluation.results {
        write_junit_case(&mut xml, result);
    }
    if !evaluation.diagnostics.is_empty() {
        let detail = evaluation
            .diagnostics
            .iter()
            .map(|diagnostic| diagnostic_code(diagnostic.code))
            .collect::<Vec<_>>()
            .join(",");
        writeln!(
            xml,
            r#"  <testcase name="run-diagnostics" classname="s3chaos.protocol.mint">"#
        )
        .expect("write to String");
        writeln!(
            xml,
            r#"    <failure type="mint-gate" message="mint-gate">{}</failure>"#,
            escape_xml(&detail)
        )
        .expect("write to String");
        writeln!(xml, "  </testcase>").expect("write to String");
    }
    writeln!(xml, "</testsuite>").expect("write to String");
    xml
}

fn write_junit_case(xml: &mut String, result: &MintFunctionResult) {
    writeln!(
        xml,
        r#"  <testcase name="{}" classname="s3chaos.protocol.mint.{}">"#,
        escape_xml(&result.function),
        escape_xml(&result.suite)
    )
    .expect("write to String");
    writeln!(xml, "    <properties>").expect("write to String");
    write_junit_property(xml, "status", function_status(result.status));
    write_junit_property(xml, "observedCount", &result.observed_count.to_string());
    writeln!(xml, "    </properties>").expect("write to String");
    match result.status {
        MintFunctionStatus::Passed => {}
        MintFunctionStatus::Failed => {
            writeln!(
                xml,
                r#"    <failure type="compatibility" message="compatibility">unexpected Mint failure</failure>"#
            )
            .expect("write to String");
        }
        MintFunctionStatus::KnownFailed => {
            let detail = result
                .known_failure
                .as_ref()
                .map(|known| format!("{} ({})", known.reason, known.issue))
                .unwrap_or_else(|| "known Mint failure".to_string());
            writeln!(
                xml,
                r#"    <skipped message="known-failure">{}</skipped>"#,
                escape_xml(&detail)
            )
            .expect("write to String");
        }
        MintFunctionStatus::NotApplicable => {
            writeln!(xml, r#"    <skipped message="not-applicable"/>"#).expect("write to String");
        }
        MintFunctionStatus::NotRun => {
            writeln!(
                xml,
                r#"    <failure type="incomplete" message="incomplete">expected Mint function was not executed</failure>"#
            )
            .expect("write to String");
        }
    }
    writeln!(xml, "  </testcase>").expect("write to String");
}

fn write_junit_property(xml: &mut String, name: &str, value: &str) {
    writeln!(
        xml,
        r#"    <property name="{}" value="{}"/>"#,
        escape_xml(name),
        escape_xml(value)
    )
    .expect("write to String");
}

fn escape_xml(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            '\t' | '\n' | '\r' => escaped.push(character),
            character
                if character >= '\u{20}' && character != '\u{fffe}' && character != '\u{ffff}' =>
            {
                escaped.push(character);
            }
            _ => escaped.push('\u{fffd}'),
        }
    }
    escaped
}

fn execution_status(status: MintExecutionStatus) -> &'static str {
    match status {
        MintExecutionStatus::Complete => "complete",
        MintExecutionStatus::Incomplete => "incomplete",
        MintExecutionStatus::InfrastructureFailed => "infrastructure-failed",
    }
}

fn compatibility_status(status: MintCompatibilityStatus) -> &'static str {
    match status {
        MintCompatibilityStatus::Passed => "passed",
        MintCompatibilityStatus::Failed => "failed",
        MintCompatibilityStatus::KnownFailed => "known-failed",
        MintCompatibilityStatus::NotEvaluated => "not-evaluated",
    }
}

fn gate_status(status: MintGateStatus) -> &'static str {
    match status {
        MintGateStatus::Passed => "passed",
        MintGateStatus::Failed => "failed",
    }
}

fn function_status(status: MintFunctionStatus) -> &'static str {
    match status {
        MintFunctionStatus::Passed => "passed",
        MintFunctionStatus::Failed => "failed",
        MintFunctionStatus::KnownFailed => "known-failed",
        MintFunctionStatus::NotApplicable => "not-applicable",
        MintFunctionStatus::NotRun => "not-run",
    }
}

fn diagnostic_code(code: MintDiagnosticCode) -> &'static str {
    match code {
        MintDiagnosticCode::BaselineDrift => "baseline-drift",
        MintDiagnosticCode::BaselineExpired => "baseline-expired",
        MintDiagnosticCode::BaselineNotActive => "baseline-not-active",
        MintDiagnosticCode::ContainerStartFailed => "container-start-failed",
        MintDiagnosticCode::ContainerRuntimeFailed => "container-runtime-failed",
        MintDiagnosticCode::ExitCodeMissing => "exit-code-missing",
        MintDiagnosticCode::LogCollectionFailed => "log-collection-failed",
        MintDiagnosticCode::LogEmpty => "log-empty",
        MintDiagnosticCode::LogMissing => "log-missing",
        MintDiagnosticCode::LogParseFailed => "log-parse-failed",
        MintDiagnosticCode::MissingFunction => "missing-function",
        MintDiagnosticCode::NetworkUnreachable => "network-unreachable",
        MintDiagnosticCode::NonzeroExitWithoutFailure => "nonzero-exit-without-failure",
        MintDiagnosticCode::UnexpectedFailure => "unexpected-failure",
        MintDiagnosticCode::UnexpectedFunction => "unexpected-function",
        MintDiagnosticCode::UnexpectedNotApplicable => "unexpected-not-applicable",
        MintDiagnosticCode::ZeroExitWithFailure => "zero-exit-with-failure",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::mint::{MintFunctionInventory, MintMode, MintProfileSpec};

    const DIGEST: &str = "sha256:08a05e68893c68be2a83b6f79556853ed6aa3c6c9e64c823a00853e4e55d2200";
    const FINGERPRINT: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    fn profile() -> MintProfile {
        MintProfile::new(MintProfileSpec {
            name: "mint-core".to_string(),
            image: format!("minio/mint:edge@{DIGEST}"),
            platform: "linux/amd64".to_string(),
            mode: MintMode::Core,
            suites: vec!["sdk".to_string()],
            region: "us-east-1".to_string(),
            target_fingerprint: FINGERPRINT.to_string(),
        })
        .expect("profile")
    }

    fn inventory() -> MintInventory {
        MintInventory {
            api_version: API_VERSION.to_string(),
            kind: super::super::INVENTORY_KIND.to_string(),
            image_digest: DIGEST.to_string(),
            platform: "linux/amd64".to_string(),
            mode: MintMode::Core,
            suites: vec!["sdk".to_string()],
            functions: vec![MintFunctionInventory {
                suite: "sdk".to_string(),
                function: "put-object".to_string(),
                allow_na: false,
            }],
        }
    }

    fn known_failures() -> MintKnownFailures {
        MintKnownFailures {
            api_version: API_VERSION.to_string(),
            kind: super::super::KNOWN_FAILURES_KIND.to_string(),
            image_digest: DIGEST.to_string(),
            platform: "linux/amd64".to_string(),
            mode: MintMode::Core,
            suites: vec!["sdk".to_string()],
            entries: Vec::new(),
        }
    }

    #[test]
    fn publication_redacts_captured_credentials_and_remains_self_consistent() {
        let directory = tempfile::tempdir().expect("tempdir");
        let root = directory.path().join("artifacts");
        let secret = "secret-value".to_string();
        let access_key = "access-key".to_string();
        let log = br#"{"name":"sdk","function":"put-object","status":"PASS"}"#;
        let publication = write_mint_artifacts(
            &root,
            &profile(),
            &inventory(),
            &known_failures(),
            MintCapturedRun {
                container_started: true,
                container_exit_code: Some(0),
                infrastructure_failure: None,
                log: Some(log),
                stdout: b"ACCESS_KEY: access-key\n",
                stderr: b"safe stderr\n",
            },
            "2026-08-24T03:00:00Z",
            &[access_key.clone(), secret],
        )
        .expect("publish");

        assert_eq!(publication.gate_exit_code, 0);
        let stdout = fs::read(root.join(MINT_STDOUT_FILE)).expect("stdout");
        assert!(!contains_subslice(&stdout, access_key.as_bytes()));
        assert!(contains_subslice(&stdout, REDACTION));
        assert!(root.join(MINT_LOG_FILE).is_file());
        assert!(root.join(MINT_ARTIFACT_VALIDATION_FILE).is_file());
        validate_mint_artifacts_and_write_report(&root, &[access_key])
            .expect("validate published artifacts");
    }

    #[test]
    fn credential_in_log_prevents_original_log_publication() {
        let directory = tempfile::tempdir().expect("tempdir");
        let root = directory.path().join("artifacts");
        let secret = "secret-value".to_string();
        let log =
            br#"{"name":"sdk","function":"put-object","status":"PASS","error":"secret-value"}"#;
        write_mint_artifacts(
            &root,
            &profile(),
            &inventory(),
            &known_failures(),
            MintCapturedRun {
                container_started: true,
                container_exit_code: Some(0),
                infrastructure_failure: None,
                log: Some(log),
                stdout: b"safe",
                stderr: b"safe",
            },
            "2026-08-24T03:00:00Z",
            std::slice::from_ref(&secret),
        )
        .expect("publish");

        assert!(!root.join(MINT_LOG_FILE).exists());
        let redacted = fs::read(root.join(MINT_REDACTED_LOG_FILE)).expect("redacted log");
        assert!(!contains_subslice(&redacted, secret.as_bytes()));
        assert!(contains_subslice(&redacted, REDACTION));
    }

    #[test]
    fn failed_gate_is_published_with_a_nonzero_gate_exit_code() {
        let directory = tempfile::tempdir().expect("tempdir");
        let root = directory.path().join("artifacts");
        let log = br#"{"name":"sdk","function":"put-object","status":"FAIL"}"#;
        let publication = write_mint_artifacts(
            &root,
            &profile(),
            &inventory(),
            &known_failures(),
            MintCapturedRun {
                container_started: true,
                container_exit_code: Some(1),
                infrastructure_failure: None,
                log: Some(log),
                stdout: b"safe",
                stderr: b"safe",
            },
            "2026-08-24T03:00:00Z",
            &[],
        )
        .expect("publish failure");

        assert_eq!(publication.gate_exit_code, 1);
        assert_eq!(publication.evaluation.gate_status, MintGateStatus::Failed);
        assert_eq!(
            fs::read_to_string(root.join(MINT_GATE_EXIT_CODE_FILE)).expect("gate exit code"),
            "1\n"
        );
    }

    #[test]
    fn validation_rejects_unindexed_artifacts_that_contain_credentials() {
        let directory = tempfile::tempdir().expect("tempdir");
        let root = directory.path().join("artifacts");
        let secret = "secret-value".to_string();
        let log = br#"{"name":"sdk","function":"put-object","status":"PASS"}"#;
        write_mint_artifacts(
            &root,
            &profile(),
            &inventory(),
            &known_failures(),
            MintCapturedRun {
                container_started: true,
                container_exit_code: Some(0),
                infrastructure_failure: None,
                log: Some(log),
                stdout: b"safe",
                stderr: b"safe",
            },
            "2026-08-24T03:00:00Z",
            std::slice::from_ref(&secret),
        )
        .expect("publish");
        fs::write(root.join("unexpected.log"), &secret).expect("unexpected artifact");

        assert!(
            validate_mint_artifacts_and_write_report(&root, &[secret]).is_err(),
            "credential material in any artifact must fail validation"
        );
    }

    #[test]
    fn validation_rejects_tampered_credential_scan_report() {
        let directory = tempfile::tempdir().expect("tempdir");
        let root = directory.path().join("artifacts");
        let access_key = "access-key".to_string();
        let log = br#"{"name":"sdk","function":"put-object","status":"PASS"}"#;
        write_mint_artifacts(
            &root,
            &profile(),
            &inventory(),
            &known_failures(),
            MintCapturedRun {
                container_started: true,
                container_exit_code: Some(0),
                infrastructure_failure: None,
                log: Some(log),
                stdout: b"ACCESS_KEY: access-key\n",
                stderr: b"safe",
            },
            "2026-08-24T03:00:00Z",
            std::slice::from_ref(&access_key),
        )
        .expect("publish");
        let mut scan: MintCredentialScanReport =
            read_json(&root.join(MINT_CREDENTIAL_SCAN_FILE)).expect("scan report");
        scan.detected = false;
        scan.files[0].redacted = false;
        scan.files[0].original_published = true;
        ProtocolArtifactWriter::file(&root)
            .write_json(MINT_CREDENTIAL_SCAN_FILE, &scan)
            .expect("tamper scan report");

        assert!(
            validate_mint_artifacts_and_write_report(&root, &[access_key]).is_err(),
            "tampered credential evidence must fail validation"
        );
    }

    #[cfg(unix)]
    #[test]
    fn validation_rejects_symlinks_before_reading_artifacts() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("tempdir");
        let root = directory.path().join("artifacts");
        let log = br#"{"name":"sdk","function":"put-object","status":"PASS"}"#;
        write_mint_artifacts(
            &root,
            &profile(),
            &inventory(),
            &known_failures(),
            MintCapturedRun {
                container_started: true,
                container_exit_code: Some(0),
                infrastructure_failure: None,
                log: Some(log),
                stdout: b"safe",
                stderr: b"safe",
            },
            "2026-08-24T03:00:00Z",
            &[],
        )
        .expect("publish");
        fs::remove_file(root.join(MINT_LOG_FILE)).expect("remove log");
        symlink("/etc/passwd", root.join(MINT_LOG_FILE)).expect("replace with symlink");

        assert!(
            validate_mint_artifacts_and_write_report(&root, &[]).is_err(),
            "artifact symlinks must be rejected before semantic reads"
        );
    }
}
