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

use std::{collections::BTreeMap, fmt::Write};

use serde::{Deserialize, Serialize};

use crate::protocol::authorization::{
    ProtocolActorSource, ProtocolGrantSource, ProtocolPolicyEffect,
};
use crate::protocol::catalog::ProtocolDomain;
use crate::protocol::credentials::ActorCredentialArtifact;

pub const PROTOCOL_JUNIT_FILE: &str = "protocol-junit.xml";
pub const PROTOCOL_FLAKE_HISTORY_FILE: &str = "protocol-flake-history.json";

fn default_protocol_variant() -> String {
    crate::protocol::catalog::DEFAULT_PROTOCOL_VARIANT.to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtocolCaseStatus {
    Passed,
    Skipped,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtocolCaseOutcome {
    Passed,
    Failed,
    NotRun,
    CapabilitySkipped,
    ExpectedDivergence,
}

impl ProtocolCaseOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::NotRun => "not-run",
            Self::CapabilitySkipped => "capability-skipped",
            Self::ExpectedDivergence => "expected-divergence",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtocolAssertionClass {
    Ok,
    AccessDenied,
    NoSuchBucket,
    NoSuchBucketPolicy,
    NoSuchKey,
    NoSuchPublicAccessBlockConfiguration,
    MalformedPolicy,
    ExpiredToken,
    InvalidToken,
    HarnessError,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolAssertion {
    pub actor_id: String,
    pub actor_source: ProtocolActorSource,
    pub grant_source: ProtocolGrantSource,
    pub policy_effect: ProtocolPolicyEffect,
    pub operation: String,
    pub bucket: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_key: Option<String>,
    pub expected: ProtocolAssertionClass,
    pub actual: ProtocolAssertionClass,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    pub retry_count: usize,
    pub elapsed_millis: u128,
    pub phase: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eventual_consistency: Option<ProtocolEventualConsistencyObservation>,
    #[serde(default)]
    pub exchange: ProtocolExchangeSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolEventualConsistencyObservation {
    pub deadline_millis: u64,
    pub interval_millis: u64,
    pub last_observed: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolExchangeSummary {
    pub method: String,
    pub resource: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub allowed_response_headers: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s3_error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    pub duration_millis: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolCaseCleanupFailure {
    pub classification: String,
    pub message: String,
    pub leftovers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolCaseReport {
    pub api_version: String,
    pub kind: String,
    pub case_id: String,
    #[serde(default = "default_protocol_variant")]
    pub variant_id: String,
    pub domain: ProtocolDomain,
    pub status: ProtocolCaseStatus,
    pub outcome: ProtocolCaseOutcome,
    pub duration_millis: u128,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<crate::protocol::catalog::ProtocolCapabilityCheck>,
    pub actors: Vec<ActorCredentialArtifact>,
    pub assertions: Vec<ProtocolAssertion>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_phase: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_classification: Option<String>,
    #[serde(default)]
    pub cleanup_succeeded: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleanup_failure: Option<ProtocolCaseCleanupFailure>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reproduction: Option<ProtocolReproduction>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolReproduction {
    pub command: String,
    pub suite: String,
    pub case_id: String,
    pub variant_id: String,
    pub seed: String,
    pub original_run_id: String,
    pub target_fingerprint: String,
    pub capability_profile: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolCaseResultSummary {
    pub case_id: String,
    pub variant_id: String,
    pub outcome: ProtocolCaseOutcome,
    pub duration_millis: u128,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_classification: Option<String>,
    pub cleanup_succeeded: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleanup_failure: Option<ProtocolCaseCleanupFailure>,
    pub report: String,
    pub evidence: Vec<String>,
    pub reproduction: ProtocolReproduction,
}

impl ProtocolCaseResultSummary {
    pub fn from_report(report: &ProtocolCaseReport, report_path: String) -> Option<Self> {
        Some(Self {
            case_id: report.case_id.clone(),
            variant_id: report.variant_id.clone(),
            outcome: report.outcome,
            duration_millis: report.duration_millis,
            failure_classification: report.failure_classification.clone(),
            cleanup_succeeded: report.cleanup_succeeded,
            cleanup_failure: report.cleanup_failure.clone(),
            report: report_path,
            evidence: report.evidence.clone(),
            reproduction: report.reproduction.clone()?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolCleanupReport {
    pub api_version: String,
    pub kind: String,
    pub attempts: Vec<ProtocolCleanupAttempt>,
    pub leftovers: Vec<String>,
    pub succeeded: bool,
}

impl ProtocolCleanupReport {
    pub fn empty(api_version: &str) -> Self {
        Self {
            api_version: api_version.to_string(),
            kind: "ProtocolCleanupReport".to_string(),
            attempts: Vec::new(),
            leftovers: Vec::new(),
            succeeded: true,
        }
    }

    pub fn append(&mut self, mut other: Self) {
        self.attempts.append(&mut other.attempts);
        self.leftovers.append(&mut other.leftovers);
        self.succeeded = self.succeeded && other.succeeded;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolCleanupAttempt {
    pub resource_id: String,
    pub resource_kind: String,
    pub resource_name: String,
    pub retry_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retry_history: Vec<ProtocolCleanupRetryObservation>,
    pub succeeded: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolCleanupRetryObservation {
    pub phase: String,
    pub attempt: usize,
    pub backoff_millis: u64,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolSuiteSummary {
    pub api_version: String,
    pub kind: String,
    pub suite: String,
    pub run_id: String,
    pub profile: crate::protocol::suite::ProtocolExecutionProfile,
    pub target_fingerprint: String,
    pub capability_matrix: Vec<crate::protocol::catalog::ProtocolCapabilityCheck>,
    pub status: ProtocolCaseStatus,
    pub plan: String,
    pub preflight: String,
    pub registry: String,
    pub cleanup: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compatibility_coverage: Option<String>,
    pub flaky_history: String,
    pub case_reports: Vec<String>,
    pub case_results: Vec<ProtocolCaseResultSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_summary: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolFlakeHistory {
    pub api_version: String,
    pub kind: String,
    pub profile: crate::protocol::suite::ProtocolExecutionProfile,
    pub entries: Vec<ProtocolFlakeHistoryEntry>,
    pub signals: Vec<ProtocolFlakeSignal>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolFlakeHistoryEntry {
    pub run_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_revision: Option<String>,
    pub case_id: String,
    pub variant_id: String,
    pub status: ProtocolCaseStatus,
    pub implicit_retry_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolFlakeSignal {
    pub case_id: String,
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub flaky: bool,
}

pub(crate) fn protocol_flake_status(report: &ProtocolCaseReport) -> ProtocolCaseStatus {
    if matches!(
        report.failure_phase.as_deref(),
        Some("preflight" | "not-run" | "capability-skip")
    ) {
        ProtocolCaseStatus::Skipped
    } else {
        report.status
    }
}

pub(crate) fn protocol_flake_signals(
    entries: &[ProtocolFlakeHistoryEntry],
) -> Vec<ProtocolFlakeSignal> {
    let mut counts = BTreeMap::<String, (usize, usize, usize)>::new();
    for entry in entries {
        let counts = counts.entry(entry.case_id.clone()).or_default();
        match entry.status {
            ProtocolCaseStatus::Passed => counts.0 += 1,
            ProtocolCaseStatus::Failed => counts.1 += 1,
            ProtocolCaseStatus::Skipped => counts.2 += 1,
        }
    }
    counts
        .into_iter()
        .map(|(case_id, (passed, failed, skipped))| ProtocolFlakeSignal {
            case_id,
            passed,
            failed,
            skipped,
            flaky: passed > 0 && failed > 0,
        })
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolFailureSummary {
    pub api_version: String,
    pub kind: String,
    pub stage: String,
    pub classification: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub case_id: Option<String>,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolArtifactValidationReport {
    pub api_version: String,
    pub kind: String,
    pub artifact_root: String,
    pub valid: bool,
    pub checked_files: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
}

/// Renders the stable protocol JUnit artifact from the same case and cleanup results used by the
/// JSON suite summary. `not-run` is represented as skipped; preflight, interruption, assertion,
/// case cleanup, and suite cleanup failures remain failures so CI cannot mistake an incomplete
/// or cleanup-contaminated suite for a pass.
pub fn protocol_junit_xml(
    suite: &str,
    cases: &[&ProtocolCaseReport],
    suite_cleanup_succeeded: bool,
) -> String {
    let statuses = cases
        .iter()
        .map(|report| junit_status(report))
        .collect::<Vec<_>>();
    let failures = statuses
        .iter()
        .filter(|status| matches!(status, ProtocolJunitStatus::Failed { .. }))
        .count()
        + usize::from(!suite_cleanup_succeeded);
    let skipped = statuses
        .iter()
        .filter(|status| matches!(status, ProtocolJunitStatus::Skipped { .. }))
        .count();
    let mut xml = String::new();
    writeln!(xml, r#"<?xml version="1.0" encoding="UTF-8"?>"#).expect("write to String");
    writeln!(
        xml,
        r#"<testsuite name="{}" tests="{}" failures="{}" skipped="{}">"#,
        escape_xml(suite),
        cases.len() + 1,
        failures,
        skipped
    )
    .expect("write to String");
    for (report, status) in cases.iter().zip(&statuses) {
        writeln!(
            xml,
            r#"  <testcase name="{}::{}" classname="s3chaos.protocol.{}" time="{:.3}">"#,
            escape_xml(&report.case_id),
            escape_xml(&report.variant_id),
            protocol_domain_name(report.domain),
            report.duration_millis as f64 / 1_000.0,
        )
        .expect("write to String");
        writeln!(xml, "    <properties>").expect("write to String");
        write_junit_property(&mut xml, "caseId", &report.case_id);
        write_junit_property(&mut xml, "variantId", &report.variant_id);
        write_junit_property(&mut xml, "domain", protocol_domain_name(report.domain));
        write_junit_property(&mut xml, "status", report.outcome.as_str());
        write_junit_property(
            &mut xml,
            "durationMillis",
            &report.duration_millis.to_string(),
        );
        write_junit_property(
            &mut xml,
            "cleanupSucceeded",
            &report.cleanup_succeeded.to_string(),
        );
        if let Some(classification) = &report.failure_classification {
            write_junit_property(&mut xml, "failureClassification", classification);
        }
        if let Some(cleanup_failure) = &report.cleanup_failure {
            write_junit_property(
                &mut xml,
                "cleanupFailureClassification",
                &cleanup_failure.classification,
            );
            write_junit_property(&mut xml, "cleanupFailure", &cleanup_failure.message);
            write_junit_property(
                &mut xml,
                "cleanupLeftovers",
                &cleanup_failure.leftovers.join(","),
            );
        }
        for capability in &report.capabilities {
            write_junit_property(
                &mut xml,
                &format!("capability.{}", capability.capability),
                match capability.state {
                    crate::protocol::catalog::ProtocolCapabilityState::Pass => "pass",
                    crate::protocol::catalog::ProtocolCapabilityState::Skip => "skip",
                    crate::protocol::catalog::ProtocolCapabilityState::Fail => "fail",
                },
            );
            write_junit_property(
                &mut xml,
                &format!("capabilityReason.{}", capability.capability),
                &capability.reason,
            );
        }
        if let Some(phase) = &report.failure_phase {
            write_junit_property(&mut xml, "failurePhase", phase);
        }
        if let Some(reproduction) = &report.reproduction {
            write_junit_property(&mut xml, "reproductionCommand", &reproduction.command);
            write_junit_property(
                &mut xml,
                "targetFingerprint",
                &reproduction.target_fingerprint,
            );
            write_junit_property(
                &mut xml,
                "capabilityProfile",
                &reproduction.capability_profile.join(","),
            );
            write_junit_property(&mut xml, "seed", &reproduction.seed);
        }
        writeln!(xml, "    </properties>").expect("write to String");
        match status {
            ProtocolJunitStatus::Passed => {}
            ProtocolJunitStatus::Skipped { reason, detail } => {
                writeln!(
                    xml,
                    r#"    <skipped message="{}">{}</skipped>"#,
                    escape_xml(reason),
                    escape_xml(detail)
                )
                .expect("write to String");
            }
            ProtocolJunitStatus::Failed {
                failure_type,
                detail,
            } => {
                writeln!(
                    xml,
                    r#"    <failure type="{}" message="{}">{}</failure>"#,
                    escape_xml(failure_type),
                    escape_xml(failure_type),
                    escape_xml(detail)
                )
                .expect("write to String");
            }
        }
        writeln!(xml, "  </testcase>").expect("write to String");
    }
    writeln!(
        xml,
        r#"  <testcase name="suite-cleanup" classname="s3chaos.protocol.cleanup">"#
    )
    .expect("write to String");
    writeln!(xml, "    <properties>").expect("write to String");
    write_junit_property(&mut xml, "scope", "suite");
    write_junit_property(
        &mut xml,
        "status",
        if suite_cleanup_succeeded {
            "passed"
        } else {
            "cleanup-failed"
        },
    );
    writeln!(xml, "    </properties>").expect("write to String");
    if !suite_cleanup_succeeded {
        writeln!(
            xml,
            r#"    <failure type="cleanup" message="cleanup">suite-level fallback cleanup failed; inspect cleanup-report.json</failure>"#
        )
        .expect("write to String");
    }
    writeln!(xml, "  </testcase>").expect("write to String");
    writeln!(xml, "</testsuite>").expect("write to String");
    xml
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProtocolJunitStatus<'a> {
    Passed,
    Skipped {
        reason: &'a str,
        detail: &'a str,
    },
    Failed {
        failure_type: &'a str,
        detail: &'a str,
    },
}

fn junit_status(report: &ProtocolCaseReport) -> ProtocolJunitStatus<'_> {
    let detail = report.failure.as_deref().unwrap_or("protocol case failed");
    match report.outcome {
        ProtocolCaseOutcome::Passed => ProtocolJunitStatus::Passed,
        ProtocolCaseOutcome::NotRun
        | ProtocolCaseOutcome::CapabilitySkipped
        | ProtocolCaseOutcome::ExpectedDivergence => ProtocolJunitStatus::Skipped {
            reason: report.outcome.as_str(),
            detail,
        },
        ProtocolCaseOutcome::Failed => ProtocolJunitStatus::Failed {
            failure_type: report
                .failure_classification
                .as_deref()
                .unwrap_or("protocol-case-failure"),
            detail,
        },
    }
}

fn write_junit_property(xml: &mut String, name: &str, value: &str) {
    writeln!(
        xml,
        r#"      <property name="{}" value="{}"/>"#,
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

fn protocol_domain_name(domain: ProtocolDomain) -> &'static str {
    match domain {
        ProtocolDomain::Bucket => "bucket",
        ProtocolDomain::Object => "object",
        ProtocolDomain::Listing => "listing",
        ProtocolDomain::CopyDelete => "copy-delete",
        ProtocolDomain::Multipart => "multipart",
        ProtocolDomain::Versioning => "versioning",
        ProtocolDomain::BucketConfig => "bucket-config",
        ProtocolDomain::IntegrityEncryption => "integrity-encryption",
        ProtocolDomain::Authorization => "authorization",
        ProtocolDomain::Iam => "iam",
        ProtocolDomain::Sts => "sts",
        ProtocolDomain::S3Select => "s3-select",
        ProtocolDomain::Notification => "notification",
        ProtocolDomain::RequestValidation => "request-validation",
        ProtocolDomain::Other => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ProtocolAssertion, ProtocolAssertionClass, ProtocolCaseCleanupFailure, ProtocolCaseOutcome,
        ProtocolCaseReport, ProtocolCaseStatus, ProtocolExchangeSummary, ProtocolReproduction,
        protocol_junit_xml,
    };
    use crate::protocol::authorization::{
        ProtocolActorSource, ProtocolGrantSource, ProtocolPolicyEffect,
    };
    use crate::protocol::catalog::{
        ProtocolCapability, ProtocolCapabilityCheck, ProtocolCapabilitySource,
        ProtocolCapabilityState, ProtocolDomain,
    };

    fn report(
        case_id: &str,
        variant_id: &str,
        status: ProtocolCaseStatus,
        phase: Option<&str>,
        failure: Option<&str>,
    ) -> ProtocolCaseReport {
        ProtocolCaseReport {
            api_version: "rustfs.com/s3chaos/v1alpha1".to_string(),
            kind: "ProtocolCaseReport".to_string(),
            case_id: case_id.to_string(),
            variant_id: variant_id.to_string(),
            domain: ProtocolDomain::RequestValidation,
            status,
            outcome: if phase == Some("not-run") {
                ProtocolCaseOutcome::NotRun
            } else if phase == Some("capability-skip") {
                ProtocolCaseOutcome::CapabilitySkipped
            } else if status == ProtocolCaseStatus::Passed {
                ProtocolCaseOutcome::Passed
            } else {
                ProtocolCaseOutcome::Failed
            },
            duration_millis: 125,
            capabilities: Vec::new(),
            actors: Vec::new(),
            assertions: Vec::new(),
            failure_phase: phase.map(ToString::to_string),
            failure: failure.map(ToString::to_string),
            failure_classification: phase.map(ToString::to_string),
            cleanup_succeeded: true,
            cleanup_failure: None,
            evidence: Vec::new(),
            reproduction: Some(ProtocolReproduction {
                command: "s3chaos protocol-suite-reproduce artifacts case".to_string(),
                suite: "suite".to_string(),
                case_id: case_id.to_string(),
                variant_id: variant_id.to_string(),
                seed: "deterministic-no-randomized-order".to_string(),
                original_run_id: "run".to_string(),
                target_fingerprint: "fingerprint".to_string(),
                capability_profile: vec!["s3".to_string()],
            }),
        }
    }

    #[test]
    fn junit_maps_all_execution_states_and_escapes_xml() {
        let passed = report("passed<&", "v\"1", ProtocolCaseStatus::Passed, None, None);
        let failed = report(
            "failed",
            "default",
            ProtocolCaseStatus::Failed,
            Some("assertion"),
            Some("expected <ok> & got 'bad'\u{1}"),
        );
        let not_run = report(
            "not-run",
            "default",
            ProtocolCaseStatus::Failed,
            Some("not-run"),
            Some("stopped after prior failure"),
        );
        let mut capability_skip = report(
            "capability-skip",
            "default",
            ProtocolCaseStatus::Skipped,
            Some("capability-skip"),
            Some("optional external provider is missing"),
        );
        capability_skip.capabilities = vec![ProtocolCapabilityCheck {
            capability: ProtocolCapability::ExternalIdp,
            source: ProtocolCapabilitySource::External,
            state: ProtocolCapabilityState::Skip,
            reason: "optional external provider is missing".to_string(),
        }];
        let preflight = report(
            "preflight",
            "default",
            ProtocolCaseStatus::Failed,
            Some("preflight"),
            Some("probe failed"),
        );
        let interrupted = report(
            "interrupted",
            "default",
            ProtocolCaseStatus::Failed,
            Some("interrupted"),
            Some("signal received"),
        );
        let timeout = report(
            "timeout",
            "default",
            ProtocolCaseStatus::Failed,
            Some("case-timeout"),
            Some("case budget expired"),
        );
        let mut capability = report(
            "capability",
            "default",
            ProtocolCaseStatus::Passed,
            Some("capability"),
            Some("external provider is not configured"),
        );
        capability.outcome = ProtocolCaseOutcome::CapabilitySkipped;
        let mut divergence = report(
            "divergence",
            "default",
            ProtocolCaseStatus::Passed,
            Some("expected-divergence"),
            Some("tracked compatibility difference"),
        );
        divergence.outcome = ProtocolCaseOutcome::ExpectedDivergence;
        let mut cleanup = report("cleanup", "default", ProtocolCaseStatus::Passed, None, None);
        cleanup.status = ProtocolCaseStatus::Failed;
        cleanup.outcome = ProtocolCaseOutcome::Failed;
        cleanup.cleanup_succeeded = false;
        cleanup.failure_classification = Some("cleanup-failure".to_string());
        cleanup.failure = Some("cleanup failed".to_string());
        cleanup.cleanup_failure = Some(ProtocolCaseCleanupFailure {
            classification: "cleanup-failure".to_string(),
            message: "cleanup failed".to_string(),
            leftovers: vec!["object:key".to_string()],
        });
        let xml = protocol_junit_xml(
            "suite<&\"'",
            &[
                &passed,
                &failed,
                &not_run,
                &capability_skip,
                &preflight,
                &interrupted,
                &timeout,
                &capability,
                &divergence,
                &cleanup,
            ],
            true,
        );
        assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"));
        assert!(xml.contains(
            "<testsuite name=\"suite&lt;&amp;&quot;&apos;\" tests=\"11\" failures=\"5\" skipped=\"4\">"
        ));
        assert!(xml.contains("name=\"passed&lt;&amp;::v&quot;1\""));
        assert!(xml.contains("name=\"failureClassification\" value=\"preflight\""));
        assert!(xml.contains("name=\"failureClassification\" value=\"interrupted\""));
        assert!(xml.contains("name=\"failureClassification\" value=\"case-timeout\""));
        assert!(xml.contains("name=\"failureClassification\" value=\"cleanup-failure\""));
        assert!(xml.contains("name=\"cleanupFailureClassification\" value=\"cleanup-failure\""));
        assert!(xml.contains("time=\"0.125\""));
        assert!(xml.contains("<skipped message=\"not-run\">"));
        assert!(xml.contains("<skipped message=\"capability-skipped\">"));
        assert!(xml.contains("<skipped message=\"expected-divergence\">"));
        assert!(xml.contains("name=\"capability.external-idp\" value=\"skip\""));
        assert!(xml.contains("name=\"capabilityReason.external-idp\""));
        assert!(xml.contains("expected &lt;ok&gt; &amp; got &apos;bad&apos;"));
        assert!(xml.contains('\u{fffd}'));
        assert!(!xml.contains("expected <ok>"));
        assert!(xml.contains("name=\"suite-cleanup\""));
        assert!(xml.contains("<property name=\"scope\" value=\"suite\"/>"));
    }

    #[test]
    fn junit_reports_suite_cleanup_failure() {
        let passed = report("passed", "default", ProtocolCaseStatus::Passed, None, None);
        let xml = protocol_junit_xml("suite", &[&passed], false);

        assert!(
            xml.contains("<testsuite name=\"suite\" tests=\"2\" failures=\"1\" skipped=\"0\">")
        );
        assert!(xml.contains("name=\"suite-cleanup\""));
        assert!(xml.contains("<property name=\"status\" value=\"cleanup-failed\"/>"));
        assert!(xml.contains(
            "<failure type=\"cleanup\" message=\"cleanup\">suite-level fallback cleanup failed"
        ));
    }

    #[test]
    fn v1alpha1_assertion_defaults_missing_eventual_consistency() {
        let assertion = ProtocolAssertion {
            actor_id: "actor".to_string(),
            actor_source: ProtocolActorSource::IamUser,
            grant_source: ProtocolGrantSource::BucketPolicy,
            policy_effect: ProtocolPolicyEffect::Allow,
            operation: "GetObject".to_string(),
            bucket: "bucket".to_string(),
            object_key: Some("key".to_string()),
            expected: ProtocolAssertionClass::Ok,
            actual: ProtocolAssertionClass::Ok,
            raw_error_code: None,
            http_status: Some(200),
            request_id: Some("request".to_string()),
            retry_count: 0,
            elapsed_millis: 1,
            phase: "assertion".to_string(),
            eventual_consistency: None,
            exchange: ProtocolExchangeSummary::default(),
        };
        let mut legacy = serde_json::to_value(&assertion).expect("legacy assertion JSON");
        legacy
            .as_object_mut()
            .expect("assertion object")
            .remove("exchange");
        assert!(legacy.get("eventualConsistency").is_none());

        let decoded: ProtocolAssertion =
            serde_json::from_value(legacy).expect("legacy assertion artifact");
        assert_eq!(decoded, assertion);
    }
}
