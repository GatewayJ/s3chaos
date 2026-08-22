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

use std::fmt::Write;

use serde::{Deserialize, Serialize};

use crate::protocol::authorization::{
    ProtocolActorSource, ProtocolGrantSource, ProtocolPolicyEffect,
};
use crate::protocol::catalog::ProtocolDomain;
use crate::protocol::credentials::ActorCredentialArtifact;

pub const PROTOCOL_JUNIT_FILE: &str = "protocol-junit.xml";

fn default_protocol_variant() -> String {
    crate::protocol::catalog::DEFAULT_PROTOCOL_VARIANT.to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtocolCaseStatus {
    Passed,
    Failed,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eventual_consistency: Option<ProtocolEventualConsistencyObservation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolEventualConsistencyObservation {
    pub deadline_millis: u64,
    pub interval_millis: u64,
    pub last_observed: String,
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
    pub actors: Vec<ActorCredentialArtifact>,
    pub assertions: Vec<ProtocolAssertion>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_phase: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<String>,
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
    pub status: ProtocolCaseStatus,
    pub plan: String,
    pub preflight: String,
    pub registry: String,
    pub cleanup: String,
    pub compatibility_coverage: String,
    pub case_reports: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_summary: Option<String>,
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
    cases: &[(&ProtocolCaseReport, bool)],
    suite_cleanup_succeeded: bool,
) -> String {
    let statuses = cases
        .iter()
        .map(|(report, cleanup_succeeded)| junit_status(report, *cleanup_succeeded))
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
    for ((report, _), status) in cases.iter().zip(&statuses) {
        writeln!(
            xml,
            r#"  <testcase name="{}::{}" classname="s3chaos.protocol.{}">"#,
            escape_xml(&report.case_id),
            escape_xml(&report.variant_id),
            protocol_domain_name(report.domain)
        )
        .expect("write to String");
        writeln!(xml, "    <properties>").expect("write to String");
        write_junit_property(&mut xml, "caseId", &report.case_id);
        write_junit_property(&mut xml, "variantId", &report.variant_id);
        write_junit_property(&mut xml, "domain", protocol_domain_name(report.domain));
        write_junit_property(&mut xml, "status", status.name());
        if let Some(phase) = &report.failure_phase {
            write_junit_property(&mut xml, "failurePhase", phase);
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

impl ProtocolJunitStatus<'_> {
    fn name(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Skipped { .. } => "not-run",
            Self::Failed {
                failure_type: "preflight",
                ..
            } => "preflight-failed",
            Self::Failed {
                failure_type: "interrupted",
                ..
            } => "interrupted",
            Self::Failed {
                failure_type: "case-timeout",
                ..
            } => "case-timeout",
            Self::Failed {
                failure_type: "suite-timeout",
                ..
            } => "suite-timeout",
            Self::Failed {
                failure_type: "cleanup",
                ..
            } => "cleanup-failed",
            Self::Failed { .. } => "failed",
        }
    }
}

fn junit_status(report: &ProtocolCaseReport, cleanup_succeeded: bool) -> ProtocolJunitStatus<'_> {
    if !cleanup_succeeded {
        return ProtocolJunitStatus::Failed {
            failure_type: "cleanup",
            detail: "protocol cleanup failed",
        };
    }
    if report.status == ProtocolCaseStatus::Passed {
        return ProtocolJunitStatus::Passed;
    }
    let phase = report.failure_phase.as_deref().unwrap_or("case");
    let detail = report.failure.as_deref().unwrap_or("protocol case failed");
    if phase == "not-run" {
        ProtocolJunitStatus::Skipped {
            reason: phase,
            detail,
        }
    } else {
        ProtocolJunitStatus::Failed {
            failure_type: phase,
            detail,
        }
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
    use super::{ProtocolCaseReport, ProtocolCaseStatus, protocol_junit_xml};
    use crate::protocol::catalog::ProtocolDomain;

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
            actors: Vec::new(),
            assertions: Vec::new(),
            failure_phase: phase.map(ToString::to_string),
            failure: failure.map(ToString::to_string),
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
        let cleanup = report("cleanup", "default", ProtocolCaseStatus::Passed, None, None);
        let xml = protocol_junit_xml(
            "suite<&\"'",
            &[
                (&passed, true),
                (&failed, true),
                (&not_run, true),
                (&preflight, true),
                (&interrupted, true),
                (&timeout, true),
                (&cleanup, false),
            ],
            true,
        );
        assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"));
        assert!(xml.contains(
            "<testsuite name=\"suite&lt;&amp;&quot;&apos;\" tests=\"8\" failures=\"5\" skipped=\"1\">"
        ));
        assert!(xml.contains("name=\"passed&lt;&amp;::v&quot;1\""));
        assert!(xml.contains("value=\"preflight-failed\""));
        assert!(xml.contains("value=\"interrupted\""));
        assert!(xml.contains("value=\"case-timeout\""));
        assert!(xml.contains("value=\"cleanup-failed\""));
        assert!(xml.contains("<skipped message=\"not-run\">"));
        assert!(xml.contains("expected &lt;ok&gt; &amp; got &apos;bad&apos;"));
        assert!(xml.contains('\u{fffd}'));
        assert!(!xml.contains("expected <ok>"));
        assert!(xml.contains("name=\"suite-cleanup\""));
        assert!(xml.contains("<property name=\"scope\" value=\"suite\"/>"));
    }

    #[test]
    fn junit_reports_suite_cleanup_failure() {
        let passed = report("passed", "default", ProtocolCaseStatus::Passed, None, None);
        let xml = protocol_junit_xml("suite", &[(&passed, true)], false);

        assert!(
            xml.contains("<testsuite name=\"suite\" tests=\"2\" failures=\"1\" skipped=\"0\">")
        );
        assert!(xml.contains("name=\"suite-cleanup\""));
        assert!(xml.contains("<property name=\"status\" value=\"cleanup-failed\"/>"));
        assert!(xml.contains(
            "<failure type=\"cleanup\" message=\"cleanup\">suite-level fallback cleanup failed"
        ));
    }
}
