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

use serde::{Deserialize, Serialize};

use crate::protocol::authorization::{
    ProtocolActorSource, ProtocolGrantSource, ProtocolPolicyEffect,
};
use crate::protocol::credentials::ActorCredentialArtifact;

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
    NoSuchKey,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolCaseReport {
    pub api_version: String,
    pub kind: String,
    pub case_id: String,
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
    pub succeeded: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
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
