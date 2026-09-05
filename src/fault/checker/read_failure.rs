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

use crate::fault::history::OperationOutcome;
use serde::{Deserialize, Serialize};

/// Structured evidence for new reports; old string records remain readable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CommittedReadFailure {
    Observed {
        key: String,
        outcome: OperationOutcome,
        http_status: Option<u16>,
        error: Option<String>,
        unexpected_body_bytes: Option<usize>,
    },
    Legacy(String),
}

impl CommittedReadFailure {
    pub(super) fn observed(
        key: &str,
        outcome: OperationOutcome,
        http_status: Option<u16>,
        error: Option<&str>,
        unexpected_body_bytes: Option<usize>,
    ) -> Self {
        Self::Observed {
            key: key.to_string(),
            outcome,
            http_status,
            error: error.map(str::to_string),
            unexpected_body_bytes,
        }
    }

    pub(super) fn key(&self) -> Option<&str> {
        match self {
            Self::Observed { key, .. } => (!key.is_empty()).then_some(key),
            Self::Legacy(message) => legacy_read_failure_key(message),
        }
    }

    pub(super) fn evidence(&self) -> Option<ReadFailureEvidence<'_>> {
        match self {
            Self::Observed {
                key,
                outcome,
                http_status,
                error,
                unexpected_body_bytes: None,
            } if !key.is_empty() => Some(ReadFailureEvidence {
                key,
                outcome: *outcome,
                http_status: *http_status,
                error: error.as_deref(),
            }),
            Self::Observed { .. } => None,
            Self::Legacy(message) => parse_legacy_read_failure(message),
        }
    }
}

#[cfg(test)]
impl From<String> for CommittedReadFailure {
    fn from(value: String) -> Self {
        Self::Legacy(value)
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct ReadFailureEvidence<'a> {
    pub(super) key: &'a str,
    pub(super) outcome: OperationOutcome,
    pub(super) http_status: Option<u16>,
    pub(super) error: Option<&'a str>,
}

const READ_FAILURE_MARKER: &str = ": outcome=";
const UNEXPECTED_BODY_MARKER: &str = ": unexpected body for ";

fn parse_legacy_read_failure(message: &str) -> Option<ReadFailureEvidence<'_>> {
    if message.match_indices(READ_FAILURE_MARKER).count() != 1
        || message.contains(UNEXPECTED_BODY_MARKER)
    {
        return None;
    }
    let (key, fields) = message.split_once(READ_FAILURE_MARKER)?;
    if key.is_empty() {
        return None;
    }
    let (outcome, mut remaining) = fields
        .split_once(' ')
        .map_or((fields, ""), |(outcome, remaining)| (outcome, remaining));
    let outcome = match outcome {
        "Ok" => OperationOutcome::Ok,
        "NotFound" => OperationOutcome::NotFound,
        "Failed" => OperationOutcome::Failed,
        "Timeout" => OperationOutcome::Timeout,
        "Unknown" => OperationOutcome::Unknown,
        _ => return None,
    };
    let mut http_status = None;
    if let Some(status_and_remaining) = remaining.strip_prefix("status=") {
        let (status, rest) = status_and_remaining
            .split_once(' ')
            .map_or((status_and_remaining, ""), |(status, rest)| (status, rest));
        http_status = Some(status.parse().ok()?);
        remaining = rest;
    }
    let error = if remaining.is_empty() {
        None
    } else {
        let error = remaining.strip_prefix("error=")?;
        (!error.is_empty()).then_some(error)
    };
    Some(ReadFailureEvidence {
        key,
        outcome,
        http_status,
        error,
    })
}

fn legacy_read_failure_key(message: &str) -> Option<&str> {
    if let Some(parsed) = parse_legacy_read_failure(message) {
        return Some(parsed.key);
    }
    if message.match_indices(UNEXPECTED_BODY_MARKER).count() != 1
        || message.contains(READ_FAILURE_MARKER)
    {
        return None;
    }
    let (key, detail) = message.split_once(UNEXPECTED_BODY_MARKER)?;
    (!key.is_empty()
        && ["Ok", "NotFound", "Failed", "Timeout", "Unknown"]
            .iter()
            .any(|outcome| detail.starts_with(outcome))
        && detail.ends_with(" bytes)"))
    .then_some(key)
}
