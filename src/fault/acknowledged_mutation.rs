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

//! Acknowledgement-driven mutation execution for durability detectors.
//!
//! This module owns the timing and eligibility rules around the narrow window
//! between an S3 mutation ACK and fault activation. Callers submit exactly one
//! quiet mutation and receive either a fully identified committed version or a
//! typed refusal to arm. Backend-specific fault mechanics stay in the supplied
//! activation callback; the caller receives only stable timing evidence.

use std::{fmt, future::Future, time::Duration};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::time::timeout;

use crate::fault::{
    history::{OperationKind, OperationOutcome, OperationRecord, Recorder},
    workload::{ObjectSpec, S3WorkloadClient},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcknowledgedMutationKind {
    Put,
    Overwrite,
    DeleteMarker,
    MultipartComplete,
}

impl AcknowledgedMutationKind {
    fn operation_kind(self) -> OperationKind {
        match self {
            Self::Put | Self::Overwrite => OperationKind::Put,
            Self::DeleteMarker => OperationKind::Delete,
            Self::MultipartComplete => OperationKind::CompleteMultipartUpload,
        }
    }
}

/// A single mutation with no concurrent traffic, post-ACK verification read,
/// or retry. Avoiding activity after the ACK prevents the calibration workload
/// from accidentally flushing the metadata whose loss it is meant to detect.
#[derive(Debug, PartialEq, Eq)]
pub struct QuietMutationWorkload {
    mutation: QuietMutation,
}

#[derive(Debug, PartialEq, Eq)]
enum QuietMutation {
    Put(ObjectSpec),
    Overwrite { object: ObjectSpec, variant: u64 },
    DeleteMarker { key: String },
    MultipartComplete(ObjectSpec),
}

impl QuietMutationWorkload {
    pub fn put(object: ObjectSpec) -> Self {
        Self {
            mutation: QuietMutation::Put(object),
        }
    }

    pub fn overwrite(object: ObjectSpec, variant: u64) -> Self {
        Self {
            mutation: QuietMutation::Overwrite { object, variant },
        }
    }

    pub fn delete_marker(key: impl Into<String>) -> std::result::Result<Self, TriggerError> {
        let key = key.into();
        if key.is_empty() {
            return Err(TriggerError::InvalidConfiguration {
                detail: "quiet delete-marker key must not be empty".to_string(),
            });
        }
        Ok(Self {
            mutation: QuietMutation::DeleteMarker { key },
        })
    }

    pub fn multipart_complete(object: ObjectSpec) -> Self {
        Self {
            mutation: QuietMutation::MultipartComplete(object),
        }
    }

    pub fn kind(&self) -> AcknowledgedMutationKind {
        match self.mutation {
            QuietMutation::Put(_) => AcknowledgedMutationKind::Put,
            QuietMutation::Overwrite { .. } => AcknowledgedMutationKind::Overwrite,
            QuietMutation::DeleteMarker { .. } => AcknowledgedMutationKind::DeleteMarker,
            QuietMutation::MultipartComplete(_) => AcknowledgedMutationKind::MultipartComplete,
        }
    }

    async fn execute(
        self,
        client: &S3WorkloadClient,
        recorder: &Recorder,
    ) -> Result<Option<OperationRecord>> {
        match self.mutation {
            QuietMutation::Put(object) => client
                .put_object_record(&object.prepare(), recorder)
                .await
                .map(Some),
            QuietMutation::Overwrite { object, variant } => client
                .put_object_record(&object.prepare_overwrite(variant), recorder)
                .await
                .map(Some),
            QuietMutation::DeleteMarker { key } => {
                client.delete_marker_record(&key, recorder).await
            }
            QuietMutation::MultipartComplete(object) => {
                client
                    .complete_multipart_object_record(&object.prepare(), recorder)
                    .await
            }
        }
    }
}

/// Executes one quiet mutation and starts a fault only when its completion is
/// a definite versioned commit. Mutation selection, waiting, activation, and
/// the deadline check are one operation so callers cannot accidentally bypass
/// a step. The activation callback returns the time when the actuator became
/// effective, not when activation merely started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcknowledgedMutationTrigger {
    operation_wait_timeout: Duration,
    max_ack_to_fault_ms: u64,
}

impl AcknowledgedMutationTrigger {
    pub fn new(
        operation_wait_timeout: Duration,
        max_ack_to_fault: Duration,
    ) -> std::result::Result<Self, TriggerError> {
        let operation_wait_timeout_ms =
            duration_ms("operation wait timeout", operation_wait_timeout)?;
        let max_ack_to_fault_ms = duration_ms("max ACK-to-fault duration", max_ack_to_fault)?;
        Ok(Self {
            operation_wait_timeout: Duration::from_millis(operation_wait_timeout_ms),
            max_ack_to_fault_ms,
        })
    }

    pub async fn execute_and_activate_fault<F>(
        self,
        client: &S3WorkloadClient,
        recorder: &Recorder,
        workload: QuietMutationWorkload,
        activate_fault: F,
    ) -> std::result::Result<AckToFaultEvidence, TriggerError>
    where
        F: FnOnce() -> Result<u64>,
    {
        let kind = workload.kind();
        let attempt = workload.execute(client, recorder);
        self.execute_attempt_and_activate(kind, attempt, activate_fault)
            .await
    }

    async fn execute_attempt_and_activate<A, F>(
        self,
        kind: AcknowledgedMutationKind,
        attempt: A,
        activate_fault: F,
    ) -> std::result::Result<AckToFaultEvidence, TriggerError>
    where
        A: Future<Output = Result<Option<OperationRecord>>>,
        F: FnOnce() -> Result<u64>,
    {
        let acknowledged = self.wait_for(kind, attempt).await?;
        let fault_activated_at_ms =
            activate_fault().map_err(|error| TriggerError::FaultActivationFailed {
                operation_id: acknowledged.trigger_operation_id.clone(),
                detail: error.to_string(),
            })?;
        acknowledged.fault_activated_at(fault_activated_at_ms)
    }

    async fn wait_for<F>(
        self,
        kind: AcknowledgedMutationKind,
        attempt: F,
    ) -> std::result::Result<AcknowledgedMutation, TriggerError>
    where
        F: Future<Output = Result<Option<OperationRecord>>>,
    {
        let record = timeout(self.operation_wait_timeout, attempt)
            .await
            .map_err(|_| TriggerError::OperationInterrupted {
                wait_timeout_ms: self.operation_wait_timeout.as_millis() as u64,
            })?
            .map_err(|error| TriggerError::WorkloadFailed {
                kind,
                detail: error.to_string(),
            })?
            .ok_or(TriggerError::NoSignal { kind })?;

        AcknowledgedMutation::from_record(kind, record, self.max_ack_to_fault_ms)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AcknowledgedMutation {
    trigger_operation_id: String,
    trigger_kind: AcknowledgedMutationKind,
    trigger_key: String,
    trigger_version_id: String,
    trigger_acknowledged_at_ms: u64,
    max_ack_to_fault_ms: u64,
}

impl AcknowledgedMutation {
    fn from_record(
        kind: AcknowledgedMutationKind,
        record: OperationRecord,
        max_ack_to_fault_ms: u64,
    ) -> std::result::Result<Self, TriggerError> {
        if record.kind != kind.operation_kind() {
            return Err(TriggerError::UnexpectedOperation {
                operation_id: record.id,
                expected: kind,
                actual: record.kind,
            });
        }
        if record.outcome != OperationOutcome::Ok {
            return Err(TriggerError::IneligibleOutcome {
                operation_id: record.id,
                outcome: record.outcome,
            });
        }
        if !record
            .http_status
            .is_some_and(|status| (200..300).contains(&status))
        {
            return Err(TriggerError::InvalidAcknowledgement {
                operation_id: record.id,
                detail: "successful mutation is missing a 2xx HTTP status".to_string(),
            });
        }
        if record.ended_at_ms < record.started_at_ms {
            return Err(TriggerError::InvalidAcknowledgement {
                operation_id: record.id,
                detail: "ACK timestamp precedes operation start".to_string(),
            });
        }
        let key = required_commit_field(&record.id, "key", record.key)?;
        let version_id = required_commit_field(&record.id, "version_id", record.version_id)?;
        if version_id.trim().is_empty() || version_id == "null" {
            return Err(TriggerError::InvalidAcknowledgement {
                operation_id: record.id,
                detail: "committed mutation does not identify a versioned object".to_string(),
            });
        }

        Ok(Self {
            trigger_operation_id: record.id,
            trigger_kind: kind,
            trigger_key: key,
            trigger_version_id: version_id,
            trigger_acknowledged_at_ms: record.ended_at_ms,
            max_ack_to_fault_ms,
        })
    }

    /// Confirms that the fault became active after the ACK and no later than
    /// the configured inclusive deadline.
    fn fault_activated_at(
        &self,
        fault_activated_at_ms: u64,
    ) -> std::result::Result<AckToFaultEvidence, TriggerError> {
        if fault_activated_at_ms < self.trigger_acknowledged_at_ms {
            return Err(TriggerError::FaultPredatesAcknowledgement {
                operation_id: self.trigger_operation_id.clone(),
                acknowledged_at_ms: self.trigger_acknowledged_at_ms,
                fault_activated_at_ms,
            });
        }
        let ack_to_fault_ms = fault_activated_at_ms - self.trigger_acknowledged_at_ms;
        if ack_to_fault_ms > self.max_ack_to_fault_ms {
            return Err(TriggerError::AckToFaultDeadlineExceeded {
                operation_id: self.trigger_operation_id.clone(),
                ack_to_fault_ms,
                max_ack_to_fault_ms: self.max_ack_to_fault_ms,
            });
        }

        Ok(AckToFaultEvidence {
            trigger_operation_id: self.trigger_operation_id.clone(),
            trigger_kind: self.trigger_kind,
            trigger_key: self.trigger_key.clone(),
            trigger_version_id: self.trigger_version_id.clone(),
            trigger_acknowledged_at_ms: self.trigger_acknowledged_at_ms,
            fault_activated_at_ms,
            ack_to_fault_ms,
            max_ack_to_fault_ms: self.max_ack_to_fault_ms,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AckToFaultEvidence {
    pub trigger_operation_id: String,
    pub trigger_kind: AcknowledgedMutationKind,
    pub trigger_key: String,
    pub trigger_version_id: String,
    pub trigger_acknowledged_at_ms: u64,
    pub fault_activated_at_ms: u64,
    pub ack_to_fault_ms: u64,
    pub max_ack_to_fault_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TriggerError {
    InvalidConfiguration {
        detail: String,
    },
    OperationInterrupted {
        wait_timeout_ms: u64,
    },
    WorkloadFailed {
        kind: AcknowledgedMutationKind,
        detail: String,
    },
    NoSignal {
        kind: AcknowledgedMutationKind,
    },
    UnexpectedOperation {
        operation_id: String,
        expected: AcknowledgedMutationKind,
        actual: OperationKind,
    },
    IneligibleOutcome {
        operation_id: String,
        outcome: OperationOutcome,
    },
    InvalidAcknowledgement {
        operation_id: String,
        detail: String,
    },
    FaultActivationFailed {
        operation_id: String,
        detail: String,
    },
    FaultPredatesAcknowledgement {
        operation_id: String,
        acknowledged_at_ms: u64,
        fault_activated_at_ms: u64,
    },
    AckToFaultDeadlineExceeded {
        operation_id: String,
        ack_to_fault_ms: u64,
        max_ack_to_fault_ms: u64,
    },
}

impl fmt::Display for TriggerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration { detail } => write!(formatter, "{detail}"),
            Self::OperationInterrupted { wait_timeout_ms } => write!(
                formatter,
                "quiet mutation was interrupted after waiting {wait_timeout_ms}ms without an acknowledgement"
            ),
            Self::WorkloadFailed { kind, detail } => {
                write!(formatter, "quiet {kind:?} mutation failed: {detail}")
            }
            Self::NoSignal { kind } => write!(
                formatter,
                "quiet {kind:?} mutation produced no completed mutation to acknowledge"
            ),
            Self::UnexpectedOperation {
                operation_id,
                expected,
                actual,
            } => write!(
                formatter,
                "operation {operation_id} was {actual:?}, expected {expected:?}"
            ),
            Self::IneligibleOutcome {
                operation_id,
                outcome,
            } => write!(
                formatter,
                "operation {operation_id} ended with {outcome:?} and cannot arm an ACK trigger"
            ),
            Self::InvalidAcknowledgement {
                operation_id,
                detail,
            } => write!(
                formatter,
                "operation {operation_id} is not an eligible ACK: {detail}"
            ),
            Self::FaultActivationFailed {
                operation_id,
                detail,
            } => write!(
                formatter,
                "fault activation for operation {operation_id} failed: {detail}"
            ),
            Self::FaultPredatesAcknowledgement {
                operation_id,
                acknowledged_at_ms,
                fault_activated_at_ms,
            } => write!(
                formatter,
                "fault for operation {operation_id} became active at {fault_activated_at_ms}ms before its ACK at {acknowledged_at_ms}ms"
            ),
            Self::AckToFaultDeadlineExceeded {
                operation_id,
                ack_to_fault_ms,
                max_ack_to_fault_ms,
            } => write!(
                formatter,
                "fault for operation {operation_id} became active {ack_to_fault_ms}ms after its ACK, exceeding maxAckToFaultMs={max_ack_to_fault_ms}"
            ),
        }
    }
}

impl std::error::Error for TriggerError {}

fn duration_ms(name: &str, duration: Duration) -> std::result::Result<u64, TriggerError> {
    let milliseconds =
        u64::try_from(duration.as_millis()).map_err(|_| TriggerError::InvalidConfiguration {
            detail: format!("{name} exceeds the supported millisecond range"),
        })?;
    if milliseconds == 0 {
        return Err(TriggerError::InvalidConfiguration {
            detail: format!("{name} must be at least 1ms"),
        });
    }
    if Duration::from_millis(milliseconds) != duration {
        return Err(TriggerError::InvalidConfiguration {
            detail: format!("{name} must use whole milliseconds"),
        });
    }
    Ok(milliseconds)
}

fn required_commit_field(
    operation_id: &str,
    name: &str,
    value: Option<String>,
) -> std::result::Result<String, TriggerError> {
    value
        .filter(|value| !value.is_empty())
        .ok_or_else(|| TriggerError::InvalidAcknowledgement {
            operation_id: operation_id.to_string(),
            detail: format!("committed versioned mutation is missing {name}"),
        })
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, future, time::Duration};

    use anyhow::Result;

    use super::{
        AcknowledgedMutation, AcknowledgedMutationKind, AcknowledgedMutationTrigger,
        QuietMutationWorkload, TriggerError,
    };
    use crate::fault::history::{OperationKind, OperationOutcome, OperationRecord};

    fn record(
        kind: OperationKind,
        outcome: OperationOutcome,
        key: Option<&str>,
        version_id: Option<&str>,
        started_at_ms: u64,
        ended_at_ms: u64,
    ) -> OperationRecord {
        OperationRecord {
            id: "op-000042".to_string(),
            scenario: "ack-trigger-test".to_string(),
            kind,
            bucket: "bucket".to_string(),
            key: key.map(str::to_string),
            value_sha256: None,
            size_bytes: None,
            version_id: version_id.map(str::to_string),
            listed_keys: None,
            payload_ref: None,
            range: None,
            started_at_ms,
            ended_at_ms,
            outcome,
            http_status: Some(200),
            error: None,
            durability_cohort: None,
            fault_window_relation: None,
        }
    }

    fn qualify(
        kind: AcknowledgedMutationKind,
        record: OperationRecord,
    ) -> std::result::Result<AcknowledgedMutation, TriggerError> {
        AcknowledgedMutation::from_record(kind, record, 25)
    }

    #[test]
    fn eligible_versioned_mutations_preserve_trigger_identity() {
        let cases = [
            (
                AcknowledgedMutationKind::Put,
                OperationKind::Put,
                "put-version",
            ),
            (
                AcknowledgedMutationKind::Overwrite,
                OperationKind::Put,
                "overwrite-version",
            ),
            (
                AcknowledgedMutationKind::DeleteMarker,
                OperationKind::Delete,
                "delete-marker-version",
            ),
            (
                AcknowledgedMutationKind::MultipartComplete,
                OperationKind::CompleteMultipartUpload,
                "multipart-version",
            ),
        ];

        for (trigger_kind, operation_kind, version_id) in cases {
            let acknowledged = qualify(
                trigger_kind,
                record(
                    operation_kind,
                    OperationOutcome::Ok,
                    Some("key"),
                    Some(version_id),
                    100,
                    110,
                ),
            )
            .expect("eligible mutation");

            assert_eq!(acknowledged.trigger_operation_id, "op-000042");
            assert_eq!(acknowledged.trigger_kind, trigger_kind);
            assert_eq!(acknowledged.trigger_key, "key");
            assert_eq!(acknowledged.trigger_version_id, version_id);
            assert_eq!(acknowledged.trigger_acknowledged_at_ms, 110);
        }
    }

    #[test]
    fn timeout_unknown_and_failed_outcomes_never_arm() {
        for outcome in [
            OperationOutcome::NotFound,
            OperationOutcome::Timeout,
            OperationOutcome::Unknown,
            OperationOutcome::Failed,
        ] {
            let error = qualify(
                AcknowledgedMutationKind::Put,
                record(
                    OperationKind::Put,
                    outcome,
                    Some("key"),
                    Some("version"),
                    100,
                    110,
                ),
            )
            .expect_err("ineligible outcome");

            assert!(matches!(
                error,
                TriggerError::IneligibleOutcome {
                    outcome: actual,
                    ..
                } if actual == outcome
            ));
        }
    }

    #[test]
    fn quiet_workload_declares_one_semantic_mutation() {
        let object = crate::fault::workload::ObjectSpec::prepare_seeded("run", 7, 4096, 42).spec;
        let cases = [
            QuietMutationWorkload::put(object.clone()),
            QuietMutationWorkload::overwrite(object.clone(), 2),
            QuietMutationWorkload::delete_marker(object.key.clone()).expect("delete marker"),
            QuietMutationWorkload::multipart_complete(object.clone()),
        ];

        assert_eq!(cases[0].kind(), AcknowledgedMutationKind::Put);
        assert_eq!(cases[1].kind(), AcknowledgedMutationKind::Overwrite);
        assert_eq!(cases[2].kind(), AcknowledgedMutationKind::DeleteMarker);
        assert_eq!(cases[3].kind(), AcknowledgedMutationKind::MultipartComplete);
        assert!(QuietMutationWorkload::delete_marker("").is_err());
    }

    #[test]
    fn missing_commit_identity_and_wrong_operation_never_arm() {
        let missing_key = qualify(
            AcknowledgedMutationKind::Put,
            record(
                OperationKind::Put,
                OperationOutcome::Ok,
                None,
                Some("version"),
                100,
                110,
            ),
        );
        assert!(matches!(
            missing_key,
            Err(TriggerError::InvalidAcknowledgement { .. })
        ));

        let missing_version = qualify(
            AcknowledgedMutationKind::DeleteMarker,
            record(
                OperationKind::Delete,
                OperationOutcome::Ok,
                Some("key"),
                None,
                100,
                110,
            ),
        );
        assert!(matches!(
            missing_version,
            Err(TriggerError::InvalidAcknowledgement { .. })
        ));

        let null_version = qualify(
            AcknowledgedMutationKind::Put,
            record(
                OperationKind::Put,
                OperationOutcome::Ok,
                Some("key"),
                Some("null"),
                100,
                110,
            ),
        );
        assert!(matches!(
            null_version,
            Err(TriggerError::InvalidAcknowledgement { .. })
        ));

        let wrong_operation = qualify(
            AcknowledgedMutationKind::MultipartComplete,
            record(
                OperationKind::Put,
                OperationOutcome::Ok,
                Some("key"),
                Some("version"),
                100,
                110,
            ),
        );
        assert!(matches!(
            wrong_operation,
            Err(TriggerError::UnexpectedOperation { .. })
        ));
    }

    #[test]
    fn malformed_ack_ordering_never_arms() {
        let result = qualify(
            AcknowledgedMutationKind::Put,
            record(
                OperationKind::Put,
                OperationOutcome::Ok,
                Some("key"),
                Some("version"),
                111,
                110,
            ),
        );

        assert!(matches!(
            result,
            Err(TriggerError::InvalidAcknowledgement { .. })
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn wait_timeout_interrupts_operation_without_arming() {
        let trigger =
            AcknowledgedMutationTrigger::new(Duration::from_millis(10), Duration::from_millis(5))
                .expect("trigger");
        let never_completes = future::pending::<Result<Option<OperationRecord>>>();

        let result = trigger
            .wait_for(AcknowledgedMutationKind::Put, never_completes)
            .await;

        assert_eq!(
            result,
            Err(TriggerError::OperationInterrupted {
                wait_timeout_ms: 10
            })
        );
    }

    #[tokio::test]
    async fn completed_workload_without_mutation_is_no_signal() {
        let trigger =
            AcknowledgedMutationTrigger::new(Duration::from_millis(10), Duration::from_millis(5))
                .expect("trigger");

        let result = trigger
            .wait_for(
                AcknowledgedMutationKind::MultipartComplete,
                future::ready(Ok(None)),
            )
            .await;

        assert_eq!(
            result,
            Err(TriggerError::NoSignal {
                kind: AcknowledgedMutationKind::MultipartComplete
            })
        );
    }

    #[tokio::test]
    async fn ineligible_operation_never_invokes_fault_actuator() {
        let trigger =
            AcknowledgedMutationTrigger::new(Duration::from_millis(10), Duration::from_millis(5))
                .expect("trigger");
        let activated = Cell::new(false);
        let attempt = future::ready(Ok(Some(record(
            OperationKind::Put,
            OperationOutcome::Unknown,
            Some("key"),
            Some("version"),
            100,
            110,
        ))));

        let result = trigger
            .execute_attempt_and_activate(AcknowledgedMutationKind::Put, attempt, || {
                activated.set(true);
                Ok(111)
            })
            .await;

        assert!(matches!(
            result,
            Err(TriggerError::IneligibleOutcome { .. })
        ));
        assert!(!activated.get());
    }

    #[test]
    fn ack_to_fault_deadline_is_inclusive_and_ordered() {
        let acknowledged = qualify(
            AcknowledgedMutationKind::Overwrite,
            record(
                OperationKind::Put,
                OperationOutcome::Ok,
                Some("key"),
                Some("version"),
                100,
                110,
            ),
        )
        .expect("acknowledged");

        let same_millisecond = acknowledged
            .fault_activated_at(110)
            .expect("same millisecond");
        assert_eq!(same_millisecond.ack_to_fault_ms, 0);

        let exact_boundary = acknowledged
            .fault_activated_at(135)
            .expect("inclusive boundary");
        assert_eq!(exact_boundary.ack_to_fault_ms, 25);

        assert!(matches!(
            acknowledged.fault_activated_at(109),
            Err(TriggerError::FaultPredatesAcknowledgement { .. })
        ));
        assert_eq!(
            acknowledged.fault_activated_at(136),
            Err(TriggerError::AckToFaultDeadlineExceeded {
                operation_id: "op-000042".to_string(),
                ack_to_fault_ms: 26,
                max_ack_to_fault_ms: 25,
            })
        );
    }

    #[test]
    fn trigger_durations_must_be_positive_whole_milliseconds() {
        let zero_wait = AcknowledgedMutationTrigger::new(Duration::ZERO, Duration::from_millis(1));
        let submillisecond_deadline = AcknowledgedMutationTrigger::new(
            Duration::from_millis(1),
            Duration::from_nanos(999_999),
        );

        assert!(matches!(
            zero_wait,
            Err(TriggerError::InvalidConfiguration { .. })
        ));
        assert!(matches!(
            submillisecond_deadline,
            Err(TriggerError::InvalidConfiguration { .. })
        ));
    }
}
