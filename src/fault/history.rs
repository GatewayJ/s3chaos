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

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    CreateBucket,
    PutBucketVersioning,
    Put,
    Get,
    Head,
    List,
    ListVersions,
    Delete,
    CreateMultipartUpload,
    UploadPart,
    CompleteMultipartUpload,
    AbortMultipartUpload,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationOutcome {
    Ok,
    NotFound,
    Failed,
    Timeout,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurabilityCohort {
    PreFault,
    FaultActive,
    PostRecovery,
}

impl DurabilityCohort {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PreFault => "pre_fault",
            Self::FaultActive => "fault_active",
            Self::PostRecovery => "post_recovery",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FaultWindowRelation {
    BeforeFault,
    DuringFault,
    AfterFault,
    OverlapsFault,
    Unknown,
}

impl FaultWindowRelation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BeforeFault => "before_fault",
            Self::DuringFault => "during_fault",
            Self::AfterFault => "after_fault",
            Self::OverlapsFault => "overlaps_fault",
            Self::Unknown => "unknown",
        }
    }
}

/// Deterministic payload generator inputs for a committed write. The workload
/// generates every non-multipart body via `seeded_bytes(seed, index, size)`,
/// so recording (seed, index) lets the checker regenerate the exact bytes —
/// the basis for verifying ranged GET slices against any committed value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayloadRef {
    pub seed: u64,
    pub index: usize,
}

/// The byte range a ranged GET requested (inclusive start offset, exact
/// length).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteRange {
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationRecord {
    pub id: String,
    pub scenario: String,
    pub kind: OperationKind,
    pub bucket: String,
    pub key: Option<String>,
    pub value_sha256: Option<String>,
    pub size_bytes: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listed_keys: Option<Vec<String>>,
    /// Set on committed writes whose body came from the seeded generator;
    /// absent for multipart bodies and legacy artifacts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_ref: Option<PayloadRef>,
    /// Set on ranged GETs: `value_sha256`/`size_bytes` then describe the
    /// returned slice, not the whole object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub range: Option<ByteRange>,
    pub started_at_ms: u64,
    pub ended_at_ms: u64,
    pub outcome: OperationOutcome,
    pub http_status: Option<u16>,
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub durability_cohort: Option<DurabilityCohort>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fault_window_relation: Option<FaultWindowRelation>,
}

#[derive(Debug, Clone)]
pub struct Recorder {
    inner: Arc<Mutex<RecorderState>>,
}

#[derive(Debug)]
struct RecorderState {
    path: PathBuf,
    scenario: String,
    run_id: String,
    next_id: usize,
    durability_cohort: DurabilityCohort,
    fault_window: FaultWindow,
    records: Vec<OperationRecord>,
    writer: BufWriter<File>,
}

#[derive(Debug, Default, Clone, Copy)]
struct FaultWindow {
    active_at_ms: Option<u64>,
    ended_at_ms: Option<u64>,
}

impl Recorder {
    pub fn create(
        path: impl Into<PathBuf>,
        scenario: impl Into<String>,
        run_id: impl Into<String>,
    ) -> Result<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let writer = BufWriter::new(File::create(&path)?);
        Ok(Self {
            inner: Arc::new(Mutex::new(RecorderState {
                path,
                scenario: scenario.into(),
                run_id: run_id.into(),
                next_id: 1,
                durability_cohort: DurabilityCohort::PreFault,
                fault_window: FaultWindow::default(),
                records: Vec::new(),
                writer,
            })),
        })
    }

    pub fn begin(
        &self,
        kind: OperationKind,
        bucket: impl Into<String>,
        key: Option<String>,
        value_sha256: Option<String>,
        size_bytes: Option<usize>,
    ) -> OperationRecord {
        let mut state = self.state();
        let id = format!("op-{:06}", state.next_id);
        state.next_id += 1;
        let started_at_ms = now_ms();

        OperationRecord {
            id,
            scenario: state.scenario.clone(),
            kind,
            bucket: bucket.into(),
            key,
            value_sha256,
            size_bytes,
            version_id: None,
            listed_keys: None,
            payload_ref: None,
            range: None,
            started_at_ms,
            ended_at_ms: started_at_ms,
            outcome: OperationOutcome::Unknown,
            http_status: None,
            error: None,
            durability_cohort: Some(state.durability_cohort),
            fault_window_relation: state
                .fault_window
                .relation_for(started_at_ms, started_at_ms),
        }
    }

    pub fn finish(
        &self,
        mut record: OperationRecord,
        outcome: OperationOutcome,
        http_status: Option<u16>,
        error: Option<String>,
    ) -> Result<OperationRecord> {
        record.ended_at_ms = now_ms();
        record.outcome = outcome;
        record.http_status = http_status;
        record.error = error.map(|message| truncate_error(&message));

        let mut state = self.state();
        record.durability_cohort = Some(state.durability_cohort);
        record.fault_window_relation = state
            .fault_window
            .relation_for(record.started_at_ms, record.ended_at_ms);
        serde_json::to_writer(&mut state.writer, &record)?;
        state.writer.write_all(b"\n")?;
        state.writer.flush()?;
        state.records.push(record.clone());
        Ok(record)
    }

    pub fn records(&self) -> Vec<OperationRecord> {
        self.state().records.clone()
    }

    pub fn scenario(&self) -> String {
        self.state().scenario.clone()
    }

    pub fn run_id(&self) -> String {
        self.state().run_id.clone()
    }

    pub fn path(&self) -> PathBuf {
        self.state().path.clone()
    }

    pub fn set_durability_cohort(&self, cohort: DurabilityCohort) {
        self.state().durability_cohort = cohort;
    }

    pub fn mark_fault_active_now(&self) -> u64 {
        let at_ms = now_ms();
        let mut state = self.state();
        state.fault_window.active_at_ms = Some(at_ms);
        state.fault_window.ended_at_ms = None;
        state.durability_cohort = DurabilityCohort::FaultActive;
        at_ms
    }

    pub fn mark_fault_ended_now(&self) -> u64 {
        let at_ms = now_ms();
        let mut state = self.state();
        state.fault_window.ended_at_ms = Some(at_ms);
        state.durability_cohort = DurabilityCohort::PostRecovery;
        at_ms
    }

    fn state(&self) -> MutexGuard<'_, RecorderState> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl FaultWindow {
    fn relation_for(self, started_at_ms: u64, ended_at_ms: u64) -> Option<FaultWindowRelation> {
        let active_at_ms = self.active_at_ms?;
        let Some(fault_ended_at_ms) = self.ended_at_ms else {
            return Some(if ended_at_ms < active_at_ms {
                FaultWindowRelation::BeforeFault
            } else {
                FaultWindowRelation::DuringFault
            });
        };

        if ended_at_ms < active_at_ms {
            Some(FaultWindowRelation::BeforeFault)
        } else if started_at_ms >= fault_ended_at_ms {
            Some(FaultWindowRelation::AfterFault)
        } else if started_at_ms >= active_at_ms && ended_at_ms <= fault_ended_at_ms {
            Some(FaultWindowRelation::DuringFault)
        } else {
            Some(FaultWindowRelation::OverlapsFault)
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

fn truncate_error(message: &str) -> String {
    const MAX_ERROR_LEN: usize = 300;
    if message.len() <= MAX_ERROR_LEN {
        message.to_string()
    } else {
        // Slice on a char boundary at or below the byte budget; error messages
        // carry object keys and backend output that can be non-ASCII, and
        // slicing mid-codepoint would panic in the failure-recording path.
        let mut end = MAX_ERROR_LEN;
        while end > 0 && !message.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &message[..end])
    }
}

#[cfg(test)]
mod tests {
    use super::{DurabilityCohort, OperationKind, OperationOutcome, Recorder};
    use std::collections::BTreeSet;

    #[test]
    fn recorder_writes_jsonl_records() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("history.jsonl");
        let recorder = Recorder::create(&path, "io-eio", "run-1").expect("recorder");
        let record = recorder.begin(
            OperationKind::Put,
            "bucket",
            Some("key".to_string()),
            Some("abc".to_string()),
            Some(3),
        );

        recorder
            .finish(record, OperationOutcome::Ok, Some(200), None)
            .expect("finish");

        let content = std::fs::read_to_string(&path).expect("history");
        assert!(content.contains("\"scenario\":\"io-eio\""));
        assert!(content.contains("\"kind\":\"put\""));
        assert_eq!(recorder.records().len(), 1);
        assert_eq!(recorder.path(), path);
    }

    #[test]
    fn records_without_version_id_still_deserialize() {
        let legacy = r#"{"id":"op-000001","scenario":"io-eio","kind":"put","bucket":"bucket","key":"k","value_sha256":"abc","size_bytes":3,"started_at_ms":1,"ended_at_ms":2,"outcome":"ok","http_status":200,"error":null}"#;

        let record = serde_json::from_str::<super::OperationRecord>(legacy).expect("legacy record");

        assert_eq!(record.version_id, None);
        assert_eq!(record.kind, OperationKind::Put);
    }

    #[test]
    fn recorder_assigns_unique_ids_across_concurrent_writers() {
        let dir = tempfile::tempdir().expect("tempdir");
        let recorder = Recorder::create(dir.path().join("history.jsonl"), "io-eio", "run-1")
            .expect("recorder");
        let writers = (0..8)
            .map(|writer| {
                let recorder = recorder.clone();
                std::thread::spawn(move || {
                    for operation in 0..25 {
                        let record = recorder.begin(
                            OperationKind::Put,
                            "bucket",
                            Some(format!("{writer}-{operation}")),
                            Some("hash".to_string()),
                            Some(4),
                        );
                        recorder
                            .finish(record, OperationOutcome::Ok, Some(200), None)
                            .expect("finish");
                    }
                })
            })
            .collect::<Vec<_>>();
        for writer in writers {
            writer.join().expect("writer thread");
        }

        let records = recorder.records();
        let ids = records
            .iter()
            .map(|record| record.id.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(records.len(), 200);
        assert_eq!(ids.len(), 200);
    }

    #[test]
    fn recorder_marks_durability_cohort_and_fault_window_relation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let recorder = Recorder::create(dir.path().join("history.jsonl"), "io-eio", "run-1")
            .expect("recorder");

        let pre_fault = recorder.begin(
            OperationKind::Put,
            "bucket",
            Some("pre".to_string()),
            Some("hash".to_string()),
            Some(4),
        );
        let pre_fault = recorder
            .finish(pre_fault, OperationOutcome::Ok, Some(200), None)
            .expect("pre fault");
        recorder.mark_fault_active_now();
        let active = recorder.begin(
            OperationKind::Put,
            "bucket",
            Some("active".to_string()),
            Some("hash".to_string()),
            Some(4),
        );
        let active = recorder
            .finish(active, OperationOutcome::Ok, Some(200), None)
            .expect("active");
        recorder.mark_fault_ended_now();
        let post = recorder.begin(
            OperationKind::Get,
            "bucket",
            Some("active".to_string()),
            None,
            None,
        );
        let post = recorder
            .finish(post, OperationOutcome::Ok, Some(200), None)
            .expect("post");

        assert_eq!(
            pre_fault.durability_cohort,
            Some(DurabilityCohort::PreFault)
        );
        assert_eq!(
            active.durability_cohort,
            Some(DurabilityCohort::FaultActive)
        );
        assert_eq!(post.durability_cohort, Some(DurabilityCohort::PostRecovery));
        assert_eq!(
            active
                .fault_window_relation
                .map(|relation| relation.as_str()),
            Some("during_fault")
        );
        assert_eq!(
            post.fault_window_relation.map(|relation| relation.as_str()),
            Some("after_fault")
        );
    }

    #[test]
    fn truncate_error_keeps_short_ascii_intact() {
        let message = "boom";
        assert_eq!(super::truncate_error(message), "boom");
    }

    #[test]
    fn truncate_error_does_not_panic_on_multibyte_boundary() {
        // A multi-byte codepoint straddling the 300-byte cut point must not
        // panic and must produce valid UTF-8. '€' is three bytes; padding the
        // prefix to 299 bytes puts the cut in the middle of a codepoint.
        let message = format!("{}{}", "a".repeat(299), "€".repeat(20));
        let truncated = super::truncate_error(&message);

        assert!(truncated.ends_with("..."));
        assert!(truncated.len() <= 303);
        // The 300th byte lands inside '€', so the boundary walk backs up to 299.
        assert_eq!(truncated, format!("{}...", "a".repeat(299)));
    }
}
