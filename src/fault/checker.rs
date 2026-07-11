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
use futures::{StreamExt, stream};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};
use tokio::time::{sleep as async_sleep, timeout};

use crate::fault::{
    history::{OperationKind, OperationOutcome, OperationRecord, Recorder},
    workload::{GetObjectResult, ObjectSpec, ObjectVersionEntry, S3WorkloadClient, sha256_hex},
};

const MAX_WARNING_SAMPLES: usize = 50;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckerReport {
    pub scenario: String,
    pub run_id: String,
    pub committed_puts: usize,
    pub expected_live_objects: usize,
    pub verified_live_objects: usize,
    pub missing_committed_objects: Vec<String>,
    pub unavailable_committed_objects: Vec<String>,
    pub unknown_committed_read_failures: Vec<String>,
    pub hash_mismatches: Vec<String>,
    pub successful_corrupted_reads: Vec<String>,
    pub unexpected_visible_deleted_objects: Vec<String>,
    #[serde(default)]
    pub unknown_writes_materialized: Vec<String>,
    #[serde(default)]
    pub unknown_writes_preserved_committed: Vec<String>,
    #[serde(default)]
    pub unknown_write_value_conflicts: Vec<String>,
    pub list_history_warning_count: usize,
    pub final_list_warning_count: usize,
    pub list_history_warnings: Vec<String>,
    pub list_warnings: Vec<String>,
    pub final_listed_objects: Option<usize>,
    #[serde(default)]
    pub versioning_expected: bool,
    #[serde(default)]
    pub expected_committed_versions: usize,
    #[serde(default)]
    pub verified_committed_versions: usize,
    #[serde(default)]
    pub committed_writes_missing_version_id_count: usize,
    #[serde(default)]
    pub committed_writes_missing_version_id: Vec<String>,
    #[serde(default)]
    pub missing_committed_versions: Vec<String>,
    #[serde(default)]
    pub unavailable_committed_versions: Vec<String>,
    #[serde(default)]
    pub version_hash_mismatches: Vec<String>,
    #[serde(default)]
    pub missing_committed_delete_markers: Vec<String>,
    #[serde(default)]
    pub resurrected_deleted_objects: Vec<String>,
    /// Committed-present keys whose latest delete was ambiguous and that
    /// returned 404 after recovery: the delete legitimately took effect, so
    /// these are recorded for audit but do not fail the run.
    #[serde(default)]
    pub tolerated_ambiguous_deletes: Vec<String>,
    #[serde(default)]
    pub operation_cohorts: BTreeMap<String, usize>,
    #[serde(default)]
    pub fault_window_relations: BTreeMap<String, usize>,
    pub tenant_recovered: bool,
    pub passed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryStabilityClassification {
    DataCorruption,
    CommittedObjectUnavailable,
    ListUnavailableOrUnknown,
    RecoveryTailReadLatency,
    AmbiguousWriteMaterialized,
    HarnessError,
}

impl RecoveryStabilityClassification {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::DataCorruption => "data_corruption",
            Self::CommittedObjectUnavailable => "committed_object_unavailable",
            Self::ListUnavailableOrUnknown => "list_unavailable_or_unknown",
            Self::RecoveryTailReadLatency => "recovery_tail_read_latency",
            Self::AmbiguousWriteMaterialized => "ambiguous_write_materialized",
            Self::HarnessError => "harness_error",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryStabilityReport {
    pub immediate_passed: bool,
    pub reread_attempted_keys: Vec<String>,
    pub reread_recovered_keys: Vec<String>,
    pub still_unavailable_keys: Vec<String>,
    pub hash_mismatches: Vec<String>,
    #[serde(default)]
    pub data_corruption_evidence: Vec<String>,
    #[serde(default)]
    pub ambiguous_write_evidence: Vec<String>,
    #[serde(default)]
    pub final_list_warning_count: usize,
    #[serde(default)]
    pub list_warnings: Vec<String>,
    pub harness_errors: Vec<String>,
    pub max_recovery_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovered_within_seconds: Option<u64>,
    pub classification: RecoveryStabilityClassification,
}

impl RecoveryStabilityReport {
    pub(crate) fn harness_error(message: impl Into<String>, max_recovery: Duration) -> Self {
        Self {
            immediate_passed: false,
            reread_attempted_keys: Vec::new(),
            reread_recovered_keys: Vec::new(),
            still_unavailable_keys: Vec::new(),
            hash_mismatches: Vec::new(),
            data_corruption_evidence: Vec::new(),
            ambiguous_write_evidence: Vec::new(),
            final_list_warning_count: 0,
            list_warnings: Vec::new(),
            harness_errors: vec![message.into()],
            max_recovery_seconds: max_recovery.as_secs(),
            recovered_within_seconds: None,
            classification: RecoveryStabilityClassification::HarnessError,
        }
    }

    pub(crate) fn evidence_classifications(&self) -> Vec<String> {
        let mut classifications = BTreeSet::new();
        classifications.insert(self.classification.as_str().to_string());
        if !self.hash_mismatches.is_empty() || !self.data_corruption_evidence.is_empty() {
            classifications.insert(
                RecoveryStabilityClassification::DataCorruption
                    .as_str()
                    .to_string(),
            );
        }
        if !self.still_unavailable_keys.is_empty() {
            classifications.insert(
                RecoveryStabilityClassification::CommittedObjectUnavailable
                    .as_str()
                    .to_string(),
            );
        }
        if self.classification == RecoveryStabilityClassification::ListUnavailableOrUnknown {
            classifications.insert(
                RecoveryStabilityClassification::ListUnavailableOrUnknown
                    .as_str()
                    .to_string(),
            );
        }
        if !self.ambiguous_write_evidence.is_empty() {
            classifications.insert(
                RecoveryStabilityClassification::AmbiguousWriteMaterialized
                    .as_str()
                    .to_string(),
            );
        }
        if !self.reread_attempted_keys.is_empty()
            && self.reread_attempted_keys == self.reread_recovered_keys
            && self.still_unavailable_keys.is_empty()
            && self.hash_mismatches.is_empty()
            && self.harness_errors.is_empty()
        {
            classifications.insert(
                RecoveryStabilityClassification::RecoveryTailReadLatency
                    .as_str()
                    .to_string(),
            );
        }
        if !self.harness_errors.is_empty() {
            classifications.insert(
                RecoveryStabilityClassification::HarnessError
                    .as_str()
                    .to_string(),
            );
        }
        classifications.into_iter().collect()
    }
}

impl CheckerReport {
    pub fn require_success(&self) -> Result<()> {
        ensure!(
            self.passed,
            "fault checker failed for scenario {} run {}: {}",
            self.scenario,
            self.run_id,
            serde_json::to_string_pretty(self)?
        );
        Ok(())
    }
}

pub async fn check_s3_history(
    s3: &S3WorkloadClient,
    recorder: &Recorder,
    tenant_recovered: bool,
    concurrency: usize,
    expect_versioning: bool,
) -> Result<CheckerReport> {
    let initial_records = recorder.records();
    let model = object_model(&initial_records);
    let read_anomalies = successful_read_anomalies(&initial_records);
    let list_history_warnings = list_history_warnings(&initial_records);
    let version_lineage = if expect_versioning {
        Some(committed_version_lineage(&initial_records))
    } else {
        None
    };
    let mut report = CheckerReport {
        scenario: recorder.scenario(),
        run_id: recorder.run_id(),
        committed_puts: model.committed_writes,
        expected_live_objects: model.live.len(),
        verified_live_objects: 0,
        missing_committed_objects: Vec::new(),
        unavailable_committed_objects: Vec::new(),
        unknown_committed_read_failures: Vec::new(),
        hash_mismatches: Vec::new(),
        successful_corrupted_reads: read_anomalies.corrupted_reads,
        unexpected_visible_deleted_objects: read_anomalies.visible_deleted_objects,
        unknown_writes_materialized: read_anomalies.unknown_writes_materialized,
        unknown_writes_preserved_committed: Vec::new(),
        unknown_write_value_conflicts: read_anomalies.unknown_write_value_conflicts,
        list_history_warning_count: list_history_warnings.total_count,
        final_list_warning_count: 0,
        list_history_warnings: list_history_warnings.samples,
        list_warnings: Vec::new(),
        final_listed_objects: None,
        versioning_expected: expect_versioning,
        expected_committed_versions: 0,
        verified_committed_versions: 0,
        committed_writes_missing_version_id_count: 0,
        committed_writes_missing_version_id: Vec::new(),
        missing_committed_versions: Vec::new(),
        unavailable_committed_versions: Vec::new(),
        version_hash_mismatches: Vec::new(),
        missing_committed_delete_markers: Vec::new(),
        resurrected_deleted_objects: Vec::new(),
        tolerated_ambiguous_deletes: Vec::new(),
        operation_cohorts: operation_cohort_counts(&initial_records),
        fault_window_relations: fault_window_relation_counts(&initial_records),
        tenant_recovered,
        passed: false,
    };

    let final_keys = model
        .live
        .keys()
        .chain(model.unknown_writes.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut final_results = stream::iter(final_keys.into_iter().map(|key| {
        let s3 = s3.clone();
        let recorder = recorder.clone();
        let expected = model.live.get(&key).cloned();
        let unknown_writes = model.unknown_writes.get(&key).cloned().unwrap_or_default();
        async move {
            let get = s3.get_object_result(&key, &recorder).await?;
            Ok::<_, anyhow::Error>((key, expected, unknown_writes, get))
        }
    }))
    .buffer_unordered(concurrency);
    while let Some(result) = final_results.next().await {
        let (key, expected, unknown_writes, get) = result?;
        if expected.is_some()
            && unknown_writes.is_empty()
            && get.outcome == OperationOutcome::NotFound
            && model.ambiguous_delete_pending.contains(&key)
        {
            // The committed object had a later ambiguous (timeout/unknown)
            // delete; a 404 means that delete took effect, which is a
            // legitimate outcome, not a lost committed object.
            report.tolerated_ambiguous_deletes.push(key);
            continue;
        }
        evaluate_final_get(&mut report, key, expected.as_ref(), &unknown_writes, get);
    }

    // Committed deletes are otherwise never re-read: the final GET loop probes
    // only live and ambiguous-write keys, so a deleted key that still serves a
    // body on the GET path (but stays absent from LIST) would pass. Probe the
    // deleted keys that carry no ambiguous write — a materialized ambiguous
    // write on a deleted key is a legitimate outcome already handled above.
    let deleted_probe_keys = model
        .deleted
        .iter()
        .filter(|key| !model.unknown_writes.contains_key(*key))
        .cloned()
        .collect::<Vec<_>>();
    let mut deleted_results = stream::iter(deleted_probe_keys.into_iter().map(|key| {
        let s3 = s3.clone();
        let recorder = recorder.clone();
        async move {
            let get = s3.get_object_result(&key, &recorder).await?;
            Ok::<_, anyhow::Error>((key, get))
        }
    }))
    .buffer_unordered(concurrency);
    while let Some(result) = deleted_results.next().await {
        let (key, get) = result?;
        if let Some(message) = evaluate_deleted_reread(&key, &get) {
            report.resurrected_deleted_objects.push(message);
        }
    }

    let run_id = recorder.run_id();
    let prefix = ObjectSpec::key_prefix(&run_id);

    if let Some(lineage) = version_lineage {
        report.expected_committed_versions = lineage.versions.len();
        report.committed_writes_missing_version_id_count = lineage.missing_version_id_count;
        report.committed_writes_missing_version_id = lineage.missing_version_id_samples.clone();

        let mut version_results = stream::iter(lineage.versions.iter().cloned().map(|version| {
            let s3 = s3.clone();
            let recorder = recorder.clone();
            async move {
                let get = s3
                    .get_object_version_result(&version.key, &version.version_id, &recorder)
                    .await?;
                Ok::<_, anyhow::Error>((version, get))
            }
        }))
        .buffer_unordered(concurrency);
        while let Some(result) = version_results.next().await {
            let (version, get) = result?;
            evaluate_committed_version_get(&mut report, &version, get);
        }

        match s3.list_object_versions(&prefix, recorder).await? {
            Some(entries) => {
                report.missing_committed_delete_markers =
                    missing_committed_delete_markers(&lineage.delete_markers, &entries);
                report.resurrected_deleted_objects =
                    resurrected_deleted_objects(&model.deleted, &latest_version_entries(&entries));
                let (materialized, conflicts) = materialized_ambiguous_versions(
                    s3,
                    recorder,
                    &model,
                    &lineage,
                    &entries,
                    concurrency,
                )
                .await?;
                report.unknown_writes_materialized.extend(materialized);
                report.unknown_write_value_conflicts.extend(conflicts);
            }
            None => report.unavailable_committed_versions.push(format!(
                "list_object_versions prefix {prefix} did not complete"
            )),
        }
    }

    let mut final_list_warnings = WarningSummary::default();
    match s3.list_prefix(&prefix, recorder).await? {
        Some(keys) => {
            report.final_listed_objects = Some(keys.len());
            let listed = keys.into_iter().collect::<BTreeSet<_>>();
            for key in model.live.keys() {
                if !listed.contains(key) {
                    final_list_warnings.push(format!(
                        "LIST prefix {prefix} did not include expected live key {key}"
                    ));
                }
            }
            for key in model.deleted {
                if listed.contains(&key) {
                    final_list_warnings
                        .push(format!("LIST prefix {prefix} included deleted key {key}"));
                }
            }
        }
        None => final_list_warnings.push(format!("LIST prefix {prefix} did not complete")),
    }
    report.final_list_warning_count = final_list_warnings.total_count;
    report.list_warnings = final_list_warnings.samples;

    report.missing_committed_objects.sort();
    report.unavailable_committed_objects.sort();
    report.unknown_committed_read_failures.sort();
    report.hash_mismatches.sort();
    sort_dedup(&mut report.unknown_writes_materialized);
    sort_dedup(&mut report.unknown_writes_preserved_committed);
    sort_dedup(&mut report.unknown_write_value_conflicts);
    report.unexpected_visible_deleted_objects.sort();
    report.list_history_warnings.sort();
    report.list_warnings.sort();
    report.committed_writes_missing_version_id.sort();
    report.missing_committed_versions.sort();
    report.unavailable_committed_versions.sort();
    report.version_hash_mismatches.sort();
    report.missing_committed_delete_markers.sort();
    report.resurrected_deleted_objects.sort();
    report.tolerated_ambiguous_deletes.sort();
    report.passed = report.tenant_recovered
        && report.missing_committed_objects.is_empty()
        && report.unavailable_committed_objects.is_empty()
        && report.unknown_committed_read_failures.is_empty()
        && report.hash_mismatches.is_empty()
        && report.successful_corrupted_reads.is_empty()
        && report.unexpected_visible_deleted_objects.is_empty()
        && report.unknown_writes_materialized.is_empty()
        && report.unknown_write_value_conflicts.is_empty()
        && report.final_list_warning_count == 0
        && report.committed_writes_missing_version_id_count == 0
        && report.missing_committed_versions.is_empty()
        && report.unavailable_committed_versions.is_empty()
        && report.version_hash_mismatches.is_empty()
        && report.missing_committed_delete_markers.is_empty()
        && report.resurrected_deleted_objects.is_empty();

    Ok(report)
}

pub async fn recovery_stability_reread(
    s3: &S3WorkloadClient,
    recorder: &Recorder,
    immediate_report: &CheckerReport,
    immediate_record_start: usize,
    concurrency: usize,
    max_recovery: Duration,
) -> Result<RecoveryStabilityReport> {
    let records = recorder.records();
    let model = object_model(&records[..immediate_record_start.min(records.len())]);
    let immediate_records = records
        .get(immediate_record_start.min(records.len())..)
        .unwrap_or_default();
    let attempted_keys = recovery_tail_candidate_keys(immediate_records, &model);
    let mut hash_mismatches = immediate_report.hash_mismatches.clone();
    hash_mismatches.extend(immediate_report.successful_corrupted_reads.iter().cloned());
    let data_corruption_evidence = immediate_data_corruption_evidence(immediate_report);
    let ambiguous_write_evidence = immediate_ambiguous_write_evidence(immediate_report);
    let mut report = RecoveryStabilityReport {
        immediate_passed: immediate_report.passed,
        reread_attempted_keys: attempted_keys.clone(),
        reread_recovered_keys: Vec::new(),
        still_unavailable_keys: immediate_still_unavailable_keys(immediate_report, &attempted_keys),
        hash_mismatches,
        data_corruption_evidence,
        ambiguous_write_evidence,
        final_list_warning_count: immediate_report.final_list_warning_count,
        list_warnings: immediate_report.list_warnings.clone(),
        harness_errors: Vec::new(),
        max_recovery_seconds: max_recovery.as_secs(),
        recovered_within_seconds: None,
        classification: classify_without_reread(immediate_report),
    };

    if immediate_report.passed || attempted_keys.is_empty() || max_recovery.is_zero() {
        finish_recovery_stability_report(&mut report, immediate_report);
        return Ok(report);
    }

    let expected = attempted_keys
        .iter()
        .filter_map(|key| {
            let expected = model.live.get(key).cloned()?;
            let ambiguous_writes = model.unknown_writes.get(key).cloned().unwrap_or_default();
            Some((key.clone(), (expected, ambiguous_writes)))
        })
        .collect::<BTreeMap<_, _>>();
    let mut pending = expected.keys().cloned().collect::<BTreeSet<_>>();
    let started = Instant::now();
    let deadline = Instant::now() + max_recovery;
    let mut delay = Duration::from_secs(1);
    let concurrency = concurrency.max(1);

    'retry: while !pending.is_empty() && report.hash_mismatches.is_empty() {
        if Instant::now() >= deadline {
            break;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        async_sleep(delay.min(remaining)).await;
        delay = delay.saturating_mul(2);
        if Instant::now() >= deadline {
            break;
        }
        let pending_keys = pending.iter().cloned().collect::<Vec<_>>();
        let mut batch = stream::iter(pending_keys.into_iter().map(|key| {
            let s3 = s3.clone();
            let recorder = recorder.clone();
            let (expected, ambiguous_writes) = expected.get(&key).expect("pending key").clone();
            async move {
                let get = s3.get_object_result(&key, &recorder).await;
                (key, expected, ambiguous_writes, get)
            }
        }))
        .buffer_unordered(concurrency);

        while let Some((key, expected, ambiguous_writes, get)) = {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break 'retry;
            }
            match timeout(remaining, batch.next()).await {
                Ok(item) => item,
                Err(_) => break 'retry,
            }
        } {
            match get {
                Ok(get) => evaluate_recovery_reread_get(
                    &mut report,
                    &mut pending,
                    key,
                    &expected,
                    &ambiguous_writes,
                    get,
                ),
                Err(error) => {
                    report.still_unavailable_keys.push(key);
                    report.classification = RecoveryStabilityClassification::HarnessError;
                    report
                        .harness_errors
                        .push(format!("reread failed: {error}"));
                    pending.clear();
                    break;
                }
            }
        }

        if pending.is_empty() && report.recovered_within_seconds.is_none() {
            report.recovered_within_seconds = Some(started.elapsed().as_secs());
        }
        if pending.is_empty() || !report.hash_mismatches.is_empty() {
            break;
        }
        if Instant::now() >= deadline {
            break;
        }
    }

    report.still_unavailable_keys.extend(pending);
    report.reread_recovered_keys.sort();
    report.still_unavailable_keys.sort();
    sort_dedup(&mut report.hash_mismatches);
    sort_dedup(&mut report.data_corruption_evidence);
    sort_dedup(&mut report.ambiguous_write_evidence);
    sort_dedup(&mut report.list_warnings);
    sort_dedup(&mut report.harness_errors);
    finish_recovery_stability_report(&mut report, immediate_report);
    Ok(report)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExpectedObject {
    sha256: String,
    size_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AmbiguousWriteAttempt {
    id: String,
    kind: OperationKind,
    outcome: OperationOutcome,
    object: ExpectedObject,
    started_at_ms: u64,
    ended_at_ms: u64,
    superseded_by: Option<SupersedingMutation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SupersedingMutation {
    id: String,
    kind: OperationKind,
    started_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AmbiguousVersionCandidate {
    key: String,
    version_id: String,
    attempts: Vec<AmbiguousWriteAttempt>,
}

#[derive(Debug, Default)]
struct ObjectModel {
    live: BTreeMap<String, ExpectedObject>,
    deleted: BTreeSet<String>,
    unknown_writes: BTreeMap<String, Vec<AmbiguousWriteAttempt>>,
    // Keys still committed-present whose latest delete was ambiguous
    // (timeout/unknown): the object may or may not have been removed, so a
    // post-recovery 404 is a legitimate outcome rather than a lost object.
    ambiguous_delete_pending: BTreeSet<String>,
    committed_writes: usize,
}

#[derive(Debug, Default)]
struct ReadAnomalies {
    corrupted_reads: Vec<String>,
    visible_deleted_objects: Vec<String>,
    unknown_writes_materialized: Vec<String>,
    unknown_write_value_conflicts: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CommittedVersion {
    key: String,
    version_id: String,
    sha256: String,
    size_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CommittedDeleteMarker {
    key: String,
    version_id: String,
}

#[derive(Debug, Default)]
struct VersionLineage {
    versions: Vec<CommittedVersion>,
    delete_markers: Vec<CommittedDeleteMarker>,
    missing_version_id_count: usize,
    missing_version_id_samples: Vec<String>,
}

fn committed_version_lineage(records: &[OperationRecord]) -> VersionLineage {
    let mut lineage = VersionLineage::default();
    for record in records {
        let is_committed_write = matches!(
            record.kind,
            OperationKind::Put | OperationKind::CompleteMultipartUpload
        ) && record.outcome == OperationOutcome::Ok;
        let is_committed_delete =
            record.kind == OperationKind::Delete && record.outcome == OperationOutcome::Ok;
        if !is_committed_write && !is_committed_delete {
            continue;
        }
        let Some(key) = record.key.as_ref() else {
            continue;
        };
        match record.version_id.as_ref() {
            Some(version_id) if is_committed_write => {
                let Some((_, expected)) = record_object(record) else {
                    continue;
                };
                lineage.versions.push(CommittedVersion {
                    key: key.clone(),
                    version_id: version_id.clone(),
                    sha256: expected.sha256,
                    size_bytes: expected.size_bytes,
                });
            }
            Some(version_id) if is_committed_delete => {
                lineage.delete_markers.push(CommittedDeleteMarker {
                    key: key.clone(),
                    version_id: version_id.clone(),
                });
            }
            Some(_) => {}
            None => {
                lineage.missing_version_id_count += 1;
                if lineage.missing_version_id_samples.len() < MAX_WARNING_SAMPLES {
                    lineage.missing_version_id_samples.push(format!(
                        "{}: committed {:?} response omitted x-amz-version-id for {key}",
                        record.id, record.kind
                    ));
                }
            }
        }
    }
    lineage
}

fn evaluate_committed_version_get(
    report: &mut CheckerReport,
    version: &CommittedVersion,
    get: GetObjectResult,
) {
    let reference = format!("{}@{}", version.key, version.version_id);
    match (get.outcome, get.body) {
        (OperationOutcome::Ok, Some(body)) => {
            let actual_hash = sha256_hex(&body);
            if actual_hash != version.sha256 || body.len() != version.size_bytes {
                report.version_hash_mismatches.push(format!(
                    "{reference}: expected {} ({} bytes), got {actual_hash} ({} bytes)",
                    version.sha256,
                    version.size_bytes,
                    body.len()
                ));
            } else {
                report.verified_committed_versions += 1;
            }
        }
        (OperationOutcome::NotFound, None) => {
            report.missing_committed_versions.push(reference);
        }
        (outcome, body) => report
            .unavailable_committed_versions
            .push(read_failure_message(
                &reference,
                outcome,
                get.http_status,
                get.error
                    .as_deref()
                    .or(body.is_some().then_some("unexpected body")),
            )),
    }
}

fn latest_version_entries(entries: &[ObjectVersionEntry]) -> BTreeMap<String, ObjectVersionEntry> {
    let mut latest = BTreeMap::new();
    for entry in entries {
        if entry.is_latest {
            latest.insert(entry.key.clone(), entry.clone());
        }
    }
    latest
}

fn resurrected_deleted_objects(
    deleted: &BTreeSet<String>,
    latest: &BTreeMap<String, ObjectVersionEntry>,
) -> Vec<String> {
    deleted
        .iter()
        .filter_map(|key| match latest.get(key) {
            Some(entry) if !entry.is_delete_marker => Some(format!(
                "{key}: latest version is not a delete marker after committed delete"
            )),
            None => Some(format!(
                "{key}: no latest version entry after committed delete"
            )),
            _ => None,
        })
        .collect()
}

fn missing_committed_delete_markers(
    committed: &[CommittedDeleteMarker],
    entries: &[ObjectVersionEntry],
) -> Vec<String> {
    let present = entries
        .iter()
        .filter(|entry| entry.is_delete_marker)
        .filter_map(|entry| Some((entry.key.clone(), entry.version_id.clone()?)))
        .collect::<BTreeSet<_>>();
    committed
        .iter()
        .filter(|marker| !present.contains(&(marker.key.clone(), marker.version_id.clone())))
        .map(|marker| {
            format!(
                "{}@{}: committed delete marker missing from ListObjectVersions",
                marker.key, marker.version_id
            )
        })
        .collect()
}

fn ambiguous_version_candidates(
    model: &ObjectModel,
    lineage: &VersionLineage,
    entries: &[ObjectVersionEntry],
) -> (Vec<AmbiguousVersionCandidate>, Vec<String>) {
    let committed_versions = lineage
        .versions
        .iter()
        .map(|version| (version.key.as_str(), version.version_id.as_str()))
        .collect::<BTreeSet<_>>();
    let mut candidates = Vec::new();
    let mut conflicts = Vec::new();

    for entry in entries.iter().filter(|entry| !entry.is_delete_marker) {
        let attempts = model
            .unknown_writes
            .get(&entry.key)
            .cloned()
            .unwrap_or_default();
        let Some(version_id) = entry.version_id.as_ref() else {
            conflicts.push(uncommitted_version_missing_id_message(
                &entry.key, &attempts,
            ));
            continue;
        };
        if committed_versions.contains(&(entry.key.as_str(), version_id.as_str())) {
            continue;
        }
        candidates.push(AmbiguousVersionCandidate {
            key: entry.key.clone(),
            version_id: version_id.clone(),
            attempts,
        });
    }

    (candidates, conflicts)
}

async fn materialized_ambiguous_versions(
    s3: &S3WorkloadClient,
    recorder: &Recorder,
    model: &ObjectModel,
    lineage: &VersionLineage,
    entries: &[ObjectVersionEntry],
    concurrency: usize,
) -> Result<(Vec<String>, Vec<String>)> {
    let (candidates, mut conflicts) = ambiguous_version_candidates(model, lineage, entries);
    let mut materialized = Vec::new();
    let mut results = stream::iter(candidates.into_iter().map(|candidate| {
        let s3 = s3.clone();
        let recorder = recorder.clone();
        async move {
            let get = s3
                .get_object_version_result(&candidate.key, &candidate.version_id, &recorder)
                .await?;
            Ok::<_, anyhow::Error>((candidate, get))
        }
    }))
    .buffer_unordered(concurrency.max(1));

    while let Some(result) = results.next().await {
        let (candidate, get) = result?;
        evaluate_ambiguous_version_get(&mut materialized, &mut conflicts, &candidate, get);
    }
    Ok((materialized, conflicts))
}

fn evaluate_ambiguous_version_get(
    materialized: &mut Vec<String>,
    conflicts: &mut Vec<String>,
    candidate: &AmbiguousVersionCandidate,
    get: GetObjectResult,
) {
    let Some(body) = get.body.as_deref() else {
        conflicts.push(uncommitted_version_unverified_message(candidate, &get));
        return;
    };
    if get.outcome != OperationOutcome::Ok {
        conflicts.push(uncommitted_version_unverified_message(candidate, &get));
        return;
    }
    if let Some(attempt) = matching_ambiguous_write(&candidate.attempts, body) {
        materialized.push(ambiguous_version_materialized_message(
            &candidate.key,
            &candidate.version_id,
            attempt,
            body,
        ));
        return;
    }
    conflicts.push(uncommitted_version_value_conflict_message(candidate, body));
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct WarningSummary {
    total_count: usize,
    samples: Vec<String>,
}

impl WarningSummary {
    fn push(&mut self, warning: String) {
        self.total_count += 1;
        if self.samples.len() < MAX_WARNING_SAMPLES {
            self.samples.push(warning);
        }
    }
}

fn sort_dedup(values: &mut Vec<String>) {
    values.sort();
    values.dedup();
}

#[cfg(test)]
fn evaluate_committed_get(
    report: &mut CheckerReport,
    key: String,
    expected: &ExpectedObject,
    get: GetObjectResult,
) {
    evaluate_final_get(report, key, Some(expected), &[], get);
}

fn evaluate_final_get(
    report: &mut CheckerReport,
    key: String,
    expected: Option<&ExpectedObject>,
    ambiguous_writes: &[AmbiguousWriteAttempt],
    get: GetObjectResult,
) {
    match (get.outcome, get.body) {
        (OperationOutcome::Ok, Some(body)) => {
            if expected.is_some_and(|expected| object_matches(expected, &body)) {
                report.verified_live_objects += 1;
                record_preserved_committed(report, &key, expected, ambiguous_writes, &body);
                return;
            }
            if let Some(attempt) = matching_active_ambiguous_write(ambiguous_writes, &body) {
                report
                    .unknown_writes_materialized
                    .push(ambiguous_write_materialized_message(&key, attempt, &body));
                return;
            }
            if let Some(attempt) = matching_superseded_ambiguous_write(ambiguous_writes, &body) {
                report
                    .unknown_writes_materialized
                    .push(ambiguous_write_materialized_message(&key, attempt, &body));
                report.unknown_write_value_conflicts.push(
                    superseded_ambiguous_write_conflict_message(&key, expected, attempt, &body),
                );
                return;
            }
            if !ambiguous_writes.is_empty() {
                report
                    .unknown_write_value_conflicts
                    .push(unknown_write_value_conflict_message(
                        &key,
                        expected,
                        ambiguous_writes,
                        &body,
                    ));
            } else if let Some(expected) = expected {
                report
                    .hash_mismatches
                    .push(hash_mismatch_message(&key, expected, &body));
            }
        }
        (OperationOutcome::NotFound, None) if expected.is_some() => {
            report.missing_committed_objects.push(key)
        }
        (OperationOutcome::Failed | OperationOutcome::Timeout, None) if expected.is_some() => {
            report
                .unavailable_committed_objects
                .push(read_failure_message(
                    &key,
                    get.outcome,
                    get.http_status,
                    get.error.as_deref(),
                ))
        }
        (OperationOutcome::Unknown | OperationOutcome::Ok, None) if expected.is_some() => report
            .unknown_committed_read_failures
            .push(read_failure_message(
                &key,
                get.outcome,
                get.http_status,
                get.error.as_deref(),
            )),
        (outcome, Some(body)) if expected.is_some() => {
            report.unknown_committed_read_failures.push(format!(
                "{}: unexpected body for {:?} ({} bytes)",
                key,
                outcome,
                body.len()
            ))
        }
        _ => {}
    }
}

/// A committed delete (latest committed op for the key was a successful Delete)
/// must not serve a body after recovery. A direct GET that returns one is a
/// resurrection; the correct outcome is not-found, and an unavailable probe
/// response (timeout/error) is not evidence of resurrection either.
fn evaluate_deleted_reread(key: &str, get: &GetObjectResult) -> Option<String> {
    match (get.outcome, get.body.as_deref()) {
        (OperationOutcome::Ok, Some(body)) => Some(format!(
            "{key}: committed delete resurrected on GET ({} bytes)",
            body.len()
        )),
        _ => None,
    }
}

fn evaluate_recovery_reread_get(
    report: &mut RecoveryStabilityReport,
    pending: &mut BTreeSet<String>,
    key: String,
    expected: &ExpectedObject,
    ambiguous_writes: &[AmbiguousWriteAttempt],
    get: GetObjectResult,
) {
    if committed_get_matches(expected, &get) {
        pending.remove(&key);
        report.reread_recovered_keys.push(key);
        return;
    }
    let Some(body) = get.body else {
        return;
    };
    if let Some(attempt) = matching_active_ambiguous_write(ambiguous_writes, &body) {
        pending.remove(&key);
        report
            .ambiguous_write_evidence
            .push(ambiguous_write_materialized_message(&key, attempt, &body));
        return;
    }
    if let Some(attempt) = matching_superseded_ambiguous_write(ambiguous_writes, &body) {
        pending.remove(&key);
        report
            .ambiguous_write_evidence
            .push(ambiguous_write_materialized_message(&key, attempt, &body));
        report.data_corruption_evidence.push(format!(
            "unknown_write_value_conflict: {}",
            superseded_ambiguous_write_conflict_message(&key, Some(expected), attempt, &body)
        ));
        return;
    }
    report
        .hash_mismatches
        .push(hash_mismatch_message(&key, expected, &body));
    pending.remove(&key);
}

fn read_failure_message(
    key: &str,
    outcome: OperationOutcome,
    http_status: Option<u16>,
    error: Option<&str>,
) -> String {
    let status = http_status
        .map(|status| format!(" status={status}"))
        .unwrap_or_default();
    let error = error
        .map(|error| format!(" error={error:?}"))
        .unwrap_or_default();
    format!("{key}: outcome={outcome:?}{status}{error}")
}

fn recovery_tail_candidate_keys(
    immediate_records: &[OperationRecord],
    model: &ObjectModel,
) -> Vec<String> {
    immediate_records
        .iter()
        .filter_map(|record| {
            let key = record.key.as_ref()?;
            (record.kind == OperationKind::Get
                && record.version_id.is_none()
                && model.live.contains_key(key)
                && is_recovery_tail_read_failure(
                    record.outcome,
                    record.http_status,
                    record.error.as_deref(),
                ))
            .then(|| key.clone())
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn is_recovery_tail_read_failure(
    outcome: OperationOutcome,
    http_status: Option<u16>,
    error: Option<&str>,
) -> bool {
    if !matches!(
        outcome,
        OperationOutcome::Timeout | OperationOutcome::Unknown
    ) {
        return false;
    }
    let Some(error) = error else {
        return false;
    };
    let error = error.to_ascii_lowercase();
    if http_status == Some(200) {
        return error.contains("body read timed out")
            || error.contains("body read timeout")
            || error.contains("streaming error");
    }
    http_status.is_none()
        && (error.contains("get object timed out") || error.contains("request timed out"))
}

fn committed_get_matches(expected: &ExpectedObject, get: &GetObjectResult) -> bool {
    get.outcome == OperationOutcome::Ok
        && get
            .body
            .as_deref()
            .is_some_and(|body| object_matches(expected, body))
}

fn object_matches(expected: &ExpectedObject, body: &[u8]) -> bool {
    body.len() == expected.size_bytes && sha256_hex(body) == expected.sha256
}

fn hash_mismatch_message(key: &str, expected: &ExpectedObject, body: &[u8]) -> String {
    let actual_hash = sha256_hex(body);
    format!(
        "{key}: expected {} ({} bytes), got {actual_hash} ({} bytes)",
        expected.sha256,
        expected.size_bytes,
        body.len()
    )
}

fn matching_ambiguous_write<'a>(
    attempts: &'a [AmbiguousWriteAttempt],
    body: &[u8],
) -> Option<&'a AmbiguousWriteAttempt> {
    attempts
        .iter()
        .rev()
        .find(|attempt| object_matches(&attempt.object, body))
}

fn matching_active_ambiguous_write<'a>(
    attempts: &'a [AmbiguousWriteAttempt],
    body: &[u8],
) -> Option<&'a AmbiguousWriteAttempt> {
    attempts
        .iter()
        .rev()
        .filter(|attempt| attempt.superseded_by.is_none())
        .find(|attempt| object_matches(&attempt.object, body))
}

fn matching_superseded_ambiguous_write<'a>(
    attempts: &'a [AmbiguousWriteAttempt],
    body: &[u8],
) -> Option<&'a AmbiguousWriteAttempt> {
    attempts
        .iter()
        .rev()
        .filter(|attempt| attempt.superseded_by.is_some())
        .find(|attempt| object_matches(&attempt.object, body))
}

fn matching_active_ambiguous_object<'a>(
    attempts: &'a [AmbiguousWriteAttempt],
    actual: &ExpectedObject,
) -> Option<&'a AmbiguousWriteAttempt> {
    attempts
        .iter()
        .rev()
        .filter(|attempt| attempt.superseded_by.is_none())
        .find(|attempt| attempt.object == *actual)
}

fn matching_superseded_ambiguous_object<'a>(
    attempts: &'a [AmbiguousWriteAttempt],
    actual: &ExpectedObject,
) -> Option<&'a AmbiguousWriteAttempt> {
    attempts
        .iter()
        .rev()
        .filter(|attempt| attempt.superseded_by.is_some())
        .find(|attempt| attempt.object == *actual)
}

fn record_preserved_committed(
    report: &mut CheckerReport,
    key: &str,
    expected: Option<&ExpectedObject>,
    attempts: &[AmbiguousWriteAttempt],
    body: &[u8],
) {
    let Some(expected) = expected else {
        return;
    };
    if attempts.is_empty() {
        return;
    }
    let actual_hash = sha256_hex(body);
    if actual_hash != expected.sha256 || body.len() != expected.size_bytes {
        report
            .unknown_write_value_conflicts
            .push(unknown_write_value_conflict_message(
                key,
                Some(expected),
                attempts,
                body,
            ));
        return;
    }
    let materially_distinct_attempt = attempts.iter().any(|attempt| {
        attempt.object.sha256 != expected.sha256 || attempt.object.size_bytes != expected.size_bytes
    });
    if materially_distinct_attempt {
        let attempts = ambiguous_write_attempt_summary(attempts);
        report.unknown_writes_preserved_committed.push(format!(
            "{key}: observed committed {} ({} bytes) after ambiguous attempts [{attempts}]",
            expected.sha256, expected.size_bytes
        ));
    }
}

fn ambiguous_write_materialized_message(
    key: &str,
    attempt: &AmbiguousWriteAttempt,
    body: &[u8],
) -> String {
    format!(
        "{key}: {} materialized as {} ({} bytes)",
        ambiguous_write_attempt_label(attempt),
        sha256_hex(body),
        body.len()
    )
}

fn ambiguous_write_materialized_from_object_message(
    key: &str,
    attempt: &AmbiguousWriteAttempt,
    actual: &ExpectedObject,
) -> String {
    format!(
        "{key}: {} materialized as {} ({} bytes)",
        ambiguous_write_attempt_label(attempt),
        actual.sha256,
        actual.size_bytes
    )
}

fn ambiguous_version_materialized_message(
    key: &str,
    version_id: &str,
    attempt: &AmbiguousWriteAttempt,
    body: &[u8],
) -> String {
    format!(
        "{key}@{version_id}: {} materialized as version {} ({} bytes)",
        ambiguous_write_attempt_label(attempt),
        sha256_hex(body),
        body.len()
    )
}

fn uncommitted_version_missing_id_message(key: &str, attempts: &[AmbiguousWriteAttempt]) -> String {
    let attempts = ambiguous_write_attempt_summary(attempts);
    format!(
        "{key}: uncommitted non-delete version from ListObjectVersions did not include a version id; ambiguous attempts [{attempts}]"
    )
}

fn uncommitted_version_unverified_message(
    candidate: &AmbiguousVersionCandidate,
    get: &GetObjectResult,
) -> String {
    let attempts = ambiguous_write_attempt_summary(&candidate.attempts);
    format!(
        "{}@{}: uncommitted version could not be verified; outcome={:?} status={:?} error={:?}; ambiguous attempts [{attempts}]",
        candidate.key, candidate.version_id, get.outcome, get.http_status, get.error
    )
}

fn uncommitted_version_value_conflict_message(
    candidate: &AmbiguousVersionCandidate,
    body: &[u8],
) -> String {
    let attempts = ambiguous_write_attempt_summary(&candidate.attempts);
    format!(
        "{}@{}: observed uncommitted version {} ({} bytes), but it matched no ambiguous attempt [{}]",
        candidate.key,
        candidate.version_id,
        sha256_hex(body),
        body.len(),
        attempts
    )
}

fn unknown_write_value_conflict_message(
    key: &str,
    expected: Option<&ExpectedObject>,
    attempts: &[AmbiguousWriteAttempt],
    body: &[u8],
) -> String {
    let committed = expected
        .map(|expected| {
            format!(
                "committed {} ({} bytes)",
                expected.sha256, expected.size_bytes
            )
        })
        .unwrap_or_else(|| "no committed object".to_string());
    let attempts = ambiguous_write_attempt_summary(attempts);
    format!(
        "{key}: observed {} ({} bytes), expected {committed} or ambiguous attempts [{attempts}]",
        sha256_hex(body),
        body.len()
    )
}

fn superseded_ambiguous_write_conflict_message(
    key: &str,
    expected: Option<&ExpectedObject>,
    attempt: &AmbiguousWriteAttempt,
    body: &[u8],
) -> String {
    let committed = expected
        .map(|expected| {
            format!(
                "committed {} ({} bytes)",
                expected.sha256, expected.size_bytes
            )
        })
        .unwrap_or_else(|| "no committed object".to_string());
    format!(
        "{key}: observed {} ({} bytes) from superseded ambiguous attempt [{}], expected {committed}",
        sha256_hex(body),
        body.len(),
        ambiguous_write_attempt_label(attempt)
    )
}

fn unknown_write_value_conflict_from_object_message(
    key: &str,
    expected: Option<&ExpectedObject>,
    attempts: &[AmbiguousWriteAttempt],
    actual: &ExpectedObject,
) -> String {
    let committed = expected
        .map(|expected| {
            format!(
                "committed {} ({} bytes)",
                expected.sha256, expected.size_bytes
            )
        })
        .unwrap_or_else(|| "no committed object".to_string());
    let attempts = ambiguous_write_attempt_summary(attempts);
    format!(
        "{key}: observed {} ({} bytes), expected {committed} or ambiguous attempts [{attempts}]",
        actual.sha256, actual.size_bytes
    )
}

fn superseded_ambiguous_object_conflict_message(
    key: &str,
    expected: Option<&ExpectedObject>,
    attempt: &AmbiguousWriteAttempt,
    actual: &ExpectedObject,
) -> String {
    let committed = expected
        .map(|expected| {
            format!(
                "committed {} ({} bytes)",
                expected.sha256, expected.size_bytes
            )
        })
        .unwrap_or_else(|| "no committed object".to_string());
    format!(
        "{key}: observed {} ({} bytes) from superseded ambiguous attempt [{}], expected {committed}",
        actual.sha256,
        actual.size_bytes,
        ambiguous_write_attempt_label(attempt)
    )
}

fn ambiguous_write_attempt_summary(attempts: &[AmbiguousWriteAttempt]) -> String {
    if attempts.is_empty() {
        return "none".to_string();
    }
    attempts
        .iter()
        .map(ambiguous_write_attempt_label)
        .collect::<Vec<_>>()
        .join(", ")
}

fn ambiguous_write_attempt_label(attempt: &AmbiguousWriteAttempt) -> String {
    let mut label = format!(
        "{} {:?} {:?} {} ({} bytes)",
        attempt.id, attempt.kind, attempt.outcome, attempt.object.sha256, attempt.object.size_bytes
    );
    if let Some(superseded_by) = &attempt.superseded_by {
        label.push_str(&format!(
            " superseded_by={} {:?} started_at_ms={}",
            superseded_by.id, superseded_by.kind, superseded_by.started_at_ms
        ));
    }
    label
}

fn classify_without_reread(report: &CheckerReport) -> RecoveryStabilityClassification {
    if has_data_corruption_signal(report) {
        RecoveryStabilityClassification::DataCorruption
    } else if !report.unknown_writes_materialized.is_empty() {
        RecoveryStabilityClassification::AmbiguousWriteMaterialized
    } else if has_committed_unavailable_signal(report) {
        RecoveryStabilityClassification::CommittedObjectUnavailable
    } else if has_list_unavailable_or_unknown_signal(report) {
        RecoveryStabilityClassification::ListUnavailableOrUnknown
    } else {
        RecoveryStabilityClassification::HarnessError
    }
}

fn has_data_corruption_signal(report: &CheckerReport) -> bool {
    !report.hash_mismatches.is_empty()
        || !report.successful_corrupted_reads.is_empty()
        || !report.unexpected_visible_deleted_objects.is_empty()
        || !report.unknown_write_value_conflicts.is_empty()
        || final_list_content_corruption_signal(report)
        || !report.version_hash_mismatches.is_empty()
        || !report.missing_committed_versions.is_empty()
        || !report.missing_committed_delete_markers.is_empty()
        || !report.resurrected_deleted_objects.is_empty()
        || report.committed_writes_missing_version_id_count > 0
}

fn final_list_content_corruption_signal(report: &CheckerReport) -> bool {
    report.list_warnings.iter().any(|warning| {
        warning.contains("did not include expected live key")
            || warning.contains("included deleted key")
    })
}

fn has_committed_unavailable_signal(report: &CheckerReport) -> bool {
    !report.missing_committed_objects.is_empty()
        || !report.unavailable_committed_objects.is_empty()
        || !report.unknown_committed_read_failures.is_empty()
        || !report.unavailable_committed_versions.is_empty()
}

fn has_list_unavailable_or_unknown_signal(report: &CheckerReport) -> bool {
    report.final_list_warning_count > 0 && !final_list_content_corruption_signal(report)
}

fn operation_cohort_counts(records: &[OperationRecord]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for cohort in records.iter().filter_map(|record| record.durability_cohort) {
        *counts.entry(cohort.as_str().to_string()).or_insert(0) += 1;
    }
    counts
}

fn fault_window_relation_counts(records: &[OperationRecord]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for relation in records
        .iter()
        .filter_map(|record| record.fault_window_relation)
    {
        *counts.entry(relation.as_str().to_string()).or_insert(0) += 1;
    }
    counts
}

fn immediate_data_corruption_evidence(report: &CheckerReport) -> Vec<String> {
    let mut evidence = Vec::new();
    evidence.extend(
        report
            .unexpected_visible_deleted_objects
            .iter()
            .map(|item| format!("unexpected_visible_deleted_object: {item}")),
    );
    evidence.extend(
        report
            .unknown_write_value_conflicts
            .iter()
            .map(|item| format!("unknown_write_value_conflict: {item}")),
    );
    evidence.extend(
        report
            .version_hash_mismatches
            .iter()
            .map(|item| format!("version_hash_mismatch: {item}")),
    );
    evidence.extend(
        report
            .missing_committed_versions
            .iter()
            .map(|item| format!("missing_committed_version: {item}")),
    );
    evidence.extend(
        report
            .missing_committed_delete_markers
            .iter()
            .map(|item| format!("missing_committed_delete_marker: {item}")),
    );
    evidence.extend(
        report
            .resurrected_deleted_objects
            .iter()
            .map(|item| format!("resurrected_deleted_object: {item}")),
    );
    evidence.extend(
        report
            .committed_writes_missing_version_id
            .iter()
            .map(|item| format!("committed_write_missing_version_id: {item}")),
    );
    if report.committed_writes_missing_version_id_count
        > report.committed_writes_missing_version_id.len()
    {
        evidence.push(format!(
            "committed_writes_missing_version_id_count: {} total, {} sampled",
            report.committed_writes_missing_version_id_count,
            report.committed_writes_missing_version_id.len()
        ));
    }
    let corruption_list_warnings = report
        .list_warnings
        .iter()
        .filter(|item| {
            item.contains("did not include expected live key")
                || item.contains("included deleted key")
        })
        .map(|item| format!("final_list_warning: {item}"))
        .collect::<Vec<_>>();
    let corruption_list_warning_count = corruption_list_warnings.len();
    evidence.extend(corruption_list_warnings);
    if final_list_content_corruption_signal(report)
        && report.final_list_warning_count > corruption_list_warning_count
    {
        evidence.push(format!(
            "final_list_content_warning_count: {} total, {} sampled",
            report.final_list_warning_count, corruption_list_warning_count
        ));
    }
    evidence.sort();
    evidence
}

fn immediate_ambiguous_write_evidence(report: &CheckerReport) -> Vec<String> {
    let mut evidence = report
        .unknown_writes_materialized
        .iter()
        .map(|item| format!("ambiguous_write_materialized: {item}"))
        .collect::<Vec<_>>();
    evidence.sort();
    evidence
}

fn immediate_still_unavailable_keys(
    report: &CheckerReport,
    reread_attempted_keys: &[String],
) -> Vec<String> {
    let attempted = reread_attempted_keys
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut keys = report
        .missing_committed_objects
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    for failure in report
        .unavailable_committed_objects
        .iter()
        .chain(report.unknown_committed_read_failures.iter())
    {
        let key = read_failure_key(failure);
        if !attempted.contains(key.as_str()) {
            keys.insert(key);
        }
    }
    keys.extend(
        report
            .unavailable_committed_versions
            .iter()
            .map(|item| format!("version:{item}")),
    );
    keys.into_iter().collect()
}

fn read_failure_key(message: &str) -> String {
    message
        .split_once(':')
        .map(|(key, _)| key)
        .unwrap_or(message)
        .to_string()
}

fn finish_recovery_stability_report(
    report: &mut RecoveryStabilityReport,
    immediate_report: &CheckerReport,
) {
    if !report.hash_mismatches.is_empty() || !report.data_corruption_evidence.is_empty() {
        report.classification = RecoveryStabilityClassification::DataCorruption;
        return;
    }
    if !report.harness_errors.is_empty() {
        report.classification = RecoveryStabilityClassification::HarnessError;
        return;
    }
    if !report.still_unavailable_keys.is_empty() {
        report.classification = RecoveryStabilityClassification::CommittedObjectUnavailable;
        return;
    }
    if !report.ambiguous_write_evidence.is_empty() {
        report.classification = RecoveryStabilityClassification::AmbiguousWriteMaterialized;
        return;
    }
    if has_list_unavailable_or_unknown_signal(immediate_report) {
        report.classification = RecoveryStabilityClassification::ListUnavailableOrUnknown;
        return;
    }
    if !report.reread_attempted_keys.is_empty()
        && immediate_failures_are_only_reread_candidates(immediate_report, report)
    {
        report.classification = RecoveryStabilityClassification::RecoveryTailReadLatency;
        return;
    }
    report.classification = classify_without_reread(immediate_report);
}

fn immediate_failures_are_only_reread_candidates(
    immediate_report: &CheckerReport,
    recovery_report: &RecoveryStabilityReport,
) -> bool {
    immediate_report.tenant_recovered
        && immediate_report.missing_committed_objects.is_empty()
        && immediate_report.hash_mismatches.is_empty()
        && immediate_report.successful_corrupted_reads.is_empty()
        && immediate_report
            .unexpected_visible_deleted_objects
            .is_empty()
        && immediate_report.unknown_writes_materialized.is_empty()
        && immediate_report.unknown_write_value_conflicts.is_empty()
        && immediate_report.final_list_warning_count == 0
        && immediate_report.committed_writes_missing_version_id_count == 0
        && immediate_report.missing_committed_versions.is_empty()
        && immediate_report.unavailable_committed_versions.is_empty()
        && immediate_report.version_hash_mismatches.is_empty()
        && immediate_report.missing_committed_delete_markers.is_empty()
        && immediate_report.resurrected_deleted_objects.is_empty()
        && immediate_report.unavailable_committed_objects.len()
            + immediate_report.unknown_committed_read_failures.len()
            == recovery_report.reread_attempted_keys.len()
        && recovery_report.reread_recovered_keys.len()
            == recovery_report.reread_attempted_keys.len()
}

fn object_model(records: &[OperationRecord]) -> ObjectModel {
    let mut model = ObjectModel::default();
    for record in records {
        apply_record_to_model(&mut model, record);
    }
    model
}

fn object_model_before(records: &[OperationRecord], started_at_ms: u64) -> ObjectModel {
    let mut model = ObjectModel::default();
    for record in records {
        if record.ended_at_ms < started_at_ms {
            apply_record_to_model(&mut model, record);
        }
    }
    model
}

fn apply_record_to_model(model: &mut ObjectModel, record: &OperationRecord) {
    match record.kind {
        OperationKind::Put | OperationKind::CompleteMultipartUpload
            if record.outcome == OperationOutcome::Ok =>
        {
            if let Some((key, object)) = record_object(record) {
                mark_superseded_ambiguous_writes(model, &key, record);
                model.committed_writes += 1;
                model.deleted.remove(&key);
                model.ambiguous_delete_pending.remove(&key);
                model.live.insert(key, object);
            }
        }
        OperationKind::Put | OperationKind::CompleteMultipartUpload
            if matches!(
                record.outcome,
                OperationOutcome::Timeout | OperationOutcome::Unknown
            ) =>
        {
            if let Some((key, object)) = record_object(record) {
                model
                    .unknown_writes
                    .entry(key)
                    .or_default()
                    .push(AmbiguousWriteAttempt {
                        id: record.id.clone(),
                        kind: record.kind,
                        outcome: record.outcome,
                        object,
                        started_at_ms: record.started_at_ms,
                        ended_at_ms: record.ended_at_ms,
                        superseded_by: None,
                    });
            }
        }
        OperationKind::Delete if record.outcome == OperationOutcome::Ok => {
            if let Some(key) = record.key.clone() {
                mark_superseded_ambiguous_writes(model, &key, record);
                model.ambiguous_delete_pending.remove(&key);
                model.live.remove(&key);
                model.deleted.insert(key);
            }
        }
        OperationKind::Delete
            if matches!(
                record.outcome,
                OperationOutcome::Timeout | OperationOutcome::Unknown
            ) =>
        {
            // An ambiguous delete of a committed object may or may not have
            // taken effect; mark it so a post-recovery 404 is tolerated instead
            // of being reported as a lost committed object.
            if let Some(key) = record.key.clone()
                && model.live.contains_key(&key)
            {
                model.ambiguous_delete_pending.insert(key);
            }
        }
        _ => {}
    }
}

fn mark_superseded_ambiguous_writes(
    model: &mut ObjectModel,
    key: &str,
    superseding_record: &OperationRecord,
) {
    mark_superseded_attempts(&mut model.unknown_writes, key, superseding_record);
}

fn mark_superseded_attempts(
    attempts_by_key: &mut BTreeMap<String, Vec<AmbiguousWriteAttempt>>,
    key: &str,
    superseding_record: &OperationRecord,
) {
    let Some(attempts) = attempts_by_key.get_mut(key) else {
        return;
    };
    for attempt in attempts {
        if attempt.superseded_by.is_none()
            && superseding_record.started_at_ms >= attempt.ended_at_ms
        {
            attempt.superseded_by = Some(SupersedingMutation {
                id: superseding_record.id.clone(),
                kind: superseding_record.kind,
                started_at_ms: superseding_record.started_at_ms,
            });
        }
    }
}

fn list_history_warnings(records: &[OperationRecord]) -> WarningSummary {
    let mut warnings = WarningSummary::default();
    for record in records.iter().filter(|record| {
        record.kind == OperationKind::List && record.outcome == OperationOutcome::Ok
    }) {
        let Some(prefix) = record.key.as_deref() else {
            continue;
        };
        let Some(listed_keys) = record.listed_keys.as_ref() else {
            warnings.push(format!("LIST {} did not record returned keys", record.id));
            continue;
        };
        let listed = listed_keys
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let stable = object_model_before(records, record.started_at_ms);
        for key in stable.live.keys().filter(|key| key.starts_with(prefix)) {
            if !listed.contains(key.as_str()) {
                warnings.push(format!(
                    "LIST {} prefix {prefix} did not include stable live key {key}",
                    record.id
                ));
            }
        }
        for key in stable.deleted.iter().filter(|key| key.starts_with(prefix)) {
            if listed.contains(key.as_str()) {
                warnings.push(format!(
                    "LIST {} prefix {prefix} included stable deleted key {key}",
                    record.id
                ));
            }
        }
    }
    warnings
}

fn successful_read_anomalies(records: &[OperationRecord]) -> ReadAnomalies {
    let mut live = BTreeMap::<String, ExpectedObject>::new();
    let mut ambiguous_writes = BTreeMap::<String, Vec<AmbiguousWriteAttempt>>::new();
    let mut anomalies = ReadAnomalies::default();
    for record in records {
        match record.kind {
            OperationKind::Put | OperationKind::CompleteMultipartUpload
                if record.outcome == OperationOutcome::Ok =>
            {
                if let Some((key, object)) = record_object(record) {
                    mark_superseded_attempts(&mut ambiguous_writes, &key, record);
                    live.insert(key, object);
                }
            }
            OperationKind::Put | OperationKind::CompleteMultipartUpload
                if matches!(
                    record.outcome,
                    OperationOutcome::Timeout | OperationOutcome::Unknown
                ) =>
            {
                if let Some((key, object)) = record_object(record) {
                    ambiguous_writes
                        .entry(key)
                        .or_default()
                        .push(AmbiguousWriteAttempt {
                            id: record.id.clone(),
                            kind: record.kind,
                            outcome: record.outcome,
                            object,
                            started_at_ms: record.started_at_ms,
                            ended_at_ms: record.ended_at_ms,
                            superseded_by: None,
                        });
                }
            }
            OperationKind::Delete if record.outcome == OperationOutcome::Ok => {
                if let Some(key) = record.key.as_ref() {
                    mark_superseded_attempts(&mut ambiguous_writes, key, record);
                    live.remove(key);
                }
            }
            OperationKind::Get if record.outcome == OperationOutcome::Ok => {
                // Versioned GETs intentionally read historical versions whose
                // hashes differ from the latest committed value; they are
                // verified against their own lineage entry instead.
                if record.version_id.is_some() {
                    continue;
                }
                let Some(key) = record.key.as_ref() else {
                    continue;
                };
                let actual_hash = record.value_sha256.as_deref().unwrap_or_default();
                let actual = ExpectedObject {
                    sha256: actual_hash.to_string(),
                    size_bytes: record.size_bytes.unwrap_or_default(),
                };
                let attempts = ambiguous_writes
                    .get(key)
                    .map(Vec::as_slice)
                    .unwrap_or_default();
                match live.get(key) {
                    Some(expected)
                        if expected.sha256 == actual.sha256
                            && expected.size_bytes == actual.size_bytes => {}
                    _ if matching_active_ambiguous_object(attempts, &actual).is_some() => {
                        let attempt = matching_active_ambiguous_object(attempts, &actual)
                            .expect("checked ambiguous object");
                        anomalies.unknown_writes_materialized.push(
                            ambiguous_write_materialized_from_object_message(key, attempt, &actual),
                        );
                    }
                    _ if matching_superseded_ambiguous_object(attempts, &actual).is_some() => {
                        let attempt = matching_superseded_ambiguous_object(attempts, &actual)
                            .expect("checked superseded ambiguous object");
                        anomalies.unknown_writes_materialized.push(
                            ambiguous_write_materialized_from_object_message(key, attempt, &actual),
                        );
                        anomalies.unknown_write_value_conflicts.push(
                            superseded_ambiguous_object_conflict_message(
                                key,
                                live.get(key),
                                attempt,
                                &actual,
                            ),
                        );
                    }
                    Some(expected) if !attempts.is_empty() => {
                        anomalies.unknown_write_value_conflicts.push(
                            unknown_write_value_conflict_from_object_message(
                                key,
                                Some(expected),
                                attempts,
                                &actual,
                            ),
                        );
                    }
                    Some(expected) => {
                        anomalies.corrupted_reads.push(format!(
                            "{key}: expected {} ({} bytes), got {} ({} bytes)",
                            expected.sha256, expected.size_bytes, actual.sha256, actual.size_bytes
                        ));
                    }
                    None if !attempts.is_empty() => anomalies.unknown_write_value_conflicts.push(
                        unknown_write_value_conflict_from_object_message(
                            key, None, attempts, &actual,
                        ),
                    ),
                    None => anomalies
                        .visible_deleted_objects
                        .push(format!("{key}: successful GET had no committed live value")),
                }
            }
            _ => {}
        }
    }
    anomalies
}

fn record_object(record: &OperationRecord) -> Option<(String, ExpectedObject)> {
    Some((
        record.key.clone()?,
        ExpectedObject {
            sha256: record.value_sha256.clone()?,
            size_bytes: record.size_bytes?,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        AmbiguousWriteAttempt, CheckerReport, ExpectedObject, RecoveryStabilityClassification,
        RecoveryStabilityReport, WarningSummary, evaluate_committed_get, evaluate_final_get,
        evaluate_recovery_reread_get, finish_recovery_stability_report,
        immediate_still_unavailable_keys, is_recovery_tail_read_failure, list_history_warnings,
        object_model, recovery_tail_candidate_keys, successful_read_anomalies,
    };
    use crate::fault::history::{OperationKind, OperationOutcome, OperationRecord};
    use crate::fault::workload::{GetObjectResult, sha256_hex};
    use std::collections::{BTreeMap, BTreeSet};

    fn record(
        id: &str,
        kind: OperationKind,
        key: &str,
        hash: &str,
        outcome: OperationOutcome,
    ) -> OperationRecord {
        OperationRecord {
            id: id.to_string(),
            scenario: "io-eio".to_string(),
            kind,
            bucket: "bucket".to_string(),
            key: Some(key.to_string()),
            value_sha256: Some(hash.to_string()),
            size_bytes: Some(1),
            version_id: None,
            started_at_ms: 1,
            ended_at_ms: 2,
            outcome,
            http_status: Some(200),
            error: None,
            listed_keys: None,
            durability_cohort: None,
            fault_window_relation: None,
        }
    }

    fn timed_record(
        id: &str,
        kind: OperationKind,
        key: &str,
        hash: &str,
        outcome: OperationOutcome,
        started_at_ms: u64,
        ended_at_ms: u64,
    ) -> OperationRecord {
        OperationRecord {
            started_at_ms,
            ended_at_ms,
            ..record(id, kind, key, hash, outcome)
        }
    }

    fn list_record(
        id: &str,
        prefix: &str,
        started_at_ms: u64,
        ended_at_ms: u64,
        keys: &[&str],
    ) -> OperationRecord {
        OperationRecord {
            id: id.to_string(),
            scenario: "io-eio".to_string(),
            kind: OperationKind::List,
            bucket: "bucket".to_string(),
            key: Some(prefix.to_string()),
            value_sha256: None,
            size_bytes: Some(keys.len()),
            version_id: None,
            listed_keys: Some(keys.iter().map(|key| key.to_string()).collect()),
            started_at_ms,
            ended_at_ms,
            outcome: OperationOutcome::Ok,
            http_status: Some(200),
            error: None,
            durability_cohort: None,
            fault_window_relation: None,
        }
    }

    fn ambiguous_attempt(id: &str, hash: &str) -> AmbiguousWriteAttempt {
        AmbiguousWriteAttempt {
            id: id.to_string(),
            kind: OperationKind::Put,
            outcome: OperationOutcome::Timeout,
            object: ExpectedObject {
                sha256: hash.to_string(),
                size_bytes: 1,
            },
            started_at_ms: 1,
            ended_at_ms: 2,
            superseded_by: None,
        }
    }

    #[test]
    fn corrupted_successful_get_is_hard_failure_input() {
        let records = vec![
            record(
                "op-1",
                OperationKind::Put,
                "k",
                "good",
                OperationOutcome::Ok,
            ),
            record("op-2", OperationKind::Get, "k", "bad", OperationOutcome::Ok),
        ];

        let anomalies = successful_read_anomalies(&records);

        assert_eq!(
            anomalies.corrupted_reads,
            vec!["k: expected good (1 bytes), got bad (1 bytes)"]
        );
    }

    #[test]
    fn object_model_tracks_overwrite_delete_and_multipart_complete() {
        let records = vec![
            record("op-1", OperationKind::Put, "k1", "v1", OperationOutcome::Ok),
            record("op-2", OperationKind::Put, "k1", "v2", OperationOutcome::Ok),
            record("op-3", OperationKind::Put, "k2", "v1", OperationOutcome::Ok),
            record(
                "op-4",
                OperationKind::Delete,
                "k2",
                "",
                OperationOutcome::Ok,
            ),
            record(
                "op-5",
                OperationKind::CompleteMultipartUpload,
                "k3",
                "mp",
                OperationOutcome::Ok,
            ),
        ];

        let model = object_model(&records);

        assert_eq!(model.committed_writes, 4);
        assert_eq!(model.live.get("k1").expect("k1").sha256, "v2");
        assert!(!model.live.contains_key("k2"));
        assert_eq!(model.live.get("k3").expect("k3").sha256, "mp");
        assert!(model.deleted.contains("k2"));
    }

    #[test]
    fn ambiguous_delete_marks_committed_key_pending() {
        let model = object_model(&[
            record("op-1", OperationKind::Put, "k", "v1", OperationOutcome::Ok),
            record(
                "op-2",
                OperationKind::Delete,
                "k",
                "",
                OperationOutcome::Timeout,
            ),
        ]);

        // The object is still committed-present, but the ambiguous delete makes
        // a post-recovery 404 a legitimate outcome.
        assert!(model.live.contains_key("k"));
        assert!(model.ambiguous_delete_pending.contains("k"));
    }

    #[test]
    fn recommit_clears_ambiguous_delete_pending() {
        let model = object_model(&[
            record("op-1", OperationKind::Put, "k", "v1", OperationOutcome::Ok),
            record(
                "op-2",
                OperationKind::Delete,
                "k",
                "",
                OperationOutcome::Unknown,
            ),
            record("op-3", OperationKind::Put, "k", "v2", OperationOutcome::Ok),
        ]);

        // A fresh committed write supersedes the ambiguous delete: the key is
        // definitively present again, so a 404 would be a real failure.
        assert!(model.live.contains_key("k"));
        assert!(!model.ambiguous_delete_pending.contains("k"));
    }

    #[test]
    fn committed_delete_clears_ambiguous_delete_pending() {
        let model = object_model(&[
            record("op-1", OperationKind::Put, "k", "v1", OperationOutcome::Ok),
            record(
                "op-2",
                OperationKind::Delete,
                "k",
                "",
                OperationOutcome::Timeout,
            ),
            record("op-3", OperationKind::Delete, "k", "", OperationOutcome::Ok),
        ]);

        // The delete became definitive; the key is deleted (handled by the
        // resurrection probe) and no longer pending-ambiguous.
        assert!(model.deleted.contains("k"));
        assert!(!model.live.contains_key("k"));
        assert!(!model.ambiguous_delete_pending.contains("k"));
    }

    #[test]
    fn ambiguous_delete_of_uncommitted_key_is_not_pending() {
        // A delete with no prior committed write leaves nothing to lose.
        let model = object_model(&[record(
            "op-1",
            OperationKind::Delete,
            "k",
            "",
            OperationOutcome::Timeout,
        )]);

        assert!(model.ambiguous_delete_pending.is_empty());
    }

    #[test]
    fn list_history_checks_stable_keys_and_ignores_overlapping_changes() {
        let records = vec![
            OperationRecord {
                started_at_ms: 1,
                ended_at_ms: 2,
                ..record(
                    "op-1",
                    OperationKind::Put,
                    "fault-test/run-1/stable",
                    "v1",
                    OperationOutcome::Ok,
                )
            },
            OperationRecord {
                started_at_ms: 4,
                ended_at_ms: 7,
                ..record(
                    "op-2",
                    OperationKind::Put,
                    "fault-test/run-1/overlap",
                    "v2",
                    OperationOutcome::Ok,
                )
            },
            list_record("op-3", "fault-test/run-1/", 5, 6, &[]),
        ];

        let warnings = list_history_warnings(&records);

        assert_eq!(warnings.total_count, 1);
        assert_eq!(
            warnings.samples,
            vec![
                "LIST op-3 prefix fault-test/run-1/ did not include stable live key fault-test/run-1/stable"
            ]
        );
        assert!(
            !warnings
                .samples
                .iter()
                .any(|warning| warning.contains("overlap"))
        );
    }

    #[test]
    fn committed_get_timeout_is_unavailable_not_missing() {
        let mut report = empty_report();
        let expected = ExpectedObject {
            sha256: "sha".to_string(),
            size_bytes: 1,
        };

        evaluate_committed_get(
            &mut report,
            "k".to_string(),
            &expected,
            GetObjectResult {
                outcome: OperationOutcome::Timeout,
                http_status: Some(200),
                error: Some("get body read timed out".to_string()),
                body: None,
            },
        );

        assert!(report.missing_committed_objects.is_empty());
        assert_eq!(
            report.unavailable_committed_objects,
            vec!["k: outcome=Timeout status=200 error=\"get body read timed out\""]
        );
    }

    #[test]
    fn ambiguous_overwrite_preserving_committed_value_is_not_materialized() {
        let mut report = empty_report();
        let committed = ExpectedObject {
            sha256: sha256_hex(b"a"),
            size_bytes: 1,
        };
        let attempted = ambiguous_attempt("op-2", &sha256_hex(b"b"));

        evaluate_final_get(
            &mut report,
            "k".to_string(),
            Some(&committed),
            &[attempted],
            GetObjectResult {
                outcome: OperationOutcome::Ok,
                http_status: Some(200),
                error: None,
                body: Some(b"a".to_vec()),
            },
        );

        assert_eq!(report.verified_live_objects, 1);
        assert!(report.hash_mismatches.is_empty());
        assert!(report.unknown_writes_materialized.is_empty());
        assert_eq!(report.unknown_writes_preserved_committed.len(), 1);
    }

    #[test]
    fn ambiguous_overwrite_materializing_is_not_committed_hash_mismatch() {
        let mut report = empty_report();
        let committed = ExpectedObject {
            sha256: sha256_hex(b"a"),
            size_bytes: 1,
        };
        let attempted = ambiguous_attempt("op-2", &sha256_hex(b"b"));

        evaluate_final_get(
            &mut report,
            "k".to_string(),
            Some(&committed),
            &[attempted],
            GetObjectResult {
                outcome: OperationOutcome::Ok,
                http_status: Some(200),
                error: None,
                body: Some(b"b".to_vec()),
            },
        );

        assert!(report.hash_mismatches.is_empty());
        assert_eq!(report.unknown_writes_materialized.len(), 1);
        assert_eq!(
            super::classify_without_reread(&report),
            RecoveryStabilityClassification::AmbiguousWriteMaterialized
        );
    }

    #[test]
    fn superseded_ambiguous_final_get_is_data_corruption_evidence() {
        let mut report = empty_report();
        let committed = ExpectedObject {
            sha256: sha256_hex(b"a"),
            size_bytes: 1,
        };
        let mut attempted = ambiguous_attempt("op-2", &sha256_hex(b"b"));
        attempted.superseded_by = Some(super::SupersedingMutation {
            id: "op-3".to_string(),
            kind: OperationKind::Put,
            started_at_ms: 3,
        });

        evaluate_final_get(
            &mut report,
            "k".to_string(),
            Some(&committed),
            &[attempted],
            GetObjectResult {
                outcome: OperationOutcome::Ok,
                http_status: Some(200),
                error: None,
                body: Some(b"b".to_vec()),
            },
        );

        assert!(report.hash_mismatches.is_empty());
        assert_eq!(report.unknown_writes_materialized.len(), 1);
        assert_eq!(report.unknown_write_value_conflicts.len(), 1);
        assert_eq!(
            super::classify_without_reread(&report),
            RecoveryStabilityClassification::DataCorruption
        );
    }

    #[test]
    fn ambiguous_overwrite_unrelated_value_is_data_corruption_evidence() {
        let mut report = empty_report();
        let committed = ExpectedObject {
            sha256: sha256_hex(b"a"),
            size_bytes: 1,
        };
        let attempted = ambiguous_attempt("op-2", &sha256_hex(b"b"));

        evaluate_final_get(
            &mut report,
            "k".to_string(),
            Some(&committed),
            &[attempted],
            GetObjectResult {
                outcome: OperationOutcome::Ok,
                http_status: Some(200),
                error: None,
                body: Some(b"c".to_vec()),
            },
        );

        assert!(report.hash_mismatches.is_empty());
        assert_eq!(report.unknown_write_value_conflicts.len(), 1);
        assert_eq!(
            super::classify_without_reread(&report),
            RecoveryStabilityClassification::DataCorruption
        );
    }

    #[test]
    fn successful_get_after_timeout_overwrite_is_ambiguous_not_corrupt() {
        let records = vec![
            record("op-1", OperationKind::Put, "k", "old", OperationOutcome::Ok),
            record(
                "op-2",
                OperationKind::Put,
                "k",
                "new",
                OperationOutcome::Timeout,
            ),
            record("op-3", OperationKind::Get, "k", "new", OperationOutcome::Ok),
        ];

        let anomalies = successful_read_anomalies(&records);

        assert!(anomalies.corrupted_reads.is_empty());
        assert_eq!(anomalies.unknown_writes_materialized.len(), 1);
    }

    #[test]
    fn later_non_overlapping_ok_write_makes_old_ambiguous_value_a_conflict() {
        let records = vec![
            timed_record(
                "op-1",
                OperationKind::Put,
                "k",
                "old",
                OperationOutcome::Ok,
                1,
                2,
            ),
            timed_record(
                "op-2",
                OperationKind::Put,
                "k",
                "timeout",
                OperationOutcome::Timeout,
                3,
                4,
            ),
            timed_record(
                "op-3",
                OperationKind::Put,
                "k",
                "new",
                OperationOutcome::Ok,
                5,
                6,
            ),
            timed_record(
                "op-4",
                OperationKind::Get,
                "k",
                "timeout",
                OperationOutcome::Ok,
                7,
                8,
            ),
        ];

        let model = object_model(&records);
        let anomalies = successful_read_anomalies(&records);

        assert_eq!(model.live.get("k").expect("live").sha256, "new");
        let attempt = model
            .unknown_writes
            .get("k")
            .expect("ambiguous")
            .first()
            .expect("attempt");
        assert_eq!(
            attempt.superseded_by.as_ref().expect("superseded").id,
            "op-3"
        );
        assert!(anomalies.corrupted_reads.is_empty());
        assert_eq!(anomalies.unknown_writes_materialized.len(), 1);
        assert_eq!(anomalies.unknown_write_value_conflicts.len(), 1);
        assert!(
            anomalies.unknown_write_value_conflicts[0].contains("superseded ambiguous attempt")
        );
    }

    #[test]
    fn recovery_reread_materialized_ambiguous_write_is_not_hash_mismatch() {
        let mut recovery = recovery_report_with_attempted_key("k");
        let mut pending = BTreeSet::from(["k".to_string()]);
        let committed = ExpectedObject {
            sha256: sha256_hex(b"a"),
            size_bytes: 1,
        };
        let attempted = ambiguous_attempt("op-2", &sha256_hex(b"b"));

        evaluate_recovery_reread_get(
            &mut recovery,
            &mut pending,
            "k".to_string(),
            &committed,
            &[attempted],
            GetObjectResult {
                outcome: OperationOutcome::Ok,
                http_status: Some(200),
                error: None,
                body: Some(b"b".to_vec()),
            },
        );

        assert!(pending.is_empty());
        assert!(recovery.hash_mismatches.is_empty());
        assert_eq!(recovery.ambiguous_write_evidence.len(), 1);
    }

    #[test]
    fn recovery_reread_superseded_ambiguous_write_is_correctness_evidence() {
        let mut recovery = recovery_report_with_attempted_key("k");
        let mut pending = BTreeSet::from(["k".to_string()]);
        let committed = ExpectedObject {
            sha256: sha256_hex(b"a"),
            size_bytes: 1,
        };
        let mut attempted = ambiguous_attempt("op-2", &sha256_hex(b"b"));
        attempted.superseded_by = Some(super::SupersedingMutation {
            id: "op-3".to_string(),
            kind: OperationKind::Put,
            started_at_ms: 3,
        });

        evaluate_recovery_reread_get(
            &mut recovery,
            &mut pending,
            "k".to_string(),
            &committed,
            &[attempted],
            GetObjectResult {
                outcome: OperationOutcome::Ok,
                http_status: Some(200),
                error: None,
                body: Some(b"b".to_vec()),
            },
        );
        finish_recovery_stability_report(&mut recovery, &empty_report());

        assert!(pending.is_empty());
        assert_eq!(recovery.ambiguous_write_evidence.len(), 1);
        assert_eq!(recovery.data_corruption_evidence.len(), 1);
        assert_eq!(
            recovery.classification,
            RecoveryStabilityClassification::DataCorruption
        );
        assert_eq!(
            recovery.evidence_classifications(),
            vec![
                "ambiguous_write_materialized".to_string(),
                "data_corruption".to_string()
            ]
        );
    }

    #[test]
    fn recovery_tail_candidates_include_body_tail_and_request_timeouts() {
        let put = record("op-1", OperationKind::Put, "k", "sha", OperationOutcome::Ok);
        let model = object_model(&[put]);
        let eligible_timeout = OperationRecord {
            kind: OperationKind::Get,
            outcome: OperationOutcome::Timeout,
            http_status: Some(200),
            error: Some("get body read timed out".to_string()),
            ..record(
                "op-2",
                OperationKind::Get,
                "k",
                "",
                OperationOutcome::Timeout,
            )
        };
        let eligible_streaming = OperationRecord {
            kind: OperationKind::Get,
            outcome: OperationOutcome::Unknown,
            http_status: Some(200),
            error: Some("get body read failed: streaming error".to_string()),
            ..record(
                "op-3",
                OperationKind::Get,
                "k",
                "",
                OperationOutcome::Unknown,
            )
        };
        let request_timeout = OperationRecord {
            kind: OperationKind::Get,
            outcome: OperationOutcome::Timeout,
            http_status: None,
            error: Some("get object timed out".to_string()),
            ..record(
                "op-4",
                OperationKind::Get,
                "k",
                "",
                OperationOutcome::Timeout,
            )
        };
        let other_error = OperationRecord {
            kind: OperationKind::Get,
            outcome: OperationOutcome::Unknown,
            http_status: Some(200),
            error: Some("unexpected EOF".to_string()),
            ..record(
                "op-5",
                OperationKind::Get,
                "k",
                "",
                OperationOutcome::Unknown,
            )
        };

        assert!(is_recovery_tail_read_failure(
            eligible_timeout.outcome,
            eligible_timeout.http_status,
            eligible_timeout.error.as_deref()
        ));
        assert!(is_recovery_tail_read_failure(
            request_timeout.outcome,
            request_timeout.http_status,
            request_timeout.error.as_deref()
        ));
        let keys = recovery_tail_candidate_keys(
            &[
                eligible_timeout,
                eligible_streaming,
                request_timeout,
                other_error,
            ],
            &model,
        );

        assert_eq!(keys, vec!["k"]);
    }

    #[test]
    fn recovery_stability_report_classifies_tail_latency_only_when_all_candidates_recover() {
        let mut immediate = empty_report();
        immediate
            .unavailable_committed_objects
            .push("k: outcome=Timeout status=200 error=\"get body read timed out\"".to_string());
        let mut recovery = recovery_report_with_attempted_key("k");
        recovery.reread_recovered_keys.push("k".to_string());

        finish_recovery_stability_report(&mut recovery, &immediate);

        assert_eq!(
            recovery.classification,
            RecoveryStabilityClassification::RecoveryTailReadLatency
        );
    }

    #[test]
    fn recovery_evidence_classifications_preserve_tail_latency_with_ambiguous_evidence() {
        let mut recovery = recovery_report_with_attempted_key("k");
        recovery.reread_recovered_keys.push("k".to_string());
        recovery
            .ambiguous_write_evidence
            .push("ambiguous_write_materialized: other op-2".to_string());
        recovery.classification = RecoveryStabilityClassification::AmbiguousWriteMaterialized;

        assert_eq!(
            recovery.evidence_classifications(),
            vec![
                "ambiguous_write_materialized".to_string(),
                "recovery_tail_read_latency".to_string()
            ]
        );
    }

    #[test]
    fn recovery_stability_report_keeps_unavailable_and_corrupt_classifications_hard() {
        let mut immediate = empty_report();
        immediate
            .unavailable_committed_objects
            .push("k: outcome=Timeout status=200 error=\"get body read timed out\"".to_string());
        let mut unavailable = recovery_report_with_attempted_key("k");
        unavailable.still_unavailable_keys.push("k".to_string());
        finish_recovery_stability_report(&mut unavailable, &immediate);
        assert_eq!(
            unavailable.classification,
            RecoveryStabilityClassification::CommittedObjectUnavailable
        );

        let mut corrupt = recovery_report_with_attempted_key("k");
        corrupt.reread_recovered_keys.push("k".to_string());
        corrupt
            .hash_mismatches
            .push("k: expected sha (1 bytes), got bad (1 bytes)".to_string());
        finish_recovery_stability_report(&mut corrupt, &immediate);
        assert_eq!(
            corrupt.classification,
            RecoveryStabilityClassification::DataCorruption
        );
    }

    #[test]
    fn recovery_stability_hard_version_signals_override_ambiguous_writes() {
        let mut immediate_corrupt = empty_report();
        immediate_corrupt
            .unknown_writes_materialized
            .push("k: op-2 materialized".to_string());
        immediate_corrupt
            .version_hash_mismatches
            .push("k@v1: expected old, got new".to_string());
        let mut corrupt = recovery_report_with_attempted_key("k");
        corrupt.ambiguous_write_evidence =
            super::immediate_ambiguous_write_evidence(&immediate_corrupt);
        corrupt.data_corruption_evidence =
            super::immediate_data_corruption_evidence(&immediate_corrupt);
        finish_recovery_stability_report(&mut corrupt, &immediate_corrupt);
        assert_eq!(
            corrupt.classification,
            RecoveryStabilityClassification::DataCorruption
        );

        let mut immediate_unavailable = empty_report();
        immediate_unavailable
            .unknown_writes_materialized
            .push("k: op-2 materialized".to_string());
        immediate_unavailable
            .unavailable_committed_versions
            .push("k@v1: outcome=Timeout".to_string());
        let keys = immediate_still_unavailable_keys(&immediate_unavailable, &[]);
        let mut unavailable = recovery_report_with_attempted_key("k");
        unavailable.ambiguous_write_evidence =
            super::immediate_ambiguous_write_evidence(&immediate_unavailable);
        unavailable.still_unavailable_keys = keys;
        finish_recovery_stability_report(&mut unavailable, &immediate_unavailable);
        assert_eq!(
            unavailable.classification,
            RecoveryStabilityClassification::CommittedObjectUnavailable
        );
    }

    #[test]
    fn recovery_stability_keeps_list_timeout_distinct_from_data_corruption() {
        let mut final_list_warning = empty_report();
        final_list_warning.final_list_warning_count = 1;
        final_list_warning
            .list_warnings
            .push("LIST prefix fault-test/ did not complete".to_string());
        assert_eq!(
            super::classify_without_reread(&final_list_warning),
            RecoveryStabilityClassification::ListUnavailableOrUnknown
        );
        assert!(super::immediate_data_corruption_evidence(&final_list_warning).is_empty());

        let mut history_list_warning = empty_report();
        history_list_warning.list_history_warning_count = 1;
        history_list_warning
            .list_history_warnings
            .push("LIST op-1 warning during workload".to_string());
        assert_eq!(
            super::classify_without_reread(&history_list_warning),
            RecoveryStabilityClassification::HarnessError
        );

        let mut final_list_content_warning = empty_report();
        final_list_content_warning.final_list_warning_count = 1;
        final_list_content_warning
            .list_warnings
            .push("LIST prefix did not include expected live key k".to_string());
        assert_eq!(
            super::classify_without_reread(&final_list_content_warning),
            RecoveryStabilityClassification::DataCorruption
        );
        assert_eq!(
            super::immediate_data_corruption_evidence(&final_list_content_warning),
            vec!["final_list_warning: LIST prefix did not include expected live key k"]
        );

        let mut visible_deleted = empty_report();
        visible_deleted
            .unexpected_visible_deleted_objects
            .push("k: deleted object returned body".to_string());
        assert_eq!(
            super::classify_without_reread(&visible_deleted),
            RecoveryStabilityClassification::DataCorruption
        );
        assert_eq!(
            super::immediate_data_corruption_evidence(&visible_deleted),
            vec!["unexpected_visible_deleted_object: k: deleted object returned body"]
        );
    }

    #[test]
    fn recovery_stability_keeps_non_candidate_immediate_failures_unavailable() {
        let mut immediate = empty_report();
        immediate
            .unavailable_committed_objects
            .push("k: outcome=Timeout error=\"get object timed out\"".to_string());
        let keys = immediate_still_unavailable_keys(&immediate, &[]);
        let mut recovery = RecoveryStabilityReport {
            immediate_passed: false,
            reread_attempted_keys: Vec::new(),
            reread_recovered_keys: Vec::new(),
            still_unavailable_keys: keys,
            hash_mismatches: Vec::new(),
            data_corruption_evidence: Vec::new(),
            ambiguous_write_evidence: Vec::new(),
            final_list_warning_count: 0,
            list_warnings: Vec::new(),
            harness_errors: Vec::new(),
            max_recovery_seconds: 60,
            recovered_within_seconds: None,
            classification: RecoveryStabilityClassification::HarnessError,
        };

        finish_recovery_stability_report(&mut recovery, &immediate);

        assert_eq!(recovery.still_unavailable_keys, vec!["k"]);
        assert_eq!(
            recovery.classification,
            RecoveryStabilityClassification::CommittedObjectUnavailable
        );
    }

    #[test]
    fn committed_version_lineage_collects_versions_and_flags_missing_ids() {
        let mut versioned_put =
            record("op-1", OperationKind::Put, "k1", "v1", OperationOutcome::Ok);
        versioned_put.version_id = Some("ver-1".to_string());
        let mut versioned_multipart = record(
            "op-2",
            OperationKind::CompleteMultipartUpload,
            "k2",
            "v2",
            OperationOutcome::Ok,
        );
        versioned_multipart.version_id = Some("ver-2".to_string());
        let unversioned_put = record("op-3", OperationKind::Put, "k3", "v3", OperationOutcome::Ok);
        let mut versioned_delete = record(
            "op-4",
            OperationKind::Delete,
            "k1",
            "",
            OperationOutcome::Ok,
        );
        versioned_delete.version_id = Some("marker-1".to_string());
        let unversioned_delete = record(
            "op-5",
            OperationKind::Delete,
            "k2",
            "",
            OperationOutcome::Ok,
        );
        let failed_put = record(
            "op-6",
            OperationKind::Put,
            "k4",
            "v4",
            OperationOutcome::Timeout,
        );

        let lineage = super::committed_version_lineage(&[
            versioned_put,
            versioned_multipart,
            unversioned_put,
            versioned_delete,
            unversioned_delete,
            failed_put,
        ]);

        assert_eq!(
            lineage
                .versions
                .iter()
                .map(|version| (version.key.as_str(), version.version_id.as_str()))
                .collect::<Vec<_>>(),
            vec![("k1", "ver-1"), ("k2", "ver-2")]
        );
        assert_eq!(
            lineage
                .delete_markers
                .iter()
                .map(|marker| (marker.key.as_str(), marker.version_id.as_str()))
                .collect::<Vec<_>>(),
            vec![("k1", "marker-1")]
        );
        assert_eq!(lineage.missing_version_id_count, 2);
        assert!(
            lineage
                .missing_version_id_samples
                .iter()
                .any(|sample| sample.contains("op-3"))
        );
        assert!(
            lineage
                .missing_version_id_samples
                .iter()
                .any(|sample| sample.contains("op-5"))
        );
    }

    #[test]
    fn committed_version_get_classifies_missing_corrupt_and_verified() {
        let version = super::CommittedVersion {
            key: "k".to_string(),
            version_id: "ver-1".to_string(),
            sha256: crate::fault::workload::sha256_hex(b"x"),
            size_bytes: 1,
        };

        let mut report = empty_report();
        super::evaluate_committed_version_get(
            &mut report,
            &version,
            GetObjectResult {
                outcome: OperationOutcome::Ok,
                http_status: Some(200),
                error: None,
                body: Some(b"x".to_vec()),
            },
        );
        assert_eq!(report.verified_committed_versions, 1);

        super::evaluate_committed_version_get(
            &mut report,
            &version,
            GetObjectResult {
                outcome: OperationOutcome::NotFound,
                http_status: Some(404),
                error: None,
                body: None,
            },
        );
        assert_eq!(report.missing_committed_versions, vec!["k@ver-1"]);

        super::evaluate_committed_version_get(
            &mut report,
            &version,
            GetObjectResult {
                outcome: OperationOutcome::Ok,
                http_status: Some(200),
                error: None,
                body: Some(b"y".to_vec()),
            },
        );
        assert_eq!(report.version_hash_mismatches.len(), 1);
        assert!(report.version_hash_mismatches[0].starts_with("k@ver-1"));

        super::evaluate_committed_version_get(
            &mut report,
            &version,
            GetObjectResult {
                outcome: OperationOutcome::Timeout,
                http_status: None,
                error: Some("get object timed out".to_string()),
                body: None,
            },
        );
        assert_eq!(report.unavailable_committed_versions.len(), 1);
    }

    #[test]
    fn resurrected_deleted_objects_require_latest_delete_marker() {
        use crate::fault::workload::ObjectVersionEntry;
        use std::collections::BTreeSet;

        let deleted = ["gone", "resurrected", "absent"]
            .iter()
            .map(|key| key.to_string())
            .collect::<BTreeSet<_>>();
        let entries = vec![
            ObjectVersionEntry {
                key: "gone".to_string(),
                version_id: Some("marker-1".to_string()),
                is_latest: true,
                is_delete_marker: true,
            },
            ObjectVersionEntry {
                key: "gone".to_string(),
                version_id: Some("ver-0".to_string()),
                is_latest: false,
                is_delete_marker: false,
            },
            ObjectVersionEntry {
                key: "resurrected".to_string(),
                version_id: Some("ver-1".to_string()),
                is_latest: true,
                is_delete_marker: false,
            },
        ];
        let latest = super::latest_version_entries(&entries);

        let violations = super::resurrected_deleted_objects(&deleted, &latest);

        assert_eq!(
            violations,
            vec![
                "absent: no latest version entry after committed delete".to_string(),
                "resurrected: latest version is not a delete marker after committed delete"
                    .to_string()
            ]
        );
    }

    #[test]
    fn missing_committed_delete_markers_are_reported() {
        use crate::fault::workload::ObjectVersionEntry;

        let committed = vec![
            super::CommittedDeleteMarker {
                key: "k".to_string(),
                version_id: "marker-1".to_string(),
            },
            super::CommittedDeleteMarker {
                key: "k".to_string(),
                version_id: "marker-2".to_string(),
            },
        ];
        let entries = vec![
            ObjectVersionEntry {
                key: "k".to_string(),
                version_id: Some("marker-1".to_string()),
                is_latest: false,
                is_delete_marker: true,
            },
            ObjectVersionEntry {
                key: "k".to_string(),
                version_id: Some("old-version".to_string()),
                is_latest: false,
                is_delete_marker: false,
            },
        ];

        let missing = super::missing_committed_delete_markers(&committed, &entries);

        assert_eq!(
            missing,
            vec!["k@marker-2: committed delete marker missing from ListObjectVersions".to_string()]
        );
    }

    #[test]
    fn ambiguous_version_candidates_ignore_committed_versions_but_keep_unknown_versions() {
        use crate::fault::workload::ObjectVersionEntry;

        let mut committed = timed_record(
            "op-1",
            OperationKind::Put,
            "k",
            "committed",
            OperationOutcome::Ok,
            1,
            2,
        );
        committed.version_id = Some("ver-ok".to_string());
        let ambiguous = timed_record(
            "op-2",
            OperationKind::Put,
            "k",
            "timeout",
            OperationOutcome::Timeout,
            3,
            4,
        );
        let mut later = timed_record(
            "op-3",
            OperationKind::Put,
            "k",
            "later",
            OperationOutcome::Ok,
            5,
            6,
        );
        later.version_id = Some("ver-later".to_string());
        let model = object_model(&[committed.clone(), ambiguous, later.clone()]);
        let lineage = super::committed_version_lineage(&[committed, later]);
        let entries = vec![
            ObjectVersionEntry {
                key: "k".to_string(),
                version_id: Some("ver-later".to_string()),
                is_latest: true,
                is_delete_marker: false,
            },
            ObjectVersionEntry {
                key: "k".to_string(),
                version_id: Some("ver-ok".to_string()),
                is_latest: false,
                is_delete_marker: false,
            },
            ObjectVersionEntry {
                key: "k".to_string(),
                version_id: Some("ver-timeout".to_string()),
                is_latest: false,
                is_delete_marker: false,
            },
            ObjectVersionEntry {
                key: "k".to_string(),
                version_id: Some("marker".to_string()),
                is_latest: false,
                is_delete_marker: true,
            },
        ];

        let (candidates, conflicts) =
            super::ambiguous_version_candidates(&model, &lineage, &entries);

        assert!(conflicts.is_empty());
        assert_eq!(
            candidates
                .iter()
                .map(|candidate| candidate.version_id.as_str())
                .collect::<Vec<_>>(),
            vec!["ver-timeout"]
        );
    }

    #[test]
    fn ambiguous_version_get_records_materialized_timeout_version() {
        let attempt = ambiguous_attempt("op-2", &sha256_hex(b"b"));
        let candidate = super::AmbiguousVersionCandidate {
            key: "k".to_string(),
            version_id: "ver-timeout".to_string(),
            attempts: vec![attempt],
        };
        let mut materialized = Vec::new();
        let mut conflicts = Vec::new();

        super::evaluate_ambiguous_version_get(
            &mut materialized,
            &mut conflicts,
            &candidate,
            GetObjectResult {
                outcome: OperationOutcome::Ok,
                http_status: Some(200),
                error: None,
                body: Some(b"b".to_vec()),
            },
        );

        assert!(conflicts.is_empty());
        assert_eq!(materialized.len(), 1);
        assert!(materialized[0].contains("k@ver-timeout"));
        assert!(materialized[0].contains("materialized as version"));
    }

    #[test]
    fn ambiguous_version_candidates_report_missing_version_ids() {
        use crate::fault::workload::ObjectVersionEntry;

        let ambiguous = timed_record(
            "op-2",
            OperationKind::Put,
            "k",
            "timeout",
            OperationOutcome::Timeout,
            3,
            4,
        );
        let model = object_model(&[ambiguous]);
        let lineage = super::committed_version_lineage(&[]);
        let entries = vec![ObjectVersionEntry {
            key: "k".to_string(),
            version_id: None,
            is_latest: false,
            is_delete_marker: false,
        }];

        let (candidates, conflicts) =
            super::ambiguous_version_candidates(&model, &lineage, &entries);

        assert!(candidates.is_empty());
        assert_eq!(conflicts.len(), 1);
        assert!(conflicts[0].contains("did not include a version id"));
    }

    #[test]
    fn uncommitted_version_with_unexpected_body_is_conflict() {
        let attempt = ambiguous_attempt("op-2", &sha256_hex(b"b"));
        let candidate = super::AmbiguousVersionCandidate {
            key: "k".to_string(),
            version_id: "ver-extra".to_string(),
            attempts: vec![attempt],
        };
        let mut materialized = Vec::new();
        let mut conflicts = Vec::new();

        super::evaluate_ambiguous_version_get(
            &mut materialized,
            &mut conflicts,
            &candidate,
            GetObjectResult {
                outcome: OperationOutcome::Ok,
                http_status: Some(200),
                error: None,
                body: Some(b"c".to_vec()),
            },
        );

        assert!(materialized.is_empty());
        assert_eq!(conflicts.len(), 1);
        assert!(conflicts[0].contains("matched no ambiguous attempt"));
    }

    #[test]
    fn version_reads_are_excluded_from_plain_read_anomalies() {
        let put = record("op-1", OperationKind::Put, "k", "new", OperationOutcome::Ok);
        let mut old_version_get =
            record("op-2", OperationKind::Get, "k", "old", OperationOutcome::Ok);
        old_version_get.version_id = Some("ver-0".to_string());

        let anomalies = successful_read_anomalies(&[put, old_version_get]);

        assert!(anomalies.corrupted_reads.is_empty());
        assert!(anomalies.visible_deleted_objects.is_empty());
    }

    #[test]
    fn warning_summary_caps_samples_but_counts_all() {
        let mut warnings = WarningSummary::default();
        for idx in 0..(super::MAX_WARNING_SAMPLES + 3) {
            warnings.push(format!("warning-{idx}"));
        }

        assert_eq!(warnings.total_count, super::MAX_WARNING_SAMPLES + 3);
        assert_eq!(warnings.samples.len(), super::MAX_WARNING_SAMPLES);
    }

    #[test]
    fn report_requires_clean_correctness_verdict() {
        let report = CheckerReport {
            scenario: "io-eio".to_string(),
            run_id: "run-1".to_string(),
            committed_puts: 1,
            expected_live_objects: 1,
            verified_live_objects: 1,
            missing_committed_objects: Vec::new(),
            unavailable_committed_objects: Vec::new(),
            unknown_committed_read_failures: Vec::new(),
            hash_mismatches: Vec::new(),
            successful_corrupted_reads: Vec::new(),
            unexpected_visible_deleted_objects: Vec::new(),
            unknown_writes_materialized: Vec::new(),
            unknown_writes_preserved_committed: Vec::new(),
            unknown_write_value_conflicts: Vec::new(),
            list_history_warning_count: 0,
            final_list_warning_count: 0,
            list_history_warnings: Vec::new(),
            list_warnings: Vec::new(),
            final_listed_objects: Some(1),
            versioning_expected: false,
            expected_committed_versions: 0,
            verified_committed_versions: 0,
            committed_writes_missing_version_id_count: 0,
            committed_writes_missing_version_id: Vec::new(),
            missing_committed_versions: Vec::new(),
            unavailable_committed_versions: Vec::new(),
            version_hash_mismatches: Vec::new(),
            missing_committed_delete_markers: Vec::new(),
            resurrected_deleted_objects: Vec::new(),
            tolerated_ambiguous_deletes: Vec::new(),
            operation_cohorts: BTreeMap::new(),
            fault_window_relations: BTreeMap::new(),
            tenant_recovered: true,
            passed: true,
        };

        assert!(report.require_success().is_ok());
    }

    fn empty_report() -> CheckerReport {
        CheckerReport {
            scenario: "io-eio".to_string(),
            run_id: "run-1".to_string(),
            committed_puts: 0,
            expected_live_objects: 0,
            verified_live_objects: 0,
            missing_committed_objects: Vec::new(),
            unavailable_committed_objects: Vec::new(),
            unknown_committed_read_failures: Vec::new(),
            hash_mismatches: Vec::new(),
            successful_corrupted_reads: Vec::new(),
            unexpected_visible_deleted_objects: Vec::new(),
            unknown_writes_materialized: Vec::new(),
            unknown_writes_preserved_committed: Vec::new(),
            unknown_write_value_conflicts: Vec::new(),
            list_history_warning_count: 0,
            final_list_warning_count: 0,
            list_history_warnings: Vec::new(),
            list_warnings: Vec::new(),
            final_listed_objects: None,
            versioning_expected: false,
            expected_committed_versions: 0,
            verified_committed_versions: 0,
            committed_writes_missing_version_id_count: 0,
            committed_writes_missing_version_id: Vec::new(),
            missing_committed_versions: Vec::new(),
            unavailable_committed_versions: Vec::new(),
            version_hash_mismatches: Vec::new(),
            missing_committed_delete_markers: Vec::new(),
            resurrected_deleted_objects: Vec::new(),
            tolerated_ambiguous_deletes: Vec::new(),
            operation_cohorts: BTreeMap::new(),
            fault_window_relations: BTreeMap::new(),
            tenant_recovered: true,
            passed: false,
        }
    }

    fn recovery_report_with_attempted_key(key: &str) -> RecoveryStabilityReport {
        RecoveryStabilityReport {
            immediate_passed: false,
            reread_attempted_keys: vec![key.to_string()],
            reread_recovered_keys: Vec::new(),
            still_unavailable_keys: Vec::new(),
            hash_mismatches: Vec::new(),
            data_corruption_evidence: Vec::new(),
            ambiguous_write_evidence: Vec::new(),
            final_list_warning_count: 0,
            list_warnings: Vec::new(),
            harness_errors: Vec::new(),
            max_recovery_seconds: 60,
            recovered_within_seconds: None,
            classification: RecoveryStabilityClassification::CommittedObjectUnavailable,
        }
    }

    #[test]
    fn committed_delete_reread_flags_body_as_resurrection() {
        let message = super::evaluate_deleted_reread(
            "gone",
            &GetObjectResult {
                outcome: OperationOutcome::Ok,
                http_status: Some(200),
                error: None,
                body: Some(b"back".to_vec()),
            },
        );

        assert_eq!(
            message.as_deref(),
            Some("gone: committed delete resurrected on GET (4 bytes)")
        );
    }

    #[test]
    fn committed_delete_reread_accepts_not_found_and_unavailable() {
        let not_found = super::evaluate_deleted_reread(
            "gone",
            &GetObjectResult {
                outcome: OperationOutcome::NotFound,
                http_status: Some(404),
                error: None,
                body: None,
            },
        );
        assert!(not_found.is_none());

        // An unavailable probe response (timeout/error) is not proof of
        // resurrection; only a returned body is.
        let unavailable = super::evaluate_deleted_reread(
            "gone",
            &GetObjectResult {
                outcome: OperationOutcome::Timeout,
                http_status: None,
                error: Some("read timed out".to_string()),
                body: None,
            },
        );
        assert!(unavailable.is_none());
    }
}
