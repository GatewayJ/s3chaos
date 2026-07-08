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

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, btree_map::Entry};
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Component, Path, PathBuf};

const MAX_ARTIFACT_SCAN_DEPTH: usize = 8;
const MAX_ARTIFACT_SCAN_FILES: usize = 10_000;
const MAX_JSON_ARTIFACT_BYTES: u64 = 1024 * 1024;
const MAX_JSONL_TAIL_BYTES: u64 = 2 * 1024 * 1024;
const MAX_HEALTH_LOG_TAIL_BYTES: u64 = 1024 * 1024;
const MAX_EXIT_CODE_BYTES: u64 = 1024;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsoleSnapshot {
    pub artifact_root: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suite_plan: Option<ConsoleSuitePlanView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suite_summary: Option<ConsoleSuiteSummaryView>,
    pub attempts: Vec<ConsoleAttemptView>,
    pub runner_failures: Vec<ConsoleRunnerFailureView>,
    pub health: Vec<ConsoleHealthArtifactView>,
    pub exit_codes: Vec<ConsoleExitCodeView>,
    pub warnings: Vec<ConsoleWarning>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsoleSuitePlanView {
    pub artifact: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suite: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_root: Option<String>,
    pub attempts: Vec<ConsolePlannedAttemptView>,
    pub raw: Value,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsolePlannedAttemptView {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scenario: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub case_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repetition: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attempt_artifact_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub case_artifact_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_stream: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsoleSuiteSummaryView {
    pub artifact: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suite: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended_at_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elapsed_seconds: Option<u64>,
    pub failures: Vec<ConsoleSuiteFailureView>,
    pub attempts: Vec<ConsoleSuiteAttemptView>,
    pub raw: Value,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsoleSuiteFailureView {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stopped_suite: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attempt_index: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scenario: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repetition: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classification: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub evidence_classifications: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attempt_artifacts_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_summary: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsoleSuiteAttemptView {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scenario: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repetition: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended_at_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifacts_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seed: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_disruptions: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommitted: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub committed: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classification: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub evidence_classifications: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsoleAttemptView {
    pub artifact_dir: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scenario: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repetition: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classification: Option<String>,
    pub cases: Vec<ConsoleCaseView>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsoleCaseView {
    pub case_name: String,
    pub artifact_dir: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_artifact: Option<String>,
    pub event_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_stage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_status: Option<String>,
    pub events: Vec<ConsoleRunEventView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_summary: Option<ConsoleFailureSummaryView>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsoleRunEventView {
    #[serde(default, alias = "at_ms", skip_serializing_if = "Option::is_none")]
    pub at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scenario: Option<String>,
    #[serde(default, alias = "run_id", skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsoleFailureSummaryView {
    pub artifact: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scenario: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classification: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_correctness: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub availability: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub evidence_classifications: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_list_warning_count: Option<u64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub list_warnings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_loss: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub corruption: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovered_within_window: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovered_within_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    pub raw: Value,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsoleRunnerFailureView {
    pub artifact: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suite: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scenario: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health_guard_failed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suite_budget_failed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rust_failure_summary_present: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suite_summary_present: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_log: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suite_log: Option<String>,
    pub raw: Value,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsoleHealthArtifactView {
    pub artifact: String,
    pub path: String,
    pub format: String,
    pub samples: Vec<ConsoleHealthSampleView>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsoleHealthSampleView {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub safe: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget: Option<bool>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<Value>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsoleExitCodeView {
    pub artifact: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<i32>,
    pub raw: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsoleWarning {
    pub artifact: String,
    pub path: String,
    pub message: String,
}

pub fn build_console_snapshot(root: impl AsRef<Path>) -> Result<ConsoleSnapshot> {
    let root = root.as_ref();
    let requested_root = fs::canonicalize(root)
        .with_context(|| format!("could not canonicalize artifact root {}", root.display()))?;
    if !requested_root.is_dir() {
        bail!(
            "artifact root {} is not a directory",
            requested_root.display()
        );
    }

    let mut warnings = Vec::new();
    let requested_index = ArtifactIndex::collect(&requested_root, &mut warnings);
    let (root, index) = select_console_root(&requested_root, requested_index, &mut warnings);
    let root = root.as_path();
    let artifact_root = root.display().to_string();

    let suite_plan = read_suite_plan(root, &mut warnings);
    let suite_summary = read_suite_summary(root, &mut warnings);
    let mut attempt_keys = BTreeMap::new();
    let mut attempts = Vec::new();

    if let Some(plan) = &suite_plan {
        for planned in &plan.attempts {
            add_planned_attempt(root, planned, &mut attempt_keys, &mut attempts);
        }
    }

    if let Some(summary) = &suite_summary {
        for summary_attempt in &summary.attempts {
            add_summary_attempt(root, summary_attempt, &mut attempt_keys, &mut attempts);
        }
    }

    if index.run_events.is_empty() {
        push_warning(
            &mut warnings,
            "run-events.jsonl",
            &artifact_root,
            "no run-events.jsonl artifacts found yet",
        );
    }
    for path in &index.run_events {
        add_event_artifact(root, path, &mut warnings, &mut attempt_keys, &mut attempts);
    }

    for path in &index.failure_summaries {
        add_failure_artifact(root, path, &mut warnings, &mut attempt_keys, &mut attempts);
    }

    let runner_failures =
        read_runner_failures(root, &index.runner_failure_summaries, &mut warnings);

    let health = read_health_artifacts(root, &index, &mut warnings);
    if health.is_empty() {
        push_warning(
            &mut warnings,
            "health-watch",
            &artifact_root,
            "no health-watch.log or health-watch.jsonl artifacts found yet",
        );
    }

    let exit_codes = read_exit_codes(root, &index.exit_codes, &mut warnings);
    if index.failure_summaries.is_empty()
        && should_warn_missing_failure_summary(suite_summary.as_ref(), &attempts)
    {
        push_warning(
            &mut warnings,
            "failure-summary.json",
            &artifact_root,
            "failed attempt state is present but no failure-summary.json artifacts were found",
        );
    }
    if runner_failures.is_empty() && should_warn_missing_runner_failure_summary(&exit_codes) {
        push_warning(
            &mut warnings,
            "runner-failure-summary.json",
            &artifact_root,
            "nonzero exit-code is present but no runner-failure-summary.json artifacts were found",
        );
    }
    if exit_codes.is_empty() {
        push_warning(
            &mut warnings,
            "exit-code",
            &artifact_root,
            "no exit-code or suite-exit-code artifacts found yet",
        );
    }

    sort_attempts(&mut attempts);

    Ok(ConsoleSnapshot {
        artifact_root,
        suite_plan,
        suite_summary,
        attempts,
        runner_failures,
        health,
        exit_codes,
        warnings,
    })
}

#[derive(Debug, Default)]
struct ArtifactIndex {
    suite_run_roots: Vec<PathBuf>,
    run_events: Vec<PathBuf>,
    failure_summaries: Vec<PathBuf>,
    runner_failure_summaries: Vec<PathBuf>,
    health_logs: Vec<PathBuf>,
    health_jsonl: Vec<PathBuf>,
    exit_codes: Vec<PathBuf>,
}

impl ArtifactIndex {
    fn collect(root: &Path, warnings: &mut Vec<ConsoleWarning>) -> Self {
        Self::collect_with_limits(root, warnings, ArtifactScanLimits::default())
    }

    fn collect_with_limits(
        root: &Path,
        warnings: &mut Vec<ConsoleWarning>,
        limits: ArtifactScanLimits,
    ) -> Self {
        let mut index = Self::default();
        let mut state = ArtifactScanState::new(limits);
        collect_artifacts(root, root, 0, &mut index, warnings, &mut state);
        index.suite_run_roots.sort();
        index.suite_run_roots.dedup();
        index.run_events.sort();
        index.failure_summaries.sort();
        index.runner_failure_summaries.sort();
        index.health_logs.sort();
        index.health_jsonl.sort();
        index.exit_codes.sort();
        index
    }
}

fn select_console_root(
    requested_root: &Path,
    requested_index: ArtifactIndex,
    warnings: &mut Vec<ConsoleWarning>,
) -> (PathBuf, ArtifactIndex) {
    if suite_marker_exists(requested_root) {
        return (requested_root.to_path_buf(), requested_index);
    }

    match requested_index.suite_run_roots.as_slice() {
        [candidate] => {
            let selected_root =
                fs::canonicalize(candidate).unwrap_or_else(|_| candidate.to_path_buf());
            let selected_index = ArtifactIndex::collect(&selected_root, warnings);
            (selected_root, selected_index)
        }
        [] => (requested_root.to_path_buf(), requested_index),
        candidates => {
            push_warning(
                warnings,
                "suite-run-root",
                display_path(requested_root, requested_root),
                format!(
                    "multiple nested suite run roots found; keeping requested artifact root to avoid guessing: {}",
                    suite_root_candidate_preview(requested_root, candidates)
                ),
            );
            (requested_root.to_path_buf(), requested_index)
        }
    }
}

fn suite_marker_exists(root: &Path) -> bool {
    root.join("suite-plan.json").is_file() || root.join("suite-summary.json").is_file()
}

fn suite_root_candidate_preview(root: &Path, candidates: &[PathBuf]) -> String {
    const MAX_PREVIEW: usize = 5;
    let mut preview = candidates
        .iter()
        .take(MAX_PREVIEW)
        .map(|candidate| display_path(root, candidate))
        .collect::<Vec<_>>();
    if candidates.len() > MAX_PREVIEW {
        preview.push(format!("... and {} more", candidates.len() - MAX_PREVIEW));
    }
    preview.join(", ")
}

#[derive(Debug, Clone, Copy)]
struct ArtifactScanLimits {
    max_depth: usize,
    max_files: usize,
}

impl Default for ArtifactScanLimits {
    fn default() -> Self {
        Self {
            max_depth: MAX_ARTIFACT_SCAN_DEPTH,
            max_files: MAX_ARTIFACT_SCAN_FILES,
        }
    }
}

#[derive(Debug)]
struct ArtifactScanState {
    limits: ArtifactScanLimits,
    files_seen: usize,
    depth_limit_warned: bool,
    file_limit_warned: bool,
    file_limit_reached: bool,
}

impl ArtifactScanState {
    fn new(limits: ArtifactScanLimits) -> Self {
        Self {
            limits,
            files_seen: 0,
            depth_limit_warned: false,
            file_limit_warned: false,
            file_limit_reached: false,
        }
    }

    fn can_scan_file(
        &mut self,
        root: &Path,
        path: &Path,
        warnings: &mut Vec<ConsoleWarning>,
    ) -> bool {
        if self.files_seen >= self.limits.max_files {
            self.file_limit_reached = true;
            if !self.file_limit_warned {
                self.file_limit_warned = true;
                push_warning(
                    warnings,
                    "artifact-dir",
                    display_path(root, path),
                    format!(
                        "artifact scan file limit reached at {} files; skipping remaining files",
                        self.limits.max_files
                    ),
                );
            }
            return false;
        }
        self.files_seen += 1;
        true
    }

    fn warn_depth_limit(&mut self, root: &Path, path: &Path, warnings: &mut Vec<ConsoleWarning>) {
        if self.depth_limit_warned {
            return;
        }
        self.depth_limit_warned = true;
        push_warning(
            warnings,
            "artifact-dir",
            display_path(root, path),
            format!(
                "artifact scan depth limit reached at {} levels; skipping nested directories",
                self.limits.max_depth
            ),
        );
    }
}

fn collect_artifacts(
    root: &Path,
    dir: &Path,
    depth: usize,
    index: &mut ArtifactIndex,
    warnings: &mut Vec<ConsoleWarning>,
    state: &mut ArtifactScanState,
) {
    if state.file_limit_reached {
        return;
    }

    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) => {
            push_warning(
                warnings,
                "artifact-dir",
                display_path(root, dir),
                format!("could not read artifact directory: {error}"),
            );
            return;
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                push_warning(
                    warnings,
                    "artifact-dir",
                    display_path(root, dir),
                    format!("could not read artifact directory entry: {error}"),
                );
                continue;
            }
        };
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(error) => {
                push_warning(
                    warnings,
                    "artifact-dir",
                    display_path(root, &entry.path()),
                    format!("could not inspect artifact path: {error}"),
                );
                continue;
            }
        };
        let path = entry.path();
        if file_type.is_symlink() {
            collect_symlink_artifact(root, &path, index, warnings, state);
            if state.file_limit_reached {
                return;
            }
            continue;
        }
        if file_type.is_dir() {
            if depth >= state.limits.max_depth {
                state.warn_depth_limit(root, &path, warnings);
                continue;
            }
            collect_artifacts(root, &path, depth + 1, index, warnings, state);
            if state.file_limit_reached {
                return;
            }
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        if !state.can_scan_file(root, &path, warnings) {
            return;
        }
        index_artifact_path(index, &path);
    }
}

fn collect_symlink_artifact(
    root: &Path,
    path: &Path,
    index: &mut ArtifactIndex,
    warnings: &mut Vec<ConsoleWarning>,
    state: &mut ArtifactScanState,
) {
    let canonical = match fs::canonicalize(path) {
        Ok(canonical) => canonical,
        Err(error) => {
            push_warning(
                warnings,
                "artifact-dir",
                display_path(root, path),
                format!("could not resolve symlink artifact path: {error}"),
            );
            return;
        }
    };
    if !canonical.starts_with(root) {
        push_warning(
            warnings,
            "artifact-dir",
            display_path(root, path),
            format!(
                "refusing symlink/path escape outside artifact root after canonicalization: {}",
                canonical.display()
            ),
        );
        return;
    }

    let metadata = match fs::metadata(&canonical) {
        Ok(metadata) => metadata,
        Err(error) => {
            push_warning(
                warnings,
                "artifact-dir",
                display_path(root, path),
                format!("could not inspect symlink target: {error}"),
            );
            return;
        }
    };
    if metadata.is_dir() {
        push_warning(
            warnings,
            "artifact-dir",
            display_path(root, path),
            "skipping symlink directory inside artifact root to avoid recursive scan cycles",
        );
        return;
    }
    if !metadata.is_file() {
        return;
    }
    if !state.can_scan_file(root, path, warnings) {
        return;
    }
    index_artifact_path(index, path);
}

fn index_artifact_path(index: &mut ArtifactIndex, path: &Path) {
    match path.file_name().and_then(|name| name.to_str()) {
        Some("suite-plan.json") | Some("suite-summary.json") => {
            if let Some(parent) = path.parent() {
                index.suite_run_roots.push(parent.to_path_buf());
            }
        }
        Some("run-events.jsonl") => index.run_events.push(path.to_path_buf()),
        Some("failure-summary.json") => index.failure_summaries.push(path.to_path_buf()),
        Some("runner-failure-summary.json") => {
            index.runner_failure_summaries.push(path.to_path_buf())
        }
        Some("health-watch.log") => index.health_logs.push(path.to_path_buf()),
        Some("health-watch.jsonl") => index.health_jsonl.push(path.to_path_buf()),
        Some("exit-code") | Some("suite-exit-code") => index.exit_codes.push(path.to_path_buf()),
        _ => {}
    }
}

fn read_suite_plan(
    root: &Path,
    warnings: &mut Vec<ConsoleWarning>,
) -> Option<ConsoleSuitePlanView> {
    let path = root.join("suite-plan.json");
    let raw = read_optional_json(root, &path, "suite-plan.json", warnings)?;
    let extract = parse_suite_plan_extract(root, &path, &raw, warnings);
    Some(ConsoleSuitePlanView {
        artifact: "suite-plan.json".to_string(),
        path: display_path(root, &path),
        suite: extract.suite,
        run_id: extract.run_id,
        artifact_root: view_artifact_path_opt(root, extract.artifact_root),
        attempts: extract
            .attempts
            .into_iter()
            .map(|attempt| ConsolePlannedAttemptView::from_extract(root, attempt))
            .collect(),
        raw,
    })
}

fn read_suite_summary(
    root: &Path,
    warnings: &mut Vec<ConsoleWarning>,
) -> Option<ConsoleSuiteSummaryView> {
    let path = root.join("suite-summary.json");
    let raw = read_optional_json(root, &path, "suite-summary.json", warnings)?;
    let extract = parse_suite_summary_extract(root, &path, &raw, warnings);
    Some(ConsoleSuiteSummaryView {
        artifact: "suite-summary.json".to_string(),
        path: display_path(root, &path),
        suite: extract.suite,
        run_id: extract.run_id,
        status: extract.status,
        started_at_ms: extract.started_at_ms,
        ended_at_ms: extract.ended_at_ms,
        elapsed_seconds: extract.elapsed_seconds,
        failures: extract
            .failures
            .into_iter()
            .map(|failure| ConsoleSuiteFailureView::from_extract(root, failure))
            .collect(),
        attempts: extract
            .attempts
            .into_iter()
            .map(|attempt| ConsoleSuiteAttemptView::from_extract(root, attempt))
            .collect(),
        raw,
    })
}

fn read_optional_json(
    root: &Path,
    path: &Path,
    artifact: &str,
    warnings: &mut Vec<ConsoleWarning>,
) -> Option<Value> {
    let raw = read_limited_text(
        root,
        path,
        artifact,
        warnings,
        MAX_JSON_ARTIFACT_BYTES,
        Some("optional artifact is missing"),
    )?;
    match serde_json::from_str(&raw) {
        Ok(value) => Some(value),
        Err(error) => {
            push_warning(
                warnings,
                artifact,
                display_path(root, path),
                format!("could not parse json artifact: {error}"),
            );
            None
        }
    }
}

#[derive(Debug, Default)]
struct JsonlReadResult {
    values: Vec<Value>,
    invalid: bool,
}

fn read_jsonl_values(
    root: &Path,
    path: &Path,
    artifact: &str,
    warnings: &mut Vec<ConsoleWarning>,
) -> JsonlReadResult {
    let Some(raw) = read_tail_text(root, path, artifact, warnings, MAX_JSONL_TAIL_BYTES, None)
    else {
        return JsonlReadResult::default();
    };
    let mut invalid = false;
    let values = raw
        .lines()
        .enumerate()
        .filter_map(|(index, line)| {
            let line = line.trim();
            if line.is_empty() {
                return None;
            }
            match serde_json::from_str(line) {
                Ok(value) => Some(value),
                Err(error) => {
                    invalid = true;
                    push_warning(
                        warnings,
                        artifact,
                        display_path(root, path),
                        format!("could not parse jsonl line {}: {error}", index + 1),
                    );
                    None
                }
            }
        })
        .collect();
    JsonlReadResult { values, invalid }
}

#[derive(Debug)]
struct SafeArtifactFile {
    canonical_path: PathBuf,
    len: u64,
}

fn resolve_artifact_file(
    root: &Path,
    path: &Path,
    artifact: &str,
    warnings: &mut Vec<ConsoleWarning>,
    missing_message: Option<&str>,
) -> Option<SafeArtifactFile> {
    let canonical_path = match fs::canonicalize(path) {
        Ok(canonical_path) => canonical_path,
        Err(error) => {
            if error.kind() == std::io::ErrorKind::NotFound {
                if let Some(message) = missing_message {
                    push_warning(warnings, artifact, display_path(root, path), message);
                } else {
                    push_warning(
                        warnings,
                        artifact,
                        display_path(root, path),
                        format!("artifact path is missing before read: {error}"),
                    );
                }
            } else {
                push_warning(
                    warnings,
                    artifact,
                    display_path(root, path),
                    format!("could not canonicalize artifact path before read: {error}"),
                );
            }
            return None;
        }
    };

    if !canonical_path.starts_with(root) {
        push_warning(
            warnings,
            artifact,
            display_path(root, path),
            format!(
                "refusing symlink/path escape outside artifact root after canonicalization: {}",
                canonical_path.display()
            ),
        );
        return None;
    }

    let metadata = match fs::metadata(&canonical_path) {
        Ok(metadata) => metadata,
        Err(error) => {
            push_warning(
                warnings,
                artifact,
                display_path(root, path),
                format!("could not inspect artifact metadata before read: {error}"),
            );
            return None;
        }
    };
    if !metadata.is_file() {
        push_warning(
            warnings,
            artifact,
            display_path(root, path),
            "artifact path is not a regular file",
        );
        return None;
    }

    Some(SafeArtifactFile {
        canonical_path,
        len: metadata.len(),
    })
}

fn read_limited_text(
    root: &Path,
    path: &Path,
    artifact: &str,
    warnings: &mut Vec<ConsoleWarning>,
    max_bytes: u64,
    missing_message: Option<&str>,
) -> Option<String> {
    let file = resolve_artifact_file(root, path, artifact, warnings, missing_message)?;
    if file.len > max_bytes {
        push_warning(
            warnings,
            artifact,
            display_path(root, path),
            format!(
                "artifact exceeds {max_bytes} byte read limit ({} bytes); refusing to read",
                file.len
            ),
        );
        return None;
    }

    match fs::read_to_string(&file.canonical_path) {
        Ok(raw) => Some(raw),
        Err(error) => {
            push_warning(
                warnings,
                artifact,
                display_path(root, path),
                format!("could not read artifact: {error}"),
            );
            None
        }
    }
}

fn read_tail_text(
    root: &Path,
    path: &Path,
    artifact: &str,
    warnings: &mut Vec<ConsoleWarning>,
    max_bytes: u64,
    missing_message: Option<&str>,
) -> Option<String> {
    let file = resolve_artifact_file(root, path, artifact, warnings, missing_message)?;
    if file.len <= max_bytes {
        return match fs::read_to_string(&file.canonical_path) {
            Ok(raw) => Some(raw),
            Err(error) => {
                push_warning(
                    warnings,
                    artifact,
                    display_path(root, path),
                    format!("could not read artifact: {error}"),
                );
                None
            }
        };
    }

    push_warning(
        warnings,
        artifact,
        display_path(root, path),
        format!(
            "artifact exceeds {max_bytes} byte tail limit ({} bytes); reading trailing bytes only",
            file.len
        ),
    );

    let mut opened = match fs::File::open(&file.canonical_path) {
        Ok(opened) => opened,
        Err(error) => {
            push_warning(
                warnings,
                artifact,
                display_path(root, path),
                format!("could not open artifact for tail read: {error}"),
            );
            return None;
        }
    };
    let start = file.len.saturating_sub(max_bytes);
    if let Err(error) = opened.seek(SeekFrom::Start(start)) {
        push_warning(
            warnings,
            artifact,
            display_path(root, path),
            format!("could not seek artifact for tail read: {error}"),
        );
        return None;
    }

    let capacity = max_bytes.min(usize::MAX as u64) as usize;
    let mut bytes = Vec::with_capacity(capacity);
    if let Err(error) = opened.read_to_end(&mut bytes) {
        push_warning(
            warnings,
            artifact,
            display_path(root, path),
            format!("could not read artifact tail: {error}"),
        );
        return None;
    }

    let mut raw = String::from_utf8_lossy(&bytes).into_owned();
    if let Some(index) = raw.find('\n') {
        raw = raw[index + 1..].to_string();
    } else {
        raw.clear();
    }
    Some(raw)
}

fn add_planned_attempt(
    root: &Path,
    planned: &ConsolePlannedAttemptView,
    attempt_keys: &mut BTreeMap<String, usize>,
    attempts: &mut Vec<ConsoleAttemptView>,
) {
    let Some(attempt_artifact_dir) = &planned.attempt_artifact_dir else {
        return;
    };
    let attempt_path = artifact_text_path(root, attempt_artifact_dir);
    let (key, artifact_dir) = keyed_display_path(root, &attempt_path);
    let attempt = get_or_insert_attempt(attempt_keys, attempts, key, artifact_dir);
    attempt.index = attempt.index.or(planned.index);
    fill_if_none(&mut attempt.scenario, planned.scenario.clone());
    attempt.repetition = attempt.repetition.or(planned.repetition);

    if let Some(case_artifact_dir) = &planned.case_artifact_dir {
        let case_path = artifact_text_path(root, case_artifact_dir);
        let case_name = planned
            .case_name
            .clone()
            .or_else(|| file_name_string(&case_path))
            .unwrap_or_else(|| "unknown-case".to_string());
        let case_dir = display_path(root, &case_path);
        get_or_insert_case(attempt, case_name, case_dir);
    }
}

fn add_summary_attempt(
    root: &Path,
    summary: &ConsoleSuiteAttemptView,
    attempt_keys: &mut BTreeMap<String, usize>,
    attempts: &mut Vec<ConsoleAttemptView>,
) {
    let attempt_path = summary
        .artifacts_dir
        .as_deref()
        .map(|dir| artifact_text_path(root, dir))
        .unwrap_or_else(|| PathBuf::from(format!("attempt-{}", summary.index.unwrap_or(0))));
    let (key, artifact_dir) = keyed_display_path(root, &attempt_path);
    let attempt = get_or_insert_attempt(attempt_keys, attempts, key, artifact_dir);
    attempt.index = attempt.index.or(summary.index);
    fill_if_none(&mut attempt.scenario, summary.scenario.clone());
    attempt.repetition = attempt.repetition.or(summary.repetition);
    fill_if_none(&mut attempt.status, summary.status.clone());
    fill_if_none(&mut attempt.severity, summary.severity.clone());
    fill_if_none(&mut attempt.classification, summary.classification.clone());
}

fn add_event_artifact(
    root: &Path,
    path: &Path,
    warnings: &mut Vec<ConsoleWarning>,
    attempt_keys: &mut BTreeMap<String, usize>,
    attempts: &mut Vec<ConsoleAttemptView>,
) {
    let read = read_jsonl_values(root, path, "run-events.jsonl", warnings);
    let mut events = Vec::new();
    let mut invalid_event_stream = read.invalid;
    for value in read.values {
        match serde_json::from_value::<ConsoleRunEventView>(value) {
            Ok(event) => events.push(event),
            Err(error) => {
                invalid_event_stream = true;
                push_warning(
                    warnings,
                    "run-events.jsonl",
                    display_path(root, path),
                    format!("could not decode run event: {error}"),
                );
            }
        }
    }

    let (attempt_path, case_path) = infer_attempt_and_case_dirs(root, path);
    let (key, artifact_dir) = keyed_display_path(root, &attempt_path);
    let case_name = file_name_string(&case_path).unwrap_or_else(|| "unknown-case".to_string());
    let case_dir = display_path(root, &case_path);
    let event_count = events.len();
    let last_stage = events.iter().rev().find_map(|event| event.stage.clone());
    let last_status = if invalid_event_stream {
        Some("invalid".to_string())
    } else {
        events.iter().rev().find_map(|event| event.status.clone())
    };
    let scenario = events.iter().find_map(|event| event.scenario.clone());

    let attempt = get_or_insert_attempt(attempt_keys, attempts, key, artifact_dir);
    fill_if_none(&mut attempt.scenario, scenario);
    if invalid_event_stream {
        mark_attempt_invalid(attempt);
    } else {
        fill_if_none(&mut attempt.status, last_status.clone());
    }

    let case = get_or_insert_case(attempt, case_name, case_dir);
    case.event_artifact = Some(display_path(root, path));
    case.event_count = event_count;
    case.last_stage = last_stage;
    case.last_status = last_status;
    promote_workflow_warnings(root, &case_path, warnings, &events);
    case.events = events;
}

fn promote_workflow_warnings(
    root: &Path,
    case_path: &Path,
    warnings: &mut Vec<ConsoleWarning>,
    events: &[ConsoleRunEventView],
) {
    for event in events {
        if event.stage.as_deref() != Some("fault-delete")
            || event.status.as_deref() != Some("succeeded")
        {
            continue;
        }
        let Some(details) = event.details.as_ref() else {
            continue;
        };
        let Some(warning_artifact) = details.get("warning_artifact").and_then(Value::as_str) else {
            continue;
        };
        let message = event
            .message
            .as_deref()
            .unwrap_or("workflow completed with a warning");
        push_warning(
            warnings,
            warning_artifact,
            display_path(root, case_path),
            format!("{message}; see {warning_artifact}"),
        );
    }
}

fn add_failure_artifact(
    root: &Path,
    path: &Path,
    warnings: &mut Vec<ConsoleWarning>,
    attempt_keys: &mut BTreeMap<String, usize>,
    attempts: &mut Vec<ConsoleAttemptView>,
) {
    let Some(raw) = read_optional_json(root, path, "failure-summary.json", warnings) else {
        return;
    };
    let failure = failure_summary_view(root, path, raw);
    let (attempt_path, case_path) = infer_attempt_and_case_dirs(root, path);
    let (key, artifact_dir) = keyed_display_path(root, &attempt_path);
    let case_name = file_name_string(&case_path).unwrap_or_else(|| "unknown-case".to_string());
    let case_dir = display_path(root, &case_path);
    let attempt = get_or_insert_attempt(attempt_keys, attempts, key, artifact_dir);

    fill_if_none(&mut attempt.scenario, failure.scenario.clone());
    fill_if_none(&mut attempt.status, Some("failed".to_string()));
    fill_if_none(&mut attempt.severity, failure.severity.clone());
    fill_if_none(&mut attempt.classification, failure.classification.clone());

    let case = get_or_insert_case(attempt, case_name, case_dir);
    case.failure_summary = Some(failure);
}

fn read_runner_failures(
    root: &Path,
    paths: &[PathBuf],
    warnings: &mut Vec<ConsoleWarning>,
) -> Vec<ConsoleRunnerFailureView> {
    paths
        .iter()
        .filter_map(|path| {
            read_optional_json(root, path, "runner-failure-summary.json", warnings)
                .map(|raw| runner_failure_view(root, path, raw))
        })
        .collect()
}

fn read_health_artifacts(
    root: &Path,
    index: &ArtifactIndex,
    warnings: &mut Vec<ConsoleWarning>,
) -> Vec<ConsoleHealthArtifactView> {
    let mut health = Vec::new();
    let jsonl_dirs = index
        .health_jsonl
        .iter()
        .filter_map(|path| path.parent().map(Path::to_path_buf))
        .collect::<BTreeSet<_>>();
    for path in &index.health_jsonl {
        health.push(read_health_jsonl(root, path, warnings));
    }
    for path in &index.health_logs {
        if path
            .parent()
            .is_some_and(|parent| jsonl_dirs.contains(parent))
        {
            continue;
        }
        health.push(read_legacy_health_log(root, path, warnings));
    }
    health
}

fn read_legacy_health_log(
    root: &Path,
    path: &Path,
    warnings: &mut Vec<ConsoleWarning>,
) -> ConsoleHealthArtifactView {
    let raw = read_tail_text(
        root,
        path,
        "health-watch.log",
        warnings,
        MAX_HEALTH_LOG_TAIL_BYTES,
        None,
    )
    .unwrap_or_default();

    let samples = raw.lines().filter_map(parse_legacy_health_line).collect();
    ConsoleHealthArtifactView {
        artifact: "health-watch.log".to_string(),
        path: display_path(root, path),
        format: "legacy-log".to_string(),
        samples,
    }
}

fn read_health_jsonl(
    root: &Path,
    path: &Path,
    warnings: &mut Vec<ConsoleWarning>,
) -> ConsoleHealthArtifactView {
    let samples = read_jsonl_values(root, path, "health-watch.jsonl", warnings)
        .values
        .into_iter()
        .map(health_sample_from_json)
        .collect();
    ConsoleHealthArtifactView {
        artifact: "health-watch.jsonl".to_string(),
        path: display_path(root, path),
        format: "jsonl".to_string(),
        samples,
    }
}

fn read_exit_codes(
    root: &Path,
    paths: &[PathBuf],
    warnings: &mut Vec<ConsoleWarning>,
) -> Vec<ConsoleExitCodeView> {
    paths
        .iter()
        .map(|path| {
            let artifact = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("exit-code")
                .to_string();
            let raw = read_limited_text(root, path, &artifact, warnings, MAX_EXIT_CODE_BYTES, None)
                .unwrap_or_default()
                .trim()
                .to_string();
            let code = raw.parse::<i32>().ok();
            if code.is_none() && !raw.is_empty() {
                push_warning(
                    warnings,
                    &artifact,
                    display_path(root, path),
                    format!("could not parse exit code value {raw:?}"),
                );
            }
            ConsoleExitCodeView {
                artifact,
                path: display_path(root, path),
                code,
                raw,
            }
        })
        .collect()
}

fn get_or_insert_attempt<'a>(
    attempt_keys: &mut BTreeMap<String, usize>,
    attempts: &'a mut Vec<ConsoleAttemptView>,
    key: String,
    artifact_dir: String,
) -> &'a mut ConsoleAttemptView {
    let index = match attempt_keys.entry(key) {
        Entry::Occupied(entry) => *entry.get(),
        Entry::Vacant(entry) => {
            let index = attempts.len();
            attempts.push(ConsoleAttemptView {
                artifact_dir,
                index: None,
                scenario: None,
                repetition: None,
                status: None,
                severity: None,
                classification: None,
                cases: Vec::new(),
            });
            entry.insert(index);
            index
        }
    };
    &mut attempts[index]
}

fn get_or_insert_case(
    attempt: &mut ConsoleAttemptView,
    case_name: String,
    artifact_dir: String,
) -> &mut ConsoleCaseView {
    if let Some(index) = attempt
        .cases
        .iter()
        .position(|case| case.artifact_dir == artifact_dir)
    {
        return &mut attempt.cases[index];
    }
    attempt.cases.push(ConsoleCaseView {
        case_name,
        artifact_dir,
        event_artifact: None,
        event_count: 0,
        last_stage: None,
        last_status: None,
        events: Vec::new(),
        failure_summary: None,
    });
    attempt.cases.last_mut().expect("case was inserted")
}

fn mark_attempt_invalid(attempt: &mut ConsoleAttemptView) {
    match attempt.status.as_deref() {
        Some("failed") | Some("invalid") => {}
        _ => attempt.status = Some("invalid".to_string()),
    }
}

fn failure_summary_view(root: &Path, path: &Path, raw: Value) -> ConsoleFailureSummaryView {
    ConsoleFailureSummaryView {
        artifact: "failure-summary.json".to_string(),
        path: display_path(root, path),
        scenario: json_string(&raw, "scenario"),
        stage: json_string(&raw, "stage"),
        verdict: json_string(&raw, "verdict"),
        severity: json_string(&raw, "severity"),
        classification: json_string(&raw, "classification"),
        data_correctness: json_string(&raw, "data_correctness"),
        availability: json_string(&raw, "availability"),
        evidence_classifications: json_string_array(&raw, "evidence_classifications"),
        final_list_warning_count: json_u64(&raw, "final_list_warning_count"),
        list_warnings: json_string_array(&raw, "list_warnings"),
        data_loss: json_bool(&raw, "data_loss"),
        corruption: json_bool(&raw, "corruption"),
        recovered_within_window: json_bool(&raw, "recovered_within_window"),
        recovered_within_seconds: json_u64(&raw, "recovered_within_seconds"),
        message: json_string(&raw, "message"),
        raw,
    }
}

fn runner_failure_view(root: &Path, path: &Path, raw: Value) -> ConsoleRunnerFailureView {
    ConsoleRunnerFailureView {
        artifact: "runner-failure-summary.json".to_string(),
        path: display_path(root, path),
        suite: json_string(&raw, "suite"),
        scenario: json_string(&raw, "scenario"),
        stage: json_string(&raw, "stage"),
        exit_code: json_i64(&raw, "exit_code"),
        health_guard_failed: json_bool(&raw, "health_guard_failed"),
        suite_budget_failed: json_bool(&raw, "suite_budget_failed"),
        rust_failure_summary_present: json_bool(&raw, "rust_failure_summary_present"),
        suite_summary_present: json_bool(&raw, "suite_summary_present"),
        test_log: view_artifact_path_opt(root, json_string(&raw, "test_log")),
        suite_log: view_artifact_path_opt(root, json_string(&raw, "suite_log")),
        raw,
    }
}

fn parse_legacy_health_line(line: &str) -> Option<ConsoleHealthSampleView> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let mut parts = line.split_whitespace();
    let at = parts.next().map(ToString::to_string);
    let mut fields = BTreeMap::new();
    for part in parts {
        if let Some((key, value)) = part.split_once('=') {
            fields.insert(key.to_string(), value.to_string());
        }
    }
    let safe = fields.get("safe").and_then(|value| parse_bool(value));
    let budget = fields.get("budget").and_then(|value| parse_bool(value));
    Some(ConsoleHealthSampleView {
        at,
        at_ms: None,
        safe,
        budget,
        fields,
        raw: Some(Value::String(line.to_string())),
    })
}

fn health_sample_from_json(raw: Value) -> ConsoleHealthSampleView {
    ConsoleHealthSampleView {
        at: json_string(&raw, "at")
            .or_else(|| json_string(&raw, "time"))
            .or_else(|| json_string(&raw, "timestamp")),
        at_ms: json_u64(&raw, "at_ms").or_else(|| json_u64(&raw, "atMs")),
        safe: json_bool(&raw, "safe"),
        budget: json_bool(&raw, "budget"),
        fields: BTreeMap::new(),
        raw: Some(raw),
    }
}

fn parse_bool(value: &str) -> Option<bool> {
    match value {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

fn parse_suite_plan_extract(
    root: &Path,
    path: &Path,
    raw: &Value,
    warnings: &mut Vec<ConsoleWarning>,
) -> SuitePlanExtract {
    match serde_json::from_value(raw.clone()) {
        Ok(extract) => extract,
        Err(error) => {
            push_warning(
                warnings,
                "suite-plan.json",
                display_path(root, path),
                format!("could not decode suite plan view: {error}"),
            );
            SuitePlanExtract::default()
        }
    }
}

fn parse_suite_summary_extract(
    root: &Path,
    path: &Path,
    raw: &Value,
    warnings: &mut Vec<ConsoleWarning>,
) -> SuiteSummaryExtract {
    match serde_json::from_value(raw.clone()) {
        Ok(extract) => extract,
        Err(error) => {
            push_warning(
                warnings,
                "suite-summary.json",
                display_path(root, path),
                format!("could not decode suite summary view: {error}"),
            );
            SuiteSummaryExtract::default()
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct SuitePlanExtract {
    suite: Option<String>,
    run_id: Option<String>,
    artifact_root: Option<String>,
    attempts: Vec<SuitePlanAttemptExtract>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct SuitePlanAttemptExtract {
    index: Option<usize>,
    scenario: Option<String>,
    case_name: Option<String>,
    repetition: Option<usize>,
    artifacts: Option<SuitePlanAttemptArtifactsExtract>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct SuitePlanAttemptArtifactsExtract {
    attempt_dir: Option<String>,
    case_dir: Option<String>,
    event_stream: Option<String>,
}

impl ConsolePlannedAttemptView {
    fn from_extract(root: &Path, value: SuitePlanAttemptExtract) -> Self {
        let artifacts = value.artifacts.unwrap_or_default();
        Self {
            index: value.index,
            scenario: value.scenario,
            case_name: value.case_name,
            repetition: value.repetition,
            attempt_artifact_dir: view_artifact_path_opt(root, artifacts.attempt_dir),
            case_artifact_dir: view_artifact_path_opt(root, artifacts.case_dir),
            event_stream: view_artifact_path_opt(root, artifacts.event_stream),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct SuiteSummaryExtract {
    suite: Option<String>,
    run_id: Option<String>,
    status: Option<String>,
    started_at_ms: Option<u64>,
    ended_at_ms: Option<u64>,
    elapsed_seconds: Option<u64>,
    failures: Vec<SuiteFailureExtract>,
    attempts: Vec<SuiteAttemptExtract>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct SuiteFailureExtract {
    index: Option<usize>,
    kind: Option<String>,
    reason: Option<String>,
    stopped_suite: Option<bool>,
    attempt_index: Option<usize>,
    scenario: Option<String>,
    repetition: Option<usize>,
    severity: Option<String>,
    classification: Option<String>,
    evidence_classifications: Vec<String>,
    attempt_artifacts_dir: Option<String>,
    failure_summary: Option<String>,
}

impl ConsoleSuiteFailureView {
    fn from_extract(root: &Path, value: SuiteFailureExtract) -> Self {
        Self {
            index: value.index,
            kind: value.kind,
            reason: value.reason,
            stopped_suite: value.stopped_suite,
            attempt_index: value.attempt_index,
            scenario: value.scenario,
            repetition: value.repetition,
            severity: value.severity,
            classification: value.classification,
            evidence_classifications: value.evidence_classifications,
            attempt_artifacts_dir: view_artifact_path_opt(root, value.attempt_artifacts_dir),
            failure_summary: view_artifact_path_opt(root, value.failure_summary),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct SuiteAttemptExtract {
    index: Option<usize>,
    scenario: Option<String>,
    repetition: Option<usize>,
    status: Option<String>,
    started_at_ms: Option<u64>,
    ended_at_ms: Option<u64>,
    artifacts_dir: Option<String>,
    seed: Option<u64>,
    client_disruptions: Option<usize>,
    recommitted: Option<usize>,
    committed: Option<usize>,
    severity: Option<String>,
    classification: Option<String>,
    evidence_classifications: Vec<String>,
    error: Option<String>,
}

impl ConsoleSuiteAttemptView {
    fn from_extract(root: &Path, value: SuiteAttemptExtract) -> Self {
        Self {
            index: value.index,
            scenario: value.scenario,
            repetition: value.repetition,
            status: value.status,
            started_at_ms: value.started_at_ms,
            ended_at_ms: value.ended_at_ms,
            artifacts_dir: view_artifact_path_opt(root, value.artifacts_dir),
            seed: value.seed,
            client_disruptions: value.client_disruptions,
            recommitted: value.recommitted,
            committed: value.committed,
            severity: value.severity,
            classification: value.classification,
            evidence_classifications: value.evidence_classifications,
            error: value.error,
        }
    }
}

fn sort_attempts(attempts: &mut [ConsoleAttemptView]) {
    for attempt in attempts.iter_mut() {
        attempt
            .cases
            .sort_by(|left, right| left.artifact_dir.cmp(&right.artifact_dir));
    }
    attempts.sort_by(|left, right| {
        left.index
            .cmp(&right.index)
            .then_with(|| left.artifact_dir.cmp(&right.artifact_dir))
    });
}

fn infer_attempt_and_case_dirs(root: &Path, artifact_path: &Path) -> (PathBuf, PathBuf) {
    let case_dir = artifact_path.parent().unwrap_or(root).to_path_buf();
    let attempt_dir = case_dir.parent().unwrap_or(root).to_path_buf();
    (attempt_dir, case_dir)
}

fn artifact_text_path(root: &Path, path: &str) -> PathBuf {
    let candidate = PathBuf::from(path);
    if candidate.is_absolute() || candidate.exists() {
        candidate
    } else {
        root.join(candidate)
    }
}

fn view_artifact_path_opt(root: &Path, path: Option<String>) -> Option<String> {
    path.map(|path| view_artifact_path(root, path))
}

fn view_artifact_path(root: &Path, path: String) -> String {
    let candidate = PathBuf::from(&path);
    if candidate.is_absolute() {
        return display_path(root, &candidate);
    }
    if relative_path_can_be_root_joined(&candidate) {
        return display_path(root, &root.join(candidate));
    }
    path
}

fn relative_path_can_be_root_joined(path: &Path) -> bool {
    path.components().all(|component| {
        !matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    })
}

fn keyed_display_path(root: &Path, path: &Path) -> (String, String) {
    (
        canonical_key(path),
        if path.exists() {
            display_path(root, path)
        } else {
            path.display().to_string()
        },
    )
}

fn canonical_key(path: &Path) -> String {
    fs::canonicalize(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .display()
        .to_string()
}

fn display_path(root: &Path, path: &Path) -> String {
    let canonical_root = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let canonical_path = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    canonical_path
        .strip_prefix(&canonical_root)
        .ok()
        .and_then(|relative| {
            let value = relative.display().to_string();
            (!value.is_empty()).then_some(value)
        })
        .unwrap_or_else(|| path.display().to_string())
}

fn should_warn_missing_failure_summary(
    suite_summary: Option<&ConsoleSuiteSummaryView>,
    attempts: &[ConsoleAttemptView],
) -> bool {
    suite_summary.is_some_and(|summary| {
        summary
            .attempts
            .iter()
            .any(|attempt| attempt.status.as_deref() == Some("failed"))
            || summary.failures.iter().any(|failure| {
                failure.attempt_index.is_some()
                    || failure.failure_summary.is_some()
                    || failure.kind.as_deref() == Some("attempt_failure")
            })
    }) || attempts
        .iter()
        .any(|attempt| attempt.status.as_deref() == Some("failed"))
}

fn should_warn_missing_runner_failure_summary(exit_codes: &[ConsoleExitCodeView]) -> bool {
    exit_codes
        .iter()
        .any(|exit_code| exit_code.code.is_some_and(|code| code != 0))
}

fn file_name_string(path: &Path) -> Option<String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(ToString::to_string)
}

fn fill_if_none(target: &mut Option<String>, value: Option<String>) {
    if target.is_none() {
        *target = value;
    }
}

fn push_warning(
    warnings: &mut Vec<ConsoleWarning>,
    artifact: impl Into<String>,
    path: impl Into<String>,
    message: impl Into<String>,
) {
    warnings.push(ConsoleWarning {
        artifact: artifact.into(),
        path: path.into(),
        message: message.into(),
    });
}

fn json_string(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

fn json_bool(value: &Value, key: &str) -> Option<bool> {
    value.get(key).and_then(Value::as_bool)
}

fn json_i64(value: &Value, key: &str) -> Option<i64> {
    value.get(key).and_then(Value::as_i64)
}

fn json_u64(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(Value::as_u64)
}

fn json_string_array(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{
        ArtifactIndex, ArtifactScanLimits, MAX_JSON_ARTIFACT_BYTES, build_console_snapshot,
    };
    use serde_json::json;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn missing_optional_files_emit_warnings() {
        let dir = tempfile::tempdir().expect("tempdir");

        let snapshot = build_console_snapshot(dir.path()).expect("snapshot");

        assert!(snapshot.suite_plan.is_none());
        assert!(snapshot.suite_summary.is_none());
        assert!(snapshot.attempts.is_empty());
        assert!(snapshot.warnings.iter().any(|warning| {
            warning.artifact == "suite-plan.json" && warning.message.contains("missing")
        }));
        assert!(snapshot.warnings.iter().any(|warning| {
            warning.artifact == "run-events.jsonl" && warning.message.contains("found yet")
        }));
        assert!(snapshot.warnings.iter().any(|warning| {
            warning.artifact == "exit-code" && warning.message.contains("found yet")
        }));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_escape_before_reading_suite_plan() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().expect("tempdir");
        let outside = tempfile::tempdir().expect("outside tempdir");
        let outside_plan = outside.path().join("suite-plan.json");
        fs::write(
            &outside_plan,
            serde_json::to_string_pretty(&json!({
                "suite": "escaped",
                "runId": "run-outside",
                "attempts": []
            }))
            .expect("plan json"),
        )
        .expect("outside plan");
        symlink(&outside_plan, dir.path().join("suite-plan.json")).expect("symlink");

        let snapshot = build_console_snapshot(dir.path()).expect("snapshot");

        assert!(snapshot.suite_plan.is_none());
        assert!(snapshot.warnings.iter().any(|warning| {
            warning.artifact == "suite-plan.json"
                && warning.message.contains("escape outside artifact root")
        }));
    }

    #[test]
    fn uses_unique_nested_suite_run_root_from_outer_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        let suite_root = dir.path().join("smoke").join("suite-1");
        fs::create_dir_all(&suite_root).expect("suite root");
        fs::write(
            suite_root.join("suite-plan.json"),
            serde_json::to_string_pretty(&json!({
                "suite": "smoke",
                "runId": "suite-1",
                "artifactRoot": suite_root.display().to_string(),
                "attempts": []
            }))
            .expect("plan json"),
        )
        .expect("plan");
        fs::write(
            suite_root.join("suite-summary.json"),
            serde_json::to_string_pretty(&json!({
                "suite": "smoke",
                "runId": "suite-1",
                "status": "succeeded",
                "attempts": []
            }))
            .expect("summary json"),
        )
        .expect("summary");

        let snapshot = build_console_snapshot(dir.path()).expect("snapshot");

        assert_eq!(
            snapshot.artifact_root,
            fs::canonicalize(&suite_root)
                .expect("canonical suite root")
                .display()
                .to_string()
        );
        assert_eq!(
            snapshot
                .suite_plan
                .as_ref()
                .and_then(|plan| plan.suite.as_deref()),
            Some("smoke")
        );
        assert!(
            !snapshot
                .warnings
                .iter()
                .any(|warning| warning.artifact == "suite-run-root")
        );
    }

    #[test]
    fn keeps_outer_root_when_multiple_nested_suite_run_roots_exist() {
        let dir = tempfile::tempdir().expect("tempdir");
        for name in ["suite-a", "suite-b"] {
            let suite_root = dir.path().join(name).join("suite-1");
            fs::create_dir_all(&suite_root).expect("suite root");
            fs::write(
                suite_root.join("suite-summary.json"),
                serde_json::to_string_pretty(&json!({
                    "suite": name,
                    "runId": "suite-1",
                    "status": "succeeded",
                    "attempts": []
                }))
                .expect("summary json"),
            )
            .expect("summary");
        }

        let snapshot = build_console_snapshot(dir.path()).expect("snapshot");

        assert_eq!(
            snapshot.artifact_root,
            fs::canonicalize(dir.path())
                .expect("canonical outer root")
                .display()
                .to_string()
        );
        assert!(snapshot.suite_summary.is_none());
        assert!(snapshot.warnings.iter().any(|warning| {
            warning.artifact == "suite-run-root"
                && warning.message.contains("multiple nested suite run roots")
                && warning.message.contains("suite-a")
                && warning.message.contains("suite-b")
        }));
    }

    #[test]
    fn aggregates_suite_summary_attempt_events_and_failure_summary() {
        let dir = tempfile::tempdir().expect("tempdir");
        let attempt_dir = dir.path().join("001-io-eio-r1");
        let case_dir = attempt_dir.join("fault_io_eio_preserves_committed_objects");
        let raw_attempt_dir = attempt_dir.display().to_string();
        let raw_failure_summary = case_dir.join("failure-summary.json").display().to_string();
        fs::create_dir_all(&case_dir).expect("case dir");
        fs::write(
            dir.path().join("suite-summary.json"),
            serde_json::to_string_pretty(&json!({
                "apiVersion": "rustfs.com/s3chaos/v1alpha1",
                "kind": "FaultSuiteRun",
                "suite": "smoke",
                "runId": "suite-1",
                "status": "failed",
                "startedAtMs": 10,
                "endedAtMs": 20,
                "elapsedSeconds": 10,
                "failures": [{
                    "index": 1,
                    "kind": "attempt_failure",
                    "reason": "recovery tail reread latency",
                    "stoppedSuite": false,
                    "attemptIndex": 1,
                    "scenario": "io-eio",
                    "repetition": 1,
                    "severity": "degraded",
                    "classification": "recovery_tail_read_latency",
                    "attemptArtifactsDir": raw_attempt_dir.clone(),
                    "failureSummary": raw_failure_summary.clone()
                }],
                "attempts": [{
                    "index": 1,
                    "scenario": "io-eio",
                    "repetition": 1,
                    "status": "failed",
                    "startedAtMs": 10,
                    "endedAtMs": 20,
                    "artifactsDir": raw_attempt_dir.clone(),
                    "severity": "degraded",
                    "classification": "recovery_tail_read_latency"
                }]
            }))
            .expect("summary json"),
        )
        .expect("summary");
        fs::write(
            case_dir.join("run-events.jsonl"),
            [
                json!({"at_ms":10,"scenario":"io-eio","run_id":"run-1","stage":"run","status":"started","message":"run started"}).to_string(),
                json!({"at_ms":20,"scenario":"io-eio","run_id":"run-1","stage":"checker-final","status":"succeeded","message":"checker final succeeded"}).to_string(),
            ]
            .join("\n"),
        )
        .expect("events");
        fs::write(
            case_dir.join("failure-summary.json"),
            serde_json::to_string_pretty(&json!({
                "scenario": "io-eio",
                "stage": "checker-pre-recommit",
                "verdict": "failed",
                "severity": "degraded",
                "classification": "recovery_tail_read_latency",
                "data_correctness": "passed",
                "availability": "recovered_after_tail_latency",
                "evidence_classifications": ["recovery_tail_read_latency"],
                "data_loss": false,
                "corruption": false,
                "recovered_within_window": true,
                "recovered_within_seconds": 37,
                "message": "strict checker failed before bounded reread recovered"
            }))
            .expect("failure json"),
        )
        .expect("failure");
        let test_log = case_dir.join("test.log");
        let raw_test_log = test_log.display().to_string();
        fs::write(&test_log, "runner log").expect("test log");
        fs::write(
            case_dir.join("runner-failure-summary.json"),
            serde_json::to_string_pretty(&json!({
                "scenario": "io-eio",
                "stage": "runner",
                "exit_code": 1,
                "rust_failure_summary_present": true,
                "test_log": raw_test_log.clone()
            }))
            .expect("runner failure json"),
        )
        .expect("runner failure");

        let snapshot = build_console_snapshot(dir.path()).expect("snapshot");
        let expected_attempt_dir = PathBuf::from("001-io-eio-r1").display().to_string();
        let expected_failure_summary = PathBuf::from("001-io-eio-r1")
            .join("fault_io_eio_preserves_committed_objects")
            .join("failure-summary.json")
            .display()
            .to_string();
        let expected_test_log = PathBuf::from("001-io-eio-r1")
            .join("fault_io_eio_preserves_committed_objects")
            .join("test.log")
            .display()
            .to_string();

        assert_eq!(
            snapshot
                .suite_summary
                .as_ref()
                .and_then(|s| s.status.as_deref()),
            Some("failed")
        );
        let suite_summary = snapshot.suite_summary.as_ref().expect("suite summary");
        assert_eq!(
            suite_summary.attempts[0].artifacts_dir.as_deref(),
            Some(expected_attempt_dir.as_str())
        );
        assert_eq!(
            suite_summary.failures[0].attempt_artifacts_dir.as_deref(),
            Some(expected_attempt_dir.as_str())
        );
        assert_eq!(
            suite_summary.failures[0].failure_summary.as_deref(),
            Some(expected_failure_summary.as_str())
        );
        assert_eq!(
            suite_summary.raw["failures"][0]["attemptArtifactsDir"].as_str(),
            Some(raw_attempt_dir.as_str())
        );
        assert_eq!(
            suite_summary.raw["failures"][0]["failureSummary"].as_str(),
            Some(raw_failure_summary.as_str())
        );
        assert_eq!(snapshot.attempts.len(), 1);
        let attempt = &snapshot.attempts[0];
        assert_eq!(attempt.index, Some(1));
        assert_eq!(attempt.scenario.as_deref(), Some("io-eio"));
        assert_eq!(attempt.severity.as_deref(), Some("degraded"));
        assert_eq!(
            attempt.classification.as_deref(),
            Some("recovery_tail_read_latency")
        );
        assert_eq!(attempt.cases.len(), 1);
        let case = &attempt.cases[0];
        assert_eq!(case.event_count, 2);
        assert_eq!(case.last_stage.as_deref(), Some("checker-final"));
        assert_eq!(case.last_status.as_deref(), Some("succeeded"));
        assert_eq!(
            case.failure_summary
                .as_ref()
                .and_then(|summary| summary.classification.as_deref()),
            Some("recovery_tail_read_latency")
        );
        assert_eq!(snapshot.runner_failures.len(), 1);
        assert_eq!(
            snapshot.runner_failures[0].test_log.as_deref(),
            Some(expected_test_log.as_str())
        );
        assert_eq!(
            snapshot.runner_failures[0].raw["test_log"].as_str(),
            Some(raw_test_log.as_str())
        );
    }

    #[test]
    fn promotes_finalizer_recovery_events_to_console_warnings() {
        let dir = tempfile::tempdir().expect("tempdir");
        let case_dir = dir
            .path()
            .join("001-io-eio-r1")
            .join("fault_io_eio_preserves_committed_objects");
        fs::create_dir_all(&case_dir).expect("case dir");
        fs::write(
            case_dir.join("run-events.jsonl"),
            [
                json!({"at_ms":10,"scenario":"io-eio","run_id":"run-1","stage":"fault-delete","status":"succeeded","message":"patched stuck IOChaos finalizer after recovery evidence","details":{"warning_artifact":"iochaos-finalizer-recovery-warning.json","iochaos":"io-eio-run-1"}}).to_string(),
                json!({"at_ms":20,"scenario":"io-eio","run_id":"run-1","stage":"checker-final","status":"succeeded","message":"checker final succeeded"}).to_string(),
            ]
            .join("\n"),
        )
        .expect("events");

        let snapshot = build_console_snapshot(dir.path()).expect("snapshot");

        assert!(snapshot.warnings.iter().any(|warning| {
            warning.artifact == "iochaos-finalizer-recovery-warning.json"
                && warning.message.contains("patched stuck IOChaos finalizer")
        }));
    }

    #[test]
    fn malformed_trailing_jsonl_marks_attempt_invalid() {
        let dir = tempfile::tempdir().expect("tempdir");
        let attempt_dir = dir.path().join("001-io-eio-r1");
        let case_dir = attempt_dir.join("fault_io_eio_preserves_committed_objects");
        fs::create_dir_all(&case_dir).expect("case dir");
        fs::write(
            dir.path().join("suite-summary.json"),
            serde_json::to_string_pretty(&json!({
                "suite": "smoke",
                "runId": "suite-1",
                "status": "succeeded",
                "attempts": [{
                    "index": 1,
                    "scenario": "io-eio",
                    "repetition": 1,
                    "status": "succeeded",
                    "artifactsDir": attempt_dir.display().to_string()
                }]
            }))
            .expect("summary json"),
        )
        .expect("summary");
        fs::write(
            case_dir.join("run-events.jsonl"),
            [
                json!({"at_ms":20,"scenario":"io-eio","stage":"checker-final","status":"succeeded"}).to_string(),
                "{\"at_ms\":21,\"scenario\":\"io-eio\",\"stage\":\"tail\"".to_string(),
            ]
            .join("\n"),
        )
        .expect("events");

        let snapshot = build_console_snapshot(dir.path()).expect("snapshot");

        let attempt = snapshot
            .attempts
            .iter()
            .find(|attempt| attempt.index == Some(1))
            .expect("attempt");
        assert_eq!(attempt.status.as_deref(), Some("invalid"));
        assert_eq!(attempt.cases.len(), 1);
        assert_eq!(attempt.cases[0].last_status.as_deref(), Some("invalid"));
        assert!(snapshot.warnings.iter().any(|warning| {
            warning.artifact == "run-events.jsonl"
                && warning.message.contains("could not parse jsonl line 2")
        }));
    }

    #[test]
    fn scan_and_read_limits_emit_warnings() {
        let file_limit_dir = tempfile::tempdir().expect("file limit tempdir");
        fs::write(file_limit_dir.path().join("a.txt"), "a").expect("a");
        fs::write(file_limit_dir.path().join("b.txt"), "b").expect("b");
        let mut warnings = Vec::new();
        let _index = ArtifactIndex::collect_with_limits(
            file_limit_dir.path(),
            &mut warnings,
            ArtifactScanLimits {
                max_depth: 8,
                max_files: 1,
            },
        );
        assert!(warnings.iter().any(|warning| {
            warning.artifact == "artifact-dir"
                && warning.message.contains("scan file limit reached")
        }));

        let depth_limit_dir = tempfile::tempdir().expect("depth limit tempdir");
        fs::create_dir_all(depth_limit_dir.path().join("nested")).expect("nested");
        let _index = ArtifactIndex::collect_with_limits(
            depth_limit_dir.path(),
            &mut warnings,
            ArtifactScanLimits {
                max_depth: 0,
                max_files: 10,
            },
        );
        assert!(warnings.iter().any(|warning| {
            warning.artifact == "artifact-dir"
                && warning.message.contains("scan depth limit reached")
        }));

        let read_limit_dir = tempfile::tempdir().expect("read limit tempdir");
        let oversized = format!(
            "{{\"padding\":\"{}\"}}",
            "x".repeat(MAX_JSON_ARTIFACT_BYTES as usize + 1)
        );
        fs::write(read_limit_dir.path().join("suite-summary.json"), oversized)
            .expect("oversized summary");

        let snapshot = build_console_snapshot(read_limit_dir.path()).expect("snapshot");

        assert!(snapshot.suite_summary.is_none());
        assert!(snapshot.warnings.iter().any(|warning| {
            warning.artifact == "suite-summary.json" && warning.message.contains("read limit")
        }));
    }

    #[test]
    fn missing_failure_artifacts_warn_only_when_failed_state_needs_them() {
        let succeeded = tempfile::tempdir().expect("succeeded tempdir");
        fs::write(
            succeeded.path().join("suite-summary.json"),
            serde_json::to_string_pretty(&json!({
                "suite": "smoke",
                "runId": "suite-1",
                "status": "succeeded",
                "attempts": [{
                    "index": 1,
                    "scenario": "io-eio",
                    "repetition": 1,
                    "status": "succeeded",
                    "artifactsDir": "001-io-eio-r1"
                }]
            }))
            .expect("summary json"),
        )
        .expect("summary");
        fs::write(succeeded.path().join("suite-exit-code"), "0").expect("exit code");

        let succeeded_snapshot = build_console_snapshot(succeeded.path()).expect("snapshot");

        assert!(
            !succeeded_snapshot
                .warnings
                .iter()
                .any(|warning| warning.artifact == "failure-summary.json")
        );
        assert!(
            !succeeded_snapshot
                .warnings
                .iter()
                .any(|warning| warning.artifact == "runner-failure-summary.json")
        );

        let failed = tempfile::tempdir().expect("failed tempdir");
        fs::write(
            failed.path().join("suite-summary.json"),
            serde_json::to_string_pretty(&json!({
                "suite": "smoke",
                "runId": "suite-1",
                "status": "failed",
                "failures": [{
                    "kind": "attempt_failure",
                    "attemptIndex": 1,
                    "failureSummary": "001-io-eio-r1/case/failure-summary.json"
                }],
                "attempts": [{
                    "index": 1,
                    "scenario": "io-eio",
                    "repetition": 1,
                    "status": "failed",
                    "artifactsDir": "001-io-eio-r1"
                }]
            }))
            .expect("summary json"),
        )
        .expect("summary");
        fs::write(failed.path().join("suite-exit-code"), "1").expect("exit code");

        let failed_snapshot = build_console_snapshot(failed.path()).expect("snapshot");

        assert!(failed_snapshot.warnings.iter().any(|warning| {
            warning.artifact == "failure-summary.json"
                && warning.message.contains("failed attempt state")
        }));
        assert!(failed_snapshot.warnings.iter().any(|warning| {
            warning.artifact == "runner-failure-summary.json"
                && warning.message.contains("nonzero exit-code")
        }));
    }

    #[test]
    fn parses_legacy_health_watch_log() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(
            dir.path().join("health-watch.log"),
            [
                "2026-07-05T01:00:00Z safe=true",
                "2026-07-05T01:00:10Z safe=false",
                "2026-07-05T01:00:20Z budget=false maxDurationSeconds=120 elapsedSeconds=120",
            ]
            .join("\n"),
        )
        .expect("health log");

        let snapshot = build_console_snapshot(dir.path()).expect("snapshot");

        assert_eq!(snapshot.health.len(), 1);
        assert_eq!(snapshot.health[0].format, "legacy-log");
        assert_eq!(snapshot.health[0].samples.len(), 3);
        assert_eq!(snapshot.health[0].samples[0].safe, Some(true));
        assert_eq!(snapshot.health[0].samples[1].safe, Some(false));
        assert_eq!(snapshot.health[0].samples[2].budget, Some(false));
        assert_eq!(
            snapshot.health[0].samples[2]
                .fields
                .get("maxDurationSeconds")
                .map(String::as_str),
            Some("120")
        );
    }

    #[test]
    fn prefers_health_jsonl_over_same_directory_legacy_log() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(
            dir.path().join("health-watch.log"),
            [
                "2026-07-05T01:00:00Z safe=true",
                "2026-07-05T01:00:10Z safe=false",
            ]
            .join("\n"),
        )
        .expect("health log");
        fs::write(
            dir.path().join("health-watch.jsonl"),
            json!({
                "at": "2026-07-05T01:00:10Z",
                "safe": false,
                "budget": true
            })
            .to_string(),
        )
        .expect("health jsonl");

        let snapshot = build_console_snapshot(dir.path()).expect("snapshot");

        assert_eq!(snapshot.health.len(), 1);
        assert_eq!(snapshot.health[0].artifact, "health-watch.jsonl");
        assert_eq!(snapshot.health[0].format, "jsonl");
        assert_eq!(snapshot.health[0].samples.len(), 1);
        assert_eq!(snapshot.health[0].samples[0].safe, Some(false));
    }
}
