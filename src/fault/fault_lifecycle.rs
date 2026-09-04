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

use crate::{
    fault::{
        backends::host::DmStatusSnapshot, config::FaultTestConfig,
        fault_artifacts::FaultFailureArtifactSource, reporting::FaultStatusSnapshot,
    },
    framework::artifacts::ArtifactCollector,
};
use anyhow::{Result, ensure};
use std::time::{Duration, Instant};

pub(super) trait FaultLifecyclePort {
    fn wait_active(&self, timeout: Duration) -> Result<()>;
    fn ensure_active(&self, stage: &str) -> Result<()>;
    fn requires_recovery_boundary(&self) -> bool {
        false
    }
    fn prepare_recovery_boundary(&mut self, _timeout: Duration, _started_at_ms: u64) -> Result<()> {
        Ok(())
    }
    fn delete(&mut self, timeout: Duration) -> Result<()>;
    fn snapshot(&self, stage: &str) -> Result<FaultStatusSnapshot>;

    fn recovery_dm_snapshot(&self) -> Option<DmStatusSnapshot> {
        None
    }

    fn failure_artifacts(&self) -> Option<&dyn FaultFailureArtifactSource> {
        None
    }

    fn recover_delete_timeout(
        &mut self,
        _request: &FaultDeleteTimeoutRecoveryRequest<'_>,
    ) -> Result<Option<FaultDeleteTimeoutRecovery>> {
        Ok(None)
    }
}

pub(super) type AppliedFault = Box<dyn FaultLifecyclePort>;

pub(super) struct AppliedFaults {
    items: Vec<AppliedFault>,
}

impl AppliedFaults {
    pub(super) fn new(items: Vec<AppliedFault>) -> Self {
        Self { items }
    }

    pub(super) fn len(&self) -> usize {
        self.items.len()
    }

    pub(super) fn wait_active(&self, timeout: Duration) -> Result<()> {
        for fault in &self.items {
            fault.wait_active(timeout)?;
        }
        Ok(())
    }

    pub(super) fn ensure_active(&self, stage: &str) -> Result<()> {
        for fault in &self.items {
            fault.ensure_active(stage)?;
        }
        Ok(())
    }

    pub(super) fn requires_recovery_boundary(&self) -> bool {
        self.items
            .iter()
            .any(|fault| fault.requires_recovery_boundary())
    }

    pub(super) fn prepare_recovery_boundary(
        &mut self,
        timeout: Duration,
        started_at_ms: u64,
    ) -> Result<()> {
        for fault in self.items.iter_mut().rev() {
            if fault.requires_recovery_boundary() {
                fault.prepare_recovery_boundary(timeout, started_at_ms)?;
            }
        }
        Ok(())
    }

    pub(super) fn delete(&mut self, timeout: Duration) -> Result<()> {
        for fault in self.items.iter_mut().rev() {
            fault.delete(timeout)?;
        }
        Ok(())
    }

    pub(super) fn snapshot(&self, stage: &str) -> Result<FaultStatusSnapshot> {
        ensure!(
            self.items.len() == 1,
            "single fault snapshot requested for {} applied faults",
            self.items.len()
        );
        self.items[0].snapshot(stage)
    }

    pub(super) fn snapshots(&self, stage: &str) -> Result<Vec<FaultStatusSnapshot>> {
        self.items
            .iter()
            .map(|fault| fault.snapshot(stage))
            .collect()
    }

    pub(super) fn recovery_dm_snapshot(&self) -> Option<DmStatusSnapshot> {
        self.items
            .iter()
            .find_map(|fault| fault.recovery_dm_snapshot())
    }

    pub(super) fn failure_artifacts(&self) -> Vec<&dyn FaultFailureArtifactSource> {
        self.items
            .iter()
            .filter_map(|fault| fault.failure_artifacts())
            .collect()
    }

    pub(super) fn recover_delete_timeout_with(
        &mut self,
        request: &FaultDeleteTimeoutRecoveryRequest<'_>,
    ) -> Result<Option<FaultDeleteTimeoutRecovery>> {
        if self.items.len() != 1 {
            return Ok(None);
        }
        self.items[0].as_mut().recover_delete_timeout(request)
    }
}

pub(super) struct FaultDeleteTimeoutRecoveryRequest<'a> {
    pub(super) config: &'a FaultTestConfig,
    pub(super) collector: &'a ArtifactCollector,
    pub(super) case_name: &'a str,
    pub(super) run_id: &'a str,
    pub(super) original_error: &'a anyhow::Error,
    pub(super) delete_started_at: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct FaultDeleteTimeoutRecovery {
    pub(super) warning_artifact: &'static str,
    pub(super) resource_name: String,
    pub(super) target_nodes: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::{
        AppliedFaults, FaultDeleteTimeoutRecovery, FaultDeleteTimeoutRecoveryRequest,
        FaultLifecyclePort,
    };
    use crate::fault::{
        backends::host::{DmStatusSnapshot, DmVolumeMapping},
        config::FaultTestConfig,
        host_storage::{HostStorageNodeSelector, HostStoragePersistentVolumeClaimRef},
        reporting::FaultStatusSnapshot,
    };
    use crate::framework::artifacts::ArtifactCollector;
    use anyhow::{Result, anyhow};
    use std::{
        cell::RefCell,
        collections::BTreeMap,
        rc::Rc,
        time::{Duration, Instant},
    };

    #[derive(Default)]
    struct RecordingFaultState {
        waits: Vec<(&'static str, Duration)>,
        deletes: Vec<(&'static str, Duration)>,
        recoveries: Vec<&'static str>,
    }

    type SharedRecordingFaultState = Rc<RefCell<RecordingFaultState>>;

    struct RecordingFault {
        name: &'static str,
        state: SharedRecordingFaultState,
        recovery_dm_snapshot: Option<DmStatusSnapshot>,
    }

    impl RecordingFault {
        fn new(name: &'static str, state: SharedRecordingFaultState) -> Self {
            Self {
                name,
                state,
                recovery_dm_snapshot: None,
            }
        }

        fn with_recovery_dm_snapshot(mut self, snapshot: DmStatusSnapshot) -> Self {
            self.recovery_dm_snapshot = Some(snapshot);
            self
        }
    }

    impl FaultLifecyclePort for RecordingFault {
        fn wait_active(&self, timeout: Duration) -> Result<()> {
            self.state.borrow_mut().waits.push((self.name, timeout));
            Ok(())
        }

        fn ensure_active(&self, _stage: &str) -> Result<()> {
            Ok(())
        }

        fn delete(&mut self, timeout: Duration) -> Result<()> {
            self.state.borrow_mut().deletes.push((self.name, timeout));
            Ok(())
        }

        fn snapshot(&self, stage: &str) -> Result<FaultStatusSnapshot> {
            Ok(FaultStatusSnapshot {
                stage: stage.to_string(),
                resource_kind: Some("recording".to_string()),
                resource_name: Some(self.name.to_string()),
                chaos_status: None,
                dm_status: None,
            })
        }

        fn recovery_dm_snapshot(&self) -> Option<DmStatusSnapshot> {
            self.recovery_dm_snapshot.clone()
        }

        fn recover_delete_timeout(
            &mut self,
            _request: &FaultDeleteTimeoutRecoveryRequest<'_>,
        ) -> Result<Option<FaultDeleteTimeoutRecovery>> {
            self.state.borrow_mut().recoveries.push(self.name);
            Ok(None)
        }
    }

    fn recording_state() -> SharedRecordingFaultState {
        Rc::new(RefCell::new(RecordingFaultState::default()))
    }

    fn recording_dm_snapshot(stage: &str, helper_pod: &str) -> DmStatusSnapshot {
        DmStatusSnapshot {
            stage: stage.to_string(),
            helper_pod: helper_pod.to_string(),
            mapping: DmVolumeMapping {
                node: "node-a".to_string(),
                node_uid: "node-uid-a".to_string(),
                node_labels: BTreeMap::from([(
                    "kubernetes.io/hostname".to_string(),
                    "node-a".to_string(),
                )]),
                pod: "rustfs-0".to_string(),
                pod_uid: "pod-uid-a".to_string(),
                volume_name: "data".to_string(),
                pvc: "data-rustfs-0".to_string(),
                pvc_uid: "pvc-uid-a".to_string(),
                pvc_phase: "Bound".to_string(),
                pv: "pv-a".to_string(),
                pv_uid: "pv-uid-a".to_string(),
                pv_phase: "Bound".to_string(),
                pv_claim_ref: HostStoragePersistentVolumeClaimRef {
                    namespace: "rustfs-fault-test".to_string(),
                    name: "data-rustfs-0".to_string(),
                    uid: "pvc-uid-a".to_string(),
                },
                node_selector: HostStorageNodeSelector {
                    key: "kubernetes.io/hostname".to_string(),
                    operator: "In".to_string(),
                    values: vec!["node-a".to_string()],
                },
                container_mount_path: "/data/rustfs0".to_string(),
                mount_path: "/data/rustfs0".to_string(),
            },
            table: "0 2048 flakey /dev/sda 0 1 1".to_string(),
            status: "0 2048 flakey 1 0".to_string(),
        }
    }

    fn recovery_request<'a>(
        config: &'a FaultTestConfig,
        collector: &'a ArtifactCollector,
        original_error: &'a anyhow::Error,
    ) -> FaultDeleteTimeoutRecoveryRequest<'a> {
        FaultDeleteTimeoutRecoveryRequest {
            config,
            collector,
            case_name: "case",
            run_id: "run-123",
            original_error,
            delete_started_at: Instant::now(),
        }
    }

    #[test]
    fn applied_faults_wait_active_visits_ports_in_insert_order() {
        let state = recording_state();
        let faults = AppliedFaults::new(vec![
            Box::new(RecordingFault::new("first", state.clone())),
            Box::new(RecordingFault::new("second", state.clone())),
            Box::new(RecordingFault::new("third", state.clone())),
        ]);

        faults
            .wait_active(Duration::from_secs(7))
            .expect("wait active");

        assert_eq!(
            state.borrow().waits.as_slice(),
            &[
                ("first", Duration::from_secs(7)),
                ("second", Duration::from_secs(7)),
                ("third", Duration::from_secs(7)),
            ]
        );
    }

    #[test]
    fn applied_faults_delete_visits_ports_in_reverse_order() {
        let state = recording_state();
        let mut faults = AppliedFaults::new(vec![
            Box::new(RecordingFault::new("first", state.clone())),
            Box::new(RecordingFault::new("second", state.clone())),
            Box::new(RecordingFault::new("third", state.clone())),
        ]);

        faults
            .delete(Duration::from_secs(1))
            .expect("delete faults");

        assert_eq!(
            state.borrow().deletes.as_slice(),
            &[
                ("third", Duration::from_secs(1)),
                ("second", Duration::from_secs(1)),
                ("first", Duration::from_secs(1)),
            ]
        );
    }

    #[test]
    fn applied_faults_single_snapshot_rejects_multiple_ports() {
        let state = recording_state();
        let faults = AppliedFaults::new(vec![
            Box::new(RecordingFault::new("first", state.clone())),
            Box::new(RecordingFault::new("second", state)),
        ]);

        let error = faults
            .snapshot("after-workload")
            .expect_err("snapshot error");

        assert!(
            error
                .to_string()
                .contains("single fault snapshot requested for 2 applied faults")
        );
    }

    #[test]
    fn applied_faults_delete_timeout_recovery_skips_multiple_ports() {
        let state = recording_state();
        let mut faults = AppliedFaults::new(vec![
            Box::new(RecordingFault::new("first", state.clone())),
            Box::new(RecordingFault::new("second", state.clone())),
        ]);
        let tempdir = tempfile::tempdir().expect("tempdir");
        let collector = ArtifactCollector::new(tempdir.path());
        let config = FaultTestConfig::for_test("k3s-s3chaos", "local-path");
        let original_error = anyhow!("delete timed out");

        let recovery = faults
            .recover_delete_timeout_with(&recovery_request(&config, &collector, &original_error))
            .expect("recovery decision");

        assert!(recovery.is_none());
        assert!(
            state.borrow().recoveries.is_empty(),
            "multi fault recovery must not dispatch to a single backend"
        );
    }

    #[test]
    fn applied_faults_recovery_dm_snapshot_returns_first_available_snapshot() {
        let state = recording_state();
        let faults = AppliedFaults::new(vec![
            Box::new(RecordingFault::new("none", state.clone())),
            Box::new(
                RecordingFault::new("first", state.clone())
                    .with_recovery_dm_snapshot(recording_dm_snapshot("recovered", "helper-a")),
            ),
            Box::new(
                RecordingFault::new("second", state)
                    .with_recovery_dm_snapshot(recording_dm_snapshot("recovered", "helper-b")),
            ),
        ]);

        let snapshot = faults
            .recovery_dm_snapshot()
            .expect("first recovery dm snapshot");

        assert_eq!(snapshot.helper_pod, "helper-a");
    }
}
