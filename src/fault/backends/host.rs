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

use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use serde_json::Value;
use std::{
    thread::sleep,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crate::{
    fault::{
        config::FaultTestConfig,
        host_storage::{
            HostStorageAllowlist, HostStorageMutationIntent, HostStorageMutationProof,
            HostStoragePostCleanupObservation, HostStorageTargetObservation,
            normalized_dm_table_sha256,
        },
        plan::{FaultInjection, FaultKind},
        scenarios::FaultScenario,
    },
    framework::{
        artifacts::ArtifactCollector, command::CommandOutput, command::CommandSpec,
        config::ClusterTestConfig, kubectl::Kubectl,
    },
};

const MANAGED_BY_LABEL: &str = "app.kubernetes.io/managed-by";
const MANAGED_BY_VALUE: &str = "s3chaos";
const CRASH_TAINT_KEY: &str = "s3chaos.rustfs.com/dm-crash";
const DROP_WRITES_DOWN_INTERVAL_SECONDS: u64 = 86_400;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum DmFaultBehavior {
    ErrorInjection,
    DropWritesCrash,
}

impl DmFaultBehavior {
    fn requires_crash_boundary(self) -> bool {
        matches!(self, Self::DropWritesCrash)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DmSuspendMode {
    Default,
    NoFlush,
    NoLockFs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DmMountState {
    Mounted,
    Unmounting,
    Unmounted,
    Mounting,
    Unknown,
}

impl DmMountState {
    fn proves_expected_mount(self) -> bool {
        matches!(self, Self::Mounted)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DmVolumeMapping {
    pub node: String,
    pub pod: String,
    pub pod_uid: String,
    pub pvc: String,
    pub pv: String,
    pub mount_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DmStatusSnapshot {
    pub stage: String,
    pub helper_pod: String,
    pub mapping: DmVolumeMapping,
    pub table: String,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct DmMountSnapshot {
    source: String,
    canonical_source: String,
    filesystem: String,
    options: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct DmCrashBoundarySnapshot {
    scenario: String,
    run_id: String,
    started_at_ms: u64,
    completed_at_ms: u64,
    taint: String,
    old_pod_uid: String,
    replacement_pod_uid: Option<String>,
    filesystem_unmounted: bool,
    mount_before: DmMountSnapshot,
    fault: DmStatusSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct DmCrashRecoverySnapshot {
    scenario: String,
    run_id: String,
    recovered_at_ms: u64,
    taint_removed: bool,
    mount: DmMountSnapshot,
    expected_table: String,
    fault: DmStatusSnapshot,
}

#[derive(Debug)]
pub struct DmFlakeyGuard {
    config: ClusterTestConfig,
    collector: ArtifactCollector,
    case_name: String,
    scenario: String,
    run_id: String,
    helper_pod: String,
    dm_name: String,
    behavior: DmFaultBehavior,
    fault_table: String,
    recovery_table: String,
    mapping: DmVolumeMapping,
    mount_snapshot: Option<DmMountSnapshot>,
    node_tainted: bool,
    mount_state: DmMountState,
    crash_boundary_completed: bool,
    recovery_snapshot: Option<DmStatusSnapshot>,
    preflight_proof: HostStorageMutationProof,
    fault_applied: bool,
    restored: bool,
}

#[derive(Debug)]
pub struct DmFlakeySpec<'a> {
    pub node: &'a str,
    pub mount_path: &'a str,
    pub helper_image: &'a str,
    pub name: &'a str,
    behavior: DmFaultBehavior,
    pub fault_table: Option<&'a str>,
    pub recovery_table: Option<&'a str>,
    pub run_id: &'a str,
}

pub(crate) struct FaultApplyRequest<'a> {
    pub config: &'a FaultTestConfig,
    pub collector: &'a ArtifactCollector,
    pub scenario: &'a FaultScenario,
    pub injection: &'a FaultInjection,
    pub run_id: &'a str,
    pub host_storage_proof: &'a HostStorageMutationProof,
}

pub(crate) struct HostStoragePreflightRequest<'a> {
    pub config: &'a FaultTestConfig,
    pub scenario: &'a FaultScenario,
    pub injection: &'a FaultInjection,
    pub run_id: &'a str,
    pub fault_name: &'a str,
}

pub(crate) fn apply_fault(request: &FaultApplyRequest<'_>) -> Result<DmFlakeyGuard> {
    match dm_behavior(request.injection.kind()) {
        Some(behavior) => {
            let spec = dm_flakey_spec(request.config, request.run_id, behavior)?;
            apply_dm_flakey(
                &request.config.cluster,
                &spec,
                request.collector,
                request.scenario.case_name,
                &request.scenario.name,
                request.host_storage_proof,
            )
        }
        None => bail!(
            "fault kind {} must be applied by a Chaos Mesh backend",
            request.injection.kind().as_str()
        ),
    }
}

pub(crate) fn validate_config(config: &FaultTestConfig, kind: FaultKind) -> Result<()> {
    let behavior = dm_behavior(kind)
        .with_context(|| format!("fault kind {} is not a device-mapper fault", kind.as_str()))?;
    let spec = dm_flakey_spec(config, "preflight", behavior)?;
    validate_dm_spec(&spec)?;
    ensure!(
        config
            .dm_observer_pod
            .as_deref()
            .is_some_and(|name| !name.trim().is_empty()),
        "RUSTFS_FAULT_TEST_DM_OBSERVER_POD is required for side-effect-free host observation"
    );
    ensure!(
        config
            .dm_observer_namespace
            .as_deref()
            .is_some_and(|name| !name.trim().is_empty()),
        "RUSTFS_FAULT_TEST_DM_OBSERVER_NAMESPACE is required for side-effect-free host observation"
    );
    ensure!(
        config.dm_observer_namespace.as_deref() != Some(config.cluster.test_namespace.as_str()),
        "host observer must be outside the disposable fault Tenant namespace"
    );
    ensure!(
        config.device_mapper_destructive_enabled,
        "device-mapper mutation requires RUSTFS_FAULT_TEST_DEVICE_MAPPER_DESTRUCTIVE=1"
    );
    require_exact_config_allowlist(
        "RUSTFS_FAULT_TEST_HOST_NODE_ALLOWLIST",
        &config.host_mutation_allowed_nodes,
        spec.node,
    )?;
    require_exact_config_allowlist(
        "RUSTFS_FAULT_TEST_HOST_DEVICE_ALLOWLIST",
        &config.host_mutation_allowed_devices,
        &format!("/dev/mapper/{}", spec.name),
    )?;
    ensure!(
        config.host_mutation_allowed_persistent_volumes.len() == 1
            && !config.host_mutation_allowed_persistent_volumes[0]
                .trim()
                .is_empty(),
        "RUSTFS_FAULT_TEST_HOST_PV_ALLOWLIST must contain exactly one non-empty PV name"
    );
    Ok(())
}

pub(crate) fn preflight_mutation(
    request: &HostStoragePreflightRequest<'_>,
) -> Result<HostStorageMutationProof> {
    let behavior = dm_behavior(request.injection.kind()).with_context(|| {
        format!(
            "fault kind {} is not a device-mapper mutation",
            request.injection.kind().as_str()
        )
    })?;
    validate_config(request.config, request.injection.kind())?;
    let spec = dm_flakey_spec(request.config, request.run_id, behavior)?;
    let observer_pod = request
        .config
        .dm_observer_pod
        .as_deref()
        .context("RUSTFS_FAULT_TEST_DM_OBSERVER_POD is required")?;
    let observer_namespace = request
        .config
        .dm_observer_namespace
        .as_deref()
        .context("RUSTFS_FAULT_TEST_DM_OBSERVER_NAMESPACE is required")?;
    let observation = observe_dm_target_read_only(
        &request.config.cluster,
        &spec,
        observer_namespace,
        observer_pod,
    )?;
    HostStorageMutationProof::prove_device_mapper(
        HostStorageMutationIntent {
            scenario: request.scenario.name.clone(),
            fault_name: request.fault_name.to_string(),
            fault_kind: request.injection.kind().as_str().to_string(),
            run_id: request.run_id.to_string(),
            context: request.config.cluster.context.clone(),
            namespace: request.config.cluster.test_namespace.clone(),
            tenant: request.config.cluster.tenant_name.clone(),
            observer_namespace: observer_namespace.to_string(),
            observer_pod: observer_pod.to_string(),
            backend_specific_destructive_opt_in: request.config.device_mapper_destructive_enabled,
            allowlist: HostStorageAllowlist {
                nodes: request.config.host_mutation_allowed_nodes.clone(),
                devices: request.config.host_mutation_allowed_devices.clone(),
                persistent_volumes: request
                    .config
                    .host_mutation_allowed_persistent_volumes
                    .clone(),
            },
        },
        observation,
    )
}

fn dm_behavior(kind: FaultKind) -> Option<DmFaultBehavior> {
    match kind {
        FaultKind::RustfsBlockDeviceFlakey => Some(DmFaultBehavior::ErrorInjection),
        FaultKind::RustfsBlockDeviceDropWritesCrash => Some(DmFaultBehavior::DropWritesCrash),
        _ => None,
    }
}

fn require_exact_config_allowlist(label: &str, values: &[String], expected: &str) -> Result<()> {
    ensure!(
        values.len() == 1 && values[0].trim() == expected,
        "{label} must contain exactly {expected:?}"
    );
    Ok(())
}

fn observe_dm_target_read_only(
    config: &ClusterTestConfig,
    spec: &DmFlakeySpec<'_>,
    observer_namespace: &str,
    observer_pod: &str,
) -> Result<HostStorageTargetObservation> {
    let mapping = verify_dm_volume_mapping(config, spec.node, spec.mount_path)?;
    validate_observer_pod(config, spec, observer_namespace, observer_pod)?;
    let mount_source =
        observer_findmnt_field(config, observer_namespace, observer_pod, &mapping, "SOURCE")?;
    let mount_canonical_source = observer_host_command(
        config,
        observer_namespace,
        observer_pod,
        ["/usr/bin/readlink", "-f", mount_source.as_str()],
    )?
    .stdout
    .trim()
    .to_string();
    let filesystem =
        observer_findmnt_field(config, observer_namespace, observer_pod, &mapping, "FSTYPE")?;
    let logical_device = format!("/dev/mapper/{}", spec.name);
    let canonical_device = observer_host_command(
        config,
        observer_namespace,
        observer_pod,
        ["/usr/bin/readlink", "-f", logical_device.as_str()],
    )?
    .stdout
    .trim()
    .to_string();
    ensure!(
        !canonical_device.is_empty() && canonical_device == mount_canonical_source,
        "fault-test PV mount {:?} on node {:?} does not resolve to device-mapper target {:?}",
        mapping.mount_path,
        mapping.node,
        spec.name
    );
    let original_table = observer_host_command(
        config,
        observer_namespace,
        observer_pod,
        ["/usr/sbin/dmsetup", "table", spec.name],
    )?
    .stdout;
    let recovery_table = spec
        .recovery_table
        .map(str::to_string)
        .unwrap_or_else(|| original_table.trim().to_string());
    ensure!(
        !recovery_table.trim().is_empty(),
        "dmsetup returned an empty recovery table for {:?}",
        spec.name
    );
    if spec.recovery_table.is_some() {
        ensure!(
            normalize_dm_table(&recovery_table) == normalize_dm_table(&original_table),
            "configured recovery table must match the active device-mapper table"
        );
    }
    Ok(HostStorageTargetObservation {
        node: mapping.node,
        pod: mapping.pod,
        pod_uid: mapping.pod_uid,
        persistent_volume_claim: mapping.pvc,
        persistent_volume: mapping.pv,
        persistent_volume_path: mapping.mount_path,
        mapper_name: spec.name.to_string(),
        logical_device,
        canonical_device,
        mount_source,
        mount_canonical_source,
        filesystem,
        recovery_table,
        observed_at_ms: now_ms(),
    })
}

fn validate_observer_pod(
    config: &ClusterTestConfig,
    spec: &DmFlakeySpec<'_>,
    observer_namespace: &str,
    observer_pod: &str,
) -> Result<()> {
    let pod = Kubectl::new(config)
        .namespaced(observer_namespace)
        .command(["get", "pod", observer_pod, "-o", "json"])
        .run_checked()
        .context("reading pre-provisioned host observer Pod")?;
    let pod = serde_json::from_str::<Value>(&pod.stdout).context("parse host observer Pod")?;
    ensure!(
        pod.pointer("/spec/nodeName").and_then(Value::as_str) == Some(spec.node),
        "host observer Pod is not pinned to device-mapper target node {:?}",
        spec.node
    );
    ensure!(
        pod.pointer("/metadata/labels/app.kubernetes.io~1managed-by")
            .and_then(Value::as_str)
            == Some(MANAGED_BY_VALUE)
            && pod
                .pointer("/metadata/labels/rustfs.com~1fault-host-observer")
                .and_then(Value::as_str)
                == Some("true"),
        "host observer Pod must carry s3chaos ownership and fault-host-observer labels"
    );
    ensure!(
        pod.pointer("/status/conditions")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .any(|condition| {
                condition.get("type").and_then(Value::as_str) == Some("Ready")
                    && condition.get("status").and_then(Value::as_str) == Some("True")
            }),
        "host observer Pod is not Ready"
    );
    let containers = pod
        .pointer("/spec/containers")
        .and_then(Value::as_array)
        .context("host observer Pod is missing containers")?;
    ensure!(
        containers.len() == 1,
        "host observer Pod must contain exactly one validated container"
    );
    let container = &containers[0];
    ensure!(
        container
            .pointer("/securityContext/privileged")
            .and_then(Value::as_bool)
            == Some(true),
        "host observer container must be privileged"
    );
    let host_volume_name = container
        .pointer("/volumeMounts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|mount| {
            mount.get("mountPath").and_then(Value::as_str) == Some("/host")
                && mount.get("readOnly").and_then(Value::as_bool) == Some(true)
        })
        .and_then(|mount| mount.get("name").and_then(Value::as_str));
    let host_volume_name = host_volume_name.context(
        "host observer Pod must expose /host through a read-only privileged volume mount",
    )?;
    ensure!(
        pod.pointer("/spec/volumes")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .any(|volume| {
                volume.get("name").and_then(Value::as_str) == Some(host_volume_name)
                    && volume.pointer("/hostPath/path").and_then(Value::as_str) == Some("/")
                    && volume.pointer("/hostPath/type").and_then(Value::as_str) == Some("Directory")
            }),
        "host observer Pod /host mount must reference the read-only host root"
    );
    let node = Kubectl::new(config)
        .command(["get", "node", spec.node, "-o", "json"])
        .run_checked()
        .context("reading host observer target node")?;
    let node = serde_json::from_str::<Value>(&node.stdout).context("parse host observer node")?;
    ensure!(
        !node
            .pointer("/spec/taints")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .any(|taint| taint.get("key").and_then(Value::as_str) == Some(CRASH_TAINT_KEY)),
        "device-mapper target node already has the crash-containment quarantine taint"
    );
    ensure!(
        pod.pointer("/spec/restartPolicy").and_then(Value::as_str) == Some("Never"),
        "host observer Pod restartPolicy must be Never"
    );
    Ok(())
}

fn observer_findmnt_field(
    config: &ClusterTestConfig,
    observer_namespace: &str,
    observer_pod: &str,
    mapping: &DmVolumeMapping,
    field: &str,
) -> Result<String> {
    let value = observer_host_command(
        config,
        observer_namespace,
        observer_pod,
        [
            "/usr/bin/findmnt",
            "-n",
            "-o",
            field,
            "--target",
            mapping.mount_path.as_str(),
        ],
    )?
    .stdout
    .trim()
    .to_string();
    ensure!(
        !value.is_empty(),
        "host observer findmnt returned empty {field}"
    );
    Ok(value)
}

fn observer_host_command<I, S>(
    config: &ClusterTestConfig,
    observer_namespace: &str,
    observer_pod: &str,
    args: I,
) -> Result<CommandOutput>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut command = vec![
        "exec".to_string(),
        observer_pod.to_string(),
        "--".to_string(),
        "chroot".to_string(),
        "/host".to_string(),
    ];
    command.extend(args.into_iter().map(Into::into));
    Kubectl::new(config)
        .namespaced(observer_namespace)
        .command(command)
        .run_checked()
}

fn dm_flakey_spec<'a>(
    config: &'a FaultTestConfig,
    run_id: &'a str,
    behavior: DmFaultBehavior,
) -> Result<DmFlakeySpec<'a>> {
    let name = config
        .dm_name
        .as_deref()
        .context("RUSTFS_FAULT_TEST_DM_NAME is required for dm-flakey")?;
    let fault_table = match behavior {
        DmFaultBehavior::ErrorInjection => Some(
            config
                .dm_fault_table
                .as_deref()
                .context("RUSTFS_FAULT_TEST_DM_FAULT_TABLE is required for dm-flakey")?,
        ),
        DmFaultBehavior::DropWritesCrash => None,
    };
    let node = config
        .dm_node
        .as_deref()
        .context("RUSTFS_FAULT_TEST_DM_NODE is required for dm-flakey")?;
    let mount_path = config
        .dm_mount_path
        .as_deref()
        .context("RUSTFS_FAULT_TEST_DM_MOUNT_PATH is required for dm-flakey")?;
    Ok(DmFlakeySpec {
        node,
        mount_path,
        helper_image: &config.dm_helper_image,
        name,
        behavior,
        fault_table,
        recovery_table: config.dm_recovery_table.as_deref(),
        run_id,
    })
}

pub fn apply_dm_flakey(
    config: &ClusterTestConfig,
    spec: &DmFlakeySpec<'_>,
    collector: &ArtifactCollector,
    case_name: &str,
    scenario: &str,
    preflight_proof: &HostStorageMutationProof,
) -> Result<DmFlakeyGuard> {
    validate_dm_spec(spec)?;
    let mapping = verify_dm_volume_mapping(config, spec.node, spec.mount_path)?;
    let helper_pod = helper_pod_name(spec.run_id);
    let manifest = dm_helper_manifest(config, &helper_pod, spec.node, spec.helper_image);
    collector.write_text(case_name, "dm-helper-manifest.yaml", &manifest)?;

    let kubectl = Kubectl::new(config).namespaced(&config.test_namespace);
    kubectl
        .command([
            "delete",
            "pod",
            &helper_pod,
            "--ignore-not-found",
            "--wait=true",
        ])
        .run_checked()?;
    kubectl.create_yaml_command(manifest).run_checked()?;

    let mut guard = DmFlakeyGuard {
        config: config.clone(),
        collector: collector.clone(),
        case_name: case_name.to_string(),
        scenario: scenario.to_string(),
        run_id: spec.run_id.to_string(),
        helper_pod,
        dm_name: spec.name.to_string(),
        behavior: spec.behavior,
        fault_table: String::new(),
        recovery_table: String::new(),
        mapping,
        mount_snapshot: None,
        node_tainted: false,
        mount_state: DmMountState::Unknown,
        crash_boundary_completed: false,
        recovery_snapshot: None,
        preflight_proof: preflight_proof.clone(),
        fault_applied: false,
        restored: false,
    };
    guard.wait_helper_ready()?;
    let mount_snapshot = guard.capture_mount_snapshot()?;
    guard.verify_mount_source(&mount_snapshot)?;
    guard.mount_snapshot = Some(mount_snapshot);
    guard.mount_state = DmMountState::Mounted;

    let original_table = guard.dmsetup(["table", spec.name])?.stdout;
    guard.recovery_table = spec
        .recovery_table
        .map(str::to_string)
        .unwrap_or_else(|| original_table.trim().to_string());
    ensure!(
        !guard.recovery_table.trim().is_empty(),
        "dmsetup returned an empty recovery table for {:?}",
        spec.name
    );
    if spec.recovery_table.is_some() {
        ensure!(
            normalize_dm_table(&guard.recovery_table) == normalize_dm_table(&original_table),
            "configured recovery table must match the device-mapper table that was active before injection; configured {:?}, active {:?}",
            guard.recovery_table,
            original_table
        );
    }
    let apply_observation = guard.target_observation(&guard.recovery_table)?;
    guard
        .preflight_proof
        .require_fresh_at(apply_observation.observed_at_ms)?;
    guard
        .preflight_proof
        .require_apply_observation(&apply_observation)?;

    guard.fault_table = match spec.behavior {
        DmFaultBehavior::ErrorInjection => spec
            .fault_table
            .context("dm-flakey fault table disappeared after validation")?
            .to_string(),
        DmFaultBehavior::DropWritesCrash => drop_writes_table(&guard.recovery_table)?,
    };
    let suspend_mode = match spec.behavior {
        DmFaultBehavior::ErrorInjection => DmSuspendMode::Default,
        DmFaultBehavior::DropWritesCrash => DmSuspendMode::NoLockFs,
    };
    guard.fault_applied = true;
    guard.load_table(&guard.fault_table.clone(), suspend_mode)?;
    let active = guard.snapshot("active")?;
    ensure!(
        normalize_dm_table(&active.table) == normalize_dm_table(&guard.fault_table),
        "device-mapper target did not switch to the requested fault table; requested {:?}, active {:?}",
        guard.fault_table,
        active.table
    );
    collector.write_text(
        case_name,
        "dm-flakey-active.json",
        &serde_json::to_string_pretty(&active)?,
    )?;

    Ok(guard)
}

pub fn run_warp_mixed(
    duration: Duration,
    collector: &ArtifactCollector,
    case_name: &str,
    endpoint: &str,
    bucket: &str,
    access_key: &str,
    secret_key: &str,
) -> Result<()> {
    let host = endpoint
        .strip_prefix("http://")
        .or_else(|| endpoint.strip_prefix("https://"))
        .unwrap_or(endpoint);
    let duration = format!("{}s", duration.as_secs());
    let command = CommandSpec::new("warp").args([
        "mixed".to_string(),
        format!("--host={host}"),
        format!("--access-key={access_key}"),
        format!("--secret-key={secret_key}"),
        format!("--bucket={bucket}"),
        format!("--duration={duration}"),
        "--obj.size=4KiB".to_string(),
        "--tls=false".to_string(),
        "--autoterm".to_string(),
    ]);
    let output = command.run()?;
    let display = command.display().replace(
        &format!("--secret-key={secret_key}"),
        "--secret-key=<redacted>",
    );
    collector.write_text(
        case_name,
        "warp-mixed.txt",
        &format!(
            "$ {}\nexit: {:?}\nstdout:\n{}\nstderr:\n{}",
            display, output.code, output.stdout, output.stderr
        ),
    )?;
    ensure!(
        output.code == Some(0),
        "warp mixed command failed with exit {:?}",
        output.code
    );
    Ok(())
}

impl DmFlakeyGuard {
    pub fn ensure_active(&self, stage: &str) -> Result<DmStatusSnapshot> {
        let snapshot = self.snapshot(stage)?;
        ensure!(
            normalize_dm_table(&snapshot.table) == normalize_dm_table(&self.fault_table),
            "device-mapper target {:?} is no longer using the requested fault table at {stage}; expected {:?}, active {:?}",
            self.dm_name,
            self.fault_table,
            snapshot.table
        );
        Ok(snapshot)
    }

    pub fn snapshot(&self, stage: &str) -> Result<DmStatusSnapshot> {
        Ok(DmStatusSnapshot {
            stage: stage.to_string(),
            helper_pod: self.helper_pod.clone(),
            mapping: self.mapping.clone(),
            table: self.dmsetup(["table", self.dm_name.as_str()])?.stdout,
            status: self.dmsetup(["status", self.dm_name.as_str()])?.stdout,
        })
    }

    fn ensure_recovery_table_active(&self) -> Result<()> {
        let snapshot = self.snapshot("recovery-table-verified")?;
        ensure!(
            normalize_dm_table(&snapshot.table) == normalize_dm_table(&self.recovery_table),
            "device-mapper target {:?} did not restore the exact pre-injection table; expected {:?}, active {:?}",
            self.dm_name,
            self.recovery_table,
            snapshot.table
        );
        Ok(())
    }

    pub fn requires_crash_boundary(&self) -> bool {
        self.behavior.requires_crash_boundary()
    }

    pub fn prepare_recovery_boundary(
        &mut self,
        timeout: Duration,
        started_at_ms: u64,
    ) -> Result<()> {
        ensure!(
            self.requires_crash_boundary(),
            "device-mapper error-injection faults do not have a crash recovery boundary"
        );
        ensure!(
            !self.crash_boundary_completed,
            "device-mapper crash recovery boundary was already completed"
        );
        let fault = self.ensure_active("before-crash-boundary")?;
        let mount_before = self
            .mount_snapshot
            .clone()
            .context("device-mapper mount snapshot is missing")?;

        self.add_node_taint()?;
        let replacement_pod_uid = self.force_delete_target_pod(timeout)?;
        self.ensure_active("before-crash-unmount")?;
        self.unmount_filesystem(timeout)?;
        self.crash_boundary_completed = true;

        let snapshot = DmCrashBoundarySnapshot {
            scenario: self.scenario.clone(),
            run_id: self.run_id.clone(),
            started_at_ms,
            completed_at_ms: now_ms(),
            taint: self.node_taint(),
            old_pod_uid: self.mapping.pod_uid.clone(),
            replacement_pod_uid,
            filesystem_unmounted: self.mount_state == DmMountState::Unmounted,
            mount_before,
            fault,
        };
        self.collector.write_text(
            &self.case_name,
            "dm-crash-boundary.json",
            &serde_json::to_string_pretty(&snapshot)?,
        )?;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<()> {
        if self.requires_crash_boundary() {
            ensure!(
                self.crash_boundary_completed,
                "refusing to complete a drop_writes durability run without force-deleting the target Pod and unmounting the filesystem while the fault table is active"
            );
        }
        let recovery_table = self.recovery_table.clone();
        let suspend_mode = match self.behavior {
            DmFaultBehavior::ErrorInjection => DmSuspendMode::NoFlush,
            DmFaultBehavior::DropWritesCrash => DmSuspendMode::NoLockFs,
        };
        self.load_table(&recovery_table, suspend_mode)?;
        self.ensure_recovery_table_active()?;
        if self.requires_crash_boundary() {
            self.ensure_filesystem_mounted()?;
        }
        if self.node_tainted {
            self.remove_node_taint()?;
        }
        self.recovery_snapshot = Some(self.snapshot("recovered")?);
        let mount = self.capture_mount_snapshot()?;
        self.verify_mount_source(&mount)?;
        let cleanup_observation = HostStoragePostCleanupObservation {
            schema_version: 1,
            scenario: self.scenario.clone(),
            fault_name: self.preflight_proof.fault_name.clone(),
            run_id: self.run_id.clone(),
            observed_at_ms: now_ms(),
            node: self.mapping.node.clone(),
            persistent_volume: self.mapping.pv.clone(),
            mapper_name: self.dm_name.clone(),
            logical_device: format!("/dev/mapper/{}", self.dm_name),
            canonical_device: self.mapper_canonical_device()?,
            mount_canonical_source: mount.canonical_source.clone(),
            filesystem_mounted: true,
            node_quarantined: self.node_has_crash_taint()?,
            recovery_table_sha256: normalized_dm_table_sha256(
                &self
                    .recovery_snapshot
                    .as_ref()
                    .context("device-mapper recovery snapshot is missing")?
                    .table,
            )?,
        };
        self.preflight_proof
            .validate_post_cleanup(&cleanup_observation)?;
        self.collector.write_text(
            &self.case_name,
            "host-storage-post-cleanup.json",
            &serde_json::to_string_pretty(&cleanup_observation)?,
        )?;
        if self.requires_crash_boundary() {
            let snapshot = DmCrashRecoverySnapshot {
                scenario: self.scenario.clone(),
                run_id: self.run_id.clone(),
                recovered_at_ms: now_ms(),
                taint_removed: !self.node_tainted,
                mount: self.capture_mount_snapshot()?,
                expected_table: self.recovery_table.clone(),
                fault: self
                    .recovery_snapshot
                    .clone()
                    .context("device-mapper recovery snapshot is missing")?,
            };
            self.collector.write_text(
                &self.case_name,
                "dm-crash-recovered.json",
                &serde_json::to_string_pretty(&snapshot)?,
            )?;
        }
        self.delete_helper()?;
        self.restored = true;
        Ok(())
    }

    pub fn recovery_snapshot(&self) -> Option<&DmStatusSnapshot> {
        self.recovery_snapshot.as_ref()
    }

    fn wait_helper_ready(&self) -> Result<()> {
        Kubectl::new(&self.config)
            .namespaced(&self.config.test_namespace)
            .command([
                "wait",
                "--for=condition=Ready",
                "pod",
                &self.helper_pod,
                "--timeout=60s",
            ])
            .run_checked()?;
        Ok(())
    }

    fn capture_mount_snapshot(&self) -> Result<DmMountSnapshot> {
        let source = self.findmnt_field("SOURCE")?;
        let filesystem = self.findmnt_field("FSTYPE")?;
        let options = self.findmnt_field("OPTIONS")?;
        let canonical_source = self
            .host_command(["/usr/bin/readlink", "-f", source.as_str()])?
            .stdout
            .trim()
            .to_string();
        ensure!(!filesystem.is_empty(), "target filesystem type is empty");
        ensure!(
            !options.is_empty(),
            "target filesystem mount options are empty"
        );
        Ok(DmMountSnapshot {
            source,
            canonical_source,
            filesystem,
            options,
        })
    }

    fn findmnt_field(&self, field: &str) -> Result<String> {
        let value = self
            .host_command([
                "/usr/bin/findmnt",
                "-n",
                "-o",
                field,
                "--target",
                self.mapping.mount_path.as_str(),
            ])?
            .stdout
            .trim()
            .to_string();
        ensure!(
            !value.is_empty(),
            "findmnt returned an empty {field} for {:?}",
            self.mapping.mount_path
        );
        Ok(value)
    }

    fn verify_mount_source(&self, mount: &DmMountSnapshot) -> Result<()> {
        let mapper = self.mapper_canonical_device()?;
        ensure!(
            mount.canonical_source == mapper,
            "fault-test PV mount {:?} on node {:?} is backed by {:?}, not device-mapper target {:?}",
            self.mapping.mount_path,
            self.mapping.node,
            mount.source,
            self.dm_name
        );
        Ok(())
    }

    fn mapper_canonical_device(&self) -> Result<String> {
        let mapper = self
            .host_command([
                "/usr/bin/readlink",
                "-f",
                &format!("/dev/mapper/{}", self.dm_name),
            ])?
            .stdout
            .trim()
            .to_string();
        ensure!(
            !mapper.is_empty(),
            "device-mapper canonical device is empty"
        );
        Ok(mapper)
    }

    fn target_observation(&self, recovery_table: &str) -> Result<HostStorageTargetObservation> {
        let mount = self
            .mount_snapshot
            .as_ref()
            .context("device-mapper mount snapshot is missing")?;
        Ok(HostStorageTargetObservation {
            node: self.mapping.node.clone(),
            pod: self.mapping.pod.clone(),
            pod_uid: self.mapping.pod_uid.clone(),
            persistent_volume_claim: self.mapping.pvc.clone(),
            persistent_volume: self.mapping.pv.clone(),
            persistent_volume_path: self.mapping.mount_path.clone(),
            mapper_name: self.dm_name.clone(),
            logical_device: format!("/dev/mapper/{}", self.dm_name),
            canonical_device: self.mapper_canonical_device()?,
            mount_source: mount.source.clone(),
            mount_canonical_source: mount.canonical_source.clone(),
            filesystem: mount.filesystem.clone(),
            recovery_table: recovery_table.to_string(),
            observed_at_ms: now_ms(),
        })
    }

    fn node_has_crash_taint(&self) -> Result<bool> {
        let node = Kubectl::new(&self.config)
            .command(["get", "node", self.mapping.node.as_str(), "-o", "json"])
            .run_checked()?;
        let node = serde_json::from_str::<Value>(&node.stdout).context("parse DM target node")?;
        Ok(node
            .pointer("/spec/taints")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .any(|taint| taint.get("key").and_then(Value::as_str) == Some(CRASH_TAINT_KEY)))
    }

    fn load_table(&self, table: &str, mode: DmSuspendMode) -> Result<()> {
        self.dmsetup(dm_suspend_args(&self.dm_name, mode))?;
        let load = self.dmsetup(["load", self.dm_name.as_str(), "--table", table]);
        let resume = self.dmsetup(dm_resume_args(&self.dm_name));
        load?;
        resume?;
        Ok(())
    }

    fn add_node_taint(&mut self) -> Result<()> {
        let node = Kubectl::new(&self.config)
            .command(["get", "node", self.mapping.node.as_str(), "-o", "json"])
            .run_checked()?;
        let node = serde_json::from_str::<Value>(&node.stdout).context("parse DM target node")?;
        let existing = node
            .pointer("/spec/taints")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .any(|taint| taint.get("key").and_then(Value::as_str) == Some(CRASH_TAINT_KEY));
        ensure!(
            !existing,
            "target node {:?} already has the s3chaos crash-containment taint; refuse to overwrite operator or stale-run state",
            self.mapping.node
        );
        let taint = self.node_taint();
        Kubectl::new(&self.config)
            .command(["taint", "node", self.mapping.node.as_str(), taint.as_str()])
            .run_checked()?;
        self.node_tainted = true;
        Ok(())
    }

    fn remove_node_taint(&mut self) -> Result<()> {
        ensure!(
            !self.requires_crash_boundary() || self.mount_state.proves_expected_mount(),
            "refusing to remove the crash-containment taint without a verified mapper-backed mount; state={:?}",
            self.mount_state
        );
        let removal = format!("{CRASH_TAINT_KEY}-");
        let output = Kubectl::new(&self.config)
            .command([
                "taint",
                "node",
                self.mapping.node.as_str(),
                removal.as_str(),
            ])
            .run()?;
        ensure!(
            output.code == Some(0)
                || format!("{}\n{}", output.stdout, output.stderr)
                    .to_ascii_lowercase()
                    .contains("not found"),
            "failed to remove node taint from {:?}: exit={:?}, stderr={}",
            self.mapping.node,
            output.code,
            output.stderr
        );
        self.node_tainted = false;
        Ok(())
    }

    fn node_taint(&self) -> String {
        let value = self
            .mapping
            .pod_uid
            .chars()
            .filter(|ch| ch.is_ascii_alphanumeric())
            .take(16)
            .collect::<String>()
            .to_ascii_lowercase();
        format!("{CRASH_TAINT_KEY}={value}:NoSchedule")
    }

    fn force_delete_target_pod(&self, timeout: Duration) -> Result<Option<String>> {
        Kubectl::new(&self.config)
            .namespaced(&self.config.test_namespace)
            .command([
                "delete",
                "pod",
                self.mapping.pod.as_str(),
                "--grace-period=0",
                "--force",
                "--wait=false",
            ])
            .run_checked()?;

        let deadline = Instant::now() + timeout;
        loop {
            let output = Kubectl::new(&self.config)
                .namespaced(&self.config.test_namespace)
                .command([
                    "get",
                    "pod",
                    self.mapping.pod.as_str(),
                    "-o",
                    "json",
                    "--ignore-not-found",
                ])
                .run_checked()?;
            if output.stdout.trim().is_empty() {
                return Ok(None);
            }
            let pod = serde_json::from_str::<Value>(&output.stdout)
                .context("parse replacement RustFS Pod")?;
            let uid = pod
                .pointer("/metadata/uid")
                .and_then(Value::as_str)
                .context("replacement RustFS Pod is missing metadata.uid")?;
            if uid != self.mapping.pod_uid {
                let node = pod.pointer("/spec/nodeName").and_then(Value::as_str);
                ensure!(
                    node != Some(self.mapping.node.as_str()),
                    "replacement Pod {:?} was scheduled on tainted node {:?} before the crash boundary completed",
                    self.mapping.pod,
                    self.mapping.node
                );
                return Ok(Some(uid.to_string()));
            }
            ensure!(
                Instant::now() < deadline,
                "target Pod {:?} with uid {:?} did not terminate within {:?}",
                self.mapping.pod,
                self.mapping.pod_uid,
                timeout
            );
            sleep(Duration::from_millis(500));
        }
    }

    fn unmount_filesystem(&mut self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        self.mount_state = DmMountState::Unmounting;
        loop {
            let command =
                self.host_command_unchecked(["/usr/bin/umount", self.mapping.mount_path.as_str()]);
            let command_summary = match &command {
                Ok(output) => format!(
                    "exit={:?}, stdout={}, stderr={}",
                    output.code, output.stdout, output.stderr
                ),
                Err(error) => format!("transport error: {error:#}"),
            };
            match self.reconcile_mount_state() {
                Ok(DmMountState::Unmounted) => return Ok(()),
                Ok(DmMountState::Mounted) => {}
                Ok(state) => bail!("unexpected reconciled mount state {state:?}"),
                Err(observe_error) => {
                    ensure!(
                        Instant::now() < deadline,
                        "timed out reconciling mount state for {:?} after forced Pod deletion while drop_writes remained active; umount {command_summary}; findmnt error: {observe_error:#}",
                        self.mapping.mount_path
                    );
                }
            }
            ensure!(
                Instant::now() < deadline,
                "timed out unmounting {:?} after forced Pod deletion while drop_writes remained active; last umount {command_summary}",
                self.mapping.mount_path,
            );
            self.ensure_active("waiting-for-crash-unmount")?;
            sleep(Duration::from_millis(500));
        }
    }

    fn observe_mount_state(&self) -> Result<DmMountState> {
        let output = self.host_command_unchecked([
            "/usr/bin/findmnt",
            "-n",
            "--target",
            self.mapping.mount_path.as_str(),
        ])?;
        match output.code {
            Some(1) => Ok(DmMountState::Unmounted),
            Some(0) => {
                let mount = self.capture_mount_snapshot()?;
                self.verify_mount_source(&mount)?;
                Ok(DmMountState::Mounted)
            }
            _ => bail!(
                "could not determine mount state for {:?}: findmnt exit={:?}, stdout={}, stderr={}",
                self.mapping.mount_path,
                output.code,
                output.stdout,
                output.stderr
            ),
        }
    }

    fn reconcile_mount_state(&mut self) -> Result<DmMountState> {
        match self.observe_mount_state() {
            Ok(state) => {
                self.mount_state = state;
                Ok(state)
            }
            Err(error) => {
                self.mount_state = DmMountState::Unknown;
                Err(error)
            }
        }
    }

    fn ensure_filesystem_mounted(&mut self) -> Result<()> {
        match self.reconcile_mount_state()? {
            DmMountState::Mounted => Ok(()),
            DmMountState::Unmounted => self.remount_filesystem(),
            state => bail!("unexpected reconciled mount state {state:?}"),
        }
    }

    fn remount_filesystem(&mut self) -> Result<()> {
        let mount = self
            .mount_snapshot
            .clone()
            .context("device-mapper mount snapshot is missing")?;
        let mapper = format!("/dev/mapper/{}", self.dm_name);
        self.mount_state = DmMountState::Mounting;
        let command = self.host_command_unchecked([
            "/usr/bin/mount",
            "-t",
            mount.filesystem.as_str(),
            "-o",
            mount.options.as_str(),
            mapper.as_str(),
            self.mapping.mount_path.as_str(),
        ]);
        let command_summary = match &command {
            Ok(output) => format!(
                "exit={:?}, stdout={}, stderr={}",
                output.code, output.stdout, output.stderr
            ),
            Err(error) => format!("transport error: {error:#}"),
        };
        match self.reconcile_mount_state() {
            Ok(DmMountState::Mounted) => Ok(()),
            Ok(DmMountState::Unmounted) => {
                bail!(
                    "failed to remount {:?} from mapper {:?}; mount {command_summary}",
                    self.mapping.mount_path,
                    mapper
                )
            }
            Ok(state) => bail!("unexpected reconciled mount state {state:?}"),
            Err(error) => Err(error).with_context(|| {
                format!(
                    "reconcile {:?} after remount attempt; mount {command_summary}",
                    self.mapping.mount_path
                )
            }),
        }
    }

    fn dmsetup<I, S>(&self, args: I) -> Result<CommandOutput>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut command = vec!["/usr/sbin/dmsetup".to_string()];
        command.extend(args.into_iter().map(Into::into));
        self.host_command(command)
    }

    fn host_command<I, S>(&self, args: I) -> Result<CommandOutput>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut command = vec![
            "exec".to_string(),
            self.helper_pod.clone(),
            "--".to_string(),
            "chroot".to_string(),
            "/host".to_string(),
        ];
        command.extend(args.into_iter().map(Into::into));
        Kubectl::new(&self.config)
            .namespaced(&self.config.test_namespace)
            .command(command)
            .run_checked()
    }

    fn host_command_unchecked<I, S>(&self, args: I) -> Result<CommandOutput>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut command = vec![
            "exec".to_string(),
            self.helper_pod.clone(),
            "--".to_string(),
            "chroot".to_string(),
            "/host".to_string(),
        ];
        command.extend(args.into_iter().map(Into::into));
        Kubectl::new(&self.config)
            .namespaced(&self.config.test_namespace)
            .command(command)
            .run()
    }

    fn delete_helper(&self) -> Result<()> {
        Kubectl::new(&self.config)
            .namespaced(&self.config.test_namespace)
            .command([
                "delete",
                "pod",
                &self.helper_pod,
                "--ignore-not-found",
                "--wait=true",
            ])
            .run_checked()?;
        Ok(())
    }
}

impl Drop for DmFlakeyGuard {
    fn drop(&mut self) {
        if !self.restored {
            let recovery_table = self.recovery_table.clone();
            let mut storage_recovered = !self.fault_applied;
            if self.fault_applied && !recovery_table.is_empty() {
                let mode = match self.behavior {
                    DmFaultBehavior::ErrorInjection => DmSuspendMode::NoFlush,
                    DmFaultBehavior::DropWritesCrash => DmSuspendMode::NoLockFs,
                };
                match self
                    .load_table(&recovery_table, mode)
                    .and_then(|()| self.ensure_recovery_table_active())
                {
                    Ok(()) => storage_recovered = true,
                    Err(error) => {
                        // A discarded failure here leaves the injected fault table on a
                        // real block device; surface it so the leak is at least visible
                        // to operators (ChaosGuard already does this for chaos CRs).
                        eprintln!(
                            "warning: failed to restore device-mapper target {name} to its recovery table on node {node} during guard cleanup: {error}",
                            name = self.dm_name,
                            node = self.mapping.node,
                        );
                    }
                }
            }
            if storage_recovered && self.requires_crash_boundary() {
                match self.ensure_filesystem_mounted() {
                    Ok(()) => {}
                    Err(error) => {
                        storage_recovered = false;
                        eprintln!(
                            "warning: failed to remount device-mapper target {name} at {mount} during guard cleanup; node {node} remains tainted: {error}",
                            name = self.dm_name,
                            mount = self.mapping.mount_path,
                            node = self.mapping.node,
                        );
                    }
                }
            }
            if storage_recovered
                && self.node_tainted
                && let Err(error) = self.remove_node_taint()
            {
                storage_recovered = false;
                eprintln!(
                    "warning: failed to remove crash-containment taint from node {node} during guard cleanup: {error}",
                    node = self.mapping.node,
                );
            }
            if self.fault_applied && !storage_recovered && !self.node_tainted {
                match self.add_node_taint() {
                    Ok(()) => eprintln!(
                        "warning: quarantined node {node} after device-mapper recovery failed",
                        node = self.mapping.node,
                    ),
                    Err(error) => eprintln!(
                        "warning: failed to quarantine node {node} after device-mapper recovery failed: {error}",
                        node = self.mapping.node,
                    ),
                }
            }
            if storage_recovered {
                if let Err(error) = self.delete_helper() {
                    eprintln!(
                        "warning: failed to delete dm-flakey helper pod {pod} during guard cleanup: {error}",
                        pod = self.helper_pod,
                    );
                }
            } else {
                eprintln!(
                    "warning: leaving dm helper pod {pod} on node {node} for manual recovery because storage cleanup did not complete",
                    pod = self.helper_pod,
                    node = self.mapping.node,
                );
            }
        }
    }
}

fn validate_dm_spec(spec: &DmFlakeySpec<'_>) -> Result<()> {
    ensure!(
        !spec.node.is_empty()
            && spec
                .node
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-')),
        "RUSTFS_FAULT_TEST_DM_NODE must be a valid node name"
    );
    ensure!(
        spec.mount_path.starts_with('/') && spec.mount_path != "/",
        "RUSTFS_FAULT_TEST_DM_MOUNT_PATH must be an absolute non-root path"
    );
    ensure!(
        !spec.mount_path.contains(['\n', '\r']),
        "RUSTFS_FAULT_TEST_DM_MOUNT_PATH must not contain newlines"
    );
    ensure!(
        !spec.name.is_empty()
            && spec
                .name
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | '+')),
        "RUSTFS_FAULT_TEST_DM_NAME contains unsupported characters"
    );
    if spec.behavior == DmFaultBehavior::ErrorInjection {
        ensure!(
            spec.fault_table
                .is_some_and(|table| !table.trim().is_empty()),
            "RUSTFS_FAULT_TEST_DM_FAULT_TABLE is required"
        );
    }
    ensure!(
        !spec.helper_image.trim().is_empty()
            && !spec.helper_image.contains(['\n', '\r', ' ', '\t']),
        "RUSTFS_FAULT_TEST_DM_HELPER_IMAGE must be a non-empty image reference"
    );
    Ok(())
}

fn dm_resume_args(name: &str) -> [&str; 3] {
    ["resume", "--noudevsync", name]
}

fn dm_suspend_args(name: &str, mode: DmSuspendMode) -> Vec<&str> {
    match mode {
        DmSuspendMode::Default => vec!["suspend", name],
        DmSuspendMode::NoFlush => vec!["suspend", "--noflush", name],
        DmSuspendMode::NoLockFs => vec!["suspend", "--nolockfs", name],
    }
}

fn drop_writes_table(recovery_table: &str) -> Result<String> {
    let fields = recovery_table.split_whitespace().collect::<Vec<_>>();
    ensure!(
        fields.len() == 5 && fields[2] == "linear",
        "drop_writes crash injection requires one linear recovery-table segment in '<start> <sectors> linear <backing> <offset>' form, got {recovery_table:?}"
    );
    let start = fields[0]
        .parse::<u64>()
        .context("parse recovery-table start sector")?;
    let sectors = fields[1]
        .parse::<u64>()
        .context("parse recovery-table sector count")?;
    let offset = fields[4]
        .parse::<u64>()
        .context("parse recovery-table backing offset")?;
    ensure!(sectors > 0, "recovery-table sector count must be positive");
    Ok(format!(
        "{start} {sectors} flakey {} {offset} 0 {DROP_WRITES_DOWN_INTERVAL_SECONDS} 1 drop_writes",
        fields[3]
    ))
}

fn verify_dm_volume_mapping(
    config: &ClusterTestConfig,
    node: &str,
    expected_mount_path: &str,
) -> Result<DmVolumeMapping> {
    let selector = format!("rustfs.tenant={}", config.tenant_name);
    let pods = Kubectl::new(config)
        .namespaced(&config.test_namespace)
        .command(["get", "pod", "-l", &selector, "-o", "json"])
        .run_checked()?;
    let pods = serde_json::from_str::<Value>(&pods.stdout).context("parse RustFS pod list")?;
    let pods_on_node = pods
        .pointer("/items")
        .and_then(Value::as_array)
        .context("RustFS pod list is missing items")?
        .iter()
        .filter(|item| item.pointer("/spec/nodeName").and_then(Value::as_str) == Some(node))
        .collect::<Vec<_>>();
    ensure!(
        pods_on_node.len() == 1,
        "device-mapper target node {node:?} must host exactly one RustFS fault-test Pod, found {}",
        pods_on_node.len()
    );
    let pod = pods_on_node[0];
    let pod_name = pod
        .pointer("/metadata/name")
        .and_then(Value::as_str)
        .context("DM target Pod is missing metadata.name")?;
    let pod_uid = pod
        .pointer("/metadata/uid")
        .and_then(Value::as_str)
        .context("DM target Pod is missing metadata.uid")?;
    let pvc = pod
        .pointer("/spec/volumes")
        .and_then(Value::as_array)
        .and_then(|volumes| {
            volumes.iter().find_map(|volume| {
                volume
                    .pointer("/persistentVolumeClaim/claimName")
                    .and_then(Value::as_str)
            })
        })
        .context("DM target Pod does not mount a PVC")?;

    let pvc_json = Kubectl::new(config)
        .namespaced(&config.test_namespace)
        .command(["get", "pvc", pvc, "-o", "json"])
        .run_checked()?;
    let pvc_json =
        serde_json::from_str::<Value>(&pvc_json.stdout).context("parse DM target PVC")?;
    let pv = pvc_json
        .pointer("/spec/volumeName")
        .and_then(Value::as_str)
        .context("DM target PVC is not bound")?;

    let pv_json = Kubectl::new(config)
        .command(["get", "pv", pv, "-o", "json"])
        .run_checked()?;
    let pv_json = serde_json::from_str::<Value>(&pv_json.stdout).context("parse DM target PV")?;
    let local_path = pv_json
        .pointer("/spec/local/path")
        .and_then(Value::as_str)
        .context("DM target PV is not a local PV")?;
    ensure!(
        local_path == expected_mount_path,
        "DM target PV {pv:?} uses local path {local_path:?}, expected {expected_mount_path:?}"
    );
    ensure!(
        pv_targets_node(&pv_json, node),
        "DM target PV {pv:?} node affinity does not target {node:?}"
    );

    Ok(DmVolumeMapping {
        node: node.to_string(),
        pod: pod_name.to_string(),
        pod_uid: pod_uid.to_string(),
        pvc: pvc.to_string(),
        pv: pv.to_string(),
        mount_path: local_path.to_string(),
    })
}

fn pv_targets_node(pv: &Value, node: &str) -> bool {
    pv.pointer("/spec/nodeAffinity/required/nodeSelectorTerms")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|term| term.get("matchExpressions").and_then(Value::as_array))
        .flatten()
        .any(|expression| {
            expression.get("key").and_then(Value::as_str) == Some("kubernetes.io/hostname")
                && expression.get("operator").and_then(Value::as_str) == Some("In")
                && expression
                    .get("values")
                    .and_then(Value::as_array)
                    .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(node)))
        })
}

fn helper_pod_name(run_id: &str) -> String {
    let suffix = run_id
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .take(12)
        .collect::<String>()
        .to_ascii_lowercase();
    format!("rustfs-fault-dm-helper-{suffix}")
}

fn dm_helper_manifest(config: &ClusterTestConfig, name: &str, node: &str, image: &str) -> String {
    format!(
        r#"apiVersion: v1
kind: Pod
metadata:
  name: {name}
  namespace: {namespace}
  labels:
    {managed_by_label}: {managed_by_value}
spec:
  nodeName: {node}
  hostPID: true
  restartPolicy: Never
  containers:
    - name: host-tools
      image: {image}
      imagePullPolicy: IfNotPresent
      command: ["sh", "-c", "trap : TERM INT; while :; do sleep 3600 & wait $!; done"]
      securityContext:
        privileged: true
      volumeMounts:
        - name: host-root
          mountPath: /host
          mountPropagation: HostToContainer
  volumes:
    - name: host-root
      hostPath:
        path: /
        type: Directory
"#,
        namespace = config.test_namespace,
        managed_by_label = MANAGED_BY_LABEL,
        managed_by_value = MANAGED_BY_VALUE,
    )
}

fn normalize_dm_table(table: &str) -> String {
    table.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{
        DmFaultBehavior, DmFlakeySpec, DmMountState, DmSuspendMode, dm_flakey_spec,
        dm_helper_manifest, dm_resume_args, dm_suspend_args, drop_writes_table, helper_pod_name,
        normalize_dm_table, pv_targets_node, validate_dm_spec,
    };
    use crate::fault::config::FaultTestConfig;

    #[test]
    fn dm_helper_is_pinned_to_one_node_and_host_root() {
        let config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        let manifest = dm_helper_manifest(
            &config.cluster,
            "rustfs-fault-dm-helper-run123",
            "worker-a",
            "busybox:test",
        );

        assert!(manifest.contains("nodeName: worker-a"));
        assert!(manifest.contains("privileged: true"));
        assert!(manifest.contains("mountPath: /host"));
        assert!(manifest.contains("path: /"));
        assert!(manifest.contains("s3chaos"));
    }

    #[test]
    fn dm_helper_stays_alive_until_explicitly_deleted() {
        let config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        let manifest = dm_helper_manifest(
            &config.cluster,
            "rustfs-fault-dm-helper-run123",
            "worker-a",
            "busybox:test",
        );

        // The guard always tears the pod down explicitly (restore/Drop), so it
        // must never self-terminate: a fixed `sleep 3600` on a restartPolicy:
        // Never pod would Complete mid-run and strand the fault table loaded on
        // the real block device once every kubectl exec starts failing.
        assert!(manifest.contains("while :; do sleep 3600 & wait $!; done"));
        assert!(!manifest.contains("sleep 3600 & wait\""));
    }

    #[test]
    fn dm_resume_disables_udev_synchronization() {
        assert_eq!(
            dm_resume_args("rustfs-fault-dm"),
            ["resume", "--noudevsync", "rustfs-fault-dm"]
        );
    }

    #[test]
    fn dm_suspend_modes_make_sync_semantics_explicit() {
        assert_eq!(
            dm_suspend_args("rustfs-fault-dm", DmSuspendMode::NoFlush),
            ["suspend", "--noflush", "rustfs-fault-dm"]
        );
        assert_eq!(
            dm_suspend_args("rustfs-fault-dm", DmSuspendMode::NoLockFs),
            ["suspend", "--nolockfs", "rustfs-fault-dm"]
        );
        assert_eq!(
            dm_suspend_args("rustfs-fault-dm", DmSuspendMode::Default),
            ["suspend", "rustfs-fault-dm"]
        );
    }

    #[test]
    fn only_a_reconciled_mapper_mount_allows_taint_removal() {
        assert!(DmMountState::Mounted.proves_expected_mount());
        assert!(!DmMountState::Unmounting.proves_expected_mount());
        assert!(!DmMountState::Unmounted.proves_expected_mount());
        assert!(!DmMountState::Mounting.proves_expected_mount());
        assert!(!DmMountState::Unknown.proves_expected_mount());
    }

    #[test]
    fn crash_table_is_always_down_and_silently_drops_writes() {
        assert_eq!(
            drop_writes_table("0 1024 linear 7:1 0").expect("drop-writes table"),
            "0 1024 flakey 7:1 0 0 86400 1 drop_writes"
        );
        assert!(drop_writes_table("0 1024 flakey 7:1 0 1 15").is_err());
        assert!(drop_writes_table("0 0 linear 7:1 0").is_err());
    }

    #[test]
    fn dm_table_comparison_uses_the_full_normalized_table() {
        assert_eq!(
            normalize_dm_table("0 1024  flakey   /dev/loop0 0 1 15\n"),
            "0 1024 flakey /dev/loop0 0 1 15"
        );
        assert_ne!(
            normalize_dm_table("0 1024 flakey /dev/loop0 0 1 15"),
            normalize_dm_table("0 1024 flakey /dev/loop1 0 1 15")
        );
    }

    #[test]
    fn dm_spec_rejects_unbounded_or_unsafe_targets() {
        let valid = DmFlakeySpec {
            node: "worker-a",
            mount_path: "/data/rustfs-fault/dm-volume",
            helper_image: "busybox:test",
            name: "rustfs-fault-dm",
            behavior: DmFaultBehavior::ErrorInjection,
            fault_table: Some("0 1024 flakey /dev/loop0 0 1 15"),
            recovery_table: None,
            run_id: "run-123",
        };
        assert!(validate_dm_spec(&valid).is_ok());

        let root = DmFlakeySpec {
            mount_path: "/",
            ..valid
        };
        assert!(validate_dm_spec(&root).is_err());
    }

    #[test]
    fn dm_flakey_spec_maps_explicit_config_fields() {
        let mut config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        config.dm_name = Some("rustfs-fault-dm".to_string());
        config.dm_node = Some("worker-a".to_string());
        config.dm_mount_path = Some("/data/rustfs-fault/dm-volume".to_string());
        config.dm_fault_table = Some("0 1024 flakey /dev/loop0 0 1 15".to_string());
        config.dm_recovery_table = Some("0 1024 linear /dev/loop0 0".to_string());

        let spec =
            dm_flakey_spec(&config, "run-123", DmFaultBehavior::ErrorInjection).expect("dm spec");

        assert_eq!(spec.name, "rustfs-fault-dm");
        assert_eq!(spec.node, "worker-a");
        assert_eq!(spec.mount_path, "/data/rustfs-fault/dm-volume");
        assert_eq!(spec.helper_image, config.dm_helper_image);
        assert_eq!(spec.fault_table, Some("0 1024 flakey /dev/loop0 0 1 15"));
        assert_eq!(spec.recovery_table, Some("0 1024 linear /dev/loop0 0"));
        assert_eq!(spec.run_id, "run-123");
    }

    #[test]
    fn dm_flakey_spec_requires_explicit_target_config() {
        let config = FaultTestConfig::for_test("real-cluster", "fast-csi");

        let error = dm_flakey_spec(&config, "run-123", DmFaultBehavior::ErrorInjection)
            .expect_err("missing dm config");

        assert!(
            error
                .to_string()
                .contains("RUSTFS_FAULT_TEST_DM_NAME is required")
        );
    }

    #[test]
    fn drop_writes_crash_spec_does_not_require_an_external_fault_table() {
        let mut config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        config.dm_name = Some("rustfs-fault-dm".to_string());
        config.dm_node = Some("worker-a".to_string());
        config.dm_mount_path = Some("/data/rustfs-fault/dm-volume".to_string());

        let spec = dm_flakey_spec(&config, "run-123", DmFaultBehavior::DropWritesCrash)
            .expect("drop-writes crash spec");

        assert_eq!(spec.behavior, DmFaultBehavior::DropWritesCrash);
        assert_eq!(spec.fault_table, None);
        assert!(validate_dm_spec(&spec).is_ok());
    }

    #[test]
    fn dm_pv_affinity_must_match_target_node() {
        let pv = serde_json::json!({
            "spec": {"nodeAffinity": {"required": {"nodeSelectorTerms": [{
                "matchExpressions": [{
                    "key": "kubernetes.io/hostname",
                    "operator": "In",
                    "values": ["worker-a"]
                }]
            }]}}}
        });

        assert!(pv_targets_node(&pv, "worker-a"));
        assert!(!pv_targets_node(&pv, "worker-b"));
        assert_eq!(
            helper_pod_name("run-ABC-123"),
            "rustfs-fault-dm-helper-runabc123"
        );
    }
}
