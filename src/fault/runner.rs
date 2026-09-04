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
        backends::{
            chaos_mesh::{self, ChaosGuard},
            host::{self, DmFlakeyGuard, DmStatusSnapshot},
        },
        checker,
        config::FaultTestConfig,
        diagnostics::diagnose_rustfs_snapshot,
        events::{RunEventRecorder, RunEventStatus},
        fault_artifacts::FaultFailureArtifactSource,
        fault_lifecycle::{
            AppliedFault, AppliedFaults, FaultDeleteTimeoutRecovery,
            FaultDeleteTimeoutRecoveryRequest, FaultLifecyclePort,
        },
        fixture,
        history::{
            ByteRange, DurabilityCohort, OperationKind, OperationOutcome, OperationRecord, Recorder,
        },
        plan::{FaultInjection, FaultPlan, FaultPlanOptions, WRITE_QUORUM_LOSS_PARTITION_TARGETS},
        pods::{
            rustfs_pod_identities, rustfs_target_inventory, wait_for_rustfs_pod_deletion,
            wait_for_rustfs_pod_replacement,
        },
        preflight::{PreflightCheck, PreflightPhase, PreflightSummary, TargetProof},
        reporting::{
            FailureSummary, FaultEvidence, FaultStatusSnapshot, PodIdentity, RunMetadata,
            write_checker_error, write_failure_summary, write_failure_summary_if_absent,
        },
        scenarios::{
            self, FaultBackend, FaultIsolation, FaultScenario, FaultScenarioSpec,
            NETWORK_PARTITION_WRITE_QUORUM_LOSS_SCENARIO,
        },
        spec::FaultRunSpec,
        workload::{
            ObjectSpec, S3WorkloadClient, WorkloadOperation, WorkloadPlan, sha256_hex,
            wait_for_s3_endpoint,
        },
    },
    framework::{
        artifacts::ArtifactCollector,
        command::{CommandOutput, CommandSpec},
        config::ClusterTestConfig,
        kube_client,
        kubectl::Kubectl,
        port_forward::{PortForwardGuard, PortForwardSpec},
        resources, wait,
    },
};
use anyhow::{Context, Result, bail, ensure};
use futures::{StreamExt, TryStreamExt, stream};
use kube::core::DynamicObject;
use serde::Serialize;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::time::sleep as async_sleep;
use uuid::Uuid;

const PREFILL_VERIFY_ATTEMPTS: usize = 3;
const PREFILL_VERIFY_RETRY_DELAY: Duration = Duration::from_secs(2);

struct FaultRunContext {
    spec: &'static FaultScenarioSpec,
    run_id: String,
    workload_plan: WorkloadPlan,
    bucket: String,
    events: RunEventRecorder,
    history: Recorder,
}

pub async fn run_selected_scenario_from_env() -> Result<()> {
    let config = FaultTestConfig::from_env()?;
    run_scenario_with_config(config).await
}

pub async fn run_scenario_with_config(config: FaultTestConfig) -> Result<()> {
    let reference_root = config.cluster.artifacts_dir.clone();
    run_scenario_with_config_and_reference_root(config, reference_root).await
}

pub(crate) async fn run_scenario_with_config_and_reference_root(
    mut config: FaultTestConfig,
    reference_root: impl Into<PathBuf>,
) -> Result<()> {
    scenarios::apply_catalog_defaults(&mut config)?;
    let scenario = FaultScenario::from_config(&config)?;
    let spec = scenarios::scenario_spec(&scenario.name)?;
    let plan = FaultPlan::from_scenario_with_options(
        &scenario,
        spec,
        FaultPlanOptions::from_config(&config),
    )?;

    config.require_destructive_enabled()?;
    config.validate_cluster(plan.requires_static_storage())?;
    eprintln!(
        "running destructive RustFS fault scenario {} against real Kubernetes context: {}",
        scenario.name, config.cluster.context
    );

    let collector =
        ArtifactCollector::with_reference_root(&config.cluster.artifacts_dir, reference_root)?;
    let result = run_fault_case(&config, &collector, &scenario, &plan).await;

    if let Err(error) = &result {
        write_failure_summary_if_absent(
            &collector,
            scenario.case_name,
            FailureSummary::new(&scenario.name, "scenario", "unknown", error.to_string())?,
        )
        .ok();
        match collector.collect_kubernetes_snapshot_with_diagnosis(
            scenario.case_name,
            &config.cluster,
            diagnose_rustfs_snapshot,
        ) {
            Ok(report) => {
                eprintln!(
                    "collected fault-test artifacts under {}",
                    report.dir.display()
                );
                eprintln!("{}", report.diagnosis);
            }
            Err(artifact_error) => {
                eprintln!("failed to collect fault-test artifacts after {error}: {artifact_error}");
            }
        }
    }

    result
}

async fn run_fault_case(
    config: &FaultTestConfig,
    collector: &ArtifactCollector,
    scenario: &FaultScenario,
    plan: &FaultPlan,
) -> Result<()> {
    let FaultRunContext {
        spec,
        run_id,
        workload_plan,
        bucket,
        events,
        history,
    } = initialize_fault_run(config, collector, scenario, plan)?;
    let mut run_completion =
        events.completion_guard("run", "fault run failed before successful completion");
    let mut preflight_phases = Vec::new();

    events.record(
        "fault-backend-preflight",
        RunEventStatus::Started,
        "checking required fault backends",
        None,
    )?;
    if let Err(error) = require_fault_backends(config, plan) {
        preflight_phases.push(PreflightPhase::new(
            "fault-backend-preflight",
            vec![PreflightCheck::failed(
                "required_fault_backends",
                error.to_string(),
                crate::fault::reporting::ResponsibilityDomain::FaultBackend,
            )],
        ));
        write_preflight_summary(collector, scenario, config, &preflight_phases).ok();
        events
            .record(
                "fault-backend-preflight",
                RunEventStatus::Failed,
                error.to_string(),
                None,
            )
            .ok();
        write_failure_summary(
            collector,
            scenario.case_name,
            FailureSummary::new(
                &scenario.name,
                "fault-backend-preflight",
                "environment_or_fault_backend",
                error.to_string(),
            )?,
        )?;
        return Err(error);
    }
    preflight_phases.push(PreflightPhase::new(
        "fault-backend-preflight",
        vec![PreflightCheck::passed(
            "required_fault_backends",
            "required fault backends are available",
            crate::fault::reporting::ResponsibilityDomain::FaultBackend,
        )],
    ));
    write_preflight_summary(collector, scenario, config, &preflight_phases)?;
    events.record(
        "fault-backend-preflight",
        RunEventStatus::Succeeded,
        "required fault backends are available",
        None,
    )?;
    events.record(
        "fault-backend-pre-cleanup",
        RunEventStatus::Started,
        "removing stale managed fault resources",
        None,
    )?;
    if let Err(error) = cleanup_fault_backends(config, plan) {
        preflight_phases.push(PreflightPhase::new(
            "fault-backend-pre-cleanup",
            vec![PreflightCheck::failed(
                "stale_fault_cleanup",
                error.to_string(),
                crate::fault::reporting::ResponsibilityDomain::FaultBackend,
            )],
        ));
        write_preflight_summary(collector, scenario, config, &preflight_phases).ok();
        events
            .record(
                "fault-backend-pre-cleanup",
                RunEventStatus::Failed,
                error.to_string(),
                None,
            )
            .ok();
        write_failure_summary(
            collector,
            scenario.case_name,
            FailureSummary::new(
                &scenario.name,
                "fault-backend-pre-cleanup",
                "environment_or_fault_backend",
                error.to_string(),
            )?,
        )?;
        return Err(error);
    }
    preflight_phases.push(PreflightPhase::new(
        "fault-backend-pre-cleanup",
        vec![PreflightCheck::passed(
            "stale_fault_cleanup",
            "stale managed fault resources were removed",
            crate::fault::reporting::ResponsibilityDomain::FaultBackend,
        )],
    ));
    write_preflight_summary(collector, scenario, config, &preflight_phases)?;
    events.record(
        "fault-backend-pre-cleanup",
        RunEventStatus::Succeeded,
        "stale managed fault resources were removed",
        None,
    )?;

    events.record(
        "fixture-prepare",
        RunEventStatus::Started,
        "preparing owned fault-test Tenant fixture",
        None,
    )?;
    if let Err(error) = prepare_fault_fixture(&config.cluster, spec.isolation) {
        events
            .record(
                "fixture-prepare",
                RunEventStatus::Failed,
                error.to_string(),
                None,
            )
            .ok();
        write_failure_summary(
            collector,
            scenario.case_name,
            FailureSummary::new(
                &scenario.name,
                "fixture-prepare",
                "test_or_environment",
                error.to_string(),
            )?,
        )?;
        return Err(error);
    }
    events.record(
        "fixture-prepare",
        RunEventStatus::Succeeded,
        "owned fault-test Tenant fixture prepared",
        None,
    )?;
    events.record(
        "tenant-ready-before-fault",
        RunEventStatus::Started,
        "waiting for Tenant readiness before fault injection",
        None,
    )?;
    if let Err(error) = wait_for_ready_tenant(&config.cluster).await {
        events
            .record(
                "tenant-ready-before-fault",
                RunEventStatus::Failed,
                error.to_string(),
                None,
            )
            .ok();
        write_failure_summary(
            collector,
            scenario.case_name,
            FailureSummary::new(
                &scenario.name,
                "tenant-ready-before-fault",
                "product_or_environment",
                error.to_string(),
            )?,
        )?;
        return Err(error);
    }
    events.record(
        "tenant-ready-before-fault",
        RunEventStatus::Succeeded,
        "Tenant is Ready before fault injection",
        None,
    )?;
    // Topology-conservation proof runs here, after the harness has created and
    // readied its own Tenant, not in the pre-fixture backend preflight: the
    // proof reads the live Tenant's pool geometry, which does not exist yet on
    // a fresh/standalone run before prepare_fault_fixture.
    let mut erasure_set_topology_proven = false;
    if plan.scenario == NETWORK_PARTITION_WRITE_QUORUM_LOSS_SCENARIO {
        events.record(
            "write-quorum-loss-topology-proof",
            RunEventStatus::Started,
            "proving the tenant matches a reference single-erasure-set topology",
            None,
        )?;
        if let Err(error) = require_write_quorum_loss_topology(config) {
            preflight_phases.push(PreflightPhase::new(
                "write-quorum-loss-topology-proof",
                vec![PreflightCheck::failed(
                    "write_quorum_loss_topology",
                    error.to_string(),
                    crate::fault::reporting::ResponsibilityDomain::Environment,
                )],
            ));
            write_preflight_summary(collector, scenario, config, &preflight_phases).ok();
            events
                .record(
                    "write-quorum-loss-topology-proof",
                    RunEventStatus::Failed,
                    error.to_string(),
                    None,
                )
                .ok();
            write_failure_summary(
                collector,
                scenario.case_name,
                FailureSummary::new(
                    &scenario.name,
                    "write-quorum-loss-topology-proof",
                    "test_or_environment",
                    error.to_string(),
                )?,
            )?;
            return Err(error);
        }
        erasure_set_topology_proven = true;
        events.record(
            "write-quorum-loss-topology-proof",
            RunEventStatus::Succeeded,
            "tenant topology provably makes a two-server partition break write quorum",
            None,
        )?;
    }
    events.record(
        "pod-stability-before-fault",
        RunEventStatus::Started,
        "waiting for RustFS pods to remain stable before fault injection",
        Some(serde_json::json!({
            "expected_pod_count": config.expected_rustfs_pod_count,
            "stable_window_seconds": config.rustfs_pod_stable_window.as_secs(),
        })),
    )?;
    if let Err(error) = wait_for_stable_rustfs_pods(
        &config.cluster,
        config.expected_rustfs_pod_count,
        config.rustfs_pod_stable_window,
    )
    .await
    {
        events
            .record(
                "pod-stability-before-fault",
                RunEventStatus::Failed,
                error.to_string(),
                None,
            )
            .ok();
        write_failure_summary(
            collector,
            scenario.case_name,
            FailureSummary::new(
                &scenario.name,
                "pod-stability-before-fault",
                "product_or_environment",
                error.to_string(),
            )?,
        )?;
        return Err(error);
    }
    events.record(
        "pod-stability-before-fault",
        RunEventStatus::Succeeded,
        "RustFS pods were stable before fault injection",
        None,
    )?;

    let cluster = &config.cluster;
    events.record(
        "initial-s3-access",
        RunEventStatus::Started,
        "opening initial S3 access path",
        Some(serde_json::json!({ "use_cluster_ip": config.use_cluster_ip })),
    )?;
    let (endpoint, mut port_forward) = match s3_access(config) {
        Ok(access) => access,
        Err(error) => {
            events
                .record(
                    "initial-s3-access",
                    RunEventStatus::Failed,
                    error.to_string(),
                    None,
                )
                .ok();
            write_failure_summary(
                collector,
                scenario.case_name,
                FailureSummary::new(
                    &scenario.name,
                    "s3-endpoint",
                    "test_or_environment",
                    error.to_string(),
                )?,
            )?;
            return Err(error);
        }
    };
    if let Err(error) = ensure_s3_access(&mut port_forward, cluster, &endpoint).await {
        events
            .record(
                "initial-s3-access",
                RunEventStatus::Failed,
                error.to_string(),
                Some(serde_json::json!({ "endpoint": endpoint })),
            )
            .ok();
        write_failure_summary(
            collector,
            scenario.case_name,
            FailureSummary::new(
                &scenario.name,
                "initial-s3-access",
                "product_or_environment",
                error.to_string(),
            )?,
        )?;
        return Err(error);
    }
    events.record(
        "initial-s3-access",
        RunEventStatus::Succeeded,
        "S3 endpoint is reachable before fault injection",
        Some(serde_json::json!({ "endpoint": endpoint })),
    )?;

    let (access_key, secret_key) = resources::test_credentials();
    events.record(
        "s3-client",
        RunEventStatus::Started,
        "constructing S3 workload client",
        Some(serde_json::json!({ "endpoint": endpoint })),
    )?;
    let s3 = match S3WorkloadClient::new(
        &endpoint,
        &bucket,
        access_key,
        secret_key,
        config.request_timeout,
    )
    .await
    {
        Ok(client) => client,
        Err(error) => {
            events
                .record("s3-client", RunEventStatus::Failed, error.to_string(), None)
                .ok();
            write_failure_summary(
                collector,
                scenario.case_name,
                FailureSummary::new(
                    &scenario.name,
                    "s3-client",
                    "test_or_environment",
                    error.to_string(),
                )?,
            )?;
            return Err(error);
        }
    };
    events.record(
        "s3-client",
        RunEventStatus::Succeeded,
        "S3 workload client is ready",
        None,
    )?;
    events.record(
        "bucket-create",
        RunEventStatus::Started,
        "creating run-scoped workload bucket",
        Some(serde_json::json!({ "bucket": bucket })),
    )?;
    let bucket_outcome = match s3.create_bucket(&history).await {
        Ok(outcome) => outcome,
        Err(error) => {
            events
                .record(
                    "bucket-create",
                    RunEventStatus::Failed,
                    error.to_string(),
                    Some(serde_json::json!({ "bucket": bucket })),
                )
                .ok();
            write_failure_summary(
                collector,
                scenario.case_name,
                FailureSummary::new(
                    &scenario.name,
                    "bucket-create",
                    "test_harness",
                    error.to_string(),
                )?,
            )?;
            return Err(error);
        }
    };
    if bucket_outcome != OperationOutcome::Ok {
        let message = format!("fault workload bucket creation did not succeed: {bucket_outcome:?}");
        events
            .record(
                "bucket-create",
                RunEventStatus::Failed,
                message.clone(),
                Some(serde_json::json!({ "bucket": bucket, "outcome": format!("{bucket_outcome:?}") })),
            )
            .ok();
        write_failure_summary(
            collector,
            scenario.case_name,
            FailureSummary::new(
                &scenario.name,
                "bucket-create",
                "product_or_environment",
                message.clone(),
            )?,
        )?;
        bail!("{message}");
    }
    events.record(
        "bucket-create",
        RunEventStatus::Succeeded,
        "run-scoped workload bucket was created",
        Some(serde_json::json!({ "bucket": bucket })),
    )?;

    if config.workload_versioning {
        let versioning_outcome = s3.enable_bucket_versioning(&history).await?;
        if versioning_outcome != OperationOutcome::Ok {
            let message = format!(
                "fault workload bucket versioning enablement did not succeed: {versioning_outcome:?}"
            );
            events
                .record(
                    "bucket-create",
                    RunEventStatus::Failed,
                    message.clone(),
                    Some(serde_json::json!({
                        "bucket": bucket,
                        "outcome": format!("{versioning_outcome:?}"),
                    })),
                )
                .ok();
            write_failure_summary(
                collector,
                scenario.case_name,
                FailureSummary::new(
                    &scenario.name,
                    "bucket-create",
                    "product_or_environment",
                    message.clone(),
                )?,
            )?;
            bail!("{message}");
        }
        events.record(
            "bucket-create",
            RunEventStatus::Succeeded,
            "run-scoped workload bucket versioning was enabled",
            Some(serde_json::json!({ "bucket": bucket })),
        )?;
    }

    events.record(
        "prefill",
        RunEventStatus::Started,
        "writing and verifying pre-fault objects",
        Some(serde_json::json!({
            "object_count": scenario.prefill_count(),
            "concurrency": config.prefill_concurrency,
        })),
    )?;
    let prefilled = match prefill_objects(
        &s3,
        &history,
        &run_id,
        &workload_plan,
        scenario.prefill_count(),
        config.prefill_concurrency,
        config.workload_directory_marker_percent,
    )
    .await
    {
        Ok(prefilled) => prefilled,
        Err(error) => {
            events
                .record("prefill", RunEventStatus::Failed, error.to_string(), None)
                .ok();
            write_failure_summary(
                collector,
                scenario.case_name,
                FailureSummary::new(
                    &scenario.name,
                    "prefill",
                    "product_or_environment",
                    error.to_string(),
                )?,
            )?;
            return Err(error);
        }
    };
    events.record(
        "prefill",
        RunEventStatus::Succeeded,
        "pre-fault objects were written and verified",
        Some(serde_json::json!({ "objects": prefilled.len() })),
    )?;
    events.record(
        "target-preflight",
        RunEventStatus::Started,
        "validating planned fault target proof",
        Some(serde_json::json!({
            "include_volume_bindings": plan_requires_volume_bindings(plan),
        })),
    )?;
    let target_inventory =
        match rustfs_target_inventory(cluster, plan_requires_volume_bindings(plan)) {
            Ok(inventory) => inventory,
            Err(error) => {
                preflight_phases.push(PreflightPhase::new(
                    "target-proof",
                    vec![PreflightCheck::failed(
                        "target_inventory",
                        error.to_string(),
                        crate::fault::reporting::ResponsibilityDomain::Harness,
                    )],
                ));
                write_preflight_summary(collector, scenario, config, &preflight_phases).ok();
                events
                    .record(
                        "target-preflight",
                        RunEventStatus::Failed,
                        error.to_string(),
                        None,
                    )
                    .ok();
                write_failure_summary(
                    collector,
                    scenario.case_name,
                    FailureSummary::new(
                        &scenario.name,
                        "target-preflight",
                        "test_or_environment",
                        error.to_string(),
                    )?,
                )?;
                return Err(error);
            }
        };
    let pods_before = target_inventory.identities;
    let mut target_proof = TargetProof::from_plan(config, scenario, spec, plan, &run_id)
        .with_resolved_pod_proofs(target_inventory.pod_proofs);
    if erasure_set_topology_proven {
        target_proof = target_proof.with_erasure_set_topology_proven();
    }
    collector.write_text(
        scenario.case_name,
        "target-proof.json",
        &serde_json::to_string_pretty(&target_proof)?,
    )?;
    preflight_phases.push(PreflightPhase::new(
        "target-proof",
        vec![target_proof.preflight_check()],
    ));
    write_preflight_summary(collector, scenario, config, &preflight_phases)?;
    if let Err(error) = target_proof.require_satisfied() {
        events
            .record(
                "target-preflight",
                RunEventStatus::Failed,
                error.to_string(),
                None,
            )
            .ok();
        write_failure_summary(
            collector,
            scenario.case_name,
            FailureSummary::new(
                &scenario.name,
                "target-preflight",
                "preflight_failed",
                error.to_string(),
            )?,
        )?;
        return Err(error);
    }
    events.record(
        "target-preflight",
        RunEventStatus::Succeeded,
        "planned fault target proof is satisfied",
        None,
    )?;
    events.record(
        "fault-apply",
        RunEventStatus::Started,
        "applying planned faults",
        Some(serde_json::json!({
            "faults": plan.faults().len(),
            "backend": plan.backend_summary(),
        })),
    )?;
    let fault_apply_started_at_ms = now_ms();
    let mut fault = match AppliedFaults::apply(config, collector, scenario, plan, &run_id) {
        Ok(fault) => fault,
        Err(error) => {
            events
                .record(
                    "fault-apply",
                    RunEventStatus::Failed,
                    error.to_string(),
                    None,
                )
                .ok();
            write_failure_summary(
                collector,
                scenario.case_name,
                FailureSummary::new(
                    &scenario.name,
                    "fault-apply",
                    "environment_or_fault_backend",
                    error.to_string(),
                )?,
            )?;
            return Err(error);
        }
    };
    events.record(
        "fault-apply",
        RunEventStatus::Succeeded,
        "planned faults were applied",
        None,
    )?;

    events.record(
        "wait-active",
        RunEventStatus::Started,
        "waiting for applied faults to become active",
        None,
    )?;
    if let Err(error) = fault.wait_active(cluster.timeout) {
        events
            .record(
                "wait-active",
                RunEventStatus::Failed,
                error.to_string(),
                None,
            )
            .ok();
        collect_fault_artifacts(collector, scenario.case_name, &fault, "wait-active-failed")?;
        write_failure_summary(
            collector,
            scenario.case_name,
            FailureSummary::new(
                &scenario.name,
                "wait-active",
                "environment_or_fault_backend",
                error.to_string(),
            )?,
        )?;
        return Err(error);
    }
    let fault_active_at_ms = history.mark_fault_active_now();
    events.record(
        "wait-active",
        RunEventStatus::Succeeded,
        "applied faults are active",
        None,
    )?;
    events.record(
        "fault-snapshot-active",
        RunEventStatus::Started,
        "capturing active fault status snapshots",
        None,
    )?;
    let active_snapshots = match fault.snapshots("active") {
        Ok(snapshots) => snapshots,
        Err(error) => {
            events
                .record(
                    "fault-snapshot-active",
                    RunEventStatus::Failed,
                    error.to_string(),
                    None,
                )
                .ok();
            collect_fault_artifacts(
                collector,
                scenario.case_name,
                &fault,
                "active-snapshot-failed",
            )?;
            write_failure_summary(
                collector,
                scenario.case_name,
                FailureSummary::new(
                    &scenario.name,
                    "fault-snapshot-active",
                    "environment_or_fault_backend",
                    error.to_string(),
                )?,
            )?;
            return Err(error);
        }
    };
    events.record(
        "fault-snapshot-active",
        RunEventStatus::Succeeded,
        "active fault status snapshots captured",
        Some(serde_json::json!({ "snapshots": active_snapshots.len() })),
    )?;

    events.record(
        "s3-access-under-fault",
        RunEventStatus::Started,
        "checking S3 access while faults are active",
        Some(serde_json::json!({ "endpoint": endpoint })),
    )?;
    if let Err(error) = ensure_s3_access(&mut port_forward, cluster, &endpoint).await {
        events
            .record(
                "s3-access-under-fault",
                RunEventStatus::Failed,
                error.to_string(),
                Some(serde_json::json!({ "endpoint": endpoint })),
            )
            .ok();
        collect_fault_artifacts(collector, scenario.case_name, &fault, "port-forward-failed")?;
        write_failure_summary(
            collector,
            scenario.case_name,
            FailureSummary::new(
                &scenario.name,
                "s3-access-under-fault",
                "environment_or_workload",
                error.to_string(),
            )?,
        )?;
        return Err(error);
    }
    events.record(
        "s3-access-under-fault",
        RunEventStatus::Succeeded,
        "S3 endpoint is reachable while faults are active",
        Some(serde_json::json!({ "endpoint": endpoint })),
    )?;

    if plan.workload_mode.runs_warp() {
        let warp_bucket = warp_bucket_name(&run_id);
        events.record(
            "warp-workload",
            RunEventStatus::Started,
            "running Warp workload under active faults",
            Some(serde_json::json!({ "bucket": warp_bucket })),
        )?;
        if let Err(error) = host::run_warp_mixed(
            config.warp_duration,
            collector,
            scenario.case_name,
            &endpoint,
            &warp_bucket,
            access_key,
            secret_key,
        ) {
            events
                .record(
                    "warp-workload",
                    RunEventStatus::Failed,
                    error.to_string(),
                    Some(serde_json::json!({ "bucket": warp_bucket })),
                )
                .ok();
            collect_fault_artifacts(collector, scenario.case_name, &fault, "warp-failed")?;
            write_failure_summary(
                collector,
                scenario.case_name,
                FailureSummary::new(
                    &scenario.name,
                    "warp-workload",
                    "workload_or_product",
                    error.to_string(),
                )?,
            )?;
            return Err(error);
        }
        events.record(
            "warp-workload",
            RunEventStatus::Succeeded,
            "Warp workload completed under active faults",
            Some(serde_json::json!({ "bucket": warp_bucket })),
        )?;

        events.record(
            "post-warp-s3-access",
            RunEventStatus::Started,
            "checking S3 access after Warp workload",
            Some(serde_json::json!({ "endpoint": endpoint })),
        )?;
        if let Err(error) = ensure_s3_access(&mut port_forward, cluster, &endpoint).await {
            events
                .record(
                    "post-warp-s3-access",
                    RunEventStatus::Failed,
                    error.to_string(),
                    Some(serde_json::json!({ "endpoint": endpoint })),
                )
                .ok();
            collect_fault_artifacts(
                collector,
                scenario.case_name,
                &fault,
                "post-warp-port-forward-failed",
            )?;
            write_failure_summary(
                collector,
                scenario.case_name,
                FailureSummary::new(
                    &scenario.name,
                    "post-warp-s3-access",
                    "environment_or_workload",
                    error.to_string(),
                )?,
            )?;
            return Err(error);
        }
        events.record(
            "post-warp-s3-access",
            RunEventStatus::Succeeded,
            "S3 endpoint is reachable after Warp workload",
            Some(serde_json::json!({ "endpoint": endpoint })),
        )?;
    }

    events.record(
        "mixed-workload",
        RunEventStatus::Started,
        "running mixed S3 workload while faults are active",
        Some(serde_json::json!({
            "object_count": scenario.mixed_workload_count(),
            "concurrency": workload_plan.concurrency,
        })),
    )?;
    let workload_started_at_ms = now_ms();
    history.set_durability_cohort(DurabilityCohort::FaultActive);
    let mut workload = match run_mixed_workload(
        &s3,
        &history,
        &run_id,
        &workload_plan,
        &prefilled,
        scenario.prefill_count(),
        scenario.mixed_workload_count(),
        config.workload_ranged_get_percent,
    )
    .await
    {
        Ok(workload) => workload,
        Err(error) => {
            events
                .record(
                    "mixed-workload",
                    RunEventStatus::Failed,
                    error.to_string(),
                    None,
                )
                .ok();
            collect_fault_artifacts(collector, scenario.case_name, &fault, "workload-failed")?;
            write_failure_summary(
                collector,
                scenario.case_name,
                FailureSummary::new(
                    &scenario.name,
                    "mixed-workload",
                    "workload_or_product",
                    error.to_string(),
                )?,
            )?;
            return Err(error);
        }
    };
    let workload_ended_at_ms = now_ms();
    events.record(
        "mixed-workload",
        RunEventStatus::Succeeded,
        "mixed S3 workload completed under active faults",
        Some(serde_json::json!({ "disruptions": workload.summary.disrupted() })),
    )?;
    collector.write_text(
        scenario.case_name,
        "workload-summary.json",
        &serde_json::to_string_pretty(&workload.summary)?,
    )?;
    let require_client_disruption =
        config.require_client_disruption || spec.impact_policy.requires_client_disruption();
    if let Err(error) = workload
        .summary
        .require_fault_evidence(require_client_disruption)
    {
        events
            .record(
                "fault-evidence",
                RunEventStatus::Failed,
                error.to_string(),
                Some(serde_json::json!({
                    "require_client_disruption": require_client_disruption,
                    "disruptions": workload.summary.disrupted(),
                })),
            )
            .ok();
        collect_fault_artifacts(
            collector,
            scenario.case_name,
            &fault,
            "workload-no-fault-evidence",
        )?;
        write_failure_summary(
            collector,
            scenario.case_name,
            FailureSummary::new(
                &scenario.name,
                "fault-evidence",
                "test_or_environment",
                error.to_string(),
            )?,
        )?;
        return Err(error);
    }
    events.record(
        "fault-evidence",
        RunEventStatus::Observed,
        "workload evidence matched the scenario impact policy",
        Some(serde_json::json!({
            "require_client_disruption": require_client_disruption,
            "disruptions": workload.summary.disrupted(),
        })),
    )?;
    if let Err(error) = fault.ensure_active("after fault workload") {
        events
            .record(
                "fault-still-active",
                RunEventStatus::Failed,
                error.to_string(),
                None,
            )
            .ok();
        collect_fault_artifacts(
            collector,
            scenario.case_name,
            &fault,
            "workload-outlived-fault",
        )?;
        write_failure_summary(
            collector,
            scenario.case_name,
            FailureSummary::new(
                &scenario.name,
                "fault-still-active",
                "test_or_environment",
                error.to_string(),
            )?,
        )?;
        return Err(error);
    }
    events.record(
        "fault-snapshot-after-workload",
        RunEventStatus::Started,
        "capturing fault status snapshots after workload",
        None,
    )?;
    let workload_snapshots = match fault.snapshots("after-workload") {
        Ok(snapshots) => snapshots,
        Err(error) => {
            events
                .record(
                    "fault-snapshot-after-workload",
                    RunEventStatus::Failed,
                    error.to_string(),
                    None,
                )
                .ok();
            collect_fault_artifacts(
                collector,
                scenario.case_name,
                &fault,
                "after-workload-snapshot-failed",
            )?;
            write_failure_summary(
                collector,
                scenario.case_name,
                FailureSummary::new(
                    &scenario.name,
                    "fault-snapshot-after-workload",
                    "environment_or_fault_backend",
                    error.to_string(),
                )?,
            )?;
            return Err(error);
        }
    };
    events.record(
        "fault-snapshot-after-workload",
        RunEventStatus::Succeeded,
        "fault status snapshots captured after workload",
        Some(serde_json::json!({ "snapshots": workload_snapshots.len() })),
    )?;

    if fault.requires_recovery_boundary() {
        events.record(
            "crash-recovery-boundary",
            RunEventStatus::Started,
            "proving an acknowledged mutation and forcing the backend-owned crash boundary",
            None,
        )?;
        let crash_boundary_started_at_ms = now_ms();
        let crash_window_evidence = match crash_window_evidence(
            &history.records(),
            &scenario.name,
            &run_id,
            fault_active_at_ms,
            crash_boundary_started_at_ms,
        ) {
            Ok(evidence) => evidence,
            Err(error) => {
                events
                    .record(
                        "crash-recovery-boundary",
                        RunEventStatus::Failed,
                        error.to_string(),
                        None,
                    )
                    .ok();
                write_failure_summary(
                    collector,
                    scenario.case_name,
                    FailureSummary::new(
                        &scenario.name,
                        "crash-recovery-boundary",
                        "no_signal",
                        error.to_string(),
                    )?,
                )?;
                return Err(error);
            }
        };
        collector.write_text(
            scenario.case_name,
            "crash-window-evidence.json",
            &serde_json::to_string_pretty(&crash_window_evidence)?,
        )?;
        if let Err(error) =
            fault.prepare_recovery_boundary(cluster.timeout, crash_boundary_started_at_ms)
        {
            events
                .record(
                    "crash-recovery-boundary",
                    RunEventStatus::Failed,
                    error.to_string(),
                    Some(serde_json::json!({
                        "trigger_operation_id": crash_window_evidence.trigger_operation_id,
                    })),
                )
                .ok();
            collect_fault_artifacts(
                collector,
                scenario.case_name,
                &fault,
                "crash-boundary-failed",
            )?;
            write_failure_summary(
                collector,
                scenario.case_name,
                FailureSummary::new(
                    &scenario.name,
                    "crash-recovery-boundary",
                    "environment_or_fault_backend",
                    error.to_string(),
                )?,
            )?;
            return Err(error);
        }
        events.record(
            "crash-recovery-boundary",
            RunEventStatus::Succeeded,
            "target Pod was force-deleted and the filesystem was unmounted while drop_writes remained active",
            Some(serde_json::json!({
                "trigger_operation_id": crash_window_evidence.trigger_operation_id,
                "ack_to_crash_boundary_ms": crash_window_evidence.ack_to_crash_boundary_ms,
            })),
        )?;
    }

    events.record(
        "fault-delete",
        RunEventStatus::Started,
        "removing applied faults",
        None,
    )?;
    let fault_delete_started_at_ms = history.mark_fault_ended_now();
    let fault_delete_started_at = Instant::now();
    if let Err(error) = fault.delete(cluster.timeout) {
        let finalizer_recovery = match fault.recover_delete_timeout(
            config,
            collector,
            scenario.case_name,
            &run_id,
            &error,
            fault_delete_started_at,
        ) {
            Ok(recovery) => recovery,
            Err(recovery_error) => {
                let _ = collector.write_text(
                    scenario.case_name,
                    "iochaos-finalizer-recovery-error.txt",
                    &format!(
                        "failed to evaluate or apply IOChaos finalizer recovery:\n{recovery_error}"
                    ),
                );
                None
            }
        };
        if let Some(recovery) = finalizer_recovery {
            events.record(
                "fault-delete",
                RunEventStatus::Succeeded,
                "patched stuck IOChaos finalizer after recovery evidence",
                Some(serde_json::json!({
                    "warning_artifact": recovery.warning_artifact,
                    "iochaos": recovery.resource_name,
                    "target_nodes": recovery.target_nodes,
                })),
            )?;
        } else {
            events
                .record(
                    "fault-delete",
                    RunEventStatus::Failed,
                    error.to_string(),
                    None,
                )
                .ok();
            collect_fault_artifacts(collector, scenario.case_name, &fault, "delete-failed")?;
            write_failure_summary(
                collector,
                scenario.case_name,
                FailureSummary::new(
                    &scenario.name,
                    "fault-delete",
                    "environment_or_fault_backend",
                    error.to_string(),
                )?,
            )?;
            return Err(error);
        }
    } else {
        events.record(
            "fault-delete",
            RunEventStatus::Succeeded,
            "applied faults were removed",
            None,
        )?;
    }

    events.record(
        "tenant-recovery",
        RunEventStatus::Started,
        "waiting for Tenant readiness after fault removal",
        None,
    )?;
    let recovery_started_at_ms = now_ms();
    history.set_durability_cohort(DurabilityCohort::PostRecovery);
    if let Err(error) = wait_for_ready_tenant(cluster).await {
        events
            .record(
                "tenant-recovery",
                RunEventStatus::Failed,
                error.to_string(),
                None,
            )
            .ok();
        write_failure_summary(
            collector,
            scenario.case_name,
            FailureSummary::new(
                &scenario.name,
                "tenant-recovery",
                "product_or_environment",
                error.to_string(),
            )?,
        )?;
        return Err(error);
    }
    events.record(
        "tenant-recovery",
        RunEventStatus::Succeeded,
        "Tenant is Ready after fault removal",
        None,
    )?;
    events.record(
        "pod-stability-after-recovery",
        RunEventStatus::Started,
        "waiting for RustFS pods to remain stable after recovery",
        Some(serde_json::json!({
            "expected_pod_count": config.expected_rustfs_pod_count,
            "stable_window_seconds": config.rustfs_pod_stable_window.as_secs(),
        })),
    )?;
    if let Err(error) = wait_for_stable_rustfs_pods(
        cluster,
        config.expected_rustfs_pod_count,
        config.rustfs_pod_stable_window,
    )
    .await
    {
        events
            .record(
                "pod-stability-after-recovery",
                RunEventStatus::Failed,
                error.to_string(),
                None,
            )
            .ok();
        write_failure_summary(
            collector,
            scenario.case_name,
            FailureSummary::new(
                &scenario.name,
                "pod-stability-after-recovery",
                "product_or_environment",
                error.to_string(),
            )?,
        )?;
        return Err(error);
    }
    events.record(
        "pod-stability-after-recovery",
        RunEventStatus::Succeeded,
        "RustFS pods were stable after recovery",
        None,
    )?;
    let pods_after = rustfs_pod_identities(cluster)?;
    events.record(
        "s3-access-after-recovery",
        RunEventStatus::Started,
        "checking S3 access after recovery",
        Some(serde_json::json!({ "endpoint": endpoint })),
    )?;
    if let Err(error) = ensure_s3_access(&mut port_forward, cluster, &endpoint).await {
        events
            .record(
                "s3-access-after-recovery",
                RunEventStatus::Failed,
                error.to_string(),
                Some(serde_json::json!({ "endpoint": endpoint })),
            )
            .ok();
        write_failure_summary(
            collector,
            scenario.case_name,
            FailureSummary::new(
                &scenario.name,
                "s3-access-after-recovery",
                "product_or_environment",
                error.to_string(),
            )?,
        )?;
        return Err(error);
    }
    events.record(
        "s3-access-after-recovery",
        RunEventStatus::Succeeded,
        "S3 endpoint is reachable after recovery",
        Some(serde_json::json!({ "endpoint": endpoint })),
    )?;
    let recovery_ended_at_ms = now_ms();
    let recovered_evidence = FaultEvidence {
        scenario: scenario.name.clone(),
        backend: plan.backend_summary(),
        target: plan.target_summary(),
        injected: true,
        active_during_workload: true,
        recovered: true,
        require_client_disruption,
        client_disruptions: workload.summary.disrupted(),
        workload_plan: workload_plan.clone(),
        pods_before: pods_before.clone(),
        pods_after: pods_after.clone(),
        active_snapshots: active_snapshots.clone(),
        workload_snapshots: workload_snapshots.clone(),
        dm_recovery_snapshot: fault.recovery_dm_snapshot(),
        fault_apply_started_at_ms: Some(fault_apply_started_at_ms),
        fault_active_at_ms: Some(fault_active_at_ms),
        workload_started_at_ms: Some(workload_started_at_ms),
        workload_ended_at_ms: Some(workload_ended_at_ms),
        fault_delete_started_at_ms: Some(fault_delete_started_at_ms),
        recovery_started_at_ms: Some(recovery_started_at_ms),
        recovery_ended_at_ms: Some(recovery_ended_at_ms),
    };
    collector.write_text(
        scenario.case_name,
        "fault-evidence.json",
        &serde_json::to_string_pretty(&recovered_evidence)?,
    )?;
    events.record(
        "checker-pre-recommit",
        RunEventStatus::Started,
        "checking recovered object model before recommit",
        None,
    )?;
    let pre_recommit_record_start = history.records().len();
    let pre_recommit_report = match checker::check_s3_history(
        &s3,
        &history,
        true,
        workload_plan.concurrency,
        config.workload_versioning,
    )
    .await
    {
        Ok(report) => report,
        Err(error) => {
            let message = error.to_string();
            events
                .record(
                    "checker-pre-recommit",
                    RunEventStatus::Failed,
                    message.clone(),
                    None,
                )
                .ok();
            write_checker_error(
                collector,
                scenario.case_name,
                "checker-pre-recommit-error.txt",
                &message,
            )?;
            let recovery_stability_report = checker::RecoveryStabilityReport::harness_error(
                message.clone(),
                config.recovery_stability_reread,
            );
            collector.write_text(
                scenario.case_name,
                "recovery-stability-report.json",
                &serde_json::to_string_pretty(&recovery_stability_report)?,
            )?;
            write_failure_summary(
                collector,
                scenario.case_name,
                FailureSummary::from_checker(
                    &scenario.name,
                    "checker-pre-recommit",
                    recovery_stability_report.classification,
                    message,
                )
                .with_recovered_within_seconds(recovery_stability_report.recovered_within_seconds)
                .with_evidence_classifications(
                    recovery_stability_report.evidence_classifications(),
                ),
            )?;
            return Err(error);
        }
    };
    collector.write_text(
        scenario.case_name,
        "checker-pre-recommit-report.json",
        &serde_json::to_string_pretty(&pre_recommit_report)?,
    )?;
    if let Err(error) = pre_recommit_report.require_success() {
        events
            .record(
                "checker-pre-recommit",
                RunEventStatus::Failed,
                error.to_string(),
                None,
            )
            .ok();
        events
            .record(
                "recovery-stability-reread",
                RunEventStatus::Started,
                "bounded reread of recovery-tail committed GET failures",
                Some(serde_json::json!({
                    "max_recovery_seconds": config.recovery_stability_reread.as_secs()
                })),
            )
            .ok();
        let recovery_stability_report = match checker::recovery_stability_reread(
            &s3,
            &history,
            &pre_recommit_report,
            pre_recommit_record_start,
            workload_plan.concurrency,
            config.recovery_stability_reread,
        )
        .await
        {
            Ok(report) => {
                events
                    .record(
                        "recovery-stability-reread",
                        RunEventStatus::Succeeded,
                        "bounded recovery stability reread completed",
                        Some(serde_json::json!({
                            "classification": report.classification.as_str(),
                            "attempted_keys": report.reread_attempted_keys.len(),
                            "recovered_keys": report.reread_recovered_keys.len(),
                            "still_unavailable_keys": report.still_unavailable_keys.len(),
                            "hash_mismatches": report.hash_mismatches.len()
                        })),
                    )
                    .ok();
                report
            }
            Err(reread_error) => {
                let message = format!("recovery stability reread failed: {reread_error}");
                events
                    .record(
                        "recovery-stability-reread",
                        RunEventStatus::Failed,
                        message.clone(),
                        None,
                    )
                    .ok();
                checker::RecoveryStabilityReport::harness_error(
                    message,
                    config.recovery_stability_reread,
                )
            }
        };
        collector.write_text(
            scenario.case_name,
            "recovery-stability-report.json",
            &serde_json::to_string_pretty(&recovery_stability_report)?,
        )?;
        write_failure_summary(
            collector,
            scenario.case_name,
            FailureSummary::from_checker(
                &scenario.name,
                "checker-pre-recommit-verdict",
                recovery_stability_report.classification,
                error.to_string(),
            )
            .with_recovered_within_seconds(recovery_stability_report.recovered_within_seconds)
            .with_evidence_classifications(recovery_stability_report.evidence_classifications())
            .with_list_warnings(
                recovery_stability_report.final_list_warning_count,
                recovery_stability_report.list_warnings.clone(),
            ),
        )?;
        return Err(error);
    }
    events.record(
        "checker-pre-recommit",
        RunEventStatus::Succeeded,
        "pre-recommit object model check passed",
        None,
    )?;
    events.record(
        "recommit-unconfirmed",
        RunEventStatus::Started,
        "recommitting previously unconfirmed writes after recovery",
        Some(serde_json::json!({ "attempted": workload.unconfirmed_puts.len() })),
    )?;
    let recommit_report = recommit_unconfirmed_objects(
        &s3,
        &history,
        &workload.unconfirmed_puts,
        workload_plan.concurrency,
    )
    .await;
    collector.write_text(
        scenario.case_name,
        "recommit-report.json",
        &serde_json::to_string_pretty(&recommit_report)?,
    )?;
    workload.summary.recommitted_after_recovery = recommit_report.committed;
    collector.write_text(
        scenario.case_name,
        "workload-summary.json",
        &serde_json::to_string_pretty(&workload.summary)?,
    )?;
    if recommit_report.has_failures() {
        let message = recommit_report.failure_message();
        events
            .record(
                "recommit-unconfirmed",
                RunEventStatus::Failed,
                message.clone(),
                Some(serde_json::json!({
                    "failed": recommit_report.failed,
                    "harness_errors": recommit_report.harness_errors,
                })),
            )
            .ok();
        write_failure_summary(
            collector,
            scenario.case_name,
            FailureSummary::new(
                &scenario.name,
                "recommit-unconfirmed",
                recommit_report.failure_classification(),
                message.clone(),
            )?,
        )?;
        bail!("{message}");
    }
    events.record(
        "recommit-unconfirmed",
        RunEventStatus::Succeeded,
        "previously unconfirmed writes were recommitted",
        Some(serde_json::json!({ "committed": recommit_report.committed })),
    )?;
    events.record(
        "checker-final",
        RunEventStatus::Started,
        "checking final recovered object model",
        None,
    )?;
    let report = match checker::check_s3_history(
        &s3,
        &history,
        true,
        workload_plan.concurrency,
        config.workload_versioning,
    )
    .await
    {
        Ok(report) => report,
        Err(error) => {
            let message = error.to_string();
            events
                .record(
                    "checker-final",
                    RunEventStatus::Failed,
                    message.clone(),
                    None,
                )
                .ok();
            write_checker_error(
                collector,
                scenario.case_name,
                "checker-final-error.txt",
                &message,
            )?;
            write_failure_summary(
                collector,
                scenario.case_name,
                FailureSummary::new(
                    &scenario.name,
                    "checker-final",
                    "checker_or_environment",
                    message,
                )?,
            )?;
            return Err(error);
        }
    };
    collector.write_text(
        scenario.case_name,
        "checker-report.json",
        &serde_json::to_string_pretty(&report)?,
    )?;
    let evidence = FaultEvidence {
        scenario: scenario.name.clone(),
        backend: plan.backend_summary(),
        target: plan.target_summary(),
        injected: true,
        active_during_workload: true,
        recovered: report.tenant_recovered,
        require_client_disruption,
        client_disruptions: workload.summary.disrupted(),
        workload_plan,
        pods_before,
        pods_after,
        active_snapshots,
        workload_snapshots,
        dm_recovery_snapshot: fault.recovery_dm_snapshot(),
        fault_apply_started_at_ms: Some(fault_apply_started_at_ms),
        fault_active_at_ms: Some(fault_active_at_ms),
        workload_started_at_ms: Some(workload_started_at_ms),
        workload_ended_at_ms: Some(workload_ended_at_ms),
        fault_delete_started_at_ms: Some(fault_delete_started_at_ms),
        recovery_started_at_ms: Some(recovery_started_at_ms),
        recovery_ended_at_ms: Some(recovery_ended_at_ms),
    };
    collector.write_text(
        scenario.case_name,
        "fault-evidence.json",
        &serde_json::to_string_pretty(&evidence)?,
    )?;
    if let Err(error) = report.require_success() {
        events
            .record(
                "checker-final",
                RunEventStatus::Failed,
                error.to_string(),
                None,
            )
            .ok();
        let classification = report.failure_classification();
        write_failure_summary(
            collector,
            scenario.case_name,
            FailureSummary::from_checker(
                &scenario.name,
                "checker-verdict",
                classification,
                error.to_string(),
            ),
        )?;
        return Err(error);
    }
    events.record(
        "checker-final",
        RunEventStatus::Succeeded,
        "final object model check passed",
        Some(serde_json::json!({
            "committed_puts": report.committed_puts,
            "verified_live_objects": report.verified_live_objects,
            "final_listed_objects": report.final_listed_objects,
        })),
    )?;
    events.record(
        "run",
        RunEventStatus::Succeeded,
        "fault run completed successfully",
        None,
    )?;
    run_completion.complete();

    Ok(())
}

fn initialize_fault_run(
    config: &FaultTestConfig,
    collector: &ArtifactCollector,
    scenario: &FaultScenario,
    plan: &FaultPlan,
) -> Result<FaultRunContext> {
    let spec = scenarios::scenario_spec(&scenario.name)?;
    let run_id = format!("run-{}", Uuid::new_v4());
    let workload_seed = config.workload_seed.unwrap_or_else(generated_seed);
    let workload_plan = WorkloadPlan::seeded_with_profile(
        workload_seed,
        scenario.object_count,
        config.workload.concurrency,
        config.workload_operation_mix,
        config.workload_payload_distribution.clone(),
        config.workload_hotspot,
    )
    .context("build workload plan")?;
    let bucket = bucket_name(&run_id);
    let events_path = collector
        .case_dir(scenario.case_name)
        .join("run-events.jsonl");
    let events = RunEventRecorder::create(events_path, &scenario.name, &run_id)?;
    let run_spec = FaultRunSpec::resolved(
        config,
        scenario,
        spec,
        plan,
        &workload_plan,
        &run_id,
        &bucket,
    );
    collector.write_text(scenario.case_name, "run-spec.yaml", &run_spec.to_yaml()?)?;
    collector.write_text(scenario.case_name, "run-spec.json", &run_spec.to_json()?)?;
    let history_path = collector.case_dir(scenario.case_name).join("history.jsonl");
    let history = Recorder::create(history_path, &scenario.name, &run_id)?;
    collector.write_text(
        scenario.case_name,
        "run-metadata.json",
        &serde_json::to_string_pretty(&RunMetadata::from_case(
            config,
            scenario,
            spec,
            plan,
            &workload_plan,
            &run_id,
            &bucket,
        ))?,
    )?;
    collector.write_text(
        scenario.case_name,
        "workload-plan.json",
        &serde_json::to_string_pretty(&workload_plan)?,
    )?;
    events.record(
        "run",
        RunEventStatus::Started,
        "fault run initialized",
        Some(serde_json::json!({
            "bucket": bucket,
            "backend": plan.backend_summary(),
            "target": plan.target_summary(),
            "faults": plan.faults().len(),
        })),
    )?;
    eprintln!(
        "fault workload seed={} objects={} concurrency={} payload_bytes={}",
        workload_plan.seed,
        workload_plan.object_count,
        workload_plan.concurrency,
        workload_plan.total_payload_bytes
    );

    Ok(FaultRunContext {
        spec,
        run_id,
        workload_plan,
        bucket,
        events,
        history,
    })
}

fn write_preflight_summary(
    collector: &ArtifactCollector,
    scenario: &FaultScenario,
    config: &FaultTestConfig,
    phases: &[PreflightPhase],
) -> Result<()> {
    let summary = PreflightSummary::single_run(config, &scenario.name, phases.to_vec());
    collector.write_text(
        scenario.case_name,
        "preflight-summary.json",
        &serde_json::to_string_pretty(&summary)?,
    )?;
    Ok(())
}

fn plan_requires_volume_bindings(plan: &FaultPlan) -> bool {
    plan.faults().iter().any(|fault| {
        matches!(
            fault.target(),
            crate::fault::plan::FaultTarget::RustfsVolume { .. }
        )
    })
}

fn require_fault_backends(config: &FaultTestConfig, plan: &FaultPlan) -> Result<()> {
    for backend in plan.required_backends() {
        require_fault_backend(config, backend)?;
    }
    for fault in plan
        .faults()
        .iter()
        .filter(|fault| fault.backend() == FaultBackend::DeviceMapper)
    {
        host::validate_config(config, fault.kind())?;
    }
    // The write-quorum-loss topology proof deliberately does NOT run here: this
    // preflight runs before prepare_fault_fixture creates the Tenant, so
    // reading the Tenant's pool geometry would NotFound on a fresh run. The
    // proof runs right after tenant readiness instead (see run_fault_case).
    Ok(())
}

/// Topology-conservation proof for the write-quorum-loss partition.
///
/// The scenario's FixedTargets(2) only means "write quorum breaks, read quorum
/// survives" on the reference tenant shapes: a single pool of 4 servers with
/// 1 or 2 volumes per server (4 or 8 drives). RustFS lays both out as a single
/// erasure set with data == parity (4 drives -> EC 2+2, 8 drives -> EC 4+4),
/// where write quorum is data+1 and read quorum is data. Isolating 2 of 4
/// servers then provably removes exactly half the drives of that one set:
/// write quorum becomes unreachable while read quorum can still be met by the
/// surviving half — and every pod is in the same set, so no same-erasure-set
/// resolution is needed. On any other shape the same count could be a no-op
/// (more servers) or a full outage (fewer), so we fail closed instead of
/// running a scenario whose oracle no longer matches its name. Replacing this
/// with a real erasure-set proof (admin cluster snapshot) generalizes it later.
fn require_write_quorum_loss_topology(config: &FaultTestConfig) -> Result<()> {
    let cluster = &config.cluster;
    let output = Kubectl::new(cluster)
        .namespaced(&cluster.test_namespace)
        .command([
            "get",
            "tenant",
            cluster.tenant_name.as_str(),
            "-o",
            "jsonpath={.spec.pools[*].persistence.volumesPerServer}",
        ])
        .run_checked()
        .context("reading tenant volumesPerServer for the write-quorum-loss topology proof")?;
    let raw = output.stdout.trim().to_string();
    let volumes: Vec<u64> = raw
        .split_whitespace()
        .map(|value| {
            value
                .parse::<u64>()
                .with_context(|| format!("tenant volumesPerServer must be numeric, got {value:?}"))
        })
        .collect::<Result<_>>()?;
    write_quorum_loss_topology_shape(config.expected_rustfs_pod_count, &volumes, &raw)
}

/// Pure shape predicate behind the write-quorum-loss topology proof: accepts
/// only the reference single-pool 4-server tenant with 1 or 2 volumes per
/// server. Kept free of kubectl I/O so the acceptance matrix is unit-testable.
fn write_quorum_loss_topology_shape(pod_count: usize, volumes: &[u64], raw: &str) -> Result<()> {
    const EXPECTED_SERVERS: usize = 4;
    const ACCEPTED_VOLUMES_PER_SERVER: [u64; 2] = [1, 2];

    ensure!(
        pod_count == EXPECTED_SERVERS,
        "network-partition-write-quorum-loss requires the reference 4-server tenant \
         (RUSTFS_POD_COUNT={}); partitioning {} of {} servers does not provably break \
         write quorum on other shapes",
        EXPECTED_SERVERS,
        WRITE_QUORUM_LOSS_PARTITION_TARGETS,
        pod_count,
    );
    ensure!(
        volumes.len() == 1 && ACCEPTED_VOLUMES_PER_SERVER.contains(&volumes[0]),
        "network-partition-write-quorum-loss requires the reference single-pool tenant with \
         volumesPerServer of 1 or 2 (4 or 8 drives; both lay out as one erasure set with \
         data == parity, so isolating 2 of 4 servers removes exactly half the drives); \
         found volumesPerServer={raw:?} — on that shape a 2-of-4 partition does not provably \
         break write quorum, so the run is rejected instead of producing a misleading verdict",
    );
    Ok(())
}

fn require_fault_backend(config: &FaultTestConfig, backend: FaultBackend) -> Result<()> {
    let cluster = &config.cluster;
    match backend {
        FaultBackend::ChaosMeshIoChaos => chaos_mesh::require_iochaos_crd(cluster),
        FaultBackend::MinioWarpWithChaos => {
            chaos_mesh::require_iochaos_crd(cluster)?;
            require_tool("warp", ["--help"])
        }
        FaultBackend::ChaosMeshPodChaos => chaos_mesh::require_podchaos_crd(cluster),
        FaultBackend::ChaosMeshNetworkChaos => chaos_mesh::require_networkchaos_crd(cluster),
        FaultBackend::ChaosMeshStressChaos => chaos_mesh::require_stresschaos_crd(cluster),
        FaultBackend::DeviceMapper => Ok(()),
        FaultBackend::PlannedReliabilityWorkflow => {
            bail!("planned reliability workflow scenarios are catalog-only and cannot execute yet")
        }
    }
}

fn require_tool<I, S>(program: &'static str, args: I) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    CommandSpec::new(program)
        .args(args)
        .run_checked()
        .with_context(|| format!("{program} is required for the selected fault scenario"))?;
    Ok(())
}

fn cleanup_fault_backends(config: &FaultTestConfig, plan: &FaultPlan) -> Result<()> {
    for backend in plan.required_backends() {
        cleanup_fault_backend(config, backend)?;
    }
    Ok(())
}

fn cleanup_fault_backend(config: &FaultTestConfig, backend: FaultBackend) -> Result<()> {
    match backend {
        FaultBackend::ChaosMeshIoChaos
        | FaultBackend::MinioWarpWithChaos
        | FaultBackend::ChaosMeshPodChaos
        | FaultBackend::ChaosMeshNetworkChaos
        | FaultBackend::ChaosMeshStressChaos => {
            // Sweep every managed chaos kind, not just this plan's backend: a
            // chaos CR leaked by a prior run or a prior suite attempt of a
            // different kind would otherwise stay active during this attempt and
            // be misattributed to (or mask) the fault under test.
            chaos_mesh::cleanup_managed_chaos(&config.cluster, &config.chaos_namespace)
        }
        FaultBackend::DeviceMapper => Ok(()),
        FaultBackend::PlannedReliabilityWorkflow => Ok(()),
    }
}

fn prepare_fault_fixture(config: &ClusterTestConfig, isolation: FaultIsolation) -> Result<()> {
    match isolation {
        FaultIsolation::ReusableTenant => fixture::apply_tenant_resources(config)?,
        FaultIsolation::FreshTenant | FaultIsolation::DedicatedLinuxBlockDevice => {
            fixture::reset_tenant_resources(config)?;
            fixture::apply_tenant_resources(config)?;
        }
    }
    Ok(())
}

struct ChaosFaultHandle {
    guard: Box<ChaosGuard>,
    active_required: bool,
}

struct PodKillFaultHandle {
    guard: Box<ChaosGuard>,
    before_pods: Vec<PodIdentity>,
    config: Box<ClusterTestConfig>,
}

struct DmFlakeyFaultHandle {
    guard: Box<DmFlakeyGuard>,
}

impl AppliedFaults {
    fn apply(
        config: &FaultTestConfig,
        collector: &ArtifactCollector,
        scenario: &FaultScenario,
        plan: &FaultPlan,
        run_id: &str,
    ) -> Result<Self> {
        ensure!(
            !plan.faults().is_empty(),
            "fault plan {} did not contain any faults",
            plan.scenario
        );

        let total = plan.faults().len();
        let mut items = Vec::with_capacity(total);
        for (index, injection) in plan.faults().iter().enumerate() {
            let manifest_name = chaos_manifest_artifact_name(total, index, injection);
            let resource_name_suffix = chaos_resource_name_suffix(total, index);
            items.push(apply_fault_backend(
                config,
                collector,
                scenario,
                injection,
                run_id,
                &manifest_name,
                &resource_name_suffix,
            )?);
        }

        Ok(Self::new(items))
    }

    fn recover_delete_timeout(
        &mut self,
        config: &FaultTestConfig,
        collector: &ArtifactCollector,
        case_name: &str,
        run_id: &str,
        original_error: &anyhow::Error,
        delete_started_at: Instant,
    ) -> Result<Option<FaultDeleteTimeoutRecovery>> {
        self.recover_delete_timeout_with(&FaultDeleteTimeoutRecoveryRequest {
            config,
            collector,
            case_name,
            run_id,
            original_error,
            delete_started_at,
        })
    }

    fn collect_failure_artifacts(
        &self,
        collector: &ArtifactCollector,
        case_name: &str,
        suffix: &str,
    ) -> Result<()> {
        let artifacts = self.failure_artifacts();
        let total = artifacts.len();
        for (index, artifacts) in artifacts.iter().enumerate() {
            artifacts.collect_failure_artifacts(collector, case_name, total, index, suffix)?;
        }
        Ok(())
    }
}

fn apply_fault_backend(
    config: &FaultTestConfig,
    collector: &ArtifactCollector,
    scenario: &FaultScenario,
    injection: &FaultInjection,
    run_id: &str,
    manifest_name: &str,
    resource_name_suffix: &str,
) -> Result<AppliedFault> {
    let request = FaultApplyRequest {
        config,
        collector,
        scenario,
        injection,
        run_id,
        manifest_name,
        resource_name_suffix,
    };
    match injection.backend() {
        FaultBackend::DeviceMapper => apply_host_fault_backend(&request),
        FaultBackend::ChaosMeshIoChaos
        | FaultBackend::ChaosMeshPodChaos
        | FaultBackend::ChaosMeshNetworkChaos
        | FaultBackend::ChaosMeshStressChaos
        | FaultBackend::MinioWarpWithChaos => apply_chaos_mesh_fault_backend(&request),
        FaultBackend::PlannedReliabilityWorkflow => {
            bail!("planned reliability workflow scenarios are catalog-only and cannot execute yet")
        }
    }
}

struct FaultApplyRequest<'a> {
    config: &'a FaultTestConfig,
    collector: &'a ArtifactCollector,
    scenario: &'a FaultScenario,
    injection: &'a FaultInjection,
    run_id: &'a str,
    manifest_name: &'a str,
    resource_name_suffix: &'a str,
}

fn apply_chaos_mesh_fault_backend(request: &FaultApplyRequest<'_>) -> Result<AppliedFault> {
    let applied = chaos_mesh::apply_fault(&chaos_mesh::FaultApplyRequest {
        config: request.config,
        collector: request.collector,
        scenario: request.scenario,
        injection: request.injection,
        run_id: request.run_id,
        manifest_name: request.manifest_name,
        resource_name_suffix: request.resource_name_suffix,
    })?;
    match applied {
        chaos_mesh::AppliedFault::Experiment {
            guard,
            active_required,
        } => Ok(Box::new(ChaosFaultHandle {
            guard: Box::new(guard),
            active_required,
        })),
        chaos_mesh::AppliedFault::PodKill { guard, before_pods } => {
            Ok(Box::new(PodKillFaultHandle {
                guard: Box::new(guard),
                before_pods,
                config: Box::new(request.config.cluster.clone()),
            }))
        }
    }
}

fn apply_host_fault_backend(request: &FaultApplyRequest<'_>) -> Result<AppliedFault> {
    Ok(Box::new(DmFlakeyFaultHandle {
        guard: Box::new(host::apply_fault(&host::FaultApplyRequest {
            config: request.config,
            collector: request.collector,
            scenario: request.scenario,
            injection: request.injection,
            run_id: request.run_id,
        })?),
    }))
}

impl FaultFailureArtifactSource for ChaosFaultHandle {
    fn collect_failure_artifacts(
        &self,
        collector: &ArtifactCollector,
        case_name: &str,
        total: usize,
        index: usize,
        suffix: &str,
    ) -> Result<()> {
        collect_chaos_failure_artifacts(
            self.guard.as_ref(),
            collector,
            case_name,
            total,
            index,
            suffix,
        )
    }
}

impl FaultLifecyclePort for ChaosFaultHandle {
    fn wait_active(&self, timeout: Duration) -> Result<()> {
        if self.active_required {
            self.guard.wait_active(timeout)?;
        }
        Ok(())
    }

    fn ensure_active(&self, stage: &str) -> Result<()> {
        if self.active_required {
            self.guard.ensure_active(stage)?;
        }
        Ok(())
    }

    fn delete(&mut self, timeout: Duration) -> Result<()> {
        self.guard.delete(timeout)
    }

    fn snapshot(&self, stage: &str) -> Result<FaultStatusSnapshot> {
        chaos_fault_snapshot(self.guard.as_ref(), stage)
    }

    fn failure_artifacts(&self) -> Option<&dyn FaultFailureArtifactSource> {
        Some(self)
    }

    fn recover_delete_timeout(
        &mut self,
        request: &FaultDeleteTimeoutRecoveryRequest<'_>,
    ) -> Result<Option<FaultDeleteTimeoutRecovery>> {
        if !self.guard.is_kind("iochaos") {
            return Ok(None);
        }
        Ok(recover_stuck_iochaos_finalizer(
            request.config,
            request.collector,
            request.case_name,
            self.guard.as_mut(),
            request.run_id,
            request.original_error,
            request.delete_started_at,
        )?
        .map(FaultDeleteTimeoutRecovery::from))
    }
}

impl FaultFailureArtifactSource for PodKillFaultHandle {
    fn collect_failure_artifacts(
        &self,
        collector: &ArtifactCollector,
        case_name: &str,
        total: usize,
        index: usize,
        suffix: &str,
    ) -> Result<()> {
        collect_chaos_failure_artifacts(
            self.guard.as_ref(),
            collector,
            case_name,
            total,
            index,
            suffix,
        )
    }
}

impl FaultLifecyclePort for PodKillFaultHandle {
    fn wait_active(&self, timeout: Duration) -> Result<()> {
        wait_for_rustfs_pod_deletion(&self.config, &self.before_pods, timeout)
    }

    fn ensure_active(&self, _stage: &str) -> Result<()> {
        Ok(())
    }

    fn delete(&mut self, timeout: Duration) -> Result<()> {
        self.guard.delete(timeout)?;
        wait_for_rustfs_pod_replacement(&self.config, &self.before_pods, timeout)
    }

    fn snapshot(&self, stage: &str) -> Result<FaultStatusSnapshot> {
        chaos_fault_snapshot(self.guard.as_ref(), stage)
    }

    fn failure_artifacts(&self) -> Option<&dyn FaultFailureArtifactSource> {
        Some(self)
    }
}

impl FaultLifecyclePort for DmFlakeyFaultHandle {
    fn wait_active(&self, _timeout: Duration) -> Result<()> {
        Ok(())
    }

    fn ensure_active(&self, stage: &str) -> Result<()> {
        self.guard.ensure_active(stage)?;
        Ok(())
    }

    fn requires_recovery_boundary(&self) -> bool {
        self.guard.requires_crash_boundary()
    }

    fn prepare_recovery_boundary(&mut self, timeout: Duration, started_at_ms: u64) -> Result<()> {
        self.guard.prepare_recovery_boundary(timeout, started_at_ms)
    }

    fn delete(&mut self, _timeout: Duration) -> Result<()> {
        self.guard.restore()
    }

    fn snapshot(&self, stage: &str) -> Result<FaultStatusSnapshot> {
        Ok(FaultStatusSnapshot {
            stage: stage.to_string(),
            resource_kind: Some("device-mapper".to_string()),
            resource_name: None,
            chaos_status: None,
            dm_status: Some(self.guard.snapshot(stage)?),
        })
    }

    fn recovery_dm_snapshot(&self) -> Option<DmStatusSnapshot> {
        self.guard.recovery_snapshot().cloned()
    }
}

fn chaos_fault_snapshot(guard: &ChaosGuard, stage: &str) -> Result<FaultStatusSnapshot> {
    Ok(FaultStatusSnapshot {
        stage: stage.to_string(),
        resource_kind: Some(guard.kind().to_string()),
        resource_name: Some(guard.name().to_string()),
        chaos_status: Some(serde_json::from_str(&guard.json()?)?),
        dm_status: None,
    })
}

fn chaos_manifest_artifact_name(total: usize, index: usize, injection: &FaultInjection) -> String {
    if total == 1 {
        "chaos-manifest.yaml".to_string()
    } else {
        format!(
            "chaos-manifest-{index:02}-{}.yaml",
            injection.kind().as_str()
        )
    }
}

fn chaos_resource_name_suffix(total: usize, index: usize) -> String {
    if total == 1 {
        String::new()
    } else {
        format!("-{index:02}")
    }
}

const IOCHAOS_FINALIZER_RECOVERY_WARNING: &str = "iochaos-finalizer-recovery-warning.json";
const IOCHAOS_FINALIZER_RECOVERY_DIAGNOSTIC: &str = "iochaos-finalizer-recovery-diagnostic.json";
const CHAOS_DAEMON_UNMOUNT_MARKER: &str = "unmount successfully";
const MANAGED_IOCHAOS_FINALIZERS: &[&str] = &[
    "chaos-mesh/records",
    "finalizer.chaos-mesh.org",
    "chaos-mesh.org/finalizer",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct IoChaosFinalizerRecoveryReport {
    iochaos_namespace: String,
    iochaos_name: String,
    source: String,
    original_error: String,
    finalizers: Vec<String>,
    managed_finalizers: Vec<String>,
    unmanaged_finalizers: Vec<String>,
    finalizers_after_patch: Vec<String>,
    deletion_timestamp: Option<String>,
    run_id_label_matches: bool,
    managed_label_matches: bool,
    podiochaos_action_cleared: bool,
    target_pod_injection_absent: bool,
    daemon_unmount_observed: bool,
    daemon_unmount_matches: Vec<DaemonUnmountLogEvidence>,
    target_pods_ready: bool,
    namespace_deleting: bool,
    safe_to_patch: bool,
    patched: bool,
    decision: String,
    target_pods: Vec<TargetPodRecoveryEvidence>,
    target_nodes: Vec<String>,
    podiochaos: PodIoChaosRecoveryEvidence,
    daemon_log_artifacts: Vec<String>,
    controller_log_artifact: String,
    daemon_log_since: String,
}

impl From<IoChaosFinalizerRecoveryReport> for FaultDeleteTimeoutRecovery {
    fn from(report: IoChaosFinalizerRecoveryReport) -> Self {
        Self {
            warning_artifact: IOCHAOS_FINALIZER_RECOVERY_WARNING,
            resource_name: report.iochaos_name,
            target_nodes: report.target_nodes,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct DaemonUnmountLogEvidence {
    node: String,
    artifact: String,
    line: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct TargetPodRecoveryEvidence {
    name: String,
    node: Option<String>,
    ready: bool,
    terminating: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct PodIoChaosRecoveryEvidence {
    query_succeeded: bool,
    related_count: usize,
    source_actions_remaining: usize,
    empty_action_objects: usize,
}

fn recover_stuck_iochaos_finalizer(
    config: &FaultTestConfig,
    collector: &ArtifactCollector,
    case_name: &str,
    guard: &mut ChaosGuard,
    run_id: &str,
    original_error: &anyhow::Error,
    delete_started_at: Instant,
) -> Result<Option<IoChaosFinalizerRecoveryReport>> {
    let mut report = collect_iochaos_finalizer_recovery_evidence(
        config,
        collector,
        case_name,
        guard,
        run_id,
        original_error,
        delete_started_at,
    )?;

    if !report.safe_to_patch {
        collector.write_text(
            case_name,
            IOCHAOS_FINALIZER_RECOVERY_DIAGNOSTIC,
            &serde_json::to_string_pretty(&report)?,
        )?;
        return Ok(None);
    }

    if let Err(error) = guard
        .replace_finalizers_and_wait_deleted(&report.finalizers_after_patch, config.cluster.timeout)
    {
        report.decision = format!("finalizer patch was allowed but failed: {error}");
        collector.write_text(
            case_name,
            IOCHAOS_FINALIZER_RECOVERY_DIAGNOSTIC,
            &serde_json::to_string_pretty(&report)?,
        )?;
        return Err(error);
    }
    report.patched = true;
    report.decision = "patched managed IOChaos finalizers after recovery evidence".to_string();
    collector.write_text(
        case_name,
        IOCHAOS_FINALIZER_RECOVERY_WARNING,
        &serde_json::to_string_pretty(&report)?,
    )?;
    Ok(Some(report))
}

fn collect_iochaos_finalizer_recovery_evidence(
    config: &FaultTestConfig,
    collector: &ArtifactCollector,
    case_name: &str,
    guard: &ChaosGuard,
    run_id: &str,
    original_error: &anyhow::Error,
    delete_started_at: Instant,
) -> Result<IoChaosFinalizerRecoveryReport> {
    let source = format!("{}/{}", guard.namespace(), guard.name());
    let iochaos_json_output = capture_command_artifact(
        collector,
        case_name,
        "iochaos-delete-timeout.json",
        Kubectl::new(&config.cluster)
            .namespaced(guard.namespace())
            .command(["get", guard.kind(), guard.name(), "-o", "json"]),
    )?;
    capture_command_artifact(
        collector,
        case_name,
        "iochaos-delete-timeout.yaml",
        Kubectl::new(&config.cluster)
            .namespaced(guard.namespace())
            .command(["get", guard.kind(), guard.name(), "-o", "yaml"]),
    )?;

    let iochaos = parse_success_json(&iochaos_json_output);
    let finalizers = iochaos
        .as_ref()
        .map(finalizers_from_resource)
        .unwrap_or_default();
    let managed_finalizers = finalizers
        .iter()
        .filter(|finalizer| is_managed_iochaos_finalizer(finalizer))
        .cloned()
        .collect::<Vec<_>>();
    let unmanaged_finalizers = finalizers
        .iter()
        .filter(|finalizer| !is_managed_iochaos_finalizer(finalizer))
        .cloned()
        .collect::<Vec<_>>();
    let finalizers_after_patch = unmanaged_finalizers.clone();
    let deletion_timestamp = iochaos
        .as_ref()
        .and_then(|value| value.pointer("/metadata/deletionTimestamp"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    let run_id_label_matches = iochaos
        .as_ref()
        .is_some_and(|value| resource_label_matches(value, chaos_mesh::RUN_ID_LABEL, run_id));
    let managed_label_matches = iochaos.as_ref().is_some_and(|value| {
        resource_label_matches(
            value,
            chaos_mesh::MANAGED_BY_LABEL,
            chaos_mesh::MANAGED_BY_VALUE,
        )
    });

    let target_pods_output = capture_command_artifact(
        collector,
        case_name,
        "target-pods-delete-timeout.json",
        Kubectl::new(&config.cluster)
            .namespaced(&config.cluster.test_namespace)
            .command([
                "get",
                "pod",
                "-l",
                &format!("rustfs.tenant={}", config.cluster.tenant_name),
                "-o",
                "json",
            ]),
    )?;
    let target_pods = parse_success_json(&target_pods_output)
        .as_ref()
        .map(target_pods_from_json)
        .unwrap_or_default();
    let target_pod_names = target_pods
        .iter()
        .map(|pod| pod.name.clone())
        .collect::<BTreeSet<_>>();
    let target_nodes = target_pods
        .iter()
        .filter_map(|pod| pod.node.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    capture_command_artifact(
        collector,
        case_name,
        "podiochaos-delete-timeout.yaml",
        Kubectl::new(&config.cluster)
            .namespaced(&config.cluster.test_namespace)
            .command(["get", "podiochaos", "-o", "yaml"]),
    )?;
    let podiochaos_json_output = capture_command_artifact(
        collector,
        case_name,
        "podiochaos-delete-timeout.json",
        Kubectl::new(&config.cluster)
            .namespaced(&config.cluster.test_namespace)
            .command(["get", "podiochaos", "-o", "json"]),
    )?;
    let podiochaos = parse_success_json(&podiochaos_json_output)
        .as_ref()
        .map(|value| podiochaos_recovery_evidence(value, &target_pod_names, &source))
        .unwrap_or(PodIoChaosRecoveryEvidence {
            query_succeeded: false,
            related_count: 0,
            source_actions_remaining: usize::MAX,
            empty_action_objects: 0,
        });

    let daemon_pods_output = capture_command_artifact(
        collector,
        case_name,
        "chaos-daemon-pods-delete-timeout.json",
        Kubectl::new(&config.cluster)
            .namespaced(&config.chaos_namespace)
            .command(["get", "pod", "-o", "json"]),
    )?;
    let daemon_pods = parse_success_json(&daemon_pods_output)
        .as_ref()
        .map(chaos_daemon_pods_from_json)
        .unwrap_or_default();
    let mut daemon_log_artifacts = Vec::new();
    let mut daemon_unmount_matches = Vec::new();
    let daemon_log_since = format!(
        "{}s",
        delete_started_at
            .elapsed()
            .as_secs()
            .saturating_add(30)
            .max(1)
    );
    for node in &target_nodes {
        let artifact = format!(
            "chaos-daemon-{}-delete-timeout.log",
            sanitize_artifact_token(node)
        );
        if let Some(daemon_pod) = daemon_pods
            .iter()
            .find(|pod| pod.node.as_deref() == Some(node.as_str()))
        {
            let output = capture_command_artifact(
                collector,
                case_name,
                &artifact,
                Kubectl::new(&config.cluster)
                    .namespaced(&config.chaos_namespace)
                    .command(vec![
                        "logs".to_string(),
                        format!("pod/{}", daemon_pod.name),
                        "--since".to_string(),
                        daemon_log_since.clone(),
                        "--tail=1000".to_string(),
                    ]),
            )?;
            daemon_unmount_matches.extend(
                unmount_success_log_lines(&output.stdout)
                    .into_iter()
                    .map(|line| DaemonUnmountLogEvidence {
                        node: node.clone(),
                        artifact: artifact.clone(),
                        line,
                    }),
            );
            daemon_log_artifacts.push(artifact);
        } else {
            collector.write_text(
                case_name,
                &artifact,
                &format!("no chaos-daemon pod was found on target node {node}\n"),
            )?;
            daemon_log_artifacts.push(artifact);
        }
    }

    let controller_log_artifact = "chaos-controller-manager-delete-timeout.log".to_string();
    capture_command_artifact(
        collector,
        case_name,
        &controller_log_artifact,
        Kubectl::new(&config.cluster)
            .namespaced(&config.chaos_namespace)
            .command(vec![
                "logs".to_string(),
                "deployment/chaos-controller-manager".to_string(),
                "--since".to_string(),
                daemon_log_since.clone(),
                "--tail=1000".to_string(),
            ]),
    )?;

    let namespace_json_output = capture_command_artifact(
        collector,
        case_name,
        "target-namespace-delete-timeout.json",
        Kubectl::new(&config.cluster).command([
            "get",
            "namespace",
            &config.cluster.test_namespace,
            "-o",
            "json",
        ]),
    )?;
    let namespace_deleting = parse_success_json(&namespace_json_output)
        .as_ref()
        .is_some_and(resource_has_deletion_timestamp);

    let podiochaos_action_cleared = podiochaos.query_succeeded
        && podiochaos.related_count > 0
        && podiochaos.empty_action_objects == podiochaos.related_count
        && podiochaos.source_actions_remaining == 0;
    let target_pod_injection_absent =
        podiochaos.query_succeeded && podiochaos.source_actions_remaining == 0;
    let target_pods_ready =
        !target_pods.is_empty() && target_pods.iter().all(|pod| pod.ready && !pod.terminating);
    let mut report = IoChaosFinalizerRecoveryReport {
        iochaos_namespace: guard.namespace().to_string(),
        iochaos_name: guard.name().to_string(),
        source,
        original_error: original_error.to_string(),
        finalizers,
        managed_finalizers,
        unmanaged_finalizers,
        finalizers_after_patch,
        deletion_timestamp,
        run_id_label_matches,
        managed_label_matches,
        podiochaos_action_cleared,
        target_pod_injection_absent,
        daemon_unmount_observed: !daemon_unmount_matches.is_empty(),
        daemon_unmount_matches,
        target_pods_ready,
        namespace_deleting,
        safe_to_patch: false,
        patched: false,
        decision: String::new(),
        target_pods,
        target_nodes,
        podiochaos,
        daemon_log_artifacts,
        controller_log_artifact,
        daemon_log_since,
    };
    report.safe_to_patch = iochaos_finalizer_patch_allowed(&report);
    report.decision = if report.safe_to_patch {
        "recovery evidence satisfied; patching finalizers is allowed".to_string()
    } else {
        "recovery evidence incomplete; leaving IOChaos failure classification unchanged".to_string()
    };
    Ok(report)
}

fn iochaos_finalizer_patch_allowed(report: &IoChaosFinalizerRecoveryReport) -> bool {
    report.run_id_label_matches
        && report.managed_label_matches
        && !report.finalizers.is_empty()
        && !report.managed_finalizers.is_empty()
        && report.unmanaged_finalizers.is_empty()
        && report.deletion_timestamp.is_some()
        && (report.podiochaos_action_cleared || report.target_pod_injection_absent)
        && report.daemon_unmount_observed
        && (report.target_pods_ready || report.namespace_deleting)
}

fn is_managed_iochaos_finalizer(finalizer: &str) -> bool {
    MANAGED_IOCHAOS_FINALIZERS.contains(&finalizer)
}

fn capture_command_artifact(
    collector: &ArtifactCollector,
    case_name: &str,
    file_name: &str,
    command: CommandSpec,
) -> Result<CommandOutput> {
    let output = command.run()?;
    let content = format!(
        "$ {cmd}\nexit: {code:?}\n\nstdout:\n{stdout}\n\nstderr:\n{stderr}\n",
        cmd = command.display(),
        code = output.code,
        stdout = output.stdout,
        stderr = output.stderr
    );
    collector.write_text(case_name, file_name, &content)?;
    Ok(output)
}

fn parse_success_json(output: &CommandOutput) -> Option<serde_json::Value> {
    if output.code == Some(0) {
        serde_json::from_str(&output.stdout).ok()
    } else {
        None
    }
}

fn finalizers_from_resource(value: &serde_json::Value) -> Vec<String> {
    value
        .pointer("/metadata/finalizers")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .map(str::to_string)
        .collect()
}

fn resource_label_matches(value: &serde_json::Value, key: &str, expected: &str) -> bool {
    value
        .pointer("/metadata/labels")
        .and_then(serde_json::Value::as_object)
        .and_then(|labels| labels.get(key))
        .and_then(serde_json::Value::as_str)
        == Some(expected)
}

fn resource_has_deletion_timestamp(value: &serde_json::Value) -> bool {
    value
        .pointer("/metadata/deletionTimestamp")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|timestamp| !timestamp.is_empty())
}

fn target_pods_from_json(value: &serde_json::Value) -> Vec<TargetPodRecoveryEvidence> {
    value
        .pointer("/items")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| {
            let name = item
                .pointer("/metadata/name")
                .and_then(serde_json::Value::as_str)?
                .to_string();
            let node = item
                .pointer("/spec/nodeName")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string);
            let ready = item
                .pointer("/status/conditions")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
                .any(|condition| {
                    condition.get("type").and_then(serde_json::Value::as_str) == Some("Ready")
                        && condition.get("status").and_then(serde_json::Value::as_str)
                            == Some("True")
                });
            let terminating = resource_has_deletion_timestamp(item);
            Some(TargetPodRecoveryEvidence {
                name,
                node,
                ready,
                terminating,
            })
        })
        .collect()
}

fn podiochaos_recovery_evidence(
    value: &serde_json::Value,
    target_pod_names: &BTreeSet<String>,
    source: &str,
) -> PodIoChaosRecoveryEvidence {
    let related = value
        .pointer("/items")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter(|item| {
            item.pointer("/metadata/name")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|name| target_pod_names.contains(name))
        })
        .collect::<Vec<_>>();
    let mut source_actions_remaining = 0usize;
    let mut empty_action_objects = 0usize;
    for item in &related {
        let actions = item
            .pointer("/spec/actions")
            .and_then(serde_json::Value::as_array);
        match actions {
            Some(actions) if actions.is_empty() => empty_action_objects += 1,
            Some(actions) => {
                source_actions_remaining += actions
                    .iter()
                    .filter(|action| {
                        action.get("source").and_then(serde_json::Value::as_str) == Some(source)
                    })
                    .count();
            }
            None => empty_action_objects += 1,
        }
    }

    PodIoChaosRecoveryEvidence {
        query_succeeded: true,
        related_count: related.len(),
        source_actions_remaining,
        empty_action_objects,
    }
}

fn chaos_daemon_pods_from_json(value: &serde_json::Value) -> Vec<TargetPodRecoveryEvidence> {
    value
        .pointer("/items")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter(|item| {
            let name_matches = item
                .pointer("/metadata/name")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|name| name.contains("chaos-daemon"));
            let label_matches = item
                .pointer("/metadata/labels")
                .and_then(serde_json::Value::as_object)
                .is_some_and(|labels| {
                    labels
                        .get("app.kubernetes.io/component")
                        .and_then(serde_json::Value::as_str)
                        == Some("chaos-daemon")
                });
            name_matches || label_matches
        })
        .filter_map(|item| {
            Some(TargetPodRecoveryEvidence {
                name: item
                    .pointer("/metadata/name")
                    .and_then(serde_json::Value::as_str)?
                    .to_string(),
                node: item
                    .pointer("/spec/nodeName")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string),
                ready: true,
                terminating: resource_has_deletion_timestamp(item),
            })
        })
        .collect()
}

fn unmount_success_log_lines(log: &str) -> Vec<String> {
    log.lines()
        .filter(|line| {
            line.to_ascii_lowercase()
                .contains(CHAOS_DAEMON_UNMOUNT_MARKER)
        })
        .take(8)
        .map(str::to_string)
        .collect()
}

fn sanitize_artifact_token(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
                ch
            } else {
                '-'
            }
        })
        .collect()
}

fn collect_fault_artifacts(
    collector: &ArtifactCollector,
    case_name: &str,
    fault: &AppliedFaults,
    suffix: &str,
) -> Result<()> {
    let status = if fault.len() == 1 {
        fault
            .snapshot(suffix)
            .and_then(|snapshot| serde_json::to_string_pretty(&snapshot).map_err(Into::into))
    } else {
        fault
            .snapshots(suffix)
            .and_then(|snapshots| serde_json::to_string_pretty(&snapshots).map_err(Into::into))
    }
    .unwrap_or_else(|error| format!("failed to collect fault status: {error}"));
    collector.write_text(case_name, &format!("fault-status-{suffix}.json"), &status)?;

    fault.collect_failure_artifacts(collector, case_name, suffix)?;
    Ok(())
}

fn collect_chaos_failure_artifacts(
    guard: &ChaosGuard,
    collector: &ArtifactCollector,
    case_name: &str,
    total: usize,
    index: usize,
    suffix: &str,
) -> Result<()> {
    let describe = guard
        .describe()
        .unwrap_or_else(|error| format!("failed to describe chaos before cleanup: {error}"));
    let describe_name = chaos_artifact_name(total, index, "chaos-describe", suffix, "txt");
    collector.write_text(case_name, &describe_name, &describe)?;

    let yaml = guard
        .yaml()
        .unwrap_or_else(|error| format!("failed to get chaos yaml before cleanup: {error}"));
    let yaml_name = chaos_artifact_name(total, index, "chaos", suffix, "yaml");
    collector.write_text(case_name, &yaml_name, &yaml)?;
    Ok(())
}

fn chaos_artifact_name(
    total: usize,
    index: usize,
    prefix: &str,
    suffix: &str,
    extension: &str,
) -> String {
    if total == 1 {
        format!("{prefix}-{suffix}.{extension}")
    } else {
        format!("{prefix}-{suffix}-{index:02}.{extension}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PodRuntimeState {
    name: String,
    uid: String,
    phase: String,
    containers_ready: bool,
    restart_count: u64,
    terminating: bool,
}

fn rustfs_pod_runtime_states(config: &ClusterTestConfig) -> Result<Vec<PodRuntimeState>> {
    let selector = format!("rustfs.tenant={}", config.tenant_name);
    let output = Kubectl::new(config)
        .namespaced(&config.test_namespace)
        .command(["get", "pod", "-l", &selector, "-o", "json"])
        .run_checked()?;
    let value = serde_json::from_str::<serde_json::Value>(&output.stdout)
        .context("parse RustFS pod list json")?;
    let items = value
        .pointer("/items")
        .and_then(serde_json::Value::as_array)
        .context("RustFS pod list did not contain an items array")?;
    let mut pods = items
        .iter()
        .map(|item| {
            let metadata = item
                .get("metadata")
                .context("RustFS pod did not contain metadata")?;
            let name = metadata
                .get("name")
                .and_then(serde_json::Value::as_str)
                .context("RustFS pod metadata did not contain a name")?;
            let uid = metadata
                .get("uid")
                .and_then(serde_json::Value::as_str)
                .context("RustFS pod metadata did not contain a uid")?;
            let phase = item
                .pointer("/status/phase")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("Unknown");
            let container_statuses = item
                .pointer("/status/containerStatuses")
                .and_then(serde_json::Value::as_array);
            let containers_ready = container_statuses.is_some_and(|statuses| {
                !statuses.is_empty()
                    && statuses.iter().all(|status| {
                        status
                            .get("ready")
                            .and_then(serde_json::Value::as_bool)
                            .unwrap_or(false)
                    })
            });
            let restart_count = container_statuses
                .into_iter()
                .flatten()
                .filter_map(|status| status.get("restartCount"))
                .filter_map(serde_json::Value::as_u64)
                .sum();

            Ok(PodRuntimeState {
                name: name.to_string(),
                uid: uid.to_string(),
                phase: phase.to_string(),
                containers_ready,
                restart_count,
                terminating: metadata.get("deletionTimestamp").is_some(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    pods.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(pods)
}

fn stable_pod_fingerprint(
    pods: &[PodRuntimeState],
    expected_pod_count: usize,
) -> Option<Vec<(String, u64)>> {
    if pods.len() != expected_pod_count
        || pods
            .iter()
            .any(|pod| pod.phase != "Running" || !pod.containers_ready || pod.terminating)
    {
        return None;
    }

    Some(
        pods.iter()
            .map(|pod| (pod.uid.clone(), pod.restart_count))
            .collect(),
    )
}

async fn wait_for_stable_rustfs_pods(
    config: &ClusterTestConfig,
    expected_pod_count: usize,
    stable_window: Duration,
) -> Result<()> {
    let deadline = Instant::now() + config.timeout;
    let mut stable_since = None;
    let mut stable_fingerprint = None;
    let mut last_snapshot = Vec::new();
    let mut last_error = "not checked yet".to_string();

    eprintln!(
        "waiting for {expected_pod_count} RustFS pods to remain ready without restarts for {stable_window:?}"
    );
    loop {
        if Instant::now() >= deadline {
            bail!(
                "timed out waiting for stable RustFS pods after {:?}\nlast: {last_snapshot:?}\nlast error: {last_error}",
                config.timeout
            );
        }

        match rustfs_pod_runtime_states(config) {
            Ok(current) => {
                if let Some(fingerprint) = stable_pod_fingerprint(&current, expected_pod_count) {
                    if stable_fingerprint.as_ref() != Some(&fingerprint) {
                        stable_since = Some(Instant::now());
                        stable_fingerprint = Some(fingerprint);
                    }
                    if stable_since.is_some_and(|started| started.elapsed() >= stable_window) {
                        eprintln!("RustFS pods remained stable for {stable_window:?}");
                        return Ok(());
                    }
                } else {
                    stable_since = None;
                    stable_fingerprint = None;
                }
                last_snapshot = current;
                last_error = "none".to_string();
            }
            Err(error) => {
                stable_since = None;
                stable_fingerprint = None;
                last_error = error.to_string();
            }
        }

        async_sleep(Duration::from_secs(1)).await;
    }
}

async fn wait_for_ready_tenant(config: &ClusterTestConfig) -> Result<DynamicObject> {
    let client = kube_client::default_client().await?;
    let tenants = kube_client::tenant_api(client, &config.test_namespace);
    wait::wait_for_tenant_ready(tenants, &config.tenant_name, config.timeout).await
}

fn s3_access(config: &FaultTestConfig) -> Result<(String, Option<PortForwardGuard>)> {
    let cluster = &config.cluster;
    if config.use_cluster_ip {
        let service = format!("{}-io", cluster.tenant_name);
        let output = Kubectl::new(cluster)
            .namespaced(&cluster.test_namespace)
            .command([
                "get".to_string(),
                "service".to_string(),
                service.clone(),
                "-o".to_string(),
                "jsonpath={.spec.clusterIP}".to_string(),
            ])
            .run_checked()
            .with_context(|| format!("read ClusterIP for fault-test service {service:?}"))?;
        let cluster_ip = output.stdout.trim();
        ensure!(
            !cluster_ip.is_empty() && cluster_ip != "None",
            "fault-test service {service:?} does not have a ClusterIP"
        );
        let host = if cluster_ip.contains(':') {
            format!("[{cluster_ip}]")
        } else {
            cluster_ip.to_string()
        };
        return Ok((format!("http://{host}:9000"), None));
    }

    let spec = PortForwardSpec::tenant_io_on_available_port(
        &cluster.test_namespace,
        &cluster.tenant_name,
    )?;
    let endpoint = spec.local_base_url();
    let kubectl = Kubectl::new(cluster);
    Ok((endpoint, Some(spec.start_with_temp_log(&kubectl)?)))
}

async fn ensure_s3_access(
    port_forward: &mut Option<PortForwardGuard>,
    config: &ClusterTestConfig,
    endpoint: &str,
) -> Result<()> {
    if let Some(guard) = port_forward {
        if guard.ensure_running().is_err() {
            let local_port = endpoint
                .rsplit_once(':')
                .and_then(|(_, port)| port.parse::<u16>().ok())
                .context("parse local S3 port-forward endpoint")?;
            let spec = PortForwardSpec::tenant_io_with_local_port(
                &config.test_namespace,
                &config.tenant_name,
                local_port,
            );
            let kubectl = Kubectl::new(config);
            *guard = spec.start_with_temp_log(&kubectl)?;
        }
        return wait_for_tenant_s3(guard, endpoint, config.timeout).await;
    }

    wait_for_s3_endpoint(endpoint, config.timeout).await
}

async fn wait_for_tenant_s3(
    port_forward: &mut PortForwardGuard,
    endpoint: &str,
    timeout: Duration,
) -> Result<()> {
    port_forward.ensure_running()?;
    wait_for_s3_endpoint(endpoint, timeout)
        .await
        .with_context(|| {
            format!(
                "S3 port-forward was not ready; command: {}; log {}:\n{}",
                port_forward.command_display(),
                port_forward.log_path().display(),
                port_forward.log_contents()
            )
        })
}

/// Whether the prefill object at `index` is created as a directory marker.
/// Pure function of (seed, index) so reruns with the same workload seed pick
/// the same keys.
fn is_directory_marker_index(percent: u8, seed: u64, index: usize) -> bool {
    if percent == 0 {
        return false;
    }
    let mut value = seed ^ (index as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0x4449_524B;
    value ^= value >> 30;
    value = value.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94D0_49BB_1331_11EB);
    value ^= value >> 31;
    value % 100 < u64::from(percent)
}

async fn prefill_objects(
    s3: &S3WorkloadClient,
    history: &Recorder,
    run_id: &str,
    plan: &WorkloadPlan,
    count: usize,
    prefill_concurrency: usize,
    directory_marker_percent: u8,
) -> Result<Vec<ObjectSpec>> {
    let tasks = (0..count).map(|index| {
        let s3 = s3.clone();
        let history = history.clone();
        let run_id = run_id.to_string();
        let size_bytes = plan.size_at(index);
        let seed = plan.seed;
        async move {
            // A deterministic (seed-stable) fraction of prefill objects are
            // zero-byte directory markers so the trailing-slash key path is
            // exercised through the whole fault/recovery cycle.
            let object = if is_directory_marker_index(directory_marker_percent, seed, index) {
                ObjectSpec::prepare_directory_marker(&run_id, index, seed)
            } else {
                ObjectSpec::prepare_seeded(&run_id, index, size_bytes, seed)
            };
            let spec = object.spec.clone();
            let write_outcome = s3.put_object(&object, &history).await?;
            ensure!(
                write_outcome == OperationOutcome::Ok,
                "prefill PUT failed before fault injection for key {}: {:?}",
                spec.key,
                write_outcome
            );
            verify_prefill_object(&s3, &history, &spec).await?;
            Ok::<_, anyhow::Error>((index, spec))
        }
    });
    let mut objects = stream::iter(tasks)
        .buffer_unordered(prefill_concurrency)
        .try_collect::<Vec<_>>()
        .await?;
    objects.sort_by_key(|(index, _)| *index);

    Ok(objects.into_iter().map(|(_, object)| object).collect())
}

async fn verify_prefill_object(
    s3: &S3WorkloadClient,
    history: &Recorder,
    spec: &ObjectSpec,
) -> Result<()> {
    let mut last_outcome = None;
    for attempt in 1..=PREFILL_VERIFY_ATTEMPTS {
        let get = s3.get_object_result(&spec.key, history).await?;
        last_outcome = Some(get.outcome);
        match get.outcome {
            OperationOutcome::Ok => {
                let body = get.body.as_deref().with_context(|| {
                    format!(
                        "prefill GET verification returned no body before fault injection for key {}",
                        spec.key
                    )
                })?;
                ensure!(
                    spec.matches_body(body),
                    "prefill GET verification returned mismatched bytes before fault injection for key {}: expected size={} sha256={}, got size={} sha256={}",
                    spec.key,
                    spec.size_bytes,
                    spec.sha256,
                    body.len(),
                    sha256_hex(body)
                );
                return Ok(());
            }
            OperationOutcome::Timeout | OperationOutcome::Unknown
                if attempt < PREFILL_VERIFY_ATTEMPTS =>
            {
                async_sleep(PREFILL_VERIFY_RETRY_DELAY).await;
            }
            _ => break,
        }
    }

    bail!(
        "prefill GET verification failed before fault injection for key {} after {} attempt(s): {:?}",
        spec.key,
        PREFILL_VERIFY_ATTEMPTS,
        last_outcome
    )
}

#[allow(clippy::too_many_arguments)]
async fn run_mixed_workload(
    s3: &S3WorkloadClient,
    history: &Recorder,
    run_id: &str,
    plan: &WorkloadPlan,
    prefilled: &[ObjectSpec],
    start_index: usize,
    count: usize,
    ranged_get_percent: u8,
) -> Result<MixedWorkloadResult> {
    let tasks = (0..count).map(|offset| {
        let s3 = s3.clone();
        let history = history.clone();
        let run_id = run_id.to_string();
        let index = start_index + offset;
        let size_bytes = plan.size_at(index);
        let seed = plan.seed;
        let existing = prefilled[plan.existing_object_offset(offset, prefilled.len())].clone();
        async move {
            let mut result = MixedTaskResult::new(index);
            match plan.operation_mix.operation_at(offset) {
                WorkloadOperation::Put => {
                    let object = ObjectSpec::prepare_seeded(&run_id, index, size_bytes, seed);
                    let spec = object.spec.clone();
                    let verified = s3.put_and_verify_object(&object, &history).await?;
                    result.puts.push(verified.write_outcome);
                    if let Some(get_outcome) = verified.verify_get_outcome {
                        result.gets.push(get_outcome);
                    }
                    if verified.write_outcome != OperationOutcome::Ok {
                        result.unconfirmed_puts.push(spec);
                    }
                }
                WorkloadOperation::Overwrite => {
                    let object = existing.prepare_overwrite(index as u64 + 1);
                    let spec = object.spec.clone();
                    let verified = s3.put_and_verify_object(&object, &history).await?;
                    result.puts.push(verified.write_outcome);
                    if let Some(get_outcome) = verified.verify_get_outcome {
                        result.gets.push(get_outcome);
                    }
                    if verified.write_outcome != OperationOutcome::Ok {
                        result.unconfirmed_puts.push(spec);
                    }
                }
                WorkloadOperation::Get => {
                    // Deterministically (seeded, resume-stable) turn a slice of
                    // GETs into ranged reads so the sharded read path is
                    // exercised at offsets, not only via whole-object streams.
                    let range =
                        ranged_get_range(ranged_get_percent, seed, index, existing.size_bytes);
                    let outcome = match range {
                        Some(range) => {
                            s3.get_object_range_result(&existing.key, range, &history)
                                .await?
                                .outcome
                        }
                        None => s3.get_object_result(&existing.key, &history).await?.outcome,
                    };
                    result.gets.push(outcome);
                }
                WorkloadOperation::List => {
                    let prefix = ObjectSpec::key_prefix(&run_id);
                    let outcome = if s3.list_prefix(&prefix, &history).await?.is_some() {
                        OperationOutcome::Ok
                    } else {
                        OperationOutcome::Unknown
                    };
                    result.lists.push(outcome);
                }
                WorkloadOperation::Delete => {
                    let (delete_outcome, verify_get) =
                        s3.delete_and_verify_absent(&existing.key, &history).await?;
                    result.deletes.push(delete_outcome);
                    if let Some(get_outcome) = verify_get {
                        result.gets.push(get_outcome);
                    }
                }
                WorkloadOperation::Multipart => {
                    let object = ObjectSpec::prepare_seeded(&run_id, index, size_bytes, seed);
                    let spec = object.spec.clone();
                    let complete_outcome = s3.complete_multipart_object(&object, &history).await?;
                    result.multipart_completes.push(complete_outcome);
                    if complete_outcome == OperationOutcome::Ok {
                        result
                            .gets
                            .push(s3.get_object_result(&spec.key, &history).await?.outcome);
                    } else {
                        result.unconfirmed_puts.push(spec);
                    }
                    let abort_object = ObjectSpec::prepare_seeded(
                        &run_id,
                        plan.object_count + index,
                        4 * 1024,
                        seed,
                    );
                    result
                        .multipart_aborts
                        .push(s3.abort_multipart_object(&abort_object, &history).await?);
                }
            }
            Ok::<_, anyhow::Error>(result)
        }
    });
    let results = stream::iter(tasks)
        .buffer_unordered(plan.concurrency)
        .collect::<Vec<_>>()
        .await;
    let mut completed = Vec::with_capacity(count);
    for result in results {
        completed.push(result?);
    }
    completed.sort_by_key(|result| result.index);

    let mut summary = WorkloadSummary::new(plan);
    let mut unconfirmed_puts = Vec::new();
    for result in completed {
        summary.record_all(&result);
        unconfirmed_puts.extend(result.unconfirmed_puts);
    }

    summary.require_exercised()?;
    Ok(MixedWorkloadResult {
        summary,
        unconfirmed_puts,
    })
}

/// Decide whether the GET at `index` runs as a ranged read, and derive a
/// deterministic in-bounds byte range for it. Everything is a pure function of
/// (seed, index) so reruns with the same workload seed replay identical
/// operations.
fn ranged_get_range(percent: u8, seed: u64, index: usize, size_bytes: usize) -> Option<ByteRange> {
    if percent == 0 || size_bytes < 2 {
        return None;
    }
    let mix = |salt: u64| -> u64 {
        let mut value = seed ^ (index as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ salt;
        value ^= value >> 30;
        value = value.wrapping_mul(0xBF58_476D_1CE4_E5B9);
        value ^= value >> 27;
        value = value.wrapping_mul(0x94D0_49BB_1331_11EB);
        value ^ (value >> 31)
    };
    if mix(0x52414E47) % 100 >= u64::from(percent) {
        return None;
    }
    let size = size_bytes as u64;
    // Length in [1, size], offset in [0, size - length]: covers single-byte,
    // interior, and suffix reads without ever leaving the object bounds.
    let length = 1 + mix(0x4C454E47) % size;
    let offset = mix(0x4F464653) % (size - length + 1);
    Some(ByteRange { offset, length })
}

async fn recommit_unconfirmed_objects(
    s3: &S3WorkloadClient,
    history: &Recorder,
    objects: &[ObjectSpec],
    concurrency: usize,
) -> RecommitReport {
    let tasks = objects.iter().cloned().map(|object| {
        let s3 = s3.clone();
        let history = history.clone();
        async move {
            let prepared = object.prepare();
            match s3.put_object_record(&prepared, &history).await {
                Ok(record) => {
                    let verify_get_outcome = if record.outcome == OperationOutcome::Ok {
                        match s3.get_object_result(&object.key, &history).await {
                            Ok(get) => Some(get.outcome),
                            Err(_) => Some(OperationOutcome::Unknown),
                        }
                    } else {
                        None
                    };
                    RecommitAttempt::from_record(object, record, verify_get_outcome)
                }
                Err(error) => {
                    RecommitAttempt::from_harness_error(object, format!("record PUT: {error}"))
                }
            }
        }
    });
    let mut attempts = stream::iter(tasks)
        .buffer_unordered(concurrency)
        .collect::<Vec<_>>()
        .await;
    attempts.sort_by(|left, right| left.key.cmp(&right.key));
    RecommitReport::from_attempts(attempts)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct RecommitReport {
    attempted: usize,
    committed: usize,
    failed: usize,
    harness_errors: usize,
    attempts: Vec<RecommitAttempt>,
}

impl RecommitReport {
    fn from_attempts(attempts: Vec<RecommitAttempt>) -> Self {
        let committed = attempts
            .iter()
            .filter(|attempt| attempt.outcome == Some(OperationOutcome::Ok))
            .count();
        let failed = attempts
            .iter()
            .filter(|attempt| attempt.is_s3_failure() || attempt.verify_get_failed())
            .count();
        let harness_errors = attempts
            .iter()
            .filter(|attempt| attempt.is_harness_error())
            .count();
        Self {
            attempted: attempts.len(),
            committed,
            failed,
            harness_errors,
            attempts,
        }
    }

    fn has_failures(&self) -> bool {
        self.failed > 0 || self.harness_errors > 0
    }

    fn failure_classification(&self) -> &'static str {
        if self.harness_errors > 0 {
            "test_harness"
        } else {
            "product_or_environment"
        }
    }

    fn failure_message(&self) -> String {
        let sample = self
            .attempts
            .iter()
            .filter_map(RecommitAttempt::failure_sample)
            .take(5)
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "{} of {} previously unconfirmed PUTs did not commit after recovery; harness_errors={}{}",
            self.failed,
            self.attempted,
            self.harness_errors,
            if sample.is_empty() {
                String::new()
            } else {
                format!("; sample: {sample}")
            }
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct RecommitAttempt {
    key: String,
    size_bytes: usize,
    sha256: String,
    outcome: Option<OperationOutcome>,
    verify_get_outcome: Option<OperationOutcome>,
    http_status: Option<u16>,
    error: Option<String>,
    harness_error: Option<String>,
}

impl RecommitAttempt {
    fn from_record(
        object: ObjectSpec,
        record: OperationRecord,
        verify_get_outcome: Option<OperationOutcome>,
    ) -> Self {
        Self {
            key: object.key,
            size_bytes: object.size_bytes,
            sha256: object.sha256,
            outcome: Some(record.outcome),
            verify_get_outcome,
            http_status: record.http_status,
            error: record.error,
            harness_error: None,
        }
    }

    fn from_harness_error(object: ObjectSpec, error: String) -> Self {
        Self {
            key: object.key,
            size_bytes: object.size_bytes,
            sha256: object.sha256,
            outcome: None,
            verify_get_outcome: None,
            http_status: None,
            error: None,
            harness_error: Some(error),
        }
    }

    fn is_s3_failure(&self) -> bool {
        matches!(
            self.outcome,
            Some(
                OperationOutcome::NotFound
                    | OperationOutcome::Failed
                    | OperationOutcome::Timeout
                    | OperationOutcome::Unknown
            )
        )
    }

    fn is_harness_error(&self) -> bool {
        self.harness_error.is_some()
    }

    fn verify_get_failed(&self) -> bool {
        self.outcome == Some(OperationOutcome::Ok)
            && self.verify_get_outcome != Some(OperationOutcome::Ok)
    }

    fn failure_sample(&self) -> Option<String> {
        if let Some(error) = &self.harness_error {
            return Some(format!("{}=harness_error({error})", self.key));
        }
        let outcome = self.outcome?;
        if outcome == OperationOutcome::Ok {
            if self.verify_get_failed() {
                return Some(format!(
                    "{}=verify_get({:?})",
                    self.key, self.verify_get_outcome
                ));
            }
            return None;
        }
        let status = self
            .http_status
            .map(|status| format!(" status={status}"))
            .unwrap_or_default();
        let error = self
            .error
            .as_ref()
            .map(|error| format!(" error={error}"))
            .unwrap_or_default();
        Some(format!("{}={outcome:?}{status}{error}", self.key))
    }
}

#[derive(Debug)]
struct MixedTaskResult {
    index: usize,
    puts: Vec<OperationOutcome>,
    gets: Vec<OperationOutcome>,
    deletes: Vec<OperationOutcome>,
    lists: Vec<OperationOutcome>,
    multipart_completes: Vec<OperationOutcome>,
    multipart_aborts: Vec<OperationOutcome>,
    unconfirmed_puts: Vec<ObjectSpec>,
}

impl MixedTaskResult {
    fn new(index: usize) -> Self {
        Self {
            index,
            puts: Vec::new(),
            gets: Vec::new(),
            deletes: Vec::new(),
            lists: Vec::new(),
            multipart_completes: Vec::new(),
            multipart_aborts: Vec::new(),
            unconfirmed_puts: Vec::new(),
        }
    }
}

#[derive(Debug)]
struct MixedWorkloadResult {
    summary: WorkloadSummary,
    unconfirmed_puts: Vec<ObjectSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct CrashWindowEvidence {
    scenario: String,
    run_id: String,
    fault_active_at_ms: u64,
    crash_boundary_started_at_ms: u64,
    committed_versioned_mutations: usize,
    trigger_operation_id: String,
    trigger_kind: OperationKind,
    trigger_key: String,
    trigger_version_id: String,
    trigger_acknowledged_at_ms: u64,
    ack_to_crash_boundary_ms: u64,
}

fn crash_window_evidence(
    records: &[OperationRecord],
    scenario: &str,
    run_id: &str,
    fault_active_at_ms: u64,
    crash_boundary_started_at_ms: u64,
) -> Result<CrashWindowEvidence> {
    let committed = records
        .iter()
        .filter(|record| {
            record.scenario == scenario
                && record.outcome == OperationOutcome::Ok
                && record.durability_cohort == Some(DurabilityCohort::FaultActive)
                && matches!(
                    record.kind,
                    OperationKind::Put
                        | OperationKind::Delete
                        | OperationKind::CompleteMultipartUpload
                )
                && record.version_id.is_some()
                && record.ended_at_ms >= fault_active_at_ms
                && record.ended_at_ms <= crash_boundary_started_at_ms
        })
        .collect::<Vec<_>>();
    let trigger = committed
        .iter()
        .max_by_key(|record| record.ended_at_ms)
        .copied()
        .context(
            "drop_writes crash window contained no successfully acknowledged versioned PUT, DELETE marker, or multipart completion; refusing a vacuous durability verdict",
        )?;
    Ok(CrashWindowEvidence {
        scenario: scenario.to_string(),
        run_id: run_id.to_string(),
        fault_active_at_ms,
        crash_boundary_started_at_ms,
        committed_versioned_mutations: committed.len(),
        trigger_operation_id: trigger.id.clone(),
        trigger_kind: trigger.kind,
        trigger_key: trigger
            .key
            .clone()
            .context("crash trigger mutation is missing its object key")?,
        trigger_version_id: trigger
            .version_id
            .clone()
            .context("crash trigger mutation is missing its version id")?,
        trigger_acknowledged_at_ms: trigger.ended_at_ms,
        ack_to_crash_boundary_ms: crash_boundary_started_at_ms.saturating_sub(trigger.ended_at_ms),
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct WorkloadSummary {
    seed: u64,
    object_count: usize,
    concurrency: usize,
    total_payload_bytes: u64,
    puts: OutcomeCounts,
    gets: OutcomeCounts,
    deletes: OutcomeCounts,
    lists: OutcomeCounts,
    multipart_completes: OutcomeCounts,
    multipart_aborts: OutcomeCounts,
    recommitted_after_recovery: usize,
}

impl WorkloadSummary {
    fn new(plan: &WorkloadPlan) -> Self {
        Self {
            seed: plan.seed,
            object_count: plan.object_count,
            concurrency: plan.concurrency,
            total_payload_bytes: plan.total_payload_bytes,
            puts: OutcomeCounts::default(),
            gets: OutcomeCounts::default(),
            deletes: OutcomeCounts::default(),
            lists: OutcomeCounts::default(),
            multipart_completes: OutcomeCounts::default(),
            multipart_aborts: OutcomeCounts::default(),
            recommitted_after_recovery: 0,
        }
    }

    fn record_all(&mut self, result: &MixedTaskResult) {
        for outcome in &result.puts {
            self.puts.record(*outcome);
        }
        for outcome in &result.gets {
            self.gets.record(*outcome);
        }
        for outcome in &result.deletes {
            self.deletes.record(*outcome);
        }
        for outcome in &result.lists {
            self.lists.record(*outcome);
        }
        for outcome in &result.multipart_completes {
            self.multipart_completes.record(*outcome);
        }
        for outcome in &result.multipart_aborts {
            self.multipart_aborts.record(*outcome);
        }
    }

    fn require_exercised(&self) -> Result<()> {
        ensure!(
            self.puts.total() > 0
                && self.gets.total() > 0
                && self.deletes.total() > 0
                && self.lists.total() > 0
                && self.multipart_completes.total() > 0
                && self.multipart_aborts.total() > 0,
            "fault workload did not exercise every required S3 object path: {self:?}"
        );
        Ok(())
    }

    fn require_fault_evidence(&self, require_client_disruption: bool) -> Result<()> {
        if require_client_disruption {
            ensure!(
                self.disrupted() > 0,
                "fault was applied but the S3 workload observed no client-visible disrupted operation; increase RUSTFS_FAULT_TEST_WORKLOAD_OBJECTS or RUSTFS_FAULT_TEST_PERCENT, or set RUSTFS_FAULT_TEST_REQUIRE_CLIENT_DISRUPTION=0 if this is expected"
            );
        } else if self.disrupted() == 0 {
            eprintln!(
                "fault was applied, but the S3 workload observed no client-visible disrupted operation"
            );
        }
        Ok(())
    }

    fn disrupted(&self) -> usize {
        self.puts.disrupted()
            + self.gets.disrupted()
            + self.deletes.disrupted()
            + self.lists.disrupted()
            + self.multipart_completes.disrupted()
            + self.multipart_aborts.disrupted()
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
struct OutcomeCounts {
    ok: usize,
    not_found: usize,
    failed: usize,
    timeout: usize,
    unknown: usize,
}

impl OutcomeCounts {
    fn record(&mut self, outcome: OperationOutcome) {
        match outcome {
            OperationOutcome::Ok => self.ok += 1,
            OperationOutcome::NotFound => self.not_found += 1,
            OperationOutcome::Failed => self.failed += 1,
            OperationOutcome::Timeout => self.timeout += 1,
            OperationOutcome::Unknown => self.unknown += 1,
        }
    }

    fn total(&self) -> usize {
        self.ok + self.not_found + self.failed + self.timeout + self.unknown
    }

    fn disrupted(&self) -> usize {
        self.failed + self.timeout + self.unknown
    }
}

fn bucket_name(run_id: &str) -> String {
    let suffix = run_id
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .take(16)
        .collect::<String>()
        .to_ascii_lowercase();
    format!("rustfs-fault-{suffix}")
}

fn generated_seed() -> u64 {
    let run = Uuid::new_v4();
    let mut bytes = [0; 8];
    bytes.copy_from_slice(&run.as_bytes()[..8]);
    u64::from_le_bytes(bytes)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

fn warp_bucket_name(run_id: &str) -> String {
    format!("{}-warp", bucket_name(run_id))
}

#[cfg(test)]
mod tests {
    use super::{
        AppliedFaults, DaemonUnmountLogEvidence, FaultFailureArtifactSource, FaultLifecyclePort,
        IoChaosFinalizerRecoveryReport, OutcomeCounts, PodIoChaosRecoveryEvidence, PodRuntimeState,
        RecommitAttempt, RecommitReport, TargetPodRecoveryEvidence, WorkloadSummary, bucket_name,
        chaos_artifact_name, chaos_daemon_pods_from_json, chaos_manifest_artifact_name,
        chaos_resource_name_suffix, finalizers_from_resource, iochaos_finalizer_patch_allowed,
        podiochaos_recovery_evidence, resource_has_deletion_timestamp, resource_label_matches,
        stable_pod_fingerprint, target_pods_from_json, unmount_success_log_lines, warp_bucket_name,
        write_quorum_loss_topology_shape,
    };
    use crate::fault::history::{ByteRange, OperationOutcome, OperationRecord};

    /// The ranged-GET sampler must be a pure function of (seed, index): zero
    /// percent and tiny objects never sample, derived ranges always stay in
    /// bounds, and identical inputs replay identically.
    #[test]
    fn ranged_get_range_is_deterministic_and_in_bounds() {
        assert!(super::ranged_get_range(0, 42, 7, 4096).is_none());
        assert!(super::ranged_get_range(100, 42, 7, 1).is_none());

        for index in 0..2000usize {
            if let Some(range) = super::ranged_get_range(100, 42, index, 4096) {
                assert!(
                    range.length >= 1 && range.length <= 4096,
                    "length {range:?}"
                );
                assert!(range.offset + range.length <= 4096, "bounds {range:?}");
            } else {
                panic!("percent=100 must always sample");
            }
        }

        let sampled = (0..2000usize)
            .filter(|index| super::ranged_get_range(30, 42, *index, 4096).is_some())
            .count();
        assert!(
            (300..=900).contains(&sampled),
            "30% sampling grossly off: {sampled}/2000"
        );
        assert_eq!(
            super::ranged_get_range(30, 42, 5, 4096),
            super::ranged_get_range(30, 42, 5, 4096),
            "must replay identically"
        );
        assert_eq!(
            super::ranged_get_range(100, 42, 5, 4096),
            Some(ByteRange {
                offset: super::ranged_get_range(100, 42, 5, 4096).unwrap().offset,
                length: super::ranged_get_range(100, 42, 5, 4096).unwrap().length,
            })
        );
    }
    use crate::fault::plan::{
        DEFAULT_RUSTFS_DATA_VOLUME, FaultInjection, FaultKind, FaultSelection, FaultTarget,
    };
    use crate::fault::reporting::FaultStatusSnapshot;
    use crate::fault::scenarios::FaultBackend;
    use crate::fault::workload::WorkloadPlan;
    use crate::framework::artifacts::ArtifactCollector;
    use anyhow::Result;
    use serde_json::json;
    use std::collections::BTreeSet;
    use std::fs;
    use std::time::Duration;

    #[test]
    fn directory_marker_selection_is_deterministic_and_rate_bounded() {
        // 0% never selects; 100% always selects.
        assert!(!super::is_directory_marker_index(0, 42, 7));
        for index in 0..500 {
            assert!(super::is_directory_marker_index(100, 42, index));
        }
        // Same (seed, index) replays identically.
        assert_eq!(
            super::is_directory_marker_index(20, 42, 9),
            super::is_directory_marker_index(20, 42, 9)
        );
        // ~20% selection over a large index range.
        let selected = (0..2000)
            .filter(|index| super::is_directory_marker_index(20, 42, *index))
            .count();
        assert!(
            (200..=600).contains(&selected),
            "20% directory-marker selection grossly off: {selected}/2000"
        );
    }

    struct RecordingFaultBackend {
        name: &'static str,
        artifact_body: Option<&'static str>,
    }

    impl FaultFailureArtifactSource for RecordingFaultBackend {
        fn collect_failure_artifacts(
            &self,
            collector: &ArtifactCollector,
            case_name: &str,
            total: usize,
            index: usize,
            suffix: &str,
        ) -> Result<()> {
            let Some(body) = self.artifact_body else {
                return Ok(());
            };
            let artifact_name =
                chaos_artifact_name(total, index, "recording-artifact", suffix, "txt");
            collector.write_text(case_name, &artifact_name, body)?;
            Ok(())
        }
    }

    impl FaultLifecyclePort for RecordingFaultBackend {
        fn wait_active(&self, _timeout: Duration) -> Result<()> {
            Ok(())
        }

        fn ensure_active(&self, _stage: &str) -> Result<()> {
            Ok(())
        }

        fn delete(&mut self, _timeout: Duration) -> Result<()> {
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

        fn failure_artifacts(&self) -> Option<&dyn FaultFailureArtifactSource> {
            self.artifact_body
                .map(|_| self as &dyn FaultFailureArtifactSource)
        }
    }

    #[test]
    fn fault_bucket_name_is_s3_compatible_and_run_scoped() {
        assert_eq!(
            bucket_name("run-12345678-abcd-efgh"),
            "rustfs-fault-run12345678abcde"
        );
        assert_eq!(
            warp_bucket_name("run-12345678-abcd-efgh"),
            "rustfs-fault-run12345678abcde-warp"
        );
    }

    #[test]
    fn composite_fault_artifacts_and_resource_names_are_indexed() {
        let injection = FaultInjection::new(
            FaultKind::RustfsVolumeIoError,
            FaultBackend::ChaosMeshIoChaos,
            FaultTarget::RustfsVolume {
                path: DEFAULT_RUSTFS_DATA_VOLUME.to_string(),
            },
            FaultSelection::Percent(20),
            std::time::Duration::from_secs(60),
        )
        .expect("valid fault");

        assert_eq!(
            chaos_manifest_artifact_name(1, 0, &injection),
            "chaos-manifest.yaml"
        );
        assert_eq!(chaos_resource_name_suffix(1, 0), "");
        assert_eq!(
            chaos_manifest_artifact_name(2, 1, &injection),
            "chaos-manifest-01-rustfs_volume_io_error.yaml"
        );
        assert_eq!(chaos_resource_name_suffix(2, 1), "-01");
    }

    #[test]
    fn applied_faults_collects_declared_artifact_sources() {
        let faults = AppliedFaults::new(vec![
            Box::new(RecordingFaultBackend {
                name: "first",
                artifact_body: Some("first artifact"),
            }),
            Box::new(RecordingFaultBackend {
                name: "second",
                artifact_body: None,
            }),
            Box::new(RecordingFaultBackend {
                name: "third",
                artifact_body: Some("third artifact"),
            }),
        ]);
        let tempdir = tempfile::tempdir().expect("tempdir");
        let collector = ArtifactCollector::new(tempdir.path());

        faults
            .collect_failure_artifacts(&collector, "case", "failed")
            .expect("collect failure artifacts");

        let case_dir = collector.case_dir("case");
        assert_eq!(
            fs::read_to_string(case_dir.join("recording-artifact-failed-00.txt"))
                .expect("first artifact"),
            "first artifact"
        );
        assert_eq!(
            fs::read_to_string(case_dir.join("recording-artifact-failed-01.txt"))
                .expect("third artifact"),
            "third artifact"
        );
        assert!(
            !case_dir.join("recording-artifact-failed.txt").exists(),
            "multiple declared artifact sources must use stable indexed names"
        );
    }

    #[test]
    fn iochaos_finalizer_scope_requires_run_and_managed_labels() {
        let iochaos = json!({
            "metadata": {
                "labels": {
                    "rustfs-fault-test/run-id": "run-123",
                    "app.kubernetes.io/managed-by": "s3chaos"
                },
                "finalizers": ["chaos-mesh/records"],
                "deletionTimestamp": "2026-06-30T01:02:03Z"
            }
        });

        assert!(resource_label_matches(
            &iochaos,
            "rustfs-fault-test/run-id",
            "run-123"
        ));
        assert!(resource_label_matches(
            &iochaos,
            "app.kubernetes.io/managed-by",
            "s3chaos"
        ));
        assert_eq!(
            finalizers_from_resource(&iochaos),
            vec!["chaos-mesh/records"]
        );
        assert!(resource_has_deletion_timestamp(&iochaos));
    }

    #[test]
    fn podiochaos_evidence_tracks_current_source_actions() {
        let mut target_pods = BTreeSet::new();
        target_pods.insert("rustfs-0".to_string());
        let podiochaos = json!({
            "items": [
                {
                    "metadata": {"name": "rustfs-0"},
                    "spec": {
                        "actions": [
                            {"source": "chaos-mesh/rustfs-fault-io-eio"}
                        ]
                    }
                }
            ]
        });

        let evidence = podiochaos_recovery_evidence(
            &podiochaos,
            &target_pods,
            "chaos-mesh/rustfs-fault-io-eio",
        );

        assert_eq!(evidence.related_count, 1);
        assert_eq!(evidence.source_actions_remaining, 1);
        assert_eq!(evidence.empty_action_objects, 0);

        let cleared = json!({
            "items": [
                {
                    "metadata": {"name": "rustfs-0"},
                    "spec": {"actions": []}
                }
            ]
        });
        let evidence =
            podiochaos_recovery_evidence(&cleared, &target_pods, "chaos-mesh/rustfs-fault-io-eio");

        assert_eq!(evidence.related_count, 1);
        assert_eq!(evidence.source_actions_remaining, 0);
        assert_eq!(evidence.empty_action_objects, 1);
    }

    #[test]
    fn finalizer_patch_requires_complete_recovery_evidence() {
        let mut report = IoChaosFinalizerRecoveryReport {
            iochaos_namespace: "chaos-mesh".to_string(),
            iochaos_name: "rustfs-fault-io-eio-run-123".to_string(),
            source: "chaos-mesh/rustfs-fault-io-eio-run-123".to_string(),
            original_error: "timeout".to_string(),
            finalizers: vec!["chaos-mesh/records".to_string()],
            managed_finalizers: vec!["chaos-mesh/records".to_string()],
            unmanaged_finalizers: Vec::new(),
            finalizers_after_patch: Vec::new(),
            deletion_timestamp: Some("2026-06-30T01:02:03Z".to_string()),
            run_id_label_matches: true,
            managed_label_matches: true,
            podiochaos_action_cleared: true,
            target_pod_injection_absent: true,
            daemon_unmount_observed: true,
            daemon_unmount_matches: vec![DaemonUnmountLogEvidence {
                node: "node-a".to_string(),
                artifact: "chaos-daemon-node-a-delete-timeout.log".to_string(),
                line: "iochaos unmount successfully".to_string(),
            }],
            target_pods_ready: true,
            namespace_deleting: false,
            safe_to_patch: false,
            patched: false,
            decision: String::new(),
            target_pods: vec![TargetPodRecoveryEvidence {
                name: "rustfs-0".to_string(),
                node: Some("node-a".to_string()),
                ready: true,
                terminating: false,
            }],
            target_nodes: vec!["node-a".to_string()],
            podiochaos: PodIoChaosRecoveryEvidence {
                query_succeeded: true,
                related_count: 1,
                source_actions_remaining: 0,
                empty_action_objects: 1,
            },
            daemon_log_artifacts: vec!["chaos-daemon-node-a-delete-timeout.log".to_string()],
            controller_log_artifact: "chaos-controller-manager-delete-timeout.log".to_string(),
            daemon_log_since: "90s".to_string(),
        };

        assert!(iochaos_finalizer_patch_allowed(&report));

        report.daemon_unmount_observed = false;
        assert!(!iochaos_finalizer_patch_allowed(&report));

        report.daemon_unmount_observed = true;
        report.finalizers.push("example.com/cleanup".to_string());
        report
            .unmanaged_finalizers
            .push("example.com/cleanup".to_string());
        report
            .finalizers_after_patch
            .push("example.com/cleanup".to_string());
        assert!(!iochaos_finalizer_patch_allowed(&report));
    }

    #[test]
    fn finalizer_recovery_parses_target_pods_and_daemon_logs() {
        let pods = json!({
            "items": [
                {
                    "metadata": {"name": "rustfs-0"},
                    "spec": {"nodeName": "node-a"},
                    "status": {
                        "conditions": [
                            {"type": "Ready", "status": "True"}
                        ]
                    }
                }
            ]
        });
        let daemon_pods = json!({
            "items": [
                {
                    "metadata": {
                        "name": "chaos-daemon-abc",
                        "labels": {"app.kubernetes.io/component": "chaos-daemon"}
                    },
                    "spec": {"nodeName": "node-a"}
                }
            ]
        });

        let target_pods = target_pods_from_json(&pods);
        assert_eq!(target_pods[0].name, "rustfs-0");
        assert_eq!(target_pods[0].node.as_deref(), Some("node-a"));
        assert!(target_pods[0].ready);

        let daemon_pods = chaos_daemon_pods_from_json(&daemon_pods);
        assert_eq!(daemon_pods[0].name, "chaos-daemon-abc");
        assert!(!unmount_success_log_lines("iochaos unmount successfully").is_empty());
        assert_eq!(
            unmount_success_log_lines("old line\niochaos unmount successfully\nother"),
            vec!["iochaos unmount successfully"]
        );
    }

    #[test]
    fn workload_summary_counts_disrupted_operations() {
        let mut summary = WorkloadSummary::new(&WorkloadPlan::seeded(42, 40000, 80));
        summary.puts.record(OperationOutcome::Ok);
        summary.gets.record(OperationOutcome::Timeout);
        summary.gets.record(OperationOutcome::NotFound);
        summary.deletes.record(OperationOutcome::Ok);
        summary.lists.record(OperationOutcome::Ok);
        summary.multipart_completes.record(OperationOutcome::Ok);
        summary.multipart_aborts.record(OperationOutcome::Ok);

        assert_eq!(summary.puts.total(), 1);
        assert_eq!(summary.gets.total(), 2);
        assert_eq!(summary.disrupted(), 1);
        assert!(summary.require_exercised().is_ok());
        assert!(summary.require_fault_evidence(true).is_ok());
    }

    #[test]
    fn workload_summary_requires_every_object_operation_family() {
        let mut summary = WorkloadSummary::new(&WorkloadPlan::seeded(42, 40000, 80));
        summary.puts.record(OperationOutcome::Ok);
        summary.gets.record(OperationOutcome::Ok);
        summary.deletes.record(OperationOutcome::Ok);
        summary.lists.record(OperationOutcome::Ok);
        summary.multipart_completes.record(OperationOutcome::Ok);

        assert!(summary.require_exercised().is_err());

        summary.multipart_aborts.record(OperationOutcome::Ok);
        assert!(summary.require_exercised().is_ok());
    }

    #[test]
    fn workload_summary_can_require_fault_evidence() {
        let summary = WorkloadSummary {
            seed: 42,
            object_count: 40000,
            concurrency: 80,
            total_payload_bytes: 20_337_459_200,
            puts: OutcomeCounts {
                ok: 1,
                ..OutcomeCounts::default()
            },
            gets: OutcomeCounts {
                ok: 1,
                ..OutcomeCounts::default()
            },
            deletes: OutcomeCounts::default(),
            lists: OutcomeCounts::default(),
            multipart_completes: OutcomeCounts::default(),
            multipart_aborts: OutcomeCounts::default(),
            recommitted_after_recovery: 0,
        };

        assert!(summary.require_fault_evidence(false).is_ok());
        assert!(summary.require_fault_evidence(true).is_err());
    }

    #[test]
    fn crash_window_evidence_selects_the_latest_versioned_mutation_ack() {
        let records = [
            serde_json::from_value::<OperationRecord>(json!({
                "id": "op-1",
                "scenario": "dm-flakey-versioned-hot",
                "kind": "put",
                "bucket": "bucket",
                "key": "key-a",
                "value_sha256": "abc",
                "size_bytes": 4096,
                "version_id": "version-a",
                "started_at_ms": 110,
                "ended_at_ms": 120,
                "outcome": "ok",
                "http_status": 200,
                "error": null,
                "durability_cohort": "fault_active",
                "fault_window_relation": "during_fault"
            }))
            .expect("first record"),
            serde_json::from_value::<OperationRecord>(json!({
                "id": "op-2",
                "scenario": "dm-flakey-versioned-hot",
                "kind": "delete",
                "bucket": "bucket",
                "key": "key-b",
                "value_sha256": null,
                "size_bytes": null,
                "version_id": "delete-marker-b",
                "started_at_ms": 130,
                "ended_at_ms": 140,
                "outcome": "ok",
                "http_status": 204,
                "error": null,
                "durability_cohort": "fault_active",
                "fault_window_relation": "during_fault"
            }))
            .expect("second record"),
        ];

        let evidence =
            super::crash_window_evidence(&records, "dm-flakey-versioned-hot", "run-1", 100, 150)
                .expect("evidence");

        assert_eq!(evidence.scenario, "dm-flakey-versioned-hot");
        assert_eq!(evidence.run_id, "run-1");
        assert_eq!(evidence.committed_versioned_mutations, 2);
        assert_eq!(evidence.trigger_operation_id, "op-2");
        assert_eq!(evidence.trigger_version_id, "delete-marker-b");
        assert_eq!(evidence.ack_to_crash_boundary_ms, 10);
    }

    #[test]
    fn crash_window_evidence_rejects_a_vacuous_window() {
        assert!(
            super::crash_window_evidence(&[], "dm-flakey-versioned-hot", "run-1", 100, 150,)
                .is_err()
        );
    }

    #[test]
    fn recommit_report_counts_and_summarizes_failed_attempts() {
        let report = RecommitReport::from_attempts(vec![
            RecommitAttempt {
                key: "object-a".to_string(),
                size_bytes: 4096,
                sha256: "sha-a".to_string(),
                outcome: Some(OperationOutcome::Ok),
                verify_get_outcome: Some(OperationOutcome::Ok),
                http_status: Some(200),
                error: None,
                harness_error: None,
            },
            RecommitAttempt {
                key: "object-b".to_string(),
                size_bytes: 4096,
                sha256: "sha-b".to_string(),
                outcome: Some(OperationOutcome::Failed),
                verify_get_outcome: None,
                http_status: Some(503),
                error: Some("service unavailable".to_string()),
                harness_error: None,
            },
        ]);

        assert_eq!(report.attempted, 2);
        assert_eq!(report.committed, 1);
        assert_eq!(report.failed, 1);
        assert_eq!(report.harness_errors, 0);
        assert!(report.has_failures());
        assert!(
            report
                .failure_message()
                .contains("object-b=Failed status=503")
        );
        assert_eq!(report.failure_classification(), "product_or_environment");
    }

    #[test]
    fn recommit_report_separates_harness_errors_from_s3_failures() {
        let report = RecommitReport::from_attempts(vec![RecommitAttempt {
            key: "object-a".to_string(),
            size_bytes: 4096,
            sha256: "sha-a".to_string(),
            outcome: None,
            verify_get_outcome: None,
            http_status: None,
            error: None,
            harness_error: Some("record PUT: disk full".to_string()),
        }]);

        assert_eq!(report.attempted, 1);
        assert_eq!(report.committed, 0);
        assert_eq!(report.failed, 0);
        assert_eq!(report.harness_errors, 1);
        assert!(report.has_failures());
        assert_eq!(report.failure_classification(), "test_harness");
        assert!(
            report
                .failure_message()
                .contains("object-a=harness_error(record PUT: disk full)")
        );
    }

    #[test]
    fn stable_pod_fingerprint_requires_four_ready_unchanged_pods() {
        let pods = (0..4)
            .map(|index| PodRuntimeState {
                name: format!("rustfs-{index}"),
                uid: format!("uid-{index}"),
                phase: "Running".to_string(),
                containers_ready: true,
                restart_count: index,
                terminating: false,
            })
            .collect::<Vec<_>>();

        assert_eq!(
            stable_pod_fingerprint(&pods, 4),
            Some(vec![
                ("uid-0".to_string(), 0),
                ("uid-1".to_string(), 1),
                ("uid-2".to_string(), 2),
                ("uid-3".to_string(), 3),
            ])
        );
        assert!(stable_pod_fingerprint(&pods[..3], 4).is_none());

        let mut unready = pods;
        unready[0].containers_ready = false;
        assert!(stable_pod_fingerprint(&unready, 4).is_none());
    }

    #[test]
    fn write_quorum_loss_topology_shape_accepts_only_reference_shapes() {
        assert!(write_quorum_loss_topology_shape(4, &[1], "1").is_ok());
        assert!(write_quorum_loss_topology_shape(4, &[2], "2").is_ok());

        // Wrong server count: partitioning 2 of N != 4 proves nothing.
        assert!(write_quorum_loss_topology_shape(5, &[1], "1").is_err());
        assert!(write_quorum_loss_topology_shape(3, &[1], "1").is_err());
        // Multi-pool tenants are not the reference single-erasure-set layout.
        assert!(write_quorum_loss_topology_shape(4, &[1, 2], "1 2").is_err());
        // Absent volumesPerServer must fail closed, not default.
        assert!(write_quorum_loss_topology_shape(4, &[], "").is_err());
        // 16 drives resolve to EC 12+4, where a 2-server partition does not
        // break write quorum.
        assert!(write_quorum_loss_topology_shape(4, &[4], "4").is_err());
    }
}
