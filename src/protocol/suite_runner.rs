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
use futures::future::join_all;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::protocol::{
    artifact_validation::validate_protocol_artifacts_and_write_report,
    cases::{ProtocolCaseExecution, ProtocolCaseServices, run_protocol_case},
    catalog::{DEFAULT_PROTOCOL_VARIANT, protocol_case},
    clients::{
        admin::RustfsAdminClient,
        keycloak::KeycloakExternalIdentityProvider,
        s3::{AwsS3ClientFactory, ProtocolS3Client},
        sts::RustfsStsClient,
        web_identity::RustfsWebIdentityStsClient,
    },
    compatibility::{
        COMPATIBILITY_COVERAGE_FILE, compatibility_coverage_report, compatibility_live_status,
    },
    credentials::{AdminCredentials, CredentialProvider, EnvCredentialProvider},
    fixture::{
        cleanup::cleanup_registered_resources_with_external,
        naming::ProtocolResourceNamer,
        registry::{RESOURCE_REGISTRY_FILE, ResourceRegistry},
    },
    ports::{
        ProtocolAdminPort, ProtocolExternalIdentityPort, ProtocolS3Port, ProtocolWebIdentityStsPort,
    },
    preflight::{
        ProtocolPreflightSummary, ProtocolProbeCapabilities,
        cleanup_interrupted_mutating_permission_probe, enforce_stale_resource_policy,
        preflight_protocol_suite_with_external, run_mutating_permission_probe,
    },
    reporting::{
        PROTOCOL_JUNIT_FILE, ProtocolCaseStatus, ProtocolCleanupReport, ProtocolFailureSummary,
        ProtocolSuiteSummary, protocol_junit_xml,
    },
    suite::{ResolvedProtocolSuite, resolve_protocol_endpoint, resolve_protocol_suite_yaml},
    suite_plan::{
        ProtocolMutatingProbeStatus, ProtocolSuitePlan, ProtocolSuitePlanCase, TargetFingerprint,
    },
};

const DEFAULT_ARTIFACT_BASE: &str = "target/protocol-tests";

struct ProtocolRunFixture {
    suite: ResolvedProtocolSuite,
    endpoint: String,
    credentials: AdminCredentials,
    admin: RustfsAdminClient,
    s3: ProtocolS3Client,
    sts: RustfsStsClient,
    external_identity: Option<KeycloakExternalIdentityProvider>,
    web_identity_sts: Option<RustfsWebIdentityStsClient>,
    preflight: ProtocolPreflightSummary,
}

struct ProtocolCaseRunner<'a> {
    artifact_root: &'a Path,
    run_id: &'a str,
    fingerprint: &'a TargetFingerprint,
    namer: &'a ProtocolResourceNamer,
    admin: &'a RustfsAdminClient,
    s3: &'a ProtocolS3Client,
    sts: &'a RustfsStsClient,
    external_identity: Option<&'a dyn ProtocolExternalIdentityPort>,
    web_identity_sts: Option<&'a dyn ProtocolWebIdentityStsPort>,
    actor_clients: &'a AwsS3ClientFactory,
    api_version: &'a str,
}

pub async fn plan_protocol_suite_from_yaml(path: impl AsRef<Path>) -> Result<ProtocolSuitePlan> {
    let runtime = ProtocolRunFixture::connect(path).await?;
    ProtocolSuitePlan::generated(
        &runtime.suite,
        runtime.preflight.target_fingerprint.clone(),
        (&runtime.preflight).into(),
        protocol_artifact_base(),
    )
}

pub async fn run_protocol_suite_from_yaml(path: impl AsRef<Path>) -> Result<()> {
    ensure_dedicated_target_acknowledgement()?;
    let path = path.as_ref();
    let mut runtime = ProtocolRunFixture::connect(path).await?;
    let mut plan = ProtocolSuitePlan::generated(
        &runtime.suite,
        runtime.preflight.target_fingerprint.clone(),
        (&runtime.preflight).into(),
        protocol_artifact_base(),
    )?;
    let artifact_root = plan.artifact_root();
    fs::create_dir_all(artifact_root.join("cases"))?;
    fs::copy(path, artifact_root.join("protocol-suite.yaml"))
        .with_context(|| format!("copy protocol suite source {}", path.display()))?;
    write_json(&artifact_root.join("protocol-suite-plan.json"), &plan)?;
    write_json(
        &artifact_root.join("preflight-summary.json"),
        &runtime.preflight,
    )?;

    let mut registry = ResourceRegistry::create(
        &artifact_root,
        &plan.run_id,
        runtime.preflight.target_fingerprint.clone(),
    )?;
    registry.set_versioned_cleanup(
        plan.cases
            .iter()
            .any(|case| case.requires.iter().any(|item| item == "versioning")),
    )?;
    let namer = ProtocolResourceNamer::new(
        &plan.target.bucket_prefix,
        &plan.target.identity_prefix,
        &plan.run_id,
    )?;

    let probe_capabilities = ProtocolProbeCapabilities::from_suite(&runtime.suite);
    let mut probe_future = Box::pin(run_mutating_permission_probe(
        &namer,
        &mut registry,
        &runtime.admin,
        &runtime.s3,
        Some(&runtime.sts),
        probe_capabilities,
    ));
    let probe_result = tokio::select! {
        probe = &mut probe_future => Ok(probe),
        signal = shutdown_signal() => Err(signal),
    };
    drop(probe_future);
    let probe = match probe_result {
        Ok(probe) => probe,
        Err(signal) => {
            let reason = match signal {
                Ok(()) => {
                    "protocol suite interrupted during mutating preflight probe; cleanup requested"
                        .to_string()
                }
                Err(error) => format!(
                    "protocol signal handler failed during mutating preflight probe: {error}"
                ),
            };
            cleanup_interrupted_mutating_permission_probe(
                &mut registry,
                &runtime.admin,
                &runtime.s3,
                reason,
            )
            .await
        }
    };
    runtime.preflight.mutating_permission_probe = probe.summary.clone();
    plan.preflight = (&runtime.preflight).into();
    write_json(&artifact_root.join("protocol-suite-plan.json"), &plan)?;
    write_json(
        &artifact_root.join("preflight-summary.json"),
        &runtime.preflight,
    )?;
    write_json(
        &artifact_root.join("preflight-cleanup-report.json"),
        &probe.cleanup,
    )?;
    let mut probe_forbidden_secrets = probe.forbidden_secrets;

    let selected_cases = plan.cases.clone();
    let actor_clients = AwsS3ClientFactory::new(&runtime.endpoint, &runtime.suite.target.region);
    let preflight_failure = probe
        .summary
        .error
        .clone()
        .unwrap_or_else(|| "mutating preflight probe failed".to_string());
    let mut case_executions = Vec::with_capacity(selected_cases.len());
    let mut stop_reason = None;
    if probe.summary.status != ProtocolMutatingProbeStatus::Passed {
        case_executions.extend(selected_cases.iter().map(|case| {
            (
                ProtocolCaseExecution::preflight_failed(&case.id, &preflight_failure),
                ProtocolCleanupReport::empty(&runtime.suite.api_version),
            )
        }));
    } else {
        let wave_count = selected_cases
            .iter()
            .map(|case| case.wave_index)
            .max()
            .map_or(0, |wave| wave + 1);
        for wave_index in 0..wave_count {
            let wave = selected_cases
                .iter()
                .filter(|case| case.wave_index == wave_index)
                .collect::<Vec<_>>();
            if let Some(reason) = &stop_reason {
                case_executions.extend(wave.iter().map(|case| {
                    (
                        ProtocolCaseExecution::not_run(&case.id, reason),
                        ProtocolCleanupReport::empty(&runtime.suite.api_version),
                    )
                }));
                continue;
            }
            let case_runner = ProtocolCaseRunner {
                artifact_root: &artifact_root,
                run_id: &plan.run_id,
                fingerprint: &plan.target.fingerprint,
                namer: &namer,
                admin: &runtime.admin,
                s3: &runtime.s3,
                sts: &runtime.sts,
                external_identity: runtime
                    .external_identity
                    .as_ref()
                    .map(|provider| provider as &dyn ProtocolExternalIdentityPort),
                web_identity_sts: runtime
                    .web_identity_sts
                    .as_ref()
                    .map(|sts| sts as &dyn ProtocolWebIdentityStsPort),
                actor_clients: &actor_clients,
                api_version: &runtime.suite.api_version,
            };
            let futures = wave.iter().map(|case| case_runner.run(case));
            let wave_result = tokio::select! {
                results = join_all(futures) => Ok(results),
                signal = shutdown_signal() => Err(signal),
            };
            match wave_result {
                Ok(results) => {
                    for result in results {
                        let (execution, cleanup) = result?;
                        if !cleanup.succeeded && stop_reason.is_none() {
                            stop_reason = Some(format!(
                                "case {} cleanup failed; later waves were not started",
                                execution.report.case_id
                            ));
                        }
                        case_executions.push((execution, cleanup));
                    }
                }
                Err(signal) => {
                    stop_reason = Some(match signal {
                        Ok(()) => "protocol suite interrupted; cleanup requested".to_string(),
                        Err(error) => format!("protocol signal handler failed: {error}"),
                    });
                    for case in wave {
                        let cleanup = cleanup_case_registry_if_present(
                            &artifact_root,
                            &case.id,
                            &runtime.admin,
                            &runtime.s3,
                            runtime
                                .external_identity
                                .as_ref()
                                .map(|provider| provider as &dyn ProtocolExternalIdentityPort),
                            &runtime.suite.api_version,
                        )
                        .await;
                        case_executions
                            .push((ProtocolCaseExecution::interrupted(&case.id), cleanup));
                    }
                }
            }
        }
    }
    let fallback_cleanup = cleanup_suite_registries(
        &artifact_root,
        &selected_cases,
        &mut registry,
        &runtime.admin,
        &runtime.s3,
        runtime
            .external_identity
            .as_ref()
            .map(|provider| provider as &dyn ProtocolExternalIdentityPort),
        &runtime.suite.api_version,
    )
    .await;
    write_json(
        &artifact_root.join("cleanup-report.json"),
        &fallback_cleanup,
    )?;

    let mut case_report_paths = Vec::with_capacity(case_executions.len());
    let mut forbidden_case_secrets = Vec::new();
    for (execution, cleanup) in &case_executions {
        let case_dir = artifact_root.join("cases").join(&execution.report.case_id);
        fs::create_dir_all(&case_dir)?;
        let case_report_path = case_dir.join("case-report.json");
        write_json(&case_report_path, &execution.report)?;
        write_json(&case_dir.join("cleanup-report.json"), cleanup)?;
        write_json_lines(
            &case_dir.join("operation-history.jsonl"),
            &execution.report.assertions,
        )?;
        case_report_paths.push(relative_path(&artifact_root, &case_report_path)?);
        forbidden_case_secrets.extend(execution.forbidden_secrets.iter().cloned());
    }
    let junit_cases = case_executions
        .iter()
        .map(|(execution, cleanup)| (&execution.report, cleanup.succeeded))
        .collect::<Vec<_>>();
    fs::write(
        artifact_root.join(PROTOCOL_JUNIT_FILE),
        protocol_junit_xml(
            &runtime.suite.metadata.name,
            &junit_cases,
            fallback_cleanup.succeeded,
        ),
    )
    .with_context(|| format!("write protocol artifact {PROTOCOL_JUNIT_FILE}"))?;
    let live_compatibility = case_executions
        .iter()
        .filter(|(execution, _)| {
            protocol_case(&execution.report.case_id)
                .is_some_and(|case| case.tags.contains(&"compatibility"))
        })
        .map(|(execution, cleanup)| {
            (
                execution.report.case_id.clone(),
                compatibility_live_status(
                    execution.report.status,
                    execution.report.failure_phase.as_deref(),
                    cleanup.succeeded,
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();
    write_json(
        &artifact_root.join(COMPATIBILITY_COVERAGE_FILE),
        &compatibility_coverage_report(&live_compatibility)?,
    )?;

    let passed = case_executions.iter().all(|(execution, cleanup)| {
        execution.report.status == ProtocolCaseStatus::Passed && cleanup.succeeded
    }) && fallback_cleanup.succeeded;
    let first_failure = case_executions.iter().find(|(execution, cleanup)| {
        execution.report.status == ProtocolCaseStatus::Failed || !cleanup.succeeded
    });
    let failure_summary = if let Some((execution, cleanup)) = first_failure {
        let (stage, classification) = if execution.report.status == ProtocolCaseStatus::Failed {
            (
                execution
                    .report
                    .failure_phase
                    .clone()
                    .unwrap_or_else(|| "case".to_string()),
                "protocol-case-failure".to_string(),
            )
        } else {
            ("cleanup".to_string(), "cleanup-failure".to_string())
        };
        let case_base = format!("cases/{}", execution.report.case_id);
        let mut evidence = vec![
            format!("{case_base}/case-report.json"),
            format!("{case_base}/cleanup-report.json"),
            RESOURCE_REGISTRY_FILE.to_string(),
        ];
        if !cleanup.succeeded || !fallback_cleanup.succeeded {
            evidence.push("cleanup-report.json".to_string());
        }
        let failure = ProtocolFailureSummary {
            api_version: runtime.suite.api_version.clone(),
            kind: "ProtocolFailureSummary".to_string(),
            stage,
            classification,
            case_id: Some(execution.report.case_id.clone()),
            evidence,
        };
        write_json(
            &artifact_root.join("protocol-failure-summary.json"),
            &failure,
        )?;
        Some("protocol-failure-summary.json".to_string())
    } else if !fallback_cleanup.succeeded {
        write_json(
            &artifact_root.join("protocol-failure-summary.json"),
            &ProtocolFailureSummary {
                api_version: runtime.suite.api_version.clone(),
                kind: "ProtocolFailureSummary".to_string(),
                stage: "cleanup".to_string(),
                classification: "cleanup-failure".to_string(),
                case_id: None,
                evidence: vec![
                    "cleanup-report.json".to_string(),
                    RESOURCE_REGISTRY_FILE.to_string(),
                ],
            },
        )?;
        Some("protocol-failure-summary.json".to_string())
    } else {
        None
    };
    let mut summary = ProtocolSuiteSummary {
        api_version: runtime.suite.api_version.clone(),
        kind: "ProtocolSuiteSummary".to_string(),
        suite: runtime.suite.metadata.name.clone(),
        run_id: plan.run_id.clone(),
        status: if passed {
            ProtocolCaseStatus::Passed
        } else {
            ProtocolCaseStatus::Failed
        },
        plan: "protocol-suite-plan.json".to_string(),
        preflight: "preflight-summary.json".to_string(),
        registry: RESOURCE_REGISTRY_FILE.to_string(),
        cleanup: "cleanup-report.json".to_string(),
        compatibility_coverage: COMPATIBILITY_COVERAGE_FILE.to_string(),
        case_reports: case_report_paths,
        failure_summary,
    };
    write_json(&artifact_root.join("protocol-suite-summary.json"), &summary)?;

    let mut forbidden = vec![
        runtime.credentials.access_key().to_string(),
        runtime.credentials.secret_key().to_string(),
    ];
    if let Some(token) = runtime.credentials.session_token() {
        forbidden.push(token.to_string());
    }
    if let Some(external_identity) = &runtime.external_identity {
        forbidden.extend(external_identity.forbidden_secrets());
    }
    forbidden.append(&mut probe_forbidden_secrets);
    forbidden.extend(forbidden_case_secrets);
    if let Err(error) = validate_phase_one_artifacts(&artifact_root, &forbidden) {
        write_json(
            &artifact_root.join("protocol-failure-summary.json"),
            &ProtocolFailureSummary {
                api_version: runtime.suite.api_version.clone(),
                kind: "ProtocolFailureSummary".to_string(),
                stage: "artifact-validation".to_string(),
                classification: "artifact-contract-failure".to_string(),
                case_id: first_failure.map(|(execution, _)| execution.report.case_id.clone()),
                evidence: vec![
                    "protocol-artifact-validation-report.json".to_string(),
                    "protocol-suite-summary.json".to_string(),
                ],
            },
        )?;
        summary.status = ProtocolCaseStatus::Failed;
        summary.failure_summary = Some("protocol-failure-summary.json".to_string());
        write_json(&artifact_root.join("protocol-suite-summary.json"), &summary)?;
        return Err(error).with_context(|| {
            format!(
                "validate Phase 1 protocol artifacts at {}",
                artifact_root.display()
            )
        });
    }

    if !passed {
        bail!(
            "protocol suite failed; artifacts preserved at {}",
            artifact_root.display()
        );
    }
    println!(
        "protocol suite {} passed; artifacts: {}",
        runtime.suite.metadata.name,
        artifact_root.display()
    );
    Ok(())
}

pub async fn cleanup_protocol_artifact_root(artifact_root: impl AsRef<Path>) -> Result<()> {
    let artifact_root = artifact_root.as_ref();
    ensure_dedicated_target_acknowledgement()?;
    let root_registry_path = artifact_root.join(RESOURCE_REGISTRY_FILE);
    let mut root_registry = load_cleanup_registry(&root_registry_path)?;
    let credentials = EnvCredentialProvider.resolve("root")?;
    let expected = root_registry.target_fingerprint.clone();
    let admin = RustfsAdminClient::new(&expected.endpoint, &expected.region, credentials.clone())?;
    let s3 =
        ProtocolS3Client::for_admin(&expected.endpoint, &expected.region, &credentials).await?;
    verify_cleanup_target(&admin, &expected).await?;

    let mut combined = ProtocolCleanupReport::empty(&root_registry.api_version);
    let cases_dir = artifact_root.join("cases");
    if cases_dir.is_dir() {
        let mut entries = Vec::new();
        match fs::read_dir(&cases_dir) {
            Ok(read_dir) => {
                for entry in read_dir {
                    match entry {
                        Ok(entry) => entries.push(entry),
                        Err(error) => combined.append(cleanup_registry_failure(
                            &root_registry.api_version,
                            &cases_dir,
                            error,
                        )),
                    }
                }
            }
            Err(error) => combined.append(cleanup_registry_failure(
                &root_registry.api_version,
                &cases_dir,
                error,
            )),
        }
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(error) => {
                    combined.append(cleanup_registry_failure(
                        &root_registry.api_version,
                        &entry.path(),
                        error,
                    ));
                    continue;
                }
            };
            if !file_type.is_dir() || file_type.is_symlink() {
                combined.append(cleanup_registry_failure(
                    &root_registry.api_version,
                    &entry.path(),
                    "protocol case artifact must be a non-symlink directory",
                ));
                continue;
            }
            let registry_path = entry.path().join(RESOURCE_REGISTRY_FILE);
            if !registry_path.is_file() {
                continue;
            }
            let mut case_registry = match load_cleanup_registry(&registry_path) {
                Ok(registry) => registry,
                Err(error) => {
                    combined.append(cleanup_registry_failure(
                        &root_registry.api_version,
                        &registry_path,
                        error,
                    ));
                    continue;
                }
            };
            if case_registry.run_id != root_registry.run_id
                || case_registry.target_fingerprint != expected
            {
                combined.append(cleanup_registry_failure(
                    &root_registry.api_version,
                    &registry_path,
                    "refuse cleanup because case registry ownership differs from the suite",
                ));
                continue;
            }
            let external_identity = match external_identity_for_registry(&case_registry) {
                Ok(provider) => provider,
                Err(error) => {
                    combined.append(cleanup_registry_failure(
                        &root_registry.api_version,
                        &registry_path,
                        error,
                    ));
                    continue;
                }
            };
            let cleanup = cleanup_registered_resources_with_external(
                &mut case_registry,
                &admin,
                &s3,
                external_identity
                    .as_ref()
                    .map(|provider| provider as &dyn ProtocolExternalIdentityPort),
            )
            .await;
            if let Err(error) = write_json(&entry.path().join("cleanup-report.json"), &cleanup) {
                combined.append(cleanup_registry_failure(
                    &root_registry.api_version,
                    &entry.path().join("cleanup-report.json"),
                    error,
                ));
            }
            combined.append(cleanup);
        }
    }
    let root_external_identity = external_identity_for_registry(&root_registry)?;
    combined.append(
        cleanup_registered_resources_with_external(
            &mut root_registry,
            &admin,
            &s3,
            root_external_identity
                .as_ref()
                .map(|provider| provider as &dyn ProtocolExternalIdentityPort),
        )
        .await,
    );
    let report_path = artifact_root.join("cleanup-report.json");
    write_json(&report_path, &combined)?;
    ensure!(
        combined.succeeded,
        "protocol cleanup left {} resource(s); inspect {}",
        combined.leftovers.len(),
        report_path.display()
    );
    println!(
        "protocol cleanup completed from artifact root: {}",
        artifact_root.display()
    );
    Ok(())
}

impl ProtocolCaseRunner<'_> {
    async fn run(
        &self,
        case: &ProtocolSuitePlanCase,
    ) -> Result<(ProtocolCaseExecution, ProtocolCleanupReport)> {
        let case_dir = self.artifact_root.join("cases").join(&case.id);
        fs::create_dir_all(&case_dir)?;
        let mut registry =
            ResourceRegistry::create(&case_dir, self.run_id, self.fingerprint.clone())?;
        registry.bind_case(
            &case.id,
            case.contract
                .as_ref()
                .map(|contract| contract.variant_id.as_str())
                .unwrap_or(DEFAULT_PROTOCOL_VARIANT),
        )?;
        registry.set_versioned_cleanup(case.requires.iter().any(|item| item == "versioning"))?;
        let case_namer = self.namer.for_worker(case.worker_index);
        let execution = run_protocol_case(
            &case.id,
            &case_namer,
            &mut registry,
            ProtocolCaseServices {
                admin: self.admin,
                admin_s3: self.s3,
                sts: self.sts,
                external_identity: self.external_identity,
                web_identity_sts: self.web_identity_sts,
                actor_clients: self.actor_clients,
            },
        )
        .await;
        let cleanup = cleanup_registered_resources_with_external(
            &mut registry,
            self.admin,
            self.s3,
            self.external_identity,
        )
        .await;
        if cleanup.api_version != self.api_version {
            bail!("case {} cleanup apiVersion changed unexpectedly", case.id);
        }
        Ok((execution, cleanup))
    }
}

async fn cleanup_case_registry_if_present(
    artifact_root: &Path,
    case_id: &str,
    admin: &impl ProtocolAdminPort,
    s3: &impl ProtocolS3Port,
    external_identity: Option<&dyn ProtocolExternalIdentityPort>,
    api_version: &str,
) -> ProtocolCleanupReport {
    let registry_path = artifact_root
        .join("cases")
        .join(case_id)
        .join(RESOURCE_REGISTRY_FILE);
    if !registry_path.is_file() {
        return ProtocolCleanupReport::empty(api_version);
    }
    match ResourceRegistry::load_path(&registry_path) {
        Ok(mut registry) => {
            cleanup_registered_resources_with_external(&mut registry, admin, s3, external_identity)
                .await
        }
        Err(error) => cleanup_registry_failure(api_version, &registry_path, error),
    }
}

async fn cleanup_suite_registries(
    artifact_root: &Path,
    cases: &[ProtocolSuitePlanCase],
    root_registry: &mut ResourceRegistry,
    admin: &impl ProtocolAdminPort,
    s3: &impl ProtocolS3Port,
    external_identity: Option<&dyn ProtocolExternalIdentityPort>,
    api_version: &str,
) -> ProtocolCleanupReport {
    let mut combined = ProtocolCleanupReport::empty(api_version);
    for case in cases {
        combined.append(
            cleanup_case_registry_if_present(
                artifact_root,
                &case.id,
                admin,
                s3,
                external_identity,
                api_version,
            )
            .await,
        );
    }
    combined.append(
        cleanup_registered_resources_with_external(root_registry, admin, s3, external_identity)
            .await,
    );
    combined
}

fn cleanup_registry_failure(
    api_version: &str,
    registry_path: &Path,
    error: impl std::fmt::Display,
) -> ProtocolCleanupReport {
    let resource = registry_path.display().to_string();
    ProtocolCleanupReport {
        api_version: api_version.to_string(),
        kind: "ProtocolCleanupReport".to_string(),
        attempts: vec![crate::protocol::reporting::ProtocolCleanupAttempt {
            resource_id: format!("registry:{resource}"),
            resource_kind: "registry".to_string(),
            resource_name: resource.clone(),
            retry_count: 0,
            succeeded: false,
            error: Some(error.to_string()),
        }],
        leftovers: vec![format!("registry:{resource}")],
        succeeded: false,
    }
}

pub async fn cleanup_protocol_registry_path(registry_path: impl AsRef<Path>) -> Result<()> {
    let registry_path = registry_path.as_ref();
    ensure!(
        registry_path.file_name().and_then(|name| name.to_str()) == Some(RESOURCE_REGISTRY_FILE),
        "standalone protocol cleanup requires a file named {RESOURCE_REGISTRY_FILE}"
    );
    let parent = registry_path
        .parent()
        .context("resource registry path has no parent")?;
    cleanup_protocol_registry(
        registry_path.to_path_buf(),
        parent.join("cleanup-report.json"),
    )
    .await
}

async fn cleanup_protocol_registry(registry_path: PathBuf, report_path: PathBuf) -> Result<()> {
    ensure_dedicated_target_acknowledgement()?;
    let mut registry = load_cleanup_registry(&registry_path)?;
    let credentials = EnvCredentialProvider.resolve("root")?;
    let expected = registry.target_fingerprint.clone();
    let admin = RustfsAdminClient::new(&expected.endpoint, &expected.region, credentials.clone())?;
    let s3 =
        ProtocolS3Client::for_admin(&expected.endpoint, &expected.region, &credentials).await?;
    verify_cleanup_target(&admin, &expected).await?;
    let external_identity = external_identity_for_registry(&registry)?;
    let cleanup = cleanup_registered_resources_with_external(
        &mut registry,
        &admin,
        &s3,
        external_identity
            .as_ref()
            .map(|provider| provider as &dyn ProtocolExternalIdentityPort),
    )
    .await;
    write_json(&report_path, &cleanup)?;
    ensure!(
        cleanup.succeeded,
        "protocol cleanup left {} resource(s); inspect {}",
        cleanup.leftovers.len(),
        report_path.display()
    );
    println!(
        "protocol cleanup completed from registry: {}",
        registry_path.display()
    );
    Ok(())
}

fn load_cleanup_registry(path: &Path) -> Result<ResourceRegistry> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect resource registry {}", path.display()))?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "resource registry must be a regular non-symlink file"
    );
    ResourceRegistry::load_path(path)
}

fn external_identity_for_registry(
    registry: &ResourceRegistry,
) -> Result<Option<KeycloakExternalIdentityProvider>> {
    let identities = registry
        .pending_cleanup()
        .filter(|resource| {
            resource.kind
                == crate::protocol::fixture::registry::ResourceKind::ExternalIdentitySubject
        })
        .map(|resource| {
            resource
                .external_identity
                .clone()
                .context("external identity registry entry omitted its provider coordinates")
        })
        .collect::<Result<BTreeSet<_>>>()?;
    ensure!(
        identities.len() <= 1,
        "resource registry contains multiple external identity coordinates"
    );
    let Some(expected) = identities.into_iter().next() else {
        return Ok(None);
    };
    ensure!(
        expected.provider == "keycloak",
        "unsupported external identity provider {} in resource registry",
        expected.provider
    );
    let provider = KeycloakExternalIdentityProvider::from_env(&expected.profile)?;
    let actual = provider.coordinates();
    ensure!(
        actual == expected,
        "refuse external identity cleanup because configured provider coordinates differ from the registry: registry={expected:?} adapter={actual:?}"
    );
    Ok(Some(provider))
}

async fn verify_cleanup_target(
    admin: &impl ProtocolAdminPort,
    expected: &TargetFingerprint,
) -> Result<()> {
    ensure!(
        !expected.deployment_id.starts_with("s3-endpoint:"),
        "refuse standalone protocol cleanup because the artifact has no verifiable deployment fingerprint"
    );
    let info = admin.server_info().await?;
    let actual = TargetFingerprint::new(
        &expected.endpoint,
        &expected.region,
        info.deployment_id,
        info.mode,
        info.region,
    )?;
    ensure!(
        actual == *expected,
        "refuse protocol cleanup because the live target fingerprint differs from the registry"
    );
    Ok(())
}

async fn shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .context("install SIGTERM handler for protocol cleanup")?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result.context("listen for Ctrl-C")?,
            _ = terminate.recv() => {}
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.context("listen for Ctrl-C")
    }
}

impl ProtocolRunFixture {
    async fn connect(path: impl AsRef<Path>) -> Result<Self> {
        let suite = resolve_protocol_suite_yaml(path)?;
        let endpoint = resolve_protocol_endpoint(&suite.target.endpoint)?;
        let credentials = EnvCredentialProvider.resolve(&suite.target.credentials.admin_profile)?;
        let admin = RustfsAdminClient::new(&endpoint, &suite.target.region, credentials.clone())?;
        let s3 = ProtocolS3Client::for_admin(&endpoint, &suite.target.region, &credentials).await?;
        let sts = RustfsStsClient::new(&endpoint, &suite.target.region)?;
        let (external_identity, web_identity_sts) = match &suite.target.external_identity {
            Some(config) => (
                Some(KeycloakExternalIdentityProvider::from_env(&config.profile)?),
                Some(RustfsWebIdentityStsClient::new(&endpoint)?),
            ),
            None => (None, None),
        };
        let stale_resource_policy = stale_resource_policy()?;
        let preflight = preflight_protocol_suite_with_external(
            &suite,
            &endpoint,
            &admin,
            &s3,
            external_identity
                .as_ref()
                .map(|provider| provider as &dyn ProtocolExternalIdentityPort),
            stale_resource_policy,
        )
        .await?;
        enforce_stale_resource_policy(&preflight)?;
        Ok(Self {
            suite,
            endpoint,
            credentials,
            admin,
            s3,
            sts,
            external_identity,
            web_identity_sts,
            preflight,
        })
    }
}

fn stale_resource_policy() -> Result<&'static str> {
    if std::env::var("RUSTFS_PROTOCOL_TEST_ALLOW_STALE").as_deref() == Ok("1") {
        ensure!(
            std::env::var("CI").is_err(),
            "RUSTFS_PROTOCOL_TEST_ALLOW_STALE is forbidden in CI"
        );
        Ok("warn-local-debug")
    } else {
        Ok("fail")
    }
}

fn protocol_artifact_base() -> PathBuf {
    std::env::var("RUSTFS_PROTOCOL_TEST_ARTIFACTS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_ARTIFACT_BASE))
}

fn ensure_dedicated_target_acknowledgement() -> Result<()> {
    ensure!(
        std::env::var("RUSTFS_PROTOCOL_TEST_DEDICATED").as_deref() == Ok("1"),
        "protocol tests require a dedicated RustFS target; set RUSTFS_PROTOCOL_TEST_DEDICATED=1 after verifying the target"
    );
    Ok(())
}

fn write_json(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    fs::write(path, format!("{}\n", serde_json::to_string_pretty(value)?))
        .with_context(|| format!("write protocol artifact {}", path.display()))
}

fn write_json_lines<T: serde::Serialize>(path: &Path, values: &[T]) -> Result<()> {
    let mut contents = String::new();
    for value in values {
        contents.push_str(&serde_json::to_string(value)?);
        contents.push('\n');
    }
    fs::write(path, contents).with_context(|| format!("write protocol artifact {}", path.display()))
}

fn relative_path(root: &Path, path: &Path) -> Result<String> {
    Ok(path
        .strip_prefix(root)
        .with_context(|| {
            format!(
                "protocol artifact {} is outside root {}",
                path.display(),
                root.display()
            )
        })?
        .display()
        .to_string())
}

fn validate_phase_one_artifacts(root: &Path, forbidden: &[String]) -> Result<()> {
    validate_protocol_artifacts_and_write_report(root, forbidden).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::{
        cleanup_suite_registries, validate_phase_one_artifacts, write_json, write_json_lines,
    };
    use crate::protocol::{
        compatibility::{COMPATIBILITY_COVERAGE_FILE, compatibility_coverage_report},
        credentials::ActorCredential,
        fixture::registry::{
            RESOURCE_REGISTRY_FILE, ResourceKind, ResourceRegistry, ResourceState,
        },
        ports::{
            ProtocolAdminError, ProtocolAdminPort, ProtocolObjectVersion, ProtocolS3Error,
            ProtocolS3Port, ProtocolServerInfo,
        },
        preflight::{ProtocolPreflightSummary, ProtocolStaleResourceScan},
        reporting::{
            PROTOCOL_JUNIT_FILE, ProtocolAssertion, ProtocolCaseReport, ProtocolCaseStatus,
            ProtocolCleanupReport, ProtocolFailureSummary, ProtocolSuiteSummary,
            protocol_junit_xml,
        },
        suite::{ProtocolSuite, protocol_suite_template_yaml},
        suite_plan::{ProtocolSuitePlan, ProtocolSuitePlanCase, TargetFingerprint},
    };
    use async_trait::async_trait;
    use std::{
        collections::{BTreeMap, BTreeSet},
        fs,
        sync::{Arc, Mutex},
    };

    #[derive(Clone, Default)]
    struct CleanupAdmin;

    #[async_trait]
    impl ProtocolAdminPort for CleanupAdmin {
        async fn server_info(&self) -> std::result::Result<ProtocolServerInfo, ProtocolAdminError> {
            Ok(ProtocolServerInfo {
                deployment_id: "deployment".to_string(),
                mode: None,
                region: None,
            })
        }

        async fn users_with_prefix(
            &self,
            _prefix: &str,
        ) -> std::result::Result<Vec<String>, ProtocolAdminError> {
            Ok(Vec::new())
        }

        async fn create_user(
            &self,
            _credential: &ActorCredential,
        ) -> std::result::Result<(), ProtocolAdminError> {
            Ok(())
        }

        async fn remove_user(
            &self,
            _access_key: &str,
        ) -> std::result::Result<(), ProtocolAdminError> {
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct CleanupS3(Arc<Mutex<BTreeSet<String>>>);

    #[async_trait]
    impl ProtocolS3Port for CleanupS3 {
        async fn list_buckets_with_prefix(
            &self,
            prefix: &str,
        ) -> std::result::Result<Vec<String>, ProtocolS3Error> {
            Ok(self
                .0
                .lock()
                .expect("buckets")
                .iter()
                .filter(|name| name.starts_with(prefix))
                .cloned()
                .collect())
        }

        async fn create_bucket(&self, bucket: &str) -> std::result::Result<(), ProtocolS3Error> {
            self.0.lock().expect("buckets").insert(bucket.to_string());
            Ok(())
        }

        async fn delete_bucket(&self, bucket: &str) -> std::result::Result<(), ProtocolS3Error> {
            self.0.lock().expect("buckets").remove(bucket);
            Ok(())
        }

        async fn put_bucket_policy(
            &self,
            _bucket: &str,
            _policy: &str,
        ) -> std::result::Result<(), ProtocolS3Error> {
            Ok(())
        }
        async fn delete_bucket_policy(
            &self,
            _bucket: &str,
        ) -> std::result::Result<(), ProtocolS3Error> {
            Ok(())
        }
        async fn list_objects(
            &self,
            _bucket: &str,
        ) -> std::result::Result<Vec<String>, ProtocolS3Error> {
            Ok(Vec::new())
        }
        async fn put_object(
            &self,
            _bucket: &str,
            _key: &str,
            _body: &[u8],
        ) -> std::result::Result<(), ProtocolS3Error> {
            Ok(())
        }
        async fn get_object(
            &self,
            _bucket: &str,
            _key: &str,
        ) -> std::result::Result<Vec<u8>, ProtocolS3Error> {
            Ok(Vec::new())
        }
        async fn delete_object(
            &self,
            _bucket: &str,
            _key: &str,
        ) -> std::result::Result<(), ProtocolS3Error> {
            Ok(())
        }
        async fn list_object_versions(
            &self,
            _bucket: &str,
        ) -> std::result::Result<Vec<ProtocolObjectVersion>, ProtocolS3Error> {
            Ok(Vec::new())
        }
        async fn delete_object_version(
            &self,
            _bucket: &str,
            _key: &str,
            _version_id: &str,
        ) -> std::result::Result<(), ProtocolS3Error> {
            Ok(())
        }
    }

    fn planned_case(id: &str) -> ProtocolSuitePlanCase {
        ProtocolSuitePlanCase {
            id: id.to_string(),
            domain: crate::protocol::catalog::ProtocolDomain::Other,
            group: "s3-compatibility".to_string(),
            tags: Vec::new(),
            requires: vec!["s3".to_string()],
            isolation: "case".to_string(),
            serial: false,
            worker_index: 0,
            wave_index: 0,
            locks: Vec::new(),
            artifact_dir: format!("cases/{id}"),
            contract: None,
        }
    }

    #[tokio::test]
    async fn corrupt_case_registry_does_not_skip_later_or_root_cleanup() {
        let base = tempfile::tempdir().expect("tempdir");
        let fingerprint = TargetFingerprint::new(
            "http://127.0.0.1:9000",
            "us-east-1",
            "deployment",
            None,
            None,
        )
        .expect("fingerprint");
        let corrupt_dir = base.path().join("cases/corrupt");
        fs::create_dir_all(&corrupt_dir).expect("corrupt case dir");
        fs::write(corrupt_dir.join(RESOURCE_REGISTRY_FILE), "not-json").expect("corrupt registry");

        let valid_dir = base.path().join("cases/valid");
        let mut valid = ResourceRegistry::create(&valid_dir, "run", fingerprint.clone())
            .expect("valid registry");
        let valid_bucket = valid
            .plan(ResourceKind::Bucket, "valid-bucket", "valid", Vec::new())
            .expect("valid bucket");
        valid
            .transition(&valid_bucket.id, ResourceState::Creating, None)
            .expect("creating");
        valid
            .transition(&valid_bucket.id, ResourceState::Created, None)
            .expect("created");

        let mut root =
            ResourceRegistry::create(base.path(), "run", fingerprint).expect("root registry");
        let root_bucket = root
            .plan(ResourceKind::Bucket, "root-bucket", "preflight", Vec::new())
            .expect("root bucket");
        root.transition(&root_bucket.id, ResourceState::Creating, None)
            .expect("creating");
        root.transition(&root_bucket.id, ResourceState::Created, None)
            .expect("created");

        let s3 = CleanupS3(Arc::new(Mutex::new(BTreeSet::from([
            "valid-bucket".to_string(),
            "root-bucket".to_string(),
        ]))));
        let report = cleanup_suite_registries(
            base.path(),
            &[planned_case("corrupt"), planned_case("valid")],
            &mut root,
            &CleanupAdmin,
            &s3,
            None,
            "rustfs.com/s3chaos/v1alpha1",
        )
        .await;

        assert!(!report.succeeded);
        assert!(
            report
                .attempts
                .iter()
                .any(|attempt| attempt.resource_kind == "registry")
        );
        assert!(s3.0.lock().expect("buckets").is_empty());
        assert!(root.pending_cleanup().next().is_none());
    }

    #[tokio::test]
    async fn standalone_cleanup_rejects_synthetic_s3_fingerprint() {
        let fingerprint = TargetFingerprint::new(
            "http://127.0.0.1:9000",
            "us-east-1",
            "s3-endpoint:http://127.0.0.1:9000",
            None,
            None,
        )
        .expect("fingerprint");

        let error = super::verify_cleanup_target(&CleanupAdmin, &fingerprint)
            .await
            .expect_err("synthetic fingerprints must fail closed");

        assert!(
            error
                .to_string()
                .contains("no verifiable deployment fingerprint")
        );
    }

    #[test]
    fn artifact_sanity_check_accepts_linked_secret_free_run() {
        let base = tempfile::tempdir().expect("tempdir");
        let suite = serde_yaml_ng::from_str::<ProtocolSuite>(protocol_suite_template_yaml())
            .expect("suite")
            .resolve()
            .expect("resolved");
        let fingerprint = TargetFingerprint::new(
            "http://127.0.0.1:9000",
            "us-east-1",
            "deployment",
            None,
            None,
        )
        .expect("fingerprint");
        let preflight = ProtocolPreflightSummary {
            api_version: suite.api_version.clone(),
            kind: "ProtocolPreflightSummary".to_string(),
            target_fingerprint: fingerprint.clone(),
            endpoint_reachable: true,
            admin_api_reachable: true,
            external_identity: None,
            selected_cases: vec!["bucket-policy-authenticated-user-rw".to_string()],
            stale_resources: ProtocolStaleResourceScan {
                bucket_prefix: "s3c".to_string(),
                identity_prefix: "s3chaos".to_string(),
                buckets: Vec::new(),
                identities: Vec::new(),
                policy: "record-only-phase-1".to_string(),
            },
            mutating_permission_probe:
                crate::protocol::suite_plan::ProtocolMutatingProbeSummary::not_run(),
        };
        let plan = ProtocolSuitePlan::build(
            &suite,
            fingerprint.clone(),
            (&preflight).into(),
            base.path(),
            "run",
        )
        .expect("plan");
        let root = plan.artifact_root();
        let case_dir = root.join("cases/bucket-policy-authenticated-user-rw");
        fs::create_dir_all(&case_dir).expect("case dir");
        fs::write(
            root.join("protocol-suite.yaml"),
            protocol_suite_template_yaml(),
        )
        .expect("suite source");
        write_json(&root.join("protocol-suite-plan.json"), &plan).expect("plan artifact");
        write_json(&root.join("preflight-summary.json"), &preflight).expect("preflight artifact");
        ResourceRegistry::create(&root, "run", fingerprint.clone()).expect("registry");
        let mut case_registry = ResourceRegistry::create(&case_dir, "run", fingerprint)
            .expect("case resource registry");
        case_registry
            .bind_case(
                "bucket-policy-authenticated-user-rw",
                crate::protocol::catalog::DEFAULT_PROTOCOL_VARIANT,
            )
            .expect("bind case resource contract");
        let cleanup = ProtocolCleanupReport {
            api_version: suite.api_version.clone(),
            kind: "ProtocolCleanupReport".to_string(),
            attempts: Vec::new(),
            leftovers: Vec::new(),
            succeeded: true,
        };
        write_json(&root.join("cleanup-report.json"), &cleanup).expect("cleanup artifact");
        let case_report = ProtocolCaseReport {
            api_version: suite.api_version.clone(),
            kind: "ProtocolCaseReport".to_string(),
            case_id: "bucket-policy-authenticated-user-rw".to_string(),
            variant_id: crate::protocol::catalog::DEFAULT_PROTOCOL_VARIANT.to_string(),
            domain: crate::protocol::catalog::ProtocolDomain::Authorization,
            status: ProtocolCaseStatus::Passed,
            actors: Vec::new(),
            assertions: Vec::new(),
            failure_phase: None,
            failure: None,
        };
        write_json(&case_dir.join("case-report.json"), &case_report).expect("case artifact");
        write_json(&case_dir.join("cleanup-report.json"), &cleanup).expect("case cleanup artifact");
        write_json_lines::<ProtocolAssertion>(&case_dir.join("operation-history.jsonl"), &[])
            .expect("case history artifact");
        write_json(
            &root.join(COMPATIBILITY_COVERAGE_FILE),
            &compatibility_coverage_report(&BTreeMap::new()).expect("coverage report"),
        )
        .expect("coverage artifact");
        let summary = ProtocolSuiteSummary {
            api_version: suite.api_version,
            kind: "ProtocolSuiteSummary".to_string(),
            suite: suite.metadata.name,
            run_id: "run".to_string(),
            status: ProtocolCaseStatus::Passed,
            plan: "protocol-suite-plan.json".to_string(),
            preflight: "preflight-summary.json".to_string(),
            registry: "resource-registry.json".to_string(),
            cleanup: "cleanup-report.json".to_string(),
            compatibility_coverage: COMPATIBILITY_COVERAGE_FILE.to_string(),
            case_reports: vec![
                "cases/bucket-policy-authenticated-user-rw/case-report.json".to_string(),
            ],
            failure_summary: None,
        };
        write_json(&root.join("protocol-suite-summary.json"), &summary).expect("summary artifact");
        fs::write(
            root.join(PROTOCOL_JUNIT_FILE),
            protocol_junit_xml(
                &summary.suite,
                &[(&case_report, cleanup.succeeded)],
                cleanup.succeeded,
            ),
        )
        .expect("JUnit artifact");

        validate_phase_one_artifacts(&root, &["not-present-secret".to_string()])
            .expect("valid artifacts");

        let case_registry_path = case_dir.join(RESOURCE_REGISTRY_FILE);
        let valid_case_registry = case_registry.clone();
        fs::remove_file(&case_registry_path).expect("remove case registry");
        assert!(validate_phase_one_artifacts(&root, &[]).is_err());
        write_json(&case_registry_path, &valid_case_registry).expect("restore case registry");

        let reject_registry_tampering = |tampered: &ResourceRegistry| {
            write_json(&case_registry_path, tampered).expect("write tampered case registry");
            assert!(validate_phase_one_artifacts(&root, &[]).is_err());
            write_json(&case_registry_path, &valid_case_registry)
                .expect("restore valid case registry");
        };

        let mut tampered = valid_case_registry.clone();
        tampered.contract = None;
        reject_registry_tampering(&tampered);

        let mut tampered = valid_case_registry.clone();
        tampered.contract.as_mut().expect("contract").case_id = "different-case".to_string();
        reject_registry_tampering(&tampered);

        let mut tampered = valid_case_registry.clone();
        tampered.contract.as_mut().expect("contract").variant_id = "different-variant".to_string();
        reject_registry_tampering(&tampered);

        let mut tampered = valid_case_registry.clone();
        tampered
            .contract
            .as_mut()
            .expect("contract")
            .ownership
            .pop();
        reject_registry_tampering(&tampered);

        let mut tampered = valid_case_registry.clone();
        tampered
            .contract
            .as_mut()
            .expect("contract")
            .cleanup_scopes
            .pop();
        reject_registry_tampering(&tampered);

        let mut tampered = valid_case_registry.clone();
        tampered
            .contract
            .as_mut()
            .expect("contract")
            .lock_requirements
            .pop();
        reject_registry_tampering(&tampered);

        validate_phase_one_artifacts(&root, &[]).expect("restored registry contract");

        let mut failed_cleanup = cleanup.clone();
        failed_cleanup.succeeded = false;
        failed_cleanup.leftovers = vec!["suite-resource".to_string()];
        write_json(&root.join("cleanup-report.json"), &failed_cleanup)
            .expect("failed suite cleanup artifact");
        write_json(
            &root.join("protocol-failure-summary.json"),
            &ProtocolFailureSummary {
                api_version: summary.api_version.clone(),
                kind: "ProtocolFailureSummary".to_string(),
                stage: "cleanup".to_string(),
                classification: "cleanup-failed".to_string(),
                case_id: None,
                evidence: vec!["cleanup-report.json".to_string()],
            },
        )
        .expect("suite cleanup failure summary");
        let mut failed_summary = summary.clone();
        failed_summary.status = ProtocolCaseStatus::Failed;
        failed_summary.failure_summary = Some("protocol-failure-summary.json".to_string());
        write_json(&root.join("protocol-suite-summary.json"), &failed_summary)
            .expect("failed suite summary");
        fs::write(
            root.join(PROTOCOL_JUNIT_FILE),
            protocol_junit_xml(&summary.suite, &[(&case_report, cleanup.succeeded)], true),
        )
        .expect("incorrect passing suite-cleanup JUnit artifact");
        assert!(validate_phase_one_artifacts(&root, &[]).is_err());
        fs::write(
            root.join(PROTOCOL_JUNIT_FILE),
            protocol_junit_xml(
                &summary.suite,
                &[(&case_report, cleanup.succeeded)],
                failed_cleanup.succeeded,
            ),
        )
        .expect("failed suite-cleanup JUnit artifact");
        validate_phase_one_artifacts(&root, &[]).expect("suite cleanup failure is linked to JUnit");

        write_json(&root.join("cleanup-report.json"), &cleanup).expect("restore cleanup artifact");
        write_json(&root.join("protocol-suite-summary.json"), &summary)
            .expect("restore suite summary");
        fs::remove_file(root.join("protocol-failure-summary.json"))
            .expect("remove suite cleanup failure summary");
        fs::write(
            root.join(PROTOCOL_JUNIT_FILE),
            protocol_junit_xml(
                &summary.suite,
                &[(&case_report, cleanup.succeeded)],
                cleanup.succeeded,
            ),
        )
        .expect("restore passing JUnit artifact");
        fs::remove_file(root.join(PROTOCOL_JUNIT_FILE)).expect("remove JUnit artifact");
        assert!(validate_phase_one_artifacts(&root, &[]).is_err());
        fs::write(root.join(PROTOCOL_JUNIT_FILE), "<testsuite/>").expect("tampered JUnit");
        assert!(validate_phase_one_artifacts(&root, &[]).is_err());
        fs::write(
            root.join(PROTOCOL_JUNIT_FILE),
            protocol_junit_xml(
                &summary.suite,
                &[(&case_report, cleanup.succeeded)],
                cleanup.succeeded,
            ),
        )
        .expect("restore JUnit artifact");
        validate_phase_one_artifacts(&root, &[]).expect("restored JUnit artifacts");
        fs::write(
            root.join("credential-leak.json"),
            r#"{"secretKey":"unknown-to-validator"}"#,
        )
        .expect("leak fixture");
        assert!(validate_phase_one_artifacts(&root, &[]).is_err());
        let report: crate::protocol::reporting::ProtocolArtifactValidationReport =
            serde_json::from_str(
                &fs::read_to_string(root.join(
                    crate::protocol::artifact_validation::PROTOCOL_ARTIFACT_VALIDATION_REPORT,
                ))
                .expect("validation report"),
            )
            .expect("parse validation report");
        assert!(!report.valid);
    }
}
