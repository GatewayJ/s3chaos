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
    },
    compatibility::{
        COMPATIBILITY_COVERAGE_FILE, compatibility_coverage_report, compatibility_live_status,
    },
    credentials::{CredentialProvider, EnvCredentialProvider},
    fixture::{
        naming::ProtocolResourceNamer,
        registry::{RESOURCE_REGISTRY_FILE, ResourceRegistry},
    },
    ports::{ProtocolAdminServerPort, ProtocolExternalIdentityPort, ProtocolWebIdentityStsPort},
    preflight::{
        ProtocolProbeCapabilities, cleanup_interrupted_mutating_permission_probe,
        run_mutating_permission_probe,
    },
    reporting::{
        PROTOCOL_JUNIT_FILE, ProtocolCaseStatus, ProtocolCleanupReport, ProtocolFailureSummary,
        ProtocolSuiteSummary, protocol_junit_xml,
    },
    runner::{
        artifacts::ProtocolArtifactWriter,
        cleanup::{ProtocolCleanupCoordinator, load_cleanup_registry, registry_failure},
        executor::{ProtocolCaseLifecycle, ProtocolShutdownSignal, ProtocolSuiteExecutor},
        preflight::run_connected_preflight,
        runtime::{
            ConnectedProtocolRuntime, DisabledProtocolTimeout, MonotonicProtocolClock,
            ProcessShutdownSignal, ensure_dedicated_target_acknowledgement, protocol_artifact_base,
        },
    },
    suite_plan::{
        ProtocolMutatingProbeStatus, ProtocolSuitePlan, ProtocolSuitePlanCase, TargetFingerprint,
    },
};

struct LiveProtocolCaseLifecycle<'a> {
    artifact_root: &'a Path,
    artifacts: &'a ProtocolArtifactWriter,
    run_id: &'a str,
    fingerprint: &'a TargetFingerprint,
    namer: &'a ProtocolResourceNamer,
    admin: &'a RustfsAdminClient,
    s3: &'a ProtocolS3Client,
    sts: &'a RustfsStsClient,
    external_identity: Option<&'a dyn ProtocolExternalIdentityPort>,
    web_identity_sts: Option<&'a dyn ProtocolWebIdentityStsPort>,
    actor_clients: &'a AwsS3ClientFactory,
    cleanup: &'a ProtocolCleanupCoordinator<'a, RustfsAdminClient, ProtocolS3Client>,
    api_version: &'a str,
}

pub async fn plan_protocol_suite_from_yaml(path: impl AsRef<Path>) -> Result<ProtocolSuitePlan> {
    let runtime = ConnectedProtocolRuntime::connect(path).await?;
    let preflight = run_connected_preflight(&runtime).await?;
    ProtocolSuitePlan::generated(
        &runtime.suite,
        preflight.target_fingerprint.clone(),
        (&preflight).into(),
        protocol_artifact_base(),
    )
}

pub async fn run_protocol_suite_from_yaml(path: impl AsRef<Path>) -> Result<()> {
    ensure_dedicated_target_acknowledgement()?;
    let path = path.as_ref();
    let runtime = ConnectedProtocolRuntime::connect(path).await?;
    let mut preflight = run_connected_preflight(&runtime).await?;
    let mut plan = ProtocolSuitePlan::generated(
        &runtime.suite,
        preflight.target_fingerprint.clone(),
        (&preflight).into(),
        protocol_artifact_base(),
    )?;
    let artifact_root = plan.artifact_root();
    let artifacts = ProtocolArtifactWriter::file(&artifact_root);
    artifacts.initialize_run(path)?;
    artifacts.write_json("protocol-suite-plan.json", &plan)?;
    artifacts.write_json("preflight-summary.json", &preflight)?;

    let mut registry = ResourceRegistry::create(
        &artifact_root,
        &plan.run_id,
        preflight.target_fingerprint.clone(),
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
        signal = ProcessShutdownSignal.wait() => Err(signal),
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
    preflight.mutating_permission_probe = probe.summary.clone();
    plan.preflight = (&preflight).into();
    artifacts.write_json("protocol-suite-plan.json", &plan)?;
    artifacts.write_json("preflight-summary.json", &preflight)?;
    artifacts.write_json("preflight-cleanup-report.json", &probe.cleanup)?;
    let mut probe_forbidden_secrets = probe.forbidden_secrets;

    let selected_cases = plan.cases.clone();
    let actor_clients = AwsS3ClientFactory::new(&runtime.endpoint, &runtime.suite.target.region);
    let preflight_failure_message = probe
        .summary
        .error
        .clone()
        .unwrap_or_else(|| "mutating preflight probe failed".to_string());
    let external_identity = runtime
        .external_identity
        .as_ref()
        .map(|provider| provider as &dyn ProtocolExternalIdentityPort);
    let cleanup = ProtocolCleanupCoordinator::new(
        &artifact_root,
        &runtime.admin,
        &runtime.s3,
        external_identity,
        &runtime.suite.api_version,
    );
    let case_lifecycle = LiveProtocolCaseLifecycle {
        artifact_root: &artifact_root,
        artifacts: &artifacts,
        run_id: &plan.run_id,
        fingerprint: &plan.target.fingerprint,
        namer: &namer,
        admin: &runtime.admin,
        s3: &runtime.s3,
        sts: &runtime.sts,
        external_identity,
        web_identity_sts: runtime
            .web_identity_sts
            .as_ref()
            .map(|sts| sts as &dyn ProtocolWebIdentityStsPort),
        actor_clients: &actor_clients,
        cleanup: &cleanup,
        api_version: &runtime.suite.api_version,
    };
    let clock = MonotonicProtocolClock::default();
    let timeout = DisabledProtocolTimeout;
    let executor = ProtocolSuiteExecutor::new(
        &case_lifecycle,
        &cleanup,
        &ProcessShutdownSignal,
        &clock,
        &timeout,
        &runtime.suite.api_version,
    );
    let preflight_failure = (probe.summary.status != ProtocolMutatingProbeStatus::Passed)
        .then_some(preflight_failure_message.as_str());
    let suite_execution = executor
        .execute(&selected_cases, &mut registry, preflight_failure)
        .await?;
    let fallback_cleanup = suite_execution.fallback_cleanup;
    let case_executions = suite_execution
        .cases
        .into_iter()
        .map(|case| (case.execution, case.cleanup))
        .collect::<Vec<_>>();
    artifacts.write_json("cleanup-report.json", &fallback_cleanup)?;

    let mut case_report_paths = Vec::with_capacity(case_executions.len());
    let mut forbidden_case_secrets = Vec::new();
    for (execution, cleanup) in &case_executions {
        artifacts.create_case_dir(&execution.report.case_id)?;
        let case_relative = Path::new("cases").join(&execution.report.case_id);
        let case_dir = artifact_root.join(&case_relative);
        let case_report_path = case_dir.join("case-report.json");
        artifacts.write_json(case_relative.join("case-report.json"), &execution.report)?;
        artifacts.write_json(case_relative.join("cleanup-report.json"), cleanup)?;
        artifacts.write_json_lines(
            case_relative.join("operation-history.jsonl"),
            &execution.report.assertions,
        )?;
        case_report_paths.push(artifacts.relative_path(&case_report_path)?);
        forbidden_case_secrets.extend(execution.forbidden_secrets.iter().cloned());
    }
    let junit_cases = case_executions
        .iter()
        .map(|(execution, cleanup)| (&execution.report, cleanup.succeeded))
        .collect::<Vec<_>>();
    artifacts.write_text(
        PROTOCOL_JUNIT_FILE,
        &protocol_junit_xml(
            &runtime.suite.metadata.name,
            &junit_cases,
            fallback_cleanup.succeeded,
        ),
    )?;
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
    artifacts.write_json(
        COMPATIBILITY_COVERAGE_FILE,
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
        artifacts.write_json("protocol-failure-summary.json", &failure)?;
        Some("protocol-failure-summary.json".to_string())
    } else if !fallback_cleanup.succeeded {
        artifacts.write_json(
            "protocol-failure-summary.json",
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
    artifacts.write_json("protocol-suite-summary.json", &summary)?;

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
        artifacts.write_json(
            "protocol-failure-summary.json",
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
        artifacts.write_json("protocol-suite-summary.json", &summary)?;
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

    let artifacts = ProtocolArtifactWriter::file(artifact_root);
    let mut combined = ProtocolCleanupReport::empty(&root_registry.api_version);
    let cases_dir = artifact_root.join("cases");
    if cases_dir.is_dir() {
        let mut entries = Vec::new();
        match fs::read_dir(&cases_dir) {
            Ok(read_dir) => {
                for entry in read_dir {
                    match entry {
                        Ok(entry) => entries.push(entry),
                        Err(error) => combined.append(registry_failure(
                            &root_registry.api_version,
                            &cases_dir,
                            error,
                        )),
                    }
                }
            }
            Err(error) => combined.append(registry_failure(
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
                    combined.append(registry_failure(
                        &root_registry.api_version,
                        &entry.path(),
                        error,
                    ));
                    continue;
                }
            };
            if !file_type.is_dir() || file_type.is_symlink() {
                combined.append(registry_failure(
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
                    combined.append(registry_failure(
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
                combined.append(registry_failure(
                    &root_registry.api_version,
                    &registry_path,
                    "refuse cleanup because case registry ownership differs from the suite",
                ));
                continue;
            }
            let external_identity = match external_identity_for_registry(&case_registry) {
                Ok(provider) => provider,
                Err(error) => {
                    combined.append(registry_failure(
                        &root_registry.api_version,
                        &registry_path,
                        error,
                    ));
                    continue;
                }
            };
            let coordinator = ProtocolCleanupCoordinator::new(
                artifact_root,
                &admin,
                &s3,
                external_identity
                    .as_ref()
                    .map(|provider| provider as &dyn ProtocolExternalIdentityPort),
                &root_registry.api_version,
            );
            let cleanup = coordinator.cleanup_registry(&mut case_registry).await;
            let report_relative = Path::new("cases")
                .join(entry.file_name())
                .join("cleanup-report.json");
            if let Err(error) = artifacts.write_json(&report_relative, &cleanup) {
                combined.append(registry_failure(
                    &root_registry.api_version,
                    &artifact_root.join(report_relative),
                    error,
                ));
            }
            combined.append(cleanup);
        }
    }
    let root_external_identity = external_identity_for_registry(&root_registry)?;
    let api_version = root_registry.api_version.clone();
    let root_coordinator = ProtocolCleanupCoordinator::new(
        artifact_root,
        &admin,
        &s3,
        root_external_identity
            .as_ref()
            .map(|provider| provider as &dyn ProtocolExternalIdentityPort),
        &api_version,
    );
    combined.append(root_coordinator.cleanup_registry(&mut root_registry).await);
    let report_path = artifact_root.join("cleanup-report.json");
    artifacts.write_json("cleanup-report.json", &combined)?;
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

#[async_trait::async_trait]
impl ProtocolCaseLifecycle for LiveProtocolCaseLifecycle<'_> {
    async fn run_case(
        &self,
        case: &ProtocolSuitePlanCase,
    ) -> Result<(ProtocolCaseExecution, ProtocolCleanupReport)> {
        let case_dir = self.artifact_root.join("cases").join(&case.id);
        self.artifacts.create_case_dir(&case.id)?;
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
        let cleanup = self.cleanup.cleanup_registry(&mut registry).await;
        if cleanup.api_version != self.api_version {
            bail!("case {} cleanup apiVersion changed unexpectedly", case.id);
        }
        Ok((execution, cleanup))
    }
}

pub async fn cleanup_protocol_registry_path(registry_path: impl AsRef<Path>) -> Result<()> {
    let registry_path = registry_path.as_ref();
    ensure!(
        registry_path.file_name().and_then(|name| name.to_str()) == Some(RESOURCE_REGISTRY_FILE),
        "standalone protocol cleanup requires a file named {RESOURCE_REGISTRY_FILE}"
    );
    let parent = artifact_parent(registry_path, "resource registry path has no parent")?;
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
    let api_version = registry.api_version.clone();
    let report_parent = artifact_parent(&report_path, "cleanup report path has no parent")?;
    let coordinator = ProtocolCleanupCoordinator::new(
        report_parent,
        &admin,
        &s3,
        external_identity
            .as_ref()
            .map(|provider| provider as &dyn ProtocolExternalIdentityPort),
        &api_version,
    );
    let cleanup = coordinator.cleanup_registry(&mut registry).await;
    let report_name = report_path
        .file_name()
        .context("cleanup report path has no file name")?;
    ProtocolArtifactWriter::file(report_parent).write_json(Path::new(report_name), &cleanup)?;
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

fn artifact_parent<'a>(path: &'a Path, missing_parent: &'static str) -> Result<&'a Path> {
    let parent = path.parent().context(missing_parent)?;
    Ok(if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    })
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
    admin: &impl ProtocolAdminServerPort,
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

fn validate_phase_one_artifacts(root: &Path, forbidden: &[String]) -> Result<()> {
    validate_protocol_artifacts_and_write_report(root, forbidden).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::{artifact_parent, validate_phase_one_artifacts};
    use crate::protocol::{
        compatibility::{COMPATIBILITY_COVERAGE_FILE, compatibility_coverage_report},
        fixture::registry::{RESOURCE_REGISTRY_FILE, ResourceRegistry},
        ports::{ProtocolAdminError, ProtocolAdminServerPort, ProtocolServerInfo},
        preflight::{ProtocolPreflightSummary, ProtocolStaleResourceScan},
        reporting::{
            PROTOCOL_JUNIT_FILE, ProtocolAssertion, ProtocolCaseReport, ProtocolCaseStatus,
            ProtocolCleanupReport, ProtocolFailureSummary, ProtocolSuiteSummary,
            protocol_junit_xml,
        },
        runner::artifacts::ProtocolArtifactWriter,
        suite::{ProtocolSuite, protocol_suite_template_yaml},
        suite_plan::{ProtocolSuitePlan, TargetFingerprint},
    };
    use async_trait::async_trait;
    use std::{collections::BTreeMap, fs, path::Path};

    #[derive(Clone, Default)]
    struct CleanupAdmin;

    #[async_trait]
    impl ProtocolAdminServerPort for CleanupAdmin {
        async fn server_info(&self) -> Result<ProtocolServerInfo, ProtocolAdminError> {
            Ok(ProtocolServerInfo {
                deployment_id: "deployment".to_string(),
                mode: None,
                region: None,
            })
        }
    }

    #[test]
    fn relative_registry_path_uses_current_directory_as_artifact_parent() {
        assert_eq!(
            artifact_parent(
                Path::new(RESOURCE_REGISTRY_FILE),
                "resource registry path has no parent"
            )
            .expect("relative registry parent"),
            Path::new(".")
        );
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
        let artifacts = ProtocolArtifactWriter::file(&root);
        let suite_source = tempfile::NamedTempFile::new().expect("suite source");
        fs::write(suite_source.path(), protocol_suite_template_yaml()).expect("suite source");
        artifacts
            .initialize_run(suite_source.path())
            .expect("initialize artifacts");
        artifacts
            .create_case_dir("bucket-policy-authenticated-user-rw")
            .expect("case dir");
        artifacts
            .write_json("protocol-suite-plan.json", &plan)
            .expect("plan artifact");
        artifacts
            .write_json("preflight-summary.json", &preflight)
            .expect("preflight artifact");
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
        artifacts
            .write_json("cleanup-report.json", &cleanup)
            .expect("cleanup artifact");
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
        artifacts
            .write_json(
                "cases/bucket-policy-authenticated-user-rw/case-report.json",
                &case_report,
            )
            .expect("case artifact");
        artifacts
            .write_json(
                "cases/bucket-policy-authenticated-user-rw/cleanup-report.json",
                &cleanup,
            )
            .expect("case cleanup artifact");
        artifacts
            .write_json_lines::<ProtocolAssertion>(
                "cases/bucket-policy-authenticated-user-rw/operation-history.jsonl",
                &[],
            )
            .expect("case history artifact");
        artifacts
            .write_json(
                COMPATIBILITY_COVERAGE_FILE,
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
        artifacts
            .write_json("protocol-suite-summary.json", &summary)
            .expect("summary artifact");
        artifacts
            .write_text(
                PROTOCOL_JUNIT_FILE,
                &protocol_junit_xml(
                    &summary.suite,
                    &[(&case_report, cleanup.succeeded)],
                    cleanup.succeeded,
                ),
            )
            .expect("JUnit artifact");

        validate_phase_one_artifacts(&root, &["not-present-secret".to_string()])
            .expect("valid artifacts");

        let case_registry_path = case_dir.join(RESOURCE_REGISTRY_FILE);
        let case_registry_relative =
            Path::new("cases/bucket-policy-authenticated-user-rw").join(RESOURCE_REGISTRY_FILE);
        let valid_case_registry = case_registry.clone();
        fs::remove_file(&case_registry_path).expect("remove case registry");
        assert!(validate_phase_one_artifacts(&root, &[]).is_err());
        artifacts
            .write_json(&case_registry_relative, &valid_case_registry)
            .expect("restore case registry");

        let reject_registry_tampering = |tampered: &ResourceRegistry| {
            artifacts
                .write_json(&case_registry_relative, tampered)
                .expect("write tampered case registry");
            assert!(validate_phase_one_artifacts(&root, &[]).is_err());
            artifacts
                .write_json(&case_registry_relative, &valid_case_registry)
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
        artifacts
            .write_json("cleanup-report.json", &failed_cleanup)
            .expect("failed suite cleanup artifact");
        artifacts
            .write_json(
                "protocol-failure-summary.json",
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
        artifacts
            .write_json("protocol-suite-summary.json", &failed_summary)
            .expect("failed suite summary");
        artifacts
            .write_text(
                PROTOCOL_JUNIT_FILE,
                &protocol_junit_xml(&summary.suite, &[(&case_report, cleanup.succeeded)], true),
            )
            .expect("incorrect passing suite-cleanup JUnit artifact");
        assert!(validate_phase_one_artifacts(&root, &[]).is_err());
        artifacts
            .write_text(
                PROTOCOL_JUNIT_FILE,
                &protocol_junit_xml(
                    &summary.suite,
                    &[(&case_report, cleanup.succeeded)],
                    failed_cleanup.succeeded,
                ),
            )
            .expect("failed suite-cleanup JUnit artifact");
        validate_phase_one_artifacts(&root, &[]).expect("suite cleanup failure is linked to JUnit");

        artifacts
            .write_json("cleanup-report.json", &cleanup)
            .expect("restore cleanup artifact");
        artifacts
            .write_json("protocol-suite-summary.json", &summary)
            .expect("restore suite summary");
        fs::remove_file(root.join("protocol-failure-summary.json"))
            .expect("remove suite cleanup failure summary");
        artifacts
            .write_text(
                PROTOCOL_JUNIT_FILE,
                &protocol_junit_xml(
                    &summary.suite,
                    &[(&case_report, cleanup.succeeded)],
                    cleanup.succeeded,
                ),
            )
            .expect("restore passing JUnit artifact");
        fs::remove_file(root.join(PROTOCOL_JUNIT_FILE)).expect("remove JUnit artifact");
        assert!(validate_phase_one_artifacts(&root, &[]).is_err());
        artifacts
            .write_text(PROTOCOL_JUNIT_FILE, "<testsuite/>")
            .expect("tampered JUnit");
        assert!(validate_phase_one_artifacts(&root, &[]).is_err());
        artifacts
            .write_text(
                PROTOCOL_JUNIT_FILE,
                &protocol_junit_xml(
                    &summary.suite,
                    &[(&case_report, cleanup.succeeded)],
                    cleanup.succeeded,
                ),
            )
            .expect("restore JUnit artifact");
        validate_phase_one_artifacts(&root, &[]).expect("restored JUnit artifacts");
        artifacts
            .write_text(
                "credential-leak.json",
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
