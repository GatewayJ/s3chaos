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
use std::fs;
use std::path::{Path, PathBuf};

use crate::protocol::{
    artifact_validation::validate_protocol_artifacts_and_write_report,
    cases::{ProtocolCaseExecution, run_protocol_case},
    clients::{
        admin::RustfsAdminClient,
        s3::{AwsS3ClientFactory, ProtocolS3Client},
        sts::RustfsStsClient,
    },
    credentials::{AdminCredentials, CredentialProvider, EnvCredentialProvider},
    fixture::{
        cleanup::cleanup_registered_resources,
        naming::ProtocolResourceNamer,
        registry::{RESOURCE_REGISTRY_FILE, ResourceRegistry},
    },
    preflight::{
        ProtocolPreflightSummary, cleanup_interrupted_mutating_permission_probe,
        enforce_stale_resource_policy, preflight_protocol_suite, run_mutating_permission_probe,
    },
    reporting::{
        ProtocolCaseStatus, ProtocolCleanupReport, ProtocolFailureSummary, ProtocolSuiteSummary,
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
    let namer = ProtocolResourceNamer::new(
        &plan.target.bucket_prefix,
        &plan.target.identity_prefix,
        &plan.run_id,
    )?;

    let requires_iam = runtime
        .suite
        .cases
        .iter()
        .any(|case| case.requires.contains(&"iam"));
    let requires_sts = runtime
        .suite
        .cases
        .iter()
        .any(|case| case.requires.contains(&"sts"));
    let mut probe_future = Box::pin(run_mutating_permission_probe(
        &namer,
        &mut registry,
        &runtime.admin,
        &runtime.s3,
        Some(&runtime.sts),
        requires_iam,
        requires_sts,
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
                            &runtime.suite.api_version,
                        )
                        .await?;
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
        &runtime.suite.api_version,
    )
    .await?;
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
        let mut entries = fs::read_dir(&cases_dir)?.collect::<std::io::Result<Vec<_>>>()?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let file_type = entry.file_type()?;
            ensure!(
                file_type.is_dir() && !file_type.is_symlink(),
                "protocol case artifact must be a non-symlink directory"
            );
            let registry_path = entry.path().join(RESOURCE_REGISTRY_FILE);
            if !registry_path.is_file() {
                continue;
            }
            let mut case_registry = load_cleanup_registry(&registry_path)?;
            ensure!(
                case_registry.run_id == root_registry.run_id
                    && case_registry.target_fingerprint == expected,
                "refuse cleanup because case registry ownership differs from the suite"
            );
            let cleanup = cleanup_registered_resources(&mut case_registry, &admin, &s3).await;
            write_json(&entry.path().join("cleanup-report.json"), &cleanup)?;
            combined.append(cleanup);
        }
    }
    combined.append(cleanup_registered_resources(&mut root_registry, &admin, &s3).await);
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
        let case_namer = self.namer.for_worker(case.worker_index);
        let execution = run_protocol_case(
            &case.id,
            &case_namer,
            &mut registry,
            self.admin,
            self.s3,
            self.sts,
            self.actor_clients,
        )
        .await;
        let cleanup = cleanup_registered_resources(&mut registry, self.admin, self.s3).await;
        if cleanup.api_version != self.api_version {
            bail!("case {} cleanup apiVersion changed unexpectedly", case.id);
        }
        Ok((execution, cleanup))
    }
}

async fn cleanup_case_registry_if_present(
    artifact_root: &Path,
    case_id: &str,
    admin: &RustfsAdminClient,
    s3: &ProtocolS3Client,
    api_version: &str,
) -> Result<ProtocolCleanupReport> {
    let registry_path = artifact_root
        .join("cases")
        .join(case_id)
        .join(RESOURCE_REGISTRY_FILE);
    if !registry_path.is_file() {
        return Ok(ProtocolCleanupReport::empty(api_version));
    }
    let mut registry = ResourceRegistry::load_path(registry_path)?;
    Ok(cleanup_registered_resources(&mut registry, admin, s3).await)
}

async fn cleanup_suite_registries(
    artifact_root: &Path,
    cases: &[ProtocolSuitePlanCase],
    root_registry: &mut ResourceRegistry,
    admin: &RustfsAdminClient,
    s3: &ProtocolS3Client,
    api_version: &str,
) -> Result<ProtocolCleanupReport> {
    let mut combined = ProtocolCleanupReport::empty(api_version);
    for case in cases {
        combined.append(
            cleanup_case_registry_if_present(artifact_root, &case.id, admin, s3, api_version)
                .await?,
        );
    }
    combined.append(cleanup_registered_resources(root_registry, admin, s3).await);
    Ok(combined)
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
    let cleanup = cleanup_registered_resources(&mut registry, &admin, &s3).await;
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

async fn verify_cleanup_target(
    admin: &RustfsAdminClient,
    expected: &TargetFingerprint,
) -> Result<()> {
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
        let stale_resource_policy = stale_resource_policy()?;
        let preflight =
            preflight_protocol_suite(&suite, &endpoint, &admin, &s3, stale_resource_policy).await?;
        enforce_stale_resource_policy(&preflight)?;
        Ok(Self {
            suite,
            endpoint,
            credentials,
            admin,
            s3,
            sts,
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
    use super::{validate_phase_one_artifacts, write_json, write_json_lines};
    use crate::protocol::{
        fixture::registry::ResourceRegistry,
        preflight::{ProtocolPreflightSummary, ProtocolStaleResourceScan},
        reporting::{
            ProtocolAssertion, ProtocolCaseReport, ProtocolCaseStatus, ProtocolCleanupReport,
            ProtocolSuiteSummary,
        },
        suite::{ProtocolSuite, protocol_suite_template_yaml},
        suite_plan::{ProtocolSuitePlan, TargetFingerprint},
    };
    use std::fs;

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
        ResourceRegistry::create(&root, "run", fingerprint).expect("registry");
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
            case_reports: vec![
                "cases/bucket-policy-authenticated-user-rw/case-report.json".to_string(),
            ],
            failure_summary: None,
        };
        write_json(&root.join("protocol-suite-summary.json"), &summary).expect("summary artifact");

        validate_phase_one_artifacts(&root, &["not-present-secret".to_string()])
            .expect("valid artifacts");
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
