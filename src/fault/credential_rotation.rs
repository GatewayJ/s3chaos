// Copyright 2026 RustFS Team
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

//! A run-owned IAM secret rotation with S3 history as the data oracle.

use anyhow::{Context, Result, anyhow, ensure};
use async_trait::async_trait;
use futures::{StreamExt, stream};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::Instant;
use uuid::Uuid;

use crate::{
    fault::{
        admin_runner::{
            AdminCancelOutcome, AdminCaseDriver, AdminWorkflowObservation, execute_admin_workflow,
            persist_admin_workflow,
        },
        checker::{self, CheckerReport},
        config::FaultTestConfig,
        events::RunEventStatus,
        history::{
            DurabilityCohort, OperationKind, OperationOutcome, OperationRecord,
            validate_history_scope_and_order,
        },
        plan::{CredentialRotationExecutionPlan, ExecutionPlan},
        pods::rustfs_pod_identities,
        preflight::{PreflightCheck, PreflightPhase},
        recovery_health::{RECOVERY_HEALTH_ARTIFACT, RecoveryHealthBaseline},
        reporting::{PodIdentity, ResponsibilityDomain},
        runner::{
            FaultRunContext, ensure_s3_access, initialize_fault_run, observe_recovery_health,
            s3_access, wait_for_ready_tenant, wait_for_stable_rustfs_pods, wait_for_tenant_s3,
            write_preflight_summary,
        },
        scenarios::{CREDENTIAL_ROTATION_MID_LOAD_SCENARIO, FaultScenario},
        shutdown::RunDeadline,
        workload::{ObjectSpec, S3WorkloadClient, execution::prefill_objects, sha256_hex},
    },
    framework::{
        artifacts::ArtifactCollector,
        kubectl::Kubectl,
        port_forward::{PortForwardGuard, PortForwardSpec},
        resources,
    },
    rustfs::{RustfsAdminTransport, SecretString, identity_admin::RustfsIdentityAdminClient},
};

pub(crate) const CREDENTIAL_ROTATION_ARTIFACT: &str = "credential-rotation.json";
const ROTATION_PATH: &str = "/rustfs/admin/v3/set-user-secret-key";
const PROPAGATION_POLL_INTERVAL: Duration = Duration::from_millis(100);
const CANCELLATION_CLEANUP_TIMEOUT: Duration = Duration::from_secs(45);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CredentialIdentityProof {
    pub principal_sha256: String,
    pub credential_sha256: String,
}

#[derive(Debug, Clone)]
struct RotationCredential {
    access_key: SecretString,
    secret_key: SecretString,
}

impl RotationCredential {
    fn generated(access_key: &str) -> Result<Self> {
        let nonce = format!("{}:{}", Uuid::new_v4(), Uuid::new_v4());
        Ok(Self {
            access_key: SecretString::new(access_key)?,
            secret_key: SecretString::new(sha256_hex(nonce.as_bytes()))?,
        })
    }
    fn access_key(&self) -> &str {
        self.access_key.expose()
    }
    fn secret_key(&self) -> &str {
        self.secret_key.expose()
    }
    fn artifact(&self) -> CredentialIdentityProof {
        CredentialIdentityProof {
            principal_sha256: sha256_hex(self.access_key().as_bytes()),
            credential_sha256: sha256_hex(self.secret_key().as_bytes()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SecretRotationReceipt {
    pub method: String,
    pub path: String,
    pub started_at_ms: u64,
    pub ended_at_ms: u64,
    /// Next S3 event at each admin boundary. Sampling preserves the recorder's
    /// complete, consecutive sequence of S3 request starts and completions.
    pub started_sequence: u64,
    pub ended_sequence: u64,
    pub accepted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PodCredentialProof {
    pub pod_name: String,
    pub pod_uid: String,
    pub old_operation_id: String,
    pub new_operation_id: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CredentialCleanupEvidence {
    pub attempted: bool,
    pub user_absent: bool,
    pub policy_absent: bool,
    pub completed_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CredentialRotationEvidence {
    pub schema_version: u8,
    pub scenario: String,
    pub run_id: String,
    pub bucket: String,
    pub context: String,
    pub namespace: String,
    pub tenant: String,
    pub tenant_uid: String,
    pub deployment_id: String,
    pub old_credential: CredentialIdentityProof,
    pub new_credential: CredentialIdentityProof,
    pub identity_absent_before_create: bool,
    pub policy_absent_before_create: bool,
    pub policy_sha256: String,
    pub pods_before: Vec<PodIdentity>,
    pub old_prefill_operation_ids: Vec<String>,
    pub old_workload_operation_ids: Vec<String>,
    pub rotation: Option<SecretRotationReceipt>,
    pub pod_auth: Vec<PodCredentialProof>,
    pub new_put_operation_id: Option<String>,
    pub new_get_operation_id: Option<String>,
    pub new_overwrite_operation_id: Option<String>,
    pub new_delete_operation_id: Option<String>,
    pub new_deleted_get_operation_id: Option<String>,
    pub verified: bool,
    pub cleanup: CredentialCleanupEvidence,
}

impl CredentialRotationEvidence {
    pub(crate) fn validate_history(&self, history: &[OperationRecord]) -> Result<()> {
        ensure!(
            self.schema_version == 1 && self.scenario == CREDENTIAL_ROTATION_MID_LOAD_SCENARIO,
            "credential rotation schema or scenario is invalid"
        );
        ensure!(
            [
                &self.run_id,
                &self.bucket,
                &self.context,
                &self.namespace,
                &self.tenant,
                &self.tenant_uid,
                &self.deployment_id
            ]
            .iter()
            .all(|value| !value.trim().is_empty()),
            "credential rotation lacks run or target identity"
        );
        ensure!(
            self.old_credential.principal_sha256.len() == 64
                && self.new_credential.principal_sha256 == self.old_credential.principal_sha256
                && self.old_credential.credential_sha256.len() == 64
                && self.new_credential.credential_sha256.len() == 64
                && self.old_credential.credential_sha256 != self.new_credential.credential_sha256,
            "credential aliases do not prove a distinct old/new run-owned identity"
        );
        ensure!(
            self.identity_absent_before_create
                && self.policy_absent_before_create
                && self.policy_sha256 == sha256_hex(bucket_policy(&self.bucket)?.as_bytes()),
            "credential fixture ownership or bucket policy proof is invalid"
        );
        validate_history_scope_and_order(history, &self.scenario, &self.run_id, &self.bucket)?;
        let by_id = history
            .iter()
            .map(|record| (record.id.as_str(), record))
            .collect::<BTreeMap<_, _>>();
        let record = |id: &str| -> Result<&OperationRecord> {
            by_id
                .get(id)
                .copied()
                .with_context(|| format!("rotation history reference {id} is absent"))
        };
        let rotation = self
            .rotation
            .as_ref()
            .context("secret rotation request receipt is absent")?;
        ensure!(
            rotation.method == "PUT"
                && rotation.path == ROTATION_PATH
                && rotation.accepted
                && rotation.started_at_ms > 0
                && rotation.ended_at_ms >= rotation.started_at_ms
                && rotation.started_sequence > 0
                && rotation.ended_sequence >= rotation.started_sequence,
            "secret rotation lacks a successful bounded request receipt"
        );
        ensure!(
            !self.old_prefill_operation_ids.is_empty(),
            "old credential has no pre-rotation writes"
        );
        ensure!(
            !self.old_workload_operation_ids.is_empty(),
            "rotation has no old-credential workload"
        );
        let mut referenced = BTreeSet::new();
        for id in &self.old_prefill_operation_ids {
            ensure!(
                referenced.insert(id),
                "rotation contains duplicate history references"
            );
            let write = record(id)?;
            require_committed_put(write)?;
            ensure!(
                write
                    .ended_sequence
                    .is_some_and(|sequence| sequence < rotation.started_sequence)
                    && write.ended_at_ms <= rotation.started_at_ms
                    && write.durability_cohort == Some(DurabilityCohort::PreFault),
                "old credential prefill was not committed before secret rotation"
            );
        }
        let mut overlapping = 0;
        for id in &self.old_workload_operation_ids {
            ensure!(
                referenced.insert(id),
                "rotation contains duplicate history references"
            );
            let write = record(id)?;
            ensure!(
                write.kind == OperationKind::Put
                    && write.durability_cohort == Some(DurabilityCohort::FaultActive),
                "old-credential workload reference is not an active-window PUT"
            );
            if write.outcome == OperationOutcome::Ok {
                require_committed_put(write)?;
            } else {
                ensure!(
                    is_auth_rejection(write),
                    "old-credential workload contains a non-auth failure"
                );
            }
            if write
                .started_sequence
                .is_some_and(|sequence| sequence < rotation.ended_sequence)
                && write
                    .ended_sequence
                    .is_some_and(|sequence| sequence >= rotation.started_sequence)
                && write.started_at_ms <= rotation.ended_at_ms
                && write.ended_at_ms >= rotation.started_at_ms
            {
                overlapping += 1;
            }
        }
        ensure!(
            overlapping > 0,
            "no recorded S3 request overlaps the actual secret rotation request"
        );
        let expected_pods = self
            .pods_before
            .iter()
            .map(|pod| (&pod.name, &pod.uid))
            .collect::<BTreeSet<_>>();
        ensure!(
            !expected_pods.is_empty() && expected_pods.len() == self.pods_before.len(),
            "credential rotation has an empty or duplicate Pod target set"
        );
        let observed_pods = self
            .pod_auth
            .iter()
            .map(|proof| (&proof.pod_name, &proof.pod_uid))
            .collect::<BTreeSet<_>>();
        ensure!(
            observed_pods == expected_pods && self.pod_auth.len() == expected_pods.len(),
            "old/new authentication does not cover the exact RustFS Pod set"
        );
        let baseline = record(&self.old_prefill_operation_ids[0])?;
        for proof in &self.pod_auth {
            ensure!(
                referenced.insert(&proof.old_operation_id)
                    && referenced.insert(&proof.new_operation_id),
                "per-Pod authentication reuses a history reference"
            );
            let old = record(&proof.old_operation_id)?;
            let new = record(&proof.new_operation_id)?;
            ensure!(
                old.kind == OperationKind::Get
                    && is_auth_rejection(old)
                    && new.kind == OperationKind::Get
                    && new.outcome == OperationOutcome::Ok
                    && old.key == baseline.key
                    && new.key == baseline.key
                    && new.value_sha256 == baseline.value_sha256
                    && new.size_bytes == baseline.size_bytes
                    && [old, new].iter().all(|operation| {
                        operation
                            .started_sequence
                            .is_some_and(|sequence| sequence >= rotation.ended_sequence)
                            && operation.started_at_ms >= rotation.ended_at_ms
                            && operation.durability_cohort == Some(DurabilityCohort::PostRecovery)
                    }),
                "per-Pod old/new authentication proof is invalid or predates rotation"
            );
        }
        let new_put = record(
            self.new_put_operation_id
                .as_deref()
                .context("new-credential PUT proof is absent")?,
        )?;
        let new_get = record(
            self.new_get_operation_id
                .as_deref()
                .context("new-credential GET proof is absent")?,
        )?;
        let overwrite = record(
            self.new_overwrite_operation_id
                .as_deref()
                .context("new-credential overwrite proof is absent")?,
        )?;
        let delete = record(
            self.new_delete_operation_id
                .as_deref()
                .context("new-credential DELETE proof is absent")?,
        )?;
        let deleted_get = record(
            self.new_deleted_get_operation_id
                .as_deref()
                .context("delete visibility proof is absent")?,
        )?;
        require_committed_put(new_put)?;
        require_committed_put(overwrite)?;
        ensure!(
            new_get.kind == OperationKind::Get
                && new_get.outcome == OperationOutcome::Ok
                && new_get.key == new_put.key
                && new_get.value_sha256 == new_put.value_sha256
                && new_get.size_bytes == new_put.size_bytes
                && overwrite.key == new_put.key
                && overwrite.version_id != new_put.version_id
                && overwrite.value_sha256 != new_put.value_sha256
                && delete.kind == OperationKind::Delete
                && delete.outcome == OperationOutcome::Ok
                && delete.key == new_put.key
                && delete.is_delete_marker == Some(true)
                && delete
                    .version_id
                    .as_ref()
                    .is_some_and(|value| !value.is_empty())
                && deleted_get.kind == OperationKind::Get
                && deleted_get.outcome == OperationOutcome::NotFound
                && deleted_get.key == new_put.key,
            "new-credential mutation and version/delete-marker proof is invalid"
        );
        let ordered = [new_put, new_get, overwrite, delete, deleted_get];
        ensure!(
            ordered.iter().all(
                |operation| operation.durability_cohort == Some(DurabilityCohort::PostRecovery)
            ) && ordered[0]
                .started_sequence
                .is_some_and(|sequence| sequence >= rotation.ended_sequence)
                && ordered.windows(2).all(|pair| pair[0]
                    .ended_sequence
                    .zip(pair[1].started_sequence)
                    .is_some_and(|(ended, started)| ended < started)),
            "new-credential operation proofs have invalid history order"
        );
        Ok(())
    }
}

pub(crate) fn validate_credential_rotation_evidence(
    evidence: &CredentialRotationEvidence,
    history: &[OperationRecord],
    checker: &CheckerReport,
) -> Result<()> {
    evidence.validate_history(history)?;
    ensure!(
        evidence.verified
            && evidence.cleanup.attempted
            && evidence.cleanup.user_absent
            && evidence.cleanup.policy_absent
            && evidence
                .cleanup
                .completed_at_ms
                .is_some_and(|value| value > 0),
        "credential rotation lacks successful verification or IAM fixture cleanup"
    );
    ensure!(
        checker.scenario == evidence.scenario
            && checker.run_id == evidence.run_id
            && checker.versioning_expected
            && checker.expected_committed_versions > 0
            && checker.expected_live_objects > 0,
        "credential rotation checker lacks the exact nonempty versioned run model"
    );
    ensure!(
        checker.failed_writes_materialized.is_empty(),
        "authentication-rejected old-credential writes became visible"
    );
    checker.require_success()?;
    checker::validate_checker_audit_against_history(checker, history)
}

fn require_committed_put(record: &OperationRecord) -> Result<()> {
    ensure!(
        record.kind == OperationKind::Put
            && record.outcome == OperationOutcome::Ok
            && record
                .version_id
                .as_ref()
                .is_some_and(|value| !value.is_empty())
            && record
                .value_sha256
                .as_ref()
                .is_some_and(|value| value.len() == 64)
            && record.size_bytes.is_some(),
        "rotation PUT lacks committed bytes or version identity"
    );
    Ok(())
}

fn is_auth_rejection(record: &OperationRecord) -> bool {
    record.outcome == OperationOutcome::Failed && matches!(record.http_status, Some(401 | 403))
}

fn bucket_policy(bucket: &str) -> Result<String> {
    Ok(serde_json::to_string(&serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["s3:*"],
            "Resource": [format!("arn:aws:s3:::{bucket}"), format!("arn:aws:s3:::{bucket}/*")]}]
    }))?)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(1)
        .max(1)
}

struct RotationState {
    // The identity cleanup guard must run while the transport is reachable.
    identity_guard: Option<IdentityCleanupGuard>,
    port_forward: Option<PortForwardGuard>,
    admin: Option<Arc<RustfsIdentityAdminClient>>,
    old_s3: Option<S3WorkloadClient>,
    new_s3: Option<S3WorkloadClient>,
    baseline: Option<RecoveryHealthBaseline>,
    operation_deadline: Option<Instant>,
    finished: bool,
}

struct LiveCredentialRotationDriver {
    config: FaultTestConfig,
    collector: ArtifactCollector,
    scenario: FaultScenario,
    plan: CredentialRotationExecutionPlan,
    context: FaultRunContext,
    deadline: RunDeadline,
    old: RotationCredential,
    new: RotationCredential,
    policy_name: String,
    evidence: Arc<Mutex<CredentialRotationEvidence>>,
    state: tokio::sync::Mutex<RotationState>,
}

impl LiveCredentialRotationDriver {
    fn new(
        config: &FaultTestConfig,
        collector: &ArtifactCollector,
        scenario: &FaultScenario,
        execution_plan: &ExecutionPlan,
        plan: &CredentialRotationExecutionPlan,
        run_id: &str,
        deadline: RunDeadline,
    ) -> Result<Self> {
        ensure!(
            config.workload_versioning && scenario.object_count >= 4,
            "credential rotation requires versioning and at least four objects"
        );
        let context = initialize_fault_run(config, collector, scenario, execution_plan, run_id)?;
        let access_key = format!("rotation-{}", Uuid::new_v4().simple());
        let old = RotationCredential::generated(&access_key)?;
        let new = RotationCredential::generated(&access_key)?;
        ensure!(
            old.secret_key() != new.secret_key(),
            "generated secrets must differ"
        );
        let (admin_access, admin_secret) = resources::test_credentials();
        collector.redact_secrets(&[
            &access_key,
            old.secret_key(),
            new.secret_key(),
            admin_access,
            admin_secret,
        ])?;
        context.history.redact_secrets(&[
            &access_key,
            old.secret_key(),
            new.secret_key(),
            admin_access,
            admin_secret,
        ])?;
        let evidence = CredentialRotationEvidence {
            schema_version: 1,
            scenario: scenario.name.clone(),
            run_id: run_id.to_string(),
            bucket: context.bucket.clone(),
            context: config.cluster.context.clone(),
            namespace: config.cluster.test_namespace.clone(),
            tenant: config.cluster.tenant_name.clone(),
            tenant_uid: String::new(),
            deployment_id: String::new(),
            old_credential: old.artifact(),
            new_credential: new.artifact(),
            identity_absent_before_create: false,
            policy_absent_before_create: false,
            policy_sha256: sha256_hex(bucket_policy(&context.bucket)?.as_bytes()),
            pods_before: Vec::new(),
            old_prefill_operation_ids: Vec::new(),
            old_workload_operation_ids: Vec::new(),
            rotation: None,
            pod_auth: Vec::new(),
            new_put_operation_id: None,
            new_get_operation_id: None,
            new_overwrite_operation_id: None,
            new_delete_operation_id: None,
            new_deleted_get_operation_id: None,
            verified: false,
            cleanup: CredentialCleanupEvidence::default(),
        };
        Ok(Self {
            config: config.clone(),
            collector: collector.clone(),
            scenario: scenario.clone(),
            plan: plan.clone(),
            context,
            deadline,
            old,
            new,
            policy_name: format!("rotation-policy-{}", Uuid::new_v4().simple()),
            evidence: Arc::new(Mutex::new(evidence)),
            state: tokio::sync::Mutex::new(RotationState {
                identity_guard: None,
                port_forward: None,
                admin: None,
                old_s3: None,
                new_s3: None,
                baseline: None,
                operation_deadline: None,
                finished: false,
            }),
        })
    }

    fn evidence(&self) -> std::sync::MutexGuard<'_, CredentialRotationEvidence> {
        self.evidence
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn persist(&self) -> Result<()> {
        write_evidence(&self.collector, self.scenario.case_name, &self.evidence)
    }

    fn redact(&self, error: anyhow::Error) -> anyhow::Error {
        let (access, secret) = resources::test_credentials();
        let mut message = format!("{error:#}");
        for value in [
            self.old.access_key(),
            self.old.secret_key(),
            self.new.secret_key(),
            access,
            secret,
        ] {
            message = message.replace(value, "[REDACTED]");
        }
        anyhow!(message)
    }

    async fn preserve<T>(&self, result: Result<T>) -> Result<T> {
        let result = result.map_err(|error| self.redact(error));
        let persisted = self.persist();
        match (result, persisted) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Err(error), Err(persisted)) => {
                Err(error.context(format!("persist rotation evidence: {persisted:#}")))
            }
        }
    }

    async fn prepare_inner(&self) -> Result<()> {
        crate::fault::runner::access::prepare_fault_fixture(
            &self.config.cluster,
            self.context.spec.isolation,
        )?;
        let tenant = wait_for_ready_tenant(&self.config.cluster).await?;
        let tenant_uid = tenant.metadata.uid.context("rotation Tenant has no UID")?;
        wait_for_stable_rustfs_pods(
            &self.config.cluster,
            self.config.expected_rustfs_pod_count,
            self.config.rustfs_pod_stable_window,
        )
        .await?;
        let pods = rustfs_pod_identities(&self.config.cluster)?;
        let (endpoint, forward) = s3_access(&self.config)?;
        self.state.lock().await.port_forward = forward;
        {
            let mut state = self.state.lock().await;
            ensure_s3_access(&mut state.port_forward, &self.config.cluster, &endpoint).await?;
        }
        let (admin_access, admin_secret) = resources::test_credentials();
        let admin = Arc::new(RustfsIdentityAdminClient::from_transport(
            RustfsAdminTransport::new(
                &endpoint,
                "us-east-1",
                admin_access,
                admin_secret,
                None,
                "s3chaos-fault-identity",
            )?,
        ));
        let layout =
            crate::rustfs::read_erasure_layout(&endpoint, "us-east-1", admin_access, admin_secret)
                .await?;
        ensure!(
            admin
                .users_with_prefix(self.old.access_key())
                .await?
                .is_empty()
                && admin
                    .policies_with_prefix(&self.policy_name)
                    .await?
                    .is_empty(),
            "generated IAM fixture already exists"
        );
        {
            let mut evidence = self.evidence();
            evidence.tenant_uid = tenant_uid;
            evidence.deployment_id = layout.deployment_id.clone();
            evidence.pods_before = pods;
            evidence.identity_absent_before_create = true;
            evidence.policy_absent_before_create = true;
        }
        self.persist()?;
        // Arm before the first mutation: losing a create response still owns
        // this unique, previously absent identity and requires removal.
        let guard = IdentityCleanupGuard {
            admin: admin.clone(),
            access_key: SecretString::new(self.old.access_key())?,
            policy_name: self.policy_name.clone(),
            collector: self.collector.clone(),
            case_name: self.scenario.case_name,
            evidence: self.evidence.clone(),
            armed: true,
        };
        {
            let mut state = self.state.lock().await;
            state.admin = Some(admin.clone());
            state.identity_guard = Some(guard);
        }
        admin
            .create_user(self.old.access_key(), self.old.secret_key())
            .await?;
        admin
            .create_policy(&self.policy_name, &bucket_policy(&self.context.bucket)?)
            .await?;
        admin
            .attach_policy(&self.policy_name, self.old.access_key(), false)
            .await?;
        ensure!(
            admin
                .policy_attached(&self.policy_name, self.old.access_key(), false)
                .await?,
            "run-owned bucket policy was not attached"
        );
        let root = S3WorkloadClient::new_without_retries(
            &endpoint,
            &self.context.bucket,
            admin_access,
            admin_secret,
            self.config.request_timeout,
        )
        .await?;
        ensure!(
            root.create_bucket(&self.context.history).await? == OperationOutcome::Ok
                && root.enable_bucket_versioning(&self.context.history).await?
                    == OperationOutcome::Ok,
            "rotation bucket creation or versioning failed"
        );
        let old_s3 = self
            .client(&endpoint, &self.old, self.config.request_timeout)
            .await?;
        let new_s3 = self
            .client(&endpoint, &self.new, self.config.request_timeout)
            .await?;
        let baseline = RecoveryHealthBaseline::from_layout(&layout, now_ms())?;
        self.context.events.record(
            "recovery-health-baseline",
            RunEventStatus::Succeeded,
            "healthy RustFS layout captured before credential rotation",
            Some(serde_json::to_value(&baseline)?),
        )?;
        prefill_objects(
            &old_s3,
            &self.context.history,
            &self.context.run_id,
            &self.context.workload_plan,
            self.scenario.prefill_count(),
            self.config.prefill_concurrency,
            self.config.workload_directory_marker_percent,
        )
        .await?;
        for write in self
            .context
            .history
            .records()
            .iter()
            .filter(|record| record.kind == OperationKind::Put)
        {
            require_committed_put(write)?;
            self.evidence()
                .old_prefill_operation_ids
                .push(write.id.clone());
        }
        {
            let mut state = self.state.lock().await;
            state.old_s3 = Some(old_s3);
            state.new_s3 = Some(new_s3);
            state.baseline = Some(baseline);
        }
        write_preflight_summary(
            &self.collector,
            &self.scenario,
            &self.config,
            &self.context.run_id,
            &[PreflightPhase::new(
                "credential-rotation-fixture",
                vec![PreflightCheck::passed(
                    "run-owned-identity",
                    "fresh Tenant, absent generated IAM identity, bucket-limited policy, versioning and old-secret writes proven",
                    ResponsibilityDomain::Harness,
                )],
            )],
        )?;
        Ok(())
    }

    async fn client(
        &self,
        endpoint: &str,
        credential: &RotationCredential,
        request_timeout: Duration,
    ) -> Result<S3WorkloadClient> {
        S3WorkloadClient::new_without_retries(
            endpoint,
            &self.context.bucket,
            credential.access_key(),
            credential.secret_key(),
            request_timeout,
        )
        .await
    }

    async fn run_workload_inner(&self) -> Result<()> {
        let (old, admin, operation_deadline) = {
            let state = self.state.lock().await;
            (
                state.old_s3.clone().context("old client is not prepared")?,
                state
                    .admin
                    .clone()
                    .context("admin client is not prepared")?,
                state
                    .operation_deadline
                    .context("rotation operation was not started")?,
            )
        };
        self.context.history.mark_fault_active_now();
        self.context.events.record(
            "credential-rotation",
            RunEventStatus::Started,
            "rotating a run-owned IAM secret during bounded S3 PUT requests",
            None,
        )?;
        let old = old.with_mutation_deadline(operation_deadline);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let workload = async {
            // join! polls this future through the first pending S3 send before
            // the rotation future can consume this notification.
            let _ = started_tx.send(());
            stream::iter(self.scenario.prefill_count()..self.scenario.object_count)
                .map(|index| {
                    let old = &old;
                    async move {
                        self.deadline.check()?;
                        let object = ObjectSpec::prepare_seeded(
                            &self.context.run_id,
                            index,
                            self.context.workload_plan.size_at(index),
                            self.context.workload_plan.seed,
                        );
                        let result = old
                            .put_object_record(&object, &self.context.history)
                            .await?;
                        self.evidence()
                            .old_workload_operation_ids
                            .push(result.id.clone());
                        Ok::<_, anyhow::Error>(result)
                    }
                })
                .buffer_unordered(self.context.workload_plan.concurrency)
                .collect::<Vec<_>>()
                .await
        };
        let rotation = async {
            started_rx.await.context("S3 workload did not begin")?;
            let mut receipt = SecretRotationReceipt {
                method: "PUT".to_string(),
                path: ROTATION_PATH.to_string(),
                started_at_ms: now_ms(),
                ended_at_ms: 0,
                started_sequence: self.context.history.next_event_sequence(),
                ended_sequence: 0,
                accepted: false,
            };
            self.evidence().rotation = Some(receipt.clone());
            let result = tokio::time::timeout_at(
                operation_deadline,
                admin.set_user_secret_key(self.new.access_key(), self.new.secret_key()),
            )
            .await;
            receipt.ended_at_ms = now_ms();
            receipt.ended_sequence = self.context.history.next_event_sequence();
            receipt.accepted = matches!(&result, Ok(Ok(())));
            self.evidence().rotation = Some(receipt);
            self.persist()?;
            result.context("secret rotation request exceeded the operation timeout")??;
            Ok::<_, anyhow::Error>(())
        };
        // Each S3 mutation finishes its own terminal history receipt. A failed
        // admin request cannot discard accepted writes in the other future.
        let (workload_result, rotation_result) = tokio::join!(workload, rotation);
        let writes = workload_result.into_iter().collect::<Result<Vec<_>>>()?;
        rotation_result?;
        ensure!(
            writes
                .iter()
                .all(|record| record.outcome == OperationOutcome::Ok || is_auth_rejection(record)),
            "old-credential load encountered a non-authentication failure"
        );
        self.context.history.mark_fault_ended_now();
        self.prove_auth_on_every_pod(operation_deadline).await?;
        self.run_new_credential_mutations(operation_deadline)
            .await?;
        self.evidence()
            .validate_history(&self.context.history.records())?;
        self.context.events.record("credential-rotation", RunEventStatus::Succeeded,
            "secret rotation, request overlap, every-Pod authentication, and new-credential mutations proven", None)?;
        self.state.lock().await.finished = true;
        Ok(())
    }

    async fn prove_auth_on_every_pod(&self, operation_deadline: Instant) -> Result<()> {
        let pods = self.evidence().pods_before.clone();
        let prefilled = self.evidence().old_prefill_operation_ids[0].clone();
        let baseline = self
            .context
            .history
            .records()
            .into_iter()
            .find(|record| record.id == prefilled)
            .context("prefill probe write is missing")?;
        let key = baseline
            .key
            .as_deref()
            .context("prefill probe key is missing")?;
        for pod in pods {
            self.deadline.check()?;
            let spec = PortForwardSpec::pod_on_available_port(
                &self.config.cluster.test_namespace,
                &pod.name,
                9000,
            )?;
            let endpoint = spec.local_base_url();
            let mut forward = spec.start_with_temp_log(&Kubectl::new(&self.config.cluster))?;
            wait_for_tenant_s3(
                &mut forward,
                &endpoint,
                operation_deadline.saturating_duration_since(Instant::now()),
            )
            .await?;
            let request_timeout = self
                .config
                .request_timeout
                .min(operation_deadline.saturating_duration_since(Instant::now()));
            ensure!(
                !request_timeout.is_zero(),
                "credential propagation exceeded the operation timeout"
            );
            let old = self
                .client(&endpoint, &self.old, request_timeout)
                .await?
                .with_request_deadline(operation_deadline);
            let new = self
                .client(&endpoint, &self.new, request_timeout)
                .await?
                .with_request_deadline(operation_deadline);
            loop {
                ensure!(
                    Instant::now() < operation_deadline,
                    "credential propagation exceeded the operation timeout"
                );
                self.deadline.check()?;
                let old_result = old
                    .get_object_recorded_result(key, &self.context.history)
                    .await?;
                let new_result = new
                    .get_object_recorded_result(key, &self.context.history)
                    .await?;
                let records = self.context.history.records();
                let old_record = records
                    .iter()
                    .find(|record| record.id == old_result.operation_id)
                    .context("old auth receipt is absent")?;
                let new_record = records
                    .iter()
                    .find(|record| record.id == new_result.operation_id)
                    .context("new auth receipt is absent")?;
                if is_auth_rejection(old_record) && new_record.outcome == OperationOutcome::Ok {
                    ensure!(
                        new_record.value_sha256 == baseline.value_sha256
                            && new_record.size_bytes == baseline.size_bytes,
                        "new secret returned incorrect committed bytes"
                    );
                    self.evidence().pod_auth.push(PodCredentialProof {
                        pod_name: pod.name,
                        pod_uid: pod.uid,
                        old_operation_id: old_result.operation_id,
                        new_operation_id: new_result.operation_id,
                    });
                    self.persist()?;
                    break;
                }
                ensure!(
                    [old_record, new_record]
                        .iter()
                        .all(|record| record.outcome == OperationOutcome::Ok
                            || is_auth_rejection(record)),
                    "credential propagation probe encountered a non-auth failure"
                );
                tokio::time::sleep(PROPAGATION_POLL_INTERVAL).await;
            }
        }
        let before = self.evidence().pods_before.clone();
        let after = rustfs_pod_identities(&self.config.cluster)?;
        ensure!(
            before
                .iter()
                .map(|pod| (&pod.name, &pod.uid))
                .collect::<BTreeSet<_>>()
                == after
                    .iter()
                    .map(|pod| (&pod.name, &pod.uid))
                    .collect::<BTreeSet<_>>(),
            "RustFS Pod identities changed during credential propagation proof"
        );
        Ok(())
    }

    async fn run_new_credential_mutations(&self, operation_deadline: Instant) -> Result<()> {
        let new = self
            .state
            .lock()
            .await
            .new_s3
            .clone()
            .context("new client is absent")?
            .with_request_deadline(operation_deadline);
        let object = ObjectSpec::prepare_seeded(
            &self.context.run_id,
            self.scenario.object_count,
            self.context.workload_plan.size_at(0).max(1),
            self.context.workload_plan.seed,
        );
        let put = new
            .put_object_record(&object, &self.context.history)
            .await?;
        self.evidence().new_put_operation_id = Some(put.id.clone());
        require_committed_put(&put)?;
        let get = new
            .get_object_recorded_result(&object.spec.key, &self.context.history)
            .await?;
        self.evidence().new_get_operation_id = Some(get.operation_id);
        ensure!(
            get.result.outcome == OperationOutcome::Ok
                && get
                    .result
                    .body
                    .as_deref()
                    .is_some_and(|body| object.spec.matches_body(body)),
            "new credential PUT/GET probe did not return matching bytes"
        );
        let replacement = object.spec.prepare_overwrite(1);
        let overwrite = new
            .put_object_record(&replacement, &self.context.history)
            .await?;
        self.evidence().new_overwrite_operation_id = Some(overwrite.id.clone());
        require_committed_put(&overwrite)?;
        let delete = new
            .delete_object_record(&object.spec.key, &self.context.history)
            .await?;
        self.evidence().new_delete_operation_id = Some(delete.id);
        ensure!(
            delete.outcome == OperationOutcome::Ok && delete.is_delete_marker == Some(true),
            "new credential DELETE did not commit a delete marker"
        );
        let get = new
            .get_object_recorded_result(&object.spec.key, &self.context.history)
            .await?;
        self.evidence().new_deleted_get_operation_id = Some(get.operation_id);
        ensure!(
            get.result.outcome == OperationOutcome::NotFound,
            "new credential delete marker did not hide the current object"
        );
        Ok(())
    }

    async fn verify_inner(&self) -> Result<()> {
        self.evidence()
            .validate_history(&self.context.history.records())?;
        let (s3, baseline) = {
            let state = self.state.lock().await;
            (
                state.new_s3.clone().context("new client is absent")?,
                state
                    .baseline
                    .clone()
                    .context("health baseline is absent")?,
            )
        };
        wait_for_stable_rustfs_pods(
            &self.config.cluster,
            self.config.expected_rustfs_pod_count,
            self.config.rustfs_pod_stable_window,
        )
        .await?;
        let pods = rustfs_pod_identities(&self.config.cluster)?;
        let (endpoint, mut forward) = s3_access(&self.config)?;
        ensure_s3_access(&mut forward, &self.config.cluster, &endpoint).await?;
        self.context.events.record(
            "recovery-health",
            RunEventStatus::Started,
            "checking RustFS health after IAM secret rotation",
            None,
        )?;
        let recovery = observe_recovery_health(
            &self.config.cluster,
            &endpoint,
            &baseline,
            &pods,
            &self.scenario.name,
            &self.context.run_id,
            &|report| {
                self.collector
                    .write_text(
                        self.scenario.case_name,
                        RECOVERY_HEALTH_ARTIFACT,
                        &serde_json::to_string_pretty(report)?,
                    )
                    .map(|_| ())
            },
        )
        .await?;
        recovery.require_success()?;
        self.context.events.record(
            "recovery-health",
            RunEventStatus::Succeeded,
            "RustFS remained healthy after IAM secret rotation",
            None,
        )?;
        let checker_start = self.context.history.records().len();
        let report = checker::check_s3_history(
            &s3,
            &self.context.history,
            true,
            self.context.workload_plan.concurrency,
            true,
        )
        .await?;
        self.collector.write_text(
            self.scenario.case_name,
            "checker-report.json",
            &serde_json::to_string_pretty(&report)?,
        )?;
        let reread = checker::recovery_stability_reread(
            &s3,
            &self.context.history,
            &report,
            checker_start,
            self.context.workload_plan.concurrency,
            self.config.recovery_stability_reread,
        )
        .await?;
        self.collector.write_text(
            self.scenario.case_name,
            "recovery-stability.json",
            &serde_json::to_string_pretty(&reread)?,
        )?;
        ensure!(
            report.failed_writes_materialized.is_empty(),
            "authentication-rejected old-credential writes became visible"
        );
        report.require_success()?;
        checker::validate_checker_audit_against_history(&report, &self.context.history.records())?;
        self.evidence().verified = true;
        self.context.events.record("checker-final", RunEventStatus::Succeeded,
            "all committed versions, historical bytes, and delete markers passed the existing checker", None)?;
        Ok(())
    }
}

#[async_trait(?Send)]
impl AdminCaseDriver for LiveCredentialRotationDriver {
    async fn prepare(&self) -> Result<()> {
        self.preserve(self.prepare_inner().await).await
    }
    async fn start(&self) -> Result<Instant> {
        let start = Instant::now();
        let operation = start
            .checked_add(self.plan.operation_timeout)
            .context("rotation deadline overflow")?;
        let operation = self
            .deadline
            .instant()?
            .map_or(operation, |deadline| operation.min(deadline));
        self.state.lock().await.operation_deadline = Some(operation);
        Ok(start)
    }
    async fn observe(&self) -> Result<AdminWorkflowObservation> {
        Ok(if self.state.lock().await.finished {
            AdminWorkflowObservation::Completed
        } else {
            AdminWorkflowObservation::Running
        })
    }
    async fn run_workload(&self) -> Result<()> {
        let result = self.run_workload_inner().await;
        self.state.lock().await.finished = true;
        self.preserve(result).await
    }
    async fn verify_completed_overlap(&self) -> Result<()> {
        self.evidence()
            .validate_history(&self.context.history.records())
    }
    async fn verify(&self) -> Result<()> {
        self.preserve(self.verify_inner().await).await
    }
    async fn cancel(&self) -> Result<AdminCancelOutcome> {
        // Secret updates are atomic and have no cancel endpoint. Removing the
        // run-owned IAM identity reconciles both accepted and ambiguous updates.
        Ok(AdminCancelOutcome::NoOwnedOperation)
    }
    async fn cleanup(&self) -> Result<()> {
        let result = async {
            let mut state = self.state.lock().await;
            if let Some(guard) = state.identity_guard.as_mut() {
                guard.cleanup().await?;
                guard.armed = false;
            }
            drop(state.identity_guard.take());
            if self.evidence().verified {
                self.context.events.record(
                    "run",
                    RunEventStatus::Succeeded,
                    "credential rotation and run-owned IAM cleanup completed",
                    None,
                )?;
            }
            drop(state.port_forward.take());
            Ok(())
        }
        .await;
        self.preserve(result).await
    }
}

struct IdentityCleanupGuard {
    admin: Arc<RustfsIdentityAdminClient>,
    access_key: SecretString,
    policy_name: String,
    collector: ArtifactCollector,
    case_name: &'static str,
    evidence: Arc<Mutex<CredentialRotationEvidence>>,
    armed: bool,
}

impl IdentityCleanupGuard {
    async fn cleanup(&self) -> Result<()> {
        cleanup_identity(
            &self.admin,
            self.access_key.expose(),
            &self.policy_name,
            &self.collector,
            self.case_name,
            &self.evidence,
        )
        .await
    }
}

impl Drop for IdentityCleanupGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let admin = self.admin.clone();
        let access_key = self.access_key.clone();
        let policy_name = self.policy_name.clone();
        let collector = self.collector.clone();
        let case_name = self.case_name;
        let evidence = self.evidence.clone();
        let thread = std::thread::Builder::new()
            .name("s3chaos-identity-cleanup".to_string())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .context("build identity cleanup runtime")?;
                runtime.block_on(async {
                    tokio::time::timeout(
                        CANCELLATION_CLEANUP_TIMEOUT,
                        cleanup_identity(
                            &admin,
                            access_key.expose(),
                            &policy_name,
                            &collector,
                            case_name,
                            &evidence,
                        ),
                    )
                    .await
                    .context("identity cancellation cleanup exceeded its timeout")?
                })
            });
        match thread {
            Ok(thread) => match thread.join() {
                Ok(Ok(())) => {}
                _ => eprintln!(
                    "warning: run-owned IAM cancellation cleanup failed; inspect credential-rotation.json"
                ),
            },
            Err(_) => eprintln!(
                "warning: could not start run-owned IAM cancellation cleanup; inspect credential-rotation.json"
            ),
        }
    }
}

async fn cleanup_identity(
    admin: &RustfsIdentityAdminClient,
    access_key: &str,
    policy_name: &str,
    collector: &ArtifactCollector,
    case_name: &str,
    evidence: &Arc<Mutex<CredentialRotationEvidence>>,
) -> Result<()> {
    evidence
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .cleanup
        .attempted = true;
    write_evidence(collector, case_name, evidence)?;
    let result = async {
        admin.remove_user(access_key).await?;
        let user_absent = admin.users_with_prefix(access_key).await?.is_empty();
        evidence
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .cleanup
            .user_absent = user_absent;
        ensure!(user_absent, "run-owned IAM user removal did not converge");
        admin.remove_policy(policy_name).await?;
        let policy_absent = admin.policies_with_prefix(policy_name).await?.is_empty();
        let mut evidence = evidence
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        evidence.cleanup.policy_absent = policy_absent;
        ensure!(
            policy_absent,
            "run-owned IAM policy removal did not converge"
        );
        evidence.cleanup.completed_at_ms = Some(now_ms());
        Ok(())
    }
    .await;
    let persisted = write_evidence(collector, case_name, evidence);
    result.and(persisted)
}

fn write_evidence(
    collector: &ArtifactCollector,
    case_name: &str,
    evidence: &Arc<Mutex<CredentialRotationEvidence>>,
) -> Result<()> {
    let evidence = evidence
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    collector.write_text(
        case_name,
        CREDENTIAL_ROTATION_ARTIFACT,
        &serde_json::to_string_pretty(&*evidence)?,
    )?;
    Ok(())
}

pub(crate) async fn run_credential_rotation_case(
    config: &FaultTestConfig,
    collector: &ArtifactCollector,
    scenario: &FaultScenario,
    execution_plan: &ExecutionPlan,
    plan: &CredentialRotationExecutionPlan,
    run_id: &str,
    deadline: RunDeadline,
) -> Result<()> {
    ensure!(
        matches!(execution_plan, ExecutionPlan::CredentialRotation(value) if value == plan)
            && plan.scenario == scenario.name
            && plan.case_name == scenario.case_name,
        "credential rotation runner received a mismatched plan"
    );
    let driver = LiveCredentialRotationDriver::new(
        config,
        collector,
        scenario,
        execution_plan,
        plan,
        run_id,
        deadline,
    )?;
    let execution = execute_admin_workflow(
        &scenario.name,
        run_id,
        &driver,
        deadline,
        Duration::from_millis(100),
        plan.operation_timeout,
        config.cluster.timeout,
    )
    .await;
    persist_admin_workflow(collector, scenario.case_name, execution)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fault::{history::Recorder, plan::ExecutionKind, scenarios};

    fn committed_write(
        history: &Recorder,
        object: &crate::fault::workload::PreparedObject,
        version: &str,
    ) -> OperationRecord {
        let mut record = history.begin(
            OperationKind::Put,
            "bucket",
            Some(object.spec.key.clone()),
            Some(object.spec.sha256.clone()),
            Some(object.spec.size_bytes),
        );
        record.version_id = Some(version.to_string());
        history
            .finish(record, OperationOutcome::Ok, Some(200), None)
            .expect("write")
    }

    fn get(
        history: &Recorder,
        key: &str,
        source: Option<&OperationRecord>,
        status: u16,
    ) -> OperationRecord {
        let mut record = history.begin(
            OperationKind::Get,
            "bucket",
            Some(key.to_string()),
            None,
            None,
        );
        if let Some(source) = source {
            record.value_sha256 = source.value_sha256.clone();
            record.size_bytes = source.size_bytes;
        }
        let outcome = match status {
            200 => OperationOutcome::Ok,
            404 => OperationOutcome::NotFound,
            _ => OperationOutcome::Failed,
        };
        history
            .finish(
                record,
                outcome,
                Some(status),
                (status != 200).then(|| "service error".to_string()),
            )
            .expect("get")
    }

    fn valid_history() -> (CredentialRotationEvidence, Vec<OperationRecord>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let history = Recorder::create(
            dir.path().join("history.jsonl"),
            CREDENTIAL_ROTATION_MID_LOAD_SCENARIO,
            "run-1",
        )
        .expect("history");
        let old = RotationCredential::generated("run-owned-user").expect("old credential");
        let new = RotationCredential::generated("run-owned-user").expect("new credential");
        let baseline_object = ObjectSpec::prepare_seeded("run-1", 0, 16, 7);
        let baseline = committed_write(&history, &baseline_object, "prefill-v1");
        let second = committed_write(
            &history,
            &ObjectSpec::prepare_seeded("run-1", 1, 16, 7),
            "prefill-v2",
        );
        history.mark_fault_active_now();
        let load_object = ObjectSpec::prepare_seeded("run-1", 2, 16, 7);
        let mut load = history.begin(
            OperationKind::Put,
            "bucket",
            Some(load_object.spec.key.clone()),
            Some(load_object.spec.sha256.clone()),
            Some(16),
        );
        load.version_id = Some("load-v1".to_string());
        let rotation_started_at = now_ms();
        let rotation_started_sequence = history.next_event_sequence();
        let load = history
            .finish(load, OperationOutcome::Ok, Some(200), None)
            .expect("load completion");
        let rejected = history.begin(
            OperationKind::Put,
            "bucket",
            Some(ObjectSpec::seeded_key("run-1", 3)),
            Some(sha256_hex(b"failed-write")),
            Some(12),
        );
        let rejected = history
            .finish(
                rejected,
                OperationOutcome::Failed,
                Some(403),
                Some("SignatureDoesNotMatch".to_string()),
            )
            .expect("rejection");
        let rotation_ended_at = now_ms();
        let rotation_ended_sequence = history.next_event_sequence();
        history.mark_fault_ended_now();
        let mut pod_auth = Vec::new();
        let pods_before = vec![
            PodIdentity {
                name: "rustfs-0".to_string(),
                uid: "uid-0".to_string(),
            },
            PodIdentity {
                name: "rustfs-1".to_string(),
                uid: "uid-1".to_string(),
            },
        ];
        for pod in &pods_before {
            let old = get(&history, &baseline_object.spec.key, None, 403);
            let new = get(&history, &baseline_object.spec.key, Some(&baseline), 200);
            pod_auth.push(PodCredentialProof {
                pod_name: pod.name.clone(),
                pod_uid: pod.uid.clone(),
                old_operation_id: old.id,
                new_operation_id: new.id,
            });
        }
        let new_object = ObjectSpec::prepare_seeded("run-1", 4, 16, 7);
        let new_put = committed_write(&history, &new_object, "new-v1");
        let new_get = get(&history, &new_object.spec.key, Some(&new_put), 200);
        let overwrite = committed_write(&history, &new_object.spec.prepare_overwrite(1), "new-v2");
        let mut delete = history.begin(
            OperationKind::Delete,
            "bucket",
            Some(new_object.spec.key.clone()),
            None,
            None,
        );
        delete.is_delete_marker = Some(true);
        delete.version_id = Some("delete-v1".to_string());
        let delete = history
            .finish(delete, OperationOutcome::Ok, Some(204), None)
            .expect("delete");
        let deleted_get = get(&history, &new_object.spec.key, None, 404);
        let evidence = CredentialRotationEvidence {
            schema_version: 1,
            scenario: CREDENTIAL_ROTATION_MID_LOAD_SCENARIO.to_string(),
            run_id: "run-1".to_string(),
            bucket: "bucket".to_string(),
            context: "context".to_string(),
            namespace: "namespace".to_string(),
            tenant: "tenant".to_string(),
            tenant_uid: "tenant-uid".to_string(),
            deployment_id: "deployment".to_string(),
            old_credential: old.artifact(),
            new_credential: new.artifact(),
            identity_absent_before_create: true,
            policy_absent_before_create: true,
            policy_sha256: sha256_hex(bucket_policy("bucket").expect("policy").as_bytes()),
            pods_before,
            old_prefill_operation_ids: vec![baseline.id, second.id],
            old_workload_operation_ids: vec![load.id, rejected.id],
            rotation: Some(SecretRotationReceipt {
                method: "PUT".to_string(),
                path: ROTATION_PATH.to_string(),
                started_at_ms: rotation_started_at,
                ended_at_ms: rotation_ended_at,
                started_sequence: rotation_started_sequence,
                ended_sequence: rotation_ended_sequence,
                accepted: true,
            }),
            pod_auth,
            new_put_operation_id: Some(new_put.id),
            new_get_operation_id: Some(new_get.id),
            new_overwrite_operation_id: Some(overwrite.id),
            new_delete_operation_id: Some(delete.id),
            new_deleted_get_operation_id: Some(deleted_get.id),
            verified: true,
            cleanup: CredentialCleanupEvidence {
                attempted: true,
                user_absent: true,
                policy_absent: true,
                completed_at_ms: Some(now_ms()),
            },
        };
        (evidence, history.records())
    }

    #[test]
    fn real_request_overlap_and_every_pod_auth_require_nonempty_history() {
        let (evidence, history) = valid_history();
        evidence.validate_history(&history).expect("valid evidence");
        assert!(evidence.validate_history(&[]).is_err());
        let mut wrong = evidence.clone();
        wrong.old_workload_operation_ids.clear();
        assert!(wrong.validate_history(&history).is_err());
        let mut wrong = evidence;
        wrong.pod_auth.pop();
        assert!(wrong.validate_history(&history).is_err());
    }

    #[test]
    fn rotation_without_an_overlapping_request_is_rejected() {
        let (mut evidence, history) = valid_history();
        let receipt = evidence.rotation.as_mut().expect("rotation");
        receipt.started_sequence = history[3].ended_sequence.expect("load end") + 1;
        receipt.ended_sequence = receipt.started_sequence + 1;
        let error = evidence
            .validate_history(&history)
            .expect_err("no overlapping load");
        assert!(
            error
                .to_string()
                .contains("overlaps the actual secret rotation"),
            "{error:#}"
        );
    }

    #[test]
    fn denied_new_credentials_and_still_valid_old_credentials_fail_proof() {
        let (evidence, history) = valid_history();
        for (id, outcome, status) in [
            (
                &evidence.pod_auth[0].old_operation_id,
                OperationOutcome::Ok,
                200,
            ),
            (
                &evidence.pod_auth[0].old_operation_id,
                OperationOutcome::Failed,
                500,
            ),
            (
                &evidence.pod_auth[0].new_operation_id,
                OperationOutcome::Failed,
                403,
            ),
        ] {
            let mut wrong = history.clone();
            let record = wrong
                .iter_mut()
                .find(|record| &record.id == id)
                .expect("record");
            record.outcome = outcome;
            record.http_status = Some(status);
            assert!(evidence.validate_history(&wrong).is_err());
        }
    }

    #[test]
    fn auth_proof_cannot_substitute_another_pod_or_other_committed_bytes() {
        let (evidence, history) = valid_history();
        let mut wrong = evidence.clone();
        wrong.pod_auth[0].pod_uid = "replacement-uid".to_string();
        assert!(wrong.validate_history(&history).is_err());
        let mut wrong_history = history;
        wrong_history
            .iter_mut()
            .find(|record| record.id == evidence.pod_auth[0].new_operation_id)
            .expect("new auth")
            .value_sha256 = Some(sha256_hex(b"other bytes"));
        assert!(evidence.validate_history(&wrong_history).is_err());
    }

    #[test]
    fn unchanged_secret_and_different_principal_are_rejected() {
        let (evidence, history) = valid_history();
        let mut wrong = evidence.clone();
        wrong.new_credential = wrong.old_credential.clone();
        assert!(wrong.validate_history(&history).is_err());
        let mut wrong = evidence;
        wrong.new_credential.principal_sha256 = sha256_hex(b"another-user");
        assert!(wrong.validate_history(&history).is_err());
    }

    #[test]
    fn non_auth_load_failure_and_unconfirmed_version_fail_closed() {
        let (evidence, history) = valid_history();
        let mut wrong = history.clone();
        wrong
            .iter_mut()
            .find(|record| record.id == evidence.old_workload_operation_ids[1])
            .expect("rejected load")
            .http_status = Some(500);
        assert!(evidence.validate_history(&wrong).is_err());
        let mut wrong = history;
        wrong
            .iter_mut()
            .find(|record| record.id == evidence.old_prefill_operation_ids[0])
            .expect("prefill")
            .version_id = None;
        assert!(evidence.validate_history(&wrong).is_err());
    }

    #[test]
    fn post_rotation_verification_requires_version_lineage_and_delete_visibility() {
        let (evidence, history) = valid_history();
        let mut wrong = history.clone();
        let original_version = wrong
            .iter()
            .find(|record| Some(&record.id) == evidence.new_put_operation_id.as_ref())
            .expect("new put")
            .version_id
            .clone();
        wrong
            .iter_mut()
            .find(|record| Some(&record.id) == evidence.new_overwrite_operation_id.as_ref())
            .expect("overwrite")
            .version_id = original_version;
        assert!(evidence.validate_history(&wrong).is_err());
        let mut wrong = history.clone();
        wrong
            .iter_mut()
            .find(|record| Some(&record.id) == evidence.new_delete_operation_id.as_ref())
            .expect("delete")
            .is_delete_marker = Some(false);
        assert!(evidence.validate_history(&wrong).is_err());
        let mut wrong = history;
        wrong
            .iter_mut()
            .find(|record| Some(&record.id) == evidence.new_deleted_get_operation_id.as_ref())
            .expect("deleted get")
            .outcome = OperationOutcome::Ok;
        assert!(evidence.validate_history(&wrong).is_err());
    }

    #[test]
    fn history_references_cannot_be_repeated_or_cross_run() {
        let (evidence, history) = valid_history();
        let mut wrong = evidence.clone();
        wrong.pod_auth[1].new_operation_id = wrong.pod_auth[0].new_operation_id.clone();
        assert!(wrong.validate_history(&history).is_err());
        let mut wrong = history;
        wrong[0].run_id = Some("other-run".to_string());
        assert!(evidence.validate_history(&wrong).is_err());
    }

    #[test]
    fn checker_empty_model_and_missing_cleanup_cannot_produce_a_pass() {
        let (evidence, history) = valid_history();
        let checker = serde_json::from_value::<CheckerReport>(serde_json::json!({
            "scenario": CREDENTIAL_ROTATION_MID_LOAD_SCENARIO, "run_id": "run-1",
            "committed_puts": 0, "expected_live_objects": 0, "verified_live_objects": 0,
            "missing_committed_objects": [], "unavailable_committed_objects": [],
            "unknown_committed_read_failures": [], "hash_mismatches": [],
            "successful_corrupted_reads": [], "unexpected_visible_deleted_objects": [],
            "list_history_warning_count": 0, "final_list_warning_count": 0,
            "list_history_warnings": [], "list_warnings": [], "final_listed_objects": 0,
            "tenant_recovered": true, "passed": true, "versioning_expected": true
        }))
        .expect("empty checker");
        assert!(validate_credential_rotation_evidence(&evidence, &history, &checker).is_err());
        let mut materialized = checker.clone();
        materialized.expected_live_objects = 1;
        materialized.expected_committed_versions = 1;
        materialized.failed_writes_materialized = vec![ObjectSpec::seeded_key("run-1", 3)];
        let error = validate_credential_rotation_evidence(&evidence, &history, &materialized)
            .expect_err("authentication rejection must not commit data");
        assert!(error.to_string().contains("authentication-rejected"));
        let mut wrong = evidence;
        wrong.cleanup.user_absent = false;
        let error = validate_credential_rotation_evidence(&wrong, &history, &checker)
            .expect_err("unfinished cleanup");
        assert!(
            error.to_string().contains("IAM fixture cleanup"),
            "{error:#}"
        );
    }

    #[test]
    fn credentials_and_debug_output_publish_only_sha256_fingerprints() {
        let old = RotationCredential::generated("generated-access-key").expect("credential");
        let artifact = serde_json::to_string(&old.artifact()).expect("artifact");
        let debug = format!("{old:?}");
        for value in [old.access_key(), old.secret_key()] {
            assert!(!artifact.contains(value));
            assert!(!debug.contains(value));
        }
        assert!(artifact.contains(&sha256_hex(old.access_key().as_bytes())));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancellation_guard_removes_owned_identity_before_transport_is_released() {
        use axum::{Router, http::StatusCode, routing::any};
        let calls = Arc::new(Mutex::new(Vec::new()));
        let observed = calls.clone();
        let app = Router::new().fallback(any(move |request: axum::extract::Request| {
            let observed = observed.clone();
            async move {
                observed
                    .lock()
                    .expect("calls")
                    .push((request.method().clone(), request.uri().path().to_string()));
                (StatusCode::OK, "{}")
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let endpoint = format!("http://{}", listener.local_addr().expect("address"));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.expect("server") });
        let transport = RustfsAdminTransport::new(
            &endpoint,
            "us-east-1",
            "admin-access",
            "admin-secret",
            None,
            "cleanup-test",
        )
        .expect("transport");
        let admin = Arc::new(RustfsIdentityAdminClient::from_transport(transport));
        let (mut fixture, _) = valid_history();
        fixture.cleanup = CredentialCleanupEvidence::default();
        let evidence = Arc::new(Mutex::new(fixture));
        let dir = tempfile::tempdir().expect("tempdir");
        let collector = ArtifactCollector::new(dir.path());
        let guard = IdentityCleanupGuard {
            admin,
            access_key: SecretString::new("owned-user").expect("identity"),
            policy_name: "owned-policy".to_string(),
            collector: collector.clone(),
            case_name: "rotation-case",
            evidence: evidence.clone(),
            armed: true,
        };
        drop(guard);
        let persisted: CredentialRotationEvidence = serde_json::from_str(
            &std::fs::read_to_string(
                collector
                    .case_dir("rotation-case")
                    .join(CREDENTIAL_ROTATION_ARTIFACT),
            )
            .expect("artifact"),
        )
        .expect("evidence");
        assert!(
            persisted.cleanup.attempted
                && persisted.cleanup.user_absent
                && persisted.cleanup.policy_absent
        );
        assert!(persisted.cleanup.completed_at_ms.is_some());
        assert_eq!(
            *calls.lock().expect("calls"),
            [
                (
                    http::Method::DELETE,
                    "/rustfs/admin/v3/remove-user".to_string()
                ),
                (http::Method::GET, "/rustfs/admin/v3/list-users".to_string()),
                (
                    http::Method::DELETE,
                    "/rustfs/admin/v3/remove-canned-policy".to_string()
                ),
                (
                    http::Method::GET,
                    "/rustfs/admin/v3/list-canned-policies".to_string()
                ),
            ]
        );
        let raw = serde_json::to_string(&persisted).expect("artifact");
        assert!(!raw.contains("owned-user") && !raw.contains("admin-secret"));
        server.abort();
    }

    #[tokio::test]
    async fn timed_out_cleanup_preserves_an_incomplete_identity_receipt() {
        use axum::{Router, http::StatusCode, routing::any};
        let app = Router::new().fallback(any(|| async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            (StatusCode::OK, "{}")
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let endpoint = format!("http://{}", listener.local_addr().expect("address"));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.expect("server") });
        let transport = RustfsAdminTransport::new(
            &endpoint,
            "us-east-1",
            "admin-access",
            "admin-secret",
            None,
            "cleanup-test",
        )
        .expect("transport");
        let admin = RustfsIdentityAdminClient::from_transport(transport);
        let (mut fixture, _) = valid_history();
        fixture.cleanup = CredentialCleanupEvidence::default();
        let evidence = Arc::new(Mutex::new(fixture));
        let dir = tempfile::tempdir().expect("tempdir");
        let collector = ArtifactCollector::new(dir.path());
        let result = tokio::time::timeout(
            Duration::from_millis(10),
            cleanup_identity(
                &admin,
                "owned-user",
                "owned-policy",
                &collector,
                "rotation-case",
                &evidence,
            ),
        )
        .await;
        assert!(result.is_err());
        let persisted: CredentialRotationEvidence = serde_json::from_str(
            &std::fs::read_to_string(
                collector
                    .case_dir("rotation-case")
                    .join(CREDENTIAL_ROTATION_ARTIFACT),
            )
            .expect("artifact"),
        )
        .expect("evidence");
        assert!(persisted.cleanup.attempted);
        assert!(!persisted.cleanup.user_absent && !persisted.cleanup.policy_absent);
        assert!(persisted.cleanup.completed_at_ms.is_none());
        server.abort();
    }

    #[test]
    fn existing_entrypoints_select_a_typed_versioned_rotation_suite() {
        let mut config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        config.scenario = CREDENTIAL_ROTATION_MID_LOAD_SCENARIO.to_string();
        scenarios::apply_catalog_defaults(&mut config).expect("defaults");
        assert!(config.workload_versioning);
        let scenario = FaultScenario::from_config(&config).expect("executable scenario");
        let plan = ExecutionPlan::from_scenario_with_options(
            &scenario,
            scenarios::scenario_spec(&scenario.name).expect("spec"),
            crate::fault::plan::FaultPlanOptions::from_config(&config),
        )
        .expect("typed plan");
        assert_eq!(plan.kind(), ExecutionKind::CredentialRotation);
        assert!(plan.injection().is_none());
        assert!(!plan.requires_static_storage());
        let suite = crate::fault::suite::resolve_fault_suite_yaml(
            "fault/examples/credential-rotation.yaml",
        )
        .expect("suite");
        assert_eq!(
            suite.scenarios[0].name,
            CREDENTIAL_ROTATION_MID_LOAD_SCENARIO
        );
    }
}
