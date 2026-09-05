// Copyright 2025 RustFS Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

//! Fault-owned policy and a typed RustFS adapter for destructive pool
//! operations. The port deliberately excludes IAM administration: callers see
//! only the capabilities required by the topology reliability cases.

use anyhow::{Context, Result, bail, ensure};
use async_trait::async_trait;
use http::Method;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

use crate::fault::scenarios::{ADMIN_DECOMMISSION_SCENARIO, ADMIN_REBALANCE_SCENARIO};
use crate::rustfs::{RustfsAdminResponse, RustfsAdminTransport};

pub const ADMIN_PREFIX: &str = "/rustfs/admin/v3";
pub const ADMIN_TOPOLOGY_PROOF_ARTIFACT: &str = "admin-topology-proof.json";
pub const ADMIN_OPERATION_ARTIFACT: &str = "admin-operation.json";
pub const ADMIN_OPERATION_PROGRESS_ARTIFACT: &str = "admin-operation-progress.jsonl";
pub const DECOMMISSION_TARGET_POOL_NAME: &str = "decommission-target";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AdminTopologyKind {
    Decommission,
    Rebalance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminTopologyPlan {
    pub kind: AdminTopologyKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_pool_id: Option<usize>,
}

impl AdminTopologyPlan {
    pub fn for_scenario(scenario: &str) -> Result<Self> {
        match scenario {
            ADMIN_DECOMMISSION_SCENARIO => Ok(Self {
                kind: AdminTopologyKind::Decommission,
                // Pool zero remains the destination. The fresh test fixture
                // creates pool one solely as the decommission target.
                target_pool_id: Some(1),
            }),
            ADMIN_REBALANCE_SCENARIO => Ok(Self {
                kind: AdminTopologyKind::Rebalance,
                target_pool_id: None,
            }),
            other => bail!("scenario {other:?} is not an admin topology case"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminPool {
    #[serde(default)]
    pub id: usize,
    #[serde(default, rename = "cmdline")]
    pub expression: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub decommission_status: String,
    #[serde(default)]
    pub rebalance_status: String,
    #[serde(default)]
    pub total_size: u64,
    #[serde(default)]
    pub current_size: u64,
    #[serde(default)]
    pub used_size: u64,
    #[serde(default)]
    pub used: f64,
    #[serde(default, rename = "decommissionInfo")]
    pub decommission: Option<DecommissionProgress>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DecommissionProgress {
    #[serde(default)]
    pub start_time: Option<String>,
    #[serde(default)]
    pub complete: bool,
    #[serde(default)]
    pub failed: bool,
    #[serde(default)]
    pub canceled: bool,
    #[serde(default)]
    pub queued: bool,
    #[serde(default)]
    pub objects_decommissioned: u64,
    #[serde(default)]
    pub objects_decommissioned_failed: u64,
    #[serde(default)]
    pub bytes_decommissioned: u64,
    #[serde(default)]
    pub bytes_decommissioned_failed: u64,
    #[serde(default)]
    pub waiting_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecommissionPoolStatus {
    pub id: usize,
    #[serde(default, rename = "cmdline")]
    pub expression: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub pool_status: String,
    #[serde(default, rename = "decommissionInfo")]
    pub decommission: Option<DecommissionProgress>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RebalanceStart {
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RebalanceCleanupWarnings {
    #[serde(default)]
    pub count: u64,
    #[serde(default, rename = "lastMsg")]
    pub last_message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RebalancePoolStatus {
    pub id: usize,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub cleanup_warnings: RebalanceCleanupWarnings,
    #[serde(default)]
    pub progress: Option<RebalanceProgress>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RebalanceProgress {
    #[serde(default, rename = "objects")]
    pub objects: u64,
    #[serde(default, rename = "versions")]
    pub versions: u64,
    #[serde(default)]
    pub bytes: u64,
    #[serde(default)]
    pub remaining_buckets: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RebalanceStatus {
    pub id: String,
    #[serde(default)]
    pub pools: Vec<RebalancePoolStatus>,
    #[serde(default)]
    pub stopped_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminRequestEvidence {
    pub method: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub query: BTreeMap<String, String>,
    pub status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminCall<T> {
    pub value: T,
    pub request: AdminRequestEvidence,
}

#[async_trait]
pub trait AdminTopologyPort: Send + Sync {
    async fn list_pools(&self) -> Result<AdminCall<Vec<AdminPool>>>;
    async fn start_decommission(&self, pool_id: usize, expression: &str) -> Result<AdminCall<()>>;
    async fn decommission_status(
        &self,
        pool_id: usize,
        expression: &str,
    ) -> Result<AdminCall<DecommissionPoolStatus>>;
    async fn cancel_decommission(&self, pool_id: usize, expression: &str) -> Result<AdminCall<()>>;
    async fn clear_decommission(&self, pool_id: usize, expression: &str) -> Result<AdminCall<()>>;
    async fn start_rebalance(&self) -> Result<AdminCall<RebalanceStart>>;
    async fn rebalance_status(&self) -> Result<AdminCall<RebalanceStatus>>;
    async fn stop_rebalance(&self) -> Result<AdminCall<()>>;
}

#[derive(Debug, Clone)]
pub struct RustfsAdminTopologyAdapter {
    transport: RustfsAdminTransport,
}

impl RustfsAdminTopologyAdapter {
    pub fn new(endpoint: &str, region: &str, access_key: &str, secret_key: &str) -> Result<Self> {
        Ok(Self {
            transport: RustfsAdminTransport::new(
                endpoint,
                region,
                access_key,
                secret_key,
                None,
                "s3chaos-fault-admin-topology",
            )?,
        })
    }

    async fn json<T: for<'de> Deserialize<'de>>(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, &str)],
    ) -> Result<AdminCall<T>> {
        let response = self
            .transport
            .request(method.clone(), path, query, Vec::new(), None)
            .await?;
        require_success(&response, path)?;
        let value = serde_json::from_slice(&response.body)
            .with_context(|| format!("decode RustFS admin response for {path}"))?;
        Ok(AdminCall {
            value,
            request: request_evidence(method, path, query, response),
        })
    }

    async fn empty(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, &str)],
    ) -> Result<AdminCall<()>> {
        let response = self
            .transport
            .request(method.clone(), path, query, Vec::new(), None)
            .await?;
        require_success(&response, path)?;
        Ok(AdminCall {
            value: (),
            request: request_evidence(method, path, query, response),
        })
    }
}

fn request_evidence(
    method: Method,
    path: &str,
    query: &[(&str, &str)],
    response: RustfsAdminResponse,
) -> AdminRequestEvidence {
    AdminRequestEvidence {
        method: method.to_string(),
        path: path.to_string(),
        query: query
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect(),
        status: response.status,
        request_id: response.request_id,
    }
}

fn require_success(response: &RustfsAdminResponse, path: &str) -> Result<()> {
    ensure!(
        (200..300).contains(&response.status),
        "RustFS admin request {path} failed: status={} request_id={}",
        response.status,
        response.request_id.as_deref().unwrap_or("unknown")
    );
    Ok(())
}

fn validate_pool_expression(expression: &str) -> Result<()> {
    ensure!(
        !expression.trim().is_empty(),
        "pool expression must not be empty"
    );
    Ok(())
}

#[async_trait]
impl AdminTopologyPort for RustfsAdminTopologyAdapter {
    async fn list_pools(&self) -> Result<AdminCall<Vec<AdminPool>>> {
        self.json(Method::GET, "/rustfs/admin/v3/pools/list", &[])
            .await
    }

    async fn start_decommission(&self, pool_id: usize, expression: &str) -> Result<AdminCall<()>> {
        validate_pool_expression(expression)?;
        let pool_id = pool_id.to_string();
        self.empty(
            Method::POST,
            "/rustfs/admin/v3/pools/decommission",
            &[("pool", pool_id.as_str()), ("by-id", "true")],
        )
        .await
    }

    async fn decommission_status(
        &self,
        pool_id: usize,
        expression: &str,
    ) -> Result<AdminCall<DecommissionPoolStatus>> {
        validate_pool_expression(expression)?;
        let pool_id = pool_id.to_string();
        self.json(
            Method::GET,
            "/rustfs/admin/v3/decommission/status",
            &[("pool", pool_id.as_str()), ("by-id", "true")],
        )
        .await
    }

    async fn cancel_decommission(&self, pool_id: usize, expression: &str) -> Result<AdminCall<()>> {
        validate_pool_expression(expression)?;
        let pool_id = pool_id.to_string();
        self.empty(
            Method::POST,
            "/rustfs/admin/v3/pools/cancel",
            &[("pool", pool_id.as_str()), ("by-id", "true")],
        )
        .await
    }

    async fn clear_decommission(&self, pool_id: usize, expression: &str) -> Result<AdminCall<()>> {
        validate_pool_expression(expression)?;
        let pool_id = pool_id.to_string();
        self.empty(
            Method::POST,
            "/rustfs/admin/v3/pools/clear",
            &[("pool", pool_id.as_str()), ("by-id", "true")],
        )
        .await
    }

    async fn start_rebalance(&self) -> Result<AdminCall<RebalanceStart>> {
        self.json(Method::POST, "/rustfs/admin/v3/rebalance/start", &[])
            .await
    }

    async fn rebalance_status(&self) -> Result<AdminCall<RebalanceStatus>> {
        self.json(Method::GET, "/rustfs/admin/v3/rebalance/status", &[])
            .await
    }

    async fn stop_rebalance(&self) -> Result<AdminCall<()>> {
        self.empty(Method::POST, "/rustfs/admin/v3/rebalance/stop", &[])
            .await
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantPoolProof {
    pub name: String,
    pub runtime_pool_id: usize,
    pub servers: u64,
    pub volumes_per_server: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminTopologyProof {
    pub scenario: String,
    pub tenant: String,
    pub tenant_uid: String,
    pub namespace: String,
    pub tenant_pools: Vec<TenantPoolProof>,
    pub runtime_pools: Vec<AdminPool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_pool_id: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_pool_expression: Option<String>,
    pub remaining_free_bytes: u64,
    pub target_used_bytes: u64,
    pub mutually_exclusive: bool,
    pub satisfied: bool,
}

impl AdminTopologyProof {
    pub fn build(
        plan: &AdminTopologyPlan,
        scenario: &str,
        tenant: &Value,
        runtime_pools: Vec<AdminPool>,
    ) -> Result<Self> {
        ensure!(
            AdminTopologyPlan::for_scenario(scenario)? == *plan,
            "admin topology plan does not match scenario {scenario}"
        );
        let tenant_name = required_string(tenant, "/metadata/name")?;
        let tenant_uid = required_string(tenant, "/metadata/uid")?;
        let namespace = required_string(tenant, "/metadata/namespace")?;
        let tenant_pools = tenant
            .pointer("/spec/pools")
            .and_then(Value::as_array)
            .context("Tenant spec.pools must be an array")?
            .iter()
            .enumerate()
            .map(|(runtime_pool_id, pool)| {
                Ok(TenantPoolProof {
                    name: required_field_string(pool, "name")?,
                    runtime_pool_id,
                    servers: required_field_u64(pool, "servers")?,
                    volumes_per_server: pool
                        .pointer("/persistence/volumesPerServer")
                        .and_then(Value::as_u64)
                        .context("Tenant pool persistence.volumesPerServer is required")?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        validate_runtime_pools(&tenant_pools, &runtime_pools)?;
        let mutually_exclusive = true;
        let (target_pool_expression, target_used_bytes, remaining_free_bytes) =
            topology_capacity(plan, &runtime_pools)?;
        let proof = Self {
            scenario: scenario.to_string(),
            tenant: tenant_name,
            tenant_uid,
            namespace,
            tenant_pools,
            runtime_pools,
            target_pool_id: plan.target_pool_id,
            target_pool_expression,
            remaining_free_bytes,
            target_used_bytes,
            mutually_exclusive,
            satisfied: true,
        };
        proof.require_satisfied()?;
        Ok(proof)
    }

    pub fn require_satisfied(&self) -> Result<()> {
        ensure!(
            self.satisfied && self.mutually_exclusive,
            "admin topology proof is not satisfied"
        );
        ensure!(
            !self.tenant.trim().is_empty()
                && !self.tenant_uid.trim().is_empty()
                && !self.namespace.trim().is_empty(),
            "admin topology proof lacks Tenant identity"
        );
        let plan = AdminTopologyPlan::for_scenario(&self.scenario)?;
        ensure!(
            self.target_pool_id == plan.target_pool_id,
            "admin topology proof target does not match its scenario"
        );
        if let Some(target_pool_id) = plan.target_pool_id {
            ensure!(
                self.tenant_pools.iter().any(|pool| {
                    pool.runtime_pool_id == target_pool_id
                        && pool.name == DECOMMISSION_TARGET_POOL_NAME
                }),
                "decommission target ID is not bound to the dedicated Tenant target pool"
            );
        }
        validate_runtime_pools(&self.tenant_pools, &self.runtime_pools)?;
        let (expression, target_used, remaining_free) =
            topology_capacity(&plan, &self.runtime_pools)?;
        ensure!(
            self.target_pool_expression == expression
                && self.target_used_bytes == target_used
                && self.remaining_free_bytes == remaining_free,
            "admin topology proof capacity or target facts do not match its runtime snapshot"
        );
        Ok(())
    }
}

fn validate_runtime_pools(
    tenant_pools: &[TenantPoolProof],
    runtime_pools: &[AdminPool],
) -> Result<()> {
    ensure!(
        tenant_pools.len() == 2,
        "admin topology cases require a fresh Tenant with exactly two pools"
    );
    let names = tenant_pools
        .iter()
        .map(|pool| pool.name.as_str())
        .collect::<BTreeSet<_>>();
    ensure!(
        names.len() == tenant_pools.len(),
        "Tenant pool names must be unique"
    );
    let tenant_runtime_ids = tenant_pools
        .iter()
        .map(|pool| pool.runtime_pool_id)
        .collect::<BTreeSet<_>>();
    ensure!(
        tenant_runtime_ids.len() == tenant_pools.len(),
        "Tenant pool runtime IDs must be unique"
    );
    ensure!(
        tenant_pools.iter().all(|pool| {
            !pool.name.trim().is_empty() && pool.servers > 0 && pool.volumes_per_server > 0
        }),
        "Tenant pools must have names and positive server/volume counts"
    );
    ensure!(
        tenant_pools.iter().all(|pool| {
            runtime_pools
                .iter()
                .any(|runtime| runtime.id == pool.runtime_pool_id)
        }),
        "Tenant pool order does not bind to the reported zero-based RustFS runtime pool IDs"
    );
    ensure!(
        runtime_pools.len() == tenant_pools.len(),
        "RustFS runtime pool count {} does not match Tenant pool count {}",
        runtime_pools.len(),
        tenant_pools.len()
    );
    let ids = runtime_pools
        .iter()
        .map(|pool| pool.id)
        .collect::<BTreeSet<_>>();
    ensure!(
        ids.len() == runtime_pools.len(),
        "RustFS runtime pool IDs must be unique"
    );
    ensure!(
        runtime_pools
            .iter()
            .all(|pool| !pool.expression.trim().is_empty()),
        "RustFS runtime pools must report exact non-empty command-line expressions"
    );
    ensure!(
        runtime_pools.iter().all(|pool| {
            pool.total_size > 0
                && pool.current_size <= pool.total_size
                && pool.used_size <= pool.total_size
                && pool.used.is_finite()
                && (0.0..=1.0).contains(&pool.used)
        }),
        "RustFS runtime pool capacity or used ratio is invalid"
    );
    ensure!(
        runtime_pools.iter().all(pool_is_idle),
        "a pool is unhealthy, another topology operation is active, or a failure is uncleared"
    );
    Ok(())
}

fn topology_capacity(
    plan: &AdminTopologyPlan,
    runtime_pools: &[AdminPool],
) -> Result<(Option<String>, u64, u64)> {
    if let Some(target_id) = plan.target_pool_id {
        ensure!(
            target_id != 0,
            "pool zero is reserved as the decommission destination"
        );
        let target = runtime_pools
            .iter()
            .find(|pool| pool.id == target_id)
            .with_context(|| format!("target pool ID {target_id} does not exist"))?;
        let remaining_free = runtime_pools
            .iter()
            .filter(|pool| pool.id != target_id)
            .try_fold(0_u64, |total, pool| total.checked_add(pool.current_size))
            .context("remaining pool free capacity overflowed")?;
        ensure!(
            remaining_free >= target.used_size,
            "remaining pools have {remaining_free} free bytes but target pool {target_id} uses {} bytes",
            target.used_size
        );
        Ok((
            Some(target.expression.clone()),
            target.used_size,
            remaining_free,
        ))
    } else {
        let remaining_free = runtime_pools
            .iter()
            .try_fold(0_u64, |total, pool| total.checked_add(pool.current_size))
            .context("pool free capacity overflowed")?;
        Ok((None, 0, remaining_free))
    }
}

fn pool_is_idle(pool: &AdminPool) -> bool {
    let pool_healthy = matches!(
        pool.status.to_ascii_lowercase().as_str(),
        "active" | "ready"
    );
    let lifecycle_idle = |value: &str| {
        matches!(
            value.to_ascii_lowercase().as_str(),
            "none" | "idle" | "complete" | "completed"
        )
    };
    pool_healthy
        && lifecycle_idle(&pool.decommission_status)
        && lifecycle_idle(&pool.rebalance_status)
        && pool.decommission.as_ref().is_none_or(|progress| {
            !progress.failed
                && !progress.canceled
                && !progress.queued
                && progress.start_time.is_none()
        })
}

fn required_string(value: &Value, pointer: &str) -> Result<String> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .with_context(|| format!("{pointer} must be a non-empty string"))
}

fn required_field_string(value: &Value, field: &str) -> Result<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .with_context(|| format!("Tenant pool {field} must be a non-empty string"))
}

fn required_field_u64(value: &Value, field: &str) -> Result<u64> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .filter(|value| *value > 0)
        .with_context(|| format!("Tenant pool {field} must be a positive integer"))
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminOperationEvidence {
    pub scenario: String,
    pub operation_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_pool_id: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_pool_expression: Option<String>,
    pub terminal_state: String,
    pub completed: bool,
    pub failed: bool,
    pub canceled_or_stopped: bool,
    pub requests: Vec<AdminRequestEvidence>,
    pub pools_before: Vec<AdminPool>,
    pub pools_after: Vec<AdminPool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminOperationProgressSample {
    pub operation_id: String,
    pub observed_at_ms: u64,
    pub state: String,
    pub completed: bool,
    pub failed: bool,
    pub canceled_or_stopped: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub objects_moved: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub versions_moved: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_moved: Option<u64>,
}

impl AdminOperationEvidence {
    pub fn from_decommission(
        proof: &AdminTopologyProof,
        status: DecommissionPoolStatus,
        requests: Vec<AdminRequestEvidence>,
        pools_after: Vec<AdminPool>,
    ) -> Result<Self> {
        proof.require_satisfied()?;
        let target_pool_id = proof
            .target_pool_id
            .context("decommission topology proof has no target pool ID")?;
        let target_pool_expression = proof
            .target_pool_expression
            .clone()
            .context("decommission topology proof has no target expression")?;
        ensure!(
            status.id == target_pool_id && status.expression == target_pool_expression,
            "decommission status does not match the proven target pool"
        );
        let progress = status
            .decommission
            .as_ref()
            .context("decommission status is missing operation progress")?;
        let start_time = progress
            .start_time
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .context("decommission status is missing operation start time")?;
        let state = status.status.to_ascii_lowercase();
        let completed = progress.complete
            && !progress.failed
            && !progress.canceled
            && progress.objects_decommissioned_failed == 0
            && progress.bytes_decommissioned_failed == 0;
        Ok(Self {
            scenario: ADMIN_DECOMMISSION_SCENARIO.to_string(),
            operation_id: format!("decommission:{target_pool_id}:{start_time}"),
            target_pool_id: Some(target_pool_id),
            target_pool_expression: Some(target_pool_expression),
            terminal_state: state.clone(),
            completed,
            failed: progress.failed || state == "failed",
            canceled_or_stopped: progress.canceled || state == "canceled",
            requests,
            pools_before: proof.runtime_pools.clone(),
            pools_after,
        })
    }

    pub fn from_rebalance(
        proof: &AdminTopologyProof,
        start: &RebalanceStart,
        status: RebalanceStatus,
        requests: Vec<AdminRequestEvidence>,
        pools_after: Vec<AdminPool>,
    ) -> Result<Self> {
        proof.require_satisfied()?;
        ensure!(
            !start.id.trim().is_empty() && status.id == start.id,
            "rebalance status operation ID does not match the start response"
        );
        ensure!(
            !status.pools.is_empty(),
            "rebalance status must report per-pool state"
        );
        let status_pool_ids = status
            .pools
            .iter()
            .map(|pool| pool.id)
            .collect::<BTreeSet<_>>();
        ensure!(
            status_pool_ids.len() == proof.runtime_pools.len()
                && proof
                    .runtime_pools
                    .iter()
                    .all(|pool| status_pool_ids.contains(&pool.id)),
            "rebalance status does not cover every proven runtime pool exactly once"
        );
        let stopped = status.stopped_at.is_some()
            || status
                .pools
                .iter()
                .any(|pool| pool.status.eq_ignore_ascii_case("stopped"));
        let failed = status.pools.iter().any(|pool| {
            pool.last_error
                .as_deref()
                .is_some_and(|error| !error.is_empty())
                || pool.cleanup_warnings.count > 0
                || pool
                    .cleanup_warnings
                    .last_message
                    .as_deref()
                    .is_some_and(|warning| !warning.is_empty())
                || pool.status.eq_ignore_ascii_case("failed")
        });
        let completed = !failed
            && !stopped
            && status.pools.iter().all(|pool| {
                matches!(
                    pool.status.to_ascii_lowercase().as_str(),
                    "complete" | "completed"
                )
            });
        let terminal_state = if failed {
            "failed"
        } else if stopped {
            "stopped"
        } else if completed {
            "completed"
        } else {
            "incomplete"
        };
        Ok(Self {
            scenario: ADMIN_REBALANCE_SCENARIO.to_string(),
            operation_id: start.id.clone(),
            target_pool_id: None,
            target_pool_expression: None,
            terminal_state: terminal_state.to_string(),
            completed,
            failed,
            canceled_or_stopped: stopped,
            requests,
            pools_before: proof.runtime_pools.clone(),
            pools_after,
        })
    }

    pub fn require_success(&self) -> Result<()> {
        ensure!(
            !self.operation_id.trim().is_empty(),
            "admin operation identity is missing"
        );
        ensure!(self.completed, "admin operation did not complete");
        ensure!(
            matches!(
                self.terminal_state.to_ascii_lowercase().as_str(),
                "complete" | "completed"
            ),
            "admin operation terminal state is not complete"
        );
        ensure!(!self.failed, "admin operation reached a failed state");
        ensure!(
            !self.canceled_or_stopped,
            "canceled/stopped admin operation cannot pass"
        );
        ensure!(
            self.requests
                .iter()
                .all(|request| (200..300).contains(&request.status)),
            "admin operation evidence contains a failed HTTP request"
        );
        if self.scenario == ADMIN_DECOMMISSION_SCENARIO {
            let target_id = self
                .target_pool_id
                .context("decommission target ID is missing")?;
            let expression = self
                .target_pool_expression
                .as_deref()
                .filter(|value| !value.is_empty())
                .context("decommission target expression is missing")?;
            let target_id_string = target_id.to_string();
            ensure!(
                self.requests.iter().any(|request| {
                    request.method == "POST"
                        && request.path == format!("{ADMIN_PREFIX}/pools/decommission")
                        && request.query.len() == 2
                        && request.query.get("pool") == Some(&target_id_string)
                        && request
                            .query
                            .get("by-id")
                            .is_some_and(|value| value == "true")
                }) && self.requests.iter().any(|request| {
                    request.method == "GET"
                        && request.path == format!("{ADMIN_PREFIX}/decommission/status")
                        && request.query.len() == 2
                        && request.query.get("pool") == Some(&target_id_string)
                        && request
                            .query
                            .get("by-id")
                            .is_some_and(|value| value == "true")
                }),
                "decommission evidence must contain exact start and status requests for the proven pool ID"
            );
            ensure!(
                self.pools_before
                    .iter()
                    .any(|pool| pool.id == target_id && pool.expression == expression),
                "decommission target was not present in the before topology"
            );
            ensure!(
                self.pools_after.iter().all(|pool| pool.id != target_id)
                    || self.pools_after.iter().any(|pool| {
                        pool.id == target_id
                            && pool.expression == expression
                            && matches!(
                                pool.status.to_ascii_lowercase().as_str(),
                                "decommissioned" | "complete" | "completed"
                            )
                    }),
                "decommission target remains active after the claimed completion"
            );
            ensure!(
                self.pools_after.iter().all(|after| {
                    self.pools_before.iter().any(|before| {
                        before.id == after.id && before.expression == after.expression
                    })
                }) && self
                    .pools_before
                    .iter()
                    .filter(|before| before.id != target_id)
                    .all(|before| {
                        self.pools_after.iter().any(|after| {
                            after.id == before.id && after.expression == before.expression
                        })
                    }),
                "decommission changed a non-target pool identity or introduced a new pool"
            );
        } else if self.scenario == ADMIN_REBALANCE_SCENARIO {
            ensure!(
                self.requests.iter().any(|request| {
                    request.method == "POST"
                        && request.path == format!("{ADMIN_PREFIX}/rebalance/start")
                        && request.query.is_empty()
                }) && self.requests.iter().any(|request| {
                    request.method == "GET"
                        && request.path == format!("{ADMIN_PREFIX}/rebalance/status")
                        && request.query.is_empty()
                }),
                "rebalance evidence must contain start and status requests"
            );
            ensure!(
                self.pools_before.len() == self.pools_after.len()
                    && self.pools_before.iter().all(|before| {
                        self.pools_after.iter().any(|after| {
                            after.id == before.id && after.expression == before.expression
                        })
                    }),
                "rebalance changed pool identity or topology scope"
            );
        } else {
            bail!("unsupported admin operation scenario {:?}", self.scenario);
        }
        Ok(())
    }
}

pub fn validate_admin_operation_progress(
    operation: &AdminOperationEvidence,
    samples: &[AdminOperationProgressSample],
) -> Result<()> {
    ensure!(!samples.is_empty(), "admin operation progress is empty");
    ensure!(
        samples
            .iter()
            .all(|sample| sample.operation_id == operation.operation_id),
        "admin operation progress contains a different operation ID"
    );
    ensure!(
        samples
            .iter()
            .all(|sample| sample.observed_at_ms > 0 && !sample.state.trim().is_empty()),
        "admin operation progress lacks observation time or state"
    );
    ensure!(
        samples.windows(2).all(|pair| {
            pair[0].observed_at_ms <= pair[1].observed_at_ms
                && optional_counter_nondecreasing(pair[0].objects_moved, pair[1].objects_moved)
                && optional_counter_nondecreasing(pair[0].versions_moved, pair[1].versions_moved)
                && optional_counter_nondecreasing(pair[0].bytes_moved, pair[1].bytes_moved)
        }),
        "admin operation progress timestamps or counters are not monotonic"
    );
    ensure!(
        samples
            .iter()
            .all(|sample| !sample.failed && !sample.canceled_or_stopped),
        "failed/canceled/stopped admin progress cannot pass"
    );
    let terminal = samples.last().expect("non-empty checked above");
    ensure!(
        terminal.completed
            && terminal
                .state
                .eq_ignore_ascii_case(&operation.terminal_state),
        "admin operation progress does not end in the claimed terminal state"
    );
    Ok(())
}

fn optional_counter_nondecreasing(before: Option<u64>, after: Option<u64>) -> bool {
    match (before, after) {
        (Some(before), Some(after)) => before <= after,
        (None, Some(_)) | (None, None) => true,
        (Some(_), None) => false,
    }
}

pub fn validate_admin_topology_artifacts(
    scenario: &str,
    proof: &AdminTopologyProof,
    operation: &AdminOperationEvidence,
) -> Result<()> {
    let _ = AdminTopologyPlan::for_scenario(scenario)?;
    ensure!(
        proof.scenario == scenario,
        "admin topology proof scenario mismatch"
    );
    ensure!(
        operation.scenario == scenario,
        "admin operation evidence scenario mismatch"
    );
    proof.require_satisfied()?;
    operation.require_success()?;
    ensure!(
        operation.pools_before == proof.runtime_pools,
        "admin operation before topology does not match the preflight proof"
    );
    if scenario == ADMIN_DECOMMISSION_SCENARIO {
        ensure!(
            operation.target_pool_id == proof.target_pool_id,
            "decommission target ID drifted after preflight"
        );
        ensure!(
            operation.target_pool_expression == proof.target_pool_expression,
            "decommission target expression drifted after preflight"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tenant() -> Value {
        serde_json::json!({
            "metadata": {"name": "fault-tenant", "uid": "tenant-uid", "namespace": "fault-ns"},
            "spec": {"pools": [
                {"name": "primary", "servers": 4, "persistence": {"volumesPerServer": 1}},
                {"name": "decommission-target", "servers": 4, "persistence": {"volumesPerServer": 1}}
            ]}
        })
    }

    fn pools() -> Vec<AdminPool> {
        vec![
            AdminPool {
                id: 0,
                expression: "/data/pool0/disk{1...4}".to_string(),
                status: "active".to_string(),
                decommission_status: "none".to_string(),
                rebalance_status: "none".to_string(),
                total_size: 2_000,
                current_size: 1_500,
                used_size: 500,
                used: 0.25,
                decommission: None,
            },
            AdminPool {
                id: 1,
                expression: "/data/pool1/disk{1...4}".to_string(),
                status: "active".to_string(),
                decommission_status: "none".to_string(),
                rebalance_status: "none".to_string(),
                total_size: 1_000,
                current_size: 800,
                used_size: 200,
                used: 0.2,
                decommission: None,
            },
        ]
    }

    #[test]
    fn decommission_preflight_binds_exact_pool_and_capacity() {
        let plan = AdminTopologyPlan::for_scenario(ADMIN_DECOMMISSION_SCENARIO).unwrap();
        let proof =
            AdminTopologyProof::build(&plan, ADMIN_DECOMMISSION_SCENARIO, &tenant(), pools())
                .expect("proof");
        assert_eq!(proof.target_pool_id, Some(1));
        assert_eq!(
            proof.target_pool_expression.as_deref(),
            Some("/data/pool1/disk{1...4}")
        );
        assert_eq!(proof.remaining_free_bytes, 1_500);
        assert_eq!(proof.target_used_bytes, 200);
    }

    #[test]
    fn preflight_rejects_single_pool_capacity_and_active_operation() {
        let plan = AdminTopologyPlan::for_scenario(ADMIN_DECOMMISSION_SCENARIO).unwrap();
        let mut single = tenant();
        single["spec"]["pools"].as_array_mut().unwrap().truncate(1);
        assert!(
            AdminTopologyProof::build(
                &plan,
                ADMIN_DECOMMISSION_SCENARIO,
                &single,
                vec![pools()[0].clone()]
            )
            .is_err()
        );

        let mut insufficient = pools();
        insufficient[0].current_size = 100;
        assert!(
            AdminTopologyProof::build(&plan, ADMIN_DECOMMISSION_SCENARIO, &tenant(), insufficient)
                .is_err()
        );

        let mut active = pools();
        active[0].rebalance_status = "Started".to_string();
        assert!(
            AdminTopologyProof::build(&plan, ADMIN_DECOMMISSION_SCENARIO, &tenant(), active)
                .is_err()
        );
    }

    #[test]
    fn artifact_validation_rejects_cancel_and_target_drift() {
        let plan = AdminTopologyPlan::for_scenario(ADMIN_DECOMMISSION_SCENARIO).unwrap();
        let proof =
            AdminTopologyProof::build(&plan, ADMIN_DECOMMISSION_SCENARIO, &tenant(), pools())
                .unwrap();
        let mut operation = AdminOperationEvidence {
            scenario: ADMIN_DECOMMISSION_SCENARIO.to_string(),
            operation_id: "decommission:1:2026-09-05T00:00:00Z".to_string(),
            target_pool_id: Some(1),
            target_pool_expression: proof.target_pool_expression.clone(),
            terminal_state: "complete".to_string(),
            completed: true,
            failed: false,
            canceled_or_stopped: false,
            requests: vec![
                AdminRequestEvidence {
                    method: "POST".to_string(),
                    path: format!("{ADMIN_PREFIX}/pools/decommission"),
                    query: BTreeMap::from([
                        ("by-id".to_string(), "true".to_string()),
                        ("pool".to_string(), "1".to_string()),
                    ]),
                    status: 200,
                    request_id: None,
                },
                AdminRequestEvidence {
                    method: "GET".to_string(),
                    path: format!("{ADMIN_PREFIX}/decommission/status"),
                    query: BTreeMap::from([
                        ("by-id".to_string(), "true".to_string()),
                        ("pool".to_string(), "1".to_string()),
                    ]),
                    status: 200,
                    request_id: None,
                },
            ],
            pools_before: proof.runtime_pools.clone(),
            pools_after: vec![proof.runtime_pools[0].clone()],
        };
        validate_admin_topology_artifacts(ADMIN_DECOMMISSION_SCENARIO, &proof, &operation).unwrap();
        operation.requests[0]
            .query
            .insert("pool".to_string(), "0".to_string());
        assert!(
            validate_admin_topology_artifacts(ADMIN_DECOMMISSION_SCENARIO, &proof, &operation)
                .is_err()
        );
        operation.requests[0]
            .query
            .insert("pool".to_string(), "1".to_string());
        operation.canceled_or_stopped = true;
        assert!(
            validate_admin_topology_artifacts(ADMIN_DECOMMISSION_SCENARIO, &proof, &operation)
                .is_err()
        );
        operation.canceled_or_stopped = false;
        operation.target_pool_expression = Some("/wrong".to_string());
        assert!(
            validate_admin_topology_artifacts(ADMIN_DECOMMISSION_SCENARIO, &proof, &operation)
                .is_err()
        );
    }

    #[test]
    fn progress_requires_one_operation_and_successful_terminal_sample() {
        let operation = AdminOperationEvidence {
            scenario: ADMIN_REBALANCE_SCENARIO.to_string(),
            operation_id: "rebalance-123".to_string(),
            target_pool_id: None,
            target_pool_expression: None,
            terminal_state: "completed".to_string(),
            completed: true,
            failed: false,
            canceled_or_stopped: false,
            requests: Vec::new(),
            pools_before: Vec::new(),
            pools_after: Vec::new(),
        };
        let mut samples = vec![
            AdminOperationProgressSample {
                operation_id: operation.operation_id.clone(),
                observed_at_ms: 1,
                state: "started".to_string(),
                completed: false,
                failed: false,
                canceled_or_stopped: false,
                objects_moved: Some(1),
                versions_moved: Some(1),
                bytes_moved: Some(10),
            },
            AdminOperationProgressSample {
                operation_id: operation.operation_id.clone(),
                observed_at_ms: 2,
                state: "completed".to_string(),
                completed: true,
                failed: false,
                canceled_or_stopped: false,
                objects_moved: Some(2),
                versions_moved: Some(2),
                bytes_moved: Some(20),
            },
        ];

        validate_admin_operation_progress(&operation, &samples).expect("terminal progress");
        samples[0].operation_id = "different".to_string();
        assert!(validate_admin_operation_progress(&operation, &samples).is_err());
        samples[0].operation_id.clone_from(&operation.operation_id);
        samples[1].canceled_or_stopped = true;
        assert!(validate_admin_operation_progress(&operation, &samples).is_err());
    }

    #[test]
    fn rebalance_requires_stable_pool_identity() {
        let plan = AdminTopologyPlan::for_scenario(ADMIN_REBALANCE_SCENARIO).unwrap();
        let proof =
            AdminTopologyProof::build(&plan, ADMIN_REBALANCE_SCENARIO, &tenant(), pools()).unwrap();
        let mut operation = AdminOperationEvidence {
            scenario: ADMIN_REBALANCE_SCENARIO.to_string(),
            operation_id: "rebalance-123".to_string(),
            target_pool_id: None,
            target_pool_expression: None,
            terminal_state: "completed".to_string(),
            completed: true,
            failed: false,
            canceled_or_stopped: false,
            requests: vec![
                AdminRequestEvidence {
                    method: "POST".to_string(),
                    path: format!("{ADMIN_PREFIX}/rebalance/start"),
                    query: BTreeMap::new(),
                    status: 200,
                    request_id: None,
                },
                AdminRequestEvidence {
                    method: "GET".to_string(),
                    path: format!("{ADMIN_PREFIX}/rebalance/status"),
                    query: BTreeMap::new(),
                    status: 200,
                    request_id: None,
                },
            ],
            pools_before: proof.runtime_pools.clone(),
            pools_after: proof.runtime_pools.clone(),
        };
        validate_admin_topology_artifacts(ADMIN_REBALANCE_SCENARIO, &proof, &operation).unwrap();
        operation.pools_after[1].expression = "/different".to_string();
        assert!(
            validate_admin_topology_artifacts(ADMIN_REBALANCE_SCENARIO, &proof, &operation)
                .is_err()
        );
    }

    #[test]
    fn typed_status_models_match_rustfs_admin_wire_format() {
        let decommission: DecommissionPoolStatus = serde_json::from_str(
            r#"{"id":1,"cmdline":"/data/pool1/disk{1...4}","status":"running","poolStatus":"decommissioning","decommissionInfo":{"startTime":"2026-09-05T00:00:00Z","complete":false,"objectsDecommissioned":3}}"#,
        ).unwrap();
        assert_eq!(decommission.id, 1);
        assert_eq!(decommission.decommission.unwrap().objects_decommissioned, 3);

        let rebalance: RebalanceStatus = serde_json::from_str(
            r#"{"id":"rebalance-1","pools":[{"id":0,"status":"Completed","cleanupWarnings":{"count":0},"progress":{"objects":2,"versions":3,"bytes":128,"remainingBuckets":0}}]}"#,
        ).unwrap();
        assert_eq!(rebalance.id, "rebalance-1");
        assert_eq!(rebalance.pools[0].progress.as_ref().unwrap().versions, 3);
    }

    #[test]
    fn decommission_terminal_builder_rejects_failed_moves() {
        let plan = AdminTopologyPlan::for_scenario(ADMIN_DECOMMISSION_SCENARIO).unwrap();
        let proof =
            AdminTopologyProof::build(&plan, ADMIN_DECOMMISSION_SCENARIO, &tenant(), pools())
                .unwrap();
        let status = DecommissionPoolStatus {
            id: 1,
            expression: "/data/pool1/disk{1...4}".to_string(),
            status: "complete".to_string(),
            pool_status: "decommissioned".to_string(),
            decommission: Some(DecommissionProgress {
                start_time: Some("2026-09-05T00:00:00Z".to_string()),
                complete: true,
                objects_decommissioned_failed: 1,
                ..Default::default()
            }),
        };
        let evidence = AdminOperationEvidence::from_decommission(
            &proof,
            status,
            vec![],
            vec![proof.runtime_pools[0].clone()],
        )
        .unwrap();
        assert!(!evidence.completed);
        assert!(evidence.require_success().is_err());
    }

    #[test]
    fn rebalance_terminal_builder_fails_closed_on_cleanup_warning() {
        let plan = AdminTopologyPlan::for_scenario(ADMIN_REBALANCE_SCENARIO).unwrap();
        let proof =
            AdminTopologyProof::build(&plan, ADMIN_REBALANCE_SCENARIO, &tenant(), pools()).unwrap();
        let start = RebalanceStart {
            id: "rebalance-1".to_string(),
        };
        let status = RebalanceStatus {
            id: start.id.clone(),
            pools: vec![
                RebalancePoolStatus {
                    id: 0,
                    status: "Completed".to_string(),
                    last_error: None,
                    cleanup_warnings: RebalanceCleanupWarnings {
                        count: 1,
                        last_message: Some("cleanup failed".to_string()),
                    },
                    progress: None,
                },
                RebalancePoolStatus {
                    id: 1,
                    status: "Completed".to_string(),
                    last_error: None,
                    cleanup_warnings: RebalanceCleanupWarnings::default(),
                    progress: None,
                },
            ],
            stopped_at: None,
        };
        let evidence = AdminOperationEvidence::from_rebalance(
            &proof,
            &start,
            status,
            vec![],
            proof.runtime_pools.clone(),
        )
        .unwrap();
        assert!(evidence.failed);
        assert!(evidence.require_success().is_err());
    }
}
