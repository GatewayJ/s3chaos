// Copyright 2025 RustFS Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::time::Duration;

use anyhow::{Context, Result, ensure};
use k8s_openapi::api::{
    authorization::v1::{ResourceAttributes, SelfSubjectAccessReview, SelfSubjectAccessReviewSpec},
    core::v1::{Namespace, Pod},
};
use kube::{
    Api, Client, Error as KubeError, ResourceExt,
    api::{DeleteParams, ListParams, PostParams, Preconditions, PropagationPolicy},
};
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::{process::Command, time::timeout};
use uuid::Uuid;

use super::API_VERSION;
use crate::{
    framework::kube_client::client_for_context,
    protocol::{
        clients::admin::RustfsAdminClient,
        credentials::{CredentialProvider, EnvCredentialProvider},
        suite_plan::TargetFingerprint,
    },
};

const TARGET_KIND: &str = "MintEphemeralTarget";
const MANAGED_BY_LABEL: &str = "app.kubernetes.io/managed-by";
const TARGET_MANAGER: &str = "s3chaos-mint";
const RUN_ID_LABEL: &str = "rustfs.com/mint-run-id";
const EXPIRES_AT_ANNOTATION: &str = "rustfs.com/mint-expires-at";
const MAX_LEASE_SECONDS: i64 = 24 * 60 * 60;
const MAX_DIAGNOSTIC_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MintTargetTimeouts {
    pub operation_seconds: u64,
    pub mint_seconds: u64,
    pub teardown_seconds: u64,
}

impl Default for MintTargetTimeouts {
    fn default() -> Self {
        Self {
            operation_seconds: 30,
            mint_seconds: 3_600,
            teardown_seconds: 300,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MintTargetSpec {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub run_id: String,
    pub context: String,
    pub namespace: String,
    pub namespace_uid: String,
    pub created_at: String,
    pub expires_at: String,
    pub server_endpoint: String,
    pub enable_https: bool,
    pub region: String,
    pub target_fingerprint: String,
    pub rustfs_image_digest: String,
    pub rustfs_container: String,
    #[serde(default)]
    pub timeouts: MintTargetTimeouts,
}

impl MintTargetSpec {
    pub fn from_yaml(raw: &str, now: &str) -> Result<Self> {
        let spec: Self =
            serde_yaml_ng::from_str(raw).context("parse Mint ephemeral target spec")?;
        spec.validate_at(now)?;
        Ok(spec)
    }

    pub fn validate_at(&self, now: &str) -> Result<()> {
        self.validate_contract()?;
        let created_at = parse_timestamp(&self.created_at, "Mint target createdAt")?;
        let expires_at = parse_timestamp(&self.expires_at, "Mint target expiresAt")?;
        let now = parse_timestamp(now, "current time")?;
        ensure!(created_at <= now, "Mint target lease is not active yet");
        ensure!(now < expires_at, "Mint target lease has expired");
        Ok(())
    }

    pub fn validate_contract(&self) -> Result<()> {
        ensure!(
            self.api_version == API_VERSION && self.kind == TARGET_KIND,
            "invalid Mint ephemeral target contract"
        );
        validate_dns_label("Mint run id", &self.run_id)?;
        validate_dns_label("Mint namespace", &self.namespace)?;
        ensure_nonempty("Mint Kubernetes context", &self.context)?;
        ensure!(
            !self.context.contains(['\n', '\r', '\0']),
            "Mint Kubernetes context contains unsafe characters"
        );
        Uuid::parse_str(&self.namespace_uid)
            .context("Mint namespaceUid must be a Kubernetes UUID")?;
        ensure_nonempty("Mint server endpoint", &self.server_endpoint)?;
        ensure!(
            !self.server_endpoint.contains(['@', '\n', '\r', '\0'])
                && !self.server_endpoint.chars().any(char::is_whitespace),
            "Mint server endpoint contains credentials or unsafe characters"
        );
        let endpoint = mint_admin_endpoint(&self.server_endpoint, self.enable_https)?;
        let endpoint = reqwest::Url::parse(&endpoint).context("parse Mint server endpoint")?;
        ensure!(
            endpoint.username().is_empty()
                && endpoint.password().is_none()
                && endpoint.host_str().is_some()
                && endpoint.path() == "/"
                && endpoint.query().is_none()
                && endpoint.fragment().is_none(),
            "Mint server endpoint must contain only an HTTP(S) authority"
        );
        ensure_nonempty("Mint region", &self.region)?;
        validate_raw_sha256("Mint target fingerprint", &self.target_fingerprint)?;
        validate_prefixed_sha256("RustFS image digest", &self.rustfs_image_digest)?;
        validate_dns_label("RustFS container name", &self.rustfs_container)?;
        validate_timeouts(self.timeouts)?;

        let created_at = parse_timestamp(&self.created_at, "Mint target createdAt")?;
        let expires_at = parse_timestamp(&self.expires_at, "Mint target expiresAt")?;
        ensure!(
            created_at < expires_at,
            "Mint target lease must have positive duration"
        );
        ensure!(
            (expires_at - created_at).whole_seconds() <= MAX_LEASE_SECONDS,
            "Mint target lease must not exceed 24 hours"
        );
        Ok(())
    }

    pub fn container_name(&self) -> String {
        let uid_prefix = self.namespace_uid.get(..8).unwrap_or(&self.namespace_uid);
        format!("s3chaos-mint-{}-{uid_prefix}", self.run_id)
    }

    fn run_selector(&self) -> String {
        format!("{RUN_ID_LABEL}={}", self.run_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MintNamespaceProof {
    pub context: String,
    pub namespace: String,
    pub namespace_uid: String,
    pub run_id: String,
    pub expires_at: String,
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MintPodProof {
    pub name: String,
    pub uid: String,
    pub node_name: String,
    pub image_id: String,
    pub ready: bool,
    pub restart_count: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MintTargetProof {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub namespace: MintNamespaceProof,
    pub namespace_pod_count: usize,
    pub rustfs_pods: Vec<MintPodProof>,
    pub rustfs_image_digest: String,
    pub delete_allowed: bool,
    pub server: TargetFingerprint,
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintTargetDiagnostic {
    pub file_name: String,
    pub contents: Vec<u8>,
    pub succeeded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MintTargetTeardownProof {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub context: String,
    pub namespace: String,
    pub namespace_uid: String,
    pub requested_at: String,
    pub verified_absent_at: String,
    pub namespace_absent: bool,
}

pub async fn prove_mint_namespace(spec: &MintTargetSpec, now: &str) -> Result<MintNamespaceProof> {
    spec.validate_at(now)?;
    let client = client_for_context(&spec.context)
        .await
        .with_context(|| format!("connect to Kubernetes context {:?}", spec.context))?;
    let namespaces: Api<Namespace> = Api::all(client);
    let namespace = timeout(
        Duration::from_secs(spec.timeouts.operation_seconds),
        namespaces.get(&spec.namespace),
    )
    .await
    .context("time out reading Mint namespace ownership")??;
    validate_namespace_ownership(spec, &namespace, now)
}

pub async fn verify_mint_target_ready(
    spec: &MintTargetSpec,
    namespace_proof: &MintNamespaceProof,
    now: &str,
) -> Result<MintTargetProof> {
    validate_namespace_proof(spec, namespace_proof)?;
    spec.validate_at(now)?;
    let client = client_for_context(&spec.context)
        .await
        .with_context(|| format!("connect to Kubernetes context {:?}", spec.context))?;
    let pods_api: Api<Pod> = Api::namespaced(client.clone(), &spec.namespace);
    let pods = timeout(
        Duration::from_secs(spec.timeouts.operation_seconds),
        pods_api.list(&ListParams::default()),
    )
    .await
    .context("time out reading Mint namespace pods")??;
    let rustfs_pods = validate_target_pods(spec, &pods.items)?;
    ensure_namespace_delete_allowed(client, spec).await?;
    let server = inspect_mint_target(
        &spec.server_endpoint,
        spec.enable_https,
        &spec.region,
        &spec.target_fingerprint,
    )
    .await?;

    Ok(MintTargetProof {
        api_version: API_VERSION.to_string(),
        kind: "MintTargetProof".to_string(),
        namespace: namespace_proof.clone(),
        namespace_pod_count: pods.items.len(),
        rustfs_pods,
        rustfs_image_digest: spec.rustfs_image_digest.clone(),
        delete_allowed: true,
        server,
        verified_at: now.to_string(),
    })
}

pub async fn collect_mint_target_diagnostics(spec: &MintTargetSpec) -> Vec<MintTargetDiagnostic> {
    let selector = spec.run_selector();
    let commands = [
        ("resources.txt", vec!["get", "all,pvc", "-o", "wide"], true),
        (
            "events.txt",
            vec!["get", "events", "--sort-by=.lastTimestamp"],
            true,
        ),
        (
            "rustfs-pods.txt",
            vec!["get", "pods", "-l", &selector, "-o", "wide"],
            true,
        ),
        (
            "rustfs-current.log",
            vec![
                "logs",
                "-l",
                &selector,
                "-c",
                &spec.rustfs_container,
                "--tail=500",
                "--prefix",
            ],
            true,
        ),
        (
            "rustfs-previous.log",
            vec![
                "logs",
                "-l",
                &selector,
                "-c",
                &spec.rustfs_container,
                "--previous",
                "--tail=500",
                "--prefix",
            ],
            false,
        ),
    ];

    let mut diagnostics = Vec::with_capacity(commands.len());
    for (file_name, args, required) in commands {
        let (contents, succeeded) =
            run_bounded_kubectl(spec, &args)
                .await
                .unwrap_or_else(|error| {
                    (
                        format!("diagnostic collection failed: {error}\n").into_bytes(),
                        false,
                    )
                });
        diagnostics.push(MintTargetDiagnostic {
            file_name: file_name.to_string(),
            contents,
            succeeded: succeeded || !required,
        });
    }
    diagnostics
}

pub async fn teardown_mint_target(
    spec: &MintTargetSpec,
    namespace_proof: &MintNamespaceProof,
    requested_at: &str,
) -> Result<MintTargetTeardownProof> {
    validate_namespace_proof(spec, namespace_proof)?;
    parse_timestamp(requested_at, "Mint teardown requestedAt")?;
    let client = client_for_context(&spec.context)
        .await
        .with_context(|| format!("connect to Kubernetes context {:?}", spec.context))?;
    let namespaces: Api<Namespace> = Api::all(client);

    let current = timeout(
        Duration::from_secs(spec.timeouts.operation_seconds),
        namespaces.get_opt(&spec.namespace),
    )
    .await
    .context("time out rechecking Mint namespace before teardown")??;
    if let Some(namespace) = current {
        validate_namespace_identity(spec, &namespace)?;
        let delete_params = DeleteParams {
            grace_period_seconds: Some(0),
            propagation_policy: Some(PropagationPolicy::Foreground),
            preconditions: Some(Preconditions {
                uid: Some(namespace_proof.namespace_uid.clone()),
                resource_version: None,
            }),
            ..DeleteParams::default()
        };
        let deletion = timeout(
            Duration::from_secs(spec.timeouts.operation_seconds),
            namespaces.delete(&spec.namespace, &delete_params),
        )
        .await
        .context("time out requesting Mint namespace deletion")?;
        if let Err(error) = deletion {
            ensure!(
                kube_error_is_not_found(&error),
                "delete exact Mint namespace: {error}"
            );
        }
    }

    timeout(Duration::from_secs(spec.timeouts.teardown_seconds), async {
        loop {
            match namespaces.get_opt(&spec.namespace).await {
                Ok(None) => return Ok::<(), anyhow::Error>(()),
                Ok(Some(namespace)) => {
                    validate_namespace_identity(spec, &namespace)?;
                }
                Err(error) if kube_error_is_not_found(&error) => return Ok(()),
                Err(error) => return Err(error.into()),
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    })
    .await
    .context("time out waiting for Mint namespace to become absent")??;

    Ok(MintTargetTeardownProof {
        api_version: API_VERSION.to_string(),
        kind: "MintTargetTeardownProof".to_string(),
        context: spec.context.clone(),
        namespace: spec.namespace.clone(),
        namespace_uid: namespace_proof.namespace_uid.clone(),
        requested_at: requested_at.to_string(),
        verified_absent_at: timestamp_now()?,
        namespace_absent: true,
    })
}

pub async fn inspect_mint_target(
    server_endpoint: &str,
    enable_https: bool,
    region: &str,
    expected_fingerprint: &str,
) -> Result<TargetFingerprint> {
    let endpoint = mint_admin_endpoint(server_endpoint, enable_https)?;
    let credentials = EnvCredentialProvider.resolve("root")?;
    let server_info = RustfsAdminClient::new(&endpoint, region, credentials)?
        .server_info()
        .await
        .context("query the live RustFS target identity for Mint")?;
    let observed = TargetFingerprint::new(
        endpoint,
        region,
        server_info.deployment_id,
        server_info.mode,
        server_info.region,
    )?;
    ensure!(
        observed.sha256 == expected_fingerprint,
        "refuse Mint because the dedicated target fingerprint changed: expected {expected_fingerprint}, observed {}",
        observed.sha256
    );
    Ok(observed)
}

pub async fn verify_mint_target(
    server_endpoint: &str,
    enable_https: bool,
    region: &str,
    expected_fingerprint: &str,
) -> Result<String> {
    let observed =
        inspect_mint_target(server_endpoint, enable_https, region, expected_fingerprint).await?;
    Ok(format!("sha256:{}", observed.sha256))
}

fn validate_namespace_ownership(
    spec: &MintTargetSpec,
    namespace: &Namespace,
    now: &str,
) -> Result<MintNamespaceProof> {
    spec.validate_at(now)?;
    validate_namespace_ownership_without_lease_time(spec, namespace)?;
    Ok(MintNamespaceProof {
        context: spec.context.clone(),
        namespace: spec.namespace.clone(),
        namespace_uid: spec.namespace_uid.clone(),
        run_id: spec.run_id.clone(),
        expires_at: spec.expires_at.clone(),
        verified_at: now.to_string(),
    })
}

fn validate_namespace_ownership_without_lease_time(
    spec: &MintTargetSpec,
    namespace: &Namespace,
) -> Result<()> {
    validate_namespace_identity(spec, namespace)?;
    ensure!(
        namespace.metadata.deletion_timestamp.is_none(),
        "refuse Mint target operation because namespace deletion is already in progress"
    );
    Ok(())
}

fn validate_namespace_identity(spec: &MintTargetSpec, namespace: &Namespace) -> Result<()> {
    let uid = namespace.metadata.uid.as_deref();
    let manager = namespace
        .metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get(MANAGED_BY_LABEL))
        .map(String::as_str);
    let run_id = namespace
        .metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get(RUN_ID_LABEL))
        .map(String::as_str);
    let expires_at = namespace
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(EXPIRES_AT_ANNOTATION))
        .map(String::as_str);
    ensure!(
        namespace.name_any() == spec.namespace
            && uid == Some(spec.namespace_uid.as_str())
            && manager == Some(TARGET_MANAGER)
            && run_id == Some(spec.run_id.as_str())
            && expires_at == Some(spec.expires_at.as_str()),
        "refuse Mint target operation because namespace identity or ownership does not match the exact target spec"
    );
    Ok(())
}

fn validate_namespace_proof(spec: &MintTargetSpec, proof: &MintNamespaceProof) -> Result<()> {
    ensure!(
        proof.context == spec.context
            && proof.namespace == spec.namespace
            && proof.namespace_uid == spec.namespace_uid
            && proof.run_id == spec.run_id
            && proof.expires_at == spec.expires_at,
        "Mint namespace proof does not match the exact target spec"
    );
    Ok(())
}

fn validate_target_pods(spec: &MintTargetSpec, pods: &[Pod]) -> Result<Vec<MintPodProof>> {
    ensure!(!pods.is_empty(), "Mint target namespace has no pods");
    let mut rustfs_pods = Vec::new();
    for pod in pods {
        let pod_run_id = pod
            .metadata
            .labels
            .as_ref()
            .and_then(|labels| labels.get(RUN_ID_LABEL))
            .map(String::as_str);
        ensure!(
            pod_run_id == Some(spec.run_id.as_str()),
            "Mint target namespace contains a pod outside run ownership: {}",
            pod.name_any()
        );
        let Some(status) = &pod.status else {
            continue;
        };
        let Some(container_status) = status.container_statuses.as_ref().and_then(|statuses| {
            statuses
                .iter()
                .find(|status| status.name == spec.rustfs_container)
        }) else {
            continue;
        };
        let ready_condition = status.conditions.as_ref().is_some_and(|conditions| {
            conditions
                .iter()
                .any(|condition| condition.type_ == "Ready" && condition.status == "True")
        });
        let image_digest = container_status
            .image_id
            .rsplit_once('@')
            .map(|(_, digest)| digest)
            .unwrap_or(container_status.image_id.as_str());
        ensure!(
            image_digest == spec.rustfs_image_digest,
            "RustFS pod {} runs imageID {:?}, expected digest {}",
            pod.name_any(),
            container_status.image_id,
            spec.rustfs_image_digest
        );
        ensure!(
            container_status.ready && ready_condition,
            "RustFS pod {} is not Ready",
            pod.name_any()
        );
        rustfs_pods.push(MintPodProof {
            name: pod.name_any(),
            uid: pod.metadata.uid.clone().unwrap_or_default(),
            node_name: pod
                .spec
                .as_ref()
                .and_then(|spec| spec.node_name.clone())
                .unwrap_or_default(),
            image_id: container_status.image_id.clone(),
            ready: true,
            restart_count: container_status.restart_count,
        });
    }
    ensure!(
        !rustfs_pods.is_empty(),
        "Mint target namespace has no Ready RustFS containers named {:?}",
        spec.rustfs_container
    );
    rustfs_pods.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(rustfs_pods)
}

async fn ensure_namespace_delete_allowed(client: Client, spec: &MintTargetSpec) -> Result<()> {
    let reviews: Api<SelfSubjectAccessReview> = Api::all(client);
    let review = SelfSubjectAccessReview {
        spec: SelfSubjectAccessReviewSpec {
            resource_attributes: Some(ResourceAttributes {
                group: Some(String::new()),
                resource: Some("namespaces".to_string()),
                version: Some("v1".to_string()),
                verb: Some("delete".to_string()),
                name: Some(spec.namespace.clone()),
                ..ResourceAttributes::default()
            }),
            ..SelfSubjectAccessReviewSpec::default()
        },
        ..SelfSubjectAccessReview::default()
    };
    let response = timeout(
        Duration::from_secs(spec.timeouts.operation_seconds),
        reviews.create(&PostParams::default(), &review),
    )
    .await
    .context("time out checking Mint namespace delete permission")??;
    let status = response
        .status
        .context("Kubernetes returned no namespace delete authorization status")?;
    ensure!(
        status.allowed,
        "Kubernetes identity cannot delete the exact Mint namespace"
    );
    Ok(())
}

async fn run_bounded_kubectl(spec: &MintTargetSpec, args: &[&str]) -> Result<(Vec<u8>, bool)> {
    let mut command = Command::new("kubectl");
    command
        .kill_on_drop(true)
        .arg("--context")
        .arg(&spec.context)
        .arg("-n")
        .arg(&spec.namespace)
        .args(args);
    let output = timeout(
        Duration::from_secs(spec.timeouts.operation_seconds),
        command.output(),
    )
    .await
    .with_context(|| format!("time out collecting kubectl diagnostic {args:?}"))??;
    let mut contents = format!("exit: {:?}\n\nstdout:\n", output.status.code()).into_bytes();
    contents.extend_from_slice(&output.stdout);
    contents.extend_from_slice(b"\n\nstderr:\n");
    contents.extend_from_slice(&output.stderr);
    ensure!(
        contents.len() <= MAX_DIAGNOSTIC_BYTES,
        "kubectl diagnostic {args:?} exceeds the {MAX_DIAGNOSTIC_BYTES} byte limit"
    );
    Ok((contents, output.status.success()))
}

fn mint_admin_endpoint(server_endpoint: &str, enable_https: bool) -> Result<String> {
    ensure!(
        !server_endpoint.trim().is_empty(),
        "Mint server endpoint must not be empty"
    );
    let scheme = if enable_https { "https" } else { "http" };
    if server_endpoint.contains("://") {
        let expected_prefix = format!("{scheme}://");
        ensure!(
            server_endpoint.starts_with(&expected_prefix),
            "Mint endpoint scheme disagrees with target enableHttps"
        );
        Ok(server_endpoint.to_string())
    } else {
        Ok(format!("{scheme}://{server_endpoint}"))
    }
}

fn validate_timeouts(timeouts: MintTargetTimeouts) -> Result<()> {
    ensure!(
        (5..=300).contains(&timeouts.operation_seconds),
        "Mint target operationSeconds must be between 5 and 300"
    );
    ensure!(
        (60..=14_400).contains(&timeouts.mint_seconds),
        "Mint target mintSeconds must be between 60 and 14400"
    );
    ensure!(
        (30..=1_800).contains(&timeouts.teardown_seconds),
        "Mint target teardownSeconds must be between 30 and 1800"
    );
    Ok(())
}

fn validate_dns_label(label: &str, value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 63
            && value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && value
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && value
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric),
        "{label} must be a lowercase DNS label"
    );
    Ok(())
}

fn validate_raw_sha256(label: &str, value: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{label} must be exactly 64 lowercase hexadecimal characters"
    );
    Ok(())
}

fn validate_prefixed_sha256(label: &str, value: &str) -> Result<()> {
    let digest = value
        .strip_prefix("sha256:")
        .with_context(|| format!("{label} must start with sha256:"))?;
    validate_raw_sha256(label, digest)?;
    ensure!(
        !value.starts_with("sha256:sha256:"),
        "{label} contains a duplicate sha256 prefix"
    );
    Ok(())
}

fn ensure_nonempty(label: &str, value: &str) -> Result<()> {
    ensure!(!value.trim().is_empty(), "{label} must not be empty");
    Ok(())
}

fn parse_timestamp(value: &str, label: &str) -> Result<OffsetDateTime> {
    OffsetDateTime::parse(value, &Rfc3339)
        .with_context(|| format!("parse {label} {value:?} as RFC3339"))
}

pub fn timestamp_now() -> Result<String> {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .context("format current UTC timestamp")
}

fn kube_error_is_not_found(error: &KubeError) -> bool {
    matches!(error, KubeError::Api(response) if response.code == 404)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::{ContainerStatus, PodCondition, PodSpec, PodStatus};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use std::collections::BTreeMap;

    const DIGEST: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const FINGERPRINT: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const UID: &str = "11111111-1111-4111-8111-111111111111";

    fn spec() -> MintTargetSpec {
        MintTargetSpec {
            api_version: API_VERSION.to_string(),
            kind: TARGET_KIND.to_string(),
            run_id: "mint-20260824-001".to_string(),
            context: "rustfs-mint".to_string(),
            namespace: "rustfs-mint-20260824-001".to_string(),
            namespace_uid: UID.to_string(),
            created_at: "2026-08-24T00:00:00Z".to_string(),
            expires_at: "2026-08-24T12:00:00Z".to_string(),
            server_endpoint: "rustfs.example:9000".to_string(),
            enable_https: false,
            region: "us-east-1".to_string(),
            target_fingerprint: FINGERPRINT.to_string(),
            rustfs_image_digest: DIGEST.to_string(),
            rustfs_container: "rustfs".to_string(),
            timeouts: MintTargetTimeouts::default(),
        }
    }

    fn namespace(spec: &MintTargetSpec) -> Namespace {
        Namespace {
            metadata: ObjectMeta {
                name: Some(spec.namespace.clone()),
                uid: Some(spec.namespace_uid.clone()),
                labels: Some(BTreeMap::from([
                    (MANAGED_BY_LABEL.to_string(), TARGET_MANAGER.to_string()),
                    (RUN_ID_LABEL.to_string(), spec.run_id.clone()),
                ])),
                annotations: Some(BTreeMap::from([(
                    EXPIRES_AT_ANNOTATION.to_string(),
                    spec.expires_at.clone(),
                )])),
                ..ObjectMeta::default()
            },
            ..Namespace::default()
        }
    }

    fn pod(spec: &MintTargetSpec, name: &str) -> Pod {
        Pod {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                uid: Some(format!("{name}-uid")),
                labels: Some(BTreeMap::from([(
                    RUN_ID_LABEL.to_string(),
                    spec.run_id.clone(),
                )])),
                ..ObjectMeta::default()
            },
            spec: Some(PodSpec {
                node_name: Some("node-1".to_string()),
                ..PodSpec::default()
            }),
            status: Some(PodStatus {
                conditions: Some(vec![PodCondition {
                    status: "True".to_string(),
                    type_: "Ready".to_string(),
                    ..PodCondition::default()
                }]),
                container_statuses: Some(vec![ContainerStatus {
                    image: "rustfs/rustfs:unused".to_string(),
                    image_id: format!("docker-pullable://rustfs/rustfs@{DIGEST}"),
                    name: spec.rustfs_container.clone(),
                    ready: true,
                    restart_count: 0,
                    ..ContainerStatus::default()
                }]),
                ..PodStatus::default()
            }),
        }
    }

    #[test]
    fn target_spec_requires_a_current_short_lived_exact_lease() {
        spec()
            .validate_at("2026-08-24T01:00:00Z")
            .expect("active lease");
        assert!(spec().validate_at("2026-08-24T13:00:00Z").is_err());
        let mut long = spec();
        long.expires_at = "2026-08-26T00:00:00Z".to_string();
        assert!(long.validate_at("2026-08-24T01:00:00Z").is_err());

        let mut prefixed_fingerprint = spec();
        prefixed_fingerprint.target_fingerprint = format!("sha256:{FINGERPRINT}");
        assert!(prefixed_fingerprint.validate_contract().is_err());

        let mut unprefixed_image = spec();
        unprefixed_image.rustfs_image_digest = DIGEST.trim_start_matches("sha256:").to_string();
        assert!(unprefixed_image.validate_contract().is_err());

        let mut credential_endpoint = spec();
        credential_endpoint.server_endpoint = "admin:secret@rustfs.example:9000".to_string();
        assert!(credential_endpoint.validate_contract().is_err());
    }

    #[test]
    fn namespace_ownership_requires_uid_run_and_expiry() {
        let spec = spec();
        validate_namespace_ownership(&spec, &namespace(&spec), "2026-08-24T01:00:00Z")
            .expect("owned namespace");

        let mut wrong = namespace(&spec);
        wrong.metadata.uid = Some("22222222-2222-4222-8222-222222222222".to_string());
        assert!(validate_namespace_ownership(&spec, &wrong, "2026-08-24T01:00:00Z").is_err());
    }

    #[test]
    fn pod_proof_rejects_foreign_unready_and_image_drift() {
        let spec = spec();
        assert_eq!(
            validate_target_pods(&spec, &[pod(&spec, "rustfs-0")])
                .expect("ready pod")
                .len(),
            1
        );

        let mut foreign = pod(&spec, "foreign");
        foreign.metadata.labels = None;
        assert!(validate_target_pods(&spec, &[foreign]).is_err());

        let mut drifted = pod(&spec, "drifted");
        drifted
            .status
            .as_mut()
            .and_then(|status| status.container_statuses.as_mut())
            .expect("statuses")[0]
            .image_id =
            "rustfs/rustfs@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                .to_string();
        assert!(validate_target_pods(&spec, &[drifted]).is_err());
    }

    #[test]
    fn admin_endpoint_matches_target_transport() {
        assert_eq!(
            mint_admin_endpoint("rustfs.example:9000", false).expect("HTTP endpoint"),
            "http://rustfs.example:9000"
        );
        assert_eq!(
            mint_admin_endpoint("https://rustfs.example:9000", true).expect("HTTPS endpoint"),
            "https://rustfs.example:9000"
        );
        assert!(mint_admin_endpoint("https://rustfs.example:9000", false).is_err());
    }
}
