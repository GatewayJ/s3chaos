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

//! Fail-closed execution route for the planned stale-disk-return qualification.

use std::{net::SocketAddr, time::Duration};

use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
};

use crate::{
    fault::{
        backends::host::preflight_stale_disk_mutation,
        config::FaultTestConfig,
        host_storage::HOST_STORAGE_PROOF_ARTIFACT,
        plan::{ExecutionPlan, StorageRecoveryExecutionPlan},
        runner::initialize_fault_run,
        scenarios::{FaultScenario, STALE_DISK_RETURN_DETECT_SCENARIO},
        shutdown::RunDeadline,
        storage_recovery::{AckLossPutEvidence, StorageRecoveryCase},
    },
    framework::artifacts::ArtifactCollector,
};

const ACK_LOSS_PROXY_IO_TIMEOUT: Duration = Duration::from_secs(10);
const ACK_LOSS_PROXY_MAX_REQUEST_BYTES: usize = 8 * 1024 * 1024;
const ACK_LOSS_PROXY_MAX_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Debug)]
pub struct AckLossProxyCapture {
    proxy_endpoint: SocketAddr,
    request_sha256: String,
    request_value_sha256: String,
    request_bytes: usize,
    upstream_http_status: u16,
    upstream_request_id: String,
    upstream_version_id: String,
    accepted_at_ms: u64,
    upstream_completed_at_ms: u64,
    connection_closed_at_ms: u64,
}

impl AckLossProxyCapture {
    pub fn bind_operation(
        self,
        record: &crate::fault::history::OperationRecord,
    ) -> Result<AckLossPutEvidence> {
        let value_sha256 = record
            .value_sha256
            .clone()
            .context("ACK-loss PUT history lacks its value digest")?;
        let size_bytes = record
            .size_bytes
            .context("ACK-loss PUT history lacks its decoded byte size")?;
        ensure!(
            self.request_bytes >= size_bytes && self.request_value_sha256 == value_sha256,
            "ACK-loss proxy request does not match the workload PUT body"
        );
        Ok(AckLossPutEvidence {
            operation_id: record.id.clone(),
            proxy_endpoint: self.proxy_endpoint.to_string(),
            request_count: 1,
            retries_disabled: true,
            request_sha256: self.request_sha256,
            value_sha256: self.request_value_sha256,
            size_bytes,
            upstream_http_status: self.upstream_http_status,
            upstream_request_id: self.upstream_request_id,
            upstream_version_id: self.upstream_version_id,
            accepted_at_ms: self.accepted_at_ms,
            upstream_completed_at_ms: self.upstream_completed_at_ms,
            client_response_bytes: 0,
            connection_closed_at_ms: self.connection_closed_at_ms,
        })
    }
}

pub struct AckLossProxy {
    endpoint: SocketAddr,
    capture: oneshot::Receiver<Result<AckLossProxyCapture>>,
    task: Option<JoinHandle<()>>,
}

impl AckLossProxy {
    pub async fn bind(upstream_endpoint: &str) -> Result<Self> {
        let upstream = loopback_http_endpoint(upstream_endpoint)?;
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .context("bind one-shot ACK-loss proxy")?;
        let endpoint = listener.local_addr()?;
        let (sender, capture) = oneshot::channel();
        let task = tokio::spawn(async move {
            let result = serve_ack_loss_once(listener, endpoint, upstream).await;
            let _ = sender.send(result);
        });
        Ok(Self {
            endpoint,
            capture,
            task: Some(task),
        })
    }

    pub fn endpoint(&self) -> String {
        format!("http://{}", self.endpoint)
    }

    pub async fn capture(mut self) -> Result<AckLossProxyCapture> {
        let capture = tokio::time::timeout(ACK_LOSS_PROXY_IO_TIMEOUT, &mut self.capture)
            .await
            .context("ACK-loss proxy capture timed out")?
            .context("ACK-loss proxy task ended without a capture")??;
        self.task
            .take()
            .expect("ACK-loss proxy task is present")
            .await
            .context("ACK-loss proxy task panicked")?;
        Ok(capture)
    }
}

impl Drop for AckLossProxy {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

async fn serve_ack_loss_once(
    listener: TcpListener,
    proxy_endpoint: SocketAddr,
    upstream: SocketAddr,
) -> Result<AckLossProxyCapture> {
    let (mut client, peer) = tokio::time::timeout(ACK_LOSS_PROXY_IO_TIMEOUT, listener.accept())
        .await
        .context("ACK-loss proxy accept timed out")??;
    ensure!(
        peer.ip().is_loopback(),
        "ACK-loss proxy accepted a non-loopback client"
    );
    let accepted_at_ms = now_ms()?;
    let request = read_content_length_message(
        &mut client,
        ACK_LOSS_PROXY_MAX_REQUEST_BYTES,
        "ACK-loss request",
    )
    .await?;
    let request_sha256 = hex::encode(Sha256::digest(&request));
    let request_value_sha256 = parse_put_request_sha256(&request)?;
    let mut server = tokio::time::timeout(ACK_LOSS_PROXY_IO_TIMEOUT, TcpStream::connect(upstream))
        .await
        .context("ACK-loss upstream connect timed out")??;
    tokio::time::timeout(ACK_LOSS_PROXY_IO_TIMEOUT, server.write_all(&request))
        .await
        .context("ACK-loss upstream request timed out")??;
    server.flush().await?;
    let response = read_content_length_message(
        &mut server,
        ACK_LOSS_PROXY_MAX_RESPONSE_BYTES,
        "ACK-loss response",
    )
    .await?;
    let upstream_completed_at_ms = now_ms()?;
    let (status, request_id, version_id) = parse_put_response(&response)?;
    // The defining action: do not forward any upstream response byte.
    client.shutdown().await?;
    let connection_closed_at_ms = now_ms()?;
    Ok(AckLossProxyCapture {
        proxy_endpoint,
        request_sha256,
        request_value_sha256,
        request_bytes: request.len(),
        upstream_http_status: status,
        upstream_request_id: request_id,
        upstream_version_id: version_id,
        accepted_at_ms,
        upstream_completed_at_ms,
        connection_closed_at_ms,
    })
}

fn parse_put_request_sha256(request: &[u8]) -> Result<String> {
    let header_end = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .context("ACK-loss request lacks complete headers")?;
    let headers =
        std::str::from_utf8(&request[..header_end]).context("ACK-loss request is not UTF-8")?;
    ensure!(
        headers
            .lines()
            .next()
            .is_some_and(|line| line.starts_with("PUT /") && line.ends_with(" HTTP/1.1")),
        "ACK-loss proxy request is not one HTTP/1.1 PUT"
    );
    let digest = headers
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("x-amz-content-sha256"))
        .map(|(_, value)| value.trim())
        .context("ACK-loss PUT lacks x-amz-content-sha256")?;
    ensure!(
        digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "ACK-loss PUT content digest is not SHA-256 hex"
    );
    Ok(digest.to_ascii_lowercase())
}

async fn read_content_length_message(
    stream: &mut TcpStream,
    max_bytes: usize,
    label: &str,
) -> Result<Vec<u8>> {
    let mut message = Vec::new();
    let header_end = loop {
        ensure!(
            message.len() < max_bytes,
            "{label} headers exceed byte budget"
        );
        let mut chunk = [0_u8; 4096];
        let count = tokio::time::timeout(ACK_LOSS_PROXY_IO_TIMEOUT, stream.read(&mut chunk))
            .await
            .with_context(|| format!("{label} read timed out"))??;
        ensure!(count > 0, "{label} ended before complete headers");
        message.extend_from_slice(&chunk[..count]);
        if let Some(index) = message.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let headers = std::str::from_utf8(&message[..header_end])
        .with_context(|| format!("{label} headers are not UTF-8"))?;
    ensure!(
        !headers.lines().any(|line| {
            line.split_once(':')
                .is_some_and(|(name, _)| name.eq_ignore_ascii_case("transfer-encoding"))
        }),
        "{label} uses unsupported transfer encoding"
    );
    let content_length = headers
        .lines()
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.trim().parse::<usize>())
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        content_length.len() <= 1,
        "{label} contains duplicate Content-Length"
    );
    let expected = header_end + content_length.first().copied().unwrap_or(0);
    ensure!(expected <= max_bytes, "{label} exceeds byte budget");
    ensure!(
        message.len() <= expected,
        "{label} contains pipelined or trailing bytes"
    );
    while message.len() < expected {
        let remaining = expected - message.len();
        let mut chunk = vec![0_u8; remaining.min(4096)];
        let count = tokio::time::timeout(ACK_LOSS_PROXY_IO_TIMEOUT, stream.read(&mut chunk))
            .await
            .with_context(|| format!("{label} body read timed out"))??;
        ensure!(count > 0, "{label} ended before its declared body");
        message.extend_from_slice(&chunk[..count]);
    }
    Ok(message)
}

fn parse_put_response(response: &[u8]) -> Result<(u16, String, String)> {
    let headers = std::str::from_utf8(response).context("ACK-loss response is not UTF-8")?;
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .context("ACK-loss response lacks status")?
        .parse::<u16>()?;
    ensure!(
        (200..300).contains(&status),
        "ACK-loss upstream PUT did not succeed"
    );
    let header = |name: &str| {
        headers.lines().find_map(|line| {
            line.split_once(':')
                .filter(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.trim().to_string())
        })
    };
    let request_id = header("x-amz-request-id").context("upstream PUT lacks request id")?;
    let version_id = header("x-amz-version-id").context("upstream PUT lacks version id")?;
    ensure!(
        !request_id.is_empty() && !version_id.is_empty() && version_id != "null",
        "upstream PUT returned an empty request or version identity"
    );
    Ok((status, request_id, version_id))
}

fn loopback_http_endpoint(endpoint: &str) -> Result<SocketAddr> {
    let authority = endpoint
        .strip_prefix("http://")
        .context("ACK-loss proxy requires a plaintext localhost upstream")?;
    ensure!(
        !authority.contains('/') && !authority.contains('@'),
        "ACK-loss upstream endpoint has an unsupported path or userinfo"
    );
    let address = authority
        .parse::<SocketAddr>()
        .context("ACK-loss upstream endpoint is not an explicit socket address")?;
    ensure!(
        address.ip().is_loopback() && address.port() > 0,
        "ACK-loss upstream must be an explicit loopback port-forward"
    );
    Ok(address)
}

fn now_ms() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock before UNIX epoch")?
        .as_millis() as u64)
}

pub(crate) async fn run_stale_disk_case(
    config: &FaultTestConfig,
    collector: &ArtifactCollector,
    scenario: &FaultScenario,
    execution_plan: &ExecutionPlan,
    plan: &StorageRecoveryExecutionPlan,
    run_id: &str,
    deadline: RunDeadline,
) -> Result<()> {
    ensure!(
        config.qualify_planned_storage
            && scenario.name == STALE_DISK_RETURN_DETECT_SCENARIO
            && plan.case == StorageRecoveryCase::StaleDiskReturn
            && plan.scenario == scenario.name,
        "stale-disk qualification requires the exact planned-storage gate and typed case"
    );
    let _context = initialize_fault_run(config, collector, scenario, execution_plan, run_id)?;
    deadline.check()?;
    let host_proof = preflight_stale_disk_mutation(config, scenario, run_id)?;
    host_proof.validate()?;
    let proof_json = serde_json::to_string_pretty(&host_proof)?;
    collector.write_text(scenario.case_name, HOST_STORAGE_PROOF_ARTIFACT, &proof_json)?;
    collector.write_text(scenario.case_name, "target-proof.json", &proof_json)?;
    bail!(
        "stale-disk production adapter is unavailable; refusing to mutate storage without a qualified run-owned DM helper"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ack_loss_proxy_forwards_exact_request_and_drops_response() {
        let upstream = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("upstream listener");
        let upstream_address = upstream.local_addr().expect("upstream address");
        let body_sha256 = hex::encode(Sha256::digest(b"abc"));
        let request = format!(
            "PUT /bucket/key HTTP/1.1\r\nHost: 127.0.0.1\r\nx-amz-content-sha256: {body_sha256}\r\nContent-Length: 3\r\n\r\nabc"
        )
        .into_bytes();
        let expected_request = request.to_vec();
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.expect("accept upstream request");
            let received = read_content_length_message(
                &mut stream,
                ACK_LOSS_PROXY_MAX_REQUEST_BYTES,
                "test request",
            )
            .await
            .expect("complete upstream request");
            assert_eq!(received, expected_request);
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nx-amz-request-id: request-1\r\nx-amz-version-id: version-1\r\n\r\n",
                )
                .await
                .expect("upstream response");
        });
        let proxy = AckLossProxy::bind(&format!("http://{upstream_address}"))
            .await
            .expect("ACK-loss proxy");
        let proxy_address = proxy.endpoint;
        let mut client = TcpStream::connect(proxy_address)
            .await
            .expect("proxy client");
        client.write_all(&request).await.expect("proxy request");
        client.flush().await.expect("flush proxy request");
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("read dropped response");
        assert!(response.is_empty());

        let capture = proxy.capture().await.expect("proxy capture");
        upstream_task.await.expect("upstream task");
        assert_eq!(capture.upstream_http_status, 200);
        assert_eq!(capture.upstream_request_id, "request-1");
        assert_eq!(capture.upstream_version_id, "version-1");
        assert_eq!(
            capture.request_sha256,
            hex::encode(Sha256::digest(&request))
        );
        assert_eq!(capture.request_value_sha256, body_sha256);
    }

    #[test]
    fn ack_loss_proxy_rejects_non_loopback_or_tls_upstream() {
        assert!(loopback_http_endpoint("https://127.0.0.1:9000").is_err());
        assert!(loopback_http_endpoint("http://192.0.2.1:9000").is_err());
        assert!(loopback_http_endpoint("http://127.0.0.1:9000/path").is_err());
    }
}
