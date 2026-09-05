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

//! Narrow, read-only adapters for runtime facts shared by fault and protocol
//! workflows. Mutation-capable protocol administration stays in `protocol`.

use anyhow::{Context, Result, bail, ensure};
use aws_credential_types::Credentials;
use aws_sigv4::http_request::{SignableBody, SignableRequest, SigningSettings, sign};
use aws_sigv4::sign::v4;
use http::{Method, Request};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime};

const ADMIN_INFO_PATH: &str = "/rustfs/admin/v3/info";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RustfsErasureLayout {
    pub deployment_id: String,
    pub standard_parity: usize,
    pub total_sets: Vec<usize>,
    pub drives_per_set: Vec<usize>,
    pub online_drives: usize,
    pub offline_drives: usize,
    pub unknown_drives: usize,
    pub servers: Vec<RustfsServerLayout>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RustfsServerLayout {
    pub endpoint: String,
    pub drives: Vec<RustfsDriveLayout>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RustfsDriveLayout {
    pub uuid: String,
    pub state: String,
    pub pool_index: i32,
    pub set_index: i32,
}

#[derive(Debug, Deserialize)]
struct ServerInfoEnvelope {
    info: ServerInfoPayload,
}

#[derive(Debug, Deserialize)]
struct ServerInfoPayload {
    #[serde(rename = "deploymentID")]
    deployment_id: Option<String>,
    backend: Option<ServerInfoBackend>,
    servers: Option<Vec<ServerInfoServer>>,
}

#[derive(Debug, Deserialize)]
struct ServerInfoBackend {
    #[serde(rename = "standardSCParity")]
    standard_sc_parity: Option<usize>,
    #[serde(rename = "totalSets")]
    total_sets: Vec<usize>,
    #[serde(rename = "totalDrivesPerSet")]
    drives_per_set: Vec<usize>,
    #[serde(rename = "onlineDisks")]
    online_drives: usize,
    #[serde(rename = "offlineDisks")]
    offline_drives: usize,
    #[serde(rename = "unknownDisks", default)]
    unknown_drives: usize,
}

#[derive(Debug, Deserialize)]
struct ServerInfoServer {
    endpoint: String,
    #[serde(rename = "drives")]
    drives: Vec<ServerInfoDrive>,
}

#[derive(Debug, Deserialize)]
struct ServerInfoDrive {
    uuid: String,
    state: String,
    pool_index: i32,
    set_index: i32,
}

pub(crate) async fn read_erasure_layout(
    endpoint: &str,
    region: &str,
    access_key: &str,
    secret_key: &str,
) -> Result<RustfsErasureLayout> {
    let endpoint = endpoint.trim_end_matches('/');
    let mut url = reqwest::Url::parse(endpoint)
        .with_context(|| format!("parse RustFS runtime endpoint {endpoint}"))?;
    url.set_path(ADMIN_INFO_PATH);
    url.set_query(None);

    let body = Vec::new();
    let payload_sha256 = hex::encode(Sha256::digest(&body));
    let mut request = Request::builder()
        .method(Method::GET)
        .uri(url.as_str())
        .header("x-amz-content-sha256", payload_sha256)
        .body(body)
        .context("build RustFS runtime info request")?;
    sign_request(&mut request, region, access_key, secret_key)?;

    let (parts, body) = request.into_parts();
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .context("build RustFS runtime info HTTP client")?
        .request(Method::GET, url)
        .headers(parts.headers)
        .body(body)
        .send()
        .await
        .context("send RustFS runtime info request")?;
    let status = response.status();
    let request_id = response
        .headers()
        .get("x-amz-request-id")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("unknown")
        .to_string();
    let response = response
        .bytes()
        .await
        .context("read RustFS runtime info response")?;
    if !status.is_success() {
        bail!(
            "RustFS runtime info request failed: status={} request_id={request_id}",
            status.as_u16()
        );
    }
    parse_erasure_layout(&response)
}

fn sign_request(
    request: &mut Request<Vec<u8>>,
    region: &str,
    access_key: &str,
    secret_key: &str,
) -> Result<()> {
    let identity = Credentials::new(
        access_key,
        secret_key,
        None,
        None,
        "s3chaos-rustfs-runtime-info",
    )
    .into();
    let params = v4::SigningParams::builder()
        .identity(&identity)
        .region(region)
        .name("s3")
        .time(SystemTime::now())
        .settings(SigningSettings::default())
        .build()
        .context("build RustFS runtime info signing parameters")?
        .into();
    let headers = request
        .headers()
        .iter()
        .map(|(name, value)| {
            Ok((
                name.as_str(),
                value
                    .to_str()
                    .context("RustFS runtime info header is not ASCII")?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let signable = SignableRequest::new(
        request.method().as_str(),
        request.uri().to_string(),
        headers.into_iter(),
        SignableBody::Bytes(request.body()),
    )
    .context("build signable RustFS runtime info request")?;
    let (instructions, _) = sign(signable, &params)
        .context("sign RustFS runtime info request")?
        .into_parts();
    instructions.apply_to_request_http1x(request);
    Ok(())
}

fn parse_erasure_layout(response: &[u8]) -> Result<RustfsErasureLayout> {
    let envelope: ServerInfoEnvelope =
        serde_json::from_slice(response).context("decode RustFS runtime info response")?;
    let deployment_id = envelope
        .info
        .deployment_id
        .filter(|value| !value.trim().is_empty())
        .context("RustFS runtime info is missing deploymentID")?;
    let backend = envelope
        .info
        .backend
        .context("RustFS runtime info is missing erasure backend data")?;
    let standard_parity = backend
        .standard_sc_parity
        .context("RustFS runtime info is missing standardSCParity")?;
    ensure!(
        !backend.total_sets.is_empty()
            && !backend.drives_per_set.is_empty()
            && backend.total_sets.len() == backend.drives_per_set.len(),
        "RustFS runtime info has inconsistent erasure layout arrays"
    );
    let servers = envelope
        .info
        .servers
        .context("RustFS runtime info is missing server drive membership")?
        .into_iter()
        .map(|server| RustfsServerLayout {
            endpoint: server.endpoint,
            drives: server
                .drives
                .into_iter()
                .map(|drive| RustfsDriveLayout {
                    uuid: drive.uuid,
                    state: drive.state,
                    pool_index: drive.pool_index,
                    set_index: drive.set_index,
                })
                .collect(),
        })
        .collect::<Vec<_>>();
    ensure!(!servers.is_empty(), "RustFS runtime info has no servers");
    Ok(RustfsErasureLayout {
        deployment_id,
        standard_parity,
        total_sets: backend.total_sets,
        drives_per_set: backend.drives_per_set,
        online_drives: backend.online_drives,
        offline_drives: backend.offline_drives,
        unknown_drives: backend.unknown_drives,
        servers,
    })
}

#[cfg(test)]
mod tests {
    use super::parse_erasure_layout;

    #[test]
    fn parses_runtime_erasure_layout_and_drive_health() {
        let layout = parse_erasure_layout(
            br#"{
                "info": {
                    "deploymentID": "deployment-1",
                    "backend": {
                        "standardSCParity": 4,
                        "totalSets": [1],
                        "totalDrivesPerSet": [8],
                        "onlineDisks": 8,
                        "offlineDisks": 0,
                        "unknownDisks": 0
                    },
                    "servers": [
                        {"endpoint": "http://rustfs-0.rustfs:9000", "drives": [
                            {"uuid": "drive-0", "state": "ok", "pool_index": 0, "set_index": 0}
                        ]},
                        {"endpoint": "http://rustfs-1.rustfs:9000", "drives": [
                            {"uuid": "drive-1", "state": "ok", "pool_index": 0, "set_index": 0}
                        ]}
                    ]
                }
            }"#,
        )
        .expect("layout");

        assert_eq!(layout.deployment_id, "deployment-1");
        assert_eq!(layout.standard_parity, 4);
        assert_eq!(layout.total_sets, vec![1]);
        assert_eq!(layout.drives_per_set, vec![8]);
        assert_eq!(layout.online_drives, 8);
        assert_eq!(layout.offline_drives, 0);
        assert_eq!(layout.unknown_drives, 0);
        assert_eq!(layout.servers.len(), 2);
        assert_eq!(layout.servers[0].drives[0].uuid, "drive-0");
        assert!(parse_erasure_layout(br#"{"info":{"deploymentID":"deployment-1"}}"#).is_err());
    }
}
