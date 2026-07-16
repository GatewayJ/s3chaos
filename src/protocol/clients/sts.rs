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

use anyhow::{Context, Result};
use aws_credential_types::Credentials;
use aws_sigv4::http_request::{SignableBody, SignableRequest, SigningSettings, sign};
use aws_sigv4::sign::v4;
use http::{Method, Request};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime};

use crate::protocol::{
    credentials::ActorCredential,
    ports::{ProtocolAssumeRoleRequest, ProtocolStsError, ProtocolStsPort},
};

#[derive(Debug, Clone)]
pub struct RustfsStsClient {
    endpoint: String,
    region: String,
    http: reqwest::Client,
}

#[derive(Serialize)]
struct AssumeRoleForm<'a> {
    #[serde(rename = "Action")]
    action: &'static str,
    #[serde(rename = "Version")]
    version: &'static str,
    #[serde(rename = "DurationSeconds")]
    duration_seconds: u32,
    #[serde(rename = "Policy", skip_serializing_if = "Option::is_none")]
    policy: Option<&'a str>,
}

impl RustfsStsClient {
    pub fn new(endpoint: impl Into<String>, region: impl Into<String>) -> Result<Self> {
        let endpoint = endpoint.into().trim_end_matches('/').to_string();
        reqwest::Url::parse(&endpoint)
            .with_context(|| format!("parse RustFS STS endpoint {endpoint}"))?;
        Ok(Self {
            endpoint,
            region: region.into(),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .context("build RustFS STS HTTP client")?,
        })
    }

    async fn assume_role_request(
        &self,
        parent: &ActorCredential,
        input: &ProtocolAssumeRoleRequest,
    ) -> std::result::Result<Vec<u8>, ProtocolStsError> {
        let url = format!("{}/", self.endpoint);
        let body = serde_urlencoded::to_string(AssumeRoleForm {
            action: "AssumeRole",
            version: "2011-06-15",
            duration_seconds: input.duration_seconds,
            policy: input.session_policy.as_deref(),
        })
        .map_err(|_| sts_protocol_error("EncodeAssumeRoleRequest"))?
        .into_bytes();
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(&url)
            .header("x-amz-content-sha256", hex::encode(Sha256::digest(&body)))
            .header(
                http::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(body)
            .map_err(|_| sts_protocol_error("BuildAssumeRoleRequest"))?;
        self.sign(parent, &mut request)?;
        let (parts, body) = request.into_parts();
        let response = self
            .http
            .post(url)
            .headers(parts.headers)
            .body(body)
            .send()
            .await
            .map_err(|_| sts_protocol_error("StsTransportError"))?;
        let status = response.status();
        let request_id = response
            .headers()
            .get("x-amz-request-id")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let body = response
            .bytes()
            .await
            .map_err(|_| sts_protocol_error("StsResponseBodyError"))?;
        if !status.is_success() {
            return Err(ProtocolStsError {
                code: extract_xml_tag(&body, "Code")
                    .unwrap_or_else(|| "AssumeRoleFailed".to_string()),
                status: Some(status.as_u16()),
                request_id,
            });
        }
        Ok(body.to_vec())
    }

    fn sign(
        &self,
        parent: &ActorCredential,
        request: &mut Request<Vec<u8>>,
    ) -> std::result::Result<(), ProtocolStsError> {
        let identity = Credentials::new(
            parent.access_key(),
            parent.secret_key(),
            parent.session_token().map(str::to_string),
            None,
            "s3chaos-protocol-sts-parent",
        )
        .into();
        let params = v4::SigningParams::builder()
            .identity(&identity)
            .region(&self.region)
            .name("sts")
            .time(SystemTime::now())
            .settings(SigningSettings::default())
            .build()
            .map_err(|_| sts_protocol_error("BuildStsSigningParameters"))?
            .into();
        let headers = request
            .headers()
            .iter()
            .filter_map(|(name, value)| value.to_str().ok().map(|value| (name.as_str(), value)));
        let signable = SignableRequest::new(
            request.method().as_str(),
            request.uri().to_string(),
            headers,
            SignableBody::Bytes(request.body()),
        )
        .map_err(|_| sts_protocol_error("BuildSignableStsRequest"))?;
        let (instructions, _) = sign(signable, &params)
            .map_err(|_| sts_protocol_error("SignStsRequest"))?
            .into_parts();
        instructions.apply_to_request_http1x(request);
        Ok(())
    }
}

#[async_trait::async_trait]
impl ProtocolStsPort for RustfsStsClient {
    async fn assume_role(
        &self,
        parent: &ActorCredential,
        request: &ProtocolAssumeRoleRequest,
        source_resource_id: &str,
    ) -> std::result::Result<ActorCredential, ProtocolStsError> {
        let response = self.assume_role_request(parent, request).await?;
        let access_key = required_xml_tag(&response, "AccessKeyId")?;
        let secret_key = required_xml_tag(&response, "SecretAccessKey")?;
        let session_token = required_xml_tag(&response, "SessionToken")?;
        let expiration = required_xml_tag(&response, "Expiration")?;
        ActorCredential::temporary(
            "sts-session",
            access_key,
            secret_key,
            session_token,
            source_resource_id,
            expiration,
        )
        .map_err(|_| sts_protocol_error("InvalidAssumeRoleCredentials"))
    }
}

fn required_xml_tag(body: &[u8], tag: &str) -> std::result::Result<String, ProtocolStsError> {
    extract_xml_tag(body, tag).ok_or_else(|| sts_protocol_error("InvalidAssumeRoleResponse"))
}

fn extract_xml_tag(body: &[u8], tag: &str) -> Option<String> {
    let xml = std::str::from_utf8(body).ok()?;
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(xml[start..end].to_string())
}

fn sts_protocol_error(code: &str) -> ProtocolStsError {
    ProtocolStsError {
        code: code.to_string(),
        status: None,
        request_id: None,
    }
}

#[cfg(test)]
mod tests {
    use super::{AssumeRoleForm, extract_xml_tag};

    #[test]
    fn assume_role_form_encodes_session_policy_and_response_parser_is_bounded() {
        let body = serde_urlencoded::to_string(AssumeRoleForm {
            action: "AssumeRole",
            version: "2011-06-15",
            duration_seconds: 900,
            policy: Some(r#"{"Version":"2012-10-17"}"#),
        })
        .expect("form");
        assert!(body.contains("Action=AssumeRole"));
        assert!(body.contains("Policy=%7B%22Version%22%3A%222012-10-17%22%7D"));
        assert_eq!(
            extract_xml_tag(
                b"<Credentials><AccessKeyId>temp</AccessKeyId></Credentials>",
                "AccessKeyId"
            ),
            Some("temp".to_string())
        );
    }
}
