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
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::time::Duration;

use crate::protocol::{
    clients::sts::{extract_xml_tag, required_xml_tag, sts_protocol_error},
    credentials::ActorCredential,
    ports::{ProtocolStsError, ProtocolWebIdentityRequest, ProtocolWebIdentityStsPort},
};

#[derive(Debug, Clone)]
pub struct RustfsWebIdentityStsClient {
    endpoint: String,
    http: reqwest::Client,
}

#[derive(Serialize)]
struct WebIdentityForm<'a> {
    #[serde(rename = "Action")]
    action: &'static str,
    #[serde(rename = "Version")]
    version: &'static str,
    #[serde(rename = "DurationSeconds")]
    duration_seconds: u32,
    #[serde(rename = "WebIdentityToken")]
    web_identity_token: &'a str,
    #[serde(rename = "Policy", skip_serializing_if = "Option::is_none")]
    policy: Option<&'a str>,
}

impl RustfsWebIdentityStsClient {
    pub fn new(endpoint: impl Into<String>) -> Result<Self> {
        let endpoint = endpoint.into().trim_end_matches('/').to_string();
        reqwest::Url::parse(&endpoint)
            .with_context(|| format!("parse RustFS WebIdentity STS endpoint {endpoint}"))?;
        Ok(Self {
            endpoint,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .context("build RustFS WebIdentity STS HTTP client")?,
        })
    }
}

#[async_trait::async_trait]
impl ProtocolWebIdentityStsPort for RustfsWebIdentityStsClient {
    fn cleanup_parent(
        &self,
        token: &crate::protocol::credentials::WebIdentityToken,
    ) -> std::result::Result<String, ProtocolStsError> {
        #[derive(serde::Deserialize)]
        struct TokenClaims {
            iss: String,
            sub: String,
        }

        let payload = token
            .expose()
            .split('.')
            .nth(1)
            .ok_or_else(|| sts_protocol_error("InvalidWebIdentityToken"))?;
        let payload = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| sts_protocol_error("InvalidWebIdentityToken"))?;
        let claims: TokenClaims = serde_json::from_slice(&payload)
            .map_err(|_| sts_protocol_error("InvalidWebIdentityToken"))?;
        if claims.iss.is_empty() || claims.sub.is_empty() {
            return Err(sts_protocol_error("InvalidWebIdentityToken"));
        }
        let mut source = Vec::with_capacity(23 + claims.sub.len() + claims.iss.len());
        source.extend_from_slice(b"openid:");
        source.extend_from_slice(&(claims.sub.len() as u64).to_be_bytes());
        source.extend_from_slice(claims.sub.as_bytes());
        source.extend_from_slice(&(claims.iss.len() as u64).to_be_bytes());
        source.extend_from_slice(claims.iss.as_bytes());
        Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(source)))
    }

    async fn assume_role_with_web_identity(
        &self,
        request: &ProtocolWebIdentityRequest,
        source_resource_id: &str,
    ) -> std::result::Result<ActorCredential, ProtocolStsError> {
        let body = serde_urlencoded::to_string(WebIdentityForm {
            action: "AssumeRoleWithWebIdentity",
            version: "2011-06-15",
            duration_seconds: request.duration_seconds,
            web_identity_token: request.token.expose(),
            policy: request.session_policy.as_deref(),
        })
        .map_err(|_| sts_protocol_error("EncodeWebIdentityRequest"))?;
        let response = self
            .http
            .post(format!("{}/", self.endpoint))
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
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
                    .unwrap_or_else(|| "AssumeRoleWithWebIdentityFailed".to_string()),
                status: Some(status.as_u16()),
                request_id,
            });
        }
        let access_key = required_xml_tag(&body, "AccessKeyId")?;
        let secret_key = required_xml_tag(&body, "SecretAccessKey")?;
        let session_token = required_xml_tag(&body, "SessionToken")?;
        let expiration = required_xml_tag(&body, "Expiration")?;
        ActorCredential::temporary_for_phase(
            "web-identity-session",
            access_key,
            secret_key,
            session_token,
            source_resource_id,
            expiration,
            "sts-assume-role-with-web-identity",
        )
        .map_err(|_| sts_protocol_error("InvalidWebIdentityCredentials"))
    }
}

#[cfg(test)]
mod tests {
    use super::{RustfsWebIdentityStsClient, WebIdentityForm};
    use crate::protocol::{
        credentials::WebIdentityToken,
        ports::{ProtocolWebIdentityRequest, ProtocolWebIdentityStsPort},
    };
    use axum::{
        Form, Router,
        http::{HeaderMap, StatusCode, header::AUTHORIZATION},
        routing::post,
    };
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use std::collections::HashMap;

    #[test]
    fn web_identity_form_uses_the_unsigned_sts_action() {
        let body = serde_urlencoded::to_string(WebIdentityForm {
            action: "AssumeRoleWithWebIdentity",
            version: "2011-06-15",
            duration_seconds: 900,
            web_identity_token: "header.payload.signature",
            policy: None,
        })
        .expect("form");
        assert!(body.contains("Action=AssumeRoleWithWebIdentity"));
        assert!(body.contains("WebIdentityToken=header.payload.signature"));
    }

    #[test]
    fn cleanup_parent_matches_rustfs_virtual_identity_algorithm() {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let payload =
            URL_SAFE_NO_PAD.encode(br#"{"iss":"https://idp.example.test","sub":"subject"}"#);
        let token = WebIdentityToken::new(format!("{header}.{payload}.signature")).expect("token");
        let client = RustfsWebIdentityStsClient::new("http://127.0.0.1:9000").expect("client");
        let parent = client.cleanup_parent(&token).expect("parent");
        assert_eq!(parent, "HwDfWftzOy4jiuS3WjKytC_Sg_A2hKhrRAFtBDhoBr0");
    }

    #[tokio::test]
    async fn adapter_exchanges_an_unsigned_web_identity_request() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("listener");
        let endpoint = format!("http://{}", listener.local_addr().expect("address"));
        let app = Router::new().route("/", post(web_identity_exchange));
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("mock RustFS STS");
        });
        let client = RustfsWebIdentityStsClient::new(endpoint).expect("client");
        let token = WebIdentityToken::new("header.payload.signature").expect("token");

        let credential = client
            .assume_role_with_web_identity(
                &ProtocolWebIdentityRequest {
                    duration_seconds: 900,
                    session_policy: None,
                    token,
                },
                "resource",
            )
            .await
            .expect("WebIdentity exchange");

        assert_eq!(credential.access_key(), "temporary-access");
        assert_eq!(credential.secret_key(), "temporary-secret");
        assert_eq!(credential.session_token(), Some("temporary-token"));

        let rejected = client
            .assume_role_with_web_identity(
                &ProtocolWebIdentityRequest {
                    duration_seconds: 900,
                    session_policy: None,
                    token: WebIdentityToken::new("invalid.payload.signature")
                        .expect("invalid token fixture"),
                },
                "resource",
            )
            .await
            .expect_err("invalid token must be rejected");
        assert_eq!(rejected.code, "InvalidIdentityToken");
        assert_eq!(rejected.status, Some(403));
        server.abort();
    }

    async fn web_identity_exchange(
        headers: HeaderMap,
        Form(form): Form<HashMap<String, String>>,
    ) -> (StatusCode, &'static str) {
        assert!(headers.get(AUTHORIZATION).is_none());
        assert_eq!(
            form.get("Action").map(String::as_str),
            Some("AssumeRoleWithWebIdentity")
        );
        assert_eq!(form.get("Version").map(String::as_str), Some("2011-06-15"));
        assert_eq!(form.get("DurationSeconds").map(String::as_str), Some("900"));
        let token = form.get("WebIdentityToken").map(String::as_str);
        if token == Some("invalid.payload.signature") {
            return (
                StatusCode::FORBIDDEN,
                "<ErrorResponse><Error><Code>InvalidIdentityToken</Code></Error></ErrorResponse>",
            );
        }
        assert_eq!(token, Some("header.payload.signature"));
        (
            StatusCode::OK,
            "<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>temporary-access</AccessKeyId><SecretAccessKey>temporary-secret</SecretAccessKey><SessionToken>temporary-token</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>",
        )
    }
}
