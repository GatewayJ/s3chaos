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

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::BTreeMap, time::Duration};

use crate::protocol::{
    credentials::{ExternalIdentityCredential, SecretString, WebIdentityToken},
    ports::{
        ProtocolExternalIdentityCoordinates, ProtocolExternalIdentityError,
        ProtocolExternalIdentityPort, ProtocolExternalIdentityProviderInfo,
    },
};

const ISSUER_ENV: &str = "RUSTFS_PROTOCOL_OIDC_ISSUER";
const ADMIN_URL_ENV: &str = "RUSTFS_PROTOCOL_OIDC_ADMIN_URL";
const REALM_ENV: &str = "RUSTFS_PROTOCOL_OIDC_REALM";
const CLIENT_ID_ENV: &str = "RUSTFS_PROTOCOL_OIDC_CLIENT_ID";
const CLIENT_SECRET_ENV: &str = "RUSTFS_PROTOCOL_OIDC_CLIENT_SECRET";
const ADMIN_USERNAME_ENV: &str = "RUSTFS_PROTOCOL_OIDC_ADMIN_USERNAME";
const ADMIN_PASSWORD_ENV: &str = "RUSTFS_PROTOCOL_OIDC_ADMIN_PASSWORD";
const ADMIN_REALM_ENV: &str = "RUSTFS_PROTOCOL_OIDC_ADMIN_REALM";
const POLICY_CLAIM_ENV: &str = "RUSTFS_PROTOCOL_OIDC_POLICY_CLAIM";

type ExternalResult<T> = std::result::Result<T, ProtocolExternalIdentityError>;

#[derive(Debug, Clone)]
pub struct KeycloakExternalIdentityProvider {
    coordinates: ProtocolExternalIdentityCoordinates,
    issuer: reqwest::Url,
    admin_url: reqwest::Url,
    realm: String,
    client_id: String,
    client_secret: SecretString,
    admin_realm: String,
    admin_username: String,
    admin_password: SecretString,
    policy_claim: String,
    http: reqwest::Client,
}

struct KeycloakProviderConfig {
    profile: String,
    issuer: reqwest::Url,
    admin_url: reqwest::Url,
    realm: String,
    client_id: String,
    client_secret: SecretString,
    admin_realm: String,
    admin_username: String,
    admin_password: SecretString,
    policy_claim: String,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    id_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DiscoveryResponse {
    issuer: String,
    token_endpoint: String,
    jwks_uri: String,
}

#[derive(Debug, Deserialize)]
struct JwksResponse {
    keys: Vec<Value>,
}

#[derive(Debug, Deserialize)]
struct KeycloakUser {
    id: String,
    username: Option<String>,
}

impl KeycloakExternalIdentityProvider {
    pub fn from_env(profile: impl Into<String>) -> Result<Self> {
        let config = KeycloakProviderConfig {
            profile: profile.into(),
            issuer: required_url(ISSUER_ENV)?,
            admin_url: required_url(ADMIN_URL_ENV)?,
            realm: required_env(REALM_ENV)?,
            client_id: required_env(CLIENT_ID_ENV)?,
            client_secret: SecretString::new(required_env(CLIENT_SECRET_ENV)?)?,
            admin_username: required_env(ADMIN_USERNAME_ENV)?,
            admin_password: SecretString::new(required_env(ADMIN_PASSWORD_ENV)?)?,
            admin_realm: std::env::var(ADMIN_REALM_ENV)
                .ok()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "master".to_string()),
            policy_claim: std::env::var(POLICY_CLAIM_ENV)
                .ok()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "policy".to_string()),
        };
        Self::new(config)
    }

    fn new(config: KeycloakProviderConfig) -> Result<Self> {
        let KeycloakProviderConfig {
            profile,
            issuer,
            admin_url,
            realm,
            client_id,
            client_secret,
            admin_realm,
            admin_username,
            admin_password,
            policy_claim,
        } = config;
        ensure!(
            !profile.trim().is_empty(),
            "Keycloak profile must not be empty"
        );
        let subject_namespace =
            append_url_segments(&admin_url, &["admin", "realms", &realm, "users"])?
                .as_str()
                .trim_end_matches('/')
                .to_string();
        let coordinates = ProtocolExternalIdentityCoordinates {
            provider: "keycloak".to_string(),
            profile,
            issuer: issuer.as_str().trim_end_matches('/').to_string(),
            subject_namespace,
        };
        Ok(Self {
            coordinates,
            issuer,
            admin_url,
            realm,
            client_id,
            client_secret,
            admin_realm,
            admin_username,
            admin_password,
            policy_claim,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .context("build Keycloak HTTP client")?,
        })
    }

    pub(crate) fn forbidden_secrets(&self) -> Vec<String> {
        vec![
            self.client_secret.expose().to_string(),
            self.admin_password.expose().to_string(),
        ]
    }

    async fn admin_token(&self) -> ExternalResult<SecretString> {
        let url = append_url_segments(
            &self.admin_url,
            &[
                "realms",
                &self.admin_realm,
                "protocol",
                "openid-connect",
                "token",
            ],
        )?;
        let response = self
            .http
            .post(url)
            .form(&[
                ("grant_type", "password"),
                ("client_id", "admin-cli"),
                ("username", self.admin_username.as_str()),
                ("password", self.admin_password.expose()),
            ])
            .send()
            .await
            .map_err(|_| external_transport("KeycloakAdminTokenTransport"))?;
        let status = response.status();
        if !status.is_success() {
            return Err(external_service("KeycloakAdminTokenRejected", status));
        }
        let token = response
            .json::<TokenResponse>()
            .await
            .map_err(|_| external_protocol("InvalidKeycloakAdminTokenResponse"))?
            .access_token
            .filter(|token| !token.is_empty())
            .ok_or_else(|| external_protocol("MissingKeycloakAdminToken"))?;
        SecretString::new(token).map_err(|_| external_protocol("MissingKeycloakAdminToken"))
    }

    fn users_url(&self) -> ExternalResult<reqwest::Url> {
        append_url_segments(&self.admin_url, &["admin", "realms", &self.realm, "users"])
    }

    async fn matching_users(&self, username: &str) -> ExternalResult<Vec<KeycloakUser>> {
        let token = self.admin_token().await?;
        let mut url = self.users_url()?;
        url.query_pairs_mut()
            .append_pair("username", username)
            .append_pair("exact", "true");
        let response = self
            .http
            .get(url)
            .bearer_auth(token.expose())
            .send()
            .await
            .map_err(|_| external_transport("KeycloakFindUserTransport"))?;
        let status = response.status();
        if !status.is_success() {
            return Err(external_service("KeycloakFindUserRejected", status));
        }
        let users = response
            .json::<Vec<KeycloakUser>>()
            .await
            .map_err(|_| external_protocol("InvalidKeycloakUserResponse"))?;
        Ok(users
            .into_iter()
            .filter(|user| user.username.as_deref() == Some(username))
            .collect())
    }
}

#[async_trait::async_trait]
impl ProtocolExternalIdentityPort for KeycloakExternalIdentityProvider {
    fn coordinates(&self) -> ProtocolExternalIdentityCoordinates {
        self.coordinates.clone()
    }

    fn policy_claim(&self) -> &str {
        &self.policy_claim
    }

    async fn provider_info(&self) -> ExternalResult<ProtocolExternalIdentityProviderInfo> {
        let discovery_url =
            append_url_segments(&self.issuer, &[".well-known", "openid-configuration"])?;
        let response = self
            .http
            .get(discovery_url)
            .send()
            .await
            .map_err(|_| external_transport("OidcDiscoveryTransport"))?;
        let status = response.status();
        if !status.is_success() {
            return Err(external_service("OidcDiscoveryRejected", status));
        }
        let discovery = response
            .json::<DiscoveryResponse>()
            .await
            .map_err(|_| external_protocol("InvalidOidcDiscoveryResponse"))?;
        if discovery.issuer.trim_end_matches('/') != self.issuer.as_str().trim_end_matches('/') {
            return Err(external_protocol("OidcIssuerMismatch"));
        }
        let expected_token_endpoint =
            append_url_segments(&self.issuer, &["protocol", "openid-connect", "token"])?;
        if discovery.token_endpoint != expected_token_endpoint.as_str() {
            return Err(external_protocol("OidcTokenEndpointMismatch"));
        }
        let jwks_url = reqwest::Url::parse(&discovery.jwks_uri)
            .map_err(|_| external_protocol("InvalidOidcJwksUrl"))?;
        let jwks_response = self
            .http
            .get(jwks_url)
            .send()
            .await
            .map_err(|_| external_transport("OidcJwksTransport"))?;
        let jwks_status = jwks_response.status();
        if !jwks_status.is_success() {
            return Err(external_service("OidcJwksRejected", jwks_status));
        }
        let jwks = jwks_response
            .json::<JwksResponse>()
            .await
            .map_err(|_| external_protocol("InvalidOidcJwksResponse"))?;
        if jwks.keys.is_empty() {
            return Err(external_protocol("EmptyOidcJwks"));
        }
        Ok(ProtocolExternalIdentityProviderInfo {
            provider: self.coordinates.provider.clone(),
            profile: self.coordinates.profile.clone(),
            issuer: self.coordinates.issuer.clone(),
            policy_claim: self.policy_claim.clone(),
        })
    }

    async fn create_subject(
        &self,
        credential: &ExternalIdentityCredential,
        claims: &BTreeMap<String, Vec<String>>,
    ) -> ExternalResult<()> {
        let token = self.admin_token().await?;
        let response = self
            .http
            .post(self.users_url()?)
            .bearer_auth(token.expose())
            .json(&json!({
                "username": credential.username,
                "enabled": true,
                "credentials": [{
                    "type": "password",
                    "value": credential.password(),
                    "temporary": false
                }],
                "attributes": claims
            }))
            .send()
            .await
            .map_err(|_| external_transport("KeycloakCreateUserTransport"))?;
        let status = response.status();
        if !status.is_success() {
            return Err(external_service("KeycloakCreateUserRejected", status));
        }
        Ok(())
    }

    async fn issue_id_token(
        &self,
        credential: &ExternalIdentityCredential,
    ) -> ExternalResult<WebIdentityToken> {
        let url = append_url_segments(&self.issuer, &["protocol", "openid-connect", "token"])?;
        let response = self
            .http
            .post(url)
            .form(&[
                ("grant_type", "password"),
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.expose()),
                ("username", credential.username.as_str()),
                ("password", credential.password()),
                ("scope", "openid"),
            ])
            .send()
            .await
            .map_err(|_| external_transport("KeycloakIssueTokenTransport"))?;
        let status = response.status();
        if !status.is_success() {
            return Err(external_service("KeycloakIssueTokenRejected", status));
        }
        let token = response
            .json::<TokenResponse>()
            .await
            .map_err(|_| external_protocol("InvalidKeycloakTokenResponse"))?
            .id_token
            .filter(|token| !token.is_empty())
            .ok_or_else(|| external_protocol("MissingKeycloakIdToken"))?;
        WebIdentityToken::new(token).map_err(|_| external_protocol("MissingKeycloakIdToken"))
    }

    async fn subject_exists(&self, username: &str) -> ExternalResult<bool> {
        Ok(!self.matching_users(username).await?.is_empty())
    }

    async fn delete_subject(&self, username: &str) -> ExternalResult<()> {
        let users = self.matching_users(username).await?;
        if users.is_empty() {
            return Ok(());
        }
        let token = self.admin_token().await?;
        for user in users {
            let url = append_url_segments(&self.users_url()?, &[user.id.as_str()])?;
            let response = self
                .http
                .delete(url)
                .bearer_auth(token.expose())
                .send()
                .await
                .map_err(|_| external_transport("KeycloakDeleteUserTransport"))?;
            let status = response.status();
            if !status.is_success() && status != reqwest::StatusCode::NOT_FOUND {
                return Err(external_service("KeycloakDeleteUserRejected", status));
            }
        }
        Ok(())
    }
}

fn required_env(name: &str) -> Result<String> {
    std::env::var(name)
        .with_context(|| format!("{name} is required for the Keycloak external identity profile"))
        .and_then(|value| {
            ensure!(!value.trim().is_empty(), "{name} must not be empty");
            Ok(value)
        })
}

fn required_url(name: &str) -> Result<reqwest::Url> {
    let value = required_env(name)?;
    let mut url = reqwest::Url::parse(&value).with_context(|| format!("parse {name}"))?;
    ensure!(
        matches!(url.scheme(), "http" | "https"),
        "{name} must use http or https"
    );
    ensure!(
        url.username().is_empty() && url.password().is_none(),
        "{name} must not contain credentials"
    );
    ensure!(
        url.query().is_none() && url.fragment().is_none(),
        "{name} must not contain a query or fragment"
    );
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

fn append_url_segments(base: &reqwest::Url, segments: &[&str]) -> ExternalResult<reqwest::Url> {
    let mut url = base.clone();
    url.set_query(None);
    url.path_segments_mut()
        .map_err(|_| external_protocol("InvalidKeycloakBaseUrl"))?
        .pop_if_empty()
        .extend(segments.iter().copied());
    Ok(url)
}

fn external_service(code: &str, status: reqwest::StatusCode) -> ProtocolExternalIdentityError {
    ProtocolExternalIdentityError::service(code, status.as_u16())
}

fn external_transport(code: &str) -> ProtocolExternalIdentityError {
    ProtocolExternalIdentityError::transport(code)
}

fn external_protocol(code: &str) -> ProtocolExternalIdentityError {
    ProtocolExternalIdentityError::protocol(code)
}

#[cfg(test)]
mod tests {
    use super::{KeycloakExternalIdentityProvider, KeycloakProviderConfig, append_url_segments};
    use crate::protocol::{
        credentials::{ExternalIdentityCredential, SecretString},
        ports::ProtocolExternalIdentityPort,
    };
    use axum::{
        Form, Json, Router,
        extract::{Path, Query, State},
        http::{HeaderMap, StatusCode, header::AUTHORIZATION},
        routing::{delete, get, post},
    };
    use serde::Deserialize;
    use serde_json::{Value, json};
    use std::{
        collections::{BTreeMap, HashMap},
        sync::{Arc, Mutex},
    };

    #[derive(Clone)]
    struct MockKeycloakState {
        issuer: String,
        user: Arc<Mutex<Option<Value>>>,
    }

    #[derive(Deserialize)]
    struct UserQuery {
        username: String,
        exact: bool,
    }

    #[test]
    fn url_builder_preserves_a_keycloak_base_path() {
        let base = reqwest::Url::parse("https://idp.example/auth/").expect("url");
        let url =
            append_url_segments(&base, &["admin", "realms", "ci", "users"]).expect("built url");
        assert_eq!(
            url.as_str(),
            "https://idp.example/auth/admin/realms/ci/users"
        );
    }

    #[tokio::test]
    async fn adapter_covers_keycloak_discovery_token_and_subject_lifecycle() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("listener");
        let base = format!("http://{}", listener.local_addr().expect("address"));
        let state = MockKeycloakState {
            issuer: format!("{base}/realms/ci"),
            user: Arc::new(Mutex::new(None)),
        };
        let app = Router::new()
            .route(
                "/realms/ci/.well-known/openid-configuration",
                get(discovery),
            )
            .route("/realms/ci/protocol/openid-connect/certs", get(jwks))
            .route(
                "/realms/master/protocol/openid-connect/token",
                post(admin_token),
            )
            .route(
                "/realms/ci/protocol/openid-connect/token",
                post(subject_token),
            )
            .route("/admin/realms/ci/users", get(find_users).post(create_user))
            .route("/admin/realms/ci/users/{id}", delete(delete_user))
            .with_state(state.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("mock Keycloak");
        });

        let provider = KeycloakExternalIdentityProvider::new(KeycloakProviderConfig {
            profile: "keycloak-ci".to_string(),
            issuer: reqwest::Url::parse(&state.issuer).expect("issuer"),
            admin_url: reqwest::Url::parse(&base).expect("admin URL"),
            realm: "ci".to_string(),
            client_id: "rustfs-ci".to_string(),
            client_secret: SecretString::new("client-secret").expect("client secret"),
            admin_realm: "master".to_string(),
            admin_username: "admin".to_string(),
            admin_password: SecretString::new("admin-password").expect("admin password"),
            policy_claim: "policy".to_string(),
        })
        .expect("provider");
        let info = provider.provider_info().await.expect("provider info");
        assert_eq!(info.issuer, state.issuer);
        assert_eq!(info.policy_claim, "policy");
        assert_eq!(
            provider.coordinates().subject_namespace,
            format!("{base}/admin/realms/ci/users")
        );

        let subject = ExternalIdentityCredential::generated("oidc-user", "resource")
            .expect("subject credentials");
        let claims = BTreeMap::from([("policy".to_string(), vec!["readonly".to_string()])]);
        provider
            .create_subject(&subject, &claims)
            .await
            .expect("create subject");
        assert!(
            provider
                .subject_exists("oidc-user")
                .await
                .expect("subject exists")
        );
        let token = provider.issue_id_token(&subject).await.expect("ID token");
        assert_eq!(token.expose(), "header.payload.signature");

        let created = state
            .user
            .lock()
            .expect("user state")
            .clone()
            .expect("created user");
        assert_eq!(created["attributes"]["policy"], json!(["readonly"]));
        assert_eq!(created["credentials"][0]["temporary"], false);

        provider
            .delete_subject("oidc-user")
            .await
            .expect("delete subject");
        assert!(
            !provider
                .subject_exists("oidc-user")
                .await
                .expect("subject absent")
        );
        server.abort();
    }

    async fn discovery(State(state): State<MockKeycloakState>) -> Json<Value> {
        Json(json!({
            "issuer": state.issuer,
            "token_endpoint": format!("{}/protocol/openid-connect/token", state.issuer),
            "jwks_uri": format!("{}/protocol/openid-connect/certs", state.issuer)
        }))
    }

    async fn jwks() -> Json<Value> {
        Json(json!({"keys": [{"kid": "test-key", "kty": "RSA"}]}))
    }

    async fn admin_token(Form(form): Form<HashMap<String, String>>) -> Json<Value> {
        assert_eq!(form.get("grant_type").map(String::as_str), Some("password"));
        assert_eq!(form.get("client_id").map(String::as_str), Some("admin-cli"));
        assert_eq!(form.get("username").map(String::as_str), Some("admin"));
        assert_eq!(
            form.get("password").map(String::as_str),
            Some("admin-password")
        );
        Json(json!({"access_token": "admin-token"}))
    }

    async fn subject_token(Form(form): Form<HashMap<String, String>>) -> Json<Value> {
        assert_eq!(form.get("grant_type").map(String::as_str), Some("password"));
        assert_eq!(form.get("client_id").map(String::as_str), Some("rustfs-ci"));
        assert_eq!(
            form.get("client_secret").map(String::as_str),
            Some("client-secret")
        );
        assert_eq!(form.get("username").map(String::as_str), Some("oidc-user"));
        assert_eq!(form.get("scope").map(String::as_str), Some("openid"));
        Json(json!({"id_token": "header.payload.signature"}))
    }

    async fn create_user(
        State(state): State<MockKeycloakState>,
        headers: HeaderMap,
        Json(user): Json<Value>,
    ) -> StatusCode {
        assert_admin_token(&headers);
        assert_eq!(user["username"], "oidc-user");
        assert_eq!(user["enabled"], true);
        *state.user.lock().expect("user state") = Some(user);
        StatusCode::CREATED
    }

    async fn find_users(
        State(state): State<MockKeycloakState>,
        headers: HeaderMap,
        Query(query): Query<UserQuery>,
    ) -> Json<Value> {
        assert_admin_token(&headers);
        assert!(query.exact);
        let user = state.user.lock().expect("user state");
        let matches = user
            .as_ref()
            .filter(|user| user["username"] == query.username)
            .map(|user| json!({"id": "user-1", "username": user["username"]}))
            .into_iter()
            .collect::<Vec<_>>();
        Json(json!(matches))
    }

    async fn delete_user(
        State(state): State<MockKeycloakState>,
        headers: HeaderMap,
        Path(id): Path<String>,
    ) -> StatusCode {
        assert_admin_token(&headers);
        assert_eq!(id, "user-1");
        *state.user.lock().expect("user state") = None;
        StatusCode::NO_CONTENT
    }

    fn assert_admin_token(headers: &HeaderMap) {
        assert_eq!(
            headers
                .get(AUTHORIZATION)
                .and_then(|value| value.to_str().ok()),
            Some("Bearer admin-token")
        );
    }
}
