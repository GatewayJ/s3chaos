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
use async_trait::async_trait;
use std::{
    future::pending,
    path::{Path, PathBuf},
    time::Instant,
};

use crate::protocol::{
    clients::{
        admin::RustfsAdminClient, keycloak::KeycloakExternalIdentityProvider, s3::ProtocolS3Client,
        sts::RustfsStsClient, web_identity::RustfsWebIdentityStsClient,
    },
    credentials::{AdminCredentials, CredentialProvider, EnvCredentialProvider},
    runner::executor::{ProtocolClock, ProtocolShutdownSignal, ProtocolTimeoutPolicy},
    suite::{ResolvedProtocolSuite, resolve_protocol_endpoint, resolve_protocol_suite_yaml},
};

const DEFAULT_ARTIFACT_BASE: &str = "target/protocol-tests";

/// Connected outer-layer adapters for one protocol-suite invocation.
///
/// Construction lives here so the suite executor never imports or instantiates
/// AWS, RustFS Admin, STS, or Keycloak implementations.
pub(crate) struct ConnectedProtocolRuntime {
    pub(crate) suite: ResolvedProtocolSuite,
    pub(crate) endpoint: String,
    pub(crate) credentials: AdminCredentials,
    pub(crate) admin: RustfsAdminClient,
    pub(crate) s3: ProtocolS3Client,
    pub(crate) sts: RustfsStsClient,
    pub(crate) external_identity: Option<KeycloakExternalIdentityProvider>,
    pub(crate) web_identity_sts: Option<RustfsWebIdentityStsClient>,
}

impl ConnectedProtocolRuntime {
    pub(crate) async fn connect(path: impl AsRef<Path>) -> Result<Self> {
        let suite = resolve_protocol_suite_yaml(path)?;
        let endpoint = resolve_protocol_endpoint(&suite.target.endpoint)?;
        let credentials = EnvCredentialProvider.resolve(&suite.target.credentials.admin_profile)?;
        let admin = RustfsAdminClient::new(&endpoint, &suite.target.region, credentials.clone())?;
        let s3 = ProtocolS3Client::for_admin(&endpoint, &suite.target.region, &credentials).await?;
        let sts = RustfsStsClient::new(&endpoint, &suite.target.region)?;
        let (external_identity, web_identity_sts) = match &suite.target.external_identity {
            Some(config) => (
                Some(KeycloakExternalIdentityProvider::from_env(&config.profile)?),
                Some(RustfsWebIdentityStsClient::new(&endpoint)?),
            ),
            None => (None, None),
        };
        Ok(Self {
            suite,
            endpoint,
            credentials,
            admin,
            s3,
            sts,
            external_identity,
            web_identity_sts,
        })
    }
}

pub(crate) struct MonotonicProtocolClock {
    started: Instant,
}

impl Default for MonotonicProtocolClock {
    fn default() -> Self {
        Self {
            started: Instant::now(),
        }
    }
}

impl ProtocolClock for MonotonicProtocolClock {
    fn now_millis(&self) -> u128 {
        self.started.elapsed().as_millis()
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct DisabledProtocolTimeout;

#[async_trait]
impl ProtocolTimeoutPolicy for DisabledProtocolTimeout {
    async fn wait_for_wave(&self, _wave_index: usize, _started_at_millis: u128) -> Result<()> {
        pending().await
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ProcessShutdownSignal;

#[async_trait]
impl ProtocolShutdownSignal for ProcessShutdownSignal {
    async fn wait(&self) -> Result<()> {
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
}

pub(crate) fn protocol_artifact_base() -> PathBuf {
    std::env::var("RUSTFS_PROTOCOL_TEST_ARTIFACTS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_ARTIFACT_BASE))
}

pub(crate) fn ensure_dedicated_target_acknowledgement() -> Result<()> {
    ensure!(
        std::env::var("RUSTFS_PROTOCOL_TEST_DEDICATED").as_deref() == Ok("1"),
        "protocol tests require a dedicated RustFS target; set RUSTFS_PROTOCOL_TEST_DEDICATED=1 after verifying the target"
    );
    Ok(())
}
