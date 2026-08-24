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

use crate::protocol::{
    clients::admin::RustfsAdminClient,
    credentials::{CredentialProvider, EnvCredentialProvider},
    suite_plan::TargetFingerprint,
};

pub async fn verify_mint_target(
    server_endpoint: &str,
    enable_https: bool,
    region: &str,
    expected_fingerprint: &str,
) -> Result<String> {
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
    mint_profile_target_fingerprint(&observed, expected_fingerprint)
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
            "Mint endpoint scheme disagrees with RUSTFS_PROTOCOL_COMPAT_ENABLE_HTTPS"
        );
        Ok(server_endpoint.to_string())
    } else {
        Ok(format!("{scheme}://{server_endpoint}"))
    }
}

fn mint_profile_target_fingerprint(observed: &TargetFingerprint, expected: &str) -> Result<String> {
    ensure!(
        observed.sha256 == expected,
        "refuse Mint because the dedicated target fingerprint changed: expected {expected}, observed {}",
        observed.sha256
    );
    Ok(format!("sha256:{}", observed.sha256))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_endpoint_matches_the_container_transport() {
        assert_eq!(
            mint_admin_endpoint("rustfs.example:9000", false).expect("HTTP endpoint"),
            "http://rustfs.example:9000"
        );
        assert_eq!(
            mint_admin_endpoint("https://rustfs.example:9000", true).expect("HTTPS endpoint"),
            "https://rustfs.example:9000"
        );
        assert!(mint_admin_endpoint("https://rustfs.example:9000", false).is_err());
        assert!(mint_admin_endpoint("", false).is_err());
    }

    #[test]
    fn profile_fingerprint_requires_the_live_server_identity_to_match() {
        let observed = TargetFingerprint::new(
            "http://rustfs.example:9000",
            "us-east-1",
            "deployment-id",
            Some("distributed".to_string()),
            Some("us-east-1".to_string()),
        )
        .expect("target fingerprint");

        assert_eq!(
            mint_profile_target_fingerprint(&observed, &observed.sha256)
                .expect("matching fingerprint"),
            format!("sha256:{}", observed.sha256)
        );
        assert!(mint_profile_target_fingerprint(&observed, "changed").is_err());
    }
}
