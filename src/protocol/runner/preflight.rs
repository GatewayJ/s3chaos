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

use anyhow::{Result, ensure};

use crate::protocol::{
    ports::ProtocolExternalIdentityPort,
    preflight::{
        ProtocolPreflightSummary, enforce_stale_resource_policy,
        preflight_protocol_suite_with_external,
    },
    runner::runtime::ConnectedProtocolRuntime,
};

/// Runs target inspection after the composition root has built its adapters.
/// Connection remains construction-only; preflight policy stays in its own use
/// case and can fail without changing adapter construction semantics.
pub(crate) async fn run_connected_preflight(
    runtime: &ConnectedProtocolRuntime,
) -> Result<ProtocolPreflightSummary> {
    let preflight = preflight_protocol_suite_with_external(
        &runtime.suite,
        &runtime.endpoint,
        &runtime.admin,
        &runtime.s3,
        runtime
            .external_identity
            .as_ref()
            .map(|provider| provider as &dyn ProtocolExternalIdentityPort),
        stale_resource_policy()?,
    )
    .await?;
    enforce_stale_resource_policy(&preflight)?;
    Ok(preflight)
}

fn stale_resource_policy() -> Result<&'static str> {
    if std::env::var("RUSTFS_PROTOCOL_TEST_ALLOW_STALE").as_deref() == Ok("1") {
        ensure!(
            std::env::var("CI").is_err(),
            "RUSTFS_PROTOCOL_TEST_ALLOW_STALE is forbidden in CI"
        );
        Ok("warn-local-debug")
    } else {
        Ok("fail")
    }
}
