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

use anyhow::{Result, bail, ensure};
use std::time::{Duration, Instant};

use crate::protocol::{
    authorization::ProtocolAuthorizationDimensions,
    cases::CaseContext,
    ports::ProtocolS3Error,
    reporting::{ProtocolAssertion, ProtocolAssertionClass},
};

const PROPAGATION_TIMEOUT: Duration = Duration::from_secs(15);
const PROPAGATION_INTERVAL: Duration = Duration::from_millis(500);

pub(crate) async fn expect_access_denied<T, F, Fut>(
    context: &mut CaseContext,
    actor_id: &str,
    operation: &str,
    bucket: &str,
    object_key: Option<&str>,
    mut invoke: F,
) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = std::result::Result<T, ProtocolS3Error>>,
{
    let started = Instant::now();
    match invoke().await {
        Err(error) if error.is_access_denied() => {
            record(
                context,
                assertion(
                    context.dimensions,
                    actor_id,
                    operation,
                    bucket,
                    object_key,
                    ProtocolAssertionClass::AccessDenied,
                    ProtocolAssertionClass::AccessDenied,
                    Some(error),
                    0,
                    started.elapsed(),
                ),
            );
            Ok(())
        }
        Err(error) => {
            let actual = class_for_error(&error);
            record(
                context,
                assertion(
                    context.dimensions,
                    actor_id,
                    operation,
                    bucket,
                    object_key,
                    ProtocolAssertionClass::AccessDenied,
                    actual,
                    Some(error),
                    0,
                    started.elapsed(),
                ),
            );
            bail!("{operation}: expected AccessDenied, received {actual:?}")
        }
        Ok(_) => {
            record(
                context,
                assertion(
                    context.dimensions,
                    actor_id,
                    operation,
                    bucket,
                    object_key,
                    ProtocolAssertionClass::AccessDenied,
                    ProtocolAssertionClass::Ok,
                    None,
                    0,
                    started.elapsed(),
                ),
            );
            bail!("{operation}: operation unexpectedly succeeded")
        }
    }
}

pub(crate) async fn expect_eventual_access_denied<T, F, Fut>(
    context: &mut CaseContext,
    actor_id: &str,
    operation: &str,
    bucket: &str,
    object_key: Option<&str>,
    mut invoke: F,
) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = std::result::Result<T, ProtocolS3Error>>,
{
    let started = Instant::now();
    let mut retries = 0;
    loop {
        match invoke().await {
            Err(error) if error.is_access_denied() => {
                record(
                    context,
                    assertion(
                        context.dimensions,
                        actor_id,
                        operation,
                        bucket,
                        object_key,
                        ProtocolAssertionClass::AccessDenied,
                        ProtocolAssertionClass::AccessDenied,
                        Some(error),
                        retries,
                        started.elapsed(),
                    ),
                );
                return Ok(());
            }
            Ok(_) if started.elapsed() < PROPAGATION_TIMEOUT => {
                retries += 1;
                tokio::time::sleep(PROPAGATION_INTERVAL).await;
            }
            Ok(_) => {
                record(
                    context,
                    assertion(
                        context.dimensions,
                        actor_id,
                        operation,
                        bucket,
                        object_key,
                        ProtocolAssertionClass::AccessDenied,
                        ProtocolAssertionClass::Ok,
                        None,
                        retries,
                        started.elapsed(),
                    ),
                );
                bail!("{operation}: operation remained allowed after grant removal")
            }
            Err(error) => {
                let actual = class_for_error(&error);
                record(
                    context,
                    assertion(
                        context.dimensions,
                        actor_id,
                        operation,
                        bucket,
                        object_key,
                        ProtocolAssertionClass::AccessDenied,
                        actual,
                        Some(error),
                        retries,
                        started.elapsed(),
                    ),
                );
                bail!("{operation}: expected AccessDenied, received {actual:?}")
            }
        }
    }
}

pub(crate) async fn expect_error_class<F, Fut>(
    context: &mut CaseContext,
    actor_id: &str,
    operation: &str,
    bucket: &str,
    expected: ProtocolAssertionClass,
    mut invoke: F,
) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = std::result::Result<(), ProtocolS3Error>>,
{
    let started = Instant::now();
    match invoke().await {
        Err(error) => {
            let actual = class_for_error(&error);
            record(
                context,
                assertion(
                    context.dimensions,
                    actor_id,
                    operation,
                    bucket,
                    None,
                    expected,
                    actual,
                    Some(error),
                    0,
                    started.elapsed(),
                ),
            );
            ensure!(
                actual == expected,
                "{operation}: received unexpected error class {actual:?}"
            );
            Ok(())
        }
        Ok(()) => {
            record(
                context,
                assertion(
                    context.dimensions,
                    actor_id,
                    operation,
                    bucket,
                    None,
                    expected,
                    ProtocolAssertionClass::Ok,
                    None,
                    0,
                    started.elapsed(),
                ),
            );
            bail!("{operation}: expected error but operation succeeded")
        }
    }
}

pub(crate) async fn expect_eventual_ok<F, Fut>(
    context: &mut CaseContext,
    actor_id: &str,
    operation: &str,
    bucket: &str,
    object_key: Option<&str>,
    invoke: F,
) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = std::result::Result<(), ProtocolS3Error>>,
{
    expect_eventual_value(context, actor_id, operation, bucket, object_key, invoke).await
}

pub(crate) async fn expect_eventual_value<T, F, Fut>(
    context: &mut CaseContext,
    actor_id: &str,
    operation: &str,
    bucket: &str,
    object_key: Option<&str>,
    mut invoke: F,
) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = std::result::Result<T, ProtocolS3Error>>,
{
    let started = Instant::now();
    let mut retries = 0;
    loop {
        match invoke().await {
            Ok(value) => {
                record(
                    context,
                    assertion(
                        context.dimensions,
                        actor_id,
                        operation,
                        bucket,
                        object_key,
                        ProtocolAssertionClass::Ok,
                        ProtocolAssertionClass::Ok,
                        None,
                        retries,
                        started.elapsed(),
                    ),
                );
                return Ok(value);
            }
            Err(error) if error.is_access_denied() && started.elapsed() < PROPAGATION_TIMEOUT => {
                retries += 1;
                tokio::time::sleep(PROPAGATION_INTERVAL).await;
            }
            Err(error) => {
                let actual = class_for_error(&error);
                record(
                    context,
                    assertion(
                        context.dimensions,
                        actor_id,
                        operation,
                        bucket,
                        object_key,
                        ProtocolAssertionClass::Ok,
                        actual,
                        Some(error),
                        retries,
                        started.elapsed(),
                    ),
                );
                bail!("{operation}: expected success, received {actual:?}")
            }
        }
    }
}

fn record(context: &mut CaseContext, mut assertion: ProtocolAssertion) {
    assertion.phase.clone_from(&context.current_phase);
    context.assertions.push(assertion);
}

#[allow(clippy::too_many_arguments)]
fn assertion(
    dimensions: ProtocolAuthorizationDimensions,
    actor_id: &str,
    operation: &str,
    bucket: &str,
    object_key: Option<&str>,
    expected: ProtocolAssertionClass,
    actual: ProtocolAssertionClass,
    error: Option<ProtocolS3Error>,
    retry_count: usize,
    elapsed: Duration,
) -> ProtocolAssertion {
    ProtocolAssertion {
        actor_id: actor_id.to_string(),
        actor_source: dimensions.actor_source,
        grant_source: dimensions.grant_source,
        policy_effect: dimensions.policy_effect,
        operation: operation.to_string(),
        bucket: bucket.to_string(),
        object_key: object_key.map(str::to_string),
        expected,
        actual,
        raw_error_code: error.as_ref().map(|error| error.code.clone()),
        http_status: error.as_ref().and_then(|error| error.status),
        request_id: error.and_then(|error| error.request_id),
        retry_count,
        elapsed_millis: elapsed.as_millis(),
        phase: String::new(),
    }
}

fn class_for_error(error: &ProtocolS3Error) -> ProtocolAssertionClass {
    if error.is_access_denied() {
        ProtocolAssertionClass::AccessDenied
    } else {
        match error.code.as_str() {
            "NoSuchBucket" => ProtocolAssertionClass::NoSuchBucket,
            "NoSuchKey" | "NotFound" => ProtocolAssertionClass::NoSuchKey,
            "MalformedPolicy" => ProtocolAssertionClass::MalformedPolicy,
            "ExpiredToken" => ProtocolAssertionClass::ExpiredToken,
            "InvalidToken" | "InvalidClientTokenId" => ProtocolAssertionClass::InvalidToken,
            _ => ProtocolAssertionClass::HarnessError,
        }
    }
}
