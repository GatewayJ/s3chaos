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
use std::time::Duration;
use tokio::time::Instant;

use crate::protocol::{
    authorization::ProtocolAuthorizationDimensions,
    cases::CaseContext,
    ports::ProtocolS3Error,
    reporting::{
        ProtocolAssertion, ProtocolAssertionClass, ProtocolEventualConsistencyObservation,
    },
    runner::retry::{eventual_consistency_policy, wait_for_eventual_retry},
};

fn propagation_timeout() -> Duration {
    Duration::from_millis(eventual_consistency_policy().deadline_millis)
}

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
                record_eventual(
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
            Ok(_) if started.elapsed() < propagation_timeout() => {
                retries += 1;
                wait_for_eventual_retry().await;
            }
            Ok(_) => {
                record_eventual(
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
                record_eventual(
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
                record_eventual(
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
            Err(error)
                if is_transient_propagation_error(context, &error)
                    && started.elapsed() < propagation_timeout() =>
            {
                retries += 1;
                wait_for_eventual_retry().await;
            }
            Err(error) => {
                let actual = class_for_error(&error);
                record_eventual(
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

fn is_transient_propagation_error(context: &CaseContext, error: &ProtocolS3Error) -> bool {
    error.is_access_denied()
        || (context.current_phase == "propagation"
            && matches!(
                context.dimensions.actor_source,
                crate::protocol::authorization::ProtocolActorSource::AssumedRole
                    | crate::protocol::authorization::ProtocolActorSource::StsSession
            )
            && matches!(error.code.as_str(), "InvalidClientTokenId" | "InvalidToken"))
}

fn record(context: &mut CaseContext, mut assertion: ProtocolAssertion) {
    assertion.phase.clone_from(&context.current_phase);
    context.assertions.push(assertion);
}

fn record_eventual(context: &mut CaseContext, mut assertion: ProtocolAssertion) {
    let policy = eventual_consistency_policy();
    assertion.eventual_consistency = Some(ProtocolEventualConsistencyObservation {
        deadline_millis: policy.deadline_millis,
        interval_millis: policy.interval_millis,
        last_observed: format!("{:?}", assertion.actual),
    });
    record(context, assertion);
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
        eventual_consistency: None,
    }
}

fn class_for_error(error: &ProtocolS3Error) -> ProtocolAssertionClass {
    if error.is_access_denied() {
        ProtocolAssertionClass::AccessDenied
    } else {
        match error.code.as_str() {
            "NoSuchBucket" => ProtocolAssertionClass::NoSuchBucket,
            "NoSuchBucketPolicy" => ProtocolAssertionClass::NoSuchBucketPolicy,
            "NoSuchPublicAccessBlockConfiguration" => {
                ProtocolAssertionClass::NoSuchPublicAccessBlockConfiguration
            }
            "NoSuchKey" | "NotFound" => ProtocolAssertionClass::NoSuchKey,
            "MalformedPolicy" => ProtocolAssertionClass::MalformedPolicy,
            "ExpiredToken" => ProtocolAssertionClass::ExpiredToken,
            "InvalidToken" | "InvalidClientTokenId" => ProtocolAssertionClass::InvalidToken,
            _ => ProtocolAssertionClass::HarnessError,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::expect_eventual_ok;
    use crate::protocol::{
        authorization::{
            ProtocolActorSource, ProtocolAuthorizationDimensions, ProtocolGrantSource,
            ProtocolPolicyEffect,
        },
        cases::CaseContext,
        ports::ProtocolS3Error,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test(start_paused = true)]
    async fn retries_invalid_client_token_during_sts_propagation() {
        let mut context = CaseContext::new(
            "sts-propagation",
            ProtocolAuthorizationDimensions {
                actor_source: ProtocolActorSource::StsSession,
                grant_source: ProtocolGrantSource::ManagedPolicy,
                policy_effect: ProtocolPolicyEffect::Allow,
            },
        );
        context.current_phase = "propagation".to_string();
        let calls = AtomicUsize::new(0);

        expect_eventual_ok(
            &mut context,
            "sts-session",
            "get-object",
            "bucket",
            Some("key"),
            || async {
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    Err(ProtocolS3Error {
                        code: "InvalidClientTokenId".to_string(),
                        status: Some(403),
                        request_id: None,
                    })
                } else {
                    Ok(())
                }
            },
        )
        .await
        .expect("transient STS credential propagation should be retried");

        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(context.assertions[0].retry_count, 1);
        let observation = context.assertions[0]
            .eventual_consistency
            .as_ref()
            .expect("eventual consistency observation");
        assert_eq!(observation.deadline_millis, 15_000);
        assert_eq!(observation.interval_millis, 500);
        assert_eq!(observation.last_observed, "Ok");
    }
}
