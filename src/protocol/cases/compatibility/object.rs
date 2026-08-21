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
    cases::{
        CaseContext,
        authz::{expect_error_class, expect_eventual_ok, expect_eventual_value},
    },
    fixture::{
        naming::ProtocolResourceNamer,
        registry::ResourceRegistry,
        resources::{create_s3_bucket, mark_object_prefix_created, plan_object_prefix},
    },
    ports::ProtocolS3Port,
    reporting::ProtocolAssertionClass,
};

pub(super) async fn run_put_get_delete(
    case_id: &str,
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    s3: &impl ProtocolS3Port,
    context: &mut CaseContext,
) -> Result<()> {
    let bucket = namer.bucket(case_id, 0)?;
    let bucket_fixture = create_s3_bucket(case_id, &bucket, registry, s3).await?;
    let key = format!("cases/{case_id}/object");
    let object_fixture = plan_object_prefix(case_id, &bucket, &bucket_fixture, registry)?;
    context.current_phase = "assertion".to_string();
    expect_eventual_ok(context, "admin", "put-object", &bucket, Some(&key), || {
        s3.put_object(&bucket, &key, b"bar")
    })
    .await?;
    mark_object_prefix_created(registry, &object_fixture)?;
    let body = expect_eventual_value(context, "admin", "get-object", &bucket, Some(&key), || {
        s3.get_object(&bucket, &key)
    })
    .await?;
    ensure!(
        body == b"bar",
        "object body changed after initial round trip"
    );
    expect_eventual_ok(
        context,
        "admin",
        "update-object",
        &bucket,
        Some(&key),
        || s3.put_object(&bucket, &key, b"soup"),
    )
    .await?;
    let updated = expect_eventual_value(
        context,
        "admin",
        "get-object-after-update",
        &bucket,
        Some(&key),
        || s3.get_object(&bucket, &key),
    )
    .await?;
    ensure!(
        updated == b"soup",
        "object update was not visible to a later read"
    );
    expect_eventual_ok(
        context,
        "admin",
        "delete-object",
        &bucket,
        Some(&key),
        || s3.delete_object(&bucket, &key),
    )
    .await?;
    expect_error_class(
        context,
        "admin",
        "get-object-after-delete",
        &bucket,
        ProtocolAssertionClass::NoSuchKey,
        || async { s3.get_object(&bucket, &key).await.map(|_| ()) },
    )
    .await
}

pub(super) async fn run_multi_object_delete(
    case_id: &str,
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    s3: &impl ProtocolS3Port,
    context: &mut CaseContext,
) -> Result<()> {
    let bucket = namer.bucket(case_id, 0)?;
    let bucket_fixture = create_s3_bucket(case_id, &bucket, registry, s3).await?;
    let object_fixture = plan_object_prefix(case_id, &bucket, &bucket_fixture, registry)?;
    let keys = (0..3)
        .map(|index| format!("cases/{case_id}/key{index}"))
        .collect::<Vec<_>>();
    context.current_phase = "assertion".to_string();
    for key in &keys {
        expect_eventual_ok(
            context,
            "admin",
            "put-delete-fixture",
            &bucket,
            Some(key),
            || s3.put_object(&bucket, key, key.as_bytes()),
        )
        .await?;
    }
    mark_object_prefix_created(registry, &object_fixture)?;
    for operation in ["delete-objects", "delete-objects-idempotent-retry"] {
        let mut deleted = expect_eventual_value(context, "admin", operation, &bucket, None, || {
            s3.delete_objects(&bucket, &keys)
        })
        .await?;
        deleted.sort();
        ensure!(
            deleted == keys,
            "{operation} did not report every requested key"
        );
        ensure!(
            s3.list_objects(&bucket).await?.is_empty(),
            "{operation} left objects in the bucket"
        );
    }
    Ok(())
}
