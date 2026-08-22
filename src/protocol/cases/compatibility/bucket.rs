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
        authz::{expect_eventual_ok, expect_eventual_value},
    },
    fixture::{
        naming::ProtocolResourceNamer, registry::ResourceRegistry, resources::create_s3_bucket,
    },
    ports::{ProtocolBucketPort, ProtocolListingPort},
};

pub(super) async fn run_head(
    case_id: &str,
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    s3: &impl ProtocolBucketPort,
    context: &mut CaseContext,
) -> Result<()> {
    let bucket = namer.bucket(case_id, 0)?;
    create_s3_bucket(case_id, &bucket, registry, s3).await?;
    context.current_phase = "assertion".to_string();
    expect_eventual_ok(context, "admin", "head-bucket", &bucket, None, || {
        s3.head_bucket(&bucket)
    })
    .await
}

pub(super) async fn run_list_create_delete(
    case_id: &str,
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    s3: &(impl ProtocolBucketPort + ProtocolListingPort),
    context: &mut CaseContext,
) -> Result<()> {
    let bucket = namer.bucket(case_id, 0)?;
    context.current_phase = "assertion".to_string();
    let before = expect_eventual_value(
        context,
        "admin",
        "list-buckets-before-create",
        &bucket,
        None,
        || s3.list_buckets_with_prefix(&bucket),
    )
    .await?;
    ensure!(
        before.is_empty(),
        "bucket unexpectedly existed before create"
    );

    context.current_phase = "setup".to_string();
    create_s3_bucket(case_id, &bucket, registry, s3).await?;
    context.current_phase = "assertion".to_string();
    let after = expect_eventual_value(
        context,
        "admin",
        "list-buckets-after-create",
        &bucket,
        None,
        || s3.list_buckets_with_prefix(&bucket),
    )
    .await?;
    ensure!(
        after == [bucket.as_str()],
        "created bucket was not listed exactly once"
    );
    let listing =
        expect_eventual_value(context, "admin", "list-empty-bucket", &bucket, None, || {
            s3.list_objects_v2_summary(&bucket)
        })
        .await?;
    ensure!(
        listing.keys.is_empty() && listing.key_count == 0,
        "new bucket returned objects or a non-zero KeyCount"
    );
    Ok(())
}
