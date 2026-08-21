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
        naming::ProtocolResourceNamer,
        registry::ResourceRegistry,
        resources::{create_s3_bucket, mark_object_prefix_created, plan_object_prefix},
    },
    ports::{ProtocolBucketPort, ProtocolListingPort, ProtocolObjectPort},
};

pub(super) async fn run_objects_v2(
    case_id: &str,
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    s3: &(impl ProtocolBucketPort + ProtocolListingPort + ProtocolObjectPort),
    context: &mut CaseContext,
) -> Result<()> {
    let bucket = namer.bucket(case_id, 0)?;
    let bucket_fixture = create_s3_bucket(case_id, &bucket, registry, s3).await?;
    let object_fixture = plan_object_prefix(case_id, &bucket, &bucket_fixture, registry)?;
    let keys = (0..5)
        .map(|index| format!("cases/{case_id}/{index}"))
        .collect::<Vec<_>>();
    context.current_phase = "assertion".to_string();
    for key in &keys {
        expect_eventual_ok(
            context,
            "admin",
            "put-list-fixture",
            &bucket,
            Some(key),
            || s3.put_object(&bucket, key, key.as_bytes()),
        )
        .await?;
    }
    mark_object_prefix_created(registry, &object_fixture)?;
    let mut listing = expect_eventual_value(
        context,
        "admin",
        "list-objects-with-key-count",
        &bucket,
        None,
        || s3.list_objects_v2_summary(&bucket),
    )
    .await?;
    listing.keys.sort();
    ensure!(
        listing.key_count == 5,
        "ListObjectsV2 returned KeyCount={} instead of 5",
        listing.key_count
    );
    ensure!(
        listing.keys == keys,
        "ListObjectsV2 returned an unexpected key set"
    );
    Ok(())
}
