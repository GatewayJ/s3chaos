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
    cases::{CaseContext, authz::expect_eventual_ok},
    fixture::{
        naming::ProtocolResourceNamer,
        registry::ResourceRegistry,
        resources::{
            create_s3_bucket, enable_versioned_cleanup, mark_object_prefix_created,
            plan_object_prefix,
        },
    },
    ports::{ProtocolBucketPort, ProtocolObjectPort, ProtocolVersioningPort},
};

pub(super) async fn run_head_removal(
    case_id: &str,
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    s3: &(impl ProtocolBucketPort + ProtocolObjectPort + ProtocolVersioningPort),
    context: &mut CaseContext,
) -> Result<()> {
    enable_versioned_cleanup(registry)?;
    let bucket = namer.bucket(case_id, 0)?;
    let bucket_fixture = create_s3_bucket(case_id, &bucket, registry, s3).await?;
    context.current_phase = "assertion".to_string();
    expect_eventual_ok(
        context,
        "admin",
        "enable-bucket-versioning",
        &bucket,
        None,
        || s3.put_bucket_versioning(&bucket, true),
    )
    .await?;
    let key = format!("cases/{case_id}/testobj");
    let object_fixture = plan_object_prefix(case_id, &bucket, &bucket_fixture, registry)?;
    for index in 0..5 {
        s3.put_object(&bucket, &key, format!("version-{index}").as_bytes())
            .await?;
    }
    mark_object_prefix_created(registry, &object_fixture)?;
    let versions = s3
        .list_object_versions(&bucket)
        .await?
        .into_iter()
        .filter(|version| version.key == key && !version.delete_marker)
        .collect::<Vec<_>>();
    ensure!(versions.len() == 5, "expected five object versions");
    let mut latest_version_id = None;
    for version in &versions {
        if s3
            .get_object_version(&bucket, &key, &version.version_id)
            .await?
            == b"version-4"
        {
            latest_version_id = Some(version.version_id.clone());
        }
    }
    let latest_version_id = latest_version_id.context("latest object version was not found")?;
    s3.delete_object_version(&bucket, &key, &latest_version_id)
        .await?;
    ensure!(
        s3.get_object(&bucket, &key).await? == b"version-3",
        "deleting the latest version did not expose its predecessor"
    );
    s3.delete_object(&bucket, &key).await?;
    let after_delete = s3.list_object_versions(&bucket).await?;
    ensure!(
        after_delete
            .iter()
            .filter(|version| version.key == key && !version.delete_marker)
            .count()
            == 4,
        "version delete changed the remaining version count"
    );
    ensure!(
        after_delete
            .iter()
            .filter(|version| version.key == key && version.delete_marker)
            .count()
            == 1,
        "deleting the current object did not create exactly one delete marker"
    );
    Ok(())
}
