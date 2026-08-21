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
        resources::{
            create_multipart_upload, create_s3_bucket, mark_multipart_upload_completed,
            mark_object_prefix_created, plan_object_prefix,
        },
    },
    ports::{ProtocolCompletedPart, ProtocolS3Port},
};

pub(super) async fn run_upload(
    case_id: &str,
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    s3: &impl ProtocolS3Port,
    context: &mut CaseContext,
) -> Result<()> {
    let bucket = namer.bucket(case_id, 0)?;
    let bucket_fixture = create_s3_bucket(case_id, &bucket, registry, s3).await?;
    let key = format!("cases/{case_id}/mymultipart");
    let object_fixture = plan_object_prefix(case_id, &bucket, &bucket_fixture, registry)?;
    let upload_fixture =
        create_multipart_upload(case_id, &bucket, &key, &bucket_fixture, registry, s3).await?;
    let etag = s3
        .upload_part(&bucket, &key, &upload_fixture.upload_id, 1, b"x")
        .await?;
    let parts = [ProtocolCompletedPart {
        part_number: 1,
        etag,
    }];
    context.current_phase = "assertion".to_string();
    expect_eventual_ok(
        context,
        "admin",
        "complete-multipart-upload",
        &bucket,
        Some(&key),
        || s3.complete_multipart_upload(&bucket, &key, &upload_fixture.upload_id, &parts),
    )
    .await?;
    expect_eventual_ok(
        context,
        "admin",
        "complete-multipart-upload-idempotent-retry",
        &bucket,
        Some(&key),
        || s3.complete_multipart_upload(&bucket, &key, &upload_fixture.upload_id, &parts),
    )
    .await?;
    mark_multipart_upload_completed(registry, &upload_fixture)?;
    mark_object_prefix_created(registry, &object_fixture)?;
    let body = expect_eventual_value(
        context,
        "admin",
        "get-completed-multipart-object",
        &bucket,
        Some(&key),
        || s3.get_object(&bucket, &key),
    )
    .await?;
    ensure!(
        body == b"x",
        "completed multipart object body was incorrect"
    );
    Ok(())
}
