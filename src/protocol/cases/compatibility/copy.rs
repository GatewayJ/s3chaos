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
    ports::ProtocolS3Port,
};

pub(super) async fn run_copy_object(
    case_id: &str,
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    s3: &impl ProtocolS3Port,
    context: &mut CaseContext,
) -> Result<()> {
    let bucket = namer.bucket(case_id, 0)?;
    let bucket_fixture = create_s3_bucket(case_id, &bucket, registry, s3).await?;
    let object_fixture = plan_object_prefix(case_id, &bucket, &bucket_fixture, registry)?;
    let source = format!("cases/{case_id}/foo123bar");
    let destination = format!("cases/{case_id}/bar321foo");
    context.current_phase = "assertion".to_string();
    expect_eventual_ok(
        context,
        "admin",
        "put-copy-source",
        &bucket,
        Some(&source),
        || s3.put_object(&bucket, &source, b"foo"),
    )
    .await?;
    expect_eventual_ok(
        context,
        "admin",
        "copy-object-same-bucket",
        &bucket,
        Some(&destination),
        || s3.copy_object(&bucket, &source, &destination),
    )
    .await?;
    mark_object_prefix_created(registry, &object_fixture)?;
    let copied = expect_eventual_value(
        context,
        "admin",
        "get-copied-object",
        &bucket,
        Some(&destination),
        || s3.get_object(&bucket, &destination),
    )
    .await?;
    ensure!(copied == b"foo", "same-bucket copy changed the object body");
    Ok(())
}
