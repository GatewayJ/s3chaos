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
        authz::{expect_error_class, expect_eventual_value},
    },
    fixture::{
        naming::ProtocolResourceNamer,
        registry::ResourceRegistry,
        resources::{create_public_access_block, create_s3_bucket, delete_public_access_block},
    },
    ports::{ProtocolBucketConfigPort, ProtocolBucketPort, ProtocolPublicAccessBlock},
    reporting::ProtocolAssertionClass,
};

pub(super) async fn run_public_access_block(
    case_id: &str,
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    s3: &(impl ProtocolBucketConfigPort + ProtocolBucketPort),
    context: &mut CaseContext,
) -> Result<()> {
    let bucket = namer.bucket(case_id, 0)?;
    let bucket_fixture = create_s3_bucket(case_id, &bucket, registry, s3).await?;
    let configuration = ProtocolPublicAccessBlock {
        block_public_acls: true,
        ignore_public_acls: true,
        block_public_policy: true,
        restrict_public_buckets: false,
    };
    let public_access_block = create_public_access_block(
        case_id,
        &bucket,
        configuration,
        &bucket_fixture,
        registry,
        s3,
    )
    .await?;
    context.current_phase = "assertion".to_string();
    let actual = expect_eventual_value(
        context,
        "admin",
        "get-public-access-block",
        &bucket,
        None,
        || s3.get_public_access_block(&bucket),
    )
    .await?;
    ensure!(
        actual == configuration,
        "public access block changed during round trip"
    );
    delete_public_access_block(&bucket, &public_access_block, registry, s3).await?;
    expect_error_class(
        context,
        "admin",
        "get-public-access-block-after-delete",
        &bucket,
        ProtocolAssertionClass::NoSuchPublicAccessBlockConfiguration,
        || async { s3.get_public_access_block(&bucket).await.map(|_| ()) },
    )
    .await
}
