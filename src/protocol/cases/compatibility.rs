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

mod bucket;
mod bucket_config;
mod copy;
mod listing;
mod multipart;
mod object;
mod versioning;

use anyhow::anyhow;

use crate::protocol::{
    authorization::{
        ProtocolActorSource, ProtocolAuthorizationDimensions, ProtocolGrantSource,
        ProtocolPolicyEffect,
    },
    cases::{CaseContext, ProtocolCaseExecution},
    catalog::{
        COMPAT_BUCKET_HEAD, COMPAT_BUCKET_LIST_CREATE_DELETE, COMPAT_LIST_OBJECTS_BASIC,
        COMPAT_MULTI_OBJECT_DELETE, COMPAT_MULTIPART_UPLOAD_SMALL, COMPAT_OBJECT_COPY_SAME_BUCKET,
        COMPAT_OBJECT_PUT_GET_DELETE, COMPAT_VERSIONING_HEAD_REMOVAL,
        PUBLIC_ACCESS_BLOCK_ROUND_TRIP,
    },
    fixture::{naming::ProtocolResourceNamer, registry::ResourceRegistry},
    ports::ProtocolS3CompatibilityPorts,
};

pub(crate) async fn run_compatibility_case(
    case_id: &str,
    namer: &ProtocolResourceNamer,
    registry: &mut ResourceRegistry,
    s3: &impl ProtocolS3CompatibilityPorts,
) -> ProtocolCaseExecution {
    let mut context = CaseContext::new(
        case_id,
        ProtocolAuthorizationDimensions {
            actor_source: ProtocolActorSource::Admin,
            grant_source: ProtocolGrantSource::AdminCredential,
            policy_effect: ProtocolPolicyEffect::Allow,
        },
    );
    let result = match case_id {
        COMPAT_BUCKET_HEAD => bucket::run_head(case_id, namer, registry, s3, &mut context).await,
        COMPAT_BUCKET_LIST_CREATE_DELETE => {
            bucket::run_list_create_delete(case_id, namer, registry, s3, &mut context).await
        }
        COMPAT_LIST_OBJECTS_BASIC => {
            listing::run_objects_v2(case_id, namer, registry, s3, &mut context).await
        }
        COMPAT_MULTI_OBJECT_DELETE => {
            object::run_multi_object_delete(case_id, namer, registry, s3, &mut context).await
        }
        COMPAT_MULTIPART_UPLOAD_SMALL => {
            multipart::run_upload(case_id, namer, registry, s3, &mut context).await
        }
        COMPAT_OBJECT_COPY_SAME_BUCKET => {
            copy::run_copy_object(case_id, namer, registry, s3, &mut context).await
        }
        COMPAT_OBJECT_PUT_GET_DELETE => {
            object::run_put_get_delete(case_id, namer, registry, s3, &mut context).await
        }
        COMPAT_VERSIONING_HEAD_REMOVAL => {
            versioning::run_head_removal(case_id, namer, registry, s3, &mut context).await
        }
        PUBLIC_ACCESS_BLOCK_ROUND_TRIP => {
            bucket_config::run_public_access_block(case_id, namer, registry, s3, &mut context).await
        }
        _ => Err(anyhow!("unsupported compatibility case {case_id}")),
    };
    context.finish(result)
}

#[cfg(test)]
mod tests;
