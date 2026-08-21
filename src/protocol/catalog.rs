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

use serde::Serialize;

pub const BUCKET_POLICY_AUTHENTICATED_USER_RW: &str = "bucket-policy-authenticated-user-rw";
pub const BUCKET_POLICY_DELETE_RESTORES_PRIVATE: &str = "bucket-policy-delete-restores-private";
pub const BUCKET_POLICY_EXPLICIT_DENY_OVERRIDES_ALLOW: &str =
    "bucket-policy-explicit-deny-overrides-allow";
pub const BUCKET_POLICY_MALFORMED_POLICY_REJECTED: &str = "bucket-policy-malformed-policy-rejected";
pub const BUCKET_POLICY_PREFIX_SCOPE: &str = "bucket-policy-prefix-scope";
pub const COMPAT_BUCKET_LIST_CREATE_DELETE: &str = "compat-bucket-list-create-delete";
pub const COMPAT_BUCKET_HEAD: &str = "compat-bucket-head";
pub const COMPAT_LIST_OBJECTS_BASIC: &str = "compat-list-objects-basic";
pub const COMPAT_MULTIPART_UPLOAD_SMALL: &str = "compat-multipart-upload-small";
pub const COMPAT_MULTI_OBJECT_DELETE: &str = "compat-multi-object-delete";
pub const COMPAT_OBJECT_COPY_SAME_BUCKET: &str = "compat-object-copy-same-bucket";
pub const COMPAT_OBJECT_PUT_GET_DELETE: &str = "compat-object-put-get-delete";
pub const COMPAT_VERSIONING_HEAD_REMOVAL: &str = "compat-versioning-head-removal";
pub const IAM_EXPLICIT_DENY_OVERRIDES_ALLOW: &str = "iam-explicit-deny-overrides-allow";
pub const IAM_GROUP_POLICY: &str = "iam-group-policy";
pub const IAM_USER_MANAGED_POLICY_READONLY: &str = "iam-user-managed-policy-readonly";
pub const IAM_USER_MANAGED_POLICY_DETACH: &str = "iam-user-managed-policy-detach";
pub const OIDC_WEB_IDENTITY_BASIC: &str = "oidc-web-identity-basic";
pub const PUBLIC_ACCESS_BLOCK_ROUND_TRIP: &str = "public-access-block-round-trip";
pub const STS_ASSUME_ROLE_BASIC: &str = "sts-assume-role-basic";
pub const STS_EXPIRED_TOKEN_DENIED: &str = "sts-expired-token-denied";
pub const STS_SESSION_POLICY_DENY_PUT: &str = "sts-session-policy-deny-put";
pub const STS_SESSION_POLICY_NARROWS_ROLE: &str = "sts-session-policy-narrows-role";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtocolIsolation {
    Case,
    Group,
    Suite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolCase {
    pub id: &'static str,
    pub group: &'static str,
    pub tags: &'static [&'static str],
    pub isolation: ProtocolIsolation,
    pub requires: &'static [&'static str],
    pub serial: bool,
}

const CASES: &[ProtocolCase] = &[
    bucket_policy_case(
        BUCKET_POLICY_AUTHENTICATED_USER_RW,
        &["authz", "parallel-safe", "smoke"],
    ),
    bucket_policy_case(
        BUCKET_POLICY_DELETE_RESTORES_PRIVATE,
        &["authz", "parallel-safe", "regression"],
    ),
    bucket_policy_case(
        BUCKET_POLICY_EXPLICIT_DENY_OVERRIDES_ALLOW,
        &["authz", "parallel-safe", "regression"],
    ),
    bucket_policy_case(
        BUCKET_POLICY_MALFORMED_POLICY_REJECTED,
        &["authz", "negative", "parallel-safe", "regression"],
    ),
    bucket_policy_case(
        BUCKET_POLICY_PREFIX_SCOPE,
        &["authz", "parallel-safe", "regression"],
    ),
    compatibility_case(COMPAT_BUCKET_HEAD),
    compatibility_case(COMPAT_BUCKET_LIST_CREATE_DELETE),
    compatibility_case(COMPAT_LIST_OBJECTS_BASIC),
    compatibility_case(COMPAT_MULTI_OBJECT_DELETE),
    compatibility_case(COMPAT_MULTIPART_UPLOAD_SMALL),
    compatibility_case(COMPAT_OBJECT_COPY_SAME_BUCKET),
    compatibility_case(COMPAT_OBJECT_PUT_GET_DELETE),
    compatibility_versioning_case(),
    iam_case(
        IAM_EXPLICIT_DENY_OVERRIDES_ALLOW,
        "iam-user",
        &["authz", "regression"],
    ),
    iam_group_case(IAM_GROUP_POLICY, "iam-group", &["authz", "regression"]),
    iam_case(
        IAM_USER_MANAGED_POLICY_READONLY,
        "iam-user",
        &["authz", "regression"],
    ),
    iam_case(
        IAM_USER_MANAGED_POLICY_DETACH,
        "iam-policy",
        &["authz", "regression"],
    ),
    oidc_web_identity_case(),
    public_access_block_case(),
    sts_case(STS_ASSUME_ROLE_BASIC, "sts-assume-role"),
    sts_expiration_case(),
    sts_case(STS_SESSION_POLICY_DENY_PUT, "sts-session-policy"),
    sts_case(STS_SESSION_POLICY_NARROWS_ROLE, "sts-session-policy"),
];

const fn bucket_policy_case(id: &'static str, tags: &'static [&'static str]) -> ProtocolCase {
    ProtocolCase {
        id,
        group: "bucket-policy",
        tags,
        isolation: ProtocolIsolation::Case,
        requires: &["s3", "admin-api", "bucket-policy", "identity"],
        serial: false,
    }
}

const fn sts_case(id: &'static str, group: &'static str) -> ProtocolCase {
    ProtocolCase {
        id,
        group,
        tags: &["authz", "regression"],
        isolation: ProtocolIsolation::Case,
        requires: &["s3", "admin-api", "iam", "sts-assume-role"],
        serial: true,
    }
}

const fn sts_expiration_case() -> ProtocolCase {
    ProtocolCase {
        id: STS_EXPIRED_TOKEN_DENIED,
        group: "sts-session-policy",
        tags: &["authz", "regression", "slow"],
        isolation: ProtocolIsolation::Case,
        requires: &["s3", "admin-api", "iam", "sts-assume-role"],
        serial: true,
    }
}

const fn oidc_web_identity_case() -> ProtocolCase {
    ProtocolCase {
        id: OIDC_WEB_IDENTITY_BASIC,
        group: "oidc-web-identity",
        tags: &["authz", "integration", "oidc", "regression"],
        isolation: ProtocolIsolation::Case,
        requires: &[
            "s3",
            "admin-api",
            "iam",
            "sts-web-identity",
            "oidc",
            "external-idp",
        ],
        serial: true,
    }
}

const fn compatibility_case(id: &'static str) -> ProtocolCase {
    ProtocolCase {
        id,
        group: "s3-compatibility",
        tags: &["ceph-style", "compatibility", "parallel-safe"],
        isolation: ProtocolIsolation::Case,
        requires: &["s3"],
        serial: false,
    }
}

const fn compatibility_versioning_case() -> ProtocolCase {
    ProtocolCase {
        id: COMPAT_VERSIONING_HEAD_REMOVAL,
        group: "s3-compatibility",
        tags: &["ceph-style", "compatibility", "parallel-safe", "versioning"],
        isolation: ProtocolIsolation::Case,
        requires: &["s3", "versioning"],
        serial: false,
    }
}

const fn public_access_block_case() -> ProtocolCase {
    ProtocolCase {
        id: PUBLIC_ACCESS_BLOCK_ROUND_TRIP,
        group: "public-access-block",
        tags: &["compatibility", "parallel-safe", "regression"],
        isolation: ProtocolIsolation::Case,
        requires: &["s3", "public-access-block"],
        serial: false,
    }
}

const fn iam_case(
    id: &'static str,
    group: &'static str,
    tags: &'static [&'static str],
) -> ProtocolCase {
    ProtocolCase {
        id,
        group,
        tags,
        isolation: ProtocolIsolation::Case,
        requires: &["s3", "admin-api", "iam"],
        serial: true,
    }
}

const fn iam_group_case(
    id: &'static str,
    group: &'static str,
    tags: &'static [&'static str],
) -> ProtocolCase {
    ProtocolCase {
        id,
        group,
        tags,
        isolation: ProtocolIsolation::Case,
        requires: &["s3", "admin-api", "iam", "iam-group"],
        serial: true,
    }
}

pub fn protocol_case_catalog() -> &'static [ProtocolCase] {
    CASES
}

pub fn protocol_case(id: &str) -> Option<&'static ProtocolCase> {
    CASES.iter().find(|case| case.id == id)
}

pub fn protocol_catalog_json() -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(CASES)?)
}

#[cfg(test)]
mod tests {
    use super::{
        BUCKET_POLICY_AUTHENTICATED_USER_RW, BUCKET_POLICY_DELETE_RESTORES_PRIVATE,
        BUCKET_POLICY_EXPLICIT_DENY_OVERRIDES_ALLOW, BUCKET_POLICY_MALFORMED_POLICY_REJECTED,
        BUCKET_POLICY_PREFIX_SCOPE, COMPAT_BUCKET_HEAD, COMPAT_BUCKET_LIST_CREATE_DELETE,
        COMPAT_LIST_OBJECTS_BASIC, COMPAT_MULTI_OBJECT_DELETE, COMPAT_MULTIPART_UPLOAD_SMALL,
        COMPAT_OBJECT_COPY_SAME_BUCKET, COMPAT_OBJECT_PUT_GET_DELETE,
        COMPAT_VERSIONING_HEAD_REMOVAL, IAM_EXPLICIT_DENY_OVERRIDES_ALLOW, IAM_GROUP_POLICY,
        IAM_USER_MANAGED_POLICY_DETACH, IAM_USER_MANAGED_POLICY_READONLY, OIDC_WEB_IDENTITY_BASIC,
        PUBLIC_ACCESS_BLOCK_ROUND_TRIP, STS_ASSUME_ROLE_BASIC, STS_EXPIRED_TOKEN_DENIED,
        STS_SESSION_POLICY_DENY_PUT, STS_SESSION_POLICY_NARROWS_ROLE, protocol_case_catalog,
    };
    use std::collections::BTreeSet;

    #[test]
    fn catalog_ids_are_unique_and_sorted() {
        let catalog = protocol_case_catalog();
        let ids = catalog.iter().map(|case| case.id).collect::<Vec<_>>();
        assert_eq!(
            ids,
            vec![
                BUCKET_POLICY_AUTHENTICATED_USER_RW,
                BUCKET_POLICY_DELETE_RESTORES_PRIVATE,
                BUCKET_POLICY_EXPLICIT_DENY_OVERRIDES_ALLOW,
                BUCKET_POLICY_MALFORMED_POLICY_REJECTED,
                BUCKET_POLICY_PREFIX_SCOPE,
                COMPAT_BUCKET_HEAD,
                COMPAT_BUCKET_LIST_CREATE_DELETE,
                COMPAT_LIST_OBJECTS_BASIC,
                COMPAT_MULTI_OBJECT_DELETE,
                COMPAT_MULTIPART_UPLOAD_SMALL,
                COMPAT_OBJECT_COPY_SAME_BUCKET,
                COMPAT_OBJECT_PUT_GET_DELETE,
                COMPAT_VERSIONING_HEAD_REMOVAL,
                IAM_EXPLICIT_DENY_OVERRIDES_ALLOW,
                IAM_GROUP_POLICY,
                IAM_USER_MANAGED_POLICY_READONLY,
                IAM_USER_MANAGED_POLICY_DETACH,
                OIDC_WEB_IDENTITY_BASIC,
                PUBLIC_ACCESS_BLOCK_ROUND_TRIP,
                STS_ASSUME_ROLE_BASIC,
                STS_EXPIRED_TOKEN_DENIED,
                STS_SESSION_POLICY_DENY_PUT,
                STS_SESSION_POLICY_NARROWS_ROLE,
            ]
        );
        assert_eq!(ids.len(), ids.iter().collect::<BTreeSet<_>>().len());
    }

    #[test]
    fn bucket_policy_declares_identity_without_full_iam_management() {
        let case = super::protocol_case(BUCKET_POLICY_AUTHENTICATED_USER_RW).expect("case");
        assert!(case.requires.contains(&"identity"));
        assert!(!case.requires.contains(&"iam"));
    }

    #[test]
    fn only_group_case_declares_group_management() {
        for case in protocol_case_catalog() {
            assert_eq!(
                case.requires.contains(&"iam-group"),
                case.id == IAM_GROUP_POLICY,
                "{} has an incorrect iam-group capability",
                case.id
            );
        }
    }

    #[test]
    fn oidc_and_signed_sts_declare_distinct_exchange_capabilities() {
        let oidc = super::protocol_case(OIDC_WEB_IDENTITY_BASIC).expect("OIDC case");
        assert!(oidc.requires.contains(&"sts-web-identity"));
        assert!(!oidc.requires.contains(&"sts-assume-role"));

        for id in [
            STS_ASSUME_ROLE_BASIC,
            STS_EXPIRED_TOKEN_DENIED,
            STS_SESSION_POLICY_DENY_PUT,
            STS_SESSION_POLICY_NARROWS_ROLE,
        ] {
            let case = super::protocol_case(id).expect("STS case");
            assert!(case.requires.contains(&"sts-assume-role"));
            assert!(!case.requires.contains(&"sts-web-identity"));
        }
    }
}
