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

use std::{collections::BTreeSet, fmt, sync::OnceLock};

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

mod authorization_descriptors;
mod bucket_config_descriptors;
mod compatibility_descriptors;
mod iam_descriptors;
mod sts_descriptors;

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

pub const DEFAULT_PROTOCOL_VARIANT: &str = "default";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ProtocolCaseId(&'static str);

impl ProtocolCaseId {
    pub const fn new(value: &'static str) -> Self {
        Self(value)
    }

    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for ProtocolCaseId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl PartialEq<&str> for ProtocolCaseId {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ProtocolVariantId(&'static str);

impl ProtocolVariantId {
    pub const fn new(value: &'static str) -> Self {
        Self(value)
    }

    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for ProtocolVariantId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtocolCapability {
    S3,
    AdminApi,
    BucketPolicy,
    Identity,
    Iam,
    IamGroup,
    StsAssumeRole,
    StsWebIdentity,
    Oidc,
    ExternalIdp,
    Versioning,
    PublicAccessBlock,
    Kms,
    Sns,
}

impl ProtocolCapability {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::S3 => "s3",
            Self::AdminApi => "admin-api",
            Self::BucketPolicy => "bucket-policy",
            Self::Identity => "identity",
            Self::Iam => "iam",
            Self::IamGroup => "iam-group",
            Self::StsAssumeRole => "sts-assume-role",
            Self::StsWebIdentity => "sts-web-identity",
            Self::Oidc => "oidc",
            Self::ExternalIdp => "external-idp",
            Self::Versioning => "versioning",
            Self::PublicAccessBlock => "public-access-block",
            Self::Kms => "kms",
            Self::Sns => "sns",
        }
    }
}

impl fmt::Display for ProtocolCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtocolCapabilitySource {
    BuiltIn,
    External,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtocolCapabilityState {
    Pass,
    Skip,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolCapabilityCheck {
    pub capability: ProtocolCapability,
    pub source: ProtocolCapabilitySource,
    pub state: ProtocolCapabilityState,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtocolExecutor {
    BucketPolicy,
    Compatibility,
    Iam,
    Sts,
    OidcWebIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtocolLockResource {
    Tenant,
    Bucket,
    Identity,
    Kms,
    Sns,
    ExternalIdp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtocolLockMode {
    Shared,
    Exclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolLockRequirement {
    pub resource: ProtocolLockResource,
    pub mode: ProtocolLockMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtocolResourceOwnership {
    ExclusiveBucket,
    SharedBucketPrefix,
    SharedBucketKey,
    SharedObjectVersion,
    ExactMultipartUpload,
    IdentityPrefix,
    ExternalIdentity,
    ExternalResource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtocolCleanupScope {
    OwnedBucket,
    BucketPolicy,
    BucketConfiguration,
    ObjectPrefix,
    ObjectKey,
    ObjectVersion,
    MultipartUpload,
    Identity,
    StsSession,
    ExternalIdentity,
    ExternalResource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
pub enum ProtocolExpectedOutcome {
    Success,
    S3Error {
        http_status: u16,
        error_code: &'static str,
    },
    Transport {
        outcome: &'static str,
    },
    ExpectedDivergence {
        issue: &'static str,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolVariant {
    pub id: ProtocolVariantId,
    /// The single discriminating protocol result for this variant. A `Success` value describes
    /// the protocol operation, not merely successful completion of the Rust test function.
    pub expected: ProtocolExpectedOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtocolIsolation {
    Case,
    Group,
    Suite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtocolDomain {
    Bucket,
    Object,
    Listing,
    CopyDelete,
    Multipart,
    Versioning,
    BucketConfig,
    IntegrityEncryption,
    Authorization,
    Iam,
    Sts,
    S3Select,
    Notification,
    RequestValidation,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolCase {
    pub id: ProtocolCaseId,
    pub domain: ProtocolDomain,
    pub group: &'static str,
    pub tags: &'static [&'static str],
    pub isolation: ProtocolIsolation,
    #[serde(rename = "requires")]
    pub capabilities: &'static [ProtocolCapability],
    pub serial: bool,
    pub executor: ProtocolExecutor,
    pub lock_requirements: &'static [ProtocolLockRequirement],
    pub ownership: &'static [ProtocolResourceOwnership],
    pub cleanup_scopes: &'static [ProtocolCleanupScope],
    pub variants: &'static [ProtocolVariant],
}

impl ProtocolCase {
    pub fn has_capability(&self, capability: ProtocolCapability) -> bool {
        self.capabilities.contains(&capability)
    }

    pub fn variant(&self, id: &str) -> Option<&ProtocolVariant> {
        self.variants
            .iter()
            .find(|variant| variant.id.as_str() == id)
    }

    pub fn default_variant(&self) -> &ProtocolVariant {
        &self.variants[0]
    }
}

const DEFAULT_SUCCESS_VARIANTS: &[ProtocolVariant] = &[ProtocolVariant {
    id: ProtocolVariantId::new(DEFAULT_PROTOCOL_VARIANT),
    expected: ProtocolExpectedOutcome::Success,
}];
const ACCESS_DENIED_VARIANTS: &[ProtocolVariant] = &[ProtocolVariant {
    id: ProtocolVariantId::new(DEFAULT_PROTOCOL_VARIANT),
    expected: ProtocolExpectedOutcome::S3Error {
        http_status: 403,
        error_code: "AccessDenied",
    },
}];
const MALFORMED_POLICY_VARIANTS: &[ProtocolVariant] = &[ProtocolVariant {
    id: ProtocolVariantId::new(DEFAULT_PROTOCOL_VARIANT),
    expected: ProtocolExpectedOutcome::S3Error {
        http_status: 400,
        error_code: "MalformedPolicy",
    },
}];
const EXPIRED_TOKEN_VARIANTS: &[ProtocolVariant] = &[ProtocolVariant {
    id: ProtocolVariantId::new(DEFAULT_PROTOCOL_VARIANT),
    expected: ProtocolExpectedOutcome::S3Error {
        http_status: 403,
        error_code: "ExpiredToken",
    },
}];
const NO_SUCH_KEY_VARIANTS: &[ProtocolVariant] = &[ProtocolVariant {
    id: ProtocolVariantId::new(DEFAULT_PROTOCOL_VARIANT),
    expected: ProtocolExpectedOutcome::S3Error {
        http_status: 404,
        error_code: "NoSuchKey",
    },
}];
const NO_SUCH_PUBLIC_ACCESS_BLOCK_VARIANTS: &[ProtocolVariant] = &[ProtocolVariant {
    id: ProtocolVariantId::new(DEFAULT_PROTOCOL_VARIANT),
    expected: ProtocolExpectedOutcome::S3Error {
        http_status: 404,
        error_code: "NoSuchPublicAccessBlockConfiguration",
    },
}];
const BUCKET_EXCLUSIVE_LOCKS: &[ProtocolLockRequirement] = &[ProtocolLockRequirement {
    resource: ProtocolLockResource::Bucket,
    mode: ProtocolLockMode::Exclusive,
}];
const BUCKET_IDENTITY_EXCLUSIVE_LOCKS: &[ProtocolLockRequirement] = &[
    ProtocolLockRequirement {
        resource: ProtocolLockResource::Bucket,
        mode: ProtocolLockMode::Exclusive,
    },
    ProtocolLockRequirement {
        resource: ProtocolLockResource::Identity,
        mode: ProtocolLockMode::Exclusive,
    },
];
const SERIAL_BUCKET_IDENTITY_LOCKS: &[ProtocolLockRequirement] = &[
    ProtocolLockRequirement {
        resource: ProtocolLockResource::Tenant,
        mode: ProtocolLockMode::Exclusive,
    },
    ProtocolLockRequirement {
        resource: ProtocolLockResource::Bucket,
        mode: ProtocolLockMode::Exclusive,
    },
    ProtocolLockRequirement {
        resource: ProtocolLockResource::Identity,
        mode: ProtocolLockMode::Exclusive,
    },
];
const SERIAL_OIDC_LOCKS: &[ProtocolLockRequirement] = &[
    ProtocolLockRequirement {
        resource: ProtocolLockResource::Tenant,
        mode: ProtocolLockMode::Exclusive,
    },
    ProtocolLockRequirement {
        resource: ProtocolLockResource::Bucket,
        mode: ProtocolLockMode::Exclusive,
    },
    ProtocolLockRequirement {
        resource: ProtocolLockResource::Identity,
        mode: ProtocolLockMode::Exclusive,
    },
    ProtocolLockRequirement {
        resource: ProtocolLockResource::ExternalIdp,
        mode: ProtocolLockMode::Exclusive,
    },
];
const BUCKET_OWNERSHIP: &[ProtocolResourceOwnership] =
    &[ProtocolResourceOwnership::ExclusiveBucket];
const BUCKET_IDENTITY_OWNERSHIP: &[ProtocolResourceOwnership] = &[
    ProtocolResourceOwnership::ExclusiveBucket,
    ProtocolResourceOwnership::IdentityPrefix,
];
const OIDC_OWNERSHIP: &[ProtocolResourceOwnership] = &[
    ProtocolResourceOwnership::ExclusiveBucket,
    ProtocolResourceOwnership::IdentityPrefix,
    ProtocolResourceOwnership::ExternalIdentity,
];
const BUCKET_CLEANUP: &[ProtocolCleanupScope] = &[
    ProtocolCleanupScope::OwnedBucket,
    ProtocolCleanupScope::ObjectPrefix,
    ProtocolCleanupScope::MultipartUpload,
];
const BUCKET_IDENTITY_CLEANUP: &[ProtocolCleanupScope] = &[
    ProtocolCleanupScope::OwnedBucket,
    ProtocolCleanupScope::ObjectPrefix,
    ProtocolCleanupScope::MultipartUpload,
    ProtocolCleanupScope::Identity,
    ProtocolCleanupScope::StsSession,
];
const BUCKET_POLICY_IDENTITY_CLEANUP: &[ProtocolCleanupScope] = &[
    ProtocolCleanupScope::OwnedBucket,
    ProtocolCleanupScope::BucketPolicy,
    ProtocolCleanupScope::ObjectPrefix,
    ProtocolCleanupScope::MultipartUpload,
    ProtocolCleanupScope::Identity,
    ProtocolCleanupScope::StsSession,
];
const BUCKET_CONFIGURATION_CLEANUP: &[ProtocolCleanupScope] = &[
    ProtocolCleanupScope::OwnedBucket,
    ProtocolCleanupScope::BucketConfiguration,
    ProtocolCleanupScope::ObjectPrefix,
    ProtocolCleanupScope::MultipartUpload,
];
const OIDC_CLEANUP: &[ProtocolCleanupScope] = &[
    ProtocolCleanupScope::OwnedBucket,
    ProtocolCleanupScope::ObjectPrefix,
    ProtocolCleanupScope::MultipartUpload,
    ProtocolCleanupScope::Identity,
    ProtocolCleanupScope::StsSession,
    ProtocolCleanupScope::ExternalIdentity,
];

const fn bucket_policy_case(id: &'static str, tags: &'static [&'static str]) -> ProtocolCase {
    ProtocolCase {
        id: ProtocolCaseId::new(id),
        domain: ProtocolDomain::Authorization,
        group: "bucket-policy",
        tags,
        isolation: ProtocolIsolation::Case,
        capabilities: &[
            ProtocolCapability::S3,
            ProtocolCapability::AdminApi,
            ProtocolCapability::BucketPolicy,
            ProtocolCapability::Identity,
        ],
        serial: false,
        executor: ProtocolExecutor::BucketPolicy,
        lock_requirements: BUCKET_IDENTITY_EXCLUSIVE_LOCKS,
        ownership: BUCKET_IDENTITY_OWNERSHIP,
        cleanup_scopes: BUCKET_POLICY_IDENTITY_CLEANUP,
        variants: DEFAULT_SUCCESS_VARIANTS,
    }
}

const fn sts_case(id: &'static str, group: &'static str) -> ProtocolCase {
    ProtocolCase {
        id: ProtocolCaseId::new(id),
        domain: ProtocolDomain::Sts,
        group,
        tags: &["authz", "regression"],
        isolation: ProtocolIsolation::Case,
        capabilities: &[
            ProtocolCapability::S3,
            ProtocolCapability::AdminApi,
            ProtocolCapability::Iam,
            ProtocolCapability::StsAssumeRole,
        ],
        serial: true,
        executor: ProtocolExecutor::Sts,
        lock_requirements: SERIAL_BUCKET_IDENTITY_LOCKS,
        ownership: BUCKET_IDENTITY_OWNERSHIP,
        cleanup_scopes: BUCKET_IDENTITY_CLEANUP,
        variants: DEFAULT_SUCCESS_VARIANTS,
    }
}

const fn sts_expiration_case() -> ProtocolCase {
    ProtocolCase {
        id: ProtocolCaseId::new(STS_EXPIRED_TOKEN_DENIED),
        domain: ProtocolDomain::Sts,
        group: "sts-session-policy",
        tags: &["authz", "regression", "slow"],
        isolation: ProtocolIsolation::Case,
        capabilities: &[
            ProtocolCapability::S3,
            ProtocolCapability::AdminApi,
            ProtocolCapability::Iam,
            ProtocolCapability::StsAssumeRole,
        ],
        serial: true,
        executor: ProtocolExecutor::Sts,
        lock_requirements: SERIAL_BUCKET_IDENTITY_LOCKS,
        ownership: BUCKET_IDENTITY_OWNERSHIP,
        cleanup_scopes: BUCKET_IDENTITY_CLEANUP,
        variants: DEFAULT_SUCCESS_VARIANTS,
    }
}

const fn oidc_web_identity_case() -> ProtocolCase {
    ProtocolCase {
        id: ProtocolCaseId::new(OIDC_WEB_IDENTITY_BASIC),
        domain: ProtocolDomain::Sts,
        group: "oidc-web-identity",
        tags: &["authz", "integration", "oidc", "regression"],
        isolation: ProtocolIsolation::Case,
        capabilities: &[
            ProtocolCapability::S3,
            ProtocolCapability::AdminApi,
            ProtocolCapability::Iam,
            ProtocolCapability::StsWebIdentity,
            ProtocolCapability::Oidc,
            ProtocolCapability::ExternalIdp,
        ],
        serial: true,
        executor: ProtocolExecutor::OidcWebIdentity,
        lock_requirements: SERIAL_OIDC_LOCKS,
        ownership: OIDC_OWNERSHIP,
        cleanup_scopes: OIDC_CLEANUP,
        variants: DEFAULT_SUCCESS_VARIANTS,
    }
}

const fn compatibility_case(id: &'static str, domain: ProtocolDomain) -> ProtocolCase {
    ProtocolCase {
        id: ProtocolCaseId::new(id),
        domain,
        group: "s3-compatibility",
        tags: &["compatibility", "parallel-safe"],
        isolation: ProtocolIsolation::Case,
        capabilities: &[ProtocolCapability::S3],
        serial: false,
        executor: ProtocolExecutor::Compatibility,
        lock_requirements: BUCKET_EXCLUSIVE_LOCKS,
        ownership: BUCKET_OWNERSHIP,
        cleanup_scopes: BUCKET_CLEANUP,
        variants: DEFAULT_SUCCESS_VARIANTS,
    }
}

const fn compatibility_versioning_case() -> ProtocolCase {
    ProtocolCase {
        id: ProtocolCaseId::new(COMPAT_VERSIONING_HEAD_REMOVAL),
        domain: ProtocolDomain::Versioning,
        group: "s3-compatibility",
        tags: &["compatibility", "parallel-safe", "versioning"],
        isolation: ProtocolIsolation::Case,
        capabilities: &[ProtocolCapability::S3, ProtocolCapability::Versioning],
        serial: false,
        executor: ProtocolExecutor::Compatibility,
        lock_requirements: BUCKET_EXCLUSIVE_LOCKS,
        ownership: BUCKET_OWNERSHIP,
        cleanup_scopes: BUCKET_CLEANUP,
        variants: DEFAULT_SUCCESS_VARIANTS,
    }
}

const fn public_access_block_case() -> ProtocolCase {
    ProtocolCase {
        id: ProtocolCaseId::new(PUBLIC_ACCESS_BLOCK_ROUND_TRIP),
        domain: ProtocolDomain::BucketConfig,
        group: "public-access-block",
        tags: &["compatibility", "parallel-safe", "regression"],
        isolation: ProtocolIsolation::Case,
        capabilities: &[
            ProtocolCapability::S3,
            ProtocolCapability::PublicAccessBlock,
        ],
        serial: false,
        executor: ProtocolExecutor::Compatibility,
        lock_requirements: BUCKET_EXCLUSIVE_LOCKS,
        ownership: BUCKET_OWNERSHIP,
        cleanup_scopes: BUCKET_CONFIGURATION_CLEANUP,
        variants: DEFAULT_SUCCESS_VARIANTS,
    }
}

const fn iam_case(
    id: &'static str,
    group: &'static str,
    tags: &'static [&'static str],
) -> ProtocolCase {
    ProtocolCase {
        id: ProtocolCaseId::new(id),
        domain: ProtocolDomain::Iam,
        group,
        tags,
        isolation: ProtocolIsolation::Case,
        capabilities: &[
            ProtocolCapability::S3,
            ProtocolCapability::AdminApi,
            ProtocolCapability::Iam,
        ],
        serial: true,
        executor: ProtocolExecutor::Iam,
        lock_requirements: SERIAL_BUCKET_IDENTITY_LOCKS,
        ownership: BUCKET_IDENTITY_OWNERSHIP,
        cleanup_scopes: BUCKET_IDENTITY_CLEANUP,
        variants: DEFAULT_SUCCESS_VARIANTS,
    }
}

const fn iam_group_case(
    id: &'static str,
    group: &'static str,
    tags: &'static [&'static str],
) -> ProtocolCase {
    ProtocolCase {
        id: ProtocolCaseId::new(id),
        domain: ProtocolDomain::Iam,
        group,
        tags,
        isolation: ProtocolIsolation::Case,
        capabilities: &[
            ProtocolCapability::S3,
            ProtocolCapability::AdminApi,
            ProtocolCapability::Iam,
            ProtocolCapability::IamGroup,
        ],
        serial: true,
        executor: ProtocolExecutor::Iam,
        lock_requirements: SERIAL_BUCKET_IDENTITY_LOCKS,
        ownership: BUCKET_IDENTITY_OWNERSHIP,
        cleanup_scopes: BUCKET_IDENTITY_CLEANUP,
        variants: DEFAULT_SUCCESS_VARIANTS,
    }
}

pub fn protocol_case_catalog() -> &'static [ProtocolCase] {
    static CASES: OnceLock<Vec<ProtocolCase>> = OnceLock::new();
    CASES.get_or_init(|| {
        authorization_descriptors::CASES
            .iter()
            .chain(compatibility_descriptors::CASES)
            .chain(iam_descriptors::CASES)
            .chain(sts_descriptors::OIDC_CASES)
            .chain(bucket_config_descriptors::CASES)
            .chain(sts_descriptors::SIGNED_STS_CASES)
            .copied()
            .collect()
    })
}

pub fn protocol_case(id: &str) -> Option<&'static ProtocolCase> {
    protocol_case_catalog()
        .iter()
        .find(|case| case.id.as_str() == id)
}

pub fn validate_protocol_catalog() -> Result<()> {
    validate_protocol_catalog_entries(protocol_case_catalog())
}

pub fn protocol_catalog_json() -> Result<String> {
    validate_protocol_catalog()?;
    Ok(serde_json::to_string_pretty(protocol_case_catalog())?)
}

fn validate_protocol_catalog_entries(cases: &[ProtocolCase]) -> Result<()> {
    let mut ids = BTreeSet::new();
    for case in cases {
        validate_protocol_case_descriptor(case)?;
        ensure!(
            ids.insert(case.id),
            "duplicate protocol case id {}",
            case.id
        );
    }
    Ok(())
}

pub fn validate_protocol_case_descriptor(case: &ProtocolCase) -> Result<()> {
    validate_stable_id("protocol case", case.id.as_str())?;
    ensure!(
        !case.group.is_empty(),
        "protocol case {} has an empty group",
        case.id
    );
    ensure!(
        !case.tags.is_empty(),
        "protocol case {} has no tags",
        case.id
    );
    ensure_unique(case.id, "tag", case.tags.iter().copied())?;
    ensure_unique(case.id, "capability", case.capabilities.iter().copied())?;
    ensure_unique(case.id, "ownership", case.ownership.iter().copied())?;
    ensure_unique(
        case.id,
        "cleanup scope",
        case.cleanup_scopes.iter().copied(),
    )?;
    ensure!(
        !case.variants.is_empty(),
        "protocol case {} has no variants",
        case.id
    );
    let mut variants = BTreeSet::new();
    for variant in case.variants {
        validate_stable_id("protocol variant", variant.id.as_str())?;
        ensure!(
            variants.insert(variant.id),
            "protocol case {} has duplicate variant {}",
            case.id,
            variant.id
        );
        validate_expected_outcome(case.id, variant)?;
    }

    let mut lock_resources = BTreeSet::new();
    for requirement in case.lock_requirements {
        ensure!(
            lock_resources.insert(requirement.resource),
            "protocol case {} has duplicate or conflicting {:?} lock requirements",
            case.id,
            requirement.resource
        );
    }
    if case.serial {
        ensure!(
            case.lock_requirements.contains(&ProtocolLockRequirement {
                resource: ProtocolLockResource::Tenant,
                mode: ProtocolLockMode::Exclusive,
            }),
            "serial protocol case {} requires an exclusive tenant lock",
            case.id
        );
    }
    validate_cleanup_contract(case)
}

fn validate_stable_id(kind: &str, id: &str) -> Result<()> {
    ensure!(!id.is_empty(), "{kind} id must not be empty");
    ensure!(
        id.bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'),
        "{kind} id {id:?} must contain only lowercase ASCII letters, digits, and hyphens"
    );
    ensure!(
        !id.starts_with('-') && !id.ends_with('-') && !id.contains("--"),
        "{kind} id {id:?} is not canonical"
    );
    Ok(())
}

fn ensure_unique<T>(
    case_id: ProtocolCaseId,
    kind: &str,
    values: impl IntoIterator<Item = T>,
) -> Result<()>
where
    T: Ord + fmt::Debug + Copy,
{
    let mut unique = BTreeSet::new();
    for value in values {
        ensure!(
            unique.insert(value),
            "protocol case {case_id} has duplicate {kind} {value:?}"
        );
    }
    Ok(())
}

fn validate_expected_outcome(case_id: ProtocolCaseId, variant: &ProtocolVariant) -> Result<()> {
    match variant.expected {
        ProtocolExpectedOutcome::Success => Ok(()),
        ProtocolExpectedOutcome::S3Error {
            http_status,
            error_code,
        } => {
            ensure!(
                (400..=599).contains(&http_status),
                "protocol case {case_id} variant {} has invalid S3 status {http_status}",
                variant.id
            );
            ensure!(
                !error_code.trim().is_empty(),
                "S3 error code must not be empty"
            );
            Ok(())
        }
        ProtocolExpectedOutcome::Transport { outcome } => {
            ensure!(
                !outcome.trim().is_empty(),
                "transport outcome must not be empty"
            );
            Ok(())
        }
        ProtocolExpectedOutcome::ExpectedDivergence { issue } => {
            ensure!(
                issue.starts_with("https://github.com/rustfs/backlog/issues/"),
                "expected divergence must link to a rustfs/backlog issue"
            );
            Ok(())
        }
    }
}

fn validate_cleanup_contract(case: &ProtocolCase) -> Result<()> {
    for ownership in case.ownership {
        let resource = match ownership {
            ProtocolResourceOwnership::ExclusiveBucket
            | ProtocolResourceOwnership::SharedBucketPrefix
            | ProtocolResourceOwnership::SharedBucketKey
            | ProtocolResourceOwnership::SharedObjectVersion
            | ProtocolResourceOwnership::ExactMultipartUpload => ProtocolLockResource::Bucket,
            ProtocolResourceOwnership::IdentityPrefix => ProtocolLockResource::Identity,
            ProtocolResourceOwnership::ExternalIdentity => ProtocolLockResource::ExternalIdp,
            ProtocolResourceOwnership::ExternalResource => {
                ensure!(
                    case.lock_requirements.iter().any(|lock| {
                        matches!(
                            lock.resource,
                            ProtocolLockResource::Kms
                                | ProtocolLockResource::Sns
                                | ProtocolLockResource::ExternalIdp
                        )
                    }),
                    "protocol case {} external ownership has no external resource lock",
                    case.id
                );
                continue;
            }
        };
        ensure!(
            case.lock_requirements
                .iter()
                .any(|lock| lock.resource == resource),
            "protocol case {} ownership {:?} has no {:?} lock",
            case.id,
            ownership,
            resource
        );
    }
    for cleanup in case.cleanup_scopes {
        let allowed = match cleanup {
            ProtocolCleanupScope::OwnedBucket => {
                case.ownership
                    .contains(&ProtocolResourceOwnership::ExclusiveBucket)
                    && case.lock_requirements.contains(&ProtocolLockRequirement {
                        resource: ProtocolLockResource::Bucket,
                        mode: ProtocolLockMode::Exclusive,
                    })
            }
            ProtocolCleanupScope::BucketPolicy | ProtocolCleanupScope::BucketConfiguration => {
                case.ownership
                    .contains(&ProtocolResourceOwnership::ExclusiveBucket)
                    && case.lock_requirements.contains(&ProtocolLockRequirement {
                        resource: ProtocolLockResource::Bucket,
                        mode: ProtocolLockMode::Exclusive,
                    })
            }
            ProtocolCleanupScope::ObjectPrefix => {
                case.ownership.iter().any(|ownership| {
                    matches!(
                        ownership,
                        ProtocolResourceOwnership::ExclusiveBucket
                            | ProtocolResourceOwnership::SharedBucketPrefix
                    )
                }) && case
                    .lock_requirements
                    .iter()
                    .any(|lock| lock.resource == ProtocolLockResource::Bucket)
            }
            ProtocolCleanupScope::MultipartUpload => {
                case.ownership.iter().any(|ownership| {
                    matches!(
                        ownership,
                        ProtocolResourceOwnership::ExclusiveBucket
                            | ProtocolResourceOwnership::SharedBucketPrefix
                            | ProtocolResourceOwnership::SharedBucketKey
                            | ProtocolResourceOwnership::ExactMultipartUpload
                    )
                }) && case
                    .lock_requirements
                    .iter()
                    .any(|lock| lock.resource == ProtocolLockResource::Bucket)
            }
            ProtocolCleanupScope::ObjectKey => {
                case.ownership.iter().any(|ownership| {
                    matches!(
                        ownership,
                        ProtocolResourceOwnership::ExclusiveBucket
                            | ProtocolResourceOwnership::SharedBucketPrefix
                            | ProtocolResourceOwnership::SharedBucketKey
                    )
                }) && case
                    .lock_requirements
                    .iter()
                    .any(|lock| lock.resource == ProtocolLockResource::Bucket)
            }
            ProtocolCleanupScope::ObjectVersion => {
                case.ownership.iter().any(|ownership| {
                    matches!(
                        ownership,
                        ProtocolResourceOwnership::ExclusiveBucket
                            | ProtocolResourceOwnership::SharedBucketPrefix
                            | ProtocolResourceOwnership::SharedBucketKey
                            | ProtocolResourceOwnership::SharedObjectVersion
                    )
                }) && case
                    .lock_requirements
                    .iter()
                    .any(|lock| lock.resource == ProtocolLockResource::Bucket)
            }
            ProtocolCleanupScope::Identity | ProtocolCleanupScope::StsSession => {
                case.ownership
                    .contains(&ProtocolResourceOwnership::IdentityPrefix)
                    && case
                        .lock_requirements
                        .iter()
                        .any(|lock| lock.resource == ProtocolLockResource::Identity)
            }
            ProtocolCleanupScope::ExternalIdentity => {
                case.ownership
                    .contains(&ProtocolResourceOwnership::ExternalIdentity)
                    && case
                        .lock_requirements
                        .iter()
                        .any(|lock| lock.resource == ProtocolLockResource::ExternalIdp)
            }
            ProtocolCleanupScope::ExternalResource => {
                case.ownership
                    .contains(&ProtocolResourceOwnership::ExternalResource)
                    && case.lock_requirements.iter().any(|lock| {
                        matches!(
                            lock.resource,
                            ProtocolLockResource::Kms
                                | ProtocolLockResource::Sns
                                | ProtocolLockResource::ExternalIdp
                        )
                    })
            }
        };
        ensure!(
            allowed,
            "protocol case {} cleanup scope {:?} is wider than its ownership or lock",
            case.id,
            cleanup
        );
    }
    ensure!(
        !(case
            .ownership
            .contains(&ProtocolResourceOwnership::SharedBucketPrefix)
            && case
                .cleanup_scopes
                .contains(&ProtocolCleanupScope::OwnedBucket)),
        "protocol case {} cannot empty a shared bucket",
        case.id
    );
    Ok(())
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
        let ids = catalog
            .iter()
            .map(|case| case.id.as_str())
            .collect::<Vec<_>>();
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
        assert!(
            catalog
                .iter()
                .all(|case| case.domain != super::ProtocolDomain::Other),
            "production catalog cases require an explicit protocol domain"
        );
    }

    #[test]
    fn bucket_policy_declares_identity_without_full_iam_management() {
        let case = super::protocol_case(BUCKET_POLICY_AUTHENTICATED_USER_RW).expect("case");
        assert!(case.has_capability(super::ProtocolCapability::Identity));
        assert!(!case.has_capability(super::ProtocolCapability::Iam));
    }

    #[test]
    fn only_group_case_declares_group_management() {
        for case in protocol_case_catalog() {
            assert_eq!(
                case.has_capability(super::ProtocolCapability::IamGroup),
                case.id.as_str() == IAM_GROUP_POLICY,
                "{} has an incorrect iam-group capability",
                case.id
            );
        }
    }

    #[test]
    fn oidc_and_signed_sts_declare_distinct_exchange_capabilities() {
        let oidc = super::protocol_case(OIDC_WEB_IDENTITY_BASIC).expect("OIDC case");
        assert!(oidc.has_capability(super::ProtocolCapability::StsWebIdentity));
        assert!(!oidc.has_capability(super::ProtocolCapability::StsAssumeRole));

        for id in [
            STS_ASSUME_ROLE_BASIC,
            STS_EXPIRED_TOKEN_DENIED,
            STS_SESSION_POLICY_DENY_PUT,
            STS_SESSION_POLICY_NARROWS_ROLE,
        ] {
            let case = super::protocol_case(id).expect("STS case");
            assert!(case.has_capability(super::ProtocolCapability::StsAssumeRole));
            assert!(!case.has_capability(super::ProtocolCapability::StsWebIdentity));
        }
    }

    const TEST_LOCKS: &[super::ProtocolLockRequirement] = &[super::ProtocolLockRequirement {
        resource: super::ProtocolLockResource::Bucket,
        mode: super::ProtocolLockMode::Exclusive,
    }];
    const TEST_OWNERSHIP: &[super::ProtocolResourceOwnership] =
        &[super::ProtocolResourceOwnership::ExclusiveBucket];
    const TEST_CLEANUP: &[super::ProtocolCleanupScope] =
        &[super::ProtocolCleanupScope::OwnedBucket];

    const fn test_case(id: &'static str) -> super::ProtocolCase {
        super::ProtocolCase {
            id: super::ProtocolCaseId::new(id),
            domain: super::ProtocolDomain::Bucket,
            group: "test",
            tags: &["test"],
            isolation: super::ProtocolIsolation::Case,
            capabilities: &[super::ProtocolCapability::S3],
            serial: false,
            executor: super::ProtocolExecutor::Compatibility,
            lock_requirements: TEST_LOCKS,
            ownership: TEST_OWNERSHIP,
            cleanup_scopes: TEST_CLEANUP,
            variants: super::DEFAULT_SUCCESS_VARIANTS,
        }
    }

    #[test]
    fn catalog_validation_rejects_duplicate_and_unstable_case_ids() {
        let duplicate = [test_case("duplicate"), test_case("duplicate")];
        assert!(super::validate_protocol_catalog_entries(&duplicate).is_err());
        assert!(super::validate_protocol_case_descriptor(&test_case("unstable--alias")).is_err());
        assert!(super::validate_protocol_case_descriptor(&test_case("")).is_err());
    }

    #[test]
    fn unknown_capability_is_rejected_at_the_typed_boundary() {
        assert!(
            serde_json::from_str::<super::ProtocolCapability>("\"future-capability\"").is_err()
        );
    }

    #[test]
    fn expected_divergence_requires_a_backlog_issue_link() {
        let invalid = super::ProtocolVariant {
            id: super::ProtocolVariantId::new("divergence"),
            expected: super::ProtocolExpectedOutcome::ExpectedDivergence { issue: "#1995" },
        };
        assert!(
            super::validate_expected_outcome(super::ProtocolCaseId::new("case"), &invalid).is_err()
        );
        let valid = super::ProtocolVariant {
            id: super::ProtocolVariantId::new("divergence"),
            expected: super::ProtocolExpectedOutcome::ExpectedDivergence {
                issue: "https://github.com/rustfs/backlog/issues/1995",
            },
        };
        super::validate_expected_outcome(super::ProtocolCaseId::new("case"), &valid)
            .expect("tracked divergence");
    }

    #[test]
    fn duplicate_or_conflicting_lock_requirements_are_rejected() {
        const CONFLICTS: &[super::ProtocolLockRequirement] = &[
            super::ProtocolLockRequirement {
                resource: super::ProtocolLockResource::Bucket,
                mode: super::ProtocolLockMode::Shared,
            },
            super::ProtocolLockRequirement {
                resource: super::ProtocolLockResource::Bucket,
                mode: super::ProtocolLockMode::Exclusive,
            },
        ];
        let case = super::ProtocolCase {
            lock_requirements: CONFLICTS,
            ..test_case("lock-conflict")
        };
        assert!(super::validate_protocol_case_descriptor(&case).is_err());
    }

    #[test]
    fn duplicate_variants_are_rejected() {
        const DUPLICATE_VARIANTS: &[super::ProtocolVariant] = &[
            super::ProtocolVariant {
                id: super::ProtocolVariantId::new("same"),
                expected: super::ProtocolExpectedOutcome::Success,
            },
            super::ProtocolVariant {
                id: super::ProtocolVariantId::new("same"),
                expected: super::ProtocolExpectedOutcome::Transport {
                    outcome: "connection-closed",
                },
            },
        ];
        let case = super::ProtocolCase {
            variants: DUPLICATE_VARIANTS,
            ..test_case("duplicate-variant")
        };
        assert!(super::validate_protocol_case_descriptor(&case).is_err());
    }

    #[test]
    fn shared_prefix_cleanup_cannot_expand_to_the_bucket() {
        const SHARED_LOCKS: &[super::ProtocolLockRequirement] = &[super::ProtocolLockRequirement {
            resource: super::ProtocolLockResource::Bucket,
            mode: super::ProtocolLockMode::Shared,
        }];
        const SHARED_OWNERSHIP: &[super::ProtocolResourceOwnership] =
            &[super::ProtocolResourceOwnership::SharedBucketPrefix];
        const PREFIX_CLEANUP: &[super::ProtocolCleanupScope] =
            &[super::ProtocolCleanupScope::ObjectPrefix];
        let shared = super::ProtocolCase {
            lock_requirements: SHARED_LOCKS,
            ownership: SHARED_OWNERSHIP,
            cleanup_scopes: PREFIX_CLEANUP,
            ..test_case("shared-prefix")
        };
        super::validate_protocol_case_descriptor(&shared).expect("exact prefix cleanup");

        const BUCKET_CLEANUP: &[super::ProtocolCleanupScope] =
            &[super::ProtocolCleanupScope::OwnedBucket];
        let overbroad = super::ProtocolCase {
            cleanup_scopes: BUCKET_CLEANUP,
            ..shared
        };
        assert!(super::validate_protocol_case_descriptor(&overbroad).is_err());
    }

    #[test]
    fn catalog_json_preserves_requires_and_adds_typed_contracts() {
        let json: serde_json::Value =
            serde_json::from_str(&super::protocol_catalog_json().expect("catalog JSON"))
                .expect("JSON value");
        let case = json
            .as_array()
            .expect("catalog array")
            .iter()
            .find(|case| case["id"] == BUCKET_POLICY_AUTHENTICATED_USER_RW)
            .expect("case");
        assert!(
            case["requires"]
                .as_array()
                .expect("requires")
                .contains(&serde_json::Value::String("identity".to_string()))
        );
        assert_eq!(case["executor"], "bucket-policy");
        assert_eq!(case["variants"][0]["id"], "default");
    }
}
