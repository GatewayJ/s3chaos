use super::*;

const CANNED_POLICY_CAPABILITIES: &[ProtocolCapability] = &[
    ProtocolCapability::S3,
    ProtocolCapability::AdminApi,
    ProtocolCapability::Iam,
];
const CANNED_POLICY_VERSIONED_CAPABILITIES: &[ProtocolCapability] = &[
    ProtocolCapability::S3,
    ProtocolCapability::AdminApi,
    ProtocolCapability::Iam,
    ProtocolCapability::Versioning,
];

pub(super) const CASES: &[ProtocolCase] = &[
    ProtocolCase {
        variants: ACCESS_DENIED_VARIANTS,
        ..canned_policy_case(
            DELETE_FORCE_HEADER_CONTRACT,
            "delete-force-header",
            ProtocolDomain::Authorization,
            &["authz", "regression"],
            CANNED_POLICY_CAPABILITIES,
        )
    },
    canned_policy_case(
        IAM_CANNED_POLICY_CONSOLE_ADMIN_DELETE,
        "iam-canned-policy",
        ProtocolDomain::Iam,
        &["authz", "smoke"],
        CANNED_POLICY_CAPABILITIES,
    ),
    ProtocolCase {
        variants: ACCESS_DENIED_VARIANTS,
        ..canned_policy_case(
            IAM_CANNED_POLICY_MATRIX,
            "iam-canned-policy",
            ProtocolDomain::Iam,
            &["authz", "regression"],
            CANNED_POLICY_VERSIONED_CAPABILITIES,
        )
    },
];
