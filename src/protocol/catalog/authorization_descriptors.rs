use super::*;

pub(super) const CASES: &[ProtocolCase] = &[
    bucket_policy_case(
        BUCKET_POLICY_AUTHENTICATED_USER_RW,
        &["authz", "parallel-safe", "smoke"],
    ),
    ProtocolCase {
        variants: ACCESS_DENIED_VARIANTS,
        ..bucket_policy_case(
            BUCKET_POLICY_DELETE_RESTORES_PRIVATE,
            &["authz", "parallel-safe", "regression"],
        )
    },
    ProtocolCase {
        variants: ACCESS_DENIED_VARIANTS,
        ..bucket_policy_case(
            BUCKET_POLICY_EXPLICIT_DENY_OVERRIDES_ALLOW,
            &["authz", "parallel-safe", "regression"],
        )
    },
    ProtocolCase {
        variants: MALFORMED_POLICY_VARIANTS,
        ..bucket_policy_case(
            BUCKET_POLICY_MALFORMED_POLICY_REJECTED,
            &["authz", "negative", "parallel-safe", "regression"],
        )
    },
    ProtocolCase {
        variants: ACCESS_DENIED_VARIANTS,
        ..bucket_policy_case(
            BUCKET_POLICY_PREFIX_SCOPE,
            &["authz", "parallel-safe", "regression"],
        )
    },
];
