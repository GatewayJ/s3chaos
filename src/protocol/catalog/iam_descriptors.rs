use super::*;

pub(super) const CASES: &[ProtocolCase] = &[
    ProtocolCase {
        variants: ACCESS_DENIED_VARIANTS,
        ..iam_case(
            IAM_EXPLICIT_DENY_OVERRIDES_ALLOW,
            "iam-user",
            &["authz", "regression"],
        )
    },
    iam_group_case(IAM_GROUP_POLICY, "iam-group", &["authz", "regression"]),
    ProtocolCase {
        variants: ACCESS_DENIED_VARIANTS,
        ..iam_case(
            IAM_USER_MANAGED_POLICY_READONLY,
            "iam-user",
            &["authz", "regression"],
        )
    },
    ProtocolCase {
        variants: ACCESS_DENIED_VARIANTS,
        ..iam_case(
            IAM_USER_MANAGED_POLICY_DETACH,
            "iam-policy",
            &["authz", "regression"],
        )
    },
];
