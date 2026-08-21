use super::*;

pub(super) const OIDC_CASES: &[ProtocolCase] = &[ProtocolCase {
    variants: ACCESS_DENIED_VARIANTS,
    ..oidc_web_identity_case()
}];

pub(super) const SIGNED_STS_CASES: &[ProtocolCase] = &[
    sts_case(STS_ASSUME_ROLE_BASIC, "sts-assume-role"),
    ProtocolCase {
        variants: EXPIRED_TOKEN_VARIANTS,
        ..sts_expiration_case()
    },
    ProtocolCase {
        variants: ACCESS_DENIED_VARIANTS,
        ..sts_case(STS_SESSION_POLICY_DENY_PUT, "sts-session-policy")
    },
    ProtocolCase {
        variants: ACCESS_DENIED_VARIANTS,
        ..sts_case(STS_SESSION_POLICY_NARROWS_ROLE, "sts-session-policy")
    },
];
