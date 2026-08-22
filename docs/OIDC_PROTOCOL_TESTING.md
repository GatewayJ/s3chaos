# Keycloak OIDC protocol test

The `oidc-web-identity-basic` case verifies the complete external identity path:

1. Create a bucket-scoped read-only RustFS IAM policy.
2. Create an isolated Keycloak user carrying that policy name in an ID-token claim.
3. Exchange the ID token through unsigned `AssumeRoleWithWebIdentity`.
4. Verify list/get access on the target bucket, write denial, and denial on an unrelated bucket.
5. Revoke the RustFS OpenID STS session, delete the Keycloak user, and verify both are absent.

The case is opt-in, serial, and holds exclusive `target` and `external-idp` locks. Tokens,
passwords, client secrets, and temporary S3 credentials are redacted and included in artifact
leak validation.

The OIDC suite probes the unsigned WebIdentity exchange directly. It does not require the
separate signed `AssumeRole` flow to be enabled.

## Keycloak fixture

Use a dedicated realm and confidential client. The client must enable direct access grants.
Add an ID-token protocol mapper with these effective settings:

- mapper: user attribute
- user attribute: `policy`
- token claim: `policy`
- add to ID token: enabled
- multivalued: enabled (a single string value is also accepted)

The Keycloak administrator used by the test must be allowed to query, create, and delete users in
the test realm. The test creates a unique enabled user per run and deletes it through the resource
registry cleanup path, including standalone crash recovery.

The resource registry records the Keycloak provider, issuer, and subject namespace. Standalone
cleanup requires the same OIDC environment configuration and refuses to delete a user if those
coordinates no longer match the registry.

Configure RustFS against the same issuer and client. The relevant values are:

```text
RUSTFS_IDENTITY_OPENID_ENABLE=on
RUSTFS_IDENTITY_OPENID_CONFIG_URL=<issuer or discovery URL>
RUSTFS_IDENTITY_OPENID_CLIENT_ID=<client id>
RUSTFS_IDENTITY_OPENID_CLIENT_SECRET=<client secret>
RUSTFS_IDENTITY_OPENID_CLAIM_NAME=policy
```

## s3chaos environment

```text
RUSTFS_PROTOCOL_TEST_ENDPOINT=http://rustfs.example:9000
RUSTFS_PROTOCOL_TEST_ADMIN_ACCESS_KEY=<dedicated RustFS admin access key>
RUSTFS_PROTOCOL_TEST_ADMIN_SECRET_KEY=<dedicated RustFS admin secret key>
RUSTFS_PROTOCOL_TEST_DEDICATED=1

RUSTFS_PROTOCOL_OIDC_ISSUER=https://keycloak.example/realms/rustfs-ci
RUSTFS_PROTOCOL_OIDC_ADMIN_URL=https://keycloak.example
RUSTFS_PROTOCOL_OIDC_REALM=rustfs-ci
RUSTFS_PROTOCOL_OIDC_CLIENT_ID=rustfs-ci
RUSTFS_PROTOCOL_OIDC_CLIENT_SECRET=<client secret>
RUSTFS_PROTOCOL_OIDC_ADMIN_USERNAME=<realm administrator>
RUSTFS_PROTOCOL_OIDC_ADMIN_PASSWORD=<administrator password>
```

Before the destructive run, obtain and review the server-verified fingerprint
from the non-mutating suite plan:

```bash
PLAN_JSON="$(scripts/protocol-test.sh suite-plan protocol/examples/oidc-keycloak.yaml)"
jq '.target.fingerprint' <<<"$PLAN_JSON"
export RUSTFS_PROTOCOL_TEST_TARGET_FINGERPRINT="$(
  jq -er '.target.fingerprint.sha256' <<<"$PLAN_JSON"
)"
```

`suite-run` repeats preflight and refuses execution if the observed target no
longer matches this fingerprint.

Optional variables:

```text
RUSTFS_PROTOCOL_OIDC_ADMIN_REALM=master
RUSTFS_PROTOCOL_OIDC_POLICY_CLAIM=policy
```

`RUSTFS_PROTOCOL_OIDC_ISSUER` is the realm issuer, without
`/.well-known/openid-configuration`. `RUSTFS_PROTOCOL_OIDC_ADMIN_URL` is the Keycloak base URL;
an installation base path such as `/auth` is supported.

Run the example suite:

```bash
scripts/protocol-test.sh suite-validate protocol/examples/oidc-keycloak.yaml
scripts/protocol-test.sh suite-plan protocol/examples/oidc-keycloak.yaml
scripts/protocol-test.sh suite-run protocol/examples/oidc-keycloak.yaml
```

If the process is interrupted, rerun cleanup with the emitted artifact root or registry:

```bash
scripts/protocol-test.sh cleanup target/protocol-tests/rustfs-oidc-keycloak/<run-id>
scripts/protocol-test.sh cleanup --registry <artifact-root>/cases/oidc-web-identity-basic/resource-registry.json
```
