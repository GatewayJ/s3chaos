# S3 Protocol Test TODO

## Goal

Add maintainable S3 protocol end-to-end tests to `s3chaos` without mixing them
into the destructive fault-test suite.

The first useful target is an authorization-focused protocol suite:

- Bucket policy
- IAM users, groups, and policies
- STS AssumeRole and session policies

The tests should stay simple at the case level: create resources, apply policy,
exercise allowed and denied actors, assert the expected S3 result, then clean up.
The long-term maintainability work belongs in the catalog, fixture, cleanup, and
scheduler layers.

This document is a development TODO, not only a design note. Every phase must
leave the harness in an executable state with stable inputs, artifacts, and
cleanup behavior.

## Reference Lessons

- MinIO keeps many policy/IAM/STS tests close to implementation, using
  table-driven checks and suite helpers. Its broader external compatibility
  checks live in Mint and run as a black-box target with structured logs.
- Ceph `s3-tests` is the closest model for a black-box protocol suite: few large
  feature modules, marker-based selection, endpoint/credential config, resource
  prefixes, and aggressive cleanup.
- RustFS already uses both local E2E tests and a pinned `ceph/s3-tests` workflow
  with `implemented`, `excluded`, and `unimplemented` test lists.

Do not copy MinIO's temporary-process cleanup model directly. `s3chaos` targets
real or shared Kubernetes/RustFS environments, so every S3/IAM/STS resource must
be explicitly named, registered, and cleaned.

## Architectural Boundary

- [x] Add a new `src/protocol/` bounded context next to `src/fault/`.
- [x] Keep `FaultSuite` focused on fault injection, workload disruption, and
      recovery validation.
- [x] Add a new `ProtocolSuite` schema instead of extending `FaultSuite`.
- [x] Reuse only lower-level framework utilities from `src/framework/`, such as
      Kubernetes access, port-forwarding, tenant setup, and artifact helpers.
- [x] Extract or wrap reusable S3 client/history functionality from `src/fault`
      only after the protocol use case needs it.
- [x] Do not reuse fault artifact validation for protocol results. Create
      protocol-specific reports and validators.

Boundary rules:

- `src/protocol` owns protocol case selection, fixture lifecycle, authorization
  assertions, protocol artifacts, protocol cleanup, and protocol validators.
- `src/fault` owns destructive fault orchestration, workload history, fault
  evidence, recovery checks, and fault-specific summaries.
- `src/framework` may provide shared infrastructure adapters, but it must not
  learn protocol case semantics or fault case semantics.
- The binary crate owns CLI argument parsing and wiring. It should call protocol
  use cases instead of embedding protocol decisions.
- The shell/Make layer owns environment setup and safety gates. It should not
  decide selected cases, expected results, or cleanup order.

Resource ownership rules:

- A case may create resources only through fixture APIs.
- A fixture must return a `ResourceHandle` and register it in the persistent
  registry as part of the creation flow.
- The registry is the durable fact source for cleanup.
- Cleanup consumes registry entries; it must not rediscover resources by broad
  prefix scans except as a stale-resource preflight warning.
- A future scheduler may read case locks from the resolved plan, but it must not
  own resource identity or cleanup logic.

Proposed module shape:

```text
src/protocol/
  mod.rs
  catalog.rs
  contract.rs
  preflight.rs
  suite.rs
  suite_plan.rs
  suite_runner.rs
  reporting.rs
  artifact_validation.rs
  clients/
    s3.rs
    admin.rs
    sts.rs
  fixture/
    mod.rs
    bucket.rs
    identity.rs
    policy.rs
    cleanup.rs
    registry.rs
  cases/
    mod.rs
    bucket_policy.rs
    iam_user.rs
    iam_group.rs
    iam_policy.rs
    sts_assume_role.rs
    sts_session_policy.rs
```

Do not create empty modules before they have a real caller. `scheduler.rs`,
OIDC-specific clients, and broader compatibility adapters belong in later
phases after the serial authorization path is working.

## CLI And Make Targets

- [x] Add `protocol-*` CLI commands to `src/bin/s3chaos.rs`.
- [x] Add matching Makefile targets.
- [x] Keep protocol commands separate from `fault-*`.

Suggested commands:

```text
s3chaos protocol-catalog-json
s3chaos protocol-suite-template
s3chaos protocol-suite-json <suite.yaml>
s3chaos protocol-suite-validate <suite.yaml>
s3chaos protocol-suite-plan <suite.yaml>
s3chaos protocol-suite-run <suite.yaml>
s3chaos protocol-validate-artifacts <artifact-root>
s3chaos protocol-cleanup <artifact-root>
s3chaos protocol-cleanup --registry <resource-registry.json>
```

Suggested Makefile targets:

```text
make protocol-list
make protocol-suite-template
make protocol-suite-validate SUITE=suite.yaml
make protocol-suite-plan SUITE=suite.yaml
make protocol-suite-run SUITE=suite.yaml
make protocol-cleanup ARTIFACT_ROOT=...
```

Runner gate TODO:

- [x] Add a protocol runner script or Make wrapper that performs preflight,
      invokes the binary, captures logs, and preserves the artifact root.
- [x] Require an explicit endpoint and admin profile before running.
- [x] Require the admin profile to resolve through a documented
      `CredentialProvider` before any target mutation.
- [x] Require a dedicated RustFS protocol-test target by default through an
      explicit safety acknowledgement plus fingerprint recording. If the runner
      cannot prove the target identity from probes, it must fail unless a local
      non-CI debug override acknowledges the dedicated target.
- [x] Record the target fingerprint in artifacts before mutating resources.
- [x] Refuse cleanup commands that are not scoped to an artifact root or an
      explicit registry path.
- [x] Keep protocol safety flags separate from fault flags such as
      `RUSTFS_FAULT_TEST_DESTRUCTIVE`.

## Suite Configuration

- [x] Keep YAML as a selector and run-control file, not as a test DSL.
- [x] Define cases in Rust code. Use YAML only to include or exclude groups,
      tags, and named cases.
- [x] Resolve the suite into a stable JSON plan before execution.
- [x] Capture endpoint, credentials, selected groups, isolation mode,
      parallelism, cleanup policy, and RustFS preflight results in the plan.
- [x] For the first implementation, accept only `execution.parallelism: 1`.
      Reject larger values until the scheduler phase lands.
- [x] For the first implementation, accept only `execution.cleanup: always`.
      Retaining resources for debug must be a separate non-CI debug flag, not a
      default suite mode.
- [x] Use catalog group ids exactly. Do not introduce YAML aliases such as
      `iam` or `sts` unless the resolver expands them into concrete group ids in
      the plan.

Draft YAML:

```yaml
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: ProtocolSuite
metadata:
  name: rustfs-authz-smoke
selector:
  groups:
    - bucket-policy
    - iam-user
    - iam-group
    - iam-policy
    - sts-assume-role
    - sts-session-policy
  tags:
    - smoke
execution:
  parallelism: 1
  defaultIsolation: case
  cleanup: always
target:
  endpoint: ${RUSTFS_PROTOCOL_TEST_ENDPOINT}
  region: us-east-1
  credentials:
    adminProfile: root
    provider: env
  ownership:
    mode: dedicated-tenant
    resourcePrefixes:
      bucket: s3c
      identity: s3chaos
  safety:
    dedicatedTarget: required
```

Field meaning:

- `apiVersion`: contract version. Use the same API group style as existing
  s3chaos suite contracts unless a migration is intentional.
- `kind`: must be `ProtocolSuite`.
- `metadata.name`: stable suite name used in plan and artifact paths.
- `selector.groups`: concrete catalog group ids.
- `selector.tags`: include cases carrying all required tags.
- `execution.parallelism`: worker count. Phase 1 validates that this is `1`.
- `execution.defaultIsolation`: default fixture scope for cases that do not
  override isolation.
- `execution.cleanup`: Phase 1 supports only `always`.
- `target.endpoint`: RustFS S3 endpoint.
- `target.region`: S3 signing region.
- `target.credentials.adminProfile`: logical credential profile name for RustFS
  admin operations. This is not a password.
- `target.credentials.provider`: where the logical profile is resolved. Phase 1
  supports `env` only.
- `target.ownership.mode`: Phase 1 requires `dedicated-tenant` unless an
  explicit future opt-in mode is added.
- `target.ownership.resourcePrefixes.bucket`: prefix for generated buckets.
- `target.ownership.resourcePrefixes.identity`: prefix for generated IAM users,
  groups, roles, policies, and access keys.
- Each actual resource name must include the configured prefix, generated
  `run_id`, and case token. Stale-resource scans and cleanup plans must list
  every configured prefix they will inspect.
- `target.safety.dedicatedTarget`: Phase 1 supports only `required`. The runner
  records a target fingerprint before mutation and refuses CI/default execution
  if the fingerprint cannot be captured.

Credential contract:

- [x] Add a `CredentialProvider` owned by `src/protocol`, with the concrete
      Phase 1 implementation reading environment variables at the binary or
      runner edge.
- [x] Suggested Phase 1 env names:
      `RUSTFS_PROTOCOL_TEST_ADMIN_ACCESS_KEY`,
      `RUSTFS_PROTOCOL_TEST_ADMIN_SECRET_KEY`, and optional
      `RUSTFS_PROTOCOL_TEST_ADMIN_SESSION_TOKEN`.
- [x] The plan may record credential profile ids and provider names, but never
      raw access keys, secret keys, or session tokens.
- [x] Add an `ActorCredential` model for credentials created during a case:
      actor id, credential id, source resource handle, creation phase, expiration
      when applicable, and redaction state.
- [x] Register generated access keys and STS sessions in the resource registry
      before using them for S3 calls.
- [x] Cleanup must delete generated access keys before deleting users, and must
      expire or forget temporary session credentials without writing raw token
      material to artifacts.
- [x] Artifact validation must fail if raw credential material appears in any
      protocol artifact.

## Case Catalog

- [x] Create a typed `ProtocolCase` catalog.
- [x] Give every case stable metadata.
- [x] Use tags for selection and scheduling.
- [x] Use RustFS API requirements to fail preflight clearly when a selected
      group cannot run.
- [x] Keep matrix combinations inside the case module, not in YAML.
- [x] Treat the Rust catalog as the sole Phase 1 authority. Compatibility status
      lists belong to Phase 7 and must not affect the first smoke suite.
- [x] Generate `protocol-catalog-json` from Rust metadata so docs, CLI, and plan
      resolution all use the same vocabulary.

Draft metadata:

```rust
ProtocolCase {
    id: "bucket-policy-authenticated-user-rw",
    group: "bucket-policy",
    tags: &["smoke", "authz"],
    isolation: Isolation::Case,
    requires: &["s3", "admin-api", "bucket-policy"],
    serial: true,
}
```

Case groups:

- [x] `bucket-policy`
- [x] `iam-user`
- [x] `iam-group`
- [x] `iam-policy`
- [x] `sts-assume-role`
- [x] `sts-session-policy`
- [x] `public-access-block`
- [x] `s3-compatibility`

Future compatibility status lists (Phase 7 only):

- [x] Defer `implemented.yaml`, `unimplemented.yaml`, `excluded.yaml`, and
      `expected_divergence.yaml` to Phase 7 compatibility expansion.

When Phase 7 adds expected divergence entries, each entry must include:

- Case id
- Product or compatibility reason
- Tracking issue or PR
- Expiration or review condition
- Whether the case should fail, skip, or warn

Selector resolution order:

1. Load all Phase 1 cases from the Rust catalog.
2. Apply `selector.groups`, `selector.tags`, and explicit case includes.
3. Apply explicit excludes from the suite file.
4. Emit the final selected case set into `protocol-suite-plan.json`.

Authorization matrix model:

- [x] Avoid one-off case definitions for every policy combination.
- [x] Model authorization cases as a typed matrix:
      `actor source + grant source + policy effect + operation/resource scope +
      expected result`.
- [x] Let each group own only the fixture differences:
      bucket policy, IAM user policy, IAM group policy, managed policy, role
      policy, or STS session policy.
- [x] Keep shared assertion helpers and expected-result normalization in one
      protocol authorization module.

Example matrix dimensions:

```text
actor source:
  anonymous | iam-user | group-member-user | assumed-role | sts-session

grant source:
  bucket-policy | user-inline-policy | group-policy | managed-policy |
  role-policy | session-policy

policy effect:
  allow | explicit-deny | detach | delete-policy | malformed

operation/resource scope:
  list-bucket | get-object | put-object | delete-object |
  allowed-prefix | denied-prefix | unrelated-bucket

expected result:
  ok | access-denied | malformed-policy | no-such-key | expired-token
```

## Fixture Model

- [x] Add `ProtocolRunFixture`.
- [x] Add `ProtocolResourceNamer`.
- [x] Generate a unique `run_id` for every suite run.
- [x] Prefix all resources with the `run_id`.
- [x] Register every resource before or immediately after creation.
- [x] Persist the registry atomically after every resource state transition.
- [x] Make cleanup idempotent.
- [x] Write a cleanup report even when cleanup partially fails.

Default resource naming:

```text
bucket:      <bucket-prefix>-<run-token>-<case-token>-<n>
object key:  cases/<case-id>/<actor>/<seq>
user:        <identity-prefix>-<run-token>-<case-token>-user-<n>
group:       <identity-prefix>-<run-token>-<case-token>-group-<n>
policy:      <identity-prefix>-<run-token>-<case-token>-policy-<n>
role:        <identity-prefix>-<run-token>-<case-token>-role-<n>
```

Naming rules:

- `bucket-prefix` and `identity-prefix` come from
  `target.ownership.resourcePrefixes` and are copied into the resolved plan.
- `run-token` is a lowercase alphanumeric token derived from `run_id`, no longer
  than 12 characters.
- `case-token` is a lowercase alphanumeric hash or slug derived from the case id,
  no longer than 10 characters.
- Bucket names must be validated before use:
  3 to 63 characters, lowercase letters, digits, and hyphens only, no leading or
  trailing hyphen, no adjacent dots, no IP-address shape.
- IAM, policy, group, and role names must use the target API's accepted
  character set and length limits.
- Full human-readable case ids stay in `resource-registry.json`,
  `case-report.json`, and operation history; they do not need to fit inside
  external resource names.
- Add unit tests for representative long case ids and unusual characters before
  implementing additional case groups.

Resource registry state machine:

```text
planned
creating
created
cleanup_attempted
cleaned
failed
```

Registry rules:

- Write a `planned` entry before beginning a multi-step create when possible.
- Move to `creating` before issuing the create call.
- Move to `created` only after the target confirms the resource exists.
- Persist each transition with atomic write-and-rename semantics.
- Include enough identifiers to clean without recomputing names:
  resource kind, name, bucket, key prefix, version id, user, group, role, policy,
  attachments, owning case id, and dependency ordering.
- Include target fingerprint and `run_id` in the registry header.
- Treat unknown or partially-created resources as cleanup work, not as success.
- Phase 1 cleanup must be able to replay cleanup from the artifact root.
- Emergency cleanup from a standalone registry path belongs to Phase 2.
- Phase 2 mutating preflight probes must use the same registry, with
  `owner_phase=preflight` and a stable synthetic case id such as
  `preflight-permission-probe`.

Supported isolation levels:

- [x] `case`: default. Each case owns unique buckets, users, policies, and roles.
- [ ] `group`: allowed only when a group intentionally shares a bucket or IAM
      identity across multiple cases. The group must run serially.
- [ ] `suite`: avoid by default. Use only for read-only compatibility smoke tests.

## Bucket And Data Reuse Rules

- [x] Default to one bucket per case.
- [x] Allow multiple object prefixes inside one case.
- [ ] Allow shared buckets only inside an explicit group fixture.
- [ ] Mark any shared-bucket group as serial.
- [x] Never depend on data created by a previous independent case.
- [x] Never allow a case to assume another case cleaned policy state correctly.

Recommended pattern:

```text
case setup:
  create bucket
  create user or role
  create initial objects if needed

case assertions:
  assert denied before policy
  apply policy
  assert allowed operation
  assert denied operation outside policy scope

case cleanup:
  remove policies and identities
  delete objects, versions, and delete markers
  delete bucket
```

## Cleanup Timing

- [x] Run cleanup after every independent case, even when the case fails.
- [x] Implement case cleanup with a `finally`/drop-style path so assertion
      failures do not skip resource deletion.
- [x] Use suite-level cleanup as a final safety pass, not as the primary cleanup
      mechanism.
- [x] Run suite-level cleanup from `resource-registry.json` after all cases
      finish or when the runner is interrupted.
- [ ] For `group` isolation, clean shared resources after the group finishes,
      not after each case inside the group.
- [ ] Require every `group` isolation fixture to run serially.
- [x] Record both case cleanup and suite fallback cleanup in
      `cleanup-report.json`.

Default cleanup behavior:

```text
case starts
  register resources as they are created
  run assertions
  cleanup resources owned by the case
case ends

suite ends
  reload resource-registry.json
  retry cleanup for any leftover resources
  write final cleanup-report.json
```

Cleanup policy:

- [x] `always`: default. Clean resources after successful and failed cases.
- [x] Phase 1 supports only `always`.
- [x] Later debug retention must be an explicit CLI flag or environment override.
      It must be rejected in CI, require an explicit artifact root, and write a
      leftover-resource report.

## Cleanup TODO

- [x] Implement `ResourceRegistry`.
- [x] Write `resource-registry.json` during the run.
- [x] Write `cleanup-report.json` after cleanup.
- [x] Trigger case cleanup immediately after each independent case.
- [ ] Trigger group cleanup after a serial group fixture finishes.
- [x] Trigger suite fallback cleanup after all cases finish.
- [x] Delete IAM attachments before deleting IAM entities.
- [ ] Delete role policies before deleting roles.
- [x] Delete bucket policy before deleting the bucket.
- [x] Delete all objects under the case prefix.
- [x] Support versioned bucket cleanup.
- [x] Support delete marker cleanup.
- [x] Record leftover resources with enough data for manual cleanup.
- [x] Add `protocol-cleanup <artifact-root>` for retrying cleanup from registry
      data.
- [x] Add `protocol-cleanup --registry <resource-registry.json>` for emergency
      cleanup when only the registry file is available.

Cleanup order:

```text
detach policies
delete inline policies
delete role policies
delete service accounts or access keys
delete roles
delete users and groups
delete bucket policy
delete objects, versions, and delete markers
delete buckets
write cleanup report
```

## Parallel Execution

- [x] Start with serial execution.
- [x] Validate `execution.parallelism == 1` in Phase 1.
- [x] Reject `execution.parallelism > 1` with a clear not-implemented error
      until the scheduler phase is complete.
- [x] Add a scheduler that honors case locks.
- [x] Run only `parallel-safe` cases concurrently.
- [x] Keep IAM propagation, STS, shared bucket, OIDC, LDAP, and global config
      cases serial unless they have proven isolation.

Lock model:

```rust
ProtocolLock {
    scope: LockScope::Tenant,
    name: "target",
    mode: LockMode::Exclusive,
}

ProtocolLock {
    scope: LockScope::Bucket,
    name: "s3c-run123-caseabcd-0",
    mode: LockMode::Exclusive,
}
```

Lock scopes:

```text
tenant
endpoint
bucket
bucket-prefix
iam-prefix
iam-user
iam-policy
iam-role
admin-api
external-idp
```

Lock modes:

- `shared`: multiple cases may hold the lock when they only read shared state.
- `exclusive`: only one case may hold the lock when it creates, modifies, or
  deletes state.
- Phase 1 runs serially and does not need to emit typed locks. It should record
  `isolation: case` and `serial: true` for selected cases. The typed lock model
  is frozen only when the Phase 6 scheduler is implemented.

Parallel-safe requirements:

- Unique bucket or bucket prefix
- Unique IAM name and path prefix
- Unique role and policy names
- Unique artifact directory
- No shared global admin state
- No prefix-wide cleanup that can remove another running case
- No `tenant`, `admin-api-global`, or external identity-provider write lock
- Passing parallel-pollution regression tests that intentionally run neighboring
  cases concurrently and prove no cross-case grant or cleanup leakage

Parallel execution uses one persisted registry per case under
`cases/<case-id>/resource-registry.json`. A worker never holds a shared mutable
suite registry across network I/O. Case cleanup operates only on that registry;
suite fallback and standalone artifact-root cleanup discover and replay every
case registry before cleaning the root preflight registry.

## Assertion Model

- [x] Treat expected S3 errors as successful assertions.
- [x] Preserve raw error code, HTTP status, request id, and operation metadata.
- [x] Add explicit assertion helpers for allowed and denied flows.
- [x] Distinguish setup failures, policy propagation failures, assertion
      failures, and cleanup failures.
- [x] Normalize assertions into stable classes while keeping raw S3 response
      details for debugging.
- [x] Record every assertion as structured data in `case-report.json`.

Required assertion helpers:

```rust
expect_ok(operation)
expect_access_denied(operation)
expect_no_such_bucket(operation)
expect_no_such_key(operation)
expect_malformed_policy(operation)
expect_expired_token(operation)
expect_invalid_token(operation)
```

Required assertion fields:

- Case id
- Actor id and credential source
- Operation name
- Bucket, object key, prefix, and resource ARN when available
- Grant source and policy effect under test
- Expected assertion class
- Actual normalized assertion class
- Raw S3 error code
- HTTP status
- Request id
- Retry count
- Elapsed time
- Phase attribution: `setup`, `assertion`, `propagation`, or `cleanup`

## Eventual Consistency

- [x] Add a standard retry helper for authorization propagation.
- [x] Retry only known transient errors.
- [x] Never hide final assertion failures behind sleeps.
- [x] Record retry count and elapsed time in the case report.

Transient examples:

- `AccessDenied` immediately after policy attach when the expected final state is allow
- `InvalidClientTokenId` immediately after STS credential creation
- `NoSuchEntity` immediately after IAM create in known eventually consistent paths

## Artifacts

- [x] Write protocol artifacts under `target/protocol-tests/`.
- [x] Keep protocol artifacts separate from `target/fault-tests/`.
- [x] Emit stable JSON artifacts for plan, summary, case result, registry,
      cleanup, and failure details.
- [x] Redact credentials and session tokens.

Suggested layout:

```text
target/protocol-tests/<timestamp>/<suite-name>/<run-id>/
  protocol-suite.yaml
  protocol-suite-plan.json
  protocol-suite-summary.json
  preflight-summary.json
  run-events.jsonl
  resource-registry.json
  cleanup-report.json
  protocol-failure-summary.json
  protocol-artifact-validation-report.json   # Phase 2
  cases/
    <case-id>/
      case-report.json
      operation-history.jsonl
      protocol-transcript.redacted.jsonl
```

Artifact contract rules:

- Protocol artifacts must not be named like fault artifacts unless they carry a
  compatible schema. Prefer protocol-prefixed names for summaries and
  validation reports.
- `protocol-suite-summary.json` indexes case reports, preflight, cleanup, and
  failure summary paths. It should not duplicate their full content.
- `protocol-failure-summary.json` records the first failing stage, normalized
  classification, selected case id, and primary evidence references.
- `preflight-summary.json` records target fingerprint, endpoint/admin
  reachability, stale resource scan results, and selected cases. Phase 2 adds
  cleanup permission probes.
- `protocol-artifact-validation-report.json` is a Phase 2 artifact. It validates
  that all required files exist, parse, link to each other, and do not contain
  raw secrets.

## Initial Bucket Policy Cases

- [x] `bucket-policy-authenticated-user-rw`
      - Create user.
      - Create bucket.
      - Assert user cannot list or put before policy.
      - Apply bucket policy for list/get/put/delete.
      - Assert allowed list/get/put/delete.
      - Assert unrelated user remains denied.

- [x] `bucket-policy-prefix-scope`
      - Allow access only under one object prefix.
      - Assert writes under allowed prefix succeed.
      - Assert writes outside prefix fail.

- [x] `bucket-policy-explicit-deny-overrides-allow`
      - Attach broad allow and narrow explicit deny.
      - Assert denied operation fails even when broader allow matches.

- [x] `bucket-policy-delete-restores-private`
      - Apply policy.
      - Assert access works.
      - Delete policy.
      - Assert access is denied again.

- [x] `bucket-policy-malformed-policy-rejected`
      - Apply malformed policy.
      - Assert the server rejects it.
      - Assert no partial policy state remains.

## Initial IAM Cases

- [x] `iam-user-managed-policy-readonly`
      - Create user.
      - Create and attach a managed read-only policy.
      - Assert get/list allowed.
      - Assert put/delete denied.

- [x] `iam-user-managed-policy-detach`
      - Create managed policy and user.
      - Attach policy.
      - Assert allowed access.
      - Detach policy.
      - Assert access denied.

- [x] `iam-group-policy`
      - Create group and user.
      - Attach policy to group.
      - Add user to group.
      - Assert access follows group membership.
      - Remove user from group.
      - Assert access denied.

- [x] `iam-explicit-deny-overrides-allow`
      - Attach allow and explicit deny.
      - Assert deny wins.

## Initial STS Cases

- [x] `sts-assume-role-basic`
      - Create parent user.
      - Create role trust policy.
      - Attach role policy.
      - Call AssumeRole.
      - Use temporary credentials for allowed S3 access.

- [x] `sts-session-policy-narrows-role`
      - Role policy allows broad S3 access.
      - Session policy allows only one bucket or prefix.
      - Assert allowed target works.
      - Assert outside target is denied.

- [x] `sts-session-policy-deny-put`
      - Role permits put/get.
      - Session policy permits get only.
      - Assert get works and put fails.

- [x] `sts-expired-token-denied`
      - Create credentials with RustFS's minimum lifetime.
      - Wait for expiration in the dedicated slow suite.
      - Assert access fails with token expiration.

## RustFS Preflight Requirements

This harness targets RustFS, not a matrix of arbitrary S3-compatible servers.
Do not expose feature capability switches such as `sts: optional` in the suite
YAML. If a selected RustFS protocol group requires a RustFS API, that API must
be available or the run should fail during preflight.

Preflight order:

1. Resolve suite and catalog selection without mutating the target.
2. Create the artifact root and initialize `resource-registry.json`.
3. Record target fingerprint with non-mutating probes.
4. Scan stale resources for every configured resource prefix and record the
   results.
5. Phase 2 only: run mutating permission probes after registry initialization.
6. Phase 2 only: clean mutating probe resources through the normal cleanup path.
7. Write `preflight-summary.json` and include it in the resolved plan.

- [x] Detect S3 endpoint availability.
- [x] Detect RustFS admin API availability.
- [x] Detect RustFS IAM management availability when IAM cases are selected.
- [x] Detect RustFS STS availability when STS cases are selected.
- [ ] Detect RustFS OIDC/WebIdentity setup only when OIDC-tagged cases are
      explicitly selected.
- [x] Detect versioning support when cleanup needs versioned bucket cleanup.
- [x] Detect Public Access Block support when its cases are selected.
- [x] Detect that admin credentials can create, attach, detach, and delete IAM
      policies, users, groups, roles, and access keys needed by selected cases.
- [x] Detect that admin credentials can put and delete bucket policies.
- [x] Detect that cleanup can delete objects, versions, delete markers, and
      buckets under the generated resource prefixes.
- [x] Detect the target fingerprint before mutation and write it to
      `preflight-summary.json`, `protocol-suite-plan.json`, and
      `resource-registry.json`.
- [x] Scan for stale resources with every configured resource prefix.
- [x] Phase 1 records stale-resource scan results. Phase 2 freezes the default
      fail-closed policy after scoped cleanup commands exist: stale resources in
      `planned`, `creating`, `created`, `cleanup_attempted`, or `failed` state
      stop the run and require explicit cleanup first.
- [x] `warn` stale-resource behavior is allowed only behind a local debug flag;
      never allow it in CI or default suite execution.
- [x] Mutating permission probes must register their probe users, policies,
      roles, access keys, buckets, and bucket policies in `resource-registry.json`
      before the first external mutation.
- [x] Validate that Phase 1 runs use `parallelism: 1` and `cleanup: always`.
- [x] Record preflight results in `protocol-suite-plan.json`.

Case behavior:

- Selected group requires missing RustFS API: fail preflight.
- OIDC/WebIdentity cases are not part of the default suite; run them only when
  selected by tag or case id.
- Expected divergence: follow the status list policy.

## Implementation Phases

### Phase 0: Contract Decisions

- [x] Require a dedicated RustFS protocol-test target for the first
      implementation.
- [x] Define target fingerprint fields and where they appear in artifacts.
- [x] Define `CredentialProvider`, `ActorCredential`, and secret redaction
      rules before adding real cases.
- [x] Define `ProtocolResourceNamer` and bucket/IAM name validators before
      adding real cases.
- [x] Define mutating preflight probe registration and cleanup semantics.
- [x] Choose the stable RustFS admin API surface for identity, policy, and role
      management.
- [x] Choose the initial STS call path, but do not block bucket-policy smoke on
      STS implementation.
- [x] Freeze Phase 1 suite schema fields:
      `apiVersion`, `kind`, `metadata`, `selector`, `execution`, `target`.
- [x] Freeze Phase 1 artifact names and required JSON files.
- [x] Freeze Phase 1 cleanup addressing as artifact-root based. Standalone
      registry-path cleanup belongs to Phase 2.
- [x] Define stale-resource scan fields for Phase 1, but defer fail-closed stale
      policy until Phase 2 cleanup commands exist.
- [x] Record `isolation` and `serial` execution hints in Phase 1 plans. Defer the
      typed lock shape to the Phase 6 scheduler.
- [x] Decide how the runner wrapper exposes safety gates and required env vars.

Phase 0 decisions:

- Phase 1 runs only when `target.ownership.mode` is `dedicated-tenant`,
  `target.safety.dedicatedTarget` is `required`, and the runner receives
  `RUSTFS_PROTOCOL_TEST_DEDICATED=1`. CI has no bypass.
- `protocol-suite-validate` is offline. `protocol-suite-plan` performs only
  non-mutating target probes and therefore requires resolvable admin
  credentials. `protocol-suite-run` persists that resolved plan before the
  first mutation.
- The target fingerprint contains the normalized endpoint, signing region,
  RustFS deployment id, server mode, reported region, and a SHA-256 digest of
  those fields. It appears in `protocol-suite-plan.json`,
  `preflight-summary.json`, and the registry header.
- Phase 1 uses the native `/rustfs/admin/v3` API with AWS SigV4 and JSON bodies.
  It does not use the `/minio/admin/v3` compatibility prefix, whose mutating
  payload contract includes MinIO-specific encryption. S3 operations use the
  existing AWS Rust SDK dependency. STS will use the AWS Query `AssumeRole`
  endpoint in Phase 5 and does not block the first bucket-policy case.
- `CredentialProvider` resolves the logical admin profile at the binary edge.
  Secret-bearing credentials are never serializable and their `Debug` output is
  redacted. Plans and reports contain only provider/profile ids.
- Generated IAM access-key ids are resource identifiers in RustFS. The registry
  may store those generated ids because replayable deletion requires the exact
  identifier; admin access-key ids, all secret keys, and all session tokens are
  forbidden in artifacts. Case reports refer to generated actors by actor id.
- The resource registry is persisted with write, file sync, atomic rename, and
  parent-directory sync after every transition. Phase 1 mutating preflight is
  disabled; Phase 2 probes must use the same registry with
  `owner_phase=preflight` before mutation.
- Phase 1 cleanup accepts only an artifact root and loads the registry from it.
  Standalone registry cleanup, retention modes, parallelism, and mutating
  preflight remain rejected until their later phases.
- Bucket and IAM names are derived from configured prefix, run token, case
  token, resource kind, and counter. Full case ids remain in artifacts; compact
  external names are validated before use.
- Phase 1 required artifacts are `protocol-suite.yaml`,
  `protocol-suite-plan.json`, `preflight-summary.json`,
  `resource-registry.json`, `cases/<case-id>/case-report.json`,
  `cleanup-report.json`, and `protocol-suite-summary.json`.
- The runner wrapper requires the endpoint, env credential provider variables,
  and the dedicated-target acknowledgement. It owns environment checks and log
  capture only; Rust owns selection, expected results, cleanup ordering, and
  artifact contracts.

### Phase 1: Minimal Protocol E2E Closure

- [x] Add `src/protocol/` module.
- [x] Add `ProtocolSuite` schema.
- [x] Add catalog and case metadata.
- [x] Add suite template, validate, plan, and run commands.
- [x] Add serial runner.
- [x] Validate that `parallelism == 1`.
- [x] Validate that `cleanup == always`.
- [x] Add protocol artifact layout.
- [x] Add `ResourceRegistry` with atomic state transitions.
- [x] Add `ProtocolResourceNamer` with S3 bucket and IAM name validation.
- [x] Add `CredentialProvider` and `ActorCredential` without writing raw secrets
      to artifacts.
- [x] Add S3 client wrapper needed by bucket policy smoke.
- [x] Add admin client wrapper needed by bucket policy smoke.
- [x] Add bucket, identity, and bucket-policy fixture helpers needed by one
      smoke case.
- [x] Implement `bucket-policy-authenticated-user-rw`.
- [x] Add allow/deny assertion helpers.
- [x] Add policy propagation retry helper.
- [x] Record a non-mutating preflight summary, including endpoint reachability,
      target fingerprint, selected cases, and stale-resource scan results.
- [x] Run case cleanup immediately after the case.
- [x] Run suite fallback cleanup from registry.
- [x] Write `preflight-summary.json`, `case-report.json`,
      `cleanup-report.json`, and `protocol-suite-summary.json`.
- [x] Add a basic artifact sanity check for required Phase 1 files and raw secret
      leakage. The full protocol artifact validator belongs to Phase 2.

Implementation status: the offline contract, adapter boundary, success path,
assertion-failure cleanup path, interruption cleanup path, and artifact linkage
checks are implemented. The original 12-case bucket-policy, IAM, and STS set
has passed against a dedicated live RustFS target, including standalone
artifact validation and zero-leftover cleanup. New compatibility cases are
covered by the scheduled live gate described in `docs/S3_PROTOCOL_TESTING.md`.

Phase 1 is complete only when this flow works end to end:

```text
preflight
create user
create bucket
assert denied before policy
apply bucket policy
assert allowed in scope
assert unrelated user denied
cleanup case resources
run suite fallback cleanup
run basic artifact and secret checks
```

### Phase 2: Fixture And Cleanup Hardening

- [x] Add complete cleanup dependency ordering.
- [x] Add cleanup retry behavior for transient S3/admin errors.
- [x] Add versioned bucket cleanup.
- [x] Add delete marker cleanup.
- [x] Add mutating preflight permission probes that register probe resources in
      the registry.
- [x] Add fail-closed stale-resource preflight policy.
- [x] Add `protocol-cleanup <artifact-root>`.
- [x] Add `protocol-cleanup --registry <resource-registry.json>`.
- [x] Add cleanup failure tests with forced mid-run interruption.
- [x] Add `protocol-validate-artifacts`.
- [x] Add `protocol-artifact-validation-report.json`.
- [x] Add secret redaction validation for all artifacts.

### Phase 3: Bucket Policy Coverage

- [x] Implement remaining initial bucket policy cases.
- [x] Add malformed policy assertions.
- [x] Add prefix-scope matrix cases.
- [x] Add explicit-deny matrix cases.
- [x] Add delete-policy-restores-private case.
- [x] Add operation history artifacts for every case.
- [x] Validate cleanup on success, assertion failure, and setup failure.

### Phase 4: IAM

- [x] Implement user policy cases.
- [x] Implement managed policy attach/detach cases.
- [x] Implement group policy cases.
- [x] Implement explicit deny cases.
- [x] Extend cleanup for IAM resources.
- [x] Reuse the typed authorization matrix instead of duplicating assertion
      logic from bucket policy cases.

RustFS exposes direct user/group policy mappings backed by named policy
documents rather than a separate inline-policy document endpoint. The
`iam-user-managed-policy-readonly` case therefore tests named managed-policy
semantics while registering and cleaning the backing policy explicitly.

### Phase 5: STS

- [x] Implement AssumeRole client.
- [x] Implement basic AssumeRole case.
- [x] Implement session policy narrowing cases.
- [x] Implement token expiration case where supported.
- [x] Redact session credentials in artifacts.

RustFS clamps `DurationSeconds` to a minimum of 900 seconds. The expiration case
therefore lives in `protocol/examples/slow-regression.yaml`, outside the normal
full suite. It waits for the real lifetime plus a small grace period and
requires the signed S3 request to fail as `ExpiredToken`.

### Phase 6: Parallel Scheduler

- [x] Add lock-aware scheduler.
- [x] Add `parallel-safe` tag enforcement.
- [x] Add per-worker resource prefixes.
- [x] Add parallel cleanup safety tests.
- [x] Default `parallelism` to `1` until proven reliable.
- [x] Add regression tests that intentionally run neighboring authz cases
      concurrently and verify no policy, identity, or cleanup leakage.

The five bucket-policy cases are marked `parallel-safe` and pass on a dedicated
RustFS target with `parallelism: 3` in two scheduler waves. IAM and STS cases
remain serial because their propagation and token-revocation behavior has not
been promoted to the parallel-safe contract.

### Phase 7: Compatibility Expansion

- [x] Import selected Ceph-style S3 compatibility cases into the catalog.
- [x] Maintain implemented, unimplemented, excluded, and expected-divergence
      lists.
- [x] Add optional Mint or SDK compatibility checks as a separate compatibility
      layer, not as the primary authorization test harness.
- [x] Classify every test in the pinned Ceph source index.
- [x] Define and validate the bounded native compatibility profile.
- [x] Add strict scheduled live RustFS and Mint gates.

The native catalog maps ten Ceph reference nodes to nine native cases: bucket
head, bucket lifecycle and empty listing variants, key count,
put/overwrite/get/delete, same-bucket copy,
multi-object delete, small multipart completion retry, version-head removal,
and Public Access Block round-trip. The mapping and status lists live under
`protocol/compatibility/` and are pinned to ceph/s3-tests revision
`5522d1c351f75bc00ae0f64f742f3f095f5939d9`. A generated checked-in index
classifies all 976 upstream pytest node ids. The CLI validates exact source
coverage, disjoint statuses, one-to-one or table-driven mapping shape,
resolvable native mappings, source-index drift, domain coverage, and the
complete native profile in `native-profile.yaml`.

Broader multi-SDK coverage remains an explicit outer compatibility layer:
`scripts/protocol-compatibility.sh mint` runs a digest-pinned Mint image,
requires a dedicated target acknowledgement, writes separate artifacts, and
supports report-only or strict failure behavior. The scheduled live workflow
uses strict mode, so any Mint compatibility failure fails the job. It does not
affect native authorization suite selection or verdicts.

## Open Decisions

- [x] Decide whether a future explicit opt-in mode may run against an existing
      tenant. Phase 1 should require a dedicated target.
- [x] Decide how protocol results should appear in the existing console viewer:
      generic artifact index or a protocol-specific viewer.
- [x] Decide whether compatibility imports should live as protocol cases or as a
      separate external compatibility layer.
- [x] Decide when OIDC/WebIdentity cases should be added and how their external
      identity-provider state is isolated.

Decisions:

- Existing tenants remain unsupported. Protocol runs and cleanup require the
  dedicated-target acknowledgement; no opt-in shared-tenant mode is planned
  until ownership can be proven without prefix-wide discovery.
- Protocol artifacts use the generic artifact index. A protocol-specific viewer
  is not justified while the stable JSON reports remain small and directly
  inspectable.
- OIDC/WebIdentity cases enter the catalog only with an explicit external IdP
  fixture provider. They must hold an exclusive `external-idp` lock, run
  serially, and register provider-side cleanup coordinates without persisting
  client secrets or tokens.

## Development Acceptance Criteria

Phase 1 is ready to implement when:

- [x] Phase 0 decisions are written down in this document or in the initial PR.
- [x] The suite schema has no optional capability flags for RustFS features that
      selected cases require.
- [x] The selector vocabulary matches the Rust catalog exactly.
- [x] `parallelism > 1` and cleanup modes other than `always` are rejected.
- [x] Bucket and IAM resource naming is deterministic, validated, and safe for
      long case ids.
- [x] Admin and actor credential sources are modeled without leaking raw secrets
      into plans or reports.
- [x] Non-mutating preflight records endpoint reachability, target fingerprint,
      selected cases, and stale-resource scan fields.
- [x] Resource prefix handling lists every prefix used for bucket and identity
      resources.
- [x] The first runner can produce a stable artifact root without running real
      fault tests.
- [x] The first cleanup path is scoped by artifact root. Standalone registry-path
      cleanup remains a Phase 2 item.

Phase 1 is ready to merge when:

- [x] `protocol-suite-template` emits a valid smoke suite.
- [x] `protocol-suite-validate` rejects unknown fields, unsupported
      parallelism, unsupported cleanup modes, and missing target ownership.
- [x] `protocol-suite-plan` writes a deterministic plan with selected case ids,
      target fingerprint, resource prefixes, `isolation: case`, `serial: true`,
      cleanup policy, and the source revision when invoked through the repository
      wrapper.
- [x] `protocol-suite-run` executes
      `bucket-policy-authenticated-user-rw` against a RustFS test target.
- [x] The case proves both denied and allowed authorization paths against a live
      RustFS target.
- [x] Case cleanup runs after success and after assertion failure.
- [x] Suite fallback cleanup can replay from `resource-registry.json`.
- [x] Stale-resource scan results cover every configured resource prefix and are
      recorded before mutation.
- [x] Long case ids produce valid bucket and IAM resource names.
- [x] Basic artifact checks verify summary, case report, registry, cleanup
      report, preflight summary, and raw secret redaction for Phase 1 files.
- [x] No protocol artifact is written under `target/fault-tests/`.
- [x] No admin access key, secret key, session token, or admin credential appears
      in artifacts. Generated actor access-key ids appear only in the resource
      registry because exact identifiers are required for cleanup replay.

## Non-Goals

- Do not rewrite the fault-test suite.
- Do not turn YAML into a protocol-testing language.
- Do not depend on previous cases for data or policy state.
- Do not rely on destroying the whole server process for cleanup.
- Do not enable parallel execution before resource isolation is proven.
- Do not store admin access keys, secret keys, or session tokens in artifacts.
  Generated actor access-key ids may appear only in the resource registry for
  exact cleanup replay.
