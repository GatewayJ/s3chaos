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

- [ ] Add a new `src/protocol/` bounded context next to `src/fault/`.
- [ ] Keep `FaultSuite` focused on fault injection, workload disruption, and
      recovery validation.
- [ ] Add a new `ProtocolSuite` schema instead of extending `FaultSuite`.
- [ ] Reuse only lower-level framework utilities from `src/framework/`, such as
      Kubernetes access, port-forwarding, tenant setup, and artifact helpers.
- [ ] Extract or wrap reusable S3 client/history functionality from `src/fault`
      only after the protocol use case needs it.
- [ ] Do not reuse fault artifact validation for protocol results. Create
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

- [ ] Add `protocol-*` CLI commands to `src/bin/s3chaos.rs`.
- [ ] Add matching Makefile targets.
- [ ] Keep protocol commands separate from `fault-*`.

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

- [ ] Add a protocol runner script or Make wrapper that performs preflight,
      invokes the binary, captures logs, and preserves the artifact root.
- [ ] Require an explicit endpoint and admin profile before running.
- [ ] Require a dedicated RustFS protocol-test target by default.
- [ ] Record the target fingerprint in artifacts before mutating resources.
- [ ] Refuse cleanup commands that are not scoped to an artifact root or an
      explicit registry path.
- [ ] Keep protocol safety flags separate from fault flags such as
      `RUSTFS_FAULT_TEST_DESTRUCTIVE`.

## Suite Configuration

- [ ] Keep YAML as a selector and run-control file, not as a test DSL.
- [ ] Define cases in Rust code. Use YAML only to include or exclude groups,
      tags, and named cases.
- [ ] Resolve the suite into a stable JSON plan before execution.
- [ ] Capture endpoint, credentials, selected groups, isolation mode,
      parallelism, cleanup policy, and RustFS preflight results in the plan.
- [ ] For the first implementation, accept only `execution.parallelism: 1`.
      Reject larger values until the scheduler phase lands.
- [ ] For the first implementation, accept only `execution.cleanup: always`.
      Retaining resources for debug must be a separate non-CI debug flag, not a
      default suite mode.
- [ ] Use catalog group ids exactly. Do not introduce YAML aliases such as
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
  ownership:
    mode: dedicated-tenant
    resourcePrefix: s3chaos
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
- `target.ownership.mode`: Phase 1 requires `dedicated-tenant` unless an
  explicit future opt-in mode is added.
- `target.ownership.resourcePrefix`: prefix for all generated resources; the
  actual run prefix must include the generated `run_id`.

## Case Catalog

- [ ] Create a typed `ProtocolCase` catalog.
- [ ] Give every case stable metadata.
- [ ] Use tags for selection and scheduling.
- [ ] Use RustFS API requirements to fail preflight clearly when a selected
      group cannot run.
- [ ] Keep matrix combinations inside the case module, not in YAML.
- [ ] Treat the Rust catalog as the authority. Status lists may override
      run-state behavior, but they must not define new groups.
- [ ] Generate `protocol-catalog-json` from Rust metadata so docs, CLI, and plan
      resolution all use the same vocabulary.

Draft metadata:

```rust
ProtocolCase {
    id: "bucket-policy-authenticated-user-rw",
    group: "bucket-policy",
    tags: &["smoke", "authz"],
    isolation: Isolation::Case,
    requires: &["s3", "admin-api", "bucket-policy"],
    locks: &["tenant", "admin-api-global", "bucket:auto", "iam-prefix:auto"],
}
```

Case groups:

- [ ] `bucket-policy`
- [ ] `iam-user`
- [ ] `iam-group`
- [ ] `iam-policy`
- [ ] `sts-assume-role`
- [ ] `sts-session-policy`
- [ ] `public-access-block`

Case status lists:

- [ ] `docs/protocol-cases/implemented.yaml`
- [ ] `docs/protocol-cases/unimplemented.yaml`
- [ ] `docs/protocol-cases/excluded.yaml`
- [ ] `docs/protocol-cases/expected_divergence.yaml`

Each expected divergence entry must include:

- Case id
- Product or compatibility reason
- Tracking issue or PR
- Expiration or review condition
- Whether the case should fail, skip, or warn

Selector resolution order:

1. Load all cases from the Rust catalog.
2. Apply `selector.groups`, `selector.tags`, and explicit case includes.
3. Apply explicit excludes.
4. Apply status lists:
   - `implemented`: selected cases are runnable.
   - `unimplemented`: selected cases fail validation unless explicitly allowed
     by a development flag.
   - `excluded`: selected cases are skipped with a reason.
   - `expected_divergence`: selected cases run, warn, skip, or fail according to
     the recorded policy.
5. Emit the final selected case set into `protocol-suite-plan.json`.

Authorization matrix model:

- [ ] Avoid one-off case definitions for every policy combination.
- [ ] Model authorization cases as a typed matrix:
      `actor source + grant source + policy effect + operation/resource scope +
      expected result`.
- [ ] Let each group own only the fixture differences:
      bucket policy, IAM user policy, IAM group policy, managed policy, role
      policy, or STS session policy.
- [ ] Keep shared assertion helpers and expected-result normalization in one
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

- [ ] Add `ProtocolRunFixture`.
- [ ] Generate a unique `run_id` for every suite run.
- [ ] Prefix all resources with the `run_id`.
- [ ] Register every resource before or immediately after creation.
- [ ] Persist the registry atomically after every resource state transition.
- [ ] Make cleanup idempotent.
- [ ] Write a cleanup report even when cleanup partially fails.

Default resource naming:

```text
bucket:      s3chaos-<run-id>-<case-id>-<n>
object key:  cases/<case-id>/<actor>/<seq>
user:        s3chaos-<run-id>-<case-id>-user-<n>
group:       s3chaos-<run-id>-<case-id>-group-<n>
policy:      s3chaos-<run-id>-<case-id>-policy-<n>
role:        s3chaos-<run-id>-<case-id>-role-<n>
```

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
- `protocol-cleanup` must be able to replay cleanup from only the artifact root
  or registry path.

Supported isolation levels:

- [ ] `case`: default. Each case owns unique buckets, users, policies, and roles.
- [ ] `group`: allowed only when a group intentionally shares a bucket or IAM
      identity across multiple cases. The group must run serially.
- [ ] `suite`: avoid by default. Use only for read-only compatibility smoke tests.

## Bucket And Data Reuse Rules

- [ ] Default to one bucket per case.
- [ ] Allow multiple object prefixes inside one case.
- [ ] Allow shared buckets only inside an explicit group fixture.
- [ ] Mark any shared-bucket group as serial.
- [ ] Never depend on data created by a previous independent case.
- [ ] Never allow a case to assume another case cleaned policy state correctly.

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

- [ ] Run cleanup after every independent case, even when the case fails.
- [ ] Implement case cleanup with a `finally`/drop-style path so assertion
      failures do not skip resource deletion.
- [ ] Use suite-level cleanup as a final safety pass, not as the primary cleanup
      mechanism.
- [ ] Run suite-level cleanup from `resource-registry.json` after all cases
      finish or when the runner is interrupted.
- [ ] For `group` isolation, clean shared resources after the group finishes,
      not after each case inside the group.
- [ ] Require every `group` isolation fixture to run serially.
- [ ] Record both case cleanup and suite fallback cleanup in
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

- [ ] `always`: default. Clean resources after successful and failed cases.
- [ ] Phase 1 supports only `always`.
- [ ] Later debug retention must be an explicit CLI flag or environment override.
      It must be rejected in CI, require an explicit artifact root, and write a
      leftover-resource report.

## Cleanup TODO

- [ ] Implement `ResourceRegistry`.
- [ ] Write `resource-registry.json` during the run.
- [ ] Write `cleanup-report.json` after cleanup.
- [ ] Trigger case cleanup immediately after each independent case.
- [ ] Trigger group cleanup after a serial group fixture finishes.
- [ ] Trigger suite fallback cleanup after all cases finish.
- [ ] Delete IAM attachments before deleting IAM entities.
- [ ] Delete role policies before deleting roles.
- [ ] Delete bucket policy before deleting the bucket.
- [ ] Delete all objects under the case prefix.
- [ ] Support versioned bucket cleanup.
- [ ] Support delete marker cleanup.
- [ ] Record leftover resources with enough data for manual cleanup.
- [ ] Add `protocol-cleanup <artifact-root>` for retrying cleanup from registry
      data.
- [ ] Add `protocol-cleanup --registry <resource-registry.json>` for emergency
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

- [ ] Start with serial execution.
- [ ] Validate `execution.parallelism == 1` in Phase 1.
- [ ] Reject `execution.parallelism > 1` with a clear not-implemented error
      until the scheduler phase is complete.
- [ ] Add a scheduler that honors case locks.
- [ ] Run only `parallel-safe` cases concurrently.
- [ ] Keep IAM propagation, STS, shared bucket, OIDC, LDAP, and global config
      cases serial unless they have proven isolation.

Lock model:

```text
tenant
endpoint
bucket:<bucket-name>
bucket-prefix:<prefix>
iam-prefix:<prefix>
iam-user:<user-name>
iam-policy:<policy-name>
iam-role:<role-name>
admin-api-global
external-idp:<name>
```

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

## Assertion Model

- [ ] Treat expected S3 errors as successful assertions.
- [ ] Preserve raw error code, HTTP status, request id, and operation metadata.
- [ ] Add explicit assertion helpers for allowed and denied flows.
- [ ] Distinguish setup failures, policy propagation failures, assertion
      failures, and cleanup failures.
- [ ] Normalize assertions into stable classes while keeping raw S3 response
      details for debugging.
- [ ] Record every assertion as structured data in `case-report.json`.

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

- [ ] Add a standard retry helper for authorization propagation.
- [ ] Retry only known transient errors.
- [ ] Never hide final assertion failures behind sleeps.
- [ ] Record retry count and elapsed time in the case report.

Transient examples:

- `AccessDenied` immediately after policy attach when the expected final state is allow
- `InvalidClientTokenId` immediately after STS credential creation
- `NoSuchEntity` immediately after IAM create in known eventually consistent paths

## Artifacts

- [ ] Write protocol artifacts under `target/protocol-tests/`.
- [ ] Keep protocol artifacts separate from `target/fault-tests/`.
- [ ] Emit stable JSON artifacts for plan, summary, case result, registry,
      cleanup, and failure details.
- [ ] Redact credentials and session tokens.

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
  protocol-artifact-validation-report.json
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
- `preflight-summary.json` records target fingerprint, selected API probes,
  cleanup permission probes, stale resource scan results, and selected cases.
- `protocol-artifact-validation-report.json` validates that all required files
  exist, parse, link to each other, and do not contain raw secrets.

## Initial Bucket Policy Cases

- [ ] `bucket-policy-authenticated-user-rw`
      - Create user.
      - Create bucket.
      - Assert user cannot list or put before policy.
      - Apply bucket policy for list/get/put/delete.
      - Assert allowed list/get/put/delete.
      - Assert unrelated user remains denied.

- [ ] `bucket-policy-prefix-scope`
      - Allow access only under one object prefix.
      - Assert writes under allowed prefix succeed.
      - Assert writes outside prefix fail.

- [ ] `bucket-policy-explicit-deny-overrides-allow`
      - Attach broad allow and narrow explicit deny.
      - Assert denied operation fails even when broader allow matches.

- [ ] `bucket-policy-delete-restores-private`
      - Apply policy.
      - Assert access works.
      - Delete policy.
      - Assert access is denied again.

- [ ] `bucket-policy-malformed-policy-rejected`
      - Apply malformed policy.
      - Assert the server rejects it.
      - Assert no partial policy state remains.

## Initial IAM Cases

- [ ] `iam-user-inline-policy-readonly`
      - Create user.
      - Attach inline read-only policy.
      - Assert get/list allowed.
      - Assert put/delete denied.

- [ ] `iam-user-managed-policy-detach`
      - Create managed policy and user.
      - Attach policy.
      - Assert allowed access.
      - Detach policy.
      - Assert access denied.

- [ ] `iam-group-policy`
      - Create group and user.
      - Attach policy to group.
      - Add user to group.
      - Assert access follows group membership.
      - Remove user from group.
      - Assert access denied.

- [ ] `iam-explicit-deny-overrides-allow`
      - Attach allow and explicit deny.
      - Assert deny wins.

## Initial STS Cases

- [ ] `sts-assume-role-basic`
      - Create parent user.
      - Create role trust policy.
      - Attach role policy.
      - Call AssumeRole.
      - Use temporary credentials for allowed S3 access.

- [ ] `sts-session-policy-narrows-role`
      - Role policy allows broad S3 access.
      - Session policy allows only one bucket or prefix.
      - Assert allowed target works.
      - Assert outside target is denied.

- [ ] `sts-session-policy-deny-put`
      - Role permits put/get.
      - Session policy permits get only.
      - Assert get works and put fails.

- [ ] `sts-expired-token-denied`
      - Create short-lived credentials if supported.
      - Wait for expiration.
      - Assert access fails with token expiration.

## RustFS Preflight Requirements

This harness targets RustFS, not a matrix of arbitrary S3-compatible servers.
Do not expose feature capability switches such as `sts: optional` in the suite
YAML. If a selected RustFS protocol group requires a RustFS API, that API must
be available or the run should fail during preflight.

- [ ] Detect S3 endpoint availability.
- [ ] Detect RustFS admin API availability.
- [ ] Detect RustFS IAM management availability when IAM cases are selected.
- [ ] Detect RustFS STS availability when STS cases are selected.
- [ ] Detect RustFS OIDC/WebIdentity setup only when OIDC-tagged cases are
      explicitly selected.
- [ ] Detect versioning support when cleanup needs versioned bucket cleanup.
- [ ] Detect that admin credentials can create, attach, detach, and delete IAM
      policies, users, groups, roles, and access keys needed by selected cases.
- [ ] Detect that admin credentials can put and delete bucket policies.
- [ ] Detect that cleanup can delete objects, versions, delete markers, and
      buckets under the generated resource prefix.
- [ ] Detect the target fingerprint before mutation and write it to
      `preflight-summary.json`, `protocol-suite-plan.json`, and
      `resource-registry.json`.
- [ ] Scan for stale resources with the configured resource prefix and fail or
      warn according to the safety policy before creating new resources.
- [ ] Validate that Phase 1 runs use `parallelism: 1` and `cleanup: always`.
- [ ] Record preflight results in `protocol-suite-plan.json`.

Case behavior:

- Selected group requires missing RustFS API: fail preflight.
- OIDC/WebIdentity cases are not part of the default suite; run them only when
  selected by tag or case id.
- Expected divergence: follow the status list policy.

## Implementation Phases

### Phase 0: Contract Decisions

- [ ] Require a dedicated RustFS protocol-test target for the first
      implementation.
- [ ] Define target fingerprint fields and where they appear in artifacts.
- [ ] Choose the stable RustFS admin API surface for identity, policy, and role
      management.
- [ ] Choose the initial STS call path, but do not block bucket-policy smoke on
      STS implementation.
- [ ] Freeze Phase 1 suite schema fields:
      `apiVersion`, `kind`, `metadata`, `selector`, `execution`, `target`.
- [ ] Freeze Phase 1 artifact names and required JSON files.
- [ ] Freeze cleanup addressing as artifact-root or registry-path based.
- [ ] Decide how the runner wrapper exposes safety gates and required env vars.

### Phase 1: Minimal Protocol E2E Closure

- [ ] Add `src/protocol/` module.
- [ ] Add `ProtocolSuite` schema.
- [ ] Add catalog and case metadata.
- [ ] Add suite template, validate, plan, and run commands.
- [ ] Add serial runner.
- [ ] Validate that `parallelism == 1`.
- [ ] Validate that `cleanup == always`.
- [ ] Add protocol artifact layout.
- [ ] Add `ResourceRegistry` with atomic state transitions.
- [ ] Add S3 client wrapper needed by bucket policy smoke.
- [ ] Add admin client wrapper needed by bucket policy smoke.
- [ ] Add bucket, identity, and bucket-policy fixture helpers needed by one
      smoke case.
- [ ] Implement `bucket-policy-authenticated-user-rw`.
- [ ] Add allow/deny assertion helpers.
- [ ] Add policy propagation retry helper.
- [ ] Run case cleanup immediately after the case.
- [ ] Run suite fallback cleanup from registry.
- [ ] Add `protocol-validate-artifacts`.
- [ ] Write `preflight-summary.json`, `case-report.json`,
      `cleanup-report.json`, `protocol-suite-summary.json`, and
      `protocol-artifact-validation-report.json`.

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
validate protocol artifacts
```

### Phase 2: Fixture And Cleanup Hardening

- [ ] Add complete cleanup dependency ordering.
- [ ] Add cleanup retry behavior for transient S3/admin errors.
- [ ] Add versioned bucket cleanup.
- [ ] Add delete marker cleanup.
- [ ] Add stale-resource preflight policy.
- [ ] Add `protocol-cleanup <artifact-root>`.
- [ ] Add `protocol-cleanup --registry <resource-registry.json>`.
- [ ] Add cleanup failure tests with forced mid-run interruption.
- [ ] Add secret redaction validation for all artifacts.

### Phase 3: Bucket Policy Coverage

- [ ] Implement remaining initial bucket policy cases.
- [ ] Add malformed policy assertions.
- [ ] Add prefix-scope matrix cases.
- [ ] Add explicit-deny matrix cases.
- [ ] Add delete-policy-restores-private case.
- [ ] Add operation history artifacts for every case.
- [ ] Validate cleanup on success, assertion failure, and setup failure.

### Phase 4: IAM

- [ ] Implement user policy cases.
- [ ] Implement managed policy attach/detach cases.
- [ ] Implement group policy cases.
- [ ] Implement explicit deny cases.
- [ ] Extend cleanup for IAM resources.
- [ ] Reuse the typed authorization matrix instead of duplicating assertion
      logic from bucket policy cases.

### Phase 5: STS

- [ ] Implement AssumeRole client.
- [ ] Implement basic AssumeRole case.
- [ ] Implement session policy narrowing cases.
- [ ] Implement token expiration case where supported.
- [ ] Redact session credentials in artifacts.

### Phase 6: Parallel Scheduler

- [ ] Add lock-aware scheduler.
- [ ] Add `parallel-safe` tag enforcement.
- [ ] Add per-worker resource prefixes.
- [ ] Add parallel cleanup safety tests.
- [ ] Default `parallelism` to `1` until proven reliable.
- [ ] Add regression tests that intentionally run neighboring authz cases
      concurrently and verify no policy, identity, or cleanup leakage.

### Phase 7: Compatibility Expansion

- [ ] Import selected Ceph-style S3 compatibility cases into the catalog.
- [ ] Maintain implemented, unimplemented, excluded, and expected-divergence
      lists.
- [ ] Add optional Mint or SDK compatibility checks as a separate compatibility
      layer, not as the primary authorization test harness.

## Open Decisions

- [ ] Decide whether a future explicit opt-in mode may run against an existing
      tenant. Phase 1 should require a dedicated target.
- [ ] Decide how protocol results should appear in the existing console viewer:
      generic artifact index or a protocol-specific viewer.
- [ ] Decide whether compatibility imports should live as protocol cases or as a
      separate external compatibility layer.
- [ ] Decide when OIDC/WebIdentity cases should be added and how their external
      identity-provider state is isolated.

## Development Acceptance Criteria

Phase 1 is ready to implement when:

- [ ] Phase 0 decisions are written down in this document or in the initial PR.
- [ ] The suite schema has no optional capability flags for RustFS features that
      selected cases require.
- [ ] The selector vocabulary matches the Rust catalog exactly.
- [ ] `parallelism > 1` and cleanup modes other than `always` are rejected.
- [ ] The first runner can produce a stable artifact root without running real
      fault tests.
- [ ] The first cleanup command is scoped by artifact root or registry path.

Phase 1 is ready to merge when:

- [ ] `protocol-suite-template` emits a valid smoke suite.
- [ ] `protocol-suite-validate` rejects unknown fields, unsupported
      parallelism, unsupported cleanup modes, and missing target ownership.
- [ ] `protocol-suite-plan` writes a deterministic plan with selected case ids,
      target fingerprint, preflight probe list, and cleanup policy.
- [ ] `protocol-suite-run` executes
      `bucket-policy-authenticated-user-rw` against a RustFS test target.
- [ ] The case proves both denied and allowed authorization paths.
- [ ] Case cleanup runs after success and after assertion failure.
- [ ] Suite fallback cleanup can replay from `resource-registry.json`.
- [ ] `protocol-validate-artifacts` verifies summary, case report, registry,
      cleanup report, preflight summary, and secret redaction.
- [ ] No protocol artifact is written under `target/fault-tests/`.
- [ ] No raw access key, secret key, session token, or admin credential appears
      in artifacts.

## Non-Goals

- Do not rewrite the fault-test suite.
- Do not turn YAML into a protocol-testing language.
- Do not depend on previous cases for data or policy state.
- Do not rely on destroying the whole server process for cleanup.
- Do not enable parallel execution before resource isolation is proven.
- Do not store raw access keys, secret keys, or session tokens in artifacts.
