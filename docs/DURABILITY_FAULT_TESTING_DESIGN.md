# RustFS Durability Fault Testing Design

This document turns the durability and power-loss discussion into an
implementation plan for s3chaos. It is intentionally scoped to fault testing and
recovery verification for S3-compatible object storage. It must not turn
s3chaos into a general chaos orchestration platform.

## Purpose

The target failure chain is:

1. A client receives a successful S3 response.
2. RustFS data or metadata is still vulnerable to process, node, disk, or
   cluster power loss.
3. After recovery, heal, stale disk return, quorum selection, or dangling cleanup
   may amplify the loss.
4. The test harness must say whether committed S3-visible state was preserved,
   lost, corrupted, unavailable, or still ambiguous.

The product boundary is:

- s3chaos owns the workload, operation history, fault intent, safety gates,
  artifacts, and final verdict.
- Fault backends only actuate supported failure modes and prove that the fault
  was active.
- RustFS internal metadata, heal logs, Kubernetes events, and host evidence help
  explain a verdict, but they do not replace the S3 history/checker verdict.

## Industry Baseline

The design borrows operating principles, not platform shape:

- [Jepsen](https://github.com/jepsen-io/jepsen): keep workload generation,
  nemesis/fault injection, operation history, and checker separate.
- [AWS Fault Injection Service](https://docs.aws.amazon.com/fis/latest/userguide/what-is.html):
  require target proof, stop conditions, bounded blast radius, and experiment
  reports before destructive work.
- [AWS FIS stop conditions](https://docs.aws.amazon.com/fis/latest/userguide/stop-conditions.html):
  stop unsafe experiments rather than trying to continue after guardrail breach.
- [Chaos Mesh Workflow](https://chaos-mesh.org/docs/create-chaos-mesh-workflow/)
  and
  [PhysicalMachineChaos](https://chaos-mesh.org/docs/simulate-physical-machine-chaos/):
  useful actuator references, but not the s3chaos user contract.
- [TiPocket](https://github.com/pingcap/tipocket) and
  [FoundationDB testing](https://apple.github.io/foundationdb/testing.html):
  favor reproducible, evidence-rich fault campaigns over ad hoc one-off chaos
  runs.

## Non-Goals

- No raw Chaos Mesh, device-mapper, power-controller, or Kubernetes manifest
  passthrough in suite YAML.
- No free-form workflow DSL with arbitrary steps, dependencies, scripts, or
  backend resources.
- No console-driven destructive execution in this roadmap. A future artifact
  viewer remains read-only.
- No production or shared-cluster support. Dedicated real Kubernetes/K3s clusters
  remain required.
- No all-node power-off until the controller, artifact writer, and recovery path
  are out-of-band and independently powered.
- No claim that pod kill or dm-flakey is literal physical power loss. Each
  scenario must state its fault model.

## Existing Anchors

The current codebase already has the right backbone:

- `src/fault/suite.rs`: strict YAML contract and suite resolution.
- `src/fault/scenarios.rs`: catalog-owned scenario semantics, backend, target,
  validation, observability, and conflict domain.
- `src/fault/plan.rs`: fault plan construction. It currently rejects multiple
  faults unless an explicit composition policy exists.
- `src/fault/runner.rs`: attempt lifecycle, workload, recovery, and checker.
- `src/fault/history.rs`: S3 operation history, response status, version id, and
  timing.
- `src/fault/checker.rs`: committed object, committed version, delete marker,
  resurrection, ambiguous write, and recovery-tail checks.
- `src/fault/reporting.rs`: failure summary, severity, data correctness, and
  availability mapping.
- `src/fault/artifact_validation.rs`: success artifact contract.
- `scripts/fault-test.sh`: operational wrapper, preflight, health guard, and
  cleanup.

The design below extends those anchors rather than replacing them.

Current implementation status matters for execution order:

- Suite planning, strict YAML validation, reusable `workloadProfiles`,
  scenario-level `workloadProfile`, `faultDuration`, and suite `maxDuration`
  already exist. Later PRs should harden and extract these surfaces rather than
  reintroduce them from scratch.
- A runner-local `FaultBackendHandle` shape already exists. The next step is to
  make lifecycle ownership explicit and testable, not to add a second backend
  abstraction beside it.
- Bucket versioning, version id recording, committed version re-read, delete
  marker checks, and recovery-tail classification already exist in first-pass
  form. Durability work should split and name those verdicts more precisely.
- `continueOnSeverities` controls whether a suite continues after a failed
  attempt. It does not make an expected failure a passing suite result. Any
  diagnostic expected-failure scenario needs an explicit catalog-owned
  expectation model before it can be used as a green gate.
- A fault-test console/artifact viewer is still a future surface in this
  checkout. The stable JSON reader/model must land before any console display
  can depend on v2 fields.

## Architecture

This is the proposed target shape. Some modules already exist; proposed modules
are introduced only when they hide enough complexity to justify the boundary.

```text
Suite YAML
  |
  v
suite.rs
  strict external contract, profile references, scenario names
  |
  v
scenarios.rs + plan.rs
  catalog semantics, typed params, target policy, named composite policy
  |
  v
suite_plan.rs
  auditable plan: attempts, faults, targets, budgets, artifacts
  |
  v
attempt_runner.rs
  one attempt lifecycle: setup, prefill, fault, workload, recovery, checker
  |
  v
fault_lifecycle.rs + backends/*
  apply, wait-active, snapshot, ensure-active, delete, cleanup
  |
  v
history.rs + checker.rs + reporting.rs
  S3-visible source of truth and final verdict
  |
  v
artifact_validation.rs + future artifact viewer
  contract validation and read-only diagnosis
```

Dependency direction:

- Suite parsing cannot import backend implementation details.
- Backends depend on domain fault intent; domain fault intent does not depend on
  Chaos Mesh CRDs, host commands, or power-controller protocols.
- Checker/reporting do not read suite budgets or backend policy.
- Suite stop policy consumes severity and the summary display key; it never
  rewrites checker facts or run failure reasons.

## Execution Readiness Gates

The plan is executable only as vertical slices. A later phase must not rely on an
implicit future contract from an earlier phase.

- Reader-first artifact migration: before new failure fields become required,
  existing readers and future console views must tolerate old
  `failure-summary.json` and `runner-failure-summary.json` files through explicit
  defaults.
- Target proof before actuation: no power, disk, PV replacement, bitrot, stale
  disk, or quorum scenario may execute until a side-effect-free target-proof
  preflight can prove the exact target set. Pure `fault-suite-plan` may stay
  environment-free and should not secretly call Kubernetes, host commands, power
  controllers, or backend secrets.
- Same-erasure-set proof before quorum scenarios: P and P+1 cases are invalid
  unless the plan proves erasure-set id, data/parity width, target volumes,
  target nodes, and non-target volume coverage.
- Expected-failure policy before expected-fail suites: a scenario that is
  expected to fail may be used as a manual diagnostic run, but it must not be
  considered a passing suite attempt until the catalog and suite summary can
  represent expected classification, severity, responsibility domain, and
  evidence refs.
- Out-of-band control proof before real power operations: the controller,
  artifact writer, recovery path, credentials, and network path must be outside
  the fault domain and recorded in preflight evidence.
- Rollback proof before host mutation: any scenario that mutates power state,
  device state, PV contents, shard bytes, or Kubernetes storage objects must
  prove rollback, quarantine, or restore capability before injection.
- Backend-specific destructive opt-in: the generic
  `RUSTFS_FAULT_TEST_DESTRUCTIVE=1` suite switch is not enough for power, PV,
  bitrot, stale-disk, or host-storage mutation. Those backends need their own
  explicit opt-in that wrappers never set implicitly.

## Composition Boundary

Composite faults are allowed only when the catalog defines a named scenario and
an explicit composition policy. YAML continues to select intent:

```yaml
scenarios:
  - name: quorum-p-power-cycle
    workloadProfile: versioned-hot-ack-tail
    faultDuration: 2m
```

YAML does not define backend steps. Rust owns the expansion. The first
implementation should keep `Single` as the default and add exactly one
catalog-owned composite scenario in `scenarios.rs`/`plan.rs`. `FaultPlan::new`
should evolve from "reject multiple faults" to "allow multiple faults only when
that named catalog scenario validates phases, targets, delete policy, and
conflict domains".

Do not introduce a generic `composition.rs`, phase enum family, or user-facing
phase model until a second real composite scenario proves that the abstraction is
shared. Generic target selectors, generic steps, and raw manifests stay out of
scope.

## Core Semantics

Committed operation:

- A write is committed only when the client receives the complete successful
  response: PUT 200, CompleteMultipartUpload 200, or DELETE 204.
- In versioned mode, committed writes and deletes are expected to carry a
  version id. Missing version ids are classified separately.
- Timeout, transport error, body read timeout, SDK unknown, and interrupted
  responses are ambiguous, not committed.
- A committed delete means the delete marker must remain the latest version.
- A committed MPU complete is a committed write. A timed-out complete is
  ambiguous.

Ack-triggered fault window:

- Power-loss scenarios must be able to trigger after a selected committed
  operation, not merely "while workload is running".
- This is a new runner lifecycle, not a small extension of the current
  apply-before-workload flow. The runner owns the trigger boundary: workload
  emits operation events, the runner decides whether a committed operation arms
  the trigger, and only a runner-owned backend handle actuates the fault.
- Suite YAML needs an explicit trigger contract, for example
  `trigger.afterCommittedOperation`, `trigger.maxAckToFaultMs`, and
  `trigger.armPolicy` (`single` first; bounded re-arm only after single-arm
  behavior is stable).
- The trigger evidence must record `trigger_operation_id`, operation kind,
  object key, version id if present, `ack_ended_at_ms`, `fault_apply_started_at_ms`,
  `fault_active_at_ms`, and `ack_to_fault_ms`.
- The plan must declare the maximum allowed `ack_to_fault_ms`. If the harness
  cannot trigger inside that bound, the run is a harness or fault-backend failure,
  not a product verdict.
- Timeout or unknown operations cannot arm an ack-triggered power-loss fault.
- Fake-backend tests must prove no fault is applied before an eligible committed
  ACK, ineligible outcomes do not arm the trigger, and missed
  `maxAckToFaultMs` is reported as harness or backend failure.

Verdict source:

- `history.jsonl` and checker reports are the S3-visible source of truth.
- Internal RustFS evidence can explain why a verdict happened but cannot turn a
  failed S3-visible invariant into a pass.
- Target semantics: successful LIST with wrong content is a correctness signal.
  LIST timeout or incomplete LIST should be availability/unknown unless returned
  content itself violates the model. Current code still promotes final LIST
  warnings into the compatibility `data_corruption` bucket, so Phase 2 must split
  wrong-content from non-completion before `list_unavailable_or_unknown` becomes
  an accepted classification.

## Artifact Model

Keep artifacts few and stable. A new artifact file is allowed only when an
existing summary/report cannot express the evidence without becoming ambiguous
or huge.

Core artifacts:

- `failure-summary.json`: the main failure entry.
- `suite-summary.json`: suite index and stop reason.
- `run-events.jsonl`: lifecycle timeline.
- `fault-evidence.json`: fault activation and recovery proof.
- `checker-pre-recommit-report.json` and `checker-report.json`: S3 model facts.
- `run-spec.json` and `run-spec.yaml`: durable attempt contract.

Conditional artifacts:

- `preflight-summary.json`: one suite/run-level preflight evidence file.
- `artifact-validation-report.json`: emitted by explicit validation or on
  validation failure.
- `recovery-stability-report.json`: emitted when immediate checker failure needs
  bounded re-read classification.
- `versioning-report.json`: emitted only when versioning, stale disk, or delete
  marker scenarios need a compact lineage summary. It summarizes checker facts
  and does not become a second verdict source.
- `runner-failure-summary.json`: shell wrapper companion artifact for scenario
  mode failures. It may be present even when Rust also wrote
  `failure-summary.json`; suite-mode runner failures should get their own
  suite-level projection rather than overloading the case artifact.

Scenario-specific explanatory artifacts:

- `heal-summary.json` and `heal-progress.jsonl`: only for heal/dangling
  scenarios.
- Disk generation and shard inventory evidence: only for stale disk, dangling,
  fresh volume, or bitrot scenarios.
- Kubernetes snapshots, host command output, RustFS logs, and backend manifests:
  explanation only, never verdict source.

### Failure Summary Schema

`failure-summary.json` should evolve as a backward-compatible v2 schema. New
fields are optional while old artifacts remain supported; new writers should
always emit them when the value exists.

Migration rules:

- Add readers and future console support before making writers strict.
- Treat missing v2-only fields in old artifacts as `null`, empty, or
  `unknown`, according to the field semantics.
- Validate v2 fields strictly only when `schema_version >= 2` or when a new
  writer emits the field.
- Keep `classification` as the compatibility display key. It mirrors
  `s3_model_classification` for checker verdicts and `run_failure_reason` for
  non-checker failures.
- Never let suite continuation policy rewrite checker facts. It may decide
  whether to continue, but the binary verdict and failure facts remain in the
  attempt summary.

| Field | Required for new failures | Nullable | Producer | Meaning |
| --- | --- | --- | --- | --- |
| `schema_version` | yes | no | reporting | Summary schema, for example `2`. |
| `scenario` | yes | no | runner/reporting | Catalog scenario or suite-selected name. |
| `run_id` | yes after run id allocation | yes | runner/reporting | Null for preflight failures before allocation. |
| `case_name` | yes after scenario resolution | yes | runner/reporting | Null for suite-level failures. |
| `attempt_index` | yes for suite attempts | yes | suite_runner | Null for single-run or pre-attempt failures. |
| `stage` | yes | no | runner/suite_runner | Existing detailed stage string. |
| `phase` | yes | no | runner/suite_runner | One of `preflight`, `setup`, `fault_injection`, `workload`, `recovery`, `checker`, `cleanup`, `runner`. |
| `classification` | yes | no | reporting | Compatibility/display field. It must equal `s3_model_classification` when present, otherwise `run_failure_reason`. |
| `s3_model_classification` | yes for checker verdicts | yes | checker/reporting | S3-visible data or availability fact. Null for pure preflight/backend/runner failures. |
| `run_failure_reason` | yes for non-checker failures | yes | runner/suite_runner/backend | Why the run failed when no S3 model verdict exists. |
| `responsibility_domain` | yes | no | reporting | Who should investigate first. |
| `severity` | yes | no | reporting | Existing severity contract. |
| `data_correctness` | yes | no | reporting | Existing data correctness contract. |
| `availability` | yes | no | reporting | Existing availability contract. |
| `primary_evidence_refs` | yes | no | reporting | Relative paths to 1-5 highest-signal artifacts. |
| `observed_at_ms` | yes | no | reporting | Event time for the summary. |

`primary_evidence_refs` must be relative paths inside the suite/run artifact
root, never absolute paths and never `..`. In single-run mode that root is the
scenario run root; in suite mode it is the suite run root. The summary artifact
itself is linked by its known location, so `primary_evidence_refs` should contain
only next-hop evidence such as `001-io-eio-r1/.../checker-report.json` or
`io-eio/.../fault-evidence.json`. A missing or escaping evidence ref is an
artifact contract failure for v2 artifacts.

### Preflight Summary Shape

`preflight-summary.json` is one file per suite/run root. It may contain multiple
phases rather than overwriting itself. The run or suite root must be allocated
before preflight starts, and the shell/Rust preflight path must be passed into
the preflight code so failures before scenario execution still leave structured
evidence.

```json
{
  "schema_version": 1,
  "status": "failed",
  "scenario_set": ["io-eio"],
  "checked_at_ms": 123,
  "context": "dedicated-k3s",
  "namespace": "rustfs-fault-test",
  "tenant": "fault-test-tenant",
  "storage_class": "local-path",
  "server_image": "docker.io/rustfs/rustfs@sha256:...",
  "phases": [
    {
      "name": "before_build",
      "status": "passed",
      "checks": [
        {
          "name": "expected_context",
          "status": "passed",
          "expected": "dedicated-k3s",
          "actual": "dedicated-k3s",
          "responsibility_domain": "environment",
          "message": "context matched"
        }
      ]
    }
  ]
}
```

Rust should own the structured model. The shell wrapper may append operational
health observations, but those observations do not replace the checker verdict.
Legacy v1 artifacts that lack `phase`, `responsibility_domain`, or evidence refs
should project derived defaults with warnings; strict validation applies only to
`schema_version >= 2`.

### Classification Model

Use three separate concepts:

- `s3_model_classification`: checker-produced S3-visible fact.
- `run_failure_reason`: runner, suite, backend, or artifact failure reason when
  the checker cannot produce a product verdict.
- `responsibility_domain`: first owner to investigate.

Current compatibility display keys:

| Classification | Severity | Data correctness | Availability | Responsibility | Primary evidence |
| --- | --- | --- | --- | --- | --- |
| `committed_object_unavailable` | `fail_availability` | `unknown` | `committed_object_unavailable` | `product` | `checker-report.json` |
| `recovery_tail_read_latency` | `degraded` | `passed` | `recovered_after_tail_latency` | `product` | `recovery-stability-report.json` |
| `data_corruption` | `fail_correctness` | `failed` | `unknown` | `product` | `checker-report.json` |
| `ambiguous_write_materialized` | `needs_investigation` | `unknown` | `unknown` | `product` | `checker-report.json` |
| `harness_error` | `infra` | `unknown` | `unknown` | `harness` | `failure-summary.json` |

Legacy non-checker display keys accepted by v2 readers:

| Legacy classification | v2 projection |
| --- | --- |
| `unknown` | `run_failure_reason=unknown`, `responsibility_domain=unknown`, `severity=needs_investigation` |
| `test_harness` | `run_failure_reason=test_harness`, `responsibility_domain=harness`, `severity=infra` |
| `test_or_environment` | `run_failure_reason=test_or_environment`, `responsibility_domain=environment`, `severity=infra` |
| `environment_or_fault_backend` | `run_failure_reason=environment_or_fault_backend`, `responsibility_domain=fault_backend`, `severity=infra` |
| `product_or_environment` | `run_failure_reason=product_or_environment`, `responsibility_domain=unknown`, `severity=needs_investigation` |

These legacy keys are compatibility inputs only. New writers should prefer
specific `run_failure_reason` and `responsibility_domain` values.

Target v2 S3 model classifications:

| Classification | Severity | Data correctness | Availability | Responsibility | Primary evidence |
| --- | --- | --- | --- | --- | --- |
| `committed_object_unavailable` | `fail_availability` | `unknown` | `committed_object_unavailable` | `product` | `checker-report.json` |
| `committed_version_missing` | `fail_correctness` | `failed` | `unknown` | `product` | `checker-report.json` |
| `committed_version_unavailable` | `fail_availability` | `unknown` | `committed_version_unavailable` | `product` | `checker-report.json` |
| `version_hash_mismatch` | `fail_correctness` | `failed` | `unknown` | `product` | `checker-report.json` |
| `delete_marker_missing` | `fail_correctness` | `failed` | `unknown` | `product` | `checker-report.json` |
| `deleted_object_resurrected` | `fail_correctness` | `failed` | `unknown` | `product` | `checker-report.json` |
| `latest_version_rolled_back` | `fail_correctness` | `failed` | `unknown` | `product` | `versioning-report.json` or `checker-report.json` |
| `stale_disk_generation_accepted` | `fail_correctness` | `failed` | `unknown` | `product` | disk generation evidence and checker report |
| `dangling_cleanup_deleted_committed_fragments` | `fail_correctness` | `failed` | `unknown` | `product` | shard inventory and heal artifacts |
| `version_id_missing_on_committed_write` | `needs_investigation` | `unknown` | `unknown` | `product` | `history.jsonl` |
| `ambiguous_write_materialized` | `needs_investigation` | `unknown` | `unknown` | `product` | `checker-report.json` |
| `list_unavailable_or_unknown` | `fail_availability` | `unknown` | `list_unavailable_or_unknown` | `product` | `checker-report.json` |
| `recovery_tail_read_latency` | `degraded` | `passed` | `recovered_after_tail_latency` | `product` | `recovery-stability-report.json` |
| `data_corruption` | `fail_correctness` | `failed` | `unknown` | `product` | `checker-report.json` |

The target v2 table requires a reporting mapper and golden-test PR before these
strings are used as suite continuation inputs. Until then, unknown target
classifications must not silently fall through to `needs_investigation` in new
writers.

Run failure reasons:

| Reason | Producer | Responsibility | Example |
| --- | --- | --- | --- |
| `preflight_failed` | shell/Rust preflight | `environment` | Wrong context or missing CRD. |
| `fault_backend_unavailable` | backend | `fault_backend` | Chaos Mesh controller unavailable. |
| `fault_not_active` | backend lifecycle | `fault_backend` | Fault resource created but never active. |
| `fault_not_recovered` | backend lifecycle | `fault_backend` | Fault cleanup did not restore the target. |
| `health_guard_failed` | shell health guard | `environment` | Non-fault tenant became non-Ready. |
| `suite_budget_exceeded` | suite_runner | `runner` | Attempt exceeded maxDuration. |
| `recovery_not_converged` | runner/recovery observer | `product` | Heal or readiness did not converge inside the declared recovery window. |
| `artifact_contract_invalid` | artifact_validation | `artifact_contract` | Evidence ref missing or escaping root. |
| `checker_execution_error` | runner/checker | `harness` | Checker could not complete due to harness I/O error. |

Examples:

- HTTP 200 with body stream timeout: `s3_model_classification` may become
  `recovery_tail_read_latency` or `committed_object_unavailable`;
  `responsibility_domain=product`.
- LIST timeout with no wrong returned content: `list_unavailable_or_unknown`,
  not `data_corruption`.
- Node DiskPressure before injection: `run_failure_reason=preflight_failed`,
  `responsibility_domain=environment`.
- Fault resource not active: `run_failure_reason=fault_not_active`,
  `responsibility_domain=fault_backend`.
- Missing version id on a 2xx write: `version_id_missing_on_committed_write`,
  `responsibility_domain=product`.

### Future Artifact Viewer First Screen

The future artifact viewer first screen should show:

1. Result: status, severity, `s3_model_classification ?? run_failure_reason`,
   responsibility domain.
2. Stop point: suite, run id, attempt index, scenario, stage, and whether the
   suite stopped.
3. Impact: data correctness, availability, data loss, corruption, recovery
   seconds.
4. Next evidence: at most five links, ordered from `failure-summary.json`,
   `recovery-stability-report.json`, checker reports, `fault-evidence.json`,
   then runner/health evidence.

The future artifact viewer remains tolerant of missing in-progress files and
reports warnings instead of inventing a verdict.

### Artifact Validation Modes

- Success strict validation: all required artifacts must exist; run-spec JSON and
  YAML must match; fault evidence must prove injected, active, and recovered;
  checker, recommit, and artifact references must be clean.
- Failure diagnostic validation: a case/scenario failure must include
  `failure-summary.json` or scenario-mode `runner-failure-summary.json`; the
  summary must have valid severity, phase, responsibility, and in-root evidence
  refs. Suite-level failures such as suite budget exhaustion must be represented
  in `suite-summary.json.failures[]` and `stopReason`, or in a future suite-level
  runner projection. Those suite-level projections must also carry or derive
  phase, responsibility domain, run failure reason, and evidence refs.
  `runner-failure-summary.json` must at least project into phase,
  responsibility domain, run failure reason, and evidence refs when it is
  present.
- In-progress artifact-view validation: missing files are warnings. The future
  viewer does not fail a running test or infer a final verdict.

Malformed summaries, missing failure summaries after a terminal failure, and
escaping evidence paths are artifact contract failures.

## Phase 1: Contract And Architecture Baseline

Goal: make the durability campaign auditable before adding more destructive
behavior.

Scope:

- Stabilize report schema additions.
- Add `preflight-summary.json`.
- Add `artifact-validation-report.json`.
- Define actuator port ownership before extracting lifecycle code.
- Harden the existing suite plan and backend lifecycle boundaries before moving
  more code.
- Keep all existing scenarios compatible.

PR split:

1. `docs: add durability fault testing design`
   - Add this design.
   - Link it from `docs/todo.md`.

2. `refactor(fault): extract suite plan model`
   - Move existing suite plan structs and pure plan construction out of
     `suite_runner.rs` into `suite_plan.rs`.
   - Preserve current `fault-suite-plan` output.
   - Add plan golden tests for current template output.

3. `refactor(fault): formalize actuator port model`
   - Turn the existing runner-local `FaultBackendHandle` shape into the owned
     lifecycle port, or document why it remains runner-local.
   - Define apply, wait-active, snapshot, recovery proof, delete, cleanup, and
     timeout-recovery request/response types near the backend layer.
   - Keep the runner as the only lifecycle caller until one lifecycle owner is
     explicit.
   - Add fake actuator tests without touching a cluster.

4. `refactor(fault): extract fault lifecycle`
   - Move `AppliedFaults` and backend lifecycle orchestration from `runner.rs`
     into `fault_lifecycle.rs`.
   - Use the formalized actuator port model instead of creating a second
     lifecycle owner.
   - Preserve current single-fault behavior.
   - Add fake backend tests for apply, wait-active, snapshot, reverse delete,
     cleanup, and aggregated cleanup errors.

5. `feat(fault): add diagnostic report fields and validation`
   - Add backward-compatible readers for old and v2 `FailureSummary` shapes.
   - Extend new `FailureSummary` writers with phase, responsibility domain,
     S3-model classification, run failure reason, observed time, and path-safe
     `primary_evidence_refs`.
   - Add `preflight-summary.json`.
   - Add a stable reader/viewer model for responsibility domain and evidence rail
     without requiring v2 fields in old artifact roots.
   - Validate new summary fields only for new-schema artifacts.
   - Validate evidence refs stay inside the artifact root.
   - Keep success artifacts strict and failure artifacts diagnostic.

Acceptance gates:

- `make fault-check`
- `make fault-suite-template | cargo run --quiet --bin s3chaos -- fault-suite-validate /dev/stdin`
- Unit or golden tests for suite plan construction using fixture config, without
  reading cluster state or environment secrets.
- `git diff --check`

Exit criteria:

- No new destructive backend is introduced.
- Existing suite YAML and artifacts remain readable.
- Any future artifact viewer remains read-only.
- A failed setup/preflight has enough artifacts to route investigation.
- The roadmap no longer treats already-landed suite planning, workload profiles,
  versioning, or backend handles as missing prerequisites.

## Phase 2: Checker Semantics And Workload Windows

Goal: make the checker answer the durability question precisely.

Scope:

- Define committed, ambiguous, pre-crash, crash-window, and post-recovery
  cohorts.
- Define ack-triggered fault windows for power-loss scenarios.
- Extend checker/reporting for durability-specific versioning and delete marker
  failures.
- Add workload profiles that exercise overwrite, delete, MPU, and hot keys.

PR split:

1. `feat(fault): record durability cohorts`
   - Add cohort labels derived from operation timing and run phase.
   - Record fault active window boundaries in `run-events.jsonl` and
     `fault-evidence.json`.
   - Preserve the current `OperationRecord` shape with backward-compatible
     optional fields.

2. `feat(fault): split final LIST classification`
   - Split successful LIST wrong-content from LIST timeout, interrupted LIST, and
     incomplete LIST non-completion.
   - Update checker classification, recovery stability classification,
     reporting, artifact validation, and goldens together.
   - Keep compatibility `classification=data_corruption` readable for old
     artifacts, but emit `list_unavailable_or_unknown` only after the mapper is
     explicit.

3. `feat(fault): classify committed version failures`
   - Split current generic correctness failures into committed object,
     committed version, version hash, missing delete marker, and resurrection
     classifications.
   - Keep checker as the single authority. Do not add a competing oracle module.

4. `feat(fault): add ack-triggered fault windows`
   - Add trigger metadata to events and fault evidence.
   - Add a single-arm or bounded re-arm trigger policy so one committed
     operation, not an arbitrary workload interval, defines the crash window.
   - Enforce maximum ack-to-fault delay.
   - Fail as harness or backend failure if no committed operation arms the
     trigger in time.
   - Do not arm the trigger from timeout, unknown, interrupted, or unversioned
     operations when the scenario requires a committed version.

5. `feat(fault): add versioned hot workload profile example`
   - Add a documented reusable suite workload profile for hotspot overwrite,
     delete, LIST, and MPU.
   - Keep `workloadProfiles` as workload scale and operation model.
   - Keep `faultDuration` as fault injection time.
   - Do not imply `workloadProfiles` enables versioning by itself. Until suite
     YAML owns `workload.versioning`, every versioned row requires
     `RUSTFS_FAULT_TEST_WORKLOAD_VERSIONING=1` plus run-spec and artifact
     validation proving `workload.versioning=true`.
   - Do not add hidden built-in workload profile selection.

6. `test(fault): add durability checker goldens`
   - Golden reports for PUT 200 loss, DELETE 204 resurrection, MPU complete loss,
     missing version id, ambiguous materialization, LIST timeout, and successful
     LIST content mismatch.
   - Include timed-out CompleteMultipartUpload materialization.
   - Keep aborted MPU cleanup and orphan part isolation out of the first gate
     unless the test also records explicit HEAD/ListMultipartUploads/ListVersions
     evidence that the client can observe.

Acceptance gates:

- `make fault-check`
- Focused checker unit tests with synthetic histories.
- Artifact validation against success and failure goldens.
- Existing scenario artifact validation remains compatible.
- Golden tests must include old `failure-summary.json` artifacts so v2 migration
  does not break existing result roots.

Exit criteria:

- A 2xx committed operation cannot disappear without a correctness or
  availability classification.
- Ambiguous operations cannot create false data-loss findings.
- DELETE and CompleteMultipartUpload have explicit, reviewable verdict paths.
- Versioned scenarios prove versioning in run spec and artifact validation, not
  only by profile name.

## Phase 3: Target-Aware Preflight And Backend Preparation

Goal: make real destructive runs fail closed before they touch the cluster.

Scope:

- Add target resolution proof.
- Make health guard target-aware.
- Add backend actuator interfaces for future power and disk operations.
- Validate out-of-band recovery requirements without executing them yet.

PR split:

1. `feat(fault): add target resolution proof`
   - Emit selected pods, PVCs, PVs, nodes, devices, erasure-set hints where
     available, and conflict domains.
   - Keep `fault-suite-plan` pure and side-effect-free. It may declare target
     intent and required proof, but it must not read cluster state, host state,
     backend credentials, or actuator secrets.
   - Add a target-proof/preflight path that may read cluster and host metadata
     without applying faults. Store resolved proof in `target-proof.json`,
     `run-spec.json`, and `preflight-summary.json`.
   - Mark scenarios that require erasure-set proof as invalid when the proof is
     unavailable; do not silently fall back to random pod or node selection.

2. `feat(fault): make health guard target-aware`
   - Allow planned target disruption while protecting control plane,
     non-target nodes, and non-fault tenants.
   - Keep DiskPressure and non-fault tenant failures as hard stops.
   - Preserve current behavior for existing scenarios.

3. `feat(fault): add power backend preflight only`
   - Add configuration shape for node power control, allowlist, expected
     context, controller identity, and recovery command.
   - Do not execute power operations.
   - Fail closed without explicit destructive opt-in, backend-specific
     power-operation opt-in, and out-of-band controller proof.
   - Validate that the controller, artifact writer, recovery path, and
     credentials are outside the target fault domain.
   - Negative preflight must prove wrappers do not set the power opt-in
     implicitly.

Acceptance gates:

- `make fault-check`
- Suite plan and preflight negative tests.
- No side-effect `fault-suite-plan` tests: plan/validate cannot apply, delete,
  patch, power-cycle, read backend secrets, or call actuator methods.
- Manual `make fault-preflight SCENARIO=<existing-p0>` on a dedicated cluster.
- Negative power preflight cases must exit non-zero and create no fault
  resources: missing destructive opt-in, target not in allowlist, controller in
  the fault domain, missing recovery proof, non-target node health loss, and
  non-fault tenant health loss.

Exit criteria:

- The plan proves exactly what would be disrupted.
- Preflight can reject unsafe target selection without applying faults.
- Power and disk adapters are present only as preflight-verifiable intents until
  Phase 4 explicitly enables execution.
- Existing Chaos Mesh and dm scenarios still run through the same public
  contract.
- Quorum scenarios remain non-executable until same-erasure-set proof is present.

## Phase 4: Minimal Destructive Durability Smoke

Goal: run the smallest useful destructive evidence path.

Scope 4A, near-power-loss smoke:

- Start with near-power-loss smoke that is safe and diagnosable.
- Treat pod kill and dm-flakey as fault models, not literal power loss.

Scope 4B, true power-cycle smoke:

- Enable real node power operations only when Phase 3 preflight-only safety
  gates pass.
- Keep the artifact writer, controller, and recovery path outside the fault
  domain.
- Preflight must record controller host, power domain, network path, credentials
  scope, recovery command, artifact-writer location, and proof that none live on
  target nodes or target power circuits.
- Require a backend-specific power opt-in that suite wrappers do not set
  implicitly.
- Use ack-triggered fault windows for after-ACK tests.

Recommended scenario order:

1. `dm-flakey-versioned-hot`
   - Dedicated Local PV.
   - Versioning on, proven by `RUSTFS_FAULT_TEST_WORKLOAD_VERSIONING=1`,
     `run-spec.*`, and artifact validation until suite YAML owns
     `workload.versioning`.
   - Hot overwrite/delete/MPU workload.
   - Oracle: committed versions and delete markers survive.

2. `pod-crash-versioned-hot`
   - Existing pod kill or pod failure backend.
   - Versioning on, proven by run spec and artifact validation.
   - Used as a negative control and recovery-tail classifier.

3. `single-node-power-cycle-after-ack` (4B)
   - Out-of-band power backend.
   - One target node only.
   - Artifact writer and controller stay outside the fault domain.
   - Triggered by a committed operation and bounded by `ack_to_fault_ms`.
   - Requires backend-specific power opt-in in addition to the generic
     destructive switch.

4. `quorum-p-power-cycle` (4B)
   - Power off exactly parity count targets.
   - Suite plan and preflight must show erasure-set id, data/parity width,
     target volumes, target nodes, and non-target volume proof.
   - Expected result: committed S3-visible state remains available or recovers
     within the declared window.

5. `quorum-p-plus-one-power-cycle` (4B)
   - Power off parity plus one targets.
   - Expected result: fail with explicit availability/correctness
     classification, not harness ambiguity.
   - This is a diagnostic/release-candidate scenario, not an ordinary PR gate,
     and does not introduce a generic expected-failure DSL.
   - Until expected-failure policy is represented in catalog metadata and
     `suite-summary.json`, this scenario may exit non-zero even when it produced
     the expected evidence. Treat that as a valid diagnostic artifact, not a
     passing suite result.

PR split:

1. `feat(fault): add dm-flakey durability smoke`
   - Catalog scenario, workload profile, run-spec metadata, artifact validation.

2. `feat(fault): add pod crash durability smoke`
   - Catalog scenario using existing pod backend.
   - Clear fault model text in catalog and reports.

3. `feat(fault): enable single node power cycle`
   - Execute only with explicit destructive env/config, backend-specific power
     opt-in, target allowlist, and out-of-band recovery proof.
   - Negative tests must show the suite wrapper does not enable this backend by
     default.

4. `feat(fault): add quorum power cycle scenarios`
   - Catalog-owned P and P+1 scenarios.
   - No generic YAML target DSL.
   - Require same-erasure-set proof before execution.
   - P+1 stays release-candidate/manual unless expected-failure policy has
     landed.

5. `docs(fault): add destructive smoke runbook`
   - Small run values: objects 64, concurrency 8, pinned image digest.
   - Recommended hot workload: versioning on, high overwrite/delete ratio,
     explicit MPU ratio, and request timeout recorded in run metadata.
   - Record `RUSTFS_FAULT_TEST_WORKLOAD_VERSIONING=1` until suite YAML exposes a
     first-class versioning field.
   - Required artifact set and first-failure triage steps.

Acceptance gates:

- Local `make fault-check`.
- Dedicated cluster preflight.
- Clean checkout and recorded commit OID.
- Pinned RustFS image digest.
- Backend-specific destructive opt-in evidence for power, PV, bitrot, stale-disk,
  and host-storage mutation scenarios.
- `fault-evidence.json` proves injected, active during workload, and recovered.
- `checker-pre-recommit-report.json`, `checker-report.json`, and
  `recommit-report.json` are clean for expected-pass scenarios.
- `failure-summary.json` has precise classification for expected-fail scenarios.
- Postflight proves the control plane and non-fault tenants are Ready, managed
  Chaos resources are gone, device-mapper/power state is restored, and cleanup
  snapshots are preserved.
- Expected-fail scenarios may exit non-zero, but they must produce the expected
  classification, severity, responsibility domain, and evidence refs. They must
  not end as `harness`, `unknown`, or missing-artifact failures. A non-zero
  expected-fail run is acceptable diagnostic evidence only when the expected
  classification is explicit in the runbook or catalog. It is not a passing CI
  signal until suite-level expected-failure semantics exist.

Exit criteria:

- A minimal destructive run can be repeated from artifacts and commands.
- Data loss, recovery-tail availability, backend failure, and environment
  failure are distinguishable.
- No full catalog destructive suite is required for ordinary PRs.

## Phase 5: Heal, Stale Disk, Dangling Cleanup, And Campaign Mode

Goal: cover the customer-visible amplification chain after disks return.

Scope:

- Stale disk return.
- Fresh volume replacement.
- Heal and dangling cleanup.
- On-disk bitrot.
- Long-run recovery campaign.

Scenario families:

1. `stale-disk-return-detect`
   - Capture old disk generation.
   - Continue writes/deletes while target is absent.
   - Reattach stale disk.
   - Oracle: latest version id, delete marker latest state, and object hash
     cannot roll back to the stale generation.
   - Must prove how the old disk generation was captured and restored without
     deleting or mutating non-target volumes.

2. `delete-marker-stale-disk-heal`
   - DELETE 204 with versioning on.
   - Reattach stale disk that predates the delete marker.
   - Oracle: deleted object is not resurrected and delete marker remains latest.

3. `dangling-cleanup-after-ack-loss`
   - Create a state where an object was externally committed but enough shards
     appear missing to trigger dangling logic.
   - Evidence: object/version shard map, shard inventory before cleanup,
     dangling cleanup event, cleanup actor, shard inventory after cleanup.
   - Oracle: fragments that were recoverable before cleanup are not deleted by
     dangling cleanup.
   - Requires a product-side trigger that can be isolated from harness-induced
     data deletion; otherwise classify only the S3-visible result.

4. `fresh-volume-replacement-heal`
   - Replace one PVC/PV with an empty volume.
   - Record original generation, quarantine location, replacement generation, and
     restore/cleanup status.
   - Oracle: format and data heal converge without committed data loss.
   - Requires a quarantine path for the original PV/PVC before replacement.

5. `on-disk-bitrot-heal`
   - Flip bytes in a shard on a dedicated host volume.
   - Record target shard, original hash, mutated hash, mutation command, and
     rollback/quarantine evidence.
   - Oracle: corrupt data is not returned as successful S3 bytes; heal repairs or
     reports unavailable explicitly.
   - Requires shard-level target proof and a byte-accurate rollback plan before
     mutation: object-to-shard mapping, file/device identity, byte offset,
     original hash, mutated hash, backup path, mutation command, and rollback
     command. Mutation outside the target shard is a harness failure.

6. `long-run-durability-campaign`
   - Continuous workload.
   - Periodic full verification.
   - Repeated fault rounds.
   - Track recovery-tail latency, fd/RSS growth, and artifact size.

PR split:

1. `feat(fault): add disk generation evidence`
   - PV/PVC/node/device generation, mount identity, and reattach events.

2. `feat(fault): add stale disk return scenarios`
   - Detection-only first. No destructive heal action in the first PR.

3. `feat(fault): add heal observer artifacts`
   - `heal-summary.json` and `heal-progress.jsonl` only for heal scenarios.
   - Internal heal data remains explanatory.

4. `feat(fault): add dangling cleanup scenario`
   - Requires clear product-side trigger and safe rollback path.
   - Requires shard inventory before and after cleanup.

5. `feat(fault): add fresh volume replacement scenario`
   - Dedicated Local PV only.
   - Strict target proof, quarantine, restore, and cleanup evidence.

6. `feat(fault): add on-disk bitrot scenario`
   - Dedicated Local PV only.
   - Device allowlist, target shard proof, mutation proof, rollback evidence.

7. `feat(fault): add durability campaign suite`
   - Named catalog/suite template.
   - Nightly or release-candidate use, not ordinary PR gate.
   - Resource ceilings for artifact size, event tail, fd/RSS trend, and wall
     time.

Acceptance gates:

- Local contract and checker goldens.
- Target-aware preflight.
- One small dedicated-cluster smoke per new scenario family.
- Rollback, quarantine, or restore evidence for every scenario that mutates host
  data, PV contents, or device state.
- No next attempt may start if rollback, quarantine, or target state is
  uncertain after a host or storage mutation.
- Device and node allowlists for every host-level mutation.
- Post-cleanup health and target state verification.
- Artifact validation for pass and fail outcomes.
- Future artifact viewer renders the first screen without reading raw logs for
  verdicts.

Exit criteria:

- The harness can reproduce the post-return amplification chain.
- It can distinguish RustFS data loss, stale-version propagation, delete
  resurrection, dangling deletion, bitrot detection, heal non-convergence, and
  recovery-tail unavailability.
- The campaign is evidence-rich enough for release qualification.
- Host and storage mutation scenarios cannot run unless their target proof,
  allowlist, rollback, and post-cleanup evidence are present.

## Use Case Matrix

| Priority | Proposed catalog scenario | Current executable proxy | Execution status | Injection | Workload and oracle | Required evidence and false-positive guard |
| --- | --- | --- | --- | --- | --- | --- |
| P0 | `dm-flakey-versioned-hot` | `dm-flakey` plus `RUSTFS_FAULT_TEST_WORKLOAD_VERSIONING=1` | Needs catalog/profile PR | Dedicated Local PV through dm-flakey/error/no-flush recovery. | Hot overwrite/delete/MPU workload; committed version GET and delete marker latest must pass. | dm active/recovered snapshots, PV/device proof, history, checker reports. If fault did not hit target device, use `run_failure_reason=fault_not_active`, not product failure. |
| P0 | `pod-crash-versioned-hot` | `pod-kill-one` or `pod-failure` plus versioning env | Needs catalog/profile PR | Pod kill/failure while workload is active. | Version lineage survives; recovery tail is separated from corruption. | Pod identity before/after, restart counts, previous logs, recovery stability report. This is process crash proxy, not physical power loss. |
| P0 | `single-node-power-cycle-after-ack` | none | Blocked on power preflight and trigger lifecycle | Out-of-band power cycle after selected committed ACK. | Ack-triggered PUT/DELETE/MPU operations; committed object/version survives after node recovery. | Trigger op id, ACK time, fault active time, node power proof, checker reports. If `ack_to_fault_ms` exceeds bound, mark harness/backend failure. |
| P0 | `delete-marker-hard-poweroff` | none | Blocked on power preflight and trigger lifecycle | Hard power during delete-heavy ack-triggered workload. | Versioning on, high DELETE weight, interleaved overwrites; delete marker remains latest. | ListObjectVersions evidence, checker report, power proof. DELETE without 204/version id is not committed. |
| P0 | `multipart-complete-hard-poweroff` | none | Blocked on power preflight and trigger lifecycle | Hard power around CompleteMultipartUpload ACK. | Complete 200 is a committed write; timed-out complete is ambiguous. | MPU operation history, version id, checker report, recommit report. Abort/orphan-part checks require explicit observable evidence before becoming gates. |
| P1 | `quorum-p-power-cycle` | none | Blocked on same-erasure-set proof | Power off exactly parity count targets in one erasure set. | EC redundancy survives or recovers within window. | Erasure-set id, data/parity width, target volume list, non-target proof. Random nodes without same-set proof are invalid. |
| P1 | `quorum-p-plus-one-power-cycle` | none | Manual/release-candidate only | Power off parity plus one targets in one erasure set. | Must fail with explicit availability/correctness classification. | Same-set proof, power proof, failure summary. Non-zero is acceptable evidence until explicit expected-failure suite semantics exist. |
| P1 | `stale-disk-return-detect` | none | Blocked on disk generation proof and rollback | Reattach old disk generation after writes/deletes. | Latest version id/delete marker/hash cannot roll back. | Disk generation proof, reattach events, versioning report, checker report. Missing generation proof is harness failure. |
| P1 | `delete-marker-stale-disk-heal` | none | Blocked on disk generation proof and heal observer | Reattach disk predating committed DELETE marker, then observe heal. | Delete marker remains latest and object is not resurrected. | Old/new disk generation, heal summary, ListObjectVersions evidence. Versioning disabled or DELETE not committed invalidates verdict. |
| P1 | `dangling-cleanup-after-ack-loss` | none | Blocked on product trigger and shard inventory | Induce missing shards beyond parity and trigger dangling cleanup path. | Recoverable committed fragments are not deleted by cleanup. | Object/version shard map, inventory before/after, cleanup actor/event, checker report. Without before/after inventory, classify only S3 unavailability, not dangling causality. |
| P2 | `fresh-volume-replacement-heal` | none | Blocked on PV quarantine/restore proof | Replace one PVC/PV with an empty volume. | Heal converges with no committed data loss. | Original and replacement generation, quarantine/restore evidence, heal summary. Non-convergence maps to `recovery_not_converged` plus checker facts. |
| P2 | `on-disk-bitrot-heal` | none | Blocked on shard target proof and rollback | Mutate shard bytes on dedicated host volume. | Corrupt bytes are never returned as successful S3 data; heal repairs or reports unavailable. | Object-to-shard mapping, file/device identity, byte offset, original/mutated hash, backup, mutation and rollback commands. Mutation outside target shard is harness failure. |
| P2 | `long-run-durability-campaign` | none | Release/nightly only | Repeated named scenarios under continuous workload. | Aggregate scenario verdicts and resource trends. | Suite summary, event tail, fd/RSS trend, artifact size report. Resource ceiling breach is runner/environment failure. |

## Review Checklist

Use this checklist for every PR in this plan:

- Does the change preserve s3chaos as a correctness harness instead of a generic
  chaos platform?
- Is the scenario catalog still the owner of user-facing fault semantics?
- Can `fault-suite-plan` explain the destructive plan without side effects?
- Is every new destructive path guarded by preflight, allowlist, target proof,
  stop condition, and cleanup evidence?
- Does the checker remain the source of truth for S3-visible correctness?
- Are ambiguous operations kept separate from committed operations?
- Are artifacts few, stable, path-safe, and artifact-viewer-readable?
- Does the failure summary route ownership through `responsibility_domain`
  rather than vague classification names?
- Can the implementation be merged as a small PR without requiring the next
  phase?

## Suggested PR Order

1. Design doc and roadmap link.
2. Suite plan extraction.
3. Actuator port ownership model.
4. Fault lifecycle extraction with fake backend tests.
5. Failure summary, preflight summary, and artifact validation.
6. Durability cohorts in history/events/evidence.
7. Ack-triggered fault windows.
8. Checker classification goldens.
9. Versioned hot workload profile example.
10. Target resolution proof.
11. Target-aware health guard.
12. Power backend preflight-only adapter.
13. dm-flakey durability smoke.
14. pod crash durability smoke.
15. single-node power cycle.
16. quorum P and P+1 power cycle.
17. stale disk return detection.
18. heal observer artifacts.
19. dangling cleanup scenario.
20. fresh volume replacement scenario.
21. on-disk bitrot scenario.
22. long-run durability campaign suite.
