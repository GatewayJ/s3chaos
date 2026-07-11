# Fault Suite Roadmap

Detailed durability fault-testing design: see
[`DURABILITY_FAULT_TESTING_DESIGN.md`](DURABILITY_FAULT_TESTING_DESIGN.md).

Ordered durability implementation TODO, including PR #15 review feedback: see
[`DURABILITY_FAULT_TESTING_TODO.md`](DURABILITY_FAULT_TESTING_TODO.md).

This document tracks the next architecture steps for the fault-suite runner. The
current suite format is valid for selecting catalog scenarios, repetitions,
durations, percent overrides, workload object count, workload concurrency, and
suite budgets. It should not grow into a free-form Chaos Mesh passthrough before
the runner has an auditable plan and stronger safety boundaries.

## 1. Consolidate Bash And Rust Responsibilities

Status: first implementation pass added Rust-owned suite planning through
`s3chaos fault-suite-plan <suite.yaml>` and made suite runs persist the resolved
plan as `suite-plan.json`.

- Move more execution contract ownership into Rust: suite planning, artifact
  layout, budget decisions, and runtime validation.
- Keep `scripts/fault-test.sh` as a thin operational wrapper for shell-specific
  setup, build preparation, process supervision, and cluster cleanup.
- Keep hardening `s3chaos fault-suite-plan <suite.yaml>` as the exact
  destructive-plan review surface before execution.
- Include each attempt's scenario, repetition, resolved fault duration, selected
  fault, target, workload profile, expected backend, required CRDs/tools, artifact
  paths, and budget impact in the plan output.
- Treat the plan output as the review surface for operators before expanding
  YAML expressiveness.

## 2. Extend The Suite YAML Contract

Status: implementation passes added catalog-declared `params.kind` support for
network delay/loss/corrupt/duplicate, IO latency, CPU stress, and memory stress,
plus named `workloadProfiles` with operation weights, payload distribution, and
hotspot behavior. Scenarios select a profile with `workloadProfile`; scenario
`faultDuration` is only the fault injection window, and `suite.budgets.maxDuration`
is the protective suite budget. Plans and run specs now carry the resolved
parameters, selected workload scale, operation mix, payload distribution, and
hotspot behavior used by execution.

- Harden and extend typed scenario parameters instead of exposing raw backend
  manifests.
- Let supported scenarios declare safe parameter schemas, such as network delay,
  packet loss, IO fault mode, target selection policy, or stress intensity.
- Extend workload profiles beyond `objects` and `concurrency` with operation
  mix, payload distribution, multipart ratio, read/write/delete/list weights,
  and hotspot behavior.
- Keep validation strict: unknown fields, unsupported params, unsafe values, and
  scenario/backend mismatches must fail before any destructive work starts.
- Preserve catalog-backed behavior so YAML describes intent while Rust owns the
  supported fault semantics.

## 3. Abstract Fault Backend Ports

Status: third implementation pass keeps the applied-fault lifecycle behind the
`FaultBackendHandle` port and moved backend-specific apply/spec construction into
the Chaos Mesh and host adapters. The runner now selects the backend family and
wraps adapter results in lifecycle handles; backend modules own manifests,
command-specific specs, and pre-apply pod identity capture. Backend intent
mapping is now split into pure spec builders with focused tests before any
Kubernetes side effects run. Remaining cleanup is optional: move the
runner-local handle wrappers out if more backends make that stateful lifecycle
logic grow.

- Formalize the existing runner-local backend handle into a clear fault-domain
  port for apply, wait-active, snapshot, ensure-active, delete, and cleanup
  operations, or document why it should remain runner-local.
- Keep Chaos Mesh, device-mapper, and future backends as adapters behind that
  port.
- Avoid adding a new backend until the scenario parameter model is stable enough
  that backend adapters do not define user-facing semantics.
- Keep backend-specific manifests, command invocations, status parsing, and
  cleanup details out of suite parsing and planning code.

## 4. Extend Scenario Coverage Toward The RustFS Reliability Plan

Status: versioned workload mode landed. `RUSTFS_FAULT_TEST_WORKLOAD_VERSIONING`
enables bucket versioning, records version ids in `history.jsonl`, verifies the
full committed version lineage by `versionId` GET after recovery, and asserts
deleted keys keep a delete marker as their latest version (resurrection check).

The current catalog covers inject-recover-verify faults. The RustFS reliability
plan (rustfs repository, `docs/testing/reliability-test-plan.md`) needs the
stateful operational flows on top, in this order:

- Quorum-parameterized fault targeting: inject IO faults into exactly P or P+1
  volumes of one erasure set, asserting reads survive at P and writes are
  rejected cleanly past the write quorum instead of half-committing.
- Fresh-volume replacement: delete one RustFS PVC and pod so the StatefulSet
  rebuilds an empty volume, then assert automatic format heal plus full data
  heal converges with no client-visible corruption. This is the Kubernetes
  equivalent of swapping in a blank disk.
- Admin-ops scenario family as catalog-owned product/recovery operations or
  observers, not as fault backend behavior: drive RustFS admin APIs (heal,
  decommission, rebalance) as orchestrated scenario steps with the same
  workload/history/checker verdict. Decommission needs a multi-pool Tenant shape
  first.
- On-disk bitrot: flip bytes inside a shard file on the host volume, then
  assert the read path rejects corrupt data and scanner/heal repairs the shard.
  IOChaos read mistakes do not exercise the on-disk heal closure.
- Long-run chaos mode: repeat scenario rounds under one continuous workload
  with periodic full verification and fd/RSS trend gates for leak detection.

## 5. Add Console And Reporting Surfaces

- Design a console-facing summary format for suite plans, live attempt status,
  artifact locations, health-guard decisions, and final verdicts.
- Link suite summaries to run specs, event streams, checker reports, workload
  summaries, and fault evidence.
- Keep suite summaries structured: `failures[]` is the ordered failure index,
  and `stopReason` points at the entry that stopped the suite early.
- Keep the console surface read-only at first; execution should continue through
  the CLI until authorization, audit, cancellation, and blast-radius controls are
  explicit.
- Use the console requirements to shape stable report JSON instead of parsing
  human-oriented logs.
