# RustFS Durability Fault Testing TODO

This TODO is the source of truth for the RustFS durability fault-testing work.
It folds the earlier durability/crash-consistency design discussion and the
PR #15 review feedback into an implementation order. Future work should follow
this file in order unless a new blocker changes the risk ranking.

Status legend:

- DONE: implemented on the current branch or already on `origin/main`.
- PARTIAL: usable foundation exists, but it is not sufficient for the review
  requirement.
- TODO: not implemented.
- BLOCKED: must not be implemented until a prerequisite proof or policy exists.
- DEFERRED: intentionally outside the current roadmap.

## Current Implemented Baseline

- [x] DONE: Ordered TODO and roadmap link.
  Meaning: this file is the implementation entry point and `docs/todo.md` links
  to it.

- [x] DONE: Suite plan extraction.
  Meaning: `suite_plan.rs` owns the pure `fault-suite-plan` model and plan
  expansion; suite execution persists `suite-plan.json`.

- [x] DONE: Basic fault lifecycle port.
  Meaning: `fault_lifecycle.rs` owns `FaultLifecyclePort` and `AppliedFaults`
  for apply/wait/snapshot/delete orchestration.

- [ ] PARTIAL: Backend lifecycle extraction.
  Meaning: the lifecycle container exists, but stateful Chaos Mesh, PodKill, and
  dm-flakey handle wrappers still live in `runner.rs`. Move them only if more
  backend state makes runner ownership unclear.

- [ ] PARTIAL: Failure summary v2.
  Meaning: new writers emit `schema_version`, `phase`,
  `s3_model_classification`, `run_failure_reason`, `responsibility_domain`,
  severity, correctness/availability, evidence classifications, and
  `primary_evidence_refs`. Remaining work is listed below because the review
  found doc/code drift and missing final-checker classification precision.

- [x] DONE: `preflight-summary.json`, `target-proof.json`, and
  `artifact-validation-report.json` are part of the success artifact gate.
  Meaning: runner writes structured preflight/target proof artifacts, run specs
  require them, and artifact validation checks them for successful runs.

- [ ] PARTIAL: Target proof.
  Meaning: current proof resolves RustFS pods, PVCs, PVs, nodes, and
  device-or-path for selector/volume targets. It does not yet prove erasure-set
  identity, data/parity width, or same-set target coverage.

- [ ] PARTIAL: Durability cohorts and fault-window evidence.
  Meaning: history/checker can report `pre_fault`, `fault_active`,
  `post_recovery`, and fault-window relations. This is not the same as a true
  ack-triggered fault executor.

- [x] DONE: LIST timeout/non-completion is separated from successful LIST
  content errors in checker classification.
  Meaning: a LIST request that does not complete is availability/unknown
  evidence, while a completed LIST with wrong content remains correctness
  evidence.

- [ ] PARTIAL: Versioned checker semantics.
  Meaning: committed version reads, delete marker checks, resurrection checks,
  ambiguous writes, and recovery-tail classification exist. Dedicated primary
  classifications such as `committed_version_missing` and
  `delete_marker_missing` are not fully wired as final failure-summary outputs.

- [x] DONE: Read-only artifact console exists.
  Meaning: `fault-console-json` and `fault-console-serve` inspect artifact
  roots.

## Implementation Order

### 1. Keep This TODO And Current Code Aligned Before More Feature Work

- [x] DONE: Remove the stale long-form roadmap from this PR.
  Meaning: this TODO is now the only durability fault-testing work queue in
  `docs/`. Future status drift should be corrected here instead of maintaining a
  second roadmap.

- [ ] TODO: Make failure-summary v2 additions explicitly optional until v3.
  Meaning: `schema_version=2` already exists. New fields that would invalidate
  existing v2 artifacts, especially `observed_at_ms`, must be optional until a
  future v3 contract.

- [ ] TODO: Treat legacy mixed classifications as real run failure reasons while
  the writer still emits them.
  Meaning: keys such as `checker_or_environment`,
  `environment_or_workload`, `workload_or_product`, and
  `product_or_environment` should be documented and validated as current writer
  outputs, not only as legacy reader inputs, until they are replaced.

- [ ] TODO: Fix the `primary_evidence_refs` contract.
  Meaning: the design says no self-reference and suite-root relative paths, but
  current writers include `failure-summary.json` and validation is same-dir. Pick
  one contract, update writer, validator, console, and docs together.

- [ ] TODO: Add exhaustive classification allowlist tests for new writers.
  Meaning: unknown or misspelled classification strings must not silently
  degrade to `needs_investigation`/`unknown` when the writer intended a product
  verdict.

### 2. Add Detector Calibration Before New Destructive Scenarios

- [ ] TODO: Add catalog metadata for detector calibration.
  Meaning: every durability scenario that can be used as a green gate must
  declare what bug family it detects, for example
  `detects=[commit-metadata-loss]` or `detects=[data-shard-loss]`.

- [ ] TODO: Implement the durability-mode calibration ladder.
  Meaning: run each detector against RustFS modes/images where the expected
  result is known: `strict` must pass, `relaxed` must fail for metadata-loss
  families, and `none` or a pinned vulnerable image must fail more broadly. A
  scenario that cannot produce this PASS/FAIL pair is diagnostic-only.

- [ ] TODO: Make calibration evidence mandatory for Phase 4 acceptance.
  Meaning: successful calibration must include mode/image, workload shape,
  target proof, non-empty crash-window cohort, expected classification, actual
  classification, and artifact validation. Missing signal is `no_signal` or
  harness/backend failure, not PASS.

- [ ] TODO: Add explicit expected-failure semantics for diagnostic suites.
  Meaning: P+1/quorum and vulnerable-mode calibration may legitimately exit
  non-zero. The catalog and suite summary need expected classification,
  severity, responsibility domain, and evidence refs before those runs can count
  as passing gates.

### 3. Correct The Soft-Power-Loss Fault Model

- [ ] TODO: Add a dm `drop_writes` actuator path.
  Meaning: EIO/flakey faults exercise error handling, not ACK-then-lost
  durability. `drop_writes` lets writes appear successful to the upper layer
  while the backend discards them, which can expose metadata/data loss after a
  committed ACK.

- [ ] TODO: Add `dmsetup suspend --nolockfs` support where suspend is still
  needed.
  Meaning: default suspend freezes and syncs the filesystem, which can flush the
  exact dirty pages the test is trying to lose. Any crash-like dm path must avoid
  implicit flushes.

- [ ] TODO: Implement true ack-triggered fault execution.
  Meaning: the runner must wait for an eligible committed operation, record
  `trigger_operation_id`, version id, ACK timestamp, and apply the fault within
  `maxAckToFaultMs`. Timeout/unknown/interrupted operations must not arm the
  trigger.

- [ ] TODO: Add a quiet single-write calibration workload.
  Meaning: hot workloads can self-defeat metadata-loss tests because later
  fdatasync/journal activity may persist earlier metadata. The first detector
  should use one committed operation, tight ack-to-fault timing, bounded retry,
  and recorded filesystem commit/writeback parameters.

- [ ] TODO: Assert a non-empty crash-window cohort.
  Meaning: if no committed operation actually fell inside the requested
  ACK-to-fault window, the run did not test the intended failure model and must
  not pass as a product verdict.

### 4. Add Per-Version-Type Quorum Math

- [ ] TODO: Add a quorum table by version/object type.
  Meaning: normal data object loss thresholds are not the same as delete marker
  or size-0 object thresholds. Delete markers and size-0 versions use roughly
  `n/2` parity behavior in RustFS, so a naive P+1 target can green-pass the bug
  class. The catalog must know which threshold applies to PUT, MPU complete,
  delete marker, and size-0 object tests.

- [ ] TODO: Record RustFS erasure-set shape in target proof.
  Meaning: quorum scenarios must prove erasure-set id, total shards, data width,
  parity width, target volumes, target nodes, and non-target coverage before
  injection.

- [ ] BLOCKED: Keep quorum scenarios non-executable until same-erasure-set proof
  exists.
  Meaning: random Pod, node, or volume selection cannot establish that P or P+1
  shards in one erasure set were affected, so it cannot prove the intended
  quorum boundary.

### 5. Implement Volume-Kind Fixed Targeting

- [ ] TODO: Allow `FixedTargets(N)` for RustFS volume fault kinds.
  Meaning: current plan validation rejects fixed target counts for the volume
  family. Quorum IO and heal force-read scenarios need same-kind multi-volume
  targeting without introducing a generic composition DSL.

- [ ] TODO: Render Chaos Mesh or host volume faults for `FixedTargets(N)`.
  Meaning: type-checking a target count is not enough; backend renderers must
  actually target N volumes/pods/devices and record the selected target set.

- [ ] TODO: Keep quorum targeting separate from heterogeneous composition.
  Meaning: quorum P/P+1 is same-kind multi-target IO faulting. It should not
  require a generic multi-phase workflow abstraction or raw YAML backend steps.

### 6. Harden Target-Aware Safety Gates

- [ ] TODO: Make the health guard target-aware.
  Meaning: planned target disruption may be allowed, but control plane,
  non-target nodes, and non-fault tenants remain hard stops. Existing scenarios
  should keep current behavior.

- [ ] TODO: Add host/storage mutation preflight.
  Meaning: before PV replacement, bitrot, stale disk, or dm mutation execution,
  preflight must prove node/device/PV allowlist match, explicit backend-specific
  destructive opt-in, rollback or quarantine command, and post-cleanup
  observation.

- [ ] TODO: Make host/storage mutation preflight side-effect free.
  Meaning: the preflight PR may read Kubernetes/host metadata and write proof
  artifacts, but it must not mutate disks, PV contents, storage objects, or power
  state.

### 7. Wire Precise Final Checker Classifications

- [ ] TODO: Project final checker evidence to product classifications.
  Meaning: final checker failures must map to S3-visible product classes such
  as `committed_version_missing`, `committed_object_unavailable`,
  `delete_marker_missing`, or `version_hash_mismatch`, not generic
  `product_or_environment`.

- [ ] TODO: Split committed version/delete marker/MPU primary classifications.
  Meaning: checker already records many facts; reporting must expose the
  highest-signal one as the primary `s3_model_classification` so #4221-style
  ACK-then-loss is routed to product correctness/availability, not unknown.

- [ ] TODO: Add durability checker goldens.
  Meaning: synthetic histories should cover PUT 200 loss, DELETE 204
  resurrection, committed MPU complete loss, missing version id, ambiguous
  materialization, LIST timeout, and completed LIST wrong content.

### 8. Add The First Calibrated Destructive Smoke Scenarios

- [ ] TODO: Add `dm-drop-writes-after-ack`.
  Meaning: this is the first executable soft-power-loss detector. It should use
  ack-trigger, quiet single-write calibration, `drop_writes`, strict/relaxed/none
  calibration, target proof, and precise final checker classification.

- [ ] TODO: Add `dm-flakey-versioned-hot` only after the detector is calibrated.
  Meaning: hot overwrite/delete/MPU workload is useful for broader regression
  coverage, but it should not be the first ACK-then-loss detector because hot
  workloads can flush or mask the signal.

- [ ] TODO: Add `pod-crash-versioned-hot` as a process-crash proxy and negative
  control.
  Meaning: it proves versioned workload/checker behavior through process
  disruption, but it must not be described as physical power loss.

- [ ] TODO: Add `quorum-p-io-fault` and `quorum-p-plus-one-io-fault`.
  Meaning: these target exactly P and P+1 volumes in one erasure set with
  same-set proof. P is expected to survive; P+1 is release-candidate or
  diagnostic until expected-failure semantics exist.

### 9. Fix Heal-Family Oracle Blind Spots

- [ ] TODO: Add force-read-through-repaired-volume support.
  Meaning: after replacing or corrupting one volume, normal GET can reconstruct
  from other shards and pass even if heal is broken. The scenario must force
  reads through the healed/repaired volume, for example by faulting the other P
  volumes, before declaring heal success.

- [ ] TODO: Add `fresh-volume-replacement-heal`.
  Meaning: replace one PVC/PV with an empty volume, record original and
  replacement generation, quarantine/restore path, heal progress, and then force
  proof that the new volume contains the committed versions.

- [ ] TODO: Add `on-disk-bitrot-heal`.
  Meaning: mutate bytes in one shard on a dedicated host volume, prove exact
  object-to-shard mapping, byte offset, original/mutated hash, rollback path,
  and verify corrupt bytes are never returned as successful S3 data.

- [ ] TODO: Add heal observer artifacts.
  Meaning: `heal-summary.json` and `heal-progress.jsonl` should explain heal
  convergence/non-convergence, but checker/history remain the S3-visible verdict
  source.

### 10. Add Stale Disk, Dangling Cleanup, And Campaign Scenarios

- [ ] TODO: Add disk generation evidence.
  Meaning: stale-disk and fresh-volume flows need PV/PVC/node/device generation,
  mount identity, reattach event, and old/new generation comparison.

- [ ] TODO: Add `stale-disk-return-detect`.
  Meaning: continue writes/deletes while one disk generation is absent, reattach
  the old generation, and prove latest version id, delete marker latest state,
  and object hash do not roll back.

- [ ] TODO: Add `dangling-cleanup-after-ack-loss`.
  Meaning: record shard inventory before/after dangling cleanup and prove the
  cleanup actor did not delete recoverable committed fragments.

- [ ] TODO: Add `long-run-durability-campaign`.
  Meaning: run repeated calibrated scenarios under continuous workload with
  periodic full verification and fd/RSS/artifact-size trend gates for release
  qualification.

### 11. Document Network Faults As A Separate Axis

- [ ] TODO: Mark network partitions as availability/consistency coverage, not
  static durability-loss coverage.
  Meaning: network scenarios are valuable and cheaper to execute, but they do
  not substitute for stale disk, data shard loss, or ACK-then-lost storage
  physics. Multi-target/asymmetric partition can be tracked separately.

### 12. Keep Physical Power Deferred

- [ ] DEFERRED: Real power-cycle backend and power scenarios.
  Meaning: `single-node-power-cycle-after-ack`,
  `delete-marker-hard-poweroff`, `multipart-complete-hard-poweroff`,
  `quorum-p-power-cycle`, and `quorum-p-plus-one-power-cycle` stay out of the
  implementation order until a lab controller can prove target allowlist,
  out-of-band artifact writing, independent recovery, credential scope, and
  network path outside the fault domain.
