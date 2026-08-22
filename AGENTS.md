# S3Chaos Agent Instructions

S3Chaos exists to serve RustFS: it provides S3 protocol compatibility
testing and fault-injection/recovery-verification testing against RustFS
deployments on Kubernetes. Every scenario, case, suite, and artifact in this
repository ultimately exists to prove or disprove a property of RustFS.
When a design decision is ambiguous, choose the option that produces the
clearest evidence about RustFS behavior.

## Precedence

1. System/developer instructions.
2. The current user request.
3. This file.

## Operating Model

- Inquiry, diagnosis, review, and planning tasks are read-only unless the user
  explicitly requests changes.
- For implementation, read the relevant code and tests first, then make
  the smallest change that satisfies the request.
- State assumptions only when they affect behavior or verification. Ask only
  when a wrong assumption would materially change the result.
- Start implementation from the latest `origin/main` and confirm the requested
  change is not already present.

## Repository Layout

- `src/fault/` — fault-injection framework: scenario catalog, Chaos Mesh and
  host device-mapper backends, workload generation, history capture,
  post-recovery verification, run lifecycle, console.
- `src/protocol/` — S3 protocol harness: native cases (`cases/`), capability
  catalog (`catalog/`), S3/STS/admin/Keycloak clients, fixture registry with
  durable cleanup, preflight, runner, reporting.
- `src/framework/` — shared Kubernetes/kubectl plumbing: kube client,
  port-forward, tenant factory, wait helpers.
- `src/bin/s3chaos.rs` — CLI entry point (`s3chaos` binary); the
  `src/bin/s3chaos/` directory holds its console server module.
- `scripts/` — thin shell entry points invoked by Make targets.
- `protocol/compatibility/` — pinned Ceph s3-tests classification data.

## Sources of Truth

- Local gates: `Makefile`.
- CI gates: `.github/workflows/ci.yml` and `.github/workflows/protocol-live.yml`.

## Change Style

- Preserve existing control flow unless changing it is required for correctness.
- Prefer a direct local edit over new files, wrappers, or speculative
  abstractions.
- Before adding helpers or constants, search the touched module and
  `src/framework/` for existing equivalents.
- Comments explain non-obvious invariants or reasons. Do not narrate code or
  record change history.

## Compatibility Data Is Pinned

The Ceph s3-tests classification under `protocol/compatibility/` is pinned by
revision, case count (`sourceCaseCount`), and canonical index SHA-256
(`native-profile.yaml`). Never hand-edit classification counts or index
entries; regenerate via `make protocol-update-s3tests-index` (requires network
access). When the revision or case set drifts, validation must fail with
expected and actual values.

## Verification

Select checks from the final task-owned diff:

### Documentation-only changes

- Run `git diff --check`. Skip Cargo checks.

### Rust changes

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets        # or the narrowest test covering the change
```

If you would run all three commands anyway, run `make check` instead; it
fully supersedes them.

### Shell script changes

```bash
bash -n <script>
```

### Behavior-affecting changes to scenarios, suites, or protocol cases

Additionally run the matching static gate before any live run:

```bash
make fault-suite-validate SUITE=...    # suite YAML changes
make protocol-suite-validate SUITE=...
make protocol-compatibility-status     # catalog/classification changes
```

For fault-side or protocol-side script changes, `make fault-check` and
`make protocol-check` each run `check` plus shell lint for their scripts;
run at most one umbrella gate and skip the individual checks it already
covers. `make fault-check` lints only `scripts/fault-test.sh`;
`make protocol-check` lints the other three scripts — for a diff touching
scripts on both sides, also run `bash -n` on any touched script not covered
by the chosen umbrella gate.

Any command that mutates the cluster or a live server requires a prepared
target and explicit user request; this includes `fault-run`, `fault-run-dm`,
`fault-suite-run`, `fault-dashboard-install` (Helm-installs Chaos Mesh),
`fault-cleanup`, `protocol-suite-run`, `protocol-compatibility-mint`, and
`protocol-cleanup`. Never start one as a side effect of an unrelated task.
After an authorized live run, validate the artifacts
(`fault-validate-artifacts <scenario> <artifact-root>` /
`protocol-validate-artifacts ARTIFACT_ROOT=<root>`) BEFORE cleaning up
(`fault-cleanup` / `protocol-cleanup`) using the exact `ARTIFACT_ROOT`
emitted by the run's own output; never guess the path. Validation must
precede cleanup because cleanup deletes registered fixtures — the artifact
root is the only record of a failed or interrupted run. Do not pass
`--allow-non-loopback` to the console unless the user asks for it.

Never weaken a gate to get green: do not suppress lints, ignore tests, or
relax assertions unless changing that policy is itself the reviewed task.

## Adversarial Validation

Adversarial validation applies to final implementation diffs, explicitly
requested adversarial/design reviews, and changes to this file or suite/scenario
contracts that alter execution. Ordinary questions, diagnoses, status reports,
non-adversarial code reviews, and low-risk planning do not trigger it.

Risk and review shape:

- **Exempt:** documentation, comments, formatting, or typos with no runtime,
  build, test, or agent-execution effect.
- **Mechanical:** renames, moves, test/tooling-only changes, and agent-rule
  changes. Run correctness and simplicity lenses.
- Scripts that orchestrate cluster execution (`scripts/*.sh`) are Standard at
  minimum; "agent-rule changes" means wording or formatting only — edits that
  change gates or risk tiers are not mechanical.
- **Standard:** localized behavior changes. Run one integrated final-diff pass
  covering correctness, simplicity, and test coverage; add only domain lenses
  matched by the diff.
- **High risk / substantial PR review:** high risk includes workload
  generation/history semantics, recovery verification and checker logic,
  fixture lifecycle and cleanup, suite orchestration and scheduling, protocol
  capability classification, credential handling, and anything that decides
  pass/fail verdicts or writes artifacts consumed as evidence. Cover all
  applicable lenses using exactly two independent reviewers when delegation is
  explicitly authorized. Split the lenses between them. Otherwise perform two
  fresh sequential passes.

Available domain lenses are correctness, simplicity, test coverage, security
(credentials, secrets, untrusted input), concurrency/durability (async shared
state, cancellation, timeouts, persisted run state), and compatibility (S3
semantics versus AWS/Ceph behavior, pinned classification consistency). Select
lenses by changed behavior, not by path name alone.

A finding must name a concrete input/state/interleaving and wrong outcome, or a
specific missing regression check, with `file:line`. Resolve it by fixing the
diff or rebutting it with code-path/test/invariant evidence. After a non-trivial
fix, rerun only affected lenses against the new exact diff.

## Git Baseline

- Follow Conventional Commits; keep the subject at most 72 characters.
- Comments, commits, PR titles, and PR bodies are in English.
- Do not commit secrets, credentials, key material, or one-shot plans,
  trackers, or agent scratch notes.
