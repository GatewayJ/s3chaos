# s3chaos

S3Chaos is a testing framework for RustFS, the S3-compatible object store.
It provides two complementary harnesses that run against RustFS deployments
on Kubernetes:

- **Fault injection** (`src/fault/`): injects real failures into a RustFS
  cluster — disk I/O errors, network partitions, pod kills, resource stress,
  quorum loss — drives mixed S3 workloads through the failure window, then
  verifies recovery and data integrity.
- **S3 protocol compatibility** (`src/protocol/`): exercises RustFS's S3 API
  surface with native test cases across authorization, IAM, STS, OIDC,
  bucket policy, and a bounded compatibility supplement alongside Mint.

## Architecture

```
src/
  bin/s3chaos.rs     CLI entry point ("s3chaos" binary); s3chaos/ holds its
                     console server module
  fault/             Fault-injection framework: scenario catalog, backends
                     (Chaos Mesh, host device-mapper), workload generation,
                     history capture, post-recovery checker, run lifecycle,
                     artifact validation, console
  protocol/          Protocol harness: native cases (cases/), capability
                     catalog (catalog/), S3/STS/admin/Keycloak clients,
                     fixture registry with ownership + durable cleanup,
                     preflight, runner, reporting
  framework/         Shared Kubernetes plumbing: kube client, kubectl wrapper,
                     port-forward, tenant factory, wait helpers
scripts/             Shell entry points invoked by Make targets
protocol/
  examples/          Ready-to-run suite YAMLs: smoke, full-regression,
                     slow-regression, oidc-keycloak
fault/
  examples/          Ready-to-run fault suites: canonical Chaos Mesh,
                     focused correctness suites, Warp performance
console/             Web console assets served by the run console
```

The `s3chaos` CLI exposes machine-readable commands (`fault-catalog-json`,
`protocol-catalog-json`, `*-suite-json`, ...) used by scripts, CI, and the
console. There is no
installed binary on a fresh checkout; run commands via Cargo:

```bash
cargo run --quiet --bin s3chaos -- help
```

## Build and Static Checks

```bash
make check            # cargo fmt --check + clippy -D warnings + tests
make fault-check      # check + fault script/YAML validation
make protocol-check   # check + bash -n on protocol scripts
```

## Fault-Injection Testing

The normal correctness workflow uses one foreground command for all ordinary
Chaos Mesh scenarios and one foreground command for exactly one device-mapper
scenario:

```bash
make fault-list                                      # scenario catalog
make fault-chaos-run                                 # canonical 19-attempt suite
make fault-dm-run SCENARIO=dm-flakey-versioned-hot  # one supervised DM run
make fault-console-serve                             # browse run artifacts

# Pin the context, namespace, and tenant recorded in the run's target proof.
export RUSTFS_FAULT_TEST_EXPECTED_CONTEXT='<run-context>'
export RUSTFS_FAULT_TEST_NAMESPACE='<run-namespace>'
export RUSTFS_FAULT_TEST_TENANT='<run-tenant>'
make fault-cleanup                                   # release cluster fixtures
```

Both live targets build once and run cluster preflight once. The Chaos wrapper
uses one pre-run plan pass. A separate `fault-preflight` command is unnecessary.
Use `make fault-chaos-plan` only when reviewing the resolved plan without
starting the suite. Override the canonical suite with
`CHAOS_SUITE=/path/to/suite.yaml`; `fault-chaos-run` rejects static storage and
Warp plans. The generic `fault-suite-*` targets remain available for custom
non-static suites and the separate Warp campaign.

Runnable scenario families (25 executable entries): I/O faults (`io-eio`,
`io-read-mistake`, `io-latency`, `disk-full`, `dm-flakey*`, and the five
typed `dm-drop-writes-after-ack-*` cases), network faults
(`network-partition-one`, `network-partition-write-quorum-loss`,
`network-delay/loss/corrupt/duplicate`), pod faults (`pod-kill-one`,
`pod-failure`, `pod-crash-versioned-hot`), stress (`stress-cpu`,
`stress-memory`), typed volume quorum (`quorum-p-io-fault`,
`quorum-p-plus-one-io-fault`), and the `warp-under-chaos` benchmark campaign.
Each typed volume quorum run captures bounded RustFS admin health samples before
its probes/workload and after the workload/controller recheck; both samples
require every non-target drive to be healthy and do not claim continuous health.
A further five catalog entries are roadmap placeholders with status `Planned`
(`fresh-volume-replacement`, admin decommission and
rebalance, `on-disk-bitrot`, `stale-disk-return-detect`): they appear in
`cargo run --bin s3chaos -- fault-catalog-json` but are filtered out of
`make fault-list` and rejected by preflight and suite validation.
Heal is a recovery mode of replacement and bitrot rather than a standalone
healthy-cluster scenario. Long-running campaigns remain suite orchestration,
not a fault backend or scenario family.
The ordered durability work queue and its safety prerequisites remain in
[`docs/DURABILITY_FAULT_TESTING_TODO.md`](docs/DURABILITY_FAULT_TESTING_TODO.md).
Volume-quorum runs require matching RustFS non-target drive-health observations
before and after the workload. These endpoint guards are not continuous health
monitoring; live qualification is still required before release gating.

Ready-to-run suites under [`fault/examples/`](fault/examples/) keep different
execution environments and verdicts separate:

| Suite | Scope | Additional requirement |
| --- | --- | --- |
| `chaos-mesh.yaml` | Canonical 19-attempt correctness run: smoke, regression, and four typed quorum checks | Dedicated cluster with Chaos Mesh; reference four-server single-erasure-set topology for the write-quorum boundary |
| `smoke.yaml` | Six short correctness and recovery checks across I/O, pod, and network faults | Dedicated cluster with Chaos Mesh |
| `regression.yaml` | Remaining ordinary Chaos Mesh scenarios, including the write-quorum boundary | Reference four-server single-erasure-set topology for `network-partition-write-quorum-loss` |
| `quorum-reliability.yaml` | Four payload/metadata checks at the P and P+1 volume boundaries | Reference four-server single-erasure-set topology |
| `warp-performance.yaml` | Performance-only Warp-under-chaos campaign; correctness still comes from the normal checker | `warp` on `PATH`; Warp defaults to 60 seconds |

The Rust runner owns `budgets.maxDuration` for both `make fault-suite-run`
and direct `s3chaos fault-suite-run` invocations. Expiration fails the suite,
including its final attempt, and stops admitting workload operations. In-flight
multipart operations and cleanup are drained before returning; device recovery
and synchronous external commands may finish after the budget. The shell wrapper
continues to supervise cluster health independently.

Warp planning requires a positive `RUSTFS_FAULT_TEST_WARP_DURATION_SECONDS`
strictly below `faultDuration - RUSTFS_FAULT_TEST_TIMEOUT_SECONDS` to leave
headroom for post-Warp operations. With this suite's 15-minute fault window and
the default 300-second timeout, Warp must be shorter than 600 seconds. When
increasing Warp duration, increase `faultDuration` and the suite's `maxDuration`
as needed, then run `make fault-suite-plan SUITE=fault/examples/warp-performance.yaml`
with the intended environment. Static `fault-suite-validate` checks YAML only.
This headroom is not a runtime guarantee: Warp setup and the correctness workload
also take time, and the run fails if the fault expires before they finish.

Each suite runs its scenarios sequentially to keep their conflict domains from
overlapping. Device-mapper scenarios are excluded from multi-attempt suites and
must run one at a time under operator supervision. Do not run multiple fault
suites concurrently against the same fault-test namespace. CI validates these
YAML contracts only; it never starts a destructive suite.

All seven device-mapper scenarios need host preparation beyond the environment
variables below: a device-mapper table over a dedicated block device, a static
local PV/storage class, and scenario-specific variables
(`RUSTFS_FAULT_TEST_DM_NAME`, `RUSTFS_FAULT_TEST_DM_NODE`,
`RUSTFS_FAULT_TEST_DM_MOUNT_PATH`, a separate pre-provisioned read-only host
observer, backend-specific destructive opt-in, exact node/device/PV allowlists,
plus a fault table name for legacy `dm-flakey`). Follow
[`docs/DM_FLAKEY.md`](docs/DM_FLAKEY.md) for the complete host device, static
Local PV, observer, privileged namespace, run, and teardown process.
There is no Make target that provisions or removes the host devices.

Required environment for non-static scenarios:

```bash
export RUSTFS_FAULT_TEST_STORAGE_CLASS=<dedicated-dynamic-storage-class>
export RUSTFS_FAULT_TEST_SERVER_IMAGE='docker.io/rustfs/rustfs@sha256:<digest>'
```

`RUSTFS_FAULT_TEST_EXPECTED_CONTEXT` (optional) pins the run to an expected
dedicated Kubernetes/K3s context and aborts if the current context differs.
Workload size and concurrency are tunable via `RUSTFS_FAULT_TEST_WORKLOAD_*`
variables; see `src/fault/config.rs`.

After a live scenario or suite starts, a runner, health guard, signal, or
artifact-check failure first preserves a failed cluster snapshot, current and
previous RustFS logs, `runner-failure-summary.json`, `runner-diagnosis.txt`, and
`failure-evidence.json`. The wrapper removes residual managed Chaos only after
those files are written. The run directory remains available for diagnosis;
verify it before the separate cluster-scoped `fault-cleanup` step.

Every scenario proves recovery beyond S3 readability. Before the fault the
runner captures the healthy RustFS layout from `/rustfs/admin/v3/info`; after
Tenant readiness and the stable Pod window it polls until every baseline
drive reports `ok`, the deployment identity and erasure geometry are
unchanged, and every RustFS Pod answers `/health/ready` through the API
server Pod proxy (`recovery-health.json`, failure classification
`recovery_health_degraded`). It then writes, reads back, lists, and deletes a
small set of fresh objects under a run-scoped prefix outside the workload
prefix (`post-recovery-write-report.json` plus its own
`post-recovery-write-history.jsonl`, classification
`post_recovery_write_failed`). The final checker also rejects listed keys that
no write explains or that GET cannot read back (`listed_key_unreadable`,
`unexpected_listed_object`). Scenarios whose fault stays inside RustFS
redundancy (`pod-kill-one`, `pod-failure`, `network-partition-one`) carry the
`availability-required` impact policy: every prefilled object must read back
with its committed hash while the fault is active and each mixed-workload
operation family must reach `RUSTFS_FAULT_TEST_MIN_AVAILABILITY_PERCENT`
(default 99; a floor below 100 always tolerates one disrupted operation per
family) non-disrupted operations (`availability-report.json`, classification
`availability_regression`). Because a `kubectl port-forward` stays pinned to
one Pod, the runner re-pins the S3 endpoint to a surviving Pod that the Chaos
Mesh controller did not target once the fault is active, so the contract
measures a client attached to a healthy node; ClusterIP endpoints need no
pinning. These contracts are not yet calibrated on a live cluster; treat the
first live runs as calibration.
`make fault-dashboard-install` mutates the current cluster (installs/upgrades
the Chaos Mesh release via Helm); treat it like a live run.
`make fault-cleanup` is scoped by the current Kubernetes context, namespace,
and tenant; it does not consume an artifact root. Verify those values against
the run and pin `RUSTFS_FAULT_TEST_EXPECTED_CONTEXT` before cleanup.

## S3 Protocol Testing

Two complementary execution layers:

1. **Native cases** (`src/protocol/cases/`): Rust test cases over authz,
   IAM, STS, OIDC (Keycloak-backed `AssumeRoleWithWebIdentity`), bucket
   policy, and a bounded compatibility supplement, with fixture ownership and
   durable cleanup. Native case results do not claim coverage of an external
   conformance suite.
2. **Mint**: black-box SDK compatibility run via
   `make protocol-compatibility-mint`. The default audited profile pins the
   `aws-sdk-php` core suite, image digest, platform, exact function inventory,
   and known-failure baseline. It accepts only a leased, run-owned Kubernetes
   namespace, captures RustFS evidence, and deletes that namespace after every
   completed, failed, timed-out, or interrupted run. Its exit status requires
   both the structured Mint gate and verified teardown to pass.

A live protocol run requires more than the fault-side inputs:

```bash
export RUSTFS_PROTOCOL_COMPAT_SERVER_ENDPOINT=<host:port>       # or RUSTFS_PROTOCOL_TEST_ENDPOINT per suite
export RUSTFS_PROTOCOL_TEST_ADMIN_ACCESS_KEY=<key>
export RUSTFS_PROTOCOL_TEST_ADMIN_SECRET_KEY=<secret>
export RUSTFS_PROTOCOL_TEST_TARGET_FINGERPRINT=<verified 64-character SHA-256>
```

Destructive execution additionally demands two acknowledgements that the
target is a verified dedicated server:

- `RUSTFS_PROTOCOL_TEST_DEDICATED=1`.
- `RUSTFS_PROTOCOL_TEST_TARGET_FINGERPRINT=<sha256>` pinning the exact server
  identity. Run `make protocol-suite-plan SUITE=...` once: its JSON output
  contains `target.fingerprint.sha256` computed from the server-reported
  deployment id; copy that value into the variable. A changed server
  fingerprint aborts the run instead of testing the wrong target.

Mint has a stricter target boundary. Deploy RustFS into a new namespace on the
independent test server, label that namespace and every pod with the same run
id, then create a target file from
`protocol/mint/ephemeral-target.example.yaml`. The namespace must have:

```text
app.kubernetes.io/managed-by=s3chaos-mint
rustfs.com/mint-run-id=<run-id>
rustfs.com/mint-expires-at=<same RFC3339 value as target expiresAt>
```

The target file pins the exact kube context, namespace UID, lease, Service,
endpoint, region, RustFS container image digest, and server fingerprint. The
endpoint must be an address or DNS name advertised by that Service, whose
owned EndpointSlices must resolve only to the proved RustFS Pod UIDs. It is a
destructive hand-off: after ownership and readiness are proven, s3chaos owns
the whole namespace and will delete it with a Kubernetes UID precondition.
Do not point it at a shared or long-lived namespace.

```bash
export RUSTFS_PROTOCOL_TEST_DEDICATED=1
export RUSTFS_PROTOCOL_MINT_TARGET_SPEC=/path/to/ephemeral-target.yaml
export RUSTFS_PROTOCOL_TEST_ADMIN_ACCESS_KEY=<key>
export RUSTFS_PROTOCOL_TEST_ADMIN_SECRET_KEY=<secret>
make protocol-compatibility-mint
```

For the `oidc-keycloak` example profile you also need a prepared Keycloak
realm and matching RustFS OIDC configuration:

- Keycloak: dedicated realm, confidential client with direct access grants
  enabled, and an ID-token protocol mapper of type "user attribute" mapping
  the user attribute `policy` to an ID-token claim `policy` (multivalued
  enabled; a single string is also accepted). The Keycloak admin user needs
  permission to create and delete users in that realm.
- RustFS server: `RUSTFS_IDENTITY_OPENID_ENABLE=on`,
  `RUSTFS_IDENTITY_OPENID_CONFIG_URL=<issuer/discovery URL>`,
  `RUSTFS_IDENTITY_OPENID_CLIENT_ID/_CLIENT_SECRET`, and
  `RUSTFS_IDENTITY_OPENID_CLAIM_NAME=policy`.
- s3chaos client: `RUSTFS_PROTOCOL_OIDC_ISSUER`, `_ADMIN_URL`, `_REALM`,
  `_CLIENT_ID`, `_CLIENT_SECRET`, `_ADMIN_USERNAME`, `_ADMIN_PASSWORD`,
  `_ADMIN_REALM` (see constants in `src/protocol/clients/keycloak.rs`).

```bash
make protocol-list                                            # case catalog
make protocol-compatibility-mint                              # audited Mint run
make protocol-validate-mint-session ARTIFACT_ROOT=target/protocol-compatibility/mint/<run>
make protocol-validate-mint-artifacts ARTIFACT_ROOT=target/protocol-compatibility/mint/<run>/mint
make protocol-mint-cleanup ARTIFACT_ROOT=target/protocol-compatibility/mint/<run> # crash recovery only
make protocol-suite-template                                  # suite skeleton
make protocol-suite-validate SUITE=protocol/examples/smoke.yaml
make protocol-suite-plan SUITE=protocol/examples/smoke.yaml   # dry-run expansion
make protocol-suite-run SUITE=protocol/examples/smoke.yaml    # live run
make protocol-validate-artifacts ARTIFACT_ROOT=target/protocol-tests/<run>  # verify run artifacts first
make protocol-cleanup ARTIFACT_ROOT=target/protocol-tests/<run>             # then release fixtures
```

Suite YAML may carry a `contracts` block for RustFS behaviors that are not
settled yet; every key and value is validated and unknown ones fail
`protocol-suite-validate`. Today it holds
`forceDeleteHeaderSingleObject` (`ignore-header`, the default, or `reject`),
asserted by `delete-force-header-contract` for a non-owner single-object
DeleteObject that carries `X-Rustfs-Force-Delete: true`
(rustfs/rustfs#7649). The selected value is recorded in
`protocol-suite-plan.json`. `full-regression.yaml` pins `reject`, the
behavior RustFS main enforces today, so the release-candidate gate is not
permanently red; flip it to `ignore-header` once #7649 settles.

Validate before cleanup: for a failed or interrupted run the artifact root is
the only record of what happened on the server, and cleanup deletes registered
fixtures.

## CI

- `.github/workflows/ci.yml`: fmt/clippy/tests plus static validation of fault
  suites, protocol contracts, all example profiles, and shell lint. No cluster
  needed; fault suites are never executed by CI.
- `.github/workflows/protocol-live.yml`: live RustFS suites (smoke gate,
  native regression, expiration regression, external OIDC regression) on the
  shared `sm-standard-4` runner. Pull requests run the smoke gate only. Full live
  execution runs on `workflow_dispatch` (inputs `rustfs_image_digest`,
  `rustfs_version`, and an optional `rustfs_endpoint` +
  `rustfs_target_fingerprint` pair that redirects the run to a
  per-candidate target) and on `repository_dispatch` with event type
  `rustfs-release-candidate`, which the rustfs repository sends for every
  release candidate with the same keys in `client_payload`, for example:
  `gh api repos/rustfs/s3chaos/dispatches -f event_type=rustfs-release-candidate -f 'client_payload[rustfs_version]=1.0.0-rc.6' -f 'client_payload[rustfs_image_digest]=sha256:...'`.
  A `validate-inputs` job gates every live job: dispatch values are
  character-restricted, and an endpoint override is honored only when its
  host is listed in the `PROTOCOL_LIVE_ENDPOINT_ALLOWLIST` repository
  variable (comma-separated hosts; unset refuses all overrides). Build
  provenance, the override host, and the allowlist decision are written to
  the run summary and to `target-provenance.env` inside every uploaded
  artifact; flake history under `.history/` is keyed by profile and target
  fingerprint so a redirected run never pollutes the shared target's
  signals. Mint is
  run by command on the independent Kubernetes test server; no Mint workflow
  or schedule is installed by this repository.

## Requirements

- Rust (see `Cargo.toml` edition/toolchain), `make`, `bash`, `jq` (the
  fault scripts pipe catalogs through it), and `kubectl`.
- Live runs additionally need Docker (the Mint layer), Helm (Chaos Mesh
  install), and for `dm-flakey*` scenarios hosts with prepared device-mapper
  flakey tables as described above.
- Live runs additionally need: a dedicated Kubernetes/K3s cluster, Chaos Mesh
  installed for chaos-backed scenarios (host device-mapper scenarios need
  `dm-flakey` capable hosts), `kubectl` access via a dedicated context, and
  the required environment variables above.
