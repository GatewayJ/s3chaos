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
  bucket policy, and compatibility domains, validated against a pinned Ceph
  `s3-tests` classification.

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
  compatibility/     Pinned Ceph s3-tests classification (revision, node
                     count, index SHA-256 pinned in native-profile.yaml)
  examples/          Ready-to-run suite YAMLs: smoke, full-regression,
                     slow-regression, oidc-keycloak
console/             Web console assets served by the run console
```

The `s3chaos` CLI exposes machine-readable commands (`fault-catalog-json`,
`protocol-catalog-json`, `protocol-compatibility-status-json`,
`*-suite-json`, ...) used by scripts, CI, and the console. There is no
installed binary on a fresh checkout; run commands via Cargo:

```bash
cargo run --quiet --bin s3chaos -- help
```

## Build and Static Checks

```bash
make check            # cargo fmt --check + clippy -D warnings + tests
make fault-check      # check + bash -n on fault-test.sh
make protocol-check   # check + bash -n on protocol scripts
```

## Fault-Injection Testing

Workflow: discover scenarios → preflight → preflight-validate a suite → plan →
run → inspect artifacts/console → cleanup.

```bash
make fault-list                                   # scenario catalog
make fault-preflight SCENARIO=io-eio              # cluster readiness checks
make fault-suite-template > suite.yaml            # generate a suite skeleton
make fault-suite-validate SUITE=suite.yaml        # static suite validation
make fault-suite-plan SUITE=suite.yaml            # dry-run expansion
make fault-suite-run SUITE=suite.yaml             # live run (needs a cluster)
make fault-console-serve                          # browse run artifacts
make fault-cleanup                                # release cluster fixtures
```

Runnable scenario families (18 executable entries): I/O faults (`io-eio`,
`io-read-mistake`, `io-latency`, `disk-full`, `dm-flakey*`), network faults
(`network-partition-one`, `network-partition-write-quorum-loss`,
`network-delay/loss/corrupt/duplicate`), pod faults (`pod-kill-one`,
`pod-failure`, `pod-crash-versioned-hot`), stress (`stress-cpu`,
`stress-memory`), and the `warp-under-chaos` benchmark campaign. A further
eight catalog entries are roadmap placeholders with status `Planned`
(`quorum-p-*-io-fault`, `fresh-volume-replacement`, all `admin-*` operations,
`on-disk-bitrot`, `long-run-chaos-campaign`): they appear in
`cargo run --bin s3chaos -- fault-catalog-json` but are filtered out of
`make fault-list` and rejected by preflight and suite validation.

The two `dm-flakey*` scenarios need host preparation beyond the environment
variables below: a device-mapper flakey table over a dedicated block device,
a static local PV/storage class, and scenario-specific variables
(`RUSTFS_FAULT_TEST_DM_NAME`, `RUSTFS_FAULT_TEST_DM_NODE`,
`RUSTFS_FAULT_TEST_DM_MOUNT_PATH`, plus a fault table name for legacy
`dm-flakey`). The required setup lives in `src/fault/backends/host.rs`;
there is no Make target that provisions the host devices.

Required environment for non-static scenarios:

```bash
export RUSTFS_FAULT_TEST_STORAGE_CLASS=<dedicated-dynamic-storage-class>
export RUSTFS_FAULT_TEST_SERVER_IMAGE='docker.io/rustfs/rustfs@sha256:<digest>'
```

`RUSTFS_FAULT_TEST_EXPECTED_CONTEXT` (optional) pins the run to an expected
dedicated Kubernetes/K3s context and aborts if the current context differs.
Workload size and concurrency are tunable via `RUSTFS_FAULT_TEST_WORKLOAD_*`
variables; see `src/fault/config.rs`.
`make fault-dashboard-install` mutates the current cluster (installs/upgrades
the Chaos Mesh release via Helm); treat it like a live run.

## S3 Protocol Testing

Three coverage layers:

1. **Native cases** (`src/protocol/cases/`): Rust test cases over authz,
   IAM, STS, OIDC (Keycloak-backed `AssumeRoleWithWebIdentity`), bucket
   policy, and a bounded compatibility profile, with fixture ownership and
   durable cleanup.
2. **Pinned Ceph classification** (`protocol/compatibility/`): every upstream
   Ceph `s3-tests` node classified as implemented / unimplemented / excluded /
   expected-divergence against revision
   `5522d1c351f75bc00ae0f64f742f3f095f5939d9`. The pin (revision, node count,
   index SHA-256) fails validation on drift. Regenerate only via
   `make protocol-update-s3tests-index`; never hand-edit.
3. **Mint**: black-box SDK compatibility run via
   `make protocol-compatibility-mint`. By default this is a non-gating
   report: Mint failures are recorded in the artifacts while the command
   still exits zero. Set `RUSTFS_PROTOCOL_COMPAT_STRICT=1` to make Mint
   failures fail the command (CI's `mint-regression` job runs strict).

A live protocol run requires more than the fault-side inputs:

```bash
export RUSTFS_PROTOCOL_COMPAT_SERVER_ENDPOINT=<host:port>       # or RUSTFS_PROTOCOL_TEST_ENDPOINT per suite
export RUSTFS_PROTOCOL_TEST_ADMIN_ACCESS_KEY=<key>
export RUSTFS_PROTOCOL_TEST_ADMIN_SECRET_KEY=<secret>
```

Destructive execution additionally demands two acknowledgements that the
target is a verified dedicated server:

- `RUSTFS_PROTOCOL_TEST_DEDICATED=1`.
- `RUSTFS_PROTOCOL_TEST_TARGET_FINGERPRINT=<sha256>` pinning the exact server
  identity. Run `make protocol-suite-plan SUITE=...` once: its JSON output
  contains `target.fingerprint.sha256` computed from the server-reported
  deployment id; copy that value into the variable. A changed server
  fingerprint aborts the run instead of testing the wrong target.

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
make protocol-compatibility-status                            # classification report
make protocol-suite-template                                  # suite skeleton
make protocol-suite-validate SUITE=protocol/examples/smoke.yaml
make protocol-suite-plan SUITE=protocol/examples/smoke.yaml   # dry-run expansion
make protocol-suite-run SUITE=protocol/examples/smoke.yaml    # live run
make protocol-validate-artifacts ARTIFACT_ROOT=target/protocol-tests/<run>  # verify run artifacts first
make protocol-cleanup ARTIFACT_ROOT=target/protocol-tests/<run>             # then release fixtures
```

Validate before cleanup: for a failed or interrupted run the artifact root is
the only record of what happened on the server, and cleanup deletes registered
fixtures.

## CI

- `.github/workflows/ci.yml`: fmt/clippy/tests plus static validation of
  protocol contracts, all example profiles, and shell lint. No cluster needed.
- `.github/workflows/protocol-live.yml`: live RustFS suites (smoke gate,
  native regression, expiration regression, external OIDC regression, Mint)
  on a self-hosted runner, scheduled and dispatchable.

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
