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
`*-suite-json`, ...) used by scripts, CI, and the console. Run `s3chaos help`
for the full list.

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

Scenario families include: I/O faults (`io-eio`, `io-read-mistake`,
`io-latency`, `disk-full`, `on-disk-bitrot`, `dm-flakey*`), network faults
(`network-partition-*`, `network-delay/loss/corrupt/duplicate`), pod faults
(`pod-kill-one`, `pod-failure`, `pod-crash-versioned-hot`), stress
(`stress-cpu`, `stress-memory`), quorum/heal operations (`quorum-p-*-io-fault`,
`admin-heal`, `admin-decommission`, `admin-rebalance`,
`fresh-volume-replacement`), and campaigns (`warp-under-chaos`,
`long-run-chaos-campaign`). Run `make fault-list` for the authoritative list.

Required environment for non-static scenarios:

```bash
export RUSTFS_FAULT_TEST_STORAGE_CLASS=<dedicated-dynamic-storage-class>
export RUSTFS_FAULT_TEST_SERVER_IMAGE='docker.io/rustfs/rustfs@sha256:<digest>'
```

`RUSTFS_FAULT_TEST_EXPECTED_CONTEXT` (optional) pins the run to an expected
dedicated Kubernetes/K3s context and aborts if the current context differs.
Workload size and concurrency are tunable via `RUSTFS_FAULT_TEST_WORKLOAD_*`
variables; see `src/fault/config.rs`.

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
3. **Mint gate**: black-box SDK compatibility run via
   `make protocol-compatibility-mint`.

```bash
make protocol-list                                            # case catalog
make protocol-compatibility-status                            # classification report
make protocol-suite-template                                  # suite skeleton
make protocol-suite-validate SUITE=protocol/examples/smoke.yaml
make protocol-suite-plan SUITE=protocol/examples/smoke.yaml   # dry-run expansion
make protocol-suite-run SUITE=protocol/examples/smoke.yaml    # live run
make protocol-cleanup ARTIFACT_ROOT=target/protocol-tests/... # release fixtures
make protocol-validate-artifacts ...                          # verify run artifacts
```

## CI

- `.github/workflows/ci.yml`: fmt/clippy/tests plus static validation of
  protocol contracts, all example profiles, and shell lint. No cluster needed.
- `.github/workflows/protocol-live.yml`: live RustFS suites (smoke gate,
  native regression, expiration regression, external OIDC regression, Mint)
  on a self-hosted runner, scheduled and dispatchable.

## Requirements

- Rust (see `Cargo.toml` edition/toolchain), `make`, `bash`.
- Live runs additionally need: a dedicated Kubernetes/K3s cluster, Chaos Mesh
  installed for chaos-backed scenarios (host device-mapper scenarios need
  `dm-flakey` capable hosts), `kubectl` access via a dedicated context, and
  the required environment variables above.
