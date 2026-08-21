# S3 Protocol Testing

The protocol harness has three deliberately separate coverage layers:

1. The native Rust cases exercise authorization and a bounded S3 compatibility
   profile with durable cleanup and structured artifacts.
2. The pinned Ceph `s3-tests` index classifies every upstream test, but only an
   `implemented` entry is an exact native semantic mapping.
3. Mint is the broader black-box SDK compatibility gate.

The compatibility source is pinned to Ceph `s3-tests` revision
`5522d1c351f75bc00ae0f64f742f3f095f5939d9`. The checked-in source index has
976 pytest node ids. `protocol/compatibility/native-profile.yaml` pins the
revision, node count, canonical index SHA-256, native case denominator, and S3
operations. A changed revision or node set fails validation with expected and
actual values.

Implemented manifest entries declare either `exact-one-to-one` or
`table-driven-many-to-one`. Table-driven entries sharing a native case require
unique `variant` values. Unknown or duplicate references, missing native cases,
and incomplete expected-divergence records fail validation. Protocol domains
are derived centrally by the compatibility catalog and included in the status
report, catalog, suite plan, and case reports.

Current pinned classification:

- 10 implemented reference nodes mapped to 9 native cases (1.02% of the upstream index)
- 964 unimplemented
- 2 excluded
- 0 expected divergences

Classification completeness is 100%; executed native upstream coverage is not.

## Local contract checks

These commands do not mutate a RustFS target:

```bash
make protocol-compatibility-status
make protocol-suite-validate SUITE=protocol/examples/full-regression.yaml
make protocol-suite-validate SUITE=protocol/examples/slow-regression.yaml
```

The status JSON separates reference-node classification from native execution:
`summary.nativeEncoded` counts Rust cases, while `nativeLivePassed`,
`nativeLiveFailed`, and `nativeNotRun` describe live evidence. With no live
artifact input, every encoded case is `not-run`.

Refresh the pinned Ceph index only when intentionally changing the pinned
revision. The command prints the new `sourceCaseCount` and
`sourceIndexSha256`; update the native profile and review the generated diff:

```bash
make protocol-update-s3tests-index
```

## Live RustFS runs

Use only a dedicated disposable RustFS target:

```bash
export RUSTFS_PROTOCOL_TEST_ENDPOINT=http://rustfs.example:9000
export RUSTFS_PROTOCOL_TEST_ADMIN_ACCESS_KEY=...
export RUSTFS_PROTOCOL_TEST_ADMIN_SECRET_KEY=...
export RUSTFS_PROTOCOL_TEST_DEDICATED=1

make protocol-suite-run SUITE=protocol/examples/full-regression.yaml
make protocol-suite-run SUITE=protocol/examples/slow-regression.yaml
```

The full suite selects every non-OIDC catalog case except the deliberately slow
`sts-expired-token-denied` case. The slow suite requests RustFS's minimum
900-second STS lifetime, waits for expiry, and requires `ExpiredToken` from a
signed S3 request. OIDC remains an explicit separate suite because it owns
external identity-provider state.

Selected versioning and Public Access Block cases are probed before execution.
The probe must preserve two object versions plus a delete marker, or round-trip
the complete Public Access Block configuration, and then clean all registered
resources.

Artifacts are written under `target/protocol-tests/`. A failed run must be
cleaned using its exact artifact registry; never delete by an unverified broad
prefix:

```bash
make protocol-cleanup ARTIFACT_ROOT=target/protocol-tests/<run>
```

Each run writes `compatibility-coverage.json`. It contains the pinned source
drift check, global and per-domain counts, native-to-reference variants, and the
live status derived from case reports. Artifact validation rejects a coverage
file that disagrees with those reports.

## Live CI gate

`.github/workflows/protocol-live.yml` runs weekly and on manual dispatch on a
self-hosted runner labelled `rustfs-protocol`. The protected
`rustfs-protocol-test` environment must provide:

- `RUSTFS_PROTOCOL_TEST_ENDPOINT`
- `RUSTFS_PROTOCOL_TEST_ADMIN_ACCESS_KEY`
- `RUSTFS_PROTOCOL_TEST_ADMIN_SECRET_KEY`
- `RUSTFS_PROTOCOL_COMPAT_SERVER_ENDPOINT` for Docker/Mint reachability

The workflow runs the native full suite, the STS expiration suite, and the
digest-pinned Mint image. Mint uses `RUSTFS_PROTOCOL_COMPAT_STRICT=1`, so
compatibility failures fail the job. All three jobs upload their artifacts even
when the test command fails.

Classification coverage is not product conformance. The status JSON reports
the entire pinned upstream denominator, while native and Mint results are the
evidence for executed behavior.
