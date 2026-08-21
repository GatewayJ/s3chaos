# s3chaos

S3Chaos is a fault-injection and recovery-verification framework for
S3-compatible object storage, starting with RustFS on Kubernetes.

It provides:

- A machine-readable fault scenario catalog.
- Kubernetes fixture ownership and cleanup guards.
- Chaos Mesh and host device-mapper fault backends.
- Mixed S3 workload generation, history capture, recommit, and post-recovery
  verification.
- Run contracts, YAML suite orchestration, and event artifacts for audit and
  visualization.

## Commands

```bash
make fault-check
make fault-list
make fault-preflight SCENARIO=io-eio
make fault-run SCENARIO=io-eio
make fault-suite-template
make fault-suite-validate SUITE=suite.yaml
make fault-suite-plan SUITE=suite.yaml
make fault-suite-run SUITE=suite.yaml
make fault-cleanup
make protocol-list
make protocol-compatibility-status
make protocol-suite-validate SUITE=protocol/examples/full-regression.yaml
make protocol-suite-run SUITE=protocol/examples/full-regression.yaml
make protocol-suite-run SUITE=protocol/examples/slow-regression.yaml
make protocol-suite-validate SUITE=protocol/examples/oidc-keycloak.yaml
make protocol-suite-run SUITE=protocol/examples/oidc-keycloak.yaml
```

Required runtime inputs for non-static scenarios:

```bash
export RUSTFS_FAULT_TEST_STORAGE_CLASS=<dedicated-dynamic-storage-class>
export RUSTFS_FAULT_TEST_SERVER_IMAGE='docker.io/rustfs/rustfs@sha256:<digest>'
```

`RUSTFS_FAULT_TEST_EXPECTED_CONTEXT` is optional. Set it to pin the run to an
expected dedicated Kubernetes or K3s context.

See [docs/FAULT_TESTING.md](docs/FAULT_TESTING.md) for cluster preparation,
scenario selection, the RustFS reliability extension scenarios, dm-flakey
setup, artifact contracts, and cleanup rules.

See [docs/OIDC_PROTOCOL_TESTING.md](docs/OIDC_PROTOCOL_TESTING.md) for the
Keycloak-backed `AssumeRoleWithWebIdentity` integration test.

See [docs/S3_PROTOCOL_TESTING.md](docs/S3_PROTOCOL_TESTING.md) for native S3
coverage, the pinned Ceph classification, live RustFS suites, strict Mint gate,
artifacts, and cleanup.
