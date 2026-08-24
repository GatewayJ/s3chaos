# Mint contract

The default contract pins the `aws-sdk-php` core suite from
`minio/mint:edge@sha256:08a05e68893c68be2a83b6f79556853ed6aa3c6c9e64c823a00853e4e55d2200`
on `linux/amd64`. Its function inventory matches the stable function strings
emitted by that image. Native Rust compatibility cases remain a separate
supplement and are not counted in Mint results.

An inventory update must be reviewed together with the exact Mint image
digest, platform, mode, and suite set. Known failures use exact suite/function
keys and require an owner, issue, introduction date, and review date. The
archived Mint codebase and its bundled SDK versions must be reviewed before
expanding this profile or replacing it with a maintained SDK matrix.

## Ephemeral target hand-off

Mint is triggered manually after an external deployment command has created a
new RustFS Kubernetes namespace. Copy `ephemeral-target.example.yaml` and fill
in live values after the deployment is Ready. `namespaceUid` comes from the
namespace metadata, `rustfsImageDigest` comes from each RustFS container
status `imageID`, and `targetFingerprint` is the unprefixed 64-character
server identity fingerprint.

The namespace is accepted only when its UID, lease annotation, manager label,
run-id label, pod ownership, Ready state, RustFS image digest, and server
fingerprint all agree with the file. The Kubernetes identity must also be
allowed to delete that exact namespace. Mint is not started if any check
fails.

Run `make protocol-compatibility-mint` with
`RUSTFS_PROTOCOL_MINT_TARGET_SPEC` pointing to the file. The command runs the
pinned Mint container, sanitizes captured output, collects bounded Kubernetes
resources/events/RustFS logs, then deletes the namespace with a UID
precondition and verifies it is absent. The outer session artifact contains
target proofs, lifecycle state, cleanup report, JSON/JUnit/exit status, and a
nested `mint/` result contract.

SIGINT, SIGTERM, timeout, test failure, and ordinary process errors enter the
same teardown path. After a host crash or `SIGKILL`, replay only from the exact
artifact root:

```bash
make protocol-mint-cleanup ARTIFACT_ROOT=target/protocol-compatibility/mint/<run>
make protocol-validate-mint-session ARTIFACT_ROOT=target/protocol-compatibility/mint/<run>
```

Recovery refuses deletion unless the artifact root contains a persisted
namespace ownership proof matching the target spec. Historical artifacts are
never stored inside or deleted with the namespace.
