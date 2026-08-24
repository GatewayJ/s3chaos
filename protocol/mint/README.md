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
