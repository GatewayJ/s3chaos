#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
MANIFEST_PATH="$ROOT_DIR/Cargo.toml"
MINT_IMAGE_DEFAULT='minio/mint:edge@sha256:08a05e68893c68be2a83b6f79556853ed6aa3c6c9e64c823a00853e4e55d2200'
MINT_PLATFORM_DEFAULT='linux/amd64'
MINT_SUITES_DEFAULT='aws-sdk-php'
MINT_INVENTORY_DEFAULT="$ROOT_DIR/protocol/mint/aws-sdk-php-core-inventory.yaml"
MINT_KNOWN_FAILURES_DEFAULT="$ROOT_DIR/protocol/mint/aws-sdk-php-core-known-failures.yaml"

die() {
  echo "protocol-compatibility: $*" >&2
  exit 1
}

run_mint() {
  [[ "${RUSTFS_PROTOCOL_TEST_DEDICATED:-}" == 1 ]] || \
    die "set RUSTFS_PROTOCOL_TEST_DEDICATED=1 only for a verified ephemeral target"
  [[ -n "${RUSTFS_PROTOCOL_MINT_TARGET_SPEC:-}" ]] || \
    die "RUSTFS_PROTOCOL_MINT_TARGET_SPEC is required"
  [[ -f "$RUSTFS_PROTOCOL_MINT_TARGET_SPEC" ]] || \
    die "Mint target spec does not exist: $RUSTFS_PROTOCOL_MINT_TARGET_SPEC"
  [[ -n "${RUSTFS_PROTOCOL_TEST_ADMIN_ACCESS_KEY:-}" ]] || \
    die "RUSTFS_PROTOCOL_TEST_ADMIN_ACCESS_KEY is required"
  [[ -n "${RUSTFS_PROTOCOL_TEST_ADMIN_SECRET_KEY:-}" ]] || \
    die "RUSTFS_PROTOCOL_TEST_ADMIN_SECRET_KEY is required"
  command -v docker >/dev/null 2>&1 || die "docker is required for the optional Mint layer"
  command -v kubectl >/dev/null 2>&1 || die "kubectl is required for Mint target evidence"

  local default_artifact_dir="$ROOT_DIR/target/protocol-compatibility/mint/$(date -u +%Y%m%dT%H%M%SZ)-$$"
  local artifact_dir=${RUSTFS_PROTOCOL_COMPAT_ARTIFACTS_DIR:-$default_artifact_dir}
  local mint_image=${RUSTFS_PROTOCOL_COMPAT_MINT_IMAGE:-$MINT_IMAGE_DEFAULT}
  local mint_platform=${RUSTFS_PROTOCOL_COMPAT_MINT_PLATFORM:-$MINT_PLATFORM_DEFAULT}
  local mint_mode=${RUSTFS_PROTOCOL_COMPAT_MINT_MODE:-core}
  local suites_spec=${RUSTFS_PROTOCOL_COMPAT_MINT_SUITES:-$MINT_SUITES_DEFAULT}
  local inventory=${RUSTFS_PROTOCOL_COMPAT_MINT_INVENTORY:-$MINT_INVENTORY_DEFAULT}
  local known_failures=${RUSTFS_PROTOCOL_COMPAT_MINT_KNOWN_FAILURES:-$MINT_KNOWN_FAILURES_DEFAULT}
  local -a suites=()
  read -r -a suites <<<"$suites_spec"
  ((${#suites[@]} > 0)) || die "Mint suite set must not be empty"
  [[ -f "$inventory" ]] || die "Mint inventory does not exist: $inventory"
  [[ -f "$known_failures" ]] || die "Mint known-failures file does not exist: $known_failures"

  export RUSTFS_PROTOCOL_COMPAT_MINT_IMAGE=$mint_image
  export RUSTFS_PROTOCOL_COMPAT_MINT_PLATFORM=$mint_platform
  export RUSTFS_PROTOCOL_COMPAT_MINT_MODE=$mint_mode
  export RUSTFS_PROTOCOL_COMPAT_MINT_SUITES=$suites_spec
  cargo run --quiet --manifest-path "$MANIFEST_PATH" --bin s3chaos -- \
    protocol-mint-run \
    "$RUSTFS_PROTOCOL_MINT_TARGET_SPEC" \
    "$inventory" \
    "$known_failures" \
    "$artifact_dir"
}

case "${1:-help}" in
  mint)
    [[ $# -eq 1 ]] || die "mint accepts no positional arguments; use RUSTFS_PROTOCOL_COMPAT_* env vars"
    run_mint
    ;;
  help|-h|--help)
    cat <<'EOF'
Usage: scripts/protocol-compatibility.sh mint

Required environment:
  RUSTFS_PROTOCOL_TEST_DEDICATED=1
  RUSTFS_PROTOCOL_MINT_TARGET_SPEC=/path/to/ephemeral-target.yaml
  RUSTFS_PROTOCOL_TEST_ADMIN_ACCESS_KEY=...
  RUSTFS_PROTOCOL_TEST_ADMIN_SECRET_KEY=...

Optional environment:
  RUSTFS_PROTOCOL_COMPAT_MINT_SUITES="aws-sdk-php"
  RUSTFS_PROTOCOL_COMPAT_MINT_MODE=core
  RUSTFS_PROTOCOL_COMPAT_MINT_PLATFORM=linux/amd64
  RUSTFS_PROTOCOL_COMPAT_MINT_INVENTORY=...
  RUSTFS_PROTOCOL_COMPAT_MINT_KNOWN_FAILURES=...
  RUSTFS_PROTOCOL_COMPAT_ARTIFACTS_DIR=...
EOF
    ;;
  *)
    die "unknown command: $1"
    ;;
esac
