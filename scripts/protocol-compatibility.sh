#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
MINT_IMAGE_DEFAULT='minio/mint:edge@sha256:08a05e68893c68be2a83b6f79556853ed6aa3c6c9e64c823a00853e4e55d2200'

die() {
  echo "protocol-compatibility: $*" >&2
  exit 1
}

run_mint() {
  [[ "${RUSTFS_PROTOCOL_TEST_DEDICATED:-}" == 1 ]] || \
    die "set RUSTFS_PROTOCOL_TEST_DEDICATED=1 only for a verified dedicated target"
  [[ -n "${RUSTFS_PROTOCOL_COMPAT_SERVER_ENDPOINT:-}" ]] || \
    die "RUSTFS_PROTOCOL_COMPAT_SERVER_ENDPOINT is required and must be reachable from Docker"
  [[ -n "${RUSTFS_PROTOCOL_TEST_ADMIN_ACCESS_KEY:-}" ]] || \
    die "RUSTFS_PROTOCOL_TEST_ADMIN_ACCESS_KEY is required"
  [[ -n "${RUSTFS_PROTOCOL_TEST_ADMIN_SECRET_KEY:-}" ]] || \
    die "RUSTFS_PROTOCOL_TEST_ADMIN_SECRET_KEY is required"
  command -v docker >/dev/null 2>&1 || die "docker is required for the optional Mint layer"

  local artifact_dir=${RUSTFS_PROTOCOL_COMPAT_ARTIFACTS_DIR:-$ROOT_DIR/target/protocol-compatibility/mint}
  local mint_image=${RUSTFS_PROTOCOL_COMPAT_MINT_IMAGE:-$MINT_IMAGE_DEFAULT}
  local mint_mode=${RUSTFS_PROTOCOL_COMPAT_MINT_MODE:-core}
  local mint_rc=0
  local -a suites=()
  if [[ -n "${RUSTFS_PROTOCOL_COMPAT_MINT_SUITES:-}" ]]; then
    read -r -a suites <<<"${RUSTFS_PROTOCOL_COMPAT_MINT_SUITES}"
  fi
  mkdir -p "$artifact_dir"

  export SERVER_ENDPOINT=$RUSTFS_PROTOCOL_COMPAT_SERVER_ENDPOINT
  export ACCESS_KEY=$RUSTFS_PROTOCOL_TEST_ADMIN_ACCESS_KEY
  export SECRET_KEY=$RUSTFS_PROTOCOL_TEST_ADMIN_SECRET_KEY
  export ENABLE_HTTPS=${RUSTFS_PROTOCOL_COMPAT_ENABLE_HTTPS:-0}
  export SERVER_REGION=${RUSTFS_PROTOCOL_COMPAT_REGION:-us-east-1}
  export MINT_MODE=$mint_mode
  set +e
  docker run --rm \
    --env SERVER_ENDPOINT \
    --env ACCESS_KEY \
    --env SECRET_KEY \
    --env ENABLE_HTTPS \
    --env SERVER_REGION \
    --env MINT_MODE \
    --volume "$artifact_dir:/mint/log" \
    "$mint_image" "${suites[@]}"
  mint_rc=$?
  set -e
  printf '%s\n' "$mint_rc" >"$artifact_dir/exit-code.txt"
  [[ -f "$artifact_dir/log.json" ]] || die "Mint produced no log.json; inspect $artifact_dir"
  if [[ "${RUSTFS_PROTOCOL_COMPAT_STRICT:-0}" == 1 && $mint_rc -ne 0 ]]; then
    die "Mint reported compatibility failures; artifacts: $artifact_dir"
  fi
  echo "Mint compatibility run completed with exit code $mint_rc; artifacts: $artifact_dir"
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
  RUSTFS_PROTOCOL_COMPAT_SERVER_ENDPOINT=host:port
  RUSTFS_PROTOCOL_TEST_ADMIN_ACCESS_KEY=...
  RUSTFS_PROTOCOL_TEST_ADMIN_SECRET_KEY=...

Optional environment:
  RUSTFS_PROTOCOL_COMPAT_MINT_SUITES="awscli minio-go"
  RUSTFS_PROTOCOL_COMPAT_MINT_MODE=core
  RUSTFS_PROTOCOL_COMPAT_STRICT=1
  RUSTFS_PROTOCOL_COMPAT_ARTIFACTS_DIR=...
EOF
    ;;
  *)
    die "unknown command: $1"
    ;;
esac
