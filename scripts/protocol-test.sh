#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
MANIFEST_PATH="$ROOT_DIR/Cargo.toml"

die() {
  echo "protocol-test: $*" >&2
  exit 1
}

require_runtime_credentials() {
  require_admin_credentials
}

require_admin_credentials() {
  [[ -n "${RUSTFS_PROTOCOL_TEST_ADMIN_ACCESS_KEY:-}" ]] || die "RUSTFS_PROTOCOL_TEST_ADMIN_ACCESS_KEY is required"
  [[ -n "${RUSTFS_PROTOCOL_TEST_ADMIN_SECRET_KEY:-}" ]] || die "RUSTFS_PROTOCOL_TEST_ADMIN_SECRET_KEY is required"
}

run_cli() {
  cargo run --quiet --manifest-path "$MANIFEST_PATH" --bin s3chaos -- "$@"
}

command=${1:-help}
case "$command" in
  list)
    run_cli protocol-catalog-json
    ;;
  compatibility-status)
    run_cli protocol-compatibility-status-json
    ;;
  suite-template)
    run_cli protocol-suite-template
    ;;
  suite-validate)
    [[ $# -eq 2 ]] || die "suite-validate requires exactly one suite path"
    run_cli protocol-suite-validate "$2"
    ;;
  suite-plan)
    [[ $# -eq 2 ]] || die "suite-plan requires exactly one suite path"
    require_runtime_credentials
    run_cli protocol-suite-plan "$2"
    ;;
  suite-run)
    [[ $# -eq 2 ]] || die "suite-run requires exactly one suite path"
    require_runtime_credentials
    [[ "${RUSTFS_PROTOCOL_TEST_DEDICATED:-}" == "1" ]] || \
      die "set RUSTFS_PROTOCOL_TEST_DEDICATED=1 only for a verified dedicated target"
    run_cli protocol-suite-run "$2"
    ;;
  cleanup)
    [[ $# -eq 2 || ( $# -eq 3 && "$2" == "--registry" ) ]] || \
      die "cleanup requires ARTIFACT_ROOT or --registry RESOURCE_REGISTRY"
    require_admin_credentials
    [[ "${RUSTFS_PROTOCOL_TEST_DEDICATED:-}" == "1" ]] || \
      die "set RUSTFS_PROTOCOL_TEST_DEDICATED=1 only for the registry's dedicated target"
    run_cli protocol-cleanup "${@:2}"
    ;;
  validate-artifacts)
    [[ $# -eq 2 ]] || die "validate-artifacts requires exactly one artifact root"
    run_cli protocol-validate-artifacts "$2"
    ;;
  help|-h|--help)
    cat <<'EOF'
Usage: scripts/protocol-test.sh COMMAND [ARGS]

Commands:
  list
  compatibility-status
  suite-template
  suite-validate SUITE
  suite-plan SUITE
  suite-run SUITE
  cleanup ARTIFACT_ROOT
  cleanup --registry RESOURCE_REGISTRY
  validate-artifacts ARTIFACT_ROOT
EOF
    ;;
  *)
    die "unknown command: $command"
    ;;
esac
