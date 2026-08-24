#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
MANIFEST_PATH="$ROOT_DIR/Cargo.toml"

if [[ -z "${S3CHAOS_SOURCE_REVISION:-}" ]] && command -v git >/dev/null 2>&1; then
  S3CHAOS_SOURCE_REVISION=$(git -C "$ROOT_DIR" rev-parse --verify HEAD 2>/dev/null || true)
  export S3CHAOS_SOURCE_REVISION
fi

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

reject_ci_overrides() {
  [[ -z "${CI:-}" ]] && return 0
  local name
  for name in \
    RUSTFS_PROTOCOL_TEST_ALLOW_STALE \
    RUSTFS_PROTOCOL_TEST_ALLOW_WIDE_CLEANUP \
    RUSTFS_PROTOCOL_TEST_DEBUG \
    RUSTFS_PROTOCOL_TEST_SKIP_TARGET_FINGERPRINT; do
    [[ -z "${!name:-}" ]] || die "$name is forbidden in CI protocol profiles"
  done
}

run_cli() {
  cargo run --quiet --manifest-path "$MANIFEST_PATH" --bin s3chaos -- "$@"
}

command=${1:-help}
case "$command" in
  list)
    run_cli protocol-catalog-json
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
  profile-validate)
    [[ $# -eq 3 ]] || die "profile-validate requires PROFILE and SUITE"
    reject_ci_overrides
    run_cli protocol-ci-profile-validate "$2" "$3"
    ;;
  profile-run)
    [[ $# -eq 3 ]] || die "profile-run requires PROFILE and SUITE"
    reject_ci_overrides
    require_runtime_credentials
    [[ "${RUSTFS_PROTOCOL_TEST_DEDICATED:-}" == "1" ]] || \
      die "set RUSTFS_PROTOCOL_TEST_DEDICATED=1 only for a verified dedicated target"
    [[ -n "${RUSTFS_PROTOCOL_TEST_TARGET_FINGERPRINT:-}" ]] || \
      die "RUSTFS_PROTOCOL_TEST_TARGET_FINGERPRINT is required"
    export RUSTFS_PROTOCOL_CI_PROFILE="$2"
    run_cli protocol-ci-profile-validate "$2" "$3"
    run_cli protocol-suite-run "$3"
    ;;
  suite-run)
    [[ $# -eq 2 ]] || die "suite-run requires exactly one suite path"
    require_runtime_credentials
    [[ "${RUSTFS_PROTOCOL_TEST_DEDICATED:-}" == "1" ]] || \
      die "set RUSTFS_PROTOCOL_TEST_DEDICATED=1 only for a verified dedicated target"
    [[ -n "${RUSTFS_PROTOCOL_TEST_TARGET_FINGERPRINT:-}" ]] || \
      die "RUSTFS_PROTOCOL_TEST_TARGET_FINGERPRINT is required"
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
  suite-template
  suite-validate SUITE
  suite-plan SUITE
  profile-validate PROFILE SUITE
  profile-run PROFILE SUITE
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
