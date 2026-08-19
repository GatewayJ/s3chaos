#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
REVISION=5522d1c351f75bc00ae0f64f742f3f095f5939d9
OUTPUT="$ROOT_DIR/protocol/compatibility/s3tests-source-index.txt"
ARCHIVE_URL="https://github.com/ceph/s3-tests/archive/$REVISION.tar.gz"

die() {
  echo "update-s3tests-index: $*" >&2
  exit 1
}

for command in curl tar rg sed sort find; do
  command -v "$command" >/dev/null 2>&1 || die "$command is required"
done

temp_root=$(mktemp -d "${TMPDIR:-/tmp}/s3tests-index.XXXXXX")
cleanup() {
  rm -rf "$temp_root"
}
trap cleanup EXIT

curl --fail --location --silent --show-error "$ARCHIVE_URL" | tar -xz -C "$temp_root"
source_root=$(find "$temp_root" -mindepth 1 -maxdepth 1 -type d | head -n 1)
[[ -n "$source_root" ]] || die "archive did not contain a source directory"

index_temp="$temp_root/s3tests-source-index.txt"
{
  echo "# ceph/s3-tests pytest function index"
  echo "# sourceRevision: $REVISION"
  LC_ALL=C rg --no-heading '^def test_[A-Za-z0-9_]+\(' \
    "$source_root/s3tests/functional" -g '*.py' |
    sed -E "s#^$source_root/##; s#:def ([A-Za-z0-9_]+)\(.*#::\1#" |
    LC_ALL=C sort -u
} >"$index_temp"

test_count=$(rg -c -v '^#' "$index_temp")
[[ "$test_count" -ge 900 ]] || die "refuse suspiciously small source index: $test_count tests"
mv "$index_temp" "$OUTPUT"
echo "updated $OUTPUT with $test_count source tests at $REVISION"
