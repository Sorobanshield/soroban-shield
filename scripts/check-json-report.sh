#!/usr/bin/env bash
# Validate the built CLI's JSON output for all fixture categories and recursive scans.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
bin="${SOROBANSHIELD_BIN:-$root/target/debug/sorobanshield}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

(cd "$root/scripts/validate-sarif" && npm ci --silent)

reports=()
for dir in "$root"/tests/fixtures/{positive,negative,edge}/*/; do
  name="$(basename "$(dirname "$dir")")-$(basename "$dir")"
  set +e
  "$bin" scan "$dir" --format json > "$work/$name.json" 2>"$work/$name.stderr"
  rc=$?
  set -e
  if [ "$rc" -gt 3 ]; then
    echo "unexpected exit code $rc for $dir" >&2
    exit 1
  fi
  if [ -s "$work/$name.json" ]; then
    reports+=("$work/$name.json")
  else
    echo "skip  $name (exit $rc, no report)"
  fi
done
set +e
"$bin" scan "$root/tests/fixtures/multi" --recursive --format json > "$work/multi-recursive.json" 2>"$work/multi.stderr"
rc=$?
set -e
if [ "$rc" -gt 3 ] || [ ! -s "$work/multi-recursive.json" ]; then
  echo "recursive fixture did not produce a report (exit $rc)" >&2
  exit 1
fi
reports+=("$work/multi-recursive.json")
node "$root/scripts/validate-sarif/validate-report.mjs" "$root/docs/report.schema.json" "${reports[@]}"
