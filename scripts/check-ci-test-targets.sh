#!/usr/bin/env bash
# CI contract check for integration test coverage (issue #240).
#
# The pull-request workflow runs `cargo test --workspace --release --tests`
# in both the --no-default-features and --all-features configurations instead
# of a hand-maintained list of `--test <name>` flags, so newly added test
# targets are picked up automatically. This script checks — it does not prove
# more than this — that the auto-discovery does not silently omit targets:
#
#   1. every `crates/*/tests/*.rs` file maps to a cargo test target with
#      `test = true`. Targets are matched by exact source path (workspace-
#      relative suffix of cargo metadata `src_path`), so identical basenames
#      in different crates cannot be confused. `autotests = false`, a missing
#      `[[test]]` entry, or `test = false` therefore cannot hide a test file;
#   2. every test target is selected by at least one matrix leg. Targets with
#      `required-features` are allowed: the --all-features leg enables every
#      workspace feature and runs them;
#   3. the integration targets required by issue #240 are present; and
#   4. a workflow still gates `cargo test --workspace --release --tests` with
#      both feature configurations.
#
# Requires `jq` (preinstalled on GitHub-hosted runners).
set -euo pipefail

repository="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repository"

if ! command -v jq >/dev/null 2>&1; then
  echo "error: jq is required" >&2
  exit 1
fi

metadata="$(cargo metadata --no-deps --format-version 1)"
temp_dir="$(mktemp -d)"
trap 'rm -rf "$temp_dir"' EXIT

# TSV rows: name <TAB> test <TAB> absolute src_path <TAB> required-features
# <TAB> package name.
jq -r '
  .packages[] as $package
  | $package.targets[]
  | select(.kind | index("test"))
  | [
      .name,
      (.test | tostring),
      .src_path,
      ((.["required-features"] // []) | join(",")),
      $package.name
    ]
  | @tsv
' <<<"$metadata" >"$temp_dir/targets.tsv"

failures=0

# 1. Every tests/*.rs file must be a runnable test target, matched by exact
#    source path (suffix comparison over the workspace-relative path).
verified=0
for file in crates/*/tests/*.rs; do
  [ -e "$file" ] || continue
  row="$(awk -F'\t' -v rel="$file" '
    {
      path = $3
      if (length(path) > length(rel) &&
          substr(path, length(path) - length(rel)) == "/" rel) {
        print
        exit
      }
    }' "$temp_dir/targets.tsv")"
  if [ -z "$row" ]; then
    echo "FAIL: $file is not a cargo test target (autotests disabled or missing [[test]]?)" >&2
    failures=$((failures + 1))
    continue
  fi
  test_flag="$(cut -f2 <<<"$row")"
  required="$(cut -f4 <<<"$row")"
  target_name="$(cut -f1 <<<"$row")"
  package="$(cut -f5 <<<"$row")"
  if [ "$test_flag" != "true" ]; then
    echo "FAIL: test target $target_name of $package has test = $test_flag and is skipped by cargo test" >&2
    failures=$((failures + 1))
  fi
  if [ -n "$required" ]; then
    echo "note: $file ($package) requires features [$required]; the --all-features leg runs it"
  fi
  verified=$((verified + 1))
  echo "ok: $file runs as test target '$target_name' of $package"
done

# 2. No test target may be hidden behind test = false, even if it does not
#    correspond to a tests/*.rs file today (e.g. a custom [[test]] path).
hidden_targets="$(awk -F'\t' '$2 != "true" {
  printf "FAIL: test target %s of %s has test = %s and is skipped by cargo test\n", $1, $5, $2
}' "$temp_dir/targets.tsv")"
if [ -n "$hidden_targets" ]; then
  echo "$hidden_targets" >&2
  hidden_count="$(wc -l <<<"$hidden_targets" | tr -d ' ')"
  failures=$((failures + hidden_count))
fi

# 3. The integration targets that issue #240 requires on every pull request.
for required_target in trbfv_e2e trlbfv_e2e profiles rns_shamir biguint \
  unified_context_integration ntt_shoup_ops; do
  if awk -F'\t' -v target="$required_target" \
    '$1 == target && $2 == "true" { found = 1 } END { exit !found }' \
    "$temp_dir/targets.tsv"; then
    echo "ok: required integration target '$required_target' is CI-covered"
  else
    echo "FAIL: required integration target '$required_target' is missing" >&2
    failures=$((failures + 1))
  fi
done

# 4. Some workflow must still run the auto-discovered matrix.
workflow_files="$(grep -rl -- 'cargo test --workspace --release --tests' .github/workflows/ || true)"
if [ -z "$workflow_files" ]; then
  echo "FAIL: no workflow runs 'cargo test --workspace --release --tests'" >&2
  failures=$((failures + 1))
else
  for features in --no-default-features --all-features; do
    # shellcheck disable=SC2086
    if grep -l -- "$features" $workflow_files >/dev/null 2>&1; then
      echo "ok: workflow matrix covers $features"
    else
      echo "FAIL: no workflow combining the integration test run covers $features" >&2
      failures=$((failures + 1))
    fi
  done
fi

if [ "$failures" -gt 0 ]; then
  echo "error: $failures CI test-target contract violation(s)" >&2
  exit 1
fi

echo "CI test-target contract verified: $verified test file(s) map to auto-discovered test targets covered by at least one matrix leg."
