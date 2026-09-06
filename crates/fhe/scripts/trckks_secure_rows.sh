#!/usr/bin/env bash
# Secure-param benchmark rows (BENCHMARKS_TRCKKS.md §6), cheapest first.
set -uo pipefail
cd "$(dirname "$0")/../../.."   # workspace root
export BENCH_MACHINE="Apple M3 Pro, 11 cores, 36 GiB, macOS 26.6.1"
B=./target/release/examples/trckks_dkg_bench
O=/tmp/trckks-bench
mkdir -p "$O"
cargo build --release --example trckks_dkg_bench >/dev/null 2>&1 || { echo BUILD_FAILED; exit 1; }

row() { # <preset> <parties> <runs> <app> [<users>]
  local tag="secure-$1-$4-n$2"
  [ -f "$O/$tag.json" ] && [ -s "$O/$tag.json" ] && { echo "[skip] $tag"; return; }
  local users=""; [ -n "${5:-}" ] && users="--users $5"
  local t0=$(date +%s)
  echo "[run] $tag"
  # shellcheck disable=SC2086
  $B --preset "$1" --parties "$2" --runs "$3" --app "$4" $users --json "$O/$tag.json" > "$O/$tag.log" 2>&1
  echo "[done] $tag rc=$? $(( $(date +%s) - t0 ))s"
}

row s1-stats 3  3 stats 4
row s1-stats 3  3 poly4
row s1-stats 3  3 cmp5  4
row s1-stats 5  3 stats 4
row s1-stats 5  3 poly4
row s1-stats 5  3 cmp5  4
row s1-stats 10 3 stats 4
row s1-stats 10 3 poly4
row s1-stats 10 3 cmp5  4
row s2-cmp12 3  1 stats 4
row s2-cmp12 3  1 poly4
row s2-cmp12 3  1 cmp6  4
row s2-cmp12 3  1 cmp12 4
row s2-cmp12 5  1 cmp12 4
row s2-cmp12 10 1 cmp12 4
row s1-stats 20 1 stats 4
echo ALL_ROWS_DONE
