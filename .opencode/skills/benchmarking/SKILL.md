---
name: benchmarking
description: Use when modifying performance-sensitive math or benchmark code, or when running criterion benchmarks in fhe.rs. Covers benchmark locations, harness configuration, and release-mode execution.
---

# Benchmarking

Use this skill when working with criterion benchmarks in fhe.rs.

## Benchmark locations

Benchmarks use criterion with `harness = false`:

### fhe crate (`crates/fhe/benches/`)
- `bfv` — BFV scheme operations
- `bfv_optimized_ops` — optimized BFV operations
- `bfv_rgsw` — RGSW operations
- `trbfv_bfv_share` — TRBFV share operations

### fhe-math crate (`crates/fhe-math/benches/`)
- `zq` — modular arithmetic
- `rq` — polynomial arithmetic
- `ntt` — NTT operations
- `rns` — RNS operations

## Running benchmarks

```bash
# All benchmarks in a crate
cargo bench --bench bfv
cargo bench --bench rq

# All benchmarks
cargo bench
```

Always run benchmarks in release mode (criterion does this by default).

## When modifying benchmarks

- Benchmarks have `harness = false` — do not add `main` functions or standard test attributes
- Criterion benchmarks live in `benches/` directories, not in `tests/`
- Do not leave criterion target output or benchmark results in the worktree

## When modifying performance-sensitive code

- Run relevant benchmarks before and after the change to measure impact
- Report significant regressions (>10%) to the user
- Prefer algorithmic improvements over micro-optimizations unless the bottleneck is identified
