# Testing

## Release mode is mandatory

Always run tests with `--release`. The trbfv secure-preset e2e tests (`crates/fhe/tests/trbfv_secure_e2e.rs`) take minutes in debug and seconds in release. CI runs `cargo test --release --all-features`.

## Focused verification

Run the narrowest check that covers the change first, then the full CI-equivalent set.

```bash
# Single crate
cargo test --release -p fhe-math
cargo test --release -p fhe

# Single test
cargo test --release -p fhe -- test_name

# Full CI-equivalent
cargo test --release --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all
```

## proptest

`fhe-math` uses proptest for property-based tests. When changing arithmetic, NTT, RNS, or polynomial operations, add or extend proptest strategies that cover edge cases and algebraic invariants, not just happy paths.

## Criterion benchmarks

Benchmarks use criterion with `harness = false`. Run a single bench:

```bash
cargo bench --bench bfv
cargo bench --bench rq
```

Do not leave benchmark results or criterion target directories in the worktree.
