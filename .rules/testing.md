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

## Smudging and threshold E2E

When modifying trBFV smudging, noise accounting, or threshold decryption:

- **Sampler support.** Test `B_enc` derivation against both the CBD branch (small variance, `2 * error1_variance`) and the uniform branch (large variance, `floor(sqrt(3 * error1_variance))`). A change to error sampling must update the matching `B_enc` test expectation.
- **Depth monotonicity.** Verify that the smudging bound `B_sm` is monotonic in multiplication depth: deeper circuits produce strictly larger (or equal) `B_sm` values. Test at depths 0, 1, and 2 with the same parameters and expected ordering.
- **Participant-count accounting.** Test the `accepted_participant_count` parameter with zero, exactly `n`, and an intermediate count to confirm the RLK aggregate error `|S| * B_e` scales correctly. The default path (no explicit count) must match `n`-participant behavior.
- **Strict Delta boundary.** Test parameters where `2 * (B_C + n * B_sm)` equals `Delta` and verify rejection. Test a value one unit below `Delta` and verify acceptance. Do not write tests that merely check round-trip decryption — they can pass even when the bound is loose.
- **Independent depth-positive threshold E2E.** Maintain the `trbfv_multiplicative_e2e.rs` test with `n` odd, multiplication depth ≥ 1, and `threshold + 1` shares. Confirm fewer shares fail to decrypt. This test exercises the accepted-participant smudging path end to end and should not be collapsed into the paper-formula test.
