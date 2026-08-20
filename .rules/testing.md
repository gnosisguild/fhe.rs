# Testing

## Scope

Release-mode tests, focused verification, property tests, criterion benchmarks, CI preflight, common failures, CRP/l-BFV tests, and smudging/threshold E2E tests.

## Invariants

1. Tests always run with `--release`; CI runs `cargo test --release --all-features`.
2. The narrowest focused check runs before the full CI-equivalent set.
3. Arithmetic, NTT, RNS, and polynomial changes add or extend proptest edge and algebraic-invariant coverage.
4. Criterion benchmarks use `harness = false`, live in the listed `crates/fhe/benches/` or `crates/fhe-math/benches/` locations, do not add `main` or test attributes, leave no output, and measure relevant changes before/after.
5. Preflight runs test, clippy, and fmt; failures are fixed and rerun individually before proceeding.
6. Library failures use `Result`/`?`, no panic/unwrap/expect/indexing; public docs, imports, formatting, protobuf availability, release speed, `fallible_impl_from`, and must-use results are checked.
7. `CommonRandomPolyVec` tests cover deterministic reconstruction, seedless randomness, length/context validation, contradictory seeds, and concrete content.
8. l-BFV CRP consumers test concrete seedless/seeded use, conversion, rejection of mismatches, functional multiplication/decryption, concrete equality, tampering, migrated consumers, and absence of stale aliases.
9. Smudging tests cover the CBD branch (`v <= 16`, bound `2 * error1_variance`), the uniform branch (`variance_to_uniform_bound`, smallest `B` with `B(B+1)/3 >= v`), depth monotonicity at 0/1/2, accepted participant counts 0/intermediate/`n`, and default `n` behavior.
10. Strict Delta tests reject equality `2 * (B_C + n * B_sm) == Delta` and accept one unit below; round trips alone do not establish smudging.
11. Threshold E2E uses odd `n`, depth at least one, `threshold + 1` shares, and confirms fewer shares fail.

## Evidence / tests

```bash
cargo test --release -p fhe-math
cargo test --release -p fhe
cargo test --release -p fhe -- test_name
cargo test --release --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all
cargo bench --bench bfv
cargo bench --bench rq
```

The full bench locations are `crates/fhe/benches/{bfv,bfv_optimized_ops,bfv_rgsw,trbfv_bfv_share}` and `crates/fhe-math/benches/{zq,rq,ntt,rns}`. Do not commit or push while anything is red.

## Sync

- Touch → update: `testing.md` — `**/tests/**`, `**/benches/**`, `.github/workflows/**`.
