---
name: fhe-verification
description: Use when running tests, linting, formatting, diagnosing CI failures, or verifying a change before commit. Covers focused cargo commands, release-mode requirements, and the full CI-equivalent verification set for fhe.rs.
---

# fhe.rs verification

Use this skill when you need to test, lint, format, or verify changes in fhe.rs.

## Focused verification

Run the narrowest check that covers the change first.

### Single crate

```bash
cargo test --release -p fhe-math
cargo test --release -p fhe
```

### Single test

```bash
cargo test --release -p fhe -- <test_name>
cargo test --release -p fhe-math -- <test_name>
```

### Clippy on a single crate

```bash
cargo clippy -p fhe-math --all-targets -- -D warnings
cargo clippy -p fhe --all-targets -- -D warnings
```

## Full CI-equivalent verification

Run all three before declaring work complete:

```bash
cargo test --release --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all
pre-commit run --all-files
```

## Release mode

Always use `--release`. The trbfv secure-preset e2e tests (`crates/fhe/tests/trbfv_secure_e2e.rs`) take minutes in debug and seconds in release. CI runs `cargo test --release --all-features`.

## Common failures

- **Clippy: `expect_used` / `panic` / `indexing_slicing`** — library code must use `?` and `Result`, not `unwrap()`/`expect()`/`panic!`. Use `get()` instead of direct indexing.
- **Missing docs** — `missing_docs` is warned. Public items need doc comments.
- **Format check** — run `cargo fmt --all`.
- **Protoc missing** — if `protoc` is not installed, `fhe` skips proto generation with a warning. Install it or use the `fhe-math` fallback.
