---
name: preflight
description: Use before push or commit to catch a red CI early. Run the same checks as CI locally — cargo test, clippy, fmt, plus a debugging guide for common failures.
---

# fhe.rs preflight (local CI parity)

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
cargo clippy -p fhe-math -- -D warnings
cargo clippy -p fhe -- -D warnings
```

## Full CI-equivalent verification

Run all three before declaring work complete:

```bash
cargo test --release --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all
```

## Release mode

Always use `--release`. The trbfv secure-preset e2e tests (`crates/fhe/tests/trbfv_secure_e2e.rs`) take minutes in debug and seconds in release. CI runs `cargo test --release --all-features`.

## Debugging failures

When a step fails, fix and re-run individually:

| Step        | Fix                                                                                              |
| ----------- | ------------------------------------------------------------------------------------------------ |
| `cargo fmt` | `cargo fmt --all`                                                                                |
| `clippy`    | `cargo clippy --all-targets --all-features -- -D warnings` — fix every warning; no suppressions  |
| `test`      | Run the failing test in isolation: `cargo test --release -p <crate> -- <test_name>`              |
| `build`     | `cargo build --all-features` — fix compile errors                                               |

### Common failures

- **Clippy: `expect_used` / `panic` / `indexing_slicing`** — library code must use `?` and `Result`, not `unwrap()`/`expect()`/`panic!`. Use `get()` instead of direct indexing. Fix by replacing with fallible alternatives; these are denied (not warned) so the build fails.
- **Missing docs (`missing_docs`)** — public items need doc comments. Add `///` doc comments to all new public types, functions, and traits. This is a warning, not a hard error.
- **Unused imports (`unused_imports`)** — remove or use the import. This is a warning.
- **Format check** — `cargo fmt --all` fixes this deterministically.
- **Protoc missing** — `protoc` is only required with `--features protobuf`. Without the feature, serialization is unavailable but core crypto operations work. Install `protoc` or use `--no-default-features` for core-only builds.
- **Slow trbfv tests** — these must run in `--release`. Debug mode takes minutes; release mode takes seconds.
- **`fallible_impl_from`** — `From` impls must be infallible. Use `TryFrom` instead, or ensure the conversion cannot fail.
- **`unused_must_use`** — a `Result` or `MustUse` type is being dropped. Handle the result with `?` or an explicit `let _ = ...`.

Do not commit or push when anything is red. These mirror CI exactly.
