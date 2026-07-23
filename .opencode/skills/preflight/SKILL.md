---
name: preflight
description: Use before push or commit to catch a red CI early. Run the same checks as CI locally — cargo test, clippy, fmt, plus a debugging guide for common failures.
---

# fhe.rs preflight (local CI parity)

Use this skill when you need to test, lint, format, or verify changes in fhe.rs.

The commands to run (focused and full CI-equivalent verification) and the release-mode requirement live in [`.rules/testing.md`](../../../.rules/testing.md) — the source of truth. Read it for the exact commands and for test-coverage invariants (proptest, criterion, CRP/l-BFV, smudging/threshold E2E) when the change touches those areas.

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
