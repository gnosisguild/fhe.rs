# Coding conventions

## Scope

Rust code in the workspace: error handling, naming, imports, documentation, mathematical comments, formatting, idioms, crate placement, versions, features, tests, and comments.

## Invariants

1. Library code never uses `panic!`, `unwrap()`, or `expect()`; it uses `?`, `Result`, fallible APIs, and safe access instead of direct slice indexing.
2. The workspace denies `expect_used`, `panic`, `indexing_slicing`, `unused_must_use`, and `fallible_impl_from` in clippy.
3. Modules and directories use `snake_case`, types/traits/enums use `PascalCase`, functions use `snake_case`, static constants use `SCREAMING_SNAKE_CASE`, const items use `snake_case`, private helpers are descriptive `snake_case`, and type parameters use a single uppercase letter or PascalCase multi-letter bound.
4. Imports are grouped `std`/`core`, external crates, `crate`, `super`, `self`; intra-crate imports use `crate::`, types and traits are explicit, and glob imports are limited to prelude modules.
5. Public items have `///` Markdown docs that document panics, errors, safety invariants, and cite the relevant ePrint paper and section for crypto code.
6. Mathematical comments use exact construction symbols, name every symbol and source in formulas and bounds, copy cited equations verbatim, mark deviations and unproven caveats, and do not silently change approximations or rounding.
7. `cargo fmt --all` is authoritative and `cargo clippy --all-targets --all-features -- -D warnings` passes without unexplained suppressions.
8. Rust is idiomatic and follows surrounding crate patterns, using `Result`/`?`, natural conversions, iterators, borrows, and standard/internal utilities over manual or C-style plumbing.
9. HE scheme code belongs in `crates/fhe`, math primitives in `crates/fhe-math`, shared traits in `crates/fhe-traits`, and utilities in `crates/fhe-util`.
10. Workspace and per-crate versions remain aligned through `version.workspace = true`.
11. Protobuf-dependent code is gated by `protobuf`, and core crypto works without that feature.
12. Unit tests are co-located, integration tests are in `crates/<name>/tests/`, tests use `--release`, arithmetic invariants use proptest, and performance tests use criterion with `harness = false`.
13. Code is self-documenting and comments explain only genuinely non-obvious reasons.

## Evidence / tests

Run `cargo fmt --all`, `cargo clippy --all-targets --all-features -- -D warnings`, and the relevant release tests.

## Sync

- Touch → update: `conventions.md` — `**/*.rs` (only when conventions change, not every edit).
