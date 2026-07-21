# Coding conventions

## Error handling

- Library code must never `panic!`, `unwrap()`, or `expect()`. Use `?`, `Result`, and fallible APIs.
- `unwrap()` and `expect()` are acceptable only in tests and benchmarks.
- Avoid direct slice indexing; use `get()` or pattern matching to handle bounds safely.
- The workspace denies `expect_used`, `panic`, `indexing_slicing`, `unused_must_use`, and `fallible_impl_from` in clippy.

## Naming

- Modules: `snake_case`, directory name matches module name.
- Types, traits, enums: `PascalCase`.
- Functions, methods: `snake_case`.
- Constants: `SCREAMING_SNAKE_CASE` for static values, `snake_case` for `const` items.
- Private helpers: `snake_case`, prefer descriptive names over abbreviations.
- Type parameters: single uppercase letter (`T`, `N`, `P`) or `PascalCase` for multi-letter bounds.

## Imports

- Group imports in this order: `std` / `core` → external crates → `crate` → `super` → `self`.
- Use `use crate::...` for intra-crate imports; avoid `super::` unless the module hierarchy is shallow.
- Prefer importing types and traits explicitly; avoid glob imports (`use foo::*`) except for prelude modules.

## Documentation

- All public items must have doc comments (`missing_docs` is warned at workspace level).
- Doc comments start with `///` and use Markdown.
- Document panics, errors, and safety invariants where applicable.
- For crypto code, cite the relevant ePrint paper and section.

## Rustfmt and clippy

- `cargo fmt --all` is the single formatting authority. No exceptions.
- `cargo clippy --all-targets --all-features -- -D warnings` must pass clean.
- Do not suppress clippy lints without a comment explaining why.

## Workspace structure

- `crates/fhe` — BFV, TRBFV, TRLBFV (threshold l-BFV key generation, participant binding, and public-key/relinearization-key aggregation), LBFV, MBFV scheme implementations
- `crates/fhe-math` — RNS, NTT, modular and polynomial arithmetic
- `crates/fhe-traits` — shared HE traits
- `crates/fhe-util` — utilities

When adding a new module or type, place it in the appropriate crate. Do not add HE scheme code to `fhe-math`, or math primitives to `fhe`.

## Feature gates

- Protobuf serialization is gated behind the `protobuf` feature (disabled by default).
- When adding protobuf-dependent code, gate it with `#[cfg(feature = "protobuf")]`.
- Core crypto operations must work without the `protobuf` feature.

## Tests

- Co-locate unit tests in a `#[cfg(test)] mod tests` block at the bottom of the source file.
- Integration tests live in `crates/<name>/tests/`.
- Use `--release` for all test runs.
- Use proptest for arithmetic invariants in `fhe-math`.
- Use criterion benchmarks with `harness = false` for performance tests.

## Comments

Prefer self-documenting code over comments. Add a comment only when the reason is genuinely non-obvious to a future reader. Identifiers should be self-describing.
