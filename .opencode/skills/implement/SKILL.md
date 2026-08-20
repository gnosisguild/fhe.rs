---
name: implement
description: Implement an approved fhe.rs design with detailed planning and TDD.
---

# fhe.rs Implement

## When to use

Use after design approval, or after an explicitly justified straightforward-task bypass.

## Inputs

The approved design, assigned scope, repository conventions, `AGENTS.md`, and every matching rule from the Touch → update table.

## Process

Derive a bite-sized plan mapped to exact files and tests, ordered by dependency; group only disjoint work. Record each failing test and focused command (`cargo test --release -p <crate> -- <test_name>`), and add rule/doc follow-up tasks for every touched area. Execute RED (minimal failing test), GREEN (minimal code), and REFACTOR (cleanup only after green). Run focused checks, then `cargo test --release --all-features`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo fmt --all`.

| TDD required | TDD pointless |
|---|---|
| Scheme logic, crypto operations, math functions | Cargo.toml changes, dependency bumps |
| Key generation, encryption, decryption, homomorphic ops | Formatting, comment-only changes |
| Parameter selection, modulus chain management | Config files, CI workflows |
| Protocol logic (threshold sharing, multiparty aggregation) | Benchmarks (verification detached from TDD) |
| Bug fixes with reproducible behavior | Protobuf schema changes (generated code) |
| Serialization encode/decode | Documentation, rule files, harness scaffolding |

## Output

Working changes, updated matching rules/docs, tests and verification results, and any blocker or ambiguity reported to the orchestrator.

## Boundaries

Library code uses `Result` and fallible APIs: never `panic!`, `unwrap()`, or `expect()`, and avoid direct slice indexing. TDD applies to scheme, crypto, math, key, protocol, serialization, and bug-fix behavior; it is pointless for configuration, formatting, docs, benchmarks, and protobuf schema changes (which still require verification). Do not commit, push, or alter branches; do not hand-edit generated protobuf output; do not make unsupported security claims. When stuck, simplify the test/design, use real code rather than mocks, and extract test helpers only when needed.

## Read-only note

This is the write-capable phase: it may edit product code, tests, and documented harness surfaces. It never commits, pushes, changes branches, or edits generated protobuf output.
