# fhe.rs

Ring-LWE-based fully homomorphic encryption library in Rust. Workspace with 4 crates under `crates/`: `fhe` (BFV, TRBFV, LBFV, MBFV scheme implementations), `fhe-math` (RNS, NTT, modular and polynomial arithmetic), `fhe-traits` (shared HE traits), `fhe-util` (utilities).

> Area rules live in [`.rules/`](.rules). Load the relevant rule before changing code in that area — see **Touch → update** below. OpenCode agents and skills live in [`.opencode/`](.opencode); see **Development workflow**.

## Prerequisites

- Rust stable toolchain
- `protoc` (protobuf compiler) — only required when building with `--features protobuf`

## Commands

```bash
cargo test --release --all-features    # tests (release mode critical for trbfv speed)
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all                        # formatting
pre-commit run --all-files             # runs fmt, clippy, typos
```

## Architecture

- `crates/fhe/src/{bfv,trbfv,lbfv,mbfv}/` — HE scheme implementations
- `crates/fhe-math/src/{rns,ntt,rq}/` — core math operations
- `crates/fhe-traits/` — traits for HE schemes
- `crates/fhe-util/` — utilities

## Code generation

Proto files compile to Rust via `prost` at build time — see [`.rules/codegen.md`](.rules/codegen.md). This is feature-gated behind `protobuf` (disabled by default).

- `fhe-math/src/proto/rq.proto` → generated into `OUT_DIR` (requires `--features protobuf`)
- `fhe/src/proto/bfv/bfv.proto` → generated into `OUT_DIR` (requires `--features protobuf`)
- `fhe/src/proto/trbfv/trbfv.proto` → generated into `OUT_DIR` (requires `--features protobuf`)

Without `--features protobuf`, no `protoc` is needed and serialization is unavailable. Core crypto operations work without the feature.

## Development workflow
For non-trivial work, OpenCode provides agents under [`.opencode/agents/`](.opencode/agents):

1. `fhe-architect` — brainstorm designs and tradeoffs (read-only).
2. `fhe-implementer` — implement the approved plan (can edit).
3. `fhe-reviewer` — general correctness, conventions, and test review (read-only).
4. `fhe-crypto-reviewer` — specialist review for scheme/key/noise/parameter/threshold changes (read-only).
5. `fhe-math-reviewer` — specialist review for RNS/NTT/modular/polynomial arithmetic (read-only).

Reusable procedures live as skills under [`.opencode/skills/`](.opencode/skills): `fhe-verification`, `crypto-change-review`, `protobuf-codegen`, `benchmarking`.

Other harnesses: `AGENTS.md` and `.rules/` are shared and portable. `CLAUDE.md` adapts Claude Code to this layout. `.opencode/` and `opencode.json` are OpenCode-specific and inert to other tools.

## Area rules

Canonical detailed guidance in `.rules/` — read the full file when relevant:

- [`.rules/workflow.md`](.rules/workflow.md) — patch discipline, git, error handling
- [`.rules/testing.md`](.rules/testing.md) — release mode, focused and full verification, proptest, criterion
- [`.rules/crypto.md`](.rules/crypto.md) — security-sensitive areas, claims policy, invariant tests
- [`.rules/math.md`](.rules/math.md) — RNS/NTT/modular/polynomial invariants, property tests
- [`.rules/codegen.md`](.rules/codegen.md) — protoc/prost feature-gated build flow
- [`.rules/harness.md`](.rules/harness.md) — this scaffolding's invariants

## Keeping rules up to date

Update the canonical `.rules/*.md` in the same change when your edit makes a rule stale. The **Touch → update** table maps file paths to the rules they affect — load the relevant rule when touching those paths.

**Touch → update:**

- `workflow.md` — any edit (applies project-wide)
- `crypto.md` — `crates/fhe/src/{bfv,trbfv,lbfv,mbfv}/**`, `crates/fhe/examples/{mulpir,sealpir}.rs`
- `math.md` — `crates/fhe-math/src/**`
- `codegen.md` — `**/build.rs`, `**/*.proto`, `**/src/proto/**`
- `testing.md` — `**/tests/**`, `**/benches/**`, `.github/workflows/**`, `.pre-commit-config.yaml`
- `harness.md` — `.rules/**`, `.opencode/**`, `AGENTS.md`, `CLAUDE.md`, `opencode.json`

## Constraints — hard rules

- **No panics in library code.** Never `panic!`, `unwrap()`, `expect()`, or direct slice indexing in library code. Use `?`, `Result`, and `get()`. `unwrap()`/`expect()` only in tests and benchmarks. The workspace denies `expect_used`, `panic`, `indexing_slicing` in clippy.
- **Always `--release`.** trbfv e2e tests take minutes in debug, seconds in release.
- **Never hand-edit generated protobuf output.** Regenerate via the build — see [`.rules/codegen.md`](.rules/codegen.md).
- **No unsupported security claims.** This library has never been independently audited — see [`.rules/crypto.md`](.rules/crypto.md).
- **Never commit, amend, or push without explicit user consent.**

## Style & lints

Workspace lints are strict — code that violates them won't pass CI:

- Deny: `expect_used`, `panic`, `indexing_slicing`, `unused_must_use`, `fallible_impl_from`
- Warn: `missing_docs`, `unused_imports`, `must_use_candidate`

## PR conventions

- Title: `[agent] <Title>`
- Run `cargo test --release --all-features`, `cargo fmt --all`, `cargo clippy --all-targets --all-features -- -D warnings` before committing
