# fhe.rs

Ring-LWE-based fully homomorphic encryption library in Rust. Workspace with 4 crates under `crates/`: `fhe` (BFV, TRBFV, TRLBFV, LBFV, MBFV scheme implementations), `fhe-math` (RNS, NTT, modular and polynomial arithmetic), `fhe-traits` (shared HE traits), `fhe-util` (utilities).

> Area rules live in [`.rules/`](.rules). Load the relevant rule before changing code in that area — see **Touch → update** below. OpenCode agents and skills live in [`.opencode/`](.opencode); see **Development workflow**.

## Core concepts

- **BFV** — Brakerski-Fan-Vercauteren fully homomorphic encryption with HPS/RNS optimizations (`crates/fhe/src/bfv/`). Supports key generation, encryption, decryption, homomorphic addition, multiplication, and relinearization.
- **TRBFV** — Threshold BFV (`crates/fhe/src/trbfv/`). Semi-malicious honest-majority threshold sharing, smudging, and decryption components. Paper: `n = 2t + 1`, static corruption ≤ `t`. Current implementation covers sharing, smudging, and decryption — not the complete DKG/broadcast orchestration.
- **TRLBFV** — Threshold l-BFV key-generation and aggregation (`crates/fhe/src/trlbfv/`). Produces operational LBFV keys from bound additive contributions; DKG orchestration, ZK proofs, and threshold decryption remain external or in TRBFV components.
- **LBFV** — BFV with linear relinearization key (`crates/fhe/src/lbfv/`). Public relinearization key that is linear in the secret key.
- **MBFV** — Multiparty BFV (`crates/fhe/src/mbfv/`). Semi-honest N-out-of-N construction with two-round relinearization.
- **RNS** — Residue Number System arithmetic (`crates/fhe-math/src/rns/`). Basis representation, conversion, Chinese Remainder Theorem.
- **NTT** — Number Theoretic Transform (`crates/fhe-math/src/ntt/`). Forward/inverse transforms for efficient polynomial multiplication.
- **Rq** — Polynomial arithmetic modulo `X^N + 1` over Z_q (`crates/fhe-math/src/rq/`). Multiplication, centering, degree management.

## Prerequisites

- Rust stable toolchain
- `protoc` (protobuf compiler) — only required when building with `--features protobuf`

## Commands

```bash
cargo test --release --all-features    # tests (release mode critical for trbfv speed)
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all                        # formatting
```

## Architecture

- `crates/fhe/src/{bfv,trbfv,trlbfv,lbfv,mbfv}/` — HE scheme implementations
- `crates/fhe-math/src/{rns,ntt,rq}/` — core math operations
- `crates/fhe-traits/` — traits for HE schemes
- `crates/fhe-util/` — utilities

## Code generation

Proto files compile to Rust via `prost` at build time — see [`.rules/codegen.md`](.rules/codegen.md). This is feature-gated behind `protobuf` (disabled by default).

- `fhe-math/src/proto/rq.proto` → generated into `OUT_DIR` (requires `--features protobuf`)
- `fhe/src/proto/bfv/bfv.proto` → generated into `OUT_DIR` (requires `--features protobuf`)
- `fhe/src/proto/trbfv/trbfv.proto` → generated into `OUT_DIR` (requires `--features protobuf`)

Without `--features protobuf`, no `protoc` is needed and serialization is unavailable. Core crypto operations work without the feature.

## Worktree and path safety

At the start of each agent session, run `git rev-parse --show-toplevel` and use only that worktree for source files. If a requested path resolves outside it, stop and report the mismatch.

## Development workflow

For any non-trivial task, switch to the **`work`** agent — it orchestrates the full flow (plan → build → review → verify) and enforces fhe.rs constraints. Starting points: `architect` for designs, `fix` for bugs, then `work` for everything else.

The agent set:

1. `work` — orchestrator. Routes plan → build → review → verification, asks user at gates. Never writes production code directly.
2. `architect` — brainstorm designs and tradeoffs (read-only).
3. `fix` — bug root-cause analysis. Reproduce, trace, explain root cause, propose fix direction. Never patches.
4. `plan` — subagent. Produces bite-sized implementation plans with exact file paths, code, and verification (read-only).
5. `implementer` — implements approved plans using TDD cycle (can edit).
6. `guard-review` — checks diff against hard constraints and conventions (read-only).
7. `quality-review` — universal Rust code quality review (read-only).
8. `reviewer` — general correctness, conventions, and test review (read-only).
9. `crypto-reviewer` — specialist review for scheme implementations, key handling, noise, parameters, serialization, decryption, threshold logic, and PIR examples (read-only).
10. `math-reviewer` — specialist review for RNS, NTT, modular arithmetic, polynomial operations, scaling, bounds, conversions, and property tests (read-only).
11. `harness` — harness lifecycle: coherence sweeps, restructuring, rule maintenance.

Reusable procedures live as skills under [`.opencode/skills/`](.opencode/skills): `review` (orchestrates all reviewers), `preflight`, `crypto-change-review`, `protobuf-codegen`, `benchmarking`.

Other harnesses: `AGENTS.md` and `.rules/` are shared and portable. `CLAUDE.md` adapts Claude Code to this layout. `.opencode/` and `opencode.json` are OpenCode-specific and inert to other tools.

## Area rules

Canonical detailed guidance in `.rules/` — read the full file when relevant:

- [`.rules/workflow.md`](.rules/workflow.md) — patch discipline, git, error handling
- [`.rules/conventions.md`](.rules/conventions.md) — Rust coding conventions, naming, imports, documentation
- [`.rules/testing.md`](.rules/testing.md) — release mode, focused and full verification, proptest, criterion
- [`.rules/crypto.md`](.rules/crypto.md) — security-sensitive areas, claims policy, invariant tests
- [`.rules/math.md`](.rules/math.md) — RNS/NTT/modular/polynomial invariants, property tests
- [`.rules/codegen.md`](.rules/codegen.md) — protoc/prost feature-gated build flow
- [`.rules/harness.md`](.rules/harness.md) — this scaffolding's invariants
- [`.rules/changelog.md`](.rules/changelog.md) — when to edit changelog, version alignment

## Keeping rules up to date

Update the canonical `.rules/*.md` in the same change when your edit makes a rule stale. The **Touch → update** table maps file paths to the rules they affect — load the relevant rule when touching those paths.

**Touch → update:**

- `workflow.md` — any edit (applies project-wide)
- `conventions.md` — `**/*.rs` (only when conventions change, not every edit)
- `crypto.md` — `crates/fhe/src/{bfv,trbfv,trlbfv,lbfv,mbfv}/**`, `crates/fhe/examples/{mulpir,sealpir}.rs`
- `math.md` — `crates/fhe-math/src/**`
- `codegen.md` — `**/build.rs`, `**/*.proto`, `**/src/proto/**`
- `testing.md` — `**/tests/**`, `**/benches/**`, `.github/workflows/**`
- `harness.md` — `.rules/**`, `.opencode/**`, `AGENTS.md`, `CLAUDE.md`, `opencode.json`
- `changelog.md` — `CHANGELOG.md`

## Constraints — hard rules

### Never panic, unwrap, or expect in library code

Library code must never `panic!`, `unwrap()`, `expect()`, or use direct slice indexing. Use `?`, `Result`, and `get()`. `unwrap()`/`expect()` only in tests and benchmarks. The workspace denies `expect_used`, `panic`, `indexing_slicing` in clippy.

### Always use `--release`

trbfv e2e tests take minutes in debug, seconds in release. Always run tests with `cargo test --release`.

### Never hand-edit generated protobuf output

Regenerate via the build — see [`.rules/codegen.md`](.rules/codegen.md).

### Never make unsupported security claims

This library has never been independently audited — see [`.rules/crypto.md`](.rules/crypto.md).

### Add or extend tests for the code you change

Even if nobody asked. Follow the testing rules in [`.rules/testing.md`](.rules/testing.md).

## Git — never commit or push without explicit consent
## Style & lints

Workspace lints are strict — code that violates them won't pass CI:

- Deny: `expect_used`, `panic`, `indexing_slicing`, `unused_must_use`, `fallible_impl_from`
- Warn: `missing_docs`, `unused_imports`, `must_use_candidate`
