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

Proto files compile to Rust via `prost` at build time — see [`.rules/protobuf.md`](.rules/protobuf.md). This is feature-gated behind `protobuf` (disabled by default).

- `fhe-math/src/proto/rq.proto` → generated into `OUT_DIR` (requires `--features protobuf`)
- `fhe/src/proto/bfv/bfv.proto` → generated into `OUT_DIR` (requires `--features protobuf`)

Without `--features protobuf`, no `protoc` is needed and serialization is unavailable. Core crypto operations work without the feature.

## Worktree and path safety

At the start of each agent session, run `git rev-parse --show-toplevel` and use only that worktree for source files. If a requested path resolves outside it, stop and report the mismatch.

## Development workflow

For any task, start with the **`orchestrator`** agent — it is the sole entry point. It routes the `architect`, `implement`, and `review` phase skills through their matching stub subagents (`architect`, `implementer`, `reviewer`), gates design approval, verification, and review, and owns harness upkeep. It always operates on the current branch and never creates or switches branches.

The agent set:

1. `orchestrator` — primary sole entry point. Routes phases, asks user at gates, and owns harness upkeep; edits only harness surfaces and never writes product code or plans.
2. `architect` — minimal stub (permissions, model, short body); its detailed workflow is the `architect` skill: explores and persists a codebase-level design plan; may ask clarifying questions.
3. `implementer` — minimal stub (permissions, model, short body); its detailed workflow is the `implement` skill: derives detailed tasks and implements an approved design with TDD.
4. `reviewer` — minimal stub (permissions, model, short body); its detailed workflow is the `review` skill: reviews diffs and root-causes bugs; never edits.

Reusable procedures live as uniformly structured skills under [`.opencode/skills/`](.opencode/skills): `architect`, `implement`, and `review`. The orchestrator dispatches the matching stub subagent with the skill content passed in the prompt. Verification/preflight, benchmark, and protobuf-codegen guidance lives in `.rules/testing.md` and `.rules/protobuf.md`; domain checklists are rules, not skills, and review loads every matching rule cumulatively via Touch → update.

Other harnesses: `AGENTS.md` and `.rules/` are shared and portable. `CLAUDE.md` adapts Claude Code to this layout. `.opencode/` is OpenCode-specific and inert to other tools.

## Area rules

Canonical detailed guidance in `.rules/` — read the full file when relevant:

- [`.rules/conventions.md`](.rules/conventions.md) — Rust coding conventions, naming, imports, documentation, idiomatic Rust
- [`.rules/testing.md`](.rules/testing.md) — release mode, focused and full verification, proptest, criterion
- [`.rules/cryptography.md`](.rules/cryptography.md) — security-sensitive areas, claims policy, invariant tests
- [`.rules/mathematics.md`](.rules/mathematics.md) — RNS/NTT/modular/polynomial invariants, property tests
- [`.rules/protobuf.md`](.rules/protobuf.md) — protoc/prost feature-gated build flow
- [`.rules/harness.md`](.rules/harness.md) — this scaffolding's invariants
- [`.rules/witness.md`](.rules/witness.md) — ZK witness API for encryption and RLK proof generation

## Keeping rules up to date

Update the canonical `.rules/*.md` in the same change when your edit makes a rule stale. The **Touch → update** table maps file paths to the rules they affect — load the relevant rule when touching those paths.

**Touch → update:**

- `conventions.md` — `**/*.rs` (only when conventions change, not every edit)
- `cryptography.md` — `crates/fhe/src/{bfv,trbfv,trlbfv,lbfv,mbfv}/**`, `crates/fhe/examples/{mulpir,sealpir}.rs`
- `mathematics.md` — `crates/fhe-math/src/**`
- `protobuf.md` — `**/build.rs`, `**/*.proto`, `**/src/proto/**`
- `testing.md` — `**/tests/**`, `**/benches/**`, `.github/workflows/**`
- `harness.md` — `.rules/**`, `.opencode/**`, `AGENTS.md`, `CLAUDE.md`
- `witness.md` — `crates/fhe/src/{lbfv,trlbfv}/**` (the `_extended` witness APIs)

## Constraints — hard rules

### Never panic, unwrap, or expect in library code

Library code must never `panic!`, `unwrap()`, `expect()`, or use direct slice indexing. Use `?`, `Result`, and `get()`. `unwrap()`/`expect()` only in tests and benchmarks. The workspace denies `expect_used`, `panic`, `indexing_slicing` in clippy.

### Always use `--release`

trbfv e2e tests take minutes in debug, seconds in release. Always run tests with `cargo test --release`.

### Never hand-edit generated protobuf output

Regenerate via the build — see [`.rules/protobuf.md`](.rules/protobuf.md).

### Never make unsupported security claims

This library has never been independently audited — see [`.rules/cryptography.md`](.rules/cryptography.md).

### Add or extend tests for the code you change

Even if nobody asked. Follow the testing rules in [`.rules/testing.md`](.rules/testing.md).

## Git — never commit or push without explicit consent

When asked to commit, follow repo style: inspect `git status`, `git diff`, and recent `git log`; stage only intended files. PR titles use the format `[agent] <Title>`.
## Style & lints

Workspace lints are strict — code that violates them won't pass CI:

- Deny: `expect_used`, `panic`, `indexing_slicing`, `unused_must_use`, `fallible_impl_from`
- Warn: `missing_docs`, `unused_imports`, `must_use_candidate`
