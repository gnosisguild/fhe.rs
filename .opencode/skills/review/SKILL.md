---
name: review
description: Use when the implementation is complete and ready for pre-commit review. Dispatches guard-reviewer and quality-reviewer subagents in parallel, plus crypto-reviewer and math-reviewer conditionally based on the diff. Synthesizes one verdict. Read-only — reports findings, never edits.
---

# fhe.rs Review (pre-commit orchestrator)

One command that dispatches up to four review subagents and folds their findings into a single verdict. The subagents cover complementary domains:

- **`guard-reviewer`** (subagent, always) — project-specific constraints and conventions: no panics/unwrap/expect/indexing in library code, `--release` tests, protobuf codegen rules, security claims policy, Touch → update parity.
- **`quality-reviewer`** (subagent, always) — universal Rust code quality: correctness, error handling, API quality, test coverage, design, performance.
- **`crypto-reviewer`** (subagent, conditional) — cryptographic correctness: key handling, noise, parameters, serialization, decryption, threshold logic. Dispatched only when the diff touches `crates/fhe/src/{bfv,trbfv,trlbfv,lbfv,mbfv}/**` or `crates/fhe/examples/{mulpir,sealpir}.rs`.
- **`math-reviewer`** (subagent, conditional) — mathematical correctness: RNS, NTT, modular arithmetic, polynomial operations, bounds, conversions. Dispatched only when the diff touches `crates/fhe-math/src/**`.

All subagents are read-only. This skill synthesizes, deduplicates, and resolves conflicts (guard-reviewer wins on project-specific conflicts by definition).

Any agent can load this skill to run a pre-commit review. `orchestrator` loads it at the review phase; you can also invoke it directly on a ready branch.

This skill orchestrates; it never commits or pushes (see AGENTS.md → Git).

## 1. Gather the diff

```bash
git fetch origin
git status --porcelain
git diff --stat
git diff origin/main...HEAD --stat
```

Determine which specialist reviewers to dispatch:

- Does the diff touch `crates/fhe/src/{bfv,trbfv,trlbfv,lbfv,mbfv}/**` or `crates/fhe/examples/{mulpir,sealpir}.rs`? → dispatch `crypto-reviewer`
- Does the diff touch `crates/fhe-math/src/**`? → dispatch `math-reviewer`

## 2. Dispatch subagents in parallel

Use the `task` tool to dispatch all applicable subagents simultaneously:

- `subagent_type: "guard-reviewer"` — reads AGENTS.md Constraints, `.rules/` conventions, cross-cutting obligations
- `subagent_type: "quality-reviewer"` — reviews the diff for correctness, error handling, API quality, design, performance
- + `subagent_type: "crypto-reviewer"` (conditional)
- + `subagent_type: "math-reviewer"` (conditional)

All receive the same diff scope. Each returns a findings report.

## 3. Synthesize one verdict

Merge all reports into a single consolidated output:

### Verdict — one line

`Ready` or `Blocked`. Blocked if any subagent reported a BLOCKING finding.

### Blocking

Hard-constraint violations (from `guard-reviewer`) and correctness/error-handling findings rated BLOCKING (from `quality-reviewer`). Plus any CRITICAL/HIGH findings from `crypto-reviewer` or `math-reviewer`. Each: `file:line` + one-line fix.

### Bugs & Risks

`quality-reviewer` correctness findings that were rated SUGGESTION. Race conditions, trait correctness, type unsafety.

### Crypto

Findings from `crypto-reviewer` rated MEDIUM or LOW. Noise, parameters, threshold, serialization.

### Math

Findings from `math-reviewer` rated MEDIUM or LOW. RNS, NTT, modular arithmetic, polynomial operations.

### API & Design

Over-engineering, duplication, misused patterns, missing docs (from `quality-reviewer`).

### Performance

Unnecessary allocations, inefficient algorithms (from `quality-reviewer`).

### Conventions

Project-specific convention deviations (from `guard-reviewer`).

### Missed Obligations

Rules sync gaps from Touch → update table (from `guard-reviewer`).

If a section is empty, say so in one line. Do not restate the diff.
