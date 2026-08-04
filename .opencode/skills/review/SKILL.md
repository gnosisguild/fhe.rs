---
name: review
description: Use when the implementation is complete and ready for pre-commit review. Dispatches the single reviewer subagent, which reviews only the diff and its blast radius, and synthesizes one verdict. Read-only — reports findings, never edits.
---

# fhe.rs Review (pre-commit)

One command that dispatches the `reviewer` subagent and folds its findings into a single verdict.

- **`reviewer`** (subagent, always) — checks the diff (only the changes and their blast radius, not the whole repo) against `AGENTS.md` Constraints, the Touch → update obligations, and universal correctness/quality. It loads the `.rules/*.md` matched to the diff via the Touch → update routing: `.rules/cryptography.md` when the diff touches `crates/fhe/src/{bfv,trbfv,trlbfv,lbfv,mbfv}/**` or `crates/fhe/examples/{mulpir,sealpir}.rs`, `.rules/mathematics.md` when it touches `crates/fhe-math/src/**`.

The subagent is read-only. This skill synthesizes and deduplicates. It never commits or pushes (see `AGENTS.md` → Git). Any agent can load this skill to run a pre-commit review; `orchestrator` loads it at the review phase.

## 1. Gather the diff

```bash
git fetch origin
git status --porcelain
git diff --stat
git diff origin/main...HEAD --stat
```

The diff scope is passed to the `reviewer`, which decides which domain skill to load.

## 2. Dispatch the reviewer

Use the `task` tool:

- `subagent_type: "reviewer"` — the request, the diff scope, and whether this is a diff review or a bug triage.

## 3. Synthesize one verdict

Merge the reviewer's findings into a single consolidated output:

### Verdict — one line

`Ready` or `Blocked`. Blocked if the reviewer reported any BLOCKING finding (or a Crypto/Math Critical/High).

### Blocking

Hard-constraint violations and definite correctness/error-handling bugs. Each: `file:line` + one-line fix.

### Bugs & Risks

Correctness findings rated SUGGESTION — race conditions, trait correctness, type unsafety.

### Crypto

Findings from the crypto checklist rated Medium/Low — noise, parameters, threshold, serialization.

### Math

Findings from the math checklist rated Medium/Low — RNS, NTT, modular arithmetic, polynomial operations.

### Conventions

Project-specific convention deviations.

### Missed Obligations

Rules sync gaps from the Touch → update table.

If a section is empty, say so in one line. Do not restate the diff.
