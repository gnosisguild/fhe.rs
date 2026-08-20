---
name: review
description: Review a completed fhe.rs diff or triage a bug without editing.
---

# fhe.rs Review

## When to use

Use only after explicit user approval for review, or first for an unclear bug that needs reproduction and root cause.

## Inputs

The request, working-tree diff and blast radius, and `AGENTS.md` plus all matching rules. Gather with `git fetch origin`, `git status --porcelain`, `git diff`, `git diff origin/main...HEAD`, and read the changed files.

## Process

The orchestrator dispatches the `reviewer` subagent (read-only, model pinned to max in `.opencode/opencode.json`) with this skill as its workflow. Review only changed hunks and their blast radius. Load all matching rules cumulatively: cryptography for BFV/trBFV/TRLBFV/LBFV/MBFV and PIR paths; mathematics for `crates/fhe-math/src/**`; testing for tests, benches, workflows; witness for l-BFV/trlBFV; protobuf for build/proto paths; harness for `.rules/**`, `.opencode/**`, `AGENTS.md`, `CLAUDE.md`. For triage: Reproduce → Trace → Explain → Fix direction, then return a Bug Triage Report.

## Output

Synthesize one verdict, `Ready` or `Blocked`, with sections: Blocking, Bugs & Risks, Crypto, Math, Conventions, and Missed Obligations. Crypto/Math Critical or High findings are BLOCKING; ordinary findings map to BLOCKING or SUGGESTION by severity. Include `file:line` evidence and a one-line fix.

## Boundaries

Review only the diff and blast radius, never the whole repository or pre-existing issues. Never edit, commit, or push. Do not claim a security audit or constant-time behavior; cite the relevant ePrint URL and section when a finding depends on a paper.

## Read-only note

This phase never edits files; it reports a verdict or Bug Triage Report only.
