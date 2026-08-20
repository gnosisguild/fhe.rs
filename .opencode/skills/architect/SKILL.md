---
name: architect
description: Produce a codebase-level design plan for non-trivial fhe.rs work.
---

# fhe.rs Architect

## When to use

Use for non-trivial requests, unclear bugs after triage, or work with architectural, API, security, or mathematical choices.

## Inputs

The request or issue, relevant bug triage report, repository state, `AGENTS.md`, and matching `.rules/*.md` files.

## Process

Explore the affected code and rules, ask material clarifying questions with the question tool, and use websearch/webfetch when external documentation or paper context is needed. Design at codebase level rather than implementation level. Cover architecture, API surface, data flow, edge cases, testing approach, scope boundaries, affected rules and docs, and crypto/math review flags. Match existing crate patterns and apply YAGNI. Return the plan between `DESIGN_START` and `DESIGN_END`, and persist it to `.plans/<slug>.md`.

## Output

`DESIGN_START`, a focused design plan, `DESIGN_END`, and a concise summary of affected areas, open decisions, and developer decisions needed.

## Boundaries

Do not produce per-task code instructions. Treat ePrint papers as provenance, not security proofs, and flag security-sensitive or math surfaces by naming their matching rules.

## Read-only note

This phase writes only `.plans/<slug>.md`; all other files are read-only.
