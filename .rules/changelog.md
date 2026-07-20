# Changelog

If the repo keeps a `CHANGELOG.md`, use [Keep a Changelog](https://keepachangelog.com/) style.

## Scope

Record user-facing or otherwise release-notable changes only. Changes exclusively to the AI harness — `.rules/`, `.opencode/`, `AGENTS.md`, `CLAUDE.md`, or `opencode.json` — do not belong in `CHANGELOG.md` unless they alter shipped user-visible behavior (e.g. a new MCP server that is part of the public API).

## When to edit `CHANGELOG.md`

**Do not** update `CHANGELOG.md` while implementing or iterating on a feature. Leave `[Unreleased]` unchanged until commit time.

Update **`## [Unreleased]`** only when:

1. The user **explicitly asks for a git commit** — add bullets (Added / Changed / Fixed / etc.) in that commit, summarizing the changes being committed.
2. The user **explicitly asks for a changelog update before commit** (e.g. "prepare changelog for commit") — then edit `[Unreleased]` without committing yet.

Otherwise, skip changelog edits even for user-facing work.

`[Unreleased]` is the draft for the **next** version: at release time, its contents move under `## [x.y.z] - YYYY-MM-DD` and `[Unreleased]` is reset for the next cycle.

## Version alignment

When bumping a version, keep `Cargo.toml` workspace version and per-crate `Cargo.toml` versions aligned. The crates in the workspace (`fhe`, `fhe-math`, `fhe-traits`, `fhe-util`) share the workspace version by default via `version.workspace = true`.

## Release checklist

- Version bumps in all relevant `Cargo.toml` files
- `CHANGELOG.md` `[Unreleased]` moved to a dated version section
- Git tag matches the version (e.g. `v0.1.0`)
- `cargo publish` for each crate in dependency order: `fhe-util` → `fhe-traits` → `fhe-math` → `fhe`
