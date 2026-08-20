# Harness

## Scope

Git-tracked scaffolding: `.rules/`, `AGENTS.md`, `CLAUDE.md`, and `.opencode/` wiring, skills, and agents. The harness is project code; ignored machine-local files are out of scope.

## Invariants

1. Exactly one primary custom agent, `.opencode/agents/orchestrator.md`, is the sole entry point; three minimal subagent stubs (`architect`, `implementer`, `reviewer`) carry permissions, models, and a short Identity/Scope/Operating model/Boundaries body — the detailed workflow lives in the matching skills.
2. Exactly three skills exist at `.opencode/skills/{architect,implement,review}/SKILL.md`, each with frontmatter `name` and `description` and the identical headings `# fhe.rs <Phase>`, `## When to use`, `## Inputs`, `## Process`, `## Output`, `## Boundaries`, `## Read-only note`. The orchestrator passes the selected skill content into the phase subagent's dispatch prompt.
3. The seven `.rules/*.md` files have corresponding Area rules and Touch → update entries in `AGENTS.md`, with no orphan or stale entry.
4. Every harness surface is covered by the harness Touch → update entry, including `.rules/**`, `.opencode/**`, `AGENTS.md`, and `CLAUDE.md`.
5. Rule and source links resolve, including all AGENTS rule links and source references named by rules.
6. The orchestrator permission intent is `'*': allow` with only `rm *: deny` and `sudo *: deny`, and its edit ceiling allows `.rules/*`, `.opencode/**`, `AGENTS.md`, and `CLAUDE.md` while denying `.opencode/opencode.json` and all other edits. Stub edit ceilings: `architect` edits only `.plans/*`, `reviewer` never edits, `implementer` may edit.
7. Phase selection uses architect for non-trivial work, allows only the stated straightforward-task bypass, implements through the `implementer` stub plus `implement` skill, reviews through the `reviewer` stub plus `review` skill, and gates design approval, verification, and review with the user.
8. `.opencode/opencode.json` remains developer-owned and is not edited by the orchestrator without explicit developer instruction; it retains build/plan settings and Context7 MCP, carries the model entries for the orchestrator and the three stubs (reviewer pinned to max reasoning), and its bash block is minimal: `'*': allow` with only `rm *: deny` and `sudo *: deny`.
9. `AGENTS.md` and `.rules/` remain harness-neutral, `CLAUDE.md` remains an adapter, and `.opencode/` is OpenCode-specific and inert elsewhere.
10. Scope is git-tracked scaffolding only.
11. This rule self-applies: it remains listed in AGENTS and changes to harness surfaces keep this rule coherent.
12. Enforcement is a manual full audit by the orchestrator at the end of restructuring or before a PR; no invariant script exists.

## Evidence / tests

The audit checks one primary agent, three stub agents, three uniform skills, seven-rule bijection, links, cumulative rule routing, permissions and edit ceilings, stub-plus-skill dispatch, current-branch/no-commit boundaries, and absence of stale agent or script references.

Construct selection: rules hold constraints and domain knowledge; skills hold reusable judgment procedures; the orchestrator is the single persistent primary persona; deterministic scripts are not part of this harness. Domain knowledge remains in rules, not skills. Built-in collisions include `build`, `plan`, `general`, `explore`, and `scout`; no custom agent may reuse them.

## Sync

- Touch → update: `harness.md` — `.rules/**`, `.opencode/**`, `AGENTS.md`, `CLAUDE.md`.
