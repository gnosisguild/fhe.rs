# Workflow

## Patch discipline

- Inspect the target file and its surrounding context before editing. Understand imports, conventions, and how the code is wired together.
- Prefer the smallest correct patch. Do not refactor unrelated code in the same change.
- Preserve unrelated worktree changes — do not stage or commit files outside the task scope.

## Git

- Do not commit, amend, push, rebase, or change git configuration unless the user explicitly asks.
- Before committing when asked, inspect `git status`, `git diff`, and recent `git log` to match repo style. Stage only intended files.
- PR title format: `[agent] <Title>`.

## Error handling

- Library code must never `panic!`, `unwrap()`, or `expect()`. Use `?`, `Result`, and fallible APIs. The workspace denies `expect_used`, `panic`, and `indexing_slicing` in clippy.
- `unwrap()` and `expect()` are acceptable only in tests and benchmarks.
- Avoid indexing slices directly; use `get()` or pattern matching to handle bounds safely.

## Key aggregation validation

- Key aggregation methods (public-key, relinearization-key, key-switching-key) must validate metadata (participant bindings, session IDs, parameter consistency) and structural shape (ciphertext count, component count, polynomial contexts, levels) **before** accessing polynomial data.
- Use fallible accessors (`first()`, `get()`, `ok_or_else`) for all key material lookups; never assume a well-formed key from serialized or external input.
- Cross-contribution polynomial equality (`a`, `d1`) must be checked by concrete value comparison, not solely by seed equality, because seedless deserialized keys carry no seed.

## CRP vectors (`fhe::bfv::CommonRandomPoly` / `CommonRandomPolyVec`)

- `CommonRandomPoly` is a single uniformly-random polynomial in `R_q`. It is the BFV-level CRP type used by MBFV single-polynomial operations and trBFV additive public-key sharing.
- `CommonRandomPolyVec` is a vector of `l = |{q_i}|` such polynomials with optional seed metadata. It is used by MBFV relinearization key generation and l-BFV `a`/`d1` material.
- Both types live in `crates/fhe/src/bfv/crp.rs` and are exported from `fhe::bfv`. Legacy scheme-local CRP/CRS modules have been consolidated here — no scheme-specific CRP wrappers remain.
- Concrete polynomials are authoritative. Seeds are metadata that reconstruct values but are not authentication. Equality comparisons of keys, shares, and CRP vectors use concrete polynomial equality, never seed equality alone.
- `CommonRandomPolyVec::from_polys` validates length, polynomial contexts, and seed consistency. Vectors with missing or contradictory seed metadata are rejected.

## L-BFV / TRLBFV boundary

- `crates/fhe/src/lbfv/**` must not import `crate::trlbfv`. Threshold bindings, shares, aggregation, and threshold validation belong exclusively to `crate::trlbfv`.
