# TRBFV Soundness Review

**Date:** 2026-07-14
**Scope:** `crates/fhe/src/trbfv/` (config, shamir, shares, smudging, threshold), plus the supporting BFV/mbfv sampling paths and `tests/trbfv_secure_e2e.rs`
**Reference:** Urban & Rambaud, *Robust Multiparty Computation from Threshold Encryption Based on RLWE* (eprint 2024/1285), passively secure variant, additions only
**Method:** Full manual read of the module, cross-checked bound formulas against the actual sampling code in this fork, independent adversarial review pass, full trbfv test suite in release mode (41/41 pass, including production-preset e2e with worst-case boundary smudging noise)

## Verdict

The core cryptographic math is sound. The full pipeline — Shamir sharing per RNS residue, share aggregation, decryption-share computation, Lagrange reconstruction, and the t/Q scaling — matches the paper and the fork's actual sampling distributions, with no soundness break in the honest-but-curious model the module claims. Several issues should be fixed before production; findings 1 and 2 are blockers.

## Verified as correct

- **Shamir math** (`shamir.rs`): share evaluation only handles non-negative values so shares land in `[0, p)`; Lagrange intermediates stay in `(-p, p)` after every `%` and `recover` normalizes with a single `+p`; duplicate x-coordinates are caught via non-invertible denominators. Evaluation points `1..=n` with `n < min(q_i)` enforced, so denominators are units mod every modulus.
- **Linearity/reconstruction**: summing share matrices mod `q_i` correctly yields shares of the summed secret; `d_i = c0 + c1·S(i) + E(i)` is a degree-T polynomial in the party index, so interpolating T+1 shares at 0 gives `c0 + c1·sk + e_sm` — including the `c0` constant (Lagrange weights sum to 1). The reshape/transpose in `generate_secret_shares_from_poly` and the row↔party-index mapping are consistent across all consumers.
- **Bound formula vs. actual sampling**: `secret_key_bound = n` matches ternary CBD(0.5) keys; `public_key_error = 2vn` matches n aggregated `Poly::small` pk errors; `b_e = 2v` matches CBD support; `b_enc = √(3σ²)` matches the uniform sampler used for `error1_variance ≥ 16` (the production path). `B_sm = 2^λ·B_C` with the `B_C + n·B_sm ≤ Q/2t` check matches the paper's Eq. 31, and all floor divisions round in the safe direction.
- **Final decryption** (`decrypt_from_shares`): the scale/`+t`/reduce-mod-q0/reduce-mod-t sequence matches standard BFV `try_decrypt` exactly; negative smudging coefficients are reduced correctly in `from_bigints`; no u64 overflow on any reachable path.
- **RNG/parallelism**: seeds are forked sequentially before rayon fan-out and indexed collects preserve order — deterministic and no RNG sharing across threads.

## Findings

### 1. λ is per-coefficient; real statistical security is λ − log₂(d) — BLOCKER

`smudging.rs:184`. `B_sm = 2^λ·B_C` gives statistical distance ~2^-λ *per coefficient*, but one decryption reveals `degree` reconstructed coefficients. With the production preset (d = 8192, λ = 50) the transcript-level distance is ~2^-37, and `MIN_SECURE_LAMBDA = 50` permits exactly this.

**Fix:** add `log2(degree)` (plus the number of decryptions ever performed under one key) to the minimum, or raise λ in the production preset to ~64+ and document that λ is per-coefficient.

### 2. Smudging noise reuse across ciphertexts neither prevented nor documented — BLOCKER

`threshold.rs:120`, `shares.rs:279`. If the same aggregated `es_poly_sum` is used to decrypt two *different* ciphertexts, the smudging cancels in the difference of published shares, leaving `(c0−c0′) + (c1−c1′)·sk_i` unsmudged — the smudging argument collapses and key material leaks. The Enclave flow (one tally per key epoch) is safe, but nothing in the API stops a caller from reusing it.

**Fix:** at minimum document "fresh noise dealing per decryption" prominently; better, make the noise share a consume-once type.

### 3. `aggregate_collected_shares` doesn't range-check incoming share entries

`shares.rs:250-256`. Only the shape is validated. Entries are exactly what arrives from other parties over transport, and `Modulus::add` assumes both operands `< p` — in release a hostile/corrupted entry (e.g. `u64::MAX`) wraps silently and permanently corrupts that party's `sk_poly_sum`; in debug it is a reachable panic on untrusted input.

**Fix:** validate `entry < q_i` per row at ingestion.

### 4. `m = 0` yields a "secure" smudging bound of zero

`smudging.rs:171-192`. With `num_ciphertexts = 0`, `B_C = 0`, all feasibility checks pass, and the generator emits all-zero noise — decryption shares then leak the exact decryption noise. `0` is a plausible caller mistake for "no homomorphic ops" (correct value: 1). Related: `n == 0` panics on division at `smudging.rs:186` (config validation is only run by `TRBFV::new`, not by the directly-constructible `SmudgingBoundCalculatorConfig`).

**Fix:** reject `m == 0` and `n == 0` in the calculator.

### 5. `b_enc` underestimates the e1 bound when `error1_variance < 16`

`smudging.rs:109` vs. `conditional_error` in `fhe-math/src/rq/mod.rs:368`. Small variances sample CBD with support ±2v, but the bound formula assumes the uniform-sampling bound √(3v) (e.g. 20 vs. 5 at v = 10). Irrelevant for the production preset (huge uniform e1) and dominated by the d·‖e_pk‖ term regardless, but the formula and sampler should agree.

**Fix:** tie `b_enc` to the actual sampling branch.

### 6. Smaller hardening items

- `ShareManager::new` skips `validate_threshold_config`, and it's publicly exported — a direct user can build threshold-0 managers. Run the validation there too.
- Level > 0 ciphertexts are rejected by the share shape check while `scalers[ciphertext.level]` suggests they're supported — dead/misleading; either support levels or reject explicitly with a clear error.
- Dealer-set consistency isn't enforced: docs allow aggregating fewer than n matrices, but all parties must agree on the same dealer subset or they hold shares of different joint keys. Protocol-level concern worth documenting.
- No zeroization of secret share matrices, `sk_poly_sum`, or smudging coefficient vectors (the `SecretKey` itself does zeroize).
- "Too many shares" and count-mismatch errors report `insufficient_shares` (`shares.rs:219`, `shares.rs:348`) — misleading during incident debugging.
- `proto/trbfv` is dead scaffolding with an opaque unvalidated `poly_data` bytes field — watch it when serialization gets wired up.
- Non-constant-time BigInt Shamir arithmetic: already documented in the module README; local-only computation, low severity, relevant to co-located attacker models.
