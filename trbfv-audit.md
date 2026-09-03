# TRBFV Crate — Full Production-Readiness Audit

**Date:** 2026-07-15
**Crate:** `crates/fhe/src/trbfv/` (`config`, `errors`, `shamir`, `shares`, `smudging`, `threshold`), the `proto/trbfv` scaffolding, and every supporting path it exercises in `fhe-math` (`Poly` ops, `Modulus`, RNS scaler, samplers) and `fhe` (`bfv` encrypt/decrypt, `mbfv` public-key share).
**Reference papers (pulled and read):**
- Urban & Rambaud, *Robust Multiparty Computation from Threshold Encryption Based on RLWE*, eprint **2024/1285** (v3, 2024-10-11). This is the scheme the module implements (passively-secure, additions-only variant). Equations cited below are from this paper.
- Fan & Vercauteren, *Somewhat Practical Fully Homomorphic Encryption*, eprint **2012/144** (the base BFV scheme and its noise/decryption analysis, referenced as `[FV12]` by the trBFV paper).
- Bajard, Eynard, Hasan & Zucca, *A Full RNS Variant of FV*, eprint **2016/510** (the RNS decryption/scaling this fork uses).

**Method:** full manual read of every file in the module; each bound formula in `smudging.rs` re-derived from the paper's Eq. (25)/(31)/(8) and checked numerically against the production preset; the constant-time discipline traced through `fhe-math` down to the `reduce1`/`reduce1_vt` branch; the decryption-share reconstruction algebra checked against Eq. (5)/(7); Shamir arithmetic and its modular normalisation traced end to end; full test suite run in release (41/41 pass, including the degree-8192 production preset e2e with worst-case boundary noise); `clippy` clean.

---

## Verdict

**The core cryptography is sound and faithfully implements the paper.** The smudging bound, the fresh-noise bound `B_fresh`, the circuit-noise bound `B_C`, the correctness budget `B_C + n·B_sm < Q/2t`, the linear reconstruction `c0 + c1·sk + e_sm`, the per-RNS-residue Shamir sharing, and the final `t/Q` rounding all match eprint 2024/1285 and the base FV/RNS papers. The production preset satisfies both parts of the paper's Eq. (8) exactly. The e2e test decrypts correctly even when the aggregated smudging noise is pushed to the exact `n·B_sm` correctness boundary.

**No math or logic bug was found that breaks correctness or leaks the key outright in the honest-but-curious model the module targets.** However, there is **one previously-unreported constant-time defect** (F1 below) and a set of **parameter, API-hardening, and threat-model issues** that should be resolved before production. The two items I would gate the release on are **F1** (secret-dependent variable-time multiply) and **F2** (statistical-security parameter is per-coefficient, so the real margin is ~2⁻³⁷, not 2⁻⁵⁰). Both have small, well-scoped fixes.

This audit **confirms and consolidates** the findings in the two prior review documents (`trbfv-soundness-review.md`, `repo-soundness-review.md`) and **adds F1**, which neither document reported.

---

## Part 1 — Implementation vs. paper: what was verified correct

### 1.1 Smudging bound `B_sm` (`smudging.rs:149-193`) — matches Eq. (31) and Eq. (8)

The paper's improved (second) threshold-decryption method (§6.0.2) requires:

- **Correctness**, Eq. (31): `B_C + n·B_sm < Δ/2 = Q/(2t)`.
- **Security**, Eq. (8), first clause: `B_C / B_sm = negl(λ)`, satisfied by `B_sm ≥ 2^λ · B_C`.

The code computes exactly `B_sm = 2^λ · B_C` (the minimal secure value) and rejects the parameter set unless `2^λ·B_C ≤ (Q/(2t) − B_C)/n`, i.e. `B_C + n·B_sm ≤ Q/(2t)`. The integer-division flooring on the upper bound only tightens the check (safe direction). The dedicated test `trbfv_smudging_bound_matches_paper_formula` pins this to the paper and passes.

### 1.2 Fresh-noise bound `B_fresh` (`smudging.rs:160-161`) — matches Eq. (25)

Paper Eq. (25): `e^(fresh) ≤ B_Enc + d·‖e^(ek)‖ + d·B·‖sk‖`, from `c[0] + c[1]·sk = Δm + u·e^(ek) + e0^(Enc) + sk·e1^(Enc)`.

Code: `b_fresh = d·e_norm + b_enc + d·b_e·sk_norm`, with the terms mapped as follows (I traced the actual encrypt path to confirm the mapping, because the code's `e1`/`e2` naming is the reverse of the paper's `e0^(Enc)`/`e1^(Enc)`):

| Paper term | Bound | Code | Where it enters encryption (`public_key.rs:176-189`) |
|---|---|---|---|
| `e0^(Enc)` (added to `c0`) | `B_Enc` | `b_enc = ⌊√(3·error1_variance)⌋` | the **large** `error_1` uniform noise added to `c0` |
| `e1^(Enc)` (added to `c1`, hit by `·sk`) | `B` | `b_e = 2·variance` | the **small** CBD `e2` added to `c1` |
| `e^(ek)` (joint pk error, via `u·e^(ek)`) | `n·2·variance` | `e_norm = public_key_error` | sum of `n` CBD pk-share errors (`mbfv/public_key_gen.rs:48`) |
| `sk` (joint key) | `n` | `sk_norm = n` | sum of `n` ternary keys, each `‖·‖≤1` |

Every term is a true worst-case (triangle-inequality) bound, and `‖a·b‖_∞ ≤ d·‖a‖·‖b‖` for the two ring products, with `‖u‖≤1`. **Correct.**

### 1.3 Circuit-noise bound `B_C` (`smudging.rs:171`) — safe for additions

Code: `B_C = m·(B_fresh + (Q mod t))`. For a sum of `m` fresh ciphertexts (the Enclave tally use-case), Eq. (26) gives per-addition noise `‖e1‖ + ‖e2‖ + (Q mod t)`, so the true bound is `m·B_fresh + (m−1)·(Q mod t)`. The code adds one extra `(Q mod t)` term — an over-estimate, i.e. the **safe** direction for correctness. Consistent with the "additions-only" scope.

### 1.4 Production preset satisfies both clauses of Eq. (8)

For the `secure_8192` preset (`tests/trbfv_secure_e2e.rs`: `d=8192, n=20, variance=10, error1_variance≈2^143.3, t=10^6, Q≈2^171`):

- Decryption clause `B_C/B_sm = 2^−λ = 2⁻⁵⁰` (per coefficient) — by construction.
- Encryption clause `2dnB/B_Enc`: `B_Enc ≈ 2^72.64`, `2dnB ≈ 2^22.64`, ratio **exactly 2⁻⁵⁰**. The bespoke `error1_variance` string was clearly solved to hit this.
- Correctness budget: `B_C + n·B_sm ≈ 2^132.6 < Q/(2t) ≈ 2^150.1`. Comfortable.

Both smudging conditions are targeted at 50-bit **per-coefficient** distance — see F2 for why the transcript-level margin is smaller.

### 1.5 Reconstruction algebra (`shares.rs:279-309, 327-488`) — matches Eq. (5)/(7)

Each party publishes `d_i = c0 + c1·S(i) + E(i)`, where `S`,`E` are the Shamir sharings of the joint key `sk` and joint smudging noise `e_sm`. Because `c0` is public and added identically by all parties, `d(x) = c0 + c1·S(x) + E(x)` is a degree-`T` polynomial, and Lagrange interpolation at `x=0` of any `T+1` shares yields `c0 + c1·sk + e_sm = Λ^c_{Dec+sm}(sk, e_sm)` (Eq. (7)) — the Lagrange weights sum to 1, so the constant `c0` survives exactly. Recovery is done independently per RNS residue and per coefficient, then CRT-lifted and `t/Q`-scaled. **Correct**, and the wrong-index test confirms there is no accidental index independence.

### 1.6 Shamir layer (`shamir.rs`) — sound and correctly normalised

Evaluation points `1..=n` with `n < min(q_i)` enforced at `ShareManager::new` and again in `generate_secret_shares_from_poly`, so all points and all denominator differences are non-zero units mod every (prime) modulus. Share values land in `[0, q_i)`; Lagrange intermediates stay in `(−p, p)` after each `%` and `recover` normalises with a single `+p`; a duplicate x-coordinate produces a non-invertible denominator and a clean error. BigInt arithmetic means no numeric overflow. Negative smudging coefficients are RNS-reduced correctly in `from_bigints` (`rq/mod.rs:411-414`).

### 1.7 Final decryption scaling (`shares.rs:418-476`) — equivalent to `try_decrypt`

The `scale → +t → reduce mod q0 → reduce mod t` sequence is line-for-line the BFV `SecretKey::try_decrypt` Small path (`secret_key.rs:316-328`). The scaler is rebuilt from scratch (into a **1-modulus** output context vs. the 2-modulus context BFV precomputes), but the `q0` residue of `round(t·x/Q)` is independent of the other output moduli, and the subsequent `v[..degree]` reads exactly that residue — so the result is identical. The worst-case-noise e2e test confirms this empirically at the correctness boundary.

### 1.8 RNG and parallelism (`shamir.rs:51-55, 142-156`; `shares.rs:381-415`)

Seeds are forked sequentially from the caller's RNG *before* any `rayon` fan-out, each task builds an independent `ChaCha20Rng`, and indexed collects preserve order. Determinism holds for testing; no RNG is shared across threads. Randomness quality is fine (256-bit ChaCha20 seeds from a `CryptoRng`).

---

## Part 2 — Findings (severity-ranked)

### F1 — Decryption share multiplies the secret key share in **variable time** — NEW · Medium (constant-time break)

`shares.rs:299-308`. Ciphertexts produced by `try_encrypt` have `allow_variable_time_computations = true` on both components (`public_key.rs:191-194`). `decryption_share` never clears it:

```rust
let c0 = ciphertext.c[0].clone().into_power_basis();   // avt = true
let c1 = ciphertext.c[1].clone();                      // avt = true
...
let c1sk = (&c1 * &sk_i).into_power_basis();
```

`Mul` for `Poly<Ntt>` ORs the operands' flags (`rq/ops.rs:182`), so the pointwise product `c1 · sk_i` dispatches to `mul_vec_vt` → `mul_vt` → `reduce1_vt`, which on macOS/AVX2 is the **data-dependent branch** `if x >= p { x - p } else { x }` (`zq/mod.rs:705-710`). One operand of that product is `sk_i`, the party's **secret** share of the joint key. So the per-coefficient timing of a party's decryption-share computation is correlated with its secret key material, and the `+ es_i` add (secret smudging share) runs variable-time too.

This is a genuine defect, not a theoretical nit: the library has a full constant-time discipline, and the standard `SecretKey::try_decrypt` is careful to call `disallow_variable_time_computations()` on the ciphertext *before* multiplying by the secret (`secret_key.rs:298-304`), as does `PublicKeyShare::new` (`mbfv/public_key_gen.rs:50`). `decryption_share` is the one secret-times-public multiply on a hot path that omits it. Threat model: a co-located / timing-observing attacker measuring a party's share computation — the same model under which the module already flags its non-constant-time BigInt Shamir arithmetic, but this one is silent and on every decryption.

**Fix (small):** mirror `try_decrypt` —
```rust
let mut c0 = ciphertext.c[0].clone(); c0.disallow_variable_time_computations();
let mut c1 = ciphertext.c[1].clone(); c1.disallow_variable_time_computations();
let c0 = c0.into_power_basis();
```
Prior reviews flagged the general `allow_variable_time` fragility but did **not** identify that the trBFV decryption-share path multiplies the key share in variable time.

### F2 — λ is per-coefficient: real statistical security is λ − log₂(d) ≈ 2⁻³⁷, not 2⁻⁵⁰ — Confirmed · High (blocker for a stated λ target)

`smudging.rs:20,184`. The smudging lemma (paper Lemma 24) gives statistical distance `≤ B_C/B_sm = 2⁻λ` **per coefficient**. A single threshold decryption reveals all `d` reconstructed coefficients, so the transcript-level distance is `≤ d·2⁻λ = 2^(log₂d − λ)`. With the production preset (`d=8192, λ=50`) that is **2⁻³⁷**, and `MIN_SECURE_LAMBDA = 50` presents exactly this as "secure." The encryption-side clause of Eq. (8) is also targeted at 2⁻⁵⁰ per coefficient and degrades the same way (~2⁻³⁷ over `d` coefficients). This is a real erosion of the advertised statistical margin, though note it bounds a *distinguishing advantage*, not direct key recovery, and Enclave performs one decryption per key epoch (no multiplicative blow-up across decryptions).

**Fix:** make the minimum account for the transcript, e.g. require `λ ≥ target + ⌈log₂ d⌉ + ⌈log₂(#decryptions per key)⌉`. For 40-bit transcript security at `d=8192` and one decryption, that is `λ ≥ 53`; raise the production preset's λ to ~64 for margin and document that λ is per-coefficient.

### F3 — Smudging noise is single-use, but nothing enforces or documents it — Confirmed · High (protocol footgun)

`threshold.rs:147-150` documents that `es_i` must be the aggregated *shared* noise, but nothing stops a caller from reusing the same aggregated `es_poly_sum` to decrypt two different ciphertexts. The paper is explicit (§6.0.2): "the noise can be used only for one threshold decryption." If the same `e_sm` masks decryptions of `c` and `c'`, the smudging cancels in the difference of published shares, leaving `(c0−c0') + (c1−c1')·sk_i` unmasked — the whole argument collapses and key material leaks. The Enclave flow (one tally per key epoch) is safe; a general caller is not.

**Fix:** at minimum, prominently document "fresh shared noise per decryption." Better, make the aggregated noise a consume-once type, or bind it to a specific ciphertext.

### F4 — `aggregate_collected_shares` does not range-check incoming entries — Confirmed · Medium (untrusted-input robustness)

`shares.rs:222-256`. Only the matrix *shape* is validated; entries are summed with `Modulus::add_vec`, whose `a,b < p` precondition is `debug_assert` only (`zq/mod.rs:241`). These entries are exactly what arrives from other parties over transport. In release, a hostile/corrupt entry (e.g. `u64::MAX`) wraps silently and permanently corrupts that party's aggregated key share; in debug it is a reachable panic on untrusted input. CI runs release only, so the assert never fires there.

**Fix:** reject any entry `≥ q_i` per row at ingestion, returning `malformed_shares`.

### F5 — `ShareManager` / `ShamirSecretSharing` accept `threshold = 0` — Confirmed · Medium (defense-in-depth)

`validate_threshold_config` (enforcing `threshold == (n−1)/2`, `n ≥ 3`) runs only inside `TRBFV::new`. `ShareManager::new` (publicly re-exported, `shares.rs:59`) skips it, and `ShamirSecretSharing::split` only rejects `threshold` too *high* (`shamir.rs:109`), not `threshold = 0`. A `threshold = 0` sharing is a degree-0 polynomial: **every share equals the secret**, so every party would receive the full joint key. Reachable by any direct `ShareManager`/`ShamirSecretSharing` user bypassing `TRBFV`.

**Fix:** call `validate_threshold_config` in `ShareManager::new`; reject `threshold = 0` (and ideally `threshold > (n−1)/2`) in `ShamirSecretSharing::split`/`new`.

### F6 — `m = 0` produces a "secure" smudging bound of **zero**; `n = 0` panics — Confirmed · Medium / Low

`smudging.rs:171-186`. With `num_ciphertexts = 0`, `B_C = 0`, all feasibility checks pass, and the generator emits **all-zero** noise — decryption shares then leak the exact decryption noise. `0` is a plausible caller mistake for "no homomorphic ops" (the correct value for a single fresh ciphertext is `1`). Separately, `n = 0` makes `upper_bound = (Q/2t − B_C)/n` a division-by-zero panic; reachable because `SmudgingBoundCalculatorConfig` is directly constructible without `TRBFV::new`'s validation.

**Fix:** reject `m == 0` and `n == 0` in the calculator.

### F7 — Decryption shares are not bound to their claimed party index — Confirmed · Low/Medium (robustness, not confidentiality)

`shares.rs:396-405` and the `test_threshold_decryption_wrong_indices_fails` test: if the coordinator pairs a share with the wrong `reconstructing_parties` index, `decrypt_from_shares` returns a **silently wrong** plaintext (`Ok`, not an error). There is no commitment/label tying a share to the party that produced it. A single malformed share therefore corrupts the result undetectably. This is exactly the gap the paper closes with PVSS/ZK-verified shares (its robustness guarantee) and that `config.rs:16-19` assumes ("shares verifiable … so honest parties never mix in bad shares"). See the threat-model note below.

### F8 — No zeroization of derived secret material — Confirmed · Low/Medium

The `SecretKey` zeroizes, but the *derived* secrets do not: the share matrices returned by `generate_secret_shares_from_poly` (`Vec<Array2<u64>>`), the aggregated key polynomial from `aggregate_collected_shares` (`sum_poly`), the `c1·sk_i` product in `decryption_share`, and the smudging coefficient vectors all linger in memory. For a threshold system whose entire purpose is protecting shared key material, this is worth closing.

### F9 — `b_enc` underestimates the `e1` bound when `error1_variance < 16` — Confirmed · Low (irrelevant to production preset)

`smudging.rs:109` computes `b_enc = √(3·error1_variance)` (the uniform-sampler bound), but `conditional_error` samples **CBD** with support `±2v` when `variance < 16` (`rq/mod.rs:368`), whose true bound is larger (e.g. 20 vs 5 at `v=10`). Harmless for the production preset (huge uniform `e1`, and the term is dominated by `d·‖e^(ek)‖` anyway), but the formula and the sampler should agree.

### F10 — Smaller items (Confirmed)

- **Level > 0 ciphertexts** are effectively unsupported (the share context check in `decryption_share` and the full-moduli shape check in `decrypt_from_shares` reject them) while `scalers[ciphertext.level]` suggests support — reject explicitly with a clear error, or support levels.
- **Dealer-set consistency** is not enforced: `aggregate_collected_shares` allows 1..n matrices, but all parties must agree on the *same* dealer subset `S` or they hold shares of different joint keys. A protocol-level requirement (paper's non-aborting set `S`) worth documenting.
- **`proto/trbfv`** is dead scaffolding whose `DecryptionShare`/`SmudgingData` carry an opaque, unvalidated `poly_data: bytes` field — harden before any serialization is wired up.
- **Error mislabeling:** "too many shares" / count-mismatch report `insufficient_shares` (`shares.rs:219-221, 348-353`) — misleading during incident triage.
- **Non-constant-time BigInt Shamir arithmetic** (already noted in the module docs; local-only, low severity, same co-located model as F1).
- **`public_key_error = n·2·variance`** is a `u64` product; only overflows at absurd `n` (~2⁶⁰), so not a practical concern, but there is no explicit upper bound on `n` beyond `n < min_modulus`.

---

## Part 3 — Threat model & deployment checklist

The module implements the **passive / semi-honest core** of eprint 2024/1285 (Shamir sharing of key and noise, linear opening, Lagrange reconstruction, `t/Q` decode). The paper's **robustness against malicious parties** comes from a verifiability layer (PVSS / ZKPs / the `F_LSS` functionality) that is **not in this crate**. Before production:

1. **Fix F1 and F2** (constant-time multiply; per-coefficient λ). These are the two I would block on.
2. **Guarantee fresh shared smudging noise per decryption** (F3) — architecturally or by the consume-once type.
3. **Validate untrusted transport at ingestion** (F4, F7): range-check share entries, and add a share↔party binding (commitment/ZK) if any party can be malicious. Without it, robustness and malicious-security do not hold — a single bad share silently corrupts the tally.
4. **Enforce `threshold = (n−1)/2` everywhere** (F5) and reject `m = 0`/`n = 0` (F6), not just in `TRBFV::new`.
5. **Confirm the plaintext modulus bounds the tally:** `Σ inputs < t`, else the sum wraps mod `t` (BFV is modular; correct behaviour, but a usage constraint).
6. Zeroize derived secrets (F8); resolve the level-handling ambiguity (F10).

---

## Part 4 — Test & tooling status

- `cargo test -p fhe --release` (trBFV + e2e): **41/41 pass**, including `trbfv_e2e_secure_8192_worst_case_smudging_noise`, which drives the aggregated noise to the exact `n·B_sm` correctness boundary under the real production preset, and `trbfv_smudging_bound_matches_paper_formula`, which pins the bound to Eq. (25)/(31)/(8).
- `cargo clippy -p fhe --release`: **clean**.
- Coverage gaps worth adding: an empirical-variance check on generated smudging noise (the existing tests only assert non-zero coefficients); a test asserting `decryption_share` is constant-time-flagged (would catch regressions of F1); negative tests for `threshold = 0` and `m = 0`.
