# fhe.rs Whole-Repo Production-Readiness Review

**Date:** 2026-07-14
**Scope:** All crates — `fhe-math` (zq, ntt, rns, rq), `fhe` (bfv, mbfv, lbfv, proto), `fhe-util`, `fhe-traits`. The `trbfv` module is covered separately in `trbfv-soundness-review.md`.
**Method:** Five independent full-read review passes (modular arithmetic/NTT, RNS/polynomial layer, BFV core, mbfv/lbfv multiparty, cross-cutting unsafe/panic/serialization sweep), each verifying findings by tracing call paths; the RNS pass additionally diffed every file against upstream `tlepoint/fhe.rs` to isolate fork-introduced logic. Severe findings spot-verified against source. Full workspace test suite passes in release mode; clippy is clean.

## Verdict

The core arithmetic is sound: Barrett/Shoup reduction bounds, NTT butterfly lazy-reduction invariants, the RNS Garner/CRT lift, and the t/Q decryption scaler were all traced and check out (and the correctness-critical RNS/ops code is byte-identical to upstream). The production blockers are at the **protocol and untrusted-input boundaries**, not in the math:

1. **mbfv decryption/key-switch shares have no smudging noise** — a confidentiality break within the stated passive model. Blocker if mbfv is in your production path (trbfv has its own smudging and is unaffected).
2. **Homomorphic `+`/`+=` panics on attacker-shaped ciphertexts that deserialize successfully** — a DoS on the exact Enclave aggregation flow. Blocker.
3. The pervasive pattern of `debug_assert`-only validation plus deserializers that accept non-canonical input means release builds silently compute garbage on malicious bytes in several places — needs a hardening pass at the serialization boundary.

---

## Blockers

### B1. mbfv key-switch/decryption shares carry no smudging noise — key leakage within the passive model

`mbfv/secret_key_switch.rs:78-79`, `mbfv/public_key_switch.rs:59-61`. The share is `h_i = (s_in − s_out)·c1 + e_i` with `e_i ← Poly::small(ctx, par.variance)` — small CBD noise, variance capped at 16. The code itself says `// TODO this should be exponential in ciphertext noise!`. `DecryptionShare` inherits this (it is SKS with a zero output key).

After aggregation every party learns `Δm + e_ct + Σe_i` with `Σe_i` small — i.e. the ciphertext noise `e_ct` almost exactly. For a ciphertext the adversary encrypted itself, `e_ct` is a known linear function of honest parties' public-key error terms; over repeated decryptions this recovers `e_pk,h` and then `s_h` from the published `p0_share = −a·s_h + e_pk,h`. This is precisely why Mouchet et al. require noise flooding; the security proof does not go through without it.

**Fix:** wire the existing smudging machinery (`trbfv/smudging.rs`, `error1_variance`) into `SecretKeySwitchShare::new` / `PublicKeySwitchShare::new`, sampling flooding noise ≥ 2^λ above the ciphertext-noise bound. If mbfv is not in the production path, gate or document it as insecure-as-is.

### B2. Homomorphic add/sub panic on malformed-but-deserializable ciphertexts (DoS on aggregation)

`bfv/ciphertext.rs:198-203` accepts any component count ≥ 2 and any valid level; `bfv/ops/mod.rs:28-29` (and the other operator impls) then `assert_eq!(self.level, rhs.level); assert_eq!(self.len(), rhs.len())`. A participant submits bytes decoding to a 3-component or level-1 ciphertext; the aggregator's `acc += &ct` panics. This is the primary consumer's exact hot path (aggregating untrusted user ciphertexts).

**Fix:** in `TryConvertFrom<&CiphertextProto>`, require exactly 2 components for transport ciphertexts (or a strict documented cap) and let the aggregator pin the expected level; and/or provide a fallible `checked_add`. At minimum, validate shape before summing in consumer code.

---

## High

### H1. Share aggregation (mbfv/lbfv) performs no cross-share validation

`mbfv/public_key_gen.rs:146-166`, `secret_key_switch.rs:107-127`, `public_key_switch.rs:89-110`, `relin_key_gen.rs:200-358`. All `Aggregate` impls sum shares with no check that parties agree on `par`, CRP, or ciphertext — those are taken from the *first* share only. `izip!` in relin aggregation silently truncates short `h0`/`h1` vectors. Poly ops only `debug_assert` context equality, so in release a mismatched-context share is added anyway, producing a structurally valid but garbage key/ciphertext. Also: no duplicate-share or party-count enforcement (an "aggregate" of one share is a key fully known to that party).

**Fix:** validate every share against the first (params, CRP/ct identity, vector lengths, contexts) and enforce an expected party set; return errors, not silence.

### H2. Deserialized coefficients are not reduced mod q; all `Modulus` preconditions are debug-only

`fhe-math/src/zq/mod.rs:816-821` (`deserialize_vec` accepts values in `[p, 2^nbits)`), `rq/convert.rs:137-148` (PowerBasis full-length path stores them raw). The `Ntt`/`NttShoup` paths self-heal (butterflies tolerate < 4p and re-canonicalize), so today's in-tree untrusted callers are safe — but any future direct `Poly<PowerBasis>` wire ingestion silently computes non-reduced garbage in release, since every `Modulus` range check is a `debug_assert`. Compounding this, CI runs release-mode tests only, so no `debug_assert` ever fires in CI.

**Fix:** reduce (or reject) out-of-range coefficients in `parse_proto`/`deserialize_vec`; add a debug-profile CI job.

### H3. Fork-added `*Raw` importers trust attacker bytes for CRT constants

`rns/mod.rs:183-210` (`RnsContextRaw::into_context`), `rns/scaler.rs:445-478`, `rq/scaler.rs:164-178`. `into_context` re-validates the moduli but trusts the supplied `garner`/`q_star`/`product` verbatim; a wrong `garner` vector makes every `RnsContext::lift` (used during decryption) return attacker-chosen values with no error. `ScalingFactorRaw` panics on a zero denominator. `PolyRaw` (`rq/mod.rs:141-158`) is dead scaffolding with no validation implied.

**Fix:** recompute the derived constants from `moduli_u64` via `RnsContext::new` / `RnsScaler::new` and discard or verify the supplied ones; make the conversions fallible.

---

## Medium

### M1. `Context` fields made `pub` (+ `Default`) — invariant erosion vs upstream

`fhe-math/src/rq/context.rs:11-28`. The fork changed every field from `pub(crate)` to `pub`; external code can assemble inconsistent contexts by struct literal, bypassing `Context::new` validation entirely. Revert to `pub(crate)`/getters.

### M2. Parameter builder validation gaps

`bfv/parameters.rs`:
- `set_variance` docs claim it errors on out-of-range values but performs no check; `build()` never validates `variance` — failure surfaces only at first encryption (`Poly::small` requires 1..=16), and `PublicKey::new` `unwrap`s that encryption → panic (`public_key.rs:33`).
- `error1_variance` is unbounded: pathological values allocate arbitrary-size BigInts per coefficient and values large vs q silently destroy plaintexts; `0` errors only at encrypt time.
- `try_deserialize` accepts unbounded `degree` (only power-of-two ≥ 8 checked) → multi-GB allocations from attacker parameter blobs (OOM DoS). Cap it (e.g. 2^20).

### M3. Large-plaintext-modulus decode centering off-by-one

`bfv/plaintext.rs:477-489`. The `Large` path centers with `x >= floor(p/2)` while the `Small` path (`Modulus::center`) uses `x > (p−1)/2`; for odd p the boundary value `(p−1)/2` decodes to the negative congruent value instead of the positive one — encode/decode round-trip breaks at the boundary and Small/Large decode disagree. Also, `to_i64().unwrap()` there panics if the centered value exceeds i64 (reachable with plaintext moduli > 2^64). Use the `(p+1)/2` threshold and a fallible conversion.

### M4. `conditional_error` sampling boundary and under-noising direction

`fhe-math/src/rq/mod.rs:368, 815-820`. Variance exactly 16 routes to the uniform sampler with bound `⌊√48⌋ = 6` (achieved variance 14) — less noise than variance 15 CBD; non-monotonic and below target. `variance_to_uniform_bound` floor-sqrts, so achieved variance is always ≤ requested — the unsafe direction for smudging noise. Use `<= 16` for the CBD branch and round the uniform bound up (solve `B(B+1)/3 ≥ σ²`). Related: `b_enc` formula/sampler mismatch already noted in the trbfv review (finding 5 there).

### M5. Deserialization hardcodes level 0 in mbfv and never binds shares to CRP/ct

`mbfv/crp.rs:67-71`, `public_key_gen.rs:93-104`, `secret_key_switch.rs:92-104`. Combined with H1, this is the practical injection vector for corrupt aggregates. Validate level/context at the deserialization boundary.

### M6. Latent UB in `NttOperatorRaw::into_operator`

`fhe-math/src/ntt/native.rs:396-410`. Reconstructs an operator from serde fields validating only the modulus; a `size > omegas.len()` operator makes `forward_vt_lazy`'s `get_unchecked` read out of bounds. Currently unreachable (not re-exported), but it is `pub` + `Deserialize` — one re-export away from memory unsafety. Validate or rebuild the tables.

## Low

- `PublicKeyShare::new_extended` (`mbfv/public_key_gen.rs:67-89`) returns the secret polynomial and error in the clear, un-zeroized, as a `pub` production API — gate behind `#[cfg(test)]` or a feature.
- Attacker-controlled `allow_variable_time` proto flag propagates through deserialized polys (`rq/convert.rs:62`); currently defused before secret-dependent ops (`secret_key.rs:299`, `public_key.rs:237`) but fragile — drop the flag on deserialize.
- `sample_vec_cbd_f32` silently truncates fractional variances other than 0.5 (`fhe-util/src/lib.rs:155-177`).
- `generate_prime` panics on `modulo == 0` (`zq/primes.rs:42`); `reduce_opt`/`reduce_opt_vt` lack the `supports_opt` debug_assert (`zq/mod.rs:671,681`).
- Panic paths on public API edge inputs: `dot_product_scalar` on an empty first ciphertext (`ops/dot_product.rs:67`), `Ciphertext::zero() += &pt` (`ops/mod.rs:92,187`), `&ct * &zero_ct` silently yields a malformed 1-component ciphertext (`ops/mod.rs:300-340`), `lbfv` `new_with_seed` unwraps (`lbfv/keys/public_key.rs:46,56`).
- `parse_proto` doesn't check proto degree against the context degree — short polys are accepted zero-padded (`rq/convert.rs:64-75`).
- `set_coefficients`/`from_coeffs_matrix` are unvalidated public setters (`rq/mod.rs:433-461`).
- `tests/ntt_shoup_ops.rs` is vacuous (compares an expression against itself); mbfv CRP freshness requirements undocumented; `LBFVRelinearizationKey::from_bytes` swallows the decode error.

## Verified correct (highlights)

- **zq**: Barrett `lazy_reduce`/`lazy_reduce_u128` bounds (incl. the pathological-modulus u128-overflow case, which self-corrects mod 2^64), `lazy_mul_shoup` < 2p for arbitrary u64 input, branchless const-time `reduce1`/`center`, Fermat inversion, NFLlib `supports_opt` condition, BPSW primality (deterministic below 2^64).
- **NTT**: forward < 4p / backward < 2p lazy invariants, twiddle bit-reversal indexing, `get_disjoint_unchecked` safety, tfhe-ntt 0.7.1 backend equivalence (bit-reversed fully-reduced outputs, 4p input tolerance).
- **RNS/rq**: the entire t/Q scaler fixed-point path, Garner/CRT lift, level-switch chain, and ops lazy-accumulation bounds are byte-identical to upstream; the PowerBasis/Ntt/NttShoup state machine is type-level, so wrong-representation ops are compile errors.
- **BFV**: seed handling and deterministic c1 reconstruction, decryption scaling path, SIMD encoding gating, secret-key zeroization (`SecretKey`, `Plaintext`, encryption intermediates), key deserializers cross-check levels and decomposition sizes.
- **mbfv/lbfv math**: pk share `p0 = −a·s + e`, relin R1/R2 protocol algebra, CRP-length checks, `u` reuse across relin rounds (required by the protocol), lbfv per-ciphertext seed derivation and deserializer validation.
- **util**: CBD sampling unbiased, transcoding round-trips at boundaries, modular inverse KATs, rand-0.9→0.8 adapter, all secret sampling generic over caller-supplied `CryptoRng`; `ChaCha8Rng` only expands public seeds.
- Full workspace tests pass in release; clippy clean.

## Recommended order of work

1. B2 + M2 (ciphertext shape/level validation at deserialize, parameter builder checks, degree cap) — small, self-contained, removes the aggregation DoS.
2. B1 (mbfv smudging) if mbfv ships; otherwise gate/document it.
3. H1 + H3 + M5 (aggregation and `*Raw` importer validation) — the untrusted-boundary hardening pass.
4. H2 + M1 + M6 (coefficient reduction on deserialize, `Context` encapsulation, `NttOperatorRaw` validation, debug-profile CI job).
5. M3 + M4 (decode centering, sampler boundary) plus the trbfv fixes from `trbfv-soundness-review.md`.
