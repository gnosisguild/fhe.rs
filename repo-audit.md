# fhe.rs — Whole-Repository Production Audit

**Date:** 2026-07-16
**Scope:** all four crates — `fhe-math` (`zq`, `ntt`, `rns`, `rq`), `fhe` (`bfv`, `mbfv`, `lbfv`, `proto`), `fhe-traits`, `fhe-util`. The `crates/fhe/src/trbfv/` module is audited separately in `trbfv-audit.md` and only its interactions are considered here.
**Reference papers (pulled and read):** Fan & Vercauteren, *Somewhat Practical FHE* (eprint 2012/144); Bajard–Eynard–Hasan–Zucca, *A Full RNS Variant of FV* (eprint 2016/510). Both fetched via Wayback snapshots (eprint's PDFs are Cloudflare-gated) and verified complete.
**Method:** six independent deep-read passes run in parallel — (1) `zq`+`ntt` modular arithmetic, (2) `rns`+`rq` scaler/convert, (3) `bfv` core keys/params/enc/dec, (4) `bfv` ciphertext ops + rgsw, (5) `mbfv`+`lbfv` multiparty, (6) cross-cutting security (unsafe/panic/serde/zeroize/constant-time). The arithmetic pass validated Barrett/Shoup/NTT bounds against millions of adversarial vectors; the RNS pass re-derived the `t/Q` scaler and CRT lift from the papers. Findings below were then deduped and the release-gating ones re-verified against source by hand. Full `fhe-math` (78) and workspace test suites pass in release; `clippy` clean. Each finding is tagged **NEW** or **CONFIRMED** relative to the existing `repo-soundness-review.md`.

---

## Verdict

**The core cryptography and arithmetic are sound.** The modular-reduction layer (Barrett `lazy_reduce_u128`, Shoup multiplication, branchless `reduce1`/`center`), the NTT butterfly lazy-reduction invariants, the RNS Garner/CRT lift, the `t/Q` decryption scaler, and the BFV encrypt/decrypt/`Δ·m` formulas were all traced to the papers and, where feasible, checked empirically — no soundness or logic bug was found in the math. The correctness-critical RNS/scaler code remains byte-identical to upstream `tlepoint/fhe.rs`, and the polynomial representation state machine is type-enforced so wrong-representation operations are compile errors.

**The production risks are at the protocol and untrusted-input boundaries, not in the math.** Two must block a production release if the corresponding path ships:

- **B1 — mbfv decryption / key-switch shares carry no smudging noise** → within the stated passive model, honest parties' secret-key shares are recoverable. The code self-admits this (`// TODO this should be exponential in ciphertext noise!`). Blocks **only if mbfv is in the production path**; trBFV has its own smudging and is unaffected.
- **B2 — homomorphic `+`/`+=`/`-` panic on attacker-shaped-but-deserializable ciphertexts** → a denial-of-service on the exact "aggregate many untrusted ciphertexts" hot path.

Beyond those, a consistent theme is **`debug_assert`-only validation combined with deserializers that accept non-canonical input**: in release, several paths silently compute on out-of-range data instead of rejecting it. This is amplified by a **CI configuration that cannot build the current code** (so the green badge is stale) and that runs **release-only** (so no `debug_assert` ever executes in CI). None of these are math errors, but they are the right things to harden before shipping.

This audit **confirms the substance of the prior `repo-soundness-review.md`** and adds several new/sharper findings (the CI build breakage, the `Arc::ptr_eq` parameter-check inconsistency, the small-modulus decryption assumption, the lbfv `l`-field trust bug, and the constant-time-relies-on-optimizer note).

---

## Blockers

### B1 — mbfv decryption/key-switch shares use tiny CBD noise instead of smudging (key-share recovery) — CONFIRMED · Critical *(if mbfv ships)*

`mbfv/secret_key_switch.rs:78-79`, `mbfv/public_key_switch.rs:59-61`; `DecryptionShare` inherits it via `SecretKeySwitchShare` (`secret_key_switch.rs:151-160`). The flooding term in `h_i = (s_in − s_out)·c1 + e_i` is sampled `Poly::<Ntt>::small(ctx, par.variance, …)`, which hard-caps the variance to `1..=16` (‖e_i‖ ≲ 32). The security proof (Mouchet et al.) requires a *smudging* term `B_sm ≈ 2^λ·B_ct`, exponentially larger than the ciphertext noise. The library already has the right primitive (`conditional_error`/`error1_variance`, used by trBFV) — mbfv just doesn't call it, and says so:

```rust
// TODO this should be exponential in ciphertext noise!
let e = Zeroizing::new(Poly::<Ntt>::small(ct[0].ctx(), par.variance, rng)?);
```

Concrete leak (decryption, `s_out = 0`): each party broadcasts `h_i = s_i·c1 + e_i` with `c1` public and `e_i` negligible, so `(c1, h_i)` is a near-noiseless RLWE sample and `s_i` is recoverable by lattice reduction from one or two rounds with independent `c1`. A single semi-honest aggregator or eavesdropper thus recovers every honest party's key share. For PublicKeySwitch (C2), the party holding the output key `s_out` computes `h0_i − s_out·h1_i = s_i·c1 + small`, recovering `s_i`.

**Fix:** sample the share noise from the smudging distribution (`B_sm ≈ 2^λ·B_ct`), exactly as `trbfv/smudging.rs` does. If mbfv is not in the production path, gate or document it as insecure-as-is.

### B2 — Homomorphic add/sub panic on malformed-but-deserializable ciphertexts (aggregation DoS) — CONFIRMED · High

`bfv/ops/mod.rs:28-29, 61-62, 123-124, 156-157` use hard `assert_eq!(self.level, rhs.level)` and `assert_eq!(self.len(), rhs.len())` (fire in release). `Ciphertext::try_convert_from` (`bfv/ciphertext.rs:197-242`) accepts **any component count ≥ 2** (proto `repeated bytes c`) and **any level ≤ max_level**, with no expected-shape check. A participant submits bytes decoding to a 3-component or level-1 ciphertext; the aggregator's `acc += &ct` panics, and one malformed submission takes down the whole fold — the primary consumer's exact hot path.

**Fix:** return a fallible error instead of asserting (or require exactly 2 components / a pinned level at the deserialization boundary for transport ciphertexts). Note `mbfv/secret_key_switch.rs:52` already does the right thing (`ct.len() != 2` → `Err`); the bfv operators should match.

---

## High

### H1 — Add/Sub/Plaintext ops gate parameters with `Arc::ptr_eq`, inconsistent with the fallible mul/dot_product APIs — NEW · Medium/High

`bfv/ops/mod.rs:19, 56, 91, 114, 151, 186, 231` assert **pointer** equality `Arc::ptr_eq(&self.par, &rhs.par)`, while `Multiplicator::multiply` (`bfv/ops/mul.rs:173`) and `dot_product_scalar` (`bfv/ops/dot_product.rs:71`) use **value** inequality and return `Err`. A consumer that rebuilds `BfvParameters` per request (e.g. via `try_deserialize`, which mints a fresh `Arc`) and then folds honest, identically-parametrized ciphertexts **panics on the first `acc += &ct`** because the two `Arc`s differ in allocation. This is a latent DoS on completely valid input and is inconsistent across the op surface.

**Fix:** use value equality (`self.par == rhs.par`) and return an error, matching `Multiplicator`/`dot_product`.

### H2 — Untrusted deserialized coefficients are not reduced mod q (PowerBasis/Ntt/NttShoup full-length paths) — CONFIRMED · Medium/High

`rq/convert.rs:139-148` (PowerBasis), `:181` (Ntt), `:200-209` (NttShoup) store coefficients from `deserialize_vec` (`zq/mod.rs:818`, which yields up to `⌈log2 q⌉`-bit values, i.e. `[q, 2^⌈log2 q⌉) ⊂ [q, 2q)`) **without `reduce_vec`**. The short-PowerBasis branch (`:163-167`) *does* reduce — an inconsistent gap the authors clearly knew about. Every `zq` op documents `a < p` as a `debug_assert` only (stripped in release), so downstream arithmetic wraps and produces incorrect results (ciphertext malleability). The Ntt path self-heals (butterflies tolerate `< 4q`), but PowerBasis does not. The realistic reach is the `TryConvertFrom<Array2<u64>>` / `<&[u64]>` constructors (`convert.rs:219-237, 278+`), which also skip reduction and are used to build polynomials from raw matrices (e.g. `trbfv/shares.rs:260, 426`).

**Fix:** `reduce_vec` (or reject out-of-range) in every deserialization branch.

---

## Medium

### M1 — `variance` is never validated; `PublicKey::new` panics (incl. from untrusted params) — CONFIRMED

`bfv/parameters.rs:444-452` (`set_variance` performs no check despite a docstring claiming it errors), `build()` never validates `variance`, and `try_deserialize` (`:792-798`) reads it from untrusted bytes. `Poly::small` requires `variance ∈ [1,16]` and returns `Err`; `PublicKey::new` (`public_key.rs:33`) `unwrap`s the encryption → **guaranteed panic** for `variance = 0` or `> 16`, reachable both from the builder and from a deserialized parameter blob. (`SecretKey::random` uses the fixed `SK_VARIANCE = 0.5`, so keygen itself is safe; the panic is in public-key generation.)

### M2 — Unbounded `degree` → OOM from untrusted parameters — CONFIRMED

`bfv/parameters.rs:540` checks only power-of-two ≥ 8; `try_deserialize` (`:772-800`) takes `degree` (proto `u32`) with no upper bound and uses caller-supplied moduli (bypassing the prime-availability guard). A serialized `BfvParameters` with `degree = 2^24` drives multi-GB NTT/bitrev/`matrix_reps_index_map` allocations → OOM/abort. Also `m = self.degree << 1` (`:724`) silently overflows for `degree ≥ 2^63`. Cap the degree (e.g. ≤ 2^16 or a configured max) and bound the moduli count.

### M3 — `Vec<i64>::try_decode` panics and has an odd-`p` off-by-one for `Large` plaintext modulus — CONFIRMED

`bfv/plaintext.rs:479-488`. For a `Large` modulus (`p > u64::MAX`), any coefficient ≥ 2^63 hits `x.to_i64().unwrap()` → panic (the `Vec<u64>` path returns a clean error instead — inconsistent). Separately, the centering threshold here is `floor(p/2)` whereas the encoder and the `Small` decode use `(p+1)/2` (`Modulus::center`); for **odd** `p`, the boundary value `(p−1)/2` decodes to the negative congruent value — disagreeing with the `Small` path (mostly masked because that value is > 2^63 and panics first). Use the `(p+1)/2` threshold and a fallible conversion.

### M4 — `*Raw::into_*` reconstructors trust caller-supplied sizes/constants → OOB read / wrong results — CONFIRMED · Medium *(latent: no in-crate caller)*

The serde-`Deserialize`, `pub` reconstructors rebuild objects from independently-trusted fields:
- `ntt/native.rs:398-410` `NttOperatorRaw::into_operator` — trusts `size` and the twiddle-array lengths; `forward_vt` then does `omegas.get_unchecked(k)` for `k` up to `size−1` → **OOB read / UB** if `omegas.len() < size` (safe `forward` panics instead).
- `rns/scaler.rs:448-477`, `rq/scaler.rs:166-176` `into_scaler` — copy `gamma/omega/...` verbatim; the scale hot loop indexes them with `get_unchecked` guarded **only by `debug_assert`**; a crafted `theta_garner_shift = 0` also underflows `shift − 1` (`scaler.rs:338`).
- `rns/mod.rs:185-209` `RnsContextRaw::into_context` — trusts `garner`/`q_star`/`product` and doesn't even length-check them against `moduli`; a wrong `garner` corrupts every CRT `lift` (used in decryption). `ScalingFactorRaw` panics on a zero denominator (`rns/scaler.rs:42`).

**Reachability (important):** grep confirms **none of these `into_*` are called inside `fhe-math` or `fhe`** — `BfvParameters` (de)serialization is protobuf and *recomputes* all constants via the builder, and the declared `bincode` dep is unused in `fhe/src`. So this is a latent public-API footgun for a downstream consumer that serde-round-trips these `pub` types (e.g. to cache tables), not a remotely-triggerable bug today. `PolyRaw` (`rq/mod.rs:142-158`) is the same trap with no converter yet.

**Fix:** validate every length against `size`/`moduli.len()` (and recompute derived constants) in each `into_*`, or make the `*Raw` types `pub(crate)` and drop `Deserialize`. (Prior review rated the scaler variant High; the no-caller fact softens live severity, but they should still be fixed before the types are used.)

### M5 — mbfv aggregation trusts the first share; no CRP/ciphertext/param/count validation — CONFIRMED

`mbfv/public_key_gen.rs:146-165`, `secret_key_switch.rs:107-127`, `public_key_switch.rs:89-109`, `relin_key_gen.rs:200-225, 302-358`. Every `Aggregate::from_shares` takes `par`/`crp`/`ct`/`last_round` from the **first** share and never checks the rest agree, sums shares bound to a different CRP/ciphertext blindly, enforces no duplicate/party-count, and in relin `izip!` (`:213-214, 321-326`) **silently truncates** to the shortest `h0`/`h1` vector → a shorter, wrong relinearization key. Validate every share against the first and enforce the expected party set.

### M6 — mbfv share/CRP deserializers hardcode level 0 and don't bind to CRP/ciphertext — CONFIRMED

`mbfv/secret_key_switch.rs:92-104`, `public_key_gen.rs:93-105`, `crp.rs:67-71` always read at `context_at_level(0)`, so the deserialize path is broken for level > 0 ciphertexts (in-memory path works because `new` uses `ct[0].ctx()`), and shares carry no cryptographic binding to the CRP/ciphertext they claim.

### M7 — `LBFVPublicKey::from_bytes` trusts an attacker-controlled `l` decoupled from `c.len()` — NEW

`lbfv/keys/public_key.rs:323` (`l: proto.l as usize`) doesn't check `l == c.len()`. `extract_b_polynomials` (`:180-183`) computes `new_l = self.l − ciphertext_level` and indexes `self.c[i]` under `#[allow(indexing_slicing)]`: a forged `l > c.len()` → OOB panic (DoS), `l < c.len()` → silently short `b_vec` → wrong relin key. `LBFVRelinearizationKey::try_convert_from` (`:406-412`) has the same missing consistency check.

### M8 — `Context` exposes all fields `pub` + derives `Default`, allowing invariant-violating construction — CONFIRMED

`rq/context.rs:8-28`. External code can build (or `Context::default()`) a context whose `degree`/`q`/`rns`/`ops` are mutually inconsistent, bypassing `Context::new`'s validation; downstream code assumes the invariants (bit-reversal shift, `garner`/`ops` lengths) → panics or wrong results. Upstream used `pub(crate)`; revert to that + getters.

### M9 — The `allow_variable_time` flag is attacker-settable over the wire — CONFIRMED

`rq/convert.rs:62` OR-s the proto's `allow_variable_time` into the poly on deserialize, so a serialized ciphertext can force the victim off the constant-time default; it propagates through ops via `|=`. Current decryption is safe because `try_decrypt`/`measure_noise`/`PublicKey::from_bytes` defensively `disallow_variable_time_computations()`, but any other consumer operating on a deserialized ciphertext inherits variable-time. Drop/ignore the flag on deserialize. (Related: the trBFV `decryption_share` variable-time multiply in `trbfv-audit.md` F1.)

### M10 — Secret-bearing `Poly` has no `ZeroizeOnDrop`; `pub` `*_extended` APIs return secrets in the clear — CONFIRMED

`Poly` implements `Zeroize` but not `Drop`/`ZeroizeOnDrop` (`rq/mod.rs:160-167`). Meanwhile `PublicKey::new_extended` returns `(pk, a, s, e)` with the **secret key** `s` and error `e` as bare `Poly` clones pulled out of `Zeroizing` (`public_key.rs:72`); `try_encrypt_extended` returns the encryption randomness `(u, e1, e2)` (`:111-133`); `mbfv PublicKeyShare::new_extended` returns the secret share and error (`public_key_gen.rs:88`); `SecretKey::encrypt_poly_with_seed_extended` returns `e` (`secret_key.rs:184`). All are `pub fn` (documented "for testing" but not `#[cfg(test)]`-gated), and because `Poly` doesn't drop-zeroize, the leaked material is never wiped. Gate behind a test/feature cfg and/or return `Zeroizing<Poly>`.

### M11 — CI cannot build the current code, and runs release-only (stale/weak test signal) — NEW

`.github/workflows/rust.yml` pins toolchain **1.85.0** with no `rust-toolchain` override, but the code calls `as_chunks_mut` (stabilized **1.88**, `zq/mod.rs:262`, `rq/ops.rs:430`) and `get_disjoint_unchecked_mut` (stabilized **1.86**, `ntt/native.rs`), and `Cargo.toml` declares `rust-version = 1.91.1`. So the main CI job (fmt/clippy/test) **cannot compile the code as written** — the passing badge is stale, or CI is silently red. Additionally, tests run `--release` only, with no `debug-assertions` lane, so **every `debug_assert!` is compiled out of the only tested build** — including the `a < p` modulus preconditions, the `< 4p` butterfly bounds, and the `get_unchecked` bounds guards in `scaler.rs:385-407`. The non-canonical-coefficient (H2) and reconstructor (M4) issues would all pass CI unnoticed. **Fix:** correct the CI toolchain to match the real MSRV, verify CI is actually green, and add a debug-assertions test lane.

---

## Low / hardening

- **`zq` add/sub have zero reduction headroom** (`zq/mod.rs:103-106, 123-126`): `add(a,b)=reduce1(a+b,p)` is only correct for `a,b < p`; an input in `[p, 2q)` (reachable via the unreduced `TryConvertFrom` of H2) yields a wrong, still-unreduced value in release. Contrast `mul`/`reduce`, which are robust for any in-range operand. **NEW** (sharper reachability than H2).
- **Small-plaintext decryption assumes `t < moduli[0]`** (`secret_key.rs:316-329`): reads only the first RNS limb; never validated (builder allows a 10-bit first modulus with a 30-bit `t`), so a small first modulus silently decrypts wrong. Add a `t < min(moduli)` check. **NEW.**
- **`generate_prime` divides by `modulo` with no zero guard** (`zq/primes.rs:42`) → panic on `generate_prime(_, 0, _)`; only reachable by direct misuse. **CONFIRMED.**
- **Panic paths on public-API edge inputs (not the aggregation path):** `Ciphertext::zero() += &pt` (`ops/mod.rs:92,187`), `&ct * &zero_ct` yields a malformed 1-component ciphertext (`ops/mod.rs:300-340`), `dot_product_scalar` on an empty first ciphertext (`dot_product.rs:68`), RGSW/Galois/inner-sum `assert_eq!(len,2)` and `.unwrap()` (`rgsw_ciphertext.rs`, `galois_key.rs`, `evaluation_key.rs`), `lbfv new_with_seed` unwraps (`lbfv/keys/public_key.rs:46,56`), `PublicKeySwitchShare::new` lacks the `ct.len()==2` check that `SecretKeySwitchShare::new` has. **CONFIRMED.**
- **`sample_vec_cbd_f32` silently truncates fractional variances ≠ 0.5** via `variance as usize` (`fhe-util/src/lib.rs:176`); `sample_vec_normal` uses `as i64` truncation (biased, not a true discrete Gaussian). Neither is on a secret-key path today. **CONFIRMED.**
- **`unwrap_used` is not in the workspace deny-lints** (only `expect_used`/`panic`/`indexing_slicing`), so `unwrap()` — which panics — is allowed in production code, and several crypto-path unwraps rely on unstated invariants (`secret_key.rs:310`, `plaintext.rs:76`). **NEW.**
- **`const_time_cond_select` relies on the optimizer** (`zq/mod.rs:24-28`): the branchless mask has no `black_box`/`subtle`-style barrier, so the constant-time claim on `reduce1`/`center` (which touch secret data) is not language-guaranteed. **NEW (hardening).**
- **`unsafe impl Send for BfvParameters`/`Plaintext`** (`parameters.rs:127`, `plaintext.rs:176`) appear redundant (no raw pointer / `!Send` field found) but a hand-written `Send` will mask a future `!Send` field — remove if auto-derivable. Latent `multiply_inverse_power_of_x` / `lazy_reduce_opt_u128` / `supports_ntt` underflows on out-of-range inputs (no production caller). **CONFIRMED / info.**
- **`proto` scaffolding** (`proto/trbfv`, `PolyRaw`) with opaque unvalidated `bytes` fields — harden before serialization is wired up.

---

## Verified correct (coverage — what was checked and holds)

**Arithmetic (`zq`/`ntt`), empirically + analytically:** Barrett `lazy_reduce_u128` output `∈ [0,2p)` and congruent for all `a < 2^128`, `p < 2^62`, with the intermediate never overflowing u128 (worst case `p = 2^61+1` tops out ≈ 2^128 − 2^70; 2.5M adversarial cases, 0 failures); Shoup `lazy_mul_shoup` `< 2p` for arbitrary u64 `a` (12M cases, covering the `a` up to 4p that butterflies feed); `reduce1`/`center`/`reduce_i64` branchless and correct incl. `i64::MIN`; the constant-time public path never calls a `_vt` primitive; NTT butterflies keep coefficients `< 4p` (forward) / `< 2p` (backward) with `4p < 2^64`, and all `get_unchecked`/`get_disjoint_unchecked_mut` indices in bounds for every size; BPSW primality (`probably_prime(n,0)`) is exact for all `n < 2^64`; `generate_prime` matches the NFLlib 62-bit KATs and degrades safely on a failed root search.

**RNS/`rq`, re-derived from the papers:** the Garner/CRT `lift = (Σ garnerᵢ·rᵢ) mod Q ∈ [0,Q)` is the correct idempotent reconstruction; the `RnsScaler` `t/Q` rounding (centered representative + odd/even half-rounding, u256 bounds) is correct across contexts (property tests to 2^62 numerators pass); the representation state machine is type-enforced (`PhantomData<R>`), so wrong-representation ops are compile errors; serialization always stores power-basis coefficients (no double-NTT); `ScalingFactorRaw` recomputes `is_one` rather than trusting it; `Modulus::new` enforces `2 ≤ p < 2^62`, `RnsContext::new` enforces coprimality.

**BFV core, against FV (2012/144):** secret-key enc `b = −a·s + e + Δ·m`, public-key enc `c0 = u·pk0 + e1 + Δ·m, c1 = u·pk1 + e2`; the `Δ·m` encoding (`δ_i = −t⁻¹ mod q_i` × centered `m·(q mod t)`) computes round-to-nearest `round(q·m/t) mod q`, hand-verified on `t=5,q=17`, with Small/Large paths and centering thresholds agreeing; the decryption rounding `scale(t/q) → +t → mod q0 → mod t` recovers `m`; `SecretKey`/`Plaintext`/`PlaintextVec` zeroize on drop and the non-extended enc/dec/keygen paths wrap `u/e1/e2/m/s` in `Zeroizing`; `matrix_reps_index_map` is a genuine permutation; ciphertext/`SecretKey`/`PublicKey` deserialization validate level ≤ max_level, `coeffs.len() == degree`, and level 0 respectively.

**Homomorphic ops:** multiplication tensoring + `t/q` down-scaling (extend basis → `c[i+j] += a[i]b[j]` → scale) decrypts to `m1·m2`; relinearization key-switches `c2` under `s²→s` (matches HPS); `Multiplicator::multiply` and key-switching validate params/level/shape and return `Err` (not panic); `dot_product` u128 accumulation is overflow-guarded (`count·qi² < 2^128`).

**mbfv/lbfv (non-smudging parts):** pk share `p0 = −a·s + e` (small `e` correct here); the 2-round relin R1/R2 algebra and required `u` reuse across rounds match Mouchet Protocol 2, with CRP-length guards; lbfv per-ciphertext seed derivation gives distinct `a_i`; `Aggregate` returns `TooFewValues` on empty input.

**RNG:** all secret/error samplers are compile-time bounded to `CryptoRng`; only *public* seeds (`a`, CRP, NTT root) are expanded deterministically; the rand-0.9→0.8 adapter faithfully forwards entropy; no secret is drawn from a non-crypto or shared-deterministic RNG.

---

## Reachability & threat-model notes

- The `*Raw::into_*` reconstructors (M4) and `PolyRaw` are **not called anywhere in-tree** — the shipping (de)serialization is protobuf and recomputes constants. They bite only a downstream consumer that serde-round-trips those `pub` types. Fix before that happens; not a live remote bug today.
- B2, H1, M1–M3, M9, H2 are the **live untrusted-input surface** (deserialize a ciphertext/parameters/share and operate on it). These are the ones an adversary can reach through the normal API.
- B1 is a **confidentiality break within the passive model** and gates only if mbfv ships. trBFV (audited separately) is unaffected — it has its own smudging.

## Suggested order of work

1. **B2 + H1 + M1 + M2** — ciphertext shape/level validation and value-equality param checks at the operator boundary; parameter `variance`/`degree` validation and cap. Small, self-contained, removes the aggregation DoS and the guaranteed-panic paths.
2. **B1** — wire smudging into mbfv share generation if mbfv ships; otherwise gate/document.
3. **H2 + M4 + M5 + M6 + M7 + M9** — the untrusted-boundary hardening pass: reduce coefficients on deserialize, validate `*Raw` lengths (or seal the types), validate mbfv/lbfv shares against the first and bind to CRP/ciphertext, drop the wire variable-time flag.
4. **M8 + M10 + M11** — `Context` encapsulation, `ZeroizeOnDrop` on `Poly` + gate the `*_extended` APIs, fix the CI toolchain and add a debug-assertions lane.
5. **M3 + the Low/hardening items**, plus the trBFV fixes in `trbfv-audit.md`.

## Test & tooling status

`cargo test --release` (workspace) and the 78 `fhe-math` lib tests pass; `clippy` clean. **But** CI cannot build the current code on its pinned 1.85.0 toolchain (M11), and runs release-only, so `debug_assert` preconditions and the `get_unchecked` bounds guards are never exercised in CI — the most important tooling fix for a production release.
