# Cryptographic safety

## Paper-to-code map

Use the cited ePrint papers as construction references, not as blanket security proofs for the implementation. Note that ePrint enforces DoS protection that blocks automated downloads; agents should treat these as human-readable provenance links rather than fetchable resources:

- <https://eprint.iacr.org/2018/117> — HPS RNS BFV scaling, basis extension, and RNS decomposition used by BFV key switching and relinearization.
- <https://eprint.iacr.org/2021/204> — modified and leveled BFV multiplication, lazy scaling, and hybrid key-switching analysis.
- <https://eprint.iacr.org/2024/1285> — l-BFV's linear relinearization key and the trBFV honest-majority protocol, including pre-shared smudging noise.
- <https://eprint.iacr.org/2020/304> — MBFV's semi-honest, dishonest-majority, N-out-of-N protocols.
- <https://eprint.iacr.org/2017/1142> — SealPIR's original substitution-based oblivious expansion.
- <https://eprint.iacr.org/2019/1483> — MulPIR and the optimized query/expansion structure also used by the SealPIR example.

Match a change to the implemented variant before importing an equation or invariant. In particular, do not apply trBFV robustness claims to MBFV, or MBFV's two-round relinearization protocol to l-BFV.

## Security-sensitive areas

Treat changes to the following as security-sensitive. Review them with extra care and require focused tests:

- **Key generation and handling** — secret keys, public keys, evaluation keys, relinearization keys
- **Noise sampling** — error distributions, smudging noise, variance calculations
- **Parameters** — BFV/TRBFV/LBFV/MBFV parameter selection, modulus chain, polynomial degree
- **Serialization** — protobuf encode/decode of keys, ciphertexts, plaintexts
- **Decryption** — BFV decryption, threshold decryption, share aggregation and combination
- **Threshold logic** — Shamir secret sharing, share distribution, reconstruction, the `(n-1)/2` threshold invariant

## Scheme-specific invariants

### BFV and HPS/RNS

- Keep plaintext scaling, ciphertext modulus, and representative conventions consistent across encryption, multiplication, key switching, and decryption. A change between `floor(q/t)`, nearest rounding, and exact rational scaling changes the noise analysis.
- RNS key switching decomposes the input in the ciphertext basis and recomposes against key-switching material in the matching key context. The number and order of RNS limbs, ciphertext level, and key level are cryptographic inputs, not storage details.
- Classify each basis operation as exact conversion, exact rounded scaling, or deliberately approximate extension. The current `fhe-math` scaler is intended to be exact; do not allow an HPS-style correction term unless a call path explicitly implements approximate `FastBaseExtension`.
- For the second multiplication strategy from <https://eprint.iacr.org/2021/204>, preserve which operand is switched from `Q` to `P`, the `QP` tensor-product basis, and the final `t/P` scale back to `Q`. Account for the initial `Q -> P` rounding error; leveled multiplication adds down-switch and up-switch rounding errors.
- Lazy scaling or lazy relinearization is valid only while all accumulated terms share compatible parameters. For the original HPS strategy, the enlarged basis must preserve the assumed unreduced sum; for the modified strategy, preserve the staged modulus-switch bounds and cancellation of terms divisible by `QP`. Perform the deferred operation exactly once and retain its noise contribution.

### l-BFV, trlBFV, and trBFV

- l-BFV's public relinearization key is linear in the secret key and has the paper form `(d0, d1, d2)`, implemented as two related key-switching keys plus the public-key `b` vector. Preserve the signs and directions `r -> s` and `s -> r`; the implementation negates `r` to represent the paper's `-a` component.
- **CRP vectors.** The shared polynomials for `a` (CRS) and `d1` (URS) are supplied as [`CommonRandomPolyVec`](crate::bfv::CommonRandomPolyVec) values — vectors of `l` concrete random polynomials with optional seed metadata. The concrete polynomials are authoritative for equality checks; seeds are reconstruction metadata, not authentication. Two independent vectors (for `a` and `d1`) must be agreed upon by all parties before key generation, and the same `a` vector must be used for both the public key and the relinearization key.
- The public random values corresponding to `a` and `d1` must be common across contributions. Replacing them with independently sampled per-party values breaks additivity.
- Distributed encryption-key, relinearization-key, secret-key-share, and pre-shared-noise contributions must use the same accepted participant set `S`. Mixing participant sets produces incompatible keys or noise shares and invalidates the robustness argument.
- **trlBFV aggregation binding.** Participant-set validation and contribution binding enforcement live in `trlbfv`. `trlbfv` owns threshold shares, `ParticipantSet`, `ContributionBinding`, and aggregation into the operational `lbfv` keys. Every accepted participant ID must appear exactly once; contributions from different sessions or with duplicate IDs are rejected. The explicit `a` (CRS) and `d1` (URS) polynomials are compared by concrete polynomial equality across contributions. Component linearity (`Σ d0_i`, `Σ d2_i`, unchanged `d1`/`a`) is verified by dedicated tests.
- **Operational keys are unbound.** After aggregation, operational LBFV keys (`lbfv::LBFVPublicKey`, `lbfv::LBFVRelinearizationKey`) carry no threshold participant set metadata. Concrete `a` (CRS) and `d1` (URS) polynomial equality is the authoritative consistency mechanism; seed metadata alone is not.
- **Metadata is not authentication.** [`trlbfv::ContributionBinding`](crate::trlbfv::ContributionBinding) provides consistency binding (ensuring all contributions reference the same session and participant set), not cryptographic authentication. No signatures, broadcast protocol, FLSS, GURS, or full robust DKG orchestration is implemented. Callers must supply their own transport and authentication layers.
- The trBFV paper assumes `n = 2t + 1`, static corruption of at most `t` parties, and a semi-malicious model. The current module implements threshold sharing, smudging, and decryption components, not the paper's complete DKG/broadcast/FLSS/GURS orchestration. Do not claim the module itself realizes the end-to-end robustness theorem.
- For paper-conforming configurations, `threshold = t = (n - 1) / 2`, `n` is odd, and reconstruction requires `t + 1` shares. Even `n` currently accepted by `trbfv/config.rs` is outside the cited theorem and must be rejected or documented as an unproven implementation-specific extension before making robustness claims.
- The l-BFV relinearization argument relies on the circular-security assumption inherited from the cited multi-key construction. Preserve this caveat in security-facing documentation.

### Smudging and threshold decryption

- Distinguish the two threshold-decryption methods in <https://eprint.iacr.org/2024/1285>: independently smudging each opening share is not the same as opening the decryption result together with one pre-shared joint noise polynomial.
- The implemented trBFV path uses pre-shared joint smudging noise. Each such noise value is one-time material and must not be reused across decryptions.
- Let `B_C` bound evaluated-ciphertext decryption noise, `B_sm` bound each party's contribution, and `Delta = floor(Q/t_plain)`. The paper requires `B_C / B_sm` negligible for hiding and the strict integer bound `2 * (B_C + n * B_sm) < Delta` for correctness. `Q/(2*t_plain)` and `Delta/2` are looser and not conservative substitutes when `Q` is not divisible by `t_plain`; always derive the bound from the exact integer `Delta`.
- Samplers must be aligned with `B_enc`: for CBD samplers, use `2 * error1_variance`; for the large-variance uniform branch, use `floor(sqrt(3 * error1_variance))`. These bounds must match the actual configured error sampler, not a fixed constant.
- Distributed RLK error must account for `|S| * B_e` (the number of accepted participants times the base error bound) or an explicitly documented aggregate bound. The smudging calculator accepts an `accepted_participant_count` parameter and folds this into the recursion.
- Smudging coefficients are sampled uniformly from `[-B_sm, B_sm]`. Do not silently replace this with a Gaussian or confuse a coefficient bound with a variance (the `B_sm` and `B_e` symbols used here are coefficient bounds, not variances).
- A decryption share API must state whether it accepts a party's local noise contribution, a Shamir share of the joint noise, or the reconstructed joint noise. These are not interchangeable.

### MBFV

- MBFV implements the semi-honest N-out-of-N construction in <https://eprint.iacr.org/2020/304>; it is not the robust `(t + 1)`-out-of-`n` trBFV protocol.
- The ideal secret key and collective public key are additive sums of party contributions. Aggregation must include each intended contribution exactly once and use the same common random polynomial ([`CommonRandomPoly`](crate::bfv::CommonRandomPoly)).
- MBFV relinearization key generation is a two-round protocol that uses a [`CommonRandomPolyVec`](crate::bfv::CommonRandomPolyVec) (one CRP per RNS modulus). Every round-2 share must be bound to the same exact round-1 aggregate; reject missing, duplicated, or cross-session contributions. Valid share order is irrelevant because aggregation is additive.
- Collective key switching and decryption reveal ciphertext noise unless fresh smudging noise dominates the current ciphertext noise. The paper's protocol requires the smudging distribution to be selected from a bound or variance for that ciphertext, not merely the fresh-encryption error distribution. Treat any code path that lacks this accounting as incomplete, not as paper-level security.

### PIR examples

- SealPIR query expansion is linear over the plaintext space and relies on substitution, monomial shifts, and normalization. Preserve the substitution element, output ordering, and normalization factor when changing `EvaluationKey::expands` or `examples/sealpir.rs`.
- MulPIR replaces recursive ciphertext-as-plaintext folding with homomorphic multiplication. Keep the query dimensions, multiplicative depth, relinearization, and final modulus-switch/noise budget consistent with `examples/mulpir.rs`.
- These are examples of query privacy in the cited threat models, not symmetric PIR. Do not claim database privacy unless a separate construction provides it.

## Known implementation gaps

Treat these as review priorities, not as properties already enforced by the code:

- `trbfv/config.rs` accepts even party counts, although the cited robustness theorem requires `n = 2t + 1`.
- `trbfv/smudging.rs` now computes the correctness bound from the strict `2 * (B_C + n * B_sm) < Delta` with `Delta = floor(Q/t_plain)`. The old `Q/(2*t_plain)` approximation has been replaced; when touching the calculator, keep the integer `Delta` branch.
- The trBFV APIs do not enforce one-time consumption of pre-shared smudging noise; callers must currently prevent reuse.
- MBFV key-switch and decryption shares sample ordinary BFV error despite the paper requiring noise flooding based on current ciphertext noise.
- MBFV final relinearization aggregation does not currently verify that every round-2 share references the same round-1 aggregate or that each intended party contributed exactly once.
- trlBFV `ParticipantSet`/aggregation does not bound `|S|` against the BFV noise budget; aggregated RLK noise grows ~`|S|·σ²`, so callers must validate the participant count against their parameters before accepting a set for key generation.

## Claims

- Do not make security claims without evidence. This library has never been independently audited.
- Do not claim code is constant-time unless you can verify it. Shamir secret sharing uses arbitrary-precision arithmetic that is not constant-time — this is a known, documented caveat.
- When reviewing crypto changes, distinguish correctness findings (the math is wrong) from security findings (the construction leaks information). The former is verifiable from code; the latter is not, without formal analysis.
- State the threat model with every protocol-level claim: semi-honest versus semi-malicious, corruption threshold, setup/CRS assumptions, and whether robustness or guaranteed output delivery is actually implemented.

## Tests

- Add or extend tests for arithmetic invariants and protocol correctness when touching crypto code.
- Threshold tests must cover: fewer than `threshold + 1` shares fail to decrypt, exactly `threshold + 1` shares decrypt correctly, and the threshold equals `(n-1)/2`.
- trBFV tests must also reject inconsistent participant sets and verify that pre-shared noise is consumed at most once when the API tracks consumption.
- Noise tests must pin both sides of the smudging interval: the hiding lower bound and the decryption-correctness upper bound. A plaintext round-trip alone does not establish adequate smudging.
- MBFV tests must preserve round binding and aggregation cardinality, and must not present ordinary BFV error sampling as secure key-switch smudging.
