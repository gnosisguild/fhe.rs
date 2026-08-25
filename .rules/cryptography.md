# Cryptographic safety

## Scope

Use cited ePrint papers as construction references, not blanket security proofs; ePrint DoS protection blocks automated downloads, so links are human-readable provenance. Paper map: <https://eprint.iacr.org/2018/117> (HPS RNS BFV scaling, basis extension, and RNS decomposition), <https://eprint.iacr.org/2021/204> (modified and leveled BFV multiplication, lazy scaling, and hybrid key-switching analysis), <https://eprint.iacr.org/2024/1285> (l-BFV's linear relinearization key and the trBFV honest-majority protocol, including pre-shared smudging noise), <https://eprint.iacr.org/2020/304> (MBFV's semi-honest, dishonest-majority, N-out-of-N protocols), <https://eprint.iacr.org/2017/1142> (SealPIR's original substitution-based oblivious expansion), and <https://eprint.iacr.org/2019/1483> (MulPIR and the optimized query/expansion structure also used by the SealPIR example). Match implemented variants before importing equations; do not apply trBFV claims to MBFV or MBFV relinearization to l-BFV.

Security-sensitive areas are key generation/handling, noise sampling, parameters, serialization, decryption, and Shamir threshold logic, including `crates/shamir-rns/**`.

The independent `shamir-rns` primitive accepts only canonical residues, uses
public points `1..=n` with the secret at zero, and requires an exact
`shares_needed` reconstruction count. Only its Barrett field kernel and
fixed-schedule Fermat inversion have a bounded constant-time
design goal;
rejection sampling, rayon scheduling, allocation, transport, and callers are
outside that claim. The crate is unaudited and supplies no commitments,
verifiability, authentication, robust DKG, or complete threshold protocol.

ZK proof generation and verification, commitments, proof aggregation, and on-chain verifiers (e.g. Interfold's Noir circuits) are external to this library; the library provides the witness values those circuits consume (see `.rules/witness.md`).

## Invariants

**Key aggregation validation**

1.1. Public-key, relinearization-key, and key-switching-key aggregation validates participant/session/parameter metadata and structural shape before polynomial access.
1.2. Key lookups use `first()`, `get()`, or `ok_or_else`, never assumptions about external or serialized keys.
1.3. Cross-contribution `a` and `d1` equality uses concrete values, not only seeds.

**BFV and HPS/RNS**

2.1. Plaintext scaling, ciphertext modulus, and representative conventions stay consistent across encryption, multiplication, switching, and decryption; `floor(q/t)`, nearest, and exact rational scaling are not interchangeable.
2.2. RNS switching decomposes in the ciphertext basis and recomposes in the matching key context with matching limbs, levels, and order.
2.3. Basis operations are classified as exact, exact rounded, or deliberately approximate; the current scaler is exact and HPS correction is forbidden unless an explicit approximate path exists.
2.4. The 2021/204 second strategy preserves operand `Q`→`P`, `QP` basis, final `t/P`→`Q`, initial rounding, and leveled down/up errors.
2.5. No lazy/deferred scaling or relinearization path currently exists. If one is introduced, it is valid only while accumulated terms share compatible parameters (enlarged-basis unreduced sum for HPS; staged modulus-switch bounds and cancellation of `QP`-divisible terms for modified), performs the deferred operation exactly once, and retains its noise contribution.
2.6. BFV encryption error sampling is asymmetric: `e1` comes from `Poly::conditional_error(error1_variance)` (CBD or uniform branch) while `e2` uses `Poly::small(params.variance)` (CBD); the l-BFV `try_encrypt_extended` witness path samples `u`, `e1`, `e2` all via `Poly::small`. Any bound depending on `B_enc` must account for the branch actually used.
2.7. `Poly::small` requires variance in `1..=16`; an `error1_variance` above 16 selects the uniform branch of `conditional_error`.

**l-BFV, trlBFV, and trBFV**

3.1. `crates/fhe/src/lbfv/**` never imports `crate::trlbfv`; threshold bindings, shares, aggregation, and validation belong to `trlbfv`.
3.2. l-BFV public RLK is linear in the secret key with `(d0,d1,d2)`, signs/directions `r -> s` and `s -> r`, and negated `r` for paper `-a`.
3.3. `CommonRandomPoly` and `CommonRandomPolyVec` in `crates/fhe/src/bfv/crp.rs` are concrete authoritative CRS/URS values; seeds are reconstruction metadata, `a` and `d1` vectors are independently agreed, and the same `a` serves PK and RLK. Seeded vectors derive one ChaCha8 sub-seed per RNS modulus, and `from_polys` validates a supplied seed against the concrete polynomials.
3.4. trlBFV and trBFV use the shared `ParticipantSet`/`ContributionBinding` vocabulary. Key and noise aggregation requires exactly one identified contribution for every member of the explicit accepted set `S`; equal-cardinality different sets, duplicate/missing contributions, and epoch mismatches are rejected before polynomial access. The same `S` and key epoch must be used across PK/RLK/SK/noise families.
3.5. trlBFV rejects missing/duplicate/wrong-session participants, checks concrete `a`/`d1`, and verifies `Σd0_i`, `Σd2_i`, unchanged `d1`/`a`; operational LBFV keys are unbound.
3.6. `ContributionBinding` provides consistency, not authentication; no signatures, broadcast, FLSS, GURS, or complete robust DKG is implemented.
3.7. The trBFV paper assumes `n = 2t + 1`, static corruption at most `t`, and semi-malicious parties; this module implements sharing, smudging, and decryption components only.
3.8. Paper configurations use `threshold = t = (n - 1) / 2`, odd `n`, and `t + 1` shares; accepted even `n` is an unproven extension and cannot support theorem claims.
3.9. l-BFV relinearization retains the circular-security caveat inherited from the cited multi-key construction.

**Smudging and threshold decryption**

4.1. Independent opening-share smudging is distinguished from joint pre-shared noise.
4.2. Implemented trBFV pre-shared joint smudging is one-time material and is not reused.
4.3. With `B_C`, `B_sm`, and `Delta = floor(Q/t_plain)`, hiding requires `B_C / B_sm` negligible and correctness the strict `2 * (B_C + n * B_sm) < Delta`; the paper's Appendix C.5 form `B_C + n * B_sm < Delta/2` (integer `Delta`) is equivalent, but `Q/(2*t_plain)` with real division is not a substitute when `Q` is not divisible by `t_plain`. `B_sm = 2^(lambda + 1) * N * B_C` is this implementation's choice satisfying negligibility — the paper does not prescribe a formula. `SmudgingCoefficients` is non-`Clone`, conversion into shareable material consumes it, and `OneTimeNoiseShare` is non-`Clone` and consumed by decryption.
4.4. `B_enc` must be derived from the actual `Poly::conditional_error` branch: CBD iff `v <= 16` with support bound `2 * v`, otherwise uniform with `variance_to_uniform_bound` (the smallest `B` with `B(B+1)/3 >= v`).
4.5. Distributed RLK error accounts for `|S| * B_e` (and aggregated noise grows ~`|S|·σ²`) or an explicit aggregate bound, and `accepted_participant_count` is included in smudging recursion.
4.6. Smudging coefficients are uniform in `[-B_sm, B_sm]`; `B_sm` and `B_e` are coefficient bounds, not variances.
4.7. Decryption-share APIs accept an identified aggregated key share and a consumed `OneTimeNoiseShare`; they verify key/noise epoch and accepted-set equality plus the caller-supplied use-session ID. Returned `DecryptionShare` values keep party IDs and metadata attached. Reconstruction checks decryptor IDs for range, uniqueness, and threshold cardinality, but does not require them to belong to the key/noise accepted set. Tags provide consistency, not authenticated identity or proof of correct decryption.
4.8. `ShareManager::new` enforces the trBFV threshold invariants (`n >= 3`, `T = (n - 1) / 2`) via `validate_threshold_config`, rejecting degree-0 sharings and configurations that break privacy or honest-party reconstruction, and requires `n < min modulus` so the Shamir evaluation points `1..=n` are distinct units modulo every modulus.
4.9. Threshold decryption follows the level-zero contract: `decryption_share` rejects 3-component (unrelinearized) ciphertexts, clears variable-time flags on ciphertext `c0` and `c1` before multiplying `c1` by secret material and adding the result, and `SecretPoly` normalizes flags on construction so every operand in the secret-bearing chain remains constant-time; `decrypt_from_shares` requires a u64 plaintext modulus.
4.10. Every secure example/benchmark preset proves smudging feasibility for its declared full configuration (moduli, `n`, `lambda`, `m`, `mult_depth`, and the accepted participant set) through the bound calculator — a preset-level feasibility test pins the exact constants the example runs with. An infeasible preset is a parameter/correctness regression to retune, not a runtime panic to unwrap (issue #113).

**MBFV**

5.1. MBFV is semi-honest N-out-of-N from <https://eprint.iacr.org/2020/304>, not robust `(t + 1)`-out-of-`n` trBFV.
5.2. Additive ideal/collective keys include each intended contribution exactly once and share `CommonRandomPoly`.
5.3. Two-round RLK uses `CommonRandomPolyVec` (one CRP per RNS modulus) and additive aggregation in which valid share order is irrelevant. Round-2 aggregation verifies that every share references one structurally identical validated round-1 aggregate and that its own validated participant set/session equals the aggregate's retained set before any vector inspection; all relin CRP and `h` vectors are anchored to the parameters' level-zero context with exactly one entry per level-zero modulus (empty or foreign-context vectors are typed errors), and all additions use checked equal lengths, never truncating zips.
5.4. Key-switch/decryption noise is exposed unless fresh smudging dominates current ciphertext noise; the paper prescribes `σ_smg² = 2^λ · σ_ct²` from the current ciphertext variance, so ordinary fresh-encryption error is incomplete paper-level accounting.
5.5. Every supported MBFV share (`PublicKeyShare`, `SecretKeySwitchShare`, `DecryptionShare`, `PublicKeySwitchShare`, `RelinKeyShare`) carries a required `ContributionBinding`; every aggregation entry point validates all bindings immediately after collecting the share list and before any parameter, context, CRP, ciphertext-component, or polynomial access. Exact one-per-member `ParticipantSet` coverage rejects duplicates, missing IDs, unknown IDs, cross-session/set contributions, and unbound shares — an unbound share is never silently excluded from coverage while its polynomial is summed. Bindings provide consistency, not authentication; contributors are not proven to have formed shares correctly.
5.6. MBFV aggregation compares concrete public inputs structurally before arithmetic: parameters by value equality, level-zero CRPs/CRP vectors by concrete polynomial values (seed metadata excluded), full input ciphertexts by parameters + declared level + component count + contexts + every component polynomial, and public-key-switch target keys by their exactly-two leveled components. Pointer identity, ad-hoc hashes, and seed-only comparisons are forbidden.
5.7. Collective MBFV public-key and RLK generation are level-zero protocols by design: a nonzero-level CRP is rejected at construction and deserialization rather than combined. Secret-key-switch serialization carries the input ciphertext's level in a versioned envelope, and deserialization derives the polynomial context from the caller-supplied ciphertext (never unconditionally level zero), rejecting level mismatches (#96). Both key-switch paths (wire and non-wire) resolve their working context from the declared ciphertext level and validate every component against it; a declared level inconsistent with component contexts is rejected. Public-key switching requires exactly two input-ciphertext components and exactly two target public-key components; zero-, one-, or three-component inputs are typed errors, never panics or silently dropped components, and a target public key already deeper than the input ciphertext is rejected (targets can only be leveled down toward the ciphertext; an equality loop would never converge). Round-2 relin generation binds to the generator's concrete CRP vector, parameters, and dimensions, not merely its participant-set label.

**PIR examples**

6.1. SealPIR preserves substitution, monomial shifts, output order, and normalization.
6.2. MulPIR preserves dimensions, depth, relinearization, final switch, and noise budget.
6.3. PIR examples do not claim database privacy without a separate construction.

**Review priorities and claims**

7.1. `crates/fhe/src/trbfv/config.rs` accepts even party counts, although the cited robustness theorem requires `n = 2t + 1`.
7.2. `crates/fhe/src/trbfv/smudging.rs` computes the strict `2 * (B_C + n * B_sm) < Delta` bound with `Delta = floor(Q/t_plain)`; the old `Q/(2*t_plain)` approximation is replaced and the integer `Delta` branch must remain.
7.3. trBFV enforces local one-time ownership: noise contributions and `OneTimeNoiseShare` are non-`Clone` and consumed through aggregation/decryption. Replay of copied or serialized transport material remains an orchestration concern.
7.4. MBFV key-switch and decryption shares sample ordinary BFV error despite the paper requiring noise flooding based on current ciphertext noise.
7.5. trlBFV `ParticipantSet`/aggregation does not bound `|S|` against the BFV noise budget; aggregated RLK noise grows ~`|S|·σ²`, so callers must validate participant count against parameters.
7.6. This library is unaudited; make no unsupported security or constant-time claims, and state threat model, corruption, setup, and robustness for protocol claims.
7.7. Distinguish verifiable correctness from security findings and cite ePrint section when paper-dependent.
7.8. trlBFV `compute_b_enc` in `crates/fhe/src/trbfv/smudging.rs` deviates from `Poly::conditional_error`: it uses the CBD branch only for `v < 16` (sampler: `v <= 16`) and `floor(sqrt(3v))` on the uniform branch instead of `variance_to_uniform_bound` (e.g. `v = 16` reports 6 while CBD(32) has support ±32; `v = 20` reports 7 while the sampler uses 8). Align it with the sampler before relying on `B_enc` for smudging bounds (tracked in issue #167).

**Serialization and timing policy**

8.1. Mathematical polynomial bytes do not select local timing policy: `Rq.allow_variable_time` on the wire is non-authoritative input metadata and is ignored during deserialization; only the trusted caller's `variable_time` argument dispatches variable-time arithmetic (caller-wins, issue #99). Deserializers that locally regenerate components from a seed may set their own policy, but never from serialized bytes.

## Evidence / tests

Crypto changes add arithmetic/protocol tests. Threshold tests cover fewer than `threshold + 1`, exactly `threshold + 1`, and `(n-1)/2`; trlBFV tests reject inconsistent participant sets. Noise tests pin both sides of the smudging interval (hiding lower bound, strict `Delta` correctness upper bound) — a plaintext round-trip alone does not establish adequate smudging. One-time smudging-noise ownership is covered by runtime and `trybuild` tests; MBFV aggregation matrices cover reordered shares, parameter/CRP/ciphertext/target-key/context/level mismatches, cross-session shares, duplicate/unknown/missing participants, truncated h vectors, missing/mismatched round-1 references, single-member exact coverage, and protobuf-gated level-aware serialization round trips at level zero and nonzero levels. Do not present ordinary BFV error sampling as secure key-switch smudging.

## Sync

- Touch → update: `cryptography.md` — `crates/fhe/src/{bfv,trbfv,trlbfv,lbfv,mbfv}/**`, `crates/fhe/examples/{mulpir,sealpir}.rs`, `crates/fhe-math/src/rq/**`, `crates/shamir-rns/**`.
