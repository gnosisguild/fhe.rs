# ZK witness generation

## Scope

This document specifies the witness material produced by the `_extended` API variants for use in ZK proofs (e.g. Noir circuits). It defines the mathematical relations the witness satisfies, the API surface, and the security requirements for handling witness values. A ZK proof of correct key generation or encryption requires the prover to commit to private values and prove that published public values satisfy specific linear equations over `R_q`; the `_extended` variants surface private values otherwise generated internally and immediately used or zeroized.

| Protocol | Public values | Witness values |
|---|---|---|
| Encryption | `(c0, c1, b, a, m)` | `u, e1, e2` |
| RLK generation | `(d0, d1, d2, a, b_vec)` | `r, errors_d0, errors_d2` |

## Invariants

1. Encryption source is `lbfv::LBFVPublicKey::try_encrypt_extended(pt, rng)` returning `Result<(Ciphertext, Poly<Ntt>, Poly<Ntt>, Poly<Ntt>)>` as `(ct,u,e1,e2)`.
2. Encryption satisfies `c0 = u·b + e1 + m`, `c1 = u·a + e2`, with `m = Δ·msg` and `Δ = floor(Q/t)`.
3. Encryption circuits prove both equations and `‖u‖∞`, `‖e1‖∞`, `‖e2‖∞ ≤ B_enc`; `sk` is not an encryption witness.
4. Encryption witnesses are `Poly<Ntt>`, only `c[0]` is used, and callers erase them.
5. Unbound RLK source is `trlbfv::RelinKeyShare::contribution_with_crp_extended(sk, crp_d1, crp_a, ct_level, key_level, rng)` → `Result<(RelinKeyShare, RlkWitness)>`.
6. Bound RLK source is `trlbfv::RelinKeyShare::contribution_with_crp_and_binding_extended(sk, crp_d1, crp_a, binding, ct_level, key_level, rng)` → `Result<(RelinKeyShare, RlkWitness)>`.
7. `RlkWitness` is `pub struct RlkWitness { pub r: Zeroizing<SecretKey>, pub errors_d0: Vec<Poly<NttShoup>>, pub errors_d2: Vec<Poly<NttShoup>> }`.
8. For each row `j`, `d0_j = e0_j − sk·d1_j + g_j·r` and `d2_j = e2_j + r·a_j + g_j·sk`, with `d1_j = crp_d1[j]`, `a_j = crp_a[j]`, and errors as specified.
9. RLK circuits prove `d0_j + sk·d1_j = e0_j + g_j·r`, `d2_j − r·a_j = e2_j + g_j·sk`, and both error infinity bounds ≤ `B_enc`.
10. `b_vec` is the separate public-key output and errors have length `l − ciphertext_level`.
11. NTT/Shoup witnesses are inverse-transformed to `PowerBasis` for integer-coefficient circuits; large values require full CRT reconstruction.
12. The same `crp_a` is used for PK and RLK (enforced by aggregation); with `b_j = e_j − a_j·sk` and `d2_j = e2_j + r·a_j + g_j·sk`, the aggregate satisfies `b_j + d2_j = e_j + e2_j + r·a_j + g_j·sk`. `r` is ephemeral and never reused.
13. `RlkWitness.r` is `Zeroizing` and errors are caller-erased; witnesses are not logged, serialized, transmitted, or stored beyond the proving session.

The encryption circuit statement is: the prover knows `(u, e1, e2, m)` and proves `c0 = u·b + e1 + m`, `c1 = u·a + e2`, and `‖u‖_∞ ≤ B_enc`, `‖e1‖_∞ ≤ B_enc`, `‖e2‖_∞ ≤ B_enc`; `sk` is not a witness and is held independently. The RLK circuit statement is: for each active row `j` (one per RNS modulus; `j ∈ {0, …, l−1}` at `ciphertext_level = 0`), the prover knows `(sk, r, errors_d0, errors_d2)` and proves `d0_j + sk·d1_j = e0_j + g_j·r`, `d2_j − r·a_j = e2_j + g_j·sk`, `‖e0_j‖_∞ ≤ B_enc`, and `‖e2_j‖_∞ ≤ B_enc`.

The l-BFV construction uses one row per modulus and the signs match the implementation's `neg_r = −r` encrypting key in `ksk_s_to_r`. `b_vec` is the per-modulus `b_j` component and is not re-derived. Errors are returned in `Poly<NttShoup>`; inverse NTT converts them to `PowerBasis`. Small-error RNS reconstruction from `u64` limbs yields `(-B_enc, +B_enc)` directly, while `r`, `d0_j`, and `d2_j` require full CRT reconstruction.

| Type | Meaning | For circuit |
|---|---|---|
| `Poly<NttShoup>` | NTT-transformed, Shoup-precomputed, in `R_q` | Need inverse NTT first |
| `Poly<Ntt>` | NTT-transformed, in `R_q` | Need inverse NTT first |
| `Poly<PowerBasis>` | Coefficient form, in `R_q` (RNS limbs as u64) | Closest to circuit inputs |

## Evidence / tests

The API signatures, equations, circuit statements, representation table (`Poly<NttShoup>`, `Poly<Ntt>`, `Poly<PowerBasis>`), and source documentation above are the contract evidence; test extended APIs against their published equations and range handling. Gap: no test currently asserts the encryption-witness equations `c0 = u·b + e1 + m` and `c1 = u·a + e2` for `try_encrypt_extended` (the RLK equations are tested in `crates/fhe/src/lbfv/keys/relinearization_key.rs`); add one when touching these APIs.

## Sync

- Touch → update: `witness.md` — `crates/fhe/src/{lbfv,trlbfv}/**` (the `_extended` witness APIs).
