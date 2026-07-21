# ZK witness generation

This document specifies the witness material produced by the `_extended` API
variants for use in ZK proofs (e.g. Noir circuits).  It defines the
mathematical relations the witness satisfies, the API surface, and the security
requirements for handling witness values.

## Overview

A ZK proof of correct key generation or encryption requires the prover to
commit to private values and prove that the published public values satisfy
specific linear equations over the ring `R_q`.  The `_extended` API variants
surface the private values that are otherwise generated internally and
immediately used or zeroized.

Two protocols need witness material:

| Protocol       | Public values           | Witness values          |
|----------------|-------------------------|-------------------------|
| Encryption     | `(c0, c1, b, a, m)`     | `u, e1, e2`             |
| RLK generation | `(d0, d1, d2, a, b_vec)`| `r, errors_d0, errors_d2` |

---

## 1. Encryption witness

### Source

`lbfv::LBFVPublicKey::try_encrypt_extended(pt, rng)`
→ `Result<(Ciphertext, Poly<Ntt>, Poly<Ntt>, Poly<Ntt>)>`
→ `(ct, u, e1, e2)`

### Equations

Using the first public-key ciphertext `(b, a) = pk.c[0]`:

```
c0 = u·b + e1 + m
c1 = u·a + e2
```

where `m = Δ·msg` is the scaled plaintext and `Δ = floor(Q/t)`.

### Circuit statement

The prover knows `(u, e1, e2, m)` and must prove:

1. `c0 = u·b + e1 + m`  (linear over `R_q`)
2. `c1 = u·a + e2`
3. `‖u‖_∞ ≤ B_enc`, `‖e1‖_∞ ≤ B_enc`, `‖e2‖_∞ ≤ B_enc`  (range checks)

`sk` is **not** a witness value here — the prover holds it independently and
does not derive it from the public-key function.

### Notes

- `u, e1, e2` are returned as `Poly<Ntt>` (not zeroized).  The caller is
  responsible for secure erasure after use.
- Only `c[0]` of the l-BFV public key is used for encryption.

---

## 2. RLK contribution witness

### Source

**Unbound:**
`trlbfv::RelinKeyShare::contribution_with_crp_extended(sk, crp_d1, crp_a, ct_level, key_level, rng)`
→ `Result<(RelinKeyShare, RlkWitness)>`

**Bound (with `ContributionBinding`):**
`trlbfv::RelinKeyShare::contribution_with_crp_and_binding_extended(sk, crp_d1, crp_a, binding, ct_level, key_level, rng)`
→ `Result<(RelinKeyShare, RlkWitness)>`

### `RlkWitness` fields

```rust
pub struct RlkWitness {
    pub r: Zeroizing<SecretKey>,         // ephemeral randomness key
    pub errors_d0: Vec<Poly<NttShoup>>,  // per-row errors in ksk_r_to_s
    pub errors_d2: Vec<Poly<NttShoup>>,  // per-row errors in ksk_s_to_r
}
```

`r` is auto-zeroized when `RlkWitness` is dropped.

### Equations

The l-BFV RLK construction generates two key-switching keys using RNS-HPS
decomposition (one row per modulus).  For row `j ∈ {0, …, l-1}`:

**`ksk_r_to_s` (d0/d1 pair):**
```
d0_j = e0_j  −  sk · d1_j  +  g_j · r
```
where `d1_j = crp_d1[j]` (public URS), `g_j` is the `j`-th Garner/gadget
coefficient, and `e0_j = errors_d0[j]` is a small error.

**`ksk_s_to_r` (d2/a pair):**
```
d2_j = e2_j  +  r · a_j  +  g_j · sk
```
where `a_j = crp_a[j]` (public CRS, same as in the l-BFV public key), and
`e2_j = errors_d2[j]` is a small error.

The sign conventions match the implementation's use of `neg_r = −r` as the
encrypting key in `ksk_s_to_r`.

### Circuit statement

The prover knows `(sk, r, errors_d0, errors_d2)` and must prove, for each row `j`:

1. `d0_j + sk·d1_j = e0_j + g_j·r`  (rearranged form of the d0 relation)
2. `d2_j − r·a_j   = e2_j + g_j·sk` (rearranged form of the d2 relation)
3. `‖e0_j‖_∞ ≤ B_enc` and `‖e2_j‖_∞ ≤ B_enc`  (range checks)

The `b_vec` from the l-BFV public key is the per-modulus `b_j` component; it
is not re-derived here but is the separate public-key output from
`trlbfv::PublicKeyShare::contribute_with_crp_and_binding`.

### Notes

- `errors_d0` and `errors_d2` have length `l − ciphertext_level` (one entry
  per active RNS modulus).
- Errors are returned in `Poly<NttShoup>`.  For a circuit operating on
  integer coefficients, convert to `PowerBasis` via the inverse NTT before
  extracting coefficients.
- The same `crp_a` must be used for both the public-key contribution
  (`PublicKeyShare::contribute_with_crp_and_binding`) and the RLK contribution
  (`RelinKeyShare::contribution_with_crp_and_binding_extended`).  Using
  different CRS polynomials for pk and rlk breaks the relinearization
  cancellation `b_vec + d2 = sk·g` in the aggregated key.
- `r` is an ephemeral `SecretKey`; it must not be reused across contributions
  or protocol sessions.

---

## 3. Polynomial representations

The circuit operates on integer coefficient vectors.  The library uses RNS
representations internally:

| Type              | Meaning                                         | For circuit |
|-------------------|-------------------------------------------------|-------------|
| `Poly<NttShoup>`  | NTT-transformed, Shoup-precomputed, in `R_q`   | Need inverse NTT first |
| `Poly<Ntt>`       | NTT-transformed, in `R_q`                      | Need inverse NTT first |
| `Poly<PowerBasis>`| Coefficient form, in `R_q` (RNS limbs as u64)  | Closest to circuit inputs |

For small-error polynomials the RNS reconstruction from `u64` limbs yields
integer values in `(-B_enc, +B_enc)` directly.  For larger polynomials (the
`r` coefficients, `d0_j`, `d2_j`) full CRT reconstruction is needed.

---

## 4. Security requirements

- Treat `RlkWitness` as secret key material: do not log, serialize, or
  transmit it outside of the local proving session.
- `RlkWitness.r` is wrapped in `Zeroizing<SecretKey>` and is erased on drop.
  `errors_d0` and `errors_d2` are plain `Vec<Poly<NttShoup>>`; the caller
  must explicitly drop or zeroize them after the proof is complete.
- `u, e1, e2` returned by `try_encrypt_extended` are plain `Poly<Ntt>` (same
  as the existing `#[allow(clippy::type_complexity)]` precedent in the public
  key); the caller is responsible for erasure.
- Witness values must not outlive the proof-generation session.  Storing them
  persistently re-introduces the private values they protect.
