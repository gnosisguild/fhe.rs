# `fhe::trckks` — threshold CKKS

Threshold (t-of-n) CKKS on top of the single-key [`fhe::ckks`](../ckks) module.
Mirrors [`fhe::trbfv`](../trbfv) so a node that already runs threshold BFV can
run CKKS with the same DKG transport, share shapes, and decryption flow.

## Protocol stack and references

| Layer | What | Reference |
|---|---|---|
| Joint key | additive `s = Σ s_i`; pk from a CRP: party publishes `pk0_i = -a·s_i + e_i` | Mouchet–Troncoso-Pastoriza–Bossuat–Hubaux, [eprint 2020/304](https://eprint.iacr.org/2020/304), Protocol 1 (`EncKeyGen`) |
| Relinearization key | two-round CRP ceremony, one instance per multiplication level | same paper, Protocol 2 (`RelinKeyGen`); ported from `fhe::mbfv::RelinKeyGenerator` |
| Hybrid relinearization key | the SAME two-round ceremony over `Q·P` with the digit gadget: ONE instance serves every level | Han–Ki, [eprint 2019/688](https://eprint.iacr.org/2019/688) §3 (hybrid key switching); Lattigo `RKGProtocol`; see [`ckks/hybrid.rs`](../ckks/hybrid.rs) |
| Shamir layer | each party Shamir-shares `s_i` and its smudging polynomial coefficient-wise mod every RNS prime; `t+1` of `n` reconstruct | Urban–Rambaud, [eprint 2024/1285](https://eprint.iacr.org/2024/1285); same code as `trbfv::ShamirSecretSharing` |
| Threshold decryption | `d_j = c0 + c1·[s]_j + [e_sm]_j`; Lagrange-combine `t+1` shares → `Δ·m + e + e_sm` | Li–Micciancio flooding: [eprint 2020/1533](https://eprint.iacr.org/2020/1533); bound derivation in [`smudging.rs`](smudging.rs) |

## API map

### Coordinator — `TRCKKS` ([`mod.rs`](mod.rs))

| Item | Role |
|---|---|
| `TRCKKS::new(n, threshold, params)` | validates `n ≥ 3`, `1 ≤ t ≤ (n-1)/2`, `n < min q_i` |
| `coeffs_to_poly(&[i64])` / `smudging_to_poly(&[BigInt])` | lift a secret contribution / smudging vector to a level-0 `Poly<PowerBasis>` (zeroizing) |
| `generate_smudging_error(bits, rng)` | `degree` uniform coefficients in `[-2^bits, 2^bits]` — feed `bits` from the calculator below |
| `generate_secret_shares_from_poly(poly, rng)` | deal: one `[n, degree]` `u64` matrix per RNS modulus (row `j` → party `j+1`); independent sharing per modulus, parallel over moduli |
| `aggregate_collected_shares(&[Array2])` | party side: sum the `[L, degree]` rows received from every dealer → own share of the joint value |
| `share_row_to_poly(dealt, j)` | single-dealer convenience (tests, trusted dealer) |
| `project_share_to_level(share, level)` | move a share to a rescaled ciphertext's level by **dropping RNS rows** (never divide) |
| `decryption_share(ct, sk_i, es_i)` | `c0 + c1·sk_i + es_i`; rejects 3-component (unrelinearized) ciphertexts; takes `es_i` by value — see single-use below |
| `decrypt(shares, party_ids, ct)` | exactly `t+1` shares with 1-based ids → `CkksPlaintext` at the ciphertext's scale/level |

### Multiparty keygen ([`keygen.rs`](keygen.rs))

| Item | Role |
|---|---|
| `CkksCrp::from_seed(par, seed)` | level-0 CRP `a` from a public 32-byte seed |
| `CkksCrp::vec_from_seed[_leveled](par, seed, size, level)` | one CRP per RNS limb remaining at `level` (relin ceremony input) |
| `CkksCrp::vec_from_seed_qp(par, seed)` | the `dnum` CRPs over `Q·P` (hybrid ceremony input); errors unless the params carry special primes |
| `CkksCrp::poly()` | the public polynomial (witness input for proofs) |
| `CkksPublicKeyShare::new(sk_i, crp, rng)` / `from_parts` / `p0_to_bytes` | party's `-a·s_i + e_i`; wire helpers |
| `CkksPublicKeyShare::aggregate(&[shares])` | joint `CkksPublicKey`; rejects mixed CRPs |

### Relinearization ceremony ([`relin_gen.rs`](relin_gen.rs))

| Item | Role |
|---|---|
| `CkksRelinKeyGenerator::new(sk_i, crp, rng)` / `new_leveled(sk_i, crp, level, rng)` | per-party generator; samples the ephemeral secret `u_i` (zeroized on drop, redacted `Debug`) |
| `new_leveled_from_seed(sk_i, crp, level, u_seed, _rng)` | deterministic `u_i` from a SECRET per-party seed (domain-separated by level) for state machines that persist between rounds |
| `round_1(rng)` → `CkksRelinKeyShare<R1>` | `h0[j] = -a_j·u_i + g_j·s_i + e`, `h1[j] = a_j·s_i + e` |
| `round_1_extended(rng)` / `u_poly()` | additionally return `(e0s, e1s)` and `u` — SECRET witnesses for a well-formedness proof; never publish |
| `CkksRelinKeyShare::<R1Aggregated>::from_shares(Vec<R1>)` | sum of all parties' round 1 |
| `round_2(&r1_agg, rng)` → `CkksRelinKeyShare<R2>` | `h0' = h0·s_i + e`, `h1' = h1·(u_i − s_i) + e` |
| `CkksRelinKeyShare::<R2>::aggregate_into_key(Vec<R2>)` / `aggregate_into_key_with_r1(shares, r1_agg)` | joint `CkksRelinearizationKey`; the `_with_r1` form reattaches the round-1 aggregate that the wire format drops |
| `CkksRelinKeyShare::{to_bytes, from_bytes, level, h0, h1}` | wire format = `level ‖ count ‖ (len ‖ poly)*` (shared with `CkksRelinearizationKey`, see [`ckks/wire.rs`](../ckks/wire.rs)) |

### Hybrid relinearization ceremony ([`hybrid_gen.rs`](hybrid_gen.rs))

Requires params built with `CkksParametersBuilder::set_special_moduli_sizes(&[k × bits])`
(+ optional `set_dnum`). One ceremony, one key (`CkksHybridRelinKey`) for every level;
key/share size `2·dnum·(L+k)` polys instead of `2·L_ℓ²` per level; key-switch noise
`≈ dnum·N·B_err·D/P` instead of `L_ℓ·q_max·N·B_err` (measured: depth-4 multiparty
relative error 1e-6 vs 1e-1 at N=8192, see `hybrid_vs_rns_depth_four_multiparty_precision_and_size`).

| Item | Role |
|---|---|
| `CkksHybridRelinKeyGenerator::new(sk_i, crp: &[CkksQpPoly], rng)` / `new_from_seed(sk_i, crp, u_seed, _rng)` | per-party generator; `u_i` over `Q·P`, zeroized, redacted `Debug` |
| `round_1(rng)` → `CkksHybridRelinKeyShare<R1>` | `h0[j] = -a_j·u_i + P·g_j·s_i + e`, `h1[j] = a_j·s_i + e` over `Q·P` |
| `CkksHybridRelinKeyShare::<R1Aggregated>::from_shares(Vec<R1>)` | sum of all parties' round 1 |
| `round_2(&r1_agg, rng)` → `CkksHybridRelinKeyShare<R2>` | `h0' = h0·s_i + e`, `h1' = h1·(u_i − s_i) + e` |
| `CkksHybridRelinKeyShare::<R2>::aggregate_into_key(Vec<R2>)` / `aggregate_into_key_with_r1(shares, r1_agg)` | joint `CkksHybridRelinKey` (`b_j = Σh0' + Σh1'`, `a_j = h1`) |
| `CkksHybridRelinKeyShare::{to_bytes, from_bytes, dnum, h0, h1}` | wire format = `0xfffffffe ‖ dnum ‖ L ‖ k ‖ (len ‖ poly)*` (`b.q, b.p, …`; shared with `CkksHybridRelinKey`) |

Evaluate: `ct = a.try_mul(&b); hybrid_rlk.relinearizes(&mut ct); ct.rescale()` — at ANY level.

### Flooding bound ([`smudging.rs`](smudging.rs))

`CkksSmudgingBoundCalculator::new(CkksSmudgingConfig { params, n_parties, circuit: CkksCircuitShape, level, input_bound, precision_loss, lambda })
    .calculate_sm_bits()` — security floor `B_sm ≥ 2^λ·B_C` checked against the two
CKKS correctness walls (no wrap mod `Q_l`; `n·B_sm ≤ precision_loss·effective_scale`).
Reuses `trbfv::Lambda`.

## Typical flow

```text
DKG (once per committee)
  each party i:  sk_i = CkksSecretKey::random
                 pk_share_i = CkksPublicKeyShare::new(sk_i, crp)
                 deal  generate_secret_shares_from_poly(coeffs_to_poly(sk_i))      -> n recipients
                 deal  generate_secret_shares_from_poly(smudging_to_poly(e_sm_i))  -> n recipients  (ONE per expected opening)
  everyone:      pk = CkksPublicKeyShare::aggregate(all pk shares)
  each party j:  [s]_j    = aggregate_collected_shares(rows received for sk)
                 [e_sm]_j = aggregate_collected_shares(rows received for e_sm)

Relin ceremony (once per multiplication level the circuit needs)
  round 1: r1_i = generator_i.round_1()          -> broadcast
  agg:     r1   = from_shares(all r1_i)
  round 2: r2_i = generator_i.round_2(&r1)       -> broadcast
  agg:     rlk_level = aggregate_into_key_with_r1(all r2_i, r1)

Evaluate:  ct = ct_a.try_mul(&ct_b); rlk[level].relinearizes(&mut ct); ct.rescale()

Threshold decrypt (t+1 parties)
  d_j = decryption_share(ct, project_share_to_level([s]_j, ct.level).into_ntt(),
                             project_share_to_level([e_sm]_j, ct.level))
  pt  = decrypt(d_shares, party_ids, ct);  values = CkksEncoder::decode(pt)
```

## Security posture

- **Flooding is mandatory.** CKKS decryption reveals `m + e`; without smudging
  noise `≥ 2^λ·B_C` a decryption transcript leaks the key (Li–Micciancio).
  Derive `bits` from the calculator, never guess it.
- **`e_sm` is single-use per ciphertext.** The dealt smudging sharing hides ONE
  opening. Opening two different ciphertexts with the same `[e_sm]_j` lets an
  observer cancel the flooding by subtraction. `decryption_share` takes the
  share by value so reuse requires an explicit `.clone()`; deal one smudging
  sharing per expected opening. Re-publishing a share for the SAME ciphertext
  is safe (deterministic).
- **Shares are per-modulus sharings.** Level projection drops RNS rows; any
  divide-and-round on a share destroys it.
- **The relin ceremony is proof-free, verified by determinism.** No
  zero-knowledge proof covers round 1 or round 2 (the `round_1_extended`
  witnesses exist so one can be added). Correctness is checked by every party
  aggregating the same public shares and comparing the resulting key bytes;
  a malicious party can make the key unusable (denial of service) but cannot
  learn anything beyond the public transcript. The same deterministic-check
  posture applies to public-key aggregation.
- **Secret material hygiene.** `CkksSecretKey` is `Zeroize + Drop` with a
  redacted `Debug`; the relin generator's `u` is `Zeroizing` and its `Debug`
  is redacted; `coeffs_to_poly`/`smudging_to_poly` return `Zeroizing` polys.
  Dealt share matrices (`Array2<u64>`) and aggregated share polynomials are
  NOT zeroizing types — callers that persist them must wrap/erase them.
- **Honest-majority threshold.** `t ≤ (n-1)/2` is enforced; the Shamir layer
  is semi-honest (no share verification here — interfold layers Reed–Solomon
  parity proofs on top).

## Benchmarks

`cargo run --release --example trckks_dkg_bench -- --preset demo512-2limb --parties 3,5,10`
measures DKG, ceremony, and threshold-decrypt compute and bandwidth per party;
see [`../../BENCHMARKS_TRCKKS.md`](../../BENCHMARKS_TRCKKS.md).
