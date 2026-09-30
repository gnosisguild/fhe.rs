# Threshold BFV (trBFV)

Shamir sharing, smudging noise, and threshold decryption based on
[Urban–Rambaud 2024](https://eprint.iacr.org/2024/1285.pdf).
Addition is supported directly; multiplication uses distributed l-BFV
relinearization keys. This is a cryptographic component, not the paper's
complete robust multiparty protocol.

## Implementation boundary

| Library provides | Application provides |
| ---------------- | -------------------- |
| BFV/l-BFV arithmetic and key contributions | DKG, PVSS, FLSS, and GURS |
| Shamir sharing and aggregation | Authenticated transport and broadcast |
| Smudging bounds and one-time noise owners | Participant/session binding and durable replay prevention |
| Decryption shares and reconstruction | Proof verification, admission policy, retries, and identifiable aborts |

`ShareManager` requires `n >= 3` and `threshold = (n - 1) / 2`. Reconstruction
uses exactly `threshold + 1` distinct **1-based** party IDs, in the same order
as the decryption shares. Odd committees (`n = 2t + 1`) match the paper's
model. Even committees are accepted but fall outside its theorem.
Proactive refresh is not implemented.

Contributions are not authenticated or bound to a participant or session by
this API. Applications must use the same agreed contributor set throughout
key generation, sharing, and decryption. Examples simulate setup and transport
locally; they do not implement the missing protocol components.

## Share ownership

1. Deal each secret-key contribution with `generate_secret_key_shares`.
2. Transport each recipient's shares and aggregate them with
   `aggregate_secret_key_shares`.
3. Sample fresh smudging noise, consume it with `generate_smudging_shares`,
   and aggregate each recipient's received noise shares.
4. Call `decryption_share` for each decrypting party, borrowing its aggregate
   secret-key share and consuming its aggregate smudging share.
5. Reconstruct with `decrypt_from_shares`.

Secret-key aggregates are reusable and zeroized on drop. Smudging noise and
aggregates are non-cloneable, one-time owners. Only dealt and individual shares
expose transport operations; sampled noise and aggregated owners do not expose
transport or proof witnesses.

Ownership prevents reuse of a live noise aggregate in safe Rust, **not replay
of transported matrices**. Persisted or copied shares can recreate the same
noise after re-aggregation. Bind transport to the ciphertext, key epoch, and
decryption domain, and prevent cross-domain reuse durably.

## Smudging configuration

`SmudgingConfig::new(params, n, m, lambda, model)` selects the bound;
`.with_mult_depth(depth)` adds multiplication levels.
`SmudgingNoiseGenerator::new` checks feasibility before sampling. The dealing
manager checks the noise owner's full BFV parameters and party count, but
cannot verify the caller's circuit, depth, `lambda`, or noise model.

### Fresh-noise model

Choose the model matching the actual encryption path:

| `FreshNoiseModel` | Input ciphertexts | Fresh-noise assumption |
| ----------------- | ----------------- | ---------------------- |
| `BfvPublicKey` | BFV public-key encryption, including aggregated MBFV keys | Ternary randomness: `u_bound = 1` |
| `LbfvPublicKey` | l-BFV public-key encryption, including aggregated keys | Small randomness: `u_bound = 2 * variance` |
| `BfvSecretKey` | BFV secret-key encryption | One small error: `B_fresh = 2 * variance` |
| `Custom(bound)` | External keys or samplers | Caller-justified positive `B_fresh` |

There is no default. An understated bound invalidates the smudging guarantee;
the library cannot verify an external noise distribution. For mixed input
paths, use the largest fresh-noise bound.

### Circuit size and depth

`m` bounds the largest sum of **fresh** ciphertexts before the modelled circuit:

| Circuit | `m` |
| ------- | --- |
| `a + b + c` | `3` |
| `a * b * c`, without pre-sums | `1` |
| `(a + b) * c` | `2` |

It is not a count of outputs or independent decryptions. Additions of evaluated
results after multiplication are not modelled automatically: analyze such
circuits and choose a conservative circuit-specific bound. Increasing `m`
inflates the bound at a feasibility cost.

`lambda` is a caller-chosen statistical-hiding policy in `0..=MAX_LAMBDA`
(`256`), not a computational bit-security claim. The library imposes no minimum;
applications must enforce their own policy and analyze repeated decryptions.

### Bound arithmetic

For ring degree `d`, ciphertext-modulus product `Q`, and plaintext modulus `t`:

```text
Delta       = floor(Q / t)
B_C[0]      = m * (B_fresh + Q mod t)
B_C[i + 1]  = 2 * t * d^2 * sk_bound * B_C[i] + B_relin
B_sm        = 2^(lambda + 1) * d * B_C[depth]
```

Correctness requires the **strict** inequality
`2 * (B_C[depth] + n * B_sm) < Delta`; equality is rejected.
`B_relin` follows the paper's Eq. 30 with aggregate error `n * B_e`,
conservatively allowing all `n` relinearization contributions.

For public-key models:

```text
B_fresh = d * u_bound * e_pk + B_enc + d * B_e * sk_bound
B_e = 2 * variance;  e_pk = n * B_e;  sk_bound = n
```

`B_enc = fhe_math::rq::error_coefficient_bound(error1_variance)` follows
the same CBD/uniform branch as the encryption sampler.

For one transcript, uniform noise on `[-B_sm, B_sm]` hides two honest shifts
bounded by `B_C` with total variation distance at most
`min(1, 2 * d * B_C / (2 * B_sm + 1))`. The degree factor covers all revealed
coefficients; the extra factor `2` in `2^(lambda + 1)` is conservative slack,
not part of the correctness inequality. This argument assumes an independent
honest noise contribution and a valid ciphertext-noise bound. Composition
across decryptions requires external analysis.

Threshold smudging and reconstruction require `t <= u64::MAX`, even though
plain BFV supports larger plaintext moduli. Both entry points reject larger
values with `ParametersError::UnsupportedPlaintextModulus`;
`ShareManager::new` alone does not check this restriction.

## Examples

* [`trbfv_add`](../../examples/trbfv_add.rs): addition and local share exchange.
* [`trbfv_add_bfv_share`](../../examples/trbfv_add_bfv_share.rs): encrypted share transport.
* [`trbfv_mul_bfv_share`](../../examples/trbfv_mul_bfv_share.rs): multiplication with distributed l-BFV keys.

```bash
cargo run --release -p fhe --features experimental-mbfv --example trbfv_add -- --num_parties=5 --threshold=2
```

The examples use repository test profiles, not deployment recommendations.
The MBFV-enabled examples inherit that feature's unresolved security limitations.

## Implementation

* `config.rs`: committee validation.
* `rns_shamir.rs`: crate-private sharing and reconstruction.
* `smudging/bound.rs`: configuration and bound arithmetic.
* `smudging/noise.rs`: centered-uniform sampling and noise ownership.
* `shares/`: dealing, aggregate owners, and decryption.
* `errors.rs`: threshold errors.

## Security

This implementation has not been independently audited. Use at your own risk.
Secret-coefficient sharing uses constant-time modular arithmetic; Lagrange
inversion depends only on public party IDs and prime moduli. These properties
do not establish end-to-end protocol security. l-BFV relinearization additionally
relies on the construction's circular-security assumption.
