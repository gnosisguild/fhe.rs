# Threshold BFV (TRBFV)

A pure-Rust implementation of threshold BFV homomorphic encryption based on the work of Antoine Urban and Matthieu Rambaud in [Robust Multiparty Computation from Threshold Encryption Based on RLWE](https://eprint.iacr.org/2024/1285.pdf) (Urban–Rambaud 2024).

The current implementation covers Shamir sharing, smudging noise, and
threshold decryption with additive and limited multiplicative support via
distributed *l*-BFV relinearization keys. It is **not** the complete robust
protocol from the paper: there is no distributed key generation, no broadcast
channel, no FLSS (function-linear secret sharing), and no GURS (guaranteed
uniform random string) generation. The smudging exchange is assumed to have
already happened out of band.

This module supplies the sharing and decryption components for `n` parties:
`threshold + 1` distinct parties can reconstruct under the supported
parameters. A secrecy claim against a coalition of at most `threshold` parties
also depends on the paper's assumptions and the external protocol components
listed below; this library does not establish that claim end to end. The
threshold must be exactly `(n-1)/2` (integer division) — see `config.rs`.

## Implementation Boundary

This crate exposes the cryptographic component used by a threshold FHE
application. It does not expose the complete multiparty protocol described in
the paper. The following table is the boundary for callers and integrators:

| Paper or application component | Responsibility |
| ------------------------------ | -------------- |
| BFV and l-BFV operations (Sections 4 and 6) | Implemented by `fhe.rs`. |
| Shamir sharing, share aggregation, smudging bounds, and threshold decryption | Implemented by `fhe.rs`. |
| DKG, PVSS, FLSS, and GURS | Must be supplied externally. |
| Authenticated transport, broadcast, retries, and identifiable aborts | Must be supplied externally. |
| Committee membership, accepted-party policy, and application lifecycle | Must be supplied externally. |
| ZK proofs and application wire formats | Must be supplied externally. |

The public `ShareManager` flow is:

1. Create a `ShareManager` instance with BFV parameters.
2. Generate and distribute Shamir shares for each party's secret contribution.
3. Aggregate the received contributions for the same externally agreed party
   set.
4. Compute one decryption share per decrypting party.
5. Reconstruct with exactly `threshold + 1` distinct 1-based party IDs.

The examples in `crates/fhe/examples/` simulate the external setup and share
transport locally. They demonstrate the supported component flow, but they do
not implement DKG, authenticated broadcast, PVSS, ZK validation, or the paper's
robustness protocol.

Paper-conforming deployments use odd `n` with `n = 2t + 1`. The current API
also accepts even `n` for compatibility; those deployments are an
implementation-specific extension and must not be presented as covered by the
paper's theorem. The API likewise does not bind a contribution matrix to a
party identity or session, so callers must enforce a common participant set and
identity/session binding at their protocol boundary.

## Architecture

The module follows a modular design with clear separation of concerns:

- `../rns_shamir.rs` - crate-private direct RNS Shamir arithmetic shared by threshold schemes
- `smudging/bound.rs` - smudging-bound configuration and arithmetic, with optimal variance calculation using arbitrary precision arithmetic
- `smudging/noise.rs` - one-time smudging noise sampling and single-use ownership
- `shares/mod.rs` - share aggregation and decryption operations management (with the single-use owners in `shares/secret_key.rs` and `shares/smudging.rs`)
- `config.rs` - Parameter validation
- `errors.rs` - Threshold-specific error types

The former public `trbfv::shamir` module and `ShamirSecretSharing` type were
removed when share generation and reconstruction moved to direct RNS
arithmetic. Callers should use `ShareManager`; its high-level share
generation, aggregation, and reconstruction APIs retain the same logical share
layout.

> **Breaking change:** `TRBFV::decrypt` has been replaced by
> `ShareManager::decrypt_from_shares`. The `TRBFV` orchestrator and
> `ShareManager::bigints_to_poly` were removed. Use `SmudgingConfig::new`
> with the correct [`FreshNoiseModel`](smudging/bound.rs) (and
> `.with_mult_depth(depth)` if needed), then `SmudgingNoiseGenerator::new`
> and `generate`. Pass the non-cloneable noise owner to
> `ShareManager::generate_smudging_shares`; see [Usage](#usage).

## Noise and Correctness Formulas (Urban–Rambaud 2024)

This section summarises the formulas implemented in
[`smudging/bound.rs`](smudging/bound.rs) (bound arithmetic) and
[`smudging/noise.rs`](smudging/noise.rs) (sampling). See the paper for full
derivations.

### Delta and the strict correctness inequality

The plaintext scaling factor is **&Delta; = &lfloor;Q / t&rfloor;** (not `Q/(2t)`):

> `2 * (B&#x1d9c; + n * B&#x209b;&#x2098;) < &Delta;`

where
- `Q` is the product of all CRT moduli,
- `t` is the plaintext modulus,
- `n` is the total number of parties,
- `B&#x1d9c;` is the ciphertext noise infinity-norm bound after circuit evaluation,
- `B&#x209b;&#x2098;` is the smudging-noise coefficient bound.

Equality (`>=`) is **rejected**: a smudging bound that merely meets &Delta; does
not guarantee correct decryption.

### Ciphertext noise recursion (multiplicative circuits)

Let `mult_depth` be the number of multiplication levels.

- **Initial bound:** `B&#x1d9c;&sup0;` = `m &middot; (B_fresh + Q mod t)`
  where `m` is the caller-chosen circuit size: an upper bound on the number
  of *fresh* ciphertexts summed together **before** the modelled circuit
  (the worst pre-multiplication addition fan-in). It is not the number of
  output ciphertexts and not the number of independent decryptions.
  `B_fresh` itself is derived from the encryption-noise and key-norm bounds,
  using the sampler-specific `B_enc` (see below) and the caller-selected
  fresh-noise model (see below).

  Choosing `m`:
  - Additive circuit `ct_a + ct_b + ct_c`: three fresh ciphertexts are
    summed before decryption, so `m = 3`.
  - Pure multiplication of fresh inputs with no pre-sum, e.g.
    `ct_a * ct_b * ct_c`: each multiplication branch carries one fresh
    ciphertext's noise, so `m = 1` even though several input ciphertexts
    feed the multiplication.
  - Mixed circuit `(ct_a + ct_b) * ct_c`: the left branch is a two-input
    sum, so the worst pre-multiplication fan-in is `m = 2`.

  Additions of evaluated results *after* a multiplication are not modelled by
  this formula: analyze such circuits and supply a conservative
  circuit-specific `m`; the library makes no generic circuit-size guarantee.
  A larger `m` only inflates `B_C` and `B_sm`, so an explicit conservative
  overprovision stays correct and safe at a feasibility cost.

- **Recursion** (Prop.&nbsp;20 of Urban–Rambaud 2024):

  > `B&#x1d9c;&sup1;&plus;&sup1; = 2&middot;k&middot;N&sup2;&middot;||sk|| &middot; B&#x1d9c;&sup1; + B_relin`

  where
  - `k = t` (plaintext modulus),
  - `N` is the polynomial ring degree,
  - `||sk||` is the secret-key infinity-norm bound,
  - `B_relin` is the relinearisation error bound (Eq.&nbsp;30 of the paper)
    with **aggregate RLK error** `n &middot; B_e`. This is conservative when fewer
    than all `n` relinearization contributions are aggregated.

- **Smudging bound:** `B&#x209b;&#x2098; = 2^(lambda + 1) &middot; d &middot; B&#x1d9c;` where
  `lambda` is the caller-selected statistical security parameter and `d` is
  the polynomial ring degree.

  *Statistical-distance argument (issue #108).* Let the integer smudging
  noise `U` be uniform on `[-B_sm, B_sm]`, and let `x`, `y` be honest noise
  shifts with `|x|, |y| <= B_C`. For one coefficient, the total variation
  distance between `U + x` and `U + y` is at most
  `min(1, |x - y| / (2*B_sm + 1)) <= min(1, 2*B_C / (2*B_sm + 1))`; when
  comparing against the unshifted distribution, use `|x| <= B_C`. One
  threshold decryption reveals all `d` coefficients of the smudging noise at
  once, so a union/hybrid bound over the coefficients bounds the whole
  transcript by `min(1, 2*d*B_C / (2*B_sm + 1))`: the degree factor `d`
  comes from revealing every coefficient. The remaining factor `2` in
  `2^(lambda + 1)` is conservative slack in the policy — it does **not**
  come from the leading `2` of the correctness inequality
  `2*(B_C + n*B_sm) < Delta`. For `B_C > 0` and
  `B_sm = 2^(lambda + 1) * d * B_C`, this idealized single-transcript bound
  is numerically below `2^-(lambda + 1)`.

  *Scope and assumptions.* This is a one-transcript argument that relies on
  the modelled assumptions: one independent honest noise contribution whose
  bound `B_C` actually holds. Post-processing such as the RNS residue
  projection cannot increase total variation distance. `lambda` is the
  deployment's own policy (see
  [below](#lambda-is-a-caller-chosen-policy)); the library does not claim a
  stronger global statistical-hiding level than the chosen `lambda`, and
  composition across multiple independent decryptions is external analysis.
  This bound is what [`smudging/noise.rs`](smudging/noise.rs) implements.

### Sampler-specific `B_enc`

`B_enc` is the worst-case coefficient magnitude returned by
`fhe_math::rq::error_coefficient_bound(error1_variance)`. This shared helper
selects the same CBD or uniform sampler as `Poly::conditional_error`, so the
smudging bound tracks the encryption sampler's actual coefficient bound.

### Fresh-noise model selection (issue #250)

The fresh-ciphertext decryption-noise bound is

> `B_fresh = d &middot; u_bound &middot; e_pk + B_enc + d &middot; e2 &middot; sk`

where `d` is the ring degree, `e_pk = n &middot; (2 &middot; variance)` bounds
the aggregated public-key error (each share contributes `2 &middot; variance`,
so a single-party key is bounded by `2 &middot; variance`), `e2 = 2 &middot;
variance` bounds the second encryption error, and `sk = n` bounds the
aggregated ternary secret key. `SmudgingConfig::new` takes an explicit
`FreshNoiseModel` that supplies `u_bound`, the actual coefficient support of
the encryption randomness `u`; there is **no silent default**, because the
paths differ in their samplers:

| Model | Encryption path | `u` support (`u_bound`) |
| ----- | --------------- | ----------------------- |
| `FreshNoiseModel::BfvPublicKey` | `bfv::PublicKey::try_encrypt` (including MBFV-aggregated keys) | `1` (ternary CBD, `sample_vec_cbd_f32` with variance `0.5`) |
| `FreshNoiseModel::LbfvPublicKey` | `lbfv::LBFVPublicKey::try_encrypt` (including aggregated l-BFV key shares) | `2 &middot; variance` (`Poly::small(params.variance)`) |
| `FreshNoiseModel::BfvSecretKey` | `bfv::SecretKey::try_encrypt` | no `u`: the fresh phase noise is one small error, so `B_fresh = 2 &middot; variance` |
| `FreshNoiseModel::Custom(bound)` | imported ciphertexts, external key generators, nonstandard samplers | caller-supplied `B_fresh` |

Selecting the wrong model understates the bound: at depth zero on the
`insecure` profile parameters, the ternary assumption applied to l-BFV
ciphertexts underestimates `B_sm` by roughly 2.9&times;. When the ciphertexts
fed to one decryption come from several of these paths, use the model with the
largest `B_fresh` (for `Custom`, the maximum of the individual bounds).

`Custom` is a caller-justified trust decision, not a checked input: this
library cannot verify the noise distribution of an externally supplied key or
ciphertext, so the bound must be derived from the actual key-generation and
encryption procedure, and an understated bound silently invalidates the
smudging guarantee. A zero `Custom` bound is rejected.

`SmudgingConfig::new` is fallible: it rejects zero parties, a zero
summed-fresh-ciphertext count `m`,
unsupported lambda values, and zero `Custom` bounds. Its fields are private;
use accessors to inspect
them and `.with_mult_depth(depth)` before passing the config to
`SmudgingNoiseGenerator::new`. The generator checks feasibility, including
during the multiplicative-depth recursion.

## Known Limitations

### One-time pre-shared noise

Smudging noise is one-time material. The supported generation, aggregation, and
decryption path uses non-cloneable owners: generation consumes the sampled
noise, aggregation produces an owned aggregate, and decryption consumes that
aggregate. Consequently, safe Rust cannot use one live aggregate in two
decryption calls. The guarantee ends at the explicit transport boundary:
serialized or copied share matrices can be replayed, so authenticated
transport and durable replay prevention remain the integrator's responsibility.
Only dealt and individual shares have public transport operations; this crate
does not export/import aggregated owners or expose the exact sampled or
aggregated noise as a proof witness. Applications needing proofs or persistence
must design those parts outside this API. In particular, retaining transported
share matrices to re-aggregate after a restart can recreate the same noise:
the integrator must bind it to its original ciphertext and decryption domain
and prevent cross-domain reuse durably.

Secret-key share material follows a separate reusable-owner path. Dealing
returns a non-cloneable `DealtSecretKeyShares`; applications explicitly convert
the per-`q_i` output at their transport boundary into `SecretKeyShare`
values. `aggregate_secret_key_shares` consumes those owners and returns a
non-cloneable `AggregatedSecretKeyShare`, which is borrowed by each decryption
call and zeroized when the key epoch ends. This allows multiple decryptions with
one aggregated key while keeping the in-memory owner protected.

### Even-`n` party counts

Party counts where `n` is even are accepted for compatibility, but
Urban–Rambaud&nbsp;2024 proves security only for odd `n` (under the
`n = 2t + 1` honest-majority model).  Even-`n` deployments fall outside the
paper's theorem and have not been independently analyzed.

### Plaintext modulus must fit in `u64`

Plain BFV supports plaintext moduli larger than `u64::MAX`
(`set_plaintext_modulus_biguint`), but the threshold arithmetic binds `t` to a
machine word: `SmudgingNoiseGenerator::new` and
`ShareManager::decrypt_from_shares` reject a >64-bit `t` with
`ParametersError::UnsupportedPlaintextModulus`, checked before any bound or
reconstruction work. `ShareManager::new` itself does not validate `t`, so
parameter-build acceptance does not mean the threshold entry points support it.

### Incomplete protocol orchestration

Sharing, smudging, and decryption do not provide the complete robust protocol.
DKG, authenticated broadcast, FLSS/GURS, retries, and identifiable aborts
remain at the [integrator boundary](#implementation-boundary). Proactive
refresh is also not implemented.

### `lambda` is a caller-chosen policy

The statistical security parameter `lambda` is a plain `usize` in
`0..=smudging::MAX_LAMBDA`. A larger `lambda` produces a stronger noise-flooding
guarantee — it is **not** a computational-security bound or a claim about
bit-security. The library enforces only representability: values above
`smudging::MAX_LAMBDA` are rejected, while values below the deployment's own
policy minimum are accepted and are simply weaker. Since achievability
depends on the full parameter set (degree, moduli, plaintext modulus,
circuit depth), the library does not impose a universal minimum; callers
validate against their own policy.

## Usage

For a complete working example demonstrating multi-party setup, share distribution, and threshold decryption, see [`examples/trbfv_add.rs`](../../examples/trbfv_add.rs). A variant that transports the Shamir shares encrypted under per-party BFV keys is in [`examples/trbfv_add_bfv_share.rs`](../../examples/trbfv_add_bfv_share.rs). A multiplicative example using distributed *l*-BFV relinearization keys is in [`examples/trbfv_mul_bfv_share.rs`](../../examples/trbfv_mul_bfv_share.rs).

The example can be run with configurable parameters (threshold must equal `(num_parties - 1) / 2`); it is feature-gated, so build with `-p fhe --features experimental-mbfv`:
```bash
cargo run --release -p fhe --features experimental-mbfv --example trbfv_add -- --num_parties=10 --threshold=4
```

Basic usage pattern:

```rust
use fhe::trbfv::{
    FreshNoiseModel, SecretKeyShare, ShareManager, SmudgingConfig, SmudgingNoiseGenerator,
    SmudgingShare,
};

// Setup threshold scheme; each party holds its own manager instance
let mut share_manager = ShareManager::new(n_parties, threshold, params.clone())?;

// Each party: deal secret shares of its key contribution.
let secret_key_dealt = share_manager.generate_secret_key_shares(secret_key_poly, &mut rng)?;
// Explicit application transport boundary; the dealt owner is consumed here.
let secret_key_dealt = secret_key_dealt.into_transport();

// Each party: sample smudging noise with the smudging machinery, then deal
// it immediately; the noise owner is one-time material consumed by the
// dealing operation and the intermediate noise polynomial is never exposed.
// The fresh-noise model must match how `ciphertext` was encrypted.
// `max_summed_fresh_inputs` is the circuit size `m`: an upper bound on the
// fresh ciphertexts summed together before the modelled circuit (the worst
// pre-multiplication fan-in), not a count of outputs or decryptions.
let config = SmudgingConfig::new(
    params.clone(), n_parties, max_summed_fresh_inputs, lambda,
    FreshNoiseModel::BfvPublicKey,
)?.with_mult_depth(mult_depth);
let generator = SmudgingNoiseGenerator::new(config)?;
let smudging_noise = generator.generate(&mut rng)?;
let smudging_dealt = share_manager.generate_smudging_shares(smudging_noise, &mut rng)?;

// Each party: aggregate the share matrices received from the other parties
// into its share of the joint secret key (and likewise for the noise)
let secret_key_aggregate = share_manager.aggregate_secret_key_shares(
    collected_secret_key
        .into_iter()
        .map(SecretKeyShare::from_transport)
        .collect(),
)?;
let smudging_aggregate = share_manager.aggregate_smudging_shares(
    collected_smudging
        .into_iter()
        .map(SmudgingShare::from_transport)
        .collect(),
)?;

// Each decrypting party: compute a decryption share from its aggregated shares
let decryption_share =
    share_manager.decryption_share(&ciphertext, &secret_key_aggregate, smudging_aggregate)?;

// Combine exactly threshold + 1 decryption shares; reconstructing_parties
// holds the 1-based indices of the parties the shares came from
let plaintext =
    share_manager.decrypt_from_shares(&decryption_shares, &reconstructing_parties, &ciphertext)?;
```

`decryption_share` borrows the ciphertext but consumes the one-time smudging
aggregate. `decrypt_from_shares` borrows the ciphertext, decryption shares, and
party indices; callers with owned `Vec`s or `Arc<Ciphertext>` should pass
references rather than cloning or transferring them.

## Security Considerations

This implementation has not been independently audited. Use with appropriate caution in production environments.

The security of the threshold scheme relies on:
- Proper parameter selection for the underlying BFV scheme
- Secure distribution of shares among parties
- Protection of individual secret key shares
- Appropriate smudging noise generation

Shamir secret sharing operates directly on canonical RNS residues. Operations
on secret coefficients use the constant-time `Modulus` arithmetic; Lagrange
inversion depends only on public party coordinates and prime ciphertext
moduli.
