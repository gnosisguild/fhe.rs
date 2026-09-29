# Threshold BFV (TRBFV)

A pure-Rust implementation of threshold BFV homomorphic encryption based on the work of Antoine Urban and Matthieu Rambaud in [Robust Multiparty Computation from Threshold Encryption Based on RLWE](https://eprint.iacr.org/2024/1285.pdf) (Urban–Rambaud 2024).

The current implementation covers Shamir sharing, smudging noise, and
threshold decryption with additive and limited multiplicative support via
distributed *l*-BFV relinearization keys. It is **not** the complete robust
protocol from the paper: there is no distributed key generation, no broadcast
channel, no FLSS (function-linear secret sharing), and no GURS (guaranteed
uniform random string) generation. The smudging exchange is assumed to have
already happened out of band.

This module enables distributed decryption between `n` parties without necessarily involving all of them: any `threshold + 1` of the `n` parties can decrypt a ciphertext, while any coalition of at most `threshold` parties learns nothing. The threshold must be exactly `(n-1)/2` (integer division), the maximal corruption tolerance under an honest majority — see `config.rs` for the derivation.

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
| ZK proofs and application wire formats | Must be supplied externally. `SmudgingNoiseWitness::into_proof_bytes` exports the exact RNS-encoded noise a proof can be built against, but the proof system itself is external. |

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
- `transport.rs` - the explicit versioned transport envelope, the opt-in proof-witness API, and the consuming persistence boundary for the aggregate owners
- `config.rs` - Parameter validation
- `errors.rs` - Threshold-specific error types

The former public `trbfv::shamir` module and `ShamirSecretSharing` type were
removed when share generation and reconstruction moved to direct RNS
arithmetic. Callers should use `ShareManager`; its high-level share
generation, aggregation, and reconstruction APIs retain the same logical share
layout.

> **Breaking change:** the `TRBFV` orchestrator struct has been removed;
> `ShareManager` is the single public trBFV type (`ShareManager::
> decrypt_from_shares` is the former `TRBFV::decrypt`). Smudging noise is
> generated directly with the smudging module's public machinery:
> `SmudgingConfig::new` (pass the [`FreshNoiseModel`](smudging/bound.rs) that
> matches the encryption path of the input ciphertexts, and chain
> `.with_mult_depth(depth)` when needed) →
> `SmudgingNoiseGenerator::new` → `generate`. Sampled noise remains a non-cloneable
> `SmudgingNoise` owner that must be dealt with
> `ShareManager::generate_smudging_shares`, which consumes
> it, and `ShareManager::bigints_to_poly` has been removed. Downstream code
> doing generate-then-convert must migrate to the generate-then-deal flow
> shown under [Usage](#usage); the old symbols fail to compile by design,
> since a cloneable noise representation cannot enforce one-time use.

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
The opt-in persistence and witness APIs documented in
[Proof Witnesses and the Persistence Boundary](#proof-witnesses-and-the-persistence-boundary)
are that explicit boundary; they do not extend one-time semantics to bytes.

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

This module implements sharing, smudging, and decryption — it does **not**
include the complete robust protocol stack from Urban–Rambaud&nbsp;2024:
- No distributed key generation (DKG).
- No authenticated broadcast channel.
- No FLSS pre-processing or GURS generation.
- No proactive refresh or identifiable-abort mechanisms.

Callers who need full end-to-end robust threshold FHE must provide these
components externally.

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

## Proof Witnesses and the Persistence Boundary

Some applications must persist threshold owners across a restart, or hand an
external zero-knowledge proof system (for example a C6-style proof of correct
decryption) the exact noise behind one dealing or one decryption. The library
supports both behind an explicit, opt-in boundary. Every existing owner stays
non-cloneable with private fields and no raw polynomial accessor; the boundary
adds consuming operations only:

| Operation | Consumes | Returns |
| --------- | -------- | ------- |
| `ShareManager::generate_smudging_shares_with_witness` | the sampled `SmudgingNoise` | dealt shares plus a `SmudgingNoiseWitness` of the exact dealt noise |
| `ShareManager::decryption_share_with_witness` | one `AggregatedSmudgingShare` (so no second decryption can use the live owner) | the decryption share plus a `SmudgingNoiseWitness` of the exact noise used |
| `AggregatedSecretKeyShare::into_persisted_bytes` / `from_persisted_bytes` | the key owner / the envelope bytes | `Zeroizing<Vec<u8>>` / a restored reusable owner |
| `AggregatedSmudgingShare::into_persisted_bytes` / `from_persisted_bytes` | the noise owner / the envelope bytes | `Zeroizing<Vec<u8>>` / a restored single-use owner |
| `SmudgingNoiseWitness::into_proof_bytes` / `validate_proof_bytes` | the witness / borrowed bytes | `Zeroizing<Vec<u8>>` / validation only |

Both witness call sites run their binding checks before reading the noise or
consuming RNG (dealing), or before any secret-dependent arithmetic
(decryption); a failed call consumes and wipes the owners and produces no
witness. For decryption this means both aggregated owners must have been
aggregated (or imported) under the manager's exact parameter set — an owner
recorded under a same-ring parameter set with a different plaintext modulus
or error variance is rejected before the witness copy, so a witness is only
ever labeled with parameters its owners were validated against. Witnesses
stay in RNS residue encoding: converting them into the
centered integers a specific proof system expects is an integrator
responsibility, as is binding a witness to the ciphertext, decryption domain,
and proof statement it supports. There is no raw noise accessor — the only
escape from a witness is its consuming export.

### Envelope format

Every payload produced by `into_persisted_bytes` / `into_proof_bytes` is a
versioned, role-tagged envelope reusing the existing serialization formats:

```text
offset 0..4    magic "FTRS"
offset 4       role tag (1 key aggregate, 2 noise aggregate,
               3 dealt-noise witness, 4 decryption-noise witness)
offset 5       format version (currently 1)
offset 6..10   parameter-section length, u32 little-endian
offset 10..14  polynomial-section length, u32 little-endian
offset 14..    serialized BFV parameters, then the serialized RNS
               polynomial (the existing Poly protobuf encoding)
```

Import and validation proceed in three phases, in the actual order:

1. *Envelope-level checks*, on lengths and headers alone: the whole input is
   within the common serialization bound, the header is complete, the magic
   matches, the role tag is known and matches the imported type (a key
   payload cannot be imported as noise or read as a witness), the format
   version is implemented, both declared section lengths are within the
   common bound, both sections are fully present (no truncation), and there
   is no trailing data. Declared lengths are bounds-checked against the
   actual input before any section is sliced or decoded.
2. *Parameter section*: decoded — which fully validates it — and compared by
   value against the importing parameters. Full value equality binds the
   payload to every parameter field (plaintext modulus, moduli, degree, error
   variances), a stronger check than ring-context equality.
3. *Polynomial payload*: decoded at level 0; this decode itself validates the
   polynomial's representation, shape, and canonical RNS residues.

### Threat model

The boundary separates what the library can enforce from what it cannot.

Guaranteed by the library:

- Live owners are unique: non-cloneable types with private fields, no raw
  noise accessor, no generic `Serialize`/`Deserialize` on owners.
- Export and import are consuming: an exported owner cannot be exported twice
  without passing through an import, and decryption consumes the noise
  aggregate even in the witness-returning variant.
- Every *secret-bearing* buffer the boundary owns is wiped — the owner
  polynomials, the envelope buffer, the exported polynomial copy, a consumed
  import envelope (on success and on every rejection), and a successfully
  decoded proof polynomial. The serialized parameter section is public data
  and is intentionally kept in an ordinary, unwiped buffer. The one exception
  class for secret material is the serializer-internal transients described
  under *Known memory limits* below, which the boundary does not own and
  cannot erase.
- Payloads are role-, version-, and parameter-bound. Envelope-level bounds
  and header checks run before any section is decoded; the embedded
  parameters are then decoded and compared, and the polynomial payload is
  decoded and validated (representation, shape, canonical residues) in turn.
  Both decryption variants additionally bind the aggregated owners to the
  manager's full parameter set before any secret-dependent arithmetic, so
  same-ring owners recorded under a different plaintext modulus or error
  variance are rejected even if they never crossed the transport boundary.

Ends at the boundary (integrator responsibilities):

- Copyability of bytes. A `Zeroizing<Vec<u8>>` envelope may be cloned *after*
  the boundary, and any copy made before an import is outside library control.
  No in-memory Rust type can prevent copying, and the library does not try.
- One-time semantics. They are a property of live values only: importing the
  same noise-aggregate bytes twice yields two independent single-use owners.
  The library cannot detect that replay; the application must bind each
  imported owner to one ciphertext and decryption domain and durably prevent
  duplicate use across restarts and retries.
- Authentication and confidentiality of stored bytes. The envelope is
  unauthenticated plaintext: *validation is not authentication*, and any party
  can craft a payload that passes every check. Corrupting a payload byte can
  also yield different-but-valid material rather than an error. Encrypt and
  authenticate persisted bytes at the application layer.
- Witness identity and proof semantics. The library cannot tell which
  ciphertext, decryption domain, session, or proof statement a witness (or a
  restored owner) belongs to; integrators own that binding, the conversion to
  proof-specific centered integers, and the retry/replay policy.

Known memory limits: `Poly::to_bytes`/`Poly::from_bytes` (in `fhe-math`) build
transient internal buffers that the math crate does not wipe, including on a
failed import's error path. The transport boundary wipes every secret-bearing
buffer it owns — the envelope, the exported polynomial copy, the consumed
input, and a successfully decoded proof polynomial; the public parameter
serialization is intentionally left unwiped — but it cannot erase those
serializer-internal transients. This is an honest limitation of the current
serialization path, not a property of the envelope format.

### Ownership table

| Concern | Owner |
| ------- | ----- |
| Envelope format, role/version tags, parameter-set binding | `fhe.rs` |
| Bounded decoding, representation/shape/canonical-residue validation | `fhe.rs` |
| Zeroizing of secret-bearing owner-controlled storage (owner polynomials, envelopes, consumed import input, decoded proof polynomials) | `fhe.rs` |
| One-live-owner guarantees for live values (end at export or witness creation) | `fhe.rs` |
| Copying, authentication, and encryption-at-rest of exported bytes | Integrator |
| Ciphertext/decryption-domain/session identity of witnesses and restored owners | Integrator |
| One-time semantics and durable replay prevention across restarts | Integrator |
| RNS-to-centered-integer conversion for proof systems | Integrator |
| Retries, duplicate detection, and replay of previous results | Integrator |

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
references rather than cloning or transferring them. Both decryption-share
variants now validate the *full* recorded parameter set of the aggregated
owners against the manager's parameters — after the ciphertext checks, before
any secret-dependent arithmetic — so same-ring owners recorded under a
different plaintext modulus or error variance are rejected; previously only
the ring context was checked. Aggregates built by `aggregate_secret_key_shares`
and `aggregate_smudging_shares` always record the manager's own parameters, so
the supported flows are unaffected.

The opt-in witness and persistence variants are documented in
[Proof Witnesses and the Persistence Boundary](#proof-witnesses-and-the-persistence-boundary):
`generate_smudging_shares_with_witness` and `decryption_share_with_witness`
return the same results plus a `SmudgingNoiseWitness` of the exact noise, and
`into_persisted_bytes`/`from_persisted_bytes` on the two aggregate types carry
an owner across an application restart.

## Security Considerations

This implementation has not been independently audited. Use with appropriate caution in production environments.

The security of the threshold scheme relies on:
- Proper parameter selection for the underlying BFV scheme
- Secure distribution of shares among parties
- Protection of individual secret key shares
- Appropriate smudging noise generation

Exported persistence bytes and exported witnesses are as sensitive as the
owners they came from, have no one-time semantics, and are unauthenticated;
see [Proof Witnesses and the Persistence Boundary](#proof-witnesses-and-the-persistence-boundary)
for the boundary's threat model and the integrator-owned responsibilities.

Shamir secret sharing operates directly on canonical RNS residues. Operations
on secret coefficients use the constant-time `Modulus` arithmetic; Lagrange
inversion depends only on public party coordinates and prime ciphertext
moduli.
