# Threshold BFV (TRBFV)

A pure-Rust implementation of threshold BFV homomorphic encryption based on the work of Antoine Urban and Matthieu Rambaud in [Robust Multiparty Computation from Threshold Encryption Based on RLWE](https://eprint.iacr.org/2024/1285.pdf).
The current implemenation is a passively secure version of the protocol (and so without PVSS etc). Also we omit for now the generation of the relinearization keys as we only perform additions over ciphertexts (and so the scheme we use for now for encryption is bfv described in section 4.1, and not lbfv described in section 4.3).



This module enables distributed decryption between `n` parties without necessarily involving all of them: any `threshold + 1` of the `n` parties can decrypt a ciphertext, while any coalition of at most `threshold` parties learns nothing. The threshold must be exactly `(n-1)/2` (integer division), the maximal corruption tolerance under an honest majority — see `config.rs` for the derivation.

## Architecture

The module follows a modular design with clear separation of concerns:

- `shamir.rs` - Shamir Secret Sharing implementation with field operations and polynomial interpolation
- `smudging.rs` - Smudging noise generation with optimal variance calculation using arbitrary precision arithmetic  
- `shares.rs` - Share aggregation and decryption operations management
- `threshold.rs` - Main TRBFV coordinator struct
- `config.rs` - Parameter validation
- `errors.rs` - Threshold-specific error types
- `normal.rs` - Truncated Gaussian sampling for large variance noise

## Usage

For a complete working example demonstrating multi-party setup, share distribution, and threshold decryption, see [`examples/trbfv_add.rs`](../../examples/trbfv_add.rs). A variant that transports the Shamir shares encrypted under per-party BFV keys is in [`examples/trbfv_add_bfv_share.rs`](../../examples/trbfv_add_bfv_share.rs).

The example can be run with configurable parameters (threshold must equal `(num_parties - 1) / 2`):
```bash
cargo run --release --example trbfv_add -- --num_parties=10 --threshold=4
```

Basic usage pattern:

```rust
use fhe::trbfv::TRBFV;

// Setup threshold scheme
let trbfv = TRBFV::new(n_parties, threshold, params.clone())?;

// Each party: deal secret shares of its key and smudging noise contributions
let sk_shares = trbfv.generate_secret_shares_from_poly(sk_poly, &mut rng)?;
let es_coeffs = trbfv.generate_smudging_error(num_ciphertexts, lambda, &mut rng)?;

// Each party: aggregate the share matrices received from the other parties
// into its share of the joint secret key (and likewise for the noise)
let sk_poly_sum = trbfv.aggregate_collected_shares(&collected_sk_shares)?;
let es_poly_sum = trbfv.aggregate_collected_shares(&collected_es_shares)?;

// Each decrypting party: compute a decryption share from its aggregated shares
let d_share = trbfv.decryption_share(ciphertext.clone(), sk_poly_sum.into_ntt(), es_poly_sum)?;

// Combine exactly threshold + 1 decryption shares; reconstructing_parties
// holds the 1-based indices of the parties the shares came from
let plaintext = trbfv.decrypt(d_share_polys, reconstructing_parties, ciphertext)?;
```

## Security Considerations

This implementation has not been independently audited. Use with appropriate caution in production environments.

The security of the threshold scheme relies on:
- Proper parameter selection for the underlying BFV scheme
- Secure distribution of shares among parties
- Protection of individual secret key shares
- Appropriate smudging noise generation
