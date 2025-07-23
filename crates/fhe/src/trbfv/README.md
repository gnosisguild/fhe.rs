# Threshold BFV (TRBFV)

A pure-Rust implementation of threshold BFV homomorphic encryption based on the scheme described by Antoine Urban and Matthieu Rambaud in [Robust Multiparty Computation from Threshold Encryption Based on RLWE](https://eprint.iacr.org/2024/1285.pdf).

This module enables distributed decryption among multiple parties where only a threshold number of parties are needed to decrypt ciphertexts. The implementation provides security against up to t-1 compromised parties in a threshold scheme.

## Architecture

The module follows a modular design with clear separation of concerns:

- `shamir.rs` - Shamir Secret Sharing implementation with field operations and polynomial interpolation
- `smudging.rs` - Smudging noise generation with optimal variance calculation using arbitrary precision arithmetic  
- `shares.rs` - Share aggregation and decryption operations management
- `threshold.rs` - Main TRBFV coordinator struct
- `config.rs` - Parameter validation
- `errors.rs` - Threshold-specific error types
- `normal.rs` - Truncated Gaussian sampling for large variance noise

The module provides complete serialization support for distributed deployments:

- `serialize_secret_share()` / `deserialize_secret_share()` - For secret share matrices
- `serialize_smudging_data()` / `deserialize_smudging_data()` - For smudging polynomials  
- `serialize_decryption_share()` / `deserialize_decryption_share()` - For decryption shares
- `TRBFV::to_bytes()` / `TRBFV::from_bytes()` - For TRBFV configuration

## Usage

For a complete working example demonstrating multi-party setup, share distribution, and threshold decryption, see [`examples/trbfv_add.rs`](../../examples/trbfv_add.rs).

The example can be run with configurable parameters:
```bash
cargo run --example trbfv_add --num_parties=10 --threshold=7
```

Basic usage pattern:

```rust
use fhe::trbfv::TRBFV;

// Setup threshold scheme
let trbfv = TRBFV::new(n_parties, threshold, params)?;

// Generate and distribute secret shares
let sk_shares = trbfv.generate_secret_shares_from_poly(sk_poly)?;

// Aggregate shares for decryption  
let sk_poly_sum = trbfv.aggregate_collected_shares(&collected_shares)?;

// Generate decryption shares
let decryption_share = trbfv.decryption_share(ciphertext, sk_poly_sum, es_poly)?;

// Threshold decryption
let plaintext = trbfv.decrypt(decryption_shares, ciphertext)?;
```

## Security Considerations

This implementation has not been independently audited. Use with appropriate caution in production environments.

The security of the threshold scheme relies on:
- Proper parameter selection for the underlying BFV scheme
- Secure distribution of shares among parties
- Protection of individual secret key shares
- Appropriate smudging noise generation
