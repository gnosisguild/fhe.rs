# Threshold BFV (TRBFV)

**A pure-Rust implementation of threshold BFV homomorphic encryption.**

This module implements Threshold BFV, which enables **distributed decryption** among multiple parties where only a threshold number of parties are needed to decrypt ciphertexts. This is based on the scheme described by Antoine Urban and Matthieu Rambaud in [Robust Multiparty Computation from Threshold Encryption Based on RLWE](https://eprint.iacr.org/2024/1285.pdf).

## Key Components

The TRBFV module is built with a modular, extensible architecture:

### Secret Sharing (`secret_sharing/`)
- **`SecretSharer` trait**: General interface for secret sharing methods
- **`ShamirSecretSharing`**: Shamir Secret Sharing implementation
- **Extensible design**: Easy to add new secret sharing methods

### Smudging (`smudging/`)
- **`SmudgingGenerator` trait**: Interface for noise generation
- **`StandardSmudgingGenerator`**: Standard smudging noise implementation
- **`SmudgingConfig`**: Configuration for smudging parameters

### Share Management (`shares.rs`)
- **`ShareManager`**: Handles share aggregation and decryption operations
- **`aggregate_collected_shares()`**: Aggregates SK_i polynomial shares
- **`decrypt_from_shares()`**: Reconstructs plaintext from threshold shares

At the end, the **`TRBFV`** is the main struct coordinating all threshold operations.

## Protobuf

### Available Serialization Functions

Located in `proto::trbfv`:

- **`serialize_secret_share()`** / **`deserialize_secret_share()`**: For `Array2<u64>` secret share matrices
- **`serialize_smudging_data()`** / **`deserialize_smudging_data()`**: For `Vec<i64>` smudging coefficients  
- **`serialize_decryption_share()`** / **`deserialize_decryption_share()`**: For `Poly` decryption shares
- **`TRBFV::to_bytes()`** / **`TRBFV::from_bytes()`**: For TRBFV configuration itself

### How it works

The following is a simple workflow using protobufs for TRBFV:

```rust
use fhe::proto::trbfv::{serialize_secret_share, deserialize_secret_share};
use fhe::trbfv::TRBFV;
use fhe_traits::Serialize;

// 1. Setup phase: Share TRBFV configuration
let config_bytes = trbfv.to_bytes(); // Send to all parties

// 2. Key generation: Distribute secret shares
let shares = trbfv.generate_secret_shares(secret_key.coeffs)?;
let serialized_shares = serialize_secret_share(&shares[0]); // Send to party

// 3. Decryption phase: Collect decryption shares
let decryption_share = trbfv.decryption_share(ciphertext, sk_poly, es_poly)?;
let serialized_share = serialize_decryption_share(&decryption_share); // Send to dealer
```

## Example Usage

```rust
use fhe::bfv::{BfvParametersBuilder, SecretKey, PublicKey, Plaintext, Encoding};
use fhe::trbfv::TRBFV;
use fhe_traits::{FheEncoder, FheEncrypter};
use rand::{thread_rng, rngs::OsRng};
use std::sync::Arc;

// Setup parameters
let params = BfvParametersBuilder::new()
    .set_degree(2048)
    .set_plaintext_modulus(4096)
    .set_moduli(&[0xffffee001, 0xffffc4001, 0x1ffffe0001])
    .build_arc()?;

// Threshold configuration: 5 parties, need 3 to decrypt
let n_parties = 5;
let threshold = 3;
let smudging_variance = 160;

let mut trbfv = TRBFV::new(n_parties, threshold, smudging_variance, params.clone())?;

// Each party generates secret key shares
let sk = SecretKey::random(&params, &mut OsRng);
let sk_shares = trbfv.generate_secret_shares(sk.coeffs.clone())?;

// Generate smudging noise
let smudging_error = trbfv.generate_smudging_error(&mut OsRng)?;
let es_shares = trbfv.generate_secret_shares(smudging_error.into_boxed_slice())?;

// After network communication and share collection...
// Aggregate shares for decryption
let sk_poly_sum = trbfv.aggregate_collected_shares(&collected_sk_shares)?;
let es_poly_sum = trbfv.aggregate_collected_shares(&collected_es_shares)?;

// Generate decryption share
let decryption_share = trbfv.decryption_share(ciphertext.clone(), sk_poly_sum, es_poly_sum)?;

// Collect threshold number of decryption shares and decrypt
let plaintext = trbfv.decrypt(decryption_shares, ciphertext)?;
```

## Complete Examples

### Local Threshold Example
See [`examples/trbfv_add.rs`](../../examples/trbfv_add.rs) for a complete threshold BFV addition example that demonstrates:
- Multi-party setup with secret sharing
- Share distribution simulation
- Threshold decryption
- Performance measurements

Run it with:
```bash
cargo run --example trbfv_add --num_parties=10 --threshold=7
```

### Protobuf Serialization

The protobuf serialization functions are available in the `proto::trbfv` module and can be used for:
- Network communication between distributed parties
- Persistent storage of TRBFV configurations and shares
- Cross-platform compatibility in distributed systems

All serialization functions are thoroughly tested and production-ready for distributed deployment scenarios.

## Security Notes

⚠️ **This implementation has not been independently audited.** 

Use at your own risk in production environments.
