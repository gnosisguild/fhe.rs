# fhe [![fhe crate version](https://img.shields.io/crates/v/fhe.svg)](https://crates.io/crates/fhe) [![documentation](https://docs.rs/fhe/badge.svg)](https://docs.rs/fhe)

Ring-LWE-based homomorphic encryption in Rust: compute additions and
multiplications without decrypting the inputs.

* `bfv`: leveled Brakerski–Fan–Vercauteren encryption using the
  [HPS RNS variant](https://eprint.iacr.org/2018/117).
* `lbfv`: linear-BFV operational public and relinearization keys.
* `trlbfv`: additive contributions and aggregation for l-BFV keys.
* `trbfv`: Shamir sharing, smudging, and threshold decryption;
  see the [threshold guide](src/trbfv/README.md).

## Installation

Published crates:

```toml
[dependencies]
fhe = "0.4.1"
fhe-traits = "0.4.1"
```

## Cargo features

* `tfhe-ntt` enables the accelerated NTT implementation from `tfhe-ntt`.
* `experimental-mbfv` exposes the incomplete multiparty BFV APIs. These APIs
  have additional unresolved security requirements and must not be used in
  production or to protect sensitive data.

## Example

Multiply a secret-key encryption of `20` by a public-key encryption of `-7`.
These parameters illustrate the API; they are not a deployment recommendation.

```rust
use fhe::bfv::{BfvParametersBuilder, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey};
use fhe_traits::*;
use rand::rng;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let parameters = BfvParametersBuilder::new()
            .set_degree(2048)
            .set_moduli(&[0x3fffffff000001])
            .set_plaintext_modulus(1 << 10)
            .build_arc()?;
    let mut rng = rng();
    let secret_key = SecretKey::random(&parameters, &mut rng);
    let public_key = PublicKey::new(&secret_key, &mut rng)?;

    let plaintext_1 = Plaintext::try_encode(&[20_u64], Encoding::poly(), &parameters)?;
    let plaintext_2 = Plaintext::try_encode(&[-7_i64], Encoding::poly(), &parameters)?;

    let ciphertext_1: Ciphertext = secret_key.try_encrypt(&plaintext_1, &mut rng)?;
    let ciphertext_2: Ciphertext = public_key.try_encrypt(&plaintext_2, &mut rng)?;

    let result = &ciphertext_1 * &ciphertext_2;

    let decrypted_plaintext = secret_key.try_decrypt(&result)?;
    let decrypted_vector = Vec::<i64>::try_decode(&decrypted_plaintext, Encoding::poly())?;

    assert_eq!(decrypted_vector[0], -140);

    Ok(())
}
```

Arithmetic is modulo the plaintext modulus, here `1024`. `Encoding::poly()`
encodes polynomial coefficients in `Z_1024[x] / (x^2048 + 1)`, so a single
value occupies the constant coefficient. `Encoding::simd()` supports slot-wise
arithmetic when the plaintext modulus is `1` modulo twice the ring degree.

## Examples

Runnable examples are in [`examples/`](./examples/), including
[SealPIR](https://eprint.iacr.org/2017/1142) and
[MulPIR](https://eprint.iacr.org/2019/1483):

```bash
cargo run --release --example sealpir
cargo run --release --example mulpir
```

## Serialization

Protobuf-backed decoders apply a 256 MiB pre-decode limit. Larger evaluation
keys require a locally authorized `EvaluationKeyDecodeRequest`; see the
[serialization limits](../../README.md#serialization-limits).

l-BFV public keys and contributions serialize as seeded or explicit
representations. Seeds compress CRS rows; they do not authenticate the CRS.
A level-0 `LBFVRelinearizationKey` can reconstruct its public key with
`reconstruct_public_key`, avoiding duplicate transport of the same rows.

## Benchmarks and tests

Benchmarks use [Criterion](https://criterion.rs). The serialization benchmark
compares seeded and explicit l-BFV public keys:

```bash
cargo bench -p fhe --bench lbfv_serialization
cargo test -p fhe
```

## Security

This crate has not been independently audited. Use at your own risk.
Multiparty primitives validate arithmetic structure, not contributor honesty
or identity. Authentication, reference-string generation, session binding,
and replay prevention belong to the surrounding protocol.
l-BFV relinearization also relies on the cited construction's circular-security
assumption; see the `lbfv` module documentation.
