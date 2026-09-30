# fhe.rs: Fully Homomorphic Encryption in Rust

[![continuous integration](https://github.com/gnosisguild/fhe.rs/actions/workflows/rust.yml/badge.svg?branch=main)](https://github.com/gnosisguild/fhe.rs/actions/workflows/rust.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

`fhe.rs` is an experimental Rust library for Ring-LWE-based homomorphic
encryption, developed by [Tancrède Lepoint](https://tancre.de). It implements
leveled BFV, l-BFV operational keys, and threshold sharing and decryption.
See [fhe.rs](https://fhe.rs) for more information.

This project is separate from Zama's [tfhe-rs](https://github.com/zama-ai/tfhe-rs).

## Crates

| Crate | Purpose |
| ----- | ------- |
| [`fhe`](crates/fhe/README.md) | Encryption schemes, keys, and homomorphic operations |
| [`fhe-math`](crates/fhe-math/README.md) | NTT, RNS, and polynomial arithmetic |
| [`fhe-traits`](crates/fhe-traits/README.md) | Shared encryption and serialization interfaces |
| [`fhe-util`](crates/fhe-util/README.md) | Sampling, primality, and modular arithmetic helpers |

## Installation

The published crates are available on crates.io:

```toml
[dependencies]
fhe = "0.4.1"
fhe-traits = "0.4.1"
```

Repository builds require Rust **1.91.1** or newer (Rust 2024 edition).
Use nightly for formatting.

## Usage

See the [`fhe` README](crates/fhe/README.md) for a BFV example and Cargo features,
and the [threshold BFV guide](crates/fhe/src/trbfv/README.md) for sharing,
smudging, and decryption. Runnable examples are in
[`crates/fhe/examples/`](crates/fhe/examples/).

## Security

The library has not been independently audited. Use at your own risk.
The `experimental-mbfv` feature exposes incomplete protocols and must not be
used in production or to protect sensitive data.

Threshold primitives are not a complete robust multiparty protocol.
Applications must supply authenticated transport, participant and session
binding, and replay prevention; see the [implementation boundary](crates/fhe/src/trbfv/README.md#implementation-boundary).

Resource limits are not security guarantees. Applications accepting untrusted
parameters must enforce their own degree, modulus-count, and construction-work
budgets in addition to the library's parameter validation.

### Serialization limits

Protobuf-backed deserializers reject payloads above
`fhe_traits::MAX_SERIALIZED_BYTES` (256 MiB) before decoding.
For larger evaluation keys, `EvaluationKey::from_bytes_with_request` derives
a bound from validated BFV parameters and a locally constructed
`EvaluationKeyDecodeRequest`. Never derive that authorization from received
bytes or a sender's size claims.

This opt-in route requires trusted, authenticated delivery; the request itself
does not authenticate a key. Its wire preflight enforces the authorized shape
and rejects unknown fields at key scopes. Polynomial-row unknown fields are
allowed only within fixed length slack. The bound limits encoded bytes, not
peak memory; apply a tighter application budget when needed. For scale, a
degree-32768 inner-sum key with nine 62-bit moduli encodes to roughly 309 MB;
its roundtrip test has used about 4 GiB of peak process memory with both
original and decoded keys retained. Full contracts are documented on
`EvaluationKeyDecodeRequest` and
`EvaluationKey::from_bytes_with_request`.

## Development

```bash
cargo test --workspace
cargo test --workspace --release --all-features
cargo test --workspace --release --no-default-features
cargo +nightly fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
```

CI checks tests and doctests with all/no-default features, examples, benchmarks,
formatting, Clippy, rustdoc, and generated Protobuf sources. Release integration
tests include the larger threshold BFV and l-BFV end-to-end profiles.

Test profiles and deterministic RNG helpers live in
[`crates/fhe/support/mod.rs`](crates/fhe/support/mod.rs), outside the public API.
`insecure` is for fast testing only. `secure8192` and `secure16384` exercise
larger parameter sets; neither the names nor passing tests establish security.

Protobuf schemas and generated Rust are checked in; normal builds do not
require `protoc`. After a schema change, regenerate and commit the Rust sources:

```bash
./scripts/regenerate-protos.sh
```

The script pins `prost-build` 0.14.4 and vendored `protoc` 31.1.
