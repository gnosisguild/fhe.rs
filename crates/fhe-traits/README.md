# fhe-traits [![fhe-traits version](https://img.shields.io/badge/fhe--traits-0.3.0-blue.svg)](https://github.com/gnosisguild/fhe.rs/tree/core/main/crates/fhe-traits) [![documentation](https://docs.rs/fhe-traits/badge.svg)](https://docs.rs/fhe-traits)

Traits defining the interface for fully homomorphic encryption types and operations.

This crate provides common abstractions for parameters, plaintext and ciphertext representations, encoding, encryption, decryption and serialization used throughout the [`fhe.rs`](https://github.com/gnosisguild/fhe.rs) crates.

## Installation

```toml
[dependencies]
fhe-traits = { git = "https://github.com/gnosisguild/fhe.rs", branch = "core/main" }
```

## Testing

```bash
cargo test -p fhe-traits
```

## License

This project is licensed under the [MIT license](https://opensource.org/licenses/MIT).

## Security / Stability

The code in this crate has not undergone an independent security audit.
Use at your own risk.
