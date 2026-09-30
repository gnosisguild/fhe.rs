# fhe-traits [![crate version](https://img.shields.io/crates/v/fhe-traits.svg)](https://crates.io/crates/fhe-traits) [![documentation](https://docs.rs/fhe-traits/badge.svg)](https://docs.rs/fhe-traits)

Shared interfaces for the [`fhe.rs`](https://github.com/gnosisguild/fhe.rs)
crates: parameters, encoding, encryption, decryption, and serialization.
It also defines explicit public-data/variable-time capabilities and the
default serialized-payload limit.

## Installation

Published crate:

```toml
[dependencies]
fhe-traits = "0.4.1"
```

## Testing

```bash
cargo test -p fhe-traits
```

## License

This project is licensed under the [MIT license](https://opensource.org/licenses/MIT).

## Security

This crate has not been independently audited. Use at your own risk.
Marking data public is a caller assertion, not a check performed by the library.
