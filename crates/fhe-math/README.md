# fhe-math [![fhe-math version](https://img.shields.io/badge/fhe--math-0.3.0-blue.svg)](https://github.com/gnosisguild/fhe.rs/tree/core/main/crates/fhe-math) [![documentation](https://docs.rs/fhe-math/badge.svg)](https://docs.rs/fhe-math)

Core mathematical primitives for the [`fhe.rs`](https://github.com/gnosisguild/fhe.rs) ecosystem.

This crate exposes building blocks such as number theoretic transforms (NTT), residue number system (RNS) arithmetic, and ring arithmetic over `Z_q` that are used by higher level crates like [`fhe`](https://crates.io/crates/fhe).

## Features

* `ntt`, `rns`, `rq`, and `zq` modules for modular arithmetic over large rings.
* Optional `tfhe-ntt` features to enable hardware accelerated NTTs via the [`tfhe-ntt`](https://crates.io/crates/tfhe-ntt) crate.

## Installation

Add the following to your `Cargo.toml`:

The `0.3.0` crate is currently available from the `core/main` branch and will be published to crates.io in the release process.

```toml
[dependencies]
fhe-math = { git = "https://github.com/gnosisguild/fhe.rs", branch = "core/main" }
```

## Testing

```bash
cargo test -p fhe-math
```

## License

This project is licensed under the [MIT license](https://opensource.org/licenses/MIT).

## Security / Stability

The code in this crate has not undergone an independent security audit.
Use at your own risk.
