# fhe-util [![fhe-util version](https://img.shields.io/badge/fhe--util-0.3.0-blue.svg)](https://github.com/gnosisguild/fhe.rs/tree/core/main/crates/fhe-util) [![documentation](https://docs.rs/fhe-util/badge.svg)](https://docs.rs/fhe-util)

Utility functions for the [`fhe.rs`](https://github.com/gnosisguild/fhe.rs) ecosystem.

The crate contains helper routines such as primality testing, centered binomial sampling, modular arithmetic helpers and other small utilities relied upon by the [`fhe`](https://crates.io/crates/fhe) and `fhe-math` crates.

## Installation

```toml
[dependencies]
fhe-util = { git = "https://github.com/gnosisguild/fhe.rs", branch = "core/main" }
```

## Testing

```bash
cargo test -p fhe-util
```

## License

This project is licensed under the [MIT license](https://opensource.org/licenses/MIT).

## Security / Stability

The code in this crate has not undergone an independent security audit.
Use at your own risk.
