# fhe-math [![crate version](https://img.shields.io/crates/v/fhe-math.svg)](https://crates.io/crates/fhe-math) [![documentation](https://docs.rs/fhe-math/badge.svg)](https://docs.rs/fhe-math)

Mathematical primitives for [`fhe.rs`](https://github.com/gnosisguild/fhe.rs):
number-theoretic transforms (NTT), residue number systems (RNS), and polynomial
and modular arithmetic.

## Features

* `ntt`: number-theoretic transforms.
* `rns`: CRT contexts and scaling.
* `rq`: polynomials over modular rings.
* `zq`: modular arithmetic and prime selection.
* `tfhe-ntt`: optional accelerated transforms via [`tfhe-ntt`](https://crates.io/crates/tfhe-ntt).

## Installation

Published crate:

```toml
[dependencies]
fhe-math = "0.4.1"
```

## Testing

```bash
cargo test -p fhe-math
```

## License

This project is licensed under the [MIT license](https://opensource.org/licenses/MIT).

## Security

This crate has not been independently audited. Use at your own risk.
Variable-time arithmetic must only be enabled for public data; consult each
operation's API contract.
