# fhe.rs: Fully Homomorphic Encryption in Rust

[![continuous integration](https://github.com/gnosisguild/fhe.rs/actions/workflows/rust.yml/badge.svg?branch=main)](https://github.com/gnosisguild/fhe.rs/actions/workflows/rust.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

This repository contains the `fhe.rs` library, an experimental cryptographic library in Rust for Ring-LWE-based homomorphic encryption, developed by [Tancrède Lepoint](https://tancre.de) and [Gnosis Guild](https://github.com/gnosisguild).
For more information about the library, see [fhe.rs](https://fhe.rs).

The library features:

* An implementation of an RNS variant of the Brakerski-Fan-Vercauteren (BFV) homomorphic encryption scheme;
* l-BFV relinearization and threshold BFV APIs;
* Experimental multiparty BFV APIs behind the `experimental-mbfv` feature;
* Performances comparable or better than state-of-the-art libraries in C++ and Go.

> **Note**
> This library is **not** related to the `tfhe-rs` library (a.k.a. `concrete`), Zama's fully homomorphic encryption in Rust, available at [tfhe.rs](https://github.com/zama-ai/tfhe-rs).

## fhe.rs crates

`fhe.rs` is implemented using the Rust programming language. The ecosystem is composed of four public crates (packages):

* [![fhe version](https://img.shields.io/badge/fhe-0.3.0-blue.svg)](https://github.com/gnosisguild/fhe.rs/tree/core/main/crates/fhe) [`fhe`](https://github.com/gnosisguild/fhe.rs/tree/core/main/crates/fhe): This crate contains the BFV, l-BFV, and threshold BFV implementations;
* [![fhe-math version](https://img.shields.io/badge/fhe--math-0.3.0-blue.svg)](https://github.com/gnosisguild/fhe.rs/tree/core/main/crates/fhe-math) [`fhe-math`](https://github.com/gnosisguild/fhe.rs/tree/core/main/crates/fhe-math): This crate contains the core mathematical operations for the `fhe` crate;
* [![fhe-traits version](https://img.shields.io/badge/fhe--traits-0.3.0-blue.svg)](https://github.com/gnosisguild/fhe.rs/tree/core/main/crates/fhe-traits) [`fhe-traits`](https://github.com/gnosisguild/fhe.rs/tree/core/main/crates/fhe-traits): This crate contains traits for homomorphic encryption schemes;
* [![fhe-util version](https://img.shields.io/badge/fhe--util-0.3.0-blue.svg)](https://github.com/gnosisguild/fhe.rs/tree/core/main/crates/fhe-util) [`fhe-util`](https://github.com/gnosisguild/fhe.rs/tree/core/main/crates/fhe-util): This crate contains utility functions for the `fhe` crate.

### Installation

To install, add the following to your project's `Cargo.toml` file:

The `0.3.0` crates are currently available from the `core/main` branch and will be published to crates.io in the release process.

```toml
[dependencies]
fhe = { git = "https://github.com/gnosisguild/fhe.rs", branch = "core/main" }
fhe-traits = { git = "https://github.com/gnosisguild/fhe.rs", branch = "core/main" }
```

## Minimum supported version / toolchain

Rust **1.91.1** or newer (Rust 2024 edition).

## ⚠️ Security / Stability

The implementations contained in the `fhe.rs` ecosystem have never been independently audited for security.

Use at your own risk.
