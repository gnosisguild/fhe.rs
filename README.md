# fhe.rs: Fully Homomorphic Encryption in Rust

[![continuous integration](https://github.com/gnosisguild/fhe.rs/actions/workflows/rust.yml/badge.svg?branch=main)](https://github.com/gnosisguild/fhe.rs/actions/workflows/rust.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

This repository contains the `fhe.rs` library, an experimental cryptographic library in Rust for Ring-LWE-based homomorphic encryption, developed by [Tancrède Lepoint](https://tancre.de).
For more information about the library, see [fhe.rs](https://fhe.rs).

The library features:

* An implementation of a RNS-variant of the Brakerski-Fan-Vercauteren (BFV) homomorphic encryption scheme;

> **Note**
> This library is **not** related to the `tfhe-rs` library (a.k.a. `concrete`), Zama's fully homomorphic encryption in Rust, available at [tfhe.rs](https://github.com/zama-ai/tfhe-rs).

## fhe.rs crates

`fhe.rs` is implemented using the Rust programming language. The ecosystem is composed of four public crates (packages):

* [![fhe crate version](https://img.shields.io/crates/v/fhe.svg)](https://crates.io/crates/fhe) [`fhe`](https://crates.io/crates/fhe): This crate contains the implementations of the homomorphic encryption schemes;
* [![fhe-math crate version](https://img.shields.io/crates/v/fhe-math.svg)](https://crates.io/crates/fhe-math) [`fhe-math`](https://crates.io/crates/fhe-math): This crate contains the core mathematical operations for the `fhe` crate;
* [![fhe-traits crate version](https://img.shields.io/crates/v/fhe-traits.svg)](https://crates.io/crates/fhe-traits) [`fhe-traits`](https://crates.io/crates/fhe-traits): This crate contains traits for homomorphic encryption schemes;
* [![fhe-util crate version](https://img.shields.io/crates/v/fhe-util.svg)](https://crates.io/crates/fhe-util) [`fhe-util`](https://crates.io/crates/fhe-util): This crate contains utility functions for the `fhe` crate.

### Installation

To install, add the following to your project's `Cargo.toml` file:

```toml
[dependencies]
fhe = "0.4.1"
fhe-traits = "0.4.1"
```

## Minimum supported version / toolchain

Rust **1.91.1** or newer (Rust 2024 edition).

## ⚠️ Security / Stability

The implementations contained in the `fhe.rs` ecosystem have never been independently audited for security.

Use at your own risk.

Some API limits are resource policies, not security guarantees and not budgets
on total construction work: `BfvParameters::MAX_CIPHERTEXT_MODULI` bounds how
many ciphertext moduli one parameter set may hold (each accepted modulus costs
a context and scaler per modulus-switching level), and
`fhe_traits::MAX_SERIALIZED_BYTES` bounds default decoder work. Applications
constructing or deserializing parameters from untrusted sources must still
bound the polynomial degree and validate parameters before use.

### Serialization limits

By default, Protobuf-backed deserializers apply a global pre-decode cap of
`MAX_SERIALIZED_BYTES` (256 MiB, from `fhe-traits`) and reject larger
payloads with `SerializationError::PayloadTooLarge`. Very large parameter
sets can produce *legitimate* objects above that cap: the evaluation key of a
degree-32768 BFV scheme with nine 62-bit moduli and inner-sum support encodes
to roughly 309 MB.

For authenticated large keys, `EvaluationKey::from_bytes_with_request(bytes,
params, &request)` is an explicit opt-in route whose resource bound is
**derived** rather than negotiated. The application constructs an
`EvaluationKeyDecodeRequest` *locally* — from its own key configuration, the
parameters it uses, the levels it operates at, and the operations it intends
to run — and the decoder enforces an encoded-size bound computed from that
request and the validated parameters alone:

* **The bound never depends on the payload or the sender.** `wire_bound`
  multiplies the authorized Galois-key entry count (an exact exponent set or
  a local count bound) by the parameter-implied key-switching row count and
  row size, and adds checked allowances for Protobuf tags, length prefixes,
  scalar fields, and the seed. All arithmetic is checked and overflow is a
  typed error, so the derivation stays correct on 32-bit platforms. The
  payload's own length and any size a remote peer claims are never inputs.
* **The request is not authentication.** It is a shape and resource
  authorization: it cannot verify who produced the bytes. Use this route
  only for keys delivered over a trusted, authenticated channel.
* **Not an application-wide memory guarantee.** A request can legitimately
  authorize a key that costs many GiB to decode: peak memory reaches
  several times the encoded size because the encoded buffer, the decoded
  Protobuf representation, and the in-memory key coexist (the 309 MB
  reference key peaks around 4 GiB with both keys in memory). Applications
  with a smaller footprint can check `bytes.len()` against their own policy
  before calling, or authorize a tighter request.
* **The opt-in route is schema-pinned.** The preflight rejects the payload
  unless its levels, Galois-key entries, and key-switching row form
  (regenerating seed or explicit rows) match the request — for exact
  requests this means the full authorized exponent set must be present, so
  a key carrying only a subset is rejected — and unknown Protobuf fields
  are rejected at the evaluation-key, Galois-key and key-switching-key scopes.
  Unknown fields inside a polynomial row may be skipped by the decoder, but
  its encoded length must stay within the row's fixed slack allowance.
  Requests that authorize more distinct entries than substitution
  exponents exist for the parameters are themselves rejected when the
  bound is derived, instead of silently loosening it. The decomposition
  base and row counts are not caller-controlled: they are derived from the
  validated parameters and levels, exactly as the constructors produce
  them. A payload that is valid for the default route may therefore be
  rejected here, with a typed error, and vice versa.
* **Decoder work stays bounded.** Before `prost` materializes the message,
  a zero-copy wire preflight (the scan borrows the payload; its
  acceptance-path allocations are bounded sets independent of the payload
  size) enforces the parameter-implied shape (exact key-switching row
  counts and bounded row lengths, level consistency, seed placement),
  rejects duplicate Galois-key exponents, repeated scalar fields, and
  varints wider than the declared `uint32` fields, so malformed payloads
  fail with typed errors before significant memory is committed.
  Post-decode validation is unchanged and remains authoritative.

## Verification

The repository's normal verification commands are:

```bash
cargo test --workspace
cargo check --workspace --all-targets --all-features
cargo test --release --workspace --all-features
cargo +nightly fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
```

Pull-request CI runs the workspace integration tests with
`cargo test --workspace --release --tests`, in both the
`--no-default-features` and `--all-features` configurations. The `--tests`
flag auto-discovers `tests/*.rs` targets, so newly added integration tests
gate merges without a hand-maintained `--test` list (unless a Cargo manifest
explicitly opts a target out). This includes the threshold BFV and distributed
l-BFV end-to-end tests and the parameter profile checks; the `secure8192`
profile check pins an exact smudging bound
while the `secure16384` profile check covers feasibility. Test targets that
require features are exercised by the `--all-features` leg. The heavy threshold
stress run remains an additional post-`main` job in
`.github/workflows/stress.yml`. Examples and criterion benchmarks are never
executed as tests.

Protobuf schemas and their generated Rust sources are checked in. Normal builds
compile the checked-in Rust sources and do not require `protoc`. A schema change
must update its generated Rust source in the same change. Regenerate all sources
with the pinned `prost-build` 0.14.4 and vendored `protoc` 31.1 toolchain by
running:

```bash
./scripts/regenerate-protos.sh
```

The test parameter profiles are named `insecure`, `secure8192`, and
`secure16384`. The `insecure` profile provides fast breadth and negative
coverage only: it uses degree-128 threshold and share-transport parameters,
lambda 2, and a depth-3 test configuration. The
larger profiles exercise production-like parameter ranges but do not constitute
a cryptographic security proof. Serialization is an unconditional part of the
current crate API, so CI tests both default/no-default core builds and the
all-features serialization boundary.

The `bfv_default_128` smoke test selects a profile from the library's
`default_parameters_128` table. It verifies BFV functionality for that profile;
the test name is not an independent security claim.

Repository-only profiles and deterministic RNG helpers live in
`crates/fhe/support/mod.rs`, shared by the test, example, and benchmark targets
without becoming part of the public `fhe` API. Fast profile and API checks are
kept separate from the full threshold BFV and distributed l-BFV workflows in
`crates/fhe/tests/trbfv_e2e.rs` and `crates/fhe/tests/trlbfv_e2e.rs`. Both
categories gate pull requests through the CI integration-test matrix described
above.
