# Protobuf code generation

## How it works

Protobuf-based serialization is feature-gated behind the `protobuf` feature, which is **disabled by default**.

When enabled, proto files compile to Rust via `prost` at build time, driven by `build.rs` scripts:

- `crates/fhe-math/build.rs` — compiles `src/proto/rq.proto` into `OUT_DIR`. Requires `protoc` to be installed.
- `crates/fhe/build.rs` — compiles `src/proto/bfv/bfv.proto` and `src/proto/trbfv/trbfv.proto` into `OUT_DIR`. BFV is compiled first because TRBFV imports from it. Requires `protoc` to be installed.

When the `protobuf` feature is disabled, the build scripts do nothing and no `protoc` is required. Serialization implementations (`Serialize`, `DeserializeParametrized`, `DeserializeWithContext`) are not available in this mode.

## Enabling protobuf

```bash
cargo build --features protobuf
cargo test --release --features protobuf
```

This requires `protoc` (the protobuf compiler) to be installed on the system.

## What is feature-gated

The following are only available with `--features protobuf`:

- `fhe::proto` module (public API)
- `fhe-math` protobuf polynomial serialization (`Poly::to_bytes`, `Poly::from_bytes`)
- BFV/LBFV/MBFV `Serialize`, `DeserializeParametrized`, and `DeserializeWithContext` implementations
- Serialization-dependent examples (`mulpir`, `sealpir`, `rgsw`)

Core BFV encryption, homomorphic operations, and threshold protocols (TRBFV, MBFV) work without the feature.

The `LbfvBinding` message and the `LBFVRelinKeyShare` message (including binding fields on `LBFVPublicKey` and `LBFVRelinearizationKey`) are generated from `crates/fhe/src/proto/bfv/bfv.proto`. Generated Rust code lives in `OUT_DIR` and is never committed.

## When changing .proto files

1. Edit the `.proto` file
2. Enable the feature: `cargo build --features protobuf`
3. Verify the generated code reflects your changes
4. Commit the `.proto` file (generated code is not committed — it is produced in `OUT_DIR` at build time)

## What not to do

- Do not manually edit generated code — it is produced in `OUT_DIR` by the build script
- Do not commit generated `.rs` files — they are build output
