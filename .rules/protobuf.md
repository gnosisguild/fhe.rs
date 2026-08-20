# Protobuf code generation

## Scope

Serialization is feature-gated behind `protobuf` (disabled by default). `crates/fhe-math/build.rs` compiles `src/proto/rq.proto`; `crates/fhe/build.rs` compiles `src/proto/bfv/bfv.proto`; both use `prost` and require `protoc` only when enabled. Generated Rust is placed in `OUT_DIR` and never committed.

## Invariants

1. Build scripts compile protobuf only when the `protobuf` feature is enabled and otherwise require no `protoc`.
2. `protoc` is installed before feature-enabled builds.
3. The public `fhe::proto`, polynomial serialization, BFV/LBFV/MBFV serialization implementations, and serialization-dependent examples are available only with `protobuf`.
4. Core BFV operations and TRBFV/MBFV threshold protocols work without `protobuf`.
5. `LbfvBinding` and `LBFVRelinKeyShare` are serialized by public `trlbfv` types from `bfv.proto`, while operational l-BFV keys carry no binding metadata and reject it.
6. Schema changes edit the `.proto`, enable the feature to regenerate, verify generated behavior, and commit only the schema.
7. Generated code is never hand-edited, committed, or regenerated with the feature disabled.

## Evidence / tests

```bash
cargo build --features protobuf
cargo test --release --features protobuf
```

## Sync

- Touch → update: `protobuf.md` — `**/build.rs`, `**/*.proto`, `**/src/proto/**`.
