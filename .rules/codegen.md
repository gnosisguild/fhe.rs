# Protobuf code generation

## How it works

Proto files compile to Rust via `prost` at build time, driven by `build.rs` scripts:

- `crates/fhe-math/build.rs` — compiles `src/proto/rq.proto` into `OUT_DIR`. If `protoc` is unavailable, falls back to the committed pre-generated file at `src/proto/fhers.rq.rs`.
- `crates/fhe/build.rs` — compiles `src/proto/bfv/bfv.proto` and `src/proto/trbfv/trbfv.proto` into `src/proto/bfv/generated.rs` and `src/proto/trbfv/generated.rs` respectively. If `protoc` is unavailable, it skips generation with a warning.

BFV is compiled first because TRBFV imports from it.

## Generated files

The following files are build output, not hand-authored source:

- `crates/fhe-math/src/proto/fhers.rq.rs`
- `crates/fhe/src/proto/bfv/generated.rs`
- `crates/fhe/src/proto/trbfv/generated.rs`

Do not manually edit generated output unless the build flow requires it. If a `.proto` file changes, run the build to regenerate and commit the updated output.

## Prerequisites

`protoc` (the protobuf compiler) must be installed. Without it, `fhe-math` falls back to the committed file, but `fhe` skips generation entirely, which means the `generated.rs` files will not reflect proto changes.
