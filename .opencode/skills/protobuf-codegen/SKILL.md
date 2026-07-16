---
name: protobuf-codegen
description: Use when changing .proto files, build.rs scripts, or generated Rust files under src/proto/. Explains the protoc and prost build flow, fallback behavior, and generated-file conventions for fhe.rs.
---

# Protobuf code generation

Use this skill when working with protobuf definitions or generated code in fhe.rs.

## Build flow

Two `build.rs` scripts drive code generation via `prost`:

### fhe-math (`crates/fhe-math/build.rs`)
- Compiles `src/proto/rq.proto` into `OUT_DIR`
- If `protoc` is unavailable, falls back to the committed file at `src/proto/fhers.rq.rs`
- This fallback means `fhe-math` builds without `protoc`

### fhe (`crates/fhe/build.rs`)
- Compiles `src/proto/bfv/bfv.proto` → `src/proto/bfv/generated.rs`
- Compiles `src/proto/trbfv/trbfv.proto` → `src/proto/trbfv/generated.rs`
- BFV is compiled first because TRBFV imports from it
- If `protoc` is unavailable, skips generation with a warning (no fallback)

## Generated files

These files are build output, not hand-authored source:
- `crates/fhe-math/src/proto/fhers.rq.rs`
- `crates/fhe/src/proto/bfv/generated.rs`
- `crates/fhe/src/proto/trbfv/generated.rs`

## When changing .proto files

1. Edit the `.proto` file
2. Ensure `protoc` is installed
3. Run `cargo build` to trigger regeneration
4. Verify the generated `.rs` files reflect your changes
5. Commit both the `.proto` and the generated files

## What not to do

- Do not manually edit generated `.rs` files — they will be overwritten on the next build
- Do not delete the `fhers.rq.rs` fallback file — it is the build fallback when `protoc` is missing
- Do not change the compile order in `fhe/build.rs` — TRBFV depends on BFV being compiled first
