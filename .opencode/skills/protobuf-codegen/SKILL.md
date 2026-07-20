# Protobuf code generation

Use this skill when working with protobuf definitions or generated code in fhe.rs.

## Build flow

Protobuf serialization is feature-gated behind the `protobuf` feature (disabled by default). Two `build.rs` scripts drive code generation via `prost`:

### fhe-math (`crates/fhe-math/build.rs`)
- When `--features protobuf` is enabled: compiles `src/proto/rq.proto` into `OUT_DIR` via `prost-build`
- When disabled: does nothing (no `protoc` required)

### fhe (`crates/fhe/build.rs`)
- When `--features protobuf` is enabled: compiles `src/proto/bfv/bfv.proto` and `src/proto/trbfv/trbfv.proto` into `OUT_DIR`
- BFV is compiled first because TRBFV imports from it
- When disabled: does nothing (no `protoc` required)

## Generated files

Generated code is produced in `OUT_DIR` at build time. No generated `.rs` files are committed to the repository.

The `proto` modules use `include!(concat!(env!("OUT_DIR"), "/fhers.*.rs"))` to pull in the generated code.

## When changing .proto files

1. Edit the `.proto` file
2. Ensure `protoc` is installed
3. Run `cargo build --features protobuf` to trigger regeneration
4. Verify the generated code reflects your changes
5. Commit the `.proto` file (generated code is not committed)

## What not to do

- Do not manually edit generated code — it is produced in `OUT_DIR`
- Do not commit generated `.rs` files — they are build output
- Do not change the compile order in `fhe/build.rs` — TRBFV depends on BFV being compiled first
