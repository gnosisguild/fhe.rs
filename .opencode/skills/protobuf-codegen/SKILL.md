---
name: protobuf-codegen
description: Use this skill when working with protobuf definitions or generated code in fhe.rs.
---

# Protobuf code generation

Use this skill when working with protobuf definitions or generated code in fhe.rs.

The build flow, feature-gating, and what's covered by `--features protobuf` live in [`.rules/codegen.md`](../../../.rules/codegen.md) — the source of truth. Read it before touching `.proto` files, `build.rs`, or generated code; do not restate it here.

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
