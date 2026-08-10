#![allow(missing_docs)]

#[cfg(feature = "protobuf")]
fn main() -> std::io::Result<()> {
    use std::env;
    use std::path::PathBuf;

    let proto_dir = "src/proto";
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    prost_build::Config::new()
        .out_dir(&out_dir)
        .compile_protos(&["src/proto/bfv/bfv.proto"], &[proto_dir])?;

    println!("cargo:rerun-if-changed=src/proto/bfv/bfv.proto");
    Ok(())
}

#[cfg(not(feature = "protobuf"))]
fn main() -> std::io::Result<()> {
    Ok(())
}
