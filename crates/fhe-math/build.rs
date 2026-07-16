#![allow(missing_docs)]

#[cfg(feature = "protobuf")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::path::PathBuf;

    let proto_path = "src/proto/rq.proto";
    let proto_dir = "src/proto";

    println!("cargo:rerun-if-changed={proto_path}");

    let out_dir = PathBuf::from(std::env::var("OUT_DIR")?);

    prost_build::Config::new()
        .out_dir(&out_dir)
        .compile_protos(&[proto_path], &[proto_dir])?;

    Ok(())
}

#[cfg(not(feature = "protobuf"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}
