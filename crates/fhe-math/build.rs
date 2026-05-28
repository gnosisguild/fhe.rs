#![allow(missing_docs)]

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_path = "src/proto/rq.proto";
    let proto_dir = "src/proto";
    let pregenerated = "src/proto/fhers.rq.rs";

    println!("cargo:rerun-if-changed={proto_path}");
    println!("cargo:rerun-if-changed={pregenerated}");

    let out_dir = PathBuf::from(std::env::var("OUT_DIR")?);

    let mut config = prost_build::Config::new();
    match config.compile_protos(&[proto_path], &[proto_dir]) {
        Ok(()) => {}
        Err(e) => {
            // If protoc is unavailable but we have a committed pre-generated file, use it.
            let fallback = PathBuf::from(pregenerated);
            if fallback.exists() {
                std::fs::copy(&fallback, out_dir.join("fhers.rq.rs"))?;
            } else {
                return Err(e.into());
            }
        }
    }
    Ok(())
}
