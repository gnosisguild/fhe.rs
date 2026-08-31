#![allow(missing_docs)]

use std::env;
use std::fs;
use std::io::Result;
use std::path::PathBuf;
use std::process::Command;

fn main() -> Result<()> {
    if !is_protoc_available() {
        println!("cargo:warning=protoc not found, skipping proto compilation");
        return Ok(());
    }

    let proto_dir = PathBuf::from("src/proto");
    let temp_dir = PathBuf::from(env::var("OUT_DIR").unwrap()).join("proto_temp");
    fs::create_dir_all(&temp_dir)?;

    // BFV first: LBFV imports from it.
    compile_proto_file(
        "src/proto/bfv/bfv.proto",
        &["src/proto"],
        &proto_dir.join("bfv").join("generated.rs"),
        &temp_dir,
        &[],
    )?;

    compile_proto_file(
        "src/proto/lbfv/lbfv.proto",
        &["src/proto"],
        &proto_dir.join("lbfv").join("generated.rs"),
        &temp_dir,
        &[(".fhers.bfv", "crate::proto::bfv")],
    )?;

    compile_proto_file(
        "src/proto/trlbfv/trlbfv.proto",
        &["src/proto"],
        &proto_dir.join("trlbfv").join("generated.rs"),
        &temp_dir,
        &[],
    )?;

    compile_proto_file(
        "src/proto/trbfv/trbfv.proto",
        &["src/proto"],
        &proto_dir.join("trbfv").join("generated.rs"),
        &temp_dir,
        &[],
    )?;

    compile_proto_file(
        "src/proto/mbfv/mbfv.proto",
        &["src/proto"],
        &proto_dir.join("mbfv").join("generated.rs"),
        &temp_dir,
        &[],
    )?;

    for proto in [
        "src/proto/bfv/bfv.proto",
        "src/proto/lbfv/lbfv.proto",
        "src/proto/trlbfv/trlbfv.proto",
        "src/proto/trbfv/trbfv.proto",
        "src/proto/mbfv/mbfv.proto",
    ] {
        println!("cargo:rerun-if-changed={proto}");
    }
    Ok(())
}

fn is_protoc_available() -> bool {
    Command::new("protoc").arg("--version").output().is_ok()
}

fn compile_proto_file(
    proto_file: &str,
    include_paths: &[&str],
    target_path: &PathBuf,
    temp_dir: &PathBuf,
    extern_paths: &[(&str, &str)],
) -> Result<()> {
    if temp_dir.exists() {
        fs::remove_dir_all(temp_dir)?;
    }
    fs::create_dir_all(temp_dir)?;

    let mut config = prost_build::Config::new();
    config.out_dir(temp_dir);
    for (proto_path, rust_path) in extern_paths {
        config.extern_path((*proto_path).to_string(), (*rust_path).to_string());
    }
    config.compile_protos(&[proto_file], include_paths)?;

    for entry in fs::read_dir(temp_dir)? {
        let entry = entry?;
        if entry.path().extension().is_some_and(|ext| ext == "rs") {
            if let Some(parent) = target_path.parent() {
                fs::create_dir_all(parent)?;
            }

            fs::copy(entry.path(), target_path)?;

            let contents = fs::read_to_string(target_path)?;
            fs::write(target_path, format!("#![allow(missing_docs)]\n{contents}"))?;

            break;
        }
    }

    Ok(())
}
