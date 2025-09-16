use std::env;
use std::fs;
use std::io::Result;
use std::path::PathBuf;
use std::process::Command;

fn main() -> Result<()> {
    // Check if protoc is available
    if !is_protoc_available() {
        println!("cargo:warning=protoc not found, skipping proto compilation");
        return Ok(());
    }

    let proto_dir = PathBuf::from("src/proto");

    // Create a temporary directory for prost output
    let temp_dir = PathBuf::from(env::var("OUT_DIR").unwrap()).join("proto_temp");
    fs::create_dir_all(&temp_dir)?;

    // Compile BFV proto file first (since TRBFV depends on it)
    compile_proto_file(
        "src/proto/bfv/bfv.proto",
        &["src/proto"],
        &proto_dir.join("bfv").join("generated.rs"),
        &temp_dir,
    )?;

    // Compile TRBFV proto file (which imports from BFV)
    compile_proto_file(
        "src/proto/trbfv/trbfv.proto",
        &["src/proto"],
        &proto_dir.join("trbfv").join("generated.rs"),
        &temp_dir,
    )?;

    println!("cargo:rerun-if-changed=src/proto/bfv/bfv.proto");
    println!("cargo:rerun-if-changed=src/proto/trbfv/trbfv.proto");
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
) -> Result<()> {
    // Clear temp directory
    if temp_dir.exists() {
        fs::remove_dir_all(temp_dir)?;
    }
    fs::create_dir_all(temp_dir)?;

    // Compile the .proto file
    prost_build::Config::new()
        .out_dir(temp_dir)
        .compile_protos(&[proto_file], include_paths)?;

    // Copy the generated file to the desired location with the desired name
    let generated_files = fs::read_dir(temp_dir)?;
    for entry in generated_files {
        let entry = entry?;
        if entry.path().extension().unwrap_or_default() == "rs" {
            // Ensure target directory exists
            if let Some(parent) = target_path.parent() {
                fs::create_dir_all(parent)?;
            }

            // Copy the file
            fs::copy(entry.path(), target_path)?;

            // Prepend #![allow(missing_docs)]
            let contents = fs::read_to_string(target_path)?;
            let new_contents = format!("#![allow(missing_docs)]\n{contents}");
            fs::write(target_path, new_contents)?;

            break;
        }
    }

    Ok(())
}