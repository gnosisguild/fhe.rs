use std::io::Result;
use std::env;
use std::path::PathBuf;
use std::fs;

fn main() -> Result<()> {
    let proto_dir = PathBuf::from("src/proto");

    // Create a temporary directory for prost output
    let temp_dir = PathBuf::from(env::var("OUT_DIR").unwrap()).join("proto_temp");
    fs::create_dir_all(&temp_dir)?;

    // Compile the .proto file
    prost_build::Config::new()
        .out_dir(&temp_dir)
        .compile_protos(&["src/proto/bfv.proto"], &["src/proto"])?;

    // Copy the generated file to the desired location with the desired name
    let generated_files = fs::read_dir(&temp_dir)?;
    for entry in generated_files {
        let entry = entry?;
        if entry.path().extension().unwrap_or_default() == "rs" {
            let target_path = proto_dir.join("bfv.rs");

            // Copy the file
            fs::copy(entry.path(), &target_path)?;

            // Prepend #![allow(missing_docs)]
            let contents = fs::read_to_string(&target_path)?;
            let new_contents = format!("#![allow(missing_docs)]\n{}", contents);
            fs::write(&target_path, new_contents)?;

            break;
        }
    }

    println!("cargo:rerun-if-changed=src/proto/bfv.proto");
    Ok(())
}
