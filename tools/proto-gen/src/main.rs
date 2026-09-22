use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

fn main() -> Result<(), Box<dyn Error>> {
    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    let output = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/generated");

    generate(
        &repository,
        &protoc,
        &output,
        "crates/fhe/src/proto/bfv/bfv.proto",
        "crates/fhe/src/proto",
        "fhers.bfv.rs",
        "crates/fhe/src/proto/bfv/generated.rs",
        &[],
        true,
    )?;
    generate(
        &repository,
        &protoc,
        &output,
        "crates/fhe/src/proto/lbfv/lbfv.proto",
        "crates/fhe/src/proto",
        "fhers.lbfv.rs",
        "crates/fhe/src/proto/lbfv/generated.rs",
        &[(".fhers.bfv", "crate::proto::bfv")],
        true,
    )?;
    generate(
        &repository,
        &protoc,
        &output,
        "crates/fhe-math/src/proto/rq.proto",
        "crates/fhe-math/src/proto",
        "fhers.rq.rs",
        "crates/fhe-math/src/proto/fhers.rq.rs",
        &[],
        false,
    )?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn generate(
    repository: &Path,
    protoc: &Path,
    output: &Path,
    proto: &str,
    include: &str,
    generated_name: &str,
    destination: &str,
    extern_paths: &[(&str, &str)],
    allow_missing_docs: bool,
) -> Result<(), Box<dyn Error>> {
    if output.exists() {
        fs::remove_dir_all(output)?;
    }
    fs::create_dir_all(output)?;

    let mut config = prost_build::Config::new();
    config.out_dir(output).protoc_executable(protoc);
    for (proto_path, rust_path) in extern_paths {
        config.extern_path(*proto_path, *rust_path);
    }
    config.compile_protos(&[repository.join(proto)], &[repository.join(include)])?;

    let mut contents = fs::read_to_string(output.join(generated_name))?;
    if allow_missing_docs {
        contents.insert_str(0, "#![allow(missing_docs)]\n");
    }
    fs::write(repository.join(destination), contents)?;
    Ok(())
}
