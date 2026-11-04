//! SS-smudging addition flow.
//! No PRF keys or synchronized local noise are used.
//! Run: `cargo run --release --no-default-features --features experimental-mbfv --example trbfv_add_ss_smudging`.
//! This local simulation is not an audited deployment or a robust DKG protocol.
#[path = "support/ss_smudging.rs"]
mod ss_smudging;

use fhe::bfv::BfvParametersBuilder;
use fhe::trbfv::{Lambda, SsSmudgingDecryptionConfig};
use ss_smudging::{NoiseMode, Scenario};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (mut m, mut n, mut threshold, mut lambda) = (50, 7, 3, 45);
    for arg in std::env::args().skip(1) {
        if arg == "--help" || arg == "-h" {
            println!(
                "SS-smudging BFV addition: --num_summed=N --num_parties=N --threshold=T --lambda=L"
            );
            return Ok(());
        }
        let (name, value) = arg.split_once('=').ok_or("expected --option=value")?;
        let value = value.parse::<usize>()?;
        match name {
            "--num_summed" => m = value,
            "--num_parties" => n = value,
            "--threshold" => threshold = value,
            "--lambda" => lambda = value,
            _ => return Err(format!("unrecognized argument: {arg}").into()),
        }
    }
    let params = BfvParametersBuilder::new()
        .set_degree(8192)
        .set_plaintext_modulus(1_000_000)
        .set_moduli(&[0x0400000000c00001, 0x0400000000a40001, 0x0400000000990001])
        .set_variance(10)
        .set_error1_variance_str("17723039943798878305384094137071261013333")?
        .build_arc()?;
    // Validate before calculating/allocating the reconstructing-party range.
    SsSmudgingDecryptionConfig::new(n, threshold, params.clone())?;
    let scenario = Scenario {
        params,
        transport: None,
        n,
        threshold,
        m,
        lambda: Lambda::secure(lambda)?,
        reconstructing: (1..=threshold + 1).collect(),
    };
    let found = ss_smudging::run(&scenario, NoiseMode::Random)?;
    println!(
        "SS-smudging tally: {found} (expected {m}); noise was sampled, dealt, and interpolated."
    );
    Ok(())
}
