//! Distributed-key BFV addition with BFV-encrypted Shamir key-share transport.
//! Smudging noise is sampled locally for synchronized decryption, never shared.

#[path = "support/threshold_addition.rs"]
mod threshold_addition;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    threshold_addition::run(true, false)
}
