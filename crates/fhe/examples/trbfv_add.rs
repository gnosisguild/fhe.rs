//! Distributed-key BFV addition with synchronized threshold decryption.
//! Key shares are exchanged in plaintext in this local simulation.

#[path = "support/threshold_addition.rs"]
mod threshold_addition;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    threshold_addition::run(false, false)
}
