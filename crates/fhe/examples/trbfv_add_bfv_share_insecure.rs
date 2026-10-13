//! BFV-encrypted key-share transport with explicitly insecure statistical noise.
//! NOT FOR PRODUCTION: small lambda does not hide the decryption noise.

#[path = "support/threshold_addition.rs"]
mod threshold_addition;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    threshold_addition::run(true, true)
}
