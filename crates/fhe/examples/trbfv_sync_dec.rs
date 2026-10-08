//! Two decryptions with existing main key sharing and opt-in synchronized decryption.
//!
//! Run: `cargo run --release --example trbfv_sync_dec --features synchronized-decryption`.
//! Small demonstration parameters only; committee keys are generated in one process.

#![allow(clippy::indexing_slicing)]

#[path = "support/synchronized.rs"]
mod support;

use fhe::bfv::{BfvParametersBuilder, Encoding, Plaintext, PublicKey, SecretKey};
use fhe::trbfv::synchronized::{SmudgingNoiseGenerator, SynchronizedDecryptor};
use fhe::trbfv::{Lambda, ShareManager, SmudgingBoundCalculatorConfig};
use fhe_traits::{FheDecoder, FheEncoder, FheEncrypter};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let params = BfvParametersBuilder::new()
        .set_degree(128)
        .set_plaintext_modulus(257)
        .set_moduli_sizes(&[50, 50, 50])
        .build_arc()?;
    let (n, threshold) = (5, 2);
    let mut rng = rand::rng();
    let mut manager = ShareManager::new(n, threshold, params.clone())?;
    let decryptor = SynchronizedDecryptor::new(n, threshold, params.clone())?;
    let secret_key = SecretKey::random(&params, &mut rng);
    let public_key = PublicKey::new(&secret_key, &mut rng);
    let shares = support::share_key(&mut manager, &secret_key, &mut rng)?;
    let keys = support::simulated_committee_prf_keys(n, &mut rng)?;
    // Each ciphertext is independently encrypted: addition fan-in m = 1.
    let generator = SmudgingNoiseGenerator::new(SmudgingBoundCalculatorConfig::new(
        params.clone(),
        n,
        1,
        Lambda::secure(40)?,
    )?)?;
    let designated = [2, 4, 5];
    for value in [7u64, 11] {
        let plaintext = Plaintext::try_encode(&[value], Encoding::poly(), &params)?;
        let ciphertext = public_key.try_encrypt(&plaintext, &mut rng)?;
        let partials = designated
            .iter()
            .map(|&id| {
                decryptor.decryption_share(
                    &ciphertext,
                    &shares[id - 1],
                    id,
                    &designated,
                    generator.generate(&mut rng)?,
                    &keys[id - 1],
                )
            })
            .collect::<Result<Vec<_>, fhe::Error>>()?;
        let result = decryptor.decrypt_from_shares(&partials, &ciphertext)?;
        let decoded = Vec::<u64>::try_decode(&result, Encoding::poly())?;
        assert_eq!(decoded[0], value);
        println!(
            "Synchronized decryption: {} (parties {designated:?})",
            decoded[0]
        );
    }
    Ok(())
}
