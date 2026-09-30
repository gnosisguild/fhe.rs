//! A plaintext modulus larger than `u64::MAX`
//! is supported by plain BFV, but the threshold entry points
//! `SmudgingNoiseGenerator::new` and `ShareManager::decrypt_from_shares`
//! reject it with a typed `ParametersError::UnsupportedPlaintextModulus`
//! before any bound computation or share reconstruction work.

#[path = "../support/mod.rs"]
mod support;

use fhe::bfv::{BfvParameters, BfvParametersBuilder, Ciphertext, Encoding};
use fhe::trbfv::{
    DecryptionShare, FreshNoiseModel, ShareManager, SmudgingConfig, SmudgingNoiseGenerator,
};
use fhe::{Error, ParametersError};
use fhe_math::rq::{Ntt, Poly, PowerBasis};
use fhe_traits::FheDecoder;
use num_bigint::BigUint;
use std::error::Error as StdError;
use std::sync::Arc;

/// Build real BFV parameters whose plaintext modulus exceeds `u64::MAX`
/// (plain BFV supports such parameters; the threshold arithmetic does not).
/// Degree 16, five 62-bit moduli.
fn threshold_large_plaintext_params() -> Result<Arc<BfvParameters>, Box<dyn StdError>> {
    let p = BigUint::parse_bytes(b"340282366920938463463374607431768211507", 10).unwrap();
    let params = BfvParametersBuilder::new()
        .set_degree(16)
        .set_plaintext_modulus_biguint(p)
        .set_moduli_sizes(&[62, 62, 62, 62, 62])
        .build_arc()?;
    assert!(params.plaintext_big().bits() > 64);
    Ok(params)
}

/// A >u64 plaintext modulus must reach the threshold smudging generator as a
/// typed `ParametersError::UnsupportedPlaintextModulus` instead of panicking
/// inside `BfvParameters::plaintext()` — including at depth zero.
#[test]
fn smudging_generator_rejects_large_plaintext_modulus() -> Result<(), Box<dyn StdError>> {
    let params = threshold_large_plaintext_params()?;

    // Depth 0: the check runs at generator entry, before any bound work.
    let depth_zero =
        SmudgingConfig::new(Arc::clone(&params), 5, 1, 2, FreshNoiseModel::BfvPublicKey)?;
    assert!(matches!(
        SmudgingNoiseGenerator::new(depth_zero),
        Err(Error::ParametersError(
            ParametersError::UnsupportedPlaintextModulus { .. }
        ))
    ));

    // Depth 1: the Prop. 20 recursion reuses the same validated value, so
    // the error type does not change with circuit depth.
    let depth_one =
        SmudgingConfig::new(params, 5, 1, 2, FreshNoiseModel::BfvPublicKey)?.with_mult_depth(1);
    assert!(matches!(
        SmudgingNoiseGenerator::new(depth_one),
        Err(Error::ParametersError(
            ParametersError::UnsupportedPlaintextModulus { .. }
        ))
    ));
    Ok(())
}

/// Threshold decryption must return the typed `UnsupportedPlaintextModulus`
/// error before any share validation or reconstruction work, so malformed
/// share inputs cannot mask it.
#[test]
fn decrypt_from_shares_rejects_large_plaintext_modulus_before_reconstruction()
-> Result<(), Box<dyn StdError>> {
    let params = threshold_large_plaintext_params()?;
    let manager = ShareManager::new(3, 1, Arc::clone(&params))?;
    let ctx = params.context_at_level(0)?;
    // A well-formed level-0 two-component ciphertext.
    let ciphertext = Ciphertext::new(
        vec![Poly::<Ntt>::zero(ctx), Poly::<Ntt>::zero(ctx)],
        &params,
    )?;

    // An empty share list and out-of-range party indices would be rejected
    // by reconstruction itself; the plaintext-modulus error must come first.
    let result = manager.decrypt_from_shares(&[], &ciphertext);
    assert!(matches!(
        result,
        Err(Error::ParametersError(
            ParametersError::UnsupportedPlaintextModulus { .. }
        ))
    ));
    Ok(())
}

/// Control: with a plaintext modulus that fits in `u64`, both the smudging
/// generator and threshold decryption succeed; decryption runs the full
/// reconstruction and scaling path on a zero ciphertext with zero shares.
#[test]
fn u64_plaintext_modulus_controls_succeed() -> Result<(), Box<dyn StdError>> {
    let params = support::presets::insecure()?.parameters;
    let ctx = params.context_at_level(0)?;

    // Generator control.
    let generator = SmudgingNoiseGenerator::new(SmudgingConfig::new(
        Arc::clone(&params),
        3,
        1,
        2,
        FreshNoiseModel::BfvPublicKey,
    )?)?;
    assert!(generator.smudging_bound() > &BigUint::from(0_u64));

    // Share-decryption control: zero two-component ciphertext, zero shares.
    let manager = ShareManager::new(3, 1, Arc::clone(&params))?;
    let ciphertext = Ciphertext::new(
        vec![Poly::<Ntt>::zero(ctx), Poly::<Ntt>::zero(ctx)],
        &params,
    )?;
    let shares = vec![
        DecryptionShare::from_parts(Poly::<PowerBasis>::zero(ctx), 1, vec![1, 2], &ciphertext)?,
        DecryptionShare::from_parts(Poly::<PowerBasis>::zero(ctx), 2, vec![1, 2], &ciphertext)?,
    ];
    let plaintext = manager.decrypt_from_shares(&shares, &ciphertext)?;
    let decoded: Vec<u64> = Vec::<u64>::try_decode(&plaintext, Encoding::poly())?;
    assert!(decoded.iter().all(|&value| value == 0));
    Ok(())
}
