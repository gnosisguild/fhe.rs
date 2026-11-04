//! Local simulation of sampled-and-dealt noise, not a robust DKG protocol.
#![allow(dead_code, clippy::indexing_slicing)]

use fhe::Error;
use fhe::bfv::{
    BfvParameters, Ciphertext, CommonRandomPoly, Encoding, Plaintext, PublicKey, SecretKey,
};
use fhe::mbfv::{AggregateIter, PublicKeyShare};
use fhe::trbfv::{
    DealerSmudgingNoise, Lambda, RecipientSmudgingShare, ShareManager,
    SmudgingBoundCalculatorConfig, SsSmudgingDecryptionConfig, SsSmudgingDecryptor,
    SsSmudgingNoiseGenerator,
};
use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};
use ndarray::Array2;
use num_bigint::BigInt;
use rayon::prelude::*;
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

pub struct Scenario {
    pub params: Arc<BfvParameters>,
    pub transport: Option<Arc<BfvParameters>>,
    pub n: usize,
    pub threshold: usize,
    pub m: usize,
    pub lambda: Lambda,
    pub reconstructing: Vec<usize>,
}

#[derive(Clone, Copy)]
pub enum NoiseMode {
    Random,
    Endpoint(i64),
}

struct Dealer {
    pk: PublicKeyShare,
    key: Vec<Array2<u64>>,
    noise: Vec<Array2<u64>>,
}

impl Drop for Dealer {
    fn drop(&mut self) {
        for matrix in self.key.iter_mut().chain(&mut self.noise) {
            matrix.iter_mut().for_each(Zeroize::zeroize);
        }
    }
}

fn receive(
    dealt: &[Array2<u64>],
    recipient: usize,
    transport: Option<(&Arc<BfvParameters>, &(SecretKey, PublicKey))>,
) -> Result<Array2<u64>, Error> {
    let mut matrix = Array2::zeros((dealt.len(), dealt[0].ncols()));
    for (row, dealt_row) in dealt.iter().enumerate() {
        let values = Zeroizing::new(dealt_row.row(recipient).to_vec());
        let restored = if let Some((params, (sk, pk))) = transport {
            let pt = Plaintext::try_encode(values.as_slice(), Encoding::poly(), params)?;
            let ct = pk.try_encrypt(&pt, &mut rand::rng())?;
            let pt = sk.try_decrypt(&ct)?;
            let restored = Zeroizing::new(Vec::<u64>::try_decode(&pt, Encoding::poly())?);
            assert_eq!(
                *restored, *values,
                "encrypted share transport changed an RNS row"
            );
            restored
        } else {
            values
        };
        for (cell, &value) in matrix.row_mut(row).iter_mut().zip(restored.iter()) {
            *cell = value;
        }
    }
    Ok(matrix)
}

pub fn run(scenario: &Scenario, mode: NoiseMode) -> Result<u64, Error> {
    let manager = ShareManager::new(scenario.n, scenario.threshold, scenario.params.clone())?;
    let decryptor = SsSmudgingDecryptor::new(SsSmudgingDecryptionConfig::new(
        scenario.n,
        scenario.threshold,
        scenario.params.clone(),
    )?);
    let generator = SsSmudgingNoiseGenerator::new(SmudgingBoundCalculatorConfig::new(
        scenario.params.clone(),
        scenario.n,
        scenario.m,
        scenario.lambda,
    )?)?;
    let mut rng = rand::rng();
    let crp = CommonRandomPoly::new(&scenario.params, &mut rng)?;
    // Preprocess key and noise contributions before encrypting the application
    // input. There is no PRF-key setup.
    let dealers: Vec<_> = (0..scenario.n)
        .into_par_iter()
        .map(|_| {
            let mut rng = rand::rng();
            let sk = SecretKey::random(&scenario.params, &mut rng);
            let pk = PublicKeyShare::new(&sk, crp.clone(), &mut rng)?;
            let mut manager =
                ShareManager::new(scenario.n, scenario.threshold, scenario.params.clone())?;
            let poly = manager.coeffs_to_poly_level0(sk.coeffs.as_ref())?;
            let key = manager.generate_secret_shares_from_poly(poly, &mut rng)?;
            let noise = match mode {
                NoiseMode::Random => generator.generate(&mut rng)?,
                NoiseMode::Endpoint(sign) => DealerSmudgingNoise::from_signed_coefficients(
                    &vec![
                        BigInt::from(sign) * BigInt::from(generator.smudging_bound().clone());
                        scenario.params.degree()
                    ],
                    &scenario.params,
                )?,
            };
            let noise = manager
                .generate_smudging_shares(noise, &mut rng)?
                .into_transport();
            Ok(Dealer { pk, key, noise })
        })
        .collect::<Result<_, Error>>()?;
    let transport_keys: Option<Vec<_>> = scenario.transport.as_ref().map(|params| {
        (0..scenario.n)
            .map(|_| {
                let sk = SecretKey::random(params, &mut rng);
                let pk = PublicKey::new(&sk, &mut rng);
                (sk, pk)
            })
            .collect()
    });
    let mut recipients: Vec<_> = (0..scenario.n)
        .into_par_iter()
        .map(|recipient| {
            let transport = scenario
                .transport
                .as_ref()
                .zip(transport_keys.as_ref().map(|keys| &keys[recipient]));
            let mut keys = Vec::with_capacity(scenario.n);
            let mut noises = Vec::with_capacity(scenario.n);
            for dealer in &dealers {
                keys.push(receive(&dealer.key, recipient, transport)?);
                noises.push(RecipientSmudgingShare::from_transport(receive(
                    &dealer.noise,
                    recipient,
                    transport,
                )?));
            }
            let key = manager.aggregate_collected_shares(&keys);
            for matrix in &mut keys {
                matrix.iter_mut().for_each(Zeroize::zeroize);
            }
            let key = Zeroizing::new(key?.into_ntt());
            let noise = manager.aggregate_smudging_shares(noises)?;
            Ok((key, Some(noise)))
        })
        .collect::<Result<_, Error>>()?;
    let pk: PublicKey = dealers.iter().map(|dealer| dealer.pk.clone()).aggregate()?;
    let mut tally = Ciphertext::zero(&scenario.params);
    for _ in 0..scenario.m {
        let pt = Plaintext::try_encode(&[1u64], Encoding::poly(), &scenario.params)?;
        tally += &pk.try_encrypt(&pt, &mut rng)?;
    }
    let mut partials = Vec::with_capacity(scenario.reconstructing.len());
    for &id in &scenario.reconstructing {
        let (key, noise) = &mut recipients[id - 1];
        let noise = noise.take().ok_or_else(|| Error::duplicate_party_id(id))?;
        partials.push(decryptor.decryption_share(&tally, key, noise)?);
    }
    let pt = decryptor.decrypt_from_shares(&partials, &scenario.reconstructing, &tally)?;
    let found = Vec::<u64>::try_decode(&pt, Encoding::poly())?;
    assert_eq!(found[0], scenario.m as u64, "SS-smudging tally failed");
    Ok(found[0])
}
