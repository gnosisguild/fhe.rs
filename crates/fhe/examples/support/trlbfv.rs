//! Local simulation of a three-party key ceremony and 2-of-3 SS decryption.
//! Private Shamir messages stay in process. No joint secret key is constructed.

#![allow(clippy::indexing_slicing)] // Fixed committee and ShareManager-generated layouts.

use fhe::Result;
use fhe::bfv::{BfvParameters, Ciphertext, CommonRandomPolyVec, Encoding, Plaintext, SecretKey};
use fhe::trbfv::{
    FreshNoiseModel, Lambda, RecipientSmudgingShare, ShareManager, SmudgingBoundCalculatorConfig,
    SsSmudgingDecryptionConfig, SsSmudgingDecryptor, SsSmudgingNoiseGenerator,
};
use fhe::trlbfv::{
    LBFVPublicKey, LBFVRelinearizationKey, PublicKeyShare, RelinKeyShare, aggregate_key_pair,
};
use fhe_math::rq::{Ntt, Poly};
use fhe_traits::{DeserializeParametrized, FheEncoder, FheEncrypter, Serialize};
use ndarray::Array2;
use rand::{CryptoRng, RngCore};
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

pub const PARTIES: usize = 3;
pub const THRESHOLD: usize = 1;
pub const OPENERS: [usize; 2] = [3, 1];

/// Clear both the dealer's outgoing matrices and the recipients' temporary inboxes.
struct PrivateMessages(Vec<Array2<u64>>);

impl Drop for PrivateMessages {
    fn drop(&mut self) {
        for matrix in &mut self.0 {
            matrix.iter_mut().for_each(Zeroize::zeroize);
        }
    }
}

impl PrivateMessages {
    fn for_party(&self, id: usize, degree: usize) -> Array2<u64> {
        Array2::from_shape_fn((self.0.len(), degree), |(limb, coeff)| {
            self.0[limb][[id - 1, coeff]]
        })
    }
}

pub struct Committee {
    pub manager: ShareManager,
    pub secret_shares: Vec<Zeroizing<Poly<Ntt>>>,
    pk: LBFVPublicKey,
    rlk: LBFVRelinearizationKey,
}

impl Committee {
    pub fn deal<R: RngCore + CryptoRng>(
        params: &Arc<BfvParameters>,
        a: &CommonRandomPolyVec,
        d1: &CommonRandomPolyVec,
        rng: &mut R,
    ) -> Result<Self> {
        let mut manager = ShareManager::new(PARTIES, THRESHOLD, params.clone())?;
        let mut pairs = Vec::new();
        let mut dealers = Vec::new();
        for _ in 0..PARTIES {
            let sk = SecretKey::random(params, rng);
            let public = PublicKeyShare::contribute_with_crp(&sk, a, rng)?;
            let relin = RelinKeyShare::contribute_with_crp(&sk, d1, a, 0, 0, rng)?;
            // A real dealer persists these bytes before publishing its pair,
            // then resends them verbatim on retry. Shamir-share the same summand.
            pairs.push((
                PublicKeyShare::from_bytes(&public.to_bytes(), params)?,
                RelinKeyShare::from_bytes(&relin.to_bytes(), params)?,
            ));
            let summand = manager.coeffs_to_poly_level0(sk.coeffs.as_ref())?;
            dealers.push(PrivateMessages(
                manager.generate_secret_shares_from_poly(summand, rng)?,
            ));
        }
        let (pk, rlk) = aggregate_key_pair(pairs)?;
        let secret_shares = (1..=PARTIES)
            .map(|id| {
                let inbox = PrivateMessages(
                    dealers
                        .iter()
                        .map(|dealer| dealer.for_party(id, params.degree()))
                        .collect(),
                );
                Ok(Zeroizing::new(
                    manager.aggregate_collected_shares(&inbox.0)?.into_ntt(),
                ))
            })
            .collect::<Result<_>>()?;
        // The evaluator only needs ordinary l-BFV keys in the existing format.
        Ok(Self {
            manager,
            secret_shares,
            pk: LBFVPublicKey::from_bytes(&pk.to_bytes(), params)?,
            rlk: LBFVRelinearizationKey::from_bytes(&rlk.to_bytes(), params)?,
        })
    }

    pub fn product<R: RngCore + CryptoRng>(
        &self,
        x: u64,
        y: u64,
        rng: &mut R,
    ) -> Result<Ciphertext> {
        let mut encrypt = |x| {
            self.pk.try_encrypt(
                &Plaintext::try_encode(&[x], Encoding::poly(), &self.manager.params)?,
                rng,
            )
        };
        let mut product = &encrypt(x)? * &encrypt(y)?;
        self.rlk.relinearizes(&mut product)?;
        Ok(product)
    }

    pub fn noise_config(&self) -> Result<SmudgingBoundCalculatorConfig> {
        // One fresh ciphertext per operand, one multiplication. All three
        // parties contributed to the RLK, irrespective of which two open.
        SmudgingBoundCalculatorConfig::new_with_fresh_noise_model(
            self.manager.params.clone(),
            PARTIES,
            1,
            1,
            Lambda::secure(40)?,
            FreshNoiseModel::LbfvPublicKey,
        )
    }

    pub fn decrypt_ss<R: RngCore + CryptoRng>(
        &mut self,
        ct: &Ciphertext,
        rng: &mut R,
    ) -> Result<Plaintext> {
        let noise = SsSmudgingNoiseGenerator::new(self.noise_config()?)?;
        let decryptor = SsSmudgingDecryptor::new(SsSmudgingDecryptionConfig::new(
            PARTIES,
            THRESHOLD,
            self.manager.params.clone(),
        )?);
        let mut dealt = Vec::new();
        for _ in 0..PARTIES {
            dealt.push(PrivateMessages(
                self.manager
                    .generate_smudging_shares(noise.generate(rng)?, rng)?
                    .into_transport(),
            ));
        }
        let mut partials = Vec::new();
        for id in OPENERS {
            let inbox = dealt
                .iter()
                .map(|d| {
                    RecipientSmudgingShare::from_transport(
                        d.for_party(id, self.manager.params.degree()),
                    )
                })
                .collect();
            let share = self.manager.aggregate_smudging_shares(inbox)?;
            partials.push(decryptor.decryption_share(ct, &self.secret_shares[id - 1], share)?);
        }
        decryptor.decrypt_from_shares(&partials, &OPENERS, ct)
    }
}
