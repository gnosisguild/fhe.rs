use std::sync::Arc;

use fhe_math::rq::traits::TryConvertFrom;
use fhe_math::rq::{Ntt, Poly, PowerBasis};

use rand::{CryptoRng, Rng as RngCore};
use zeroize::Zeroizing;

use crate::bfv::{BfvParameters, Ciphertext, PublicKey, SecretKey};
use crate::{Error, MultipartyError, Result};

use super::Aggregate;
use super::validate::{same_params, switch_ciphertext};

/// A party's share in the public key switch protocol.
///
/// Each party uses the `PublicKeySwitchShare` to generate their share of the
/// new ciphertext and participate in the "Protocol 4: PubKeySwitch" protocol detailed in as detailed in [Multiparty BFV](https://eprint.iacr.org/2020/304.pdf) (p7). Use the [`Aggregate`] impl to combine the shares into a [`Ciphertext`].
pub struct PublicKeySwitchShare {
    pub(crate) params: Arc<BfvParameters>,
    /// The first component of the input ciphertext
    pub(crate) c0: Poly<Ntt>,
    // Shared public inputs must agree across all contributions.
    input_c1: Poly<Ntt>,
    output_key: Ciphertext,
    pub(crate) h0_share: Poly<Ntt>,
    pub(crate) h1_share: Poly<Ntt>,
}

impl PublicKeySwitchShare {
    /// Participate in a new PubKeySwitch protocol.
    ///
    /// 1. *Private input*: BFV secret key share
    /// 2. *Public input*: BFV output public key
    /// 3. *Public input*: Ciphertext
    // 4. *Public input*: TODO: variance of the ciphertext noise
    pub fn new<R: RngCore + CryptoRng>(
        sk_share: &SecretKey,
        public_key: &PublicKey,
        ct: &Ciphertext,
        rng: &mut R,
    ) -> Result<Self> {
        if sk_share.params != public_key.params {
            return Err(Error::ParameterMismatch {
                left: crate::ParameterSource::SecretKey,
                right: crate::ParameterSource::PublicKey,
            });
        }
        if public_key.params != ct.params {
            return Err(Error::ParameterMismatch {
                left: crate::ParameterSource::PublicKey,
                right: crate::ParameterSource::Ciphertext,
            });
        }
        let params = sk_share.params.clone();
        switch_ciphertext(ct, &params)?;

        // Get appropriate context / level for the following computations
        let mut pk_ct = public_key.c.clone();
        switch_ciphertext(&pk_ct, &params)?;
        while pk_ct.level != ct.level {
            pk_ct.switch_down()?;
        }
        switch_ciphertext(&pk_ct, &params)?;
        let ctx = params.context_at_level(ct.level)?;

        let mut s = Zeroizing::new(
            Poly::<PowerBasis>::try_convert_from(sk_share.coeffs.as_ref(), ctx, false)?.into_ntt(),
        );
        s.disallow_variable_time_computations();

        let u = Zeroizing::new(Poly::<Ntt>::small(ctx, params.variance, rng)?);
        // TODO this should be exponential in ciphertext noise!
        let e0 = Zeroizing::new(Poly::<Ntt>::small(ctx, params.variance, rng)?);
        let e1 = Zeroizing::new(Poly::<Ntt>::small(ctx, params.variance, rng)?);

        let mut h0 = pk_ct[0].clone();
        h0.disallow_variable_time_computations();
        h0 *= u.as_ref();
        *s.as_mut() *= &ct[1];
        h0 += s.as_ref();
        h0 += e0.as_ref();

        let mut h1 = pk_ct[1].clone();
        h1.disallow_variable_time_computations();
        h1 *= u.as_ref();
        h1 += e1.as_ref();

        let variable_time = fhe_traits::VariableTime::new(fhe_traits::PublicData::assert_public());
        h0.allow_variable_time_computations(variable_time);
        h1.allow_variable_time_computations(variable_time);

        Ok(Self {
            params,
            c0: ct[0].clone(),
            input_c1: ct[1].clone(),
            output_key: pk_ct,
            h0_share: h0,
            h1_share: h1,
        })
    }
}

impl Aggregate<PublicKeySwitchShare> for Ciphertext {
    fn from_shares<T>(iter: T) -> Result<Self>
    where
        T: IntoIterator<Item = PublicKeySwitchShare>,
    {
        let mut shares = iter.into_iter();
        let share = shares.next().ok_or(crate::MultipartyError::NoShares)?;
        let ctx = share.c0.ctx();
        let level = share.params.level_of_context(ctx)?;
        switch_ciphertext(&share.output_key, &share.params)?;
        if share.output_key.level != level
            || share.input_c1.ctx() != ctx
            || share.h0_share.ctx() != ctx
            || share.h1_share.ctx() != ctx
        {
            return Err(MultipartyError::IncompatibleShares {
                reason: "public-key-switch share contexts or levels differ",
            }
            .into());
        }
        let mut h0 = share.h0_share;
        let mut h1 = share.h1_share;
        for sh in shares {
            same_params(&share.params, &sh.params)?;
            switch_ciphertext(&sh.output_key, &sh.params)?;
            if sh.c0 != share.c0
                || sh.input_c1 != share.input_c1
                || sh.output_key.c != share.output_key.c
                || sh.output_key.level != level
                || sh.h0_share.ctx() != ctx
                || sh.h1_share.ctx() != ctx
            {
                return Err(MultipartyError::IncompatibleShares {
                    reason: "public-key-switch shares use different ciphertexts, keys, or contexts",
                }
                .into());
            }
            h0 += &sh.h0_share;
            h1 += &sh.h1_share;
        }

        let c0 = &share.c0 + &h0;

        Ciphertext::new(vec![c0, h1], &share.params)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use fhe_traits::{FheDecrypter, FheEncoder, FheEncrypter};
    use rand::rng;

    use crate::{
        bfv::{
            BfvParameters, Ciphertext, CommonRandomPoly, Encoding, Plaintext, PublicKey, SecretKey,
        },
        mbfv::{Aggregate, AggregateIter, PublicKeyShare, PublicKeySwitchShare},
    };

    const NUM_PARTIES: usize = 11;

    #[test]
    fn aggregation_rejects_public_switch_input_and_output_mismatch() {
        let mut rng = rng();
        let params = BfvParameters::default_arc(1, 8);
        let ctx = params.context_at_level(0).unwrap();
        let sk = SecretKey::random(&params, &mut rng);
        let output = PublicKey::new(&sk, &mut rng);
        let other_output = PublicKey::new(&sk, &mut rng);
        let ct = Ciphertext::new(
            vec![
                fhe_math::rq::Poly::random(ctx, &mut rng),
                fhe_math::rq::Poly::random(ctx, &mut rng),
            ],
            &params,
        )
        .unwrap();
        let other_ct = Ciphertext::new(
            vec![
                fhe_math::rq::Poly::random(ctx, &mut rng),
                fhe_math::rq::Poly::random(ctx, &mut rng),
            ],
            &params,
        )
        .unwrap();
        let first = PublicKeySwitchShare::new(&sk, &output, &ct, &mut rng).unwrap();
        let wrong_input = PublicKeySwitchShare::new(&sk, &output, &other_ct, &mut rng).unwrap();
        let wrong_output = PublicKeySwitchShare::new(&sk, &other_output, &ct, &mut rng).unwrap();
        for wrong in [wrong_input, wrong_output] {
            assert!(matches!(
                Ciphertext::from_shares([
                    PublicKeySwitchShare::new(&sk, &output, &ct, &mut rng).unwrap(),
                    wrong
                ]),
                Err(crate::Error::Multiparty(
                    crate::MultipartyError::IncompatibleShares { .. }
                ))
            ));
        }
        let same_inputs = PublicKeySwitchShare::new(&sk, &output, &ct, &mut rng).unwrap();
        assert!(Ciphertext::from_shares([first, same_inputs]).is_ok());
    }

    struct Party {
        sk_share: SecretKey,
        pk_share: PublicKeyShare,
    }

    #[test]
    fn encrypt_keyswitch_decrypt() {
        let mut rng = rng();
        for params in [
            BfvParameters::default_arc(1, 16),
            BfvParameters::default_arc(6, 32),
        ] {
            for level in 0..=params.max_level() {
                for _ in 0..20 {
                    let crp = CommonRandomPoly::new(&params, &mut rng).unwrap();

                    // Parties collectively generate public key
                    let mut parties: Vec<Party> = vec![];
                    for _ in 0..NUM_PARTIES {
                        let sk_share = SecretKey::random(&params, &mut rng);
                        let pk_share =
                            PublicKeyShare::new(&sk_share, crp.clone(), &mut rng).unwrap();
                        parties.push(Party { sk_share, pk_share })
                    }

                    let public_key: PublicKey = parties
                        .iter()
                        .map(|p| p.pk_share.clone())
                        .aggregate()
                        .unwrap();

                    // Use it to encrypt a random polynomial ct1
                    let pt1 = Plaintext::try_encode(
                        &fhe_math::zq::Modulus::new(params.plaintext())
                            .unwrap()
                            .random_vec(params.degree(), &mut rng),
                        Encoding::poly_at_level(level),
                        &params,
                    )
                    .unwrap();
                    let ct1 = Arc::new(public_key.try_encrypt(&pt1, &mut rng).unwrap());

                    // Key switch ct1 to a new keypair
                    let sk_out = SecretKey::random(&params, &mut rng);
                    let pk_out = PublicKey::new(&sk_out, &mut rng);
                    let ct2 = parties
                        .iter()
                        .map(|p| PublicKeySwitchShare::new(&p.sk_share, &pk_out, &ct1, &mut rng))
                        .aggregate()
                        .unwrap();

                    let pt2 = sk_out.try_decrypt(&ct2).unwrap();
                    assert_eq!(pt1, pt2);
                }
            }
        }
    }
}
