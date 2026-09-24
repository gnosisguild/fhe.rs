use std::sync::Arc;

use fhe_math::rq::{Ntt, Poly, PowerBasis, traits::TryConvertFrom};
use fhe_traits::{DeserializeWithContext, Serialize};
use itertools::Itertools;
use num_bigint::BigUint;
use rand::{CryptoRng, Rng as RngCore};
use zeroize::Zeroizing;

use crate::bfv::{BfvParameters, Ciphertext, Plaintext, SecretKey};
use crate::{Error, MultipartyError, Result};

use super::Aggregate;
use super::validate::{same_params, switch_ciphertext};

/// A party's share in the secret key switch protocol.
///
/// Each party uses the `SecretKeySwitchShare` to generate their share of the
/// new ciphertext and participate in the "Protocol 3: KeySwitch" protocol
/// detailed in [Multiparty BFV](https://eprint.iacr.org/2020/304.pdf) (p7). Use the [`Aggregate`] impl to combine the
/// shares into a [`Ciphertext`].
///
/// Note: this protocol assumes the output key is split into the same number of
/// parties as the input key, and is likely only useful for niche scenarios.
pub struct SecretKeySwitchShare {
    pub(crate) params: Arc<BfvParameters>,
    /// The original input ciphertext
    // Probably doesn't need to be Arc in real usage but w/e
    pub(crate) ct: Arc<Ciphertext>,
    pub(crate) h_share: Poly<Ntt>,
}

impl SecretKeySwitchShare {
    /// Participate in a new KeySwitch protocol
    ///
    /// 1. *Private input*: BFV input secret key share
    /// 2. *Private input*: BFV output secret key share
    /// 3. *Public input*: Input ciphertext to keyswitch
    // 4. *Public input*: TODO: variance of the ciphertext noise
    pub fn new<R: RngCore + CryptoRng>(
        sk_input_share: &SecretKey,
        sk_output_share: &SecretKey,
        ct: Arc<Ciphertext>,
        rng: &mut R,
    ) -> Result<Self> {
        if sk_input_share.params != sk_output_share.params {
            return Err(Error::ParameterMismatch {
                left: crate::ParameterSource::InputSecretKey,
                right: crate::ParameterSource::OutputSecretKey,
            });
        }
        if sk_output_share.params != ct.params {
            return Err(Error::ParameterMismatch {
                left: crate::ParameterSource::OutputSecretKey,
                right: crate::ParameterSource::Ciphertext,
            });
        }
        // Note: M-BFV implementation only supports ciphertext of length 2
        if ct.len() != 2 {
            return Err(crate::CiphertextError::InvalidPolynomialCount {
                operation: crate::CiphertextOperation::MultipartyKeySwitch,
                actual: ct.len(),
                expected: 2,
            }
            .into());
        }

        let params = sk_input_share.params.clone();
        switch_ciphertext(&ct, &params)?;
        let s_in = Zeroizing::new(
            Poly::<PowerBasis>::try_convert_from(
                sk_input_share.coeffs.as_ref(),
                ct[0].ctx(),
                false,
            )?
            .into_ntt(),
        );
        let s_out = Zeroizing::new(
            Poly::<PowerBasis>::try_convert_from(
                sk_output_share.coeffs.as_ref(),
                ct[0].ctx(),
                false,
            )?
            .into_ntt(),
        );

        // Sample error
        // TODO this should be exponential in ciphertext noise!
        let e = Zeroizing::new(Poly::<Ntt>::small(ct[0].ctx(), params.variance, rng)?);

        // Create h_i share
        let mut h_share = s_in.as_ref() - s_out.as_ref();
        h_share.disallow_variable_time_computations();
        h_share *= &ct[1];
        h_share += e.as_ref();

        Ok(Self {
            params,
            ct,
            h_share,
        })
    }

    /// Deserialize a SecretKeySwitchShare from bytes with the given parameters
    /// and ciphertext. The bytes contain only the share polynomial; callers
    /// must associate it with the original ciphertext and authenticate that
    /// association at the protocol layer.
    pub fn deserialize(
        bytes: &[u8],
        params: &Arc<BfvParameters>,
        ct: Arc<Ciphertext>,
    ) -> Result<Self> {
        switch_ciphertext(&ct, params)?;
        let ctx = params.context_at_level(ct.level)?;
        let h_share = Poly::<Ntt>::from_bytes(bytes, ctx)?;
        Ok(Self {
            params: params.clone(),
            ct,
            h_share,
        })
    }
}

impl Aggregate<SecretKeySwitchShare> for Ciphertext {
    fn from_shares<T>(iter: T) -> Result<Self>
    where
        T: IntoIterator<Item = SecretKeySwitchShare>,
    {
        let mut shares = iter.into_iter();
        let share = shares.next().ok_or(crate::MultipartyError::NoShares)?;
        switch_ciphertext(&share.ct, &share.params)?;
        if share.h_share.ctx() != share.ct[0].ctx() {
            return Err(MultipartyError::IncompatibleShares {
                reason: "secret-key-switch share context does not match ciphertext",
            }
            .into());
        }
        let mut h = share.h_share;
        for sh in shares {
            same_params(&share.params, &sh.params)?;
            switch_ciphertext(&sh.ct, &sh.params)?;
            if sh.ct.c != share.ct.c
                || sh.ct.level != share.ct.level
                || sh.h_share.ctx() != share.ct[0].ctx()
            {
                return Err(MultipartyError::IncompatibleShares {
                    reason: "secret-key-switch shares use different ciphertexts or contexts",
                }
                .into());
            }
            h += &sh.h_share;
        }

        let c0 = &share.ct[0] + &h;
        let c1 = share.ct[1].clone();

        Ciphertext::new(vec![c0, c1], &share.params)
    }
}

impl Serialize for SecretKeySwitchShare {
    fn to_bytes(&self) -> Vec<u8> {
        self.h_share.to_bytes()
    }
}

/// A party's share in the decryption protocol.
///
/// Each party uses the `DecryptionShare` to generate their share of the
/// plaintext output. Note that this is a special case of the "Protocol 3:
/// KeySwitch" protocol detailed in [Multiparty BFV](https://eprint.iacr.org/2020/304.pdf) (p7), using an output key of zero. Use the
/// [`Aggregate`] impl to combine the shares into a [`Plaintext`].
pub struct DecryptionShare {
    pub(crate) sks_share: SecretKeySwitchShare,
}

impl DecryptionShare {
    /// Participate in a new Decryption protocol.
    ///
    /// 1. *Private input*: BFV input secret key share
    /// 3. *Public input*: Ciphertext to decrypt
    // 4. *Public input*: TODO: variance of the ciphertext noise
    pub fn new<R: RngCore + CryptoRng>(
        sk_input_share: &SecretKey,
        ct: &Arc<Ciphertext>,
        rng: &mut R,
    ) -> Result<Self> {
        let params = &sk_input_share.params;
        let zero = SecretKey::new(vec![0; params.degree()], params);
        let sks_share = SecretKeySwitchShare::new(sk_input_share, &zero, ct.clone(), rng)?;
        Ok(DecryptionShare { sks_share })
    }

    /// Deserialize a DecryptionShare from bytes with the given parameters and
    /// ciphertext. Callers must authenticate the ciphertext association; the
    /// serialized share polynomial does not carry a ciphertext identifier.
    pub fn deserialize(
        bytes: &[u8],
        params: &Arc<BfvParameters>,
        ct: Arc<Ciphertext>,
    ) -> Result<Self> {
        Ok(Self {
            sks_share: SecretKeySwitchShare::deserialize(bytes, params, ct)?,
        })
    }
}

impl Serialize for DecryptionShare {
    fn to_bytes(&self) -> Vec<u8> {
        self.sks_share.to_bytes()
    }
}

impl Aggregate<DecryptionShare> for Plaintext {
    fn from_shares<T>(iter: T) -> Result<Self>
    where
        T: IntoIterator<Item = DecryptionShare>,
    {
        let sks_shares = iter.into_iter().map(|s| s.sks_share);
        let ct = Ciphertext::from_shares(sks_shares)?;

        // Note: during SKS, c[1]*sk has already been added to c[0].
        let mut c = Zeroizing::new(ct[0].clone());
        c.disallow_variable_time_computations();
        let ctx = c.ctx().clone();
        let c_inner = std::mem::replace(c.as_mut(), Poly::<Ntt>::zero(&ctx));
        let c = Zeroizing::new(c_inner.into_power_basis());

        // The true decryption part is done during SKS; all that is left is to scale
        let ctx_lvl = ct.params.context_level_at(ct.level)?;
        let d = Zeroizing::new(c.as_ref().scale(&ctx_lvl.cipher_plain_context.scaler)?);

        let v: Vec<BigUint> = Vec::<BigUint>::try_from(d.as_ref())?
            .into_iter()
            .map(|vi| vi + ct.params.plaintext_big())
            .collect_vec();

        let mut w = v[..ct.params.degree()].to_vec();
        let q_poly = d.as_ref().ctx().modulus();
        w.iter_mut().for_each(|wi| *wi %= q_poly);

        ct.params.plaintext.reduce_vec(&mut w);

        let poly =
            Poly::<PowerBasis>::try_convert_from(w.as_slice(), ct[0].ctx(), false)?.into_ntt();

        let pt = Plaintext {
            params: ct.params.clone(),
            encoding: None,
            poly_ntt: poly,
        };

        Ok(pt)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use fhe_traits::{FheDecoder, FheEncoder, FheEncrypter, Serialize};
    use rand::rng;

    use crate::{
        bfv::{BfvParameters, CommonRandomPoly, Encoding, Plaintext, PublicKey, SecretKey},
        mbfv::{Aggregate, AggregateIter, DecryptionShare, PublicKeyShare, SecretKeySwitchShare},
    };

    const NUM_PARTIES: usize = 11;

    #[test]
    fn aggregation_rejects_secret_switch_and_decryption_ciphertext_mismatch() {
        let mut rng = rng();
        let params = BfvParameters::default_arc(1, 8);
        let ctx = params.context_at_level(0).unwrap();
        let sk = SecretKey::random(&params, &mut rng);
        let mk_ct = |rng: &mut _| {
            Arc::new(
                crate::bfv::Ciphertext::new(
                    vec![
                        fhe_math::rq::Poly::random(ctx, rng),
                        fhe_math::rq::Poly::random(ctx, rng),
                    ],
                    &params,
                )
                .unwrap(),
            )
        };
        let ct = mk_ct(&mut rng);
        let other_ct = mk_ct(&mut rng);
        let first = SecretKeySwitchShare::new(&sk, &sk, ct.clone(), &mut rng).unwrap();
        let wrong = SecretKeySwitchShare::new(&sk, &sk, other_ct.clone(), &mut rng).unwrap();
        assert!(matches!(
            crate::bfv::Ciphertext::from_shares([first, wrong]),
            Err(crate::Error::Multiparty(
                crate::MultipartyError::IncompatibleShares { .. }
            ))
        ));
        assert!(matches!(
            crate::bfv::Plaintext::from_shares([
                DecryptionShare::new(&sk, &ct, &mut rng).unwrap(),
                DecryptionShare::new(&sk, &other_ct, &mut rng).unwrap(),
            ]),
            Err(crate::Error::Multiparty(
                crate::MultipartyError::IncompatibleShares { .. }
            ))
        ));
        assert!(
            crate::bfv::Plaintext::from_shares([
                DecryptionShare::new(&sk, &ct, &mut rng).unwrap(),
                DecryptionShare::new(&sk, &ct, &mut rng).unwrap(),
            ])
            .is_ok()
        );
    }

    #[test]
    fn deserialization_binds_switch_share_at_ciphertext_level() {
        let mut rng = rng();
        let params = BfvParameters::default_arc(2, 8);
        let ctx = params.context_at_level(1).unwrap();
        let sk = SecretKey::random(&params, &mut rng);
        let ct = Arc::new(
            crate::bfv::Ciphertext::new(
                vec![
                    fhe_math::rq::Poly::random(ctx, &mut rng),
                    fhe_math::rq::Poly::random(ctx, &mut rng),
                ],
                &params,
            )
            .unwrap(),
        );
        let share = SecretKeySwitchShare::new(&sk, &sk, ct.clone(), &mut rng).unwrap();
        let restored = SecretKeySwitchShare::deserialize(&share.to_bytes(), &params, ct).unwrap();
        assert_eq!(restored.h_share, share.h_share);
    }

    struct Party {
        sk_share: SecretKey,
        pk_share: PublicKeyShare,
    }

    #[test]
    fn encrypt_decrypt() {
        let mut rng = rng();
        for params in [
            BfvParameters::default_arc(1, 16),
            BfvParameters::default_arc(6, 32),
        ] {
            for level in 0..=params.max_level() {
                for _ in 0..20 {
                    let crp = CommonRandomPoly::new(&params, &mut rng).unwrap();

                    let mut parties: Vec<Party> = vec![];

                    // Parties collectively generate public key
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

                    // Use it to encrypt a random polynomial
                    let q = fhe_math::zq::Modulus::new(params.plaintext()).unwrap();
                    let pt1 = Plaintext::try_encode(
                        &q.random_vec(params.degree(), &mut rng),
                        Encoding::poly_at_level(level),
                        &params,
                    )
                    .unwrap();
                    let ct = Arc::new(public_key.try_encrypt(&pt1, &mut rng).unwrap());

                    // Parties perform a collective decryption
                    let decryption_shares = parties
                        .iter()
                        .map(|p| DecryptionShare::new(&p.sk_share, &ct, &mut rng));
                    let pt2 = Plaintext::from_shares(decryption_shares).unwrap();

                    assert_eq!(pt1, pt2);
                }
            }
        }
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

                    let public_key =
                        PublicKey::from_shares(parties.iter().map(|p| p.pk_share.clone())).unwrap();

                    // Use it to encrypt a random polynomial ct1
                    let q = fhe_math::zq::Modulus::new(params.plaintext()).unwrap();
                    let pt1 = Plaintext::try_encode(
                        &q.random_vec(params.degree(), &mut rng),
                        Encoding::poly_at_level(level),
                        &params,
                    )
                    .unwrap();
                    let ct1 = Arc::new(public_key.try_encrypt(&pt1, &mut rng).unwrap());

                    // Key switch ct1 to a different set of parties
                    let mut out_parties = Vec::new();
                    for _ in 0..NUM_PARTIES {
                        let sk_share = SecretKey::random(&params, &mut rng);
                        let pk_share =
                            PublicKeyShare::new(&sk_share, crp.clone(), &mut rng).unwrap();
                        out_parties.push(Party { sk_share, pk_share })
                    }
                    let ct2 = parties
                        .iter()
                        .zip(out_parties.iter())
                        .map(|(ip, op)| {
                            SecretKeySwitchShare::new(
                                &ip.sk_share,
                                &op.sk_share,
                                ct1.clone(),
                                &mut rng,
                            )
                        })
                        .aggregate()
                        .unwrap();
                    let ct2 = Arc::new(ct2);

                    // The second set of parties then does a collective decryption
                    let pt2 = out_parties
                        .iter()
                        .map(|p| DecryptionShare::new(&p.sk_share, &ct2, &mut rng))
                        .aggregate()
                        .unwrap();

                    assert_eq!(pt1, pt2);
                }
            }
        }
    }

    #[test]
    fn collective_keys_enable_homomorphic_addition() {
        let mut rng = rng();
        for params in [
            BfvParameters::default_arc(1, 16),
            BfvParameters::default_arc(6, 32),
        ] {
            for level in 0..=params.max_level() {
                for _ in 0..20 {
                    let crp = CommonRandomPoly::new(&params, &mut rng).unwrap();

                    let mut parties: Vec<Party> = vec![];

                    // Parties collectively generate public key
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

                    // Parties encrypt two plaintexts
                    let q = fhe_math::zq::Modulus::new(params.plaintext()).unwrap();
                    let a = q.random_vec(params.degree(), &mut rng);
                    let b = q.random_vec(params.degree(), &mut rng);
                    let mut expected = a.clone();
                    q.add_vec(&mut expected, &b);

                    let pt_a =
                        Plaintext::try_encode(&a, Encoding::poly_at_level(level), &params).unwrap();
                    let pt_b =
                        Plaintext::try_encode(&b, Encoding::poly_at_level(level), &params).unwrap();
                    let ct_a = public_key.try_encrypt(&pt_a, &mut rng).unwrap();
                    let ct_b = public_key.try_encrypt(&pt_b, &mut rng).unwrap();

                    // and add them together
                    let ct = Arc::new(&ct_a + &ct_b);

                    // Parties perform a collective decryption
                    let pt = parties
                        .iter()
                        .map(|p| DecryptionShare::new(&p.sk_share, &ct, &mut rng))
                        .aggregate()
                        .unwrap();

                    assert_eq!(
                        Vec::<u64>::try_decode(&pt, Encoding::poly_at_level(level)).unwrap(),
                        expected
                    );
                }
            }
        }
    }
}
