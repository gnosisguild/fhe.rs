//! Validation of public contribution messages and explicit key material.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use fhe::bfv::{BfvParameters, BfvParametersBuilder, CommonRandomPolyVec, SecretKey};
use fhe::proto::lbfv::{
    LbfvPublicKeyShare, LbfvRelinKeyContribution, LbfvRelinKeyShare, LbfvRelinearizationKey,
};
use fhe::trlbfv::{
    Aggregate, LBFVPublicKey, LBFVRelinearizationKey, PublicKeyShare, RelinKeyShare,
    aggregate_key_pair, aggregate_relinearization_key,
};
use fhe::{Error, MultipartyError, ReferenceStringRole, Result};
use fhe_math::rq::{Ntt, Poly, PowerBasis, traits::TryConvertFrom};
use fhe_traits::{DeserializeParametrized, Serialize};
use ndarray::Array2;
use prost::Message;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use std::sync::Arc;

fn params(plaintext: u64) -> Result<Arc<BfvParameters>> {
    BfvParametersBuilder::new()
        .set_degree(16)
        .set_plaintext_modulus(plaintext)
        .set_moduli_sizes(&[40; 3])
        .build_arc()
}

#[test]
fn share_envelopes_preserve_the_pre_compact_wire_tags() {
    // Frozen schema fixtures from 85ee978, before dev's public-key encoding
    // changed. These test protobuf tags, not cryptographic key validity.
    const PK: &[u8] = &[0x0a, 0x06, 0x10, 0x02, 0x1a, 0x02, 0xaa, 0xbb];
    const RLK: &[u8] = &[
        0x0a, 0x19, 0x0a, 0x0c, 0x0a, 0x01, 0xaa, 0x1a, 0x01, 0xcc, 0x20, 0x01, 0x28, 0x02, 0x30,
        0x03, 0x12, 0x09, 0x12, 0x01, 0xbb, 0x20, 0x04, 0x28, 0x05, 0x30, 0x06,
    ];
    let pk = LbfvPublicKeyShare::decode(PK).unwrap();
    assert_eq!(pk.encode_to_vec(), PK);
    let key = pk.key.unwrap();
    assert_eq!((key.l, key.seed), (2, vec![0xaa, 0xbb]));
    let rlk = LbfvRelinKeyShare::decode(RLK).unwrap();
    assert_eq!(rlk.encode_to_vec(), RLK);
    let part = rlk.contribution.unwrap();
    assert_eq!(part.ksk_r_to_s.unwrap().c0, [vec![0xaa]]);
    assert_eq!(part.ksk_s_to_r.unwrap().c1, [vec![0xbb]]);
}

#[test]
fn mixed_seed_metadata_uses_concrete_rows_and_the_leveled_prefix() -> Result<()> {
    let params = params(17)?;
    let mut rng = ChaCha8Rng::from_seed([73; 32]);
    let a = CommonRandomPolyVec::from_seed(&params, [1; 32])?;
    let d1 = CommonRandomPolyVec::from_seed(&params, [2; 32])?;
    let explicit_a = CommonRandomPolyVec::from_polys(&params, a.to_polys(), None)?;
    let pairs = [&a, &explicit_a]
        .map(|rows| -> Result<_> {
            let sk = SecretKey::random(&params, &mut rng);
            let share = RelinKeyShare::contribute_with_crp(&sk, &d1, rows, 1, 0, &mut rng)?;
            assert_eq!(share.a_components().len(), 2);
            for (actual, expected) in share.a_components().iter().zip(a.as_slice()) {
                assert_eq!(actual.coefficients(), expected.poly().coefficients());
            }
            Ok((
                PublicKeyShare::contribute_with_crp(&sk, rows, &mut rng)?,
                share,
            ))
        })
        .into_iter()
        .collect::<Result<Vec<_>>>()?;
    let (pk, rk) = aggregate_key_pair(pairs)?;
    assert_eq!(pk.seed, None);
    let proto = LbfvRelinearizationKey::decode(rk.to_bytes().as_slice()).unwrap();
    let (d, a) = (proto.ksk_r_to_s.unwrap(), proto.ksk_s_to_r.unwrap());
    assert!(d.seed.is_empty());
    assert_eq!(d.c1.len(), 2);
    assert!(a.seed.is_empty());
    assert_eq!(a.c1.len(), 2);
    assert_eq!(
        LBFVRelinearizationKey::from_bytes(&rk.to_bytes(), &params)?,
        rk
    );

    // The single-party API also uses a seedless PK's actual a rows.
    let sk = SecretKey::random(&params, &mut rng);
    let pk = LBFVPublicKey::new_with_crp(&sk, &explicit_a, &mut rng)?;
    let via_crp =
        LBFVRelinearizationKey::new_leveled_with_crp(&sk, &pk, &d1, 1, 0, &mut rng.clone())?;
    let via_seed = LBFVRelinearizationKey::new_leveled(&sk, &pk, d1.seed(), 1, 0, &mut rng)?;
    assert_eq!(via_crp, via_seed);
    Ok(())
}

#[test]
fn rejects_malformed_wire_layouts_before_aggregation() -> Result<()> {
    let params = params(17)?;
    let mut rng = ChaCha8Rng::from_seed([74; 32]);
    let a = CommonRandomPolyVec::new(&params, &mut rng)?;
    let d1 = CommonRandomPolyVec::new(&params, &mut rng)?;
    let sk = SecretKey::random(&params, &mut rng);
    let pk = PublicKeyShare::contribute_with_crp(&sk, &a, &mut rng)?;
    let rlk = RelinKeyShare::contribute_with_crp(&sk, &d1, &a, 0, 0, &mut rng)?;
    assert!(PublicKeyShare::from_bytes(&[], &params).is_err());
    assert!(RelinKeyShare::from_bytes(&[], &params).is_err());

    let pk_wire = LbfvPublicKeyShare::decode(pk.to_bytes().as_slice())
        .unwrap()
        .key
        .unwrap();
    let rejects_pk = |edit: fn(&mut fhe::proto::lbfv::LbfvPublicKey)| {
        let mut key = pk_wire.clone();
        edit(&mut key);
        let bytes = LbfvPublicKeyShare { key: Some(key) }.encode_to_vec();
        assert!(PublicKeyShare::from_bytes(&bytes, &params).is_err());
    };
    rejects_pk(|p| p.l += 1);
    rejects_pk(|p| p.seed = vec![9; 32]);
    rejects_pk(|p| {
        let extra = p.c[1].c[0].clone();
        p.c[0].c.push(extra);
    });
    rejects_pk(|p| p.c[2].c[1] = p.c[0].c[1].clone());
    rejects_pk(|p| p.c[0].level = 1);

    let part = LbfvRelinKeyShare::decode(rlk.to_bytes().as_slice())
        .unwrap()
        .contribution
        .unwrap();
    let rejects = |edit: fn(&mut LbfvRelinKeyContribution)| {
        let mut p = part.clone();
        edit(&mut p);
        let wire = LbfvRelinKeyShare {
            contribution: Some(p),
        }
        .encode_to_vec();
        assert!(RelinKeyShare::from_bytes(&wire, &params).is_err());
    };
    rejects(|p| p.ksk_s_to_r = None);
    rejects(|p| p.ksk_r_to_s.as_mut().unwrap().ksk_level = 1);
    rejects(|p| p.ksk_s_to_r.as_mut().unwrap().ciphertext_level = 1);
    rejects(|p| p.ksk_s_to_r.as_mut().unwrap().log_base = 2);
    rejects(|p| {
        p.ksk_r_to_s.as_mut().unwrap().c0.pop();
    });
    rejects(|p| {
        p.ksk_s_to_r.as_mut().unwrap().c1.pop();
    });
    rejects(|p| p.ksk_r_to_s.as_mut().unwrap().seed = vec![2; 32]);
    rejects(|p| {
        p.ksk_s_to_r.as_mut().unwrap().c1[1] = p.ksk_r_to_s.as_ref().unwrap().c1[2].clone()
    });

    let (_, full) = aggregate_key_pair([(pk, rlk)])?;
    let mut full = LbfvRelinearizationKey::decode(full.to_bytes().as_slice()).unwrap();
    full.b_vec.pop();
    assert!(LBFVRelinearizationKey::from_bytes(&full.encode_to_vec(), &params).is_err());
    Ok(())
}

#[test]
fn mutable_keys_and_external_polynomials_are_checked_before_use() -> Result<()> {
    let par = params(17)?;
    let mut rng = ChaCha8Rng::from_seed([75; 32]);
    let sk = SecretKey::random(&par, &mut rng);
    let pk = LBFVPublicKey::new_with_seed(&sk, [1; 32], &mut rng);
    let rlk = RelinKeyShare::contribute_with_seed(&sk, [2; 32], [1; 32], 0, 0, &mut rng)?;
    let aggregate =
        |pk: &LBFVPublicKey| aggregate_relinearization_key(std::slice::from_ref(&rlk), pk);
    let mut changed = pk.clone();
    changed.seed = Some([9; 32]);
    assert!(matches!(
        aggregate(&changed),
        Err(Error::Multiparty(
            MultipartyError::CommonRandomPolynomialSeedMismatch { .. }
        ))
    ));
    changed = pk.clone();
    changed.c.swap(0, 1);
    assert!(aggregate(&changed).is_err());
    changed = pk.clone();
    changed.l = 0;
    assert!(aggregate(&changed).is_err());
    changed = pk.clone();
    changed.c[0][0].set_coefficients(Array2::zeros((3, 8)));
    assert!(aggregate(&changed).is_err());
    changed = pk;
    let mut malformed = changed.c[0][0].coefficients().to_owned();
    malformed[[0, 0]] = par.moduli()[0];
    changed.c[0][0].set_coefficients(malformed);
    assert!(aggregate(&changed).is_err());

    let a = CommonRandomPolyVec::new(&par, &mut rng)?.to_polys();
    let mut d1 = CommonRandomPolyVec::new(&par, &mut rng)?.to_polys();
    d1[2] = a[0].clone();
    let shoup = |v: Vec<Poly<Ntt>>| v.into_iter().map(Poly::<Ntt>::into_ntt_shoup).collect();
    assert!(matches!(
        RelinKeyShare::contribute_with_polys(&sk, shoup(d1), shoup(a.clone()), 0, 0, &mut rng),
        Err(Error::Multiparty(
            MultipartyError::OverlappingReferenceStringRows {
                crs_index: 0,
                urs_index: 2
            }
        ))
    ));
    let mut repeated = a.clone();
    repeated[2] = repeated[0].clone();
    assert!(matches!(
        CommonRandomPolyVec::from_polys(&par, repeated, None),
        Err(Error::Multiparty(
            MultipartyError::RepeatedReferenceStringRow {
                role: ReferenceStringRole::CommonRandomPolyVector,
                ..
            }
        ))
    ));
    let other_params = params(19)?; // Same ring, different plaintext space.
    let other_sk = SecretKey::random(&other_params, &mut rng);
    let pks = [&sk, &other_sk].map(|sk| PublicKeyShare::contribute_with_polys(sk, &a, &mut rng));
    assert!(LBFVPublicKey::from_shares(pks).is_err());
    assert!(
        RelinKeyShare::contribute_with_seed(&sk, [2; 32], [1; 32], par.max_level(), 0, &mut rng)
            .is_err()
    );
    assert!(RelinKeyShare::contribute_with_seed(&sk, [2; 32], [1; 32], 1, 1, &mut rng).is_err());
    let truncated = SecretKey::new(vec![1], &par);
    assert!(PublicKeyShare::contribute_with_seed(&truncated, [1; 32], &mut rng).is_err());
    Ok(())
}

#[test]
fn leveled_urs_cannot_reuse_a_public_key_row_outside_the_prefix() -> Result<()> {
    let params = params(17)?;
    let mut rng = ChaCha8Rng::from_seed([77; 32]);
    let sk = SecretKey::random(&params, &mut rng);
    let a = CommonRandomPolyVec::new(&params, &mut rng)?;
    let mut d1 = CommonRandomPolyVec::new(&params, &mut rng)?.to_polys();
    d1[0] = a.as_slice()[2].poly().clone();
    let d1 = CommonRandomPolyVec::from_polys(&params, d1, None)?;
    let check = |err| {
        assert_eq!(
            err,
            Error::Multiparty(MultipartyError::OverlappingReferenceStringRows {
                crs_index: 2,
                urs_index: 0
            })
        )
    };
    check(RelinKeyShare::contribute_with_crp(&sk, &d1, &a, 1, 0, &mut rng).unwrap_err());
    let pk = PublicKeyShare::contribute_with_crp(&sk, &a, &mut rng)?;
    let single = LBFVPublicKey::from_shares([pk.clone()])?;
    check(
        LBFVRelinearizationKey::new_leveled_with_crp(&sk, &single, &d1, 1, 0, &mut rng)
            .unwrap_err(),
    );

    // An imported share only has the first two CRS rows. The collision is
    // observable when its concrete URS meets the full public key.
    let prefix = |v: &CommonRandomPolyVec| {
        v.to_polys()
            .into_iter()
            .take(2)
            .map(Poly::<Ntt>::into_ntt_shoup)
            .collect()
    };
    let share = RelinKeyShare::contribute_with_polys(&sk, prefix(&d1), prefix(&a), 1, 0, &mut rng)?;
    check(aggregate_key_pair([(pk, share)]).unwrap_err());
    Ok(())
}

#[test]
fn guarded_witness_satisfies_both_key_equations() -> Result<()> {
    let params = params(17)?;
    let ctx = params.context_at_level(0)?;
    let mut rng = ChaCha8Rng::from_seed([76; 32]);
    let a = CommonRandomPolyVec::from_seed(&params, [1; 32])?;
    let d1 = CommonRandomPolyVec::from_seed(&params, [2; 32])?;
    let sk = SecretKey::random(&params, &mut rng);
    let ordinary = RelinKeyShare::contribute_with_crp(&sk, &d1, &a, 0, 0, &mut rng.clone())?;
    let (share, w) = RelinKeyShare::contribute_with_crp_and_witness(&sk, &d1, &a, 0, 0, &mut rng)?;
    assert_eq!(share, ordinary);
    let s = Poly::<PowerBasis>::try_convert_from(sk.coeffs.as_ref(), ctx, false)?.into_ntt();
    let r = Poly::<PowerBasis>::try_convert_from(w.r.coeffs.as_ref(), ctx, false)?.into_ntt();
    assert_eq!(w.errors_d0.len(), params.moduli().len());
    assert_eq!(w.errors_d2.len(), params.moduli().len());
    for (i, (e0, e2)) in w.errors_d0.iter().zip(&w.errors_d2).enumerate() {
        let g = ctx.rns.get_garner(i).unwrap();
        assert!(!e0.allows_variable_time_computations() && !e2.allows_variable_time_computations());
        let mut d0 = e0.as_ref().clone().into_ntt();
        d0 -= &(&s * &share.d1_components()[i]);
        d0 += &(g * &r);
        let mut d2 = e2.as_ref().clone().into_ntt();
        d2 += &(&r * &share.a_components()[i]);
        d2 += &(g * &s);
        assert_eq!(d0.coefficients(), share.d0_components()[i].coefficients());
        assert_eq!(d2.coefficients(), share.d2_components()[i].coefficients());
    }
    Ok(())
}
