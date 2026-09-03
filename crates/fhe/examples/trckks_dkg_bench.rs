// SPDX-License-Identifier: MIT

//! Threshold-CKKS DKG + relinearization-ceremony + threshold-decryption
//! benchmark: compute AND bandwidth, per party and per committee, across
//! committee sizes and parameter presets (including 128-bit-secure shapes).
//!
//! Replaces the earlier `trckks_bench` / `relin_ceremony_bench` examples.
//!
//! ```text
//! cargo run --release --example trckks_dkg_bench -- \
//!     --preset demo512-2limb --parties 3,5,10 --relin-levels all --runs 3 \
//!     --json /tmp/trckks-bench/demo512-2limb.json
//! # hybrid (special-prime) key switching: ONE ceremony for all levels
//! cargo run --release --example trckks_dkg_bench -- \
//!     --preset secure32768-L20 --parties 3,5 --keyswitch hybrid \
//!     --special-primes 2 --json /tmp/trckks-bench/hybrid-secure32768-L20.json
//! ```
//!
//! `--keyswitch rns` (default) runs the per-level RNS-decomposition
//! ceremony at every requested level; `--keyswitch hybrid` runs the
//! single hybrid ceremony (`k = --special-primes` 60-bit special primes,
//! `dnum = --dnum` or the default `ceil(L/k)`) and uses that one key for
//! the multiply check at the same deepest level, so the `relin.*` and
//! `mult.*` rows of the two modes are directly comparable. Hybrid runs
//! additionally report `mult.chain_rel_error` — the relative error after a
//! depth-4 mul/relin/rescale chain from level 0 — under BOTH modes when
//! `--chain-compare` is set (this runs the four RNS level keys too).
//!
//! Presets (`--preset`):
//! - `demo512-2limb`: N=512, [45,45], delta=2^40 (unit-test shape)
//! - `demo512-ladder`: N=512, 45 + 37x40 (38 limbs, 1525 bits), delta=2^40
//!   — the 12-iteration sign-extraction ladder
//! - `stats512-3limb`: N=512, [36,36,36], delta=2^40 (salary-survey shape)
//! - `secure32768-L20`: N=32768, 45 + 19x40 (20 limbs, 805 bits), delta=2^40
//! - `secure65536-ladder` (alias `secure65536-L40`): N=65536, 45 + 37x40
//!   (38 limbs, 1525 bits), delta=2^40
//!
//! Security of the secure presets: the HE Standard (Albrecht et al., 2018,
//! <https://homomorphicencryption.org/standard/>) Table 1, ternary secret,
//! classical 128-bit, allows log2(Q) <= 881 at N=32768; the same estimator
//! extended to N=65536 (as used by Lattigo/OpenFHE default tables) allows
//! log2(Q) <= 1772. 805 < 881 and 1525 < 1772.
//!
//! Every timing is `std::time::Instant` wall time of ONE party's work
//! (median across parties within a run), reported as min/median over
//! `--runs` independent runs. Bandwidth numbers are exact serialized byte
//! counts of the objects a party sends.

#![allow(
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::too_many_lines,
    clippy::cast_precision_loss
)]

use clap::Parser;
use fhe::ckks::{
    CkksCiphertext, CkksEncoder, CkksHybridRelinKey, CkksParameters, CkksParametersBuilder,
    CkksRelinearizationKey, CkksSecretKey,
};
use fhe::trckks::{
    CkksCrp, CkksHybridRelinKeyGenerator, CkksHybridRelinKeyShare, CkksPublicKeyShare,
    CkksRelinKeyGenerator, CkksRelinKeyShare, R1Aggregated, R2, TRCKKS,
};
use fhe_traits::Serialize;
use ndarray::Array2;
use rand::RngCore;
use std::collections::BTreeMap;
use std::error::Error;
use std::sync::Arc;
use std::time::Instant;

#[derive(Parser, Debug)]
#[command(about = "Threshold-CKKS DKG / relin-ceremony / decrypt benchmark")]
struct Args {
    /// Committee sizes to benchmark (comma-separated), e.g. `3,5,10`.
    #[arg(long, default_value = "3,5", value_delimiter = ',')]
    parties: Vec<usize>,
    /// Parameter preset (see module docs).
    #[arg(long, default_value = "demo512-2limb")]
    preset: String,
    /// Relinearization levels to run the ceremony at: `all` (every level
    /// with >= 2 limbs), `ladder` (the sign-extraction multiplication
    /// levels 1+3i, 3+3i), or a comma-separated list. The deepest
    /// multiplication level (L-2) is always included for the multiply
    /// check.
    #[arg(long, default_value = "auto")]
    relin_levels: String,
    /// Independent runs per (preset, n); min and median are reported.
    #[arg(long, default_value_t = 3)]
    runs: usize,
    /// Smudging bits for the dealt flooding polynomial (compute cost is
    /// insensitive to this; use the calculator for real deployments).
    #[arg(long, default_value_t = 20)]
    smudging_bits: usize,
    /// Write results as JSON to this path (one object per committee size).
    #[arg(long)]
    json: Option<String>,
    /// Key-switching mode: `rns` (per-level keys) or `hybrid` (one key).
    #[arg(long, default_value = "rns")]
    keyswitch: String,
    /// Number of 60-bit special primes for `--keyswitch hybrid`.
    #[arg(long, default_value_t = 2)]
    special_primes: usize,
    /// Gadget digit count for `--keyswitch hybrid` (default `ceil(L/k)`).
    #[arg(long)]
    dnum: Option<usize>,
    /// Also run a depth-4 mul/relin/rescale chain under BOTH modes and
    /// report both relative errors (costs four extra RNS level ceremonies).
    #[arg(long, default_value_t = false)]
    chain_compare: bool,
}

struct Preset {
    name: &'static str,
    degree: usize,
    moduli_sizes: Vec<usize>,
    scale_bits: i32,
    security_note: &'static str,
}

fn ladder_sizes(iterations: usize) -> Vec<usize> {
    // Mirrors interfold `sign_extraction_moduli_sizes`: 45-bit base +
    // (1 + 3*iterations) 40-bit rescale limbs.
    let mut sizes = vec![45usize];
    sizes.extend(std::iter::repeat_n(40usize, 1 + 3 * iterations));
    sizes
}

fn preset(name: &str) -> Result<Preset, Box<dyn Error>> {
    Ok(match name {
        "demo512-2limb" => Preset {
            name: "demo512-2limb",
            degree: 512,
            moduli_sizes: vec![45, 45],
            scale_bits: 40,
            security_note: "INSECURE demo shape (N=512)",
        },
        "demo512-ladder" => Preset {
            name: "demo512-ladder",
            degree: 512,
            moduli_sizes: ladder_sizes(12),
            scale_bits: 40,
            security_note: "INSECURE demo shape (N=512); 12-iteration sign-extraction ladder",
        },
        "stats512-3limb" => Preset {
            name: "stats512-3limb",
            degree: 512,
            moduli_sizes: vec![36, 36, 36],
            scale_bits: 40,
            security_note: "INSECURE demo shape (N=512); salary-survey statistics shape",
        },
        "secure32768-L20" => Preset {
            name: "secure32768-L20",
            degree: 32768,
            moduli_sizes: {
                let mut s = vec![45usize];
                s.extend(std::iter::repeat_n(40usize, 19));
                s
            },
            scale_bits: 40,
            security_note: "128-bit classical (HE Standard 2018 Table 1: log Q <= 881 at N=32768; \
                            here 805)",
        },
        "secure65536-ladder" | "secure65536-L40" => Preset {
            name: "secure65536-ladder",
            degree: 65536,
            moduli_sizes: ladder_sizes(12),
            scale_bits: 40,
            security_note: "128-bit classical (HE Standard estimator extended to N=65536: log Q <= \
                            1772; here 1525)",
        },
        other => return Err(format!("unknown preset {other}").into()),
    })
}

fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1e3
}

fn median(v: &mut [f64]) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = v.len();
    if n == 0 {
        f64::NAN
    } else if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    }
}

/// Metrics of one run: key -> value (ms or bytes; see key suffix).
type Run = BTreeMap<String, f64>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum KeySwitch {
    Rns,
    Hybrid,
}

/// A relinearization key of either kind.
enum Relin {
    Rns(CkksRelinearizationKey),
    Hybrid(CkksHybridRelinKey),
}

impl Relin {
    fn relinearizes(&self, ct: &mut CkksCiphertext) -> fhe::Result<()> {
        match self {
            Relin::Rns(k) => k.relinearizes(ct),
            Relin::Hybrid(k) => k.relinearizes(ct),
        }
    }
}

/// Per-level RNS ceremony (Protocol 2) for `sks`; returns the joint key
/// and fills the `relin.level_XX.*` metrics.
fn rns_ceremony(
    params: &Arc<CkksParameters>,
    sks: &[CkksSecretKey],
    level: usize,
    out: &mut Run,
    rng: &mut impl rand::CryptoRng,
) -> Result<(CkksRelinearizationKey, f64, f64), Box<dyn Error>> {
    let num_limbs = params.moduli().len();
    let len = num_limbs - level;
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let crp = CkksCrp::vec_from_seed_leveled(params, seed, len, level)?;

    let mut t_gen = Vec::new();
    let generators = sks
        .iter()
        .map(|sk| {
            let t = Instant::now();
            let g = CkksRelinKeyGenerator::new_leveled(sk, &crp, level, rng);
            t_gen.push(ms(t));
            g
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut t_r1 = Vec::new();
    let r1: Vec<_> = generators
        .iter()
        .map(|g| {
            let t = Instant::now();
            let s = g.round_1(rng);
            t_r1.push(ms(t));
            s
        })
        .collect::<Result<Vec<_>, _>>()?;
    let t = Instant::now();
    let r1_bytes = r1[0].to_bytes().len();
    let r1_ser_ms = ms(t);

    let t = Instant::now();
    let r1_agg = Arc::new(CkksRelinKeyShare::<R1Aggregated>::from_shares(r1)?);
    let t_r1agg = ms(t);

    let mut t_r2 = Vec::new();
    let r2: Vec<_> = generators
        .iter()
        .map(|g| {
            let t = Instant::now();
            let s = g.round_2(&r1_agg, rng);
            t_r2.push(ms(t));
            s
        })
        .collect::<Result<Vec<_>, _>>()?;
    let r2_bytes = r2[0].to_bytes().len();
    drop(generators);

    let t = Instant::now();
    let rlk = CkksRelinKeyShare::<R2>::aggregate_into_key(r2)?;
    let t_r2agg = ms(t);
    let rlk_bytes = rlk.to_bytes().len();
    drop(r1_agg);

    let p = format!("relin.level_{level:02}");
    let gen_ms = median(&mut t_gen);
    let r1m = median(&mut t_r1);
    let r2m = median(&mut t_r2);
    out.insert(format!("{p}.limbs"), len as f64);
    out.insert(format!("{p}.gen_u_ms"), gen_ms);
    out.insert(format!("{p}.r1_gen_ms"), r1m);
    out.insert(format!("{p}.r1_serialize_ms"), r1_ser_ms);
    out.insert(format!("{p}.r1_aggregate_ms"), t_r1agg);
    out.insert(format!("{p}.r2_gen_ms"), r2m);
    out.insert(format!("{p}.r2_aggregate_ms"), t_r2agg);
    out.insert(format!("{p}.r1_share_bytes"), r1_bytes as f64);
    out.insert(format!("{p}.r2_share_bytes"), r2_bytes as f64);
    out.insert(format!("{p}.key_bytes"), rlk_bytes as f64);
    // Per-party wall: own gen + R1 + R2 + aggregating (every party
    // aggregates to verify by determinism).
    let per_party = gen_ms + r1m + r2m + t_r1agg + t_r2agg;
    out.insert(format!("{p}.per_party_ms"), per_party);
    Ok((rlk, per_party, (r1_bytes + r2_bytes) as f64))
}

/// The single hybrid ceremony; fills `relin.hybrid.*` metrics.
fn hybrid_ceremony(
    params: &Arc<CkksParameters>,
    sks: &[CkksSecretKey],
    out: &mut Run,
    rng: &mut impl rand::CryptoRng,
) -> Result<(CkksHybridRelinKey, f64, f64), Box<dyn Error>> {
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let crp = CkksCrp::vec_from_seed_qp(params, seed)?;

    let mut t_gen = Vec::new();
    let generators = sks
        .iter()
        .map(|sk| {
            let t = Instant::now();
            let g = CkksHybridRelinKeyGenerator::new(sk, &crp, rng);
            t_gen.push(ms(t));
            g
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut t_r1 = Vec::new();
    let r1: Vec<_> = generators
        .iter()
        .map(|g| {
            let t = Instant::now();
            let s = g.round_1(rng);
            t_r1.push(ms(t));
            s
        })
        .collect::<Result<Vec<_>, _>>()?;
    let t = Instant::now();
    let r1_bytes = r1[0].to_bytes().len();
    let r1_ser_ms = ms(t);

    let t = Instant::now();
    let r1_agg = Arc::new(CkksHybridRelinKeyShare::<R1Aggregated>::from_shares(r1)?);
    let t_r1agg = ms(t);

    let mut t_r2 = Vec::new();
    let r2: Vec<_> = generators
        .iter()
        .map(|g| {
            let t = Instant::now();
            let s = g.round_2(&r1_agg, rng);
            t_r2.push(ms(t));
            s
        })
        .collect::<Result<Vec<_>, _>>()?;
    let r2_bytes = r2[0].to_bytes().len();
    drop(generators);

    let t = Instant::now();
    let rlk = CkksHybridRelinKeyShare::<R2>::aggregate_into_key(r2)?;
    let t_r2agg = ms(t);
    let rlk_bytes = rlk.to_bytes().len();
    drop(r1_agg);

    let p = "relin.hybrid";
    let gen_ms = median(&mut t_gen);
    let r1m = median(&mut t_r1);
    let r2m = median(&mut t_r2);
    out.insert(format!("{p}.dnum"), params.dnum() as f64);
    out.insert(
        format!("{p}.special_primes"),
        params.special_moduli().len() as f64,
    );
    out.insert(format!("{p}.gen_u_ms"), gen_ms);
    out.insert(format!("{p}.r1_gen_ms"), r1m);
    out.insert(format!("{p}.r1_serialize_ms"), r1_ser_ms);
    out.insert(format!("{p}.r1_aggregate_ms"), t_r1agg);
    out.insert(format!("{p}.r2_gen_ms"), r2m);
    out.insert(format!("{p}.r2_aggregate_ms"), t_r2agg);
    out.insert(format!("{p}.r1_share_bytes"), r1_bytes as f64);
    out.insert(format!("{p}.r2_share_bytes"), r2_bytes as f64);
    out.insert(format!("{p}.key_bytes"), rlk_bytes as f64);
    let per_party = gen_ms + r1m + r2m + t_r1agg + t_r2agg;
    out.insert(format!("{p}.per_party_ms"), per_party);
    Ok((rlk, per_party, (r1_bytes + r2_bytes) as f64))
}

/// Depth-`depth` chain x -> x^(2^depth) with mul/relin/rescale from level
/// 0; returns the max relative error of the joint-secret decryption.
fn chain_rel_error(
    encoder: &CkksEncoder,
    pk: &fhe::ckks::CkksPublicKey,
    sk_joint: &CkksSecretKey,
    depth: usize,
    relin: &dyn Fn(&mut CkksCiphertext, usize) -> fhe::Result<()>,
    rng: &mut impl rand::CryptoRng,
) -> Result<f64, Box<dyn Error>> {
    let x: Vec<f64> = vec![1.1, -0.9, 0.7, 1.05];
    let expected: Vec<f64> = x.iter().map(|v| v.powi(1 << depth)).collect();
    let mut y = pk.try_encrypt(&encoder.encode(&x, 0)?, rng)?;
    for l in 0..depth {
        let mut sq = y.try_mul(&y)?;
        relin(&mut sq, l)?;
        sq.rescale()?;
        y = sq;
    }
    let d = encoder.decode(&sk_joint.try_decrypt(&y)?)?;
    Ok(expected
        .iter()
        .zip(d.iter())
        .map(|(e, v)| ((e - v) / e).abs())
        .fold(0f64, f64::max))
}

/// Party j's `[L, degree]` rows from every dealer's `[n, degree]`-per-modulus
/// matrices.
fn collect_rows(dealt: &[Vec<Array2<u64>>], j: usize) -> Vec<Array2<u64>> {
    dealt
        .iter()
        .map(|dealer| {
            let mut arr = Array2::<u64>::zeros((dealer.len(), dealer[0].ncols()));
            for (r, m) in dealer.iter().enumerate() {
                arr.row_mut(r).assign(&m.row(j));
            }
            arr
        })
        .collect()
}

/// Deepest level at which ONE product of small values still fits: the
/// product carries scale `delta^2`, so `Q_l` must exceed `2*scale_bits`
/// plus headroom for the values and noise. With 36-bit limbs and
/// delta = 2^40 that rules out the two-limb tail (72 < 80 bits): the
/// statistics policy multiplies at level 0 for exactly this reason.
fn mult_level(params: &Arc<CkksParameters>) -> usize {
    let sizes = params.moduli_sizes();
    let scale_bits = params.scale().log2().round() as usize;
    let need = 2 * scale_bits + 8;
    let num_limbs = sizes.len();
    (0..=num_limbs - 2)
        .rev()
        .find(|&l| sizes[..num_limbs - l].iter().sum::<usize>() >= need)
        .unwrap_or(0)
}

/// Levels to run the ceremony at; the multiply-check level is always
/// included and nothing beyond `L-2` (a single limb cannot key-switch).
fn resolve_levels(spec: &str, preset_name: &str, params: &Arc<CkksParameters>) -> Vec<usize> {
    let num_limbs = params.moduli().len();
    let deepest = num_limbs - 2;
    let mut levels: Vec<usize> = match spec {
        "auto" => {
            if preset_name.contains("ladder") {
                (0..12).flat_map(|i| [1 + 3 * i, 3 + 3 * i]).collect()
            } else {
                (0..=deepest).collect()
            }
        }
        "all" => (0..=deepest).collect(),
        "ladder" => (0..12).flat_map(|i| [1 + 3 * i, 3 + 3 * i]).collect(),
        list => list
            .split(',')
            .map(|s| s.trim().parse::<usize>().expect("level"))
            .collect(),
    };
    levels.push(mult_level(params));
    levels.retain(|&l| l <= deepest);
    levels.sort_unstable();
    levels.dedup();
    levels
}

fn one_run(
    params: &Arc<CkksParameters>,
    n: usize,
    threshold: usize,
    levels: &[usize],
    smudging_bits: usize,
    keyswitch: KeySwitch,
    chain_compare: bool,
) -> Result<Run, Box<dyn Error>> {
    let mut rng = rand::rng();
    let mut out = Run::new();
    let trckks = TRCKKS::new(n, threshold, params.clone())?;
    let encoder = CkksEncoder::new(params);
    let num_limbs = params.moduli().len();
    let depth = 4.min(num_limbs - 1);

    // ── DKG ────────────────────────────────────────────────────────────────
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let crp = CkksCrp::from_seed(params, seed)?;

    let mut sks = Vec::with_capacity(n);
    let mut pk_shares = Vec::with_capacity(n);
    let mut sk_dealt = Vec::with_capacity(n);
    let mut es_dealt = Vec::with_capacity(n);
    let (mut t_sample, mut t_pk, mut t_deal_sk, mut t_deal_es) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let mut pk_share_bytes = 0usize;
    let mut dealt_bytes_per_recipient = 0usize;
    for _ in 0..n {
        let t = Instant::now();
        let sk = CkksSecretKey::random(params, &mut rng);
        t_sample.push(ms(t));

        let t = Instant::now();
        let pk_share = CkksPublicKeyShare::new(&sk, crp.clone(), &mut rng)?;
        t_pk.push(ms(t));
        pk_share_bytes = pk_share.p0_to_bytes().len();

        let t = Instant::now();
        let sk_poly = trckks.coeffs_to_poly(sk.coeffs.as_ref())?;
        let shares = trckks.generate_secret_shares_from_poly(sk_poly, &mut rng)?;
        t_deal_sk.push(ms(t));
        // Transport payload to ONE recipient: its row of every modulus
        // matrix, one u64 per coefficient per limb.
        dealt_bytes_per_recipient = shares.iter().map(|m| m.ncols() * 8).sum();
        sk_dealt.push(shares);

        let t = Instant::now();
        let es = trckks.generate_smudging_error(smudging_bits, &mut rng)?;
        let es_poly = trckks.smudging_to_poly(&es)?;
        es_dealt.push(trckks.generate_secret_shares_from_poly(es_poly, &mut rng)?);
        t_deal_es.push(ms(t));

        sks.push(sk);
        pk_shares.push(pk_share);
    }
    let t = Instant::now();
    let pk = CkksPublicKeyShare::aggregate(&pk_shares)?;
    out.insert("dkg.pk_aggregate_ms".into(), ms(t));

    // Each party aggregates the rows it received from all n dealers.
    let mut t_agg = Vec::new();
    let mut sk_shares_j = Vec::with_capacity(n);
    let mut es_shares_j = Vec::with_capacity(n);
    for j in 0..n {
        let rows_sk = collect_rows(&sk_dealt, j);
        let rows_es = collect_rows(&es_dealt, j);
        let t = Instant::now();
        let s = trckks.aggregate_collected_shares(&rows_sk)?;
        let e = trckks.aggregate_collected_shares(&rows_es)?;
        t_agg.push(ms(t));
        sk_shares_j.push(s);
        es_shares_j.push(e);
    }
    drop(sk_dealt);
    drop(es_dealt);

    out.insert("dkg.sk_sample_ms".into(), median(&mut t_sample));
    out.insert("dkg.pk_share_gen_ms".into(), median(&mut t_pk));
    out.insert("dkg.deal_sk_shamir_ms".into(), median(&mut t_deal_sk));
    out.insert("dkg.deal_esm_shamir_ms".into(), median(&mut t_deal_es));
    out.insert("dkg.aggregate_received_ms".into(), median(&mut t_agg));
    out.insert("dkg.pk_share_bytes".into(), pk_share_bytes as f64);
    out.insert(
        "dkg.dealt_bytes_per_recipient_sk".into(),
        dealt_bytes_per_recipient as f64,
    );
    out.insert(
        "dkg.dealt_bytes_per_recipient_total".into(),
        (2 * dealt_bytes_per_recipient) as f64,
    );
    // A dealer sends (n-1) recipients sk+e_sm rows; the committee moves n
    // times that.
    out.insert(
        "dkg.dealt_bytes_per_party_out".into(),
        (2 * dealt_bytes_per_recipient * (n - 1)) as f64,
    );
    out.insert(
        "dkg.dealt_bytes_committee".into(),
        (2 * dealt_bytes_per_recipient * (n - 1) * n) as f64,
    );
    out.insert("dkg.per_party_total_ms".into(), {
        out["dkg.sk_sample_ms"]
            + out["dkg.pk_share_gen_ms"]
            + out["dkg.deal_sk_shamir_ms"]
            + out["dkg.deal_esm_shamir_ms"]
            + out["dkg.aggregate_received_ms"]
    });

    // Joint secret (for the precision chain only; never exists in a real
    // deployment).
    let mut joint = vec![0i64; params.degree()];
    for sk in &sks {
        for (j, c) in sk.coeffs.iter().enumerate() {
            joint[j] += *c;
        }
    }
    let sk_joint = CkksSecretKey::new(joint, params);

    // ── Relinearization ceremony ───────────────────────────────────────────
    // RNS: one ceremony per level; only the multiply-check key is kept
    // (holding every level's key would need ~12 GiB at N=65536 x 38 limbs).
    // Hybrid: ONE ceremony, the key serves every level.
    let deepest = mult_level(params);
    let mut deepest_rlk: Option<Relin> = None;
    let mut chain_rns: Vec<CkksRelinearizationKey> = Vec::new();
    let mut ceremony_total_ms = 0f64;
    let mut ceremony_bytes_per_party = 0f64;
    match keyswitch {
        KeySwitch::Rns => {
            for &level in levels {
                let (rlk, per_party, bytes) =
                    rns_ceremony(params, &sks, level, &mut out, &mut rng)?;
                ceremony_total_ms += per_party;
                ceremony_bytes_per_party += bytes;
                if level == deepest {
                    deepest_rlk = Some(Relin::Rns(rlk.clone()));
                }
                if chain_compare && level < depth {
                    chain_rns.push(rlk);
                }
            }
            out.insert("relin.levels_run".into(), levels.len() as f64);
        }
        KeySwitch::Hybrid => {
            let (rlk, per_party, bytes) = hybrid_ceremony(params, &sks, &mut out, &mut rng)?;
            ceremony_total_ms += per_party;
            ceremony_bytes_per_party += bytes;
            deepest_rlk = Some(Relin::Hybrid(rlk));
            out.insert("relin.levels_run".into(), 1.0);
            out.insert("relin.levels_served".into(), (num_limbs - 1) as f64);
        }
    }
    out.insert("relin.per_party_total_ms".into(), ceremony_total_ms);
    out.insert(
        "relin.upload_bytes_per_party".into(),
        ceremony_bytes_per_party,
    );
    out.insert(
        "relin.download_bytes_per_party".into(),
        ceremony_bytes_per_party * (n - 1) as f64,
    );
    out.insert(
        "relin.bytes_committee".into(),
        ceremony_bytes_per_party * n as f64,
    );

    // ── Threshold decryption of a fresh (level-0) ciphertext ───────────────
    let a: Vec<f64> = vec![1.5, -2.0, 0.25];
    let ct = pk.try_encrypt(&encoder.encode(&a, 0)?, &mut rng)?;
    out.insert("ct.fresh_bytes".into(), ct.to_bytes().len() as f64);
    let parties: Vec<usize> = (1..=threshold + 1).collect();
    let mut t_ds = Vec::new();
    let mut d_shares = Vec::new();
    let mut ds_bytes = 0usize;
    for &j in &parties {
        let sk_j = sk_shares_j[j - 1].clone().into_ntt();
        let es_j = es_shares_j[j - 1].clone();
        let t = Instant::now();
        let d = trckks.decryption_share(&ct, sk_j, es_j)?;
        t_ds.push(ms(t));
        ds_bytes = d.to_bytes().len();
        d_shares.push(d);
    }
    let t = Instant::now();
    let pt = trckks.decrypt(d_shares, parties.clone(), &ct)?;
    let t_combine = ms(t);
    let decoded = encoder.decode(&pt)?;
    let err = a
        .iter()
        .zip(decoded.iter())
        .map(|(x, y)| (x - y).abs())
        .fold(0f64, f64::max);
    out.insert("decrypt.share_ms".into(), median(&mut t_ds));
    out.insert("decrypt.combine_ms".into(), t_combine);
    out.insert("decrypt.share_bytes".into(), ds_bytes as f64);
    out.insert("decrypt.max_abs_error".into(), err);

    // ── One multiply + relin + rescale at the deepest level, then open ─────
    let x = vec![1.5, -2.0];
    let y = vec![2.0, 4.0];
    let mut ct_x = pk.try_encrypt(&encoder.encode(&x, 0)?, &mut rng)?;
    let mut ct_y = pk.try_encrypt(&encoder.encode(&y, 0)?, &mut rng)?;
    ct_x.mod_switch_to_level(deepest)?;
    ct_y.mod_switch_to_level(deepest)?;
    let rlk = deepest_rlk
        .as_ref()
        .expect("the multiply level is always in the level list");
    let t = Instant::now();
    let mut prod = ct_x.try_mul(&ct_y)?;
    let t_mul = ms(t);
    let t = Instant::now();
    rlk.relinearizes(&mut prod)?;
    let t_relin = ms(t);
    let t = Instant::now();
    prod.rescale()?;
    let t_rescale = ms(t);
    out.insert("mult.level".into(), deepest as f64);
    out.insert("mult.mul_ms".into(), t_mul);
    out.insert("mult.relin_ms".into(), t_relin);
    out.insert("mult.rescale_ms".into(), t_rescale);
    out.insert("ct.deepest_bytes".into(), prod.to_bytes().len() as f64);

    let mut t_ds = Vec::new();
    let mut d_shares = Vec::new();
    let mut ds_bytes = 0usize;
    for &j in &parties {
        let sk_j = trckks.project_share_to_level(&sk_shares_j[j - 1], prod.level)?;
        let es_j = trckks.project_share_to_level(&es_shares_j[j - 1], prod.level)?;
        let t = Instant::now();
        let d = trckks.decryption_share(&prod, sk_j.into_ntt(), es_j)?;
        t_ds.push(ms(t));
        ds_bytes = d.to_bytes().len();
        d_shares.push(d);
    }
    let t = Instant::now();
    let pt = trckks.decrypt(d_shares, parties, &prod)?;
    let t_combine = ms(t);
    let decoded = encoder.decode(&pt)?;
    let err = x
        .iter()
        .zip(y.iter())
        .zip(decoded.iter())
        .map(|((a, b), d)| (a * b - d).abs())
        .fold(0f64, f64::max);
    out.insert("mult.decrypt_share_ms".into(), median(&mut t_ds));
    out.insert("mult.decrypt_combine_ms".into(), t_combine);
    out.insert("mult.decrypt_share_bytes".into(), ds_bytes as f64);
    out.insert("mult.max_abs_error".into(), err);

    // ── Depth-4 chain precision (joint-secret decrypt) ─────────────────────
    if let Some(Relin::Hybrid(hk)) = &deepest_rlk {
        let e = chain_rel_error(
            &encoder,
            &pk,
            &sk_joint,
            depth,
            &|c, _| hk.relinearizes(c),
            &mut rng,
        )?;
        out.insert("mult.chain_depth".into(), depth as f64);
        out.insert("mult.chain_rel_error_hybrid".into(), e);
    }
    if chain_compare {
        // Make sure every chain level has an RNS key (hybrid mode runs no
        // RNS ceremony; rns mode may have skipped levels).
        let mut have: BTreeMap<usize, CkksRelinearizationKey> =
            chain_rns.into_iter().map(|k| (k.level(), k)).collect();
        let mut scratch = Run::new();
        for l in 0..depth {
            if let std::collections::btree_map::Entry::Vacant(slot) = have.entry(l) {
                let (k, _, _) = rns_ceremony(params, &sks, l, &mut scratch, &mut rng)?;
                slot.insert(k);
            }
        }
        let e = chain_rel_error(
            &encoder,
            &pk,
            &sk_joint,
            depth,
            &|c, l| have[&l].relinearizes(c),
            &mut rng,
        )?;
        out.insert("mult.chain_depth".into(), depth as f64);
        out.insert("mult.chain_rel_error_rns".into(), e);
    }

    Ok(out)
}

fn fmt_bytes(b: f64) -> String {
    if b >= 1024.0 * 1024.0 * 1024.0 {
        format!("{:.2} GiB", b / (1024.0 * 1024.0 * 1024.0))
    } else if b >= 1024.0 * 1024.0 {
        format!("{:.2} MiB", b / (1024.0 * 1024.0))
    } else if b >= 1024.0 {
        format!("{:.1} KiB", b / 1024.0)
    } else {
        format!("{b:.0} B")
    }
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let preset = preset(&args.preset)?;
    let keyswitch = match args.keyswitch.as_str() {
        "rns" => KeySwitch::Rns,
        "hybrid" => KeySwitch::Hybrid,
        other => return Err(format!("unknown --keyswitch {other} (rns|hybrid)").into()),
    };
    let mut builder = CkksParametersBuilder::new()
        .set_degree(preset.degree)
        .set_moduli_sizes(&preset.moduli_sizes)
        .set_scale(2f64.powi(preset.scale_bits));
    if keyswitch == KeySwitch::Hybrid {
        builder = builder.set_special_moduli_sizes(&vec![60usize; args.special_primes]);
        if let Some(d) = args.dnum {
            builder = builder.set_dnum(d);
        }
    }
    let params = builder.build_arc()?;
    let num_limbs = params.moduli().len();
    let log_q: usize = params.moduli_sizes().iter().sum();
    let levels = resolve_levels(&args.relin_levels, preset.name, &params);

    println!(
        "== preset {} : N={}, L={} limbs, log2(Q)={}, delta=2^{} ==",
        preset.name, preset.degree, num_limbs, log_q, preset.scale_bits
    );
    println!("   security: {}", preset.security_note);
    match keyswitch {
        KeySwitch::Rns => println!(
            "   keyswitch: rns   relin levels: {levels:?}   runs: {}",
            args.runs
        ),
        KeySwitch::Hybrid => println!(
            "   keyswitch: hybrid   k={} special primes (60-bit)   dnum={}   runs: {}",
            params.special_moduli().len(),
            params.dnum(),
            args.runs
        ),
    }

    let mut json_objects = Vec::new();
    for &n in &args.parties {
        let threshold = (n - 1) / 2;
        println!("\n-- n={n}, t={threshold} --");
        let mut runs: Vec<Run> = Vec::with_capacity(args.runs);
        for r in 0..args.runs {
            let t = Instant::now();
            runs.push(one_run(
                &params,
                n,
                threshold,
                &levels,
                args.smudging_bits,
                keyswitch,
                args.chain_compare,
            )?);
            println!("   run {} done in {:.1}s", r + 1, t.elapsed().as_secs_f64());
        }
        // min / median across runs.
        let mut agg: BTreeMap<String, (f64, f64)> = BTreeMap::new();
        for key in runs[0].keys() {
            let mut vals: Vec<f64> = runs.iter().map(|r| r[key]).collect();
            let min = vals.iter().cloned().fold(f64::INFINITY, f64::min);
            let med = median(&mut vals);
            agg.insert(key.clone(), (min, med));
        }

        for (k, (min, med)) in &agg {
            if k.contains("bytes") {
                println!("   {k:48} {:>14}", fmt_bytes(*med));
            } else if k.ends_with("_ms") {
                println!("   {k:48} min {min:10.2} ms   median {med:10.2} ms");
            } else {
                println!("   {k:48} {med}");
            }
        }

        let mut obj = String::new();
        obj.push_str("  {\n");
        obj.push_str(&format!(
            "    \"preset\": \"{}\", \"degree\": {}, \"limbs\": {}, \"log_q\": {}, \"scale_bits\": {},\n",
            preset.name, preset.degree, num_limbs, log_q, preset.scale_bits
        ));
        obj.push_str(&format!(
            "    \"security\": \"{}\",\n    \"moduli_sizes\": {:?},\n",
            json_escape(preset.security_note),
            preset.moduli_sizes
        ));
        obj.push_str(&format!(
            "    \"parties\": {n}, \"threshold\": {threshold}, \"runs\": {}, \"smudging_bits\": {},\n    \"relin_levels\": {:?},\n    \"keyswitch\": \"{}\", \"special_primes\": {}, \"dnum\": {},\n",
            args.runs,
            args.smudging_bits,
            levels,
            args.keyswitch,
            params.special_moduli().len(),
            params.dnum()
        ));
        obj.push_str("    \"metrics\": {\n");
        let entries: Vec<String> = agg
            .iter()
            .map(|(k, (min, med))| format!("      \"{k}\": {{\"min\": {min}, \"median\": {med}}}"))
            .collect();
        obj.push_str(&entries.join(",\n"));
        obj.push_str("\n    }\n  }");
        json_objects.push(obj);
    }

    if let Some(path) = &args.json {
        if let Some(parent) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(parent)?;
        }
        let machine = std::env::var("BENCH_MACHINE").unwrap_or_default();
        let doc = format!(
            "{{\n  \"machine\": \"{}\",\n  \"results\": [\n{}\n  ]\n}}\n",
            json_escape(&machine),
            json_objects.join(",\n")
        );
        std::fs::write(path, doc)?;
        println!("\nwrote {path}");
    }
    Ok(())
}
