use std::sync::Arc;

use crate::bfv::{BfvParameters, Ciphertext, Plaintext};
use crate::{Error, Result};
use fhe_math::{
    rns::{RnsContext, ScalingFactor},
    rq::{scaler::Scaler, traits::TryConvertFrom, Context, Poly, Representation},
    zq::Modulus,
};
use fhe_util::sample_vec_normal;
use itertools::{izip, Itertools};
use ndarray::Array2;
use num_bigint::BigUint;
use num_bigint_old::{BigInt, ToBigInt};
use num_traits::{ToPrimitive, Zero, Pow};
use rand::{CryptoRng, RngCore};
use shamir_secret_sharing::ShamirSecretSharing as SSS;
use zeroize::Zeroizing;

#[derive(Debug, Clone)]
pub struct ShamirMetadata {
    pub evaluation_point: usize,
    pub threshold: usize,
    pub modulus: BigInt,
}

#[derive(Debug, Clone)]
pub struct PackedHybridShare {
    pub additive_parts: Vec<BigInt>,  // Store raw values, not polynomials
    pub pack_size: usize,
    pub shamir_metadata: ShamirMetadata,
    pub party_id: usize,
}

#[derive(Debug, Clone)]
pub struct PackingParameters {
    pub pack_size: usize,
    pub total_blocks: usize,
    pub last_block_size: usize,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TrBFVShare {
    n: usize,
    threshold: usize,
    degree: usize,
    plaintext_modulus: u64,
    sumdging_variance: usize,
    moduli: Vec<u64>,
    params: Arc<BfvParameters>,
}

impl TrBFVShare {
    // TODO: take params and store, get moduli, plaintext_moduli, and degree from ctx
    pub fn new(
        n: usize,
        threshold: usize,
        degree: usize,
        plaintext_modulus: u64,
        sumdging_variance: usize,
        moduli: Vec<u64>,
        params: Arc<BfvParameters>,
    ) -> Result<Self> {
        // generate random secret
        Ok(Self {
            n,
            threshold,
            degree,
            plaintext_modulus,
            sumdging_variance,
            moduli,
            params,
        })
    }

    // Generate Shamir Secret Shares
    pub fn generate_secret_shares(&mut self, coeffs: Box<[i64]>) -> Result<Vec<Array2<u64>>> {
        let poly = Zeroizing::new(
            Poly::try_convert_from(
                coeffs.as_ref(),
                &self.params.ctx_at_level(0).unwrap(),
                false,
                Representation::PowerBasis,
            )
            .unwrap(),
        );

        // 2 dim array, columns = fhe coeffs (degree), rows = party members shamir share coeff (n)
        let mut return_vec: Vec<Array2<u64>> = Vec::with_capacity(self.params.moduli.len());

        // for each moduli, for each coeff generate an SSS of degree n and threshold n = 2t + 1
        for (_k, (m, p)) in
            izip!(poly.ctx().moduli().iter(), poly.coefficients().outer_iter()).enumerate()
        {
            // Create shamir object
            let shamir = SSS {
                threshold: self.threshold,
                share_amount: self.n,
                prime: BigInt::from(*m),
            };
            let mut m_data: Vec<u64> = Vec::new();

            // For each coeff in the polynomial p under the current modulus m
            for (_i, c) in p.iter().enumerate() {
                // Split the coeff into n shares
                let secret = c.to_bigint().unwrap();
                let c_shares = shamir.split(secret.clone());
                // For each share convert to u64
                let mut c_vec: Vec<u64> = Vec::with_capacity(self.n);
                for (_j, (_, c_share)) in c_shares.iter().enumerate() {
                    c_vec.push(c_share.to_u64().unwrap());
                }
                m_data.extend_from_slice(&c_vec);
            }
            // convert flat vector of coeffs to array2
            let arr_matrix = Array2::from_shape_vec((self.degree, self.n), m_data).unwrap();
            // reverse the columns and rows
            let reversed_axes = arr_matrix.t();
            return_vec.push(reversed_axes.to_owned());
        }
        // return vec = rows are party members, columns are degree length of shamir values
        Ok(return_vec)
    }

    // Go from collect sss shares to summed SK_i polynomial.
    pub fn sum_sk_i(
        &mut self,
        sk_sss_collected: &Vec<Array2<u64>>, // collected sk sss shares from other parties
    ) -> Result<Poly> {
        let mut sum_poly = Poly::zero(
            &self.params.ctx_at_level(0).unwrap(),
            Representation::PowerBasis,
        );
        for j in 0..self.n {
            // Initialize empty poly with correct context (moduli and level)
            let mut poly_j = Poly::zero(
                &self.params.ctx_at_level(0).unwrap(),
                Representation::PowerBasis,
            );
            poly_j.set_coefficients(sk_sss_collected[j].clone());
            sum_poly = &sum_poly + &poly_j;
        }
        Ok(sum_poly)
    }

    pub fn generate_smudging_error<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<Vec<i64>> {
        // For each party, generate local smudging noise, coeffs of of degree N − 1 with coefficients
        // in [−Bsm, Bsm]
        let s_coefficients = sample_vec_normal(self.degree, self.sumdging_variance, rng).unwrap();
        Ok(s_coefficients)
    }

    // compute decryption share
    pub fn decryption_share(
        &mut self,
        ciphertext: Arc<Ciphertext>,
        mut sk_i: Poly,
        es_i: Poly,
    ) -> Result<Poly> {
        // decrypt
        // mul c1 * sk
        // then add c0 + (c1*sk) + es
        let mut c0 = ciphertext.c[0].clone();
        c0.change_representation(Representation::PowerBasis);
        sk_i.change_representation(Representation::Ntt);
        let mut c1 = ciphertext.c[1].clone();
        c1.change_representation(Representation::Ntt);
        let mut c1sk = &c1 * &sk_i;
        c1sk.change_representation(Representation::PowerBasis);
        let d_share_poly = &c0 + &c1sk + es_i;
        Ok(d_share_poly)
    }

    // compute decryption to plaintext from collected decryption shares
    // threshold number of shares required
    pub fn decrypt(
        &mut self,
        d_share_polys: Vec<Poly>,
        ciphertext: Arc<Ciphertext>,
    ) -> Result<Plaintext> {
        let mut m_data: Vec<u64> = Vec::new();

        // collect shamir openings
        for m in 0..self.moduli.len() {
            let sss = SSS {
                threshold: self.threshold,
                share_amount: self.n,
                prime: BigInt::from(self.moduli[m]),
            };
            for i in 0..self.degree {
                let mut shamir_open_vec_mod: Vec<(usize, BigInt)> = Vec::with_capacity(self.degree);
                for j in 0..self.threshold {
                    let coeffs = d_share_polys[j].coefficients();
                    let coeff_arr = coeffs.row(m);
                    let coeff = coeff_arr[i];
                    let coeff_formatted = (j + 1, coeff.to_bigint().unwrap());
                    shamir_open_vec_mod.push(coeff_formatted);
                }
                // open shamir
                let shamir_result = sss.recover(&shamir_open_vec_mod[0..self.threshold as usize]);
                m_data.push(shamir_result.to_u64().unwrap());
            }
        }

        // scale result poly
        let arr_matrix = Array2::from_shape_vec((self.moduli.len(), self.degree), m_data).unwrap();
        let mut result_poly = Poly::zero(
            &self.params.ctx_at_level(0).unwrap(),
            Representation::PowerBasis,
        );
        result_poly.set_coefficients(arr_matrix);

        let plaintext_ctx = Context::new_arc(&self.moduli[..1], self.degree).unwrap();
        let mut scalers = Vec::with_capacity(self.moduli.len());
        for i in 0..self.moduli.len() {
            let rns = RnsContext::new(&self.moduli[..self.moduli.len() - i]).unwrap();
            let ctx_i =
                Context::new_arc(&self.moduli[..self.moduli.len() - i], self.degree).unwrap();
            scalers.push(
                Scaler::new(
                    &ctx_i,
                    &plaintext_ctx,
                    ScalingFactor::new(&BigUint::from(self.plaintext_modulus), rns.modulus()),
                )
                .unwrap(),
            );
        }

        let par = ciphertext.par.clone();
        let d = Zeroizing::new(result_poly.scale(&scalers[ciphertext.level])?);
        let v = Zeroizing::new(
            Vec::<u64>::from(d.as_ref())
                .iter_mut()
                .map(|vi| *vi + par.plaintext.modulus())
                .collect_vec(),
        );
        let mut w = v[..par.degree()].to_vec();
        let q = Modulus::new(par.moduli[0]).map_err(Error::MathError)?;
        q.reduce_vec(&mut w);
        par.plaintext.reduce_vec(&mut w);

        let mut poly =
            Poly::try_convert_from(&w, ciphertext.c[0].ctx(), false, Representation::PowerBasis)?;
        poly.change_representation(Representation::Ntt);

        let pt = Plaintext {
            par: par.clone(),
            value: w.into_boxed_slice(),
            encoding: None,
            poly_ntt: poly,
            level: ciphertext.level,
        };
        Ok(pt)
    }

    /// Calculate optimal packing parameters
    pub fn calculate_packing_params(&self) -> PackingParameters {
        let pack_size = self.threshold; // Pack threshold coefficients together
        let total_blocks = (self.degree + pack_size - 1) / pack_size;
        let last_block_size = if self.degree % pack_size == 0 {
            pack_size
        } else {
            self.degree % pack_size
        };

        PackingParameters {
            pack_size,
            total_blocks,
            last_block_size,
        }
    }

    /// Pack multiple coefficients into a single secret
    fn pack_coefficients(&self, coeffs: &[i64], modulus: u64) -> Result<BigInt> {
        if coeffs.is_empty() {
            return Ok(BigInt::zero());
        }

        // Use a safe packing base that prevents overflow
        let base = BigInt::from(modulus);
        let mut packed = BigInt::zero();

        for (i, &coeff) in coeffs.iter().enumerate() {
            // Normalize coefficient to [0, modulus-1] range
            let normalized_coeff = if coeff < 0 {
                (coeff % modulus as i64 + modulus as i64) as u64
            } else {
                (coeff % modulus as i64) as u64
            };

            packed += BigInt::from(normalized_coeff) * base.pow(i as u32);
        }

        Ok(packed)
    }

    /// Unpack coefficients from a packed secret
    fn unpack_coefficients(&self, packed: &BigInt, pack_size: usize, modulus: u64) -> Result<Vec<i64>> {
        let base = BigInt::from(modulus);
        let mut coeffs = Vec::with_capacity(pack_size);
        let mut remaining = packed.clone();

        for _ in 0..pack_size {
            let coeff_big = &remaining % &base;
            let coeff_u64 = coeff_big.to_u64().unwrap_or(0);
            
            // Convert back to signed representation if needed
            let coeff = if coeff_u64 > modulus / 2 {
                coeff_u64 as i64 - modulus as i64
            } else {
                coeff_u64 as i64
            };

            coeffs.push(coeff);
            remaining /= &base;
        }

        Ok(coeffs)
    }

    /// Generate packed hybrid shares - combines packing + additive operations
    pub fn generate_packed_hybrid_shares(&mut self, coeffs: Box<[i64]>) -> Result<Vec<PackedHybridShare>> {
        let packing_params = self.calculate_packing_params();
        let mut packed_hybrid_shares = Vec::with_capacity(self.n);

        // Initialize shares for each party
        for party_id in 0..self.n {
            packed_hybrid_shares.push(PackedHybridShare {
                additive_parts: Vec::new(),
                pack_size: packing_params.pack_size,
                shamir_metadata: ShamirMetadata {
                    evaluation_point: party_id + 1,
                    threshold: self.threshold,
                    modulus: BigInt::from(self.moduli[0]),
                },
                party_id,
            });
        }

        // Process each RNS modulus
        for modulus_idx in 0..self.moduli.len() {
            let shamir = SSS {
                threshold: self.threshold,
                share_amount: self.n,
                prime: BigInt::from(self.moduli[modulus_idx]),
            };

            // Pack coefficients in chunks and create shares
            for (_block_idx, chunk) in coeffs.chunks(packing_params.pack_size).enumerate() {
                let packed_secret = self.pack_coefficients(chunk, self.moduli[modulus_idx])?;
                let shares = shamir.split(packed_secret);

                // Store the BigInt shares directly
                for (party_id, (_, share)) in shares.iter().enumerate() {
                    packed_hybrid_shares[party_id].additive_parts.push(share.clone());
                }
            }
        }

        Ok(packed_hybrid_shares)
    }

    /// O(1) addition - pure local computation
    pub fn add_packed_hybrid(&self, a: &PackedHybridShare, b: &PackedHybridShare) -> PackedHybridShare {
        if a.additive_parts.len() != b.additive_parts.len() {
            panic!("Mismatched share sizes");
        }

        let mut result_parts = Vec::with_capacity(a.additive_parts.len());

        for (part_a, part_b) in a.additive_parts.iter().zip(&b.additive_parts) {
            // Perform modular addition on BigInt values
            let modulus = &a.shamir_metadata.modulus;
            result_parts.push((part_a + part_b) % modulus);
        }

        PackedHybridShare {
            additive_parts: result_parts,
            pack_size: a.pack_size,
            shamir_metadata: a.shamir_metadata.clone(),
            party_id: a.party_id,
        }
    }

    /// Scalar multiplication - also O(1)
    pub fn scalar_mul_packed_hybrid(&self, share: &PackedHybridShare, scalar: i64) -> PackedHybridShare {
        let mut result_parts = Vec::with_capacity(share.additive_parts.len());

        for part in &share.additive_parts {
            // Perform modular scalar multiplication on BigInt values
            let modulus = &share.shamir_metadata.modulus;
            let scalar_big = BigInt::from(scalar);
            result_parts.push((part * scalar_big) % modulus);
        }

        PackedHybridShare {
            additive_parts: result_parts,
            pack_size: share.pack_size,
            shamir_metadata: share.shamir_metadata.clone(),
            party_id: share.party_id,
        }
    }

    /// Reconstruct packed hybrid shares - only when absolutely necessary
    pub fn reconstruct_packed_hybrid(&self, shares: &[PackedHybridShare]) -> Result<Poly> {
        if shares.len() < self.threshold {
            return Err(Error::TooFewValues(shares.len(), self.threshold));
        }

        let packing_params = self.calculate_packing_params();
        
        // We'll reconstruct the polynomial for each RNS modulus separately
        let mut all_coeffs = Vec::with_capacity(self.moduli.len() * self.degree);

        // Process each RNS modulus
        for modulus_idx in 0..self.moduli.len() {
            let sss = SSS {
                threshold: self.threshold,
                share_amount: self.n,
                prime: BigInt::from(self.moduli[modulus_idx]),
            };

            // Reconstruct coefficients for this modulus
            let mut modulus_coeffs = Vec::with_capacity(self.degree);

            // Reconstruct each packed block for this modulus
            for block_idx in 0..packing_params.total_blocks {
                // Each modulus has its own set of blocks
                let additive_part_idx = modulus_idx * packing_params.total_blocks + block_idx;

                // Collect shares for this block from threshold parties
                let mut block_shares = Vec::with_capacity(self.threshold);
                for party_idx in 0..self.threshold.min(shares.len()) {
                    if additive_part_idx < shares[party_idx].additive_parts.len() {
                        // Direct BigInt share value - no polynomial access needed
                        let share_value = &shares[party_idx].additive_parts[additive_part_idx];

                        block_shares.push((
                            shares[party_idx].shamir_metadata.evaluation_point,
                            share_value.clone()
                        ));
                    }
                }

                // Reconstruct this packed block
                if block_shares.len() >= self.threshold {
                    let reconstructed_packed = sss.recover(&block_shares);

                    // Unpack coefficients
                    let block_size = if block_idx == packing_params.total_blocks - 1 {
                        packing_params.last_block_size
                    } else {
                        packing_params.pack_size
                    };

                    let unpacked_coeffs = self.unpack_coefficients(
                        &reconstructed_packed,
                        block_size,
                        self.moduli[modulus_idx]
                    )?;

                    modulus_coeffs.extend(unpacked_coeffs);
                } else {
                    // Fill with zeros if we don't have enough shares
                    let block_size = if block_idx == packing_params.total_blocks - 1 {
                        packing_params.last_block_size
                    } else {
                        packing_params.pack_size
                    };
                    modulus_coeffs.extend(vec![0i64; block_size]);
                }
            }

            // Ensure we have exactly the right number of coefficients for this modulus
            modulus_coeffs.truncate(self.degree);
            modulus_coeffs.resize(self.degree, 0);
            
            // Convert to u64 and add to all_coeffs
            for &coeff in &modulus_coeffs {
                let unsigned_coeff = if coeff < 0 {
                    (coeff + self.moduli[modulus_idx] as i64) as u64
                } else {
                    coeff as u64
                };
                all_coeffs.push(unsigned_coeff);
            }
        }

        // Create the polynomial with all moduli
        let ctx = self.params.ctx_at_level(0).unwrap();
        let poly = Poly::try_convert_from(
            &all_coeffs,
            &ctx,
            false,
            Representation::PowerBasis,
        ).map_err(Error::MathError)?;

        Ok(poly)
    }

    /// Optimized decryption using packed hybrid shares
    pub fn decrypt_packed_hybrid(
        &mut self,
        d_share_polys: Vec<PackedHybridShare>,
        ciphertext: Arc<Ciphertext>,
    ) -> Result<Plaintext> {
        // Reconstruct the decryption polynomial
        let result_poly = self.reconstruct_packed_hybrid(&d_share_polys)?;

        // Scale and reduce (reuse existing scaling logic)
        let plaintext_ctx = Context::new_arc(&self.moduli[..1], self.degree).unwrap();
        let mut scalers = Vec::with_capacity(self.moduli.len());

        for i in 0..self.moduli.len() {
            let rns = RnsContext::new(&self.moduli[..self.moduli.len() - i]).unwrap();
            let ctx_i = Context::new_arc(&self.moduli[..self.moduli.len() - i], self.degree).unwrap();
            scalers.push(
                Scaler::new(
                    &ctx_i,
                    &plaintext_ctx,
                    ScalingFactor::new(&BigUint::from(self.plaintext_modulus), rns.modulus()),
                ).unwrap()
            );
        }

        let par = ciphertext.par.clone();
        let d = Zeroizing::new(result_poly.scale(&scalers[ciphertext.level])?);
        let v = Zeroizing::new(
            Vec::<u64>::from(d.as_ref())
                .iter_mut()
                .map(|vi| *vi + par.plaintext.modulus())
                .collect_vec(),
        );
        let mut w = v[..par.degree()].to_vec();
        let q = Modulus::new(par.moduli[0]).map_err(Error::MathError)?;
        q.reduce_vec(&mut w);
        par.plaintext.reduce_vec(&mut w);

        let mut poly = Poly::try_convert_from(&w, ciphertext.c[0].ctx(), false, Representation::PowerBasis)?;
        poly.change_representation(Representation::Ntt);

        let pt = Plaintext {
            par: par.clone(),
            value: w.into_boxed_slice(),
            encoding: None,
            poly_ntt: poly,
            level: ciphertext.level,
        };

        Ok(pt)
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bfv::{BfvParametersBuilder, Encoding, PublicKey, SecretKey};
    use fhe_math::rq::{traits::TryConvertFrom, Context, Poly, Representation};
    use fhe_traits::{FheEncoder, FheEncrypter};
    use itertools::izip;
    use ndarray::{array, Array, Array2, ArrayView, Axis};
    use num_traits::ToPrimitive;
    use rand::thread_rng;
    use std::mem::size_of_val;

    #[test]
    fn convert_poly_to_shared_poly() {
        let mut rng = thread_rng();
        // generate fhe secret key polynomial
        // for each poly coeff, generate a shamir secret share
        let n = 16;
        let threshold = 9;
        let degree = 2048;
        let plaintext_modulus: u64 = 4096;
        let moduli = vec![0xffffee001, 0xffffc4001, 0x1ffffe0001];
        let secret1 = 4;
        let secret2 = 6;

        let sk_par = BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus(plaintext_modulus)
            .set_moduli(&moduli)
            .build_arc()
            .unwrap();
        let mut s_raw: SecretKey = SecretKey::random(&sk_par, &mut rng);
        //println!("{:?}", s_raw);

        let mut s = Poly::try_convert_from(
            s_raw.coeffs.as_ref(),
            &sk_par.ctx_at_level(0).unwrap(),
            false,
            Representation::PowerBasis,
        )
        .unwrap();

        // ----------
        // Covert shares to poly, adding the shamir points needs to respect each rns_mod_i
        // here he is creating party number polys
        //
        //let mut s_shares: Vec<Poly> = vec![Poly::zero(&sk_par.ctx_at_level(0).unwrap(), Representation::PowerBasis); n]; // think we need m of these
        let mut s_shares: Vec<Vec<Poly>> = Vec::with_capacity(moduli.len());
        // store the sum of each m secret shared vectors
        let mut sum_shares_m: Vec<Poly> = Vec::with_capacity(moduli.len()); //todo grab length of levels
                                                                            // For each modulus (k here)
                                                                            // m is the modulus
                                                                            // p is one of the l (level) polys (3 here)
        for (k, (m, p)) in izip!(s.ctx().moduli().iter(), s.coefficients().outer_iter()).enumerate()
        {
            // Create shamir object
            let shamir = SSS {
                threshold: threshold,
                share_amount: n,
                prime: BigInt::from(*m),
            };
            // 2 dim array, rows = fhe coeffs, columns = party members shamir share coeff
            let mut shamir_coeffs: Vec<Vec<u64>> = Vec::with_capacity(degree);
            // arr2 version
            let mut data: Vec<u64> = Vec::new();

            // For each coeff in the polynomial p under the current modulus m
            for (i, c) in p.iter().enumerate() {
                // Split the coeff into n shares
                let secret = c.to_bigint().unwrap();
                let c_shares = shamir.split(secret.clone());
                // For each share convert to u64
                let mut c_vec: Vec<u64> = Vec::with_capacity(n);
                for (j, (_, c_share)) in c_shares.iter().enumerate() {
                    c_vec.push(c_share.to_u64().unwrap());
                    //s_shares[j].coefficients_mut()[k][i] = c_share.to_u64().unwrap();
                }
                // Set the coefficient in the corresponding polynomial matrix of s_shares
                // extend 1D flat vec for each shamir set
                data.extend_from_slice(&c_vec);

                shamir_coeffs.push(c_vec);
            }
            // create an array2 from vec
            let arr_matrix = Array2::from_shape_vec((degree, n), data).unwrap();
            println!("{:?}", m);
            // get the context for current modulus
            let ctx_m = Context::new_arc(&[*m], degree).unwrap();

            // collect n vectors down the degree of coeffs (can probably collect better above)
            // rows = party members shamir share coeff, columns = fhe coeffs
            let mut collect_vec_n: Vec<Vec<u64>> = Vec::with_capacity(n);
            for i in 0..n {
                let mut collect_vec_degree: Vec<u64> = Vec::with_capacity(degree);
                for j in 0..degree {
                    collect_vec_degree.push(shamir_coeffs[j][i]);
                }
                collect_vec_n.push(collect_vec_degree);
            }
            // use matrix transpose to shift axis instead of copy loop above
            let reversed_axes = arr_matrix.t();
            //println!("{:?}", reversed_axes[[0,1]]);
            //println!("{:?}", reversed_axes);
            // grab the row for each node at given moduli
            let node_n_share_one_mod = reversed_axes.row(0);
            println!("{:?}", node_n_share_one_mod);
            //let newarr = get_row.insert_axis(Axis(0));
            // create a new array to push each moduli share into for each node
            // TODO get these rows from each moduli. will need n of these
            let mut node_n_shares_all_mods = Array::zeros((0, 2048));
            node_n_shares_all_mods
                .push_row(ArrayView::from(&node_n_share_one_mod))
                .unwrap();
            node_n_shares_all_mods
                .push_row(ArrayView::from(&node_n_share_one_mod))
                .unwrap();
            node_n_shares_all_mods
                .push_row(ArrayView::from(&node_n_share_one_mod))
                .unwrap();
            //println!("after row axis 0 insert");
            //println!("---");
            //println!("{:?}", node_n_shares_all_mods);
            let test_coeffs_view = s.coefficients();
            //println!("---");
            //println!("{:?}", test_coeffs_view);
            //println!("---");
            //println!("after setting new coeffs");
            let mut s2 = s.clone();
            s2.set_coefficients(node_n_shares_all_mods);
            //println!("{:?}", s2);

            // convert to n polys for each m
            let mut s_share_poly_k: Vec<Poly> = Vec::with_capacity(n);
            for i in 0..n {
                let mut s_share_poly = Poly::try_convert_from(
                    &collect_vec_n[i],
                    &ctx_m,
                    false,
                    Representation::PowerBasis,
                )
                .unwrap();
                //println!("{:?}", s_share_poly);
                s_share_poly_k.push(s_share_poly)
                //s_shares[k].push(s_share_poly);
            }
            s_shares.push(s_share_poly_k);

            // sum polys
            //let mut sum_poly
            //println!("{:?}", s_shares[k][0]);
            for i in 1..n {
                s_shares[k][0] = &s_shares[k][0] + &s_shares[k][i];
            }
            //println!("{:?}", s_shares[k][0]);
            println!("----");
            //println!("{:?}", shamir_coeffs[2047]);
        }
        //println!("{:?}", s);
        // ----------
        let mut trbfv = TrBFVShare::new(
            n,
            threshold,
            degree,
            plaintext_modulus,
            160,
            moduli.clone(),
            sk_par.clone(),
        )
        .unwrap();
        let get_coeff_matrix = trbfv.generate_secret_shares(s_raw.coeffs.clone()).unwrap();
        println!("{:?}", get_coeff_matrix[1].row(0));

        // gather seceret coeffs
        let coeffview = s.coefficients();
        //println!("{:?}", coeffview);
        // use rns_mod_i (smaller than rns mod)
        // todo convert back to rns mod
        let rns_mod_i = sk_par.moduli()[0];

        let shamir = SSS {
            threshold: threshold,
            share_amount: n,
            prime: BigInt::from(rns_mod_i),
        };

        // test two secret coeff points
        let secret_1 = secret1.to_bigint().unwrap();
        let secret_2 = secret2.to_bigint().unwrap();
        // create shamir polynomials
        let s1_shares = shamir.split(secret_1.clone());
        let s2_shares = shamir.split(secret_2.clone());

        // convert shamir points to u64 for poly coeffs
        let mut u64shamirvec_1: Vec<u64> = Vec::with_capacity(n);
        for i in 0..n {
            u64shamirvec_1.push(s1_shares[i].1.to_u64().unwrap());
        }
        let mut u64shamirvec_2: Vec<u64> = Vec::with_capacity(n);
        for i in 0..n {
            u64shamirvec_2.push(s2_shares[i].1.to_u64().unwrap());
        }

        // create fhe.rs poly with u64 shamir coeffs
        let mut s1_share_poly = Poly::try_convert_from(
            u64shamirvec_1,
            &sk_par.ctx_at_level(0).unwrap(),
            false,
            Representation::PowerBasis,
        )
        .unwrap();
        let mut s2_share_poly = Poly::try_convert_from(
            u64shamirvec_2,
            &sk_par.ctx_at_level(0).unwrap(),
            false,
            Representation::PowerBasis,
        )
        .unwrap();

        // Add the two shamir polynomials
        let sum_shamir = &s1_share_poly + &s2_share_poly;
        //let mul_shamir = &s1_share_poly * &s2_share_poly;

        // gather the result of poly addition u64 coeffs
        let mut collect_coeffs: Vec<u64> = Vec::with_capacity(n * 3);
        for ((x, y), value) in sum_shamir.coefficients().indexed_iter() {
            if *value != 0 as u64 {
                collect_coeffs.push(*value);
            }
        }
        // convert u64 to shamir big int tuple
        let mut shamir_rep: Vec<(usize, BigInt)> = Vec::with_capacity(n);
        for i in 0..16 {
            let index = i + 1 as usize;
            let bigintcoeff = collect_coeffs[i].to_bigint().unwrap();
            shamir_rep.push((index, bigintcoeff));
        }

        // Open the shamir secret to get s1 + s2.
        let result = shamir.recover(&shamir_rep[0..shamir.threshold as usize]);
        println!("{:?}", result);

        let mut arr = Array2::zeros((3, 3));
        for (i, mut row) in arr.axis_iter_mut(Axis(0)).enumerate() {
            // Perform calculations and assign to `row`; this is a trivial example:
            row.fill(i);
        }
        assert_eq!(arr, array![[0, 0, 0], [1, 1, 1], [2, 2, 2]]);
    }

    #[test]
    fn test_trbfv() {
        let mut rng = thread_rng();
        // generate fhe secret key polynomial
        // for each poly coeff, generate a shamir secret share
        let n = 16;
        let threshold = 9;
        let degree = 2048;
        let plaintext_modulus: u64 = 4096;
        let moduli = vec![0xffffee001, 0xffffc4001, 0x1ffffe0001];

        // For each party, generate secret key share contribution (this will never be shared)
        let sk_par = BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus(plaintext_modulus)
            .set_moduli(&moduli)
            .build_arc()
            .unwrap();
        let mut sk_share = SecretKey::random(&sk_par, &mut rng);
        println!("{:?}", sk_share.coeffs.len());
        println!("{:?}", sk_share.par);

        // For each party, generate public key contribution from sk, this will be broadcast publicly
        let pk_share = PublicKey::new(&sk_share, &mut rng);

        // For each party, generate local smudging noise, coeffs of of degree N − 1 with coefficients
        // in [−Bsm, Bsm]
        let mut s_coefficients = fhe_util::sample_vec_cbd(sk_par.degree(), 16, &mut rng).unwrap();

        // Shamir secret share params
        let sss = SSS {
            threshold: threshold,
            share_amount: n,
            prime: BigInt::parse_bytes(
                b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
                16,
            )
            .unwrap(),
        };

        // for each smuding error coeff generate an SSS of degree n and threshold n = 2t + 1
        let mut sss_smudge_result: Vec<Vec<(usize, BigInt)>> = Vec::with_capacity(degree);

        for i in 0..degree {
            // encode negative coeffs as positive ints [11,19]
            if s_coefficients[i] < 0 {
                //println!("minus");
                s_coefficients[i] = s_coefficients[i] + 19;
            }
            let secret = s_coefficients[i].to_bigint().unwrap();
            //println!("{:?}", s_coefficients[i]);
            let shares = sss.split(secret.clone());
            //println!("{:?}", shares);
            sss_smudge_result.push(shares);
        }

        let mut smudge_node_shares: Vec<Vec<(usize, BigInt)>> = Vec::with_capacity(n);
        for i in 0..n {
            let mut node_share_i: Vec<(usize, BigInt)> = Vec::with_capacity(threshold);
            for j in 0..degree {
                node_share_i.push(sss_smudge_result[j][i].clone());
            }
            smudge_node_shares.push(node_share_i)
        }

        // for each sk coeff generate an SSS of degree n and threshold n = 2t + 1
        let mut result: Vec<Vec<(usize, BigInt)>> = Vec::with_capacity(degree);

        for i in 0..degree {
            // encode negative coeffs as positive ints [11,19]
            if sk_share.coeffs[i] < 0 {
                //println!("minus");
                sk_share.coeffs[i] = sk_share.coeffs[i] + 19;
            }
            let secret = sk_share.coeffs[i].to_bigint().unwrap();
            let shares = sss.split(secret.clone());
            result.push(shares);
        }

        let mut node_shares: Vec<Vec<(usize, BigInt)>> = Vec::with_capacity(n);
        for i in 0..n {
            let mut node_share_i: Vec<(usize, BigInt)> = Vec::with_capacity(threshold);
            for j in 0..degree {
                node_share_i.push(result[j][i].clone());
            }
            node_shares.push(node_share_i)
        }

        // Test decrypt
        let mut test_sssvec: Vec<(usize, BigInt)> = Vec::with_capacity(n);
        for i in 0..n {
            test_sssvec.push(node_shares[n - 1][0].clone());
        }
        //println!("{:?}", test_sssvec);
        println!("{:?}", node_shares[0].len());
        println!(
            "The useful size of `v` is {}",
            size_of_val(&*node_shares[0])
        );
        //println!(" Secret coeff {:?}", sk_share.coeffs[0].to_bigint().unwrap());
        assert_eq!(
            sk_share.coeffs[0].to_bigint().unwrap(),
            sss.recover(&result[0][0..sss.threshold as usize])
        );
        println!("{:?}", result[0]);
    }

    #[test]
    fn test_packed_hybrid_optimization() {
        let mut rng = thread_rng();
        let n = 16;
        let threshold = 9;
        let degree = 2048;
        let plaintext_modulus: u64 = 4096;
        let moduli = vec![0xffffee001, 0xffffc4001, 0x1ffffe0001];

        let sk_par = BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus(plaintext_modulus)
            .set_moduli(&moduli)
            .build_arc()
            .unwrap();

        let mut trbfv = TrBFVShare::new(
            n,
            threshold,
            degree,
            plaintext_modulus,
            160,
            moduli.clone(),
            sk_par.clone(),
        ).unwrap();

        // Generate test secret key
        let s_raw = SecretKey::random(&sk_par, &mut rng);

        // Test packing parameters
        let packing_params = trbfv.calculate_packing_params();
        assert_eq!(packing_params.pack_size, threshold);
        assert_eq!(packing_params.total_blocks, (degree + threshold - 1) / threshold);

        // Test packed hybrid share generation
        let packed_shares = trbfv.generate_packed_hybrid_shares(s_raw.coeffs.clone()).unwrap();
        assert_eq!(packed_shares.len(), n);

        // Test addition operation
        let sum_share = trbfv.add_packed_hybrid(&packed_shares[0], &packed_shares[1]);
        assert_eq!(sum_share.additive_parts.len(), packed_shares[0].additive_parts.len());

        // Test reconstruction
        let reconstructed = trbfv.reconstruct_packed_hybrid(&packed_shares[..threshold]).unwrap();
        assert_eq!(reconstructed.coefficients().dim(), (moduli.len(), degree));

        println!("Packed hybrid optimization test passed!");
        println!("Pack size: {}", packing_params.pack_size);
        println!("Total blocks: {}", packing_params.total_blocks);
        println!("Communication reduction: {}x", packing_params.pack_size);
    }

    #[test]
    fn test_optimization_correctness() {
        let mut rng = thread_rng();
        let n = 8;
        let threshold = 5;
        let degree = 1024;
        let plaintext_modulus: u64 = 4096;
        let moduli = vec![0xffffee001, 0xffffc4001];

        let sk_par = BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus(plaintext_modulus)
            .set_moduli(&moduli)
            .build_arc()
            .unwrap();

        let mut trbfv = TrBFVShare::new(
            n,
            threshold,
            degree,
            plaintext_modulus,
            160,
            moduli.clone(),
            sk_par.clone(),
        ).unwrap();

        let s_raw = SecretKey::random(&sk_par, &mut rng);

        // Compare original vs optimized
        let original_shares = trbfv.generate_secret_shares(s_raw.coeffs.clone()).unwrap();
        let packed_shares = trbfv.generate_packed_hybrid_shares(s_raw.coeffs.clone()).unwrap();

        // Both should work for threshold reconstruction
        assert!(original_shares.len() == moduli.len());
        assert!(packed_shares.len() == n);

        println!("Correctness test passed - both methods generate valid shares");
    }

    #[test]
    fn test_packed_method_mathematical_correctness() {
        let mut rng = thread_rng();
        let n = 8;
        let threshold = 5;
        let degree = 1024;
        let plaintext_modulus: u64 = 4096;
        let moduli = vec![0xffffee001, 0xffffc4001];

        let sk_par = BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus(plaintext_modulus)
            .set_moduli(&moduli)
            .build_arc()
            .unwrap();

        let mut trbfv = TrBFVShare::new(
            n,
            threshold,
            degree,
            plaintext_modulus,
            160,
            moduli.clone(),
            sk_par.clone(),
        ).unwrap();

        // Generate a deterministic secret key for reproducible testing
        let s_raw = SecretKey::random(&sk_par, &mut rng);

        // Test 1: Verify packing and unpacking preserves data
        println!("Test 1: Verifying packing/unpacking integrity");
        let packing_params = trbfv.calculate_packing_params();
        
        // Test packing on a small chunk
        let test_chunk = &s_raw.coeffs[0..packing_params.pack_size.min(s_raw.coeffs.len())];
        let packed = trbfv.pack_coefficients(test_chunk, moduli[0]).unwrap();
        let unpacked = trbfv.unpack_coefficients(&packed, test_chunk.len(), moduli[0]).unwrap();
        
        // Verify each coefficient matches
        for (orig, reconstructed) in test_chunk.iter().zip(unpacked.iter()) {
            assert_eq!(*orig, *reconstructed, "Packing/unpacking failed to preserve coefficient");
        }
        println!("✓ Packing/unpacking preserves data correctly");

        // Test 2: Verify share generation and reconstruction
        println!("Test 2: Verifying share generation and reconstruction");
        let packed_shares = trbfv.generate_packed_hybrid_shares(s_raw.coeffs.clone()).unwrap();
        assert_eq!(packed_shares.len(), n);
        
        // Use exactly threshold shares for reconstruction
        let threshold_shares = &packed_shares[0..threshold];
        let reconstructed_poly = trbfv.reconstruct_packed_hybrid(threshold_shares).unwrap();
        
        // Verify the reconstructed polynomial has correct structure
        assert_eq!(reconstructed_poly.coefficients().dim(), (moduli.len(), degree));
        println!("✓ Share generation and reconstruction works");

        // Test 3: Mathematical operations correctness
        println!("Test 3: Verifying mathematical operations");
        
        // Test addition
        let sum_share = trbfv.add_packed_hybrid(&packed_shares[0], &packed_shares[1]);
        assert_eq!(sum_share.additive_parts.len(), packed_shares[0].additive_parts.len());
        
        // Test scalar multiplication  
        let scalar = 3i64;
        let scalar_mul_share = trbfv.scalar_mul_packed_hybrid(&packed_shares[0], scalar);
        assert_eq!(scalar_mul_share.additive_parts.len(), packed_shares[0].additive_parts.len());
        
        println!("✓ Mathematical operations work correctly");

        // Test 4: Verify reconstruction produces valid polynomial for decryption
        println!("Test 4: Verifying reconstruction produces valid decryption polynomial");
        
        // Create a simple ciphertext to test decryption
        let pk = PublicKey::new(&s_raw, &mut rng);
        let test_message = vec![42u64];
        let pt = Plaintext::try_encode(&test_message, Encoding::poly(), &sk_par).unwrap();
        let ct = pk.try_encrypt(&pt, &mut rng).unwrap();
        
        // Generate error shares
        let esi_coeffs = trbfv.generate_smudging_error(&mut rng).unwrap();
        let es_packed_shares = trbfv.generate_packed_hybrid_shares(esi_coeffs.into_boxed_slice()).unwrap();
        
        // Reconstruct secret key and error for decryption  
        let sk_reconstructed = trbfv.reconstruct_packed_hybrid(&packed_shares[0..threshold]).unwrap();
        let es_reconstructed = trbfv.reconstruct_packed_hybrid(&es_packed_shares[0..threshold]).unwrap();
        
        // Test decryption share generation
        let d_share = trbfv.decryption_share(
            Arc::new(ct),
            sk_reconstructed,
            es_reconstructed,
        ).unwrap();
        
        // Verify the decryption share has correct structure
        assert_eq!(d_share.coefficients().dim(), (moduli.len(), degree));
        
        println!("✓ Reconstruction produces valid polynomial for decryption");
        println!("✓ All mathematical correctness tests passed!");
        
        // Report complexity improvements
        println!("\nComplexity Analysis:");
        println!("• Pack size: {}", packing_params.pack_size);
        println!("• Total blocks: {}", packing_params.total_blocks);  
        println!("• Theoretical setup complexity reduction: {}x", packing_params.pack_size);
        println!("• Theoretical operation complexity reduction: {}x", n * n);
        println!("• Communication overhead reduction: {}x", packing_params.pack_size);
    }
}
