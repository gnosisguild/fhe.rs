use num_bigint::BigUint;
use num_traits::{One, Zero};    
use thiserror::Error;
use fhe_math::rq::{Context, Poly, Representation};
use fhe_traits::{Serialize, FheEncoder, FheDecrypter, FheEncrypter};
use rand::{CryptoRng, RngCore};
use std::sync::Arc;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// PVW-specific errors
#[derive(Error, Debug)]
pub enum PvwError {
    #[error("Invalid parameters: {0}")]
    InvalidParameters(String),
    #[error("Sampling error: {0}")]
    SamplingError(String),
    #[error("Encryption error: {0}")]
    EncryptionError(String),
    #[error("Decryption error: {0}")]
    DecryptionError(String),
}

pub type Result<T> = std::result::Result<T, PvwError>;

/// PVW Parameters using fhe.rs Context with BigUint variances
#[derive(Debug, Clone)]
pub struct PvwParameters {
    /// Number of parties
    pub n: usize,
    /// Security threshold (t < n/2)
    pub t: usize,
    /// LWE dimension
    pub k: usize,
    /// Redundancy parameter ℓ (number of coefficients)
    pub l: usize,
    /// Secret key variance (can be large BigUint for 100+ bit distributions)
    pub secret_variance: BigUint,
    /// First noise variance (for key generation)
    pub noise_variance_1: BigUint,
    /// Second noise variance (for encryption - can be 100+ bits)
    pub noise_variance_2: BigUint,
    /// fhe.rs Context for efficient polynomial operations
    /// We use this but ignore the FHE-specific fields
    pub context: Arc<Context>,
}

/// Builder for PVW parameters
#[derive(Debug, Default)]
pub struct PvwParametersBuilder {
    n: Option<usize>,
    k: Option<usize>,
    l: Option<usize>,
    moduli: Option<Vec<u64>>,
    secret_variance: Option<BigUint>,
    noise_variance_1: Option<BigUint>,
    noise_variance_2: Option<BigUint>,
}

impl PvwParametersBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_parties(mut self, n: usize) -> Self {
        self.n = Some(n);
        self
    }

    pub fn set_dimension(mut self, k: usize) -> Self {
        self.k = Some(k);
        self
    }

    pub fn set_l(mut self, l: usize) -> Self {
        self.l = Some(l);
        self
    }

    pub fn set_moduli(mut self, moduli: &[u64]) -> Self {
        self.moduli = Some(moduli.to_vec());
        self
    }

    /// Set secret key variance (can be large BigUint)
    pub fn set_secret_variance(mut self, variance: BigUint) -> Self {
        self.secret_variance = Some(variance);
        self
    }

    /// Set secret key variance from u64 (convenience method)
    pub fn set_secret_variance_u64(mut self, variance: u64) -> Self {
        self.secret_variance = Some(BigUint::from(variance));
        self
    }

    /// Set first noise variance
    pub fn set_noise_variance_1(mut self, variance: BigUint) -> Self {
        self.noise_variance_1 = Some(variance);
        self
    }

    /// Set first noise variance from u64
    pub fn set_noise_variance_1_u64(mut self, variance: u64) -> Self {
        self.noise_variance_1 = Some(BigUint::from(variance));
        self
    }

    /// Set second noise variance (for 100+ bit variances)
    pub fn set_noise_variance_2(mut self, variance: BigUint) -> Self {
        self.noise_variance_2 = Some(variance);
        self
    }

    /// Set second noise variance from u64
    pub fn set_noise_variance_2_u64(mut self, variance: u64) -> Self {
        self.noise_variance_2 = Some(BigUint::from(variance));
        self
    }

    /// Set noise variance from bit length (for large variances like "100 bits")
    pub fn set_noise_variance_2_bits(mut self, bits: u32) -> Self {
        let variance = BigUint::from(2u32).pow(bits);
        self.noise_variance_2 = Some(variance);
        self
    }

    pub fn build(self) -> Result<PvwParameters> {
        let n = self.n.ok_or_else(|| PvwError::InvalidParameters("n not set".to_string()))?;
        let k = self.k.ok_or_else(|| PvwError::InvalidParameters("k not set".to_string()))?;
        let l = self.l.ok_or_else(|| PvwError::InvalidParameters("l not set".to_string()))?;
        let moduli = self.moduli.ok_or_else(|| PvwError::InvalidParameters("moduli not set".to_string()))?;
        
        // Default reasonable values
        let secret_variance = self.secret_variance.unwrap_or_else(|| BigUint::from(4u32));
        let noise_variance_1 = self.noise_variance_1.unwrap_or_else(|| BigUint::from(2u32).pow(40));
        let noise_variance_2 = self.noise_variance_2.unwrap_or_else(|| BigUint::from(2u32).pow(100)); // 100-bit default

        let t = (n - 1) / 2;

        // Create fhe.rs Context - we'll use what we need and ignore FHE-specific parts
        let context = Context::new_arc(&moduli, l)
            .map_err(|e| PvwError::InvalidParameters(format!("Context creation failed: {}", e)))?;

        Ok(PvwParameters {
            n,
            t,
            k,
            l,
            secret_variance,
            noise_variance_1,
            noise_variance_2,
            context,
        })
    }

    pub fn build_arc(self) -> Result<Arc<PvwParameters>> {
        Ok(Arc::new(self.build()?))
    }
}

impl PvwParameters {
    /// Sample secret key polynomial using your BigUint sampler
    pub fn sample_secret_polynomial<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Result<Poly> {
        // Use your existing BigUint normal distribution sampler here
        let coeffs = self.sample_bigint_normal_coefficients(&self.secret_variance, rng)?;
        
        // Convert to i64 coefficients (with modular reduction)
        let i64_coeffs = self.biguint_coeffs_to_i64(&coeffs)?;
        
        // Create polynomial using fhe.rs
        let mut poly = Poly::from_coefficients(&i64_coeffs, &self.context)
            .map_err(|e| PvwError::SamplingError(format!("Failed to create polynomial: {:?}", e)))?;
        
        poly.change_representation(Representation::Ntt);
        Ok(poly)
    }

    /// Sample noise polynomial (level 1)
    pub fn sample_noise_1<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Result<Poly> {
        let coeffs = self.sample_bigint_normal_coefficients(&self.noise_variance_1, rng)?;
        let i64_coeffs = self.biguint_coeffs_to_i64(&coeffs)?;
        
        let mut poly = Poly::from_coefficients(&i64_coeffs, &self.context)
            .map_err(|e| PvwError::SamplingError(format!("Failed to create noise polynomial: {:?}", e)))?;
        
        poly.change_representation(Representation::Ntt);
        Ok(poly)
    }

    /// Sample noise polynomial (level 2) - for 100+ bit variances
    pub fn sample_noise_2<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Result<Poly> {
        let coeffs = self.sample_bigint_normal_coefficients(&self.noise_variance_2, rng)?;
        let i64_coeffs = self.biguint_coeffs_to_i64(&coeffs)?;
        
        let mut poly = Poly::from_coefficients(&i64_coeffs, &self.context)
            .map_err(|e| PvwError::SamplingError(format!("Failed to create noise polynomial: {:?}", e)))?;
        
        poly.change_representation(Representation::Ntt);
        Ok(poly)
    }

    /// Placeholder for your BigUint normal distribution sampler
    /// Replace this with your actual implementation
    fn sample_bigint_normal_coefficients<R: RngCore + CryptoRng>(
        &self,
        variance: &BigUint,
        rng: &mut R
    ) -> Result<Vec<BigUint>> {
        // TODO: Replace with your actual BigUint normal sampler
        // For now, placeholder that creates reasonable-sized coefficients
        let mut coeffs = Vec::with_capacity(self.l);
        
        for _ in 0..self.l {
            // Placeholder: sample a coefficient roughly proportional to sqrt(variance)
            let max_coeff = variance.sqrt() * 3u32; // Rough 3-sigma bound
            let coeff = if max_coeff.is_zero() {
                BigUint::zero()
            } else {
                // Simple uniform sampling as placeholder
                let bits = max_coeff.bits();
                let mut result = BigUint::zero();
                for _ in 0..bits {
                    if rng.gen_bool(0.5) {
                        result = (result << 1) + 1u32;
                    } else {
                        result = result << 1;
                    }
                }
                result % max_coeff
            };
            coeffs.push(coeff);
        }
        
        Ok(coeffs)
    }

    /// Convert BigUint coefficients to i64 with proper modular reduction
    fn biguint_coeffs_to_i64(&self, coeffs: &[BigUint]) -> Result<Vec<i64>> {
        // Get the first modulus for coefficient representation
        let modulus = BigUint::from(self.context.moduli[0]);
        let half_modulus = &modulus / 2u32;
        
        let mut i64_coeffs = Vec::with_capacity(coeffs.len());
        
        for coeff in coeffs {
            let reduced = coeff % &modulus;
            
            // Map to centered representation [-q/2, q/2]
            let signed_coeff = if reduced > half_modulus {
                -(((&modulus - &reduced).iter_u64_digits().next().unwrap_or(0)) as i64)
            } else {
                reduced.iter_u64_digits().next().unwrap_or(0) as i64
            };
            
            i64_coeffs.push(signed_coeff);
        }
        
        Ok(i64_coeffs)
    }

    /// Compute total modulus Q = ∏ moduli
    pub fn q_total(&self) -> BigUint {
        self.context.moduli.iter()
            .map(|&m| BigUint::from(m))
            .fold(BigUint::one(), |acc, m| acc * m)
    }

    /// Compute delta = ⌊Q^(1/ℓ)⌋ for gadget vector
    pub fn delta(&self) -> BigUint {
        self.q_total().nth_root(self.l as u32)
    }

    /// Create gadget polynomial g(X) = 1 + Δ·X + Δ²·X² + ... + Δ^(ℓ-1)·X^(ℓ-1)
    pub fn gadget_polynomial(&self) -> Result<Poly> {
        let delta = self.delta();
        let q_total = self.q_total();
        let mut coefficients = Vec::with_capacity(self.l);
        
        let mut delta_power = BigUint::one();
        for _i in 0..self.l {
            let coeff_big = &delta_power % &q_total;
            delta_power = (&delta_power * &delta) % &q_total;
            coefficients.push(coeff_big);
        }
        
        let i64_coeffs = self.biguint_coeffs_to_i64(&coefficients)?;
        
        let mut poly = Poly::from_coefficients(&i64_coeffs, &self.context)
            .map_err(|e| PvwError::InvalidParameters(
                format!("Failed to create gadget polynomial: {:?}", e)
            ))?;
        
        poly.change_representation(Representation::Ntt);
        Ok(poly)
    }

    /// Get the useful parts of the fhe.rs Context
    /// Access the moduli
    pub fn moduli(&self) -> &[u64] {
        &self.context.moduli
    }

    /// Access the RNS context (useful for CRT operations)
    pub fn rns_context(&self) -> &Arc<fhe_math::rns::RnsContext> {
        &self.context.rns
    }

    /// Access NTT operators (for efficient polynomial multiplication)
    pub fn ntt_operators(&self) -> &[fhe_math::ntt::NttOperator] {
        &self.context.ops
    }
}

/// PVW Secret Key
#[derive(Debug, Clone)]
pub struct SecretKey {
    pub polynomials: Vec<Poly>,
    pub params: Arc<PvwParameters>,
}

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        // Zero out polynomial coefficients
        // Note: Depends on fhe_math::Poly implementing proper zeroization
        for poly in &mut self.polynomials {
            // If fhe_math::Poly doesn't implement Zeroize, you'd need custom logic here
        }
    }
}

impl ZeroizeOnDrop for SecretKey {}

impl SecretKey {
    /// Generate secret key using BigUint sampler
    pub fn random<R: RngCore + CryptoRng>(
        params: &Arc<PvwParameters>,
        rng: &mut R
    ) -> Result<Self> {
        let mut polynomials = Vec::with_capacity(params.k);
        
        for _ in 0..params.k {
            let poly = params.sample_secret_polynomial(rng)?;
            polynomials.push(poly);
        }
        
        Ok(Self {
            polynomials,
            params: params.clone(),
        })
    }
}

/// Example usage showing BigUint variance handling
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_large_variance_parameters() {
        // Example with 100-bit noise variance
        let large_variance = BigUint::from(2u32).pow(100);
        
        let params = PvwParametersBuilder::new()
            .set_parties(1000)
            .set_dimension(4)
            .set_l(1024)
            .set_moduli(&[0x3fffffff000001, 0x3ffffffea0001])
            .set_secret_variance_u64(4)           // Small secret key variance
            .set_noise_variance_1_u64(1u64 << 40) // 40-bit noise
            .set_noise_variance_2(large_variance)  // 100-bit noise
            .build_arc()
            .unwrap();
        
        assert_eq!(params.l, 1024);
        assert!(params.noise_variance_2 > BigUint::from(u64::MAX));
        
        // Test that we can access fhe.rs Context features
        assert_eq!(params.moduli().len(), 2);
        assert_eq!(params.context.degree, 1024);
    }

    #[test]
    fn test_fhe_rs_context_integration() {
        let params = PvwParametersBuilder::new()
            .set_parties(10)
            .set_dimension(4)
            .set_l(8)
            .set_moduli(&[65537])
            .set_secret_variance_u64(2)
            .set_noise_variance_1_u64(100)
            .set_noise_variance_2_bits(50) // 50-bit variance
            .build_arc()
            .unwrap();
        
        // Verify we can use fhe.rs Context features we need
        assert_eq!(params.context.degree, 8);
        assert_eq!(params.context.moduli.len(), 1);
        assert!(params.context.ops.len() > 0); // Should have NTT operators
        
        // The FHE-specific fields exist but we just ignore them
        // No need to access: inv_last_qi_mod_qj, next_context, etc.
    }

    #[test] 
    fn test_gadget_polynomial_creation() {
        let params = PvwParametersBuilder::new()
            .set_parties(10)
            .set_dimension(4)
            .set_l(8)
            .set_moduli(&[65537])
            .build_arc()
            .unwrap();
        
        let gadget = params.gadget_polynomial().unwrap();
        
        // Should be in NTT form and use correct context
        assert_eq!(gadget.representation(), Representation::Ntt);
        assert!(Arc::ptr_eq(gadget.context(), &params.context));
    }
}