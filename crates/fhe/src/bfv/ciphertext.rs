//! Ciphertext type in the BFV encryption scheme.

use crate::bfv::{parameters::BfvParameters, traits::TryConvertFrom};
use crate::proto::bfv::Ciphertext as CiphertextProto;
use crate::{Error, Result};
use fhe_math::rq::{Poly, Representation};
use fhe_traits::{
    DeserializeParametrized, DeserializeWithContext, FheCiphertext, FheParametrized, Serialize,
};
use prost::Message;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use std::sync::Arc;
use std::{convert::TryInto, mem::size_of};

const HEADER_LEVEL_SIZE: usize = size_of::<u32>();
const HEADER_NUM_POLYS_SIZE: usize = size_of::<u16>();
const HEADER_RESERVED_SIZE: usize = size_of::<u16>();
const METADATA_SIZE: usize = HEADER_LEVEL_SIZE + HEADER_NUM_POLYS_SIZE + HEADER_RESERVED_SIZE;

/// A ciphertext encrypting a plaintext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ciphertext {
    /// The parameters of the underlying BFV encryption scheme.
    pub(crate) par: Arc<BfvParameters>,

    /// The seed that generated the polynomial c1 in a fresh ciphertext.
    pub(crate) seed: Option<<ChaCha8Rng as SeedableRng>::Seed>,

    /// The ciphertext elements.
    pub c: Vec<Poly>,

    /// The ciphertext level
    pub level: usize,
}

impl Ciphertext {
    /// Modulo switch the ciphertext to the last level.
    pub fn mod_switch_to_last_level(&mut self) -> Result<()> {
        self.level = self.par.max_level();
        let last_ctx = self.par.ctx_at_level(self.level)?;
        self.seed = None;
        for ci in self.c.iter_mut() {
            if ci.ctx() != last_ctx {
                ci.change_representation(Representation::PowerBasis);
                ci.mod_switch_down_to(last_ctx)?;
                ci.change_representation(Representation::Ntt);
            }
        }
        Ok(())
    }

    /// Modulo switch the ciphertext to the next level.
    pub fn mod_switch_to_next_level(&mut self) -> Result<()> {
        if self.level < self.par.max_level() {
            self.seed = None;
            for ci in self.c.iter_mut() {
                ci.change_representation(Representation::PowerBasis);
                ci.mod_switch_down_next()?;
                ci.change_representation(Representation::Ntt);
            }
            self.level += 1
        }
        Ok(())
    }

    /// Create a ciphertext from a vector of polynomials.
    /// A ciphertext must contain at least two polynomials, and all polynomials
    /// must be in Ntt representation and with the same context.
    pub fn new(c: Vec<Poly>, par: &Arc<BfvParameters>) -> Result<Self> {
        if c.len() < 2 {
            return Err(Error::TooFewValues(c.len(), 2));
        }

        let ctx = c[0].ctx();
        let level = par.level_of_ctx(ctx)?;

        // Check that all polynomials have the expected representation and context.
        for ci in c.iter() {
            if ci.representation() != &Representation::Ntt {
                return Err(Error::MathError(fhe_math::Error::IncorrectRepresentation(
                    ci.representation().clone(),
                    Representation::Ntt,
                )));
            }
            if ci.ctx() != ctx {
                return Err(Error::MathError(fhe_math::Error::InvalidContext));
            }
        }

        Ok(Self {
            par: par.clone(),
            seed: None,
            c,
            level,
        })
    }

    /// Get the i-th polynomial of the ciphertext.
    pub fn get(&self, i: usize) -> Option<&Poly> {
        self.c.get(i)
    }

    /// Generate the zero ciphertext.
    pub fn zero(par: &Arc<BfvParameters>) -> Self {
        Self {
            par: par.clone(),
            seed: None,
            c: Default::default(),
            level: 0,
        }
    }

    /// Creates a Ciphertext directly from a flat byte buffer containing metadata
    /// and concatenated raw u64 NTT coefficients.
    ///
    /// # Format
    /// - Header (8 bytes, little-endian):
    ///   - `level`: `u32`
    ///   - `num_polys`: `u16`
    ///   - `reserved`: `u16` (must be 0)
    /// - `coefficients`: Concatenated `u64` coefficient data (native-endian)
    ///
    /// # Safety
    /// - The caller MUST ensure `raw_ntt_data` contains valid, correctly formatted,
    ///   and aligned data according to the specified format.
    /// - The parameters `par` MUST be the correct ones corresponding to the data.
    /// - Incorrect data or parameters can lead to undefined behavior or incorrect results.
    pub unsafe fn from_raw_ntt_bytes(
        raw_ntt_data: &[u8],
        par: &Arc<BfvParameters>,
    ) -> Result<Self> {
        if raw_ntt_data.len() < METADATA_SIZE {
            return Err(Error::SerializationError);
        }

        // Read header (Little Endian)
        let level = u32::from_le_bytes(raw_ntt_data[0..4].try_into().unwrap());
        let num_polys = u16::from_le_bytes(raw_ntt_data[4..6].try_into().unwrap());
        let reserved = u16::from_le_bytes(raw_ntt_data[6..METADATA_SIZE].try_into().unwrap());
        
        // Validate header fields
        if reserved != 0 {
             return Err(Error::SerializationError);
        }

        let level = level as usize;
        let num_polys = num_polys as usize;

        if num_polys == 0 {
            if level == 0 && raw_ntt_data.len() == METADATA_SIZE {
                return Ok(Self::zero(par)); 
            } else {
                return Err(Error::SerializationError);
            }
        }
        
        if num_polys < 2 { 
             return Err(Error::SerializationError);
        }
        let ctx = par.ctx_at_level(level).map_err(|_| Error::SerializationError)?;

        let poly_coeffs_len = ctx.degree
            .checked_mul(ctx.q.len())
            .ok_or(Error::SerializationError)?;

        let expected_coeffs_bytes = poly_coeffs_len
            .checked_mul(num_polys)
            .and_then(|v| v.checked_mul(size_of::<u64>()))
            .ok_or(Error::SerializationError)?;
        
        let expected_total_bytes = METADATA_SIZE
            .checked_add(expected_coeffs_bytes)
            .ok_or(Error::SerializationError)?;

        if raw_ntt_data.len() != expected_total_bytes {
            return Err(Error::SerializationError);
        }

        let coeffs_data = &raw_ntt_data[METADATA_SIZE..];

        if coeffs_data.as_ptr() as usize % std::mem::align_of::<u64>() != 0 {
             return Err(Error::DefaultError(
                "Coefficient data in buffer is not aligned for u64".to_string(),
            ));
        }

        let all_coeffs: &[u64] = std::slice::from_raw_parts(
            coeffs_data.as_ptr() as *const u64,
             poly_coeffs_len * num_polys,
        );

        let mut c = Vec::with_capacity(num_polys);
        for i in 0..num_polys {
            let start = i * poly_coeffs_len;
            let end = start + poly_coeffs_len;
            let poly_coeffs_slice = &all_coeffs[start..end];
            let poly = Poly::from_raw_ntt_coeffs(ctx, poly_coeffs_slice)?;
            c.push(poly);
        }

        Ok(Ciphertext {
            par: par.clone(),
            seed: None, 
            c,
            level,
        })
    }

    /// Serializes the Ciphertext into a flat byte vector containing metadata
    /// (level, num_polys, reserved) followed by the concatenated 
    /// raw u64 NTT coefficients.
    ///
    /// # Format (Little Endian)
    /// - `level`: `u32`
    /// - `num_polys`: `u16`
    /// - `reserved`: `u16` (0)
    /// - `coefficients`: Concatenated `u64` coefficient data (native-endian)
    ///
    /// # Errors
    /// Returns an error if level or num_polys exceed limits, or if any polynomial 
    /// component is not in `Representation::Ntt`.
    pub fn to_raw_ntt_bytes(&self) -> Result<Vec<u8>> {
        let level32: u32 = self.level.try_into().map_err(|_| Error::SerializationError)?;
        let num_polys16: u16 = self.c.len().try_into().map_err(|_| Error::SerializationError)?;

        if self.c.is_empty() {
            if self.level != 0 {
                 return Err(Error::SerializationError);
            }
            let mut header = Vec::with_capacity(METADATA_SIZE);
            header.extend_from_slice(&0u32.to_le_bytes());
            header.extend_from_slice(&0u16.to_le_bytes());
            header.extend_from_slice(&0u16.to_le_bytes());
            return Ok(header);
        }

        for poly in self.c.iter() {
            if poly.representation() != &Representation::Ntt {
                return Err(Error::MathError(fhe_math::Error::IncorrectRepresentation(
                    poly.representation().clone(),
                    Representation::Ntt,
                )));
            }
        }

        let num_polys = self.c.len();
        let ctx = self.c[0].ctx(); 
        let degree = ctx.degree;
        let num_moduli = ctx.q.len();
        let poly_coeffs_len = degree * num_moduli;
        let poly_bytes_len = poly_coeffs_len * std::mem::size_of::<u64>();
        let coeffs_total_bytes = num_polys * poly_bytes_len;
        
        let mut result_bytes = Vec::with_capacity(METADATA_SIZE + coeffs_total_bytes);

        result_bytes.extend_from_slice(&level32.to_le_bytes());
        result_bytes.extend_from_slice(&num_polys16.to_le_bytes());
        result_bytes.extend_from_slice(&0u16.to_le_bytes());

        for poly in self.c.iter() {
            if let Some(coeffs_slice) = poly.coefficients().as_slice() {
                let byte_slice = unsafe {
                    std::slice::from_raw_parts(
                        coeffs_slice.as_ptr() as *const u8,
                        coeffs_slice.len() * std::mem::size_of::<u64>(),
                    )
                };
                result_bytes.extend_from_slice(byte_slice);
            } else {
                return Err(Error::DefaultError(
                    "Failed to get contiguous slice from polynomial coefficients".to_string(),
                ));
            }
        }

        Ok(result_bytes)
    }
}

impl FheCiphertext for Ciphertext {}

impl FheParametrized for Ciphertext {
    type Parameters = BfvParameters;
}

impl Serialize for Ciphertext {
    fn to_bytes(&self) -> Vec<u8> {
        CiphertextProto::from(self).encode_to_vec()
    }
}

impl DeserializeParametrized for Ciphertext {
    fn from_bytes(bytes: &[u8], par: &Arc<BfvParameters>) -> Result<Self> {
        if let Ok(ctp) = Message::decode(bytes) {
            Ciphertext::try_convert_from(&ctp, par)
        } else {
            Err(Error::SerializationError)
        }
    }

    type Error = Error;
}

/// Conversions from and to protobuf.
impl From<&Ciphertext> for CiphertextProto {
    fn from(ct: &Ciphertext) -> Self {
        let mut proto = CiphertextProto::default();
        for i in 0..ct.c.len() - 1 {
            proto.c.push(ct.c[i].to_bytes())
        }
        if let Some(seed) = ct.seed {
            proto.seed = seed.to_vec()
        } else {
            proto.c.push(ct.c[ct.c.len() - 1].to_bytes())
        }
        proto.level = ct.level as u32;
        proto
    }
}

impl TryConvertFrom<&CiphertextProto> for Ciphertext {
    fn try_convert_from(value: &CiphertextProto, par: &Arc<BfvParameters>) -> Result<Self> {
        if value.c.is_empty() || (value.c.len() == 1 && value.seed.is_empty()) {
            return Err(Error::DefaultError("Not enough polynomials".to_string()));
        }

        if value.level as usize > par.max_level() {
            return Err(Error::DefaultError("Invalid level".to_string()));
        }

        let ctx = par.ctx_at_level(value.level as usize)?;

        let mut c = Vec::with_capacity(value.c.len() + 1);
        for cip in &value.c {
            c.push(Poly::from_bytes(cip, ctx)?)
        }

        let mut seed = None;
        if !value.seed.is_empty() {
            let try_seed = <ChaCha8Rng as SeedableRng>::Seed::try_from(value.seed.clone())
                .map_err(|_| {
                    Error::MathError(fhe_math::Error::InvalidSeedSize(
                        value.seed.len(),
                        <ChaCha8Rng as SeedableRng>::Seed::default().len(),
                    ))
                })?;
            seed = Some(try_seed);
            let mut c1 = Poly::random_from_seed(ctx, Representation::Ntt, try_seed);
            unsafe { c1.allow_variable_time_computations() }
            c.push(c1)
        }

        Ok(Ciphertext {
            par: par.clone(),
            seed,
            c,
            level: value.level as usize,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::bfv::{
        traits::TryConvertFrom, BfvParameters, Ciphertext, Encoding, Plaintext, SecretKey, 
    };
    use crate::proto::bfv::Ciphertext as CiphertextProto;
    use fhe_math::rq::{Poly, Representation};
    use fhe_traits::FheDecrypter;
    use fhe_traits::{DeserializeParametrized, FheEncoder, FheEncrypter, Serialize, FheDecoder};
    use rand::thread_rng;
    use std::error::Error as StdError;
    use std::mem::size_of; 

    // Define constants within the test module scope (8 bytes total now)
    const HEADER_LEVEL_SIZE: usize = size_of::<u32>();
    const HEADER_NUM_POLYS_SIZE: usize = size_of::<u16>();
    const HEADER_RESERVED_SIZE: usize = size_of::<u16>();
    const METADATA_SIZE: usize = HEADER_LEVEL_SIZE + HEADER_NUM_POLYS_SIZE + HEADER_RESERVED_SIZE;

    #[test]
    fn proto_conversion() -> Result<(), Box<dyn StdError>> {
        let mut rng = thread_rng();
        for params in [
            BfvParameters::default_arc(1, 8),
            BfvParameters::default_arc(6, 8),
        ] {
            let sk = SecretKey::random(&params, &mut rng);
            let v = params.plaintext.random_vec(params.degree(), &mut rng);
            let pt = Plaintext::try_encode(&v, Encoding::poly(), &params)?;
            let ct = sk.try_encrypt(&pt, &mut rng)?;
            let ct_proto = CiphertextProto::from(&ct);
            assert_eq!(ct, Ciphertext::try_convert_from(&ct_proto, &params)?);

            let ct = &ct * &ct;
            let ct_proto = CiphertextProto::from(&ct);
            assert_eq!(ct, Ciphertext::try_convert_from(&ct_proto, &params)?)
        }
        Ok(())
    }

    #[test]
    fn serialize() -> Result<(), Box<dyn StdError>> {
        let mut rng = thread_rng();
        for params in [
            BfvParameters::default_arc(1, 8),
            BfvParameters::default_arc(6, 8),
        ] {
            let sk = SecretKey::random(&params, &mut rng);
            let v = params.plaintext.random_vec(params.degree(), &mut rng);
            let pt = Plaintext::try_encode(&v, Encoding::poly(), &params)?;
            let ct: Ciphertext = sk.try_encrypt(&pt, &mut rng)?;
            let ct_bytes = ct.to_bytes();
            assert_eq!(ct, Ciphertext::from_bytes(&ct_bytes, &params)?);
        }
        Ok(())
    }

    #[test]
    fn new() -> Result<(), Box<dyn StdError>> {
        let mut rng = thread_rng();
        for params in [
            BfvParameters::default_arc(1, 8),
            BfvParameters::default_arc(6, 8),
        ] {
            let sk = SecretKey::random(&params, &mut rng);
            let v = params.plaintext.random_vec(params.degree(), &mut rng);
            let pt = Plaintext::try_encode(&v, Encoding::poly(), &params)?;
            let ct: Ciphertext = sk.try_encrypt(&pt, &mut rng)?;
            let mut ct3 = &ct * &ct;

            let c0 = ct3.get(0).unwrap();
            let c1 = ct3.get(1).unwrap();
            let c2 = ct3.get(2).unwrap();

            assert_eq!(
                ct3,
                Ciphertext::new(vec![c0.clone(), c1.clone(), c2.clone()], &params)?
            );
            assert_eq!(ct3.level, 0);

            ct3.mod_switch_to_last_level()?;

            let c0 = ct3.get(0).unwrap();
            let c1 = ct3.get(1).unwrap();
            let c2 = ct3.get(2).unwrap();
            assert_eq!(
                ct3,
                Ciphertext::new(vec![c0.clone(), c1.clone(), c2.clone()], &params)?
            );
            assert_eq!(ct3.level, params.max_level());
        }

        Ok(())
    }

    #[test]
    fn mod_switch_to_last_level() -> Result<(), Box<dyn StdError>> {
        let mut rng = thread_rng();
        for params in [
            BfvParameters::default_arc(1, 8),
            BfvParameters::default_arc(6, 8),
        ] {
            let sk = SecretKey::random(&params, &mut rng);
            let v = params.plaintext.random_vec(params.degree(), &mut rng);
            let pt = Plaintext::try_encode(&v, Encoding::poly(), &params)?;
            let mut ct: Ciphertext = sk.try_encrypt(&pt, &mut rng)?;

            assert_eq!(ct.level, 0);
            ct.mod_switch_to_last_level()?;
            assert_eq!(ct.level, params.max_level());

            let decrypted = sk.try_decrypt(&ct)?;
            assert_eq!(decrypted.value, pt.value);
        }

        Ok(())
    }

    #[test]
    fn from_raw_ntt_bytes_invalid_size() -> Result<(), Box<dyn StdError>> {
        let params = BfvParameters::default_arc(6, 8);
        let level: u32 = 0;
        let num_polys: u16 = 2;
        let ctx = params.ctx_at_level(level as usize)?;
        let poly_len = ctx.degree * ctx.q.len();
        let coeffs_bytes_len = (num_polys as usize) * poly_len * std::mem::size_of::<u64>();
        let header_len = METADATA_SIZE; // Use constant
        let total_len = header_len + coeffs_bytes_len;

        let mut buffer = vec![0u8; total_len];
        buffer[0..4].copy_from_slice(&level.to_le_bytes());
        buffer[4..6].copy_from_slice(&num_polys.to_le_bytes());
        buffer[6..METADATA_SIZE].copy_from_slice(&0u16.to_le_bytes()); // reserved

        // Test too small (remove one byte from end)
        let bytes_small = &buffer[..total_len - 1];
        let result_small = unsafe { Ciphertext::from_raw_ntt_bytes(bytes_small, &params) };
        assert!(result_small.is_err());
        assert!(matches!(result_small, Err(crate::Error::SerializationError)), "Expected SerializationError for too small");

        // Test too large (add one byte)
        let mut buffer_large = buffer.clone();
        buffer_large.push(0);
        let result_large = unsafe { Ciphertext::from_raw_ntt_bytes(&buffer_large, &params) };
        assert!(result_large.is_err());
        assert!(matches!(result_large, Err(crate::Error::SerializationError)), "Expected SerializationError for too large");
        
        // Test invalid metadata size (less than header)
        let bytes_meta_short = &buffer[..header_len - 1];
        let result_meta_short = unsafe { Ciphertext::from_raw_ntt_bytes(bytes_meta_short, &params) };
        assert!(result_meta_short.is_err());
        assert!(matches!(result_meta_short, Err(crate::Error::SerializationError)), "Expected SerializationError for short metadata");

        Ok(())
    }

     #[test]
    fn from_raw_ntt_bytes_unaligned() -> Result<(), Box<dyn StdError>> {
        let mut rng = thread_rng();
        let params = BfvParameters::default_arc(6, 8);
        let sk = SecretKey::random(&params, &mut rng);
        
        let pt_values = params.plaintext.random_vec(params.ctx_at_level(0)?.degree, &mut rng);
        let pt = Plaintext::try_encode(&pt_values, Encoding::poly(), &params)?;
        let ct_orig: Ciphertext = sk.try_encrypt(&pt, &mut rng)?;
        let valid_bytes = ct_orig.to_raw_ntt_bytes()?;
        let valid_len = valid_bytes.len();
        assert!(valid_len > METADATA_SIZE); 

        let mut unaligned_buffer = vec![0u8; valid_len + 1];
        unaligned_buffer[1..].copy_from_slice(&valid_bytes);
        let unaligned_slice = &unaligned_buffer[1..];

        let result = unsafe {
            Ciphertext::from_raw_ntt_bytes(unaligned_slice, &params)
        };
        
        assert!(result.is_err(), "Expected an error but got Ok");
        match result {
            Err(crate::Error::DefaultError(msg)) => {
                assert!(msg.contains("Coefficient data in buffer is not aligned for u64"), "Unexpected error message: {}", msg);
            }
            Err(e) => panic!("Expected DefaultError for unaligned data, got {:?}", e),
            Ok(_) => panic!("Function unexpectedly succeeded"),
        }

        Ok(())
    }

    #[test]
    fn to_from_raw_ntt_bytes_roundtrip() -> Result<(), Box<dyn StdError>> {
        let mut rng = thread_rng();
        let params = BfvParameters::default_arc(6, 8);
        let sk = SecretKey::random(&params, &mut rng);

        let pt_values = params.plaintext.random_vec(params.ctx_at_level(0)?.degree, &mut rng);
        let pt = Plaintext::try_encode(&pt_values, Encoding::poly(), &params)?;
        let ct_orig: Ciphertext = sk.try_encrypt(&pt, &mut rng)?;

        let raw_bytes = ct_orig.to_raw_ntt_bytes()?;
        assert!(raw_bytes.len() >= METADATA_SIZE);

        let ct_reconstructed = unsafe {
            Ciphertext::from_raw_ntt_bytes(&raw_bytes, &params)?
        };

        let mut ct_reconstructed_test = ct_reconstructed.clone();
        for poly in ct_reconstructed_test.c.iter_mut() {
            unsafe { poly.allow_variable_time_computations() };
        }

        assert_eq!(ct_orig.c, ct_reconstructed_test.c);
        assert_eq!(ct_orig.level, ct_reconstructed_test.level);
        assert_eq!(ct_orig.par, ct_reconstructed_test.par);
        assert!(ct_orig.seed.is_some());
        assert!(ct_reconstructed_test.seed.is_none());

        Ok(())
    }

    #[test]
    fn to_raw_ntt_bytes_incorrect_representation() -> Result<(), Box<dyn StdError>> {
        let mut rng = thread_rng();
        let params = BfvParameters::default_arc(6, 8);
        
        let ctx = params.ctx_at_level(0)?;
        let poly_pb = Poly::random(ctx, Representation::PowerBasis, &mut rng);
        let poly_ntt = Poly::random(ctx, Representation::Ntt, &mut rng);

        let mut ct_bad = Ciphertext {
             par: params.clone(),
             seed: None,
             c: vec![poly_pb, poly_ntt.clone()], 
             level: 0,
        };

        let result = ct_bad.to_raw_ntt_bytes();
        assert!(result.is_err());
        match result {
            Err(crate::Error::MathError(fhe_math::Error::IncorrectRepresentation(rep, expected))) => {
                assert_eq!(rep, Representation::PowerBasis);
                assert_eq!(expected, Representation::Ntt);
            }
            _ => panic!("Expected IncorrectRepresentation error")
        }

        ct_bad.c = vec![poly_ntt, ct_bad.c.remove(0)]; 
         let result2 = ct_bad.to_raw_ntt_bytes();
        assert!(result2.is_err());
         match result2 {
            Err(crate::Error::MathError(fhe_math::Error::IncorrectRepresentation(rep, expected))) => {
                assert_eq!(rep, Representation::PowerBasis);
                assert_eq!(expected, Representation::Ntt);
            }
            _ => panic!("Expected IncorrectRepresentation error")
        }

        Ok(())
    }

    #[test]
    fn from_raw_ntt_bytes_header_checks() -> Result<(), Box<dyn StdError>> {
        let params = BfvParameters::default_arc(6, 8);
        let level: u32 = 0;
        let num_polys: u16 = 2;
        let header_len = METADATA_SIZE;
        let ctx = params.ctx_at_level(level as usize)?;
        let poly_len = ctx.degree * ctx.q.len();
        let coeffs_bytes_len = (num_polys as usize) * poly_len * std::mem::size_of::<u64>();
        let total_len = header_len + coeffs_bytes_len;
        let mut buffer = vec![0u8; total_len];

        buffer[0..4].copy_from_slice(&level.to_le_bytes());
        buffer[4..6].copy_from_slice(&num_polys.to_le_bytes());
        buffer[6..METADATA_SIZE].copy_from_slice(&0u16.to_le_bytes());

        let mut buffer_bad_reserved = buffer.clone();
        buffer_bad_reserved[6..METADATA_SIZE].copy_from_slice(&1u16.to_le_bytes()); // reserved=1
        let res_bad_reserved = unsafe { Ciphertext::from_raw_ntt_bytes(&buffer_bad_reserved, &params) };
        assert!(matches!(res_bad_reserved, Err(crate::Error::SerializationError)), "Expected error for non-zero reserved field");

        let mut buffer_bad_level = buffer.clone();
        let invalid_level = (params.max_level() + 1) as u32;
        buffer_bad_level[0..4].copy_from_slice(&invalid_level.to_le_bytes());
        let res_bad_level = unsafe { Ciphertext::from_raw_ntt_bytes(&buffer_bad_level, &params) };
        assert!(matches!(res_bad_level, Err(crate::Error::SerializationError)), "Expected error for invalid level");

        let mut buffer_bad_num_polys = buffer.clone();
        buffer_bad_num_polys[4..6].copy_from_slice(&1u16.to_le_bytes()); // num_polys = 1
        let res_bad_num_polys = unsafe { Ciphertext::from_raw_ntt_bytes(&buffer_bad_num_polys, &params) };
        assert!(matches!(res_bad_num_polys, Err(crate::Error::SerializationError)), "Expected error for num_polys < 2");

        Ok(())
    }

    #[test]
    fn raw_ntt_bytes_serialization_and_usage() -> Result<(), Box<dyn StdError>> {
        let mut rng = thread_rng();
        let params = BfvParameters::default_arc(6, 128);
        let sk = SecretKey::random(&params, &mut rng);

        let pt_values1 = params.plaintext.random_vec(params.ctx_at_level(0)?.degree, &mut rng);
        let pt1 = Plaintext::try_encode(&pt_values1, Encoding::poly(), &params)?;

        let pt_values2 = params.plaintext.random_vec(params.ctx_at_level(0)?.degree, &mut rng);
        let pt2 = Plaintext::try_encode(&pt_values2, Encoding::poly(), &params)?;

        let ct1_orig: Ciphertext = sk.try_encrypt(&pt1, &mut rng)?;
        let ct2: Ciphertext = sk.try_encrypt(&pt2, &mut rng)?;

        let raw_bytes_ct1 = ct1_orig.to_raw_ntt_bytes()?;

        let ct1_reconstructed = unsafe {
            Ciphertext::from_raw_ntt_bytes(&raw_bytes_ct1, &params)?
        };

        let ct_sum = &ct1_reconstructed + &ct2;

        let pt_sum_decrypted = sk.try_decrypt(&ct_sum)?;
        let pt_sum_values = Vec::<u64>::try_decode(&pt_sum_decrypted, Encoding::poly())?;

        let p = params.plaintext.modulus();
        let expected_sum_values: Vec<u64> = pt_values1
            .iter()
            .zip(pt_values2.iter())
            .map(|(&v1, &v2)| (v1 + v2) % p)
            .collect();

        assert_eq!(pt_sum_values, expected_sum_values, "Decrypted sum did not match expected sum");

        Ok(())
    }
}
