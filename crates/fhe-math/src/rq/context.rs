use fhe_traits::{Deserialize, Serialize};
use itertools::Itertools;
use num_bigint::BigUint;
use std::{fmt::Debug, sync::Arc};

use crate::{ntt::NttOperator, rns::RnsContext, zq::Modulus, Error, Result};

/// Struct that holds the context associated with elements in rq.
#[derive(Default, Clone, PartialEq, Eq)]
pub struct Context {
    /// List of prime moduli
    pub moduli: Box<[u64]>,
    /// Modulus operators for each prime
    pub q: Box<[Modulus]>,
    /// RNS context for CRT operations
    pub rns: Arc<RnsContext>,
    /// NTT operators for each prime
    pub ops: Box<[NttOperator]>,
    /// Polynomial degree (must be power of 2)
    pub degree: usize,
    /// Bit-reversed indices for NTT operations
    pub bitrev: Box<[usize]>,
    /// Inverse of last qi modulo qj for modulus switching
    pub inv_last_qi_mod_qj: Box<[u64]>,
    /// Shoup representation of inv_last_qi_mod_qj
    pub inv_last_qi_mod_qj_shoup: Box<[u64]>,
    /// Link to context with one less modulus (for level management)
    pub next_context: Option<Arc<Context>>,
}

impl Debug for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Context")
            .field("moduli", &self.moduli)
            // .field("q", &self.q)
            // .field("rns", &self.rns)
            // .field("ops", &self.ops)
            // .field("degree", &self.degree)
            // .field("bitrev", &self.bitrev)
            // .field("inv_last_qi_mod_qj", &self.inv_last_qi_mod_qj)
            // .field("inv_last_qi_mod_qj_shoup", &self.inv_last_qi_mod_qj_shoup)
            .field("next_context", &self.next_context)
            .finish()
    }
}

impl Context {
    /// Creates a context from a list of moduli and a polynomial degree.
    ///
    /// Returns an error if the moduli are not primes less than 62 bits which
    /// supports the NTT of size `degree`.
    pub fn new(moduli: &[u64], degree: usize) -> Result<Self> {
        if !degree.is_power_of_two() || degree < 8 {
            Err(Error::Default(
                "The degree is not a power of two larger or equal to 8".to_string(),
            ))
        } else {
            let mut q = Vec::with_capacity(moduli.len());
            let rns = Arc::new(RnsContext::new(moduli)?);
            let mut ops = Vec::with_capacity(moduli.len());
            for modulus in moduli {
                let qi = Modulus::new(*modulus)?;
                if let Some(op) = NttOperator::new(&qi, degree) {
                    q.push(qi);
                    ops.push(op);
                } else {
                    return Err(Error::Default(
                        "Impossible to construct a Ntt operator".to_string(),
                    ));
                }
            }
            let bitrev = (0..degree)
                .map(|j| j.reverse_bits() >> (degree.leading_zeros() + 1))
                .collect_vec();

            let mut inv_last_qi_mod_qj = vec![];
            let mut inv_last_qi_mod_qj_shoup = vec![];
            let q_last = moduli.last().unwrap();
            for qi in &q[..q.len() - 1] {
                let inv = qi.inv(qi.reduce(*q_last)).unwrap();
                inv_last_qi_mod_qj.push(inv);
                inv_last_qi_mod_qj_shoup.push(qi.shoup(inv));
            }

            let next_context = if moduli.len() >= 2 {
                Some(Arc::new(Context::new(&moduli[..moduli.len() - 1], degree)?))
            } else {
                None
            };

            Ok(Self {
                moduli: moduli.to_owned().into_boxed_slice(),
                q: q.into_boxed_slice(),
                rns,
                ops: ops.into_boxed_slice(),
                degree,
                bitrev: bitrev.into_boxed_slice(),
                inv_last_qi_mod_qj: inv_last_qi_mod_qj.into_boxed_slice(),
                inv_last_qi_mod_qj_shoup: inv_last_qi_mod_qj_shoup.into_boxed_slice(),
                next_context,
            })
        }
    }

    /// Creates a context in an `Arc`.
    pub fn new_arc(moduli: &[u64], degree: usize) -> Result<Arc<Self>> {
        Self::new(moduli, degree).map(Arc::new)
    }

    /// Returns the modulus as a BigUint.
    pub fn modulus(&self) -> &BigUint {
        self.rns.modulus()
    }

    /// Returns a reference to the moduli in this context.
    pub fn moduli(&self) -> &[u64] {
        &self.moduli
    }

    /// Returns a reference to the moduli as Modulus in this context.
    pub fn moduli_operators(&self) -> &[Modulus] {
        &self.q
    }

    /// Returns the number of iterations to switch to a children context.
    /// Returns an error if the context provided is not a child context.
    pub fn niterations_to(&self, context: &Arc<Context>) -> Result<usize> {
        if context.as_ref() == self {
            return Ok(0);
        }

        let mut niterations = 0;
        let mut found = false;
        let mut current_ctx = Arc::new(self.clone());
        while current_ctx.next_context.is_some() {
            niterations += 1;
            current_ctx = current_ctx.next_context.as_ref().unwrap().clone();
            if &current_ctx == context {
                found = true;
                break;
            }
        }
        if found {
            Ok(niterations)
        } else {
            Err(Error::InvalidContext)
        }
    }

    /// Returns the context after `i` iterations.
    pub fn context_at_level(&self, i: usize) -> Result<Arc<Self>> {
        if i >= self.moduli.len() {
            Err(Error::Default(
                "No context at the specified level".to_string(),
            ))
        } else {
            let mut current_ctx = Arc::new(self.clone());
            for _ in 0..i {
                current_ctx = current_ctx.next_context.as_ref().unwrap().clone();
            }
            Ok(current_ctx)
        }
    }

    /// Reconstruct the next_context chain from a list of contexts.
    /// This is used during deserialization to rebuild the recursive structure.
    pub fn reconstruct_chain(contexts: &mut [Arc<Context>]) {
        for i in 0..contexts.len() {
            if i + 1 < contexts.len() {
                // Use Arc::get_mut to get a mutable reference, but we need to clone
                // since we can't mutate Arc directly. Instead, we'll create a new Context.
                let next_ctx = contexts[i + 1].clone();
                let current = Arc::get_mut(&mut contexts[i])
                    .expect("Context should be uniquely owned during reconstruction");
                current.next_context = Some(next_ctx);
            } else {
                let current = Arc::get_mut(&mut contexts[i])
                    .expect("Context should be uniquely owned during reconstruction");
                current.next_context = None;
            }
        }
    }
}

impl Serialize for Context {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        // Serialize moduli
        bytes.extend_from_slice(&(self.moduli.len() as u64).to_le_bytes());
        for m in self.moduli.iter() {
            bytes.extend_from_slice(&m.to_le_bytes());
        }
        // Serialize degree
        bytes.extend_from_slice(&(self.degree as u64).to_le_bytes());
        // Serialize rns
        let rns_bytes = self.rns.to_bytes();
        bytes.extend_from_slice(&(rns_bytes.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&rns_bytes);
        // Serialize ops (NTT operators)
        bytes.extend_from_slice(&(self.ops.len() as u64).to_le_bytes());
        for op in self.ops.iter() {
            let op_bytes = op.to_bytes();
            bytes.extend_from_slice(&(op_bytes.len() as u64).to_le_bytes());
            bytes.extend_from_slice(&op_bytes);
        }
        // Serialize bitrev
        bytes.extend_from_slice(&(self.bitrev.len() as u64).to_le_bytes());
        for b in self.bitrev.iter() {
            bytes.extend_from_slice(&(*b as u64).to_le_bytes());
        }
        // Serialize inv_last_qi_mod_qj
        bytes.extend_from_slice(&(self.inv_last_qi_mod_qj.len() as u64).to_le_bytes());
        for inv in self.inv_last_qi_mod_qj.iter() {
            bytes.extend_from_slice(&inv.to_le_bytes());
        }
        // Serialize inv_last_qi_mod_qj_shoup
        bytes.extend_from_slice(&(self.inv_last_qi_mod_qj_shoup.len() as u64).to_le_bytes());
        for inv_shoup in self.inv_last_qi_mod_qj_shoup.iter() {
            bytes.extend_from_slice(&inv_shoup.to_le_bytes());
        }
        // Note: We don't serialize next_context - it will be reconstructed
        bytes
    }
}

impl Deserialize for Context {
    type Error = Error;

    fn try_deserialize(bytes: &[u8]) -> std::result::Result<Self, Self::Error> {
        let mut offset = 0;

        // Deserialize moduli
        if offset + 8 > bytes.len() {
            return Err(Error::Serialization("Invalid Context serialization".to_string()));
        }
        let moduli_len = u64::from_le_bytes([
            bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3],
            bytes[offset + 4], bytes[offset + 5], bytes[offset + 6], bytes[offset + 7],
        ]) as usize;
        offset += 8;

        let mut moduli = Vec::with_capacity(moduli_len);
        for _ in 0..moduli_len {
            if offset + 8 > bytes.len() {
                return Err(Error::Serialization("Invalid Context serialization".to_string()));
            }
            let m = u64::from_le_bytes([
                bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3],
                bytes[offset + 4], bytes[offset + 5], bytes[offset + 6], bytes[offset + 7],
            ]);
            moduli.push(m);
            offset += 8;
        }

        // Reconstruct q (Modulus operators) from moduli
        let mut q = Vec::with_capacity(moduli_len);
        for m in &moduli {
            q.push(Modulus::new(*m)?);
        }

        // Deserialize degree
        if offset + 8 > bytes.len() {
            return Err(Error::Serialization("Invalid Context serialization".to_string()));
        }
        let degree = u64::from_le_bytes([
            bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3],
            bytes[offset + 4], bytes[offset + 5], bytes[offset + 6], bytes[offset + 7],
        ]) as usize;
        offset += 8;

        // Deserialize rns
        if offset + 8 > bytes.len() {
            return Err(Error::Serialization("Invalid Context serialization".to_string()));
        }
        let rns_len = u64::from_le_bytes([
            bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3],
            bytes[offset + 4], bytes[offset + 5], bytes[offset + 6], bytes[offset + 7],
        ]) as usize;
        offset += 8;
        if offset + rns_len > bytes.len() {
            return Err(Error::Serialization("Invalid Context serialization".to_string()));
        }
        let rns = Arc::new(RnsContext::try_deserialize(&bytes[offset..offset + rns_len])?);
        offset += rns_len;

        // Deserialize ops (NTT operators)
        if offset + 8 > bytes.len() {
            return Err(Error::Serialization("Invalid Context serialization".to_string()));
        }
        let ops_len = u64::from_le_bytes([
            bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3],
            bytes[offset + 4], bytes[offset + 5], bytes[offset + 6], bytes[offset + 7],
        ]) as usize;
        offset += 8;

        let mut ops = Vec::with_capacity(ops_len);
        for _ in 0..ops_len {
            if offset + 8 > bytes.len() {
                return Err(Error::Serialization("Invalid Context serialization".to_string()));
            }
            let op_len = u64::from_le_bytes([
                bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3],
                bytes[offset + 4], bytes[offset + 5], bytes[offset + 6], bytes[offset + 7],
            ]) as usize;
            offset += 8;
            if offset + op_len > bytes.len() {
                return Err(Error::Serialization("Invalid Context serialization".to_string()));
            }
            let op = NttOperator::try_deserialize(&bytes[offset..offset + op_len])?;
            ops.push(op);
            offset += op_len;
        }

        // Deserialize bitrev
        if offset + 8 > bytes.len() {
            return Err(Error::Serialization("Invalid Context serialization".to_string()));
        }
        let bitrev_len = u64::from_le_bytes([
            bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3],
            bytes[offset + 4], bytes[offset + 5], bytes[offset + 6], bytes[offset + 7],
        ]) as usize;
        offset += 8;

        let mut bitrev = Vec::with_capacity(bitrev_len);
        for _ in 0..bitrev_len {
            if offset + 8 > bytes.len() {
                return Err(Error::Serialization("Invalid Context serialization".to_string()));
            }
            let b = u64::from_le_bytes([
                bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3],
                bytes[offset + 4], bytes[offset + 5], bytes[offset + 6], bytes[offset + 7],
            ]) as usize;
            bitrev.push(b);
            offset += 8;
        }

        // Deserialize inv_last_qi_mod_qj
        if offset + 8 > bytes.len() {
            return Err(Error::Serialization("Invalid Context serialization".to_string()));
        }
        let inv_len = u64::from_le_bytes([
            bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3],
            bytes[offset + 4], bytes[offset + 5], bytes[offset + 6], bytes[offset + 7],
        ]) as usize;
        offset += 8;

        let mut inv_last_qi_mod_qj = Vec::with_capacity(inv_len);
        for _ in 0..inv_len {
            if offset + 8 > bytes.len() {
                return Err(Error::Serialization("Invalid Context serialization".to_string()));
            }
            let inv = u64::from_le_bytes([
                bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3],
                bytes[offset + 4], bytes[offset + 5], bytes[offset + 6], bytes[offset + 7],
            ]);
            inv_last_qi_mod_qj.push(inv);
            offset += 8;
        }

        // Deserialize inv_last_qi_mod_qj_shoup
        if offset + 8 > bytes.len() {
            return Err(Error::Serialization("Invalid Context serialization".to_string()));
        }
        let inv_shoup_len = u64::from_le_bytes([
            bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3],
            bytes[offset + 4], bytes[offset + 5], bytes[offset + 6], bytes[offset + 7],
        ]) as usize;
        offset += 8;

        let mut inv_last_qi_mod_qj_shoup = Vec::with_capacity(inv_shoup_len);
        for _ in 0..inv_shoup_len {
            if offset + 8 > bytes.len() {
                return Err(Error::Serialization("Invalid Context serialization".to_string()));
            }
            let inv_shoup = u64::from_le_bytes([
                bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3],
                bytes[offset + 4], bytes[offset + 5], bytes[offset + 6], bytes[offset + 7],
            ]);
            inv_last_qi_mod_qj_shoup.push(inv_shoup);
            offset += 8;
        }

        Ok(Self {
            moduli: moduli.into_boxed_slice(),
            q: q.into_boxed_slice(),
            rns,
            ops: ops.into_boxed_slice(),
            degree,
            bitrev: bitrev.into_boxed_slice(),
            inv_last_qi_mod_qj: inv_last_qi_mod_qj.into_boxed_slice(),
            inv_last_qi_mod_qj_shoup: inv_last_qi_mod_qj_shoup.into_boxed_slice(),
            next_context: None, // Will be reconstructed later
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{error::Error, sync::Arc};

    use crate::ntt::supports_ntt;
    use crate::rq::Context;

    const MODULI: &[u64; 5] = &[
        1153,
        4611686018326724609,
        4611686018309947393,
        4611686018232352769,
        4611686018171535361,
    ];

    #[test]
    fn context_constructor() {
        for modulus in MODULI {
            // modulus is = 1 modulo 2 * 8
            assert!(Context::new(&[*modulus], 8).is_ok());

            if supports_ntt(*modulus, 128) {
                assert!(Context::new(&[*modulus], 128).is_ok());
            } else {
                assert!(Context::new(&[*modulus], 128).is_err());
            }
        }

        // All moduli in MODULI are = 1 modulo 2 * 8
        assert!(Context::new(MODULI, 8).is_ok());

        // This should fail since 1153 != 1 moduli 2 * 128
        assert!(Context::new(MODULI, 128).is_err());
    }

    #[test]
    fn next_context() -> Result<(), Box<dyn Error>> {
        // A context should have a children pointing to a context with one less modulus.
        let context = Arc::new(Context::new(MODULI, 8)?);
        assert_eq!(
            context.next_context,
            Some(Arc::new(Context::new(&MODULI[..MODULI.len() - 1], 8)?))
        );

        // We can go down the chain of the MODULI.len() - 1 context's.
        let mut number_of_children = 0;
        let mut current = context;
        while current.next_context.is_some() {
            number_of_children += 1;
            current = current.next_context.as_ref().unwrap().clone();
        }
        assert_eq!(number_of_children, MODULI.len() - 1);

        Ok(())
    }

    #[test]
    fn niterations_to() -> Result<(), Box<dyn Error>> {
        // A context should have a children pointing to a context with one less modulus.
        let context = Arc::new(Context::new(MODULI, 8)?);

        assert_eq!(context.niterations_to(&context).ok(), Some(0));

        assert_eq!(
            context
                .niterations_to(&Arc::new(Context::new(&MODULI[1..], 8)?))
                .err(),
            Some(crate::Error::InvalidContext)
        );

        for i in 1..MODULI.len() {
            assert_eq!(
                context
                    .niterations_to(&Arc::new(Context::new(&MODULI[..MODULI.len() - i], 8)?))
                    .ok(),
                Some(i)
            );
        }

        Ok(())
    }
}
