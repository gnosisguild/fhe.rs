//! Traits used for the BFV homomorphic encryption scheme.

use crate::bfv::{BfvParameters, Ciphertext, RelinearizationKey as BfvRelinearizationKey};
use crate::lbfv::LBFVRelinearizationKey;
use crate::Result;
use std::sync::Arc;
use std::fmt::Debug;

/// Conversions.
///
/// We unfortunately cannot use the `TryFrom` trait from std::convert because we
/// need to specify additional parameters, and if we try to redefine a `TryFrom`
/// trait here, we need to fully specify the trait when we use it because of the
/// blanket implementation <https://github.com/rust-lang/rust/issues/50133#issuecomment-488512355>.
pub trait TryConvertFrom<T>
where
    Self: Sized,
{
    /// Attempt to convert the `value` with a specific parameter.
    fn try_convert_from(value: T, par: &Arc<BfvParameters>) -> Result<Self>;
}

/// Enum that can hold any type of relinearization key
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenericRelinearizationKey {
    Standard(BfvRelinearizationKey),
    LBFV(LBFVRelinearizationKey),
}

impl From<&BfvRelinearizationKey> for GenericRelinearizationKey {
    fn from(rk: &BfvRelinearizationKey) -> Self {
        Self::Standard(rk.clone())
    }
}

impl From<&LBFVRelinearizationKey> for GenericRelinearizationKey {
    fn from(rk: &LBFVRelinearizationKey) -> Self {
        Self::LBFV(rk.clone())
    }
}

impl GenericRelinearizationKey {
    pub fn relinearizes(&self, ct: &mut Ciphertext) -> Result<()> {
        match self {
            GenericRelinearizationKey::Standard(rk) => rk.relinearizes(ct),
            GenericRelinearizationKey::LBFV(rk) => rk.relinearizes(ct),
        }
    }

    pub fn ciphertext_level(&self) -> usize {
        match self {
            GenericRelinearizationKey::Standard(rk) => rk.ksk.ciphertext_level,
            GenericRelinearizationKey::LBFV(rk) => rk.ksk_r_to_s.ciphertext_level,
        }
    }

    pub fn parameters(&self) -> Arc<BfvParameters> {
        match self {
            GenericRelinearizationKey::Standard(rk) => rk.ksk.par.clone(),
            GenericRelinearizationKey::LBFV(rk) => rk.ksk_r_to_s.par.clone(),
        }
    }
}