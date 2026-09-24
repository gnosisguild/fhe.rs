use crate::{MultipartyError, Result};
use fhe_math::rq::{Poly, RepresentationTag};
use std::sync::Arc;

use crate::bfv::{BfvParameters, Ciphertext};

pub(super) fn same_params(a: &Arc<BfvParameters>, b: &Arc<BfvParameters>) -> Result<()> {
    // Shares can cross a transport boundary and be rehydrated with distinct
    // parameter Arcs. Compare parameter values here (and polynomial contexts
    // below), unlike in-memory BFV plaintext validation's identity check.
    if a != b {
        return Err(MultipartyError::IncompatibleShares {
            reason: "different BFV parameters",
        }
        .into());
    }
    Ok(())
}

pub(super) fn same_polys<R: RepresentationTag>(
    polys: &[Poly<R>],
    expected: usize,
    component: &'static str,
    params: &Arc<BfvParameters>,
) -> Result<()> {
    if polys.len() != expected {
        return Err(MultipartyError::SharePolynomialCountMismatch {
            component,
            actual: polys.len(),
            expected,
        }
        .into());
    }
    let ctx = params.context_at_level(0)?;
    if polys.iter().any(|p| p.ctx() != ctx) {
        return Err(MultipartyError::IncompatibleShares {
            reason: "polynomial context does not match share parameters",
        }
        .into());
    }
    Ok(())
}

pub(super) fn switch_ciphertext(ct: &Ciphertext, params: &Arc<BfvParameters>) -> Result<()> {
    same_params(&ct.params, params)?;
    if ct.len() != 2 {
        return Err(MultipartyError::SharePolynomialCountMismatch {
            component: "switch ciphertext",
            actual: ct.len(),
            expected: 2,
        }
        .into());
    }
    let ctx = params.context_at_level(ct.level)?;
    if ct.iter().any(|p| p.ctx() != ctx) {
        return Err(MultipartyError::IncompatibleShares {
            reason: "switch ciphertext context does not match its level",
        }
        .into());
    }
    Ok(())
}
