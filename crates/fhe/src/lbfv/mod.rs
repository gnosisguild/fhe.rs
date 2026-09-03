//!
//! Single-party l-BFV operational keys: [`LBFVPublicKey`] and
//! [`LBFVRelinearizationKey`].
//!
//! The l-BFV (linear BFV) relinearization algorithm is described in [Robust
//! Multiparty Computation from Threshold Encryption Based on
//! RLWE](https://eprint.iacr.org/2024/1285.pdf). This module provides
//! single-party l-BFV operational keys and their constructors.
//!
//! Threshold/multiparty shares, bindings, and aggregation live separately in
//! [`crate::trlbfv`]. The keys produced here do not carry threshold participant
//! set metadata.
//!
//! The shared polynomials `a` (CRS) and `d1` (URS) are supplied as
//! [`CommonRandomPolyVec`](crate::bfv::CommonRandomPolyVec) values. The
//! implementation's `l` equals the number of RNS moduli, which need not match
//! the paper's gadget dimension because of the HPS optimisation
//! (<https://eprint.iacr.org/2018/117>).
//!
//! The l-BFV relinearization argument relies on the circular-security
//! assumption inherited from the cited multi-key construction. This caveat
//! applies to all key material produced by this module and by [`crate::trlbfv`].

pub(crate) mod keys;

pub use keys::{LBFVPublicKey, LBFVRelinearizationKey};
