/*!
 * Implementation of the l-BFV relinearization algorithm as described in
 * [Robust Multiparty Computation from Threshold Encryption Based on RLWE](https://eprint.iacr.org/2024/1285.pdf).
 *
 * The l-BFV (linear BFV) relinearization algorithm provides several key
 * advantages over traditional relinearization approaches:
 *
 * 1. Linear Communication: The protocol achieves linear communication
 *    complexity, making it more efficient than quadratic alternatives.
 *
 * 2. Single Round: Unlike traditional approaches that require two rounds of
 *    communication, l-BFV completes relinearization in a single round,
 *    significantly reducing latency and network overhead.
 *
 * 3. Robustness Compatibility: The single-round nature makes the protocol
 *    compatible with the Urban–Rambaud robust protocol, but this crate
 *    provides key-generation and aggregation components only. It does not
 *    implement robust DKG, broadcast, authentication, FLSS/GURS, or
 *    guaranteed output delivery.
 *
 * # CRP vectors
 *
 * The shared polynomials `a` (CRS) and `d1` (URS) are supplied as
 * [`CommonRandomPolyVec`](crate::bfv::CommonRandomPolyVec) values —
 * vectors of `l` concrete random polynomials (one per RNS modulus).
 *
 * - Every [`CommonRandomPolyVec`] **always** stores concrete polynomials.
 *   Equality checks use the polynomials, never relying on seeds alone.
 * - The optional seed in a [`CommonRandomPolyVec`] is reconstruction
 *   metadata only; it reconstructs the same values but is not
 *   authentication.  A seed that contradicts the concrete polynomials is
 *   rejected at construction.
 * - Two independent [`CommonRandomPolyVec`] values (for `a` and `d1`) must
 *   be agreed upon by all parties before key generation — this is the
 *   protocol-level CRS/URS agreement step.  DKG, broadcast, authentication,
 *   coin-tossing, FLSS, GURS, and guaranteed output delivery remain caller
 *   responsibilities.
 * - The implementation's `l` equals the number of RNS moduli, which need not
 *   match the paper's gadget dimension because of the HPS optimisation
 *   (<https://eprint.iacr.org/2018/117>).
 *
 * # Distributed key aggregation
 *
 * This crate supports multi-party distributed key generation for l-BFV
 * public keys and relinearization keys.  All participants must agree on a
 * common [`LBFVParticipantSet`] (a sorted, unique set of nonzero participant
 * IDs bound to a 32-byte session identifier) **before** any contributions
 * are created.
 *
 * - Every accepted participant contributes exactly once.  Aggregation
 *   rejects duplicate, missing, or cross-session contributions.
 * - The public-key and relinearization-key aggregation paths validate that
 *   all contributions belong to the **same** session and participant set.
 * - The explicit `a` (CRS) and `d1` (URS) polynomials are compared by
 *   concrete polynomial equality across contributions.  Seed-based
 *   representations are an optional compression optimization; the
 *   authoritative values are the polynomials.
 * - Participant set metadata is **consistency binding, not authentication**.
 *   No FLSS, broadcast protocol, GURS, or full robust DKG orchestration is
 *   provided by this module.  Callers must supply their own transport and
 *   authentication layers.
 *
 * # Circular-security caveat
 *
 * The l-BFV relinearization argument relies on the circular-security
 * assumption inherited from the cited multi-key construction.  This caveat
 * applies to all key material produced by this module.
 */

pub mod keys;

pub use keys::{
    LBFVContributionBinding, LBFVParticipantSet, LBFVPublicKey, LBFVRelinKeyShare,
    LBFVRelinearizationKey,
};
