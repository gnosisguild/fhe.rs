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
