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
 * 3. Enhanced Robustness: The single-round nature of the protocol
 *    inherently provides robustness in the threshold setting.
 */

pub mod keys;

pub use keys::LBFVPublicKey;
pub use keys::LBFVRelinearizationKey;
