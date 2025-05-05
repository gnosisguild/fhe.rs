/*!
 * Implementation of the l-BFV relinearization algorithm as described in
 * [Robust Multiparty Computation from Threshold Encryption Based on RLWE](https://eprint.iacr.org/2024/1285.pdf).
 *
 * This module contains the public key and relinearization key for the 
 * l-BFV scheme, along with the relinearization key relinearization 
 * algorithm.
 */

mod public_key;
mod relinearization_key;
pub use public_key::LBFVPublicKey;
pub use relinearization_key::LBFVRelinearizationKey;
