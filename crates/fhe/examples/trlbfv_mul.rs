//! Three parties generate l-BFV keys and two decrypt a relinearized product.
//! Small parameters for a local demonstration, not a deployment parameter set.

#[path = "support/trlbfv.rs"]
mod ceremony;

use fhe::bfv::{BfvParametersBuilder, CommonRandomPolyVec, Encoding};
use fhe_traits::FheDecoder;

fn main() -> fhe::Result<()> {
    let mut rng = rand::rng();
    let params = BfvParametersBuilder::new()
        .set_degree(16)
        .set_plaintext_modulus(257)
        .set_moduli_sizes(&[55; 5])
        .build_arc()?;
    let a = CommonRandomPolyVec::new(&params, &mut rng)?;
    let d1 = CommonRandomPolyVec::new(&params, &mut rng)?;
    let mut committee = ceremony::Committee::deal(&params, &a, &d1, &mut rng)?;
    let product = committee.product(3, 5, &mut rng)?;
    let plaintext = committee.decrypt_ss(&product, &mut rng)?;
    let result = Vec::<u64>::try_decode(&plaintext, Encoding::poly())?;
    assert_eq!(result.first(), Some(&15));
    println!("2-of-3 threshold decryption: 3 × 5 = 15");
    Ok(())
}
