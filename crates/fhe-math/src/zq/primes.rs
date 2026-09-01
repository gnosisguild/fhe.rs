//! Optimized primes generated as in the NFLlib library.

use fhe_util::is_prime;
use num_bigint::BigUint;

/// Returns whether the modulus supports optimized multiplication and reduction.
/// These optimized operations are possible when the modulus verifies
/// Equation (1) of <https://hal.archives-ouvertes.fr/hal-01242273/document>.
#[must_use]
pub fn supports_opt(p: u64) -> bool {
    if p.leading_zeros() < 1 {
        return false;
    }

    // Let's multiply the inequality by (2^s0+1)*2^(3s0):
    // we want to output true when
    //    (2^(3s0)+1) * 2^64 < 2^(3s0) * (2^s0+1) * p
    let mut middle = BigUint::from(1u64) << (3 * p.leading_zeros() as usize);
    let left_side = (&middle + 1u64) << 64;
    middle *= (1u64 << p.leading_zeros()) + 1;
    middle *= p;

    left_side < middle
}

/// Generate a `num_bits`-bit prime, congruent to 1 mod `modulo`, strictly
/// smaller than `upper_bound`. The search descends from `upper_bound - 1` as in
/// the NFLlib library.
///
/// `num_bits` must belong to `10..=62`, `modulo` must be nonzero (a zero
/// modulus cannot define a congruence), and `upper_bound` must leave at least
/// one `num_bits`-bit candidate below it: it must be in
/// `(1 << (num_bits - 1), 1 << num_bits]`. `modulo == 1` is the vacuous
/// congruence (every integer satisfies `x ≡ 1 mod 1`), so the largest
/// `num_bits`-bit prime below the bound is returned.
///
/// Returns `None` for an invalid request or when no prime satisfies the
/// constraints in the requested range. Invalid inputs are rejected before any
/// subtraction or remainder, so the return value is identical in debug and
/// release builds.
#[must_use]
pub fn generate_prime(num_bits: usize, modulo: u64, upper_bound: u64) -> Option<u64> {
    // Validate all inputs before any subtraction or modulo so the `Option<u64>`
    // contract holds identically in debug and release builds.
    if !(10..=62).contains(&num_bits) {
        return None;
    }
    // A zero modulus would divide by zero during the congruence search.
    if modulo == 0 {
        return None;
    }
    // The strict upper bound must be within the `num_bits` domain and leave at
    // least one `num_bits`-bit candidate strictly below it.
    if upper_bound == 0
        || upper_bound > (1u64 << num_bits)
        || upper_bound <= (1u64 << (num_bits - 1))
    {
        return None;
    }

    let leading_zeros = (64 - num_bits) as u32;

    // Descend from the strict upper bound to the largest value congruent to
    // `1 % modulo`; for `modulo == 1` this is the vacuous congruence, satisfied
    // by every value, so the search starts directly at `upper_bound - 1`.
    let mut tentative_prime = upper_bound - 1;
    while tentative_prime % modulo != 1 % modulo && tentative_prime.leading_zeros() == leading_zeros
    {
        tentative_prime -= 1
    }

    while tentative_prime.leading_zeros() == leading_zeros
        && !is_prime(tentative_prime)
        && tentative_prime >= modulo
    {
        tentative_prime -= modulo
    }

    if tentative_prime.leading_zeros() == leading_zeros && is_prime(tentative_prime) {
        Some(tentative_prime)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{generate_prime, is_prime};

    // Verifies that the same moduli as in the NFLlib library are generated.
    // <https://github.com/quarkslab/NFLlib/blob/master/include/nfl/params.hpp>
    #[test]
    fn nfl_62bit_primes() {
        let mut generated = vec![];
        let mut upper_bound = u64::MAX >> 2;
        while generated.len() != 20 {
            let p = generate_prime(62, 2 * 1048576, upper_bound);
            assert!(p.is_some());
            upper_bound = p.unwrap();
            generated.push(upper_bound);
        }
        assert_eq!(
            generated,
            vec![
                4611686018326724609,
                4611686018309947393,
                4611686018282684417,
                4611686018257518593,
                4611686018232352769,
                4611686018171535361,
                4611686018106523649,
                4611686018058289153,
                4611686018051997697,
                4611686017974403073,
                4611686017812922369,
                4611686017781465089,
                4611686017773076481,
                4611686017678704641,
                4611686017666121729,
                4611686017647247361,
                4611686017590624257,
                4611686017554972673,
                4611686017529806849,
                4611686017517223937
            ]
        )
    }

    #[test]
    fn zero_modulo_returns_none() {
        // A zero modulus would divide by zero during the congruence search; it
        // must be rejected with `None` instead of panicking in both debug and
        // release builds.
        assert!(generate_prime(10, 0, 1 << 10).is_none());
    }

    #[test]
    fn invalid_num_bits_returns_none() {
        assert!(generate_prime(9, 1, 1 << 9).is_none());
        assert!(generate_prime(63, 1, u64::MAX).is_none());
    }

    #[test]
    fn invalid_upper_bound_returns_none() {
        // Zero and tiny upper bounds leave no `num_bits`-bit candidate strictly
        // below them (512 is the smallest 10-bit number).
        assert!(generate_prime(10, 1, 0).is_none());
        assert!(generate_prime(10, 1, 1).is_none());
        assert!(generate_prime(10, 1, 512).is_none());
        // Oversized upper bounds exceed the `num_bits` domain.
        assert!(generate_prime(62, 2 * 1048576, (1 << 62) + 1).is_none());
        assert!(generate_prime(62, 2 * 1048576, u64::MAX).is_none());
    }

    #[test]
    fn modulo_one_is_vacuous_congruence() {
        // Every integer satisfies x ≡ 1 mod 1, so the largest `num_bits`-bit
        // prime below the bound is returned.
        assert_eq!(generate_prime(10, 1, 1 << 10), Some(1021));
        assert_eq!(generate_prime(11, 1, 1033), Some(1031));
    }

    #[test]
    fn strict_upper_bound_is_exclusive() {
        // The candidate must be strictly smaller than `upper_bound`: with the
        // bound exactly on a prime, the returned value is the previous prime.
        assert_eq!(generate_prime(10, 1, 1021), Some(1019));
        assert_eq!(generate_prime(10, 1, 1022), Some(1021));
        assert_eq!(generate_prime(10, 1, 1020), Some(1019));
    }

    proptest! {
        #[test]
        fn generate_prime_properties(num_bits in 10..=62usize, modulo in 2u64..(1 << 16), frac: u64) {
            // Derive the strict upper bound from `num_bits` so the request is a
            // valid bounded one, in `(2^(num_bits - 1), 2^num_bits]`; this keeps
            // the property test on the valid-input path (invalid bounds are
            // covered by the deterministic `invalid_upper_bound_returns_none`).
            let min = (1u64 << (num_bits - 1)) + 1;
            let max = 1u64 << num_bits;
            let upper_bound = min + frac % (max - min + 1);

            let result = generate_prime(num_bits, modulo, upper_bound);
            if let Some(p) = result {
                prop_assert!(is_prime(p));
                prop_assert_eq!(64 - p.leading_zeros() as usize, num_bits);
                prop_assert!(p < upper_bound);
                prop_assert_eq!(p % modulo, 1 % modulo);
            }
        }
    }

    #[test]
    fn modulo_too_large() {
        assert!(generate_prime(10, 2048, 1 << 10).is_none());
    }

    #[test]
    fn not_found() {
        // 1033 is the smallest 11-bit prime congruent to 1 modulo 16, so looking for a
        // smaller one should fail.
        assert!(generate_prime(11, 16, 1033).is_none());
    }
}
