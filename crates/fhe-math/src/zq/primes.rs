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
/// smaller than `upper_bound`. Returns `None` if `num_bits` is outside
/// `10..=62`, `modulo` is zero, or `upper_bound` is outside
/// `(2^(num_bits - 1), 2^num_bits]`. A modulus of one imposes no congruence
/// constraint. The upper bound is exclusive.
#[must_use]
pub fn generate_prime(num_bits: usize, modulo: u64, upper_bound: u64) -> Option<u64> {
    if !(10..=62).contains(&num_bits) || modulo == 0 {
        return None;
    }

    let lower_bound = 1u64 << (num_bits - 1);
    if upper_bound <= lower_bound || upper_bound > (1u64 << num_bits) {
        return None;
    }

    let start = upper_bound - 1;
    let residue = 1 % modulo;
    let remainder = start % modulo;
    let offset = if remainder >= residue {
        remainder - residue
    } else {
        modulo - (residue - remainder)
    };
    let mut candidate = start.checked_sub(offset)?;

    while candidate >= lower_bound {
        if is_prime(candidate) {
            return Some(candidate);
        }
        candidate = candidate.checked_sub(modulo)?;
    }

    None
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
    fn invalid_inputs_return_none() {
        for num_bits in [0, 9, 63, usize::MAX] {
            assert_eq!(generate_prime(num_bits, 16, 1 << 10), None);
        }
        for upper_bound in [0, 1, 1 << 9, (1 << 62) + 1, u64::MAX] {
            assert_eq!(generate_prime(62, 16, upper_bound), None);
        }
        assert_eq!(generate_prime(10, 0, 1 << 10), None);
        assert_eq!(generate_prime(10, 16, 1 << 9), None);
        assert_eq!(generate_prime(10, 16, (1 << 10) + 1), None);
    }

    #[test]
    fn strict_bound_and_vacuous_congruence() {
        assert_eq!(generate_prime(10, 1, 1024), Some(1021));
        assert_eq!(generate_prime(10, 1, 1021), Some(1019));
        assert_eq!(generate_prime(10, 16, 1009), Some(977));
        assert_eq!(generate_prime(10, u64::MAX, 1024), None);
    }

    #[test]
    fn finds_largest_prime_in_congruence_class_below_bound() {
        for upper_bound in (513..=1024).step_by(17) {
            for modulo in [1, 2, 3, 16, 1023, u64::MAX] {
                let expected = (512..upper_bound)
                    .rev()
                    .find(|&p| p % modulo == 1 % modulo && is_prime(p));
                assert_eq!(generate_prime(10, modulo, upper_bound), expected);
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
