//! Deterministic construction-time primality validation.

/// Deterministic Miller–Rabin for the supported odd `u64` range.
///
/// The fixed bases are the published deterministic base set for all values
/// below `2^64`. This is a validation precondition for the field arithmetic,
/// not a cryptographic proof about a modulus supplied by an untrusted party.
pub(crate) fn is_prime(value: u64) -> bool {
    if value < 2 {
        return false;
    }
    if value == 2 || value == 3 {
        return true;
    }
    if value.is_multiple_of(2) {
        return false;
    }

    let mut odd_part = value - 1;
    let mut powers_of_two = 0;
    while odd_part.is_multiple_of(2) {
        odd_part /= 2;
        powers_of_two += 1;
    }

    [2_u64, 325, 9_375, 28_178, 450_775, 9_780_504, 1_795_265_022]
        .into_iter()
        .all(|base| miller_rabin_round(value, odd_part, powers_of_two, base))
}

fn miller_rabin_round(value: u64, odd_part: u64, powers_of_two: u32, base: u64) -> bool {
    let base = base % value;
    if base == 0 {
        return true;
    }
    let mut result = mod_pow(base, odd_part, value);
    if result == 1 || result == value - 1 {
        return true;
    }
    for _ in 1..powers_of_two {
        result = mul_mod(result, result, value);
        if result == value - 1 {
            return true;
        }
    }
    false
}

fn mod_pow(mut base: u64, mut exponent: u64, modulus: u64) -> u64 {
    let mut result = 1_u64;
    while exponent != 0 {
        if exponent & 1 == 1 {
            result = mul_mod(result, base, modulus);
        }
        base = mul_mod(base, base, modulus);
        exponent >>= 1;
    }
    result
}

fn mul_mod(left: u64, right: u64, modulus: u64) -> u64 {
    ((left as u128 * right as u128) % modulus as u128) as u64
}
