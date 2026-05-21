use primus_integer::{DivRemScalar, WideningMul};
use primus_modulus::BarrettModulus;
use primus_reduce::Reduce;

use crate::CrtValueT;

/// Try to convert a `num::BigUint` to `u128`.
///
/// Returns `None` if the value requires more than 128 bits.
pub fn biguint_to_u128(n: &num::BigUint) -> Option<u128> {
    let mut iter = n.iter_u64_digits();
    let lo = iter.next().unwrap_or(0) as u128;
    match iter.next() {
        None => Some(lo),
        Some(hi) => {
            if iter.next().is_some() {
                None
            } else {
                Some(lo | ((hi as u128) << 64))
            }
        }
    }
}

/// Scale `value` by `q_prime/q` with round-to-nearest (ties away from zero),
/// store the result in `value`, and compute `result % delta_prime` stored in `e`.
///
/// Uses u128 native arithmetic. Caller must ensure `q`, `q_prime`, `delta_prime`
/// all fit in u128 and that `value` represents a number < q.
pub fn scale_round_and_mod(
    value: &mut [CrtValueT; 2],
    e: &mut [CrtValueT; 2],
    q: u128,
    q_prime: u128,
    delta_prime: BarrettModulus<u128>,
) {
    let val = read_u128(value);

    let (lo, hi) = WideningMul::widening_mul(val, q_prime);

    let mut quotient = [0u128; 2];
    let rem = u128::div_rem_scalar(&[lo, hi], q, &mut quotient);
    let mut result = quotient[0];

    if rem * 2 >= q {
        result += 1;
    }

    write_u128(result, value);

    let e_val = delta_prime.reduce(result);

    write_u128(e_val, e);
}

/// Read a u128 from two u64 limbs (little-endian).
#[inline(always)]
pub fn read_u128(limbs: &[CrtValueT; 2]) -> u128 {
    limbs[0] as u128 | ((limbs[1] as u128) << 64)
}

/// Write a u128 into two u64 limbs (little-endian).
#[inline(always)]
pub fn write_u128(value: u128, limbs: &mut [CrtValueT; 2]) {
    limbs[0] = value as CrtValueT;
    limbs[1] = (value >> 64) as CrtValueT;
}

/// `*a = (*a + b) % modulus`. All values must be < modulus.
#[inline(always)]
pub fn add_mod_u128(a: &mut [CrtValueT; 2], b: &[CrtValueT; 2], modulus: u128) {
    let mut sum = read_u128(a).wrapping_add(read_u128(b));
    if sum >= modulus {
        sum -= modulus;
    }
    write_u128(sum, a);
}

/// `*a = (*a - b) % modulus`. All values must be < modulus.
#[inline(always)]
pub fn sub_mod_u128(a: &mut [CrtValueT; 2], b: &[CrtValueT; 2], modulus: u128) {
    let a_val = read_u128(a);
    let b_val = read_u128(b);
    if a_val >= b_val {
        write_u128(a_val - b_val, a);
    } else {
        write_u128(a_val + modulus - b_val, a);
    }
}

/// `*a = (-*a) % modulus`. Input must be < modulus.
#[inline(always)]
pub fn neg_mod_u128(a: &mut [CrtValueT; 2], modulus: u128) {
    let val = read_u128(a);
    if val != 0 {
        write_u128(modulus - val, a);
    }
}
