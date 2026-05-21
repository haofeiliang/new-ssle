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
    let val = value[0] as u128 | ((value[1] as u128) << 64);

    let (lo, hi) = WideningMul::widening_mul(val, q_prime);

    let mut quotient = [0u128; 2];
    let rem = u128::div_rem_scalar(&[lo, hi], q, &mut quotient);
    let mut result = quotient[0];

    if rem * 2 >= q {
        result += 1;
    }

    value[0] = result as CrtValueT;
    value[1] = (result >> 64) as CrtValueT;

    let e_val = delta_prime.reduce(result);

    e[0] = e_val as CrtValueT;
    e[1] = (e_val >> 64) as CrtValueT;
}
