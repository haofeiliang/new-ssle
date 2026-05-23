use std::{hint::cold_path, time::Instant};

use num::Integer;
use primus_factor::ShoupFactor;
#[cfg(not(feature = "parallel"))]
use primus_fhe_core::DcrtGlweExpandCoeffContext;
#[cfg(feature = "parallel")]
use primus_fhe_core::DcrtGlweExpandCoeffSyncPool;
use primus_fhe_core::NttRlwePublicKey;
use primus_integer::{AsInto, DataMut, izip};
use primus_lattice::{
    context::DcrtGlevContext,
    ggsw::DcrtGgsw,
    glwe::{CrtGlwe, DcrtGlwe},
    rlwe::{NttRlwe, Rlwe, RlweOwned},
};
use primus_modulus::BarrettModulus;
use primus_ntt::{DcrtTable, NttTable};
use primus_poly::{ArrayBase, DcrtPolynomial, Polynomial, PolynomialOwned};
use primus_reduce::{Modulus, ReduceInv};
use primus_rns::RNSBase;
use rand::RngExt;
use tracing::{debug, info};

use crate::{
    CoefficientExpansionKey, CommitModulus, CommitTable, CommitValueT, CrtTable, CrtValueT,
    MasterPublicKey, MasterSecretKey, MasterSecretKeyShare, add_mod_u128, biguint_to_u128,
    neg_mod_u128, read_u128, scale_round_and_mod, sub_mod_u128,
};

// ===== Helper: slice-to-array conversion =====

/// Convert a 2-element slice to a `&[CrtValueT; 2]` reference. Panics if the slice length is not 2.
#[inline(always)]
fn as_array2(slice: &[CrtValueT]) -> &[CrtValueT; 2] {
    slice.try_into().unwrap()
}

/// Convert a 2-element mutable slice to a `&mut [CrtValueT; 2]` reference.
#[inline(always)]
fn as_array2_mut(slice: &mut [CrtValueT]) -> &mut [CrtValueT; 2] {
    slice.try_into().unwrap()
}

// ===== Step 1: External Product Chain =====

/// External product chain: accumulates all RGSW ciphertexts into the ACC.
///
/// Computes ACC ← ∏_{i=0}^{n-1} RGSW_i ⊡ ACC via repeated external product
/// (paper §4.3.1, Algorithm 2 lines 20-21: ct ← ctr_i ⊡ ct).
///
/// Each intermediate result is converted back to coefficient form for the next
/// multiplication. The final result stays in NTT form (`ex_product_out`, a
/// `DcrtGlwe`) so it can be fed directly into coefficient expansion.
///
/// `acc` holds the initial ACC and is consumed; `ex_product_out` must be
/// pre-allocated with length `rns_glwe_len`.
#[inline]
pub fn external_product_chain(
    acc: &mut CrtGlwe<Vec<CrtValueT>>,
    all_rotate_ggsw: &[DcrtGgsw<Vec<CrtValueT>>],
    ex_product_out: &mut DcrtGlwe<Vec<CrtValueT>>,
    basis: &primus_decompose::big_integer::BigUintApproxSignedBasis<CrtValueT>,
    table: &CrtTable,
    base_q: &RNSBase<CrtValueT, BarrettModulus<CrtValueT>>,
    context: &mut DcrtGlevContext<CrtValueT>,
) {
    let (last, pre) = all_rotate_ggsw.split_last().unwrap();

    for rotate_rgsw in pre.iter() {
        acc.mul_dcrt_ggsw_inplace(rotate_rgsw, ex_product_out, basis, table, base_q, context);
        ex_product_out.to_coeff_form_inplace(acc, table);
    }

    acc.mul_dcrt_ggsw_inplace(last, ex_product_out, basis, table, base_q, context);
}

// ===== Step 2: Coefficient Expansion =====

/// Coefficient expansion (serial path).
#[cfg(not(feature = "parallel"))]
#[inline]
pub fn expand_selectors(
    eck: &CoefficientExpansionKey,
    ex_product: &DcrtGlwe<Vec<CrtValueT>>,
    selectors: &mut [DcrtGlwe<Vec<CrtValueT>>],
    expand_coeff_params: &primus_fhe_core::CrtGlevParameters<CrtValueT, BarrettModulus<CrtValueT>>,
    base_q: &RNSBase<CrtValueT, BarrettModulus<CrtValueT>>,
    context: &mut DcrtGlweExpandCoeffContext<CrtValueT>,
) {
    eck.expand_partial_coefficients_inplace(
        ex_product,
        selectors,
        expand_coeff_params,
        base_q,
        context,
    );
}

/// Coefficient expansion (parallel path).
#[cfg(feature = "parallel")]
#[inline]
pub fn expand_selectors(
    eck: &CoefficientExpansionKey,
    ex_product: &DcrtGlwe<Vec<CrtValueT>>,
    selectors: &mut [DcrtGlwe<Vec<CrtValueT>>],
    expand_coeff_params: &primus_fhe_core::CrtGlevParameters<CrtValueT, BarrettModulus<CrtValueT>>,
    base_q: &RNSBase<CrtValueT, BarrettModulus<CrtValueT>>,
    context_pool: &mut DcrtGlweExpandCoeffSyncPool<CrtValueT>,
) {
    eck.expand_partial_coefficients_inplace_parallel(
        ex_product,
        selectors,
        expand_coeff_params,
        base_q,
        context_pool,
    );
}

// ===== Step 3a: Commit Re-randomization =====

/// Re-randomize one party's commit ciphertext.
///
/// 1. Encrypts zeros with `commit_pk` (in NTT form)
/// 2. Inverse-NTT transforms back to coefficient form
/// 3. Adds the original `commit` element-wise (mod CommitModulus)
///
/// Result is written to `rr_commit`.
#[inline]
pub fn rerandomize_commit<R: rand::Rng + rand::CryptoRng>(
    commit: &RlweOwned<CommitValueT>,
    commit_pk: &NttRlwePublicKey<Vec<CommitValueT>>,
    rr_commit: &mut RlweOwned<CommitValueT>,
    commit_params: &primus_fhe_core::RlweParameters<CommitValueT, CommitModulus>,
    commit_ntt_table: &CommitTable,
    rng: &mut R,
) {
    let mut output = NttRlwe(rr_commit.as_mut());
    commit_pk.encrypt_zeros_inplace(&mut output, commit_params, commit_ntt_table, rng);

    let commit_poly_length = commit_params.poly_length();
    output
        .iter_ntt_poly_mut(commit_poly_length)
        .for_each(|poly| {
            commit_ntt_table.inverse_transform_slice(poly.0);
        });

    rr_commit.add_element_wise_assign(commit, CommitModulus);
}

// ===== Step 3b: Encode Single Commit =====

/// Encode one party's re-randomized commit using its selector.
///
/// Encodes the inner product ⟨selector, commit⟩ in the CRT basis.
///
/// Implements Algorithm 2 lines 27-28 (parta += sel_i ⊙ a_{i,k}, partb +=
/// sel_i ⊙ b_{i,k}). Each commit coefficient is decomposed into the CRT basis,
/// NTT-transformed, and accumulated with the selector via
/// `add_dcrt_glwe_mul_dcrt_polynomial_assign`. Called once per party; the
/// accumulation is additive.
///
/// `temp` (ring_poly_length) and `msg` (rns_poly_len) are scratch buffers reused
/// across calls.
#[inline]
pub fn encode_single_commit(
    selector: &DcrtGlwe<Vec<CrtValueT>>,
    rr_commit: &RlweOwned<CommitValueT>,
    encode_commit_a: &mut [CrtValueT],
    encode_commit_b: &mut [CrtValueT],
    temp: &mut [CrtValueT],
    msg: &mut DcrtPolynomial<Vec<CrtValueT>>,
    commit_poly_length: usize,
    ring_poly_length: usize,
    base_q: &RNSBase<CrtValueT, BarrettModulus<CrtValueT>>,
    commit_modulus_val: CrtValueT,
    table: &CrtTable,
    cipher_moduli: &[BarrettModulus<CrtValueT>],
) {
    for (encode_commit, poly) in izip!(
        [encode_commit_a, encode_commit_b].into_iter(),
        rr_commit.iter_poly(commit_poly_length),
    ) {
        temp.iter_mut()
            .zip(poly.iter())
            .for_each(|(x, y)| *x = *y as CrtValueT);
        base_q.wrapping_decompose_small_values_inplace(
            temp,
            msg.as_mut(),
            ring_poly_length,
            commit_modulus_val,
        );
        table.transform_slice(msg.as_mut());
        DcrtGlwe(encode_commit).add_dcrt_glwe_mul_dcrt_polynomial_assign(
            selector,
            msg,
            ring_poly_length,
            cipher_moduli,
        );
    }
}

// ===== Step 3c: Aggregate Encoded Commits =====

/// Sum all parties' encoded commits into a single result.
///
/// `all_encode_commits`: shape `[party_count][rns_glwe_len * 2]`.
/// `final_encode_commits`: zero-initialized, length `rns_glwe_len * 2`.
pub fn aggregate_encode_commits(
    all_encode_commits: &[CrtValueT],
    final_encode_commits: &mut [CrtValueT],
    rns_glwe_len: usize,
    ring_poly_length: usize,
    rns_poly_len: usize,
    cipher_moduli: &[BarrettModulus<CrtValueT>],
) {
    all_encode_commits
        .chunks_exact(rns_glwe_len * 2)
        .for_each(|ecs| {
            ecs.chunks_exact(rns_glwe_len)
                .zip(final_encode_commits.chunks_exact_mut(rns_glwe_len))
                .for_each(|(x, y)| {
                    DcrtGlwe(y).add_element_wise_assign(
                        &DcrtGlwe(x),
                        ring_poly_length,
                        rns_poly_len,
                        cipher_moduli,
                    );
                });
        });
}

// ===== Step 4a: Decrypt and Compose =====

/// Phase-decrypt one GLWE slot and compose CRT residues to BigUint.
///
/// Party 0 uses `phase_inplace` (full secret key material); other parties
/// use `phase_a_inplace` (their secret key share). This computes an additive
/// share of u_q = Δ·m + e_q, corresponding to step 1 of the Ajax distributed
/// decryption protocol (2025/1834, Figure 10, line 1).
///
/// After phase decryption, the CRT polynomial is inverse-NTT-transformed and
/// composed from the RNS basis into BigUint coefficients.
///
/// `crt_out` (scratch, `rns_poly_len`) and `big_uint_out` (output,
/// `big_uint_poly_len`) must be pre-allocated. `compose_buffer` is obtained
/// from the external product context.
#[inline]
pub fn decrypt_and_compose_slot(
    msk_share: &MasterSecretKeyShare,
    glwe_slot: &[CrtValueT],
    crt_out: &mut [CrtValueT],
    big_uint_out: &mut [CrtValueT],
    ring_poly_length: usize,
    table: &CrtTable,
    base_q: &RNSBase<CrtValueT, BarrettModulus<CrtValueT>>,
    compose_buffer: &mut [CrtValueT],
    is_party_0: bool,
) {
    if is_party_0 {
        msk_share.phase_inplace(&DcrtGlwe(glwe_slot), &mut DcrtPolynomial(&mut *crt_out));
    } else {
        msk_share.phase_a_inplace(&DcrtGlwe(glwe_slot), &mut DcrtPolynomial(&mut *crt_out));
    }
    table.inverse_transform_slice(crt_out);
    base_q.compose_multiple_values_inplace(crt_out, big_uint_out, ring_poly_length, compose_buffer);
}

/// Process one party's full distributed decryption share.
///
/// Implements the "mask-then-open" distributed decryption from Ajax
/// (2025/1834, Figure 10). SSLE adapts this by using pre-shared independent
/// randoms (r_Δ', r_q') from setup, rather than Ajax's online MPC-generated
/// coupled double-sharing (r, r_q) over two rings. This simplification is
/// valid in the all-but-one threshold setting.
///
/// For each of the two GLWE slots:
///   1. Phase-decrypt → additive share of u_q = Δ·m + e_q  (Fig.10 step 1)
///   2. INTT + RNS compose → BigUint coefficients
///   3. Scale-round: value = round(u_q · q' / q) mod q'  (modulus switching)
///      e = value mod Δ'  (extract error share, Fig.10 step 1 bottom)
///   4. Mask: e += r_Δ' (mod Δ'), value += r_q' (mod q')  (Fig.10 steps 2-3)
///
/// The u128 fast path is used when q, q', Δ' all fit in u128 (true for
/// all current parameter sets); otherwise the BigUint fallback is taken.
///
/// After all parties complete, Party 0 aggregates e-shares (opens e+r,
/// Fig.10 step 2), centers, and subtracts e from value to recover Δ·m
/// (Fig.10 step 3). The Combine phase (§4.4, Alg.2 lines 36-38) then
/// reconstructs the final result.
#[inline]
#[allow(clippy::too_many_arguments)]
fn decrypt_share_for_party(
    msk_share: &MasterSecretKeyShare,
    crt_dec_share: &mut [CrtValueT],
    big_uint_dec_share: &mut [CrtValueT],
    e_share: &mut [CrtValueT],
    r_mod_delta_prime_share: &[CrtValueT],
    r_mod_q_prime_share: &[CrtValueT],
    final_encode_commits: &[CrtValueT],
    ring_poly_length: usize,
    rns_glwe_len: usize,
    big_uint_value_len: usize,
    table: &CrtTable,
    base_q: &RNSBase<CrtValueT, BarrettModulus<CrtValueT>>,
    compose_buffer: &mut [CrtValueT],
    is_party_0: bool,
    fast_q: Option<u128>,
    fast_qp: Option<u128>,
    fast_dp: Option<BarrettModulus<u128>>,
    q_big: &num::BigUint,
    q_prime_big: &num::BigUint,
    delta_prime_big: &num::BigUint,
    delta_prime: &primus_integer::BigUint<Vec<CrtValueT>>,
    q_prime: &primus_integer::BigUint<Vec<CrtValueT>>,
) {
    for (encode_commit, crt_dec, big_uint_dec) in izip!(
        final_encode_commits.chunks_exact(rns_glwe_len),
        crt_dec_share.chunks_exact_mut(crt_dec_share.len() / 2),
        big_uint_dec_share.chunks_exact_mut(big_uint_dec_share.len() / 2),
    ) {
        decrypt_and_compose_slot(
            msk_share,
            encode_commit,
            crt_dec,
            big_uint_dec,
            ring_poly_length,
            table,
            base_q,
            compose_buffer,
            is_party_0,
        );
    }

    if let (Some(q128), Some(qp128), Some(dp128)) = (fast_q, fast_qp, fast_dp) {
        let dp = dp128.value_unchecked();
        for ((v_chunk, e_chunk), (r_dp_chunk, r_qp_chunk)) in izip!(
            izip!(
                big_uint_dec_share.chunks_exact_mut(2),
                e_share.chunks_exact_mut(2),
            ),
            izip!(
                r_mod_delta_prime_share.chunks_exact(2),
                r_mod_q_prime_share.chunks_exact(2),
            ),
        ) {
            let v_arr = as_array2_mut(v_chunk);
            let e_arr = as_array2_mut(e_chunk);
            scale_round_and_mod(v_arr, e_arr, q128, qp128, dp128);
            add_mod_u128(e_arr, as_array2(r_dp_chunk), dp);
            add_mod_u128(v_arr, as_array2(r_qp_chunk), qp128);
        }
    } else {
        cold_path();
        for (value, e, r_mod_delta_prime) in izip!(
            big_uint_dec_share.chunks_exact_mut(big_uint_value_len),
            e_share.chunks_exact_mut(big_uint_value_len),
            r_mod_delta_prime_share.chunks_exact(big_uint_value_len),
        ) {
            scale_round_mod_biguint(
                value,
                e,
                r_mod_delta_prime,
                q_big,
                q_prime_big,
                delta_prime_big,
                delta_prime,
                big_uint_value_len,
            );
        }
        add_random_biguint(
            big_uint_dec_share,
            r_mod_q_prime_share,
            q_prime,
            big_uint_value_len,
        );
    }
}

// ===== Step 4b: Scale/Round BigUint Fallback =====

/// BigUint fallback for scale-round-and-mod (cold path, `#[inline(never)]`).
///
/// Implements the modulus-switching step of Ajax (2025/1834, Fig.10 step 1):
///   value ← round(value · q' / q) mod q'    (switch modulus from q to q')
///   e     ← (value mod Δ') + r_Δ'  mod Δ'  (extract error share, mask)
///
/// The u128 fast path (`scale_round_and_mod`) is preferred for the current
/// parameter sets (q, q', Δ' all fit in u128); this fallback uses generic
/// BigUint arithmetic for correctness at any parameter size.
///
/// Note: `r_mod_q_prime` is NOT added to `value` here — call
/// `add_random_biguint` separately after the network round.
#[inline(never)]
pub fn scale_round_mod_biguint(
    value: &mut [CrtValueT],
    e: &mut [CrtValueT],
    r_mod_delta_prime: &[CrtValueT],
    q_big: &num::BigUint,
    q_prime_big: &num::BigUint,
    delta_prime_big: &num::BigUint,
    delta_prime: &primus_integer::BigUint<Vec<CrtValueT>>,
    _big_uint_value_len: usize,
) {
    let mut temp = num::BigUint::from_slice(bytemuck::cast_slice(value));

    temp *= q_prime_big;

    let (mut temp, rem) = temp.div_rem(q_big);
    if rem * 2u8 >= *q_big {
        temp += 1u8;
    }

    value.fill(0);

    value
        .iter_mut()
        .zip(temp.iter_u64_digits())
        .for_each(|(x, y)| *x = y);

    temp %= delta_prime_big;

    e.iter_mut()
        .zip(temp.iter_u64_digits())
        .for_each(|(x, y)| *x = y);

    primus_integer::BigUint(e)
        .add_modulo_assign(&primus_integer::BigUint(r_mod_delta_prime), delta_prime);
}

// ===== Step 4c: Party 0 Aggregation Helpers =====

/// Aggregate e-shares (mod delta_prime). Both slices must have length divisible by 2.
#[inline]
pub fn aggregate_e_shares_u128(
    p0_e_share: &mut [CrtValueT],
    other_e_shares: &[CrtValueT],
    modulus: u128,
) {
    for (a_chunk, b_chunk) in izip!(
        p0_e_share.chunks_exact_mut(2),
        other_e_shares.chunks_exact(2),
    ) {
        add_mod_u128(as_array2_mut(a_chunk), as_array2(b_chunk), modulus);
    }
}

/// Aggregate e-shares (BigUint fallback).
#[inline(never)]
pub fn aggregate_e_shares_biguint(
    p0_e_share: &mut [CrtValueT],
    other_e_shares: &[CrtValueT],
    delta_prime: &primus_integer::BigUint<Vec<CrtValueT>>,
    big_uint_value_len: usize,
) {
    for e_share in other_e_shares.chunks_exact(big_uint_value_len * 2) {
        for (value, e) in izip!(
            p0_e_share.chunks_exact_mut(big_uint_value_len),
            e_share.chunks_exact(big_uint_value_len),
        ) {
            primus_integer::BigUint(value)
                .add_modulo_assign(&primus_integer::BigUint(e), delta_prime);
        }
    }
}

/// Centering: if e >= modulus/2, replace e with modulus - e.
/// `p0_e_share` length must be divisible by 2.
#[inline]
pub fn center_e_shares_u128(p0_e_share: &mut [CrtValueT], modulus: u128) {
    let half = modulus / 2;
    for chunk in p0_e_share.chunks_exact_mut(2) {
        let arr = as_array2_mut(chunk);
        if read_u128(arr) >= half {
            neg_mod_u128(arr, modulus);
        }
    }
}

/// Centering (BigUint fallback).
#[inline(never)]
pub fn center_e_shares_biguint(
    p0_e_share: &mut [CrtValueT],
    delta_prime_half: &primus_integer::BigUint<Vec<CrtValueT>>,
    delta_prime: &primus_integer::BigUint<Vec<CrtValueT>>,
    big_uint_value_len: usize,
) {
    for value in p0_e_share.chunks_exact_mut(big_uint_value_len) {
        let mut v = primus_integer::BigUint(value);
        if v.cmp(delta_prime_half).is_ge() {
            v.neg_modulo_assign(delta_prime);
        }
    }
}

/// Subtract e from value and add q'-random: value = value - e + r (mod q_prime).
/// All slices must have length divisible by 2.
#[inline]
pub fn sub_e_add_random_u128(
    value: &mut [CrtValueT],
    e: &[CrtValueT],
    r_mod_q_prime: &[CrtValueT],
    modulus: u128,
) {
    for (v_chunk, e_chunk, r_chunk) in izip!(
        value.chunks_exact_mut(2),
        e.chunks_exact(2),
        r_mod_q_prime.chunks_exact(2),
    ) {
        let v_arr = as_array2_mut(v_chunk);
        sub_mod_u128(v_arr, as_array2(e_chunk), modulus);
        add_mod_u128(v_arr, as_array2(r_chunk), modulus);
    }
}

/// Subtract e from value and add q'-random (BigUint fallback).
#[inline(never)]
pub fn sub_e_add_random_biguint(
    value: &mut [CrtValueT],
    e: &[CrtValueT],
    r_mod_q_prime: &[CrtValueT],
    q_prime: &primus_integer::BigUint<Vec<CrtValueT>>,
    big_uint_value_len: usize,
) {
    for (v, e_val, r) in izip!(
        value.chunks_exact_mut(big_uint_value_len),
        e.chunks_exact(big_uint_value_len),
        r_mod_q_prime.chunks_exact(big_uint_value_len),
    ) {
        primus_integer::BigUint(&mut *v)
            .sub_modulo_assign(&primus_integer::BigUint(e_val), q_prime);
        primus_integer::BigUint(&mut *v).add_modulo_assign(&primus_integer::BigUint(r), q_prime);
    }
}

/// Just add q'-random to value (mod q_prime). Used by non-Party-0 parties.
/// `value` and `r_mod_q_prime` length must be divisible by 2.
#[inline]
pub fn add_random_u128(value: &mut [CrtValueT], r_mod_q_prime: &[CrtValueT], modulus: u128) {
    for (v_chunk, r_chunk) in izip!(value.chunks_exact_mut(2), r_mod_q_prime.chunks_exact(2),) {
        add_mod_u128(as_array2_mut(v_chunk), as_array2(r_chunk), modulus);
    }
}

/// Just add q'-random to value (BigUint fallback).
#[inline(never)]
pub fn add_random_biguint(
    value: &mut [CrtValueT],
    r_mod_q_prime: &[CrtValueT],
    q_prime: &primus_integer::BigUint<Vec<CrtValueT>>,
    big_uint_value_len: usize,
) {
    for (v, r) in izip!(
        value.chunks_exact_mut(big_uint_value_len),
        r_mod_q_prime.chunks_exact(big_uint_value_len),
    ) {
        primus_integer::BigUint(v).add_modulo_assign(&primus_integer::BigUint(r), q_prime);
    }
}

/// Aggregate value shares (mod q_prime). `p0_share` and `other_shares` length
/// must be divisible by 2.
#[inline]
pub fn aggregate_value_shares_u128(
    p0_share: &mut [CrtValueT],
    other_shares: &[CrtValueT],
    modulus: u128,
) {
    for (a_chunk, b_chunk) in izip!(p0_share.chunks_exact_mut(2), other_shares.chunks_exact(2),) {
        add_mod_u128(as_array2_mut(a_chunk), as_array2(b_chunk), modulus);
    }
}

/// Aggregate value shares (BigUint fallback).
#[inline(never)]
pub fn aggregate_value_shares_biguint(
    p0_share: &mut [CrtValueT],
    other_shares: &[CrtValueT],
    q_prime: &primus_integer::BigUint<Vec<CrtValueT>>,
    big_uint_value_len: usize,
) {
    for share in other_shares.chunks_exact(big_uint_value_len * 2) {
        for (x, y) in izip!(
            p0_share.chunks_exact_mut(big_uint_value_len),
            share.chunks_exact(big_uint_value_len),
        ) {
            primus_integer::BigUint(x).add_modulo_assign(&primus_integer::BigUint(y), q_prime);
        }
    }
}

// ===== Step 5a: div_v =====

/// Compute `poly = (poly - poly · X^{party_count}) · inv_two` mod CommitModulus.
///
/// Implements the factor u^{-1} = 2^{-1}(1 - X^G) from §4.5 (Verify).
/// This "folds" the ring by party_count: coefficients at positions i and
/// i + party_count are combined via (c_i - c_{i+party_count}) / 2. After
/// applying to both A and B parts of `final_commit`, each party's small
/// RLWE ciphertext occupies a distinct chunk of length `commit_poly_length`.
///
/// `scratch` must be pre-allocated with length `ring_poly_length`.
#[inline]
pub fn div_v_inplace(
    poly: &mut [CommitValueT],
    scratch: &mut PolynomialOwned<CommitValueT>,
    party_count: usize,
    inv_two_factor: ShoupFactor<CommitValueT>,
) {
    scratch.copy_from(poly.as_ref());
    scratch.mul_monomial_assign(party_count, CommitModulus);

    let mut p = Polynomial(poly);
    p.sub_assign(scratch, CommitModulus);
    p.mul_factor_assign(inv_two_factor, CommitModulus.value_unchecked());
}

// ===== Step 5b: Decode Commit =====

/// Recover the leader's small RLWE ciphertext from the folded final commit.
///
/// Implements Algorithm 2 line 40: com ← (v·a_r, v·b_r) · u^{-1} mod (X^n+1).
/// After `div_v` (which applies u^{-1}), `final_commit` is folded into chunks
/// of `commit_poly_length` coefficients. Each chunk corresponds to one party's
/// differential RLWE ciphertext.
///
/// **Why only two chunks are non-zero**: The selectors {sel_i} from
/// PartialObliviousExpand (Alg.2 line 22) ensure only one sel_r encrypts a
/// non-zero value v = u · X^{w·G}. All other sel_i encrypt 0. During the
/// inner-product encoding (Alg.2 lines 27-28), only the leader's and its
/// paired party's contributions survive; the rest cancel.
///
/// **Decode algorithm**: scan the chunks. Adjacent non-zero chunks →
/// subtract (leader and pair are neighbours). Non-adjacent → add (sign flip
/// from X^N = -1 in the cyclotomic ring). The result is the leader's
/// original RLWE encryption of 0 (§4.5, Algorithm 2 lines 41-43).
pub fn decode_commit(
    final_commit: &[CommitValueT],
    decoded_commit: &mut [CommitValueT],
    commit_poly_length: usize,
    ring_poly_length: usize,
) {
    let (a_in, b_in) = final_commit.split_at(ring_poly_length);
    let (a_out, b_out) = decoded_commit.split_at_mut(commit_poly_length);

    let mut a_arr = ArrayBase(a_out);
    let mut b_arr = ArrayBase(b_out);

    let mut last: Option<usize> = None;
    for (i, (a_chunk, b_chunk)) in a_in
        .chunks_exact(commit_poly_length)
        .zip(b_in.chunks_exact(commit_poly_length))
        .enumerate()
    {
        if !ArrayBase(a_chunk).is_zero() || !ArrayBase(b_chunk).is_zero() {
            if let Some(last) = last {
                if last + 1 != i {
                    a_arr.add_element_wise_assign(&ArrayBase(a_chunk), CommitModulus);
                    b_arr.add_element_wise_assign(&ArrayBase(b_chunk), CommitModulus);
                } else {
                    a_arr.sub_element_wise_assign(&ArrayBase(a_chunk), CommitModulus);
                    b_arr.sub_element_wise_assign(&ArrayBase(b_chunk), CommitModulus);
                }
                return;
            } else {
                a_arr.copy_from_slice(a_chunk);
                b_arr.copy_from_slice(b_chunk);
                last = Some(i);
            }
        }
    }
}

// ===== Step 4d: Final Value Conversion =====

/// Convert a 2-limb BigUint value to CommitValueT: round(value / delta_prime).
#[inline]
pub fn final_value_to_commit_u128(big_uint_slot: &[CrtValueT], dp: u128) -> CommitValueT {
    let b_val = big_uint_slot[0] as u128 | ((big_uint_slot[1] as u128) << 64);
    let (b_q, rem) = b_val.div_rem(&dp);
    (if rem * 2 >= dp { b_q + 1 } else { b_q }) as CommitValueT
}

/// Convert BigUint value to CommitValueT (BigUint fallback).
#[inline(never)]
pub fn final_value_to_commit_biguint(
    big_uint_value: &[CrtValueT],
    delta_prime_big: &num::BigUint,
) -> CommitValueT {
    let b = num::BigUint::from_slice(bytemuck::cast_slice(big_uint_value));
    let (mut b, rem) = b.div_rem(delta_prime_big);
    if rem * 2u8 >= *delta_prime_big {
        b += 1u8;
    }
    b.iter_u32_digits().next().unwrap_or(0)
}

// ===== Compute-Time Protocol Runner =====

/// Timing measurements for each SSLE protocol phase.
#[derive(Clone, Copy)]
pub struct PhaseTimings {
    pub rlwe_mul_rgsw: std::time::Duration,
    pub expand_coefficients: std::time::Duration,
    pub compute_local_encode_commit: std::time::Duration,
    pub compute_final_encode_commit: std::time::Duration,
    pub distributed_decrypt: std::time::Duration,
    pub decrypt_commit: std::time::Duration,
    pub all_compute: std::time::Duration,
}

/// Run the full SSLE protocol, simulating all parties locally (no network).
///
/// This function is the single-party benchmark entry point used by the
/// `ssle_compute_time` and `ssle_ge_256_compute_time_improve` examples.
/// It returns per-phase timings for performance analysis.
///
/// # Protocol outline (Algorithm 2)
///
///   1. **External product chain** (§4.3.1, Alg.2 lines 20-21):
///      ct ← RLWE(u); for i: ct ← ctr_i ⊡ ct
///
///   2. **Coefficient expansion** (§4.3.1, Alg.2 line 22):
///      {sel_i} ← PartialObliviousExpand(ct, G)
///
///   3. **Commit re-randomization, encoding & aggregation**
///      (§4.3.1 ParElect lines 24-28 + §4.3.2 Elect lines 31-32):
///      com_{i,k} ← com_i + RLWE.Enc(pk_i, 0); parta += sel_i ⊙ a_{i,k}; ...
///      then parta = Σ parta_i, partb = Σ partb_i
///
///   4. **Distributed decryption** (Ajax 2025/1834 "mask-then-open", Fig.10;
///      instantiates Relect Alg.2 lines 33-38, §4.3.2 Elect + §4.4 Combine):
///      PartialDec with msk_i; masked share; open e+r; Combine → (v·a_r, v·b_r)
///
///   5. **Verification** (§4.5 Verify, Alg.2 lines 39-43):
///      com ← (v·a_r, v·b_r) · u^{-1} mod (X^n+1); Dec(H(sk), com) == 0
///
/// # Parameters
/// - `party_count`: number of parties (power of 2)
/// - `rgsw_count`: RGSW count; can be < `party_count` for large-party
///   optimization (fixed at 128 for party_count ≥ 256)
/// - `msk`/`mpk`/`eck`: keys from `KeyGen::generate_keys`
/// - `msk_shares`: master secret key shares (one per party)
/// - `dd_randoms`: distributed decryption random masks (one per party)
///
/// Returns `(leader_index, phase_timings)`.
pub fn run_compute_time_protocol(
    party_count: usize,
    rgsw_count: usize,
    msk: &MasterSecretKey,
    mpk: &MasterPublicKey,
    eck: &CoefficientExpansionKey,
    msk_shares: &[MasterSecretKeyShare],
    dd_randoms: &[(Vec<CrtValueT>, Vec<CrtValueT>)],
    #[allow(unused_variables)] num_threads: usize,
) -> (usize, PhaseTimings) {
    let rng = &mut rand::rng();

    // --- Extract parameters ---
    let ssle_params = mpk.params();
    let commit_params = ssle_params.commit_params();
    let ring_params = ssle_params.ring_params();
    let ggsw_params = ssle_params.ggsw_params();
    let expand_coeff_params = ssle_params.expand_coeff_params();

    let commit_poly_length = commit_params.poly_length();
    let ring_poly_length = ring_params.poly_length();
    let table = mpk.table();
    let commit_rlwe_len = commit_poly_length * 2;
    let moduli_count = ring_params.cipher_moduli_count();
    let rns_poly_len = ring_params.rns_poly_len();
    let rns_glwe_len = ring_params.rns_glwe_len();
    let big_uint_poly_len = ring_params.big_uint_poly_len();
    let rns_ggsw_len = ggsw_params.rns_ggsw_len();
    let base_q = ring_params.base_q();
    let big_uint_value_len = ring_params.big_uint_value_len();

    // --- Pre-compute constants ---
    let commit_ntt_table =
        CommitTable::new(commit_poly_length.trailing_zeros(), CommitModulus).unwrap();

    let inv_two = CommitModulus.reduce_inv(2);
    let inv_two_factor = ShoupFactor::new(inv_two, CommitModulus.value_unchecked());

    // --- Pre-compute BigUint fast-path params ---
    let p = num::BigUint::from(ring_params.plain_modulus_value());
    let q = base_q.moduli_product();
    let q_big = num::BigUint::from_slice(bytemuck::cast_slice(q.digits()));
    let q_prime_big = q_big.next_multiple_of(&p);
    let q_prime: primus_integer::BigUint<Vec<CrtValueT>> =
        primus_integer::BigUint(q_prime_big.iter_u64_digits().collect());
    let delta_prime_big = &q_prime_big / &p;
    let delta_prime: primus_integer::BigUint<Vec<CrtValueT>> =
        primus_integer::BigUint(delta_prime_big.iter_u64_digits().collect());
    let mut delta_prime_half = delta_prime.clone();
    delta_prime_half.right_shift_assign(1);

    let fast_q = biguint_to_u128(&q_big);
    let fast_qp = biguint_to_u128(&q_prime_big);
    let fast_dp = biguint_to_u128(&delta_prime_big).map(BarrettModulus::new);

    // --- Pre-allocate contexts ---
    let mut external_product_context = DcrtGlevContext::new(
        ring_poly_length,
        rns_poly_len,
        big_uint_poly_len,
        moduli_count,
    );

    #[cfg(not(feature = "parallel"))]
    let mut expand_coeff_context = DcrtGlweExpandCoeffContext::new(
        expand_coeff_params.dimension(),
        ring_poly_length,
        rns_poly_len,
        big_uint_poly_len,
        moduli_count,
    );

    #[cfg(feature = "parallel")]
    let mut expand_coeff_context_pool = DcrtGlweExpandCoeffSyncPool::with_capacity(
        num_threads,
        expand_coeff_params.dimension(),
        ring_poly_length,
        rns_poly_len,
        big_uint_poly_len,
        moduli_count,
    );

    // --- Pre-allocate working buffers ---
    let mut poly_for_div_v: PolynomialOwned<CommitValueT> = Polynomial::zero(ring_poly_length);

    let mut all_rotate_ggsw: Vec<DcrtGgsw<Vec<CrtValueT>>> =
        vec![DcrtGgsw::zero(rns_ggsw_len); rgsw_count];
    let mut ex_product_glwe: DcrtGlwe<Vec<CrtValueT>> = DcrtGlwe::zero(rns_glwe_len);
    let mut selectors = vec![DcrtGlwe::zero(rns_glwe_len); party_count];

    let mut all_encode_commits: Vec<CrtValueT> = vec![0; rns_glwe_len * 2 * party_count];
    let mut final_encode_commits: Vec<CrtValueT> = vec![0; rns_glwe_len * 2];
    let mut temp: Vec<CrtValueT> = vec![0; ring_poly_length];
    let mut msg: DcrtPolynomial<Vec<CrtValueT>> = DcrtPolynomial::zero(rns_poly_len);

    let mut crt_dec_shares: Vec<CrtValueT> = vec![0; rns_poly_len * 2 * party_count];
    let mut big_uint_dec_shares: Vec<CrtValueT> = vec![0; big_uint_poly_len * 2 * party_count];
    let mut all_e_shares: Vec<CrtValueT> = vec![0; big_uint_poly_len * 2 * party_count];

    let mut final_commit: Vec<CommitValueT> = vec![0; ring_poly_length * 2];
    let mut decoded_commit: Vec<CommitValueT> = vec![0; commit_poly_length * 2];

    // --- Generate random degrees and pre-compute the elected leader index ---
    let uniform_ring_poly_length = rand::distr::Uniform::new(0, ring_poly_length * 2).unwrap();
    let all_degree: Vec<usize> = rng
        .sample_iter(uniform_ring_poly_length)
        .take(rgsw_count)
        .collect();
    let choose = all_degree.iter().sum::<usize>() % party_count;
    info!(
        "=== SSLE Protocol === {} parties, {} RGSWs, ring_poly_length = {} ===",
        party_count, rgsw_count, ring_poly_length
    );
    debug!("Expected leader (secret): party {choose}");

    // --- Generate commit keys and commits ---
    let (all_commit_sk, all_commit_pk): (Vec<_>, Vec<_>) = (0..party_count)
        .map(|_| mpk.generate_commit_key_pair(&commit_ntt_table, rng))
        .collect();

    let all_commit: Vec<RlweOwned<CommitValueT>> = all_commit_sk
        .iter()
        .map(|sk| {
            sk.encrypt_zeros(commit_params, &commit_ntt_table, rng)
                .into_coeff_form(&commit_ntt_table)
        })
        .collect();

    let mut all_rr_commit: Vec<RlweOwned<CommitValueT>> =
        vec![Rlwe::zero(commit_rlwe_len); party_count];

    // --- Generate RGSW for parties 1..rgsw_count ---
    all_rotate_ggsw
        .iter_mut()
        .zip(all_degree.iter())
        .skip(1)
        .for_each(|(rgsw, &degree)| {
            mpk.generate_rotate_rgsw_inplace(degree, rgsw, rng);
        });

    // Pre-encrypt zeros for parties 1..party_count into encode_commits
    // (each party occupies rns_glwe_len * 2 elements = 2 chunks; skip(2) skips party 0)
    all_encode_commits
        .chunks_exact_mut(rns_glwe_len)
        .skip(2)
        .for_each(|ecs| {
            msk.encrypt_zeros_inplace(&mut DcrtGlwe(ecs), ring_params, table, rng);
        });

    let encode_commits = &mut all_encode_commits[0..rns_glwe_len * 2];

    // ===== Phase 1/5: External Product Chain (§4.3.1, Alg.2 lines 20-21) =====
    // ct ← RLWE(u); for i: ct ← ctr_i ⊡ ct  (RGSW external product chain)
    debug!(
        "[Phase 1/5] External product chain — accumulating {} RGSW ciphertexts",
        rgsw_count
    );
    let phase1_start = Instant::now();

    let mut acc: CrtGlwe<Vec<CrtValueT>> = mpk.generate_init_acc(party_count);
    mpk.generate_rotate_rgsw_inplace(all_degree[0], &mut all_rotate_ggsw[0], rng);

    external_product_chain(
        &mut acc,
        &all_rotate_ggsw,
        &mut ex_product_glwe,
        ggsw_params.basis(),
        table,
        base_q,
        &mut external_product_context,
    );

    // ===== Phase 2/5: Coefficient Expansion (§4.3.1, Alg.2 line 22) =====
    // {sel_i} ← PartialObliviousExpand(ct, G) → per-party selector ciphertexts
    debug!(
        "[Phase 2/5] Coefficient expansion → {} selectors",
        party_count
    );
    let expand_partial_coefficients_start = Instant::now();

    #[cfg(not(feature = "parallel"))]
    expand_selectors(
        eck,
        &ex_product_glwe,
        &mut selectors,
        expand_coeff_params,
        base_q,
        &mut expand_coeff_context,
    );

    #[cfg(feature = "parallel")]
    expand_selectors(
        eck,
        &ex_product_glwe,
        &mut selectors,
        expand_coeff_params,
        base_q,
        &mut expand_coeff_context_pool,
    );

    let expand_partial_coefficients_end = Instant::now();

    // ===== Phase 3/5: Commit Re-randomization & Encoding =====
    // (§4.3.1 ParElect lines 24-28: com_{i,k} ← com_i + RLWE.Enc(pk_i, 0),
    //  parta += sel_i ⊙ a_{i,k}, partb += sel_i ⊙ b_{i,k};
    //  + §4.3.2 Elect lines 31-32: aggregate parta = Σ parta_i, partb = Σ partb_i)
    debug!("[Phase 3/5] Commit re-randomization, encoding & aggregation");
    for (commit, commit_pk, rr_commit) in izip!(
        all_commit.iter(),
        all_commit_pk.iter(),
        all_rr_commit.iter_mut(),
    ) {
        rerandomize_commit(
            commit,
            commit_pk,
            rr_commit,
            commit_params,
            &commit_ntt_table,
            rng,
        );
    }

    let commit_modulus_val = CommitModulus.value_unchecked().as_into();
    let cipher_moduli = ring_params.cipher_moduli();

    let (enc_a, enc_b) = encode_commits.split_at_mut(rns_glwe_len);
    for (selector, rr_commit) in selectors.iter().zip(all_rr_commit.iter()) {
        encode_single_commit(
            selector,
            rr_commit,
            enc_a,
            enc_b,
            &mut temp,
            &mut msg,
            commit_poly_length,
            ring_poly_length,
            base_q,
            commit_modulus_val,
            table,
            cipher_moduli,
        );
    }

    let encode_mid = Instant::now();

    aggregate_encode_commits(
        &all_encode_commits,
        &mut final_encode_commits,
        rns_glwe_len,
        ring_poly_length,
        rns_poly_len,
        cipher_moduli,
    );

    let phase1_end = Instant::now();

    // ===== Phase 4/5: Distributed Decryption =====
    // "Mask-then-open" from Ajax (2025/1834, Fig.10), instantiating
    // Relect §4.3.2 Elect (Alg.2 lines 33-35: PartialDec) +
    // §4.4 Combine (Alg.2 lines 36-38: ThFHE.Combine).
    // Each party: phase → INTT → RNS compose → scale-round → mask with randoms.
    // Party 0 opens e+r, centers, subtracts e from value → recovers Δ·m.
    debug!(
        "[Phase 4/5] Distributed decryption — {} parties computing shares",
        party_count
    );
    debug!(
        "  Parties 1..{} start (not timed — parallel in real execution)",
        party_count - 1
    );
    for (
        msk_share,
        crt_dec_share,
        big_uint_dec_share,
        e_share,
        (r_mod_delta_prime_share, r_mod_q_prime_share),
    ) in izip!(
        msk_shares.iter(),
        crt_dec_shares.chunks_exact_mut(rns_poly_len * 2),
        big_uint_dec_shares.chunks_exact_mut(big_uint_poly_len * 2),
        all_e_shares.chunks_exact_mut(big_uint_poly_len * 2),
        dd_randoms.iter()
    )
    .skip(1)
    {
        decrypt_share_for_party(
            msk_share,
            crt_dec_share,
            big_uint_dec_share,
            e_share,
            r_mod_delta_prime_share,
            r_mod_q_prime_share,
            &final_encode_commits,
            ring_poly_length,
            rns_glwe_len,
            big_uint_value_len,
            table,
            base_q,
            external_product_context.compose_buffer_mut(),
            false,
            fast_q,
            fast_qp,
            fast_dp,
            &q_big,
            &q_prime_big,
            &delta_prime_big,
            &delta_prime,
            &q_prime,
        );
    }

    debug!("  Parties 1..{} shares complete", party_count - 1);

    // Party 0 (timed as `distributed_decrypt`).
    debug!("  Party 0 computing its share (timed as distributed_decrypt)");
    let ddec_start = Instant::now();
    for (
        msk_share,
        crt_dec_share,
        big_uint_dec_share,
        e_share,
        (r_mod_delta_prime_share, r_mod_q_prime_share),
    ) in izip!(
        msk_shares.iter(),
        crt_dec_shares.chunks_exact_mut(rns_poly_len * 2),
        big_uint_dec_shares.chunks_exact_mut(big_uint_poly_len * 2),
        all_e_shares.chunks_exact_mut(big_uint_poly_len * 2),
        dd_randoms.iter()
    )
    .take(1)
    {
        decrypt_share_for_party(
            msk_share,
            crt_dec_share,
            big_uint_dec_share,
            e_share,
            r_mod_delta_prime_share,
            r_mod_q_prime_share,
            &final_encode_commits,
            ring_poly_length,
            rns_glwe_len,
            big_uint_value_len,
            table,
            base_q,
            external_product_context.compose_buffer_mut(),
            true,
            fast_q,
            fast_qp,
            fast_dp,
            &q_big,
            &q_prime_big,
            &delta_prime_big,
            &delta_prime,
            &q_prime,
        );
    }

    debug!("  Party 0 aggregation complete");

    // --- Party 0 aggregate e-shares ---
    let (p0_e_share, other_e_shares) = all_e_shares.split_at_mut(big_uint_poly_len * 2);

    if let Some(dp128) = fast_dp {
        let dp = dp128.value_unchecked();
        for e_share in other_e_shares.chunks_exact(big_uint_poly_len * 2) {
            aggregate_e_shares_u128(p0_e_share, e_share, dp);
        }
    } else {
        cold_path();
        aggregate_e_shares_biguint(p0_e_share, other_e_shares, &delta_prime, big_uint_value_len);
    }

    // --- Party 0 centering ---
    if let Some(dp128) = fast_dp {
        let dp = dp128.value_unchecked();
        center_e_shares_u128(p0_e_share, dp);
    } else {
        cold_path();
        center_e_shares_biguint(
            p0_e_share,
            &delta_prime_half,
            &delta_prime,
            big_uint_value_len,
        );
    }

    // --- Party 0 subtract e from value, aggregate value shares ---
    let (p0_big_uint_dec_share, other_big_uint_dec_share) =
        big_uint_dec_shares.split_at_mut(big_uint_poly_len * 2);

    if let Some(qp128) = fast_qp {
        sub_e_add_random_u128(p0_big_uint_dec_share, p0_e_share, &dd_randoms[0].1, qp128);

        for share in other_big_uint_dec_share.chunks_exact(big_uint_poly_len * 2) {
            aggregate_value_shares_u128(p0_big_uint_dec_share, share, qp128);
        }
    } else {
        cold_path();
        sub_e_add_random_biguint(
            p0_big_uint_dec_share,
            p0_e_share,
            &dd_randoms[0].1,
            &q_prime,
            big_uint_value_len,
        );
        aggregate_value_shares_biguint(
            p0_big_uint_dec_share,
            other_big_uint_dec_share,
            &q_prime,
            big_uint_value_len,
        );
    }

    // --- Convert to final commit values ---
    if let Some(dp128) = fast_dp {
        let dp = dp128.value_unchecked();
        for (a, b_chunk) in final_commit
            .iter_mut()
            .zip(p0_big_uint_dec_share.chunks_exact(2))
        {
            *a = final_value_to_commit_u128(b_chunk, dp);
        }
    } else {
        cold_path();
        for (a, b) in final_commit
            .iter_mut()
            .zip(p0_big_uint_dec_share.chunks_exact(big_uint_value_len))
        {
            *a = final_value_to_commit_biguint(b, &delta_prime_big);
        }
    }

    let ddec_end = Instant::now();

    // ===== Phase 5/5: Verification (§4.5, Alg.2 lines 39-43) =====
    // com ← (v·a_r, v·b_r) · u^{-1} mod (X^n+1), then Dec(H(sk), com) == 0?
    debug!("[Phase 5/5] Verification — recovering leader's commit & decrypting");
    let phase2_start = Instant::now();

    final_commit
        .chunks_exact_mut(ring_poly_length)
        .for_each(|poly| {
            div_v_inplace(poly, &mut poly_for_div_v, party_count, inv_two_factor);
        });

    decode_commit(
        &final_commit,
        &mut decoded_commit,
        commit_poly_length,
        ring_poly_length,
    );

    let cipher = Rlwe(decoded_commit);
    let cipher = cipher.into_ntt_form(&commit_ntt_table);
    let msgs = all_commit_sk[choose].decrypt(&cipher, commit_params, &commit_ntt_table);
    let is_leader = msgs.iter().all(|&v| v == 0);

    let phase2_end = Instant::now();

    if is_leader {
        info!("✓ Result: party {choose} elected as leader");
    } else {
        debug!("Verification failed — leader identity mismatch");
    }

    // --- Compute timings ---
    let rlwe_mul_rgsw = expand_partial_coefficients_start - phase1_start;
    let expand_coefficients = expand_partial_coefficients_end - expand_partial_coefficients_start;
    let compute_local_encode_commit = encode_mid - expand_partial_coefficients_end;
    let compute_final_encode_commit = phase1_end - encode_mid;
    let distributed_decrypt = ddec_end - ddec_start;

    let timings = PhaseTimings {
        rlwe_mul_rgsw,
        expand_coefficients,
        compute_local_encode_commit,
        compute_final_encode_commit,
        distributed_decrypt,
        decrypt_commit: phase2_end - phase2_start,
        all_compute: (phase1_end - phase1_start)
            + distributed_decrypt
            + (phase2_end - phase2_start),
    };

    (choose, timings)
}
