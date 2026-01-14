// cargo run --release --package ssle_core --example ssle_compute_time -- -p 4
// cargo run --release --package ssle_core --example ssle_compute_time --features="gt32" -- -p 64
// cargo run --release --package ssle_core --example ssle_compute_time --features="gt128" -- -p 256
// cargo +nightly run --release --package ssle_core --example ssle_compute_time --features="nightly" -- -p 4
// cargo +nightly run --release --package ssle_core --example ssle_compute_time --features="nightly gt32" -- -p 64
// cargo +nightly run --release --package ssle_core --example ssle_compute_time --features="nightly gt128" -- -p 256

use std::{sync::Arc, time::Duration};

use clap::Parser;
use itertools::izip;
use num::Integer;
use primus_factor::ShoupFactor;
use primus_fhe_core::CrtGlweTraceContext;
use primus_integer::AsInto;
use primus_lattice::{
    context::DcrtGlevContext,
    ggsw::DcrtGgsw,
    glwe::{CrtGlwe, DcrtGlwe},
    rlwe::{NttRlwe, Rlwe, RlweOwned},
};
use primus_ntt::{DcrtTable, NttTable};
use primus_poly::{ArrayBase, DcrtPolynomial, Polynomial, PolynomialOwned};
use primus_reduce::Modulus;
use primus_reduce::ops::ReduceInv;
use rand::{Rng, distr::Uniform};
use ssle_core::{
    CoefficientExpansionKey, CommitModulus, CommitTable, CommitValueT, CrtValueT, KeyGen,
    MasterPublicKey, MasterSecretKey, MasterSecretKeyShare, SsleParameters, generate_dd_random,
};
use tabled::{Table, Tabled, settings::Rotate};
use tracing::{Level, debug, error, info};
use tracing_subscriber::fmt::format::FmtSpan;

#[cfg(feature = "gt32")]
const GT32: bool = true;

#[cfg(not(feature = "gt32"))]
const GT32: bool = false;

#[cfg(feature = "gt128")]
const GT128: bool = true;

#[cfg(not(feature = "gt128"))]
const GT128: bool = false;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Clone, Copy, Tabled)]
struct TimeInfo {
    #[tabled(format = "{:?}")]
    rlwe_mul_rgsw: Duration,
    #[tabled(format = "{:?}")]
    expand_coefficients: Duration,
    #[tabled(format = "{:?}")]
    compute_local_encode_commit: Duration,
    #[tabled(format = "{:?}")]
    compute_final_encode_commit: Duration,
    #[tabled(format = "{:?}")]
    distributed_decrypt: Duration,
    #[tabled(format = "{:?}")]
    decrypt_commit: Duration,
    #[tabled(format = "{:?}")]
    all_compute: Duration,
}

#[derive(Parser)]
struct Args {
    /// party count
    #[arg(short = 'p', long)]
    party_count: Option<usize>,
}

fn check_args(args: Args) -> (usize, SsleParameters) {
    let party_count = args.party_count;

    let party_count = match party_count {
        Some(p) => {
            if !p.is_power_of_two() {
                error!("Party count {p} is not power of two!");
                panic!("Party count {p} is not power of two!")
            }
            p
        }
        None => 2,
    };

    let params = if party_count <= 32 {
        if !GT32 && !GT128 {
            SsleParameters::new(party_count)
        } else {
            error!("Don't enable feature `gt32` and `gt128` for party count: {party_count}<=32!");
            panic!("Don't enable feature `gt32` and `gt128` for party count: {party_count}<=32!");
        }
    } else if party_count <= 128 {
        if GT32 && !GT128 {
            SsleParameters::new(party_count)
        } else {
            if !GT32 {
                error!("Enable feature `gt32` for party count: {party_count}!");
                panic!("Enable feature `gt32` for party count: {party_count}!");
            } else {
                error!("Don't enable feature `gt128` for party count: {party_count}<=128!");
                panic!("Don't enable feature `gt128` for party count: {party_count}<=128!");
            }
        }
    } else if party_count > 128 && party_count <= 2048 {
        if GT128 {
            SsleParameters::new(party_count)
        } else {
            if GT32 {
                error!("Don't enable feature `gt32` for party count: {party_count}>128!");
                panic!("Don't enable feature `gt32` for party count: {party_count}>128!");
            } else {
                error!("Enable feature `gt128` for party count: {party_count}!");
                panic!("Enable feature `gt128` for party count: {party_count}!");
            }
        }
    } else {
        error!("no preparation for party count lager than 2048!");
        panic!("no preparation for party count lager than 2048!");
    };

    info!("Party count: {party_count}");

    (party_count, params)
}

fn main() {
    tracing_subscriber::fmt()
        .compact()
        .with_span_events(FmtSpan::CLOSE)
        .with_max_level(Level::DEBUG)
        .init();

    let args = Args::parse();

    let (party_count, params) = check_args(args);

    let params = Arc::new(params);

    let rng = &mut rand::rng();

    let (msk, mpk, eck) = KeyGen::generate_keys(&params, rng);

    let msk_shares = msk.generate_shares(party_count, rng);

    let dd_randoms = generate_dd_random(
        party_count,
        params.ring_params().poly_length() * 2,
        &params,
        rng,
    );

    debug!("Key Generation done!");

    let time_info = party_operation(party_count, msk, mpk, eck, &msk_shares, &dd_randoms);

    let mut table = Table::new([time_info]);
    table.with(Rotate::Left);
    table.with(Rotate::Top);
    println!("{table}");
}

fn party_operation(
    party_count: usize,
    msk: MasterSecretKey,
    mpk: MasterPublicKey,
    eck: CoefficientExpansionKey,
    msk_shares: &[MasterSecretKeyShare],
    dd_randoms: &[(Vec<CrtValueT>, Vec<CrtValueT>)],
) -> TimeInfo {
    let rng = &mut rand::rng();

    let ssle_params = mpk.params();
    let commit_params = ssle_params.commit_params();
    let ring_params = ssle_params.ring_params();
    let ggsw_params = ssle_params.ggsw_params();
    let expand_coeff_params = ssle_params.expand_coeff_params();

    let commit_poly_length = commit_params.poly_length();

    let ring_poly_length = ring_params.poly_length();

    let table = mpk.table();

    let commit_rlwe_len = commit_poly_length * 2;
    let rns_poly_len = ring_params.rns_poly_len();
    let rns_glwe_len = ring_params.rns_glwe_len();
    let big_uint_poly_len = ring_params.big_uint_poly_len();
    let rns_ggsw_len = ggsw_params.rns_ggsw_len();
    let base_q = ring_params.base_q();
    let big_uint_value_len = ring_params.big_uint_value_len();

    let commit_ntt_table =
        CommitTable::new(commit_poly_length.trailing_zeros(), CommitModulus).unwrap();

    let mut external_product_context =
        DcrtGlevContext::new(ring_poly_length, rns_poly_len, big_uint_poly_len);

    let mut expand_coeff_context = CrtGlweTraceContext::new(
        expand_coeff_params.dimension(),
        ring_poly_length,
        rns_poly_len,
        big_uint_poly_len,
    );

    let inv_two = CommitModulus.reduce_inv(2);
    let inv_two_factor = ShoupFactor::new(inv_two, CommitModulus.value_unchecked());

    let mut poly_for_div_v: PolynomialOwned<CommitValueT> = Polynomial::zero(ring_poly_length);

    let mut div_v = |poly: &mut [CommitValueT]| {
        poly_for_div_v.copy_from(poly.as_ref());
        poly_for_div_v.mul_monomial_assign(party_count, CommitModulus);

        let mut p = Polynomial(poly);

        p.sub_assign(&poly_for_div_v, CommitModulus);
        p.mul_factor_assign(inv_two_factor, CommitModulus.value_unchecked());
    };

    let mut acc: CrtGlwe<Vec<CrtValueT>> = mpk.generate_init_acc(party_count);
    let uniform_ring_poly_length = Uniform::new(0, ring_poly_length * 2).unwrap();

    let all_degree: Vec<usize> = rng
        .sample_iter(uniform_ring_poly_length)
        .take(party_count)
        .collect();

    let choose = all_degree.iter().sum::<usize>() % party_count;
    debug!("Party {choose} is chosen to be leader. This is secret now.");

    // Generate commit pk and sk.
    let (all_commit_sk, all_commit_pk): (Vec<_>, Vec<_>) = (0..party_count)
        .map(|_| mpk.generate_commit_key_pair(&commit_ntt_table, rng))
        .collect();

    // Generate commit
    let all_commit: Vec<RlweOwned<CommitValueT>> = all_commit_sk
        .iter()
        .map(|sk| {
            sk.encrypt_zeros(commit_params, &commit_ntt_table, rng)
                .into_coeff_form(&commit_ntt_table)
        })
        .collect();

    let mut all_rr_commit: Vec<RlweOwned<CommitValueT>> =
        vec![Rlwe::zero(commit_rlwe_len); party_count];

    let mut all_rotate_ggsw: Vec<DcrtGgsw<Vec<CrtValueT>>> =
        vec![DcrtGgsw::zero(rns_ggsw_len); party_count];

    all_rotate_ggsw
        .iter_mut()
        .zip(all_degree.iter())
        .skip(1)
        .for_each(|(rotate_ggsw, &degree)| {
            mpk.generate_rotate_rgsw_inplace(degree, rotate_ggsw, rng);
        });

    let mut ex_product_glwe: DcrtGlwe<Vec<CrtValueT>> = DcrtGlwe::zero(rns_glwe_len);

    let mut expand_result = vec![<CrtGlwe<Vec<CrtValueT>>>::zero(rns_glwe_len); party_count];
    let mut selectors = vec![<DcrtGlwe<Vec<CrtValueT>>>::zero(rns_glwe_len); party_count];

    let mut temp: Vec<CrtValueT> = vec![0; ring_poly_length];
    let mut msg: DcrtPolynomial<Vec<CrtValueT>> = DcrtPolynomial::zero(rns_poly_len);

    let mut all_encode_commits: Vec<CrtValueT> = vec![0; rns_glwe_len * 2 * party_count];
    let mut final_encode_commits: Vec<CrtValueT> = vec![0; rns_glwe_len * 2];
    let mut final_commit: Vec<CommitValueT> = vec![0; ring_poly_length * 2];
    let mut decoded_commit: Vec<CommitValueT> = vec![0; commit_poly_length * 2];

    let mut crt_dec_shares: Vec<CrtValueT> = vec![0; rns_poly_len * 2 * party_count];
    let mut big_uint_dec_shares: Vec<CrtValueT> = vec![0; big_uint_poly_len * 2 * party_count];
    let mut all_e_shares: Vec<CrtValueT> = vec![0; big_uint_poly_len * 2 * party_count];

    let p = num::BigUint::from(ring_params.plain_modulus_value());

    let q = base_q.moduli_product();
    let q_big = num::BigUint::from_slice(bytemuck::cast_slice(q.digits()));

    let q_prime_big = q_big.next_multiple_of(&p);
    let q_prime: primus_integer::BigUint<Vec<CrtValueT>> =
        primus_integer::BigUint(q_prime_big.iter_u64_digits().collect());

    let q_prime_bits = q_prime_big.bits();

    let delta_prime_big = &q_prime_big / p;
    let delta_prime: primus_integer::BigUint<Vec<CrtValueT>> =
        primus_integer::BigUint(delta_prime_big.iter_u64_digits().collect());

    let delta_prime_bits = delta_prime_big.bits();

    let mut delta_prime_half = delta_prime.clone();
    delta_prime_half.right_shift_assign(1);

    all_encode_commits
        .chunks_exact_mut(rns_glwe_len)
        .skip(2)
        .for_each(|ecs| {
            msk.encrypt_zeros_inplace(&mut DcrtGlwe(ecs), ring_params, table, rng);
        });

    let encode_commits = &mut all_encode_commits[0..rns_glwe_len * 2];

    debug!("Start Relect ...");

    let phase1_start = quanta::Instant::now();

    mpk.generate_rotate_rgsw_inplace(all_degree[0], &mut all_rotate_ggsw[0], rng);

    for rotate_rgsw in all_rotate_ggsw.iter() {
        acc.mul_dcrt_ggsw_inplace(
            rotate_rgsw,
            &mut ex_product_glwe,
            ggsw_params.basis(),
            table,
            base_q,
            &mut external_product_context,
        );

        ex_product_glwe.to_coeff_form_inplace(&mut acc, table);
    }

    let expand_partial_coefficients_start = quanta::Instant::now();

    eck.expand_partial_coefficients_inplace(
        &acc,
        &mut expand_result,
        &expand_coeff_params,
        base_q,
        &mut expand_coeff_context,
    );

    expand_result
        .iter()
        .zip(selectors.iter_mut())
        .for_each(|(x, y)| {
            x.to_ntt_form_inplace(y, table);
        });

    let expand_partial_coefficients_end = quanta::Instant::now();

    for (commit, commit_pk, rr_commit) in izip!(
        all_commit.iter(),
        all_commit_pk.iter(),
        all_rr_commit.iter_mut(),
    ) {
        let mut output = NttRlwe(rr_commit.as_mut());
        commit_pk.encrypt_zeros_inplace(&mut output, commit_params, &commit_ntt_table, rng);

        output
            .iter_ntt_poly_mut(commit_poly_length)
            .for_each(|poly| {
                commit_ntt_table.inverse_transform_slice(poly.0);
            });

        rr_commit.add_element_wise_assign(commit, CommitModulus);
    }

    selectors
        .iter()
        .zip(all_rr_commit.iter())
        .for_each(|(selector, rr_commit)| {
            encode_commits
                .chunks_exact_mut(rns_glwe_len)
                .zip(rr_commit.iter_poly(commit_poly_length))
                .for_each(|(encode_commit, poly)| {
                    temp.fill(0);
                    temp.iter_mut()
                        .zip(poly.iter())
                        .for_each(|(x, y)| *x = *y as CrtValueT);
                    base_q.wrapping_decompose_small_values_inplace(
                        &temp,
                        msg.as_mut(),
                        ring_poly_length,
                        CommitModulus.value_unchecked().as_into(),
                    );
                    table.transform_slice(msg.as_mut());
                    DcrtGlwe(encode_commit).add_dcrt_glwe_mul_dcrt_polynomial_assign(
                        selector,
                        &msg,
                        ring_poly_length,
                        ring_params.cipher_moduli(),
                    );
                });
        });

    let encode_mid = quanta::Instant::now();

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
                        ring_params.cipher_moduli(),
                    );
                });
        });

    let phase1_end = quanta::Instant::now();

    debug!("The encode commit is computed.");

    debug!("Start Distributed Decryption");
    debug!("Party 1 to Party {} start decrypt.", party_count - 1);

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
        for (encode_commit, crt_dec, big_uint_dec) in izip!(
            final_encode_commits.chunks_exact(rns_glwe_len),
            crt_dec_share.chunks_exact_mut(rns_poly_len),
            big_uint_dec_share.chunks_exact_mut(big_uint_poly_len),
        ) {
            msk_share.phase_a_inplace(&DcrtGlwe(encode_commit), &mut DcrtPolynomial(&mut *crt_dec));
            table.inverse_transform_slice(crt_dec);
            base_q.compose_multiple_values_inplace(crt_dec, big_uint_dec, ring_poly_length);
        }

        for (value, e, r_mod_delta_prime, r_mod_q_prime) in izip!(
            big_uint_dec_share.chunks_exact_mut(big_uint_value_len),
            e_share.chunks_exact_mut(big_uint_value_len),
            r_mod_delta_prime_share.chunks_exact(big_uint_value_len),
            r_mod_q_prime_share.chunks_exact(big_uint_value_len),
        ) {
            let mut temp = num::BigUint::from_slice(bytemuck::cast_slice(value));

            temp *= &q_prime_big;

            let (mut temp, rem) = temp.div_rem(&q_big);
            if rem * 2u8 >= q_big {
                temp += 1u8;
            }

            value.fill(0);

            value
                .iter_mut()
                .zip(temp.iter_u64_digits())
                .for_each(|(x, y)| *x = y);

            temp %= &delta_prime_big;

            e.iter_mut()
                .zip(temp.iter_u64_digits())
                .for_each(|(x, y)| *x = y);

            primus_integer::BigUint(e)
                .add_modulo_assign(&primus_integer::BigUint(r_mod_delta_prime), &delta_prime);

            primus_integer::BigUint(value)
                .add_modulo_assign(&primus_integer::BigUint(r_mod_q_prime), &q_prime);
        }
    }

    debug!("Party 1 to Party {} end decrypt.", party_count - 1);

    debug!("Party 0 start decrypt.");

    let ddec_start = quanta::Instant::now();

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
        for (encode_commit, crt_dec, big_uint_dec) in izip!(
            final_encode_commits.chunks_exact(rns_glwe_len),
            crt_dec_share.chunks_exact_mut(rns_poly_len),
            big_uint_dec_share.chunks_exact_mut(big_uint_poly_len),
        ) {
            msk_share.phase_inplace(&DcrtGlwe(encode_commit), &mut DcrtPolynomial(&mut *crt_dec));
            table.inverse_transform_slice(crt_dec);
            base_q.compose_multiple_values_inplace(crt_dec, big_uint_dec, ring_poly_length);
        }

        for (value, e, r_mod_delta_prime, r_mod_q_prime) in izip!(
            big_uint_dec_share.chunks_exact_mut(big_uint_value_len),
            e_share.chunks_exact_mut(big_uint_value_len),
            r_mod_delta_prime_share.chunks_exact(big_uint_value_len),
            r_mod_q_prime_share.chunks_exact(big_uint_value_len),
        ) {
            let mut temp = num::BigUint::from_slice(bytemuck::cast_slice(value));

            temp *= &q_prime_big;

            let (mut temp, rem) = temp.div_rem(&q_big);
            if rem * 2u8 >= q_big {
                temp += 1u8;
            }

            value.fill(0);

            value
                .iter_mut()
                .zip(temp.iter_u64_digits())
                .for_each(|(x, y)| *x = y);

            temp %= &delta_prime_big;

            e.iter_mut()
                .zip(temp.iter_u64_digits())
                .for_each(|(x, y)| *x = y);

            primus_integer::BigUint(e)
                .add_modulo_assign(&primus_integer::BigUint(r_mod_delta_prime), &delta_prime);

            primus_integer::BigUint(value)
                .add_modulo_assign(&primus_integer::BigUint(r_mod_q_prime), &q_prime);
        }
    }

    let (p0_e_share, other_e_shares) = all_e_shares.split_at_mut(big_uint_poly_len * 2);

    for e_share in other_e_shares.chunks_exact(big_uint_poly_len * 2) {
        for (value, e) in izip!(
            p0_e_share.chunks_exact_mut(big_uint_value_len),
            e_share.chunks_exact(big_uint_value_len),
        ) {
            primus_integer::BigUint(value)
                .add_modulo_assign(&primus_integer::BigUint(e), &delta_prime);
        }
    }

    for value in p0_e_share.chunks_exact_mut(big_uint_value_len) {
        let mut value = primus_integer::BigUint(value);

        if value.cmp(&delta_prime_half).is_ge() {
            value.neg_modulo_assign(&delta_prime);
        }
    }

    let (p0_big_uint_dec_share, other_big_uint_dec_share) =
        big_uint_dec_shares.split_at_mut(big_uint_poly_len * 2);

    for (value, e) in p0_big_uint_dec_share
        .chunks_exact_mut(big_uint_value_len)
        .zip(p0_e_share.chunks_exact(big_uint_value_len))
    {
        primus_integer::BigUint(value).sub_modulo_assign(&primus_integer::BigUint(e), &q_prime);
    }

    for big_uint_dec_share in other_big_uint_dec_share.chunks_exact(big_uint_poly_len * 2) {
        for (x, y) in p0_big_uint_dec_share
            .chunks_exact_mut(big_uint_value_len)
            .zip(big_uint_dec_share.chunks_exact(big_uint_value_len))
        {
            primus_integer::BigUint(x).add_modulo_assign(&primus_integer::BigUint(y), &q_prime);
        }
    }

    for (a, b) in final_commit
        .iter_mut()
        .zip(p0_big_uint_dec_share.chunks_exact(big_uint_value_len))
    {
        let b = num::BigUint::from_slice(bytemuck::cast_slice(b));
        let (mut b, rem) = b.div_rem(&delta_prime_big);
        if rem * 2u8 >= delta_prime_big {
            b += 1u8;
        }
        *a = b.iter_u32_digits().next().unwrap_or(0);
    }

    let ddec_end = quanta::Instant::now();

    debug!("Party 0 finish decrypt.");

    debug!("Decrypt done, start final verifying.");

    debug!("Party {choose}: start verifying.",);

    let phase2_start = quanta::Instant::now();

    final_commit
        .chunks_exact_mut(ring_poly_length)
        .for_each(|poly| div_v(poly));

    {
        let (a_in, b_in) = final_commit.split_at_mut(ring_poly_length);
        let (a_out, b_out) = decoded_commit.split_at_mut(commit_poly_length);

        let mut a_arr = ArrayBase(a_out);
        let mut b_arr = ArrayBase(b_out);

        let mut last = None;
        'o: for (i, (a_chunk, b_chunk)) in a_in
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
                    break 'o;
                } else {
                    a_arr.copy_from_slice(a_chunk);
                    b_arr.copy_from_slice(b_chunk);
                    last = Some(i);
                }
            }
        }
    }

    let cipher = Rlwe(decoded_commit);
    let cipher = cipher.into_ntt_form(&commit_ntt_table);

    let msgs = all_commit_sk[choose].decrypt(&cipher, commit_params, &commit_ntt_table);

    let is_leader = msgs.iter().all(|&v| v == 0);

    let phase2_end = quanta::Instant::now();

    if is_leader {
        info!("Party {choose}: I'm leader!",);
    }

    debug!("Verify done.");
    debug!("Relect done.");

    let rlwe_mul_rgsw = expand_partial_coefficients_start - phase1_start;
    let expand_coefficients = expand_partial_coefficients_end - expand_partial_coefficients_start;
    let compute_local_encode_commit = encode_mid - expand_partial_coefficients_end;
    let compute_final_encode_commit = phase1_end - encode_mid;
    let distributed_decrypt = ddec_end - ddec_start;

    let info = TimeInfo {
        rlwe_mul_rgsw,
        compute_local_encode_commit,
        compute_final_encode_commit,
        expand_coefficients,
        distributed_decrypt,
        decrypt_commit: phase2_end - phase2_start,
        all_compute: (phase1_end - phase1_start)
            + distributed_decrypt
            + (phase2_end - phase2_start),
    };

    // println!("commit bytes count: {}", all_commit[0].bytes_count());
    // println!("commit pk bytes count: {}", all_commit_pk[0].bytes_count());
    // println!("ggsw bytes count: {}", all_rotate_ggsw[0].bytes_count());

    let factor = if party_count <= 128 {
        50.0 / 64.0
    } else {
        37.0 / 64.0
    };

    let size1 = (all_rotate_ggsw[0].byte_count() * (party_count - 1)) as f64 * factor / 1024.0;
    let size2 =
        primus_integer::size::Size::byte_count(&all_encode_commits) as f64 * factor / 1024.0;

    let single_size1 = (all_rotate_ggsw[0].byte_count()) as f64 * factor / 1024.0;
    let single_size2 = size2 / party_count as f64;

    let size2 = single_size2 * (party_count - 1) as f64;

    debug!("First Round single size: {single_size1}KB");
    debug!("Second Round single size: {single_size2}KB");

    debug!("First Round size: {size1}KB");
    debug!("Second Round size: {size2}KB");

    let dec_size1 = p0_e_share.len() as f64
        * 8.0
        * (delta_prime_bits as f64 / (big_uint_value_len as f64 * 64.0))
        / 1024.0;
    let single_dec_size2 = p0_big_uint_dec_share.len() as f64
        * 8.0
        * (q_prime_bits as f64 / (big_uint_value_len as f64 * 64.0))
        / 1024.0;
    let dec_size2 = single_dec_size2 * (party_count - 1) as f64;

    debug!("Distributed Decryption First Round size: {dec_size1}KB");
    debug!("Distributed Decryption Second Round single size: {single_dec_size2}KB");
    debug!("Distributed Decryption Second Round size: {dec_size2}KB");

    let size = size1 + size2 + dec_size1 + dec_size2;

    debug!("communication size: {size}KB");
    debug!("communication size: {}MB", size / 1024.0);

    info
}
