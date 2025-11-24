// cargo run --release --package ssle_core --example ssle_ge_256_compute_time_improve --features="gt128" -- -p 256
// cargo +nightly run --release --package ssle_core --example ssle_ge_256_compute_time_improve --features="nightly gt128" -- -p 256

use std::{sync::Arc, time::Duration};

use clap::Parser;
use itertools::izip;
use primus_factor::ShoupFactor;
use primus_fhe_core::{CrtGlweTraceContext, DcrtGlweDecryptContext};
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
    MasterPublicKey, MasterSecretKey, SsleParameters,
};
use tabled::{Table, Tabled, settings::Rotate};

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
    decrypt_commit: Duration,
    #[tabled(format = "{:?}")]
    all_compute: Duration,
    #[tabled(format = "{:?}")]
    all: Duration,
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
                panic!("Party count {p} is no power of two!")
            }
            p
        }
        None => 2,
    };

    let params = if party_count <= 128 || party_count > 2048 {
        panic!("This example is for party count >= 256!")
    } else {
        if GT128 {
            SsleParameters::new(party_count)
        } else {
            if GT32 {
                panic!("Don't enable feature `gt32` for party count: {party_count}>128!")
            } else {
                panic!("Enable feature `gt128` for party count: {party_count}!")
            }
        }
    };

    println!("Party count: {party_count}");

    (party_count, params)
}

fn main() {
    let args = Args::parse();

    let (party_count, params) = check_args(args);

    let params = Arc::new(params);

    let rng = &mut rand::rng();

    let (msk, mpk, eck) = KeyGen::generate_keys(&params, rng);

    println!("Key Generation done!");

    let time_info = party_operation(party_count, msk, mpk, eck);

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
    let uniform_ring_poly_length = Uniform::new(0, ring_poly_length).unwrap();

    let all_degree: Vec<usize> = rng
        .sample_iter(uniform_ring_poly_length)
        .take(128)
        .collect();

    let choose = all_degree.iter().sum::<usize>() % party_count;

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
        vec![DcrtGgsw::zero(rns_ggsw_len); 128];

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
    let mut decoded_commit: Vec<CommitValueT> = vec![0; commit_poly_length * 2];

    all_encode_commits
        .chunks_exact_mut(rns_glwe_len)
        .skip(2)
        .for_each(|ecs| {
            msk.encrypt_zeros_inplace(&mut DcrtGlwe(ecs), ring_params, table, rng);
        });

    let encode_commits = &mut all_encode_commits[0..rns_glwe_len * 2];

    let phase1_start = quanta::Instant::now();

    // Check random degree for rgsw
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

    let mut final_commit = sim_thfhe_decrypt(party_count, &msk, ssle_params, final_encode_commits);

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
        println!("\nParty {choose}: I'm leader!",);
    }

    let rlwe_mul_rgsw = expand_partial_coefficients_start - phase1_start;
    let expand_coefficients = expand_partial_coefficients_end - expand_partial_coefficients_start;
    let compute_local_encode_commit = encode_mid - expand_partial_coefficients_end;
    let compute_final_encode_commit = phase1_end - encode_mid;

    let info = TimeInfo {
        rlwe_mul_rgsw,
        compute_local_encode_commit,
        compute_final_encode_commit,
        expand_coefficients,
        decrypt_commit: phase2_end - phase2_start,
        all_compute: (phase1_end - phase1_start) + (phase2_end - phase2_start),
        all: phase2_end - phase1_start,
    };

    info
}

fn sim_thfhe_decrypt(
    _party_count: usize,
    msk: &MasterSecretKey,
    params: &SsleParameters,
    encoded_commits: Vec<CrtValueT>,
) -> Vec<CommitValueT> {
    let ring_params = params.ring_params();
    let ring_poly_length = ring_params.poly_length();

    let mid = encoded_commits.len() / 2;

    let mut commit_data: Vec<CrtValueT> = vec![0; ring_poly_length * 2];
    let mut context =
        DcrtGlweDecryptContext::new(ring_params.cipher_moduli_count(), ring_poly_length);

    for (poly, encoded_commit) in commit_data
        .chunks_mut(ring_poly_length)
        .zip(encoded_commits.chunks_exact(mid))
    {
        msk.decrypt_inplace(
            &DcrtGlwe(encoded_commit),
            &mut Polynomial(poly),
            params.ring_params(),
            msk.table(),
            &mut context,
        );
    }

    let final_commit: Vec<CommitValueT> = commit_data
        .into_iter()
        .map(|v| v.try_into().unwrap())
        .collect();

    final_commit
}
