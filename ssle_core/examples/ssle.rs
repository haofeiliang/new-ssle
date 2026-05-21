// cargo run --release --package ssle_core --example ssle -- -p 4
// cargo run --release --package ssle_core --example ssle --features="parallel" -- -p 4 -t 2
// cargo run --release --package ssle_core --example ssle --features="gt16" -- -p 64
// cargo run --release --package ssle_core --example ssle --features="gt16 parallel" -- -p 64 -t 8
// cargo run --release --package ssle_core --example ssle --features="gt128" -- -p 256
// cargo run --release --package ssle_core --example ssle --features="gt128 parallel" -- -p 256 -t 16

use std::sync::Arc;

use clap::Parser;
use itertools::izip;
use mimalloc::MiMalloc;
use network::{Id, netio::Participant};
use num::Integer;
#[cfg(not(feature = "parallel"))]
use primus_fhe_core::DcrtGlweExpandCoeffContext;
#[cfg(feature = "parallel")]
use primus_fhe_core::DcrtGlweExpandCoeffSyncPool;
use primus_fhe_core::NttRlwePublicKey;
use primus_integer::{AsInto, BigUint, DataMut, DivRem};
use primus_lattice::{
    context::DcrtGlevContext,
    ggsw::DcrtGgsw,
    glwe::{CrtGlwe, DcrtGlwe},
    rlwe::{NttRlwe, Rlwe, RlweOwned},
};
use primus_modulus::BarrettModulus;
use primus_ntt::{DcrtTable, NttTable};
use primus_poly::{ArrayBase, DcrtPolynomial, Polynomial, PolynomialOwned};
use primus_reduce::Modulus;
use rand::RngExt;
use ssle_core::{
    CoefficientExpansionKey, CommitModulus, CommitTable, CommitValueT, CrtValueT, KeyGen,
    MasterPublicKey, MasterSecretKeyShare, Party, SsleParameters, biguint_to_u128,
    generate_dd_random, scale_round_and_mod,
};
use tracing::{Level, debug, error, info};
use tracing_subscriber::fmt::format::FmtSpan;

#[cfg(feature = "gt16")]
const GT16: bool = true;

#[cfg(not(feature = "gt16"))]
const GT16: bool = false;

#[cfg(feature = "gt128")]
const GT128: bool = true;

#[cfg(not(feature = "gt128"))]
const GT128: bool = false;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

const BASE_PORT: u16 = 30000;

#[derive(Parser)]
struct Args {
    /// thread count per party
    #[arg(short = 't', long)]
    thread_count: Option<usize>,
    /// party count
    #[arg(short = 'p', long)]
    party_count: Option<usize>,
}

fn check_args(args: Args) -> (usize, usize, SsleParameters) {
    let thread_count = args.thread_count.unwrap_or(1);
    let party_count = args.party_count;

    let max_cpu_cores = num_cpus::get();

    #[cfg(not(feature = "parallel"))]
    if thread_count != 1 {
        panic!("Enable feature `parallel` for thread count {thread_count} > 1");
    }

    let party_count = match party_count {
        Some(p) => {
            if !p.is_power_of_two() {
                error!("Party count {p} is not power of two!");
                panic!("Party count {p} is not power of two!")
            }
            if p * thread_count > max_cpu_cores {
                error!("Your CPU has not enough cores!");
                panic!("Your CPU has not enough cores!")
            }
            p
        }
        None => 2,
    };

    let params = if party_count <= 16 {
        if !GT16 && !GT128 {
            SsleParameters::new(party_count)
        } else {
            error!("Don't enable feature `gt16` and `gt128` for party count: {party_count}<=16!");
            panic!("Don't enable feature `gt16` and `gt128` for party count: {party_count}<=16!")
        }
    } else if party_count <= 128 {
        if GT16 && !GT128 {
            SsleParameters::new(party_count)
        } else {
            if !GT16 {
                error!("Enable feature `gt16` for party count: {party_count}!");
                panic!("Enable feature `gt16` for party count: {party_count}!")
            } else {
                error!("Don't enable feature `gt128` for party count: {party_count}<=128!");
                panic!("Don't enable feature `gt128` for party count: {party_count}<=128!")
            }
        }
    } else if party_count > 128 && party_count <= 2048 {
        if GT128 {
            SsleParameters::new(party_count)
        } else {
            if GT16 {
                error!("Don't enable feature `gt16` for party count: {party_count}>128!");
                panic!("Don't enable feature `gt16` for party count: {party_count}>128!")
            } else {
                error!("Enable feature `gt128` for party count: {party_count}!");
                panic!("Enable feature `gt128` for party count: {party_count}!")
            }
        }
    } else {
        error!("no preparation for party count lager than 2048!");
        panic!("no preparation for party count lager than 2048!")
    };

    info!("Party count: {party_count}");
    info!("Thread count per party: {thread_count}");

    (party_count, thread_count, params)
}

fn main() {
    tracing_subscriber::fmt()
        .compact()
        .with_span_events(FmtSpan::CLOSE)
        .with_thread_ids(true)
        .with_max_level(Level::DEBUG)
        .init();
    let args = Args::parse();

    let (party_count, thread_count, params) = check_args(args);
    let params = Arc::new(params);

    let rng = &mut rand::rng();

    let participants = Participant::from_default(party_count, BASE_PORT);

    let (msk, mpk, eck) = KeyGen::generate_keys(&params, rng);

    let msk_shares = msk.generate_shares(party_count, rng);

    let dd_randoms = generate_dd_random(
        party_count,
        params.ring_params().poly_length() * 2,
        &params,
        rng,
    );

    info!("Key Generation done!");

    let threads = (0..party_count as Id)
        .zip(dd_randoms)
        .zip(msk_shares)
        .map(|((party_id, dd_random), msk_share)| {
            let participants_c = participants.clone();
            let mpk_c = mpk.clone();
            let eck_c = eck.clone();

            std::thread::spawn(move || {
                let threads_pool = rayon::ThreadPoolBuilder::new()
                    .num_threads(thread_count)
                    .build()
                    .unwrap();

                threads_pool.install(|| {
                    party_operation(
                        party_id,
                        participants_c,
                        msk_share,
                        mpk_c,
                        eck_c,
                        thread_count,
                        dd_random,
                    )
                })
            })
        })
        .collect::<Vec<_>>();

    check_result(party_count, threads);
}

fn party_operation(
    party_id: Id,
    participants: Vec<Participant>,
    msk_share: MasterSecretKeyShare,
    mpk: MasterPublicKey,
    eck: CoefficientExpansionKey,
    thread_count: usize,
    (r_mod_delta_prime_share, r_mod_q_prime_share): (Vec<CrtValueT>, Vec<CrtValueT>),
) -> usize {
    let rng = &mut rand::rng();

    let party_count = participants.len();
    let party = Party::new(party_id, participants, mpk, thread_count);

    let ssle_params = party.params();
    let commit_params = ssle_params.commit_params();
    let ring_params = ssle_params.ring_params();
    let ggsw_params = ssle_params.ggsw_params();
    let expand_coeff_params = ssle_params.expand_coeff_params();

    let commit_poly_length = commit_params.poly_length();
    let commit_rlwe_len = commit_poly_length * 2;

    let table = party.table();

    let moduli_count = ring_params.cipher_moduli_count();
    let ring_poly_length = ring_params.poly_length();
    let rns_poly_len = ring_params.rns_poly_len();
    let rns_glwe_len = ring_params.rns_glwe_len();
    let big_uint_poly_len = ring_params.big_uint_poly_len();
    let rns_ggsw_len = ggsw_params.rns_ggsw_len();

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
        rayon::current_num_threads(),
        expand_coeff_params.dimension(),
        ring_poly_length,
        rns_poly_len,
        big_uint_poly_len,
        moduli_count,
    );

    // let mut decrypt_context =
    //     DcrtGlweDecryptContext::new(ring_params.cipher_moduli_count(), ring_poly_length);

    let commit_ntt_table =
        CommitTable::new(commit_poly_length.trailing_zeros(), CommitModulus).unwrap();

    let inv_two_factor = party.inv_two_factor();

    let mut poly_for_div_v: PolynomialOwned<CommitValueT> = Polynomial::zero(ring_poly_length);

    let mut div_v = |poly: &mut [CommitValueT]| {
        poly_for_div_v.copy_from(poly.as_ref());
        poly_for_div_v.mul_monomial_assign(party_count, CommitModulus);

        let mut p = Polynomial(poly);

        p.sub_assign(&poly_for_div_v, CommitModulus);
        // p.mul_scalar_assign(inv_two, CommitModulus);
        p.mul_factor_assign(inv_two_factor, CommitModulus.value_unchecked());
    };

    // Generate commit pk and sk.
    let (commit_sk, commit_pk) = party.generate_commit_key_pair(&commit_ntt_table, rng);

    // Generate commit
    let commit = commit_sk.encrypt_zeros(commit_params, &commit_ntt_table, rng);

    // Check commit
    let decrypt_commit = commit_sk.decrypt(&commit, &commit_params, &commit_ntt_table);
    assert!(decrypt_commit.iter().copied().all(|v| v == 0));

    let mut commit = commit.into_coeff_form(&commit_ntt_table);

    commit.mul_factor_assign(
        party.inv_party_count_factor(),
        CommitModulus.value_unchecked(),
    );

    // Share commit and commit pk
    let mut all_commit: Vec<RlweOwned<CommitValueT>> =
        vec![Rlwe::zero(commit_rlwe_len); party_count];
    let mut all_commit_pk: Vec<NttRlwePublicKey<Vec<CommitValueT>>> =
        vec![NttRlwePublicKey::zero(commit_rlwe_len); party_count];
    let mut all_rr_commit: Vec<RlweOwned<CommitValueT>> =
        vec![Rlwe::zero(commit_rlwe_len); party_count];

    if party_id == 0 {
        debug!("Party {party_id}: Start share commit.");
    }

    party.share_v3(&commit, all_commit.as_mut_slice());

    if party_id == 0 {
        debug!("Party {party_id}: Start share pk.");
    }

    party.share_v3(&commit_pk, all_commit_pk.as_mut_slice());

    if party_id == 0 {
        debug!("Party {party_id}: Commit and commit pk shared.");
    }

    let mut rotate_ggsw: DcrtGgsw<Vec<CrtValueT>> = DcrtGgsw::zero(rns_ggsw_len);
    let mut all_rotate_ggsw: Vec<DcrtGgsw<Vec<CrtValueT>>> =
        vec![DcrtGgsw::zero(rns_ggsw_len); party_count];

    let degree = rng.random_range(0..ring_poly_length * 2);

    // Generate ACC
    let mut acc: CrtGlwe<Vec<CrtValueT>> = party.generate_init_acc();

    if party_id == 0 {
        debug!("Party {party_id}: Start generate RGSW.");
    }

    party.generate_rotate_rgsw_inplace(degree, &mut rotate_ggsw, rng);

    party.share_v3(&rotate_ggsw, all_rotate_ggsw.as_mut_slice());

    let mut temp_dcrt_glwe: DcrtGlwe<Vec<CrtValueT>> = DcrtGlwe::zero(rns_glwe_len);

    if party_id == 0 {
        debug!("Party {party_id}: Start aggregate all randomness.");
    }

    let (last, pre) = all_rotate_ggsw.split_last().unwrap();

    for rotate_rgsw in pre.iter() {
        acc.mul_dcrt_ggsw_inplace(
            rotate_rgsw,
            &mut temp_dcrt_glwe,
            ggsw_params.basis(),
            table,
            ring_params.base_q(),
            &mut external_product_context,
        );

        temp_dcrt_glwe.to_coeff_form_inplace(&mut acc, table);
    }

    acc.mul_dcrt_ggsw_inplace(
        last,
        &mut temp_dcrt_glwe,
        ggsw_params.basis(),
        table,
        ring_params.base_q(),
        &mut external_product_context,
    );

    let mut selectors = vec![<DcrtGlwe<Vec<CrtValueT>>>::zero(rns_glwe_len); party_count];

    if party_id == 0 {
        debug!("Party {party_id}: Start generate Selectors.");
    }

    #[cfg(not(feature = "parallel"))]
    eck.expand_partial_coefficients_inplace(
        &temp_dcrt_glwe,
        &mut selectors,
        &expand_coeff_params,
        ring_params.base_q(),
        &mut expand_coeff_context,
    );

    #[cfg(feature = "parallel")]
    eck.expand_partial_coefficients_inplace_parallel(
        &temp_dcrt_glwe,
        &mut selectors,
        &expand_coeff_params,
        ring_params.base_q(),
        &mut expand_coeff_context_pool,
    );

    if party_id == 0 {
        debug!("Party {party_id}: Start re-randomize commit.");
    }

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

    let mut temp: Vec<CrtValueT> = vec![0; ring_poly_length];
    let mut msg: DcrtPolynomial<Vec<CrtValueT>> = DcrtPolynomial::zero(rns_poly_len);

    let mut encode_commits: Vec<CrtValueT> = vec![0; rns_glwe_len * 2];
    let mut final_encode_commits: Vec<CrtValueT> = vec![0; rns_glwe_len * 2];
    let mut all_encode_commits: Vec<CrtValueT> = vec![0; rns_glwe_len * 2 * party_count];

    if party_id == 0 {
        debug!("Party {party_id}: Start encode randomized commits.");
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
                        .for_each(|(x, &y)| *x = y as CrtValueT);
                    ring_params
                        .base_q()
                        .wrapping_decompose_small_values_inplace(
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

    // Share commits
    party.share_v2(encode_commits.as_ref(), all_encode_commits.as_mut());

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

    if party_id == 0 {
        debug!("Party {party_id}: Start distributed decryption.");
    }

    let mut dec_share: Vec<CrtValueT> = vec![0; rns_poly_len * 2];

    for (x, y) in final_encode_commits
        .chunks_exact(rns_glwe_len)
        .zip(dec_share.chunks_exact_mut(rns_poly_len))
    {
        if party_id == 0 {
            msk_share.phase_inplace(&DcrtGlwe(x), &mut DcrtPolynomial(&mut *y));
        } else {
            msk_share.phase_a_inplace(&DcrtGlwe(x), &mut DcrtPolynomial(&mut *y));
        }

        table.inverse_transform_slice(y);
    }

    let mut big_uint_dec_share: Vec<CrtValueT> = vec![0; big_uint_poly_len * 2];
    let mut all_big_uint_dec_share: Vec<CrtValueT> = vec![0; big_uint_poly_len * 2 * party_count];
    let rns_base = ring_params.base_q();
    let big_uint_value_len = ring_params.big_uint_value_len();

    for (x, y) in dec_share
        .chunks_exact(rns_poly_len)
        .zip(big_uint_dec_share.chunks_exact_mut(big_uint_poly_len))
    {
        rns_base.compose_multiple_values_inplace(
            x,
            y,
            ring_poly_length,
            external_product_context.compose_buffer_mut(),
        );
    }

    let p = num::BigUint::from(ring_params.plain_modulus_value());

    let q = rns_base.moduli_product();
    let q_big = num::BigUint::from_slice(bytemuck::cast_slice(q.digits()));

    let q_prime_big = q_big.next_multiple_of(&p);
    let q_prime: primus_integer::BigUint<Vec<CrtValueT>> =
        primus_integer::BigUint(q_prime_big.iter_u64_digits().collect());

    let delta_prime_big = &q_prime_big / p;
    let delta_prime: primus_integer::BigUint<Vec<CrtValueT>> =
        primus_integer::BigUint(delta_prime_big.iter_u64_digits().collect());

    let fast_q = biguint_to_u128(&q_big);
    let fast_qp = biguint_to_u128(&q_prime_big);
    let fast_dp = biguint_to_u128(&delta_prime_big).map(BarrettModulus::new);

    let mut e_shares: Vec<CrtValueT> = vec![0; big_uint_poly_len * 2];
    let mut all_e_shares: Vec<CrtValueT> = vec![0; big_uint_poly_len * 2 * party_count];

    if let (Some(q128), Some(qp128), Some(dp128)) = (fast_q, fast_qp, fast_dp) {
        for (value, e, r) in izip!(
            big_uint_dec_share.as_chunks_mut::<2>().0.iter_mut(),
            e_shares.as_chunks_mut::<2>().0.iter_mut(),
            r_mod_delta_prime_share.as_chunks::<2>().0.iter(),
        ) {
            scale_round_and_mod(value, e, q128, qp128, dp128);
            primus_integer::BigUint(e).add_modulo_assign(&primus_integer::BigUint(r), &delta_prime);
        }
    } else {
        for (value, e, r) in izip!(
            big_uint_dec_share.chunks_exact_mut(big_uint_value_len),
            e_shares.chunks_exact_mut(big_uint_value_len),
            r_mod_delta_prime_share.chunks_exact(big_uint_value_len),
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

            primus_integer::BigUint(e).add_modulo_assign(&primus_integer::BigUint(r), &delta_prime);
        }
    }

    if party_id == 0 {
        party.share_to_p0(&e_shares, Some(&mut all_e_shares));
    } else {
        party.share_to_p0(&e_shares, None);
    }

    if party_id == 0 {
        e_shares.fill(0);
        all_e_shares
            .chunks_exact(big_uint_poly_len * 2)
            .for_each(|x| {
                for (a, b) in e_shares
                    .chunks_exact_mut(big_uint_value_len)
                    .zip(x.chunks_exact(big_uint_value_len))
                {
                    BigUint(a).add_modulo_assign(&BigUint(b), &delta_prime);
                }
            });
        let mut delta_prime_half = delta_prime.clone();
        delta_prime_half.right_shift_assign(1);
        e_shares.chunks_exact_mut(big_uint_value_len).for_each(|v| {
            let mut value = BigUint(v);

            if value.cmp(&delta_prime_half).is_ge() {
                value.neg_modulo_assign(&delta_prime);
            }
        });
    }

    if party_id == 0 {
        for (a, b, c) in izip!(
            big_uint_dec_share.chunks_exact_mut(big_uint_value_len),
            e_shares.chunks_exact(big_uint_value_len),
            r_mod_q_prime_share.chunks_exact(big_uint_value_len),
        ) {
            BigUint(&mut *a).sub_modulo_assign(&BigUint(b), &q_prime);
            BigUint(a).add_modulo_assign(&BigUint(c), &q_prime);
        }
    } else {
        for (a, b) in izip!(
            big_uint_dec_share.chunks_exact_mut(big_uint_value_len),
            r_mod_q_prime_share.chunks_exact(big_uint_value_len),
        ) {
            BigUint(a).add_modulo_assign(&BigUint(b), &q_prime);
        }
    }

    party.share_v2(&big_uint_dec_share, &mut all_big_uint_dec_share);

    big_uint_dec_share.fill(0);
    all_big_uint_dec_share
        .chunks_exact(big_uint_poly_len * 2)
        .for_each(|x| {
            for (a, b) in big_uint_dec_share
                .chunks_exact_mut(big_uint_value_len)
                .zip(x.chunks_exact(big_uint_value_len))
            {
                BigUint(a).add_modulo_assign(&BigUint(b), &q_prime);
            }
        });

    let mut final_commit: Vec<CommitValueT> = vec![0; ring_poly_length * 2];

    if let Some(dp128) = fast_dp {
        let dp = dp128.value_unchecked();
        for (a, b) in final_commit
            .iter_mut()
            .zip(big_uint_dec_share.as_chunks::<2>().0.iter())
        {
            let b_val = b[0] as u128 | ((b[1] as u128) << 64);
            let (b_q, rem) = b_val.div_rem(dp);
            *a = if rem * 2 >= dp { b_q + 1 } else { b_q } as CommitValueT;
        }
    } else {
        for (a, b) in final_commit
            .iter_mut()
            .zip(big_uint_dec_share.chunks_exact(big_uint_value_len))
        {
            let b = num::BigUint::from_slice(bytemuck::cast_slice(b));
            let (mut b, rem) = b.div_rem(&delta_prime_big);
            if rem * 2u8 >= delta_prime_big {
                b += 1u8;
            }
            *a = b.iter_u32_digits().next().unwrap_or(0);
        }
    }

    if party_id == 0 {
        debug!("Party {party_id}: Start verifying.");
    }

    final_commit
        .chunks_exact_mut(ring_poly_length)
        .for_each(|poly| div_v(poly));

    let mut decoded_commit: Vec<CommitValueT> = vec![0; commit_poly_length * 2];

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

    let msgs = commit_sk.decrypt(&cipher, commit_params, &commit_ntt_table);

    let is_leader = msgs.iter().all(|&v| v == 0);

    if is_leader {
        info!("Party {party_id}: I'm leader!",);
    }

    degree
}

fn check_result(party_count: usize, threads: Vec<std::thread::JoinHandle<usize>>) {
    let degrees: Vec<usize> = threads.into_iter().map(|h| h.join().unwrap()).collect();

    let sum = degrees.into_iter().sum::<usize>();

    let leader = sum % party_count;

    info!("leader: {leader}\n");
}
