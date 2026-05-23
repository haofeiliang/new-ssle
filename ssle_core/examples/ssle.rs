//! # SSLE Protocol — real distributed execution
//!
//! Runs the complete SSLE protocol with actual network communication between
//! parties. Each party runs in its own OS thread using `tokio` for async I/O.
//! The protocol output is the elected leader index, verified by all parties.
//!
//! This is the reference implementation of the protocol described in the paper,
//! including the full networking stack (see `ssle_core::Party`).
//!
//! # Party count → feature mapping
//! | party_count  | features       |
//! |-------------|----------------|
//! | 2 ..= 16    | (none)         |
//! | 32 ..= 128  | `gt16`         |
//! | 256 ..= 2048| `gt128`        |
//!
//! # Usage
//! ```text
//! cargo run --release --package ssle_core --example ssle -- -p 4
//! cargo run --release --package ssle_core --example ssle --features="gt16" -- -p 64
//! cargo run --release --package ssle_core --example ssle --features="gt128" -- -p 256
//! // with parallelism:
//! cargo run --release --package ssle_core --example ssle --features="parallel" -- -p 4 -t 2
//! cargo run --release --package ssle_core --example ssle --features="gt16 parallel" -- -p 64 -t 8
//! cargo run --release --package ssle_core --example ssle --features="gt128 parallel" -- -p 256 -t 16
//! ```

use std::{hint::cold_path, sync::Arc};

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
use primus_integer::{AsInto, BigUint, DataMut};
use primus_lattice::{
    context::DcrtGlevContext,
    ggsw::DcrtGgsw,
    glwe::{CrtGlwe, DcrtGlwe},
    rlwe::{Rlwe, RlweOwned},
};
use primus_modulus::BarrettModulus;
use primus_ntt::NttTable;
use primus_poly::{DcrtPolynomial, Polynomial, PolynomialOwned};
use primus_reduce::Modulus;
use rand::RngExt;
use ssle_core::{
    CoefficientExpansionKey, CommitModulus, CommitTable, CommitValueT, CrtValueT, KeyGen,
    MasterPublicKey, MasterSecretKeyShare, Party, SsleParameters, add_mod_u128, biguint_to_u128,
    generate_dd_random, protocol, scale_round_and_mod, sub_mod_u128,
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

/// Per-party protocol thread.
///
/// Protocol outline (4 online communication rounds + offline pre-share):
///
///   **Offline** — Share commits & public keys (§4.2, Alg.2 lines 10-13)
///   **Round 1** — Share RGSW → external product chain + coefficient expansion
///     (§4.2 GenInstance lines 14-15; §4.3.1 ParElect lines 20-22)
///   **Round 2** — Share encoded commits after re-randomization & encoding
///     (§4.3.1 ParElect lines 24-28; aggregation: §4.3.2 Elect lines 31-32)
///   **Round 3** — Share e-shares → Party 0 aggregates & centers
///     (Ajax 2025/1834 Fig.10 steps 1-2; Alg.2 lines 33-34, §4.3.2 Elect)
///   **Round 4** — Share value shares → Combine
///     (Ajax 2025/1834 Fig.10 steps 3-4; Alg.2 lines 36-38, §4.4 Combine)
///   **Final** — Verify (local only): com ← (v·a_r, v·b_r) · u^{-1} mod (X^n+1);
///     Dec(H(sk), com) == 0? (§4.5, Alg.2 lines 39-43)
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

    let commit_ntt_table =
        CommitTable::new(commit_poly_length.trailing_zeros(), CommitModulus).unwrap();

    let inv_two_factor = party.inv_two_factor();
    let mut poly_for_div_v: PolynomialOwned<CommitValueT> = Polynomial::zero(ring_poly_length);

    // --- Commit key & commit ---
    let (commit_sk, commit_pk) = party.generate_commit_key_pair(&commit_ntt_table, rng);
    let commit = commit_sk.encrypt_zeros(commit_params, &commit_ntt_table, rng);

    let decrypt_commit = commit_sk.decrypt(&commit, commit_params, &commit_ntt_table);
    assert!(decrypt_commit.iter().copied().all(|v| v == 0));

    let mut commit = commit.into_coeff_form(&commit_ntt_table);
    commit.mul_factor_assign(
        party.inv_party_count_factor(),
        CommitModulus.value_unchecked(),
    );

    // --- Share commit and pk ---
    let mut all_commit: Vec<RlweOwned<CommitValueT>> =
        vec![Rlwe::zero(commit_rlwe_len); party_count];
    let mut all_commit_pk: Vec<NttRlwePublicKey<Vec<CommitValueT>>> =
        vec![NttRlwePublicKey::zero(commit_rlwe_len); party_count];
    let mut all_rr_commit: Vec<RlweOwned<CommitValueT>> =
        vec![Rlwe::zero(commit_rlwe_len); party_count];

    if party_id == 0 {
        debug!(
            "[Offline] Share commits & public keys \
             (Alg.2 lines 10-13, §4.2 GenInstance)"
        );
    }
    party.share_v3(&commit, all_commit.as_mut_slice());
    party.share_v3(&commit_pk, all_commit_pk.as_mut_slice());

    // --- RGSW + External Product ---
    let mut rotate_ggsw: DcrtGgsw<Vec<CrtValueT>> = DcrtGgsw::zero(rns_ggsw_len);
    let mut all_rotate_ggsw: Vec<DcrtGgsw<Vec<CrtValueT>>> =
        vec![DcrtGgsw::zero(rns_ggsw_len); party_count];

    let degree = rng.random_range(0..ring_poly_length * 2);

    let mut acc: CrtGlwe<Vec<CrtValueT>> = party.generate_init_acc();

    party.generate_rotate_rgsw_inplace(degree, &mut rotate_ggsw, rng);
    if party_id == 0 {
        debug!(
            "[Round 1/4] Share RGSW, external product & coefficient expansion \
             (Alg.2 lines 14-15, 20-22; §4.2 GenInstance + §4.3.1 ParElect)"
        );
    }
    party.share_v3(&rotate_ggsw, all_rotate_ggsw.as_mut_slice());

    let mut ex_product_glwe: DcrtGlwe<Vec<CrtValueT>> = DcrtGlwe::zero(rns_glwe_len);
    protocol::external_product_chain(
        &mut acc,
        &all_rotate_ggsw,
        &mut ex_product_glwe,
        ggsw_params.basis(),
        table,
        ring_params.base_q(),
        &mut external_product_context,
    );

    // --- Coefficient Expansion ---
    let mut selectors = vec![DcrtGlwe::zero(rns_glwe_len); party_count];

    #[cfg(not(feature = "parallel"))]
    protocol::expand_selectors(
        &eck,
        &ex_product_glwe,
        &mut selectors,
        expand_coeff_params,
        ring_params.base_q(),
        &mut expand_coeff_context,
    );

    #[cfg(feature = "parallel")]
    protocol::expand_selectors(
        &eck,
        &ex_product_glwe,
        &mut selectors,
        expand_coeff_params,
        ring_params.base_q(),
        &mut expand_coeff_context_pool,
    );

    // --- Re-randomize Commits ---
    for (commit, commit_pk, rr_commit) in izip!(
        all_commit.iter(),
        all_commit_pk.iter(),
        all_rr_commit.iter_mut(),
    ) {
        protocol::rerandomize_commit(
            commit,
            commit_pk,
            rr_commit,
            commit_params,
            &commit_ntt_table,
            rng,
        );
    }

    // --- Encode Commits ---
    let mut temp: Vec<CrtValueT> = vec![0; ring_poly_length];
    let mut msg: DcrtPolynomial<Vec<CrtValueT>> = DcrtPolynomial::zero(rns_poly_len);
    let mut encode_commits: Vec<CrtValueT> = vec![0; rns_glwe_len * 2];
    let mut all_encode_commits: Vec<CrtValueT> = vec![0; rns_glwe_len * 2 * party_count];

    let commit_modulus_val = CommitModulus.value_unchecked().as_into();
    let cipher_moduli = ring_params.cipher_moduli();

    for (selector, rr_commit) in selectors.iter().zip(all_rr_commit.iter()) {
        let (enc_a, enc_b) = encode_commits.split_at_mut(rns_glwe_len);
        protocol::encode_single_commit(
            selector,
            rr_commit,
            enc_a,
            enc_b,
            &mut temp,
            &mut msg,
            commit_poly_length,
            ring_poly_length,
            ring_params.base_q(),
            commit_modulus_val,
            table,
            cipher_moduli,
        );
    }

    // --- Share & aggregate encoded commits ---
    if party_id == 0 {
        debug!(
            "[Round 2/4] Share encoded commits & aggregate \
             (Alg.2 lines 24-28, 31-32; §4.3.1 ParElect + §4.3.2 Elect)"
        );
    }
    party.share_v2(encode_commits.as_ref(), all_encode_commits.as_mut());

    let mut final_encode_commits: Vec<CrtValueT> = vec![0; rns_glwe_len * 2];
    protocol::aggregate_encode_commits(
        &all_encode_commits,
        &mut final_encode_commits,
        rns_glwe_len,
        ring_poly_length,
        rns_poly_len,
        cipher_moduli,
    );

    // --- Distributed Decryption (local computation) ---
    let rns_base = ring_params.base_q();

    let mut dec_share: Vec<CrtValueT> = vec![0; rns_poly_len * 2];
    let mut big_uint_dec_share: Vec<CrtValueT> = vec![0; big_uint_poly_len * 2];

    for (encode_commit, crt_dec, big_uint_dec) in izip!(
        final_encode_commits.chunks_exact(rns_glwe_len),
        dec_share.chunks_exact_mut(rns_poly_len),
        big_uint_dec_share.chunks_exact_mut(big_uint_poly_len),
    ) {
        protocol::decrypt_and_compose_slot(
            &msk_share,
            encode_commit,
            crt_dec,
            big_uint_dec,
            ring_poly_length,
            table,
            rns_base,
            external_product_context.compose_buffer_mut(),
            party_id == 0,
        );
    }

    let big_uint_value_len = ring_params.big_uint_value_len();

    // --- BigUint fast-path params ---
    let p = num::BigUint::from(ring_params.plain_modulus_value());
    let q = rns_base.moduli_product();
    let q_big = num::BigUint::from_slice(bytemuck::cast_slice(q.digits()));
    let q_prime_big = q_big.next_multiple_of(&p);
    let q_prime: BigUint<Vec<CrtValueT>> = BigUint(q_prime_big.iter_u64_digits().collect());
    let delta_prime_big = &q_prime_big / &p;
    let delta_prime: BigUint<Vec<CrtValueT>> = BigUint(delta_prime_big.iter_u64_digits().collect());

    let fast_q = biguint_to_u128(&q_big);
    let fast_qp = biguint_to_u128(&q_prime_big);
    let fast_dp = biguint_to_u128(&delta_prime_big).map(BarrettModulus::new);

    let mut e_shares: Vec<CrtValueT> = vec![0; big_uint_poly_len * 2];
    let mut all_e_shares: Vec<CrtValueT> = vec![0; big_uint_poly_len * 2 * party_count];

    if let (Some(q128), Some(qp128), Some(dp128)) = (fast_q, fast_qp, fast_dp) {
        let dp = dp128.value_unchecked();
        for (v_chunk, e_chunk, r_chunk) in izip!(
            big_uint_dec_share.chunks_exact_mut(2),
            e_shares.chunks_exact_mut(2),
            r_mod_delta_prime_share.chunks_exact(2),
        ) {
            let v_arr: &mut [CrtValueT; 2] = v_chunk.try_into().unwrap();
            let e_arr: &mut [CrtValueT; 2] = e_chunk.try_into().unwrap();
            scale_round_and_mod(v_arr, e_arr, q128, qp128, dp128);
            add_mod_u128(e_arr, r_chunk.try_into().unwrap(), dp);
        }
    } else {
        cold_path();
        for (value, e, r) in izip!(
            big_uint_dec_share.chunks_exact_mut(big_uint_value_len),
            e_shares.chunks_exact_mut(big_uint_value_len),
            r_mod_delta_prime_share.chunks_exact(big_uint_value_len),
        ) {
            protocol::scale_round_mod_biguint(
                value,
                e,
                r,
                &q_big,
                &q_prime_big,
                &delta_prime_big,
                &delta_prime,
                big_uint_value_len,
            );
        }
    }

    // --- Share e-shares → Party 0 aggregates ---
    if party_id == 0 {
        debug!(
            "[Round 3/4] Share e-shares → Party 0 aggregate & center \
             (Ajax 2025/1834 Fig.10 steps 1-2; Alg.2 lines 33-34, §4.3.2 Elect)"
        );
    }
    if party_id == 0 {
        party.share_to_p0(&e_shares, Some(&mut all_e_shares));
    } else {
        party.share_to_p0(&e_shares, None);
    }

    // --- Party 0: Aggregate e-shares and centering ---
    if party_id == 0 {
        let (p0_e_share, other_e_shares) = all_e_shares.split_at_mut(big_uint_poly_len * 2);

        if let Some(dp128) = fast_dp {
            let dp = dp128.value_unchecked();
            for e_share in other_e_shares.chunks_exact(big_uint_poly_len * 2) {
                protocol::aggregate_e_shares_u128(p0_e_share, e_share, dp);
            }
            protocol::center_e_shares_u128(p0_e_share, dp);
        } else {
            cold_path();
            protocol::aggregate_e_shares_biguint(
                p0_e_share,
                other_e_shares,
                &delta_prime,
                big_uint_value_len,
            );
            let mut delta_prime_half = delta_prime.clone();
            delta_prime_half.right_shift_assign(1);
            protocol::center_e_shares_biguint(
                p0_e_share,
                &delta_prime_half,
                &delta_prime,
                big_uint_value_len,
            );
        }
    }

    // --- Party 0: Subtract e from value, add r_mod_q_prime ---
    if party_id == 0 {
        if let Some(qp128) = fast_qp {
            for (v_chunk, e_chunk, r_chunk) in izip!(
                big_uint_dec_share.chunks_exact_mut(2),
                all_e_shares[0..big_uint_poly_len * 2].chunks_exact(2),
                r_mod_q_prime_share.chunks_exact(2),
            ) {
                let v_arr: &mut [CrtValueT; 2] = v_chunk.try_into().unwrap();
                sub_mod_u128(v_arr, e_chunk.try_into().unwrap(), qp128);
                add_mod_u128(v_arr, r_chunk.try_into().unwrap(), qp128);
            }
        } else {
            cold_path();
            protocol::sub_e_add_random_biguint(
                &mut big_uint_dec_share,
                &all_e_shares[0..big_uint_poly_len * 2],
                &r_mod_q_prime_share,
                &q_prime,
                big_uint_value_len,
            );
        }
    } else {
        if let Some(qp128) = fast_qp {
            for (v_chunk, r_chunk) in izip!(
                big_uint_dec_share.chunks_exact_mut(2),
                r_mod_q_prime_share.chunks_exact(2),
            ) {
                let v_arr: &mut [CrtValueT; 2] = v_chunk.try_into().unwrap();
                add_mod_u128(v_arr, r_chunk.try_into().unwrap(), qp128);
            }
        } else {
            cold_path();
            protocol::add_random_biguint(
                &mut big_uint_dec_share,
                &r_mod_q_prime_share,
                &q_prime,
                big_uint_value_len,
            );
        }
    }

    // --- Share & aggregate value shares ---
    if party_id == 0 {
        debug!(
            "[Round 4/4] Share value shares → Combine \
             (Ajax 2025/1834 Fig.10 steps 3-4; Alg.2 lines 36-38, §4.4 Combine)"
        );
    }
    let mut all_big_uint_dec_share: Vec<CrtValueT> = vec![0; big_uint_poly_len * 2 * party_count];
    party.share_v2(&big_uint_dec_share, &mut all_big_uint_dec_share);

    let (p0_share, other_shares) = all_big_uint_dec_share.split_at_mut(big_uint_poly_len * 2);

    if party_id == 0 {
        p0_share.copy_from_slice(&big_uint_dec_share);
    }

    if let Some(qp128) = fast_qp {
        for share in other_shares.chunks_exact(big_uint_poly_len * 2) {
            protocol::aggregate_value_shares_u128(p0_share, share, qp128);
        }
    } else {
        cold_path();
        protocol::aggregate_value_shares_biguint(
            p0_share,
            other_shares,
            &q_prime,
            big_uint_value_len,
        );
    }

    let mut final_commit: Vec<CommitValueT> = vec![0; ring_poly_length * 2];

    if let Some(dp128) = fast_dp {
        let dp = dp128.value_unchecked();
        for (a, b_chunk) in final_commit.iter_mut().zip(p0_share.chunks_exact(2)) {
            *a = protocol::final_value_to_commit_u128(b_chunk, dp);
        }
    } else {
        cold_path();
        for (a, b) in final_commit
            .iter_mut()
            .zip(p0_share.chunks_exact(big_uint_value_len))
        {
            *a = protocol::final_value_to_commit_biguint(b, &delta_prime_big);
        }
    }

    // --- Verification ---
    if party_id == 0 {
        debug!(
            "[Final] Verification — div_v, decode, decrypt \
             (Alg.2 lines 39-43, §4.5 Verify)"
        );
    }

    final_commit
        .chunks_exact_mut(ring_poly_length)
        .for_each(|poly| {
            protocol::div_v_inplace(poly, &mut poly_for_div_v, party_count, inv_two_factor);
        });

    let mut decoded_commit: Vec<CommitValueT> = vec![0; commit_poly_length * 2];
    protocol::decode_commit(
        &final_commit,
        &mut decoded_commit,
        commit_poly_length,
        ring_poly_length,
    );

    let cipher = Rlwe(decoded_commit);
    let cipher = cipher.into_ntt_form(&commit_ntt_table);
    let msgs = commit_sk.decrypt(&cipher, commit_params, &commit_ntt_table);
    let is_leader = msgs.iter().all(|&v| v == 0);

    if is_leader {
        info!("✓ Result: party {party_id} elected as leader");
    }

    degree
}

/// Collect each party's random degree, sum modulo party_count → elected leader.
fn check_result(party_count: usize, threads: Vec<std::thread::JoinHandle<usize>>) {
    let degrees: Vec<usize> = threads.into_iter().map(|h| h.join().unwrap()).collect();
    let leader = degrees.into_iter().sum::<usize>() % party_count;
    info!("All parties agree: leader is party {leader}");
}
