// cargo run --release --package ssle_core --example new_ssle_v2 -- -t 1 -p 4
// cargo +nightly run --release --package ssle_core --example new_ssle_v2 --features="nightly" -- -t 1 -p 4

use std::sync::Arc;

use clap::Parser;
use itertools::izip;
use mimalloc::MiMalloc;
use network::{Id, netio::Participant};
use primus_fhe_core::{
    CrtGlweTraceContext, DcrtGlweCiphertext, DcrtGlweDecryptContext, NttRlwePublicKey,
};
use primus_integer::AsInto;
use primus_lattice::{
    context::DcrtGlevContext,
    ggsw::DcrtGgsw,
    glwe::{CrtGlwe, DcrtGlwe},
    rlwe::{NttRlwe, Rlwe, RlweOwned},
};
use primus_ntt::{Dcrt, Ntt, NttTable};
use primus_poly::{ArrayBase, Polynomial, PolynomialOwned, dcrt::DcrtPolynomial};
use primus_reduce::Modulus;
use primus_reduce::ops::*;
use rand::Rng;
use ssle_core::{
    CoefficientExpansionKey, CommitModulus, CommitTable, CommitValueT, CrtValueT, KeyGen,
    MasterPublicKey, MasterSecretKey, Party, SsleParameters,
};

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

    let party_count = match party_count {
        Some(p) => {
            if !p.is_power_of_two() {
                panic!("Party count {p} is no power of two!")
            }
            if p * thread_count > max_cpu_cores {
                panic!("Your CPU has not enough cores!")
            }
            p
        }
        None => 2,
    };

    let params = if party_count <= 128 {
        if !GT128 {
            SsleParameters::new(party_count)
        } else {
            panic!("Don't enable feature `gt128` for party count: {party_count}<=128!")
        }
    } else if party_count > 128 && party_count <= 2048 {
        if GT128 {
            SsleParameters::new(party_count)
        } else {
            panic!("Enable feature `gt128` for party count: {party_count}!")
        }
    } else {
        panic!("no preparation for party count lager than 2048!")
    };

    println!("Party count: {party_count}");
    println!("Thread count per party: {thread_count}");

    (party_count, thread_count, params)
}

fn main() {
    let args = Args::parse();

    let (party_count, thread_count, params) = check_args(args);
    let params = Arc::new(params);

    let rng = &mut rand::rng();

    let participants = Participant::from_default(party_count, BASE_PORT);

    let (msk, mpk, eck) = KeyGen::generate_keys(&params, rng);

    println!("Key Generation done!");

    let (tx, recv_commits) = std::sync::mpsc::channel();
    let mut final_commit_senders = Vec::with_capacity(party_count);

    let threads = (0..party_count as Id)
        .map(|party_id| {
            let participants_c = participants.clone();

            let mpk_c = mpk.clone();
            let eck_c = eck.clone();
            let send_commit_sum = if party_id == 0 {
                Some(tx.clone())
            } else {
                None
            };
            let (send_final_commit, recv_final_commit) = crossbeam_channel::bounded(1);
            final_commit_senders.push(send_final_commit);

            std::thread::spawn(move || {
                let threads_pool = rayon::ThreadPoolBuilder::new()
                    .num_threads(thread_count)
                    .build()
                    .unwrap();

                threads_pool.install(|| {
                    party_operation(
                        party_id,
                        participants_c,
                        mpk_c,
                        eck_c,
                        thread_count,
                        send_commit_sum,
                        recv_final_commit,
                    )
                })
            })
        })
        .collect::<Vec<_>>();

    drop(tx);

    sim_thfhe_decrypt(
        party_count,
        &msk,
        &params,
        recv_commits,
        final_commit_senders,
    );

    check_result(party_count, threads);
}

fn sim_thfhe_decrypt(
    _party_count: usize,
    msk: &MasterSecretKey,
    params: &SsleParameters,
    recv_commits: std::sync::mpsc::Receiver<Vec<CrtValueT>>,
    final_commit_senders: Vec<crossbeam_channel::Sender<Vec<CommitValueT>>>,
) {
    if let Ok(encoded_commits) = recv_commits.recv() {
        let commit_poly_length = params.commit_params().poly_length();
        let ring_params = params.ring_params();

        let mid = encoded_commits.len() / 2;

        assert_eq!(mid, ring_params.rns_glwe_len());

        let mut commit_data: Vec<CrtValueT> = vec![0; commit_poly_length * 2];
        let mut context = DcrtGlweDecryptContext::new(
            ring_params.cipher_moduli_count(),
            ring_params.poly_length(),
        );

        for (poly, encoded_commit) in commit_data
            .chunks_mut(commit_poly_length)
            .zip(encoded_commits.chunks_exact(mid))
        {
            msk.decrypt_inplace(
                &DcrtGlweCiphertext::new(ArrayBase(encoded_commit)),
                &mut Polynomial(ArrayBase(poly)),
                params.ring_params(),
                msk.table(),
                &mut context,
            );
        }

        let final_commit: Vec<CommitValueT> = commit_data
            .into_iter()
            .map(|v| v.try_into().unwrap())
            .collect();

        for tx in final_commit_senders {
            tx.send(final_commit.clone()).unwrap();
        }
    }
}

fn party_operation(
    party_id: Id,
    participants: Vec<Participant>,
    mpk: MasterPublicKey,
    eck: CoefficientExpansionKey,
    thread_count: usize,
    send_commit_sum: Option<std::sync::mpsc::Sender<Vec<CrtValueT>>>,
    recv_final_commit: crossbeam_channel::Receiver<Vec<CommitValueT>>,
) -> usize {
    let rng = &mut rand::rng();

    let party_count = participants.len();
    let party = Party::new(party_id, participants, mpk, thread_count);

    let ssle_params = party.params();
    let commit_params = ssle_params.commit_params();
    let ring_params = ssle_params.ring_params();
    let ggsw_params = ssle_params.ggsw_params();
    let expand_coeff_params = ssle_params.expand_coeff_params();

    let poly_length = commit_params.poly_length();

    assert_eq!(poly_length, ring_params.poly_length());

    let table = party.table();

    let commit_rlwe_len = poly_length * 2;
    let rns_poly_len = ring_params.rns_poly_len();
    let rns_glwe_len = ring_params.rns_glwe_len();
    let big_uint_poly_len = ring_params.big_uint_poly_len();
    let rns_ggsw_len = ggsw_params.rns_ggsw_len();

    let mut external_product_context =
        DcrtGlevContext::new(poly_length, rns_poly_len, big_uint_poly_len);

    let mut expand_coeff_context = CrtGlweTraceContext::new(
        expand_coeff_params.dimension(),
        poly_length,
        rns_poly_len,
        big_uint_poly_len,
    );

    let commit_ntt_table = CommitTable::new(poly_length.trailing_zeros(), CommitModulus).unwrap();

    // Generate commit pk and sk.
    let (commit_sk, commit_pk) = party.generate_commit_key_pair(&commit_ntt_table, rng);

    // Generate commit
    let commit = commit_sk.encrypt_zeros(commit_params, &commit_ntt_table, rng);

    // Check commit
    let decrypt_commit = commit_sk.decrypt(&commit, &commit_params, &commit_ntt_table);
    assert!(decrypt_commit.iter().copied().all(|v| v == 0));

    let mut commit = commit.into_coeff_form(&commit_ntt_table);

    let inv_party_count = commit_params
        .cipher_modulus()
        .reduce_inv(party_count.as_into());

    commit.mul_scalar_assign(inv_party_count, CommitModulus);

    // Share commit and commit pk
    let mut all_commit: Vec<RlweOwned<CommitValueT>> =
        vec![Rlwe::zero(commit_rlwe_len); party_count];
    let mut all_commit_pk: Vec<NttRlwePublicKey<Vec<CommitValueT>>> =
        vec![NttRlwePublicKey::zero(commit_rlwe_len); party_count];
    let mut all_rr_commit: Vec<RlweOwned<CommitValueT>> =
        vec![Rlwe::zero(commit_rlwe_len); party_count];

    if party_id == 0 {
        println!("Party {party_id}: Start share commit.");
    }

    party.share_v3(&commit, all_commit.as_mut_slice());

    if party_id == 0 {
        println!("Party {party_id}: Start share pk.");
    }

    party.share_v3(&commit_pk, all_commit_pk.as_mut_slice());

    if party_id == 0 {
        println!("Party {party_id}: Commit and commit pk shared.");
    }

    let mut rotate_ggsw: DcrtGgsw<Vec<CrtValueT>> = DcrtGgsw::zero(rns_ggsw_len);
    let mut all_rotate_ggsw: Vec<DcrtGgsw<Vec<CrtValueT>>> =
        vec![DcrtGgsw::zero(rns_ggsw_len); party_count];

    // Check random degree for rgsw
    let degree = rng.random_range(0..poly_length);

    party.generate_rotate_rgsw_inplace(degree, &mut rotate_ggsw, rng);

    // Generate ACC
    let mut acc: CrtGlwe<Vec<CrtValueT>> = CrtGlwe::zero(rns_glwe_len);
    let (_, b) = acc.a_b_mut_slices(ring_params.rns_glwe_mid());
    b.chunks_exact_mut(poly_length)
        .zip(ring_params.delta_mod_q())
        .for_each(|(poly, &one)| {
            poly.iter_mut().step_by(party_count).for_each(|v| *v = one);
        });

    party.share_v3(&rotate_ggsw, all_rotate_ggsw.as_mut_slice());

    let mut temp_dcrt_glwe: DcrtGlwe<Vec<CrtValueT>> = DcrtGlwe::zero(rns_glwe_len);

    for rotate_rgsw in all_rotate_ggsw.iter() {
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

    let mut expand_result = vec![<CrtGlwe<Vec<CrtValueT>>>::zero(rns_glwe_len); party_count];
    let mut selectors = vec![<DcrtGlwe<Vec<CrtValueT>>>::zero(rns_glwe_len); party_count];

    eck.expand_partial_coefficients_inplace(
        &acc,
        &mut expand_result,
        &expand_coeff_params,
        ring_params.base_q(),
        &mut expand_coeff_context,
    );

    expand_result
        .iter()
        .zip(selectors.iter_mut())
        .for_each(|(x, y)| {
            x.to_ntt_form_inplace(y, table);
        });

    for (commit, commit_pk, rr_commit) in izip!(
        all_commit.iter(),
        all_commit_pk.iter(),
        all_rr_commit.iter_mut(),
    ) {
        let mut output = NttRlwe::new(ArrayBase(rr_commit.as_mut()));
        commit_pk.encrypt_zeros_inplace(&mut output, commit_params, &commit_ntt_table, rng);

        output.iter_ntt_poly_mut(poly_length).for_each(|poly| {
            commit_ntt_table.inverse_transform_slice(poly);
        });

        rr_commit.add_element_wise_assign(commit, CommitModulus);
    }

    let mut temp: Vec<CrtValueT> = vec![0; poly_length];
    let mut msg: DcrtPolynomial<Vec<CrtValueT>> = DcrtPolynomial::zero(rns_poly_len);

    let mut encode_commits: Vec<CrtValueT> = vec![0; rns_glwe_len * 2];
    let mut final_encode_commits: Vec<CrtValueT> = vec![0; rns_glwe_len * 2];
    let mut all_encode_commits: Vec<CrtValueT> = vec![0; rns_glwe_len * 2 * party_count];

    izip!(selectors.iter(), all_rr_commit.iter()).for_each(|(selector, rr_commit)| {
        encode_commits
            .chunks_exact_mut(rns_glwe_len)
            .zip(rr_commit.iter_poly(poly_length))
            .for_each(|(encode_commit, poly)| {
                temp.iter_mut()
                    .zip(poly)
                    .for_each(|(x, y)| *x = *y as CrtValueT);
                ring_params
                    .base_q()
                    .wrapping_decompose_small_values_inplace(
                        &temp,
                        msg.as_mut(),
                        poly_length,
                        CommitModulus.value_unchecked().as_into(),
                    );
                table.transform_slice(msg.as_mut());
                DcrtGlwe::new(ArrayBase(encode_commit)).add_dcrt_glwe_mul_dcrt_polynomial_assign(
                    selector,
                    &msg,
                    poly_length,
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
                    DcrtGlwe::new(ArrayBase(y)).add_element_wise_assign(
                        &DcrtGlwe::new(ArrayBase(x)),
                        poly_length,
                        rns_poly_len,
                        ring_params.cipher_moduli(),
                    );
                });
        });

    if let Some(send_commit_sum) = send_commit_sum {
        send_commit_sum.send(final_encode_commits).unwrap();
        drop(send_commit_sum);
    }

    if let Ok(final_commit) = recv_final_commit.recv() {
        let mut factor = PolynomialOwned::zero(poly_length);
        factor.iter_mut().step_by(party_count).for_each(|v| *v = 1);
        let factor = commit_ntt_table.transform_inplace(factor);

        let inv_factor = factor.try_inv(CommitModulus).unwrap();

        let cipher = Rlwe::new(ArrayBase(final_commit));
        let mut cipher = cipher.into_ntt_form(&commit_ntt_table);
        cipher.mul_ntt_polynomial_assign(&inv_factor, CommitModulus);

        let msgs = commit_sk.decrypt(&cipher, commit_params, &commit_ntt_table);

        let is_leader = msgs.iter().all(|&v| v == 0);

        if is_leader {
            println!("\nParty {party_id}: I'm leader!",);
        }
    }

    degree
}

fn check_result(party_count: usize, threads: Vec<std::thread::JoinHandle<usize>>) {
    let degrees: Vec<usize> = threads.into_iter().map(|h| h.join().unwrap()).collect();

    println!(
        "\nleader: {}\n",
        degrees.into_iter().sum::<usize>() % party_count
    );
    println!("Parties count: {party_count}");
}
