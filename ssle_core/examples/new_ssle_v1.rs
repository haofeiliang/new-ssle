// cargo run --release --package ssle_core --example new_ssle_v1 -- -t 1 -p 4

use bytes::{Bytes, BytesMut};
use clap::Parser;
use itertools::izip;
use mimalloc::MiMalloc;
use network::{Id, netio::Participant};
use primus_fhe_core::{
    CrtGlweTraceContext, DcrtGlweCiphertext, DcrtGlweDecryptContext, NttRlweCiphertext,
    NttRlwePublicKey,
};
use primus_integer::{AsInto, ByteCount};
use primus_lattice::{
    context::DcrtGlevContext,
    ggsw::DcrtGgsw,
    glwe::{CrtGlwe, DcrtGlwe},
};
use primus_ntt::{Dcrt, NttTable};
use primus_poly::{ArrayBase, Polynomial, dcrt::DcrtPolynomial};
use primus_reduce::Modulus;
use primus_reduce::ops::*;
use rand::Rng;
use ssle_core::{
    CoefficientExpansionKey, CommitModulus, CommitTable, CommitValueT, CrtValueT, KeyGen,
    MasterPublicKey, MasterSecretKey, Party, SsleParameters,
};

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

    let params = SsleParameters::new(party_count);

    println!("Party count: {party_count}");
    println!("Thread count per party: {thread_count}");

    (party_count, thread_count, params)
}

fn main() {
    let args = Args::parse();

    let (party_count, thread_count, params) = check_args(args);

    let rng = &mut rand::rng();

    let participants = Participant::from_default(party_count, BASE_PORT);

    let (msk, mpk, eck) = KeyGen::generate_keys(params.clone(), rng);

    println!("Key Generation done!");

    let (tx, recv_commits) = std::sync::mpsc::channel();
    let mut send_decrypted_commits = Vec::with_capacity(party_count);

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
            let (send_decrypted_commit, recv_decrypted_commit) = crossbeam_channel::bounded(1);
            send_decrypted_commits.push(send_decrypted_commit);

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
                        recv_decrypted_commit,
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
        send_decrypted_commits,
    );

    check_result(party_count, threads);
}

fn sim_thfhe_decrypt(
    _party_count: usize,
    msk: &MasterSecretKey,
    params: &SsleParameters,
    recv_commits: std::sync::mpsc::Receiver<Vec<CrtValueT>>,
    send_decrypted_commits: Vec<crossbeam_channel::Sender<Bytes>>,
) {
    if let Ok(encoded_commits_sum) = recv_commits.recv() {
        let commit_params = params.commit_params();
        let commit_poly_length = commit_params.poly_length();
        let ring_params = params.ring_params();

        let encoded_commits_sum_mid = encoded_commits_sum.len() / 2;

        let mut commit_bytes: BytesMut =
            BytesMut::zeroed(commit_poly_length * 2 * <CrtValueT as ByteCount>::BYTES_COUNT);
        let mut context =
            DcrtGlweDecryptContext::new(ring_params.cipher_moduli_count(), commit_poly_length);
        let cipher_slice: &mut [CrtValueT] = bytemuck::cast_slice_mut(commit_bytes.as_mut());

        for (poly, encoded_commit_chunk) in cipher_slice
            .chunks_mut(commit_poly_length)
            .zip(encoded_commits_sum.chunks_exact(encoded_commits_sum_mid))
        {
            let ec: &[CrtValueT] = bytemuck::cast_slice(encoded_commit_chunk);
            msk.decrypt_inplace(
                &DcrtGlweCiphertext::new(ArrayBase(ec)),
                &mut Polynomial(ArrayBase(poly)),
                params.ring_params(),
                msk.table(),
                &mut context,
            );
        }

        let decrypted_commit = if <CrtValueT as ByteCount>::BYTES_COUNT
            != <CommitValueT as ByteCount>::BYTES_COUNT
        {
            let mut temp: BytesMut =
                BytesMut::zeroed(commit_poly_length * 2 * <CommitValueT as ByteCount>::BYTES_COUNT);

            let x: &mut [CommitValueT] = bytemuck::cast_slice_mut(temp.as_mut());
            let y: &[CrtValueT] = bytemuck::cast_slice(commit_bytes.as_ref());

            x.iter_mut().zip(y.iter()).for_each(|(a, &b)| {
                *a = b as CommitValueT;
            });

            temp.freeze()
        } else {
            commit_bytes.freeze()
        };

        for tx in send_decrypted_commits {
            tx.send(decrypted_commit.clone()).unwrap();
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
    recv_decrypted_commit: crossbeam_channel::Receiver<Bytes>,
) -> usize {
    let rng = &mut rand::rng();

    let party_count = participants.len();
    let party = Party::new(party_id, participants, mpk, thread_count);

    let params = party.params();
    let commit_params = params.commit_params();
    let ring_params = params.ring_params();
    let ggsw_params = params.ggsw_params();
    let expand_coeff_params = params.expand_coeff_params();

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

    let mut expand_context = CrtGlweTraceContext::new(
        expand_coeff_params.dimension(),
        poly_length,
        rns_poly_len,
        big_uint_poly_len,
    );

    let commit_ntt_table = CommitTable::new(poly_length.trailing_zeros(), CommitModulus).unwrap();

    // Generate commit pk and sk.
    let (commit_sk, commit_pk) = party.generate_commit_key_pair(&commit_ntt_table, rng);

    // Generate commit
    let mut commit = commit_sk.encrypt_zeros(commit_params, &commit_ntt_table, rng);

    // Check commit
    let decrypt_commit = commit_sk.decrypt(&commit, &commit_params, &commit_ntt_table);
    assert!(decrypt_commit.iter().copied().all(|v| v == 0));

    let inv_party_count = commit_params
        .cipher_modulus()
        .reduce_inv(party_count.as_into());

    commit.mul_scalar_assign(inv_party_count, CommitModulus);

    if party_id == 0 {
        println!("Party {party_id}: Start share commit.");
    }

    // Share commit and commit pk
    let mut all_commits: Vec<CommitValueT> = vec![0; commit_rlwe_len * party_count];
    let mut re_random_all_commits: Vec<CommitValueT> = vec![0; commit_rlwe_len * party_count];
    party.share_v2(commit.as_ref(), &mut all_commits);

    if party_id == 0 {
        println!("Party {party_id}: Start share pk.");
    }

    let mut all_commit_pks: Vec<CommitValueT> = vec![0; commit_rlwe_len * party_count];
    party.share_v2(commit_pk.as_ref(), &mut all_commit_pks);

    if party_id == 0 {
        println!("Party {party_id}: Commit and commit pk shared.");
    }

    let mut rotate_rgsw: Vec<CrtValueT> = vec![0; rns_ggsw_len];
    let mut all_rotate_rgsw: Vec<CrtValueT> = vec![0; rns_ggsw_len * party_count];

    // Check random degree for rgsw
    let degree = rng.random_range(0..poly_length);

    party.generate_rotate_rgsw_inplace(
        degree,
        &mut DcrtGgsw::new(ArrayBase(rotate_rgsw.as_mut())),
        rng,
    );

    // Generate ACC
    let mut acc: CrtGlwe<Vec<CrtValueT>> = CrtGlwe::zero(rns_glwe_len);
    let (_, b) = acc.a_b_mut_slices(ring_params.rns_glwe_mid());
    b.chunks_exact_mut(poly_length)
        .zip(ring_params.delta_mod_q())
        .for_each(|(poly, &one)| {
            poly.iter_mut().step_by(party_count).for_each(|v| *v = one);
        });

    party.share_v2(rotate_rgsw.as_ref(), all_rotate_rgsw.as_mut());

    let mut temp_dcrt_glwe: DcrtGlwe<Vec<CrtValueT>> = DcrtGlwe::zero(rns_glwe_len);

    for rotate_rgsw in all_rotate_rgsw.chunks_exact(rns_ggsw_len) {
        acc.mul_dcrt_ggsw_inplace(
            &DcrtGgsw::new(ArrayBase(rotate_rgsw)),
            &mut temp_dcrt_glwe,
            ggsw_params.basis(),
            table,
            ring_params.base_q(),
            &mut external_product_context,
        );

        temp_dcrt_glwe.to_coeff_form_inplace(&mut acc, table);
    }

    let mut expand_result = vec![<CrtGlwe<Vec<CrtValueT>>>::zero(rns_glwe_len); party_count];
    let mut ntt_expand_result = vec![<DcrtGlwe<Vec<CrtValueT>>>::zero(rns_glwe_len); party_count];

    let mut encode_commits: Vec<CrtValueT> = vec![0; rns_glwe_len * 2];
    let mut encode_commits_sum: Vec<CrtValueT> = vec![0; rns_glwe_len * 2];
    let mut all_encode_commits: Vec<CrtValueT> = vec![0; rns_glwe_len * 2 * party_count];

    eck.expand_partial_coefficients_inplace(
        &acc,
        &mut expand_result,
        &expand_coeff_params,
        ring_params.base_q(),
        &mut expand_context,
    );

    expand_result
        .iter()
        .zip(ntt_expand_result.iter_mut())
        .for_each(|(x, y)| {
            x.to_ntt_form_inplace(y, table);
        });

    for (commit, re_random_commit, commit_pk) in izip!(
        all_commits.chunks_exact(rns_glwe_len),
        re_random_all_commits.chunks_exact_mut(rns_glwe_len),
        all_commit_pks.chunks_exact(rns_glwe_len),
    ) {
        let input = NttRlweCiphertext::new(ArrayBase(commit));
        let mut output = NttRlweCiphertext::new(ArrayBase(re_random_commit));
        let pk = NttRlweCiphertext::new(ArrayBase(commit_pk));

        let pk = NttRlwePublicKey::from(pk);
        pk.encrypt_zeros_inplace(&mut output, commit_params, &commit_ntt_table, rng);

        output.add_element_wise_assign(&input, CommitModulus);
    }

    let mut temp: Vec<CrtValueT> = vec![0; poly_length];
    let mut msg: DcrtPolynomial<Vec<CrtValueT>> = DcrtPolynomial::zero(poly_length);

    izip!(
        ntt_expand_result.iter(),
        re_random_all_commits.chunks_exact_mut(rns_glwe_len)
    )
    .for_each(|(selector, random_commit)| {
        let random_commit = NttRlweCiphertext::new(ArrayBase(random_commit));

        encode_commits
            .chunks_exact_mut(rns_glwe_len)
            .zip(random_commit.iter_ntt_poly(poly_length))
            .for_each(|(encode_commit, ntt_poly)| {
                temp.iter_mut()
                    .zip(ntt_poly)
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
                    &DcrtPolynomial(ArrayBase(msg.as_ref())),
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
                .zip(encode_commits_sum.chunks_exact_mut(rns_glwe_len))
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
        send_commit_sum.send(encode_commits_sum).unwrap();
        drop(send_commit_sum);
    }

    if let Ok(decrypted_commit) = recv_decrypted_commit.recv() {
        let cipher_slice: &[CommitValueT] = bytemuck::cast_slice(decrypted_commit.as_ref());
        let msgs = commit_sk.decrypt(
            &NttRlweCiphertext::new(ArrayBase(cipher_slice)),
            commit_params,
            &commit_ntt_table,
        );

        println!("Party {party_id}: {:?}", msgs.as_ref());

        let is_leader = msgs.iter().all(|&v| v == 0);

        if is_leader {
            println!("Party {party_id}: I'm leader!",);
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
