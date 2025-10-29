use bytes::{Bytes, BytesMut};
use clap::Parser;
use mimalloc::MiMalloc;
use network::{Id, netio::Participant};
use primus_fhe_core::CrtGlweTraceContext;
use primus_integer::{AsInto, ByteCount};
use primus_lattice::{
    context::DcrtGlevContext,
    ggsw::DcrtGgsw,
    glwe::{CrtGlwe, DcrtGlwe},
    rlwe::RlweOwned,
};
use primus_ntt::NttTable;
use primus_poly::ArrayBase;
use primus_reduce::ops::*;
use rand::Rng;
use ssle_core::{
    CoefficientExpansionKey, CommitModulus, CommitTable, CrtValueT, KeyGen, MasterPublicKey, Party,
    SsleParameters,
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

    let (msk, mpk, eck) = KeyGen::generate_keys(params, rng);

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
}

fn party_operation(
    party_id: Id,
    participants: Vec<Participant>,
    mpk: MasterPublicKey,
    eck: CoefficientExpansionKey,
    thread_count: usize,
    send_commit_sum: Option<std::sync::mpsc::Sender<Vec<DcrtGlwe<Vec<CrtValueT>>>>>,
    recv_decrypted_commit: crossbeam_channel::Receiver<RlweOwned<u32>>,
) -> usize {
    let party_count = participants.len();

    let rng = &mut rand::rng();

    let party = Party::new(party_id, participants, mpk, thread_count);

    let params = party.params();

    let commit_params = params.commit_params();
    let commit_poly_length = commit_params.poly_length();

    let table = party.table();

    let ring_params = params.ring_params();
    let ring_poly_length = ring_params.poly_length();

    let ggsw_params = params.ggsw_params();
    let gadget_basis = ggsw_params.basis();

    let mut external_product_context = DcrtGlevContext::new(
        ggsw_params.poly_length(),
        ggsw_params.rns_poly_len(),
        ggsw_params.big_uint_poly_len(),
    );

    let expand_coeff_params = params.expand_coeff_params();

    let mut expand_context = CrtGlweTraceContext::new(
        expand_coeff_params.dimension(),
        expand_coeff_params.poly_length(),
        expand_coeff_params.rns_poly_len(),
        expand_coeff_params.big_uint_poly_len(),
    );

    let commit_ntt_table =
        CommitTable::new(commit_poly_length.trailing_zeros(), CommitModulus).unwrap();

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
    let commit_bytes = Bytes::from_owner(commit.to_bytes());
    let commit_bytes_count = commit_bytes.len();
    let all_commit_bytes = BytesMut::zeroed(commit_bytes_count * party_count);
    let all_commit_bytes = party.share(commit_bytes, all_commit_bytes);

    if party_id == 0 {
        println!("Party {party_id}: Start share pk.");
    }

    let commit_pk_bytes = Bytes::from_owner(commit_pk.into_bytes());
    let commit_pk_bytes_count = commit_pk_bytes.len();
    let commit_pks_bytes = BytesMut::zeroed(commit_pk_bytes_count * party_count);
    let commit_pks_bytes = party.share(commit_pk_bytes, commit_pks_bytes);

    if party_id == 0 {
        println!("Party {party_id}: Commit and commit pk shared.");
    }

    let rotate_rgsw_bytes_count =
        ggsw_params.rns_ggsw_len() * <CrtValueT as ByteCount>::BYTES_COUNT;
    let mut rotate_rgsw_bytes = BytesMut::zeroed(rotate_rgsw_bytes_count);
    let all_rotate_rgsw_bytes = BytesMut::zeroed(rotate_rgsw_bytes_count * party_count);

    // Check random degree for rgsw
    let degree = rng.random_range(0..ring_poly_length);

    let rotate_rgsw = bytemuck::cast_slice_mut(rotate_rgsw_bytes.as_mut());
    party.generate_rotate_rgsw_inplace(degree, &mut DcrtGgsw::new(ArrayBase(rotate_rgsw)), rng);

    // Generate ACC
    let mut acc: CrtGlwe<Vec<CrtValueT>> = CrtGlwe::zero(ring_params.rns_glwe_len());
    let delta_mod_q = ring_params.delta_mod_q();
    let (_, b) = acc.a_b_mut_slices(ring_params.rns_glwe_mid());
    b.chunks_exact_mut(ring_poly_length)
        .zip(delta_mod_q)
        .for_each(|(poly, &one)| {
            poly.iter_mut().step_by(party_count).for_each(|v| *v = one);
        });

    let all_rotate_rgsw_bytes = party.share(rotate_rgsw_bytes.freeze(), all_rotate_rgsw_bytes);

    let mut temp_dcrt_glwe: DcrtGlwe<Vec<CrtValueT>> = DcrtGlwe::zero(ring_params.rns_glwe_len());

    for rotate_rgsw in all_rotate_rgsw_bytes.chunks_exact(rotate_rgsw_bytes_count) {
        let temp = bytemuck::cast_slice(rotate_rgsw);
        acc.mul_dcrt_ggsw_inplace(
            &DcrtGgsw::new(ArrayBase(temp)),
            &mut temp_dcrt_glwe,
            ggsw_params.basis(),
            table,
            ring_params.base_q(),
            &mut external_product_context,
        );

        temp_dcrt_glwe.to_coeff_form_inplace(&mut acc, table);
    }

    let mut expand_result =
        vec![<CrtGlwe<Vec<CrtValueT>>>::zero(expand_coeff_params.rns_glwe_len()); party_count];

    eck.expand_partial_coefficients_inplace(
        &acc,
        &mut expand_result,
        &expand_coeff_params,
        ring_params.base_q(),
        &mut expand_context,
    );

    todo!()
}
