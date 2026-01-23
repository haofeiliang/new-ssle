// cargo run --release --package ssle_core --example check_commit -- -p 4
// cargo run --release --package ssle_core --example check_commit --features="gt32" -- -p 64
// cargo run --release --package ssle_core --example check_commit --features="gt128" -- -p 256

use std::sync::Arc;

use clap::Parser;
use mimalloc::MiMalloc;
use network::netio::Participant;
use primus_integer::AsInto;
use primus_lattice::rlwe::NttRlwe;
use primus_ntt::NttTable;
use primus_reduce::ops::*;
use rand::Rng;
use ssle_core::{
    CommitModulus, CommitTable, CommitValueT, KeyGen, MasterPublicKey, SsleParameters,
};

#[cfg(feature = "gt32")]
const GT32: bool = true;

#[cfg(not(feature = "gt32"))]
const GT32: bool = false;

#[cfg(feature = "gt128")]
const GT128: bool = true;

#[cfg(not(feature = "gt128"))]
const GT128: bool = false;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

const BASE_PORT: u16 = 30000;

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

    let params = if party_count <= 32 {
        if !GT32 && !GT128 {
            SsleParameters::new(party_count)
        } else {
            panic!("Don't enable feature `gt32` and `gt128` for party count: {party_count}<=32!")
        }
    } else if party_count <= 128 {
        if GT32 && !GT128 {
            SsleParameters::new(party_count)
        } else {
            if !GT32 {
                panic!("Enable feature `gt32` for party count: {party_count}!")
            } else {
                panic!("Don't enable feature `gt128` for party count: {party_count}<=128!")
            }
        }
    } else if party_count > 128 && party_count <= 2048 {
        if GT128 {
            SsleParameters::new(party_count)
        } else {
            if GT32 {
                panic!("Don't enable feature `gt32` for party count: {party_count}>128!")
            } else {
                panic!("Enable feature `gt128` for party count: {party_count}!")
            }
        }
    } else {
        panic!("no preparation for party count lager than 2048!")
    };

    println!("Party count: {party_count}");

    (party_count, params)
}

fn main() {
    let args = Args::parse();

    let (party_count, params) = check_args(args);
    let params = Arc::new(params);

    let rng = &mut rand::rng();

    let participants = Participant::from_default(party_count, BASE_PORT);

    let (_msk, mpk, _eck) = KeyGen::generate_keys(&params, rng);

    println!("Key Generation done!");

    check_commit(participants, mpk);
}

fn check_commit(participants: Vec<Participant>, mpk: MasterPublicKey) {
    let rng = &mut rand::rng();

    let party_count = participants.len();

    let ssle_params = mpk.params();
    let commit_params = ssle_params.commit_params();
    let commit_poly_length = commit_params.poly_length();
    let commit_rlwe_len = commit_poly_length * 2;

    let commit_ntt_table =
        CommitTable::new(commit_poly_length.trailing_zeros(), CommitModulus).unwrap();

    let inv_party_count = commit_params
        .cipher_modulus()
        .reduce_inv(party_count.as_into());
    // let inv_party_count_factor = ShoupFactor::new(inv_party_count, CommitModulus.value_unchecked());

    // Generate commit pk and sk.
    let (all_commit_sk, all_commit_pk): (Vec<_>, Vec<_>) = (0..party_count)
        .map(|_| mpk.generate_commit_key_pair(&commit_ntt_table, rng))
        .collect();

    // Generate commit
    let all_commit: Vec<NttRlwe<Vec<CommitValueT>>> = all_commit_sk
        .iter()
        .map(|sk| {
            let mut temp = sk.encrypt_zeros(commit_params, &commit_ntt_table, rng);
            temp.mul_scalar_assign(inv_party_count, CommitModulus);
            temp
        })
        .collect();

    let mut rr_commit: NttRlwe<Vec<CommitValueT>> = NttRlwe::zero(commit_rlwe_len);
    let mut temp_commit: NttRlwe<Vec<CommitValueT>> = NttRlwe::zero(commit_rlwe_len);

    let choose = rng.random_range(0..party_count);

    let choose_pk = &all_commit_pk[choose];
    let choose_commit = &all_commit[choose];

    for _ in 0..party_count {
        choose_pk.encrypt_zeros_inplace(&mut temp_commit, commit_params, &commit_ntt_table, rng);
        temp_commit.add_element_wise_assign(choose_commit, CommitModulus);
        rr_commit.add_element_wise_assign(&temp_commit, CommitModulus);
    }

    for (i, sk) in all_commit_sk.iter().enumerate() {
        let m = sk.decrypt(&rr_commit, commit_params, &commit_ntt_table);
        if m.is_zero() {
            println!("Party {i} vs Choose {choose}");
        }
    }
}
