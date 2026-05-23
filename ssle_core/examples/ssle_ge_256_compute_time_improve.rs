//! # SSLE Compute-Time Benchmark — optimized for large party counts
//!
//! Same single-party simulation as `ssle_compute_time`, but with the RGSW
//! count **fixed at 128** instead of scaling with `party_count`.
//!
//! **Why this is valid**: by honest majority, a random subset of κ parties
//! (here κ = 128) suffices to guarantee at least one honest party contributes
//! uniform randomness, so the elected leader is uniform over [G]. The subset
//! sampling optimization is described in paper §2.5 ("For G ≥ κ").
//! Capping the RGSW count avoids the external product chain (§4.3.1, Alg.2
//! lines 20-21) scaling linearly with party_count.
//!
//! # Usage
//! ```text
//! cargo run --release --package ssle_core --example ssle_ge_256_compute_time_improve --features="gt128" -- -p 256
//! cargo run --release --package ssle_core --example ssle_ge_256_compute_time_improve --features="gt128 parallel" -- -p 256 -t 16
//! ```

use std::{sync::Arc, time::Duration};

use clap::Parser;
use ssle_core::{KeyGen, SsleParameters, generate_dd_random, protocol};
use tabled::{Table, Tabled, settings::Rotate};
use tracing::{debug, error, info, level_filters::LevelFilter};
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan};

#[cfg(feature = "gt16")]
const GT16: bool = true;

#[cfg(not(feature = "gt16"))]
const GT16: bool = false;

#[cfg(feature = "gt128")]
const GT128: bool = true;

#[cfg(not(feature = "gt128"))]
const GT128: bool = false;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// RGSW count fixed at 128 instead of party_count.
///
/// By honest majority, a random subset of κ = 128 parties suffices to
/// guarantee the elected leader is uniform over [G] (paper §2.5).
const FIXED_RGSW_COUNT: usize = 128;

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
    /// thread count per party
    #[arg(short = 't', long)]
    thread_count: Option<usize>,
    /// party count
    #[arg(short = 'p', long)]
    party_count: Option<usize>,
}

fn check_args(args: Args) -> (usize, usize, SsleParameters) {
    let party_count = args.party_count;
    let thread_count = args.thread_count.unwrap_or(1);

    let party_count = match party_count {
        Some(p) => {
            if !p.is_power_of_two() {
                error!("Party count {p} is not power of two!");
                panic!("Party count {p} is not power of two!");
            }
            p
        }
        None => 2,
    };

    #[cfg(feature = "parallel")]
    if thread_count > num_cpus::get() {
        panic!("Your CPU has not enough cores!")
    }

    #[cfg(not(feature = "parallel"))]
    if thread_count != 1 {
        panic!("Enable feature `parallel` for thread count {thread_count} > 1");
    }

    let params = if party_count <= 128 || party_count > 2048 {
        error!("This example is for party count >= 256!");
        panic!("This example is for party count >= 256!");
    } else {
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
    };

    info!("Party count: {party_count}");

    (party_count, thread_count, params)
}

fn main() {
    tracing_subscriber::fmt()
        .compact()
        .with_span_events(FmtSpan::CLOSE)
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        )
        .init();

    let args = Args::parse();

    #[allow(unused_variables)]
    let (party_count, num_threads, params) = check_args(args);

    #[cfg(feature = "parallel")]
    rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build_global()
        .unwrap();

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

    let (_choose, timings) = protocol::run_compute_time_protocol(
        party_count,
        FIXED_RGSW_COUNT,
        &msk,
        &mpk,
        &eck,
        &msk_shares,
        &dd_randoms,
        num_threads,
    );

    let time_info = TimeInfo {
        rlwe_mul_rgsw: timings.rlwe_mul_rgsw,
        expand_coefficients: timings.expand_coefficients,
        compute_local_encode_commit: timings.compute_local_encode_commit,
        compute_final_encode_commit: timings.compute_final_encode_commit,
        distributed_decrypt: timings.distributed_decrypt,
        decrypt_commit: timings.decrypt_commit,
        all_compute: timings.all_compute,
    };

    let mut table = Table::new([time_info]);
    table.with(Rotate::Left);
    table.with(Rotate::Top);
    println!("{table}");
}
