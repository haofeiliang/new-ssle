//! # SSLE Compute-Time Benchmark — optimized for large party counts
//!
//! Same approach as `ssle_compute_time`, but with the RGSW
//! count **fixed at 128** instead of scaling with `party_count`. Only party 0
//! runs the full SSLE protocol path and is timed; other parties contribute
//! pre-computed or placeholder values. All timings reflect party 0's
//! computation.
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
//! // stable toolchain (default):
//! cargo run --release --package ssle_core --example ssle_ge_256_compute_time_improve --features="gt128" -- -p 256
//! cargo run --release --package ssle_core --example ssle_ge_256_compute_time_improve --features="gt128 parallel" -- -p 256 -t 16
//! // nightly toolchain with SIMD (as used in paper benchmarks):
//! cargo +nightly run --release --package ssle_core --example ssle_ge_256_compute_time_improve --features="gt128 simd" -- -p 256
//! cargo +nightly run --release --package ssle_core --example ssle_ge_256_compute_time_improve --features="gt128 parallel simd" -- -p 256 -t 16
//! ```
//!
//! Paper benchmarks were collected via:
//! ```text
//! bash run_bench.sh -c nightly -s
//! ```

use std::{sync::Arc, time::Duration};

use clap::Parser;
use num::Integer;
use ssle_core::{CrtValueT, KeyGen, SsleParameters, generate_dd_random, protocol};
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
    /// rayon thread count for party 0 (requires `parallel` feature)
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
        .with_span_events(FmtSpan::CLOSE)
        .with_target(false)
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        )
        .with_timer(())
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

    // Communication size estimation.
    // Computes the bandwidth per party for Round 1 (Relect, §4.3.1) and
    // Round 2 (distributed decryption via Ajax 2025/1834 "mask-then-open",
    // instantiating Relect §4.3.2 + §4.4) under the current RNS parameter sets.
    {
        let ring_params = params.ring_params();
        let ggsw_params = params.ggsw_params();
        let rns_ggsw_len = ggsw_params.rns_ggsw_len();
        let rns_glwe_len = ring_params.rns_glwe_len();
        let big_uint_value_len = ring_params.big_uint_value_len();

        let ggsw_size = std::mem::size_of::<CrtValueT>() * rns_ggsw_len;
        let encode_commits_size = std::mem::size_of::<CrtValueT>() * rns_glwe_len * 2 * party_count;

        let p = num::BigUint::from(ring_params.plain_modulus_value());
        let q = ring_params.base_q().moduli_product();
        let q_big = num::BigUint::from_slice(bytemuck::cast_slice(q.digits()));
        let q_prime_big = q_big.next_multiple_of(&p);
        let q_prime_bits = q_prime_big.bits();
        let delta_prime_big = &q_prime_big / p;
        let delta_prime_bits = delta_prime_big.bits();

        let factor = if party_count <= 128 {
            50.0 / 64.0
        } else {
            37.0 / 64.0
        };

        let size1 = (ggsw_size * (party_count - 1)) as f64 * factor / 1024.0;
        let size2 = encode_commits_size as f64 * factor / 1024.0;

        let single_size1 = ggsw_size as f64 * factor / 1024.0;
        let single_size2 = size2 / party_count as f64;

        let size2 = single_size2 * (party_count - 1) as f64;

        debug!("First Round single size: {single_size1}KB");
        debug!("Second Round single size: {single_size2}KB");

        debug!("First Round size: {size1}KB");
        debug!("Second Round size: {size2}KB");

        let big_uint_poly_len = ring_params.big_uint_poly_len();
        let per_party_elem_count = big_uint_poly_len * 2;

        // Round 3 (share_to_p0): e-shares from (party_count-1) parties to party 0
        let dec_size1 = per_party_elem_count as f64
            * 8.0
            * (delta_prime_bits as f64 / (big_uint_value_len as f64 * 64.0))
            / 1024.0;
        // Round 4 (share_v2 / broadcast): value shares to (party_count-1) peers
        let single_dec_size2 = per_party_elem_count as f64
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
    }
}
