//! # SSLE Compute-Time Benchmark
//!
//! Measures the computation time of the SSLE protocol (no network I/O).
//! Only party 0 runs the full SSLE protocol
//! path and is timed; other parties contribute pre-computed or placeholder
//! values so that the aggregation steps can proceed. All reported timings
//! reflect **party 0's computation only**.
//!
//! This example corresponds to the full protocol in **paper §4, Algorithm 2**.
//! The communication size estimation at the end computes the concrete bandwidth
//! costs for Round 1 (Relect) and Round 2 (Distributed Decryption) under the
//! current parameter sets.
//!
//! # Party count → feature mapping
//! | party_count  | features       |
//! |-------------|----------------|
//! | 2 ..= 16    | (none)         |
//! | 32 ..= 128  | `gt16`         |
//! | 256 ..= 2048| `gt128`        |
//!
//! Note: for `party_count >= 256`, the `ssle_ge_256_compute_time_improve`
//! example (which caps the RGSW count at 128) is preferred.
//!
//! # Usage
//!
//! ```text
//! // stable toolchain (default):
//! cargo run --release --package ssle_core --example ssle_compute_time -- -p 4
//! cargo run --release --package ssle_core --example ssle_compute_time --features="gt16" -- -p 64
//! cargo run --release --package ssle_core --example ssle_compute_time --features="gt128" -- -p 256
//! // with parallelism (`-t` rayon threads for party 0's computation):
//! cargo run --release --package ssle_core --example ssle_compute_time --features="parallel" -- -p 4 -t 4
//! cargo run --release --package ssle_core --example ssle_compute_time --features="gt16 parallel" -- -p 64 -t 8
//! cargo run --release --package ssle_core --example ssle_compute_time --features="gt128 parallel" -- -p 256 -t 8
//! // nightly toolchain with SIMD (as used in paper benchmarks):
//! cargo +nightly run --release --package ssle_core --example ssle_compute_time --features="simd" -- -p 4
//! cargo +nightly run --release --package ssle_core --example ssle_compute_time --features="gt16 simd" -- -p 64
//! cargo +nightly run --release --package ssle_core --example ssle_compute_time --features="gt128 simd" -- -p 256
//! // nightly + parallelism + SIMD:
//! cargo +nightly run --release --package ssle_core --example ssle_compute_time --features="parallel simd" -- -p 4 -t 4
//! ```
//!
//! Paper benchmarks were collected via:
//! ```text
//! bash run_bench.sh -c nightly -s
//! ```

use std::{sync::Arc, time::Duration};

use clap::Parser;
use num::Integer;
use primus_lattice::ggsw::DcrtGgsw;
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

/// Per-phase timing breakdown for the protocol.
/// The field names correspond to the internal measurement points in
/// `protocol::run_compute_time_protocol`.
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
                panic!("Party count {p} is not power of two!")
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

    let params = if party_count <= 16 {
        if !GT16 && !GT128 {
            SsleParameters::new(party_count)
        } else {
            error!("Don't enable feature `gt16` and `gt128` for party count: {party_count}<=16!");
            panic!("Don't enable feature `gt16` and `gt128` for party count: {party_count}<=16!");
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
        party_count,
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

        let ggsw = DcrtGgsw::<Vec<CrtValueT>>::zero(rns_ggsw_len);
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

        let size1 = (ggsw.byte_count() * (party_count - 1)) as f64 * factor / 1024.0;
        let size2 = encode_commits_size as f64 * factor / 1024.0;

        let single_size1 = ggsw.byte_count() as f64 * factor / 1024.0;
        let single_size2 = size2 / party_count as f64;

        let size2 = single_size2 * (party_count - 1) as f64;

        debug!("First Round single size: {single_size1}KB");
        debug!("Second Round single size: {single_size2}KB");

        debug!("First Round size: {size1}KB");
        debug!("Second Round size: {size2}KB");

        let p0_e_share_len = big_uint_value_len * 2;
        let dec_size1 = p0_e_share_len as f64
            * 8.0
            * (delta_prime_bits as f64 / (big_uint_value_len as f64 * 64.0))
            / 1024.0;
        let p0_big_uint_len = big_uint_value_len * 2;
        let single_dec_size2 = p0_big_uint_len as f64
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
