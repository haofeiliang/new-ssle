# Relect

## Abstract

In a single secret leader election (SSLE) protocol, all parties collectively and obliviously elect one leader. Parties other than the selected leader should not be able to learn the identity of the leader unless it is revealed by the leader itself. The problem is first formalized by Boneh *et al.* (AFT 2020), and the first concretely feasible lattice-based SSLE with proof-of-concept implementations, $\mathsf{Qelect}$, was recently introduced by Wang and Zhang (USENIX 2025).

In this work, we present $\mathsf{Relect}$, an efficient SSLE protocol, based on the Ring Learning with Error assumption. We build it by leveraging the algebraic structure of the underlying threshold Fully Homomorphic Encryption (FHE) and by designing tailored homomorphic circuits. Compared to prior works, $\mathsf{Relect}$ (1) achieves substantially higher efficiency and (2) removes the strong environment assumption in $\mathsf{Qelect}$ (a trusted setup), and thereby also allows a dynamic leader selection for each round.

Concretely, for $32$ -- $2048$ parties, our local FHE computation runtime achieves $7.15$ -- $42.4\times$ faster than $\mathsf{Qelect}$, which **is** the major efficiency bottleneck of the entire SSLE procedure. Furthermore, we show that for the same parameters, our communication cost is also $1.14$ -- $2\times$ smaller. As mentioned, this is achieved while removing the trusted setup.

In terms of end-to-end runtime, following $\mathsf{Qelect}$, we tested $2$ -- $128$ parties. we show that under the LAN setting, $\mathsf{Relect}$ is $2.77$ -- $335\times$ faster than $\mathsf{Qelect}$ per round. Under the WAN setting, $\mathsf{Relect}$ is $1.94$ to $17.2\times$ faster than $\mathsf{Qelect}$. Note that these performance gains are all achieved while removing the trusted assumption and achieving dynamic leader selection for each round.

## Code structure

```
new-ssle/
├── ssle_core/                  # Main library crate
│   ├── src/
│   │   ├── lib.rs              # Crate root, re-exports
│   │   ├── parameters.rs       # SSLE parameter sets (party-count-dependent)
│   │   ├── keygen/             # Key generation (Setup in Algorithm 2)
│   │   ├── master_public_key.rs
│   │   ├── master_secret_key.rs
│   │   ├── party.rs            # Networked Party abstraction (TCP via tokio)
│   │   ├── fast_path.rs        # u128 modular arithmetic for small-modulus fast path
│   │   └── protocol.rs         # Shared protocol helpers (this is the core)
│   └── examples/
│       ├── ssle.rs             # Full distributed election (real TCP networking)
│       ├── ssle_compute_time.rs        # Single-party simulation, G ≤ 128
│       └── ssle_ge_256_compute_time_improve.rs  # Same, G ≥ 256 (RGSW capped at 128)
├── network/                    # TCP networking library (pairwise channels)
├── network2/                   # TCP networking library (collect / tree topologies)
├── run_bench.ps1               # Benchmark script (Windows)
└── run_bench.sh                # Benchmark script (Linux; untested on macOS)
```

### Key module: `ssle_core::protocol`

The protocol logic is centralized in `protocol.rs`. It provides:

- **Leaf helper functions** — one per protocol step, operating in-place on pre-allocated
  buffers. Each function's doc comment maps it to the paper (Algorithm 2 line numbers
  and/or Ajax 2025/1834 Figure 10 steps):
  - `external_product_chain` — RGSW external product accumulation (§4.3.1)
  - `expand_selectors` — coefficient expansion → per-party selectors
  - `rerandomize_commit` — commit re-randomization
  - `encode_single_commit` — selector × commit inner product (CRT basis)
  - `aggregate_encode_commits` — sum all parties' encoded commits
  - `decrypt_and_compose_slot` — phase decrypt + INTT + RNS compose
  - `decrypt_share_for_party` — full per-party distributed decryption share
  - `div_v_inplace` — ring folding (u⁻¹ factor, §4.5)
  - `decode_commit` — recover leader's small RLWE ciphertext

- **`run_compute_time_protocol`** — orchestrates all phases for the two
  compute-time examples, returning per-phase timings.

### Examples

| Example | Purpose | Networking |
|---------|---------|-----------|
| `ssle` | Real distributed election. Each party runs in its own OS thread with TCP communication. Verifies the leader identity. | Yes |
| `ssle_compute_time` | Single-party simulation, $G \leq 128$. Measures only FHE computation time (no network I/O). Reports per-phase timing and communication estimates. | No |
| `ssle_ge_256_compute_time_improve` | Same as above, $G \geq 256$. RGSW count fixed at 128 via subset sampling (§2.5). | No |

## Prerequisites

### Rust toolchains

Two toolchains are required:

| Toolchain | Purpose |
|-----------|---------|
| **stable** | Build and run functional examples (`ssle`). Requires Rust 2024 edition. Tested on 1.95.0. |
| **nightly** | Benchmark with SIMD (`run_bench.ps1 -c nightly -s`). Tested on 1.97.0-nightly. |

Install both via rustup:

```bash
rustup install stable
rustup install nightly
```

Verify:

```bash
rustc --version     # e.g. rustc 1.95.0
cargo --version
rustup run nightly rustc --version
```

### Platform

- Tested on **Windows 11** and **Linux**. macOS is not tested.
- **AVX-512** support is required for the SIMD feature (used in benchmarks).
- For the `ssle` example (real distributed execution), $G$ CPU cores are needed when testing $G$ parties.

## Quick start

### Party count → feature mapping

| party count $G$ | features | example |
|---|---|---|
| $2 \dots 16$ | *(none)* | `ssle_compute_time` |
| $32 \dots 128$ | `gt16` | `ssle_compute_time` |
| $256 \dots 2048$ | `gt128` | `ssle_ge_256_compute_time_improve` |

### Functional test: real distributed election

```bash
cargo run --release --package ssle_core --example ssle -- -p 4
```

### Compute-time benchmark: single-party simulation

```bash
# G = 2 .. 16
cargo run --release --package ssle_core --example ssle_compute_time -- -p 4

# G = 32 .. 128
cargo run --release --package ssle_core --example ssle_compute_time --features="gt16" -- -p 64

# G = 256 .. 2048 (improved variant with fixed RGSW count = 128)
cargo run --release --package ssle_core --example ssle_ge_256_compute_time_improve --features="gt128" -- -p 256
```

## Log output

By default the subscriber uses `EnvFilter` with a `DEBUG` default directive, so all messages
appear. To see only key results, set `RUST_LOG=info`:

```bash
RUST_LOG=info cargo run --release --package ssle_core --example ssle_compute_time -- -p 4
```

Each `[Phase X/5]` log line references a step in Algorithm 2 of the paper. Phase 4
(distributed decryption) uses the "mask-then-open" protocol from Ajax (ePrint 2025/1834,
Figure 10).

## Examples

### `ssle` — real distributed election

Runs the full protocol with actual TCP communication between $G$ threads.

```bash
cargo run --release --package ssle_core --example ssle -- -p 4
```

Expected output:

```text
Party count: 4
Thread count per party: 1
Key Generation done!

Party 0: I'm leader!

leader: 0
```

### `ssle_compute_time` — FHE computation time, $G \leq 128$

Simulates all parties locally in a single thread. Reports per-phase computation time
(no network I/O) and communication cost estimates.

```bash
cargo run --release --package ssle_core --example ssle_compute_time -- -p 4
```

Expected output:

```text
Party count: 4
Key Generation done!
=== SSLE Protocol === 4 parties, 4 RGSWs, ring_poly_length = 4096 ===
Expected leader (secret): party 0
[Phase 1/5] External product chain — accumulating 4 RGSW ciphertexts
[Phase 2/5] Coefficient expansion → 4 selectors
[Phase 3/5] Commit re-randomization, encoding & aggregation
[Phase 4/5] Distributed decryption — 4 parties computing shares
  Parties 1..3 start (not timed — parallel in real execution)
  Parties 1..3 shares complete
  Party 0 computing its share (timed as distributed_decrypt)
  Party 0 aggregation complete
[Phase 5/5] Verification — recovering leader's commit & decrypting
✓ Result: party 0 elected as leader
+-----------------------------+----------+
| rlwe_mul_rgsw               | ~2.2ms   |
+-----------------------------+----------+
| expand_coefficients         | ~0.6ms   |
+-----------------------------+----------+
| compute_local_encode_commit | ~0.4ms   |
+-----------------------------+----------+
| compute_final_encode_commit | ~0.05ms  |
+-----------------------------+----------+
| distributed_decrypt          | ~0.5ms   |
+-----------------------------+----------+
| decrypt_commit              | ~0.02ms  |
+-----------------------------+----------+
| all_compute                 | ~3.7ms   |
+-----------------------------+----------+
First Round single size: 600KB
Second Round single size: 200KB
First Round size: 1800KB
Second Round size: 600KB
communication size: ~2400KB (~2.3MB)
```

### `ssle_ge_256_compute_time_improve` — FHE computation time, $G \geq 256$

Same as above but caps the RGSW count at 128 (subset sampling, paper §2.5).

```bash
cargo run --release --package ssle_core --example ssle_ge_256_compute_time_improve --features="gt128" -- -p 256
```

Expected output:

```text
Party count: 256
Key Generation done!
=== SSLE Protocol === 256 parties, 128 RGSWs, ring_poly_length = NNN ===
Expected leader (secret): party 135
[Phase 1/5] External product chain — accumulating 128 RGSW ciphertexts
[Phase 2/5] Coefficient expansion → 256 selectors
[Phase 3/5] Commit re-randomization, encoding & aggregation
[Phase 4/5] Distributed decryption — 256 parties computing shares
  Parties 1..255 start (not timed — parallel in real execution)
  Parties 1..255 shares complete
  Party 0 computing its share (timed as distributed_decrypt)
  Party 0 aggregation complete
[Phase 5/5] Verification — recovering leader's commit & decrypting
✓ Result: party 135 elected as leader
+-----------------------------+---------------+
| rlwe_mul_rgsw               | ~130ms        |
+-----------------------------+---------------+
| expand_coefficients         | ~138ms        |
+-----------------------------+---------------+
| compute_local_encode_commit | ~42ms         |
+-----------------------------+---------------+
| compute_final_encode_commit | ~4.4ms        |
+-----------------------------+---------------+
| distributed_decrypt          | ~0.02ms       |
+-----------------------------+---------------+
| decrypt_commit              | ~0.02ms       |
+-----------------------------+---------------+
| all_compute                 | ~314ms        |
+-----------------------------+---------------+
```

## Reproducing paper benchmarks

The paper's compute-time results are obtained with the **nightly** toolchain and **SIMD**
feature enabled:

```powershell
# Windows (PowerShell)
.\run_bench.ps1 -c nightly -s
```

```bash
# Linux (untested on macOS)
bash run_bench.sh -c nightly -s
```

This runs the full benchmark suite (5 repetitions per data point, all party counts
2 … 2048) and writes results to `results/`. For a quick single-point test:

```powershell
cargo +nightly run --release --package ssle_core --example ssle_compute_time --features="simd" -- -p 128
```

### Script options

| Flag | Description |
|------|-------------|
| `-r N` | Number of repetitions (default: 5) |
| `-t "T1,T2,..."` | Thread counts (default: `"1"`) |
| `-c nightly` | Use nightly toolchain |
| `-s` | Enable SIMD feature |

## Notes

- The `ssle` example spawns one OS thread per party and communicates over TCP on `localhost`. Ensure port range `30000..30000+party_count` is available.
- Benchmark scripts suppress log output during runs (`RUST_LOG=off` at binary invocation only) to keep result files clean. Running examples manually after the script is not affected.
- The distributed decryption technique is from Ajax (ePrint [2025/1834](https://eprint.iacr.org/2025/1834), §4.3, Fig. 10), adapted with pre-shared independent randoms.
