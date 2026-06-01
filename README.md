# Relect

## Abstract

In a single secret leader election (SSLE) protocol, all parties collectively and obliviously elect one leader. Parties other than the selected leader should not be able to learn the identity of the leader unless it is revealed by the leader itself. The problem is first formalized by Boneh *et al.* (AFT 2020), and the first concretely feasible lattice-based SSLE with proof-of-concept implementations, $\mathsf{Qelect}$, was recently introduced by Wang and Zhang (USENIX 2025).

In this work, we present $\mathsf{Relect}$, an efficient SSLE protocol, based on the Ring Learning with Error assumption. We build it by leveraging the algebraic structure of the underlying threshold Fully Homomorphic Encryption (FHE) and by designing tailored homomorphic circuits. Compared to prior works, $\mathsf{Relect}$ (1) achieves substantially higher efficiency and (2) removes the strong environment assumption in $\mathsf{Qelect}$ (a trusted setup), and thereby also allows a dynamic leader selection for each round.

Concretely, for $32$ -- $2048$ parties, our local FHE computation runtime achieves $7.15$ -- $42.4\times$ faster than $\mathsf{Qelect}$, which **is** the major efficiency bottleneck of the entire SSLE procedure. Furthermore, we show that for the same parameters, our communication cost is also $1.14$ -- $2\times$ smaller. As mentioned, this is achieved while removing the trusted setup.

In terms of end-to-end runtime, following $\mathsf{Qelect}$, we tested $2$ -- $128$ parties. we show that under the LAN setting, $\mathsf{Relect}$ is $2.77$ -- $335\times$ faster than $\mathsf{Qelect}$ per round. Under the WAN setting, $\mathsf{Relect}$ is $1.94$ to $17.2\times$ faster than $\mathsf{Qelect}$. Note that these performance gains are all achieved while removing the trusted assumption and achieving dynamic leader selection for each round.

## Code structure

```text
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
│       ├── ssle_compute_time.rs        # FHE benchmark, G ≤ 128
│       └── ssle_ge_256_compute_time_improve.rs  # Same, G ≥ 256 (only 128 RGSWs)
├── network/                    # TCP networking library (pairwise channels)
├── network2/                   # TCP networking library (collect / tree topologies)
├── run_bench.ps1               # Benchmark script (Windows)
├── run_bench.sh                # Benchmark script (Ubuntu & macOS)
├── analyze_bench.ps1           # Result analysis (Windows)
└── analyze_bench.sh            # Result analysis (Ubuntu & macOS)
```

### Key module: `ssle_core::protocol`

The protocol logic lives in `protocol.rs`. It provides:

- **Helper functions** — one per protocol step. Each function's doc comment maps
  it to the paper (Algorithm 2 line numbers and/or Ajax 2025/1834 Figure 10
  steps):
  - `external_product_chain` — RGSW external product accumulation (§4.3.1)
  - `expand_selectors` — coefficient expansion → per-party selectors
  - `rerandomize_commit` — commit re-randomization
  - `encode_single_commit` — selector × commit inner product (CRT basis)
  - `aggregate_encode_commits` — sum all parties' encoded commits
  - `decrypt_and_compose_slot` — phase decrypt + INTT + RNS compose
  - `decrypt_share_for_party` — full per-party distributed decryption share
  - `div_v_inplace` — ring folding (u⁻¹ factor, §4.5)
  - `decode_commit` — recover leader's small RLWE ciphertext

- **`run_compute_time_protocol`** — runs all phases for the two compute-time
  examples and returns per-phase timings.

### Examples

| Example | Purpose | Networking |
|---------|---------|-----------|
| `ssle` | Real distributed election. Each party runs in its own OS thread with TCP communication. Verifies the leader identity. | Yes |
| `ssle_compute_time` | FHE benchmark, $G \leq 128$. Measures only computation time (no network I/O). Reports per-phase timing and communication estimates. | No |
| `ssle_ge_256_compute_time_improve` | Same as above, $G \geq 256$. Uses only 128 RGSW ciphertexts via subset sampling (§2.5). | No |

## Prerequisites

### Rust toolchains

Two toolchains are needed:

| Toolchain | Purpose |
|-----------|---------|
| **stable** | Build and run functional examples (`ssle`). Requires Rust 2024 edition. Tested on 1.95.0. |
| **nightly** | Benchmark with SIMD (`run_bench.ps1 -c nightly -s`). Tested on 1.97.0-nightly. |

Install Rust via <https://rustup.rs>:

- **Windows**: download and run `rustup-init.exe`.
- **Linux / macOS**: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`

The stable toolchain is included by default. Install nightly:

```bash
rustup install nightly
```

Verify:

```bash
rustc --version     # e.g. rustc 1.95.0
cargo --version
rustup run nightly rustc --version
```

### Platform

- Tested on **Windows 11**, **Ubuntu**, and **macOS**.
- The `simd` feature uses Rust's `portable_simd` and does not require a specific CPU feature.
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

### Compute-time benchmark

```bash
# G = 2 .. 16
cargo run --release --package ssle_core --example ssle_compute_time -- -p 4

# G = 32 .. 128
cargo run --release --package ssle_core --example ssle_compute_time --features="gt16" -- -p 64

# G = 256 .. 2048 (only 128 RGSW ciphertexts, subset sampling §2.5)
cargo run --release --package ssle_core --example ssle_ge_256_compute_time_improve --features="gt128" -- -p 256
```

## Log output

By default, the logger shows all messages at `DEBUG` level and above.
To see only key results, set `RUST_LOG=info`:

```bash
RUST_LOG=info cargo run --release --package ssle_core --example ssle_compute_time -- -p 4
```

Each `[Phase X/5]` log line matches a step in Algorithm 2 of the paper. Phase 4 (distributed decryption) follows the protocol from Ajax (ePrint [2025/1834](https://eprint.iacr.org/2025/1834), §4.3, Fig. 10).

## Examples

### `ssle` — real distributed election

Runs the full protocol with actual TCP communication between $G$ threads.

```bash
cargo run --release --package ssle_core --example ssle -- -p 4
```

Expected output:

```log
  INFO Party count: 4
  INFO Thread count per party: 1
  INFO Key Generation done!
 DEBUG [Offline] Share commits & public keys (Alg.2 lines 10-13, §4.2 GenInstance)
 DEBUG [Round 1/4] Share RGSW, external product & coefficient expansion (Alg.2 lines 14-15, 20-22; §4.2 GenInstance + §4.3.1 ParElect)
 DEBUG [Round 2/4] Share encoded commits & aggregate (Alg.2 lines 24-28, 31-32; §4.3.1 ParElect + §4.3.2 Elect)
 DEBUG [Round 3/4] Share e-shares → Party 0 aggregate & center (Ajax 2025/1834 Fig.10 steps 1-2; Alg.2 lines 33-34, §4.3.2 Elect)
 DEBUG [Round 4/4] Share value shares → Combine (Ajax 2025/1834 Fig.10 steps 3-4; Alg.2 lines 36-38, §4.4 Combine)
 DEBUG [Final] Verification — div_v, decode, decrypt (Alg.2 lines 39-43, §4.5 Verify)
  INFO ✓ Result: party 1 elected as leader
  INFO All parties agree: leader is party 1
```

### `ssle_compute_time` — FHE computation time, $G \leq 128$

Measures only computation time (no network I/O). Reports per-phase timing and communication cost estimates.

```bash
cargo run --release --package ssle_core --example ssle_compute_time -- -p 4
```

Expected output:

```log
  INFO Party count: 4
 DEBUG Key Generation done!
  INFO === SSLE Protocol === 4 parties, 4 RGSWs, ring_poly_length = 4096 ===
 DEBUG Expected leader (secret): party 1
 DEBUG [Phase 1/5] External product chain — accumulating 4 RGSW ciphertexts
 DEBUG [Phase 2/5] Coefficient expansion → 4 selectors
 DEBUG [Phase 3/5] Commit re-randomization, encoding & aggregation
 DEBUG [Phase 4/5] Distributed decryption — 4 parties computing shares
 DEBUG   Parties 1..3 start (not timed — parallel in real execution)
 DEBUG   Parties 1..3 shares complete
 DEBUG   Party 0 computing its share (timed as distributed_decrypt)
 DEBUG   Party 0 aggregation complete
 DEBUG [Phase 5/5] Verification — recovering leader's commit & decrypting
  INFO ✓ Result: party 1 elected as leader
+-----------------------------+-----------+
| rlwe_mul_rgsw               | 5.9594ms  |
+-----------------------------+-----------+
| expand_coefficients         | 1.6977ms  |
+-----------------------------+-----------+
| compute_local_encode_commit | 1.2002ms  |
+-----------------------------+-----------+
| compute_final_encode_commit | 112.5µs   |
+-----------------------------+-----------+
| distributed_decrypt         | 1.373ms   |
+-----------------------------+-----------+
| decrypt_commit              | 21.9µs    |
+-----------------------------+-----------+
| all_compute                 | 10.3647ms |
+-----------------------------+-----------+
 DEBUG First Round single size: 600KB
 DEBUG Second Round single size: 200KB
 DEBUG First Round size: 1800KB
 DEBUG Second Round size: 600KB
 DEBUG Distributed Decryption First Round size: 0.021240234375KB
 DEBUG Distributed Decryption Second Round single size: 0.0244140625KB
 DEBUG Distributed Decryption Second Round size: 0.0732421875KB
 DEBUG communication size: 2400.094482421875KB
 DEBUG communication size: 2.3438422679901123MB
```

### `ssle_ge_256_compute_time_improve` — FHE computation time, $G \geq 256$

Same as above but uses only 128 RGSW ciphertexts regardless of party count (subset sampling, paper §2.5).

```bash
cargo run --release --package ssle_core --example ssle_ge_256_compute_time_improve --features="gt128" -- -p 256
```

Expected output:

```log
  INFO Party count: 256
 DEBUG Key Generation done!
  INFO === SSLE Protocol === 256 parties, 128 RGSWs, ring_poly_length = 4096 ===
 DEBUG Expected leader (secret): party 217
 DEBUG [Phase 1/5] External product chain — accumulating 128 RGSW ciphertexts
 DEBUG [Phase 2/5] Coefficient expansion → 256 selectors
 DEBUG [Phase 3/5] Commit re-randomization, encoding & aggregation
 DEBUG [Phase 4/5] Distributed decryption — 256 parties computing shares
 DEBUG   Parties 1..255 start (not timed — parallel in real execution)
 DEBUG   Parties 1..255 shares complete
 DEBUG   Party 0 computing its share (timed as distributed_decrypt)
 DEBUG   Party 0 aggregation complete
 DEBUG [Phase 5/5] Verification — recovering leader's commit & decrypting
  INFO ✓ Result: party 217 elected as leader
+-----------------------------+------------+
| rlwe_mul_rgsw               | 290.043ms  |
+-----------------------------+------------+
| expand_coefficients         | 240.4727ms |
+-----------------------------+------------+
| compute_local_encode_commit | 93.5674ms  |
+-----------------------------+------------+
| compute_final_encode_commit | 8.3653ms   |
+-----------------------------+------------+
| distributed_decrypt         | 8.4285ms   |
+-----------------------------+------------+
| decrypt_commit              | 57.1µs     |
+-----------------------------+------------+
| all_compute                 | 640.934ms  |
+-----------------------------+------------+
```

## Reproducing paper benchmarks

The paper's compute-time results were collected using the **nightly** toolchain and **SIMD** feature:

```powershell
# Windows (PowerShell)
.\run_bench.ps1 -c nightly -s
```

```bash
# Linux
bash run_bench.sh -c nightly -s
```

This runs the benchmarks for all party counts (G = 2..2048, 5 repetitions each) and writes results to `results/`. For a quick single-point test:

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
- Benchmark scripts turn off log output during runs (`RUST_LOG=off`) to keep result files clean. Running examples manually is not affected.
