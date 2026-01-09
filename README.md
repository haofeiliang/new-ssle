# Relect

## Install Rust

This project relies on Rust and the nightly toolchain. Installation can be done by following these steps:

1. Install Rust using rustup (the recommended Rust installer):
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. After installation, verify Rust is installed correctly:
   ```bash
   rustc --version
   cargo --version
   ```

3. Install the nightly toolchain:
   ```bash
   rustup toolchain install nightly
   ```

4. Verify the nightly toolchain is available:
   ```bash
   rustc +nightly --version
   ```

For more information, see the [Rust installation guide](https://www.rust-lang.org/tools/install).

## Run examples

### Examples:
- `ssle_core/exmaples/check_commit.rs`: Check the correctness of the commit encryption and decryption.
- `ssle_core/exmaples/ssle.rs`: Simulate multi parties on local computer (You needs $G$ cores on your computer for testing $G$ parties.).
- `ssle_core/exmaples/ssle_compute_time.rs`: Test the compute time (Test single party, the data of other parties is generated in advance).
- `ssle_core/exmaples/ssle_ge_256_compute_time_improve.rs`: Test the improved compute time with the $G>128$ (Test single party, the data of other parties is generated in advance).

### Parameters:
- `party-count` or `p`: G, the number of parties

### For AVX512 support:

Note: AVX512 support requires:
1. Nightly Rust toolchain
2. CPU with AVX512 support
3. `--features="nightly"` flag when running

### Run our codes with parties count $G$ in [2, 4, 8, 16, 32]

```bash
cargo run --release --package ssle_core --example ssle_compute_time -- -p 4
# or enable avx512
cargo +nightly run --release --package ssle_core --example ssle_compute_time --features="nightly" -- -p 4
```

Expected output:
```txt
Party count: 4
Key Generation done!

Party 1: I'm leader!
First Round single size: 600KB
Second Round single size: 200KB
First Round size: 1800KB
Second Round size: 600KB
communication size: 2400KB
communication size: 2.34375MB
+-----------------------------+------------+
| rlwe_mul_rgsw               | 2.95731ms  |
+-----------------------------+------------+
| expand_coefficients         | 927.951µs  |
+-----------------------------+------------+
| compute_local_encode_commit | 404.419µs  |
+-----------------------------+------------+
| compute_final_encode_commit | 48.361µs   |
+-----------------------------+------------+
| decrypt_commit              | 11.251µs   |
+-----------------------------+------------+
| all_compute                 | 4.349292ms |
+-----------------------------+------------+
| all                         | 4.615652ms |
+-----------------------------+------------+
```

### Run our codes with parties count $G$ in [64, 128]

```bash
cargo run --release --package ssle_core --example ssle_compute_time --features="gt32" -- -p 64
# or enable avx512
cargo +nightly run --release --package ssle_core --example ssle_compute_time --features="nightly gt32" -- -p 64
```

Expected output:
```txt
Party count: 64
Key Generation done!

Party 61: I'm leader!
First Round single size: 1000KB
Second Round single size: 200KB
First Round size: 63000KB
Second Round size: 12600KB
communication size: 75600KB
communication size: 73.828125MB
+-----------------------------+-------------+
| rlwe_mul_rgsw               | 46.097077ms |
+-----------------------------+-------------+
| expand_coefficients         | 26.433379ms |
+-----------------------------+-------------+
| compute_local_encode_commit | 7.405105ms  |
+-----------------------------+-------------+
| compute_final_encode_commit | 879µs       |
+-----------------------------+-------------+
| decrypt_commit              | 23.554µs    |
+-----------------------------+-------------+
| all_compute                 | 80.838115ms |
+-----------------------------+-------------+
| all                         | 81.161612ms |
+-----------------------------+-------------+
```

### Run our codes with parties count $G$ in [256, 512, 1024, 2048]

```bash
cargo run --release --package ssle_core --example ssle_ge_256_compute_time_improve --features="gt128" -- -p 256
# or enable avx512
cargo +nightly run --release --package ssle_core --example ssle_ge_256_compute_time_improve --features="nightly gt128" -- -p 256
```

Expected output:
```text
Party count: 256
Key Generation done!

Party 135: I'm leader!
+-----------------------------+--------------+
| rlwe_mul_rgsw               | 129.661389ms |
+-----------------------------+--------------+
| expand_coefficients         | 138.326706ms |
+-----------------------------+--------------+
| compute_local_encode_commit | 41.902945ms  |
+-----------------------------+--------------+
| compute_final_encode_commit | 4.358487ms   |
+-----------------------------+--------------+
| decrypt_commit              | 22.242µs     |
+-----------------------------+--------------+
| all_compute                 | 314.271769ms |
+-----------------------------+--------------+
| all                         | 314.648836ms |
+-----------------------------+--------------
```

## Notes

Our benchmark data was obtained through testing on a platform equipped with AVX-512 instructions.