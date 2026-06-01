#!/bin/bash
# Usage: ./run_bench.sh [OPTIONS]
#   -r, --repeat N      number of runs per test (default: 5)
#   -t, --threads LIST  comma-separated thread counts (default: "1")
#   -c, --toolchain TC  cargo toolchain, e.g. "nightly" or "+nightly"
#   -s, --simd          enable simd feature
#
# Examples:
#   ./run_bench.sh -r 5 -t "1,2,4,8,16,32" -c nightly
#   ./run_bench.sh -c nightly -s

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

# --- Defaults ---
REPEATS=5
THREADS_ARG="1"
TOOLCHAIN_ARG=""
SIMD=false

# Parse arguments
while [ $# -gt 0 ]; do
    case "$1" in
        -r|--repeat)    REPEATS="$2"; shift 2 ;;
        -t|--threads)   THREADS_ARG="$2"; shift 2 ;;
        -c|--toolchain) TOOLCHAIN_ARG="$2"; shift 2 ;;
        -s|--simd)      SIMD=true; shift ;;
        -h|--help)      cat <<'USAGE'
Usage: ./run_bench.sh [OPTIONS]
  -r, --repeat N      number of runs per test (default: 5)
  -t, --threads LIST  comma-separated thread counts (default: "1")
  -c, --toolchain TC  cargo toolchain, e.g. "nightly" or "+nightly"
  -s, --simd          enable simd feature
  -h, --help          show this help message

Examples:
  ./run_bench.sh -r 5 -t "1,2,4,8,16,32" -c nightly
  ./run_bench.sh -c nightly -s
USAGE
                        exit 0 ;;
        *)              echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# Parse thread list
THREADS=()
IFS=',' read -ra RAW <<< "$THREADS_ARG"
for t in "${RAW[@]}"; do
    t=$(echo "$t" | xargs)
    [ -n "$t" ] && THREADS+=("$t")
done

# Normalize toolchain prefix
CARGO_TC=""
if [ -n "$TOOLCHAIN_ARG" ]; then
    [[ "$TOOLCHAIN_ARG" != +* ]] && TOOLCHAIN_ARG="+$TOOLCHAIN_ARG"
    CARGO_TC="$TOOLCHAIN_ARG"
fi

# --- System tuning for consistent benchmarks ---

# Raise process priority to reduce scheduling jitter
renice -n -10 -p $$ 2>/dev/null && echo "Process niceness: -10" || echo "Process priority: default (may need CAP_SYS_NICE or sudo)"

# Check CPU governor (Linux only; changing it requires root, so just warn)
if [ -f /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor ]; then
    governor=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null)
    if [ "$governor" = "performance" ]; then
        echo "CPU governor: performance (optimal)"
    else
        echo "WARNING: CPU governor is '$governor'. For consistent results:"
        echo "  sudo cpupower frequency-set -g performance"
    fi
fi

echo ""

# --- Output setup ---
OUTPUT_DIR="results"
mkdir -p "$OUTPUT_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M)

# Result file tag (append _nightly / _simd as needed)
RESULT_TAG="$TIMESTAMP"
if [ -n "$CARGO_TC" ] && [[ "$CARGO_TC" == *nightly* ]]; then
    RESULT_TAG="${TIMESTAMP}_nightly"
fi
if [ "$SIMD" = true ]; then
    RESULT_TAG="${RESULT_TAG}_simd"
fi

BUILD_LOG="$OUTPUT_DIR/build_log.txt"
: > "$BUILD_LOG"

echo "Results: ${OUTPUT_DIR}/${RESULT_TAG}_t*.txt"
echo "Build log: $BUILD_LOG"
echo "Threads: ${THREADS[*]}"
if [ -z "$CARGO_TC" ]; then
    echo "Toolchain: default"
else
    echo "Toolchain: $CARGO_TC"
fi
echo "SIMD: $SIMD"

# Init per-thread result files
for t in "${THREADS[@]}"; do
    OUTFILE="${OUTPUT_DIR}/${RESULT_TAG}_t${t}.txt"
    {
        echo "Results for thread count t=$t"
        echo "Repeat each test $REPEATS times"
        echo "=========================================="
    } > "$OUTFILE"
done

# Test blocks: "base_features|example|party_list"
BLOCKS=(
    "|ssle_compute_time|2 4 8 16"
    "gt16|ssle_compute_time|32 64 128"
    "gt128|ssle_ge_256_compute_time_improve|256 512 1024 2048"
)

LAST_FEATURES="random"

for block in "${BLOCKS[@]}"; do
    IFS='|' read -r base example p_list <<< "$block"
    echo "=========================================="
    echo "Block: features='$base', example='$example', parties={$p_list}"

    for t in "${THREADS[@]}"; do
        OUTFILE="${OUTPUT_DIR}/${RESULT_TAG}_t${t}.txt"

        # Assemble features: base + parallel (if multi-threaded)
        if [ "$t" -eq 1 ]; then
            features="$base"
            t_args=""
        else
            features="${base:+$base }parallel"
            t_args="-t $t"
        fi
        features=$(echo "$features" | xargs)

        # Append simd feature if requested
        if [ "$SIMD" = true ]; then
            features="${features:+$features }simd"
        fi

        echo "--- t=$t, features: '$features' ---" | tee -a "$OUTFILE"

        # Rebuild only when features change
        if [ "$features" != "$LAST_FEATURES" ]; then
            echo "Rebuilding (features: $LAST_FEATURES -> $features)..." | tee -a "$OUTFILE"
            cargo $CARGO_TC build --quiet --release \
                --package ssle_core \
                --example "$example" \
                --features="$features" >> "$BUILD_LOG"
            LAST_FEATURES="$features"
            echo "Build done." | tee -a "$OUTFILE"
            sleep 2
        else
            echo "Features unchanged, skip build." | tee -a "$OUTFILE"
        fi

        # Run the compiled binary directly (avoids cargo run overhead)
        BINARY="$SCRIPT_DIR/target/release/examples/$example"
        if [ ! -f "$BINARY" ]; then
            echo "Compiled binary not found: $BINARY" >&2
            exit 1
        fi

        for p in $p_list; do
            echo "--- Testing p=$p ---" | tee -a "$OUTFILE"
            for ((i=1; i<=REPEATS; i++)); do
                echo "Run $i/$REPEATS" | tee -a "$OUTFILE"
                RUST_LOG=off "$BINARY" -p "$p" $t_args >> "$OUTFILE"
                sleep 1
            done

            # Cooldown: longer pause after large party counts to avoid thermal throttling
            if [ "$p" -ge 1024 ]; then
                sleep 5
            elif [ "$p" -ge 512 ]; then
                sleep 3
            else
                sleep 0.5
            fi
        done
    done
done

echo "Benchmark completed. Results in ${OUTPUT_DIR}/${RESULT_TAG}_t*.txt"

# Run analysis
ANALYZE_SCRIPT="${SCRIPT_DIR}/analyze_bench.sh"
if [ ! -f "$ANALYZE_SCRIPT" ]; then
    echo "Analyze script not found: $ANALYZE_SCRIPT" >&2
    exit 1
fi

# When multiple thread counts are configured, label single-threaded as "Relect(1 thread)"
# so it's visually consistent with "Relect(N threads)".
MULTI_THREAD=0
[ ${#THREADS[@]} -gt 1 ] && MULTI_THREAD=1

echo
echo "Average all_compute time:"
echo "scheme, party_count, avg_all_compute_ms"
for t in "${THREADS[@]}"; do
    if [ "$MULTI_THREAD" -eq 1 ]; then
        bash "$ANALYZE_SCRIPT" "${OUTPUT_DIR}/${RESULT_TAG}_t${t}.txt" --data-only | sed 's/^Relect,/Relect(1 thread),/'
    else
        bash "$ANALYZE_SCRIPT" "${OUTPUT_DIR}/${RESULT_TAG}_t${t}.txt" --data-only
    fi
done

echo
echo "--- Statistics ---"
echo "scheme, party_count, runs, avg_ms, stddev_ms, min_ms, max_ms"
for t in "${THREADS[@]}"; do
    if [ "$MULTI_THREAD" -eq 1 ]; then
        bash "$ANALYZE_SCRIPT" "${OUTPUT_DIR}/${RESULT_TAG}_t${t}.txt" --data-only --stats | sed 's/^Relect,/Relect(1 thread),/'
    else
        bash "$ANALYZE_SCRIPT" "${OUTPUT_DIR}/${RESULT_TAG}_t${t}.txt" --data-only --stats
    fi
done
