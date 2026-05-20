#!/bin/bash
# 用法: ./run_bench.sh [重复次数] [线程数列表] [cargo toolchain] [-Simd]
# 线程数列表格式：逗号分隔的数字，例如 "1,2,4,8,16"；默认为 "1"（只测单线程）
# cargo toolchain 可选，例如 "+nightly" 或 "nightly"；默认为当前默认 toolchain
# -Simd 可选；只有显式传入时才启用 simd feature
# 示例: ./run_bench.sh 5 "1,2,4,8,16,32" +nightly
# 示例: ./run_bench.sh 5 "1,2,4,8,16,32" +nightly -Simd

set -e

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

REPEATS=${1:-5}
THREADS_ARG=${2:-"1"}
TOOLCHAIN_ARG=""
SIMD=false

if [ "$#" -ge 3 ]; then
    for arg in "${@:3}"; do
        case "$arg" in
            -Simd|--simd)
                SIMD=true
                ;;
            "")
                ;;
            *)
                if [ -z "$TOOLCHAIN_ARG" ]; then
                    TOOLCHAIN_ARG="$arg"
                else
                    echo "Unknown argument: $arg" >&2
                    exit 1
                fi
                ;;
        esac
    done
fi

THREADS=()
IFS=',' read -ra RAW_THREADS <<< "$THREADS_ARG"
for raw_t in "${RAW_THREADS[@]}"; do
    t=$(echo "$raw_t" | xargs)
    if [ -n "$t" ]; then
        THREADS+=("$t")
    fi
done

CARGO_TOOLCHAIN=()
if [ -n "$TOOLCHAIN_ARG" ]; then
    if [[ "$TOOLCHAIN_ARG" == +* ]]; then
        CARGO_TOOLCHAIN=("$TOOLCHAIN_ARG")
    else
        CARGO_TOOLCHAIN=("+$TOOLCHAIN_ARG")
    fi
fi

cargo_bench_flags() {
    local rustflags="${RUSTFLAGS:-}"

    if [[ "$rustflags" != *target-cpu* && "$rustflags" != *target_cpu* ]]; then
        rustflags="${rustflags:+$rustflags }-C target-cpu=native"
    fi

    if [[ "$rustflags" != *linker-messages* && "$rustflags" != *linker_messages* ]]; then
        rustflags="${rustflags:+$rustflags }-A linker-messages"
    fi

    if [ "${RUST_LOG+x}" ]; then
        RUSTFLAGS="$rustflags" RUST_LOG="$RUST_LOG" cargo "$@"
    else
        RUSTFLAGS="$rustflags" cargo "$@"
    fi
}

OUTPUT_DIR="results"
mkdir -p "$OUTPUT_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M)
RESULT_FILE_TAG="$TIMESTAMP"
if [ ${#CARGO_TOOLCHAIN[@]} -gt 0 ]; then
    TOOLCHAIN_NAME="${CARGO_TOOLCHAIN[0]#+}"
    if [[ "$TOOLCHAIN_NAME" == nightly* ]]; then
        RESULT_FILE_TAG="${TIMESTAMP}_nightly"
    fi
fi
if [ "$SIMD" = true ]; then
    RESULT_FILE_TAG="${RESULT_FILE_TAG}_simd"
fi

echo "Results will be saved to ${OUTPUT_DIR}/${RESULT_FILE_TAG}_t*.txt"
BUILD_LOG="${OUTPUT_DIR}/build_log.txt"
: > "$BUILD_LOG"
echo "Build log will be saved to ${BUILD_LOG}"
echo "Thread counts to test: ${THREADS[*]}"
if [ ${#CARGO_TOOLCHAIN[@]} -eq 0 ]; then
    echo "Cargo toolchain: default"
else
    echo "Cargo toolchain: ${CARGO_TOOLCHAIN[0]}"
fi
echo "SIMD feature: $SIMD"

# 为每个线程数创建输出文件，写入头部
for t in "${THREADS[@]}"; do
    OUTFILE="${OUTPUT_DIR}/${RESULT_FILE_TAG}_t${t}.txt"
    echo "Results for thread count t=$t" > "$OUTFILE"
    echo "Repeat each test $REPEATS times" >> "$OUTFILE"
    echo "==========================================" >> "$OUTFILE"
done

# 定义三个测试块：基础 feature | example | party count 列表
blocks=(
    "|ssle_compute_time|2 4 8 16"
    "gt16|ssle_compute_time|32 64 128"
    "gt128|ssle_ge_256_compute_time_improve|256 512 1024 2048"
)

# 记录上一次构建的 features（初始为一个不存在的features，确保第一次一定build）
last_features="random"

# 外层循环：遍历所有 block
for block in "${blocks[@]}"; do
    IFS='|' read -r base_features example p_list <<< "$block"
    echo "=========================================="
    echo "Processing block: base_features='$base_features', example='$example', p in {$p_list}"

    # 中层循环：遍历所有线程数 t
    for t in "${THREADS[@]}"; do
        OUTFILE="${OUTPUT_DIR}/${RESULT_FILE_TAG}_t${t}.txt"

        # 根据 t 确定 features 和命令行参数
        if [ "$t" -eq 1 ]; then
            features="$base_features"
            t_args=""
        else
            if [ -n "$base_features" ]; then
                features="${base_features} parallel"
            else
                features="parallel"
            fi
            t_args="-t $t"
        fi
        # 去除多余空格，使 features 字符串干净
        features=$(echo "$features" | xargs)

        if [ "$SIMD" = true ]; then
            features="${features} simd"
            features=$(echo "$features" | xargs)
        fi

        echo "--- Thread t=$t, features: '$features' ---" | tee -a "$OUTFILE"

        # 检查当前 features 是否与上一次构建的 features 相同
        if [ "$features" != "$last_features" ]; then
            echo "Features changed from '$last_features' to '$features'. Rebuilding..." | tee -a "$OUTFILE"
            cargo_bench_flags "${CARGO_TOOLCHAIN[@]}" build --quiet --release \
                --package ssle_core \
                --example "$example" \
                --features="$features" >> "$BUILD_LOG"
            last_features="$features"
            echo "Build completed. Sleeping 2 seconds..." | tee -a "$OUTFILE"
            sleep 2
        else
            echo "Features unchanged, skipping build." | tee -a "$OUTFILE"
        fi

        # 内层循环：对该 block 内的所有 p 运行测试
        for p in $p_list; do
            echo "--- Testing p=$p with features: '$features', example: $example ---" | tee -a "$OUTFILE"

            for ((i=1; i<=REPEATS; i++)); do
                echo "Run $i for p=$p, t=$t" | tee -a "$OUTFILE"

                RUST_LOG=off cargo_bench_flags "${CARGO_TOOLCHAIN[@]}" run --quiet --release \
                    --package ssle_core \
                    --example "$example" \
                    --features="$features" \
                    -- -p "$p" $t_args >> "$OUTFILE"

                echo "--- End run $i for p=$p, t=$t ---" >> "$OUTFILE"
                sleep 1   # 短暂休息，避免资源争用
            done
        done
    done
done

echo "Benchmark completed. Results in ${OUTPUT_DIR}/${RESULT_FILE_TAG}_t*.txt"

ANALYZE_SCRIPT="${SCRIPT_DIR}/analyze_bench.sh"
if [ ! -f "$ANALYZE_SCRIPT" ]; then
    echo "Analyze script not found: $ANALYZE_SCRIPT" >&2
    exit 1
fi

echo
echo "Average all_compute time:"
echo "scheme, party_count, avg_all_compute_ms"
for t in "${THREADS[@]}"; do
    OUTFILE="${OUTPUT_DIR}/${RESULT_FILE_TAG}_t${t}.txt"
    bash "$ANALYZE_SCRIPT" --data-only "$OUTFILE"
done
