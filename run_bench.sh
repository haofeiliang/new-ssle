#!/bin/bash
# 用法: ./run_bench.sh [重复次数] [线程数列表]
# 线程数列表格式：逗号分隔的数字，例如 "1,2,4,8,16"；默认为 "1"（只测单线程）
# 示例: ./run_bench.sh 5 "1,2,4,8,16,32"

set -e

REPEATS=${1:-5}
THREADS_ARG=${2:-"1"}

IFS=',' read -ra THREADS <<< "$THREADS_ARG"

OUTPUT_DIR="results"
mkdir -p "$OUTPUT_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo "Results will be saved to ${OUTPUT_DIR}/benchmark_${TIMESTAMP}_t*.txt"
echo "Thread counts to test: ${THREADS[*]}"

# 为每个线程数创建输出文件，写入头部
for t in "${THREADS[@]}"; do
    OUTFILE="${OUTPUT_DIR}/benchmark_${TIMESTAMP}_t${t}.txt"
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
        OUTFILE="${OUTPUT_DIR}/benchmark_${TIMESTAMP}_t${t}.txt"

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

        echo "--- Thread t=$t, features: '$features' ---" | tee -a "$OUTFILE"

        # 检查当前 features 是否与上一次构建的 features 相同
        if [ "$features" != "$last_features" ]; then
            echo "Features changed from '$last_features' to '$features'. Rebuilding..." | tee -a "$OUTFILE"
            cargo build --release \
                --package ssle_core \
                --example "$example" \
                --features="$features" >> "$OUTPUT_DIR/build_log.txt" 2>&1
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

                RUST_LOG=off cargo run --release \
                    --package ssle_core \
                    --example "$example" \
                    --features="$features" \
                    -- -p "$p" $t_args >> "$OUTFILE" 2>&1

                echo "--- End run $i for p=$p, t=$t ---" >> "$OUTFILE"
                sleep 1   # 短暂休息，避免资源争用
            done
        done
    done
done

echo "Benchmark completed. Results in ${OUTPUT_DIR}/benchmark_${TIMESTAMP}_t*.txt"