#!/bin/bash
# Parse benchmark result files and compute average all_compute time per party count.
# Outputs CSV rows: scheme, party_count, avg_all_compute_ms
#
# Usage: ./analyze_bench.sh <result-file> [--data-only] [--stats]
#   --data-only   suppress the header lines, print only CSV data
#   --stats       append a statistics table (stddev, min, max) after the CSV output

set -euo pipefail

# --- Parse arguments ---
data_only=0
stats=0
input_file=""

for arg in "$@"; do
    case "$arg" in
        --data-only) data_only=1 ;;
        --stats)     stats=1 ;;
        *)
            if [ -z "$input_file" ]; then
                input_file="${arg//\\//}"
            else
                echo "Usage: $0 <benchmark-result-file> [--data-only] [--stats]" >&2
                exit 2
            fi
            ;;
    esac
done

if [ -z "$input_file" ]; then
    echo "Usage: $0 [--data-only] [--stats] <benchmark-result-file>" >&2
    exit 2
fi

if [ ! -f "$input_file" ]; then
    echo "Input file not found: $input_file" >&2
    exit 1
fi

# --- Check for awk (requires gawk for the 3-argument match() function) ---
if ! command -v awk >/dev/null 2>&1; then
    echo "awk not found" >&2
    exit 1
fi

# --- Parse the benchmark output with awk ---
awk '
# Convert a time value with unit to milliseconds
function to_ms(value, unit) {
    if (unit == "s")              return value * 1000.0
    if (unit == "ms")             return value
    if (unit == "us" || unit == "µs" || unit == "μs") return value / 1000.0
    if (unit == "ns")             return value / 1000000.0

    printf("Unsupported time unit: %s\n", unit) > "/dev/stderr"
    exit 1
}

# Detect party count section header, e.g. "--- Testing p=4 ---"
match($0, /--- Testing p=([0-9]+)/, p_match) {
    current_p = p_match[1]
    seen[current_p] = 1
    next
}

# Detect thread count from result file header
thread_count == "" && match($0, /Results for thread count t=([0-9]+)/, thread_match) {
    thread_count = thread_match[1]
    next
}

# Extract all_compute elapsed time, e.g. "| all_compute        | 1.234 ms |"
current_p != "" && match($0, /\|[[:space:]]*all_compute[[:space:]]*\|[[:space:]]*([0-9]+(\.[0-9]+)?)[[:space:]]*(ns|us|µs|μs|ms|s)[[:space:]]*\|/, time_match) {
    v = to_ms(time_match[1] + 0.0, time_match[3])
    sums[current_p]   += v
    counts[current_p] += 1
    idx[current_p]++
    vals[current_p, idx[current_p]] = v
}

END {
    # Default to single-threaded if not found (older result files may lack the header)
    if (thread_count == "") thread_count = 1

    if (thread_count == 1) {
        scheme = "Relect"
    } else {
        scheme = sprintf("Relect(%d threads)", thread_count)
    }

    if (!data_only) {
        print "Input: " input_file
        print "scheme, party_count, avg_all_compute_ms"
    }

    # Collect party counts that have results, then sort them numerically
    found = 0
    for (p in seen) {
        if (counts[p] > 0) {
            found = 1
            ordered[++n] = p + 0
        }
    }

    if (!found) {
        printf("No all_compute results found in: %s\n", input_file) > "/dev/stderr"
        exit 1
    }

    # Simple sort (party counts are few, bubble sort is fine)
    for (i = 1; i <= n; i++) {
        for (j = i + 1; j <= n; j++) {
            if (ordered[i] > ordered[j]) {
                tmp = ordered[i]
                ordered[i] = ordered[j]
                ordered[j] = tmp
            }
        }
    }

    # Output sorted CSV results
    for (i = 1; i <= n; i++) {
        p = ordered[i]
        printf "%s, %d, %.6f\n", scheme, p, sums[p] / counts[p]
    }

    # --- Statistics table (optional) ---
    if (stats) {
        printf "\n"
        print "--- Statistics ---"
        print "scheme, party_count, runs, avg_ms, stddev_ms, min_ms, max_ms"

        for (i = 1; i <= n; i++) {
            p = ordered[i]
            c = counts[p]
            m = sums[p] / c

            if (c < 2) {
                printf "%s, %d, %d, %.6f, %s, %.6f, %.6f\n", scheme, p, c, m, "N/A", m, m
                continue
            }

            # Sample standard deviation
            ss = 0
            for (j = 1; j <= c; j++) {
                d = vals[p, j] - m
                ss += d * d
            }
            stddev = sqrt(ss / (c - 1))

            # Min / max
            minv = vals[p, 1]
            maxv = vals[p, 1]
            for (j = 2; j <= c; j++) {
                if (vals[p, j] < minv) minv = vals[p, j]
                if (vals[p, j] > maxv) maxv = vals[p, j]
            }

            printf "%s, %d, %d, %.6f, %.6f, %.6f, %.6f\n", scheme, p, c, m, stddev, minv, maxv
        }
    }
}
' data_only="$data_only" stats="$stats" input_file="$input_file" "$input_file"
