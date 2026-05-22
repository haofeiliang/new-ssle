#!/bin/bash
# Parse benchmark result files and compute average all_compute time per party count.
# Outputs CSV rows: scheme, party_count, avg_all_compute_ms
#
# Usage: ./analyze_bench.sh [--data-only] <result-file>
#   --data-only   suppress the header lines, print only CSV data

set -euo pipefail

# --- Parse arguments ---
data_only=0
if [ "$#" -eq 2 ] && [ "$1" = "--data-only" ]; then
    data_only=1
    input_file="${2//\\//}"
elif [ "$#" -eq 1 ]; then
    input_file="${1//\\//}"
else
    echo "Usage: $0 [--data-only] <benchmark-result-file>" >&2
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
    sums[current_p]   += to_ms(time_match[1] + 0.0, time_match[3])
    counts[current_p] += 1
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

    # Output sorted results
    for (i = 1; i <= n; i++) {
        p = ordered[i]
        printf "%s, %d, %.6f\n", scheme, p, sums[p] / counts[p]
    }
}
' data_only="$data_only" input_file="$input_file" "$input_file"
