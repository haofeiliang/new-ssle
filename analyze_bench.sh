#!/bin/bash

set -euo pipefail

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

if command -v awk >/dev/null 2>&1; then
    AWK_BIN=$(command -v awk)
elif [ -x /usr/bin/awk ]; then
    AWK_BIN=/usr/bin/awk
elif [ -x /bin/awk ]; then
    AWK_BIN=/bin/awk
else
    echo "awk not found" >&2
    exit 1
fi

"$AWK_BIN" '
function to_ms(value, unit) {
    if (unit == "s") {
        return value * 1000.0
    }
    if (unit == "ms") {
        return value
    }
    if (unit == "us" || unit == "µs" || unit == "μs") {
        return value / 1000.0
    }
    if (unit == "ns") {
        return value / 1000000.0
    }

    printf("Unsupported time unit: %s\n", unit) > "/dev/stderr"
    exit 1
}

match($0, /--- Testing p=([0-9]+)/, p_match) {
    current_p = p_match[1]
    seen[current_p] = 1
    next
}

thread_count == "" && match($0, /Results for thread count t=([0-9]+)/, thread_match) {
    thread_count = thread_match[1]
    next
}

current_p != "" && match($0, /\|[[:space:]]*all_compute[[:space:]]*\|[[:space:]]*([0-9]+(\.[0-9]+)?)[[:space:]]*(ns|us|µs|μs|ms|s)[[:space:]]*\|/, time_match) {
    sums[current_p] += to_ms(time_match[1] + 0.0, time_match[3])
    counts[current_p] += 1
    seen[current_p] = 1
}

END {
    found = 0
    if (thread_count == "") {
        thread_count = 1
    }
    if (thread_count == 1) {
        scheme = "Relect"
    } else {
        scheme = sprintf("Relect(%d threads)", thread_count)
    }

    if (!data_only) {
        print "Input: " input_file
        print "scheme, party_count, avg_all_compute_ms"
    }

    for (p in seen) {
        if (counts[p] > 0) {
            found = 1
            ordered[++n] = p + 0
        }
    }

    for (i = 1; i <= n; i++) {
        for (j = i + 1; j <= n; j++) {
            if (ordered[i] > ordered[j]) {
                tmp = ordered[i]
                ordered[i] = ordered[j]
                ordered[j] = tmp
            }
        }
    }

    for (i = 1; i <= n; i++) {
        p = ordered[i]
        printf "%s, %d, %.6f\n", scheme, p, sums[p] / counts[p]
    }

    if (!found) {
        printf("No all_compute results found in: %s\n", input_file) > "/dev/stderr"
        exit 1
    }
}
' data_only="$data_only" input_file="$input_file" "$input_file"
