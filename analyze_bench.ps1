# Parse benchmark result files and compute average all_compute time per party count.
# Outputs CSV rows: scheme, party_count, avg_all_compute_ms
#
# Usage: .\analyze_bench.ps1 <result-file> [-DataOnly] [-Stats]
#   -DataOnly   suppress the header lines, print only CSV data
#   -Stats      append a statistics table (stddev, min, max) after the CSV output

param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$InputFile,

    [switch]$DataOnly,
    [switch]$Stats
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $InputFile -PathType Leaf)) {
    throw "Input file not found: $InputFile"
}

# --- Time unit conversion ---
function Convert-ToMilliseconds {
    param(
        [double]$Value,
        [string]$Unit
    )

    switch ($Unit) {
        "s"  { return $Value * 1000.0 }
        "ms" { return $Value }
        "us" { return $Value / 1000.0 }
        "µs" { return $Value / 1000.0 }
        "μs" { return $Value / 1000.0 }
        "ns" { return $Value / 1000000.0 }
        default { throw "Unsupported time unit: $Unit" }
    }
}

# --- Parse benchmark output ---

# Regex to match the all_compute timing line, e.g.:
#   | all_compute        | 1.234 ms |
$AllComputePattern = '\|\s*all_compute\s*\|\s*([0-9]+(?:\.[0-9]+)?)\s*(ns|us|µs|μs|ms|s)\s*\|'

$PartyStats = @{}
$CurrentP = $null
$ThreadCount = $null
$InvariantCulture = [System.Globalization.CultureInfo]::InvariantCulture

foreach ($Line in Get-Content -LiteralPath $InputFile) {
    # Detect thread count from result file header
    if ($null -eq $ThreadCount -and $Line -match "Results for thread count t=(\d+)\b") {
        $ThreadCount = [int]$Matches[1]
        continue
    }

    # Detect party count section
    if ($Line -match "--- Testing p=(\d+)\b") {
        $CurrentP = [int]$Matches[1]
        if (-not $PartyStats.ContainsKey($CurrentP)) {
            $PartyStats[$CurrentP] = [pscustomobject]@{
                Count  = 0
                SumMs  = 0.0
                Values = [System.Collections.Generic.List[double]]::new()
            }
        }
        continue
    }

    # Extract all_compute elapsed time
    if ($null -ne $CurrentP -and $Line -match $AllComputePattern) {
        $ElapsedMs = Convert-ToMilliseconds -Value ([double]$Matches[1]) -Unit $Matches[2]
        $PartyStats[$CurrentP].Count += 1
        $PartyStats[$CurrentP].SumMs += $ElapsedMs
        $PartyStats[$CurrentP].Values.Add($ElapsedMs)
    }
}

if ($PartyStats.Count -eq 0) {
    throw "No all_compute results found in: $InputFile"
}

# --- Scheme name ---
# Single-threaded = "Relect"; multi-threaded = "Relect(N threads)"
if ($null -eq $ThreadCount) {
    $ThreadCount = 1
}

if ($ThreadCount -eq 1) {
    $Scheme = "Relect"
}
else {
    $Scheme = "Relect($ThreadCount threads)"
}

# --- CSV Output (always) ---
if (-not $DataOnly) {
    "Input: $InputFile"
    "scheme, party_count, avg_all_compute_ms"
}

foreach ($P in ($PartyStats.Keys | Sort-Object {[int]$_})) {
    $Item = $PartyStats[$P]
    if ($Item.Count -gt 0) {
        $AverageMs = $Item.SumMs / $Item.Count
        "{0}, {1}, {2}" -f $Scheme, $P, $AverageMs.ToString("F6", $InvariantCulture)
    }
}

# --- Statistics Table (optional) ---
if ($Stats) {
    ""
    "--- Statistics ---"
    "scheme, party_count, runs, avg_ms, stddev_ms, min_ms, max_ms"

    foreach ($P in ($PartyStats.Keys | Sort-Object {[int]$_})) {
        $Item = $PartyStats[$P]
        $n = $Item.Count
        if ($n -lt 2) {
            # Need at least 2 runs for sample stddev
            $AvgMs = if ($n -eq 1) { $Item.Values[0] } else { 0 }
            "{0}, {1}, {2}, {3}, {4}, {5}, {6}" -f $Scheme, $P, $n,
                $AvgMs.ToString("F6", $InvariantCulture),
                "N/A",
                $AvgMs.ToString("F6", $InvariantCulture),
                $AvgMs.ToString("F6", $InvariantCulture)
            continue
        }

        $AvgMs = $Item.SumMs / $n
        $Variance = ($Item.Values | ForEach-Object { ($_ - $AvgMs) * ($_ - $AvgMs) } | Measure-Object -Sum).Sum / ($n - 1)
        $StddevMs = [Math]::Sqrt($Variance)
        $MinMs = ($Item.Values | Measure-Object -Minimum).Minimum
        $MaxMs = ($Item.Values | Measure-Object -Maximum).Maximum

        "{0}, {1}, {2}, {3}, {4}, {5}, {6}" -f $Scheme, $P, $n,
            $AvgMs.ToString("F6", $InvariantCulture),
            $StddevMs.ToString("F6", $InvariantCulture),
            $MinMs.ToString("F6", $InvariantCulture),
            $MaxMs.ToString("F6", $InvariantCulture)
    }
}
