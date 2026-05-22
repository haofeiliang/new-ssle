# Parse benchmark result files and compute average all_compute time per party count.
# Outputs CSV rows: scheme, party_count, avg_all_compute_ms
#
# Usage: .\analyze_bench.ps1 <result-file> [-DataOnly]
#   -DataOnly   suppress the header lines, print only CSV data

param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$InputFile,

    [switch]$DataOnly
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

$Stats = @{}
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
        if (-not $Stats.ContainsKey($CurrentP)) {
            $Stats[$CurrentP] = [pscustomobject]@{
                Count = 0
                SumMs = 0.0
            }
        }
        continue
    }

    # Extract all_compute elapsed time
    if ($null -ne $CurrentP -and $Line -match $AllComputePattern) {
        $ElapsedMs = Convert-ToMilliseconds -Value ([double]$Matches[1]) -Unit $Matches[2]
        $Stats[$CurrentP].Count += 1
        $Stats[$CurrentP].SumMs += $ElapsedMs
    }
}

if ($Stats.Count -eq 0) {
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

# --- Output ---
if (-not $DataOnly) {
    "Input: $InputFile"
    "scheme, party_count, avg_all_compute_ms"
}

foreach ($P in ($Stats.Keys | Sort-Object {[int]$_})) {
    $Item = $Stats[$P]
    if ($Item.Count -gt 0) {
        $AverageMs = $Item.SumMs / $Item.Count
        "{0}, {1}, {2}" -f $Scheme, $P, $AverageMs.ToString("F6", $InvariantCulture)
    }
}
