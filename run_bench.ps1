# Usage: .\run_bench.ps1 [OPTIONS]
#   -r, -Repeat N       number of runs per test (default: 5)
#   -t, -Threads LIST   comma-separated thread counts (default: "1")
#   -c, -Toolchain TC   cargo toolchain, e.g. "nightly" or "+nightly"
#   -s, -Simd           enable simd feature
#
# Examples:
#   .\run_bench.ps1 -r 5 -t "1,2,4,8,16,32" -c nightly
#   .\run_bench.ps1 -c nightly -s

param(
    [Alias("r")] [int]$Repeat = 5,
    [Alias("t")] [string]$ThreadsArg = "1",
    [Alias("c")] [string]$Toolchain = "",
    [Alias("s")] [switch]$Simd,
    [Alias("h")] [switch]$Help
)

$ErrorActionPreference = "Stop"

if ($Help) {
    @'
Usage: .\run_bench.ps1 [OPTIONS]
  -r, -Repeat N       number of runs per test (default: 5)
  -t, -Threads LIST   comma-separated thread counts (default: "1")
  -c, -Toolchain TC   cargo toolchain, e.g. "nightly" or "+nightly"
  -s, -Simd           enable simd feature
  -h, -Help           show this help message

Examples:
  .\run_bench.ps1 -r 5 -t "1,2,4,8,16,32" -c nightly
  .\run_bench.ps1 -c nightly -s
'@
    exit 0
}

# Ensure UTF-8 output on Windows consoles
$Utf8NoBom = [System.Text.UTF8Encoding]::new($false)
[Console]::InputEncoding = $Utf8NoBom
[Console]::OutputEncoding = $Utf8NoBom
$OutputEncoding = $Utf8NoBom

$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

# --- System tuning for consistent benchmarks ---

# Raise process priority to reduce scheduling jitter (High does not require admin)
try {
    [System.Diagnostics.Process]::GetCurrentProcess().PriorityClass =
        [System.Diagnostics.ProcessPriorityClass]::High
    Write-Host "Process priority: High"
}
catch {
    Write-Host "Process priority: Normal (could not raise)"
}

# Check power plan (changing it requires admin, so just warn)
$powerPlan = powercfg /getactivescheme 2>$null
if ($powerPlan -match "High performance") {
    Write-Host "Power plan: High Performance (optimal)"
}
else {
    Write-Host "WARNING: Power plan is not 'High Performance'."
    Write-Host "  For consistent results, run (as admin):"
    Write-Host "  powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
}

Write-Host ""

# --- Parameters ---
$Threads = $ThreadsArg -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }

# Normalize toolchain prefix
$CargoToolchainArgs = @()
if ($Toolchain.Trim() -ne "") {
    $CargoToolchain = $Toolchain.Trim()
    if (-not $CargoToolchain.StartsWith("+")) {
        $CargoToolchain = "+$CargoToolchain"
    }
    $CargoToolchainArgs = @($CargoToolchain)
}

# --- Output setup ---
$OutputDir = "results"
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

$Timestamp = Get-Date -Format "yyyyMMdd_HHmm"

# Result file tag (append _nightly / _simd as needed)
$ResultTag = $Timestamp
if ($CargoToolchainArgs.Count -gt 0 -and $CargoToolchainArgs[0].TrimStart("+").StartsWith("nightly")) {
    $ResultTag = "${Timestamp}_nightly"
}
if ($Simd) {
    $ResultTag = "${ResultTag}_simd"
}

$BuildLog = Join-Path $OutputDir "build_log.txt"
"" | Out-File -FilePath $BuildLog -Encoding utf8

Write-Host "Results: $OutputDir/${ResultTag}_t*.txt"
Write-Host "Build log: $BuildLog"
Write-Host "Threads: $($Threads -join ' ')"
if ($CargoToolchainArgs.Count -eq 0) {
    Write-Host "Toolchain: default"
} else {
    Write-Host "Toolchain: $($CargoToolchainArgs[0])"
}
Write-Host "SIMD: $([bool]$Simd)"

function Write-Log {
    param([string]$Message, [string]$FilePath)
    $Message | Tee-Object -FilePath $FilePath -Append
}

# Init per-thread result files
foreach ($t in $Threads) {
    $OutFile = Join-Path $OutputDir "${ResultTag}_t${t}.txt"
    "Results for thread count t=$t" | Out-File -FilePath $OutFile -Encoding utf8
    "Repeat each test $Repeat times" | Out-File -FilePath $OutFile -Append -Encoding utf8
    "==========================================" | Out-File -FilePath $OutFile -Append -Encoding utf8
}

# Test blocks: BaseFeatures / Example / PartyList
$Blocks = @(
    @{ BaseFeatures = "";      Example = "ssle_compute_time";                  PList = "2 4 8 16" }
    @{ BaseFeatures = "gt16";  Example = "ssle_compute_time";                  PList = "32 64 128" }
    @{ BaseFeatures = "gt128"; Example = "ssle_ge_256_compute_time_improve";   PList = "256 512 1024 2048" }
)

$LastFeatures = "random"

foreach ($Block in $Blocks) {
    $BaseFeatures = $Block.BaseFeatures
    $Example = $Block.Example
    $PList = $Block.PList

    Write-Host "=========================================="
    Write-Host "Block: features='$BaseFeatures', example='$Example', parties={$PList}"

    foreach ($t in $Threads) {
        $OutFile = Join-Path $OutputDir "${ResultTag}_t${t}.txt"

        # Assemble features: base + parallel (if multi-threaded)
        if ([int]$t -eq 1) {
            $Features = $BaseFeatures
            $TArgs = @()
        } else {
            $Features = if ($BaseFeatures) { "$BaseFeatures parallel" } else { "parallel" }
            $TArgs = @("-t", "$t")
        }
        $Features = ($Features -split "\s+" | Where-Object { $_ -ne "" }) -join " "

        # Append simd feature if requested
        if ($Simd) {
            $Features = if ($Features) { "$Features simd" } else { "simd" }
        }

        Write-Log "--- t=$t, features: '$Features' ---" $OutFile

        # Rebuild only when features change
        if ($Features -ne $LastFeatures) {
            Write-Log "Rebuilding (features: $LastFeatures -> $Features)..." $OutFile

            $BuildArgs = $CargoToolchainArgs + @(
                "build", "--quiet", "--release",
                "--package", "ssle_core",
                "--example", $Example,
                "--features=$Features"
            )

            & cargo @BuildArgs >> $BuildLog
            if ($LASTEXITCODE -ne 0) {
                throw "cargo build failed with exit code $LASTEXITCODE"
            }

            $LastFeatures = $Features
            Write-Log "Build done." $OutFile
            Start-Sleep -Seconds 2
        } else {
            Write-Log "Features unchanged, skip build." $OutFile
        }

        # Run the compiled binary directly (avoids cargo run overhead)
        $Binary = Join-Path $ScriptDir "target/release/examples/$Example.exe"
        if (-not (Test-Path -LiteralPath $Binary -PathType Leaf)) {
            throw "Compiled binary not found: $Binary"
        }

        foreach ($p in ($PList -split "\s+" | Where-Object { $_ -ne "" })) {
            Write-Log "--- Testing p=$p ---" $OutFile

            for ($i = 1; $i -le $Repeat; $i++) {
                Write-Log "Run $i/$Repeat" $OutFile

                $RunArgs = @("-p", "$p") + $TArgs

                $env:RUST_LOG = "off"
                & $Binary @RunArgs |
                    Out-File -FilePath $OutFile -Append -Encoding utf8
                $env:RUST_LOG = $null

                if ($LASTEXITCODE -ne 0) {
                    throw "binary run failed with exit code $LASTEXITCODE"
                }

                Start-Sleep -Seconds 1
            }

            # Cooldown: longer pause after large party counts to avoid thermal throttling
            $CooldownMs = if ([int]$p -ge 1024) { 5000 } elseif ([int]$p -ge 512) { 3000 } else { 500 }
            Start-Sleep -Milliseconds $CooldownMs
        }
    }
}

Write-Host "Benchmark completed. Results in $OutputDir/${ResultTag}_t*.txt"

# Run analysis
$AnalyzeScript = Join-Path $ScriptDir "analyze_bench.ps1"
if (-not (Test-Path -LiteralPath $AnalyzeScript -PathType Leaf)) {
    throw "Analyze script not found: $AnalyzeScript"
}

Write-Host ""
Write-Host "Average all_compute time:"
Write-Host "scheme, party_count, avg_all_compute_ms"
foreach ($t in $Threads) {
    $OutFile = Join-Path $OutputDir "${ResultTag}_t${t}.txt"
    & $AnalyzeScript $OutFile -DataOnly -Stats
}
