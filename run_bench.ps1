# 用法: .\run_bench.ps1 [重复次数] [线程数列表] [cargo toolchain]
# 线程数列表格式：逗号分隔的数字，例如 "1,2,4,8,16"；默认为 "1"（只测单线程）
# cargo toolchain 可选，例如 "+nightly" 或 "nightly"；默认为当前默认 toolchain
# 示例: .\run_bench.ps1 5 "1,2,4,8,16,32" +nightly

param(
    [int]$Repeats = 5,
    [string]$ThreadsArg = "1",
    [string]$ToolchainArg = ""
)

$ErrorActionPreference = "Stop"

$Utf8NoBom = [System.Text.UTF8Encoding]::new($false)
[Console]::InputEncoding = $Utf8NoBom
[Console]::OutputEncoding = $Utf8NoBom
$OutputEncoding = $Utf8NoBom

$Threads = $ThreadsArg -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }

$CargoToolchainArgs = @()
if ($ToolchainArg.Trim() -ne "") {
    $CargoToolchain = $ToolchainArg.Trim()
    if (-not $CargoToolchain.StartsWith("+")) {
        $CargoToolchain = "+$CargoToolchain"
    }
    $CargoToolchainArgs = @($CargoToolchain)
}

$OutputDir = "results"
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$BuildLog = Join-Path $OutputDir "build_log.txt"

Write-Host "Results will be saved to $OutputDir/benchmark_${Timestamp}_t*.txt"
Write-Host "Thread counts to test: $($Threads -join ' ')"
if ($CargoToolchainArgs.Count -eq 0) {
    Write-Host "Cargo toolchain: default"
}
else {
    Write-Host "Cargo toolchain: $($CargoToolchainArgs[0])"
}

function Write-Log {
    param(
        [string]$Message,
        [string]$FilePath
    )

    $Message | Tee-Object -FilePath $FilePath -Append
}

# 为每个线程数创建输出文件，写入头部
foreach ($t in $Threads) {
    $OutFile = Join-Path $OutputDir "benchmark_${Timestamp}_t${t}.txt"

    "Results for thread count t=$t" | Out-File -FilePath $OutFile -Encoding utf8
    "Repeat each test $Repeats times" | Out-File -FilePath $OutFile -Append -Encoding utf8
    "==========================================" | Out-File -FilePath $OutFile -Append -Encoding utf8
}

# 定义三个测试块：基础 feature | example | party count 列表
$Blocks = @(
    @{
        BaseFeatures = ""
        Example      = "ssle_compute_time"
        PList        = "2 4 8 16"
    },
    @{
        BaseFeatures = "gt16"
        Example      = "ssle_compute_time"
        PList        = "32 64 128"
    },
    @{
        BaseFeatures = "gt128"
        Example      = "ssle_ge_256_compute_time_improve"
        PList        = "256 512 1024 2048"
    }
)

# 记录上一次构建的 features（初始为一个不存在的 features，确保第一次一定 build）
$LastFeatures = "random"

foreach ($Block in $Blocks) {
    $BaseFeatures = $Block.BaseFeatures
    $Example = $Block.Example
    $PList = $Block.PList

    Write-Host "=========================================="
    Write-Host "Processing block: base_features='$BaseFeatures', example='$Example', p in {$PList}"

    foreach ($t in $Threads) {
        $OutFile = Join-Path $OutputDir "benchmark_${Timestamp}_t${t}.txt"

        # 根据 t 确定 features 和命令行参数
        if ([int]$t -eq 1) {
            $Features = $BaseFeatures
            $TArgs = @()
        }
        else {
            if ($BaseFeatures.Trim() -ne "") {
                $Features = "$BaseFeatures parallel"
            }
            else {
                $Features = "parallel"
            }

            $TArgs = @("-t", "$t")
        }

        # 去除多余空格
        $Features = ($Features -split "\s+" | Where-Object { $_ -ne "" }) -join " "

        Write-Log "--- Thread t=$t, features: '$Features' ---" $OutFile

        if ($Features -ne $LastFeatures) {
            Write-Log "Features changed from '$LastFeatures' to '$Features'. Rebuilding..." $OutFile

            $BuildArgs = $CargoToolchainArgs + @(
                "build",
                "--quiet",
                "--release",
                "--package", "ssle_core",
                "--example", $Example,
                "--features=$Features"
            )

            & cargo @BuildArgs >> $BuildLog
            if ($LASTEXITCODE -ne 0) {
                throw "cargo build failed with exit code $LASTEXITCODE"
            }

            $LastFeatures = $Features

            Write-Log "Build completed. Sleeping 2 seconds..." $OutFile
            Start-Sleep -Seconds 2
        }
        else {
            Write-Log "Features unchanged, skipping build." $OutFile
        }

        foreach ($p in ($PList -split "\s+" | Where-Object { $_ -ne "" })) {
            Write-Log "--- Testing p=$p with features: '$Features', example: $Example ---" $OutFile

            for ($i = 1; $i -le $Repeats; $i++) {
                Write-Log "Run $i for p=$p, t=$t" $OutFile

                $RunArgs = $CargoToolchainArgs + @(
                    "run",
                    "--quiet",
                    "--release",
                    "--package", "ssle_core",
                    "--example", $Example,
                    "--features=$Features",
                    "--",
                    "-p", "$p"
                ) + $TArgs

                $OldRustLog = $env:RUST_LOG
                $env:RUST_LOG = "off"

                try {
                    & cargo @RunArgs |
                        Out-File -FilePath $OutFile -Append -Encoding utf8

                    if ($LASTEXITCODE -ne 0) {
                        throw "cargo run failed with exit code $LASTEXITCODE"
                    }
                }
                finally {
                    if ($null -eq $OldRustLog) {
                        Remove-Item Env:RUST_LOG -ErrorAction SilentlyContinue
                    }
                    else {
                        $env:RUST_LOG = $OldRustLog
                    }
                }

                "--- End run $i for p=$p, t=$t ---" | Out-File -FilePath $OutFile -Append -Encoding utf8
                Start-Sleep -Seconds 1
            }
        }
    }
}

Write-Host "Benchmark completed. Results in $OutputDir/benchmark_${Timestamp}_t*.txt"
