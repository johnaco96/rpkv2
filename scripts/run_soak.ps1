param(
    [string]$Config = "configs/benchmark/soak.env",
    [int]$DurationSecs = 0,
    [int]$Pps = 0,
    [int]$Payload = 0,
    [int]$SampleIntervalSecs = 0,
    [string]$OutJson = "",
    [string]$StorageDir = ""
)

$ErrorActionPreference = "Stop"

function Read-EnvFile($Path) {
    $values = @{}
    if (Test-Path $Path) {
        foreach ($line in Get-Content $Path) {
            $trimmed = $line.Trim()
            if ($trimmed.Length -eq 0 -or $trimmed.StartsWith("#")) {
                continue
            }
            $parts = $trimmed.Split("=", 2)
            if ($parts.Length -eq 2) {
                $values[$parts[0]] = $parts[1]
            }
        }
    }
    return $values
}

$configValues = Read-EnvFile $Config
$durationDefault = if ($configValues.ContainsKey("DURATION_SECS")) { $configValues["DURATION_SECS"] } else { "3600" }
$ppsDefault = if ($configValues.ContainsKey("PPS")) { $configValues["PPS"] } else { "10000" }
$payloadDefault = if ($configValues.ContainsKey("PAYLOAD")) { $configValues["PAYLOAD"] } else { "256" }
$sampleDefault = if ($configValues.ContainsKey("SAMPLE_INTERVAL_SECS")) { $configValues["SAMPLE_INTERVAL_SECS"] } else { "10" }
$storageDefault = if ($configValues.ContainsKey("STORAGE_DIR")) { $configValues["STORAGE_DIR"] } else { "benchmarks/results/soak/store" }
$outDefault = if ($configValues.ContainsKey("OUT_JSON")) { $configValues["OUT_JSON"] } else { "benchmarks/results/soak/soak-summary.json" }

$duration = if ($DurationSecs -gt 0) { $DurationSecs } else { [int]$durationDefault }
$ppsValue = if ($Pps -gt 0) { $Pps } else { [int]$ppsDefault }
$payloadValue = if ($Payload -gt 0) { $Payload } else { [int]$payloadDefault }
$sampleInterval = if ($SampleIntervalSecs -gt 0) { $SampleIntervalSecs } else { [int]$sampleDefault }
$storage = if ($StorageDir.Length -gt 0) { $StorageDir } else { $storageDefault }
$out = if ($OutJson.Length -gt 0) { $OutJson } else { $outDefault }

cargo run --release --features ed25519 --bin soak_bench -- `
    --duration-secs $duration `
    --pps $ppsValue `
    --payload $payloadValue `
    --sample-interval-secs $sampleInterval `
    --storage-dir $storage `
    --out-json $out
