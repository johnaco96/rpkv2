param(
    [string]$Config = "configs/benchmark/overload.env",
    [string]$WorkDir = "",
    [string]$OutJson = "",
    [int]$OfferedPackets = 0,
    [int]$ReplayPackets = 0,
    [int]$InvalidSignaturePackets = 0
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
$workDefault = if ($configValues.ContainsKey("WORK_DIR")) { $configValues["WORK_DIR"] } else { "benchmarks/results/overload" }
$outDefault = if ($configValues.ContainsKey("OUT_JSON")) { $configValues["OUT_JSON"] } else { "benchmarks/results/overload/overload-summary.json" }
$offeredDefault = if ($configValues.ContainsKey("OFFERED_PACKETS")) { $configValues["OFFERED_PACKETS"] } else { "20000" }
$replayDefault = if ($configValues.ContainsKey("REPLAY_PACKETS")) { $configValues["REPLAY_PACKETS"] } else { "500" }
$invalidDefault = if ($configValues.ContainsKey("INVALID_SIGNATURE_PACKETS")) { $configValues["INVALID_SIGNATURE_PACKETS"] } else { "2000" }

$work = if ($WorkDir.Length -gt 0) { $WorkDir } else { $workDefault }
$out = if ($OutJson.Length -gt 0) { $OutJson } else { $outDefault }
$offered = if ($OfferedPackets -gt 0) { $OfferedPackets } else { [int]$offeredDefault }
$replay = if ($ReplayPackets -gt 0) { $ReplayPackets } else { [int]$replayDefault }
$invalid = if ($InvalidSignaturePackets -gt 0) { $InvalidSignaturePackets } else { [int]$invalidDefault }

cargo run --release --features ed25519 --bin overload_suite -- `
    --work-dir $work `
    --out-json $out `
    --offered-packets $offered `
    --replay-packets $replay `
    --invalid-signature-packets $invalid
