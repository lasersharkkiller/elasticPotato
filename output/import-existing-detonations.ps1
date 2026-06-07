<#
.SYNOPSIS
    One-shot orchestrator that pushes all four known detonation corpora into
    per-session Elastic replay indices via Push-DetonationLogsToElastic.

.DESCRIPTION
    Walks four hard-coded corpora paths (Havoc, Merlin, Sliver SO 3.0 pulls
    plus the AndySliver vanilla ES HTTP pull) and replays each into its own
    deterministically-named index on the scratch Elastic cluster. Missing or
    empty corpora are skipped with a warning.

.PARAMETER DryRun
    Parse + count + tag everything but skip the POST.

.PARAMETER Confirm
    Pause before each corpus push for human OK. Off by default.

.EXAMPLE
    .\import-existing-detonations.ps1

.EXAMPLE
    .\import-existing-detonations.ps1 -DryRun

.EXAMPLE
    .\import-existing-detonations.ps1 -Confirm
#>
[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$Confirm
)

$ErrorActionPreference = 'Stop'

# --- Load module ---
$modulePath = Join-Path -Path (Split-Path -Parent $PSScriptRoot) -ChildPath 'purpleTeaming\Push-DetonationLogsToElastic.psm1'
if (-not (Test-Path -LiteralPath $modulePath)) {
    throw "Module not found: $modulePath"
}
Import-Module $modulePath -Force

# --- Corpora ---
$corpora = @(
    'C:/githubProjects/DetonationLogs/C2Frameworks/Havoc_2026-05-28_16-50_to_16-54UTC'
    'C:/githubProjects/DetonationLogs/C2Frameworks/Merlin_2026-05-28_16-33_to_16-36UTC'
    'C:/githubProjects/DetonationLogs/C2Frameworks/Sliver_2026-05-28_16-12_to_16-17UTC'
    'C:/githubProjects/elasticPotato/detonation_logs/AndySliver_2026-06-06_17-30_to_20-30UTC'
)

# --- Banner ---
Write-Host ""
Write-Host "##################################################################" -ForegroundColor Cyan
Write-Host "#  import-existing-detonations.ps1                               #" -ForegroundColor Cyan
Write-Host "#  Push 4 detonation corpora into the scratch Elastic stack      #" -ForegroundColor Cyan
Write-Host "##################################################################" -ForegroundColor Cyan
Write-Host ""

$totalNdjsonBytes = 0
$totalNdjsonFiles = 0
$validCorpora = @()
foreach ($c in $corpora) {
    $exists = Test-Path -LiteralPath $c -PathType Container
    if (-not $exists) {
        Write-Host "  [MISS] $c" -ForegroundColor Red
        continue
    }
    $ndjson = @(Get-ChildItem -LiteralPath $c -Filter '*.ndjson' -File -ErrorAction SilentlyContinue)
    if ($ndjson.Count -eq 0) {
        Write-Host "  [SKIP] $c  (no *.ndjson files - empty corpus)" -ForegroundColor Yellow
        continue
    }
    $bytes = ($ndjson | Measure-Object -Property Length -Sum).Sum
    $totalNdjsonBytes += $bytes
    $totalNdjsonFiles += $ndjson.Count
    $validCorpora += [PSCustomObject]@{
        Path  = $c
        Files = $ndjson.Count
        Bytes = $bytes
    }
    $mb = '{0:N1}' -f ($bytes / 1MB)
    Write-Host ("  [OK]   {0}  files={1}  size={2} MB" -f $c, $ndjson.Count, $mb) -ForegroundColor Green
}

Write-Host ""
Write-Host ("Total: {0} corpora, {1} ndjson files, {2:N1} MB" -f $validCorpora.Count, $totalNdjsonFiles, ($totalNdjsonBytes / 1MB)) -ForegroundColor Cyan
if ($DryRun) { Write-Host "Mode : DRY RUN (no docs will be POSTed)" -ForegroundColor Yellow }
Write-Host ""

if ($validCorpora.Count -eq 0) {
    Write-Host "[ABORT] No valid corpora found." -ForegroundColor Red
    return
}

# --- Iterate + push ---
$grandResults = [System.Collections.Generic.List[object]]::new()
$grandStart   = Get-Date

foreach ($corpus in $validCorpora) {
    Write-Host ""
    Write-Host "------------------------------------------------------------------" -ForegroundColor DarkCyan
    Write-Host "  Pushing: $($corpus.Path)" -ForegroundColor Cyan
    Write-Host "------------------------------------------------------------------" -ForegroundColor DarkCyan

    if ($Confirm) {
        $resp = Read-Host "  Proceed? [y/N]"
        if ($resp -notmatch '^[yY]') {
            Write-Host "  [SKIPPED by user]" -ForegroundColor Yellow
            continue
        }
    }

    try {
        $r = Push-DetonationLogsToElastic -SourceDir $corpus.Path -DryRun:$DryRun
        $grandResults.Add($r) | Out-Null
    } catch {
        Write-Host "  [FAIL] $($_.Exception.Message)" -ForegroundColor Red
        $grandResults.Add([PSCustomObject]@{
            Index        = "(failed: $($corpus.Path))"
            Sent         = 0
            Accepted     = 0
            Rejected     = 0
            BulkRequests = 0
            DurationMs   = 0
            Failures     = @($_.Exception.Message)
        }) | Out-Null
    }
}

$grandEnd = Get-Date

# --- Grand summary ---
Write-Host ""
Write-Host "##################################################################" -ForegroundColor Cyan
Write-Host "#  GRAND SUMMARY                                                 #" -ForegroundColor Cyan
Write-Host "##################################################################" -ForegroundColor Cyan

$totalSent     = 0
$totalAccepted = 0
$totalRejected = 0
$totalBulk     = 0
foreach ($r in $grandResults) {
    $totalSent     += $r.Sent
    $totalAccepted += $r.Accepted
    $totalRejected += $r.Rejected
    $totalBulk     += $r.BulkRequests
    $status = if ($r.Rejected -gt 0) { 'PARTIAL' } elseif ($r.Sent -eq 0) { 'EMPTY' } else { 'OK' }
    $color  = switch ($status) { 'OK' { 'Green' } 'PARTIAL' { 'Yellow' } default { 'Red' } }
    Write-Host ("  {0,-7}  {1,-55}  sent={2,-7} ok={3,-7} fail={4}" -f $status, $r.Index, $r.Sent, $r.Accepted, $r.Rejected) -ForegroundColor $color
}

Write-Host ""
Write-Host ("  Corpora processed : {0}" -f $grandResults.Count) -ForegroundColor DarkGray
Write-Host ("  Docs sent         : {0}" -f $totalSent)          -ForegroundColor DarkGray
Write-Host ("  Docs accepted     : {0}" -f $totalAccepted)      -ForegroundColor Green
if ($totalRejected -gt 0) {
    Write-Host ("  Docs rejected     : {0}" -f $totalRejected)  -ForegroundColor Red
} else {
    Write-Host ("  Docs rejected     : {0}" -f $totalRejected)  -ForegroundColor DarkGray
}
Write-Host ("  Bulk requests     : {0}" -f $totalBulk)          -ForegroundColor DarkGray
Write-Host ("  Wall time         : {0}" -f ($grandEnd - $grandStart).ToString('hh\:mm\:ss\.fff')) -ForegroundColor DarkGray

if ($DryRun) {
    Write-Host ""
    Write-Host "[NOTE] Dry-run mode - no documents were actually POSTed to Elasticsearch." -ForegroundColor Yellow
}
