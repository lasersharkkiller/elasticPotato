<#
.SYNOPSIS
  Build a complete, OFFLINE-ready KAPE folder for elasticPotato option 2b.

.DESCRIPTION
  Run this ONCE on an INTERNET-connected Windows host. It assembles a fully
  self-contained KAPE directory at <repo>\tools\kape so the air-gapped DFIR VM
  can deploy KAPE to Windows targets via option 2b with zero internet access.

  What it does NOT do: download kape.exe / gkape.exe for you. Kroll's KAPE
  binaries are proprietary ("licensed, not sold" - KAPE EULA) and are gated
  behind a registration form + EULA acceptance at https://www.kroll.com/kape.
  You download KAPE yourself, then point this script at it with -KapeSource.
  The Kroll binaries are git-ignored and never committed to this public repo;
  only this staging helper and the .gitignore guard are tracked in git.

  The MIT-licensed pieces ARE fetched automatically (best effort, need internet):
    * Targets / Modules  (kape.exe --sync from EricZimmerman/KapeFiles, MIT)
    * EZ Tools           (Get-ZimmermanTools.ps1 into Modules\bin, MIT)

.PARAMETER KapeSource
  Path to your Kroll-downloaded KAPE - either a folder that contains kape.exe,
  or a KAPE .zip. Required unless a KAPE already exists at -Destination.

.PARAMETER Destination
  Where to stage. Default: <repo>\tools\kape (what Deploy-KAPE.ps1 auto-discovers).

.PARAMETER NetVersion
  .NET flavor of EZ Tools to pull via Get-ZimmermanTools (0 = all, 4 = .NET 4,
  6 = .NET 6, 9 = .NET 9). Default 9. Note: 0 nests tools under net<n> subfolders.

.PARAMETER SyncUrl
  Override the KapeFiles sync source for 'kape.exe --sync' (e.g. a fork's
  archive .zip URL). Default: KAPE's built-in EricZimmerman/KapeFiles master.

.PARAMETER SkipKapeUpdate
  Skip the Get-KAPEUpdate.ps1 self-update of kape.exe.

.PARAMETER SkipSync
  Skip the Targets/Modules sync.

.PARAMETER SkipEZTools
  Skip populating Modules\bin with EZ Tools.

.PARAMETER Force
  Overwrite an existing -Destination with the -KapeSource contents.

.PARAMETER DryRun
  Print each phase's planned action without downloading or copying anything.

.EXAMPLE
  .\Get-KAPE-Offline.ps1 -KapeSource 'C:\Users\me\Downloads\KAPE.zip'

.EXAMPLE
  .\Get-KAPE-Offline.ps1 -KapeSource 'D:\tools\KAPE' -NetVersion 9

.NOTES
  Compatible with Windows PowerShell 5.1 and PowerShell 7+.
  Kroll KAPE EULA: https://www.kroll.com/en/kape-license-agreement
#>
[CmdletBinding()]
param(
    [string]$KapeSource,
    [string]$Destination,
    [ValidateSet(0, 4, 6, 9)] [int]$NetVersion = 9,
    [string]$SyncUrl,
    [switch]$SkipKapeUpdate,
    [switch]$SkipSync,
    [switch]$SkipEZTools,
    [switch]$Force,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

function Write-Kape {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Warn', 'Error', 'Success', 'Step')] [string]$Level = 'Info'
    )
    $color = 'Cyan'
    switch ($Level) {
        'Info'    { $color = 'Cyan' }
        'Warn'    { $color = 'Yellow' }
        'Error'   { $color = 'Red' }
        'Success' { $color = 'Green' }
        'Step'    { $color = 'Magenta' }
    }
    $tag = if ($DryRun) { '[KAPE-stage][DRYRUN]' } else { '[KAPE-stage]' }
    Write-Host "$tag $Message" -ForegroundColor $color
}

function Resolve-KapeRoot {
    # Return the directory that directly contains kape.exe (KAPE zips often
    # extract into a nested \KAPE subfolder). Returns $null if not found.
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    if (Test-Path -LiteralPath (Join-Path $Path 'kape.exe')) {
        return (Resolve-Path -LiteralPath $Path).Path
    }
    $hit = Get-ChildItem -LiteralPath $Path -Filter 'kape.exe' -Recurse -Depth 2 -File -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($hit) { return $hit.Directory.FullName }
    return $null
}

# --- resolve destination -----------------------------------------------------
if (-not $Destination) {
    $toolsRoot = Split-Path -Path $PSScriptRoot -Parent   # tools\deploy -> tools
    $Destination = Join-Path -Path $toolsRoot -ChildPath 'kape'
}
Write-Kape "Destination: $Destination" 'Step'

# TLS 1.2 for web calls on Windows PowerShell 5.1 (older default can break HTTPS)
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }

$destHasKape = Test-Path -LiteralPath (Join-Path $Destination 'kape.exe')

# --- phase 1: obtain the Kroll KAPE binaries (from -KapeSource, never the net) ---
Write-Kape "Phase 1/4  Stage KAPE binaries" 'Step'
if ($KapeSource) {
    if (-not (Test-Path -LiteralPath $KapeSource)) { throw "KapeSource not found: $KapeSource" }
    $item = Get-Item -LiteralPath $KapeSource
    $srcRoot = $null
    $tempExtract = $null

    if (-not $item.PSIsContainer -and $item.Extension -match '(?i)\.zip$') {
        Write-Kape "Expanding $($item.Name) ..." 'Info'
        if (-not $DryRun) {
            $tempExtract = Join-Path ([IO.Path]::GetTempPath()) ('KAPEstage_' + [Guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $tempExtract -Force | Out-Null
            Expand-Archive -LiteralPath $item.FullName -DestinationPath $tempExtract -Force
            $srcRoot = Resolve-KapeRoot $tempExtract
        }
    }
    elseif ($item.PSIsContainer) {
        if (-not $DryRun) { $srcRoot = Resolve-KapeRoot $item.FullName }
    }
    else {
        throw "KapeSource must be a folder containing kape.exe or a KAPE .zip. Got: $KapeSource"
    }

    if ($DryRun) {
        Write-Kape "would copy KAPE from '$KapeSource' -> $Destination" 'Info'
    }
    else {
        if (-not $srcRoot) {
            throw "kape.exe not found inside -KapeSource ($KapeSource). Download KAPE from https://www.kroll.com/kape and point -KapeSource at the extracted folder or the .zip."
        }
        $srcRootResolved = (Resolve-Path -LiteralPath $srcRoot).Path
        $destResolved = if (Test-Path -LiteralPath $Destination) { (Resolve-Path -LiteralPath $Destination).Path } else { '' }

        if ($destResolved -and ($srcRootResolved -ieq $destResolved)) {
            Write-Kape "KapeSource already IS the destination - using in place." 'Info'
        }
        else {
            if ($destHasKape -and -not $Force) {
                throw "A KAPE already exists at $Destination. Re-run with -Force to overwrite, or choose a clean -Destination."
            }
            New-Item -ItemType Directory -Path $Destination -Force | Out-Null
            Write-Kape "Copying KAPE from $srcRootResolved -> $Destination" 'Info'
            Get-ChildItem -LiteralPath $srcRootResolved -Force | ForEach-Object {
                Copy-Item -LiteralPath $_.FullName -Destination $Destination -Recurse -Force
            }
        }
    }

    if ($tempExtract -and (Test-Path -LiteralPath $tempExtract)) {
        Remove-Item -LiteralPath $tempExtract -Recurse -Force -ErrorAction SilentlyContinue
    }
}
elseif ($destHasKape) {
    Write-Kape "No -KapeSource given; using existing KAPE at $Destination." 'Info'
}
else {
    Write-Kape "No KAPE found and no -KapeSource provided." 'Error'
    Write-Kape "KAPE's binaries are proprietary and cannot be auto-downloaded." 'Error'
    Write-Kape "Get KAPE from https://www.kroll.com/kape (registration + EULA), then re-run:" 'Error'
    Write-Kape "  .\Get-KAPE-Offline.ps1 -KapeSource '<path to KAPE.zip or KAPE folder>'" 'Error'
    throw 'KAPE binaries required (-KapeSource). See messages above.'
}

$kapeExe = Join-Path $Destination 'kape.exe'
if (-not $DryRun -and -not (Test-Path -LiteralPath $kapeExe)) {
    throw "Staging incomplete: kape.exe is not present at $kapeExe."
}

# --- phase 2: update kape.exe (Get-KAPEUpdate.ps1 - Kroll) -------------------
Write-Kape "Phase 2/4  Update kape.exe" 'Step'
if ($SkipKapeUpdate) {
    Write-Kape "Skipped (-SkipKapeUpdate)." 'Warn'
}
else {
    $updater = Join-Path $Destination 'Get-KAPEUpdate.ps1'
    if (Test-Path -LiteralPath $updater) {
        if ($DryRun) {
            Write-Kape "would run: $updater" 'Info'
        }
        else {
            try {
                Push-Location $Destination
                & $updater
            }
            catch { Write-Kape "Get-KAPEUpdate failed (continuing): $($_.Exception.Message)" 'Warn' }
            finally { Pop-Location }
        }
    }
    else {
        Write-Kape "Get-KAPEUpdate.ps1 not present - skipping self-update." 'Warn'
    }
}

# --- phase 3: sync Targets / Modules (MIT KapeFiles) ------------------------
Write-Kape "Phase 3/4  Sync Targets/Modules (kape.exe --sync)" 'Step'
if ($SkipSync) {
    Write-Kape "Skipped (-SkipSync)." 'Warn'
}
else {
    $syncArgs = @('--sync')
    if ($SyncUrl) { $syncArgs = @('--sync', $SyncUrl) }
    if ($DryRun) {
        Write-Kape ("would run: kape.exe " + ($syncArgs -join ' ')) 'Info'
    }
    else {
        try {
            Push-Location $Destination
            & $kapeExe @syncArgs
        }
        catch { Write-Kape "kape.exe --sync failed (continuing): $($_.Exception.Message)" 'Warn' }
        finally { Pop-Location }
    }
}

# --- phase 4: EZ Tools into Modules\bin (MIT) ------------------------------
Write-Kape "Phase 4/4  Populate Modules\bin with EZ Tools (.NET $NetVersion)" 'Step'
if ($SkipEZTools) {
    Write-Kape "Skipped (-SkipEZTools)." 'Warn'
}
else {
    $binDir = Join-Path $Destination 'Modules\bin'
    $gztUrl = 'https://raw.githubusercontent.com/EricZimmerman/Get-ZimmermanTools/master/Get-ZimmermanTools.ps1'
    if ($DryRun) {
        Write-Kape "would fetch Get-ZimmermanTools.ps1 and run: -Dest '$binDir' -NetVersion $NetVersion" 'Info'
    }
    else {
        try {
            New-Item -ItemType Directory -Path $binDir -Force | Out-Null
            $gzt = Get-ChildItem -LiteralPath $Destination -Filter 'Get-ZimmermanTools.ps1' -Recurse -Depth 2 -File -ErrorAction SilentlyContinue |
                Select-Object -First 1
            if ($gzt) {
                $gztPath = $gzt.FullName
                Write-Kape "Using bundled Get-ZimmermanTools.ps1: $gztPath" 'Info'
            }
            else {
                $gztPath = Join-Path ([IO.Path]::GetTempPath()) ('Get-ZimmermanTools_' + [Guid]::NewGuid().ToString('N') + '.ps1')
                Write-Kape "Downloading Get-ZimmermanTools.ps1 ..." 'Info'
                Invoke-WebRequest -Uri $gztUrl -OutFile $gztPath -UseBasicParsing
            }
            & $gztPath -Dest $binDir -NetVersion $NetVersion
        }
        catch {
            Write-Kape "EZ Tools population failed - KAPE still collects, but artifact-parsing Modules need these." 'Warn'
            Write-Kape "  reason: $($_.Exception.Message)" 'Warn'
            Write-Kape "  retry later on the internet host with KAPE's own module:" 'Warn'
            Write-Kape "    .\kape.exe --msource $Destination --mdest `$env:TEMP\null --module !!ToolSync --debug" 'Warn'
        }
    }
}

# --- summary + safety checks ------------------------------------------------
Write-Host ''
Write-Kape "Staging complete." 'Success'
if (-not $DryRun) {
    $targetsN = 0; $modulesN = 0; $binN = 0
    $tDir = Join-Path $Destination 'Targets'
    if (Test-Path -LiteralPath $tDir) { $targetsN = @(Get-ChildItem -LiteralPath $tDir -Filter *.tkape -Recurse -File -ErrorAction SilentlyContinue).Count }
    $mDir = Join-Path $Destination 'Modules'
    if (Test-Path -LiteralPath $mDir) { $modulesN = @(Get-ChildItem -LiteralPath $mDir -Filter *.mkape -Recurse -File -ErrorAction SilentlyContinue).Count }
    $bDir = Join-Path $Destination 'Modules\bin'
    if (Test-Path -LiteralPath $bDir) { $binN = @(Get-ChildItem -LiteralPath $bDir -Filter *.exe -Recurse -File -ErrorAction SilentlyContinue).Count }
    Write-Kape ("  kape.exe present : {0}" -f (Test-Path -LiteralPath $kapeExe)) 'Info'
    Write-Kape ("  Targets (.tkape) : {0}" -f $targetsN) 'Info'
    Write-Kape ("  Modules (.mkape) : {0}" -f $modulesN) 'Info'
    Write-Kape ("  Modules\bin .exe : {0}" -f $binN) 'Info'

    # Confirm the .gitignore guard is actually in effect for this destination.
    try {
        $repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)  # tools\deploy -> tools -> repo
        $null = & git -C $repoRoot check-ignore -- $Destination 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Kape "gitignore guard OK - '$Destination' is ignored by git (will NOT be committed)." 'Success'
        }
        else {
            Write-Kape "WARNING: '$Destination' is NOT git-ignored. Do NOT commit it - add it to .gitignore first." 'Error'
        }
    }
    catch { Write-Kape "Could not run 'git check-ignore' to verify the guard (git not found or not a repo)." 'Warn' }
}

Write-Host ''
Write-Kape "Next steps:" 'Step'
Write-Kape "  1. Copy the WHOLE elasticPotato tree to the air-gapped DFIR VM (removable media / robocopy)." 'Info'
Write-Kape "     The git-ignored KAPE payload copies at the filesystem level - gitignore only affects git." 'Info'
Write-Kape "  2. On the VM, run elasticPotato_Main.ps1 -> option 2b. It auto-discovers tools\kape and" 'Info'
Write-Kape "     pushes KAPE to your Windows targets over SMB with no internet calls." 'Info'
