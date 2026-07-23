<#
.SYNOPSIS
  Stage the elasticPotato toolkit's OWN runtime dependencies for air-gapped use,
  then install them on the offline analysis VM.

.DESCRIPTION
  Same pattern as tools\deploy\Get-KAPE-Offline.ps1, but for the dependencies the
  toolkit itself needs to run (not the collector packages it deploys).

    Mode Download  (run on an INTERNET-connected host)
       * PS modules      -> tools\deps\psmodules\   via Save-Module (PSGallery)
       * pip wheels       -> tools\deps\pip\          via pip download (sigma-cli)
       * redistributable  -> tools\deps\tools\        via GitHub releases (-IncludeTools)
         CLIs/collectors
    Mode Install   (run on the AIR-GAPPED analysis VM)
       * copies the saved PS modules into your PowerShell module path
       * pip install --no-index the staged wheels
       * distributes the staged tools to the locations the toolkit looks in
       * offers to register the SecretStore vault (LocalSecrets)

  Everything staged under tools\deps\ (and the tool destinations) is git-ignored,
  so it rides to the air-gapped VM on disk but never enters this public repo.

  NOT handled automatically (proprietary / live-API / OS features - guidance only):
    KAPE (use tools\deploy\Get-KAPE-Offline.ps1), THOR Lite (Nextron registration),
    Python / Git / 7-Zip / OpenSSH client (vendor or Windows features), and the
    live threat-intel APIs (VirusTotal / abuse.ch / OTX) which cannot be bundled.

.PARAMETER Mode
  Download (internet host) or Install (offline VM). If omitted, you are prompted.

.PARAMETER StageRoot
  Staging directory. Default: <repo>\tools\deps.

.PARAMETER IncludeTools
  Also download/distribute the redistributable CLI + collector tools
  (YARA, Scorecard, Loki, UAC, DFIR-ORC). Larger; best effort per tool.

.PARAMETER SkipPip
  Skip the pip (sigma-cli) phase.

.PARAMETER Force
  Overwrite existing staged content / re-copy on install.

.PARAMETER DryRun
  Print each phase's planned action without downloading, copying, or installing.

.EXAMPLE
  # On an internet host:
  .\Get-Dependencies-Offline.ps1 -Mode Download -IncludeTools

.EXAMPLE
  # On the air-gapped VM after carrying the tree over:
  .\Get-Dependencies-Offline.ps1 -Mode Install -IncludeTools

.NOTES
  Compatible with Windows PowerShell 5.1 and PowerShell 7+.
#>
[CmdletBinding()]
param(
    [ValidateSet('Download', 'Install')] [string]$Mode,
    [string]$StageRoot,
    [switch]$IncludeTools,
    [switch]$SkipPip,
    [switch]$Force,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

function Write-Dep {
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
    $tag = if ($DryRun) { '[deps][DRYRUN]' } else { '[deps]' }
    Write-Host "$tag $Message" -ForegroundColor $color
}

# ---- manifests --------------------------------------------------------------
# PS modules from PSGallery (all MIT/Apache, redistributable). Save-Module pulls
# each module's own dependencies too.
$PSModules = @(
    @{ Name = 'Microsoft.PowerShell.SecretManagement'; Hard = $true;  Why = 'Get-Secret / vault - used everywhere' },
    @{ Name = 'Microsoft.PowerShell.SecretStore';      Hard = $true;  Why = 'encrypted vault backend for the secrets' },
    @{ Name = 'Posh-SSH';                              Hard = $false; Why = 'SSH transport (SO 3.0 / router); ssh.exe is the fallback' },
    @{ Name = 'PSSQLite';                              Hard = $false; Why = 'NSRL SQLite enrichment path' },
    @{ Name = 'powershell-yaml';                       Hard = $false; Why = 'declared for Sigma; currently unused by code' }
)
# pip packages (sigma-cli + its elasticsearch backend). LGPL, redistributable.
$PipPackages = @('sigma-cli', 'pysigma-backend-elasticsearch')
# Redistributable release tools. Dest = subfolder under tools\deps\tools; Install
# copies them to the location the toolkit actually looks in (Runtime).
$GitHubTools = @(
    @{ Name = 'YARA';      Repo = 'VirusTotal/yara';    Pattern = 'yara-*win64.zip';   Sub = 'yara';      Runtime = 'codeScanning' },
    @{ Name = 'Scorecard'; Repo = 'ossf/scorecard';     Pattern = '*windows_amd64*';   Sub = 'scorecard'; Runtime = 'codeScanning' },
    @{ Name = 'Loki';      Repo = 'Neo23x0/Loki';       Pattern = 'loki_*.zip';        Sub = 'loki';      Runtime = 'tools\loki' },
    @{ Name = 'UAC';       Repo = 'tclahr/uac';         Pattern = 'uac-*.tar.gz';      Sub = 'uac';       Runtime = 'tools' },
    @{ Name = 'DFIR-ORC';  Repo = 'DFIR-ORC/dfir-orc';  Pattern = '*.zip';             Sub = 'dfir-orc';  Runtime = 'tools' }
)

# ---- resolve paths ----------------------------------------------------------
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)   # tools\deps -> tools -> repo
if (-not $StageRoot) { $StageRoot = Join-Path $repoRoot 'tools\deps' }
$psmodDir = Join-Path $StageRoot 'psmodules'
$pipDir   = Join-Path $StageRoot 'pip'
$toolsDir = Join-Path $StageRoot 'tools'

# ---- pick mode --------------------------------------------------------------
if (-not $PSBoundParameters.ContainsKey('Mode')) {
    Write-Host ''
    Write-Host 'Dependency staging - choose a mode:' -ForegroundColor Cyan
    Write-Host '  [D] Download  - on an INTERNET host, fetch dependencies into tools\deps' -ForegroundColor Gray
    Write-Host '  [I] Install   - on the AIR-GAPPED VM, install the staged dependencies' -ForegroundColor Gray
    $ans = (Read-Host 'Mode [D/I]').Trim().ToUpper()
    if ($ans -eq 'I') { $Mode = 'Install' } else { $Mode = 'Download' }
}
Write-Dep "Mode: $Mode   StageRoot: $StageRoot" 'Step'

# TLS 1.2 for PS 5.1 web calls
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }

function Get-GHReleaseAsset {
    param([string]$Repo, [string]$Pattern, [string]$OutDir)
    $headers = @{ 'User-Agent' = 'elasticPotato-deps' }
    try {
        $tok = Get-Secret -Name 'Github_Access_Token' -AsPlainText -ErrorAction SilentlyContinue
        if ($tok) { $headers['Authorization'] = "token $tok" }
    } catch { }
    $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers $headers -UseBasicParsing
    $asset = @($rel.assets | Where-Object { $_.name -like $Pattern }) | Select-Object -First 1
    if (-not $asset) { throw "no asset matching '$Pattern' in $Repo latest release ($($rel.tag_name))" }
    if (-not (Test-Path -LiteralPath $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
    $out = Join-Path $OutDir $asset.name
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $out -Headers $headers -UseBasicParsing
    return $out
}

# =============================================================================
# DOWNLOAD MODE
# =============================================================================
if ($Mode -eq 'Download') {

    # -- phase 1: PowerShell modules (Save-Module) ----------------------------
    Write-Dep "Phase 1  PowerShell modules -> $psmodDir" 'Step'
    if (-not $DryRun) {
        New-Item -ItemType Directory -Path $psmodDir -Force | Out-Null
        try { Import-PackageProvider -Name NuGet -Force -ErrorAction SilentlyContinue | Out-Null } catch { }
        try { Install-PackageProvider -Name NuGet -Force -Scope CurrentUser -ErrorAction SilentlyContinue | Out-Null } catch { }
    }
    foreach ($m in $PSModules) {
        $tag = if ($m.Hard) { 'REQUIRED' } else { 'optional' }
        if ($DryRun) { Write-Dep "would Save-Module $($m.Name)  ($tag - $($m.Why))" 'Info'; continue }
        try {
            Save-Module -Name $m.Name -Path $psmodDir -Repository PSGallery -Force -ErrorAction Stop
            Write-Dep "saved $($m.Name)  ($tag)" 'Success'
        } catch {
            $lvl = if ($m.Hard) { 'Error' } else { 'Warn' }
            Write-Dep "Save-Module $($m.Name) failed ($tag): $($_.Exception.Message)" $lvl
        }
    }

    # -- phase 2: pip wheels (sigma-cli) --------------------------------------
    Write-Dep "Phase 2  pip wheels -> $pipDir" 'Step'
    if ($SkipPip) {
        Write-Dep "Skipped (-SkipPip)." 'Warn'
    } else {
        $py = $null
        $pipArgsBase = $null
        $pyCmd = Get-Command python -ErrorAction SilentlyContinue
        if (-not $pyCmd) { $pyCmd = Get-Command python3 -ErrorAction SilentlyContinue }
        if ($pyCmd) { $py = $pyCmd.Source; $pipArgsBase = @('-m', 'pip') }
        if ($DryRun) {
            Write-Dep ("would run: python -m pip download " + ($PipPackages -join ' ') + " -d $pipDir") 'Info'
        } elseif (-not $py) {
            Write-Dep "Python not found - skipping pip. (sigma-cli is optional; install Python then re-run, or -SkipPip.)" 'Warn'
        } else {
            try {
                New-Item -ItemType Directory -Path $pipDir -Force | Out-Null
                & $py @pipArgsBase download @PipPackages -d $pipDir
                if ($LASTEXITCODE -ne 0) { throw "pip download exited $LASTEXITCODE" }
                Write-Dep "pip wheels downloaded." 'Success'
            } catch { Write-Dep "pip download failed (continuing): $($_.Exception.Message)" 'Warn' }
        }
    }

    # -- phase 3: redistributable tools (GitHub releases) ---------------------
    Write-Dep "Phase 3  Redistributable tools -> $toolsDir" 'Step'
    if (-not $IncludeTools) {
        Write-Dep "Skipped (add -IncludeTools to fetch YARA / Scorecard / Loki / UAC / DFIR-ORC)." 'Warn'
    } else {
        foreach ($t in $GitHubTools) {
            $dest = Join-Path $toolsDir $t.Sub
            if ($DryRun) { Write-Dep "would fetch $($t.Name) ($($t.Repo), '$($t.Pattern)') -> $dest" 'Info'; continue }
            try {
                $file = Get-GHReleaseAsset -Repo $t.Repo -Pattern $t.Pattern -OutDir $dest
                Write-Dep "fetched $($t.Name): $(Split-Path $file -Leaf)" 'Success'
            } catch {
                Write-Dep "$($t.Name) fetch failed (continuing): $($_.Exception.Message)" 'Warn'
            }
        }
    }

    # -- guidance for the non-redistributable / manual pieces -----------------
    Write-Host ''
    Write-Dep "Manual / non-redistributable dependencies (not fetched here):" 'Step'
    Write-Dep "  KAPE      -> tools\deploy\Get-KAPE-Offline.ps1 (Kroll EULA; separate helper)" 'Info'
    Write-Dep "  THOR Lite -> register at nextron-systems.com, place thor*.exe under .\tools" 'Info'
    Write-Dep "  Python/Git/7-Zip/OpenSSH client -> vendor installers or Windows features" 'Info'
    Write-Dep "  VirusTotal / abuse.ch / OTX -> live APIs (set API-key secrets; pre-run enrichment online)" 'Info'

    # -- gitignore self-check (check a payload dir, not tools\deps itself, since
    #    the helper + README under tools\deps are intentionally tracked) --------
    if (-not $DryRun) {
        try {
            $null = & git -C $repoRoot check-ignore -- $psmodDir 2>$null
            if ($LASTEXITCODE -eq 0) { Write-Dep "gitignore guard OK - staged payloads under '$StageRoot' are ignored by git." 'Success' }
            else { Write-Dep "WARNING: '$psmodDir' is NOT git-ignored. Do NOT commit staged deps; check .gitignore." 'Error' }
        } catch { Write-Dep "Could not run 'git check-ignore' to verify the guard." 'Warn' }
    }

    Write-Host ''
    Write-Dep "Download complete. Next: carry the whole elasticPotato tree to the air-gapped VM," 'Step'
    Write-Dep "  then run:  .\tools\deps\Get-Dependencies-Offline.ps1 -Mode Install$(if($IncludeTools){' -IncludeTools'})" 'Step'
}

# =============================================================================
# INSTALL MODE
# =============================================================================
if ($Mode -eq 'Install') {

    # -- phase 1: PowerShell modules into the module path ---------------------
    Write-Dep "Phase 1  Install PowerShell modules" 'Step'
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        $modDest = Join-Path $HOME 'Documents\PowerShell\Modules'
    } else {
        $modDest = Join-Path $HOME 'Documents\WindowsPowerShell\Modules'
    }
    if (-not (Test-Path -LiteralPath $psmodDir)) {
        Write-Dep "No staged modules at $psmodDir - run -Mode Download on an internet host first." 'Error'
    } else {
        if ($DryRun) {
            Write-Dep "would copy module folders from $psmodDir -> $modDest" 'Info'
        } else {
            New-Item -ItemType Directory -Path $modDest -Force | Out-Null
            foreach ($modFolder in @(Get-ChildItem -LiteralPath $psmodDir -Directory -ErrorAction SilentlyContinue)) {
                try {
                    Copy-Item -LiteralPath $modFolder.FullName -Destination $modDest -Recurse -Force
                    Write-Dep "installed module: $($modFolder.Name)" 'Success'
                } catch { Write-Dep "copy $($modFolder.Name) failed: $($_.Exception.Message)" 'Warn' }
            }
            foreach ($n in 'Microsoft.PowerShell.SecretManagement', 'Microsoft.PowerShell.SecretStore') {
                if (Get-Module -ListAvailable -Name $n) { Write-Dep "available: $n" 'Success' }
                else { Write-Dep "NOT available after install: $n" 'Error' }
            }
        }
    }

    # -- phase 2: pip install --no-index --------------------------------------
    Write-Dep "Phase 2  Install pip wheels (offline)" 'Step'
    if ($SkipPip) {
        Write-Dep "Skipped (-SkipPip)." 'Warn'
    } elseif (-not (Test-Path -LiteralPath $pipDir)) {
        Write-Dep "No staged wheels at $pipDir - skipping." 'Warn'
    } else {
        $pyCmd = Get-Command python -ErrorAction SilentlyContinue
        if (-not $pyCmd) { $pyCmd = Get-Command python3 -ErrorAction SilentlyContinue }
        if ($DryRun) {
            Write-Dep ("would run: python -m pip install --no-index --find-links $pipDir " + ($PipPackages -join ' ')) 'Info'
        } elseif (-not $pyCmd) {
            Write-Dep "Python not found on this VM - install Python, then: pip install --no-index --find-links '$pipDir' sigma-cli" 'Warn'
        } else {
            try {
                & $pyCmd.Source -m pip install --no-index --find-links $pipDir @PipPackages
                if ($LASTEXITCODE -ne 0) { throw "pip install exited $LASTEXITCODE" }
                Write-Dep "sigma-cli installed offline." 'Success'
            } catch { Write-Dep "pip install failed (continuing): $($_.Exception.Message)" 'Warn' }
        }
    }

    # -- phase 3: distribute tools to their runtime locations -----------------
    Write-Dep "Phase 3  Distribute tools" 'Step'
    if (-not $IncludeTools) {
        Write-Dep "Skipped (add -IncludeTools if you staged tools during Download)." 'Warn'
    } elseif (-not (Test-Path -LiteralPath $toolsDir)) {
        Write-Dep "No staged tools at $toolsDir - skipping." 'Warn'
    } else {
        foreach ($t in $GitHubTools) {
            $src = Join-Path $toolsDir $t.Sub
            if (-not (Test-Path -LiteralPath $src)) { continue }
            $rtDest = Join-Path $repoRoot $t.Runtime
            if ($DryRun) { Write-Dep "would place $($t.Name): $src -> $rtDest" 'Info'; continue }
            try {
                New-Item -ItemType Directory -Path $rtDest -Force | Out-Null
                Copy-Item -LiteralPath (Join-Path $src '*') -Destination $rtDest -Recurse -Force
                Write-Dep "placed $($t.Name) -> $rtDest" 'Success'
            } catch { Write-Dep "place $($t.Name) failed: $($_.Exception.Message)" 'Warn' }
        }
        Write-Dep "Note: archive tools (UAC .tar.gz, some Loki/YARA .zip) may need extracting in place." 'Info'
    }

    # -- phase 4: offer to register the SecretStore vault ---------------------
    Write-Dep "Phase 4  SecretStore vault" 'Step'
    if ($DryRun) {
        Write-Dep "would offer: Register-SecretVault -Name LocalSecrets -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault" 'Info'
    } else {
        $already = $false
        try { $already = @(Get-SecretVault -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'LocalSecrets' }).Count -gt 0 } catch { }
        if ($already) {
            Write-Dep "Vault 'LocalSecrets' already registered." 'Success'
        } else {
            $reg = (Read-Host "Register the default SecretStore vault 'LocalSecrets' now? [y/N]").Trim()
            if ($reg -match '^[yY]') {
                try {
                    Register-SecretVault -Name LocalSecrets -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault
                    Write-Dep "Registered 'LocalSecrets'. Add secrets with Set-Secret (see the #Requirements header)." 'Success'
                } catch { Write-Dep "Register-SecretVault failed: $($_.Exception.Message)" 'Warn' }
            } else {
                Write-Dep "Skipped. Register later: Register-SecretVault -Name LocalSecrets -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault" 'Info'
            }
        }
    }

    Write-Host ''
    Write-Dep "Install complete. The toolkit's PS-module + Sigma dependencies are now available offline." 'Success'
}
