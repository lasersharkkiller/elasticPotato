<#
.SYNOPSIS
    Downloads vulnerable driver lists from multiple sources and caches a filtered,
    compact version for use by ElasticAlertAgent BYOVD detection.

.DESCRIPTION
    Sources (all fetched and merged):
      1. https://www.loldrivers.io/api/drivers.json          (~509 entries, ~26 MB)
      2. LOLDrivers GitHub Sigma detection YAML              (~490 filenames)
      3. SigmaHQ community Sigma detection YAML              (~413 filenames)

    Output  : detections\loldrivers\loldrivers_cache.json
              detections\loldrivers\_meta.json

    Filters OUT:
      - Core Windows system drivers (always loaded; would cause FPs)
      - MD5/hash-named files (e.g. 4118b86e49...sys)
      - driver_XXXXXXXX.sys hash-based names
      - Single-char / double-char filenames (1.sys, a.sys, b1.sys)
      - Pure numeric filenames (80.sys, 81.sys)

    Offline fallback: if all downloads fail and a cache already exists,
    reports the cached count and returns silently. Partial success (some
    sources reachable) still writes an updated cache.

    Auto-update is called from Elastic alert triage menu options (3b/3c/3f).

.EXAMPLE
    Update-LolDriversCache
    Update-LolDriversCache -Force   # re-download even if cache is fresh (<24h)
#>

function Update-LolDriversCache {
    [CmdletBinding()]
    param(
        [string]$CacheDir = (Join-Path $PSScriptRoot "loldrivers"),
        [switch]$Force
    )

    $urlApi     = "https://www.loldrivers.io/api/drivers.json"
    $urlSigma1  = "https://raw.githubusercontent.com/magicsword-io/LOLDrivers/main/detections/sigma/driver_load_win_vuln_drivers_names.yml"
    $urlSigma2  = "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/driver_load/driver_load_win_vuln_drivers_names.yml"
    $cacheFile  = Join-Path $CacheDir "loldrivers_cache.json"
    $metaFile   = Join-Path $CacheDir "_meta.json"

    # ------------------------------------------------------------------
    # Core Windows drivers that are legitimately always loaded — including
    # them would create constant false positives on every analysed host.
    # ------------------------------------------------------------------
    $windowsCoreDrivers = @(
        'afd.sys','cng.sys','classpnp.sys','csc.sys','fltmgr.sys',
        'fwpkclnt.sys','ks.sys','ksecdd.sys','mup.sys','ndis.sys',
        'netio.sys','portcls.sys','rdbss.sys','scsiport.sys','tdi.sys',
        'usbd.sys','wdfldr.sys','wmilib.sys','wpprecorder.sys',
        'usbxhci.sys','usbhub.sys','usbport.sys'
    )

    # ------------------------------------------------------------------
    # Skip re-download if cache was refreshed in the last 24 hours
    # ------------------------------------------------------------------
    if (-not $Force -and (Test-Path $cacheFile) -and (Test-Path $metaFile)) {
        try {
            $meta = Get-Content $metaFile -Raw -ErrorAction Stop | ConvertFrom-Json
            $age  = (Get-Date) - [datetime]$meta.last_updated
            if ($age.TotalHours -lt 24) {
                Write-Host "[LolDrivers] Cache fresh ($([int]$age.TotalHours)h old, $($meta.driver_count) drivers). Use -Force to refresh." -ForegroundColor DarkGray
                return
            }
        } catch {}
    }

    # ------------------------------------------------------------------
    # Ensure cache directory exists
    # ------------------------------------------------------------------
    if (-not (Test-Path $CacheDir)) {
        New-Item -Path $CacheDir -ItemType Directory -Force | Out-Null
    }

    # ------------------------------------------------------------------
    # Download from all three sources (individual error handling)
    # ------------------------------------------------------------------
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add('User-Agent', 'LoadedPotato-LolDriversUpdater/1.0')

    # Source 1: loldrivers.io JSON API
    $rawApi = $null
    Write-Host "[LolDrivers] [1/3] Downloading loldrivers.io API..." -ForegroundColor Cyan
    try {
        $rawApi = $wc.DownloadString($urlApi)
        Write-Host "[LolDrivers]       OK ($([Math]::Round($rawApi.Length / 1MB, 1)) MB)" -ForegroundColor DarkGray
    } catch {
        Write-Host "[LolDrivers]       Failed: $_" -ForegroundColor Yellow
    }

    # Source 2: LOLDrivers GitHub Sigma YAML
    $rawSigma1 = $null
    Write-Host "[LolDrivers] [2/3] Downloading LOLDrivers Sigma YAML..." -ForegroundColor Cyan
    try {
        $rawSigma1 = $wc.DownloadString($urlSigma1)
        Write-Host "[LolDrivers]       OK ($([Math]::Round($rawSigma1.Length / 1KB, 0)) KB, $($rawSigma1.Split("`n").Count) lines)" -ForegroundColor DarkGray
    } catch {
        Write-Host "[LolDrivers]       Failed: $_" -ForegroundColor Yellow
    }

    # Source 3: SigmaHQ community Sigma YAML
    $rawSigma2 = $null
    Write-Host "[LolDrivers] [3/3] Downloading SigmaHQ Sigma YAML..." -ForegroundColor Cyan
    try {
        $rawSigma2 = $wc.DownloadString($urlSigma2)
        Write-Host "[LolDrivers]       OK ($([Math]::Round($rawSigma2.Length / 1KB, 0)) KB, $($rawSigma2.Split("`n").Count) lines)" -ForegroundColor DarkGray
    } catch {
        Write-Host "[LolDrivers]       Failed: $_" -ForegroundColor Yellow
    }

    # If all sources failed, fall back to existing cache
    if (-not $rawApi -and -not $rawSigma1 -and -not $rawSigma2) {
        Write-Host "[LolDrivers] All sources unreachable." -ForegroundColor Yellow
        if (Test-Path $cacheFile) {
            try {
                $n = @(Get-Content $cacheFile -Raw | ConvertFrom-Json).Count
                Write-Host "[LolDrivers] Offline - using $n cached drivers." -ForegroundColor DarkGray
            } catch {
                Write-Host "[LolDrivers] Offline and cache unreadable - hardcoded fallback active." -ForegroundColor DarkYellow
            }
        } else {
            Write-Host "[LolDrivers] Offline and no cache found - hardcoded fallback active." -ForegroundColor DarkYellow
        }
        return
    }

    # ------------------------------------------------------------------
    # Extract and merge filenames from all sources
    # Shared filter rules applied uniformly across all sources.
    # ------------------------------------------------------------------
    Write-Host "[LolDrivers] Extracting and merging driver filenames..." -ForegroundColor DarkGray

    $hashNameRx   = '^[0-9a-f]{32}$'        # pure MD5 filename stem
    $hashDrvRx    = '^driver_[0-9a-f]{6,}$' # driver_XXXXXXXX hash names
    $singleCharRx = '^[a-z0-9]{1,2}$'       # a, b1, c, d2 etc.
    $genericNumRx = '^[0-9]+$'              # 80, 81, 834761775

    $seen    = @{}
    $drivers = [System.Collections.Generic.List[PSCustomObject]]::new()
    $countApi    = 0
    $countSigma1 = 0
    $countSigma2 = 0
    $entryCount  = 0

    # --- Source 1: loldrivers.io JSON API ---
    # Uses Filename / OriginalFilename fields. Regex avoids ConvertFrom-Json
    # failure on duplicate keys ('init'/'INIT') present in the feed.
    if ($rawApi) {
        $entryCount = ([regex]::Matches($rawApi, '"Id"\s*:\s*"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"')).Count

        $rxApi = [System.Text.RegularExpressions.Regex]::new(
            '"(?:Filename|OriginalFilename)"\s*:\s*"([^"]+\.sys)"',
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
        )
        foreach ($m in $rxApi.Matches($rawApi)) {
            $fn   = $m.Groups[1].Value.Trim().ToLower()
            if (-not $fn -or $fn.Length -lt 5)     { continue }
            if ($fn -notmatch '\.sys$')             { continue }
            $stem = [System.IO.Path]::GetFileNameWithoutExtension($fn)
            if ($windowsCoreDrivers -contains $fn)  { continue }
            if ($stem -match $hashNameRx)            { continue }
            if ($stem -match $hashDrvRx)             { continue }
            if ($stem -match $singleCharRx)          { continue }
            if ($stem -match $genericNumRx)          { continue }
            if ($seen.ContainsKey($fn))              { continue }
            $seen[$fn] = $true
            [void]$drivers.Add([PSCustomObject]@{ n = $fn })
            $countApi++
        }
        Write-Host "[LolDrivers]   Source 1 (loldrivers.io API)  : $countApi drivers from $entryCount catalogue entries" -ForegroundColor DarkGray
    }

    # --- Source 2: LOLDrivers GitHub Sigma YAML ---
    # Entries are YAML string values like: - '\rtcore64.sys'
    # Regex captures the filename after the leading single backslash.
    if ($rawSigma1) {
        $rxSigma = [System.Text.RegularExpressions.Regex]::new(
            "\\([a-zA-Z0-9_.\-]+\.sys)",
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
        )
        foreach ($m in $rxSigma.Matches($rawSigma1)) {
            $fn   = $m.Groups[1].Value.Trim().ToLower()
            if (-not $fn -or $fn.Length -lt 5)     { continue }
            $stem = [System.IO.Path]::GetFileNameWithoutExtension($fn)
            if ($windowsCoreDrivers -contains $fn)  { continue }
            if ($stem -match $hashNameRx)            { continue }
            if ($stem -match $hashDrvRx)             { continue }
            if ($stem -match $singleCharRx)          { continue }
            if ($stem -match $genericNumRx)          { continue }
            if ($seen.ContainsKey($fn))              { continue }
            $seen[$fn] = $true
            [void]$drivers.Add([PSCustomObject]@{ n = $fn })
            $countSigma1++
        }
        Write-Host "[LolDrivers]   Source 2 (LOLDrivers Sigma)    : +$countSigma1 new drivers" -ForegroundColor DarkGray
    }

    # --- Source 3: SigmaHQ community Sigma YAML ---
    # Same format as Source 2.
    if ($rawSigma2) {
        $rxSigma = [System.Text.RegularExpressions.Regex]::new(
            "\\([a-zA-Z0-9_.\-]+\.sys)",
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
        )
        foreach ($m in $rxSigma.Matches($rawSigma2)) {
            $fn   = $m.Groups[1].Value.Trim().ToLower()
            if (-not $fn -or $fn.Length -lt 5)     { continue }
            $stem = [System.IO.Path]::GetFileNameWithoutExtension($fn)
            if ($windowsCoreDrivers -contains $fn)  { continue }
            if ($stem -match $hashNameRx)            { continue }
            if ($stem -match $hashDrvRx)             { continue }
            if ($stem -match $singleCharRx)          { continue }
            if ($stem -match $genericNumRx)          { continue }
            if ($seen.ContainsKey($fn))              { continue }
            $seen[$fn] = $true
            [void]$drivers.Add([PSCustomObject]@{ n = $fn })
            $countSigma2++
        }
        Write-Host "[LolDrivers]   Source 3 (SigmaHQ community)   : +$countSigma2 new drivers" -ForegroundColor DarkGray
    }

    Write-Host "[LolDrivers] Total: $($drivers.Count) unique trackable drivers (merged, filtered)" -ForegroundColor Cyan

    # ------------------------------------------------------------------
    # Write cache files
    # ------------------------------------------------------------------
    $drivers | ConvertTo-Json -Depth 4 -Compress | Set-Content -LiteralPath $cacheFile -Encoding UTF8

    [PSCustomObject]@{
        last_updated    = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')
        sources         = @("loldrivers.io/api", "LOLDrivers-sigma", "SigmaHQ-sigma")
        entry_count     = $entryCount
        driver_count    = $drivers.Count
        source_breakdown = [PSCustomObject]@{
            loldrivers_api   = $countApi
            loldrivers_sigma = $countSigma1
            sigmahq_sigma    = $countSigma2
        }
    } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $metaFile -Encoding UTF8

    Write-Host "[LolDrivers] Cache written -> $cacheFile" -ForegroundColor Green
    Write-Host "[LolDrivers] $($drivers.Count) drivers tracked across 3 sources" -ForegroundColor Green
}

Export-ModuleMember -Function Update-LolDriversCache
