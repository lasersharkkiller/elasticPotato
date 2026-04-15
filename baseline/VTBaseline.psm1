function Get-VTBaseline {
    param(
        [string]$AttributionPattern = "equifax"
    )

    # --- API SETUP ---
    # Dynamically discover every VT_API_Key_* secret in the vault so new keys
    # (VT_API_Key_4, VT_API_Key_5, ...) auto-join the rotation without edits.
    # Secrets are sorted by the trailing number so rotation order stays stable.
    $VTKeys = @()
    try {
        $infos = Get-SecretInfo -Name 'VT_API_Key_*' -ErrorAction Stop |
                 Sort-Object { if ($_.Name -match '_(\d+)$') { [int]$matches[1] } else { [int]::MaxValue } }
    } catch {
        Write-Error "Unable to enumerate secrets matching 'VT_API_Key_*'. Is SecretManagement loaded and a vault registered?"
        return
    }

    foreach ($info in $infos) {
        try {
            $k = (Get-Secret -Name $info.Name -AsPlainText -ErrorAction Stop).Trim()
            if (-not [string]::IsNullOrWhiteSpace($k)) { $VTKeys += $k }
        } catch {
            Write-Host "[WARN] Could not load $($info.Name) from vault." -ForegroundColor Yellow
        }
    }

    if ($VTKeys.Count -eq 0) {
        Write-Error "No VT API keys found in vault (expected one or more VT_API_Key_* secrets, e.g. VT_API_Key_1, VT_API_Key_2)."
        return
    }

    Write-Host "Loaded $($VTKeys.Count) VT API key(s) ($(($infos | ForEach-Object Name) -join ', ')). Rotating with 15s spacing per key (~$($VTKeys.Count * 4) req/min combined)." -ForegroundColor DarkCyan

    # Per-key last-call timestamps - using script scope so nested function can update them
    $script:VTMinDelayMs = 15000  # 4 req/min = 15s minimum spacing per key
    $script:VTKeyLastCall = @{}
    for ($j = 0; $j -lt $VTKeys.Count; $j++) {
        $script:VTKeyLastCall[$j] = [DateTime]::MinValue
    }

    function Invoke-VTRequest {
        param([string]$Uri, [string]$Method = "Get")

        # Find the key whose cooldown has expired, or the one closest to ready
        $now           = [DateTime]::UtcNow
        $chosenIdx     = -1
        $earliestReady = [DateTime]::MaxValue

        for ($k = 0; $k -lt $VTKeys.Count; $k++) {
            $readyAt = $script:VTKeyLastCall[$k].AddMilliseconds($script:VTMinDelayMs)
            if ($readyAt -le $now) {
                $chosenIdx = $k
                break
            }
            if ($readyAt -lt $earliestReady) {
                $earliestReady = $readyAt
                $chosenIdx = $k
            }
        }

        $waitMs = ($script:VTKeyLastCall[$chosenIdx].AddMilliseconds($script:VTMinDelayMs) - [DateTime]::UtcNow).TotalMilliseconds
        if ($waitMs -gt 0) {
            $waitSec = [Math]::Round($waitMs / 1000, 1)
            Write-Host "    [Rate Limit] Key $($chosenIdx + 1) cooling down - waiting ${waitSec}s..." -ForegroundColor DarkGray
            Start-Sleep -Milliseconds ([Math]::Ceiling($waitMs))
        }

        $script:VTKeyLastCall[$chosenIdx] = [DateTime]::UtcNow
        $Headers = @{ "x-apikey" = $VTKeys[$chosenIdx]; "Content-Type" = "application/json" }

        return Invoke-RestMethod -Uri $Uri -Headers $Headers -Method $Method
    }

    # --- FOLDER CONFIGURATION ---
    $mainBase      = "output-baseline\VirusTotal-main"
    $behaviorsBase = "output-baseline\VirusTotal-behaviors"

    # Known-good signed/verified
    $mainSignedVerified      = Join-Path $mainBase      "SignedVerified"
    $behaviorsSignedVerified = Join-Path $behaviorsBase "SignedVerified"
    # Unsigned Windows
    $mainUnsignedWin       = Join-Path $mainBase      "unsignedWin"
    $behaviorsUnsignedWin  = Join-Path $behaviorsBase "unsignedWin"
    # Unsigned Linux
    $mainUnsignedLinux       = Join-Path $mainBase      "unsignedLinux"
    $behaviorsUnsignedLinux  = Join-Path $behaviorsBase "unsignedLinux"
    # Unverified
    $mainUnverified     = Join-Path $mainBase      "unverified"
    $behaviorsUnverified = Join-Path $behaviorsBase "unverified"
    # Drivers
    $mainDrivers        = Join-Path $mainBase      "drivers"
    $behaviorsDrivers   = Join-Path $behaviorsBase "drivers"
    # Malicious (kept strictly separate from known-good)
    $mainMalicious      = Join-Path $mainBase      "malicious"
    $behaviorsMalicious = Join-Path $behaviorsBase "malicious"

    foreach ($path in @(
        $mainSignedVerified, $behaviorsSignedVerified,
        $mainUnsignedWin, $behaviorsUnsignedWin,
        $mainUnsignedLinux, $behaviorsUnsignedLinux,
        $mainUnverified, $behaviorsUnverified,
        $mainDrivers, $behaviorsDrivers,
        $mainMalicious, $behaviorsMalicious
    )) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
    }

    # --- LOAD MISSING HASHES TRACKER ---
    $missingHashesPath = "output\MissingHashes.csv"
    $missingHashes = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    if (Test-Path $missingHashesPath) {
        try {
            Import-Csv -Path $missingHashesPath | ForEach-Object {
                if ($_.Hash) { [void]$missingHashes.Add($_.Hash) }
            }
            Write-Host "Loaded $($missingHashes.Count) known-404 hashes from MissingHashes.csv." -ForegroundColor DarkGray
        } catch {
            Write-Host "[WARN] Could not read MissingHashes.csv: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    # --- LOAD BASELINES ---
    $unverifiedProcsBaseline    = Get-Content output\unverifiedProcsBaseline.json    | ConvertFrom-Json
    $unsignedWinProcsBaseline   = Get-Content output\unsignedWinProcsBaseline.json   | ConvertFrom-Json
    $unsignedLinuxProcsBaseline = Get-Content output\unsignedLinuxProcsBaseline.json | ConvertFrom-Json
    $signedVerifiedProcsBaseline = Get-Content output\signedVerifiedProcsBaseline.json | ConvertFrom-Json
    $maliciousProcsBaseline     = Get-Content output\maliciousProcsBaseline.json     | ConvertFrom-Json
    $driversBaseline            = Get-Content output\driversBaseline.json            | ConvertFrom-Json

    # --- LOAD NSRL CSV ---
    # Windows: VT signature_info checked at lookup time → SignedVerified or unsignedWin
    # Linux:   always unsignedLinux (no Authenticode)
    $nsrlWindowsHashes = [System.Collections.Generic.List[string]]::new()
    $nsrlLinuxHashes   = [System.Collections.Generic.List[string]]::new()
    $nsrlCsvPath = "NSRL\nsrl_reduced.csv"
    if (Test-Path $nsrlCsvPath) {
        Import-Csv $nsrlCsvPath | ForEach-Object {
            if (-not $_.Hash) { return }
            if ($_.OsName -like '*Windows*') { $nsrlWindowsHashes.Add($_.Hash) }
            else                             { $nsrlLinuxHashes.Add($_.Hash)   }
        }
        Write-Host "Loaded NSRL: $($nsrlWindowsHashes.Count) Windows, $($nsrlLinuxHashes.Count) Linux." -ForegroundColor DarkGray
    } else {
        Write-Host "[WARN] NSRL\nsrl_reduced.csv not found - skipping NSRL section." -ForegroundColor Yellow
    }

    # ---------------------------------------------------------
    # HELPER: Process-Hash
    # ---------------------------------------------------------
    function Process-Hash {
        param(
            [string]$Hash,
            [string]$MainPath,
            [string]$BehaviorsPath
        )

        $mainFile   = Join-Path $MainPath     "$Hash.json"
        $behaveFile = Join-Path $BehaviorsPath "$Hash.json"

        # Skip if already confirmed missing from VT
        if ($missingHashes.Contains($Hash)) {
            Write-Host "  [SKIP] $Hash is in MissingHashes.csv - known 404." -ForegroundColor DarkGray
            return
        }

        if ((Test-Path $mainFile) -and (Test-Path $behaveFile)) { return }

        # 1. Main VT Report
        if (-not (Test-Path $mainFile)) {
            Write-Host "  Main report missing for $Hash. Querying VirusTotal..." -ForegroundColor Yellow
            try {
                $response = Invoke-VTRequest -Uri "https://www.virustotal.com/api/v3/files/$Hash"
                $response | ConvertTo-Json -Depth 6 | Set-Content -Path $mainFile
                Write-Host "  [OK] Main report saved." -ForegroundColor Green
            } catch {
                $code = $null
                try { $code = $_.Exception.Response.StatusCode.value__ } catch {}

                if ($code -eq 429) {
                    Write-Host "  [!] VT Quota Exceeded (429). Stopping." -ForegroundColor Red
                    $script:QuotaHit = $true
                    return
                } elseif ($code -eq 404) {
                    Write-Host "  [404] $Hash not found in VT. Adding to MissingHashes.csv." -ForegroundColor DarkGray
                    [void]$missingHashes.Add($Hash)
                    [PSCustomObject]@{ Hash = $Hash; DateChecked = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ") } |
                        Export-Csv -Path $missingHashesPath -Append -NoTypeInformation
                    return
                } else {
                    Write-Host "  [ERROR] HTTP $code - $($_.Exception.Message)" -ForegroundColor Red
                }
            }
        }

        if ($script:QuotaHit) { return }

        # 2. Behaviors Report
        if (-not (Test-Path $behaveFile)) {
            Write-Host "  Behaviors report missing for $Hash. Querying VirusTotal..." -ForegroundColor Yellow
            try {
                $response = Invoke-VTRequest -Uri "https://www.virustotal.com/api/v3/files/$Hash/behaviour_summary"
                $response | ConvertTo-Json -Depth 10 | Set-Content -Path $behaveFile
                Write-Host "  [OK] Behaviors report saved." -ForegroundColor Green
            } catch {
                $code = $null
                try { $code = $_.Exception.Response.StatusCode.value__ } catch {}
                if ($code -eq 429) {
                    Write-Host "  [!] VT Quota Exceeded (429). Stopping." -ForegroundColor Red
                    $script:QuotaHit = $true
                }
                else { Write-Host "  [ERROR] Behaviors HTTP $code - $($_.Exception.Message)" -ForegroundColor Red }
            }
        }
    }

    # --- PROCESSING LOOPS ---
    $script:QuotaHit = $false

    # 1. Unverified Baseline
    Write-Host "`nIterating Through Unverified Baseline..." -ForegroundColor DarkCyan
    foreach ($proc in $unverifiedProcsBaseline) {
        if ($script:QuotaHit) { break }
        $fileHash = $proc.value[2]
        if (-not $fileHash) { continue }
        Process-Hash -Hash $fileHash -MainPath $mainUnverified -BehaviorsPath $behaviorsUnverified
    }

    # 2. Windows Unsigned Baseline
    Write-Host "`nIterating Through Windows Unsigned Baseline..." -ForegroundColor DarkCyan
    foreach ($proc in $unsignedWinProcsBaseline) {
        if ($script:QuotaHit) { break }
        $fileHash = $proc.value[2]
        if (-not $fileHash) { continue }
        Process-Hash -Hash $fileHash -MainPath $mainUnsignedWin -BehaviorsPath $behaviorsUnsignedWin
    }

    # 3. Linux Unsigned Baseline
    Write-Host "`nIterating Through Linux Unsigned Baseline..." -ForegroundColor DarkCyan
    foreach ($proc in $unsignedLinuxProcsBaseline) {
        if ($script:QuotaHit) { break }
        $fileHash = $proc.value[2]
        if (-not $fileHash) { continue }
        Process-Hash -Hash $fileHash -MainPath $mainUnsignedLinux -BehaviorsPath $behaviorsUnsignedLinux
    }

    # 4. Signed Verified Baseline
    Write-Host "`nIterating Through SignedVerified Baseline..." -ForegroundColor DarkCyan
    foreach ($proc in $signedVerifiedProcsBaseline) {
        if ($script:QuotaHit) { break }
        $fileHash = $proc.value[2]
        if (-not $fileHash) { continue }
        Process-Hash -Hash $fileHash -MainPath $mainSignedVerified -BehaviorsPath $behaviorsSignedVerified
    }

    # 4b. NSRL Windows - VT signature check routes to SignedVerified, unverified, or unsignedWin
    Write-Host "`nIterating Through NSRL Windows Hashes..." -ForegroundColor DarkCyan
    foreach ($fileHash in $nsrlWindowsHashes) {
        if ($script:QuotaHit) { break }
        if ($missingHashes.Contains($fileHash)) { continue }

        $svMain = Join-Path $mainSignedVerified "$fileHash.json"
        $uvMain = Join-Path $mainUnverified     "$fileHash.json"
        $uwMain = Join-Path $mainUnsignedWin    "$fileHash.json"
        if ((Test-Path $svMain) -or (Test-Path $uvMain) -or (Test-Path $uwMain)) { continue }

        try {
            $vtData  = Invoke-VTRequest -Uri "https://www.virustotal.com/api/v3/files/$fileHash"
            $sigInfo    = $vtData.data.attributes.signature_info
            $sigVerified = if ($sigInfo) { $sigInfo.verified } else { $null }
            $destMain, $destBeh, $label = if ([string]::IsNullOrEmpty($sigVerified)) {
                $mainUnsignedWin,    $behaviorsUnsignedWin,    'unsignedWin'
            } elseif ($sigVerified -eq "Signed") {
                $mainSignedVerified, $behaviorsSignedVerified, 'SignedVerified'
            } else {
                $mainUnverified,     $behaviorsUnverified,     'unverified'
            }

            $vtData | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $destMain "$fileHash.json")
            Write-Host "  [OK] $fileHash -> $label" -ForegroundColor Green

            try {
                $beh = Invoke-VTRequest -Uri "https://www.virustotal.com/api/v3/files/$fileHash/behaviour_summary"
                $beh | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $destBeh "$fileHash.json")
            } catch { Write-Host "  [WARN] Behaviors unavailable for $fileHash" -ForegroundColor DarkGray }

        } catch {
            $code = $null
            try { $code = $_.Exception.Response.StatusCode.value__ } catch {}
            if ($code -eq 429) {
                Write-Host "  [!] VT Quota Exceeded (429). Stopping." -ForegroundColor Red
                $script:QuotaHit = $true
            } elseif ($code -eq 404) {
                Write-Host "  [404] $fileHash not in VT." -ForegroundColor DarkGray
                [void]$missingHashes.Add($fileHash)
                [PSCustomObject]@{ Hash = $fileHash; DateChecked = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ") } |
                    Export-Csv -Path $missingHashesPath -Append -NoTypeInformation
            } else {
                Write-Host "  [ERROR] HTTP $code - $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }

    # 4c. NSRL Linux - always unsignedLinux (no Authenticode signing on Linux)
    Write-Host "`nIterating Through NSRL Linux Hashes..." -ForegroundColor DarkCyan
    foreach ($fileHash in $nsrlLinuxHashes) {
        if ($script:QuotaHit) { break }
        Process-Hash -Hash $fileHash -MainPath $mainUnsignedLinux -BehaviorsPath $behaviorsUnsignedLinux
    }

    # 5. Malicious Baseline (written to separate \malicious subfolder - never mixed with known-good)
    Write-Host "`nIterating Through Malicious Baseline..." -ForegroundColor DarkCyan
    foreach ($proc in $maliciousProcsBaseline) {
        if ($script:QuotaHit) { break }
        $fileHash = $proc.value[2]
        if (-not $fileHash) { continue }
        Process-Hash -Hash $fileHash -MainPath $mainMalicious -BehaviorsPath $behaviorsMalicious
    }

    # 6. Drivers Baseline
    Write-Host "`nIterating Through Drivers Baseline..." -ForegroundColor DarkCyan
    foreach ($proc in $driversBaseline) {
        if ($script:QuotaHit) { break }
        $fileHash = $proc.value[2]
        if (-not $fileHash) { continue }
        Process-Hash -Hash $fileHash -MainPath $mainDrivers -BehaviorsPath $behaviorsDrivers
    }

    if ($script:QuotaHit) {
        Write-Host "`n[!] Run stopped early due to VT quota. Re-run to continue from where it left off (existing files are skipped)." -ForegroundColor Yellow
    } else {
        Write-Host "`n[DONE] Baseline collection complete." -ForegroundColor Green
    }
}

Export-ModuleMember -Function Get-VTBaseline