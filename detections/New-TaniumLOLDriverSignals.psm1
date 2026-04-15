<#
.SYNOPSIS
    Generates Tanium Threat Response signals for LOLDrivers (BYOVD detection).

.DESCRIPTION
    Reads detections\loldrivers\loldrivers_cache.json (418+ known-vulnerable
    driver filenames from loldrivers.io, LOLDrivers GitHub Sigma, and SigmaHQ)
    and produces Tanium signals that alert when any of these drivers are loaded.

    Tanium Recorder captures driver loads as process events where the file_path
    ends with the driver name. Signals are batched into groups of ~50 drivers
    to stay within practical query length limits.

    Also emits a single "Critical EDR Killers" signal for the highest-risk
    subset — drivers actively used by ransomware and APTs to kill EDR processes.

    Output: detections\tanium-loldrivers\TaniumLOLDrivers_Import.json
            (single file, importable via Threat Response > Intel > Import)

.NOTES
    Run Update-LolDriversCache first to refresh the driver list.
#>

function New-TaniumLOLDriverSignals {
    [CmdletBinding()]
    param(
        [string]$CacheFile = ".\detections\loldrivers\loldrivers_cache.json",
        [string]$OutDir    = ".\detections\tanium-loldrivers"
    )

    if (-not (Test-Path $CacheFile)) {
        Write-Error "LOLDrivers cache not found at $CacheFile. Run Update-LolDriversCache first."
        return
    }

    $cache = Get-Content -Path $CacheFile -Raw | ConvertFrom-Json
    $driverNames = @($cache | ForEach-Object { $_.n } | Where-Object { $_ } | Sort-Object -Unique)

    if ($driverNames.Count -eq 0) {
        Write-Error "LOLDrivers cache is empty."
        return
    }

    Write-Host "[*] Loaded $($driverNames.Count) LOLDriver names from cache." -ForegroundColor DarkCyan

    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

    $timestamp = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss.fffZ')
    $allSignals = [System.Collections.Generic.List[object]]::new()

    # ================================================================
    # 1. CRITICAL EDR KILLERS (curated high-risk subset)
    # ================================================================
    # These are the drivers most commonly used by ransomware operators
    # and APTs to terminate EDR/AV processes via BYOVD attacks.
    $edrKillers = @(
        'rtcore64.sys'          # MSI Afterburner - RansomHub, BlackByte, AvosLocker
        'rtcore32.sys'          # MSI Afterburner 32-bit
        'dbutil_2_3.sys'        # Dell BIOS utility - multiple ransomware
        'gdrv.sys'              # GIGABYTE - RobinHood ransomware
        'kprocesshacker.sys'    # Process Hacker - EDR killer
        'procexp152.sys'        # Sysinternals Process Explorer - Medusa, AuKill
        'zamguard64.sys'        # Zemana AntiMalware - BlackByte BYOVD
        'zam64.sys'             # Zemana - BlackByte variant
        'truesight.sys'         # Adlice/RogueKiller - SbaProxy, Poortry
        'rentdrv2.sys'          # EDR killer seen in the wild
        'gmer64.sys'            # GMER rootkit detector - abused to kill AV
        'aswarpot.sys'          # Avast anti-rootkit - AvosLocker, Cuba
        'aswarpotsys'           # Avast variant name
        'aswvmm.sys'            # Avast VM monitor
        'viragt64.sys'          # TG Soft Vir.IT - used in BYOVD
        'iqvw64e.sys'           # Intel Network Adapter - Scattered Spider
        'iqvw64.sys'            # Intel variant
        'winio64.sys'           # WinIo - kernel R/W primitive
        'winio32.sys'           # WinIo 32-bit
        'elrawdsk.sys'          # RawDisk - Shamoon/Dustman wiper
        'rawdisk.sys'           # RawDisk variant
        'daxin_blank5.sys'      # Daxin APT backdoor driver
        'ktgn.sys'              # Lazarus Group BYOVD
        'wintapix.sys'          # Iranian APT driver backdoor
        'reddriver.sys'         # RedDriver - Chinese browser hijacker
        'ntbios.sys'            # FiveSys rootkit
        'asio64.sys'            # ASUS - kernel R/W
        'cpuz141.sys'           # CPU-Z - kernel read (various APTs)
        'ene.sys'               # ENE Technology - kernel R/W
        'inpoutx64.sys'        # InpOut - direct port I/O
        'mhyprot2.sys'          # miHoYo anti-cheat - abused for kernel access
        'mhyprot3.sys'          # miHoYo variant
        'speedfan.sys'          # SpeedFan - kernel R/W
        'pchunter.sys'          # PCHunter - rootkit tool
    )

    # Filter to only drivers that exist in our cache
    $edrKillersInCache = @($edrKillers | Where-Object { $driverNames -contains $_ })
    $edrKillersNotInCache = @($edrKillers | Where-Object { $driverNames -notcontains $_ })

    Write-Host "  Critical EDR killers: $($edrKillersInCache.Count) in cache, $($edrKillersNotInCache.Count) added as extra coverage." -ForegroundColor DarkCyan

    # Combine: use all curated names regardless of cache presence
    $allEdrKillers = $edrKillers | Sort-Object -Unique

    $edrKillerQuery = ($allEdrKillers | ForEach-Object {
        "process.path ends with '\\$_'"
    }) -join ' OR '

    $allSignals.Add([ordered]@{
        type          = 'tanium-signal'
        typeVersion   = '1.0'
        isSchemaValid = $true
        createdAt     = $timestamp
        updatedAt     = $timestamp
        data          = [ordered]@{
            id          = 'BYOVD-CRITICAL: EDR Killer Driver Load'
            name        = 'BYOVD-CRITICAL: EDR Killer Driver Load'
            description = "CRITICAL: Detects loading of $($allEdrKillers.Count) drivers actively used by ransomware operators and APTs to kill EDR/AV processes (BYOVD - Bring Your Own Vulnerable Driver). Includes RTCore64 (RansomHub, BlackByte), ProcExp152 (AuKill/Medusa), Truesight (Poortry), Zamguard (BlackByte), Avast anti-rootkit (AvosLocker, Cuba), and others. Any match on a production endpoint is a strong indicator of active compromise."
            contents    = $edrKillerQuery
            syntax_version = 1
            mitreAttack = @{
                techniques = @(
                    @{ id = 'T1068'; name = 'Exploitation for Privilege Escalation' }
                    @{ id = 'T1562.001'; name = 'Impair Defenses: Disable or Modify Tools' }
                    @{ id = 'T1014'; name = 'Rootkit' }
                )
            }
            platforms   = @('windows')
            labels      = @('Windows','Privilege Escalation','Defense Evasion','Critical')
        }
    })

    # ================================================================
    # 2. ALL LOLDrivers (batched by ~50)
    # ================================================================
    $batchSize = 50
    $batchNum  = 0

    for ($i = 0; $i -lt $driverNames.Count; $i += $batchSize) {
        $batchNum++
        $batch = $driverNames[$i..([Math]::Min($i + $batchSize - 1, $driverNames.Count - 1))]

        $batchQuery = ($batch | ForEach-Object {
            "process.path ends with '\\$_'"
        }) -join ' OR '

        $startName = $batch[0]
        $endName   = $batch[-1]

        $allSignals.Add([ordered]@{
            type          = 'tanium-signal'
            typeVersion   = '1.0'
            isSchemaValid = $true
            createdAt     = $timestamp
            updatedAt     = $timestamp
            data          = [ordered]@{
                id          = "BYOVD-BATCH-${batchNum}: LOLDrivers ($startName - $endName)"
                name        = "BYOVD-BATCH-${batchNum}: LOLDrivers ($startName - $endName)"
                description = "Detects loading of known-vulnerable drivers from loldrivers.io (batch $batchNum of $([Math]::Ceiling($driverNames.Count / $batchSize)), covering $($batch.Count) drivers: $startName through $endName). These drivers have known vulnerabilities that allow kernel-level read/write, process termination, or arbitrary code execution. Source: LOLDrivers.io + SigmaHQ + magicsword-io."
                contents    = $batchQuery
                syntax_version = 1
                mitreAttack = @{
                    techniques = @(
                        @{ id = 'T1068'; name = 'Exploitation for Privilege Escalation' }
                        @{ id = 'T1562.001'; name = 'Impair Defenses: Disable or Modify Tools' }
                    )
                }
                platforms   = @('windows')
                labels      = @('Windows','Privilege Escalation','Defense Evasion','BYOVD')
            }
        })
    }

    Write-Host "  Generated 1 critical EDR killer signal + $batchNum batch signals ($($driverNames.Count) drivers total)." -ForegroundColor DarkCyan

    # ================================================================
    # 3. WRITE IMPORT BUNDLE
    # ================================================================
    $exportBundle = [ordered]@{
        signals = @($allSignals)
        labels  = @(
            @{ name = 'Windows';              description = 'Signals built for Windows hosts.' }
            @{ name = 'Privilege Escalation';  description = 'MITRE ATT&CK: Privilege Escalation' }
            @{ name = 'Defense Evasion';       description = 'MITRE ATT&CK: Defense Evasion' }
            @{ name = 'BYOVD';                description = 'Bring Your Own Vulnerable Driver detections' }
            @{ name = 'Critical';             description = 'Highest-severity signals requiring immediate investigation' }
            @{ name = 'LoadedPotato';         description = 'Auto-generated from Loaded-Potato LOLDrivers cache' }
        )
    }

    $importFile = Join-Path $OutDir "TaniumLOLDrivers_Import.json"
    $exportBundle | ConvertTo-Json -Depth 8 -Compress | Set-Content -Path $importFile -Encoding UTF8

    # ================================================================
    # 4. TRACE CONSOLE QUERIES
    # ================================================================
    $queryFile = Join-Path $OutDir "TaniumLOLDrivers_Console_Queries.txt"
    $q = [System.Text.StringBuilder]::new()

    $null = $q.AppendLine("# ============================================================")
    $null = $q.AppendLine("# Tanium Threat Response Trace Queries: LOLDrivers / BYOVD")
    $null = $q.AppendLine("# Generated: $timestamp")
    $null = $q.AppendLine("# Source: detections\loldrivers\loldrivers_cache.json ($($driverNames.Count) drivers)")
    $null = $q.AppendLine("#")
    $null = $q.AppendLine("# HOW TO USE:")
    $null = $q.AppendLine("#   Threat Response -> Trace -> paste query -> set time range -> run")
    $null = $q.AppendLine("# ============================================================")
    $null = $q.AppendLine("")

    # Critical EDR killers query for Trace
    $null = $q.AppendLine("# -- CRITICAL: EDR Killer Drivers ($($allEdrKillers.Count) drivers) --")
    $null = $q.AppendLine("# Any match = likely active compromise / ransomware pre-positioning")
    $edrKillerTrace = ($allEdrKillers | ForEach-Object { "file_path contains `"$_`"" }) -join ' OR '
    $null = $q.AppendLine("type:driver_load AND ($edrKillerTrace)")
    $null = $q.AppendLine("")
    $null = $q.AppendLine("# Same query via image_load (some Recorder configs log drivers here)")
    $null = $q.AppendLine("type:image_load AND ($edrKillerTrace)")
    $null = $q.AppendLine("")

    # Full LOLDrivers query split into batches for Trace
    $batchNum = 0
    for ($i = 0; $i -lt $driverNames.Count; $i += $batchSize) {
        $batchNum++
        $batch = $driverNames[$i..([Math]::Min($i + $batchSize - 1, $driverNames.Count - 1))]
        $batchTrace = ($batch | ForEach-Object { "file_path contains `"$_`"" }) -join ' OR '
        $null = $q.AppendLine("# -- Batch ${batchNum}: $($batch[0]) - $($batch[-1]) ($($batch.Count) drivers) --")
        $null = $q.AppendLine("type:driver_load AND ($batchTrace)")
        $null = $q.AppendLine("")
    }

    Set-Content -Path $queryFile -Value $q.ToString() -Encoding UTF8

    # ================================================================
    # 5. OUTPUT
    # ================================================================
    Write-Host ""
    Write-Host "[DONE] LOLDriver Tanium signals generated." -ForegroundColor Green
    Write-Host "       Import bundle:   $importFile" -ForegroundColor DarkCyan
    Write-Host "       Console queries: $queryFile" -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host "=== Signal Summary ===" -ForegroundColor Cyan
    Write-Host "  1x  CRITICAL   BYOVD EDR Killer Driver Load ($($allEdrKillers.Count) drivers)" -ForegroundColor Red
    Write-Host "  ${batchNum}x  HIGH       LOLDrivers batch signals ($($driverNames.Count) drivers total, $batchSize/batch)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "=== How to use ===" -ForegroundColor Cyan
    Write-Host "  IMMEDIATE HUNTING:" -ForegroundColor DarkCyan
    Write-Host "    Threat Response -> Trace -> paste from: $queryFile" -ForegroundColor Gray
    Write-Host "    Start with the CRITICAL EDR Killer query first." -ForegroundColor Gray
    Write-Host ""
    Write-Host "  ONGOING DETECTION:" -ForegroundColor DarkCyan
    Write-Host "    Threat Response -> Intel -> Import -> From File:" -ForegroundColor Gray
    Write-Host "    $(try { (Resolve-Path $importFile).Path } catch { $importFile })" -ForegroundColor White
}

Export-ModuleMember -Function New-TaniumLOLDriverSignals
