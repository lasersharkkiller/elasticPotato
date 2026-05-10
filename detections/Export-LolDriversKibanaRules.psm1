<#
.SYNOPSIS
    Generates Kibana NDJSON detection rules from the LOL Drivers cache for
    import into Elastic Security (SIEM).

.DESCRIPTION
    Reads detections\loldrivers\loldrivers_cache.json and produces three rules
    written to detections\kibanaImport\loldrivers-byovd-detections.ndjson:

      Rule 1 - BYOVD Sysmon EID 6       : All cached drivers, winlogbeat/Sysmon source
      Rule 2 - BYOVD Elastic Defend      : All cached drivers, Elastic Defend source
      Rule 3 - Critical EDR Killers       : Highest-risk subset, severity critical, both sources

    Backslash escaping chain (required for KQL inside JSON):
      PS string  "\\"  =  2 literal backslash chars
      ConvertTo-Json doubles each: "\\\\", stored in NDJSON file
      JSON parser decodes "\\\\": "\\", delivered to KQL engine
      KQL interprets "\\": escaped backslash = one literal "\"
      Result: wildcard *\rtcore64.sys matches any path ending in \rtcore64.sys  ✓

    Run Update-LolDriversCache first to refresh the driver list, then run this
    function to regenerate the rules from the updated cache.

    Stable rule_id UUIDs mean re-import overwrites the existing rule in Kibana
    (use the "Overwrite existing rules" option on import).

.EXAMPLE
    Export-LolDriversKibanaRules
    Export-LolDriversKibanaRules -OutputDir "C:\custom\path"
#>

# ---------------------------------------------------------------------------
# Module-private helpers
# ---------------------------------------------------------------------------

function Build-PathOrList {
    param([string[]]$Names)
    # Each entry becomes  *\\drivername.sys  in the PS string.
    # ConvertTo-Json will double the backslashes to  *\\\\  in the JSON,
    # which KQL receives as  *\\  = escaped backslash = literal \.
    return ($Names | ForEach-Object { "*\\$_" }) -join " OR "
}

function Build-NameOrList {
    param([string[]]$Names)
    return $Names -join " OR "
}

function New-ByovdRule {
    param(
        [string]   $Uuid,
        [string]   $Name,
        [string]   $Description,
        [string]   $Query,
        [string[]] $Index,
        [int]      $RiskScore,
        [string]   $Severity,
        [string[]] $Tags
    )
    return [PSCustomObject]@{
        id          = $Uuid
        rule_id     = $Uuid
        name        = $Name
        description = $Description
        enabled     = $false
        type        = "query"
        language    = "kuery"
        query       = $Query
        index       = $Index
        risk_score  = $RiskScore
        severity    = $Severity
        tags        = $Tags
        author      = @("Loaded Potato")
        from        = "now-24h"
        interval    = "5m"
        max_signals = 100
        version     = 1
    }
}

# ---------------------------------------------------------------------------
# Exported function
# ---------------------------------------------------------------------------

function Export-LolDriversKibanaRules {
    [CmdletBinding()]
    param(
        [string]$CacheDir  = (Join-Path $PSScriptRoot "loldrivers"),
        [string]$OutputDir = (Join-Path $PSScriptRoot "kibanaImport")
    )

    $cacheFile = Join-Path $CacheDir "loldrivers_cache.json"
    $metaFile  = Join-Path $CacheDir "_meta.json"
    $outFile   = Join-Path $OutputDir "loldrivers-byovd-detections.ndjson"

    # ------------------------------------------------------------------
    # Load driver cache
    # ------------------------------------------------------------------
    if (-not (Test-Path $cacheFile)) {
        Write-Host "[LolDrivers] Cache not found. Run Update-LolDriversCache first (menu 10e)." -ForegroundColor Yellow
        return
    }

    $cacheEntries = Get-Content $cacheFile -Raw | ConvertFrom-Json
    $allDrivers   = @($cacheEntries | ForEach-Object { $_.n } | Where-Object { $_ } | Sort-Object)

    if ($allDrivers.Count -eq 0) {
        Write-Host "[LolDrivers] Cache is empty. Run Update-LolDriversCache first." -ForegroundColor Yellow
        return
    }

    # Enrich description with cache metadata
    $metaDate    = (Get-Date -Format 'yyyy-MM-dd')
    $metaSources = "loldrivers.io API + LOLDrivers Sigma + SigmaHQ"
    if (Test-Path $metaFile) {
        try {
            $meta = Get-Content $metaFile -Raw | ConvertFrom-Json
            if ($meta.last_updated) { $metaDate = $meta.last_updated.Substring(0,10) }
        } catch {}
    }

    Write-Host "[LolDrivers] Building Kibana rules for $($allDrivers.Count) cached drivers..." -ForegroundColor Cyan

    # ------------------------------------------------------------------
    # Critical EDR-killer driver subset
    # Individually confirmed in active ransomware / APT campaigns.
    # ------------------------------------------------------------------
    $criticalDrivers = @(
        'rtcore64.sys',    'rtcore32.sys',                          # MSI Afterburner   -  BlackByte, SCATTERED SPIDER
        'mhyprot.sys',     'mhyprot2.sys',    'mhyprot3.sys',       # Genshin Impact    -  widely abused ransomware EDR killer
        'mhyprotect.sys',  'mhyprotnap.sys',                        # Genshin variants
        'zamguard64.sys',  'zam64.sys',                             # Zemana            -  BURNTCIGAR / Terminator tool
        'gdrv.sys',                                                  # Gigabyte          -  RobbinHood ransomware
        'dbutil_2_3.sys',  'dbutildrv2.sys',  'dbutil.sys',         # Dell BIOS util    -  CVE-2021-21551 exploit
        'iqvw64e.sys',     'iqvw64.sys',                            # Intel NIC diag    -  ransomware / POORTRY
        'procexp152.sys',  'procexp.sys',                           # Sysinternals ProcExp  -  EDR process kill
        'aswarpot.sys',    'aswvmm.sys',                            # Avast kernel      -  AvosLocker / POORTRY
        'kprocesshacker.sys',                                        # Process Hacker    -  Lazarus, multiple threat actors
        'truesight.sys',                                             # RogueKiller       -  EDR bypass
        'bedaisy.sys',                                              # BattlEye anti-cheat  -  Lazarus group
        'capcom.sys',                                                # Capcom SF5        -  classic ring-0 code execution
        'blackbone.sys',   'blackbonedrv10.sys'                     # BlackBone         -  kernel process manipulation
    )

    # Intersect with cache so we only include what we actually track
    $critInCache = @($criticalDrivers | Where-Object { $allDrivers -contains $_ } | Sort-Object -Unique)

    Write-Host "[LolDrivers]   All drivers  : $($allDrivers.Count)" -ForegroundColor DarkGray
    Write-Host "[LolDrivers]   Critical set : $($critInCache.Count) (severity: critical)" -ForegroundColor DarkGray

    # ------------------------------------------------------------------
    # Build KQL OR fragments
    # ------------------------------------------------------------------
    $allPathList  = Build-PathOrList  $allDrivers
    $critPathList = Build-PathOrList  $critInCache
    $critNameList = Build-NameOrList  $critInCache

    $descCommon = "Sources: $metaSources. Cache contains $($allDrivers.Count) drivers as of $metaDate. " +
                  "Enable rule and set schedule appropriate to your environment. " +
                  "Regenerate from menu option 10e after updating the LOL Drivers cache."

    # ------------------------------------------------------------------
    # Rule 1  -  Sysmon EID 6 (DriverLoad), all drivers
    #   winlogbeat / Sysmon telemetry path
    # ------------------------------------------------------------------
    $rule1 = New-ByovdRule `
        -Uuid        "b10ld001-cafe-4200-dead-000000000001" `
        -Name        "[Loaded Potato] BYOVD - Known Vulnerable Driver Loaded (Sysmon EID 6)" `
        -Description ("Detects Sysmon Event ID 6 (DriverLoad) for any driver in the LOL Drivers " +
                      "database. Attackers load signed but exploitable kernel drivers (BYOVD  -  Bring Your Own " +
                      "Vulnerable Driver) to disable EDR/AV, escalate to ring-0 privileges, or read/write " +
                      "kernel memory. MITRE ATT&CK: T1068 (Exploitation for Privilege Escalation), " +
                      "T1543.003 (Windows Service). $descCommon") `
        -Query       "winlog.event_id: 6 AND winlog.event_data.ImageLoaded: ($allPathList)" `
        -Index       @("logs-*","winlogbeat-*","filebeat-*","endgame-*",".siem-signals-*") `
        -RiskScore   73 `
        -Severity    "high" `
        -Tags        @("Loaded Potato","BYOVD","LOLDrivers","T1068","T1543.003",
                       "attack.privilege-escalation","attack.persistence","Sysmon","Driver")

    # ------------------------------------------------------------------
    # Rule 2  -  Elastic Defend driver events, all drivers
    #   Elastic Defend / endpoint telemetry path
    # ------------------------------------------------------------------
    $rule2 = New-ByovdRule `
        -Uuid        "b10ld001-cafe-4200-dead-000000000002" `
        -Name        "[Loaded Potato] BYOVD - Known Vulnerable Driver Loaded (Elastic Defend)" `
        -Description ("Detects an Elastic Defend driver-load event for any driver in the LOL Drivers " +
                      "database. Attackers load signed but exploitable kernel drivers (BYOVD  -  Bring Your Own " +
                      "Vulnerable Driver) to disable EDR/AV, escalate to ring-0 privileges, or read/write " +
                      "kernel memory. MITRE ATT&CK: T1068 (Exploitation for Privilege Escalation), " +
                      "T1543.003 (Windows Service). $descCommon") `
        -Query       "event.category: driver AND event.type: load AND driver.path: ($allPathList)" `
        -Index       @("logs-*","endgame-*",".siem-signals-*") `
        -RiskScore   73 `
        -Severity    "high" `
        -Tags        @("Loaded Potato","BYOVD","LOLDrivers","T1068","T1543.003",
                       "attack.privilege-escalation","attack.persistence","Elastic Defend","Driver")

    # ------------------------------------------------------------------
    # Rule 3  -  Critical EDR killers, both sources, severity: critical
    #   Covers the highest-risk confirmed-in-the-wild BYOVD drivers.
    #   Any match here is high-confidence malicious.
    # ------------------------------------------------------------------
    $critDriverList = $critInCache -join ", "
    $rule3 = New-ByovdRule `
        -Uuid        "b10ld001-cafe-4200-dead-000000000003" `
        -Name        "[Loaded Potato] BYOVD - Critical EDR Killer Driver Loaded" `
        -Description ("Detects the highest-risk BYOVD kernel drivers individually confirmed in active " +
                      "ransomware and nation-state APT campaigns specifically to kill EDR/AV and escalate " +
                      "kernel privileges. Any match is high-confidence malicious with no expected legitimate " +
                      "use in a production environment. Covered drivers: $critDriverList. " +
                      "Campaigns: BlackByte (RTCore64), SCATTERED SPIDER (RTCore64), Genshin ransomware " +
                      "(mhyprot variants), Terminator/BURNTCIGAR (zamguard64/zam64), RobbinHood (gdrv), " +
                      "AvosLocker/POORTRY (aswArPot), Lazarus Group (bedaisy, kprocesshacker). " +
                      "MITRE ATT&CK: T1068, T1543.003, T1562.001.") `
        -Query       ("(winlog.event_id: 6 AND winlog.event_data.ImageLoaded: ($critPathList)) OR " +
                      "(event.category: driver AND event.type: load AND driver.path: ($critPathList))") `
        -Index       @("logs-*","winlogbeat-*","filebeat-*","endgame-*",".siem-signals-*") `
        -RiskScore   99 `
        -Severity    "critical" `
        -Tags        @("Loaded Potato","BYOVD","LOLDrivers","EDR Killer","T1068","T1543.003","T1562.001",
                       "attack.privilege-escalation","attack.defense-evasion","attack.persistence","Critical","Driver")

    # ------------------------------------------------------------------
    # Write NDJSON  -  one JSON object per line
    # ------------------------------------------------------------------
    if (-not (Test-Path $OutputDir)) {
        New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
    }

    $ndjson = @($rule1, $rule2, $rule3) |
              ForEach-Object { $_ | ConvertTo-Json -Depth 10 -Compress }

    $ndjson -join "`n" | Set-Content -LiteralPath $outFile -Encoding UTF8

    Write-Host "[LolDrivers] Rules written  -> $outFile" -ForegroundColor Green
    Write-Host "[LolDrivers]   Rule 1 (Sysmon EID 6)       : $($allDrivers.Count) drivers, severity: high" -ForegroundColor Green
    Write-Host "[LolDrivers]   Rule 2 (Elastic Defend)      : $($allDrivers.Count) drivers, severity: high" -ForegroundColor Green
    Write-Host "[LolDrivers]   Rule 3 (Critical EDR killers): $($critInCache.Count) drivers, severity: critical" -ForegroundColor Green
    Write-Host "[LolDrivers] Import: Kibana -> Security -> Rules -> Import -> select file -> check Overwrite" -ForegroundColor Cyan
}

# ---------------------------------------------------------------------------
# Sigma YAML rule export
# ---------------------------------------------------------------------------

function Export-LolDriversSigmaRules {
    <#
    .SYNOPSIS
        Generates Sigma YAML detection rules from the LOL Drivers cache.
    .DESCRIPTION
        Reads the merged LOL Drivers cache and produces Sigma-format YAML rules
        written to detections\sigma\:

          Rule 1 - LOLDriver Vulnerable Driver Load (all cached drivers, driver_load)
          Rule 2 - LOLDriver Critical EDR Killer Load (critical subset, driver_load)
          Rule 3 - LOLDriver Vulnerable Driver File Creation (all drivers, file_event)

        These complement the upstream SigmaHQ rules by covering the full merged
        cache (loldrivers.io API + LOLDrivers Sigma + SigmaHQ community).
    .EXAMPLE
        Export-LolDriversSigmaRules
    #>
    [CmdletBinding()]
    param(
        [string]$CacheDir  = (Join-Path $PSScriptRoot "loldrivers"),
        [string]$OutputDir = (Join-Path $PSScriptRoot "sigma")
    )

    $cacheFile = Join-Path $CacheDir "loldrivers_cache.json"
    $metaFile  = Join-Path $CacheDir "_meta.json"

    if (-not (Test-Path $cacheFile)) {
        Write-Host "[LolDrivers-Sigma] Cache not found. Run Update-LolDriversCache first." -ForegroundColor Yellow
        return
    }

    $cacheEntries = Get-Content $cacheFile -Raw | ConvertFrom-Json
    $allDrivers   = @($cacheEntries | ForEach-Object { $_.n } | Where-Object { $_ } | Sort-Object)

    if ($allDrivers.Count -eq 0) {
        Write-Host "[LolDrivers-Sigma] Cache is empty." -ForegroundColor Yellow
        return
    }

    $metaDate = (Get-Date -Format 'yyyy/MM/dd')
    if (Test-Path $metaFile) {
        try {
            $meta = Get-Content $metaFile -Raw | ConvertFrom-Json
            if ($meta.last_updated) { $metaDate = $meta.last_updated.Substring(0,10).Replace('-','/') }
        } catch {}
    }

    if (-not (Test-Path $OutputDir)) {
        New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
    }

    # Critical EDR-killer subset (same list as NDJSON export)
    $criticalDrivers = @(
        'rtcore64.sys','rtcore32.sys',
        'mhyprot.sys','mhyprot2.sys','mhyprot3.sys',
        'mhyprotect.sys','mhyprotnap.sys',
        'zamguard64.sys','zam64.sys',
        'gdrv.sys',
        'dbutil_2_3.sys','dbutildrv2.sys','dbutil.sys',
        'iqvw64e.sys','iqvw64.sys',
        'procexp152.sys','procexp.sys',
        'aswarpot.sys','aswvmm.sys',
        'kprocesshacker.sys',
        'truesight.sys',
        'bedaisy.sys',
        'capcom.sys',
        'blackbone.sys','blackbonedrv10.sys'
    )
    $critInCache = @($criticalDrivers | Where-Object { $allDrivers -contains $_ } | Sort-Object -Unique)

    Write-Host "[LolDrivers-Sigma] Building Sigma rules for $($allDrivers.Count) drivers ($($critInCache.Count) critical)..." -ForegroundColor Cyan

    # ---- Helper: build YAML list of \drivername.sys entries ----
    function Build-SigmaDriverList {
        param([string[]]$Drivers, [string]$Indent = "            ")
        $lines = $Drivers | ForEach-Object { "${Indent}- '\$_'" }
        return $lines -join "`n"
    }

    # ------------------------------------------------------------------
    # Rule 1 - All vulnerable drivers, driver_load category
    # ------------------------------------------------------------------
    $allDriverYaml = Build-SigmaDriverList $allDrivers
    $rule1Path = Join-Path $OutputDir "LOLDrivers BYOVD Vulnerable Driver Load (Full Cache).yml"
    $rule1 = @"
title: LOLDrivers BYOVD Vulnerable Driver Load (Full Cache)
id: b10ld001-5167-4200-ba0d-100000000001
status: stable
description: |
    Detects loading of any driver from the merged LOL Drivers cache
    (loldrivers.io API + LOLDrivers Sigma + SigmaHQ community).
    $($allDrivers.Count) drivers tracked. Auto-generated by Loaded Potato.
    MITRE ATT&CK: T1068 (Exploitation for Privilege Escalation),
    T1543.003 (Windows Service).
references:
    - https://loldrivers.io/
    - https://github.com/magicsword-io/LOLDrivers
author: Loaded Potato (auto-generated from LOLDrivers cache)
date: $metaDate
tags:
    - attack.privilege_escalation
    - attack.persistence
    - attack.t1543.003
    - attack.t1068
logsource:
    product: windows
    category: driver_load
detection:
    selection:
        ImageLoaded|endswith:
$allDriverYaml
    condition: selection
falsepositives:
    - Legitimate use of a vulnerable but non-malicious driver (e.g. CPU-Z, HWMonitor).
      Verify the driver version and context before suppressing.
level: medium
"@

    Set-Content -LiteralPath $rule1Path -Value $rule1 -Encoding UTF8

    # ------------------------------------------------------------------
    # Rule 2 - Critical EDR killers, driver_load category
    # ------------------------------------------------------------------
    $critDriverYaml = Build-SigmaDriverList $critInCache
    $critList = $critInCache -join ', '
    $rule2Path = Join-Path $OutputDir "LOLDrivers BYOVD Critical EDR Killer Driver Load.yml"
    $rule2 = @"
title: LOLDrivers BYOVD Critical EDR Killer Driver Load
id: b10ld001-5167-4200-ba0d-100000000002
status: stable
description: |
    Detects loading of highest-risk BYOVD kernel drivers confirmed in active
    ransomware and APT campaigns to kill EDR/AV. Any match is high-confidence
    malicious. Covered: $critList.
    Campaigns: BlackByte (RTCore64), SCATTERED SPIDER (RTCore64),
    Genshin ransomware (mhyprot variants), Terminator/BURNTCIGAR (zamguard64/zam64),
    RobbinHood (gdrv), AvosLocker/POORTRY (aswArPot), Lazarus (bedaisy, kprocesshacker).
references:
    - https://loldrivers.io/
    - https://github.com/magicsword-io/LOLDrivers
author: Loaded Potato (auto-generated from LOLDrivers cache)
date: $metaDate
tags:
    - attack.privilege_escalation
    - attack.defense_evasion
    - attack.persistence
    - attack.t1543.003
    - attack.t1068
    - attack.t1562.001
logsource:
    product: windows
    category: driver_load
detection:
    selection:
        ImageLoaded|endswith:
$critDriverYaml
    condition: selection
falsepositives:
    - None expected. These drivers have no legitimate use in production environments.
level: critical
"@

    Set-Content -LiteralPath $rule2Path -Value $rule2 -Encoding UTF8

    # ------------------------------------------------------------------
    # Rule 3 - All vulnerable drivers, file_event category (file drop)
    # ------------------------------------------------------------------
    $rule3Path = Join-Path $OutputDir "LOLDrivers BYOVD Vulnerable Driver File Created.yml"
    $rule3 = @"
title: LOLDrivers BYOVD Vulnerable Driver File Created
id: b10ld001-5167-4200-ba0d-100000000003
status: stable
description: |
    Detects creation of a known vulnerable driver file on disk. Attackers
    frequently drop BYOVD .sys files to temp directories, service paths,
    or user-writable locations before loading them. This rule fires on the
    file write, before the driver load attempt.
    $($allDrivers.Count) drivers tracked from merged LOL Drivers cache.
references:
    - https://loldrivers.io/
    - https://github.com/magicsword-io/LOLDrivers
author: Loaded Potato (auto-generated from LOLDrivers cache)
date: $metaDate
tags:
    - attack.privilege_escalation
    - attack.persistence
    - attack.t1543.003
    - attack.t1068
    - attack.resource_development
    - attack.t1588.002
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
$allDriverYaml
    condition: selection
falsepositives:
    - Legitimate software installation that includes a known-vulnerable driver.
      Verify the installer and context.
level: medium
"@

    Set-Content -LiteralPath $rule3Path -Value $rule3 -Encoding UTF8

    # ------------------------------------------------------------------
    # Rule 4 - sc.exe / service creation for vulnerable driver (process creation)
    # ------------------------------------------------------------------
    $rule4Path = Join-Path $OutputDir "LOLDrivers BYOVD Driver Service Installation.yml"
    $rule4 = @"
title: LOLDrivers BYOVD Driver Service Installation
id: b10ld001-5167-4200-ba0d-100000000004
status: stable
description: |
    Detects sc.exe creating a kernel-type service pointing to a known
    vulnerable driver. This catches the BYOVD installation step before
    the driver is actually loaded.
references:
    - https://loldrivers.io/
    - https://github.com/magicsword-io/LOLDrivers
author: Loaded Potato (auto-generated from LOLDrivers cache)
date: $metaDate
tags:
    - attack.privilege_escalation
    - attack.persistence
    - attack.t1543.003
    - attack.t1068
logsource:
    product: windows
    category: process_creation
detection:
    selection_sc:
        Image|endswith: '\sc.exe'
        CommandLine|contains: 'kernel'
    selection_driver:
        CommandLine|contains:
$(($allDrivers | ForEach-Object { "            - '$_'" }) -join "`n")
    condition: selection_sc and selection_driver
falsepositives:
    - Legitimate installation of hardware monitoring tools that ship vulnerable drivers.
level: high
"@

    Set-Content -LiteralPath $rule4Path -Value $rule4 -Encoding UTF8

    Write-Host "[LolDrivers-Sigma] Rules written:" -ForegroundColor Green
    Write-Host "[LolDrivers-Sigma]   $rule1Path" -ForegroundColor Green
    Write-Host "[LolDrivers-Sigma]   $rule2Path" -ForegroundColor Green
    Write-Host "[LolDrivers-Sigma]   $rule3Path" -ForegroundColor Green
    Write-Host "[LolDrivers-Sigma]   $rule4Path" -ForegroundColor Green
}


# ---------------------------------------------------------------------------
# YARA rule export
# ---------------------------------------------------------------------------

function Export-LolDriversYaraRules {
    <#
    .SYNOPSIS
        Generates YARA rules from the LOL Drivers cache for filesystem scanning.
    .DESCRIPTION
        Reads the merged LOL Drivers cache and produces YARA rules written to
        detections\yara\:

          Rule 1 - BYOVD_LOLDriver_Vulnerable_Name  (filename match, all drivers)
          Rule 2 - BYOVD_Critical_EDR_Killer         (filename match, critical subset)
          Rule 3 - BYOVD_LOLDriver_Service_Install   (sc.exe + driver name in strings)

        These rules are designed for endpoint filesystem sweeps (Thor, Loki,
        yarGen, osquery+yara) to find vulnerable driver files staged on disk.
    .EXAMPLE
        Export-LolDriversYaraRules
    #>
    [CmdletBinding()]
    param(
        [string]$CacheDir  = (Join-Path $PSScriptRoot "loldrivers"),
        [string]$OutputDir = (Join-Path $PSScriptRoot "yara")
    )

    $cacheFile = Join-Path $CacheDir "loldrivers_cache.json"
    $metaFile  = Join-Path $CacheDir "_meta.json"

    if (-not (Test-Path $cacheFile)) {
        Write-Host "[LolDrivers-YARA] Cache not found. Run Update-LolDriversCache first." -ForegroundColor Yellow
        return
    }

    $cacheEntries = Get-Content $cacheFile -Raw | ConvertFrom-Json
    $allDrivers   = @($cacheEntries | ForEach-Object { $_.n } | Where-Object { $_ } | Sort-Object)

    if ($allDrivers.Count -eq 0) {
        Write-Host "[LolDrivers-YARA] Cache is empty." -ForegroundColor Yellow
        return
    }

    $metaDate = (Get-Date -Format 'yyyy-MM-dd')
    if (Test-Path $metaFile) {
        try {
            $meta = Get-Content $metaFile -Raw | ConvertFrom-Json
            if ($meta.last_updated) { $metaDate = $meta.last_updated.Substring(0,10) }
        } catch {}
    }

    if (-not (Test-Path $OutputDir)) {
        New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
    }

    # Critical EDR-killer subset
    $criticalDrivers = @(
        'rtcore64.sys','rtcore32.sys',
        'mhyprot.sys','mhyprot2.sys','mhyprot3.sys',
        'mhyprotect.sys','mhyprotnap.sys',
        'zamguard64.sys','zam64.sys',
        'gdrv.sys',
        'dbutil_2_3.sys','dbutildrv2.sys','dbutil.sys',
        'iqvw64e.sys','iqvw64.sys',
        'procexp152.sys','procexp.sys',
        'aswarpot.sys','aswvmm.sys',
        'kprocesshacker.sys',
        'truesight.sys',
        'bedaisy.sys',
        'capcom.sys',
        'blackbone.sys','blackbonedrv10.sys'
    )
    $critInCache = @($criticalDrivers | Where-Object { $allDrivers -contains $_ } | Sort-Object -Unique)

    Write-Host "[LolDrivers-YARA] Building YARA rules for $($allDrivers.Count) drivers ($($critInCache.Count) critical)..." -ForegroundColor Cyan

    # ---- Helper: build YARA string block ----
    # Uses nocase + wide ascii so both UTF-8 and UTF-16 paths are matched.
    # Strips .sys extension for the variable name to create valid identifiers.
    function Build-YaraStrings {
        param([string[]]$Drivers, [string]$Prefix = "drv")
        $lines = @()
        $idx = 0
        foreach ($d in $Drivers) {
            $idx++
            $safeName = $d -replace '[^a-zA-Z0-9]','_'
            $lines += "        `$$($Prefix)_$($safeName) = `"\\$d`" wide ascii nocase"
        }
        return $lines -join "`n"
    }

    # ------------------------------------------------------------------
    # Rule 1 - All vulnerable drivers (filename path match)
    # ------------------------------------------------------------------
    $allStrings = Build-YaraStrings $allDrivers "drv"
    $outFile1 = Join-Path $OutputDir "BYOVD_LOLDriver_Vulnerable_Name.yar"
    $rule1 = @"
/*
    BYOVD_LOLDriver_Vulnerable_Name
    Auto-generated by Loaded Potato from merged LOL Drivers cache.
    Detects known vulnerable driver filenames in file paths or strings.
    Sources: loldrivers.io API + LOLDrivers Sigma + SigmaHQ community.
    Drivers tracked: $($allDrivers.Count)
    Generated: $metaDate

    Use for: filesystem sweeps, memory scanning, incident response triage.
    MITRE ATT&CK: T1068, T1543.003
*/

rule BYOVD_LOLDriver_Vulnerable_Name
{
    meta:
        author = "Loaded Potato (auto-generated)"
        description = "Detects known vulnerable/abusable driver filenames from the LOL Drivers database"
        reference = "https://loldrivers.io/"
        date = "$metaDate"
        score = 60

    strings:
$allStrings

    condition:
        1 of them
}
"@

    Set-Content -LiteralPath $outFile1 -Value $rule1 -Encoding UTF8

    # ------------------------------------------------------------------
    # Rule 2 - Critical EDR killers (high-confidence malicious)
    # ------------------------------------------------------------------
    $critStrings = Build-YaraStrings $critInCache "edr"
    $outFile2 = Join-Path $OutputDir "BYOVD_Critical_EDR_Killer.yar"
    $critList = $critInCache -join ', '
    $rule2 = @"
/*
    BYOVD_Critical_EDR_Killer
    Auto-generated by Loaded Potato from merged LOL Drivers cache.
    Highest-risk BYOVD drivers confirmed in ransomware / APT campaigns
    specifically to disable EDR/AV.
    Drivers: $critList
    Generated: $metaDate

    Any match is high-confidence malicious in a production environment.
    Campaigns: BlackByte, SCATTERED SPIDER, Genshin ransomware,
    Terminator/BURNTCIGAR, RobbinHood, AvosLocker/POORTRY, Lazarus.
*/

rule BYOVD_Critical_EDR_Killer
{
    meta:
        author = "Loaded Potato (auto-generated)"
        description = "Detects critical BYOVD EDR-killer driver filenames confirmed in active campaigns"
        reference = "https://loldrivers.io/"
        date = "$metaDate"
        score = 90

    strings:
$critStrings

    condition:
        1 of them
}
"@

    Set-Content -LiteralPath $outFile2 -Value $rule2 -Encoding UTF8

    # ------------------------------------------------------------------
    # Rule 3 - Service installation pattern (sc.exe + driver name)
    # ------------------------------------------------------------------
    $scStrings = Build-YaraStrings $critInCache "svc"
    $outFile3 = Join-Path $OutputDir "BYOVD_Driver_Service_Install.yar"
    $rule3 = @"
/*
    BYOVD_Driver_Service_Install
    Auto-generated by Loaded Potato from merged LOL Drivers cache.
    Detects artifacts of sc.exe kernel service creation for critical
    BYOVD drivers. Useful for scanning process memory, script files,
    batch files, and PowerShell logs for BYOVD installation commands.
    Generated: $metaDate
*/

rule BYOVD_Driver_Service_Install
{
    meta:
        author = "Loaded Potato (auto-generated)"
        description = "Detects sc.exe service creation commands referencing critical BYOVD drivers"
        reference = "https://loldrivers.io/"
        date = "$metaDate"
        score = 85

    strings:
        `$sc1 = "sc create" wide ascii nocase
        `$sc2 = "sc.exe create" wide ascii nocase
        `$sc3 = "New-Service" wide ascii nocase
        `$kernel = "kernel" wide ascii nocase
$scStrings

    condition:
        (`$sc1 or `$sc2 or `$sc3) and `$kernel and 1 of (`$svc_*)
}
"@

    Set-Content -LiteralPath $outFile3 -Value $rule3 -Encoding UTF8

    Write-Host "[LolDrivers-YARA] Rules written:" -ForegroundColor Green
    Write-Host "[LolDrivers-YARA]   $outFile1" -ForegroundColor Green
    Write-Host "[LolDrivers-YARA]   $outFile2" -ForegroundColor Green
    Write-Host "[LolDrivers-YARA]   $outFile3" -ForegroundColor Green
}


# ---------------------------------------------------------------------------
# Orchestrator: cache update + all detection exports
# ---------------------------------------------------------------------------

function Update-LolDriversDetections {
    <#
    .SYNOPSIS
        Full LOL Drivers detection pipeline: update cache from 3 sources,
        then export Kibana NDJSON, Sigma YAML, and YARA rules.
    .DESCRIPTION
        Orchestrates the complete detection update workflow:
          1. Update-LolDriversCache  (pull loldrivers.io + LOLDrivers Sigma + SigmaHQ)
          2. Export-LolDriversKibanaRules  (3 Kibana NDJSON rules)
          3. Export-LolDriversSigmaRules   (4 Sigma YAML rules)
          4. Export-LolDriversYaraRules    (3 YARA rules)

        Use -Force to re-download the cache even if it was refreshed recently.
    .EXAMPLE
        Update-LolDriversDetections
        Update-LolDriversDetections -Force
    #>
    [CmdletBinding()]
    param(
        [switch]$Force
    )

    Write-Host @"

  ================================================================
   LOL Drivers Detection Pipeline
   Cache update + Kibana NDJSON + Sigma YAML + YARA rules
  ================================================================

"@ -ForegroundColor Cyan

    # Step 1: Update cache
    Write-Host "--- [Step 1/5] Updating LOL Drivers cache ---" -ForegroundColor Yellow
    if ($Force) {
        Update-LolDriversCache -Force
    } else {
        Update-LolDriversCache
    }
    Write-Host ""

    # Step 2: Export Kibana NDJSON
    Write-Host "--- [Step 2/5] Exporting Kibana NDJSON rules ---" -ForegroundColor Yellow
    Export-LolDriversKibanaRules
    Write-Host ""

    # Step 3: Export Sigma YAML
    Write-Host "--- [Step 3/5] Exporting Sigma YAML rules ---" -ForegroundColor Yellow
    Export-LolDriversSigmaRules
    Write-Host ""

    # Step 4: Export YARA rules
    Write-Host "--- [Step 4/5] Exporting YARA rules ---" -ForegroundColor Yellow
    Export-LolDriversYaraRules
    Write-Host ""

    # Step 5: Export Tanium Threat Response signals
    Write-Host "--- [Step 5/5] Exporting Tanium Threat Response signals ---" -ForegroundColor Yellow
    New-TaniumLOLDriverSignals
    Write-Host ""

    Write-Host @"

  ================================================================
   Pipeline complete.

   Outputs:
     NDJSON  : detections\kibanaImport\loldrivers-byovd-detections.ndjson
     Sigma   : detections\sigma\LOLDrivers BYOVD *.yml  (4 rules)
     YARA    : detections\yara\BYOVD_*.yar              (3 rules)
     Tanium  : detections\tanium-loldrivers\TaniumLOLDrivers_Import.json

   Next steps:
     - Import NDJSON into Kibana: Security > Rules > Import
     - Sigma rules can be used with sigma-cli or imported via 11b/11c
     - YARA rules can be deployed to Thor, Loki, or osquery
     - Import Tanium signals: Threat Response > Intel > Import
  ================================================================

"@ -ForegroundColor Cyan
}

Export-ModuleMember -Function @(
    'Export-LolDriversKibanaRules',
    'Export-LolDriversSigmaRules',
    'Export-LolDriversYaraRules',
    'Update-LolDriversDetections'
)
