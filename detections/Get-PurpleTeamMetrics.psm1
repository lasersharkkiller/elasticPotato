# Get-PurpleTeamMetrics.psm1
# Purple Teaming Metrics Dashboard
#
# Sections:
#   1. Detection rules in Kibana (total / enabled / disabled)
#   2. Alerts triggered in the last N days (top rules by hit count)
#   3. Local detection artifacts: ndjson rules, Sigma rules, YARA rules
#   4. Malware detonation history (Detonation_Report.csv files)
#   5. Detonation session inventory  (session_info.txt walk of DetonationLogs)
#   6. Cross-run differential        (alert coverage delta: latest 2 runs per family)
#   7. Observable indicators         (process drops, suspicious DNS, persistence)
#
# Auth:
#   Kibana rules  -> Kibana_URL  + Elastic_User / Elastic_Pass  (port 5601)
#   Alert signals -> Elastic_URL + Elastic_User / Elastic_Pass  (port 9200)

function Get-PurpleTeamMetrics {
    [CmdletBinding()]
    param(
        # How many days back to look for triggered alerts (live SIEM)
        [int]$AlertDays = 30,

        # How many top rules to show in the live alerts section
        [int]$TopN = 10,

        # Root path to walk for detonation log directories.
        # Defaults to D:\DetonationLogs if it exists, else skips sections 5-7.
        [string]$DetonationLogsPath = '',

        # Show cross-run differential (sections 6-7). Can be slow for large dirs.
        [switch]$ShowDiff,

        # Max alert rule rows to show in the differential tables
        [int]$DiffTopN = 20
    )

    # ---- TLS / cert setup --------------------------------------------------------
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    }
    $restArgs   = if ($PSVersionTable.PSVersion.Major -ge 6) { @{ SkipCertificateCheck = $true } } else { @{} }
    $kibanaArgs = $restArgs.Clone()
    $irmMeta    = Get-Command Invoke-RestMethod -ErrorAction SilentlyContinue
    if ($irmMeta -and $irmMeta.Parameters.ContainsKey('HttpVersion')) {
        $kibanaArgs['HttpVersion'] = [System.Version]::new(1, 1)
    }

    # ---- Credentials -------------------------------------------------------------
    $esUser = $null; $esPass = $null
    try {
        $esUser = (Get-Secret -Name 'Elastic_User' -AsPlainText -ErrorAction SilentlyContinue).Trim()
        $esPass = (Get-Secret -Name 'Elastic_Pass' -AsPlainText -ErrorAction SilentlyContinue).Trim()
    } catch { }
    if (-not $esUser) { $esUser = (Read-Host 'Elastic/Kibana username').Trim() }
    if (-not $esPass) { $esPass = (Read-Host 'Elastic/Kibana password').Trim() }

    $b64Auth   = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${esUser}:${esPass}"))
    $esHeaders = @{ 'Authorization' = "Basic $b64Auth"; 'Content-Type' = 'application/json' }
    $kbHeaders = @{ 'Authorization' = "Basic $b64Auth"; 'Content-Type' = 'application/json'; 'kbn-xsrf' = 'true' }

    # ---- URLs --------------------------------------------------------------------
    $kibanaUrl = $null; $esUrl = $null
    try { $kibanaUrl = (Get-Secret -Name 'Kibana_URL'  -AsPlainText -ErrorAction SilentlyContinue).Trim().TrimEnd('/') } catch { }
    try { $esUrl     = (Get-Secret -Name 'Elastic_URL' -AsPlainText -ErrorAction SilentlyContinue).Trim().TrimEnd('/') } catch { }
    if (-not $kibanaUrl) { $kibanaUrl = (Read-Host 'Kibana URL (e.g. https://192.168.1.10:5601)').Trim().TrimEnd('/') }
    if (-not $esUrl)     { $esUrl     = (Read-Host 'Elasticsearch URL (e.g. https://192.168.1.10:9200)').Trim().TrimEnd('/') }

    # ---- Resolve DetonationLogsPath ----------------------------------------------
    if (-not $DetonationLogsPath) {
        $candidates = @('D:\DetonationLogs', 'C:\DetonationLogs',
                        'D:\githubProjects\DetonationLogs',
                        (Join-Path $env:USERPROFILE 'DetonationLogs'),
                        (Join-Path $env:USERPROFILE 'githubProjects\DetonationLogs'),
                        (Join-Path ([System.IO.Path]::GetPathRoot($PSScriptRoot)) 'githubProjects\DetonationLogs'))
        foreach ($c in $candidates) {
            if (Test-Path -LiteralPath $c) { $DetonationLogsPath = $c; break }
        }
    }
    $detonLogsOk = $DetonationLogsPath -and (Test-Path -LiteralPath $DetonationLogsPath)

    # ?????? NDJSON helper: count alert rule names in one session directory ???????????????????????????????????????
    function Get-AlertCounts {
        param([string]$SessionDir)
        $counts = @{}
        $alertFiles = @('alerts.ndjson','api_events.ndjson','process_events.ndjson',
                        'file_events.ndjson','registry_events.ndjson',
                        'network_events.ndjson','image_load.ndjson','driver_and_pipe.ndjson')
        foreach ($fname in $alertFiles) {
            $fp = Join-Path $SessionDir $fname
            if (-not (Test-Path -LiteralPath $fp)) { continue }
            foreach ($line in [System.IO.File]::ReadAllLines($fp)) {
                $t = $line.Trim()
                if (-not $t) { continue }
                try {
                    $e = $t | ConvertFrom-Json
                    $n = $e.'kibana.alert.rule.name'
                    if ($n) { $counts[$n] = ($counts[$n] -as [int]) + 1 }
                } catch { }
            }
        }
        return $counts
    }

    # ?????? Parse session_info.txt into a hashtable ????????????????????????????????????????????????????????????????????????????????????????????????????????????
    function Read-SessionInfo {
        param([string]$SessionDir)
        $fp = Join-Path $SessionDir 'session_info.txt'
        if (-not (Test-Path -LiteralPath $fp)) { return $null }
        $info = @{ Path = $SessionDir }
        foreach ($line in [System.IO.File]::ReadAllLines($fp)) {
            if ($line -match '^\s*(\w[\w\s]*?)\s*:\s*(.+)$') {
                $info[$Matches[1].Trim()] = $Matches[2].Trim()
            }
            if ($line -match '^\s+([\w_]+)\s+(\d+)$') {
                $info["cat_$($Matches[1].Trim())"] = [int]$Matches[2]
            }
        }
        return $info
    }

    # ?????? Domain allowlist for suspicious-DNS filter ????????????????????????????????????????????????????????????????????????????????????????????????
    $knownGoodDomains = @(
        'microsoft','windows','elastic','google','apple','digicert','verisign',
        'symantec','cloudflare','amazonaws','azure','office365','onedrive',
        'bing\.com','msn\.com','live\.com','msftconnecttest','gvt','googleapis',
        'gstatic','akamai','windowsupdate','visualstudio','github','ocsp\.',
        'pki\.','crl\.','ctldl\.','smartscreen','sophosxl','trendmicro',
        'kaspersky','mcafee','cylance','sentinelone','crowdstrike'
    )
    $knownGoodPattern = ($knownGoodDomains -join '|')

    # ?????? Extract suspicious DNS queries from a session dir ???????????????????????????????????????????????????????????????????????????
    function Get-SuspiciousDns {
        param([string]$SessionDir)
        $fp = Join-Path $SessionDir 'network_events.ndjson'
        if (-not (Test-Path -LiteralPath $fp)) { return @() }
        $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($line in [System.IO.File]::ReadAllLines($fp)) {
            $t = $line.Trim(); if (-not $t) { continue }
            try {
                $e = $t | ConvertFrom-Json
                $q = $e.dns.question.name
                if ($q -and $q -notmatch $knownGoodPattern -and $q -notmatch '^(localhost|wpad|.*\.local)$') {
                    $proc = ($e.process.name) -replace '.*\\',''
                    if (-not $proc) { $proc = ($e.process.executable) -replace '.*\\','' }
                    [void]$seen.Add("[$proc]  $q")
                }
            } catch { }
        }
        return @($seen)
    }

    # ?????? Extract malware process drops (user-writable, non-Windows paths) ??????????????????????????????
    function Get-MalwareDrops {
        param([string]$SessionDir)
        $fp = Join-Path $SessionDir 'process_events.ndjson'
        if (-not (Test-Path -LiteralPath $fp)) { return @() }
        $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($line in [System.IO.File]::ReadAllLines($fp)) {
            $t = $line.Trim(); if (-not $t) { continue }
            try {
                $e    = $t | ConvertFrom-Json
                $exe  = $e.process.executable
                if ($exe -and
                    $exe -notlike '*\FreeSamples\*' -and
                    $exe -notlike '*\Windows\*'     -and
                    $exe -notlike '*\Program Files*' -and
                    $exe -notlike '*\Elastic\*'      -and
                    $exe -notlike 'MemCompression'   -and
                    $exe -notlike 'Registry'         -and
                    ($exe -like '*\AppData\*' -or $exe -like '*\ProgramData\*' -or $exe -like '*\Temp\*')) {
                    [void]$seen.Add($exe)
                }
            } catch { }
        }
        return @($seen | Sort-Object)
    }

    # ?????? Extract persistence-related alert rule names ?????????????????????????????????????????????????????????????????????????????????????????????
    function Get-PersistenceSignals {
        param([hashtable]$AlertCounts)
        $persistKeys = @('Run Key','Startup','Scheduled Task','schtasks','sc.exe',
                         'Service','COM Hijack','Winlogon','AppInit','Boot Execute',
                         'Root Certificate','Script Block Logging')
        $results = @{}
        foreach ($k in $AlertCounts.Keys) {
            foreach ($pk in $persistKeys) {
                if ($k -match [regex]::Escape($pk)) { $results[$k] = $AlertCounts[$k]; break }
            }
        }
        return $results
    }

    # ==========================================================================
    Write-Host ""
    Write-Host "  +============================================================+" -ForegroundColor Magenta
    Write-Host "  |           Purple Teaming Metrics Dashboard                 |" -ForegroundColor Magenta
    Write-Host "  +============================================================+" -ForegroundColor Magenta
    Write-Host ""

    # ==========================================================================
    # SECTION 1: Kibana Detection Rules
    # ==========================================================================
    Write-Host "  [ 1 ]  Detection Rules - Kibana SIEM" -ForegroundColor Cyan
    Write-Host "  -------------------------------------" -ForegroundColor DarkGray

    $totalRules   = 0
    $enabledRules = 0
    $kibanaOk     = $false

    try {
        $page = 1; $fetched = 0; $kbTotal = -1
        do {
            $uri  = "$kibanaUrl/api/detection_engine/rules/_find?page=$page&per_page=500"
            $resp = Invoke-RestMethod -Uri $uri -Method Get -Headers $kbHeaders -UseBasicParsing @kibanaArgs
            if ($kbTotal -eq -1) { $kbTotal = [int]$resp.total }
            foreach ($r in $resp.data) {
                $totalRules++
                if ($r.enabled) { $enabledRules++ }
            }
            $fetched += $resp.data.Count
            $page++
        } while ($fetched -lt $kbTotal -and $resp.data.Count -gt 0)
        $kibanaOk = $true
    } catch {
        Write-Host "  [!] Could not reach Kibana rules API: $_" -ForegroundColor Red
    }

    if ($kibanaOk) {
        $disabledRules = $totalRules - $enabledRules
        Write-Host ("  Total rules in SIEM  : {0}" -f $totalRules)   -ForegroundColor White
        Write-Host ("  Enabled              : {0}" -f $enabledRules)  -ForegroundColor Green
        Write-Host ("  Disabled             : {0}" -f $disabledRules) -ForegroundColor DarkYellow
    }
    Write-Host ""

    # ==========================================================================
    # SECTION 2: Alerts Triggered (last N days)
    # ==========================================================================
    Write-Host ("  [ 2 ]  Alerts Triggered - Last {0} Days" -f $AlertDays) -ForegroundColor Cyan
    Write-Host "  ----------------------------------------" -ForegroundColor DarkGray

    $alertIndex = ".alerts-security.alerts-default"
    $fromMs     = [DateTimeOffset]::UtcNow.AddDays(-$AlertDays).ToUnixTimeMilliseconds()
    $alertQuery = @{
        size  = 0
        query = @{ bool = @{ filter = @(
            @{ range = @{ "@timestamp" = @{ gte = $fromMs; format = "epoch_millis" } } }
        ) } }
        aggs = @{
            by_rule      = @{ terms = @{ field = "kibana.alert.rule.name"; size = $TopN; order = @{ _count = "desc" } } }
            total_alerts = @{ value_count = @{ field = "kibana.alert.rule.name" } }
        }
    } | ConvertTo-Json -Depth 10 -Compress

    try {
        $aResp       = Invoke-RestMethod -Uri "$esUrl/$alertIndex/_search" -Method Post -Headers $esHeaders -Body $alertQuery @restArgs
        $totalAlerts = [int]$aResp.aggregations.total_alerts.value
        Write-Host ("  Total alerts         : {0}" -f $totalAlerts) -ForegroundColor White
        Write-Host ""
        Write-Host ("  Top {0} triggered rules:" -f $TopN) -ForegroundColor DarkGray
        $rank = 1
        foreach ($bucket in $aResp.aggregations.by_rule.buckets) {
            $ruleName = $bucket.key
            if ($ruleName.Length -gt 90) { $ruleName = $ruleName.Substring(0, 87) + '...' }
            Write-Host ("    {0,2}. [{1,5}]  {2}" -f $rank, $bucket.doc_count, $ruleName) -ForegroundColor Yellow
            $rank++
        }
    } catch {
        Write-Host "  [!] Could not query alert index: $_" -ForegroundColor Red
    }
    Write-Host ""

    # ==========================================================================
    # SECTION 3: Local Detection Artifacts
    # ==========================================================================
    Write-Host "  [ 3 ]  Local Detection Artifacts" -ForegroundColor Cyan
    Write-Host "  ---------------------------------" -ForegroundColor DarkGray

    $ndjsonDir      = Join-Path $PSScriptRoot 'kibanaImport'
    $localNdjson    = @(Get-ChildItem -LiteralPath $ndjsonDir -Filter '*.ndjson' -File -ErrorAction SilentlyContinue)
    $localRuleCount = 0
    foreach ($f in $localNdjson) {
        $localRuleCount += ([System.IO.File]::ReadAllLines($f.FullName) |
            Where-Object { $_.Trim() -and -not $_.Trim().StartsWith('//') } |
            Where-Object { ($_ | ConvertFrom-Json -ErrorAction SilentlyContinue).rule_id }).Count
    }
    Write-Host ("  Local ndjson files   : {0}  ({1} rules)" -f $localNdjson.Count, $localRuleCount) -ForegroundColor White

    $sigmaDir   = Join-Path $PSScriptRoot 'sigma'
    $sigmaRules = @(Get-ChildItem -LiteralPath $sigmaDir -Recurse -Filter '*.yml' -File -ErrorAction SilentlyContinue)
    Write-Host ("  Sigma rules (.yml)   : {0}" -f $sigmaRules.Count) -ForegroundColor White

    $yaraDir   = Join-Path $PSScriptRoot 'yara'
    $yaraRules = @(Get-ChildItem -LiteralPath $yaraDir -Recurse -Include '*.yar','*.yara' -File -ErrorAction SilentlyContinue)
    Write-Host ("  YARA rules           : {0}" -f $yaraRules.Count) -ForegroundColor White
    Write-Host ""

    # ==========================================================================
    # SECTION 4: Detonation History (CSV-based)
    # ==========================================================================
    Write-Host "  [ 4 ]  Malware Detonation History (CSV)" -ForegroundColor Cyan
    Write-Host "  ----------------------------------------" -ForegroundColor DarkGray

    $searchRoot = $PSScriptRoot
    for ($i = 0; $i -lt 4; $i++) {
        if (Test-Path (Join-Path $searchRoot 'LoadedPotato_Main.ps1')) { break }
        $searchRoot = Split-Path $searchRoot -Parent
    }

    $detonationCsvs = @(Get-ChildItem -LiteralPath $searchRoot -Recurse -Filter 'Detonation_Report.csv' -File -ErrorAction SilentlyContinue)
    if ($detonationCsvs.Count -eq 0) {
        Write-Host "  No Detonation_Report.csv files found under project root." -ForegroundColor DarkGray
    } else {
        $totalDetonated = 0; $totalSuccess = 0; $totalFailed = 0
        foreach ($csv in $detonationCsvs) {
            try {
                $rows = Import-Csv $csv.FullName
                $totalDetonated += $rows.Count
                $totalSuccess   += ($rows | Where-Object { $_.Status -eq 'Success' }).Count
                $totalFailed    += ($rows | Where-Object { $_.Status -ne 'Success' }).Count
            } catch { }
        }
        Write-Host ("  Report files found   : {0}" -f $detonationCsvs.Count)  -ForegroundColor White
        Write-Host ("  Total samples run    : {0}" -f $totalDetonated)         -ForegroundColor White
        Write-Host ("  Successful exec      : {0}" -f $totalSuccess)           -ForegroundColor Green
        Write-Host ("  Failed exec          : {0}" -f $totalFailed)            -ForegroundColor DarkYellow
        $newest = ($detonationCsvs | Sort-Object LastWriteTime -Descending | Select-Object -First 1)
        Write-Host ("  Last detonation      : {0}" -f $newest.LastWriteTime.ToString('yyyy-MM-dd HH:mm')) -ForegroundColor White
    }
    Write-Host ""

    # ==========================================================================
    # SECTIONS 5-7: Detonation Log Analysis (session_info / NDJSON)
    # ==========================================================================
    if (-not $detonLogsOk) {
        Write-Host "  [ 5-7 ] Detonation log analysis skipped (no DetonationLogs directory found)." -ForegroundColor DarkGray
        Write-Host "          Pass -DetonationLogsPath to specify a path." -ForegroundColor DarkGray
        Write-Host ""
    } else {

    # =========================================================================
    # SECTION 5: Detonation Session Inventory
    # =========================================================================
    Write-Host "  [ 5 ]  Detonation Session Inventory" -ForegroundColor Cyan
    Write-Host ("         Scanning: {0}" -f $DetonationLogsPath) -ForegroundColor DarkGray
    Write-Host "  ------------------------------------" -ForegroundColor DarkGray

    $sessionInfoFiles = @(Get-ChildItem -LiteralPath $DetonationLogsPath -Recurse -Filter 'session_info.txt' -File -ErrorAction SilentlyContinue)

    if ($sessionInfoFiles.Count -eq 0) {
        Write-Host "  No session_info.txt files found." -ForegroundColor DarkGray
    } else {
        # Collect all sessions
        $sessions = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($sf in $sessionInfoFiles) {
            $si = Read-SessionInfo -SessionDir $sf.DirectoryName
            if ($si) { $sessions.Add($si) }
        }

        # Group by threat family (grandparent folder relative to DetonationLogsPath)
        $familyGroups = @{}
        foreach ($si in $sessions) {
            # Derive family name: path relative to DetonationLogsPath, take first 2 components
            $rel   = $si.Path.Substring($DetonationLogsPath.Length).TrimStart('\','/')
            $parts = $rel -split '[\\\/]'
            $family = if ($parts.Count -ge 2) { "$($parts[0])\$($parts[1])" } else { $parts[0] }
            if (-not $familyGroups[$family]) { $familyGroups[$family] = @() }
            $familyGroups[$family] += $si
        }

        Write-Host ("  Sessions found       : {0}  across {1} threat families" -f $sessions.Count, $familyGroups.Count) -ForegroundColor White
        Write-Host ""

        foreach ($family in ($familyGroups.Keys | Sort-Object)) {
            $runs = @($familyGroups[$family])
            Write-Host ("  ?????? {0}  ({1} run{2})" -f $family, $runs.Count, $(if ($runs.Count -ne 1) {'s'} else {''})) -ForegroundColor Magenta

            foreach ($si in ($runs | Sort-Object { $si.Start })) {
                $sessionName = Split-Path $si.Path -Leaf
                $start    = $si['Start']
                $dur      = $si['Duration']
                $procEv   = $si['cat_process_events']
                $netEv    = $si['cat_network_events']
                $fileEv   = $si['cat_file_events']
                $regEv    = $si['cat_registry_events']
                $alerts   = $si['cat_alerts']
                $apiEv    = $si['cat_api_events']

                Write-Host ("  ???   {0}" -f $sessionName) -ForegroundColor White
                Write-Host ("  ???     Start: {0,-28}  Duration: {1}" -f $start, $dur) -ForegroundColor DarkGray

                # Event category bar
                $evLine = "  ???     Events: "
                if ($procEv)  { $evLine += "proc=$procEv  " }
                if ($netEv)   { $evLine += "net=$netEv  " }
                if ($fileEv)  { $evLine += "file=$fileEv  " }
                if ($regEv)   { $evLine += "reg=$regEv  " }
                if ($apiEv)   { $evLine += "api=$apiEv  " }
                if ($alerts)  { $evLine += "alerts=$alerts" }
                Write-Host $evLine -ForegroundColor DarkGray
            }
            Write-Host "  ???" -ForegroundColor Magenta
            Write-Host ""
        }
    }

    # =========================================================================
    # SECTION 6: Cross-Run Differential Analysis
    # =========================================================================
    if ($ShowDiff -and $sessionInfoFiles.Count -ge 2) {

    Write-Host "  [ 6 ]  Cross-Run Differential Analysis" -ForegroundColor Cyan
    Write-Host "  ----------------------------------------" -ForegroundColor DarkGray
    Write-Host "  Comparing most recent 2 runs per threat family..." -ForegroundColor DarkGray
    Write-Host ""

    foreach ($family in ($familyGroups.Keys | Sort-Object)) {
        $runs = @($familyGroups[$family] | Sort-Object { $_['Start'] })
        if ($runs.Count -lt 2) { continue }

        # Take the two most recent runs
        $runA = $runs[$runs.Count - 2]   # older of the two
        $runB = $runs[$runs.Count - 1]   # newer / retest

        $nameA = Split-Path $runA.Path -Leaf
        $nameB = Split-Path $runB.Path -Leaf

        Write-Host ("  ?????????  {0}" -f $family) -ForegroundColor Magenta
        Write-Host ("  ???  Run A (initial) : {0}" -f $nameA) -ForegroundColor DarkGray
        Write-Host ("  ???  Run B (retest)  : {0}" -f $nameB) -ForegroundColor DarkGray

        $countsA = Get-AlertCounts -SessionDir $runA.Path
        $countsB = Get-AlertCounts -SessionDir $runB.Path

        $totalA  = ($countsA.Values | Measure-Object -Sum).Sum
        $totalB  = ($countsB.Values | Measure-Object -Sum).Sum
        $deltaT  = $totalB - $totalA
        $deltaColor = if ($deltaT -lt 0) { 'Green' } elseif ($deltaT -gt 0) { 'Yellow' } else { 'White' }
        $deltaSign  = if ($deltaT -gt 0) { '+' } else { '' }

        Write-Host ("  ???  Total alerts    : {0}  ???  {1}  ({2}{3})" -f $totalA, $totalB, $deltaSign, $deltaT) -ForegroundColor $deltaColor

        # Rules present in B but not in A (net-new coverage)
        $netNew = @($countsB.Keys | Where-Object { -not $countsA.ContainsKey($_) } | Sort-Object)
        # Rules present in A but not in B (coverage lost)
        $lost   = @($countsA.Keys | Where-Object { -not $countsB.ContainsKey($_) } | Sort-Object)
        # Rules in both but count changed significantly
        $gained = @($countsB.Keys | Where-Object { $countsA.ContainsKey($_) -and ($countsB[$_] -gt $countsA[$_]) } |
                    Sort-Object { $countsB[$_] - $countsA[$_] } -Descending |
                    Select-Object -First $DiffTopN)
        $reduced = @($countsB.Keys | Where-Object { $countsA.ContainsKey($_) -and ($countsB[$_] -lt $countsA[$_]) } |
                    Sort-Object { $countsA[$_] - $countsB[$_] } -Descending |
                    Select-Object -First $DiffTopN)

        if ($netNew.Count -gt 0) {
            Write-Host ("  ???") -ForegroundColor Magenta
            Write-Host ("  ???  ++ NET-NEW signals in retest ({0}):" -f $netNew.Count) -ForegroundColor Green
            foreach ($r in ($netNew | Select-Object -First $DiffTopN)) {
                $n = $r; if ($n.Length -gt 80) { $n = $n.Substring(0,77) + '...' }
                Write-Host ("  ???       [{0,4}]  {1}" -f $countsB[$r], $n) -ForegroundColor Green
            }
            if ($netNew.Count -gt $DiffTopN) {
                Write-Host ("  ???       ... and {0} more" -f ($netNew.Count - $DiffTopN)) -ForegroundColor DarkGray
            }
        }

        if ($lost.Count -gt 0) {
            Write-Host ("  ???") -ForegroundColor Magenta
            Write-Host ("  ???  -- LOST signals (in A, missing in B) ({0}):" -f $lost.Count) -ForegroundColor Red
            foreach ($r in ($lost | Select-Object -First $DiffTopN)) {
                $n = $r; if ($n.Length -gt 80) { $n = $n.Substring(0,77) + '...' }
                Write-Host ("  ???       [{0,4}]  {1}" -f $countsA[$r], $n) -ForegroundColor Red
            }
            if ($lost.Count -gt $DiffTopN) {
                Write-Host ("  ???       ... and {0} more" -f ($lost.Count - $DiffTopN)) -ForegroundColor DarkGray
            }
        }

        if ($gained.Count -gt 0) {
            Write-Host ("  ???") -ForegroundColor Magenta
            Write-Host ("  ???  ???  Improved coverage (count increased):" -f $null) -ForegroundColor Cyan
            foreach ($r in $gained) {
                $n = $r; if ($n.Length -gt 72) { $n = $n.Substring(0,69) + '...' }
                $delta = $countsB[$r] - $countsA[$r]
                Write-Host ("  ???       {0} ??? {1}  (+{2})  {3}" -f $countsA[$r], $countsB[$r], $delta, $n) -ForegroundColor Cyan
            }
        }

        if ($reduced.Count -gt 0) {
            Write-Host ("  ???") -ForegroundColor Magenta
            Write-Host ("  ???  ???  Reduced signals (may be noise reduction or tuning gap):" -f $null) -ForegroundColor DarkYellow
            foreach ($r in $reduced) {
                $n = $r; if ($n.Length -gt 72) { $n = $n.Substring(0,69) + '...' }
                $delta = $countsA[$r] - $countsB[$r]
                Write-Host ("  ???       {0} ??? {1}  (-{2})  {3}" -f $countsA[$r], $countsB[$r], $delta, $n) -ForegroundColor DarkYellow
            }
        }

        Write-Host ("  ???" + ('???' * 60)) -ForegroundColor Magenta
        Write-Host ""
    }

    } elseif ($ShowDiff) {
        Write-Host "  [ 6 ]  Differential skipped ??? need at least 2 sessions to compare." -ForegroundColor DarkGray
        Write-Host ""
    }

    # =========================================================================
    # SECTION 7: Observable Indicators (latest run per family)
    # =========================================================================
    Write-Host "  [ 7 ]  Observable Indicators  (latest run per family)" -ForegroundColor Cyan
    Write-Host "  -------------------------------------------------------" -ForegroundColor DarkGray

    if ($sessionInfoFiles.Count -eq 0) {
        Write-Host "  No sessions found." -ForegroundColor DarkGray
    } else {

        foreach ($family in ($familyGroups.Keys | Sort-Object)) {
            $runs   = @($familyGroups[$family] | Sort-Object { $_['Start'] })
            $latest = $runs[$runs.Count - 1]
            $label  = Split-Path $latest.Path -Leaf

            Write-Host ("  ?????? {0}" -f $family) -ForegroundColor Magenta
            Write-Host ("     Session: {0}" -f $label) -ForegroundColor DarkGray

            # Malware drops
            $drops = Get-MalwareDrops -SessionDir $latest.Path
            if ($drops.Count -gt 0) {
                Write-Host "     [Malware Drops / Staged Binaries]" -ForegroundColor Yellow
                foreach ($d in ($drops | Select-Object -First 20)) {
                    Write-Host ("       {0}" -f $d) -ForegroundColor DarkYellow
                }
                if ($drops.Count -gt 20) {
                    Write-Host ("       ... and {0} more" -f ($drops.Count - 20)) -ForegroundColor DarkGray
                }
            } else {
                Write-Host "     [Malware Drops] None detected in user-writable paths." -ForegroundColor DarkGray
            }

            # Suspicious DNS
            $dns = Get-SuspiciousDns -SessionDir $latest.Path
            if ($dns.Count -gt 0) {
                Write-Host "     [Suspicious DNS Queries]" -ForegroundColor Yellow
                foreach ($d in ($dns | Sort-Object | Select-Object -First 25)) {
                    Write-Host ("       {0}" -f $d) -ForegroundColor DarkYellow
                }
                if ($dns.Count -gt 25) {
                    Write-Host ("       ... and {0} more" -f ($dns.Count - 25)) -ForegroundColor DarkGray
                }
            } else {
                Write-Host "     [Suspicious DNS] None detected." -ForegroundColor DarkGray
            }

            # Persistence signals
            $alertCounts = Get-AlertCounts -SessionDir $latest.Path
            $persists    = Get-PersistenceSignals -AlertCounts $alertCounts
            if ($persists.Count -gt 0) {
                Write-Host "     [Persistence Signals]" -ForegroundColor Yellow
                foreach ($k in ($persists.Keys | Sort-Object)) {
                    $n = $k; if ($n.Length -gt 80) { $n = $n.Substring(0,77) + '...' }
                    Write-Host ("       [{0,4}]  {1}" -f $persists[$k], $n) -ForegroundColor DarkYellow
                }
            } else {
                Write-Host "     [Persistence Signals] None detected." -ForegroundColor DarkGray
            }

            Write-Host "  ???" -ForegroundColor Magenta
            Write-Host ""
        }
    }

    } # end detonLogsOk block

    Write-Host "  +============================================================+" -ForegroundColor Magenta
    Write-Host ""
}

Export-ModuleMember -Function Get-PurpleTeamMetrics

