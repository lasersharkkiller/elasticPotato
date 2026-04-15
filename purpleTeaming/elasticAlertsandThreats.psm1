function Get-ElasticAlertsAndThreats {
    <#
    .SYNOPSIS
        Pulls forensic artifacts and security alerts for a specified host over a
        defined time window. All artifact categories are queried independently of
        any alert - alerts are included as one section of the output alongside
        process, network, file, registry, DNS, and scheduled task data.

    .NOTES
        Connects directly to the Elasticsearch REST API.
        Compatible with on-prem, GovCloud, and air-gapped DoD stacks.
        Requires vault secrets: Elastic_URL, Elastic_User, Elastic_Pass
    #>

    # --- TLS + CERT SETUP ---
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    }
    $restArgs = if ($PSVersionTable.PSVersion.Major -ge 6) { @{ SkipCertificateCheck = $true } } else { @{} }

    # --- API SETUP ---
    $esUrl  = (Get-Secret -Name 'Elastic_URL'  -AsPlainText -ErrorAction SilentlyContinue).Trim().TrimEnd('/')
    $esUser = (Get-Secret -Name 'Elastic_User' -AsPlainText -ErrorAction SilentlyContinue).Trim()
    $esPass = (Get-Secret -Name 'Elastic_Pass' -AsPlainText -ErrorAction SilentlyContinue).Trim()

    if ([string]::IsNullOrWhiteSpace($esUrl)) {
        $esUrl = (Read-Host "[?] Elastic URL not in vault (e.g. https://192.168.1.10:9200)").TrimEnd('/')
    }
    if ([string]::IsNullOrWhiteSpace($esUrl)) { Write-Error "Elastic URL required."; return }

    if ($esUrl -notmatch '^https?://') { $esUrl = "https://$esUrl" }

    try {
        $uri = [Uri]$esUrl
        if (-not $uri.Host) { throw "No host" }
    } catch {
        Write-Host "[ERROR] Elastic URL is not valid: '$esUrl'" -ForegroundColor Red; return
    }

    $b64Auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${esUser}:${esPass}"))
    $headers = @{
        'Authorization' = "Basic $b64Auth"
        'Content-Type'  = 'application/json'
    }

    if ($esUrl -match '^http://') {
        $httpsUrl = $esUrl -replace '^http://', 'https://'
        try {
            [void](Invoke-RestMethod -Uri "$httpsUrl/_cluster/health" -Headers $headers -Method Get @restArgs -ErrorAction Stop)
            Write-Host "  [INFO] Auto-upgraded URL to https:// (ES 8.x HTTPS detected)" -ForegroundColor DarkCyan
            $esUrl = $httpsUrl
        } catch {}
    }

    $alertIndex  = ".alerts-security.alerts-default"
    $eventsIndex = "logs-*,winlogbeat-*,filebeat-*,endgame-*"

    # --- INPUT ---
    $hostName = Read-Host "Enter the Endpoint Name"
    if ($hostName -eq "") { $hostName = $env:COMPUTERNAME }

    $sStart = Read-Host "Enter start date/time (e.g. 2025-03-18 or 2025-03-18 08:00:00) - leave blank for yesterday"
    $sEnd   = Read-Host "Enter end date/time   (e.g. 2025-03-19 or 2025-03-19 20:00:00) - leave blank for now"

    if ($sStart) {
        try   { $dtStart = Get-Date $sStart }
        catch { Write-Host "Invalid start date, using yesterday."; $dtStart = (Get-Date).AddDays(-1) }
    } else {
        $dtStart = (Get-Date).AddDays(-1)
    }

    if ($sEnd) {
        try   { $dtEnd = Get-Date $sEnd }
        catch { Write-Host "Invalid end date, using now."; $dtEnd = Get-Date }
    } else {
        $dtEnd = Get-Date
    }

    $fromTime = $dtStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $toTime   = $dtEnd.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

    Write-Host "`nHost:      $hostName" -ForegroundColor DarkCyan
    Write-Host "Window:    $fromTime  -->  $toTime" -ForegroundColor DarkCyan

    if (-not (Test-Path "output")) { New-Item -Path "output" -ItemType Directory | Out-Null }

    $indicatorBaselinePath = "output\elasticDetectionsBaseline.csv"
    $BaselineMainRoot      = "output-baseline\VirusTotal-main"
    $BaselineBehaviorRoot  = "output-baseline\VirusTotal-behaviors"
    $VtCategories          = @("SignedVerified","unsignedWin","unsignedLinux","unverified","drivers","malicious")

    # ---------------------------------------------------------
    # HELPER: Find-VTHashBaseline
    # Returns @{ Category; MainFile; BehaviorFile } or $null
    # ---------------------------------------------------------
    function Find-VTHashBaseline {
        param([string]$Hash)
        if ([string]::IsNullOrWhiteSpace($Hash)) { return $null }
        $h = $Hash.Trim().ToLower()
        foreach ($cat in $VtCategories) {
            $mainPath = Join-Path $BaselineMainRoot "$cat\$h.json"
            if (Test-Path $mainPath) {
                $behPath = Join-Path $BaselineBehaviorRoot "$cat\$h.json"
                return @{
                    Category     = $cat
                    MainFile     = $mainPath
                    BehaviorFile = if (Test-Path $behPath) { $behPath } else { $null }
                }
            }
        }
        return $null
    }

    function Get-VTMainSummary {
        param([string]$Path)
        if (-not $Path -or -not (Test-Path $Path)) { return $null }
        try {
            $j = Get-Content $Path -Raw | ConvertFrom-Json
            $a = $j.data.attributes
            $stats   = $a.last_analysis_stats
            $detMal = if ($stats) { $stats.malicious } else { 0 }
            $detTot = if ($stats) { ($stats.malicious + $stats.suspicious + $stats.undetected + $stats.harmless) } else { 0 }
            $threat  = $a.popular_threat_classification
            return @{
                MeaningfulName = $a.meaningful_name
                DetectionRatio = "$detMal/$detTot engines"
                DetectionsMal  = $detMal
                ThreatLabel    = if ($threat) { $threat.suggested_threat_label } else { "" }
                Signer         = if ($a.signature_info) { $a.signature_info.product } else { "" }
                SignerStatus   = if ($a.signature_info) { $a.signature_info.verified } else { "unsigned" }
                FirstSeen      = if ($a.first_submission_date) {
                                     [DateTimeOffset]::FromUnixTimeSeconds($a.first_submission_date).ToString("yyyy-MM-dd")
                                 } else { "" }
            }
        } catch { return $null }
    }

    function Get-VTBehaviorSummary {
        param([string]$Path)
        if (-not $Path -or -not (Test-Path $Path)) { return $null }
        try {
            $j = Get-Content $Path -Raw | ConvertFrom-Json
            $d = $j.data
            $mitre = if ($d.mitre_attack_techniques) {
                $d.mitre_attack_techniques | ForEach-Object { "$($_.id) $($_.signature_description)" } |
                    Select-Object -Unique | Select-Object -First 15
            } else { @() }
            $sigs = if ($d.signatures) {
                $d.signatures | Where-Object { $_.severity -ge 5 } |
                    Sort-Object severity -Descending |
                    ForEach-Object { "[$($_.severity)/10] $($_.name)" } |
                    Select-Object -First 8
            } else { @() }
            # API calls logged by VT sandbox
            $apis = if ($d.calls_highlighted) {
                $d.calls_highlighted | Select-Object -Unique -First 20
            } elseif ($d.api_highlight) {
                $d.api_highlight | Select-Object -Unique -First 20
            } else { @() }
            return @{ MitreAttack = $mitre; HighSigs = $sigs; ApiCalls = $apis }
        } catch { return $null }
    }

    # ---------------------------------------------------------
    # HELPER: Invoke-ESQuery
    # ---------------------------------------------------------
    function Invoke-ESQuery {
        param([string]$Index, [hashtable]$Body, [int]$Size = 1000)
        $Body['size'] = $Size
        $uri      = "$esUrl/$Index/_search"
        $bodyJson = $Body | ConvertTo-Json -Depth 20 -Compress
        try {
            return Invoke-RestMethod -Uri $uri -Headers $headers -Method Post -Body $bodyJson @restArgs
        } catch {
            $code = $null
            try { $code = $_.Exception.Response.StatusCode.value__ } catch {}
            Write-Host "  [ERROR] ES query failed (HTTP $code): $($_.Exception.Message)" -ForegroundColor Red
            return $null
        }
    }

    $timeFilter = @{ range = @{ "@timestamp" = @{ gte = $fromTime; lte = $toTime } } }
    $hostFilter = @{ term  = @{ "host.name" = $hostName } }

    $results = [ordered]@{}

    # ---------------------------------------------------------
    # SECTION 1: SECURITY ALERTS
    # ---------------------------------------------------------
    Write-Host "`n[1/8] Querying security alerts..." -ForegroundColor Magenta

    $alertQuery = @{
        query = @{
            bool = @{
                must = @( $timeFilter, $hostFilter )
            }
        }
        aggs = @{
            by_rule      = @{ terms = @{ field = "kibana.alert.rule.name";               size = 100 } }
            by_technique = @{ terms = @{ field = "kibana.alert.rule.threat.technique.id"; size = 100 } }
            by_severity  = @{ terms = @{ field = "kibana.alert.severity";                 size = 10  } }
        }
        sort = @( @{ "@timestamp" = "desc" } )
    }

    $alertResp  = Invoke-ESQuery -Index $alertIndex -Body $alertQuery -Size 200
    $alertHits  = if ($alertResp) { $alertResp.hits.hits } else { @() }

    $alertRows = foreach ($hit in $alertHits) {
        $s = $hit._source
        [PSCustomObject]@{
            Timestamp   = $s.'@timestamp'
            Rule        = $s.'kibana.alert.rule.name'
            RuleType    = $s.'kibana.alert.rule.type'
            Severity    = $s.'kibana.alert.severity'
            Process     = $s.'process.name'
            ProcessPath = $s.'process.executable'
            Parent      = $s.'process.parent.name'
            Hash        = $s.'process.hash.sha256'
            Signer      = $s.'process.code_signature.subject_name'
            Trusted     = $s.'process.code_signature.trusted'
            Technique   = ($s.'kibana.alert.rule.threat.technique.id' -join ', ')
        }
    }

    # Fidelity categorization against baseline CSV
    $indicatorBaseline = @{}
    if (Test-Path $indicatorBaselinePath) {
        try {
            Import-Csv -Path $indicatorBaselinePath | ForEach-Object {
                $indicatorBaseline[$_.Indicator] = $_.Effectiveness
            }
        } catch {}
    }

    $fidelity = @{ Super = @(); Exceptions = @(); Noisy = @(); New = @() }
    $allRuleNames = if ($alertResp) {
        $alertResp.aggregations.by_rule.buckets | ForEach-Object { $_.key }
    } else { @() }

    foreach ($rule in $allRuleNames) {
        $cat = if ($indicatorBaseline.ContainsKey($rule)) { $indicatorBaseline[$rule] } else { 'New' }
        if ($fidelity.ContainsKey($cat)) { $fidelity[$cat] += $rule }
    }

    $results['Alerts'] = @{
        TotalHits = $alertHits.Count
        Rows      = $alertRows
        Fidelity  = $fidelity
        RuleCounts = if ($alertResp) { $alertResp.aggregations.by_rule.buckets } else { @() }
        Techniques = if ($alertResp) { $alertResp.aggregations.by_technique.buckets } else { @() }
    }

    Write-Host "  Found $($alertHits.Count) alert(s)." -ForegroundColor $(if ($alertHits.Count -gt 0) { 'Red' } else { 'Gray' })

    # ---------------------------------------------------------
    # SECTION 2: PROCESS CREATION
    # ---------------------------------------------------------
    Write-Host "[2/8] Querying process creation events..." -ForegroundColor Magenta

    $procQuery = @{
        query = @{ bool = @{ must = @(
            $timeFilter, $hostFilter,
            @{ term = @{ "event.category" = "process" } },
            @{ term = @{ "event.type"     = "start"   } }
        ) } }
        aggs = @{
            by_name   = @{ terms = @{ field = "process.name";        size = 200 } }
            by_parent = @{ terms = @{ field = "process.parent.name";  size = 100 } }
            by_path   = @{ terms = @{ field = "process.executable";   size = 200 } }
            by_hash   = @{ terms = @{ field = "process.hash.sha256";  size = 500 } }
        }
    }

    $procResp = Invoke-ESQuery -Index $eventsIndex -Body $procQuery -Size 0
    $results['Process Creation'] = @{
        UniqueProcesses = if ($procResp) { $procResp.aggregations.by_name.buckets }   else { @() }
        UniqueParents   = if ($procResp) { $procResp.aggregations.by_parent.buckets } else { @() }
        UniquePaths     = if ($procResp) { $procResp.aggregations.by_path.buckets }   else { @() }
        Hashes          = if ($procResp) { $procResp.aggregations.by_hash.buckets }   else { @() }
    }
    $procCount = ($results['Process Creation'].UniqueProcesses | Measure-Object).Count
    Write-Host "  $procCount unique processes." -ForegroundColor Gray

    # ---------------------------------------------------------
    # SECTION 3: NETWORK CONNECTIONS (external IPs only)
    # ---------------------------------------------------------
    Write-Host "[3/8] Querying network connections..." -ForegroundColor Magenta

    $privateFilter = @{ regexp = @{ "destination.ip" = "^(10\.|127\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.|::1)" } }

    $netQuery = @{
        query = @{ bool = @{
            must     = @( $timeFilter, $hostFilter, @{ term = @{ "event.category" = "network" } } )
            must_not = @( $privateFilter )
        } }
        aggs = @{
            by_dst_ip   = @{ terms = @{ field = "destination.ip";      size = 200 } }
            by_dst_port = @{ terms = @{ field = "destination.port";     size = 100 } }
            by_process  = @{ terms = @{ field = "process.name";         size = 100 } }
        }
    }

    $netResp = Invoke-ESQuery -Index $eventsIndex -Body $netQuery -Size 0
    $results['Network Connections'] = @{
        DestinationIPs   = if ($netResp) { $netResp.aggregations.by_dst_ip.buckets } else { @() }
        DestinationPorts = if ($netResp) { $netResp.aggregations.by_dst_port.buckets } else { @() }
        ProcessesMaking  = if ($netResp) { $netResp.aggregations.by_process.buckets } else { @() }
    }
    $netCount = ($results['Network Connections'].DestinationIPs | Measure-Object).Count
    Write-Host "  $netCount unique external IPs." -ForegroundColor Gray

    # ---------------------------------------------------------
    # SECTION 4: DNS REQUESTS
    # ---------------------------------------------------------
    Write-Host "[4/8] Querying DNS requests..." -ForegroundColor Magenta

    $dnsQuery = @{
        query = @{ bool = @{ must = @(
            $timeFilter, $hostFilter,
            @{ term = @{ "event.category" = "network" } },
            @{ term = @{ "event.action"   = "lookup_requested" } }
        ) } }
        aggs = @{
            by_domain  = @{ terms = @{ field = "dns.question.name"; size = 200 } }
            by_process = @{ terms = @{ field = "process.name";       size = 100 } }
        }
    }

    $dnsResp = Invoke-ESQuery -Index $eventsIndex -Body $dnsQuery -Size 0
    $results['DNS Requests'] = @{
        Domains   = if ($dnsResp) { $dnsResp.aggregations.by_domain.buckets } else { @() }
        Processes = if ($dnsResp) { $dnsResp.aggregations.by_process.buckets } else { @() }
    }
    $dnsCount = ($results['DNS Requests'].Domains | Measure-Object).Count
    Write-Host "  $dnsCount unique domains." -ForegroundColor Gray

    # ---------------------------------------------------------
    # SECTION 5: FILE CREATION
    # ---------------------------------------------------------
    Write-Host "[5/8] Querying file creation events..." -ForegroundColor Magenta

    $fileQuery = @{
        query = @{ bool = @{ must = @(
            $timeFilter, $hostFilter,
            @{ term = @{ "event.category" = "file"     } },
            @{ term = @{ "event.type"     = "creation" } }
        ) } }
        aggs = @{
            by_name      = @{ terms = @{ field = "file.name";      size = 200 } }
            by_extension = @{ terms = @{ field = "file.extension"; size = 50  } }
            by_process   = @{ terms = @{ field = "process.name";   size = 100 } }
        }
    }

    $fileResp = Invoke-ESQuery -Index $eventsIndex -Body $fileQuery -Size 0
    $results['File Creation'] = @{
        Files      = if ($fileResp) { $fileResp.aggregations.by_name.buckets } else { @() }
        Extensions = if ($fileResp) { $fileResp.aggregations.by_extension.buckets } else { @() }
        Processes  = if ($fileResp) { $fileResp.aggregations.by_process.buckets } else { @() }
    }
    $fileCount = ($results['File Creation'].Files | Measure-Object).Count
    Write-Host "  $fileCount unique files created." -ForegroundColor Gray

    # ---------------------------------------------------------
    # SECTION 6: REGISTRY MODIFICATIONS
    # ---------------------------------------------------------
    Write-Host "[6/8] Querying registry modifications..." -ForegroundColor Magenta

    $regQuery = @{
        query = @{ bool = @{ must = @(
            $timeFilter, $hostFilter,
            @{ term  = @{ "event.category" = "registry" } },
            @{ terms = @{ "event.type"     = @("creation","change") } }
        ) } }
        aggs = @{
            by_key     = @{ terms = @{ field = "registry.key";   size = 200 } }
            by_process = @{ terms = @{ field = "process.name";   size = 100 } }
        }
    }

    $regResp = Invoke-ESQuery -Index $eventsIndex -Body $regQuery -Size 0
    $results['Registry Modifications'] = @{
        Keys      = if ($regResp) { $regResp.aggregations.by_key.buckets } else { @() }
        Processes = if ($regResp) { $regResp.aggregations.by_process.buckets } else { @() }
    }
    $regCount = ($results['Registry Modifications'].Keys | Measure-Object).Count
    Write-Host "  $regCount unique registry keys touched." -ForegroundColor Gray

    # ---------------------------------------------------------
    # SECTION 7: SCHEDULED TASKS
    # ---------------------------------------------------------
    Write-Host "[7/8] Querying scheduled tasks..." -ForegroundColor Magenta

    $taskQuery = @{
        query = @{ bool = @{ must = @(
            $timeFilter, $hostFilter,
            @{ term = @{ "event.category" = "process"      } },
            @{ term = @{ "process.name"   = "schtasks.exe" } }
        ) } }
        aggs = @{
            by_cmdline = @{ terms = @{ field = "process.command_line"; size = 100 } }
        }
    }

    $taskResp = Invoke-ESQuery -Index $eventsIndex -Body $taskQuery -Size 0
    $results['Scheduled Tasks'] = @{
        Commands = if ($taskResp) { $taskResp.aggregations.by_cmdline.buckets } else { @() }
    }
    $taskCount = ($results['Scheduled Tasks'].Commands | Measure-Object).Count
    Write-Host "  $taskCount scheduled task command(s)." -ForegroundColor Gray

    # ---------------------------------------------------------
    # SECTION 8: POWERSHELL COMMANDS
    # ---------------------------------------------------------
    Write-Host "[8/8] Querying PowerShell commands..." -ForegroundColor Magenta

    $psQuery = @{
        query = @{ bool = @{ must = @(
            $timeFilter, $hostFilter,
            @{ term  = @{ "event.category" = "process" } },
            @{ terms = @{ "process.name"   = @("powershell.exe","pwsh.exe") } }
        ) } }
        aggs = @{
            by_cmdline = @{ terms = @{ field = "process.command_line"; size = 200 } }
            by_parent  = @{ terms = @{ field = "process.parent.name";  size = 50  } }
        }
    }

    $psResp = Invoke-ESQuery -Index $eventsIndex -Body $psQuery -Size 0
    $results['PowerShell Commands'] = @{
        Commands = if ($psResp) { $psResp.aggregations.by_cmdline.buckets } else { @() }
        Parents  = if ($psResp) { $psResp.aggregations.by_parent.buckets } else { @() }
    }
    $psCount = ($results['PowerShell Commands'].Commands | Measure-Object).Count
    Write-Host "  $psCount unique PowerShell command line(s)." -ForegroundColor Gray

    # ---------------------------------------------------------
    # SECTION 9: HASH ENRICHMENT (VT offline baseline)
    # Collect all unique SHA256 hashes from alerts + process events,
    # look each up in output-baseline, and categorize as:
    #   known-good (SignedVerified/unsignedWin/etc.)
    #   known-malicious
    #   not in baseline
    # ---------------------------------------------------------
    Write-Host "[9/10] Cross-referencing hashes against VT offline baseline..." -ForegroundColor Magenta

    $allHashes = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    # Hashes from alert hits
    foreach ($hit in $alertHits) {
        $h = $hit._source.'process.hash.sha256'
        if ($h) { [void]$allHashes.Add($h) }
    }

    # Hashes from process creation aggregation
    foreach ($b in $results['Process Creation'].Hashes) {
        if ($b.key) { [void]$allHashes.Add($b.key) }
    }

    $knownGood      = [System.Collections.Generic.List[PSObject]]::new()
    $knownMalicious = [System.Collections.Generic.List[PSObject]]::new()
    $notInBaseline  = [System.Collections.Generic.List[string]]::new()

    foreach ($hash in $allHashes) {
        $vtResult = Find-VTHashBaseline -Hash $hash
        if (-not $vtResult) {
            $notInBaseline.Add($hash)
            continue
        }
        $main = Get-VTMainSummary -Path $vtResult.MainFile
        $beh  = Get-VTBehaviorSummary -Path $vtResult.BehaviorFile
        $entry = [PSCustomObject]@{
            Hash        = $hash
            Category    = $vtResult.Category
            Name        = if ($main) { $main.MeaningfulName } else { "" }
            Detections  = if ($main) { $main.DetectionRatio } else { "" }
            ThreatLabel = if ($main) { $main.ThreatLabel }    else { "" }
            Signer      = if ($main) { $main.Signer }         else { "" }
            FirstSeen   = if ($main) { $main.FirstSeen }      else { "" }
            MitreAttack = if ($beh)  { $beh.MitreAttack }     else { @() }
            ApiCalls    = if ($beh)  { $beh.ApiCalls }        else { @() }
            HighSigs    = if ($beh)  { $beh.HighSigs }        else { @() }
        }
        if ($vtResult.Category -eq 'malicious') {
            $knownMalicious.Add($entry)
        } else {
            $knownGood.Add($entry)
        }
    }

    $results['HashEnrichment'] = @{
        KnownGood      = $knownGood
        KnownMalicious = $knownMalicious
        NotInBaseline  = $notInBaseline
    }

    Write-Host "  $($knownMalicious.Count) known-malicious  |  $($knownGood.Count) known-good  |  $($notInBaseline.Count) not in baseline" -ForegroundColor $(if ($knownMalicious.Count -gt 0) { 'Red' } else { 'Gray' })

    # ---------------------------------------------------------
    # SECTION 10: API CALL HUNTING (Elastic endpoint telemetry)
    # Elastic endpoint agent logs API-level behavioral events
    # under process.Ext.api.name - query for any in the window
    # that have known high-fidelity malicious API signatures.
    # Falls back to memory threat / behavior protection events
    # if API call logging is not enabled.
    # ---------------------------------------------------------
    Write-Host "[10/10] Hunting for API-level behavioral events..." -ForegroundColor Magenta

    $apiQuery = @{
        query = @{ bool = @{ must = @(
            $timeFilter, $hostFilter
        )
        filter = @(
            @{ exists = @{ field = "process.Ext.api.name" } }
        ) } }
        aggs = @{
            by_api     = @{ terms = @{ field = "process.Ext.api.name";       size = 200 } }
            by_process = @{ terms = @{ field = "process.name";                size = 100 } }
        }
    }

    $apiResp = Invoke-ESQuery -Index "logs-endpoint.events.process-*,logs-endpoint.alerts-*" -Body $apiQuery -Size 0

    # Also query for memory threat / behavior protection events
    $memQuery = @{
        query = @{ bool = @{ must = @(
            $timeFilter, $hostFilter,
            @{ terms = @{ "event.action" = @("memory_threat","api_call","behavior","ransomware","shellcode") } }
        ) } }
        aggs = @{
            by_action  = @{ terms = @{ field = "event.action";  size = 50  } }
            by_process = @{ terms = @{ field = "process.name";  size = 100 } }
            by_rule    = @{ terms = @{ field = "rule.name";     size = 100 } }
        }
    }

    $memResp = Invoke-ESQuery -Index "logs-endpoint.alerts-*,logs-endpoint.events.process-*" -Body $memQuery -Size 0

    $results['API Hunting'] = @{
        ApiCalls      = if ($apiResp) { $apiResp.aggregations.by_api.buckets }      else { @() }
        ApiProcesses  = if ($apiResp) { $apiResp.aggregations.by_process.buckets }  else { @() }
        MemActions    = if ($memResp) { $memResp.aggregations.by_action.buckets }   else { @() }
        MemProcesses  = if ($memResp) { $memResp.aggregations.by_process.buckets }  else { @() }
        MemRules      = if ($memResp) { $memResp.aggregations.by_rule.buckets }     else { @() }
    }

    $apiCount = ($results['API Hunting'].ApiCalls | Measure-Object).Count
    $memCount = ($results['API Hunting'].MemActions | Measure-Object).Count
    Write-Host "  $apiCount unique API calls logged  |  $memCount memory/behavior action types." -ForegroundColor Gray

    # ---------------------------------------------------------
    # OUTPUT
    # ---------------------------------------------------------
    Write-Host "`n==========================================" -ForegroundColor DarkCyan
    Write-Host "  FORENSIC ANALYSIS RESULTS"
    Write-Host "  Host:   $hostName"
    Write-Host "  Window: $fromTime --> $toTime"
    Write-Host "==========================================" -ForegroundColor DarkCyan

    # -- Alerts --
    Write-Host "`n--- SECURITY ALERTS ($($alertHits.Count) total) ---" -ForegroundColor $(if ($alertHits.Count -gt 0) { 'Red' } else { 'Cyan' })
    if ($alertHits.Count -eq 0) {
        Write-Host "  No alerts in this window." -ForegroundColor Gray
    } else {
        $fidelityColors = @{ Super = 'Green'; New = 'Cyan'; Exceptions = 'Yellow'; Noisy = 'Red' }
        foreach ($cat in @('Super','New','Exceptions','Noisy')) {
            if ($fidelity[$cat].Count -gt 0) {
                Write-Host "  [$cat]" -ForegroundColor $fidelityColors[$cat]
                $fidelity[$cat] | ForEach-Object { Write-Host "    - $_" -ForegroundColor $fidelityColors[$cat] }
            }
        }
        Write-Host "`n  Top rules fired:"
        $results['Alerts'].RuleCounts | Select-Object -First 10 | ForEach-Object {
            Write-Host "    ($($_.doc_count)x) $($_.key)"
        }
        if ($results['Alerts'].Techniques.Count -gt 0) {
            Write-Host "`n  MITRE Techniques: $($results['Alerts'].Techniques.key -join ', ')" -ForegroundColor DarkYellow
        }
    }

    # -- Process Creation --
    Write-Host "`n--- PROCESS CREATION ($procCount unique) ---" -ForegroundColor DarkCyan
    $results['Process Creation'].UniqueProcesses | Select-Object -First 15 | ForEach-Object {
        Write-Host "  ($($_.doc_count)x) $($_.key)"
    }

    # -- Network --
    Write-Host "`n--- EXTERNAL NETWORK CONNECTIONS ($netCount unique IPs) ---" -ForegroundColor DarkCyan
    $results['Network Connections'].DestinationIPs | Select-Object -First 15 | ForEach-Object {
        Write-Host "  ($($_.doc_count)x) $($_.key)"
    }
    if ($results['Network Connections'].DestinationPorts.Count -gt 0) {
        $ports = ($results['Network Connections'].DestinationPorts | Select-Object -First 10).key -join ', '
        Write-Host "  Ports: $ports" -ForegroundColor DarkGray
    }

    # -- DNS --
    Write-Host "`n--- DNS REQUESTS ($dnsCount unique domains) ---" -ForegroundColor DarkCyan
    $results['DNS Requests'].Domains | Select-Object -First 15 | ForEach-Object {
        Write-Host "  ($($_.doc_count)x) $($_.key)"
    }

    # -- File Creation --
    Write-Host "`n--- FILE CREATION ($fileCount unique files) ---" -ForegroundColor DarkCyan
    $results['File Creation'].Files | Select-Object -First 10 | ForEach-Object {
        Write-Host "  ($($_.doc_count)x) $($_.key)"
    }

    # -- Registry --
    Write-Host "`n--- REGISTRY MODIFICATIONS ($regCount unique keys) ---" -ForegroundColor DarkCyan
    $results['Registry Modifications'].Keys | Select-Object -First 10 | ForEach-Object {
        Write-Host "  ($($_.doc_count)x) $($_.key)"
    }

    # -- Scheduled Tasks --
    if ($taskCount -gt 0) {
        Write-Host "`n--- SCHEDULED TASKS ($taskCount) ---" -ForegroundColor Yellow
        $results['Scheduled Tasks'].Commands | ForEach-Object {
            Write-Host "  [!] $($_.key)" -ForegroundColor Yellow
        }
    }

    # -- PowerShell --
    if ($psCount -gt 0) {
        Write-Host "`n--- POWERSHELL COMMANDS ($psCount) ---" -ForegroundColor Yellow
        $results['PowerShell Commands'].Commands | Select-Object -First 10 | ForEach-Object {
            Write-Host "  $($_.key)"
        }
    }

    # -- Hash Enrichment --
    Write-Host "`n--- HASH ENRICHMENT (VT Offline Baseline) ---" -ForegroundColor DarkCyan

    if ($knownMalicious.Count -gt 0) {
        Write-Host "`n  [!] KNOWN MALICIOUS ($($knownMalicious.Count))" -ForegroundColor Red
        foreach ($e in $knownMalicious) {
            Write-Host "  $($e.Hash.Substring(0,16))...  $($e.Name)  [$($e.ThreatLabel)]  $($e.Detections)" -ForegroundColor Red
            if ($e.MitreAttack.Count -gt 0) {
                Write-Host "    MITRE: $($e.MitreAttack -join ' | ')" -ForegroundColor DarkRed
            }
            if ($e.ApiCalls.Count -gt 0) {
                Write-Host "    VT API calls: $($e.ApiCalls -join ', ')" -ForegroundColor DarkRed
            }
            if ($e.HighSigs.Count -gt 0) {
                Write-Host "    Behaviors: $($e.HighSigs -join ' | ')" -ForegroundColor DarkRed
            }
        }
    }

    if ($knownGood.Count -gt 0) {
        Write-Host "`n  Known-good ($($knownGood.Count) hashes across categories):" -ForegroundColor Green
        $knownGood | Group-Object Category | ForEach-Object {
            Write-Host "    $($_.Name): $($_.Count) hash(es)" -ForegroundColor DarkGreen
        }
    }

    if ($notInBaseline.Count -gt 0) {
        Write-Host "`n  Not in offline baseline ($($notInBaseline.Count) hashes - consider submitting to VT):" -ForegroundColor Yellow
        $notInBaseline | Select-Object -First 10 | ForEach-Object {
            Write-Host "    $_" -ForegroundColor DarkYellow
        }
    }

    # -- API Hunting --
    if ($apiCount -gt 0 -or $memCount -gt 0) {
        Write-Host "`n--- API / BEHAVIORAL EVENT HUNTING ---" -ForegroundColor DarkCyan

        if ($apiCount -gt 0) {
            Write-Host "`n  Elastic endpoint API calls logged ($apiCount unique):" -ForegroundColor Yellow
            $results['API Hunting'].ApiCalls | Select-Object -First 20 | ForEach-Object {
                Write-Host "  ($($_.doc_count)x) $($_.key)"
            }
        }

        if ($memCount -gt 0) {
            Write-Host "`n  Memory/behavior protection events:" -ForegroundColor Yellow
            $results['API Hunting'].MemActions | ForEach-Object {
                Write-Host "  [!] $($_.key)  ($($_.doc_count) events)" -ForegroundColor Red
            }
            if ($results['API Hunting'].MemRules.Count -gt 0) {
                Write-Host "`n  Rules triggered:" -ForegroundColor Yellow
                $results['API Hunting'].MemRules | Select-Object -First 10 | ForEach-Object {
                    Write-Host "    $($_.key)" -ForegroundColor Red
                }
            }
        }
    } else {
        Write-Host "`n--- API / BEHAVIORAL EVENT HUNTING ---" -ForegroundColor DarkCyan
        Write-Host "  No API call or memory protection events found." -ForegroundColor Gray
        Write-Host "  (Requires Elastic endpoint agent with API monitoring / memory threat protection enabled)" -ForegroundColor DarkGray
    }

    Write-Host "`n==========================================" -ForegroundColor DarkCyan
    Write-Host "  Analysis complete." -ForegroundColor Green
    Write-Host "==========================================" -ForegroundColor DarkCyan

    # Save full results
    $outPath = "output\ElasticForensics_${hostName}_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $results | ConvertTo-Json -Depth 8 | Set-Content -Path $outPath
    Write-Host "Full results saved to: $outPath" -ForegroundColor Green
}

Export-ModuleMember -Function Get-ElasticAlertsAndThreats
