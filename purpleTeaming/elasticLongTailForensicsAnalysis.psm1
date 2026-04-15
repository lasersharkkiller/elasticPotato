function Get-ElasticForensicLongTailAnalysis {
    <#
    .SYNOPSIS
        Performs long tail forensic analysis against Elastic/ECS telemetry,
        mirroring the SentinelOne Get-ForensicLongTailAnalysis workflow.

        For each artifact category, finds what occurred on the target host
        then cross-references against the enterprise to surface only items
        seen on fewer than $RarityThreshold unique hosts - the rare/anomalous
        signal used for threat hunting and incident response.

    .PARAMETER RarityThreshold
        Maximum number of unique hosts an artifact can appear on enterprise-wide
        and still be considered rare. Default: 50 (matches S1 version).
    #>

    param(
        [int]$RarityThreshold = 50,
        [int]$ContextSampleLimit = 2,
        [int]$MaxContextValuesPerCategory = 20
    )

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

    # Auto-upgrade http:// to https:// if ES 8.x is running HTTPS (self-signed cert)
    if ($esUrl -match '^http://') {
        $httpsUrl = $esUrl -replace '^http://', 'https://'
        try {
            [void](Invoke-RestMethod -Uri "$httpsUrl/_cluster/health" -Headers $headers -Method Get @restArgs -ErrorAction Stop)
            Write-Host "  [INFO] Auto-upgraded URL to https:// (ES 8.x HTTPS detected)" -ForegroundColor DarkCyan
            $esUrl = $httpsUrl
        } catch {}
    }

    $eventsIndex  = "logs-*,winlogbeat-*,filebeat-*,endgame-*"
    $outputPath         = "output\LongTailAnalysisResults.json"
    $enrichedOutputPath = "output\LongTailAnalysisResults_Enriched.json"

    # --- INPUT ---
    $hostName = Read-Host "Enter the Endpoint Name"
    if ($hostName -eq "") { $hostName = $env:COMPUTERNAME }

    $s = Read-Host "Enter date or leave blank for today (Ex: 2025-02-25 or 2025-02-25 02:25:25)"
    if ($s) {
        try   { $result = Get-Date $s }
        catch { Write-Host "Invalid date, using today."; $result = Get-Date }
    } else {
        $result = Get-Date
    }

    $currentTime  = $result.AddDays(+1).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $lastDayTime  = $result.AddDays(-1).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

    Write-Host "`nTarget:    $hostName" -ForegroundColor DarkCyan
    Write-Host "Timeframe: $lastDayTime to $currentTime" -ForegroundColor DarkCyan
    Write-Host "Rarity threshold: fewer than $RarityThreshold unique hosts" -ForegroundColor DarkCyan

    if (-not (Test-Path "output")) { New-Item -Path "output" -ItemType Directory | Out-Null }

    # ---------------------------------------------------------
    # HELPER: Invoke-ESQuery
    # ---------------------------------------------------------
    function Invoke-ESQuery {
        param([string]$Index, [hashtable]$Body, [int]$Size = 0)
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

    # ---------------------------------------------------------
    # HELPER: Get-EcsField
    # Dot-path lookup that supports literal dotted ECS keys and
    # nested object traversal on deserialized JSON documents.
    # ---------------------------------------------------------
    function Get-EcsField {
        param($Obj, [string]$Path)
        if ($null -eq $Obj -or [string]::IsNullOrWhiteSpace($Path)) { return $null }

        try {
            $flat = $Obj.PSObject.Properties[$Path]
            if ($null -ne $flat) { return $flat.Value }
        } catch {}

        $cur = $Obj
        foreach ($seg in ($Path -split '\.')) {
            if ($null -eq $cur) { return $null }
            try {
                $prop = $cur.PSObject.Properties[$seg]
                if ($null -eq $prop) { return $null }
                $cur = $prop.Value
            } catch {
                return $null
            }
        }
        return $cur
    }

    function To-ShortText {
        param($v, [int]$MaxLen = 120)
        if ($null -eq $v) { return '' }
        if ($v -is [System.Array]) { $v = ($v -join ', ') }
        $s = "$v"
        if ($s.Length -gt $MaxLen) { return $s.Substring(0, $MaxLen) + '...' }
        return $s
    }

    function Format-ForensicContextLine {
        param($Src)

        $ts      = To-ShortText (Get-EcsField $Src '@timestamp') 32
        $evCat   = To-ShortText (Get-EcsField $Src 'event.category') 24
        $evAct   = To-ShortText (Get-EcsField $Src 'event.action') 40
        $evType  = To-ShortText (Get-EcsField $Src 'event.type') 30

        $pName   = To-ShortText (Get-EcsField $Src 'process.name') 40
        $pExe    = To-ShortText (Get-EcsField $Src 'process.executable') 100
        $pCmd    = To-ShortText (Get-EcsField $Src 'process.command_line') 180
        $pParent = To-ShortText (Get-EcsField $Src 'process.parent.name') 40
        $pUser   = To-ShortText (Get-EcsField $Src 'process.user.name') 40
        if (-not $pUser) { $pUser = To-ShortText (Get-EcsField $Src 'user.name') 40 }
        $pHash   = To-ShortText (Get-EcsField $Src 'process.hash.sha256') 70

        $sigSubj = To-ShortText (Get-EcsField $Src 'process.code_signature.subject_name') 80
        $sigTr   = To-ShortText (Get-EcsField $Src 'process.code_signature.trusted') 10
        $integ   = To-ShortText (Get-EcsField $Src 'process.Ext.token.integrity_level_name') 25
        $apiN    = To-ShortText (Get-EcsField $Src 'process.Ext.api.name') 40
        $apiB    = To-ShortText (Get-EcsField $Src 'process.Ext.api.behaviors') 60

        $dIp     = To-ShortText (Get-EcsField $Src 'destination.ip') 45
        $dPort   = To-ShortText (Get-EcsField $Src 'destination.port') 10
        $dnsQ    = To-ShortText (Get-EcsField $Src 'dns.question.name') 80
        $urlDom  = To-ShortText (Get-EcsField $Src 'url.domain') 60

        $fPath   = To-ShortText (Get-EcsField $Src 'file.path') 100
        if (-not $fPath) { $fPath = To-ShortText (Get-EcsField $Src 'file.name') 60 }
        $fHash   = To-ShortText (Get-EcsField $Src 'file.hash.sha256') 70
        $fEnt    = To-ShortText (Get-EcsField $Src 'file.Ext.entropy') 12

        $rKey    = To-ShortText (Get-EcsField $Src 'registry.key') 100
        $rVal    = To-ShortText (Get-EcsField $Src 'registry.value') 60
        $rData   = To-ShortText (Get-EcsField $Src 'registry.data.strings') 100

        $parts = [System.Collections.Generic.List[string]]::new()
        if ($ts)                { [void]$parts.Add("ts=$ts") }
        if ($evCat -or $evAct)  { [void]$parts.Add("event=$evCat/$evAct/$evType") }
        if ($pName)             { [void]$parts.Add("proc=$pName") }
        if ($pParent)           { [void]$parts.Add("parent=$pParent") }
        if ($pUser)             { [void]$parts.Add("user=$pUser") }
        if ($pCmd)              { [void]$parts.Add("cmd=$pCmd") }
        if ($pExe)              { [void]$parts.Add("exe=$pExe") }
        if ($pHash)             { [void]$parts.Add("sha256=$pHash") }
        if ($sigSubj -or $sigTr){ [void]$parts.Add("sig=$sigSubj trusted=$sigTr") }
        if ($integ)             { [void]$parts.Add("integrity=$integ") }
        if ($apiN -or $apiB)    { [void]$parts.Add("api=$apiN beh=$apiB") }
        if ($dIp -or $dPort)    { [void]$parts.Add("net=$($dIp):$($dPort)") }
        if ($dnsQ)              { [void]$parts.Add("dns=$dnsQ") }
        if ($urlDom)            { [void]$parts.Add("url=$urlDom") }
        if ($fPath)             { [void]$parts.Add("file=$fPath") }
        if ($fHash)             { [void]$parts.Add("file_sha256=$fHash") }
        if ($fEnt)              { [void]$parts.Add("entropy=$fEnt") }
        if ($rKey)              { [void]$parts.Add("reg=$rKey") }
        if ($rVal)              { [void]$parts.Add("reg_val=$rVal") }
        if ($rData)             { [void]$parts.Add("reg_data=$rData") }

        return ($parts -join " | ")
    }

    # ---------------------------------------------------------
    # HELPER: Get-ArtifactContextMap
    # Pulls forensic context docs for rare values on the target host.
    # ---------------------------------------------------------
    function Get-ArtifactContextMap {
        param(
            [hashtable]$HostFilter,
            [string]$AggField,
            [object[]]$ArtifactValues
        )

        $ctxMap = @{}
        $normalizedValues = @($ArtifactValues | ForEach-Object { "$_" } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
        foreach ($v in $normalizedValues) {
            $ctxMap[$v] = [System.Collections.Generic.List[string]]::new()
        }
        if ($normalizedValues.Count -eq 0) { return $ctxMap }

        $termsObj = @{}
        $termsObj[$AggField] = @($normalizedValues)

        $ctxQuery = @{
            query = @{
                bool = @{
                    must = @(
                        @{ range = @{ "@timestamp" = @{ gte = $lastDayTime; lte = $currentTime } } },
                        @{ term  = @{ "host.name" = $hostName } },
                        @{ terms = $termsObj }
                    ) + @($HostFilter)
                }
            }
            _source = @(
                '@timestamp','host.name','host.os.name',
                'event.category','event.type','event.action',
                'process.name','process.executable','process.command_line','process.parent.name',
                'process.user.name','user.name',
                'process.hash.sha256',
                'process.code_signature.trusted','process.code_signature.subject_name',
                'process.Ext.token.integrity_level_name',
                'process.Ext.api.name','process.Ext.api.behaviors',
                'destination.ip','destination.port','dns.question.name','url.domain',
                'file.name','file.path','file.hash.sha256','file.Ext.entropy',
                'registry.key','registry.value','registry.data.strings'
            )
            sort = @(@{ '@timestamp' = 'desc' })
        }

        $ctxResp = Invoke-ESQuery -Index $eventsIndex -Body $ctxQuery -Size 800
        if (-not $ctxResp -or -not $ctxResp.hits -or -not $ctxResp.hits.hits) { return $ctxMap }

        foreach ($hit in @($ctxResp.hits.hits)) {
            $src = $hit._source
            if ($null -eq $src) { continue }

            $rawVal = Get-EcsField -Obj $src -Path $AggField
            $vals = if ($rawVal -is [System.Array]) { @($rawVal | ForEach-Object { "$_" }) } else { @("$rawVal") }
            $ctxLine = Format-ForensicContextLine -Src $src

            foreach ($v in $vals) {
                if ([string]::IsNullOrWhiteSpace($v)) { continue }
                if (-not $ctxMap.ContainsKey($v)) { continue }
                if ($ctxMap[$v].Count -ge $ContextSampleLimit) { continue }
                $ctxMap[$v].Add($ctxLine)
            }
        }
        return $ctxMap
    }

    # ---------------------------------------------------------
    # HELPER: Get-RareArtifacts
    #
    # Two-phase approach mirroring the S1 join logic:
    #   Phase A - get the set of values seen on the target host
    #   Phase B - for each of those values, count unique hosts
    #             enterprise-wide; keep only those below threshold
    #
    # Returns array of [artifactValue, enterpriseHostCount] pairs.
    # ---------------------------------------------------------
    function Get-RareArtifacts {
        param(
            [string]$Category,
            [hashtable]$HostFilter,       # must clause to scope to event type on host
            [hashtable]$EnterpriseFilter, # must clause to scope to event type enterprise-wide
            [string]$AggField             # ECS field to aggregate on
        )

        # Phase A: values seen on alert host in the alert window
        $hostQuery = @{
            query = @{
                bool = @{
                    must = @(
                        @{ range = @{ "@timestamp" = @{ gte = $lastDayTime; lte = $currentTime } } },
                        @{ term  = @{ "host.name" = $hostName } }
                    ) + @($HostFilter)
                }
            }
            aggs = @{
                host_values = @{
                    terms = @{ field = $AggField; size = 1000; min_doc_count = 1 }
                }
            }
        }

        $hostResp = Invoke-ESQuery -Index $eventsIndex -Body $hostQuery
        if (-not $hostResp) { return @() }
        $hostValues = $hostResp.aggregations.host_values.buckets | ForEach-Object { $_.key }
        if ($hostValues.Count -eq 0) { return @() }

        # Phase B: for each host value, get enterprise-wide unique host count
        # Use a terms agg with a bucket_selector to filter below threshold
        $enterpriseQuery = @{
            query = @{
                bool = @{
                    must = @(
                        @{ range = @{ "@timestamp" = @{ gte = $lastDayTime; lte = $currentTime } } },
                        @{ terms = @{ $AggField = @($hostValues) } }
                    ) + @($EnterpriseFilter)
                }
            }
            aggs = @{
                artifacts = @{
                    terms = @{ field = $AggField; size = 1000; min_doc_count = 1 }
                    aggs  = @{
                        unique_hosts = @{
                            cardinality = @{ field = "host.name" }
                        }
                        rare_filter = @{
                            bucket_selector = @{
                                buckets_path = @{ hostCount = "unique_hosts" }
                                script       = "params.hostCount < $RarityThreshold"
                            }
                        }
                    }
                }
            }
        }

        $entResp = Invoke-ESQuery -Index $eventsIndex -Body $enterpriseQuery
        if (-not $entResp) { return @() }

        $results = @()
        foreach ($bucket in $entResp.aggregations.artifacts.buckets) {
            $results += ,@($bucket.key, $bucket.unique_hosts.value)
        }
        # Sort ascending by host count (rarest first)
        return $results | Sort-Object { $_[1] }
    }

    # ---------------------------------------------------------
    # ARTIFACT DEFINITIONS
    # Each entry mirrors a query in the S1 version.
    # HostFilter    = event type scope for the target host
    # EnterpriseFilter = event type scope enterprise-wide
    # AggField      = ECS field equivalent to S1 column
    # ---------------------------------------------------------
    $artifacts = [ordered]@{

        "Behavioral Indicators" = @{
            HostFilter       = @{ term = @{ "event.category" = "intrusion_detection" } }
            EnterpriseFilter = @{ term = @{ "event.category" = "intrusion_detection" } }
            AggField         = "rule.name"
        }

        "Driver Loads" = @{
            HostFilter       = @{ bool = @{ must = @(@{ term = @{ "event.category" = "driver" } }, @{ term = @{ "event.action" = "load" } }) } }
            EnterpriseFilter = @{ bool = @{ must = @(@{ term = @{ "event.category" = "driver" } }, @{ term = @{ "event.action" = "load" } }) } }
            AggField         = "file.path"
        }

        "Remote Process Handle" = @{
            HostFilter       = @{ bool = @{ must = @(@{ term = @{ "event.category" = "process" } }, @{ term = @{ "event.action" = "access" } }) } }
            EnterpriseFilter = @{ bool = @{ must = @(@{ term = @{ "event.category" = "process" } }, @{ term = @{ "event.action" = "access" } }) } }
            AggField         = "process.command_line"
        }

        "Remote/Duplicate Threads" = @{
            HostFilter       = @{ bool = @{ must = @(@{ term = @{ "event.category" = "process" } }, @{ terms = @{ "event.action" = @("remote_thread","create_remote_thread") } }) } }
            EnterpriseFilter = @{ bool = @{ must = @(@{ term = @{ "event.category" = "process" } }, @{ terms = @{ "event.action" = @("remote_thread","create_remote_thread") } }) } }
            AggField         = "process.command_line"
        }

        "Process Creation" = @{
            HostFilter       = @{ bool = @{ must = @(@{ term = @{ "event.category" = "process" } }, @{ term = @{ "event.type" = "start" } }) } }
            EnterpriseFilter = @{ bool = @{ must = @(@{ term = @{ "event.category" = "process" } }, @{ term = @{ "event.type" = "start" } }) } }
            AggField         = "process.name"
        }

        "Process Executable Path" = @{
            HostFilter       = @{ bool = @{ must = @(@{ term = @{ "event.category" = "process" } }, @{ term = @{ "event.type" = "start" } }) } }
            EnterpriseFilter = @{ bool = @{ must = @(@{ term = @{ "event.category" = "process" } }, @{ term = @{ "event.type" = "start" } }) } }
            AggField         = "process.executable"
        }

        "Process Command Line (All)" = @{
            HostFilter       = @{ bool = @{ must = @(@{ term = @{ "event.category" = "process" } }, @{ term = @{ "event.type" = "start" } }) } }
            EnterpriseFilter = @{ bool = @{ must = @(@{ term = @{ "event.category" = "process" } }, @{ term = @{ "event.type" = "start" } }) } }
            AggField         = "process.command_line"
        }

        "Process SHA256" = @{
            HostFilter       = @{ bool = @{ must = @(@{ term = @{ "event.category" = "process" } }, @{ term = @{ "event.type" = "start" } }) } }
            EnterpriseFilter = @{ bool = @{ must = @(@{ term = @{ "event.category" = "process" } }, @{ term = @{ "event.type" = "start" } }) } }
            AggField         = "process.hash.sha256"
        }

        "Parent Process Names" = @{
            HostFilter       = @{ bool = @{ must = @(@{ term = @{ "event.category" = "process" } }, @{ term = @{ "event.type" = "start" } }) } }
            EnterpriseFilter = @{ bool = @{ must = @(@{ term = @{ "event.category" = "process" } }, @{ term = @{ "event.type" = "start" } }) } }
            AggField         = "process.parent.name"
        }

        "Process Users" = @{
            HostFilter       = @{ bool = @{ must = @(@{ term = @{ "event.category" = "process" } }, @{ term = @{ "event.type" = "start" } }) } }
            EnterpriseFilter = @{ bool = @{ must = @(@{ term = @{ "event.category" = "process" } }, @{ term = @{ "event.type" = "start" } }) } }
            AggField         = "process.user.name"
        }

        "Code Signer Subject" = @{
            HostFilter       = @{ bool = @{ must = @(@{ term = @{ "event.category" = "process" } }, @{ term = @{ "event.type" = "start" } }) } }
            EnterpriseFilter = @{ bool = @{ must = @(@{ term = @{ "event.category" = "process" } }, @{ term = @{ "event.type" = "start" } }) } }
            AggField         = "process.code_signature.subject_name"
        }

        "Integrity Levels" = @{
            HostFilter       = @{ bool = @{ must = @(@{ term = @{ "event.category" = "process" } }, @{ term = @{ "event.type" = "start" } }) } }
            EnterpriseFilter = @{ bool = @{ must = @(@{ term = @{ "event.category" = "process" } }, @{ term = @{ "event.type" = "start" } }) } }
            AggField         = "process.Ext.token.integrity_level_name"
        }

        "API Behaviors" = @{
            HostFilter       = @{ bool = @{ must = @(@{ bool = @{ should = @(@{ term = @{ "event.category" = "api" } }, @{ term = @{ "event.dataset" = "endpoint.events.api" } }); minimum_should_match = 1 } }) } }
            EnterpriseFilter = @{ bool = @{ must = @(@{ bool = @{ should = @(@{ term = @{ "event.category" = "api" } }, @{ term = @{ "event.dataset" = "endpoint.events.api" } }); minimum_should_match = 1 } }) } }
            AggField         = "process.Ext.api.behaviors"
        }

        "API Names" = @{
            HostFilter       = @{ bool = @{ must = @(@{ bool = @{ should = @(@{ term = @{ "event.category" = "api" } }, @{ term = @{ "event.dataset" = "endpoint.events.api" } }); minimum_should_match = 1 } }) } }
            EnterpriseFilter = @{ bool = @{ must = @(@{ bool = @{ should = @(@{ term = @{ "event.category" = "api" } }, @{ term = @{ "event.dataset" = "endpoint.events.api" } }); minimum_should_match = 1 } }) } }
            AggField         = "process.Ext.api.name"
        }

        "All Shell/CLI Commands (Windows+Linux)" = @{
            HostFilter       = @{ bool = @{ must = @(@{ term = @{ "event.category" = "process" } }, @{ terms = @{ "process.name" = @(
                "cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","wmic.exe",
                "bash","sh","dash","zsh","ksh","mksh","pdksh","yash","ash","hush","fish","busybox","toybox","buyobu","tmux","screen"
            ) } }) } }
            EnterpriseFilter = @{ bool = @{ must = @(@{ term = @{ "event.category" = "process" } }, @{ terms = @{ "process.name" = @(
                "cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","wmic.exe",
                "bash","sh","dash","zsh","ksh","mksh","pdksh","yash","ash","hush","fish","busybox","toybox","buyobu","tmux","screen"
            ) } }) } }
            AggField         = "process.command_line"
        }

        "File Creation" = @{
            HostFilter       = @{ bool = @{ must = @(@{ term = @{ "event.category" = "file" } }, @{ term = @{ "event.type" = "creation" } }) } }
            EnterpriseFilter = @{ bool = @{ must = @(@{ term = @{ "event.category" = "file" } }, @{ term = @{ "event.type" = "creation" } }) } }
            AggField         = "file.name"
        }

        "Network Connections (IP)" = @{
            HostFilter       = @{ bool = @{ must = @(@{ term = @{ "event.category" = "network" } }, @{ terms = @{ "event.type" = @("connection","start") } }) } }
            EnterpriseFilter = @{ bool = @{ must = @(@{ term = @{ "event.category" = "network" } }, @{ terms = @{ "event.type" = @("connection","start") } }) } }
            AggField         = "destination.ip"
        }

        "DNS Requests" = @{
            HostFilter       = @{ bool = @{ must = @(@{ term = @{ "event.category" = "network" } }, @{ term = @{ "event.action" = "lookup_requested" } }) } }
            EnterpriseFilter = @{ bool = @{ must = @(@{ term = @{ "event.category" = "network" } }, @{ term = @{ "event.action" = "lookup_requested" } }) } }
            AggField         = "dns.question.name"
        }

        "HTTP Requests" = @{
            HostFilter       = @{ bool = @{ must = @(@{ term = @{ "event.category" = "network" } }, @{ term = @{ "network.protocol" = "http" } }) } }
            EnterpriseFilter = @{ bool = @{ must = @(@{ term = @{ "event.category" = "network" } }, @{ term = @{ "network.protocol" = "http" } }) } }
            AggField         = "url.domain"
        }

        "Registry Modifications" = @{
            HostFilter       = @{ bool = @{ must = @(@{ term = @{ "event.category" = "registry" } }, @{ terms = @{ "event.type" = @("creation","change") } }) } }
            EnterpriseFilter = @{ bool = @{ must = @(@{ term = @{ "event.category" = "registry" } }, @{ terms = @{ "event.type" = @("creation","change") } }) } }
            AggField         = "registry.key"
        }

        "Scheduled Tasks" = @{
            HostFilter       = @{ bool = @{ must = @(@{ term = @{ "event.category" = "process" } }, @{ term = @{ "process.name" = "schtasks.exe" } }) } }
            EnterpriseFilter = @{ bool = @{ must = @(@{ term = @{ "event.category" = "process" } }, @{ term = @{ "process.name" = "schtasks.exe" } }) } }
            AggField         = "process.command_line"
        }

        "Logon Events" = @{
            HostFilter       = @{ bool = @{ must = @(@{ term = @{ "event.category" = "authentication" } }, @{ term = @{ "event.type" = "start" } }) } }
            EnterpriseFilter = @{ bool = @{ must = @(@{ term = @{ "event.category" = "authentication" } }, @{ term = @{ "event.type" = "start" } }) } }
            AggField         = "process.name"
        }

        "PowerShell Commands" = @{
            HostFilter       = @{ bool = @{ must = @(@{ term = @{ "event.category" = "process" } }, @{ terms = @{ "process.name" = @("powershell.exe","pwsh.exe") } }) } }
            EnterpriseFilter = @{ bool = @{ must = @(@{ term = @{ "event.category" = "process" } }, @{ terms = @{ "process.name" = @("powershell.exe","pwsh.exe") } }) } }
            AggField         = "process.command_line"
        }
    }

    # ---------------------------------------------------------
    # EXECUTION LOOP
    # ---------------------------------------------------------
    $globalResults     = [ordered]@{}
    $enrichedResults   = [ordered]@{}
    $total             = $artifacts.Count
    $currentIdx        = 0

    Write-Host "`n--- Starting Long Tail Analysis ($total artifact types) ---`n" -ForegroundColor Yellow

    foreach ($key in $artifacts.Keys) {
        $currentIdx++
        $def = $artifacts[$key]

        Write-Host "[$currentIdx/$total] Analyzing: $key" -ForegroundColor Magenta

        $rare = Get-RareArtifacts `
            -Category        $key `
            -HostFilter      $def.HostFilter `
            -EnterpriseFilter $def.EnterpriseFilter `
            -AggField        $def.AggField

        if ($rare.Count -gt 0) {
            Write-Host "  > Found $($rare.Count) rare artifact(s)." -ForegroundColor Green
            Write-Host "    Top findings:" -ForegroundColor Gray
            $rare | Select-Object -First 3 | ForEach-Object {
                Write-Host "    - ($($_[1]) hosts) $($_[0])"
            }
            $globalResults[$key] = $rare

            $ctxValues = @($rare | Select-Object -First $MaxContextValuesPerCategory | ForEach-Object { "$($_[0])" })
            $ctxMap = Get-ArtifactContextMap -HostFilter $def.HostFilter -AggField $def.AggField -ArtifactValues $ctxValues
            $enrichedRows = @()
            foreach ($row in $rare) {
                $val = "$($row[0])"
                $samples = if ($ctxMap.ContainsKey($val)) { @($ctxMap[$val]) } else { @() }
                $enrichedRows += [PSCustomObject]@{
                    ArtifactValue        = $val
                    EnterpriseHostCount  = [int]$row[1]
                    ForensicContext      = @($samples)
                }
            }
            $enrichedResults[$key] = $enrichedRows

            if ($enrichedRows.Count -gt 0) {
                $topWithCtx = $enrichedRows | Where-Object { $_.ForensicContext.Count -gt 0 } | Select-Object -First 2
                foreach ($r in $topWithCtx) {
                    Write-Host ("      context: {0}" -f (To-ShortText ($r.ForensicContext[0]) 260)) -ForegroundColor DarkGray
                }
            }
        } else {
            Write-Host "  > No rare artifacts found (all seen on $RarityThreshold+ hosts, or no events)." -ForegroundColor Gray
            $globalResults[$key] = @()
            $enrichedResults[$key] = @()
        }
    }

    # ---------------------------------------------------------
    # OUTPUT
    # ---------------------------------------------------------
    Write-Host "`n--- Analysis Complete ---" -ForegroundColor Yellow

    $globalResults | ConvertTo-Json -Depth 6 | Set-Content -Path $outputPath

    $enrichedEnvelope = [ordered]@{
        Meta = [ordered]@{
            HostName                     = $hostName
            TimeframeUtcStart            = $lastDayTime
            TimeframeUtcEnd              = $currentTime
            RarityThreshold              = $RarityThreshold
            ContextSampleLimit           = $ContextSampleLimit
            MaxContextValuesPerCategory  = $MaxContextValuesPerCategory
            GeneratedUtc                 = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        }
        EnrichedResults = $enrichedResults
    }
    $enrichedEnvelope | ConvertTo-Json -Depth 8 | Set-Content -Path $enrichedOutputPath

    Write-Host "Full raw results saved to: $outputPath" -ForegroundColor Green
    Write-Host "Forensic-enriched results saved to: $enrichedOutputPath" -ForegroundColor Green
}

Export-ModuleMember -Function Get-ElasticForensicLongTailAnalysis
