function Get-ElasticDetonationLogs {
    <#
    .SYNOPSIS
        Pulls all Elastic logs from a detonation window and saves them to a
        timestamped folder for offline analysis.

        Prompts for start/end times in any natural format (e.g. "8PM EST",
        "20:00", "2026-03-18 20:00 EST"). Queries process, network, file,
        registry, and alert events separately and saves each as NDJSON + a
        combined summary CSV.
    .NOTES
        Requires vault secrets: Elastic_URL, Elastic_User, Elastic_Pass
    #>

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # Bypass self-signed certificate validation for internal Elasticsearch clusters.
    # PS 5.1 uses ServicePointManager; PS 7+ uses -SkipCertificateCheck per call.
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    }
    $restArgs = if ($PSVersionTable.PSVersion.Major -ge 6) { @{ SkipCertificateCheck = $true } } else { @{} }

    # --- AUTH ---
    $esUrl  = (Get-Secret -Name 'Elastic_URL'  -AsPlainText -ErrorAction SilentlyContinue).Trim().TrimEnd('/')
    $esUser = (Get-Secret -Name 'Elastic_User' -AsPlainText -ErrorAction SilentlyContinue).Trim()
    $esPass = (Get-Secret -Name 'Elastic_Pass' -AsPlainText -ErrorAction SilentlyContinue).Trim()

    if ([string]::IsNullOrWhiteSpace($esUrl)) {
        $esUrl = Read-Host "[?] Elastic URL not found in vault (e.g. https://elasticsearch.yourdomain:9200)"
        $esUrl = $esUrl.TrimEnd('/')
    }
    if ([string]::IsNullOrWhiteSpace($esUrl)) { Write-Error "Elastic URL required."; return }

    # Auto-prefix https:// if no scheme provided
    if ($esUrl -notmatch '^https?://') { $esUrl = "https://$esUrl" }

    try {
        $uri = [Uri]$esUrl
        if (-not $uri.Host) { throw "No host" }
    } catch {
        Write-Host "[ERROR] Elastic URL is not valid: '$esUrl'" -ForegroundColor Red; return
    }

    $b64   = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${esUser}:${esPass}"))
    $esHdr = @{ 'Authorization' = "Basic $b64"; 'Content-Type' = 'application/json' }

    # If stored as http:// but server is actually HTTPS (common with ES 8.x),
    # auto-upgrade to https:// so -SkipCertificateCheck can handle self-signed certs.
    if ($esUrl -match '^http://') {
        $httpsUrl = $esUrl -replace '^http://', 'https://'
        try {
            [void](Invoke-RestMethod -Uri "$httpsUrl/_cluster/health" -Headers $esHdr -Method Get @restArgs -ErrorAction Stop)
            Write-Host "  [INFO] Auto-upgraded URL from http:// to https:// (ES 8.x HTTPS detected)" -ForegroundColor DarkCyan
            $esUrl = $httpsUrl
        } catch {
            # https didn't work either -- keep original http:// and let the main check report the error
        }
    }

    # --- TIME PARSING HELPER ---
    # Accepts flexible input: "8PM EST", "20:00", "8:28 PM", "2026-03-18 20:00 EST", etc.
    # If no date is given, assumes today. Converts to UTC for the ES query.
    function ConvertTo-DetonUtc {
        param([string]$Raw, [string]$Label)

        $Raw = $Raw.Trim()

        # Extract timezone abbreviation if present
        $tzOffset = $null
        $tzMap = @{
            "EST" = -5; "EDT" = -4
            "CST" = -6; "CDT" = -5
            "MST" = -7; "MDT" = -6
            "PST" = -8; "PDT" = -7
            "UTC" = 0;  "GMT" = 0
        }
        foreach ($tz in $tzMap.Keys) {
            if ($Raw -match "\b$tz\b") {
                $tzOffset = $tzMap[$tz]
                $Raw = $Raw -replace "\b$tz\b", "" -replace "\s{2,}", " " | ForEach-Object { $_.Trim() }
                break
            }
        }

        # Try parsing what remains
        $parsed = $null
        $formats = @(
            "yyyy-MM-dd HH:mm:ss", "yyyy-MM-dd HH:mm", "yyyy-MM-dd h:mm tt",
            "M/d/yyyy HH:mm:ss",   "M/d/yyyy HH:mm",   "M/d/yyyy h:mm tt",
            "HH:mm:ss", "HH:mm", "h:mm tt", "h tt", "htt"
        )

        foreach ($fmt in $formats) {
            try {
                $parsed = [datetime]::ParseExact($Raw, $fmt, [System.Globalization.CultureInfo]::InvariantCulture)
                break
            } catch {}
        }

        # Last resort: .NET general parsing
        if (-not $parsed) {
            try { $parsed = [datetime]::Parse($Raw) } catch {}
        }

        if (-not $parsed) {
            Write-Host "[ERROR] Could not parse $Label time: '$Raw'" -ForegroundColor Red
            return $null
        }

        # If no date component was in the input, attach today's date
        if ($parsed.Year -eq 1 -or $parsed.Year -eq 1899) {
            $today  = Get-Date
            $parsed = [datetime]::new($today.Year, $today.Month, $today.Day,
                                      $parsed.Hour, $parsed.Minute, $parsed.Second)
        }

        # Apply explicit tz offset -> UTC; otherwise treat as local -> UTC
        if ($null -ne $tzOffset) {
            $parsed = $parsed.AddHours(-$tzOffset)   # to UTC
        } else {
            $parsed = $parsed.ToUniversalTime()
        }

        return $parsed
    }

    # --- INPUT ---
    Write-Host ""
    Write-Host "Elastic Detonation Log Puller" -ForegroundColor DarkCyan
    Write-Host "Accepts times like: '8PM EST', '20:00', '8:28 PM CDT', '2026-03-18 20:00 UTC'" -ForegroundColor DarkGray
    Write-Host ""

    $startRaw = Read-Host "[?] Detonation START time"
    $endRaw   = Read-Host "[?] Detonation END time  "
    $label    = Read-Host "[?] Label for this session (e.g. APT42, cobalt_strike) [default: detonation]"
    if ([string]::IsNullOrWhiteSpace($label)) { $label = "detonation" }
    $label = $label -replace '[\\/:*?"<>|\s]', '_'

    $outRootRaw = Read-Host "[?] Output root directory [default: .\detonation_logs]"
    if ([string]::IsNullOrWhiteSpace($outRootRaw)) { $outRootRaw = ".\detonation_logs" }

    $startUtc = ConvertTo-DetonUtc -Raw $startRaw -Label "START"
    $endUtc   = ConvertTo-DetonUtc -Raw $endRaw   -Label "END"
    if (-not $startUtc -or -not $endUtc) { return }
    if ($endUtc -le $startUtc) { Write-Host "[ERROR] END time must be after START time." -ForegroundColor Red; return }

    $startStr = $startUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")
    $endStr   = $endUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")
    $duration = ($endUtc - $startUtc).TotalMinutes

    Write-Host ""
    Write-Host "Window : $startStr --> $endStr  ($([math]::Round($duration,1)) min)" -ForegroundColor DarkCyan

    # --- OUTPUT DIR ---
    $folderName = "$label`_$($startUtc.ToString('yyyy-MM-dd_HH-mm'))_to_$($endUtc.ToString('HH-mm'))UTC"
    $outDir     = Join-Path $outRootRaw $folderName
    if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Force -Path $outDir | Out-Null }
    $outDir = (Resolve-Path $outDir).Path
    Write-Host "Output : $outDir" -ForegroundColor DarkCyan

    # --- OPTIONAL HOSTNAME FILTER ---
    $hostFilter = Read-Host "[?] Filter by sandbox hostname (leave blank for all hosts)"
    $hostFilter = $hostFilter.Trim()

    # --- PRE-FLIGHT DIAGNOSTICS ---
    Write-Host ""
    Write-Host "[Pre-flight] Checking Elasticsearch connectivity..." -ForegroundColor DarkCyan
    Write-Host "  URL     : $esUrl" -ForegroundColor DarkGray
    Write-Host "  PS ver  : $($PSVersionTable.PSVersion)" -ForegroundColor DarkGray
    Write-Host "  User    : $esUser" -ForegroundColor DarkGray

    try {
        $health = Invoke-RestMethod -Uri "$esUrl/_cluster/health" -Headers $esHdr -Method Get @restArgs
        Write-Host "  Cluster : $($health.cluster_name)  Status: $($health.status)  Nodes: $($health.number_of_nodes)" -ForegroundColor Green
    } catch {
        Write-Host "  [ERROR] Cannot reach Elasticsearch." -ForegroundColor Red
        Write-Host "  Exception type : $($_.Exception.GetType().FullName)" -ForegroundColor Yellow
        Write-Host "  Message        : $($_.Exception.Message)" -ForegroundColor Yellow
        if ($_.Exception.InnerException) {
            Write-Host "  Inner exception: $($_.Exception.InnerException.Message)" -ForegroundColor Yellow
        }
        Write-Host ""
        Write-Host "  Common causes:" -ForegroundColor DarkYellow
        Write-Host "    1. Wrong port - Kibana is 5601, Elasticsearch is 9200" -ForegroundColor DarkYellow
        Write-Host "    2. Wrong credentials stored in vault" -ForegroundColor DarkYellow
        Write-Host "    3. Elasticsearch requires an API key instead of Basic auth" -ForegroundColor DarkYellow
        Write-Host "    4. Firewall blocking the connection from this machine" -ForegroundColor DarkYellow
        return
    }

    # Show which indices/data streams are actually present
    $defaultIndices = "*"
    Write-Host ""
    Write-Host "[Pre-flight] Checking available indices and data streams..." -ForegroundColor DarkCyan
    try {
        # Check concrete indices (Winlogbeat/Filebeat style)
        $catResp = Invoke-RestMethod -Uri "$esUrl/_cat/indices/$defaultIndices`?h=index,docs.count&s=index&expand_wildcards=all" `
                       -Headers $esHdr -Method Get @restArgs
        $indexLines = $catResp -split "`n" | Where-Object { $_.Trim() -ne "" }
        # Also check data streams (Elastic Agent/Fleet style)
        $dsResp = Invoke-RestMethod -Uri "$esUrl/_data_stream/logs-*" -Headers $esHdr -Method Get @restArgs -ErrorAction SilentlyContinue
        $dsCount = if ($dsResp -and $dsResp.data_streams) { $dsResp.data_streams.Count } else { 0 }
        if ($indexLines.Count -gt 0) {
            Write-Host "  Found $($indexLines.Count) concrete index/indices:" -ForegroundColor Green
            $indexLines | Select-Object -First 20 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
            if ($indexLines.Count -gt 20) { Write-Host "    ... ($($indexLines.Count - 20) more)" -ForegroundColor DarkGray }
        }
        if ($dsCount -gt 0) {
            Write-Host "  Found $dsCount data stream(s) matching logs-* (Elastic Agent/Fleet)" -ForegroundColor Green
        }
        if ($indexLines.Count -eq 0 -and $dsCount -eq 0) {
            Write-Host "  [WARN] No indices or data streams found - proceeding anyway (events may still exist)" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  [WARN] Could not list indices, proceeding with default pattern." -ForegroundColor Yellow
    }

    # Count all docs in the window before doing full pull
    Write-Host ""
    Write-Host "[Pre-flight] Counting events in window..." -ForegroundColor DarkCyan
    $countMust = [System.Collections.Generic.List[object]]::new()
    $countMust.Add(@{ range = @{ "@timestamp" = @{ gte = $startStr; lte = $endStr } } })
    if ($hostFilter) {
        $countMust.Add(@{ bool = @{ should = @(
            @{ term = @{ "host.name"     = $hostFilter } }
            @{ term = @{ "agent.name"    = $hostFilter } }
            @{ term = @{ "host.hostname" = $hostFilter } }
        ); minimum_should_match = 1 } })
    }
    $countQuery = @{ query = @{ bool = @{ must = $countMust.ToArray() } } }
    $countBody = $countQuery | ConvertTo-Json -Depth 20 -Compress

    try {
        $countResp = Invoke-RestMethod -Uri "$esUrl/$defaultIndices/_count" `
                         -Headers $esHdr -Method Post -Body $countBody @restArgs
        $totalCount = $countResp.count
        if ($totalCount -eq 0) {
            Write-Host "  [WARN] 0 documents found in window $startStr -> $endStr" -ForegroundColor Yellow
            if ($hostFilter) {
                Write-Host "         (host.name filter: '$hostFilter')" -ForegroundColor Yellow
                Write-Host "         Try leaving hostname blank to check if events exist for any host." -ForegroundColor DarkYellow
            } else {
                Write-Host "         Check that:" -ForegroundColor DarkYellow
                Write-Host "           1. The time window is correct (currently in UTC)" -ForegroundColor DarkYellow
                Write-Host "           2. The sandbox agent is shipping to this Elasticsearch cluster" -ForegroundColor DarkYellow
                Write-Host "           3. The index pattern '$defaultIndices' matches your setup" -ForegroundColor DarkYellow
            }
            $proceed = Read-Host "[?] Proceed anyway? (y/N)"
            if ($proceed -notmatch "^[yY]") { return }
        } else {
            $hostSuffix = if ($hostFilter) { " for host '$hostFilter'" } else { "" }
            Write-Host "  Found $totalCount total event(s) in window$hostSuffix." -ForegroundColor Green
        }
    } catch {
        Write-Host "  [WARN] Count query failed: $($_.Exception.Message) - proceeding anyway." -ForegroundColor Yellow
    }

    # Sample one document to show which fields are actually present - helps diagnose
    # ECS-normalized vs raw Sysmon/Winlogbeat field name differences.
    Write-Host ""
    Write-Host "[Pre-flight] Sampling a document to inspect field mapping..." -ForegroundColor DarkCyan
    try {
        $sampleBody = @{
            size    = 1
            query   = @{ bool = @{ filter = @(
                @{ range = @{ "@timestamp" = @{ gte = $startStr; lte = $endStr } } }
            ) } }
            _source = $true
        } | ConvertTo-Json -Depth 20 -Compress
        $sampleResp = Invoke-RestMethod -Uri "$esUrl/$defaultIndices/_search" `
                          -Headers $esHdr -Method Post -Body $sampleBody @restArgs
        if ($sampleResp.hits.hits.Count -gt 0) {
            $sd = $sampleResp.hits.hits[0]._source
            $topFields = ($sd | Get-Member -MemberType NoteProperty).Name
            Write-Host "  Top-level fields : $($topFields -join ', ')" -ForegroundColor DarkGray
            if ($sd.event)  { Write-Host "  event.category  : $($sd.event.category)   event.kind: $($sd.event.kind)" -ForegroundColor DarkGray }
            if ($sd.winlog) { Write-Host "  winlog.event_id : $($sd.winlog.event_id)   provider: $($sd.winlog.provider_name)" -ForegroundColor DarkGray }
        } else {
            Write-Host "  (no docs returned from sample query)" -ForegroundColor DarkYellow
        }
    } catch {
        Write-Host "  [WARN] Sample query failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # --- INDICES ---
    $allIndices = $defaultIndices

    # --- QUERY CATEGORIES ---
    # Each filter uses bool.should with THREE branches:
    #   1. ECS event.category  (Elastic Agent / Fleet / Elastic Defend)
    #   2. event.dataset       (Elastic Defend explicit data stream label  -  most reliable for Elastic Defend)
    #   3. winlog.event_id     (Sysmon / Winlogbeat without ECS normalization)
    #
    # Sysmon event ID reference:
    #   1=ProcessCreate  2=FileCreateTime  3=NetworkConnect  6=DriverLoad
    #   7=ImageLoad      8=CreateRemoteThread  10=ProcessAccess  11=FileCreate
    #   12=RegistryObjectCreateDelete  13=RegistryValueSet  14=RegistryKeyRename
    #   15=FileCreateStreamHash  17=PipeCreated  18=PipeConnected  22=DnsQuery
    $categories = @(
        @{
            Name    = "process_events"
            Indices = $allIndices
            Filter  = @{ bool = @{
                should = @(
                    @{ term  = @{ "event.category"  = "process" } }
                    @{ term  = @{ "event.dataset"   = "endpoint.events.process" } }
                    @{ term  = @{ "winlog.event_id" = 1 } }
                )
                minimum_should_match = 1
            } }
        },
        @{
            Name    = "network_events"
            Indices = $allIndices
            Filter  = @{ bool = @{
                should = @(
                    @{ term  = @{ "event.category"  = "network" } }
                    @{ term  = @{ "event.dataset"   = "endpoint.events.network" } }
                    @{ term  = @{ "winlog.event_id" = 3 } }
                )
                minimum_should_match = 1
            } }
        },
        @{
            Name    = "file_events"
            Indices = $allIndices
            Filter  = @{ bool = @{
                should = @(
                    @{ term  = @{ "event.category"  = "file" } }
                    @{ term  = @{ "event.dataset"   = "endpoint.events.file" } }
                    @{ terms = @{ "winlog.event_id" = @(2, 11, 15) } }
                )
                minimum_should_match = 1
            } }
        },
        @{
            Name    = "registry_events"
            Indices = $allIndices
            Filter  = @{ bool = @{
                should = @(
                    @{ term  = @{ "event.category"  = "registry" } }
                    @{ term  = @{ "event.dataset"   = "endpoint.events.registry" } }
                    @{ terms = @{ "winlog.event_id" = @(12, 13, 14) } }
                )
                minimum_should_match = 1
            } }
        },
        @{
            Name    = "alerts"
            Indices = ".alerts-security*,.siem-signals*"
            Filter  = @{ exists = @{ field = "kibana.alert.rule.name" } }
        },
        @{
            Name    = "dns_events"
            Indices = $allIndices
            Filter  = @{ bool = @{
                should = @(
                    @{ term  = @{ "event.category"  = "dns" } }
                    @{ term  = @{ "event.dataset"   = "endpoint.events.dns" } }
                    @{ term  = @{ "winlog.event_id" = 22 } }
                )
                minimum_should_match = 1
            } }
        },
        @{
            Name    = "image_load"
            Indices = $allIndices
            Filter  = @{ bool = @{
                should = @(
                    @{ term  = @{ "event.category"  = "library" } }
                    @{ term  = @{ "event.dataset"   = "endpoint.events.library" } }
                    @{ term  = @{ "winlog.event_id" = 7 } }
                )
                minimum_should_match = 1
            } }
        },
        @{
            Name    = "injection_events"
            Indices = $allIndices
            Filter  = @{ terms = @{ "winlog.event_id" = @(8, 10) } }  # Sysmon CreateRemoteThread, ProcessAccess
        },
        @{
            Name    = "driver_and_pipe"
            Indices = $allIndices
            Filter  = @{ terms = @{ "winlog.event_id" = @(6, 17, 18) } }  # Sysmon DriverLoad, PipeCreated, PipeConnected
        },
        @{
            # Elastic Endpoint API monitoring  -  captures Windows API call sequences
            # (process injection, memory manipulation, LSASS reads, etc.)
            # Distinct from Sysmon; generated by Elastic Defend's kernel-level sensor.
            # AttackIQ simulations frequently surface here rather than in process_events.
            Name    = "api_events"
            Indices = $allIndices
            Filter  = @{ bool = @{
                should = @(
                    @{ term  = @{ "event.dataset"   = "endpoint.events.api" } }
                    @{ term  = @{ "event.category"  = "api" } }
                    @{ term  = @{ "event.category"  = "intrusion_detection" } }
                    @{ term  = @{ "event.dataset"   = "endpoint.events.memory" } }
                    @{ term  = @{ "event.dataset"   = "endpoint.events.security" } }
                )
                minimum_should_match = 1
            } }
        }
    )

    # --- FETCH HELPER ---
    # Paginated fetch using the scroll API to retrieve ALL matching documents.
    # The scroll API works on all ES versions (7.x/8.x) and all index types
    # including data streams.
    function Invoke-EsPagedQuery {
        param(
            [string]$Index,
            [hashtable]$BoolFilter,
            [string]$Label,
            [int]$PageSize = 5000
        )

        $allDocs = [System.Collections.Generic.List[object]]::new()

        $tF = @{ range = @{ "@timestamp" = @{ gte = $startStr; lte = $endStr } } }
        $hF = if ($hostFilter) {
            @{ bool = @{ should = @(
                @{ term = @{ "host.name"     = $hostFilter } }
                @{ term = @{ "agent.name"    = $hostFilter } }
                @{ term = @{ "host.hostname" = $hostFilter } }
            ); minimum_should_match = 1 } }
        } else { $null }

        $mustClauses = if ($hF) { @($tF, $hF) } else { @($tF) }

        # ---- PRE-CHECK: count matching docs ----
        try {
            $countBody = @{ query = @{ bool = @{ must = $mustClauses; filter = @( $BoolFilter ) } } } |
                         ConvertTo-Json -Depth 20 -Compress
            $countResp = Invoke-RestMethod -Uri "$esUrl/$Index/_count" -Headers $esHdr -Method Post -Body $countBody @restArgs
            $esCount   = $countResp.count
            Write-Host "  $Label : ES reports $esCount matching document(s)" -ForegroundColor DarkGray
        } catch {
            $esCount = -1
            Write-Host "  $Label : _count query failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }

        if ($esCount -eq 0) { return $allDocs }

        # ---- PAGINATED FETCH using scroll API ----
        $scrollTtl  = "5m"
        $scrollId   = $null

        # Initial scroll request
        $query = @{
            size    = $PageSize
            query   = @{ bool = @{ must = $mustClauses; filter = @( $BoolFilter ) } }
            sort    = @( "_doc" )
            _source = $true
        }
        $body = $query | ConvertTo-Json -Depth 20 -Compress

        try {
            $resp = Invoke-RestMethod -Uri "$esUrl/$Index/_search?scroll=$scrollTtl" `
                        -Headers $esHdr -Method Post -Body $body @restArgs
        } catch {
            $code = $null; try { $code = $_.Exception.Response.StatusCode.value__ } catch {}
            Write-Host "  [WARN] $Label initial scroll query failed (HTTP $code): $($_.Exception.Message)" -ForegroundColor Yellow
            return $allDocs
        }

        $scrollId = $resp._scroll_id
        $hits     = $resp.hits.hits

        if ($hits -and $hits.Count -gt 0) {
            foreach ($h in $hits) { $allDocs.Add($h._source) }
        }

        # Continue scrolling until no more hits
        $maxScrollPages = 200   # safety valve: 200 pages × 5000 = 1M docs max
        $scrollPage     = 0
        while ($hits -and $hits.Count -gt 0) {
            if ($hits.Count -lt $PageSize) { break }
            $scrollPage++
            if ($scrollPage -ge $maxScrollPages) {
                Write-Host "  [WARN] $Label : hit $maxScrollPages page safety limit ($($allDocs.Count) docs) - stopping" -ForegroundColor Yellow
                break
            }

            if ($esCount -gt 0) {
                Write-Host "  $Label : fetched $($allDocs.Count) / $esCount ..." -ForegroundColor DarkGray
            }

            $scrollBody = @{ scroll = $scrollTtl; scroll_id = $scrollId } |
                          ConvertTo-Json -Compress

            try {
                $resp = Invoke-RestMethod -Uri "$esUrl/_search/scroll" `
                            -Headers $esHdr -Method Post -Body $scrollBody @restArgs
            } catch {
                Write-Host "  [WARN] $Label scroll page failed: $($_.Exception.Message)" -ForegroundColor Yellow
                break
            }

            $scrollId = $resp._scroll_id
            $hits     = $resp.hits.hits

            if ($hits -and $hits.Count -gt 0) {
                foreach ($h in $hits) { $allDocs.Add($h._source) }
            }
        }

        # Clean up scroll context
        if ($scrollId) {
            try {
                $clearBody = @{ scroll_id = $scrollId } | ConvertTo-Json -Compress
                [void](Invoke-RestMethod -Uri "$esUrl/_search/scroll" `
                           -Headers $esHdr -Method Delete -Body $clearBody @restArgs)
            } catch {
                # Scroll context cleanup is best-effort
            }
        }

        if ($esCount -gt 0 -and $allDocs.Count -eq 0) {
            Write-Host "  [WARN] ES reported $esCount docs but 0 were retrieved  -  printing query for diagnosis:" -ForegroundColor Red
            $dbg = @{ query = @{ bool = @{ must = $mustClauses; filter = @( $BoolFilter ) } } } |
                   ConvertTo-Json -Depth 20
            Write-Host $dbg -ForegroundColor DarkGray
        } elseif ($esCount -gt 0 -and $allDocs.Count -lt $esCount) {
            Write-Host "  [WARN] $Label : ES reported $esCount docs but only $($allDocs.Count) were retrieved  -  possible scroll/pagination issue" -ForegroundColor Yellow
        }

        Write-Host "  $Label : $($allDocs.Count) document(s) retrieved" -ForegroundColor $(if ($allDocs.Count -gt 0) { 'Green' } else { 'DarkGray' })
        return $allDocs
    }

    # --- PULL EACH CATEGORY ---
    $summary = @()

    foreach ($cat in $categories) {
        Write-Host ""
        Write-Host "[$($cat.Name)]" -ForegroundColor Yellow

        $docs = Invoke-EsPagedQuery -Index $cat.Indices -BoolFilter $cat.Filter -Label $cat.Name

        $outFile = Join-Path $outDir "$($cat.Name).ndjson"

        if ($docs.Count -gt 0) {
            $stream = [System.IO.StreamWriter]::new($outFile, $false, [System.Text.Encoding]::UTF8)
            foreach ($doc in $docs) {
                $stream.WriteLine(($doc | ConvertTo-Json -Depth 20 -Compress))
            }
            $stream.Close()
            Write-Host "  Saved $($docs.Count) events -> $($cat.Name).ndjson" -ForegroundColor Green
        } else {
            Write-Host "  No events found." -ForegroundColor DarkGray
        }

        $summary += [PSCustomObject]@{
            Category   = $cat.Name
            EventCount = $docs.Count
            File       = if ($docs.Count -gt 0) { "$($cat.Name).ndjson" } else { "" }
        }
    }

    # --- SUMMARY FILE ---
    $summary | Export-Csv -Path (Join-Path $outDir "summary.csv") -NoTypeInformation -Encoding UTF8

    $metaLines = @(
        "Session  : $label",
        "Start    : $startStr  ($startRaw)",
        "End      : $endStr  ($endRaw)",
        "Duration : $([math]::Round($duration,1)) minutes",
        "Pulled   : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') UTC",
        "",
        "Category Counts:"
    )
    foreach ($s in $summary) {
        $metaLines += "  $($s.Category.PadRight(20)) $($s.EventCount)"
    }
    $metaLines | Set-Content -Path (Join-Path $outDir "session_info.txt") -Encoding UTF8

    # --- DONE ---
    Write-Host ""
    Write-Host "Done. Detonation logs saved to:" -ForegroundColor Green
    Write-Host "  $outDir" -ForegroundColor DarkCyan
    Write-Host ""
    $summary | Format-Table -AutoSize
}

Export-ModuleMember -Function Get-ElasticDetonationLogs
