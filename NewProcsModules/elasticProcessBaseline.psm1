function Get-ElasticProcessBaseline {
    <#
    .SYNOPSIS
        Elastic equivalent of the S1 process baselining suite.
        Covers four workflows:
          1. Unverified processes  (code_signature.trusted = false)
          2. Unsigned processes    (code_signature.exists = false, Win + Linux)
          3. New Windows publishers (signed+verified, find new publishers then drill per publisher)
          4. Drivers               (driver loads where Elastic hasn't marked them clean)
          5. Specific process      (ad-hoc single process name across all baselines)

        For each new hash not in the baseline:
          - Try VirusTotal first
          - If VT returns 404 (unknown), flag for manual file retrieval
          - Intezer is intentionally skipped
          - On VT hit, write result to appropriate baseline JSON

    .PARAMETER Mode
        UnverifiedProcs | UnsignedWin | UnsignedLinux | NewWinPublishers | Drivers | SpecificProc

    .PARAMETER ProcName
        Required when Mode = SpecificProc

    .PARAMETER QueryDays
        How far back the Recent query looks. Defaults vary by mode.

    .PARAMETER BaselineDays
        How far back the Baseline query looks when no baseline file exists. Default: 37 days ago
        to 30 days ago (matching S1 version).
    #>

    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("UnverifiedProcs","UnsignedWin","UnsignedLinux","NewWinPublishers","Drivers","SpecificProc")]
        [string]$Mode,

        [string]$ProcName,   # Required for SpecificProc mode

        [int]$QueryDays   = -3,   # Recent window
        [int]$BaselineDays = -30  # How far back baseline goes (end point; starts 7 days earlier)
    )

    # --- API SETUP ---
    $esUrl  = Get-Secret -Name 'Elastic_URL'  -AsPlainText
    $esUser = Get-Secret -Name 'Elastic_User' -AsPlainText
    $esPass = Get-Secret -Name 'Elastic_Pass' -AsPlainText
    $vtKey  = $null
    try { $vtKey = (Get-Secret -Name 'VT_API_Key_1' -AsPlainText -ErrorAction Stop).Trim() } catch {}

    $b64Auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${esUser}:${esPass}"))
    $esHeaders = @{ 'Authorization' = "Basic $b64Auth"; 'Content-Type' = 'application/json' }
    $vtHeaders  = @{ 'x-apikey' = $vtKey; 'Content-Type' = 'application/json' }

    $eventsIndex = "logs-*,winlogbeat-*,filebeat-*,endgame-*"

    if (-not (Test-Path "output")) { New-Item -Path "output" -ItemType Directory | Out-Null }

    # Validate SpecificProc mode
    if ($Mode -eq "SpecificProc" -and [string]::IsNullOrWhiteSpace($ProcName)) {
        Write-Error "ProcName is required when Mode is SpecificProc."
        return
    }

    $now          = Get-Date
    $currentTime  = $now.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $recentFrom   = $now.AddDays($QueryDays).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $baselineEnd  = $now.AddDays($BaselineDays).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $baselineStart = $now.AddDays($BaselineDays - 7).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

    Write-Host "`n[Mode: $Mode]" -ForegroundColor DarkCyan
    Write-Host "Recent window:   $recentFrom -> $currentTime"
    Write-Host "Baseline window: $baselineStart -> $baselineEnd"

    # =========================================================
    # HELPER: Invoke-ESQuery
    # =========================================================
    function Invoke-ESQuery {
        param([hashtable]$Body, [int]$Size = 0)
        $Body['size'] = $Size
        $uri      = "$esUrl/$eventsIndex/_search"
        $bodyJson = $Body | ConvertTo-Json -Depth 20 -Compress
        try {
            return Invoke-RestMethod -Uri $uri -Headers $esHeaders -Method Post -Body $bodyJson
        } catch {
            $code = $null
            try { $code = $_.Exception.Response.StatusCode.value__ } catch {}
            Write-Host "  [ERROR] ES query failed (HTTP $code): $($_.Exception.Message)" -ForegroundColor Red
            return $null
        }
    }

    # =========================================================
    # HELPER: Get-ProcessHashes
    # Runs an ES aggregation and returns array of hashtables:
    # @{ Name, SignedStatus, Sha256, VerifiedStatus, OS, Publisher }
    # $mustClauses  = array of ES must clause hashtables
    # $fromTime / $toTime = ISO8601 strings
    # =========================================================
    function Get-ProcessHashes {
        param(
            [array]$MustClauses,
            [string]$FromTime,
            [string]$ToTime,
            [int]$Size = 10000
        )

        $query = @{
            query = @{
                bool = @{
                    must = @(
                        @{ range = @{ "@timestamp" = @{ gte = $FromTime; lte = $ToTime } } }
                    ) + $MustClauses
                }
            }
            aggs = @{
                by_hash = @{
                    terms = @{ field = "process.hash.sha256"; size = $Size; min_doc_count = 1 }
                    aggs  = @{
                        proc_name  = @{ terms = @{ field = "process.name";                        size = 1 } }
                        signed     = @{ terms = @{ field = "process.code_signature.exists";        size = 1 } }
                        verified   = @{ terms = @{ field = "process.code_signature.trusted";       size = 1 } }
                        publisher  = @{ terms = @{ field = "process.code_signature.subject_name";  size = 1 } }
                        os_family  = @{ terms = @{ field = "host.os.family";                       size = 1 } }
                    }
                }
            }
        }

        $resp = Invoke-ESQuery -Body $query -Size 0
        if (-not $resp) { return @() }

        $results = @()
        foreach ($bucket in $resp.aggregations.by_hash.buckets) {
            $results += @{
                Sha256         = $bucket.key
                Name           = ($bucket.proc_name.buckets | Select-Object -First 1).key
                SignedStatus   = ($bucket.signed.buckets   | Select-Object -First 1).key_as_string
                VerifiedStatus = ($bucket.verified.buckets | Select-Object -First 1).key_as_string
                Publisher      = ($bucket.publisher.buckets | Select-Object -First 1).key
                OS             = ($bucket.os_family.buckets | Select-Object -First 1).key
            }
        }
        return $results
    }

    # =========================================================
    # HELPER: Get-BaselineHashes
    # Returns a HashSet of SHA256 strings already in a baseline file
    # =========================================================
    function Get-BaselineHashes {
        param([string]$BaselineFile)
        $set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        if (Test-Path $BaselineFile) {
            try {
                $data = Get-Content $BaselineFile | ConvertFrom-Json
                foreach ($entry in $data) {
                    if ($entry.Sha256) { [void]$set.Add($entry.Sha256) }
                }
            } catch {
                Write-Host "  [WARN] Could not read baseline file $BaselineFile" -ForegroundColor Yellow
            }
        }
        return $set
    }

    # =========================================================
    # HELPER: Add-ToBaseline
    # Appends a new entry to a baseline JSON file
    # =========================================================
    function Add-ToBaseline {
        param([string]$BaselineFile, [hashtable]$Entry)
        $existing = @()
        if (Test-Path $BaselineFile) {
            try { $existing = @(Get-Content $BaselineFile | ConvertFrom-Json) } catch {}
        }
        $existing += $Entry
        $existing | ConvertTo-Json -Depth 5 | Set-Content -Path $BaselineFile
    }

    # =========================================================
    # HELPER: Invoke-VTLookup
    # Returns VT response or $null if 404/no key.
    # Respects 4 req/min rate limit.
    # =========================================================
    $script:VTLastCall = [DateTime]::MinValue
    function Invoke-VTLookup {
        param([string]$Sha256)

        if ([string]::IsNullOrWhiteSpace($vtKey)) {
            Write-Host "  [VT] No VT API key available, skipping." -ForegroundColor DarkGray
            return $null
        }

        $waitMs = ($script:VTLastCall.AddSeconds(15) - [DateTime]::UtcNow).TotalMilliseconds
        if ($waitMs -gt 0) {
            Write-Host "  [VT] Rate limit - waiting $([Math]::Round($waitMs/1000,1))s..." -ForegroundColor DarkGray
            Start-Sleep -Milliseconds ([Math]::Ceiling($waitMs))
        }

        $script:VTLastCall = [DateTime]::UtcNow
        $uri = "https://www.virustotal.com/api/v3/files/$Sha256"

        try {
            return Invoke-RestMethod -Uri $uri -Headers $vtHeaders -Method Get -ErrorAction Stop
        } catch {
            $code = $null
            try { $code = $_.Exception.Response.StatusCode.value__ } catch {}
            if ($code -eq 404) {
                Write-Host "  [VT] $Sha256 - Not found in VirusTotal." -ForegroundColor Yellow
            } elseif ($code -eq 429) {
                Write-Host "  [VT] Rate limited by VT API." -ForegroundColor Red
            } else {
                Write-Host "  [VT] Error $code - $($_.Exception.Message)" -ForegroundColor Red
            }
            return $null
        }
    }

    # =========================================================
    # HELPER: Process-NewHash
    # Core enrichment loop for a single new hash.
    # 1. Try VT
    # 2. If VT hit - write to appropriate baseline, show verdict
    # 3. If VT miss - flag for manual file retrieval
    # =========================================================
    function Process-NewHash {
        param(
            [string]$Sha256,
            [string]$FileName,
            [string]$SignedStatus,
            [string]$VerifiedStatus,
            [string]$OS,
            [string]$Publisher,
            [string]$BaselineFile
        )

        Write-Host "`n  Hash: $Sha256" -ForegroundColor DarkCyan
        Write-Host "  File: $FileName | Signed: $SignedStatus | Verified: $VerifiedStatus | OS: $OS | Publisher: $Publisher"

        $vtResult = Invoke-VTLookup -Sha256 $Sha256

        if ($vtResult) {
            $malicious   = $vtResult.data.attributes.last_analysis_stats.malicious
            $suspicious  = $vtResult.data.attributes.last_analysis_stats.suspicious
            $undetected  = $vtResult.data.attributes.last_analysis_stats.undetected
            $totalEngines = $malicious + $suspicious + $undetected +
                            $vtResult.data.attributes.last_analysis_stats.harmless

            $popularName = $vtResult.data.attributes.popular_threat_classification.suggested_threat_label
            $vtNames     = ($vtResult.data.attributes.names | Select-Object -First 3) -join ", "

            if ($malicious -gt 5) {
                $color      = "Red"
                $verdict    = "MALICIOUS ($malicious/$totalEngines engines)"
                $targetFile = "output\maliciousProcsBaseline.json"
            } elseif ($malicious -gt 0 -or $suspicious -gt 3) {
                $color      = "Yellow"
                $verdict    = "SUSPICIOUS ($malicious malicious, $suspicious suspicious / $totalEngines engines)"
                $targetFile = $BaselineFile
            } else {
                $color      = "Green"
                $verdict    = "Clean ($malicious/$totalEngines)"
                $targetFile = $BaselineFile
            }

            Write-Host "  [VT] $verdict" -ForegroundColor $color
            if ($popularName) { Write-Host "  [VT] Threat label: $popularName" -ForegroundColor $color }
            if ($vtNames)     { Write-Host "  [VT] Known names: $vtNames" }

            Add-ToBaseline -BaselineFile $targetFile -Entry @{
                Name           = $FileName
                Sha256         = $Sha256
                SignedStatus   = $SignedStatus
                VerifiedStatus = $VerifiedStatus
                OS             = $OS
                Publisher      = $Publisher
                VTMalicious    = $malicious
                VTSuspicious   = $suspicious
                VTTotal        = $totalEngines
                VTLabel        = $popularName
                AddedAt        = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
            }
            Write-Host "  [+] Added to $targetFile" -ForegroundColor DarkGray

        } else {
            # VT miss - flag for manual retrieval
            Write-Host "  [!] NOT IN VIRUSTOTAL - Manual file retrieval needed." -ForegroundColor Red
            Write-Host "      SHA256:   $Sha256" -ForegroundColor Red
            Write-Host "      FileName: $FileName" -ForegroundColor Red
            Write-Host "      To retrieve via Elastic: POST /api/endpoint/action/get-file" -ForegroundColor DarkGray
            Write-Host "      Body: { ""endpoint_ids"": [""<agent-id>""], ""parameters"": { ""path"": ""<full-path>"" } }" -ForegroundColor DarkGray

            # Still log it to a pending file so nothing is lost
            Add-ToBaseline -BaselineFile "output\pendingManualReview.json" -Entry @{
                Name           = $FileName
                Sha256         = $Sha256
                SignedStatus   = $SignedStatus
                VerifiedStatus = $VerifiedStatus
                OS             = $OS
                Publisher      = $Publisher
                Reason         = "Not found in VirusTotal - manual retrieval required"
                FlaggedAt      = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
            }
        }
    }

    # =========================================================
    # HELPER: Ensure-Baseline
    # If baseline file doesn't exist, runs a baseline ES query
    # and saves results. Returns the path to use.
    # =========================================================
    function Ensure-Baseline {
        param(
            [string]$BaselineFile,
            [array]$MustClauses
        )
        if (Test-Path $BaselineFile) {
            Write-Host "  Baseline exists: $BaselineFile" -ForegroundColor DarkGray
            return
        }
        Write-Host "  No baseline found. Building from $baselineStart to $baselineEnd..." -ForegroundColor Yellow
        $hashes = Get-ProcessHashes -MustClauses $MustClauses -FromTime $baselineStart -ToTime $baselineEnd
        Write-Host "  Baseline query returned $($hashes.Count) unique hashes." -ForegroundColor Green
        $hashes | ConvertTo-Json -Depth 5 | Set-Content -Path $BaselineFile
    }

    # =========================================================
    # WORKFLOW DEFINITIONS
    # Each workflow:
    #   1. Ensure baseline exists (build if not)
    #   2. Query recent window
    #   3. Differential (exclude hashes already in baseline)
    #   4. Process each new hash through VT
    # =========================================================

    # --------------------------------------------------
    # WORKFLOW: Unverified Processes
    # S1: src.process.verifiedStatus = 'unverified'
    # ECS: process.code_signature.trusted = false
    # --------------------------------------------------
    if ($Mode -eq "UnverifiedProcs") {
        $baselineFile = "output\unverifiedProcsBaseline.json"
        $mustClauses  = @(
            @{ term  = @{ "event.category" = "process" } },
            @{ term  = @{ "event.type"     = "start" } },
            @{ term  = @{ "process.code_signature.trusted" = $false } },
            @{ exists = @{ field = "process.hash.sha256" } }
        )

        Ensure-Baseline -BaselineFile $baselineFile -MustClauses $mustClauses

        Write-Host "`nQuerying recent unverified processes..." -ForegroundColor DarkCyan
        $recent   = Get-ProcessHashes -MustClauses $mustClauses -FromTime $recentFrom -ToTime $currentTime
        $baseline = Get-BaselineHashes -BaselineFile $baselineFile

        $newProcs = $recent | Where-Object { -not $baseline.Contains($_.Sha256) }
        Write-Host "  Recent: $($recent.Count) | Baseline: $($baseline.Count) | New: $($newProcs.Count)"

        foreach ($proc in $newProcs) {
            Process-NewHash -Sha256 $proc.Sha256 -FileName $proc.Name -SignedStatus $proc.SignedStatus `
                -VerifiedStatus $proc.VerifiedStatus -OS $proc.OS -Publisher $proc.Publisher `
                -BaselineFile $baselineFile
        }
    }

    # --------------------------------------------------
    # WORKFLOW: Unsigned Processes (Windows or Linux)
    # S1: src.process.signedStatus = 'unsigned' and endpoint.os = '$os'
    # ECS: process.code_signature.exists = false + host.os.family
    # --------------------------------------------------
    if ($Mode -in @("UnsignedWin","UnsignedLinux")) {
        $osFamily     = if ($Mode -eq "UnsignedWin") { "windows" } else { "linux" }
        $baselineFile = if ($Mode -eq "UnsignedWin") { "output\unsignedWinProcsBaseline.json" } else { "output\unsignedLinuxProcsBaseline.json" }

        $mustClauses = @(
            @{ term  = @{ "event.category" = "process" } },
            @{ term  = @{ "event.type"     = "start" } },
            @{ term  = @{ "process.code_signature.exists" = $false } },
            @{ term  = @{ "host.os.family" = $osFamily } },
            @{ exists = @{ field = "process.hash.sha256" } }
        )

        Ensure-Baseline -BaselineFile $baselineFile -MustClauses $mustClauses

        Write-Host "`nQuerying recent unsigned $osFamily processes..." -ForegroundColor DarkCyan
        $recent   = Get-ProcessHashes -MustClauses $mustClauses -FromTime $recentFrom -ToTime $currentTime
        $baseline = Get-BaselineHashes -BaselineFile $baselineFile

        $newProcs = $recent | Where-Object { -not $baseline.Contains($_.Sha256) }
        Write-Host "  Recent: $($recent.Count) | Baseline: $($baseline.Count) | New: $($newProcs.Count)"

        foreach ($proc in $newProcs) {
            Process-NewHash -Sha256 $proc.Sha256 -FileName $proc.Name -SignedStatus $proc.SignedStatus `
                -VerifiedStatus $proc.VerifiedStatus -OS $proc.OS -Publisher $proc.Publisher `
                -BaselineFile $baselineFile
        }
    }

    # --------------------------------------------------
    # WORKFLOW: New Windows Publishers
    # S1: signedStatus=signed, verifiedStatus=verified, endpoint.os=windows
    # Step 1: find unique publishers in recent that are NOT in baseline publisher list
    # Step 2: for each new publisher, drill into their specific hashes
    # --------------------------------------------------
    if ($Mode -eq "NewWinPublishers") {
        $svBaselineFile  = "output\signedVerifiedProcsBaseline.json"
        $pubBaselineFile = "output\winPublishersBaseline.json"

        $svMustClauses = @(
            @{ term  = @{ "event.category" = "process" } },
            @{ term  = @{ "event.type"     = "start" } },
            @{ term  = @{ "process.code_signature.exists"  = $true } },
            @{ term  = @{ "process.code_signature.trusted" = $true } },
            @{ term  = @{ "host.os.family" = "windows" } },
            @{ exists = @{ field = "process.hash.sha256" } }
        )

        # Build signed/verified baseline if needed
        Ensure-Baseline -BaselineFile $svBaselineFile -MustClauses $svMustClauses

        # Derive publisher list from the signed/verified baseline
        if (-not (Test-Path $pubBaselineFile)) {
            Write-Host "  Building publisher list from signed/verified baseline..." -ForegroundColor Yellow
            $svData = @()
            try { $svData = @(Get-Content $svBaselineFile | ConvertFrom-Json) } catch {}
            $publishers = ($svData | Where-Object { $_.Publisher } | ForEach-Object { $_.Publisher }) | Sort-Object -Unique
            $publishers | ConvertTo-Json | Set-Content $pubBaselineFile
            Write-Host "  Found $($publishers.Count) baseline publishers." -ForegroundColor Green
        }

        $baselinePublishers = @()
        try { $baselinePublishers = @(Get-Content $pubBaselineFile | ConvertFrom-Json) } catch {}
        $baselinePublisherSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($p in $baselinePublishers) { if ($p) { [void]$baselinePublisherSet.Add($p) } }

        # Query recent publishers
        Write-Host "`nQuerying recent signed/verified Windows publishers..." -ForegroundColor DarkCyan
        $pubQuery = @{
            query = @{
                bool = @{
                    must = @(
                        @{ range = @{ "@timestamp" = @{ gte = $recentFrom; lte = $currentTime } } },
                        @{ term  = @{ "event.category" = "process" } },
                        @{ term  = @{ "event.type"     = "start" } },
                        @{ term  = @{ "process.code_signature.exists"  = $true } },
                        @{ term  = @{ "process.code_signature.trusted" = $true } },
                        @{ term  = @{ "host.os.family" = "windows" } }
                    )
                }
            }
            aggs = @{
                publishers = @{
                    terms = @{ field = "process.code_signature.subject_name"; size = 10000 }
                }
            }
        }

        $pubResp = Invoke-ESQuery -Body $pubQuery -Size 0
        if (-not $pubResp) { Write-Host "  [ERROR] Publisher query failed." -ForegroundColor Red; return }

        $recentPublishers = $pubResp.aggregations.publishers.buckets | ForEach-Object { $_.key }
        $newPublishers    = $recentPublishers | Where-Object { -not $baselinePublisherSet.Contains($_) }

        Write-Host "  Recent publishers: $($recentPublishers.Count) | Baseline: $($baselinePublisherSet.Count) | New: $($newPublishers.Count)"
        if ($newPublishers.Count -eq 0) { Write-Host "  No new publishers found." -ForegroundColor Green; return }

        Write-Host "`n--- New Publishers ---" -ForegroundColor DarkCyan
        $newPublishers | ForEach-Object { Write-Host "  - $_" }

        # Drill into each new publisher's hashes
        foreach ($publisher in $newPublishers) {
            Write-Host "`n  [Publisher] $publisher" -ForegroundColor Magenta
            $pubHashClauses = $svMustClauses + @(
                @{ term = @{ "process.code_signature.subject_name" = $publisher } }
            )
            $pubHashes = Get-ProcessHashes -MustClauses $pubHashClauses -FromTime $recentFrom -ToTime $currentTime -Size 1000

            $svBaseline = Get-BaselineHashes -BaselineFile $svBaselineFile
            $newHashes  = $pubHashes | Where-Object { -not $svBaseline.Contains($_.Sha256) }
            Write-Host "  Hashes for this publisher: $($pubHashes.Count) | Not in baseline: $($newHashes.Count)"

            foreach ($proc in $newHashes) {
                Process-NewHash -Sha256 $proc.Sha256 -FileName $proc.Name -SignedStatus $proc.SignedStatus `
                    -VerifiedStatus $proc.VerifiedStatus -OS $proc.OS -Publisher $proc.Publisher `
                    -BaselineFile $svBaselineFile
            }
        }
    }

    # --------------------------------------------------
    # WORKFLOW: Drivers (not marked benign/clean)
    # S1: driver.loadVerdict not in (BENIGN, EXCLUDED)
    # ECS: event.category=driver + event.action=load
    #      exclude where process.code_signature.trusted=true AND no detections
    # Note: Elastic Endpoint stores driver load events; filter out known-good
    # by excluding trusted+signed with no VT hits (handled in Process-NewHash)
    # --------------------------------------------------
    if ($Mode -eq "Drivers") {
        $baselineFile = "output\driversBaseline.json"
        $mustClauses  = @(
            @{ term  = @{ "event.category" = "driver" } },
            @{ term  = @{ "event.action"   = "load" } },
            @{ exists = @{ field = "process.hash.sha256" } }
        )
        # Exclude drivers that are signed and trusted (equivalent of BENIGN/EXCLUDED)
        $driverQuery = @{
            query = @{
                bool = @{
                    must     = @(
                        @{ range = @{ "@timestamp" = @{ gte = $recentFrom; lte = $currentTime } } }
                    ) + $mustClauses
                    must_not = @(
                        @{ bool = @{ must = @(
                            @{ term = @{ "process.code_signature.exists"  = $true } },
                            @{ term = @{ "process.code_signature.trusted" = $true } }
                        ) } }
                    )
                }
            }
            aggs = @{
                by_hash = @{
                    terms = @{ field = "process.hash.sha256"; size = 10000; min_doc_count = 1 }
                    aggs  = @{
                        svc_name  = @{ terms = @{ field = "process.name";                       size = 1 } }
                        signed    = @{ terms = @{ field = "process.code_signature.exists";       size = 1 } }
                        verified  = @{ terms = @{ field = "process.code_signature.trusted";      size = 1 } }
                        publisher = @{ terms = @{ field = "process.code_signature.subject_name"; size = 1 } }
                    }
                }
            }
        }

        # Build baseline using same filter if not present
        if (-not (Test-Path $baselineFile)) {
            Write-Host "  No driver baseline found. Building from $baselineStart to $baselineEnd..." -ForegroundColor Yellow
            $blQuery = $driverQuery.Clone()
            $blQuery.query.bool.must[0] = @{ range = @{ "@timestamp" = @{ gte = $baselineStart; lte = $baselineEnd } } }
            $blResp = Invoke-ESQuery -Body $blQuery -Size 0
            if ($blResp) {
                $blHashes = @()
                foreach ($b in $blResp.aggregations.by_hash.buckets) {
                    $blHashes += @{
                        Sha256    = $b.key
                        Name      = ($b.svc_name.buckets  | Select-Object -First 1).key
                        Publisher = ($b.publisher.buckets | Select-Object -First 1).key
                    }
                }
                $blHashes | ConvertTo-Json -Depth 5 | Set-Content $baselineFile
                Write-Host "  Driver baseline built with $($blHashes.Count) entries." -ForegroundColor Green
            }
        }

        Write-Host "`nQuerying recent non-benign driver loads..." -ForegroundColor DarkCyan
        $resp = Invoke-ESQuery -Body $driverQuery -Size 0
        if (-not $resp) { return }

        $baseline = Get-BaselineHashes -BaselineFile $baselineFile
        $newDrivers = @()
        foreach ($b in $resp.aggregations.by_hash.buckets) {
            if (-not $baseline.Contains($b.key)) {
                $newDrivers += @{
                    Sha256    = $b.key
                    Name      = ($b.svc_name.buckets  | Select-Object -First 1).key
                    Signed    = ($b.signed.buckets     | Select-Object -First 1).key_as_string
                    Verified  = ($b.verified.buckets   | Select-Object -First 1).key_as_string
                    Publisher = ($b.publisher.buckets  | Select-Object -First 1).key
                }
            }
        }

        Write-Host "  Recent drivers: $($resp.aggregations.by_hash.buckets.Count) | Baseline: $($baseline.Count) | New: $($newDrivers.Count)"

        foreach ($driver in $newDrivers) {
            Process-NewHash -Sha256 $driver.Sha256 -FileName $driver.Name -SignedStatus $driver.Signed `
                -VerifiedStatus $driver.Verified -OS "windows" -Publisher $driver.Publisher `
                -BaselineFile $baselineFile
        }
    }

    # --------------------------------------------------
    # WORKFLOW: Specific Process
    # S1: query by src.process.name, check all four baselines for SHA256
    # ECS: query by process.name, check all four baseline files
    # --------------------------------------------------
    if ($Mode -eq "SpecificProc") {
        Write-Host "`nQuerying process: $ProcName" -ForegroundColor DarkCyan

        $mustClauses = @(
            @{ term  = @{ "event.category" = "process" } },
            @{ term  = @{ "event.type"     = "start" } },
            @{ term  = @{ "process.name"   = $ProcName } },
            @{ exists = @{ field = "process.hash.sha256" } }
        )

        $recent = Get-ProcessHashes -MustClauses $mustClauses -FromTime $recentFrom -ToTime $currentTime

        # Load all four baselines into one combined hash set
        $allBaselineFiles = @(
            "output\unsignedWinProcsBaseline.json",
            "output\unsignedLinuxProcsBaseline.json",
            "output\unverifiedProcsBaseline.json",
            "output\signedVerifiedProcsBaseline.json"
        )
        $combinedBaseline = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($f in $allBaselineFiles) {
            $hashes = Get-BaselineHashes -BaselineFile $f
            foreach ($h in $hashes) { [void]$combinedBaseline.Add($h) }
        }

        $newProcs = $recent | Where-Object { -not $combinedBaseline.Contains($_.Sha256) }
        Write-Host "  Found $($recent.Count) hashes for $ProcName | In baseline: $($recent.Count - $newProcs.Count) | New: $($newProcs.Count)"

        foreach ($proc in $newProcs) {
            # Route to the correct baseline based on signature status
            if ($proc.SignedStatus -eq "true" -and $proc.VerifiedStatus -eq "true") {
                $targetBaseline = "output\signedVerifiedProcsBaseline.json"
            } elseif ($proc.VerifiedStatus -eq "false" -and $proc.SignedStatus -eq "true") {
                $targetBaseline = "output\unverifiedProcsBaseline.json"
            } elseif ($proc.OS -eq "windows") {
                $targetBaseline = "output\unsignedWinProcsBaseline.json"
            } else {
                $targetBaseline = "output\unsignedLinuxProcsBaseline.json"
            }

            Process-NewHash -Sha256 $proc.Sha256 -FileName $proc.Name -SignedStatus $proc.SignedStatus `
                -VerifiedStatus $proc.VerifiedStatus -OS $proc.OS -Publisher $proc.Publisher `
                -BaselineFile $targetBaseline
        }
    }

    Write-Host "`n[Done] Mode: $Mode complete." -ForegroundColor Green
}

Export-ModuleMember -Function Get-ElasticProcessBaseline