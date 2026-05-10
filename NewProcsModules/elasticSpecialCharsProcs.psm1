function Get-ElasticSpecialCharsProcs {
    <#
    .SYNOPSIS
        Elastic equivalent of Get-SpecialCharsProcs.

        Hunts for processes whose code signing publisher name contains
        non-ASCII (Unicode) characters - a classic masquerade/typosquatting
        indicator. Legitimate publishers do not use Unicode in signing certs.

        Workflow:
          1. Query recent process starts where publisher contains non-ASCII
          2. Diff against unverified + signedVerified baselines (SHA256)
          3. For each new hash: try VT enrichment
          4. If VT 404: log to pendingManualReview.json for file retrieval
    #>

    param(
        [int]$QueryDays = -3
    )

    # --- API SETUP ---
    $esUrl  = Get-Secret -Name 'Elastic_URL'  -AsPlainText
    $esUser = Get-Secret -Name 'Elastic_User' -AsPlainText
    $esPass = Get-Secret -Name 'Elastic_Pass' -AsPlainText
    $vtKey  = $null
    try { $vtKey = (Get-Secret -Name 'VT_API_Key_1' -AsPlainText -ErrorAction Stop).Trim() } catch {}

    $b64Auth  = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${esUser}:${esPass}"))
    $esHeaders = @{ 'Authorization' = "Basic $b64Auth"; 'Content-Type' = 'application/json' }
    $vtHeaders  = @{ 'x-apikey' = $vtKey; 'Content-Type' = 'application/json' }

    $eventsIndex = "logs-*,winlogbeat-*,filebeat-*,endgame-*"

    if (-not (Test-Path "output")) { New-Item -Path "output" -ItemType Directory | Out-Null }

    $now         = Get-Date
    $currentTime = $now.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $fromTime    = $now.AddDays($QueryDays).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

    Write-Host "`n[Special Chars Publisher Hunt]" -ForegroundColor DarkCyan
    Write-Host "Window: $fromTime -> $currentTime"
    Write-Host "Looking for non-ASCII characters in process.code_signature.subject_name`n"

    # =========================================================
    # HELPER: Invoke-ESQuery
    # =========================================================
    function Invoke-ESQuery {
        param([hashtable]$Body)
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
    # HELPER: Get-BaselineHashes
    # Returns a HashSet of SHA256s from a baseline JSON file
    # =========================================================
    function Get-BaselineHashes {
        param([string]$Path)
        $set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        if (Test-Path $Path) {
            try {
                $data = Get-Content $Path | ConvertFrom-Json
                foreach ($entry in $data) {
                    # Support both new Elastic baseline format (Sha256 property)
                    # and old S1 baseline format (value array, SHA256 at index 2)
                    if ($entry.Sha256)       { [void]$set.Add($entry.Sha256) }
                    elseif ($entry.value[2]) { [void]$set.Add($entry.value[2]) }
                }
            } catch {
                Write-Host "  [WARN] Could not read baseline: $Path" -ForegroundColor Yellow
            }
        }
        return $set
    }

    # =========================================================
    # HELPER: Add-ToBaseline
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
    # =========================================================
    $script:VTLastCall = [DateTime]::MinValue
    function Invoke-VTLookup {
        param([string]$Sha256)
        if ([string]::IsNullOrWhiteSpace($vtKey)) {
            Write-Host "  [VT] No VT API key - skipping." -ForegroundColor DarkGray
            return $null
        }
        $waitMs = ($script:VTLastCall.AddSeconds(15) - [DateTime]::UtcNow).TotalMilliseconds
        if ($waitMs -gt 0) {
            Write-Host "  [VT] Cooling down $([Math]::Round($waitMs/1000,1))s..." -ForegroundColor DarkGray
            Start-Sleep -Milliseconds ([Math]::Ceiling($waitMs))
        }
        $script:VTLastCall = [DateTime]::UtcNow
        try {
            return Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files/$Sha256" `
                                     -Headers $vtHeaders -Method Get -ErrorAction Stop
        } catch {
            $code = $null
            try { $code = $_.Exception.Response.StatusCode.value__ } catch {}
            if     ($code -eq 404) { Write-Host "  [VT] $Sha256 not found in VirusTotal." -ForegroundColor Yellow }
            elseif ($code -eq 429) { Write-Host "  [VT] Rate limited." -ForegroundColor Red }
            else                   { Write-Host "  [VT] Error $code - $($_.Exception.Message)" -ForegroundColor Red }
            return $null
        }
    }

    # =========================================================
    # PHASE 1: QUERY - processes with non-ASCII publisher names
    #
    # S1 query: src.process.publisher matches '[^\x00-\x7F]'
    #
    # Elastic equivalent: use a script query to check whether
    # the publisher field contains any character with code > 127.
    # This is the only reliable way to detect Unicode in a field
    # value in Elasticsearch without storing a separate flag.
    # =========================================================
    Write-Host "Phase 1: Querying for non-ASCII publisher names..." -ForegroundColor DarkCyan

    $esQuery = @{
        size = 0
        query = @{
            bool = @{
                must = @(
                    @{ range = @{ "@timestamp" = @{ gte = $fromTime; lte = $currentTime } } },
                    @{ term  = @{ "event.category" = "process" } },
                    @{ term  = @{ "event.type"     = "start" } },
                    @{ exists = @{ field = "process.code_signature.subject_name" } },
                    @{ exists = @{ field = "process.hash.sha256" } },
                    @{
                        # Script query: publisher contains at least one char with codepoint > 127
                        script = @{
                            script = @{
                                source = @"
def pub = doc['process.code_signature.subject_name.keyword'].size() > 0
    ? doc['process.code_signature.subject_name.keyword'].value
    : null;
if (pub == null) return false;
for (int i = 0; i < pub.length(); i++) {
    if ((int) pub.charAt(i) > 127) return true;
}
return false;
"@
                                lang   = "painless"
                            }
                        }
                    }
                )
            }
        }
        aggs = @{
            by_hash = @{
                terms = @{ field = "process.hash.sha256"; size = 10000; min_doc_count = 1 }
                aggs  = @{
                    proc_name  = @{ terms = @{ field = "process.name";                        size = 1 } }
                    publisher  = @{ terms = @{ field = "process.code_signature.subject_name"; size = 1 } }
                    verified   = @{ terms = @{ field = "process.code_signature.trusted";      size = 1 } }
                    signed     = @{ terms = @{ field = "process.code_signature.exists";       size = 1 } }
                    os_family  = @{ terms = @{ field = "host.os.family";                      size = 1 } }
                }
            }
        }
    }

    $resp = Invoke-ESQuery -Body $esQuery
    if (-not $resp) { Write-Host "Query failed. Exiting." -ForegroundColor Red; return }

    $buckets = $resp.aggregations.by_hash.buckets
    Write-Host "  Found $($buckets.Count) unique hashes with non-ASCII publisher names." -ForegroundColor $(if ($buckets.Count -gt 0) { "Yellow" } else { "Green" })

    if ($buckets.Count -eq 0) {
        Write-Host "  No suspicious publishers found in the last $([Math]::Abs($QueryDays)) days." -ForegroundColor Green
        return
    }

    # Map buckets to structured objects
    $recentProcs = $buckets | ForEach-Object {
        [PSCustomObject]@{
            Sha256         = $_.key
            Name           = ($_.proc_name.buckets  | Select-Object -First 1).key
            Publisher      = ($_.publisher.buckets  | Select-Object -First 1).key
            VerifiedStatus = ($_.verified.buckets   | Select-Object -First 1).key_as_string
            SignedStatus   = ($_.signed.buckets     | Select-Object -First 1).key_as_string
            OS             = ($_.os_family.buckets  | Select-Object -First 1).key
            Count          = $_.doc_count
        }
    } | Sort-Object Count

    # Print what was found - show the suspicious publisher names clearly
    Write-Host "`n  --- Processes with Non-ASCII Publisher Names ---" -ForegroundColor Yellow
    $recentProcs | ForEach-Object {
        Write-Host "  [$($_.Count)x] $($_.Name)" -ForegroundColor Yellow
        Write-Host "       Publisher : $($_.Publisher)" -ForegroundColor Red
        Write-Host "       SHA256    : $($_.Sha256)"
        Write-Host "       Verified  : $($_.VerifiedStatus) | Signed: $($_.SignedStatus) | OS: $($_.OS)"
    }

    # =========================================================
    # PHASE 2: DIFFERENTIAL against both baselines
    # S1 checks unverifiedProcsBaseline + signedVerifiedProcsBaseline
    # =========================================================
    Write-Host "`nPhase 2: Diffing against baselines..." -ForegroundColor DarkCyan

    $unverifiedBaseline   = Get-BaselineHashes -Path "output\unverifiedProcsBaseline.json"
    $signedVerifBaseline  = Get-BaselineHashes -Path "output\signedVerifiedProcsBaseline.json"

    $combinedBaseline = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($h in $unverifiedBaseline)  { [void]$combinedBaseline.Add($h) }
    foreach ($h in $signedVerifBaseline) { [void]$combinedBaseline.Add($h) }

    $newProcs = $recentProcs | Where-Object { -not $combinedBaseline.Contains($_.Sha256) }

    Write-Host "  Recent: $($recentProcs.Count) | Already baselined: $($recentProcs.Count - $newProcs.Count) | New: $($newProcs.Count)"

    if ($newProcs.Count -eq 0) {
        Write-Host "  All hashes already in baseline - nothing new to enrich." -ForegroundColor Green
        return
    }

    Write-Host "`n  --- New Hashes Not In Baseline ---" -ForegroundColor DarkCyan
    $newProcs | ForEach-Object {
        Write-Host "  $($_.Name) | $($_.Publisher) | $($_.Sha256)" -ForegroundColor DarkCyan
    }

    # =========================================================
    # PHASE 3: VT ENRICHMENT for each new hash
    # Route to the correct baseline file based on verified status
    # =========================================================
    Write-Host "`nPhase 3: VT enrichment for $($newProcs.Count) new hash(es)..." -ForegroundColor DarkCyan

    foreach ($proc in $newProcs) {
        Write-Host "`n  [$($proc.Name)]" -ForegroundColor Magenta
        Write-Host "  Publisher : $($proc.Publisher)" -ForegroundColor Red
        Write-Host "  SHA256    : $($proc.Sha256)"
        Write-Host "  Verified  : $($proc.VerifiedStatus) | Signed: $($proc.SignedStatus)"

        # Route to correct baseline - mirrors S1 logic
        $targetBaseline = if ($proc.VerifiedStatus -eq "false") {
            "output\unverifiedProcsBaseline.json"
        } else {
            "output\signedVerifiedProcsBaseline.json"
        }

        $vtResult = Invoke-VTLookup -Sha256 $proc.Sha256

        if ($vtResult) {
            $malicious   = $vtResult.data.attributes.last_analysis_stats.malicious
            $suspicious  = $vtResult.data.attributes.last_analysis_stats.suspicious
            $undetected  = $vtResult.data.attributes.last_analysis_stats.undetected
            $harmless    = $vtResult.data.attributes.last_analysis_stats.harmless
            $totalEngines = $malicious + $suspicious + $undetected + $harmless
            $vtLabel     = $vtResult.data.attributes.popular_threat_classification.suggested_threat_label

            if ($malicious -gt 5) {
                $color   = "Red"
                $verdict = "MALICIOUS ($malicious/$totalEngines)"
                $targetBaseline = "output\maliciousProcsBaseline.json"
            } elseif ($malicious -gt 0 -or $suspicious -gt 3) {
                $color   = "Yellow"
                $verdict = "SUSPICIOUS ($malicious malicious, $suspicious suspicious / $totalEngines)"
            } else {
                $color   = "Green"
                $verdict = "Clean ($malicious/$totalEngines)"
            }

            Write-Host "  [VT] $verdict" -ForegroundColor $color
            if ($vtLabel) { Write-Host "  [VT] Threat label: $vtLabel" -ForegroundColor $color }

            # Flag even clean results - a clean VT score on a Unicode-publisher
            # binary is still worth noting since legitimate publishers don't do this
            if ($color -eq "Green") {
                Write-Host "  [!] VT clean but non-ASCII publisher is still anomalous - review manually." -ForegroundColor Yellow
            }

            Add-ToBaseline -BaselineFile $targetBaseline -Entry @{
                Name           = $proc.Name
                Sha256         = $proc.Sha256
                Publisher      = $proc.Publisher
                VerifiedStatus = $proc.VerifiedStatus
                SignedStatus   = $proc.SignedStatus
                OS             = $proc.OS
                VTMalicious    = $malicious
                VTSuspicious   = $suspicious
                VTTotal        = $totalEngines
                VTLabel        = $vtLabel
                HuntSource     = "SpecialCharsPublisher"
                AddedAt        = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
            }
            Write-Host "  [+] Written to $targetBaseline" -ForegroundColor DarkGray

        } else {
            # VT miss - log for manual retrieval
            Write-Host "  [!] NOT IN VIRUSTOTAL - manual file retrieval needed." -ForegroundColor Red
            Write-Host "      To retrieve via Elastic Endpoint:" -ForegroundColor DarkGray
            Write-Host "      POST /api/endpoint/action/get-file" -ForegroundColor DarkGray
            Write-Host "      Body: { ""endpoint_ids"": [""<agent-id>""], ""parameters"": { ""path"": ""<full-path>"" } }" -ForegroundColor DarkGray

            Add-ToBaseline -BaselineFile "output\pendingManualReview.json" -Entry @{
                Name           = $proc.Name
                Sha256         = $proc.Sha256
                Publisher      = $proc.Publisher
                VerifiedStatus = $proc.VerifiedStatus
                SignedStatus   = $proc.SignedStatus
                OS             = $proc.OS
                Reason         = "Non-ASCII publisher - not found in VirusTotal"
                HuntSource     = "SpecialCharsPublisher"
                FlaggedAt      = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
            }
        }
    }

    Write-Host "`n[Done] Special chars publisher hunt complete." -ForegroundColor Green
}

Export-ModuleMember -Function Get-ElasticSpecialCharsProcs