function Push-DetonationLogsToElastic {
    <#
    .SYNOPSIS
        Imports a directory of saved detonation NDJSON files into a per-session
        replay index on Elasticsearch via the _bulk API.

    .DESCRIPTION
        Walks $SourceDir for *.ndjson files, parses each line as a flat ECS
        document, enriches it with replay.* tracking fields, and pushes it to
        a deterministically-named per-session replay index using the
        Elasticsearch _bulk API (application/x-ndjson).

        Designed for offline analysis workflows: pull logs once from the SIEM
        via Get-ElasticDetonationLogs (HTTP) or Save-TorchElasticDetonationLogs
        (SSH), archive them to disk, then replay the entire corpus into a
        scratch Elastic cluster for Kibana / EQL / Sigma exploration without
        touching the original SOC stack.

    .PARAMETER SourceDir
        Directory containing one or more *.ndjson files. Recursed top-level
        only (matches the layout that Get-ElasticDetonationLogs produces).

    .PARAMETER Label
        Short identifier injected into the replay index name and the
        replay.label field on every document. Defaults to the source directory
        name with the trailing _YYYY-MM-DD_HH-MM_to_HH-MMUTC suffix stripped.

    .PARAMETER IndexPrefix
        Index name prefix. Default 'detonation-replay'. Do NOT use 'logs-*' or
        any built-in data-stream prefix - those are claimed by index templates
        that reject ad-hoc writes.

    .PARAMETER IndexDate
        yyyymmdd date suffix for the index. Default today UTC.

    .PARAMETER BatchSize
        Max documents per _bulk request. Flush also triggers when the staged
        body exceeds ~5 MB. Default 500.

    .PARAMETER DryRun
        Parse + count + tag everything but skip the POST. Useful for sanity-
        checking corpus shape before sending bytes.

    .PARAMETER VaultUrl / VaultUser / VaultPass / VaultApiKey
        Names of the SecretManagement vault entries that hold the connection
        details. Defaults match Get-ElasticDetonationLogs.

    .NOTES
        Auth precedence matches Get-ElasticDetonationLogs:
          1. ApiKey  -  vault secret Elastic_ApiKey  (preferred)
          2. Basic   -  vault secrets Elastic_User + Elastic_Pass

        Bulk contract gotchas this module handles for you:
          * Content-Type forced to application/x-ndjson (not application/json)
          * Body terminated with a single LF (\n) - mandatory record separator
          * All joins are LF, never CRLF (Out-File default would corrupt body)
          * Body is encoded as UTF-8 byte[] before send to dodge PS string
            re-encoding and to keep the trailing \n intact
          * Per-doc errors surface via response.items[] (HTTP 200 != success);
            this function walks them and reports the first 3 unique reasons

        Corpus shape handled (per investigation):
          * Flat ECS docs (no _source wrapper) - SO 3.0 SSH pulls + vanilla
            ES HTTP pulls both emit the inner document only
          * _source-wrapped docs - if the line happens to be an ES search-API
            response envelope, the _source is unwrapped automatically
          * UTF-8 BOM tolerance - StreamReader auto-detects so AndySliver-
            style BOM-prefixed files parse cleanly
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourceDir,

        [string]$Label,

        [string]$IndexPrefix = 'detonation-replay',

        [string]$IndexDate,

        [int]$BatchSize = 500,

        [switch]$DryRun,

        [string]$VaultUrl    = 'Elastic_URL',
        [string]$VaultUser   = 'Elastic_User',
        [string]$VaultPass   = 'Elastic_Pass',
        [string]$VaultApiKey = 'Elastic_ApiKey'
    )

    # --- TLS / cert bypass (self-signed lab clusters) ---
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    }
    $restArgs = if ($PSVersionTable.PSVersion.Major -ge 6) { @{ SkipCertificateCheck = $true } } else { @{} }

    # --- VALIDATE SOURCE ---
    if (-not (Test-Path -LiteralPath $SourceDir -PathType Container)) {
        throw "SourceDir not found or not a directory: $SourceDir"
    }
    $SourceDir = (Resolve-Path -LiteralPath $SourceDir).Path

    # --- AUTH ---
    # Pre-init so .Trim() on a null Get-Secret result does not throw NullReferenceException.
    $esUrl = $null; $esApiKey = $null; $esUser = $null; $esPass = $null
    try { $esUrl    = (Get-Secret -Name $VaultUrl    -AsPlainText -ErrorAction Stop).Trim().TrimEnd('/') } catch {}
    try { $esApiKey = (Get-Secret -Name $VaultApiKey -AsPlainText -ErrorAction Stop).Trim() } catch {}
    try { $esUser   = (Get-Secret -Name $VaultUser   -AsPlainText -ErrorAction Stop).Trim() } catch {}
    try { $esPass   = (Get-Secret -Name $VaultPass   -AsPlainText -ErrorAction Stop).Trim() } catch {}

    if ([string]::IsNullOrWhiteSpace($esUrl)) {
        throw "Vault secret '$VaultUrl' is empty or missing. Set-Secret -Name $VaultUrl -Secret 'http://host:9200'"
    }
    if ($esUrl -notmatch '^https?://') { $esUrl = "https://$esUrl" }

    $authMode = ''
    $esHdr    = $null
    if (-not [string]::IsNullOrWhiteSpace($esApiKey)) {
        $apiKeyEncoded = $esApiKey
        if ($esApiKey -match '^[^:]+:[^:]+$' -and $esApiKey -notmatch '=$') {
            $apiKeyEncoded = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($esApiKey))
        }
        $esHdr = @{ 'Authorization' = "ApiKey $apiKeyEncoded" }
        $authMode = 'ApiKey'
    } elseif (-not [string]::IsNullOrWhiteSpace($esUser) -and -not [string]::IsNullOrWhiteSpace($esPass)) {
        $b64   = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${esUser}:${esPass}"))
        $esHdr = @{ 'Authorization' = "Basic $b64" }
        $authMode = "Basic ($esUser)"
    } else {
        throw "No Elastic credentials in vault. Set ONE of: '$VaultApiKey' OR ('$VaultUser' AND '$VaultPass')."
    }

    # --- DERIVE LABEL ---
    if ([string]::IsNullOrWhiteSpace($Label)) {
        $dirName = Split-Path -Path $SourceDir -Leaf
        # Strip trailing _YYYY-MM-DD_HH-MM_to_HH-MMUTC pattern
        $Label = $dirName -replace '_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}_to_\d{2}-\d{2}UTC$', ''
    }
    # Sanitize for index name: lowercase + hyphens for invalid chars
    $labelSafe = ($Label.ToLower() -replace '[^a-z0-9-]', '-') -replace '-+', '-'
    $labelSafe = $labelSafe.Trim('-')
    if ([string]::IsNullOrWhiteSpace($labelSafe)) { $labelSafe = 'unlabeled' }

    if ([string]::IsNullOrWhiteSpace($IndexDate)) {
        $IndexDate = (Get-Date).ToUniversalTime().ToString('yyyyMMdd')
    }

    $indexPrefixSafe = ($IndexPrefix.ToLower() -replace '[^a-z0-9-]', '-') -replace '-+', '-'
    $indexPrefixSafe = $indexPrefixSafe.Trim('-')
    $targetIndex = "$indexPrefixSafe-$labelSafe-$IndexDate"

    # --- BANNER ---
    Write-Host ""
    Write-Host "==== Push-DetonationLogsToElastic ====" -ForegroundColor Cyan
    Write-Host "  Source  : $SourceDir"                    -ForegroundColor DarkGray
    Write-Host "  Label   : $Label"                        -ForegroundColor DarkGray
    Write-Host "  Index   : $targetIndex"                  -ForegroundColor Cyan
    Write-Host "  URL     : $esUrl"                        -ForegroundColor DarkGray
    Write-Host "  Auth    : $authMode"                     -ForegroundColor DarkGray
    Write-Host "  Batch   : $BatchSize docs / 5 MB max"    -ForegroundColor DarkGray
    Write-Host "  DryRun  : $($DryRun.IsPresent)"          -ForegroundColor DarkGray

    # --- PRE-FLIGHT _cluster/health ---
    if (-not $DryRun) {
        Write-Host ""
        Write-Host "[Pre-flight] Checking Elasticsearch connectivity..." -ForegroundColor DarkCyan
        try {
            $health = Invoke-RestMethod -Uri "$esUrl/_cluster/health" -Headers $esHdr -Method Get @restArgs -ErrorAction Stop
            Write-Host "  Cluster : $($health.cluster_name)  Status: $($health.status)  Nodes: $($health.number_of_nodes)" -ForegroundColor Green
        } catch {
            $hint = ''
            if ($_.Exception.Message -match 'SSL|certificate|trust') {
                $hint = "  (hint: -SkipCertificateCheck is already on - check that the host is reachable and the port is 9200, not 5601)"
            }
            throw "Cannot reach Elasticsearch at $esUrl - $($_.Exception.Message)$hint"
        }
    }

    # --- ENUMERATE FILES ---
    $ndjsonFiles = @(Get-ChildItem -LiteralPath $SourceDir -Filter '*.ndjson' -File -ErrorAction SilentlyContinue)
    if ($ndjsonFiles.Count -eq 0) {
        Write-Host ""
        Write-Host "[WARN] No *.ndjson files found in $SourceDir" -ForegroundColor Yellow
        return [PSCustomObject]@{
            Index         = $targetIndex
            Sent          = 0
            Accepted      = 0
            Rejected      = 0
            BulkRequests  = 0
            DurationMs    = 0
            Failures      = @()
        }
    }

    Write-Host ""
    Write-Host "[Import] $($ndjsonFiles.Count) NDJSON file(s) found." -ForegroundColor Cyan

    # --- STATE ---
    $stopwatch    = [System.Diagnostics.Stopwatch]::StartNew()
    $importedAt   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $totalRead    = 0
    $totalParsed  = 0
    $totalSent    = 0
    $totalOk      = 0
    $totalFail    = 0
    $bulkCount    = 0
    $failureReasons = [System.Collections.Generic.List[string]]::new()
    $firstFailedDoc = $null

    # Batch buffer: list of NDJSON line strings (action + source pairs)
    $batchLines = [System.Collections.Generic.List[string]]::new()
    $batchDocs  = 0
    $batchBytes = 0
    $sizeFlushBytes = 5 * 1024 * 1024  # 5 MB threshold

    $bulkUri = "$esUrl/$targetIndex/_bulk"

    # --- BULK FLUSH HELPER ---
    # Inline function rather than a closure: PS scope rules make $script:
    # mutation from a captured scriptblock unreliable in modules. The caller
    # adds returned counters to its own totals.
    function Invoke-LocalFlush {
        param(
            [System.Collections.Generic.List[string]]$Lines,
            [string]$BulkUri,
            [hashtable]$Hdr,
            [hashtable]$RestArgs,
            [bool]$IsDryRun,
            [int]$DocCount
        )
        if ($DocCount -le 0) {
            return [PSCustomObject]@{ Ok = 0; Fail = 0; Reasons = @(); Threw = $false; ThrewMsg = $null }
        }
        if ($IsDryRun) {
            return [PSCustomObject]@{ Ok = $DocCount; Fail = 0; Reasons = @(); Threw = $false; ThrewMsg = $null }
        }
        $body  = ($Lines -join "`n") + "`n"
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($body)
        $headers = @{ 'Authorization' = $Hdr['Authorization'] }
        try {
            $resp = Invoke-RestMethod -Uri $BulkUri -Headers $headers -Method Post `
                       -Body $bytes -ContentType 'application/x-ndjson' @RestArgs -ErrorAction Stop
        } catch {
            $status = $null
            try { $status = $_.Exception.Response.StatusCode.value__ } catch {}
            $errBody = $null
            try {
                if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $errBody = $_.ErrorDetails.Message }
            } catch {}
            if ($errBody -and $errBody.Length -gt 400) { $errBody = $errBody.Substring(0, 400) + '...' }
            return [PSCustomObject]@{
                Ok       = 0
                Fail     = $DocCount
                Reasons  = @()
                Threw    = $true
                ThrewMsg = "Bulk POST failed (HTTP $status): $($_.Exception.Message)`n$errBody"
            }
        }

        $ok      = 0
        $fail    = 0
        $reasons = [System.Collections.Generic.List[string]]::new()
        if ($resp -and $resp.items) {
            foreach ($item in $resp.items) {
                $entry = $item.index
                if (-not $entry) { $entry = $item.create }
                if (-not $entry) { continue }
                if ($entry.error) {
                    $fail++
                    $reason = "$($entry.error.type): $($entry.error.reason)"
                    if ($reason.Length -gt 200) { $reason = $reason.Substring(0, 200) + '...' }
                    [void]$reasons.Add($reason)
                } else {
                    $ok++
                }
            }
        } else {
            if ($resp.errors) { $fail = $DocCount } else { $ok = $DocCount }
        }
        return [PSCustomObject]@{
            Ok       = $ok
            Fail     = $fail
            Reasons  = $reasons
            Threw    = $false
            ThrewMsg = $null
        }
    }

    # --- WALK FILES ---
    foreach ($file in $ndjsonFiles) {
        $fileName    = $file.Name
        $fileRead    = 0
        $fileParsed  = 0
        $fileFail    = 0

        # StreamReader auto-detects BOM (handles AndySliver UTF-8 BOM cleanly).
        $reader = $null
        try {
            $reader = [System.IO.StreamReader]::new($file.FullName, [System.Text.Encoding]::UTF8, $true)
        } catch {
            Write-Host "  [WARN] Cannot open $($file.FullName) - $($_.Exception.Message)" -ForegroundColor Yellow
            continue
        }

        try {
            while (-not $reader.EndOfStream) {
                $line = $reader.ReadLine()
                $fileRead++
                if ([string]::IsNullOrWhiteSpace($line)) { continue }
                $line = $line.Trim()
                if (-not $line.StartsWith('{')) { continue }  # Skip non-JSON noise lines

                $doc = $null
                try {
                    $doc = $line | ConvertFrom-Json -ErrorAction Stop
                } catch {
                    $fileFail++
                    continue
                }
                if (-not $doc) { continue }

                # Auto-unwrap ES search-API _source envelope
                if ($doc.PSObject.Properties.Name -contains '_source' -and $doc._source) {
                    $doc = $doc._source
                }

                # --- ENRICH (preserve @timestamp; never overwrite) ---
                # tags
                $existingTags = @()
                if ($doc.PSObject.Properties.Name -contains 'tags' -and $doc.tags) {
                    $existingTags = @($doc.tags)
                }
                $newTags = @($existingTags)
                if ($newTags -notcontains 'detonation-replay') { $newTags += 'detonation-replay' }
                if ($newTags -notcontains $Label) { $newTags += $Label }
                if ($doc.PSObject.Properties.Name -contains 'tags') {
                    $doc.tags = $newTags
                } else {
                    Add-Member -InputObject $doc -NotePropertyName 'tags' -NotePropertyValue $newTags -Force
                }

                # replay.* block
                $replayObj = [PSCustomObject]@{
                    source_file = $fileName
                    imported_at = $importedAt
                    label       = $Label
                }
                if ($doc.PSObject.Properties.Name -contains 'replay') {
                    $doc.replay = $replayObj
                } else {
                    Add-Member -InputObject $doc -NotePropertyName 'replay' -NotePropertyValue $replayObj -Force
                }

                # --- SERIALIZE for bulk body ---
                $docJson = $doc | ConvertTo-Json -Depth 30 -Compress
                # Defensive: kill any embedded raw newlines (would corrupt ndjson framing)
                if ($docJson -match "[`r`n]") {
                    $docJson = $docJson -replace "`r", '' -replace "`n", ''
                }

                [void]$batchLines.Add('{"index":{}}')
                [void]$batchLines.Add($docJson)
                $batchDocs++
                $batchBytes += $docJson.Length + 14  # ~size estimate

                $fileParsed++

                # --- FLUSH on threshold ---
                if ($batchDocs -ge $BatchSize -or $batchBytes -ge $sizeFlushBytes) {
                    $result = Invoke-LocalFlush -Lines $batchLines -BulkUri $bulkUri -Hdr $esHdr `
                                  -RestArgs $restArgs -IsDryRun $DryRun.IsPresent -DocCount $batchDocs
                    if ($result.Threw) {
                        throw $result.ThrewMsg
                    }
                    $totalSent  += $batchDocs
                    $totalOk    += $result.Ok
                    $totalFail  += $result.Fail
                    $bulkCount++
                    foreach ($r in $result.Reasons) {
                        if (-not $failureReasons.Contains($r)) { [void]$failureReasons.Add($r) }
                    }
                    if ($result.Fail -gt 0 -and -not $firstFailedDoc) { $firstFailedDoc = $docJson }
                    $batchLines.Clear() | Out-Null
                    $batchDocs = 0
                    $batchBytes = 0
                }
            }
        } finally {
            if ($reader) { $reader.Close(); $reader.Dispose() }
        }

        $totalRead   += $fileRead
        $totalParsed += $fileParsed

        $color = if ($fileFail -gt 0) { 'Yellow' } else { 'DarkGray' }
        Write-Host ("  {0,-45}  read={1,-7} parsed={2,-7} parse-fail={3}" -f $fileName, $fileRead, $fileParsed, $fileFail) -ForegroundColor $color
    }

    # --- FINAL FLUSH ---
    if ($batchDocs -gt 0) {
        $result = Invoke-LocalFlush -Lines $batchLines -BulkUri $bulkUri -Hdr $esHdr `
                      -RestArgs $restArgs -IsDryRun $DryRun.IsPresent -DocCount $batchDocs
        if ($result.Threw) {
            throw $result.ThrewMsg
        }
        $totalSent += $batchDocs
        $totalOk   += $result.Ok
        $totalFail += $result.Fail
        $bulkCount++
        foreach ($r in $result.Reasons) {
            if (-not $failureReasons.Contains($r)) { [void]$failureReasons.Add($r) }
        }
        $batchLines.Clear() | Out-Null
        $batchDocs = 0
        $batchBytes = 0
    }

    $stopwatch.Stop()

    # --- SUMMARY ---
    Write-Host ""
    Write-Host "==== Summary ====" -ForegroundColor Cyan
    Write-Host "  Index         : $targetIndex"             -ForegroundColor Cyan
    Write-Host "  Files         : $($ndjsonFiles.Count)"    -ForegroundColor DarkGray
    Write-Host "  Lines read    : $totalRead"               -ForegroundColor DarkGray
    Write-Host "  Docs parsed   : $totalParsed"             -ForegroundColor DarkGray
    Write-Host "  Docs sent     : $totalSent"               -ForegroundColor DarkGray
    Write-Host "  Accepted      : $totalOk"                 -ForegroundColor Green
    if ($totalFail -gt 0) {
        Write-Host "  Rejected      : $totalFail"           -ForegroundColor Red
    } else {
        Write-Host "  Rejected      : $totalFail"           -ForegroundColor DarkGray
    }
    Write-Host "  Bulk requests : $bulkCount"               -ForegroundColor DarkGray
    Write-Host "  Duration      : $($stopwatch.Elapsed.ToString('hh\:mm\:ss\.fff'))" -ForegroundColor DarkGray

    if ($failureReasons.Count -gt 0) {
        Write-Host ""
        Write-Host "  First $([Math]::Min(3, $failureReasons.Count)) unique failure reason(s):" -ForegroundColor Yellow
        $failureReasons | Select-Object -First 3 | ForEach-Object {
            Write-Host "    - $_" -ForegroundColor Yellow
        }
        if ($failureReasons | Where-Object { $_ -match 'mapper_parsing_exception' }) {
            Write-Host ""
            Write-Host "  HINT: mapper_parsing_exception usually means field-type conflicts from auto-mapping" -ForegroundColor DarkYellow
            Write-Host "        (e.g. event.code seen as both int and string). The first failing doc body:" -ForegroundColor DarkYellow
            if ($firstFailedDoc) {
                $preview = $firstFailedDoc
                if ($preview.Length -gt 400) { $preview = $preview.Substring(0, 400) + '...' }
                Write-Host "        $preview" -ForegroundColor DarkGray
            }
        }
    }

    return [PSCustomObject]@{
        Index         = $targetIndex
        Sent          = $totalSent
        Accepted      = $totalOk
        Rejected      = $totalFail
        BulkRequests  = $bulkCount
        DurationMs    = $stopwatch.ElapsedMilliseconds
        Failures      = @($failureReasons)
    }
}

Export-ModuleMember -Function Push-DetonationLogsToElastic
