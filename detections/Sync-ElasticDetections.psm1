# Sync-ElasticDetections.psm1
# Reads *.ndjson from detections\kibanaImport\, diffs against a live Kibana SIEM,
# and pushes any rules missing from the SIEM.
#
# Auth priority (first available wins):
#   1. -ApiKey parameter
#   2. SecretManagement secret 'Kibana_ApiKey'
#   3. SecretManagement secrets 'Elastic_User' + 'Elastic_Pass' (basic auth)
#   4. Interactive prompt

function Invoke-KibanaRequest {
    param(
        [string]$Uri,
        [string]$Method = 'GET',
        [hashtable]$Headers = @{},
        [string]$Body = $null
    )

    # PS 6+ (.NET Core / .NET 5+): use HttpClient directly — no Add-Type needed,
    # types are natively available. SocketsHttpHandler lets us pin HTTP/1.1 exactly,
    # preventing the HTTP/2 framing error Kibana throws when the client upgrades.
    # PS 5.1 (.NET Framework): always HTTP/1.1, use ServicePointManager cert bypass
    # and plain Invoke-RestMethod.
    if ($PSVersionTable.PSVersion.Major -ge 6) {

        $handler = [System.Net.Http.SocketsHttpHandler]::new()

        # Cert bypass only needed for https — skip for http to avoid delegate issues
        if ($Uri -like 'https://*') {
            $bypass = [System.Net.Security.RemoteCertificateValidationCallback]{
                param($s,$c,$ch,$e); return $true
            }
            $sslOpts = [System.Net.Security.SslClientAuthenticationOptions]::new()
            $sslOpts.RemoteCertificateValidationCallback = $bypass
            $handler.SslOptions = $sslOpts
        }

        $client = [System.Net.Http.HttpClient]::new($handler)
        $client.DefaultRequestVersion = [System.Version]::new(1, 1)
        # DefaultVersionPolicy is .NET 5+ — guard so this also runs on .NET Core 3.1
        if ($client | Get-Member -Name 'DefaultVersionPolicy' -ErrorAction SilentlyContinue) {
            $client.DefaultVersionPolicy = [System.Net.Http.HttpVersionPolicy]::RequestVersionExact
        }

        $req = [System.Net.Http.HttpRequestMessage]::new(
            [System.Net.Http.HttpMethod]::new($Method),
            [Uri]$Uri
        )
        $req.Version = [System.Version]::new(1, 1)

        foreach ($k in $Headers.Keys) {
            if ($k -eq 'Content-Type') { continue }
            [void]$req.Headers.TryAddWithoutValidation($k, [string]$Headers[$k])
        }
        if ($Body) {
            $req.Content = [System.Net.Http.StringContent]::new(
                $Body, [System.Text.Encoding]::UTF8, 'application/json'
            )
        }

        try {
            $resp    = $client.SendAsync($req).GetAwaiter().GetResult()
            $content = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            if (-not $resp.IsSuccessStatusCode) {
                throw "HTTP $([int]$resp.StatusCode) $($resp.ReasonPhrase): $content"
            }
            return $content | ConvertFrom-Json
        } finally {
            $client.Dispose()
            $handler.Dispose()
        }

    } else {
        # PS 5.1 / .NET Framework — always HTTP/1.1, no HTTP/2 risk
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        [System.Net.ServicePointManager]::SecurityProtocol =
            [System.Net.SecurityProtocolType]::Tls12

        $irmParams = @{
            Uri         = $Uri
            Method      = $Method
            Headers     = $Headers
            ContentType = 'application/json'
            ErrorAction = 'Stop'
        }
        if ($Body) { $irmParams['Body'] = $Body }
        return Invoke-RestMethod @irmParams
    }
}

function Sync-ElasticDetections {
    [CmdletBinding()]
    param(
        # Base URL of your Kibana instance, e.g. https://kibana.corp:5601
        [string]$KibanaUrl,

        # Kibana API key (the full base64 string returned by Kibana, NOT id:key).
        # Passed verbatim as: Authorization: ApiKey <value>
        [string]$ApiKey,

        # If set, report what would be pushed but do not create any rules.
        [switch]$DryRun,

        # Path to folder containing *.ndjson detection files.
        [string]$DetectionsPath
    )

    # ---- Resolve DetectionsPath ---------------------------------------------------
    if (-not $DetectionsPath) {
        $DetectionsPath = Join-Path $PSScriptRoot 'kibanaImport'
    }

    if (-not (Test-Path -LiteralPath $DetectionsPath)) {
        Write-Host "[!] DetectionsPath not found: $DetectionsPath" -ForegroundColor Red
        return
    }

    # ---- Resolve KibanaUrl -------------------------------------------------------
    if (-not $KibanaUrl) {
        try {
            $KibanaUrl = Get-Secret -Name 'Kibana_URL' -AsPlainText -ErrorAction SilentlyContinue
        } catch { }
    }
    if (-not $KibanaUrl) {
        $KibanaUrl = (Read-Host 'Kibana base URL (e.g. https://kibana.corp:5601)').Trim()
    }
    $KibanaUrl = $KibanaUrl.TrimEnd('/')

    # ---- Resolve auth headers ----------------------------------------------------
    $getHeaders  = @{}
    $postHeaders = @{}

    $getHeaders['kbn-xsrf']      = 'true'
    $getHeaders['Content-Type']  = 'application/json'
    $postHeaders['kbn-xsrf']     = 'true'
    $postHeaders['Content-Type'] = 'application/json'

    # Try ApiKey parameter first
    if (-not $ApiKey) {
        try {
            $ApiKey = Get-Secret -Name 'Kibana_ApiKey' -AsPlainText -ErrorAction SilentlyContinue
        } catch { }
    }

    if ($ApiKey) {
        $authValue = "ApiKey $ApiKey"
        $getHeaders['Authorization']  = $authValue
        $postHeaders['Authorization'] = $authValue
    } else {
        # Fall back to basic auth from Elastic_User / Elastic_Pass secrets
        $eUser = $null
        $ePass = $null
        try {
            $eUser = Get-Secret -Name 'Elastic_User' -AsPlainText -ErrorAction SilentlyContinue
            $ePass = Get-Secret -Name 'Elastic_Pass' -AsPlainText -ErrorAction SilentlyContinue
        } catch { }

        if (-not $eUser) { $eUser = (Read-Host 'Kibana username').Trim() }
        if (-not $ePass) { $ePass = (Read-Host 'Kibana password' -AsSecureString | ForEach-Object { [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($_)) }) }

        $encoded   = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${eUser}:${ePass}"))
        $authValue = "Basic $encoded"
        $getHeaders['Authorization']  = $authValue
        $postHeaders['Authorization'] = $authValue
    }

    # ---- Read local NDJSON rules -------------------------------------------------
    Write-Host ""
    Write-Host "[*] Reading local detection rules from: $DetectionsPath" -ForegroundColor Cyan

    $ndjsonFiles = @(Get-ChildItem -LiteralPath $DetectionsPath -Filter '*.ndjson' -File)
    if ($ndjsonFiles.Count -eq 0) {
        Write-Host "[!] No *.ndjson files found in $DetectionsPath" -ForegroundColor Yellow
        return
    }
    Write-Host "    Found $($ndjsonFiles.Count) NDJSON file(s):" -ForegroundColor DarkGray
    foreach ($nf in $ndjsonFiles) { Write-Host "      $($nf.Name)" -ForegroundColor DarkGray }

    $localRules = [System.Collections.Generic.List[PSCustomObject]]::new()
    $parseErrors = 0

    foreach ($ndjsonFile in $ndjsonFiles) {
        $lines = [System.IO.File]::ReadAllLines($ndjsonFile.FullName)
        foreach ($line in $lines) {
            $trimmed = $line.Trim()
            if (-not $trimmed -or $trimmed.StartsWith('//')) { continue }
            try {
                $obj = ConvertFrom-Json $trimmed
                if ($obj -and $obj.rule_id) {
                    $localRules.Add($obj)
                }
            } catch {
                $parseErrors++
            }
        }
    }

    if ($parseErrors -gt 0) {
        Write-Host "    [!] $parseErrors line(s) failed JSON parse and were skipped." -ForegroundColor Yellow
    }
    Write-Host "    Loaded $($localRules.Count) local rule(s) with valid rule_id fields." -ForegroundColor Cyan

    if ($localRules.Count -eq 0) {
        Write-Host "[!] No valid rules found. Nothing to sync." -ForegroundColor Yellow
        return
    }

    # Deduplicate local rules by rule_id (keep first occurrence)
    $seenLocal    = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $dedupedLocal = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($lr in $localRules) {
        if ($seenLocal.Add($lr.rule_id)) {
            $dedupedLocal.Add($lr)
        }
    }
    if ($dedupedLocal.Count -lt $localRules.Count) {
        $dupeCount = $localRules.Count - $dedupedLocal.Count
        Write-Host "    [!] Deduplicated $dupeCount local rule(s) with duplicate rule_id." -ForegroundColor Yellow
    }
    $localRules = $dedupedLocal

    # ---- Fetch existing SIEM rules (paginated) -----------------------------------
    Write-Host ""
    Write-Host "[*] Fetching existing rules from Kibana SIEM..." -ForegroundColor Cyan

    $existingRuleIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $page    = 1
    $perPage = 500
    $fetched = 0
    $total   = -1

    do {
        $findUri = "$KibanaUrl/api/detection_engine/rules/_find?page=$page&per_page=$perPage"
        try {
            $resp = Invoke-KibanaRequest -Uri $findUri -Method GET -Headers $getHeaders
        } catch {
            Write-Host "[!] Failed to query Kibana SIEM: $_" -ForegroundColor Red
            $inner = $_.Exception
            while ($inner.InnerException) { $inner = $inner.InnerException }
            Write-Host "    Root cause: $($inner.GetType().Name): $($inner.Message)" -ForegroundColor Red
            Write-Host "    Check KibanaUrl, credentials, and that the Detection Engine is enabled." -ForegroundColor DarkGray
            return
        }

        if ($total -eq -1) { $total = [int]$resp.total }

        foreach ($siemRule in $resp.data) {
            if ($siemRule.rule_id) {
                [void]$existingRuleIds.Add($siemRule.rule_id)
            }
        }

        $fetched += $resp.data.Count
        $page++

        if ($total -gt 0 -and $fetched -lt $total) {
            Write-Host "    Fetched $fetched / $total rules..." -ForegroundColor DarkGray
        }

    } while ($fetched -lt $total -and $resp.data.Count -gt 0)

    Write-Host "    SIEM currently has $($existingRuleIds.Count) unique rule_id(s) (total reported: $total)." -ForegroundColor Cyan

    # ---- Diff and push -----------------------------------------------------------
    Write-Host ""
    if ($DryRun) {
        Write-Host "[*] DRY RUN - no rules will be created." -ForegroundColor Yellow
    } else {
        Write-Host "[*] Syncing missing rules..." -ForegroundColor Cyan
    }
    Write-Host ""

    $countAdded   = 0
    $countPresent = 0
    $countError   = 0
    $missingRules = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($rule in $localRules) {
        if ($existingRuleIds.Contains($rule.rule_id)) {
            $countPresent++
        } else {
            $missingRules.Add($rule)
        }
    }

    Write-Host "    Already in SIEM : $countPresent" -ForegroundColor DarkGray
    Write-Host "    Missing (to push): $($missingRules.Count)" -ForegroundColor $(if ($missingRules.Count -gt 0) { 'Yellow' } else { 'DarkGray' })
    Write-Host ""

    foreach ($rule in $missingRules) {
        $ruleName = $rule.name
        $ruleId   = $rule.rule_id

        if ($DryRun) {
            Write-Host "  [DRY RUN] Would push: $ruleName" -ForegroundColor Cyan
            $countAdded++
            continue
        }

        # Build rule body - strip server-assigned 'id' field, Kibana assigns its own
        $ruleProps = $rule | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
        $bodyHash  = [ordered]@{}
        foreach ($prop in $ruleProps) {
            if ($prop -eq 'id') { continue }
            $bodyHash[$prop] = $rule.$prop
        }

        $body = ConvertTo-Json $bodyHash -Depth 20 -Compress

        try {
            $createUri = "$KibanaUrl/api/detection_engine/rules"
            Invoke-KibanaRequest -Uri $createUri -Method POST -Headers $postHeaders -Body $body | Out-Null
            Write-Host "  [+] Pushed  : $ruleName" -ForegroundColor Green
            $countAdded++
        } catch {
            $errMsg = $_.Exception.Message
            Write-Host "  [!] Error   : $ruleName" -ForegroundColor Red
            Write-Host "      rule_id : $ruleId" -ForegroundColor DarkGray
            Write-Host "      msg     : $errMsg" -ForegroundColor DarkGray
            $countError++
        }
    }

    # ---- Summary -----------------------------------------------------------------
    Write-Host ""
    Write-Host "  +-------------------------------------------+" -ForegroundColor Cyan
    Write-Host "  |         Sync-ElasticDetections Summary    |" -ForegroundColor Cyan
    Write-Host "  +-------------------------------------------+" -ForegroundColor Cyan
    Write-Host "  Local rules loaded    : $($localRules.Count)" -ForegroundColor White
    Write-Host "  Already in SIEM       : $countPresent" -ForegroundColor DarkGray
    if ($DryRun) {
        Write-Host "  Would push (dry run)  : $countAdded" -ForegroundColor Cyan
    } else {
        Write-Host "  Pushed successfully   : $countAdded" -ForegroundColor Green
        if ($countError -gt 0) {
            Write-Host "  Push errors           : $countError" -ForegroundColor Red
        }
    }
    Write-Host ""

    if (-not $DryRun -and $countAdded -gt 0) {
        Write-Host "  All new rules are created with enabled=false." -ForegroundColor DarkGray
        Write-Host "  Review and enable in Kibana: Stack Management -> Security -> Detection Rules." -ForegroundColor DarkGray
        Write-Host ""
    }
}

Export-ModuleMember -Function Sync-ElasticDetections
