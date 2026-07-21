function Get-ElasticDetonationLogs {
    <#
    .SYNOPSIS
        Pulls all Elastic logs from a detonation window and saves them to a
        timestamped folder for offline analysis.

        Prompts for start/end times in any natural format (e.g. "8PM EST",
        "20:00", "2026-03-18 20:00 EST"). Queries process, network, file,
        registry, and alert events separately and saves each as NDJSON + a
        combined summary CSV.
    .PARAMETER ElasticUrl
        Elastic base URL. Overrides the Elastic_URL vault secret. Use this in
        offline / no-vault environments (e.g. 'https://elasticsearch.lab:9200').
    .PARAMETER ElasticApiKey
        Elastic API key as 'id:api_key' (or pre-encoded base64). Overrides the
        Elastic_ApiKey vault secret. Preferred auth for SO 3.0 / proxied stacks.
    .PARAMETER ElasticUser
        Elastic username for Basic auth. Overrides Elastic_User (use with -ElasticPass).
    .PARAMETER ElasticPass
        Elastic password for Basic auth. Overrides Elastic_Pass.
    .PARAMETER SshHost
        Security Onion SSH host/IP for the SSH connector, used when the pull
        auto-routes to Save-TorchElasticDetonationLogs (SO 3.0 / proxied ES).
        Overrides the TORCH_SSH_Host vault secret; missing values are prompted for.
    .PARAMETER SshUser
        SO SSH username. Overrides TORCH_SSH_User.
    .PARAMETER SshPass
        SO SSH password. Overrides TORCH_SSH_Pass. Also used for sudo unless -SudoPass is set.
    .PARAMETER SshKeyPath
        Path to an OpenSSH private key (alternative to -SshPass). Overrides TORCH_SSH_KeyPath.
    .PARAMETER SudoPass
        Password for 'sudo so-elasticsearch-query' on the SO box (defaults to -SshPass).
    .EXAMPLE
        # Offline / no vault - pass credentials directly:
        Get-ElasticDetonationLogs -ElasticUrl 'https://elasticsearch.lab:9200' -ElasticApiKey 'id:api_key'
        Get-ElasticDetonationLogs -ElasticUrl 'https://elasticsearch.lab:9200' -ElasticUser 'elastic' -ElasticPass 'changeme'
    .EXAMPLE
        # Security Onion, fully offline (no vault) - Elastic auth + SSH connector creds so the
        # auto-route to the SSH pull runs prompt-free:
        Get-ElasticDetonationLogs -ElasticUrl 'https://192.168.71.10:9200' -ElasticApiKey 'id:api_key' `
            -SshHost '192.168.71.10' -SshUser 'onion' -SshPass 'P@ss'
    .NOTES
        Auth precedence (first available wins):
          1. ApiKey  -  vault secret Elastic_ApiKey  (preferred; required for
             Security Onion 3.0 + similar nginx-proxied SO/ECS stacks that
             redirect unauthenticated Basic requests to a SOC login page)
          2. Basic   -  vault secrets Elastic_User + Elastic_Pass  (vanilla
             Elasticsearch native auth, or any stack that exposes :9200 with
             Basic enabled)

        Required regardless: vault secret Elastic_URL.

        For Security Onion the Elasticsearch REST API is on port :9200, e.g.
        'https://192.168.71.10:9200'. It is FIREWALLED from external hosts by
        default - allow your workstation IP in the SOC UI under
        Administration > Configuration > firewall > hostgroups > elasticsearch_rest,
        then Options > SYNCHRONIZE GRID. (Some SO builds instead front ES with an
        nginx proxy at 'https://<host>/elasticsearch'; if the :9200 probe returns a
        302 the tool auto-offers the SSH connector.) For vanilla Elastic the URL is
        the :9200 endpoint directly, e.g. 'https://elasticsearch.lab:9200'.
    #>
    [CmdletBinding()]
    param(
        [string]$ElasticUrl,
        [string]$ElasticApiKey,
        [string]$ElasticUser,
        [string]$ElasticPass,
        # Offline / no-vault SSH connector credentials, used when the pull auto-routes
        # to Save-TorchElasticDetonationLogs (SO 3.0 / proxied ES). Override the
        # TORCH_SSH_* vault secrets; anything still missing is prompted for.
        [string]$SshHost,
        [string]$SshUser,
        [string]$SshPass,
        [string]$SshKeyPath,
        [string]$SudoPass
    )

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # Bypass self-signed certificate validation for internal Elasticsearch clusters.
    # PS 5.1 uses ServicePointManager; PS 7+ uses -SkipCertificateCheck per call.
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        if (-not ([System.Management.Automation.PSTypeName]'ElasticPotatoCertBypass').Type) { Add-Type -TypeDefinition 'using System.Net;using System.Net.Security;using System.Security.Cryptography.X509Certificates;public static class ElasticPotatoCertBypass{public static void Enable(){ServicePointManager.ServerCertificateValidationCallback=delegate(object s,X509Certificate c,X509Chain ch,SslPolicyErrors e){return true;};}}' }; [ElasticPotatoCertBypass]::Enable()  # PS5.1: compiled delegate avoids the "no Runspace" cert-callback crash
    }
    $restArgs = if ($PSVersionTable.PSVersion.Major -ge 6) { @{ SkipCertificateCheck = $true } } else { @{} }

    # --- AUTH ---
    # Pre-init so .Trim() on a null Get-Secret result does not throw
    # NullReferenceException ('You cannot call a method on a null-valued
    # expression') when a vault entry is missing. -ErrorAction Stop inside
    # try/catch absorbs both the Get-Secret error AND the trim's null deref.
    $esUrl = $null; $esApiKey = $null; $esUser = $null; $esPass = $null
    try { $esUrl    = (Get-Secret -Name 'Elastic_URL'    -AsPlainText -ErrorAction Stop).Trim().TrimEnd('/') } catch {}
    try { $esApiKey = (Get-Secret -Name 'Elastic_ApiKey' -AsPlainText -ErrorAction Stop).Trim() } catch {}
    try { $esUser   = (Get-Secret -Name 'Elastic_User'   -AsPlainText -ErrorAction Stop).Trim() } catch {}
    try { $esPass   = (Get-Secret -Name 'Elastic_Pass'   -AsPlainText -ErrorAction Stop).Trim() } catch {}

    # Explicit parameters override the vault. This is the offline / no-vault path:
    # pass -ElasticUrl plus (-ElasticApiKey  OR  -ElasticUser + -ElasticPass) directly,
    # e.g. Get-ElasticDetonationLogs -ElasticUrl '...' -ElasticApiKey 'id:api_key'.
    # The Get-Secret calls above are wrapped in try/catch, so a missing vault (or the
    # SecretManagement module not being installed at all) leaves these null and the
    # parameters / prompts below fill them in.
    if (-not [string]::IsNullOrWhiteSpace($ElasticUrl))    { $esUrl    = $ElasticUrl.Trim().TrimEnd('/') }
    if (-not [string]::IsNullOrWhiteSpace($ElasticApiKey)) { $esApiKey = $ElasticApiKey.Trim() }
    if (-not [string]::IsNullOrWhiteSpace($ElasticUser))   { $esUser   = $ElasticUser.Trim() }
    if (-not [string]::IsNullOrWhiteSpace($ElasticPass))   { $esPass   = $ElasticPass.Trim() }

    if ([string]::IsNullOrWhiteSpace($esUrl)) {
        $esUrl = Read-Host "[?] Elastic URL not found in vault (e.g. https://192.168.71.10:9200 or https://elasticsearch.lab:9200)"
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

    # Interactive credential fallback (offline / no vault): if nothing came from
    # the vault OR parameters, prompt rather than erroring - mirrors the URL prompt
    # above. Leave the API-key answer blank to fall through to username + password.
    if ([string]::IsNullOrWhiteSpace($esApiKey) -and
        ([string]::IsNullOrWhiteSpace($esUser) -or [string]::IsNullOrWhiteSpace($esPass))) {
        Write-Host "[?] No Elastic credentials in vault or parameters - enter them now:" -ForegroundColor Yellow
        $inKey = Read-Host "    Elastic API key as 'id:api_key' or base64 (blank = use username/password)"
        if (-not [string]::IsNullOrWhiteSpace($inKey)) {
            $esApiKey = $inKey.Trim()
        } else {
            $inUser = Read-Host "    Elastic username"
            if (-not [string]::IsNullOrWhiteSpace($inUser)) {
                $esUser  = $inUser.Trim()
                # Read the password as a SecureString so it is not echoed, then
                # convert to plain text for the Basic header (matches the vault's
                # -AsPlainText usage). BSTR is zeroed/freed immediately after.
                $secPass = Read-Host "    Elastic password" -AsSecureString
                if ($secPass -and $secPass.Length -gt 0) {
                    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secPass)
                    try   { $esPass = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
                    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
                }
            }
        }
    }

    # Build the auth header. Prefer API key when present; fall back to Basic.
    # API key encoding: the secret can be stored in either the already-base64-
    # encoded form (id:api_key base64) or as the raw 'id:api_key' string; we
    # accept both and emit the canonical "ApiKey <base64>" header.
    $authMode = ''
    if (-not [string]::IsNullOrWhiteSpace($esApiKey)) {
        $apiKeyEncoded = $esApiKey
        # If it doesn't look like base64 (contains a literal ':' and not '='),
        # assume it's raw 'id:api_key' and base64-encode it ourselves.
        if ($esApiKey -match '^[^:]+:[^:]+$' -and $esApiKey -notmatch '=$') {
            $apiKeyEncoded = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($esApiKey))
        }
        $esHdr = @{ 'Authorization' = "ApiKey $apiKeyEncoded"; 'Content-Type' = 'application/json' }
        $authMode = 'ApiKey'
    } elseif (-not [string]::IsNullOrWhiteSpace($esUser) -and -not [string]::IsNullOrWhiteSpace($esPass)) {
        $b64   = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${esUser}:${esPass}"))
        $esHdr = @{ 'Authorization' = "Basic $b64"; 'Content-Type' = 'application/json' }
        $authMode = "Basic ($esUser)"
    } else {
        Write-Host "[ERROR] No Elastic credentials supplied (vault, parameters, and prompt all empty). Provide ONE of:" -ForegroundColor Red
        Write-Host ""
        Write-Host "  Option A - store in the SecretManagement vault:" -ForegroundColor Yellow
        Write-Host "    Set-Secret -Name Elastic_ApiKey -Secret '<id>:<api_key>'   (or pre-encoded base64)" -ForegroundColor DarkGray
        Write-Host "    Set-Secret -Name Elastic_User   -Secret '<user>'           (and Elastic_Pass)" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  Option B - pass directly as parameters (offline / no vault):" -ForegroundColor Yellow
        Write-Host "    Get-ElasticDetonationLogs -ElasticUrl '<url>' -ElasticApiKey '<id>:<api_key>'" -ForegroundColor DarkGray
        Write-Host "    Get-ElasticDetonationLogs -ElasticUrl '<url>' -ElasticUser '<user>' -ElasticPass '<pass>'" -ForegroundColor DarkGray
        return
    }
    Write-Host "  Auth    : $authMode" -ForegroundColor DarkGray

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

    # Security Onion proxy probe: SO 3.0 redirects unauthenticated Basic requests
    # to its SOC login (HTTP 302 to /login). When detected we set a flag so the
    # function auto-routes the pull through the SSH connector
    # (Save-TorchElasticDetonationLogs) AFTER collecting the standard inputs
    # (start/end/host/label), and skips the HTTP pull entirely.
    $soKratosDetected = $false
    try {
        Invoke-WebRequest -Uri "$esUrl/_cluster/health" -Headers $esHdr -Method Get -MaximumRedirection 0 @restArgs -ErrorAction Stop | Out-Null
    } catch {
        $resp = $_.Exception.Response
        if ($resp -and ([int]$resp.StatusCode) -eq 302) {
            $loc = $resp.Headers.Location
            $soKratosDetected = $true
            Write-Host "[INFO] Elastic URL '$esUrl' returned HTTP 302 -> $loc" -ForegroundColor Cyan
            Write-Host "       Detected nginx-proxied Elasticsearch (Security Onion 3.0 / Kratos)." -ForegroundColor Cyan
            Write-Host "       Headless HTTP auth (ApiKey / Basic / Bearer) is NOT supported here." -ForegroundColor Cyan
            Write-Host "       Will auto-route the pull through the SSH connector after collecting window inputs." -ForegroundColor Cyan
            Write-Host "       Required vault secrets: TORCH_SSH_Host, TORCH_SSH_User, TORCH_SSH_Pass (or TORCH_SSH_KeyPath)." -ForegroundColor DarkGray
        }
        # Continue regardless; non-302 errors fall through to the main query.
    }

    # Capability probe: some endpoints (Security Onion's nginx-proxied ES, a
    # coordinating/aggregating proxy, or a document-level-security-restricted user)
    # answer _cluster/health and _count but CANNOT return document bodies from
    # _search - the response comes back with hits.total>0 yet zero hits and NO
    # _shards block (a raw ES node always returns _shards). Detect that signature
    # here so we route to the SSH connector instead of running a full HTTP pull that
    # retrieves nothing (the "reported N docs but 0 retrieved" symptom on SO).
    $soDegradedDetected = $false
    if (-not $soKratosDetected) {
        try {
            $capBody     = @{ size = 1; track_total_hits = $true; query = @{ match_all = @{} } } | ConvertTo-Json -Compress
            $cap         = Invoke-RestMethod -Uri "$esUrl/_search?ignore_unavailable=true" -Headers $esHdr -Method Post -Body $capBody @restArgs
            $capTotal    = if ($cap.hits -and $cap.hits.total) { if ($cap.hits.total.PSObject.Properties.Name -contains 'value') { $cap.hits.total.value } else { $cap.hits.total } } else { 0 }
            $capHits     = if ($cap.hits.hits) { @($cap.hits.hits).Count } else { 0 }
            $capNoShards = ($null -eq $cap._shards)
            if ($capTotal -gt 0 -and $capHits -eq 0 -and $capNoShards) {
                $soDegradedDetected = $true
                Write-Host "[INFO] Endpoint '$esUrl' answers _count/_search but returns NO documents and NO _shards" -ForegroundColor Cyan
                Write-Host "       (match_all hits.total=$capTotal, hits.hits=0). This is a proxied / coordinating-only" -ForegroundColor Cyan
                Write-Host "       endpoint (e.g. Security Onion's nginx-proxied ES) that cannot serve document bodies" -ForegroundColor Cyan
                Write-Host "       over HTTP - a direct pull retrieves 0 docs. Will auto-route through the SSH connector" -ForegroundColor Cyan
                Write-Host "       after collecting window inputs." -ForegroundColor Cyan
                Write-Host "       Required vault secrets: TORCH_SSH_Host, TORCH_SSH_User, TORCH_SSH_Pass (or TORCH_SSH_KeyPath)." -ForegroundColor DarkGray
            }
        } catch {
            # Probe failure is non-fatal - fall through to the normal HTTP path / other detection.
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

        # Apply explicit tz offset -> UTC; otherwise treat as local -> UTC.
        # CRITICAL: always tag the result with Kind=Utc so that downstream
        # consumers calling .ToUniversalTime() do NOT re-interpret an
        # Unspecified-Kind value as Local time and shift it by the local
        # offset a second time (the bug that caused 16:12 UTC input to be
        # queried as 20:12 UTC on EDT machines).
        if ($null -ne $tzOffset) {
            $parsed = [DateTime]::SpecifyKind($parsed.AddHours(-$tzOffset), [DateTimeKind]::Utc)
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

    # --- SO 3.0 / KRATOS / PROXIED-ES AUTO-ROUTE ---------------------------
    # Route the pull through the SSH connector when EITHER (a) the URL probe
    # returned HTTP 302 (SO 3.0 / Kratos login redirect - headless HTTP auth
    # unsupported), OR (b) the capability probe found a proxied/coordinating
    # endpoint that answers counts but returns no documents / no _shards. In both
    # cases the direct HTTP pull retrieves nothing. All inputs the SSH connector
    # needs (start/end/host/label/outdir) have been collected by this point, so we
    # hand off to Save-TorchElasticDetonationLogs and return its output dir instead
    # of running the futile HTTP pull.
    if ($soKratosDetected -or $soDegradedDetected) {
        $routeReason = if ($soKratosDetected) { 'SO 3.0 / Kratos 302 redirect' } else { 'proxied ES (answers counts but returns no documents)' }
        Write-Host ""
        Write-Host "[Auto-Route] $routeReason detected - calling Save-TorchElasticDetonationLogs (SSH connector)..." -ForegroundColor DarkCyan
        $connectorPath = Join-Path $PSScriptRoot 'Invoke-TorchElasticQuery.psm1'
        if (Test-Path $connectorPath) {
            try { Import-Module $connectorPath -Force -DisableNameChecking -ErrorAction Stop | Out-Null } catch {
                Write-Host "[WARN] Could not force-reimport connector ($($_.Exception.Message)) - using whatever is cached." -ForegroundColor Yellow
            }
        }
        if (-not (Get-Command Save-TorchElasticDetonationLogs -ErrorAction SilentlyContinue)) {
            Write-Host "[ERROR] Save-TorchElasticDetonationLogs is not available. Falling back to HTTP path (likely to fail)." -ForegroundColor Red
        } else {
            try {
                # TODO (index-pattern escape hatch): the orchestrator hardcodes
                # the SO 3.0 Fleet 'logs-*' default baked into
                # Save-TorchElasticDetonationLogs because that is the 95% case
                # 3a is designed for. Operators on non-Fleet clusters
                # (Winlogbeat-only, Filebeat-only, hybrid 'logs-*,winlogbeat-*')
                # can invoke Save-TorchElasticDetonationLogs directly with
                # -IndexPattern 'winlogbeat-*' (or whatever CSV combination
                # they need). A 3a-level interactive prompt can land here when
                # the first operator reports needing it - YAGNI today.
                Save-TorchElasticDetonationLogs `
                    -StartTime  $startUtc `
                    -EndTime    $endUtc `
                    -OutputDir  $outDir `
                    -HostFilter $hostFilter `
                    -SshHost $SshHost -SshUser $SshUser -SshPass $SshPass -SshKeyPath $SshKeyPath -SudoPass $SudoPass `
                    -SessionInfoCampaign $label -ErrorAction Stop | Out-Null
                return $outDir
            } catch {
                Write-Host "[ERROR] SSH pull failed: $($_.Exception.Message)" -ForegroundColor Red
                Write-Host "        Falling back to HTTP path (likely to also fail against SO 3.0)." -ForegroundColor DarkGray
            }
        }
    }

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
        Write-Host "    5. PowerShell 5.1 cert-callback bug - if the inner error mentions 'no Runspace'," -ForegroundColor DarkYellow
        Write-Host "       re-run in PowerShell 7 (pwsh) or update elasticPotato (bypass is now runspace-safe)" -ForegroundColor DarkYellow

        # A network-level failure (timeout / refused / unreachable) means HTTP cannot
        # reach ES at all. On Security Onion, ES is usually bound internal-only, so
        # direct :9200 from a workstation never answers - offer the SSH connector,
        # which pulls via so-elasticsearch-query and never touches :9200. The window
        # inputs (start/end/host/label/outdir) were already collected above, and the
        # connector prompts for SSH creds when no vault/params are present.
        $connMsg = "$($_.Exception.Message) $(if ($_.Exception.InnerException) { $_.Exception.InnerException.Message })"
        if ($connMsg -match 'did not properly respond|timed out|actively refused|[Uu]nable to connect|failed to respond|No such host|unreachable') {
            Write-Host ""
            Write-Host "  This is a network-level failure reaching $esUrl (not an auth error)." -ForegroundColor Cyan
            Write-Host "  On Security Onion, Elasticsearch is usually internal-only, so direct :9200 from a" -ForegroundColor Cyan
            Write-Host "  workstation never answers - the supported path there is the SSH connector." -ForegroundColor Cyan
            $sshAns = Read-Host "  Fall back to the SSH connector (pull over SSH via so-elasticsearch-query)? [y/N]"
            if ($sshAns -and $sshAns.Trim().ToUpper().StartsWith('Y')) {
                $connectorPath = Join-Path $PSScriptRoot 'Invoke-TorchElasticQuery.psm1'
                if (Test-Path $connectorPath) {
                    try { Import-Module $connectorPath -Force -DisableNameChecking -ErrorAction Stop | Out-Null } catch {}
                }
                if (Get-Command Save-TorchElasticDetonationLogs -ErrorAction SilentlyContinue) {
                    try {
                        Save-TorchElasticDetonationLogs `
                            -StartTime  $startUtc `
                            -EndTime    $endUtc `
                            -OutputDir  $outDir `
                            -HostFilter $hostFilter `
                            -SshHost $SshHost -SshUser $SshUser -SshPass $SshPass -SshKeyPath $SshKeyPath -SudoPass $SudoPass `
                            -SessionInfoCampaign $label -ErrorAction Stop | Out-Null
                        return $outDir
                    } catch {
                        Write-Host "  [ERROR] SSH pull failed: $($_.Exception.Message)" -ForegroundColor Red
                    }
                } else {
                    Write-Host "  [ERROR] Save-TorchElasticDetonationLogs not available - is the Posh-SSH module installed? (Install-Module Posh-SSH -Scope CurrentUser)" -ForegroundColor Red
                }
            }
        }
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

    # --- AUTO-CATEGORIZE & TARGET (offline-adaptive) ---
    # A bare "*" fan-out hits every index (Kibana/security/ILM/monitoring/async-search/
    # etc.). Across a big offline cluster the scroll search then lands on shards that pass
    # the query phase but fail the FETCH phase -> "ES reported N docs but 0 retrieved".
    # Resolve what is actually present, drop system/internal noise, and query only the
    # security-relevant index families. No external calls - safe air-gapped.
    Write-Host ""
    Write-Host "[Pre-flight] Auto-categorizing indices for this environment..." -ForegroundColor DarkCyan
    $targetSet  = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $catBuckets = [ordered]@{ endpoint = 0; windows = 0; network = 0; other = 0 }

    $isSystemName = {
        param([string]$n)
        if ([string]::IsNullOrWhiteSpace($n)) { return $true }
        if ($n.StartsWith('.ds-'))            { return $true }   # data-stream backing index (reached via its data stream)
        if ($n[0] -eq '.')                    { return $true }   # any other dotted index = internal/system
        foreach ($p in @('ilm-history', 'slm-history', 'apm-', 'metrics-endpoint.metadata')) {
            if ($n.StartsWith($p)) { return $true }
        }
        return $false
    }
    $familyOf = {
        param([string]$n)
        if ($n -match '^(.+?)-\d') { return "$($matches[1])-*" }  # collapse rollover: foo-8.11.0-2024.01-000001 -> foo-*
        return $n
    }
    $bucketOf = {
        param([string]$n)
        if     ($n -match '(?i)endpoint|defend')                        { return 'endpoint' }
        elseif ($n -match '(?i)winlog|sysmon|windows|system\.security') { return 'windows' }
        elseif ($n -match '(?i)network|packetbeat|netflow|zeek|suricata|firewall') { return 'network' }
        else                                                            { return 'other' }
    }

    try {
        $resolve = Invoke-RestMethod -Uri "$esUrl/_resolve/index/*?expand_wildcards=open" `
                       -Headers $esHdr -Method Get @restArgs
        Write-Host "  _resolve returned $(@($resolve.data_streams).Count) data stream(s), $(@($resolve.indices).Count) index/indices, $(@($resolve.aliases).Count) alias(es)" -ForegroundColor DarkGray
        foreach ($ds in @($resolve.data_streams)) {
            if (-not $ds -or -not $ds.name)  { continue }
            if (& $isSystemName $ds.name)    { continue }
            if ($ds.name -match '^(metrics|synthetics|profiling|traces)-') { continue }  # trim non-security fan-out
            [void]$targetSet.Add((& $familyOf $ds.name)); $catBuckets[(& $bucketOf $ds.name)]++
        }
        foreach ($ix in @($resolve.indices)) {
            if (-not $ix -or -not $ix.name)  { continue }
            if ($ix.PSObject.Properties.Name -contains 'data_stream' -and $ix.data_stream) { continue }  # backing index
            if (& $isSystemName $ix.name)    { continue }
            if ($ix.name -match '^(metrics|synthetics|profiling|traces)-') { continue }
            [void]$targetSet.Add((& $familyOf $ix.name)); $catBuckets[(& $bucketOf $ix.name)]++
        }
    } catch {
        Write-Host "  [WARN] _resolve/index failed ($($_.Exception.Message))." -ForegroundColor Yellow
    }

    if ($targetSet.Count -gt 0) {
        $defaultIndices = ($targetSet | Sort-Object) -join ','
        Write-Host "  Targeting $($targetSet.Count) index family/families  [endpoint:$($catBuckets.endpoint) windows:$($catBuckets.windows) network:$($catBuckets.network) other:$($catBuckets.other)]" -ForegroundColor Green
        $targetSet | Sort-Object | Select-Object -First 25 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
        if ($targetSet.Count -gt 25) { Write-Host "    ... ($($targetSet.Count - 25) more)" -ForegroundColor DarkGray }
    } else {
        # Fallback: keep everything EXCEPT the noisy system families ("*" still matches data streams by name)
        $defaultIndices = '*,-.kibana*,-.security*,-.fleet*,-.async-search*,-.geoip*,-.ml*,-.monitoring*,-.transform*,-.tasks,-.watches*,-.triggered_watches,-.apm-*,-.ilm-history*,-.slm-history*,-.enrich*,-.reporting*,-.logstash*,-.deprecation*,-.snapshot*,-.internal*,-.lists*,-.items*,-.alerts*'
        Write-Host "  Could not resolve families - using system-exclusion pattern instead of bare '*'." -ForegroundColor DarkYellow
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
            $countResp = Invoke-RestMethod -Uri "$esUrl/$Index/_count?ignore_unavailable=true" -Headers $esHdr -Method Post -Body $countBody @restArgs
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
            $resp = Invoke-RestMethod -Uri "$esUrl/$Index/_search?scroll=$scrollTtl&ignore_unavailable=true" `
                        -Headers $esHdr -Method Post -Body $body @restArgs
        } catch {
            $code = $null; try { $code = $_.Exception.Response.StatusCode.value__ } catch {}
            $errBody = $null; try { $errBody = $_.ErrorDetails.Message } catch {}
            Write-Host "  [WARN] $Label initial scroll query failed (HTTP $code): $($_.Exception.Message)" -ForegroundColor Yellow
            if ($errBody) { Write-Host "    ES said: $errBody" -ForegroundColor DarkYellow }
            return $allDocs
        }

        # Surface shard-level FETCH failures. A data-stream / synthetic-_source shard can pass
        # the query phase (so _count sees the doc) yet fail the fetch phase, returning 0 hits
        # with NO top-level error - the real cause of "reported N docs but 0 retrieved".
        if ($resp._shards -and $resp._shards.failed -and $resp._shards.failed -gt 0) {
            Write-Host "  [WARN] $Label : $($resp._shards.failed)/$($resp._shards.total) shard(s) failed on the search - docs on those shards are lost:" -ForegroundColor Red
            foreach ($f in @($resp._shards.failures | Select-Object -First 3)) {
                $fIdx = $f.index
                $fRsn = $null; try { $fRsn = $f.reason.reason; if (-not $fRsn) { $fRsn = $f.reason.type } } catch {}
                Write-Host "    - '$fIdx' : $fRsn" -ForegroundColor DarkYellow
            }
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
            Write-Host "  [WARN] ES reported $esCount docs but 0 were retrieved  -  auto-diagnosing:" -ForegroundColor Red
            # Probe: a PLAIN (non-scroll) search with an _index breakdown + shard stats.
            #   - hits.hits > 0 here  => the SCROLL is the problem (not the query)
            #   - hits.total = 0 but count > 0 / skipped shards => data on a SKIPPED shard
            #     (frozen / cold searchable-snapshot tier that _count sees but _search skips)
            #   - by_index shows exactly which index holds the counted doc
            try {
                $probeBody = @{
                    size             = 1
                    track_total_hits = $true
                    query            = @{ bool = @{ must = $mustClauses; filter = @( $BoolFilter ) } }
                    aggs             = @{ by_index = @{ terms = @{ field = "_index"; size = 10 } } }
                } | ConvertTo-Json -Depth 20 -Compress
                $probe    = Invoke-RestMethod -Uri "$esUrl/$Index/_search?ignore_unavailable=true" -Headers $esHdr -Method Post -Body $probeBody @restArgs
                $hitCount = if ($probe.hits.hits) { @($probe.hits.hits).Count } else { 0 }
                $probeView = [ordered]@{
                    took          = $probe.took
                    timed_out     = $probe.timed_out
                    _shards       = $probe._shards
                    hits_total    = $probe.hits.total
                    hits_returned = $hitCount
                    by_index      = if ($probe.aggregations -and $probe.aggregations.by_index) { $probe.aggregations.by_index.buckets } else { $null }
                }
                Write-Host "    [diag] plain non-scroll _search result:" -ForegroundColor Cyan
                Write-Host ($probeView | ConvertTo-Json -Depth 6) -ForegroundColor Cyan
                if ($hitCount -gt 0) {
                    Write-Host "    [diag] -> doc IS returnable without scroll: the SCROLL path is the problem." -ForegroundColor Cyan
                } elseif ($probe._shards -and $probe._shards.skipped -gt 0) {
                    Write-Host "    [diag] -> shard(s) SKIPPED with 0 returned: data on a frozen/cold tier _count sees but _search skips (needs ignore_throttled=false)." -ForegroundColor Cyan
                } else {
                    Write-Host "    [diag] -> total>0 but 0 returned, no skip/fail: inspect the 'by_index' index's state (closed? searchable-snapshot? _source disabled?)." -ForegroundColor Cyan
                }
            } catch {
                Write-Host "    [diag] probe failed: $($_.Exception.Message)" -ForegroundColor DarkYellow
            }
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
    $summary | Format-Table -AutoSize | Out-Host
    return $outDir
}

Export-ModuleMember -Function Get-ElasticDetonationLogs
