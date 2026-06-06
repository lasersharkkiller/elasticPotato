# =============================================================================
# Invoke-TorchElasticQuery.psm1
# -----------------------------------------------------------------------------
# SSH-based access to Security Onion 3.0 Elasticsearch via the
# so-elasticsearch-query helper script.
#
# WHY SSH?
#   Security Onion 3.0 fronts Elasticsearch and Kibana with Kratos session-
#   cookie authentication. Kratos issues HttpOnly session cookies after an
#   interactive login flow; there is no headless equivalent. As a result every
#   form of direct HTTP auth against the SO 3.0 reverse proxy fails:
#     - ApiKey   -> rejected, Kratos requires a session cookie
#     - Basic    -> rejected, no LDAP/local-htpasswd realm on the proxy
#     - Bearer   -> rejected, Kratos does not mint API JWTs for ES
#   The supported automation path documented by the SO project is to SSH into
#   the SO host and invoke /usr/sbin/so-elasticsearch-query under sudo. That
#   helper reads /opt/so/conf/elasticsearch/curl.config (root-readable) which
#   contains localhost-only Basic credentials, talks to ES over 127.0.0.1, and
#   prints the raw _search response to stdout. We capture stdout over the SSH
#   channel and parse JSON on the Windows side.
#
#   For non-SO Elastic clusters (ESS, ECE, self-managed with ApiKey enabled)
#   use Get-ElasticDetonationLogs in GetElasticDetonationLogs.psm1 instead.
#
# DIAGNOSTICS
#   Invoke-TorchElasticDiagnose probes the SO 3.0 cluster (indices list,
#   unfiltered count, event.dataset + host.name/host.hostname/agent.name terms
#   aggs) to triage 'all datasets returned 0' situations. Save-TorchElastic-
#   DetonationLogs auto-invokes the same probe when every dataset reports 0,
#   and exposes a -Diagnose switch to run probe-only without a full pull.
# =============================================================================

# --- Posh-SSH soft dependency check (warn-only at module load) ---------------
if (-not (Get-Module -ListAvailable -Name 'Posh-SSH')) {
    Write-Warning "Posh-SSH is not installed. Install with:"
    Write-Warning "    Install-Module -Name Posh-SSH -Scope CurrentUser -Force"
    Write-Warning "Functions in this module will fail until Posh-SSH is available."
}

# -----------------------------------------------------------------------------
function Resolve-TorchSecret {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name, [switch]$AsPlainText)
    try {
        if (-not (Get-Command Get-Secret -ErrorAction SilentlyContinue)) { return $null }
        if ($AsPlainText) {
            return (Get-Secret -Name $Name -AsPlainText -ErrorAction Stop)
        } else {
            return (Get-Secret -Name $Name -ErrorAction Stop)
        }
    } catch { return $null }
}

# -----------------------------------------------------------------------------
function Assert-PoshSSH {
    if (-not (Get-Module -ListAvailable -Name 'Posh-SSH')) {
        throw "Posh-SSH module is required but not installed. Run: Install-Module -Name Posh-SSH -Scope CurrentUser -Force"
    }
    Import-Module Posh-SSH -ErrorAction Stop | Out-Null
}

# -----------------------------------------------------------------------------
function Get-TorchSSHSession {
<#
.SYNOPSIS
    Open (or reuse) an SSH session to a Security Onion 3.0 host.

.DESCRIPTION
    Reads connection material from SecretManagement:
        TORCH_SSH_Host      hostname / IP of the SO 3.0 manager node
        TORCH_SSH_User      SSH username (typically the SO admin account)
        TORCH_SSH_Pass      OPTIONAL password (used only if key path absent)
        TORCH_SSH_KeyPath   OPTIONAL path to an OpenSSH private key file
    If both TORCH_SSH_KeyPath and TORCH_SSH_Pass are present, key wins.

    Returns a PSCustomObject with .Session (the Posh-SSH SSH session) and
    metadata. Pass it back into Invoke-TorchElasticQuery via -Session for reuse.

.NOTES
    SO 3.0 Kratos cookie auth blocks all headless HTTP. SSH is the supported
    automation channel - see file header for the full rationale.
    For non-SO stacks use Get-ElasticDetonationLogs.
#>
    [CmdletBinding()]
    param(
        [string]$VaultHost    = 'TORCH_SSH_Host',
        [string]$VaultUser    = 'TORCH_SSH_User',
        [string]$VaultPass    = 'TORCH_SSH_Pass',
        [string]$VaultKeyPath = 'TORCH_SSH_KeyPath',
        [int]$Port            = 22
    )

    Assert-PoshSSH

    $sshHost = Resolve-TorchSecret -Name $VaultHost -AsPlainText
    $sshUser = Resolve-TorchSecret -Name $VaultUser -AsPlainText
    $sshKey  = Resolve-TorchSecret -Name $VaultKeyPath -AsPlainText
    $sshPass = Resolve-TorchSecret -Name $VaultPass

    $missing = @()
    if ([string]::IsNullOrWhiteSpace($sshHost)) { $missing += $VaultHost }
    if ([string]::IsNullOrWhiteSpace($sshUser)) { $missing += $VaultUser }
    if ([string]::IsNullOrWhiteSpace($sshKey) -and -not $sshPass) {
        $missing += "$VaultKeyPath or $VaultPass"
    }
    if ($missing.Count -gt 0) {
        throw "Missing vault secret(s): $($missing -join ', '). Set with: Set-Secret -Name <name> -Secret <value>"
    }

    try {
        if ($sshKey -and (Test-Path $sshKey)) {
            # Key-based auth. Posh-SSH wants a PSCredential even for key auth;
            # the password field is the optional key passphrase (empty allowed).
            $emptyPw = ConvertTo-SecureString -String ' ' -AsPlainText -Force
            $cred = [pscredential]::new($sshUser, $emptyPw)
            $session = New-SSHSession -ComputerName $sshHost -Port $Port `
                                      -Credential $cred -KeyFile $sshKey `
                                      -AcceptKey -ErrorAction Stop
            $authMode = 'key'
        }
        else {
            if ($sshPass -isnot [securestring]) {
                $sshPass = ConvertTo-SecureString -String ([string]$sshPass) -AsPlainText -Force
            }
            $cred = [pscredential]::new($sshUser, $sshPass)
            $session = New-SSHSession -ComputerName $sshHost -Port $Port `
                                      -Credential $cred -AcceptKey -ErrorAction Stop
            $authMode = 'password'
        }
    }
    catch {
        $msg = $_.Exception.Message
        if ($msg -match 'refused|timed out|No such host|unreachable') {
            throw "SSH connection to $sshHost`:$Port failed ($msg). Check: VPN connected, SO host up, 22/tcp open from your VPN subnet."
        }
        throw "SSH session open failed: $msg"
    }

    [PSCustomObject]@{
        Session   = $session
        SessionId = $session.SessionId
        Host      = $sshHost
        User      = $sshUser
        AuthMode  = $authMode
        OpenedAt  = (Get-Date).ToUniversalTime()
    }
}

# -----------------------------------------------------------------------------
function Invoke-TorchElasticQuery {
<#
.SYNOPSIS
    Run an Elasticsearch _search against Security Onion 3.0 over SSH.

.DESCRIPTION
    Serializes the supplied query hashtable to JSON, base64-encodes it (to
    sidestep ALL shell quoting issues with embedded quotes, backslashes, and
    dollar signs), writes the decoded body to a unique /tmp file on the SO
    host, and invokes:

        sudo so-elasticsearch-query '<index>/_search?size=<n>' -d '@/tmp/<file>'

    The helper authenticates to localhost ES via /opt/so/conf/elasticsearch/
    curl.config. Returns parsed JSON unless -Raw is specified.

.PARAMETER IndexPattern
    Index or alias pattern, e.g. 'logs-*' or '.ds-logs-windows.sysmon-*'.

.PARAMETER Query
    Hashtable that will become the _search request body (query, sort, size,
    search_after, aggs, etc.).

.PARAMETER Size
    Page size on the URL. Default 1000.

.PARAMETER CommandTimeout
    SSH command timeout in seconds. Default 120.

.PARAMETER Session
    Optional reused session object from Get-TorchSSHSession.

.PARAMETER Raw
    Return raw stdout instead of parsed JSON.

.NOTES
    SO 3.0 Kratos cookie auth makes ApiKey / Basic / Bearer impossible against
    the proxy. See module header for the full explanation. For non-SO Elastic
    clusters use Get-ElasticDetonationLogs.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$IndexPattern,
        [Parameter(Mandatory)][hashtable]$Query,
        [int]$Size = 1000,
        [int]$CommandTimeout = 120,
        [PSCustomObject]$Session,
        [switch]$Raw
    )

    Assert-PoshSSH

    $ownSession = $false
    if (-not $Session) {
        $Session = Get-TorchSSHSession
        $ownSession = $true
    }

    try {
        # --- serialize body ---
        $bodyJson = $Query | ConvertTo-Json -Depth 20 -Compress
        $b64      = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($bodyJson))
        $tempPath = "/tmp/tq_$([guid]::NewGuid().ToString('N')).json"
        $urlPath  = "$IndexPattern/_search?size=$Size"

        # --- resolve sudo password ---
        # so-elasticsearch-query reads /opt/so/conf/elasticsearch/curl.config
        # which is root-owned mode 600, so sudo is required. Over Posh-SSH
        # there's no TTY for the interactive password prompt, so we have to
        # feed sudo via stdin using `sudo -S`. Try a dedicated TORCH_SSH_
        # SudoPass secret first; fall back to TORCH_SSH_Pass (which is the
        # same SSH login password on most SO 3.0 setups since the secon
        # account uses the same password for both).
        $sudoPass = $null
        try { $sudoPass = (Get-Secret -Name 'TORCH_SSH_SudoPass' -AsPlainText -ErrorAction Stop).Trim() } catch {}
        if ([string]::IsNullOrWhiteSpace($sudoPass)) {
            try { $sudoPass = (Get-Secret -Name 'TORCH_SSH_Pass' -AsPlainText -ErrorAction Stop).Trim() } catch {}
        }
        if ([string]::IsNullOrWhiteSpace($sudoPass)) {
            throw "sudo so-elasticsearch-query requires a password but neither TORCH_SSH_SudoPass nor TORCH_SSH_Pass is set in the vault. Set one with Set-Secret, or ask the SO admin to configure NOPASSWD sudo for /usr/sbin/so-elasticsearch-query."
        }

        # --- build remote command ---
        # Single-quoted base64 is shell-safe (no $, no `, no \).
        # For the sudo password embedded in the shell command, single-quote
        # escape any literal apostrophes via the '\'' idiom.
        $sudoPassQuoted = $sudoPass -replace "'", "'\''"
        $cmd = "echo '$b64' | base64 -d > $tempPath && printf '%s\n' '$sudoPassQuoted' | sudo -S -p '' so-elasticsearch-query '$urlPath' -d '@$tempPath' ; rc=`$? ; rm -f $tempPath ; exit `$rc"

        # --- execute ---
        $result = Invoke-SSHCommand -SessionId $Session.SessionId -Command $cmd -TimeOut $CommandTimeout -ErrorAction Stop

        $stdout = ($result.Output    | Out-String)
        $stderr = ($result.Error     | Out-String)
        $rc     = $result.ExitStatus

        if ($rc -ne 0) {
            if ($stderr -match 'so-elasticsearch-query.*not found|command not found') {
                throw "so-elasticsearch-query missing on $($Session.Host). SO 3.0 helper not installed - escalate to your Security Onion admin."
            }
            throw "so-elasticsearch-query failed (exit=$rc).`nSTDERR:`n$stderr`nSTDOUT:`n$stdout"
        }

        # --- surface stderr even on rc=0 -----------------------------------
        # rc=0 with non-empty stderr usually means sudo/curl/MOTD chatter
        # leaked into the channel. -Verbose always sees it. If the chatter
        # smells like a sudo / cred / lecture failure, warn loudly because
        # stdout is probably corrupted JSON.
        if (-not [string]::IsNullOrWhiteSpace($stderr)) {
            Write-Verbose "so-elasticsearch-query stderr (rc=0): $stderr"
            if ($stderr -match '(?i)\bsudo\b|\bpassword\b|\bdenied\b|Sorry, try again') {
                Write-Warning "so-elasticsearch-query returned rc=0 but stderr smells like a sudo / credential failure - stdout is likely corrupted:`n$stderr"
            }
        }

        if ($Raw) { return $stdout }

        try {
            return ($stdout | ConvertFrom-Json -Depth 20 -ErrorAction Stop)
        } catch {
            Write-Warning "ConvertFrom-Json failed: $($_.Exception.Message). Returning raw stdout."
            return $stdout
        }
    }
    finally {
        if ($ownSession -and $Session -and $null -ne $Session.SessionId) {
            try { Remove-SSHSession -SessionId $Session.SessionId -ErrorAction SilentlyContinue | Out-Null } catch { }
        }
    }
}

# -----------------------------------------------------------------------------
function Invoke-TorchElasticDiagnose {
<#
.SYNOPSIS
    Triage probe for Security Onion 3.0 Elasticsearch pulls that return zero
    events across all datasets.

.DESCRIPTION
    Runs four labelled probes against the same SSH/sudo path the real pull
    uses, so anything broken end-to-end reproduces inside the probe:

      A. _cat/indices?v&s=index   - lists the top indices on the cluster so
                                    the operator can see whether logs-* even
                                    exists and which Fleet datastreams are
                                    backing it.
      B. Unfiltered count on logs-* over [StartTime, EndTime] - proves
         whether Fleet is shipping ANY events in the window. 0 here means
         the ingest path is the problem, not the dataset/host filters.
      C. terms agg on event.dataset over the same window - reveals the
         real dataset strings Fleet is writing (e.g. SO 3.0 frequently
         labels Sysmon as 'windows.sysmon_operational' but some integrations
         use 'windows.sysmon' or 'sysmon').
      D. terms aggs on host.name, host.hostname, agent.name over the same
         window - reveals which host field carries the detonation hostname
         and in what casing, so -HostFilter can be tuned.

    Probes B/C/D deliberately IGNORE -HostFilter so the operator can see
    whether the host filter itself was the cause of the zero result.

    Auto-invoked by Save-TorchElasticDetonationLogs when every dataset
    returns 0. Also reachable via Save-TorchElasticDetonationLogs -Diagnose
    (probe only, no NDJSON pull).

.PARAMETER StartTime
    Inclusive lower bound. Default: 24 hours ago (UTC).

.PARAMETER EndTime
    Inclusive upper bound. Default: now (UTC).

.PARAMETER HostFilter
    Informational only. Printed in the banner so the operator can see what
    filter the failing pull was using; probes B/C/D do not apply it.

.PARAMETER Session
    Optional reused session object from Get-TorchSSHSession.

.NOTES
    Probe output is printed to the host stream. Nothing is returned. The
    function does not throw on per-probe failures; it prints and continues
    so later probes still run.
#>
    [CmdletBinding()]
    param(
        [datetime]$StartTime    = (Get-Date).ToUniversalTime().AddHours(-24),
        [datetime]$EndTime      = (Get-Date).ToUniversalTime(),
        [string]$HostFilter,
        [PSCustomObject]$Session
    )

    Assert-PoshSSH

    $ownSession = $false
    if (-not $Session) {
        $Session = Get-TorchSSHSession
        $ownSession = $true
    }

    # DateTime.ToUniversalTime() treats Kind=Unspecified as Local and shifts
    # by the local-to-UTC offset, which silently produces a wrong-window query
    # if a caller passes a parser-output DateTime that was already in UTC but
    # not tagged. Handle each Kind explicitly so we trust Utc, convert Local,
    # and assume Utc for Unspecified.
    $toUtc = {
        param([datetime]$t)
        if     ($t.Kind -eq [DateTimeKind]::Utc)   { return $t }
        elseif ($t.Kind -eq [DateTimeKind]::Local) { return $t.ToUniversalTime() }
        else                                       { return [DateTime]::SpecifyKind($t, [DateTimeKind]::Utc) }
    }
    $startUtc = & $toUtc $StartTime
    $endUtc   = & $toUtc $EndTime
    $startIso = $startUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")
    $endIso   = $endUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")

    try {
        Write-Host ""
        Write-Host "================================================================" -ForegroundColor Cyan
        Write-Host " TORCH Elastic diagnostic probe" -ForegroundColor Cyan
        Write-Host "   Window     : $startIso  ->  $endIso" -ForegroundColor Cyan
        Write-Host "   HostFilter : $(if ($HostFilter) { $HostFilter } else { '(none)' })" -ForegroundColor Cyan
        Write-Host "================================================================" -ForegroundColor Cyan

        # --- helper: print ES error envelope if present, return $true if it was an error ---
        $printEsError = {
            param($resp, $label)
            if ($resp -is [pscustomobject] -and $resp.PSObject.Properties.Name -contains 'error' -and $resp.error) {
                $etype   = if ($resp.error.PSObject.Properties.Name -contains 'type')   { $resp.error.type }   else { '(no type)' }
                $ereason = if ($resp.error.PSObject.Properties.Name -contains 'reason') { $resp.error.reason } else { '(no reason)' }
                Write-Warning "[$label] Elasticsearch error envelope: $etype - $ereason"
                return $true
            }
            return $false
        }

        # --------------------------------------------------------------
        # Probe A - _cat/indices?v&s=index&format=json
        # --------------------------------------------------------------
        Write-Host ""
        Write-Host "[A] _cat/indices  (top indices by docs.count) ---------------" -ForegroundColor Yellow
        try {
            # _cat/indices is not a _search endpoint, so the helper's URL
            # shape ('<index>/_search?size=N') in Invoke-TorchElasticQuery
            # cannot produce _cat output. Call so-elasticsearch-query
            # directly over the existing SSH session for this one probe.
            $sudoPass = $null
            try { $sudoPass = (Get-Secret -Name 'TORCH_SSH_SudoPass' -AsPlainText -ErrorAction Stop).Trim() } catch {}
            if ([string]::IsNullOrWhiteSpace($sudoPass)) {
                try { $sudoPass = (Get-Secret -Name 'TORCH_SSH_Pass' -AsPlainText -ErrorAction Stop).Trim() } catch {}
            }
            if ([string]::IsNullOrWhiteSpace($sudoPass)) {
                Write-Warning "[A] Cannot run _cat/indices probe - no sudo password in vault."
            } else {
                $sudoPassQuoted = $sudoPass -replace "'", "'\''"
                $catCmd = "printf '%s\n' '$sudoPassQuoted' | sudo -S -p '' so-elasticsearch-query '_cat/indices?v&s=index'"
                $catResult = Invoke-SSHCommand -SessionId $Session.SessionId -Command $catCmd -TimeOut 60 -ErrorAction Stop
                $catOut = ($catResult.Output | Out-String)
                $catErr = ($catResult.Error  | Out-String)
                if (-not [string]::IsNullOrWhiteSpace($catErr)) {
                    Write-Warning "[A] stderr: $catErr"
                }
                if ([string]::IsNullOrWhiteSpace($catOut)) {
                    Write-Warning "[A] _cat/indices returned no stdout."
                } else {
                    # _cat/indices header looks like:
                    # health status index uuid pri rep docs.count docs.deleted store.size pri.store.size
                    $lines = $catOut -split "`r?`n" | Where-Object { $_ -and $_.Trim().Length -gt 0 }
                    if ($lines.Count -lt 2) {
                        Write-Host "    (header only - cluster has no indices)" -ForegroundColor DarkGray
                    } else {
                        $header  = $lines[0]
                        $body    = $lines | Select-Object -Skip 1
                        # Parse docs.count column (index 6 in default _cat layout)
                        $parsed = foreach ($l in $body) {
                            $cols = ($l -split '\s+') | Where-Object { $_ -ne '' }
                            if ($cols.Count -ge 7) {
                                [PSCustomObject]@{
                                    Index    = $cols[2]
                                    Docs     = [int64]($cols[6] -replace '[^\d]', '0')
                                    StoreSz  = if ($cols.Count -ge 9) { $cols[8] } else { '' }
                                }
                            }
                        }
                        $top = $parsed | Sort-Object Docs -Descending | Select-Object -First 30
                        Write-Host "    $header" -ForegroundColor DarkGray
                        $top | Format-Table -AutoSize | Out-String | Write-Host
                    }
                }
            }
        } catch {
            Write-Warning "[A] probe failed: $($_.Exception.Message)"
        }

        # --------------------------------------------------------------
        # Probe B - unfiltered count on logs-* over the window
        # --------------------------------------------------------------
        Write-Host ""
        Write-Host "[B] logs-*  unfiltered count in window ----------------------" -ForegroundColor Yellow
        try {
            $bBody = @{
                size              = 0
                track_total_hits  = $true
                query             = @{
                    range = @{ '@timestamp' = @{ gte = $startIso; lte = $endIso } }
                }
            }
            $bResp = Invoke-TorchElasticQuery -IndexPattern 'logs-*' `
                                              -Query $bBody `
                                              -Size 0 `
                                              -Session $Session
            if (-not (& $printEsError $bResp 'B')) {
                $total = $null
                if ($bResp -and $bResp.hits -and $bResp.hits.total) {
                    if ($bResp.hits.total.PSObject.Properties.Name -contains 'value') {
                        $total = $bResp.hits.total.value
                    } else {
                        $total = $bResp.hits.total
                    }
                }
                if ($null -eq $total) {
                    Write-Warning "[B] response had no hits.total - response may be malformed."
                } elseif ($total -eq 0) {
                    Write-Host "    hits.total.value = 0" -ForegroundColor Red
                    Write-Host "    -> Fleet is NOT shipping any events into logs-* in this window." -ForegroundColor Red
                    Write-Host "    -> Check Fleet agent health on the detonation host, integration policies, and clock skew." -ForegroundColor Red
                } else {
                    Write-Host "    hits.total.value = $total" -ForegroundColor Green
                    Write-Host "    -> Fleet IS shipping. The zero result is from dataset/host filters, not ingest." -ForegroundColor Green
                }
            }
        } catch {
            Write-Warning "[B] probe failed: $($_.Exception.Message)"
        }

        # --------------------------------------------------------------
        # Probe C - terms agg on event.dataset
        # --------------------------------------------------------------
        Write-Host ""
        Write-Host "[C] logs-*  terms agg on event.dataset (top 25) -------------" -ForegroundColor Yellow
        try {
            $cBody = @{
                size  = 0
                query = @{
                    range = @{ '@timestamp' = @{ gte = $startIso; lte = $endIso } }
                }
                aggs  = @{
                    ds = @{ terms = @{ field = 'event.dataset'; size = 25 } }
                }
            }
            $cResp = Invoke-TorchElasticQuery -IndexPattern 'logs-*' `
                                              -Query $cBody `
                                              -Size 0 `
                                              -Session $Session
            if (-not (& $printEsError $cResp 'C')) {
                $buckets = @()
                if ($cResp -and $cResp.aggregations -and $cResp.aggregations.ds -and $cResp.aggregations.ds.buckets) {
                    $buckets = $cResp.aggregations.ds.buckets
                }
                if (-not $buckets -or $buckets.Count -eq 0) {
                    Write-Host "    (no event.dataset buckets)" -ForegroundColor Red
                    Write-Host "    -> Either no events in window, or event.dataset is not indexed as a keyword field." -ForegroundColor Red
                } else {
                    $buckets | ForEach-Object {
                        [PSCustomObject]@{ EventDataset = $_.key; DocCount = $_.doc_count }
                    } | Format-Table -AutoSize | Out-String | Write-Host
                }
            }
        } catch {
            Write-Warning "[C] probe failed: $($_.Exception.Message)"
        }

        # --------------------------------------------------------------
        # Probe D - terms aggs on host.name, host.hostname, agent.name
        # --------------------------------------------------------------
        Write-Host ""
        Write-Host "[D] logs-*  terms aggs on host.name / host.hostname / agent.name (top 25 each) ---" -ForegroundColor Yellow
        try {
            $dBody = @{
                size  = 0
                query = @{
                    range = @{ '@timestamp' = @{ gte = $startIso; lte = $endIso } }
                }
                aggs  = @{
                    by_host_name     = @{ terms = @{ field = 'host.name';     size = 25 } }
                    by_host_hostname = @{ terms = @{ field = 'host.hostname'; size = 25 } }
                    by_agent_name    = @{ terms = @{ field = 'agent.name';    size = 25 } }
                }
            }
            $dResp = Invoke-TorchElasticQuery -IndexPattern 'logs-*' `
                                              -Query $dBody `
                                              -Size 0 `
                                              -Session $Session
            if (-not (& $printEsError $dResp 'D')) {
                $fieldMap = @(
                    @{ Label = 'host.name';     Path = 'by_host_name' },
                    @{ Label = 'host.hostname'; Path = 'by_host_hostname' },
                    @{ Label = 'agent.name';    Path = 'by_agent_name' }
                )
                foreach ($fm in $fieldMap) {
                    Write-Host "    -- $($fm.Label) --" -ForegroundColor DarkGray
                    $buckets = @()
                    if ($dResp -and $dResp.aggregations -and $dResp.aggregations.($fm.Path) -and $dResp.aggregations.($fm.Path).buckets) {
                        $buckets = $dResp.aggregations.($fm.Path).buckets
                    }
                    if (-not $buckets -or $buckets.Count -eq 0) {
                        Write-Host "       (no buckets)" -ForegroundColor DarkGray
                    } else {
                        $buckets | ForEach-Object {
                            [PSCustomObject]@{ Value = $_.key; DocCount = $_.doc_count }
                        } | Format-Table -AutoSize | Out-String | Write-Host
                    }
                }
                if (-not [string]::IsNullOrWhiteSpace($HostFilter)) {
                    Write-Host "    NOTE: pull used -HostFilter '$HostFilter' as an EXACT match on host.name." -ForegroundColor Yellow
                    Write-Host "          If '$HostFilter' is missing or differently-cased above, that explains the zero result." -ForegroundColor Yellow
                }
            }
        } catch {
            Write-Warning "[D] probe failed: $($_.Exception.Message)"
        }

        Write-Host ""
        Write-Host "================================================================" -ForegroundColor Cyan
        Write-Host " End of diagnostic probe" -ForegroundColor Cyan
        Write-Host "================================================================" -ForegroundColor Cyan
        Write-Host ""
    }
    finally {
        if ($ownSession -and $Session -and $null -ne $Session.SessionId) {
            try { Remove-SSHSession -SessionId $Session.SessionId -ErrorAction SilentlyContinue | Out-Null } catch { }
        }
    }
}

# -----------------------------------------------------------------------------
function Save-TorchElasticDetonationLogs {
<#
.SYNOPSIS
    Pull detonation-window logs from Security Onion 3.0 over SSH and write
    NDJSON files matching the offline ElasticAlertAgent partition shim layout.

.DESCRIPTION
    For each dataset in:
        windows.sysmon_operational
        windows.powershell_operational
        windows.powershell
        system.security
        system.application
        system.system
    runs a time-bounded query (event.dataset = <dataset> AND @timestamp in
    [StartTime, EndTime]), paginates via sort + search_after on @timestamp,
    and writes one document per line to <OutputDir>/<dataset>.ndjson.

    Also writes session_info.txt in the format the offline ElasticAlertAgent
    partition shim already parses:
        Campaign         : <name>
        Detonation host  : <host>
        Detonation start : <iso8601 Z>
        Detonation end   : <iso8601 Z>
        Window end       : <iso8601 Z>

.PARAMETER Diagnose
    Skip the dataset pull and run only Invoke-TorchElasticDiagnose (lists
    indices, runs unfiltered count, terms-agg on event.dataset and
    host.name / host.hostname / agent.name) against [StartTime, EndTime].
    Use to validate Fleet ingest + field shape before a real pull. On this
    path OutputDir is unused; no NDJSON / session_info.txt / summary.csv
    are written.

.NOTES
    When every dataset reports 0 events the function auto-invokes
    Invoke-TorchElasticDiagnose against the same window/host filter before
    closing the SSH session, so the operator gets triage output in the same
    run without having to re-execute.

    For non-SO clusters use Get-ElasticDetonationLogs (GetElasticDetonationLogs
    .psm1). SO 3.0 Kratos cookie auth blocks all headless HTTP - see module
    header.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][datetime]$StartTime,
        [Parameter(Mandatory)][datetime]$EndTime,
        [Parameter(Mandatory)][string]$OutputDir,
        [string]$HostFilter,
        [string]$SessionInfoCampaign,
        [int]$PageSize = 1000,
        [int]$MaxPages = 200,
        [switch]$Diagnose
    )

    Assert-PoshSSH

    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }

    # DateTime.ToUniversalTime() treats Kind=Unspecified as Local and shifts
    # by the local-to-UTC offset, which silently produces a wrong-window query
    # if a caller passes a parser-output DateTime that was already in UTC but
    # not tagged. Handle each Kind explicitly so we trust Utc, convert Local,
    # and assume Utc for Unspecified.
    $toUtc = {
        param([datetime]$t)
        if     ($t.Kind -eq [DateTimeKind]::Utc)   { return $t }
        elseif ($t.Kind -eq [DateTimeKind]::Local) { return $t.ToUniversalTime() }
        else                                       { return [DateTime]::SpecifyKind($t, [DateTimeKind]::Utc) }
    }
    $startUtc = & $toUtc $StartTime
    $endUtc   = & $toUtc $EndTime
    $startIso = $startUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")
    $endIso   = $endUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")

    # Canonical Fleet dataset name -> acceptable alternates we'll OR against.
    # SO 3.0 Fleet ships windows.* via the Windows integration today, but
    # historically the same telemetry has landed under bare 'sysmon',
    # 'winlog.sysmon', 'powershell.operational', etc. depending on the
    # integration version or whether it shipped via Winlogbeat. Using `terms`
    # (plural) with the alias list keeps a renamed/older deployment from
    # silently returning zero events.
    $datasetAliases = [ordered]@{
        'windows.sysmon_operational'      = @('windows.sysmon_operational', 'windows.sysmon', 'sysmon', 'winlog.sysmon')
        'windows.powershell_operational'  = @('windows.powershell_operational', 'windows.powershell.operational', 'powershell.operational', 'powershell_operational')
        'windows.powershell'              = @('windows.powershell', 'powershell')
        'system.security'                 = @('system.security', 'windows.security', 'security', 'winlog.security')
        'system.application'              = @('system.application', 'windows.application', 'application', 'winlog.application')
        'system.system'                   = @('system.system', 'windows.system', 'system', 'winlog.system')
    }
    $datasets = @($datasetAliases.Keys)

    $session = Get-TorchSSHSession
    $summary = @()

    # --- -Diagnose: probe only, no pull, no NDJSON, no summary files ---------
    if ($Diagnose) {
        try {
            Invoke-TorchElasticDiagnose -StartTime $StartTime `
                                        -EndTime   $EndTime `
                                        -HostFilter $HostFilter `
                                        -Session   $session
        }
        finally {
            try { Remove-SSHSession -SessionId $session.SessionId -ErrorAction SilentlyContinue | Out-Null } catch { }
        }
        return
    }

    try {
        foreach ($ds in $datasets) {
            Write-Host "[*] Pulling $ds  $startIso -> $endIso" -ForegroundColor DarkCyan

            # `terms` (plural) lets event.dataset match any of the canonical
            # name or its known alternates (see $datasetAliases above).
            $filters = @(
                @{ terms = @{ 'event.dataset' = $datasetAliases[$ds] } },
                @{ range = @{ '@timestamp' = @{ gte = $startIso; lte = $endIso } } }
            )
            if (-not [string]::IsNullOrWhiteSpace($HostFilter)) {
                # Match the supplied -HostFilter against any of the five
                # fields Fleet / winlogbeat / Elastic Agent commonly populate
                # for Windows hosts, in any casing the user might have
                # supplied OR that Fleet's "Host name format" policy may have
                # written. Wildcard clauses on the lowercased value catch
                # FQDN-formatted values (e.g. win11_sandbox.lab.local) per
                # ECS host.name guidance + the SO 3.0 Fleet FQDN toggle.
                $hostCasings = @(
                    $HostFilter,
                    $HostFilter.ToLowerInvariant(),
                    $HostFilter.ToUpperInvariant()
                ) | Select-Object -Unique
                $hostFields = @('host.name', 'host.hostname', 'agent.name', 'agent.hostname', 'winlog.computer_name')
                $hostShould = @()
                foreach ($field in $hostFields) {
                    foreach ($casing in $hostCasings) {
                        $hostShould += @{ term = @{ $field = $casing } }
                    }
                }
                $hostLower = $HostFilter.ToLowerInvariant()
                foreach ($field in @('host.name', 'host.hostname', 'agent.name', 'agent.hostname')) {
                    $hostShould += @{ wildcard = @{ $field = "*$hostLower*" } }
                }
                $filters += @{ bool = @{ should = $hostShould; minimum_should_match = 1 } }
            }

            $outFile = Join-Path $OutputDir "$ds.ndjson"
            if (Test-Path $outFile) { Remove-Item $outFile -Force }

            $writer   = [System.IO.StreamWriter]::new($outFile, $false, [System.Text.Encoding]::UTF8)
            $total    = 0
            $searchAfter = $null

            try {
                for ($page = 0; $page -lt $MaxPages; $page++) {
                    $body = @{
                        size  = $PageSize
                        sort  = @( @{ '@timestamp' = 'asc' }, @{ '_id' = 'asc' } )
                        query = @{ bool = @{ filter = $filters } }
                    }
                    if ($searchAfter) { $body['search_after'] = $searchAfter }

                    $resp = Invoke-TorchElasticQuery -IndexPattern 'logs-*' `
                                                     -Query $body `
                                                     -Size $PageSize `
                                                     -Session $session

                    $hits = @()
                    if ($resp -and $resp.hits -and $resp.hits.hits) { $hits = $resp.hits.hits }
                    if (-not $hits -or $hits.Count -eq 0) { break }

                    foreach ($h in $hits) {
                        $writer.WriteLine(($h | ConvertTo-Json -Depth 20 -Compress))
                    }
                    $total += $hits.Count

                    $last = $hits[-1]
                    if (-not $last.sort) { break }
                    $searchAfter = $last.sort
                    if ($hits.Count -lt $PageSize) { break }
                }
            }
            finally { $writer.Close() }

            Write-Host "    -> $total events ($outFile)" -ForegroundColor Green
            $summary += [PSCustomObject]@{ Dataset = $ds; Count = $total; File = "$ds.ndjson" }
        }

        # --- auto-diagnostic when every dataset returned 0 events ---------
        # Runs INSIDE the outer try so the SSH session is still open. This
        # is intentionally informational - a probe failure does not block
        # the session_info.txt / summary.csv writes below.
        $zeroAcrossAll = ($summary.Count -gt 0) -and (($summary | Where-Object { $_.Count -gt 0 }).Count -eq 0)
        if ($zeroAcrossAll) {
            Write-Host ""
            Write-Host "[!] All datasets returned 0 - running auto-diagnostic probe..." -ForegroundColor Yellow
            try {
                Invoke-TorchElasticDiagnose -StartTime $StartTime `
                                            -EndTime   $EndTime `
                                            -HostFilter $HostFilter `
                                            -Session   $session
            } catch {
                Write-Warning "Auto-diagnostic probe failed: $($_.Exception.Message)"
            }
        }
    }
    finally {
        try { Remove-SSHSession -SessionId $session.SessionId -ErrorAction SilentlyContinue | Out-Null } catch { }
    }

    # --- session_info.txt (format consumed by ElasticAlertAgent shim) -------
    $metaLines = @()
    if (-not [string]::IsNullOrWhiteSpace($SessionInfoCampaign)) {
        $metaLines += "Campaign         : $SessionInfoCampaign"
    }
    if (-not [string]::IsNullOrWhiteSpace($HostFilter)) {
        $metaLines += "Detonation host  : $HostFilter"
    }
    $metaLines += "Detonation start : $startIso"
    $metaLines += "Detonation end   : $endIso"
    $metaLines += "Window end       : $endIso"
    $metaLines += ""
    $metaLines += "Dataset Counts:"
    foreach ($s in $summary) {
        $metaLines += ("  {0} {1}" -f $s.Dataset.PadRight(34), $s.Count)
    }
    $metaLines | Set-Content -Path (Join-Path $OutputDir 'session_info.txt') -Encoding UTF8

    $summary | Export-Csv -Path (Join-Path $OutputDir 'summary.csv') -NoTypeInformation -Encoding UTF8

    Write-Host ""
    Write-Host "Done. Detonation logs saved to:" -ForegroundColor Green
    Write-Host "  $OutputDir" -ForegroundColor DarkCyan
    $summary | Format-Table -AutoSize | Out-Host
    return $OutputDir
}

# -----------------------------------------------------------------------------
Export-ModuleMember -Function Get-TorchSSHSession, Invoke-TorchElasticQuery, Invoke-TorchElasticDiagnose, Save-TorchElasticDetonationLogs
