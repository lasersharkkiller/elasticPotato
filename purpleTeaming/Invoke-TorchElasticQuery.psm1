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

        # --- build remote command ---
        # Single-quoted base64 is shell-safe (no $, no `, no \).
        $cmd = "echo '$b64' | base64 -d > $tempPath && sudo so-elasticsearch-query '$urlPath' -d '@$tempPath' ; rc=`$? ; rm -f $tempPath ; exit `$rc"

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

        if ($Raw) { return $stdout }

        try {
            return ($stdout | ConvertFrom-Json -Depth 20 -ErrorAction Stop)
        } catch {
            Write-Warning "ConvertFrom-Json failed: $($_.Exception.Message). Returning raw stdout."
            return $stdout
        }
    }
    finally {
        if ($ownSession -and $Session -and $Session.SessionId -ne $null) {
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

.NOTES
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
        [int]$MaxPages = 200
    )

    Assert-PoshSSH

    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }

    $startIso = $StartTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $endIso   = $EndTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

    $datasets = @(
        'windows.sysmon_operational',
        'windows.powershell_operational',
        'windows.powershell',
        'system.security',
        'system.application',
        'system.system'
    )

    $session = Get-TorchSSHSession
    $summary = @()

    try {
        foreach ($ds in $datasets) {
            Write-Host "[*] Pulling $ds  $startIso -> $endIso" -ForegroundColor DarkCyan

            $filters = @(
                @{ term  = @{ 'event.dataset' = $ds } },
                @{ range = @{ '@timestamp' = @{ gte = $startIso; lte = $endIso } } }
            )
            if (-not [string]::IsNullOrWhiteSpace($HostFilter)) {
                $filters += @{ term = @{ 'host.name' = $HostFilter } }
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
    $summary | Format-Table -AutoSize
}

# -----------------------------------------------------------------------------
Export-ModuleMember -Function Get-TorchSSHSession, Invoke-TorchElasticQuery, Save-TorchElasticDetonationLogs
