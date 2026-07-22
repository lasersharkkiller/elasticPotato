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

# --- SSH transport soft check (warn-only at module load) ---------------------
# Prefer Posh-SSH; fall back to the native Windows OpenSSH client (ssh.exe) so the
# SSH connector still works on air-gapped hosts with no PSGallery access.
if (-not (Get-Module -ListAvailable -Name 'Posh-SSH')) {
    if (Get-Command ssh.exe -ErrorAction SilentlyContinue) {
        Write-Verbose "Posh-SSH not installed; the SSH connector will use the native OpenSSH client (ssh.exe)."
    } else {
        Write-Warning "Neither Posh-SSH nor the native OpenSSH client (ssh.exe) was found - the SSH connector will fail."
        Write-Warning "Install Posh-SSH (Install-Module -Name Posh-SSH -Scope CurrentUser -Force), or enable the"
        Write-Warning "built-in Windows OpenSSH Client (Settings > Optional Features > OpenSSH Client)."
    }
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
# Resolve the sudo password for so-elasticsearch-query. A password carried on the
# SSH session object (set by Get-TorchSSHSession from a -SshPass / -SudoPass param
# or an interactive prompt) wins; otherwise fall back to the TORCH_SSH_SudoPass /
# TORCH_SSH_Pass vault secrets. This lets the SO pull run offline with no vault.
function Resolve-TorchSudoPass {
    param($Session)
    if ($Session -and ($Session.PSObject.Properties.Name -contains 'SudoPass') -and
        -not [string]::IsNullOrWhiteSpace($Session.SudoPass)) {
        return $Session.SudoPass
    }
    $sp = $null
    try { $sp = (Get-Secret -Name 'TORCH_SSH_SudoPass' -AsPlainText -ErrorAction Stop).Trim() } catch {}
    if ([string]::IsNullOrWhiteSpace($sp)) {
        try { $sp = (Get-Secret -Name 'TORCH_SSH_Pass' -AsPlainText -ErrorAction Stop).Trim() } catch {}
    }
    return $sp
}

# -----------------------------------------------------------------------------
# Ensure SOME SSH transport is available. Posh-SSH is preferred (handles password
# auth non-interactively); otherwise the native Windows OpenSSH client (ssh.exe) is
# used. Throws only if NEITHER is present. (Name kept for existing call sites.)
function Assert-PoshSSH {
    if (Get-Module -ListAvailable -Name 'Posh-SSH') {
        Import-Module Posh-SSH -ErrorAction Stop | Out-Null
        return
    }
    if (Get-TorchSshExe) { return }   # native ssh.exe fallback
    throw "No SSH transport available. Install Posh-SSH (Install-Module -Name Posh-SSH -Scope CurrentUser -Force) or enable the built-in Windows OpenSSH Client (Settings > Optional Features > OpenSSH Client / ssh.exe on PATH)."
}

# Path to the native OpenSSH client (built into Windows 10/11, 1809+). $null if absent.
function Get-TorchSshExe {
    $c = Get-Command ssh.exe -ErrorAction SilentlyContinue
    if ($c -and $c.Source) { return $c.Source }
    $sys = Join-Path $env:WINDIR 'System32\OpenSSH\ssh.exe'
    if (Test-Path $sys) { return $sys }
    return $null
}

# Recursively rehydrate JavaScriptSerializer output (Dictionary / Object[]) into
# PSCustomObjects + arrays so it matches ConvertFrom-Json's shape exactly.
function ConvertTo-TorchPSObject {
    param($InputObject)
    if ($InputObject -is [System.Collections.IDictionary]) {
        $h = [ordered]@{}
        foreach ($k in $InputObject.Keys) { $h[$k] = ConvertTo-TorchPSObject $InputObject[$k] }
        return [PSCustomObject]$h
    }
    if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
        return @(foreach ($item in $InputObject) { ConvertTo-TorchPSObject $item })
    }
    return $InputObject
}

# Cross-version, size-safe JSON parse. Windows PowerShell 5.1's ConvertFrom-Json uses
# JavaScriptSerializer, which throws once the JSON exceeds MaxJsonLength (~2MB) - a large
# ES page (e.g. PowerShell 4104 scriptblocks) blows past it and the page is lost. PS6+
# ConvertFrom-Json handles any size. On 5.1 we try ConvertFrom-Json first (fast, native
# types) and fall back to an unbounded serializer, rehydrated to the same PSCustomObject
# shape so callers see no difference.
function ConvertFrom-TorchJson {
    param([Parameter(Mandatory)][string]$Json)
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        return ($Json | ConvertFrom-Json -ErrorAction Stop)
    }
    try {
        return ($Json | ConvertFrom-Json -ErrorAction Stop)
    } catch {
        Add-Type -AssemblyName System.Web.Extensions -ErrorAction Stop
        $ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer
        $ser.MaxJsonLength  = [int]::MaxValue
        $ser.RecursionLimit = 1000
        return (ConvertTo-TorchPSObject ($ser.DeserializeObject($Json)))
    }
}

# Run one remote command over the native OpenSSH client, returning an object shaped
# like Posh-SSH's Invoke-SSHCommand result (.Output / .Error / .ExitStatus). The
# command is base64-wrapped so Windows/PowerShell argument quoting cannot mangle its
# pipes/quotes/semicolons - the wire form is only [A-Za-z0-9+/=] plus a fixed shell.
function Invoke-TorchNativeSshCommand {
    param($Session, [string]$Command, [int]$TimeOut = 120)

    $cmdB64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Command))
    $remote = "echo $cmdB64 | base64 -d | bash"

    $argv = New-Object System.Collections.Generic.List[string]
    $argv.Add('-p'); $argv.Add([string]$Session.Port)
    $argv.Add('-o'); $argv.Add('StrictHostKeyChecking=accept-new')
    $argv.Add('-o'); $argv.Add('ConnectTimeout=15')
    $argv.Add('-o'); $argv.Add('LogLevel=ERROR')
    if ($Session.KeyPath) { $argv.Add('-o'); $argv.Add('BatchMode=yes'); $argv.Add('-i'); $argv.Add([string]$Session.KeyPath) }
    $argv.Add("$($Session.User)@$($Session.Host)")
    $argv.Add($remote)
    # Quote only the args that contain whitespace (the base64-wrapped remote cmd; a key path).
    $quoted = $argv | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName               = $Session.SshExe
    $psi.Arguments              = ($quoted -join ' ')
    $psi.UseShellExecute        = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    if ($Session.Interactive) {
        # Password-prompt fallback: keep the console (don't redirect stdin) so ssh can read the
        # password from CONIN$; stdout/stderr are still captured via the pipes above.
        $psi.RedirectStandardInput = $false
        $psi.CreateNoWindow        = $false
    } else {
        # Non-interactive: key (-i/BatchMode) or SSH_ASKPASS (env). No TTY -> ssh uses askpass.
        $psi.RedirectStandardInput = $true
        $psi.CreateNoWindow        = $true
    }

    $proc = [System.Diagnostics.Process]::Start($psi)
    if (-not $Session.Interactive) { try { $proc.StandardInput.Close() } catch {} }
    # Read both streams concurrently (async) to avoid a pipe-buffer deadlock on large output.
    $outTask = $proc.StandardOutput.ReadToEndAsync()
    $errTask = $proc.StandardError.ReadToEndAsync()
    $waitMs  = if ($Session.Interactive) { [int]::MaxValue } else { $TimeOut * 1000 }
    if (-not $proc.WaitForExit($waitMs)) {
        try { $proc.Kill() } catch {}
        return [PSCustomObject]@{ Output = ''; Error = "native ssh command timed out after $TimeOut s"; ExitStatus = 124 }
    }
    $proc.WaitForExit()
    $stdout = $outTask.Result
    $stderr = $errTask.Result
    $rc     = $proc.ExitCode
    if ($rc -eq 255) {
        # ssh transport-level failure (auth / host / connection), not a remote-command rc.
        $stderr = "ssh transport error (exit 255) to $($Session.User)@$($Session.Host): $stderr"
    }
    return [PSCustomObject]@{ Output = $stdout; Error = $stderr; ExitStatus = $rc }
}

# Dispatch a remote command over whichever transport the session was opened with.
function Invoke-TorchRemoteCommand {
    param($Session, [string]$Command, [int]$TimeOut = 120)
    if ($Session.Transport -eq 'native') {
        return (Invoke-TorchNativeSshCommand -Session $Session -Command $Command -TimeOut $TimeOut)
    }
    $r = Invoke-SSHCommand -SessionId $Session.SessionId -Command $Command -TimeOut $TimeOut -ErrorAction Stop
    return [PSCustomObject]@{ Output = $r.Output; Error = $r.Error; ExitStatus = $r.ExitStatus }
}

# Tear down a session for whichever transport it uses.
function Close-TorchSSHSession {
    param($Session)
    if (-not $Session) { return }
    if ($Session.Transport -eq 'native') {
        if ($Session.AskpassExe) {
            try { Remove-Item -Force -ErrorAction SilentlyContinue $Session.AskpassExe } catch {}
        }
        $env:SSH_ASKPASS = $null; $env:SSH_ASKPASS_REQUIRE = $null; $env:DISPLAY = $null; $env:TORCH_ASKPASS_VALUE = $null
        return
    }
    if ($null -ne $Session.SessionId) {
        try { Remove-SSHSession -SessionId $Session.SessionId -ErrorAction SilentlyContinue | Out-Null } catch {}
    }
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
        # Direct SSH credentials (offline / no vault). Each overrides the matching
        # TORCH_SSH_* vault secret below; anything still missing is prompted for.
        [string]$SshHost,
        [string]$SshUser,
        [string]$SshPass,
        [string]$SshKeyPath,
        [string]$SudoPass,
        [string]$VaultHost    = 'TORCH_SSH_Host',
        [string]$VaultUser    = 'TORCH_SSH_User',
        [string]$VaultPass    = 'TORCH_SSH_Pass',
        [string]$VaultKeyPath = 'TORCH_SSH_KeyPath',
        [int]$Port            = 22
    )

    Assert-PoshSSH

    # Precedence: explicit parameter > vault secret > interactive prompt.
    $sshHost = if (-not [string]::IsNullOrWhiteSpace($SshHost))    { $SshHost }    else { Resolve-TorchSecret -Name $VaultHost -AsPlainText }
    $sshUser = if (-not [string]::IsNullOrWhiteSpace($SshUser))    { $SshUser }    else { Resolve-TorchSecret -Name $VaultUser -AsPlainText }
    $sshKey  = if (-not [string]::IsNullOrWhiteSpace($SshKeyPath)) { $SshKeyPath } else { Resolve-TorchSecret -Name $VaultKeyPath -AsPlainText }
    $sshPass = if (-not [string]::IsNullOrWhiteSpace($SshPass))    { $SshPass }    else { Resolve-TorchSecret -Name $VaultPass }

    # Interactive fallback (offline / no vault): prompt for anything still missing.
    if ([string]::IsNullOrWhiteSpace($sshHost)) { $sshHost = (Read-Host "[?] Security Onion SSH host / IP").Trim() }
    if ([string]::IsNullOrWhiteSpace($sshUser)) { $sshUser = (Read-Host "[?] SO SSH username").Trim() }
    if ([string]::IsNullOrWhiteSpace($sshKey) -and -not $sshPass) {
        $__sp = Read-Host "[?] SO SSH password (blank to use a private key file instead)" -AsSecureString
        if ($__sp -and $__sp.Length -gt 0) { $sshPass = $__sp }
        else { $sshKey = (Read-Host "[?] SO SSH private key path").Trim() }
    }

    $missing = @()
    if ([string]::IsNullOrWhiteSpace($sshHost)) { $missing += 'host' }
    if ([string]::IsNullOrWhiteSpace($sshUser)) { $missing += 'user' }
    if ([string]::IsNullOrWhiteSpace($sshKey) -and -not $sshPass) { $missing += 'password or key' }
    if ($missing.Count -gt 0) {
        throw "Missing SSH credential(s): $($missing -join ', '). Pass -SshHost/-SshUser/-SshPass (or -SshKeyPath), set TORCH_SSH_* vault secrets, or answer the prompts."
    }

    # Normalize the login password to plaintext for sudo reuse: so-elasticsearch-query
    # needs it via `sudo -S`. Stored on the returned session as .SudoPass; -SudoPass
    # overrides when the sudo password differs from the SSH login password.
    $sshPassPlain = $null
    if ($sshPass -is [securestring]) {
        $__b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sshPass)
        try   { $sshPassPlain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($__b) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($__b) }
    } elseif ($sshPass) {
        $sshPassPlain = [string]$sshPass
    }
    $sudoPassPlain = if (-not [string]::IsNullOrWhiteSpace($SudoPass)) { $SudoPass } else { $sshPassPlain }

    if (Get-Module -ListAvailable -Name 'Posh-SSH') {
        # --- Posh-SSH transport (preferred: handles password auth non-interactively) ---
        Import-Module Posh-SSH -ErrorAction Stop | Out-Null
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

        return [PSCustomObject]@{
            Transport = 'posh'
            Session   = $session
            SessionId = $session.SessionId
            Host      = $sshHost
            User      = $sshUser
            Port      = $Port
            AuthMode  = $authMode
            SudoPass  = $sudoPassPlain   # plaintext, reused for `sudo -S so-elasticsearch-query`
            OpenedAt  = (Get-Date).ToUniversalTime()
        }
    }

    # --- Native OpenSSH client transport (offline / no PSGallery) --------------------
    # Posh-SSH is absent, so use the built-in Windows ssh.exe. Key auth is fully
    # non-interactive. Password auth can't be passed on the command line, and Windows
    # OpenSSH ControlMaster multiplexing is broken (getsockname/EBADF), so we feed the
    # password via SSH_ASKPASS + a helper exe compiled on the fly (non-interactive); if
    # the local OpenSSH won't honor it, we fall back to a per-command console prompt.
    $sshExe = Get-TorchSshExe
    if (-not $sshExe) {
        throw "Posh-SSH is not installed and the native OpenSSH client (ssh.exe) was not found. Install Posh-SSH (Install-Module -Name Posh-SSH -Scope CurrentUser -Force) or enable Windows' built-in OpenSSH Client."
    }
    $keyPath     = if ($sshKey -and (Test-Path $sshKey)) { $sshKey } else { $null }
    $askpassExe  = $null
    $interactive = $false
    if (-not $keyPath) {
        if ([string]::IsNullOrWhiteSpace($sshPassPlain)) {
            throw "Native ssh password auth needs the password but none was resolved. Provide -SshPass / TORCH_SSH_Pass, use a key (-SshKeyPath / TORCH_SSH_KeyPath), or install Posh-SSH."
        }
        # Compile a tiny askpass helper that echoes an env var (unique class name so a second
        # pull in the same session doesn't collide on the type).
        $askClass   = "TorchAskpass_$([guid]::NewGuid().ToString('N'))"
        $askpassExe = Join-Path ([System.IO.Path]::GetTempPath()) "torch_askpass_$([guid]::NewGuid().ToString('N')).exe"
        try {
            Add-Type -OutputType ConsoleApplication -OutputAssembly $askpassExe -ErrorAction Stop `
                     -TypeDefinition "using System; class $askClass { static void Main() { string v = Environment.GetEnvironmentVariable(`"TORCH_ASKPASS_VALUE`"); Console.WriteLine(v == null ? `"`" : v); } }"
        } catch {
            $askpassExe = $null
            Write-Host "[SSH] askpass helper compile failed ($($_.Exception.Message)); will prompt per command." -ForegroundColor DarkYellow
        }
        $env:TORCH_ASKPASS_VALUE = $sshPassPlain
        if ($askpassExe -and (Test-Path $askpassExe)) {
            $env:SSH_ASKPASS         = $askpassExe
            $env:SSH_ASKPASS_REQUIRE = 'force'
            $env:DISPLAY             = 'localhost:0.0'
            Write-Host "[SSH] Testing non-interactive password auth to $sshUser@$sshHost (SSH_ASKPASS)..." -ForegroundColor DarkCyan
            $probeSession = [PSCustomObject]@{ Transport = 'native'; SshExe = $sshExe; Host = $sshHost; User = $sshUser; Port = $Port; KeyPath = $null; Interactive = $false }
            $askOk = $false
            try {
                $probe = Invoke-TorchNativeSshCommand -Session $probeSession -Command 'echo torch_probe_ok' -TimeOut 25
                if ($probe -and ($probe.Output -match 'torch_probe_ok')) { $askOk = $true }
            } catch {}
            if ($askOk) {
                Write-Host "[SSH] Non-interactive password auth established (SSH_ASKPASS)." -ForegroundColor DarkGreen
            } else {
                Remove-Item -Force -ErrorAction SilentlyContinue $askpassExe
                $askpassExe = $null
                $env:SSH_ASKPASS = $null; $env:SSH_ASKPASS_REQUIRE = $null; $env:DISPLAY = $null; $env:TORCH_ASKPASS_VALUE = $null
                $interactive = $true
                Write-Host "[SSH] Non-interactive auth unavailable - you'll be prompted for the SSH password once per query (use -SshKeyPath for zero prompts)." -ForegroundColor DarkYellow
            }
        } else {
            $env:TORCH_ASKPASS_VALUE = $null
            $interactive = $true
        }
    }

    return [PSCustomObject]@{
        Transport   = 'native'
        SshExe      = $sshExe
        Session     = $null
        SessionId   = $null
        Host        = $sshHost
        User        = $sshUser
        Port        = $Port
        KeyPath     = $keyPath
        AskpassExe  = $askpassExe
        Interactive = $interactive
        AuthMode    = if ($keyPath) { 'key' } elseif ($interactive) { 'password-prompt' } else { 'password-askpass' }
        SudoPass    = $sudoPassPlain   # plaintext, reused for `sudo -S so-elasticsearch-query`
        OpenedAt    = (Get-Date).ToUniversalTime()
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
        $sudoPass = Resolve-TorchSudoPass -Session $Session
        if ([string]::IsNullOrWhiteSpace($sudoPass)) {
            throw "sudo so-elasticsearch-query requires a password but none was available (session, TORCH_SSH_SudoPass, or TORCH_SSH_Pass). Provide -SshPass/-SudoPass to Save-TorchElasticDetonationLogs, set the vault secret, or configure NOPASSWD sudo for /usr/sbin/so-elasticsearch-query."
        }

        # --- build remote command ---
        # Single-quoted base64 is shell-safe (no $, no `, no \).
        # For the sudo password embedded in the shell command, single-quote
        # escape any literal apostrophes via the '\'' idiom.
        $sudoPassQuoted = $sudoPass -replace "'", "'\''"
        $cmd = "echo '$b64' | base64 -d > $tempPath && printf '%s\n' '$sudoPassQuoted' | sudo -S -p '' so-elasticsearch-query '$urlPath' -d '@$tempPath' ; rc=`$? ; rm -f $tempPath ; exit `$rc"

        # --- execute ---
        $result = Invoke-TorchRemoteCommand -Session $Session -Command $cmd -TimeOut $CommandTimeout

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
            return (ConvertFrom-TorchJson $stdout)
        } catch {
            Write-Warning "JSON parse failed: $($_.Exception.Message). Returning raw stdout."
            return $stdout
        }
    }
    finally {
        if ($ownSession -and $Session) {
            Close-TorchSSHSession -Session $Session
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

.PARAMETER IndexPattern
    Elasticsearch index pattern targeted by probes B/C/D/E/F. Default is
    'logs-*' which is the SO 3.0 Fleet datastream pattern (matches the
    95% case). Operators on non-Fleet clusters should override with
    'winlogbeat-*', 'filebeat-*', 'auditbeat-*', or a CSV combining
    patterns such as 'logs-*,winlogbeat-*'. Probe A is pattern-independent
    (it lists all indices on the cluster regardless of this value).

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
        [string]$IndexPattern   = 'logs-*',
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
            $sudoPass = Resolve-TorchSudoPass -Session $Session
            if ([string]::IsNullOrWhiteSpace($sudoPass)) {
                Write-Warning "[A] Cannot run _cat/indices probe - no sudo password available (session or vault)."
            } else {
                $sudoPassQuoted = $sudoPass -replace "'", "'\''"
                $catCmd = "printf '%s\n' '$sudoPassQuoted' | sudo -S -p '' so-elasticsearch-query '_cat/indices?v&s=index'"
                $catResult = Invoke-TorchRemoteCommand -Session $Session -Command $catCmd -TimeOut 60
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
        Write-Host "[B] $IndexPattern  unfiltered count in window ----------------------" -ForegroundColor Yellow
        try {
            $bBody = @{
                size              = 0
                track_total_hits  = $true
                query             = @{
                    range = @{ '@timestamp' = @{ gte = $startIso; lte = $endIso } }
                }
            }
            $bResp = Invoke-TorchElasticQuery -IndexPattern $IndexPattern `
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
                    Write-Host "    -> Fleet is NOT shipping any events into $IndexPattern in this window." -ForegroundColor Red
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
        Write-Host "[C] $IndexPattern  terms agg on event.dataset (top 25) -------------" -ForegroundColor Yellow
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
            $cResp = Invoke-TorchElasticQuery -IndexPattern $IndexPattern `
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
        Write-Host "[D] $IndexPattern  terms aggs on host.name / host.hostname / agent.name (top 25 each) ---" -ForegroundColor Yellow
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
            $dResp = Invoke-TorchElasticQuery -IndexPattern $IndexPattern `
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

        # --------------------------------------------------------------
        # Probe E - cross-tab event.dataset x host.name/.hostname/agent.name
        # --------------------------------------------------------------
        # Resolves the puzzle when probe C says 'event.dataset = X has Y
        # docs' AND probe D says 'host.name = Z has W docs' but the pull's
        # conjunction returns zero. Either (a) the X docs are from a host
        # OTHER than Z, or (b) the X docs are missing host.name entirely.
        # This nested agg shows the per-dataset host breakdown.
        Write-Host ""
        Write-Host "[E] $IndexPattern  cross-tab: event.dataset -> host.name / host.hostname / agent.name ---" -ForegroundColor Yellow
        try {
            $eBody = @{
                size  = 0
                query = @{
                    range = @{ '@timestamp' = @{ gte = $startIso; lte = $endIso } }
                }
                aggs  = @{
                    by_dataset = @{
                        terms = @{ field = 'event.dataset'; size = 15 }
                        aggs  = @{
                            by_host_name     = @{ terms = @{ field = 'host.name';     size = 5 } }
                            by_host_hostname = @{ terms = @{ field = 'host.hostname'; size = 5 } }
                            by_agent_name    = @{ terms = @{ field = 'agent.name';    size = 5 } }
                        }
                    }
                }
            }
            $eResp = Invoke-TorchElasticQuery -IndexPattern $IndexPattern `
                                              -Query $eBody `
                                              -Size 0 `
                                              -Session $Session
            if (-not (& $printEsError $eResp 'E')) {
                $dsBuckets = @()
                if ($eResp -and $eResp.aggregations -and $eResp.aggregations.by_dataset -and $eResp.aggregations.by_dataset.buckets) {
                    $dsBuckets = $eResp.aggregations.by_dataset.buckets
                }
                if (-not $dsBuckets -or $dsBuckets.Count -eq 0) {
                    Write-Host "    (no event.dataset buckets returned)" -ForegroundColor Red
                } else {
                    foreach ($db in $dsBuckets) {
                        $dsKey   = $db.key
                        $dsCount = $db.doc_count
                        Write-Host ""
                        Write-Host "    event.dataset = $dsKey  ($dsCount docs)" -ForegroundColor Cyan
                        $subFieldMap = @(
                            @{ Label = 'host.name    '; Path = 'by_host_name'     },
                            @{ Label = 'host.hostname'; Path = 'by_host_hostname' },
                            @{ Label = 'agent.name   '; Path = 'by_agent_name'    }
                        )
                        foreach ($sf in $subFieldMap) {
                            $sub = @()
                            if ($db.($sf.Path) -and $db.($sf.Path).buckets) { $sub = $db.($sf.Path).buckets }
                            if (-not $sub -or $sub.Count -eq 0) {
                                Write-Host "       $($sf.Label) : (none)" -ForegroundColor DarkGray
                            } else {
                                $pairs = ($sub | ForEach-Object { "$($_.key)=$($_.doc_count)" }) -join ', '
                                Write-Host "       $($sf.Label) : $pairs" -ForegroundColor DarkGray
                            }
                        }
                    }
                }
            }
        } catch {
            Write-Warning "[E] probe failed: $($_.Exception.Message)"
        }

        # --------------------------------------------------------------
        # Probe F - replay the EXACT pull body for sysmon and dump both
        # request JSON and ES response. Used when the pull keeps returning
        # 0 even though probes B/C/D/E prove the data is there - the only
        # remaining culprits are (1) something about how the pull body
        # serializes, (2) something in the SO so-elasticsearch-query
        # wrapper that we cannot see from here, (3) a field-mapping quirk
        # (text vs keyword) that does not affect aggregations but does
        # affect term queries.
        Write-Host ""
        Write-Host "[F] REPLAY pull body for windows.sysmon_operational + dump request/response ---" -ForegroundColor Yellow
        try {
            # Reconstruct the EXACT shape Save-TorchElasticDetonationLogs builds.
            # The pull only adds the host.name terms clause when HostFilter is set
            # (see Save-TorchElasticDetonationLogs lines 891-913), so the replay
            # must mirror that to be a true replay. Host-less replay is what we
            # actually want when the user reports the pull failing without
            # -HostFilter.
            $sysAliases = @('windows.sysmon_operational', 'windows.sysmon', 'sysmon', 'winlog.sysmon')
            $fFilters = @(
                @{ terms = @{ 'event.dataset' = $sysAliases } },
                @{ range = @{ '@timestamp' = @{ gte = $startIso; lte = $endIso } } }
            )
            if (-not [string]::IsNullOrWhiteSpace($HostFilter)) {
                $hostValues = @($HostFilter, $HostFilter.ToLowerInvariant(), $HostFilter.ToUpperInvariant()) | Select-Object -Unique
                $fFilters += @{ terms = @{ 'host.name' = $hostValues } }
            }
            $fBody = @{
                size              = 0
                track_total_hits  = $true
                query             = @{ bool = @{ filter = $fFilters } }
            }

            Write-Host "    --- REQUEST BODY (exact JSON sent to ES) ---" -ForegroundColor DarkGray
            $reqJson = $fBody | ConvertTo-Json -Depth 20 -Compress
            Write-Host "    $reqJson" -ForegroundColor DarkGray

            $fRespRaw = Invoke-TorchElasticQuery -IndexPattern $IndexPattern `
                                                -Query $fBody `
                                                -Size 0 `
                                                -Session $Session `
                                                -Raw
            Write-Host ""
            Write-Host "    --- RAW ES RESPONSE (first 4000 chars) ---" -ForegroundColor DarkGray
            $respPreview = if ($fRespRaw -and $fRespRaw.Length -gt 4000) { $fRespRaw.Substring(0, 4000) + "...[truncated]" } else { $fRespRaw }
            Write-Host "    $respPreview" -ForegroundColor DarkGray

            # Surface byte-level corruption (sudo PAM lecture, BOM, ANSI escapes
            # leaking into stdout) that would silently break ConvertFrom-Json.
            # Theory: base64-of-sudo-stdout corrupted by terminal control codes.
            if ($fRespRaw -and $fRespRaw.Length -gt 0) {
                $firstChar = [int][char]$fRespRaw[0]
                $lastChar  = [int][char]$fRespRaw[$fRespRaw.Length - 1]
                $startsClean = ($fRespRaw[0] -eq '{')
                $endsClean   = ($fRespRaw.TrimEnd()[-1] -eq '}')
                Write-Host "    --- RAW response sanity: len=$($fRespRaw.Length) firstByte=0x$('{0:X2}' -f $firstChar) lastByte=0x$('{0:X2}' -f $lastChar) startsWithBrace=$startsClean endsWithBrace=$endsClean" -ForegroundColor DarkGray
                if (-not $startsClean) {
                    Write-Warning "    Raw response does NOT start with '{' - sudo/PAM/BOM corruption likely. ConvertFrom-Json will fail silently in the pull."
                }
            }
            Write-Host ""

            # Variants 1-3 are host-agnostic and run unconditionally - these
            # are the most diagnostic when the pull is failing without a
            # -HostFilter.
            $variants = @(
                @{
                    Label = 'range only (sanity, expect ~1276)'
                    Body  = @{ size = 0; track_total_hits = $true; query = @{ range = @{ '@timestamp' = @{ gte = $startIso; lte = $endIso } } } }
                },
                @{
                    Label = 'range + terms event.dataset (expect ~99)'
                    Body  = @{ size = 0; track_total_hits = $true; query = @{ bool = @{ filter = @(
                        @{ range = @{ '@timestamp' = @{ gte = $startIso; lte = $endIso } } },
                        @{ terms = @{ 'event.dataset' = $sysAliases } }
                    ) } } }
                },
                @{
                    Label = 'range + term event.dataset SINGLE (expect ~99)'
                    Body  = @{ size = 0; track_total_hits = $true; query = @{ bool = @{ filter = @(
                        @{ range = @{ '@timestamp' = @{ gte = $startIso; lte = $endIso } } },
                        @{ term  = @{ 'event.dataset' = 'windows.sysmon_operational' } }
                    ) } } }
                }
            )

            # ----- Diagnostic variants for Input 2 theories (HIGH/MEDIUM only) -----
            # Each variant isolates ONE difference between the pull body and the
            # already-passing probes B/C/E. Whichever variant first goes to 0 is
            # the killer.

            # T1 (HIGH): sort on `_id` triggers shard-level failure that the SO
            #            wrapper renders as empty hits, not an error envelope.
            #            This variant is the EXACT pull body shape (sort +
            #            size=PageSize-ish + track_total_hits + bool.filter) -
            #            the pull body has never been replayed verbatim.
            $variants += @{
                Label = 'EXACT PULL BODY: sort[@timestamp,_id] + size=1000 + track_total_hits (HIGH theory: _id sort kills it)'
                Body  = @{
                    size              = 1000
                    track_total_hits  = $true
                    sort              = @( @{ '@timestamp' = 'asc' }, @{ '_id' = 'asc' } )
                    query             = @{ bool = @{ filter = @(
                        @{ terms = @{ 'event.dataset' = $sysAliases } },
                        @{ range = @{ '@timestamp' = @{ gte = $startIso; lte = $endIso } } }
                    ) } }
                }
            }

            # T1b (HIGH): same as above but DROP the _id secondary sort - if this
            #             one returns ~99 while T1 returns 0, _id sort is the
            #             killer.
            $variants += @{
                Label = 'sort[@timestamp ONLY] + size=1000 + track_total_hits (HIGH theory: _id sort is the killer)'
                Body  = @{
                    size              = 1000
                    track_total_hits  = $true
                    sort              = @( @{ '@timestamp' = 'asc' } )
                    query             = @{ bool = @{ filter = @(
                        @{ terms = @{ 'event.dataset' = $sysAliases } },
                        @{ range = @{ '@timestamp' = @{ gte = $startIso; lte = $endIso } } }
                    ) } }
                }
            }

            # T2 (MEDIUM): URL ?size=N vs body size conflict. The pull goes
            #              through Invoke-TorchElasticQuery which appends
            #              ?size=$Size to the URL AND sets body.size. This
            #              variant tests body size only (-Size 0 on the URL).
            $variants += @{
                Label = 'body size=1000 but URL size=0 (MED theory: URL size collides with body size)'
                Body  = @{
                    size              = 1000
                    track_total_hits  = $true
                    query             = @{ bool = @{ filter = @(
                        @{ terms = @{ 'event.dataset' = $sysAliases } },
                        @{ range = @{ '@timestamp' = @{ gte = $startIso; lte = $endIso } } }
                    ) } }
                }
            }

            # T3 (MEDIUM): ConvertTo-Json may merge the two-hashtable sort array
            #              into a single object. We can verify by dumping it
            #              right now and inspecting the JSON.
            $sortDump = @( @{ '@timestamp' = 'asc' }, @{ '_id' = 'asc' } ) | ConvertTo-Json -Depth 5 -Compress
            Write-Host "    --- sort-array JSON sanity (MED theory: array collapses to object) ---" -ForegroundColor DarkGray
            Write-Host "    sort = $sortDump" -ForegroundColor DarkGray
            if ($sortDump -notmatch '^\[' -or $sortDump -notmatch '\]$') {
                Write-Warning "    sort array did NOT serialize as a JSON array - this matches the MEDIUM theory."
            }

            # T4 (MEDIUM): `+=` on a hashtable array produces object[] not
            #              hashtable[]; ConvertTo-Json may treat the dotted key
            #              `event.dataset` as a nested path. Variant uses a
            #              single literal @(...) for $filters (no `+=`).
            $literalFilters = @(
                @{ terms = @{ 'event.dataset' = $sysAliases } },
                @{ range = @{ '@timestamp' = @{ gte = $startIso; lte = $endIso } } }
            )
            $variants += @{
                Label = 'filters built as ONE literal @(...) no `+=` (MED theory: += corrupts dotted key)'
                Body  = @{
                    size              = 0
                    track_total_hits  = $true
                    query             = @{ bool = @{ filter = $literalFilters } }
                }
            }

            # T5 (MEDIUM): event.dataset is constant_keyword on Fleet backing
            #              indices; a multi-value `terms` list can return 0 on
            #              ES 8.0-8.4. This variant is a SINGLE-element terms
            #              list against the one true canonical name.
            $variants += @{
                Label = 'range + terms event.dataset SINGLE-ELEMENT [windows.sysmon_operational] (MED theory: constant_keyword regression)'
                Body  = @{
                    size              = 0
                    track_total_hits  = $true
                    query             = @{ bool = @{ filter = @(
                        @{ range = @{ '@timestamp' = @{ gte = $startIso; lte = $endIso } } },
                        @{ terms = @{ 'event.dataset' = @('windows.sysmon_operational') } }
                    ) } }
                }
            }

            # T6 (MEDIUM): Posh-SSH buffer truncation on large responses. Same
            #              pull body but tiny page size - if size=10 returns
            #              non-zero and size=1000 returns 0, buffer truncation
            #              is confirmed.
            $variants += @{
                Label = 'pull body but size=10 (MED theory: Posh-SSH buffer truncates >1MB responses)'
                Body  = @{
                    size              = 10
                    track_total_hits  = $true
                    sort              = @( @{ '@timestamp' = 'asc' }, @{ '_id' = 'asc' } )
                    query             = @{ bool = @{ filter = @(
                        @{ terms = @{ 'event.dataset' = $sysAliases } },
                        @{ range = @{ '@timestamp' = @{ gte = $startIso; lte = $endIso } } }
                    ) } }
                }
            }

            # T7 (LOW promoted to add coverage): track_total_hits = $false may
            #     change ES code path away from the buggy preflight rewrite.
            $variants += @{
                Label = 'range + terms event.dataset + track_total_hits=$false (LOW theory: rewrite path)'
                Body  = @{
                    size              = 0
                    track_total_hits  = $false
                    query             = @{ bool = @{ filter = @(
                        @{ range = @{ '@timestamp' = @{ gte = $startIso; lte = $endIso } } },
                        @{ terms = @{ 'event.dataset' = $sysAliases } }
                    ) } }
                }
            }

            # Variants 4-8 (host-specific) only meaningful when HostFilter is set.
            if (-not [string]::IsNullOrWhiteSpace($HostFilter)) {
                $variants += @(
                    @{
                        Label = 'range + term host.name (lowercase)  (expect ~221 if host.name is keyword)'
                        Body  = @{ size = 0; track_total_hits = $true; query = @{ bool = @{ filter = @(
                            @{ range = @{ '@timestamp' = @{ gte = $startIso; lte = $endIso } } },
                            @{ term  = @{ 'host.name' = $HostFilter.ToLowerInvariant() } }
                        ) } } }
                    },
                    @{
                        Label = 'range + term host.name.keyword (lowercase)'
                        Body  = @{ size = 0; track_total_hits = $true; query = @{ bool = @{ filter = @(
                            @{ range = @{ '@timestamp' = @{ gte = $startIso; lte = $endIso } } },
                            @{ term  = @{ 'host.name.keyword' = $HostFilter.ToLowerInvariant() } }
                        ) } } }
                    },
                    @{
                        Label = 'range + match host.name (lowercase)'
                        Body  = @{ size = 0; track_total_hits = $true; query = @{ bool = @{ filter = @(
                            @{ range = @{ '@timestamp' = @{ gte = $startIso; lte = $endIso } } },
                            @{ match = @{ 'host.name' = $HostFilter.ToLowerInvariant() } }
                        ) } } }
                    },
                    @{
                        Label = 'range + match agent.name (preserved case)'
                        Body  = @{ size = 0; track_total_hits = $true; query = @{ bool = @{ filter = @(
                            @{ range = @{ '@timestamp' = @{ gte = $startIso; lte = $endIso } } },
                            @{ match = @{ 'agent.name' = $HostFilter } }
                        ) } } }
                    },
                    @{
                        Label = 'range + term agent.name (preserved case, keyword test)'
                        Body  = @{ size = 0; track_total_hits = $true; query = @{ bool = @{ filter = @(
                            @{ range = @{ '@timestamp' = @{ gte = $startIso; lte = $endIso } } },
                            @{ term  = @{ 'agent.name' = $HostFilter } }
                        ) } } }
                    }
                )
            } else {
                Write-Host "    (no HostFilter supplied - skipping host-specific variants 4-8)" -ForegroundColor Yellow
            }

            Write-Host "    --- FALLBACK VARIANT TESTS (each is range + ONE more filter) ---" -ForegroundColor DarkGray
            foreach ($v in $variants) {
                try {
                    # For variants that exercise the pull body shape (size > 0)
                    # use -Size matching body.size so URL ?size=N is consistent.
                    $urlSize = if ($v.Body.ContainsKey('size')) { [int]$v.Body['size'] } else { 0 }
                    $vr = Invoke-TorchElasticQuery -IndexPattern $IndexPattern -Query $v.Body -Size $urlSize -Session $Session
                    $vt = $null
                    if ($vr -and $vr.hits -and $vr.hits.total) {
                        $vt = if ($vr.hits.total.PSObject.Properties.Name -contains 'value') { $vr.hits.total.value } else { $vr.hits.total }
                    }
                    if ($vr -is [pscustomobject] -and $vr.PSObject.Properties.Name -contains 'error' -and $vr.error) {
                        Write-Host "      [ERR] $($v.Label): $($vr.error.type) - $($vr.error.reason)" -ForegroundColor Red
                    } elseif ($vr -is [pscustomobject] -and $vr.PSObject.Properties.Name -contains '_shards' -and $vr._shards.failed -gt 0) {
                        # Theory T1: partial shard failure surfaces in _shards.failures,
                        # NOT in a top-level error envelope. Surface it loudly.
                        $shardReason = if ($vr._shards.failures -and $vr._shards.failures[0].reason) { $vr._shards.failures[0].reason.reason } else { '(no reason)' }
                        Write-Host "      [SHARD-FAIL] $($v.Label) = $vt (failed=$($vr._shards.failed)): $shardReason" -ForegroundColor Magenta
                    } else {
                        $color = if ($vt -gt 0) { 'Green' } else { 'Red' }
                        Write-Host "      $($v.Label) = $vt" -ForegroundColor $color
                    }
                } catch {
                    Write-Host "      [EXC] $($v.Label): $($_.Exception.Message)" -ForegroundColor Red
                }
            }
        } catch {
            Write-Warning "[F] probe failed: $($_.Exception.Message)"
        }

        Write-Host ""
        Write-Host "================================================================" -ForegroundColor Cyan
        Write-Host " End of diagnostic probe" -ForegroundColor Cyan
        Write-Host "================================================================" -ForegroundColor Cyan
        Write-Host ""
    }
    finally {
        if ($ownSession -and $Session) {
            Close-TorchSSHSession -Session $Session
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

.PARAMETER IndexPattern
    Elasticsearch index pattern queried for every dataset. Default is
    'logs-*' which is the SO 3.0 Fleet datastream pattern (matches the
    95% case - this is what the 3a orchestrator currently expects).
    Operators on non-Fleet clusters should override with 'winlogbeat-*',
    'filebeat-*', 'auditbeat-*', or a CSV combining patterns such as
    'logs-*,winlogbeat-*' (the SO so-elasticsearch-query wrapper passes
    the CSV through to the URL transparently). When -Diagnose is used,
    this same pattern is forwarded to Invoke-TorchElasticDiagnose.

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
        [string]$IndexPattern = 'logs-*',
        [string]$SessionInfoCampaign,
        [int]$PageSize = 1000,
        [int]$MaxPages = 200,
        [switch]$Diagnose,
        # Offline / no-vault SSH credentials. Override the TORCH_SSH_* vault secrets;
        # anything still missing is prompted for. -SudoPass defaults to -SshPass (SO
        # typically uses the same password for SSH login and sudo).
        [string]$SshHost,
        [string]$SshUser,
        [string]$SshPass,
        [string]$SshKeyPath,
        [string]$SudoPass
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

    # Linux Fleet / Elastic Agent dataset coverage. Concatenated unconditionally
    # so a single pull works against mixed Windows/Linux clusters. On a
    # Windows-only SO 3.0 lab these entries simply write empty NDJSON files
    # (0 hits) and add zero rows to summary.csv - they cannot reduce the
    # Windows result count. On a Linux Fleet-enrolled host, the 3a orchestrator's
    # Linux-detection regex at elasticPotato_Main.ps1 (matches `linux.`,
    # `auth_events`, `system.auth`, `system.syslog` filenames) auto-routes the
    # output directory to 3c (Invoke-ElasticLinuxTriage). The auditd ->
    # category-file shim (process_events.ndjson, file_events.ndjson,
    # network_events.ndjson, auth_events.ndjson) is deferred to a follow-up
    # commit; until it lands, the Linux triage module sees raw per-dataset
    # files but reports 0 events (its input contract is preserved unchanged).
    $linuxDatasetAliases = [ordered]@{
        'linux.auditd'              = @('linux.auditd', 'auditd.log', 'auditd', 'auditbeat.auditd')
        'system.auth'               = @('system.auth', 'linux.auth', 'auth', 'system.syslog')
        'system.syslog'             = @('system.syslog', 'linux.syslog', 'syslog', 'system.system')
        'system.journal'            = @('system.journal', 'journald', 'linux.journald')
        'endpoint.events.process'   = @('endpoint.events.process')
        'endpoint.events.network'   = @('endpoint.events.network')
        'endpoint.events.file'      = @('endpoint.events.file')
        'endpoint.events.library'   = @('endpoint.events.library')
        'endpoint.events.session'   = @('endpoint.events.session')
        'endpoint.events.api'       = @('endpoint.events.api')
        'file_integrity'            = @('file_integrity', 'auditbeat.file_integrity', 'fim')
    }
    foreach ($k in $linuxDatasetAliases.Keys) {
        $datasetAliases[$k] = $linuxDatasetAliases[$k]
    }

    $datasets = @($datasetAliases.Keys)

    # Open one SSH session and reuse it for every dataset. Credential params flow
    # through here (offline / no vault); the resolved sudo password rides on the
    # returned session and is read by Invoke-TorchElasticQuery / -Diagnose.
    $session = Get-TorchSSHSession -SshHost $SshHost -SshUser $SshUser -SshPass $SshPass -SshKeyPath $SshKeyPath -SudoPass $SudoPass
    $summary = @()

    # When no -HostFilter was supplied, we still want session_info.txt to
    # carry a 'Detonation host' line so the downstream Elastic Alert Agent
    # display shows the real hostname instead of falling back to the output
    # directory name. We sniff this from the first written doc - see the
    # candidate-field probe inside the foreach below. The probe tries fields
    # in priority order to be robust across Fleet / Winlogbeat / Auditbeat /
    # legacy beats deployments.
    $detectedHost = $null
    $hostCandidateFields = @(
        'host.hostname',          # OS-reported, preserves case (Win11_Sandbox)
        'agent.name',             # Fleet enrollment name; often matches hostname
        'host.name',              # ECS, may be lowercased/FQDN by policy
        'agent.hostname',          # Some older Elastic Agent ships
        'winlog.computer_name',   # Winlogbeat classic Windows event log
        'beat.hostname'           # very old beats; legacy fallback
    )

    # --- -Diagnose: probe only, no pull, no NDJSON, no summary files ---------
    if ($Diagnose) {
        try {
            Invoke-TorchElasticDiagnose -StartTime    $StartTime `
                                        -EndTime      $EndTime `
                                        -HostFilter   $HostFilter `
                                        -IndexPattern $IndexPattern `
                                        -Session      $session
        }
        finally {
            Close-TorchSSHSession -Session $session
        }
        return
    }

    try {
        foreach ($ds in $datasets) {
            Write-Host "[*] Pulling $ds  $startIso -> $endIso" -ForegroundColor DarkCyan

            # `terms` (plural) lets event.dataset match any of the canonical
            # name or its known alternates (see $datasetAliases above).
            # TODO: `$filters` is reassigned per dataset (so cross-dataset
            # filter bleed is NOT possible despite the audit's concern), but
            # the subsequent `$filters += @{...}` below promotes the array
            # type from hashtable[] to object[]. If Probe F's "filters built
            # as ONE literal @(...)" variant returns hits while the EXACT
            # pull body variant returns 0, switch to a [List[hashtable]] here.
            $filters = @(
                @{ terms = @{ 'event.dataset' = $datasetAliases[$ds] } },
                @{ range = @{ '@timestamp' = @{ gte = $startIso; lte = $endIso } } }
            )
            if (-not [string]::IsNullOrWhiteSpace($HostFilter)) {
                # Multi-field host filter: bool.should disjunction across the
                # five canonical host-identifier fields ECS exposes, each
                # carrying the three case variants of -HostFilter (literal,
                # lower, upper). minimum_should_match=1 means a doc qualifies
                # if ANY field matches ANY case - so non-Fleet deployments
                # that only populate host.hostname or agent.hostname (or
                # Winlogbeat which only writes winlog.computer_name) are now
                # covered without needing -HostFilter to be re-tuned.
                #
                # The inner bool runs in filter context (no scoring, cacheable)
                # which is the documented ES idiom. Probe F variant T1b proved
                # this multi-field shape works once the `_id` -> `_doc`
                # tiebreaker fix at the sort line below removed the previous
                # shard-rejection killer that masked the multi-field approach.
                #
                # Wildcard / FQDN expansion (e.g. host.name = 'WIN11*' or
                # 'win11.lab.local') is deferred to a follow-up iteration -
                # operators with FQDN deployments can still pass the exact
                # FQDN as -HostFilter today.
                $hostValues = @(
                    $HostFilter,
                    $HostFilter.ToLowerInvariant(),
                    $HostFilter.ToUpperInvariant()
                ) | Select-Object -Unique
                $hostFields = @('host.name', 'host.hostname', 'agent.name', 'agent.hostname', 'winlog.computer_name')
                $hostShould = foreach ($hf in $hostFields) {
                    @{ terms = @{ $hf = $hostValues } }
                }
                $filters += @{ bool = @{ should = @($hostShould); minimum_should_match = 1 } }
            }

            $outFile = Join-Path $OutputDir "$ds.ndjson"
            if (Test-Path $outFile) { Remove-Item $outFile -Force }

            $writer   = [System.IO.StreamWriter]::new($outFile, $false, [System.Text.Encoding]::UTF8)
            $total    = 0
            $searchAfter = $null

            $esTotalReported = $null   # what ES says hits.total.value is on page 0
            try {
                for ($page = 0; $page -lt $MaxPages; $page++) {
                    $body = @{
                        size              = $PageSize
                        track_total_hits  = $true
                        # Tiebreaker = `_doc` (NOT `_id`). Probe F variant test
                        # confirmed: ES 8.x rejects sort on `_id` because Fleet
                        # data streams ship with fielddata disabled on `_id`
                        # (the documented default since 7.10). The rejection
                        # surfaces as `_shards.failed > 0` with `hits.total=0`
                        # and empty `hits.hits` - NOT a top-level error envelope -
                        # which is why this looked like "no data matched" for
                        # many iterations. `_doc` is the official ES tiebreaker
                        # recommendation for `search_after` pagination without
                        # PIT (per https://elastic.co/docs/reference/elasticsearch
                        # /rest-apis/paginate-search-results#search-after).
                        sort              = @( @{ '@timestamp' = 'asc' }, '_doc' )
                        query             = @{ bool = @{ filter = $filters } }
                    }
                    if ($searchAfter) { $body['search_after'] = $searchAfter }

                    $resp = Invoke-TorchElasticQuery -IndexPattern $IndexPattern `
                                                     -Query $body `
                                                     -Size $PageSize `
                                                     -Session $session

                    # Pull-loop silent-failure audit finding #4 (HIGH): when
                    # ConvertFrom-Json fails inside Invoke-TorchElasticQuery
                    # the function returns the raw stdout STRING instead of a
                    # PSCustomObject. Without this guard the existing $resp.hits
                    # check silently sees $null and we break the page loop with
                    # zero hits written, no warning. Surface it loudly so the
                    # operator knows ES actually returned malformed JSON (BOM,
                    # sudo PAM lecture, truncation by Posh-SSH buffer, etc.).
                    if ($resp -is [string]) {
                        $preview = if ($resp.Length -gt 400) { $resp.Substring(0, 400) + '...[truncated]' } else { $resp }
                        Write-Warning "    Invoke-TorchElasticQuery returned a string instead of a parsed object on $ds (page $page) - ConvertFrom-Json upstream failed silently. Raw preview: $preview"
                        break
                    }

                    # ES error envelope detection - audit finding #4. Without this
                    # check a structurally-valid error response (400 mapper_parsing,
                    # 400 illegal_argument on bad query DSL, 503 shard failure, etc.)
                    # collapses identically to "no hits in window" because $resp.hits
                    # is null on error envelopes.
                    if ($resp -is [pscustomobject] -and $resp.PSObject.Properties.Name -contains 'error' -and $resp.error) {
                        $etype   = if ($resp.error.PSObject.Properties.Name -contains 'type')   { $resp.error.type }   else { '(no type)' }
                        $ereason = if ($resp.error.PSObject.Properties.Name -contains 'reason') { $resp.error.reason } else { '(no reason)' }
                        Write-Warning "    ES error envelope on $ds (page $page): $etype - $ereason"
                        break
                    }

                    # Input 2 theory T1 (HIGH): partial shard failures (e.g. sort
                    # on _id rejected by Fleet backing indices) surface in
                    # _shards.failures[], NOT in a top-level error envelope.
                    # Probe F only sees the top-level error path; without this
                    # the pull silently writes 0 docs when shards fail.
                    if ($resp -is [pscustomobject] -and $resp.PSObject.Properties.Name -contains '_shards' -and $resp._shards.failed -gt 0) {
                        $shardReason = if ($resp._shards.failures -and $resp._shards.failures[0].reason) { $resp._shards.failures[0].reason.reason } else { '(no reason)' }
                        Write-Warning "    ES shard failure on $ds (page $page): failed=$($resp._shards.failed) reason=$shardReason"
                    }

                    if ($null -eq $esTotalReported -and $resp -and $resp.hits -and $resp.hits.total) {
                        $esTotalReported = if ($resp.hits.total.PSObject.Properties.Name -contains 'value') {
                            $resp.hits.total.value
                        } else { $resp.hits.total }
                    }

                    $hits = @()
                    if ($resp -and $resp.hits -and $resp.hits.hits) { $hits = $resp.hits.hits }
                    if (-not $hits -or $hits.Count -eq 0) { break }

                    foreach ($h in $hits) {
                        # Extract _source instead of writing the full search hit
                        # wrapper. The offline parser (ElasticAlertAgent) expects
                        # flat-_source shape - the same shape we already produce
                        # for the canonical local detonation dumps (e.g.
                        # DetonationLogs\C2Frameworks\Sliver_*). Writing the
                        # wrapped hit ({_index, _id, _score, _source, sort})
                        # left the offline partitioner looking for event.code at
                        # the top level when it was actually nested under _source,
                        # silently zeroing every Sysmon EID bucket. Fall back to
                        # the whole hit if _source is unexpectedly absent.
                        $src = if ($h.PSObject.Properties.Name -contains '_source' -and $h._source) { $h._source } else { $h }
                        $writer.WriteLine(($src | ConvertTo-Json -Depth 20 -Compress))

                        # When the operator did not supply -HostFilter, sniff
                        # the first written doc for any of the canonical host-
                        # identifier fields so session_info.txt can carry a
                        # 'Detonation host' line. This makes the downstream
                        # ElasticAlertAgent display show the real hostname
                        # (Win11_Sandbox, fleet01.lab.local, etc.) instead of
                        # the output-directory name fallback.
                        if ($null -eq $detectedHost -and [string]::IsNullOrWhiteSpace($HostFilter)) {
                            foreach ($cf in $hostCandidateFields) {
                                $parts = $cf -split '\.'
                                $cur = $src
                                foreach ($p in $parts) {
                                    if ($null -eq $cur) { break }
                                    $cur = $cur.$p
                                }
                                if (-not [string]::IsNullOrWhiteSpace([string]$cur)) {
                                    $detectedHost = [string]$cur
                                    break
                                }
                            }
                        }
                    }
                    $total += $hits.Count

                    $last = $hits[-1]
                    if (-not $last.sort) { break }
                    $searchAfter = $last.sort
                    if ($hits.Count -lt $PageSize) { break }
                }
            }
            finally { $writer.Close() }

            # Surface ES-reported total alongside written count. When these
            # disagree (ES total > 0 but we wrote 0, or vice versa), the
            # discrepancy is itself the diagnostic clue.
            $totalLabel = if ($null -ne $esTotalReported) { " (ES total: $esTotalReported)" } else { "" }
            $color = if ($total -eq 0 -and $esTotalReported -and $esTotalReported -gt 0) { 'Red' } else { 'Green' }
            Write-Host "    -> $total events written$totalLabel" -ForegroundColor $color
            if ($total -eq 0 -and $esTotalReported -and $esTotalReported -gt 0) {
                Write-Warning "    Pagination bug: ES matched $esTotalReported docs but we wrote 0. Likely sort/search_after issue."
            }
            $summary += [PSCustomObject]@{ Dataset = $ds; Count = $total; File = "$ds.ndjson"; ESTotal = $esTotalReported }
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
                Invoke-TorchElasticDiagnose -StartTime    $StartTime `
                                            -EndTime      $EndTime `
                                            -HostFilter   $HostFilter `
                                            -IndexPattern $IndexPattern `
                                            -Session      $session
            } catch {
                Write-Warning "Auto-diagnostic probe failed: $($_.Exception.Message)"
            }
        }
    }
    finally {
        Close-TorchSSHSession -Session $session
    }

    # --- session_info.txt (format consumed by ElasticAlertAgent shim) -------
    $metaLines = @()
    if (-not [string]::IsNullOrWhiteSpace($SessionInfoCampaign)) {
        $metaLines += "Campaign         : $SessionInfoCampaign"
    }
    # Prefer the explicit -HostFilter when supplied; otherwise use whatever
    # was sniffed from the first written doc during the pull loop. Either
    # way the downstream ElasticAlertAgent display gets a real hostname
    # instead of the OutputDir-name fallback.
    $effectiveHost = if (-not [string]::IsNullOrWhiteSpace($HostFilter))     { $HostFilter }
                     elseif (-not [string]::IsNullOrWhiteSpace($detectedHost)) { $detectedHost }
                     else                                                      { $null }
    if (-not [string]::IsNullOrWhiteSpace($effectiveHost)) {
        $metaLines += "Detonation host  : $effectiveHost"
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
