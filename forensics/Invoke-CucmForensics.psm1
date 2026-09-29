# ===============================================================================
#  Invoke-CucmForensics.psm1  -  Loaded Potato / elasticPotato
#  Cisco Unified Communications Manager (CUCM / Call Manager) forensic client.
#
#  Companion to Invoke-CiscoPhoneTriage.psm1: where that triages a single phone,
#  this pulls CUCM-side ground truth for the whole cluster.
#
#  Save-CucmForensicDump   Live collector over two channels:
#                            * AXL (Administrative XML Layer) SOAP API on
#                              https://<cucm>:8443/axl/ - runs executeSQLQuery and
#                              config queries (device inventory, end users,
#                              application users, role/group membership, DNs,
#                              security profiles, cluster nodes).
#                            * CDR/CMR - SFTP-pulls the Call Detail Record flat
#                              files from a billing server CUCM pushes them to.
#                          Saves raw AXL SOAP XML + CDR CSVs + dump_manifest.json.
#
#  Invoke-CucmTriage       Live (collect+analyze) or Offline (analyze a dump dir).
#                          Flags rogue/unexpected application users (AXL/API
#                          persistence), privileged accounts, non-secure device
#                          security profiles, and toll-fraud / off-hours / flagged-
#                          number call patterns from the CDRs -> dark HTML report.
#
#  READ-ONLY: AXL executeSQLQuery is a SELECT-only path; CDR is an SFTP GET. AXL
#  needs an application user with the "Standard AXL API Access" role. Offline-first;
#  compatible with Windows PowerShell 5.1 and PowerShell 7+.
# ===============================================================================

$script:LPC_CSS = @'
*{box-sizing:border-box;margin:0;padding:0}
body{background:#080d12;color:#c0ccd8;font-family:'Courier New',Courier,monospace;font-size:10px;padding:18px 24px}
h1{color:#e07030;font-size:18px;letter-spacing:2px;margin-bottom:4px;text-transform:uppercase}
h2{color:#4a9acb;font-size:13px;letter-spacing:1px;margin:18px 0 6px;text-transform:uppercase;border-bottom:1px solid #1e3a5f;padding-bottom:3px}
h3{color:#88aacc;font-size:11px;margin:12px 0 4px;text-transform:uppercase}
.meta{color:#557799;font-size:9px;margin-bottom:16px}
.section{background:#0d1520;border:1px solid #1a2d42;border-radius:3px;padding:12px 16px;margin-bottom:14px}
.finding{padding:4px 8px 4px 14px;margin:3px 0;border-left:3px solid #333;font-size:9px;line-height:1.5}
.f-critical{border-color:#cc2200;background:rgba(204,34,0,.06)}
.f-high{border-color:#e07820;background:rgba(224,120,32,.05)}
.f-medium{border-color:#c8a000;background:rgba(200,160,0,.04)}
.f-low{border-color:#3a9a3a;background:rgba(58,154,58,.04)}
.f-info{border-color:#2a5a8a;background:rgba(42,90,138,.04)}
.sev-CRITICAL{color:#ff5533;font-weight:bold}
.sev-HIGH{color:#ffaa44;font-weight:bold}
.sev-MEDIUM{color:#ffe055;font-weight:bold}
.sev-LOW{color:#55cc55;font-weight:bold}
.sev-INFO{color:#5599cc;font-weight:bold}
.cat{color:#6688aa;font-weight:bold}
.title{color:#dde8f0;font-weight:bold}
.detail{color:#9aaabb}
.technique{color:#446688;font-size:8px;margin-left:8px}
.kv-table{width:100%;border-collapse:collapse;font-size:9px;margin:6px 0}
.kv-table th{background:rgba(30,58,95,.5);color:#4a7abf;padding:4px 10px;text-align:left;font-weight:bold;letter-spacing:1px;border-bottom:1px solid #1e3a5f}
.kv-table td{padding:3px 10px;color:#99aabb;border-bottom:1px solid #0d1520;word-break:break-all}
.kv-table tr:nth-child(even) td{background:rgba(255,255,255,.02)}
.ioc-hash{color:#88ccee;font-family:'Courier New',monospace}
.ioc-ip{color:#aaffaa;font-family:'Courier New',monospace}
.ioc-path{color:#ffcc88;font-family:'Courier New',monospace}
.match-hit{color:#ff5533;font-weight:bold}
.match-clean{color:#557755}
.badge{display:inline-block;padding:1px 6px;border-radius:2px;font-size:8px;font-weight:bold;margin-left:6px;vertical-align:middle}
.badge-critical{background:#4a0800;color:#ff5533;border:1px solid #cc2200}
.badge-high{background:#3a2000;color:#ffaa44;border:1px solid #e07820}
.badge-medium{background:#2a2000;color:#ffe055;border:1px solid #c8a000}
.mitre-tbl{width:100%;border-collapse:collapse;font-size:9px;margin:6px 0}
.mitre-tbl th{background:rgba(30,58,95,.5);color:#4a7abf;padding:4px 10px;text-align:left;font-weight:bold;letter-spacing:1px;border-bottom:1px solid #1e3a5f}
.mitre-tbl td{padding:3px 10px;border-bottom:1px solid #0d1520;vertical-align:top}
.mitre-tid{color:#4a9acb;font-weight:bold}
.mitre-name{color:#dde8f0}
.mitre-ev{color:#9aaabb;font-size:8px}
.tl-entry{padding:3px 0 3px 12px;border-left:2px solid #1e3a5f;margin:2px 0 2px 8px;font-size:9px}
.tl-time{color:#446688;margin-right:8px}
.tl-event{color:#c0ccd8}
.tl-sus{border-left-color:#e07820;background:rgba(224,120,32,.04)}
.tl-crit{border-left-color:#cc2200;background:rgba(204,34,0,.06)}
.summary-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:8px;margin:8px 0}
.summary-box{background:#0d1520;border:1px solid #1a2d42;border-radius:3px;padding:10px 12px;text-align:center}
.summary-num{font-size:28px;font-weight:bold;display:block;line-height:1}
.summary-lbl{color:#557799;font-size:8px;text-transform:uppercase;letter-spacing:1px;margin-top:3px}
.live-badge{display:inline-block;background:#1f0a00;border:1px solid #8a3a00;color:#ffaa44;padding:3px 10px;border-radius:2px;font-size:8px;font-weight:bold;letter-spacing:2px;margin-left:10px;vertical-align:middle}
.platform-badge{display:inline-block;padding:2px 8px;border-radius:2px;font-size:9px;font-weight:bold;margin-left:8px;vertical-align:middle;background:#0a1a2a;border:1px solid #2a5a8a;color:#5599cc}
footer{color:#334455;font-size:8px;margin-top:20px;border-top:1px solid #1a2d42;padding-top:8px;text-align:center}
'@

$script:LPC_MITRE_NAMES = @{
    'T1078'     = 'Valid Accounts'
    'T1078.003' = 'Valid Accounts: Local Accounts'
    'T1136'     = 'Create Account'
    'T1098'     = 'Account Manipulation'
    'T1190'     = 'Exploit Public-Facing Application'
    'T1071'     = 'Application Layer Protocol'
    'T1213'     = 'Data from Information Repositories'
    'T1602'     = 'Data from Configuration Repository'
    'T1005'     = 'Data from Local System'
    'T1552.001' = 'Unsecured Credentials: Credentials In Files'
    'T1557'     = 'Adversary-in-the-Middle'
    'T1204'     = 'User Execution'
    'T1568'     = 'Dynamic Resolution'
    'T1657'     = 'Financial Theft'
}

function Get-LpcFileName {
    param([string]$Name)
    (($Name -replace '[^a-zA-Z0-9\-]', '_') -replace '_+', '_' -replace '^_|_$', '')
}

# Read-only forensic AXL executeSQLQuery battery. Each runs independently; a query
# that fails on a given CUCM schema version is skipped, not fatal.
function Get-LpcAxlQueries {
    @(
        @{ Name = 'devices';         Sql = 'SELECT name, description FROM device' }
        @{ Name = 'endusers';        Sql = 'SELECT userid, firstname, lastname, status FROM enduser' }
        @{ Name = 'appusers';        Sql = 'SELECT name FROM applicationuser' }
        @{ Name = 'directorynumbers'; Sql = 'SELECT dnorpattern, description FROM numplan WHERE tkpatternusage = 2' }
        @{ Name = 'processnodes';    Sql = 'SELECT name FROM processnode' }
        @{ Name = 'securityprofiles'; Sql = 'SELECT name FROM securityprofile' }
        @{ Name = 'enduser_roles';   Sql = 'SELECT eu.userid AS userid, dg.name AS grpname FROM enduser eu, enduserdirgroupmap m, dirgroup dg WHERE eu.pkid = m.fkenduser AND m.fkdirgroup = dg.pkid' }
        @{ Name = 'appuser_roles';   Sql = 'SELECT au.name AS name, dg.name AS grpname FROM applicationuser au, applicationuserdirgroupmap m, dirgroup dg WHERE au.pkid = m.fkapplicationuser AND m.fkdirgroup = dg.pkid' }
    )
}

# ---- AXL SOAP call ----------------------------------------------------------
# Returns the raw SOAP XML response string (or $null). Namespace version is
# tolerated by CUCM as long as it is <= the server version.
function Invoke-CucmAxl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CucmHost,
        [Parameter(Mandatory)][System.Management.Automation.PSCredential]$Credential,
        [string]$AxlVersion = '12.5',
        [Parameter(Mandatory)][string]$Method,
        [string]$InnerXml = '',
        [int]$TimeoutSec = 30
    )
    $url = "https://${CucmHost}:8443/axl/"
    $body = @"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns="http://www.cisco.com/AXL/API/$AxlVersion">
<soapenv:Header/><soapenv:Body><ns:$Method>$InnerXml</ns:$Method></soapenv:Body></soapenv:Envelope>
"@
    $user = $Credential.UserName
    $pass = $Credential.GetNetworkCredential().Password
    $auth = 'Basic ' + [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("${user}:${pass}"))
    $headers = @{ 'SOAPAction' = "CUCM:DB ver=$AxlVersion $Method"; 'Authorization' = $auth }

    $prevCb = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
    try { [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12 } catch { }
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { param($s, $c, $ch, $e) $true }
    try {
        $resp = Invoke-WebRequest -Uri $url -Method Post -Body $body -ContentType 'text/xml; charset=utf-8' -Headers $headers -UseBasicParsing -TimeoutSec $TimeoutSec -ErrorAction Stop
        return [string]$resp.Content
    } catch {
        # AXL returns 500 with a SOAP fault body for query errors - capture it if present.
        $r = $_.Exception.Response
        if ($r) {
            try {
                $sr = New-Object System.IO.StreamReader($r.GetResponseStream())
                return [string]$sr.ReadToEnd()
            } catch { }
        }
        return $null
    } finally {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $prevCb
    }
}

# Parse executeSQLQuery / list response rows into [ordered] hashtables (namespace-agnostic).
function ConvertFrom-LpcAxlRows {
    param([string]$Xml)
    $rows = New-Object System.Collections.Generic.List[object]
    if ([string]::IsNullOrWhiteSpace($Xml)) { return $rows }
    try {
        $doc = [xml]$Xml
        foreach ($rowNode in $doc.SelectNodes("//*[local-name()='row']")) {
            $h = [ordered]@{}
            foreach ($col in $rowNode.ChildNodes) {
                if ($col.NodeType -eq [System.Xml.XmlNodeType]::Element) { $h[$col.LocalName] = ([string]$col.InnerText).Trim() }
            }
            if ($h.Count -gt 0) { [void]$rows.Add([pscustomobject]$h) }
        }
    } catch { }
    return $rows
}

# ===============================================================================
#  Save-CucmForensicDump  -  live collector (AXL + CDR)
# ===============================================================================
function Save-CucmForensicDump {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CucmHost,

        # AXL application user (Standard AXL API Access). Omit to skip AXL and only pull CDR.
        [System.Management.Automation.PSCredential]$Credential,

        [string]$AxlVersion = '12.5',

        # CDR/CMR flat files: SFTP source that CUCM pushes billing records to.
        [string]$CdrSftpHost,
        [System.Management.Automation.PSCredential]$CdrSftpCredential,
        [string]$CdrSftpPath = '/',

        [string]$OutputPath = (Get-Location).Path,

        [int]$TimeoutSec = 30
    )

    if (-not [System.IO.Path]::IsPathRooted($OutputPath)) { $OutputPath = Join-Path (Get-Location).Path $OutputPath }
    $safeHost = $CucmHost -replace '[\\/:*?"<>|]', '_'
    $dumpDir  = Join-Path $OutputPath "CucmDump_${safeHost}_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    $null = New-Item -ItemType Directory -Force -Path $dumpDir

    Write-Host "`n[LP-CUCM] ============================================================" -ForegroundColor Cyan
    Write-Host "[LP-CUCM] Save-CucmForensicDump  -  Loaded Potato" -ForegroundColor Cyan
    Write-Host "[LP-CUCM] CUCM     : $CucmHost  (AXL ver $AxlVersion)" -ForegroundColor White
    Write-Host "[LP-CUCM] Dump dir : $dumpDir" -ForegroundColor White
    Write-Host "[LP-CUCM] ============================================================" -ForegroundColor Cyan

    $axlSaved = 0
    $version  = ''

    # ---- AXL ------------------------------------------------------------------
    if ($Credential) {
        $verXml = Invoke-CucmAxl -CucmHost $CucmHost -Credential $Credential -AxlVersion $AxlVersion -Method 'getCCMVersion' -TimeoutSec $TimeoutSec
        if ($verXml) {
            [System.IO.File]::WriteAllText((Join-Path $dumpDir 'axl_getCCMVersion.xml'), $verXml, [System.Text.Encoding]::UTF8)
            if ($verXml -match '(?is)<version>\s*([0-9][0-9.\-]+)') { $version = $Matches[1] }
            if ($verXml -match '(?i)Unauthorized|401|authentication') { Write-Host "[LP-CUCM] AXL auth may have failed - check the app user has 'Standard AXL API Access'." -ForegroundColor DarkYellow }
        } else {
            Write-Host "[LP-CUCM] AXL getCCMVersion returned nothing (unreachable / :8443 blocked / AXL service off)." -ForegroundColor DarkYellow
        }
        foreach ($q in (Get-LpcAxlQueries)) {
            $inner = '<sql>' + ($q.Sql -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;') + '</sql>'
            $xml = Invoke-CucmAxl -CucmHost $CucmHost -Credential $Credential -AxlVersion $AxlVersion -Method 'executeSQLQuery' -InnerXml $inner -TimeoutSec $TimeoutSec
            if ($xml -and $xml.Trim()) {
                $fn = 'axl_' + (Get-LpcFileName $q.Name) + '.xml'
                [System.IO.File]::WriteAllText((Join-Path $dumpDir $fn), $xml, [System.Text.Encoding]::UTF8)
                $axlSaved++
                $rc = (ConvertFrom-LpcAxlRows $xml).Count
                Write-Host "[LP-CUCM] axl  > $($q.Name)  [$rc row(s)]" -ForegroundColor DarkGray
            } else {
                Write-Host "[LP-CUCM] axl  > $($q.Name)  [SKIP]" -ForegroundColor DarkGray
            }
        }
    } else {
        Write-Host "[LP-CUCM] AXL skipped (no -Credential)." -ForegroundColor DarkYellow
    }

    # ---- CDR (SFTP pull of the flat billing files) ----------------------------
    $cdrSaved = 0
    if ($CdrSftpHost -and $CdrSftpCredential) {
        $cdrDir = Join-Path $dumpDir 'cdr'
        $null = New-Item -ItemType Directory -Force -Path $cdrDir
        $sUser = $CdrSftpCredential.UserName
        $sPass = $CdrSftpCredential.GetNetworkCredential().Password
        $psftp = Get-Command 'psftp.exe' -ErrorAction SilentlyContinue
        $scp   = Get-Command 'scp.exe'   -ErrorAction SilentlyContinue
        try {
            if ($psftp) {
                $batch = Join-Path $env:TEMP ("lp_cdr_" + [guid]::NewGuid().ToString('N') + '.txt')
                @("cd `"$CdrSftpPath`"", "lcd `"$cdrDir`"", 'mget *', 'quit') | Set-Content -Path $batch -Encoding ASCII
                $a = @('-batch', '-pw', $sPass, "$sUser@$CdrSftpHost", '-b', $batch)
                $p = Start-Process $psftp.Source -ArgumentList $a -NoNewWindow -PassThru -Wait
                Remove-Item $batch -Force -ErrorAction SilentlyContinue
            } elseif ($scp) {
                # scp can't take a password non-interactively; needs key auth or an agent.
                Write-Host "[LP-CUCM] cdr  > only scp.exe found (no psftp). Use key-based SFTP or run manually:" -ForegroundColor DarkYellow
                Write-Host "[LP-CUCM]        scp $sUser@${CdrSftpHost}:$CdrSftpPath/* `"$cdrDir`"" -ForegroundColor DarkGray
            } else {
                Write-Host "[LP-CUCM] cdr  > no psftp.exe/scp.exe. Install PuTTY (psftp) or pull the CDR files manually into: $cdrDir" -ForegroundColor DarkYellow
            }
        } catch { Write-Host "[LP-CUCM] cdr  > SFTP pull failed: $($_.Exception.Message)" -ForegroundColor DarkYellow }
        $cdrSaved = @(Get-ChildItem -LiteralPath $cdrDir -File -ErrorAction SilentlyContinue).Count
        Write-Host "[LP-CUCM] cdr files pulled : $cdrSaved" -ForegroundColor White
    } else {
        Write-Host "[LP-CUCM] CDR skipped (no -CdrSftpHost/-CdrSftpCredential)." -ForegroundColor DarkYellow
        Write-Host "[LP-CUCM]   CUCM pushes CDR/CMR flat files to configured billing servers (Serviceability >" -ForegroundColor DarkGray
        Write-Host "[LP-CUCM]   CDR Management). Point -CdrSftp* at that server, or export from CDR Analysis and" -ForegroundColor DarkGray
        Write-Host "[LP-CUCM]   Reporting (CAR) and drop the CSVs into <dump>\cdr\ for offline triage." -ForegroundColor DarkGray
    }

    # ---- manifest -------------------------------------------------------------
    $manifest = [ordered]@{
        CucmHost       = $CucmHost
        CcmVersion     = $version
        AxlVersion     = $AxlVersion
        AxlQueriesSaved = $axlSaved
        CdrFilesSaved  = $cdrSaved
        CollectedBy    = $env:USERNAME
        CollectionTime = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        CollectionHost = $env:COMPUTERNAME
    } | ConvertTo-Json
    [System.IO.File]::WriteAllText((Join-Path $dumpDir 'dump_manifest.json'), $manifest, [System.Text.Encoding]::UTF8)

    Write-Host "`n[LP-CUCM] Saved $axlSaved AXL result(s), $cdrSaved CDR file(s)" -ForegroundColor Cyan
    Write-Host "[LP-CUCM] Dump : $dumpDir" -ForegroundColor Cyan
    Write-Host "[LP-CUCM] Run  : Invoke-CucmTriage -DumpPath '$dumpDir' -OpenReport" -ForegroundColor Yellow
    Write-Host "[LP-CUCM] ============================================================" -ForegroundColor Cyan

    return $dumpDir
}

# ===============================================================================
#  Invoke-CucmTriage  -  live (collect+analyze) or offline (analyze dump)
# ===============================================================================
function Invoke-CucmTriage {
    [CmdletBinding(DefaultParameterSetName = 'Live')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Live')]
        [string]$CucmHost,

        [Parameter(Mandatory, ParameterSetName = 'Offline')]
        [string]$DumpPath,

        [Parameter(ParameterSetName = 'Live')]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(ParameterSetName = 'Live')]
        [string]$AxlVersion = '12.5',

        [Parameter(ParameterSetName = 'Live')][string]$CdrSftpHost,
        [Parameter(ParameterSetName = 'Live')][System.Management.Automation.PSCredential]$CdrSftpCredential,
        [Parameter(ParameterSetName = 'Live')][string]$CdrSftpPath = '/',

        # Application users you expect to exist (AXL/integration accounts). Any app
        # user NOT on this list is flagged HIGH (rogue API account / persistence).
        [string[]]$ExpectedAppUsers = @(),

        # Phone-number substrings to flag in CDRs (known-bad / premium-rate / attacker).
        [string[]]$FlaggedNumbers = @(),

        [string]$OutputPath = (Get-Location).Path,

        [switch]$OpenReport
    )

    $offlineMode = $PSCmdlet.ParameterSetName -eq 'Offline'
    if (-not [System.IO.Path]::IsPathRooted($OutputPath)) { $OutputPath = Join-Path (Get-Location).Path $OutputPath }

    if (-not $offlineMode) {
        $cp = @{ CucmHost = $CucmHost; AxlVersion = $AxlVersion; OutputPath = $OutputPath }
        if ($Credential)        { $cp['Credential'] = $Credential }
        if ($CdrSftpHost)       { $cp['CdrSftpHost'] = $CdrSftpHost }
        if ($CdrSftpCredential) { $cp['CdrSftpCredential'] = $CdrSftpCredential }
        if ($CdrSftpPath)       { $cp['CdrSftpPath'] = $CdrSftpPath }
        $DumpPath = Save-CucmForensicDump @cp
        if (-not $DumpPath -or -not (Test-Path -LiteralPath $DumpPath)) {
            Write-Host "[LP-CUCM] Live collection produced no dump directory - nothing to analyze." -ForegroundColor Red
            return
        }
    }
    if (-not (Test-Path -LiteralPath $DumpPath)) {
        Write-Host "[LP-CUCM] DumpPath not found: $DumpPath" -ForegroundColor Red
        return
    }

    $manifest = $null
    $mp = Join-Path $DumpPath 'dump_manifest.json'
    if (Test-Path $mp) { try { $manifest = Get-Content $mp -Raw | ConvertFrom-Json } catch { } }
    $cucm    = if ($CucmHost) { $CucmHost } elseif ($manifest -and $manifest.CucmHost) { $manifest.CucmHost } else { Split-Path $DumpPath -Leaf }
    $version = if ($manifest -and $manifest.CcmVersion) { [string]$manifest.CcmVersion } else { '' }

    Write-Host "`n[LP-CUCM] ============================================================" -ForegroundColor Cyan
    Write-Host "[LP-CUCM] CUCM Forensic Triage  ($(if ($offlineMode) { 'OFFLINE' } else { 'LIVE' }))" -ForegroundColor Cyan
    Write-Host "[LP-CUCM] Dump : $DumpPath" -ForegroundColor White
    Write-Host "[LP-CUCM] ============================================================" -ForegroundColor Cyan

    # -- accumulators -----------------------------------------------------------
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $iocList  = [System.Collections.Generic.List[PSCustomObject]]::new()
    $timeline = [System.Collections.Generic.List[PSCustomObject]]::new()
    $mitreMap = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.List[string]]]::new()
    $devProfile = [ordered]@{}

    function Add-Finding {
        param([string]$Sev, [string]$Cat, [string]$Title, [string]$Detail, [string[]]$Techniques = @())
        $findings.Add([PSCustomObject]@{ Severity = $Sev; Category = $Cat; Title = $Title; Detail = $Detail; Techniques = $Techniques })
        foreach ($t in $Techniques) {
            if ($t) {
                if (-not $mitreMap.ContainsKey($t)) { $mitreMap[$t] = [System.Collections.Generic.List[string]]::new() }
                if (-not $mitreMap[$t].Contains($Title)) { [void]$mitreMap[$t].Add($Title) }
            }
        }
    }
    function Add-IOC {
        param([string]$Type, [string]$Value, [string]$Context, [string]$ThreatMatch = '')
        if ([string]::IsNullOrWhiteSpace($Value)) { return }
        if (-not ($iocList | Where-Object { $_.Type -eq $Type -and $_.Value -eq $Value })) {
            $iocList.Add([PSCustomObject]@{ Type = $Type; Value = $Value; Context = $Context; ThreatMatch = $ThreatMatch })
        }
    }
    function Add-Timeline {
        param([string]$Time, [string]$Severity, [string]$Event)
        $timeline.Add([PSCustomObject]@{ Time = $Time; Severity = $Severity; Event = $Event })
    }
    function Escape-Html {
        param([string]$s)
        if (-not $s) { return '' }
        $s -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;'
    }
    function Read-AxlRows {
        param([string]$Name)
        $p = Join-Path $DumpPath ('axl_' + (Get-LpcFileName $Name) + '.xml')
        if (Test-Path -LiteralPath $p) { return (ConvertFrom-LpcAxlRows (Get-Content -LiteralPath $p -Raw)) }
        return @()
    }

    # -- AXL: inventory + accounts ----------------------------------------------
    $devices   = @(Read-AxlRows 'devices')
    $endusers  = @(Read-AxlRows 'endusers')
    $appusers  = @(Read-AxlRows 'appusers')
    $dns       = @(Read-AxlRows 'directorynumbers')
    $nodes     = @(Read-AxlRows 'processnodes')
    $secProf   = @(Read-AxlRows 'securityprofiles')
    $euRoles   = @(Read-AxlRows 'enduser_roles')
    $auRoles   = @(Read-AxlRows 'appuser_roles')

    $devProfile['CUCM Host']        = $cucm
    $devProfile['CCM Version']      = $version
    $devProfile['Devices']         = "$($devices.Count)"
    $devProfile['End users']       = "$($endusers.Count)"
    $devProfile['Application users'] = "$($appusers.Count)"
    $devProfile['Directory numbers'] = "$($dns.Count)"
    $devProfile['Cluster nodes']   = ($nodes | ForEach-Object { $_.name }) -join ', '
    $devProfile['Security profiles'] = "$($secProf.Count)"

    if ($version) { Add-Finding 'INFO' 'Platform' "CUCM version: $version" 'Cross-check against Cisco advisories for AXL/CUCM CVEs affecting this release.' }

    # Rogue / unexpected application users (AXL & API persistence)
    foreach ($au in $appusers) {
        $n = [string]$au.name
        if (-not $n) { continue }
        Add-IOC 'Account' $n 'CUCM application user'
        # Built-in system app users are expected; flag the rest against -ExpectedAppUsers.
        $builtin = $n -match '(?i)^(CCMSysUser|CCMAdministrator|WDSysUser|CCMQRTSysUser|IPMASysUser|WDSecureSysUser|TabSyncSysUser|CUCService|ACSysUser|CCMServerPostInstall|SubscriptionCallCredentials|MobileSysUser|MobilityServiceUser)$'
        if (-not $builtin -and $ExpectedAppUsers.Count -gt 0 -and ($ExpectedAppUsers -notcontains $n)) {
            Add-Finding 'HIGH' 'Accounts' "Unexpected CUCM application user: $n" "This application user is not built-in and not in the expected set ($($ExpectedAppUsers -join ', ')). Application users hold API/AXL and integration access - a rogue one is a stealthy persistence and data-exfiltration foothold on the cluster." @('T1136', 'T1078.003', 'T1190')
            Add-IOC 'Account' $n 'Unexpected CUCM application user' 'Possible rogue API/AXL account'
        } elseif (-not $builtin -and $ExpectedAppUsers.Count -eq 0) {
            Add-Finding 'INFO' 'Accounts' "Application user present: $n" 'Non-built-in application user. Pass -ExpectedAppUsers to auto-flag unknowns.' @('T1078.003')
        }
    }

    # Privileged role membership (Super Users / admin groups)
    $privRe = '(?i)(Super\s*Users|Standard CCM Super Users|Standard CCM Admin|Standard AXL API Access|Standard CUCM Admin|Standard Serviceability Administration|Standard RealtimeAndTraceCollection)'
    foreach ($r in $auRoles) {
        if ([string]$r.grpname -match $privRe) {
            Add-Finding 'MEDIUM' 'Accounts' "Application user '$($r.name)' has privileged role: $($r.grpname)" 'Application user holds a high-privilege CUCM role. Confirm it is a sanctioned integration account and its credentials are controlled.' @('T1078.003')
        }
    }
    foreach ($r in $euRoles) {
        if ([string]$r.grpname -match $privRe) {
            Add-Finding 'MEDIUM' 'Accounts' "End user '$($r.userid)' has privileged role: $($r.grpname)" 'End user holds a high-privilege administrative role. Verify this is expected and MFA/controls apply.' @('T1078')
        }
    }
    if ($euRoles.Count -eq 0 -and $auRoles.Count -eq 0 -and $appusers.Count -eq 0 -and $devices.Count -eq 0) {
        Add-Finding 'INFO' 'Collection' 'No AXL results parsed' 'No AXL query results were found in the dump. AXL may have been unreachable, the app user may lack Standard AXL API Access, or only CDR was collected.'
    }

    # -- CDR analysis -----------------------------------------------------------
    $cdrDir = Join-Path $DumpPath 'cdr'
    $cdrFiles = @()
    if (Test-Path -LiteralPath $cdrDir) { $cdrFiles = @(Get-ChildItem -LiteralPath $cdrDir -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -match '(?i)\.(csv|txt)$' -or $_.Name -match '(?i)cdr' }) }
    $totalCalls = 0
    $intlCalls  = 0
    $intlDest   = @{}
    $flaggedHits = 0
    $offHours   = 0
    $epoch = [datetime]'1970-01-01 00:00:00'

    foreach ($cf in $cdrFiles) {
        $lines = @(Get-Content -LiteralPath $cf.FullName -ErrorAction SilentlyContinue)
        if ($lines.Count -lt 2) { continue }
        # CUCM CDR flat files carry two header rows (field names, then field types).
        # Drop the second (types) row so Import-Csv sees clean data.
        $hdr = $lines[0]
        $dataLines = @($lines | Select-Object -Skip 1 | Where-Object { $_ -notmatch '(?i)^"?(INTEGER|VARCHAR|BIGINT|SMALLINT|CHAR|UNSIGNED)"?' -and $_ -notmatch '^\s*$' })
        $rows = @()
        try { $rows = @(($hdr + "`n" + ($dataLines -join "`n")) | ConvertFrom-Csv) } catch { $rows = @() }
        foreach ($row in $rows) {
            $called = ''
            foreach ($k in 'finalCalledPartyNumber', 'originalCalledPartyNumber', 'callingPartyNumber') {
                if ($row.PSObject.Properties.Name -contains $k -and $row.$k) { $called = [string]$row.$k; break }
            }
            if (-not $called) { continue }
            $called = $called.Trim('"').Trim()
            $totalCalls++
            $when = ''
            if ($row.PSObject.Properties.Name -contains 'dateTimeOrigination') {
                $ep = 0
                if ([int]::TryParse(([string]$row.dateTimeOrigination).Trim('"'), [ref]$ep) -and $ep -gt 0) {
                    $when = $epoch.AddSeconds($ep).ToString('yyyy-MM-dd HH:mm:ss')
                    $hour = $epoch.AddSeconds($ep).Hour
                    if ($hour -lt 6 -or $hour -ge 20) { $offHours++ }
                }
            }
            $isIntl = ($called -match '^(011|00|\+)' -or ($called -match '^\d{11,}$'))
            if ($isIntl) { $intlCalls++; if (-not $intlDest.ContainsKey($called)) { $intlDest[$called] = 0 }; $intlDest[$called]++ }
            foreach ($fn in $FlaggedNumbers) {
                if ($fn -and $called -like "*$fn*") {
                    $flaggedHits++
                    Add-Finding 'HIGH' 'Call Records' "Call to flagged number: $called" "A CDR shows a call to/involving a flagged number ($fn). Origin device: $([string]$row.origDeviceName)." @('T1657')
                    Add-IOC 'Phone#' $called 'Flagged number in CDR' 'Matched -FlaggedNumbers'
                    Add-Timeline $when 'HIGH' "Call to flagged number $called (device $([string]$row.origDeviceName))"
                }
            }
        }
    }

    if ($cdrFiles.Count -eq 0) {
        Add-Finding 'INFO' 'Call Records' 'No CDR files in dump' 'No CDR/CMR flat files were collected (needs a billing-server SFTP source or a CAR export dropped into <dump>\cdr\). Call-pattern analysis skipped.'
    } else {
        $devProfile['CDR files']  = "$($cdrFiles.Count)"
        $devProfile['CDR calls']  = "$totalCalls"
        if ($intlCalls -gt 0) {
            $top = ($intlDest.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 8 | ForEach-Object { "$($_.Key) x$($_.Value)" }) -join ', '
            Add-Finding 'HIGH' 'Call Records' "International / long-format calls in CDR: $intlCalls" "Possible toll fraud. Top destinations: $top. Review whether international dialing is authorized for the originating devices/users." @('T1657')
            foreach ($d in ($intlDest.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 15)) { Add-IOC 'Phone#' $d.Key "International destination (x$($d.Value))" }
        }
        if ($offHours -gt 0) {
            $sev = if ($offHours -ge 20) { 'MEDIUM' } else { 'INFO' }
            Add-Finding $sev 'Call Records' "Off-hours calls (before 06:00 / after 20:00): $offHours" 'A concentration of off-hours calling can indicate toll fraud or compromised handsets used outside business hours.' @('T1657')
        }
    }

    # -- tallies + verdict ------------------------------------------------------
    $critCount  = @($findings | Where-Object { $_.Severity -eq 'CRITICAL' }).Count
    $highCount  = @($findings | Where-Object { $_.Severity -eq 'HIGH' }).Count
    $medCount   = @($findings | Where-Object { $_.Severity -eq 'MEDIUM' }).Count
    $lowCount   = @($findings | Where-Object { $_.Severity -eq 'LOW' }).Count
    $totalCount = $findings.Count
    $reportDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    if ($highCount -gt 0)     { $execSev = 'HIGH';   $execVerdict = 'High-risk CUCM accounts and/or call patterns detected - review before clearing.' }
    elseif ($medCount -gt 0)  { $execSev = 'MEDIUM'; $execVerdict = 'Moderate CUCM exposures present - review privileged accounts and call activity.' }
    else                      { $execSev = 'INFO';   $execVerdict = 'No high-risk CUCM accounts or call patterns detected in the collected data.' }

    # -- HTML report ------------------------------------------------------------
    $html = [System.Text.StringBuilder]::new()
    [void]$html.AppendLine('<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">')
    [void]$html.AppendLine("<title>CUCM Forensic Triage  -  $(Escape-Html $cucm)</title>")
    [void]$html.AppendLine("<style>$script:LPC_CSS</style></head><body>")
    $modeBadge = if ($offlineMode) { "<span class='platform-badge'>OFFLINE</span>" } else { "<span class='live-badge'>LIVE</span>" }
    [void]$html.AppendLine("<h1>CUCM FORENSIC TRIAGE $modeBadge<span class='platform-badge'>CALL MANAGER</span></h1>")
    [void]$html.AppendLine("<div class='meta'>CUCM: <b>$(Escape-Html $cucm)</b> &nbsp;|&nbsp; Version: $(Escape-Html $version) &nbsp;|&nbsp; Devices: $($devices.Count) &nbsp;|&nbsp; App users: $($appusers.Count) &nbsp;|&nbsp; CDR calls: $totalCalls &nbsp;|&nbsp; Collected: $reportDate &nbsp;|&nbsp; Engine: Loaded Potato CUCM Triage v1.0</div>")

    [void]$html.AppendLine("<div class='section'><div class='summary-grid'>")
    [void]$html.AppendLine("<div class='summary-box'><span class='summary-num' style='color:#ff5533'>$critCount</span><div class='summary-lbl'>Critical</div></div>")
    [void]$html.AppendLine("<div class='summary-box'><span class='summary-num' style='color:#ffaa44'>$highCount</span><div class='summary-lbl'>High</div></div>")
    [void]$html.AppendLine("<div class='summary-box'><span class='summary-num' style='color:#ffe055'>$medCount</span><div class='summary-lbl'>Medium</div></div>")
    [void]$html.AppendLine("<div class='summary-box'><span class='summary-num' style='color:#55cc55'>$lowCount</span><div class='summary-lbl'>Low</div></div>")
    [void]$html.AppendLine("<div class='summary-box'><span class='summary-num' style='color:#5599cc'>$totalCount</span><div class='summary-lbl'>Total</div></div>")
    [void]$html.AppendLine('</div></div>')

    [void]$html.AppendLine("<div class='section'><h2>EXECUTIVE SUMMARY</h2>")
    [void]$html.AppendLine("<div class='finding f-$($execSev.ToLower())'><span class='sev-$execSev'>[$execSev]</span> <span class='cat'>[Verdict]</span> <span class='title'>$(Escape-Html $execVerdict)</span><br>")
    [void]$html.AppendLine("<span class='detail'>Read-only collection (AXL executeSQLQuery SELECTs + CDR SFTP GET). $($findings.Count) finding(s) at $reportDate.</span></div></div>")

    [void]$html.AppendLine("<div class='section'><h2>CLUSTER PROFILE</h2><table class='kv-table'><tr><th>Property</th><th>Value</th></tr>")
    foreach ($kv in $devProfile.GetEnumerator()) { if ($kv.Value) { [void]$html.AppendLine("<tr><td>$(Escape-Html $kv.Key)</td><td>$(Escape-Html ([string]$kv.Value))</td></tr>") } }
    [void]$html.AppendLine('</table></div>')

    $sevOrder = @('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')
    [void]$html.AppendLine("<div class='section'><h2>FINDINGS</h2>")
    foreach ($sev in $sevOrder) {
        $sf = @($findings | Where-Object { $_.Severity -eq $sev })
        if ($sf.Count -eq 0) { continue }
        [void]$html.AppendLine("<h3>$sev ($($sf.Count))</h3>")
        foreach ($f in $sf) {
            $tecs = ($f.Techniques | Where-Object { $_ } | ForEach-Object { "<span class='technique'>[$_]</span>" }) -join ''
            [void]$html.AppendLine("<div class='finding f-$($f.Severity.ToLower())'><span class='sev-$($f.Severity)'>[$($f.Severity)]</span> <span class='cat'>[$(Escape-Html $f.Category)]</span> <span class='title'>$(Escape-Html $f.Title)</span>$tecs<br><span class='detail'>$(Escape-Html $f.Detail)</span></div>")
        }
    }
    [void]$html.AppendLine('</div>')

    if ($iocList.Count -gt 0) {
        [void]$html.AppendLine("<div class='section'><h2>INDICATORS OF INTEREST</h2><table class='kv-table'><tr><th>Type</th><th>Indicator</th><th>Context</th><th>Threat Match</th></tr>")
        foreach ($ioc in ($iocList | Sort-Object Type, Value)) {
            $tc = if ($ioc.Type -eq 'IP') { 'ioc-ip' } elseif ($ioc.Type -match 'Account|Phone') { 'ioc-hash' } else { 'ioc-path' }
            $mh = if ($ioc.ThreatMatch) { "<span class='match-hit'>$(Escape-Html $ioc.ThreatMatch)</span>" } else { "<span class='match-clean'> &mdash; </span>" }
            [void]$html.AppendLine("<tr><td>$(Escape-Html $ioc.Type)</td><td class='$tc'>$(Escape-Html $ioc.Value)</td><td>$(Escape-Html $ioc.Context)</td><td>$mh</td></tr>")
        }
        [void]$html.AppendLine('</table></div>')
    }

    if ($mitreMap.Count -gt 0) {
        [void]$html.AppendLine("<div class='section'><h2>MITRE ATT&amp;CK COVERAGE</h2><table class='mitre-tbl'><tr><th>Technique ID</th><th>Name</th><th>Evidence (findings)</th></tr>")
        foreach ($tid in ($mitreMap.Keys | Sort-Object)) {
            $tn = if ($script:LPC_MITRE_NAMES.ContainsKey($tid)) { $script:LPC_MITRE_NAMES[$tid] } else { 'See MITRE ATT&amp;CK' }
            $ev = ($mitreMap[$tid] | Select-Object -First 3) -join '; '
            [void]$html.AppendLine("<tr><td class='mitre-tid'>$tid</td><td class='mitre-name'>$(Escape-Html $tn)</td><td class='mitre-ev'>$(Escape-Html $ev)</td></tr>")
        }
        [void]$html.AppendLine('</table></div>')
    }

    if ($timeline.Count -gt 0) {
        [void]$html.AppendLine("<div class='section'><h2>ACTIVITY TIMELINE</h2>")
        foreach ($te in ($timeline | Sort-Object Time | Select-Object -First 100)) {
            $tl = if ($te.Severity -eq 'CRITICAL') { 'tl-crit' } elseif ($te.Severity -eq 'HIGH') { 'tl-sus' } else { '' }
            [void]$html.AppendLine("<div class='tl-entry $tl'><span class='tl-time'>$(Escape-Html $te.Time)</span><span class='tl-event'>$(Escape-Html $te.Event)</span></div>")
        }
        [void]$html.AppendLine('</div>')
    }

    $modeLabel = if ($offlineMode) { "OFFLINE DUMP ANALYSIS ($(Escape-Html $DumpPath))" } else { "LIVE COLLECTION (read-only)" }
    [void]$html.AppendLine("<footer>Loaded Potato CUCM Triage Engine v1.0 &nbsp;|&nbsp; $modeLabel &nbsp;|&nbsp; CUCM: $(Escape-Html $cucm) &nbsp;|&nbsp; $reportDate</footer></body></html>")

    $safe = $cucm -replace '[\\/:*?"<>|]', '_'
    $reportPath = Join-Path $OutputPath "CucmTriage_${safe}_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    $null = New-Item -ItemType Directory -Force -Path $OutputPath
    [System.IO.File]::WriteAllText($reportPath, $html.ToString(), [System.Text.Encoding]::UTF8)

    Write-Host "`n[LP-CUCM] TRIAGE COMPLETE  -  CRIT:$critCount HIGH:$highCount MED:$medCount TOTAL:$totalCount" -ForegroundColor $(if ($highCount -gt 0) { 'Yellow' } else { 'Green' })
    Write-Host "[LP-CUCM] Report : $reportPath" -ForegroundColor Cyan
    if ($OpenReport) { try { Start-Process $reportPath } catch { } }

    return [PSCustomObject]@{ ReportPath = $reportPath; DumpPath = $DumpPath; High = $highCount; Medium = $medCount; Total = $totalCount; Findings = $findings }
}

Export-ModuleMember -Function Save-CucmForensicDump, Invoke-CucmTriage, Invoke-CucmAxl
