# ===============================================================================
#  Invoke-CiscoPhoneTriage.psm1  -  Loaded Potato / elasticPotato
#  Cisco IP Phone forensic collection + triage (78xx/88xx and 79xx families).
#
#  Save-CiscoPhoneDump      Live collector. Pulls the phone's forensic surface over
#                           three channels (auto-tries what is reachable):
#                             * HTTP(S) device web pages (DeviceInformation,
#                               NetworkConfiguration, PortInformation, Ethernet/
#                               Streaming statistics, console/status logs)
#                             * SSH shell (78xx/88xx with SSH enabled)
#                             * CUCM TFTP  ->  the authoritative SEP<MAC>.cnf.xml
#                           Saves raw files + dump_manifest.json for offline triage.
#
#  Invoke-CiscoPhoneTriage  Live (collect+analyze) or Offline (analyze a dump dir).
#                           Extracts the device profile and flags phone-specific
#                           forensic findings (rogue TFTP/CUCM provisioning, non-
#                           secure device mode, SSH/web/settings access, PC-port
#                           span, gratuitous ARP, unexpected DNS/syslog, firmware,
#                           recent RTP peers) into a dark HTML report matching the
#                           router triage engine.
#
#  All collection is READ-ONLY (HTTP GET / show commands / TFTP GET). Offline-first;
#  compatible with Windows PowerShell 5.1 and PowerShell 7+.
# ===============================================================================

$script:LPP_CSS = @'
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
.badge-low{background:#0a2a0a;color:#55cc55;border:1px solid #3a9a3a}
.badge-info{background:#0a1a2a;color:#5599cc;border:1px solid #2a5a8a}
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

# MITRE ATT&CK technique names relevant to IP-phone provisioning / access attacks.
$script:LPP_MITRE_NAMES = @{
    'T1078'     = 'Valid Accounts'
    'T1021.004' = 'Remote Services: SSH'
    'T1040'     = 'Network Sniffing'
    'T1557'     = 'Adversary-in-the-Middle'
    'T1557.002' = 'Adversary-in-the-Middle: ARP Cache Poisoning'
    'T1071.001' = 'Application Layer Protocol: Web Protocols'
    'T1542'     = 'Pre-OS Boot'
    'T1542.005' = 'Pre-OS Boot: TFTP Boot'
    'T1601'     = 'Modify System Image'
    'T1195.002' = 'Supply Chain Compromise: Compromise Software Supply Chain'
    'T1200'     = 'Hardware Additions'
    'T1602'     = 'Data from Configuration Repository'
    'T1602.001' = 'Data from Configuration Repository: SNMP (MIB Dump)'
    'T1602.002' = 'Data from Configuration Repository: Network Device Configuration Dump'
    'T1048'     = 'Exfiltration Over Alternative Protocol'
    'T1590'     = 'Gather Victim Network Information'
    'T1046'     = 'Network Service Discovery'
    'T1552'     = 'Unsecured Credentials'
    'T1552.001' = 'Unsecured Credentials: Credentials In Files'
    'T1200.000' = 'Hardware Additions'
}

# -------- shared helpers (module scope) ---------------------------------------

# Sanitize a web page name / command to a safe filename stem.
function Get-LppFileName {
    param([string]$Name)
    (($Name -replace '[^a-zA-Z0-9\-]', '_') -replace '_+', '_' -replace '^_|_$', '')
}

# Candidate device web pages. Covers 79xx (…X endpoints) and 78xx/88xx
# (Serviceability adapter XML). The collector tries every one and keeps whatever
# returns content, so it works across firmware variants without model branching.
function Get-LppWebPages {
    @(
        @{ Name = 'DeviceInformation';    Path = '/DeviceInformationX' }
        @{ Name = 'NetworkConfiguration'; Path = '/NetworkConfigurationX' }
        @{ Name = 'NetworkSetup';         Path = '/NetworkSetupX' }
        @{ Name = 'PortInformation_1';    Path = '/PortInformationX?1' }
        @{ Name = 'PortInformation_2';    Path = '/PortInformationX?2' }
        @{ Name = 'EthernetInformation';  Path = '/EthernetInformationX' }
        @{ Name = 'StreamingStatistics_1'; Path = '/StreamingStatisticsX?1' }
        @{ Name = 'StreamingStatistics_2'; Path = '/StreamingStatisticsX?2' }
        @{ Name = 'StreamingStatistics_3'; Path = '/StreamingStatisticsX?3' }
        @{ Name = 'DeviceLog';            Path = '/DeviceLogX' }
        @{ Name = 'StatusMessages';       Path = '/StatusMessagesX' }
        @{ Name = 'SecurityConfiguration'; Path = '/SecurityConfigurationX' }
        # 78xx / 88xx Serviceability adapters (XML)
        @{ Name = 'Stats_Device';         Path = '/CGI/Java/Serviceability?adapter=device.statistics.device' }
        @{ Name = 'Stats_Configuration';  Path = '/CGI/Java/Serviceability?adapter=device.statistics.configuration' }
        @{ Name = 'Stats_Network';        Path = '/CGI/Java/Serviceability?adapter=device.statistics.port.network' }
        @{ Name = 'Stats_ConsoleLog';     Path = '/CGI/Java/Serviceability?adapter=device.statistics.consolelog&Number=0' }
        @{ Name = 'Stats_StatusMessages'; Path = '/CGI/Java/Serviceability?adapter=device.statistics.statusmessage' }
    )
}

# Cisco phone SSH debug-shell commands (78xx/88xx with SSH enabled).
function Get-LppSshCommands {
    @(
        'show network eth0'
        'show network'
        'show status'
        'show registration'
        'show config'
        'show image'
        'show inventory'
        'show hardware'
        'show provisioning'
        'show log'
        'show trace'
        'show tech-support'
    )
}

# ===============================================================================
#  Save-CiscoPhoneDump  -  live collector
# ===============================================================================
function Save-CiscoPhoneDump {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Target,

        [ValidateSet('auto', '78xx', '88xx', '79xx')]
        [string]$Platform = 'auto',

        # Optional creds for HTTP basic auth on locked web pages and/or SSH login.
        [System.Management.Automation.PSCredential]$Credential,

        [string]$SshKey,

        # Which surfaces to attempt. 'auto' = web + ssh (+ cucm when -CucmHost given).
        [ValidateSet('auto', 'web', 'ssh', 'cucm')]
        [string[]]$Access = @('auto'),

        # CUCM TFTP server to pull the authoritative SEP<MAC>.cnf.xml from.
        [string]$CucmHost,

        # Phone MAC (any of 00:11.., 0011.., SEP0011..). Needed for the TFTP pull;
        # auto-detected from the web pages when omitted.
        [string]$Mac,

        [string]$OutputPath = (Get-Location).Path,

        # Try plain HTTP only (skip HTTPS). Default tries HTTPS then HTTP.
        [switch]$NoTls,

        [int]$TimeoutSec = 20
    )

    $doWeb  = $Access -contains 'auto' -or $Access -contains 'web'
    $doSsh  = $Access -contains 'auto' -or $Access -contains 'ssh'
    $doCucm = $Access -contains 'cucm' -or (($Access -contains 'auto') -and $CucmHost)

    if (-not [System.IO.Path]::IsPathRooted($OutputPath)) {
        $OutputPath = Join-Path (Get-Location).Path $OutputPath
    }
    $safeTarget = $Target -replace '[\\/:*?"<>|]', '_'
    $dumpDir    = Join-Path $OutputPath "CiscoPhoneDump_${safeTarget}_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    $null = New-Item -ItemType Directory -Force -Path $dumpDir

    Write-Host "`n[LP-PHONE] ============================================================" -ForegroundColor Cyan
    Write-Host "[LP-PHONE] Save-CiscoPhoneDump  -  Loaded Potato" -ForegroundColor Cyan
    Write-Host "[LP-PHONE] Target   : $Target" -ForegroundColor White
    Write-Host "[LP-PHONE] Surfaces : web=$doWeb ssh=$doSsh cucm=$doCucm" -ForegroundColor White
    Write-Host "[LP-PHONE] Dump dir : $dumpDir" -ForegroundColor White
    Write-Host "[LP-PHONE] ============================================================" -ForegroundColor Cyan

    $saved   = 0
    $webOk   = 0
    $sshOk   = 0
    $detMac  = $Mac
    $detPlat = $Platform

    # ---- HTTP(S) web scrape ---------------------------------------------------
    if ($doWeb) {
        # Trust self-signed phone certs for the duration of the scrape (restored after).
        $prevCb = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
        try {
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
        } catch { }
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { param($s, $c, $ch, $e) $true }

        $schemes = if ($NoTls) { @('http') } else { @('https', 'http') }
        foreach ($pg in (Get-LppWebPages)) {
            $content = $null
            foreach ($scheme in $schemes) {
                $url = "${scheme}://$Target$($pg.Path)"
                try {
                    $iwr = @{ Uri = $url; UseBasicParsing = $true; TimeoutSec = $TimeoutSec; ErrorAction = 'Stop' }
                    if ($Credential) { $iwr['Credential'] = $Credential }
                    $resp = Invoke-WebRequest @iwr
                    if ($resp -and $resp.Content -and $resp.Content.Trim()) { $content = [string]$resp.Content; break }
                } catch { }
            }
            if ($content) {
                $fn = 'web_' + (Get-LppFileName $pg.Name) + '.html'
                [System.IO.File]::WriteAllText((Join-Path $dumpDir $fn), $content, [System.Text.Encoding]::UTF8)
                $saved++; $webOk++
                Write-Host "[LP-PHONE] web  > $($pg.Name)  [OK]" -ForegroundColor DarkGray
                if (-not $detMac -and $content -match '(?im)(?:MAC\s*Address|MACAddress)\D*((?:[0-9A-F]{2}[:\-\.]){5}[0-9A-F]{2}|[0-9A-F]{12})') {
                    $detMac = ($Matches[1] -replace '[:\-\.]', '')
                }
                if ($detPlat -eq 'auto' -and $content -match '(?i)CP-?(\d{4})') {
                    $mn = $Matches[1]
                    if ($mn -match '^7[89]') { $detPlat = '79xx' }
                    elseif ($mn -match '^78') { $detPlat = '78xx' }
                    elseif ($mn -match '^88') { $detPlat = '88xx' }
                }
            }
        }
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $prevCb
        Write-Host "[LP-PHONE] web pages saved : $webOk" -ForegroundColor White
    }

    # ---- SSH shell ------------------------------------------------------------
    if ($doSsh) {
        $sshUser = ''
        $sshPass = ''
        if ($Credential) {
            $sshUser = $Credential.UserName
            $sshPass = $Credential.GetNetworkCredential().Password
        }
        $plinkExe = Get-Command 'plink.exe' -ErrorAction SilentlyContinue
        $sshExe   = Get-Command 'ssh.exe'   -ErrorAction SilentlyContinue
        if (-not ($plinkExe -or $sshExe) -or -not ($sshUser -or $SshKey)) {
            Write-Host "[LP-PHONE] ssh skipped (no ssh client, or no credentials/key provided)." -ForegroundColor DarkYellow
        } else {
            $outTmp = Join-Path $env:TEMP ("lp_phone_out_" + [guid]::NewGuid().ToString('N') + '.txt')
            $errTmp = Join-Path $env:TEMP ("lp_phone_err_" + [guid]::NewGuid().ToString('N') + '.txt')
            foreach ($cmd in (Get-LppSshCommands)) {
                $out = $null
                try {
                    if ($plinkExe -and $sshPass) {
                        $a = @('-ssh', '-batch', '-pw', $sshPass, "$sshUser@$Target", $cmd)
                        $p = Start-Process $plinkExe.Source -ArgumentList $a -NoNewWindow -PassThru -RedirectStandardOutput $outTmp -RedirectStandardError $errTmp
                    } elseif ($sshExe -and $SshKey) {
                        $a = @('-o', 'StrictHostKeyChecking=no', '-o', 'BatchMode=yes', '-i', $SshKey, '-o', "ConnectTimeout=$TimeoutSec", "$sshUser@$Target", $cmd)
                        $p = Start-Process $sshExe.Source -ArgumentList $a -NoNewWindow -PassThru -RedirectStandardOutput $outTmp -RedirectStandardError $errTmp
                    } else {
                        continue
                    }
                    $p.WaitForExit($TimeoutSec * 1000) | Out-Null
                    if (-not $p.HasExited) { $p.Kill() }
                    $out = Get-Content $outTmp -Raw -ErrorAction SilentlyContinue
                } catch { }
                if ($out -and $out.Trim() -and $out -notmatch '(?i)(connection refused|permission denied|authentication failed|no route to host)') {
                    $fn = 'ssh_' + (Get-LppFileName $cmd) + '.txt'
                    [System.IO.File]::WriteAllText((Join-Path $dumpDir $fn), $out.Trim(), [System.Text.Encoding]::UTF8)
                    $saved++; $sshOk++
                    Write-Host "[LP-PHONE] ssh  > $cmd  [OK]" -ForegroundColor DarkGray
                }
            }
            Remove-Item $outTmp, $errTmp -Force -ErrorAction SilentlyContinue
            Write-Host "[LP-PHONE] ssh outputs saved : $sshOk" -ForegroundColor White
        }
    }

    # ---- CUCM TFTP: authoritative SEP<MAC>.cnf.xml ----------------------------
    if ($doCucm) {
        if (-not $CucmHost) {
            Write-Host "[LP-PHONE] cucm skipped (no -CucmHost)." -ForegroundColor DarkYellow
        } elseif (-not $detMac) {
            Write-Host "[LP-PHONE] cucm skipped (MAC unknown - pass -Mac or collect web pages first)." -ForegroundColor DarkYellow
        } else {
            $macClean = ($detMac -replace '[:\-\.]', '').ToUpper()
            $sepFile  = "SEP$macClean.cnf.xml"
            $tftpExe  = Get-Command 'tftp.exe' -ErrorAction SilentlyContinue
            $dest     = Join-Path $dumpDir $sepFile
            if ($tftpExe) {
                try {
                    Push-Location $dumpDir
                    & $tftpExe.Source '-i' $CucmHost 'GET' $sepFile $dest | Out-Null
                    Pop-Location
                } catch { Pop-Location -ErrorAction SilentlyContinue }
                if (Test-Path -LiteralPath $dest) {
                    $saved++
                    Write-Host "[LP-PHONE] cucm > $sepFile  [OK]" -ForegroundColor DarkGray
                } else {
                    Write-Host "[LP-PHONE] cucm > $sepFile  [FAIL] (TFTP GET returned nothing)" -ForegroundColor DarkYellow
                }
            } else {
                Write-Host "[LP-PHONE] cucm > tftp.exe not installed. Enable it (Windows Features > TFTP Client) or run:" -ForegroundColor DarkYellow
                Write-Host "[LP-PHONE]        tftp -i $CucmHost GET $sepFile `"$dest`"" -ForegroundColor DarkGray
                Write-Host "[LP-PHONE]        For CDR/CMR call records + RIS registration, export from CUCM: Cisco Unified" -ForegroundColor DarkGray
                Write-Host "[LP-PHONE]        Serviceability > Tools > CDR Analysis and Reporting; RTMT device search." -ForegroundColor DarkGray
            }
        }
    }

    # ---- manifest -------------------------------------------------------------
    $manifest = [ordered]@{
        Target         = $Target
        Platform       = $detPlat
        Mac            = $detMac
        CucmHost       = $CucmHost
        SurfacesTried  = @($(if ($doWeb) { 'web' }), $(if ($doSsh) { 'ssh' }), $(if ($doCucm) { 'cucm' })) | Where-Object { $_ }
        WebPagesSaved  = $webOk
        SshOutputsSaved = $sshOk
        CollectedBy    = $env:USERNAME
        CollectionTime = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        CollectionHost = $env:COMPUTERNAME
        FilesSaved     = $saved
    } | ConvertTo-Json
    [System.IO.File]::WriteAllText((Join-Path $dumpDir 'dump_manifest.json'), $manifest, [System.Text.Encoding]::UTF8)

    Write-Host "`n[LP-PHONE] Saved $saved file(s)  (web=$webOk ssh=$sshOk)" -ForegroundColor Cyan
    Write-Host "[LP-PHONE] Dump : $dumpDir" -ForegroundColor Cyan
    Write-Host "[LP-PHONE] Run  : Invoke-CiscoPhoneTriage -DumpPath '$dumpDir' -OpenReport" -ForegroundColor Yellow
    Write-Host "[LP-PHONE] ============================================================" -ForegroundColor Cyan

    return $dumpDir
}

# ===============================================================================
#  Invoke-CiscoPhoneTriage  -  live (collect+analyze) or offline (analyze dump)
# ===============================================================================
function Invoke-CiscoPhoneTriage {
    [CmdletBinding(DefaultParameterSetName = 'Live')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Live', HelpMessage = 'Hostname or IP of the Cisco IP phone to triage')]
        [string]$Target,

        [Parameter(Mandatory, ParameterSetName = 'Offline', HelpMessage = 'Path to a dump directory created by Save-CiscoPhoneDump')]
        [string]$DumpPath,

        [Parameter(ParameterSetName = 'Live')]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(ParameterSetName = 'Live')]
        [string]$SshKey,

        [Parameter(ParameterSetName = 'Live')]
        [ValidateSet('auto', 'web', 'ssh', 'cucm')]
        [string[]]$Access = @('auto'),

        [Parameter(ParameterSetName = 'Live')]
        [string]$CucmHost,

        [Parameter(ParameterSetName = 'Live')]
        [string]$Mac,

        [ValidateSet('auto', '78xx', '88xx', '79xx')]
        [string]$Platform = 'auto',

        # Optional: the org's legitimate provisioning servers. Any TFTP/CUCM the phone
        # points at that is NOT on these lists is flagged HIGH (rogue provisioning).
        [string[]]$ExpectedTftp = @(),
        [string[]]$ExpectedCucm = @(),

        [string]$OutputPath = (Get-Location).Path,

        [switch]$OpenReport
    )

    $offlineMode = $PSCmdlet.ParameterSetName -eq 'Offline'

    if (-not [System.IO.Path]::IsPathRooted($OutputPath)) {
        $OutputPath = Join-Path (Get-Location).Path $OutputPath
    }

    # -- Live mode: collect into a dump dir first, then analyze it --------------
    if (-not $offlineMode) {
        $collectParams = @{ Target = $Target; Platform = $Platform; Access = $Access; OutputPath = $OutputPath }
        if ($Credential) { $collectParams['Credential'] = $Credential }
        if ($SshKey)     { $collectParams['SshKey']     = $SshKey }
        if ($CucmHost)   { $collectParams['CucmHost']   = $CucmHost }
        if ($Mac)        { $collectParams['Mac']        = $Mac }
        $DumpPath = Save-CiscoPhoneDump @collectParams
        if (-not $DumpPath -or -not (Test-Path -LiteralPath $DumpPath)) {
            Write-Host "[LP-PHONE] Live collection produced no dump directory - nothing to analyze." -ForegroundColor Red
            return
        }
    }

    if (-not (Test-Path -LiteralPath $DumpPath)) {
        Write-Host "[LP-PHONE] DumpPath not found: $DumpPath" -ForegroundColor Red
        return
    }

    # -- Read manifest ----------------------------------------------------------
    $manifest = $null
    $manifestPath = Join-Path $DumpPath 'dump_manifest.json'
    if (Test-Path $manifestPath) {
        try { $manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json } catch { }
    }
    if ($Platform -eq 'auto' -and $manifest -and $manifest.Platform -and $manifest.Platform -ne 'auto') { $Platform = $manifest.Platform }
    $target = if ($Target) { $Target } elseif ($manifest -and $manifest.Target) { $manifest.Target } else { Split-Path $DumpPath -Leaf }

    Write-Host "`n[LP-PHONE] ============================================================" -ForegroundColor Cyan
    Write-Host "[LP-PHONE] Cisco IP Phone Forensic Triage" -ForegroundColor Cyan
    Write-Host "[LP-PHONE] Mode     : $(if ($offlineMode) { 'OFFLINE (dump directory)' } else { 'LIVE' })" -ForegroundColor White
    Write-Host "[LP-PHONE] Dump     : $DumpPath" -ForegroundColor White
    Write-Host "[LP-PHONE] Output   : $OutputPath" -ForegroundColor White
    Write-Host "[LP-PHONE] ============================================================" -ForegroundColor Cyan

    # -- Load all collected text (raw) + parse SEP config -----------------------
    $files   = @(Get-ChildItem -LiteralPath $DumpPath -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'dump_manifest.json' })
    $allText = ''
    $sepXml  = $null
    foreach ($f in $files) {
        $c = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction SilentlyContinue
        if ($c) { $allText += "`n" + $c }
        if ($f.Name -match '(?i)^SEP[0-9A-F]{12}\.cnf\.xml$' -or ($c -and $c -match '(?i)<device>.*<loadInformation')) {
            try { $sepXml = [xml]$c } catch { }
        }
    }
    # Strip HTML tags for label/value matching (keep angle-bracket-free copy too).
    $plainText = ($allText -replace '(?is)<script.*?</script>', ' ' -replace '(?is)<style.*?</style>', ' ' -replace '<[^>]+>', ' ')
    $plainText = $plainText -replace '&nbsp;', ' ' -replace '&amp;', '&' -replace '&lt;', '<' -replace '&gt;', '>'

    # -- Findings accumulators --------------------------------------------------
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
        $exists = $iocList | Where-Object { $_.Type -eq $Type -and $_.Value -eq $Value }
        if (-not $exists) { $iocList.Add([PSCustomObject]@{ Type = $Type; Value = $Value; Context = $Context; ThreatMatch = $ThreatMatch }) }
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
    # First capture group of a regex over the collected plain text ('' if none).
    function Fld {
        param([string]$Pattern)
        if ($plainText -match $Pattern) { return $Matches[1].Trim() }
        return ''
    }
    # Read a value from the SEP config XML by element name ('' if absent).
    function Sep {
        param([string]$XPath)
        if (-not $sepXml) { return '' }
        try {
            $n = $sepXml.SelectSingleNode($XPath)
            if ($n) { return ([string]$n.InnerText).Trim() }
        } catch { }
        return ''
    }
    # Normalize a Cisco enabled/disabled/yes/no/0/1 flag to $true when "on".
    function Is-On {
        param([string]$v)
        if ([string]::IsNullOrWhiteSpace($v)) { return $null }
        if ($v -match '(?i)^(enabled|yes|true|on)$' -or $v -eq '1') { return $true }
        if ($v -match '(?i)^(disabled|no|false|off)$' -or $v -eq '0') { return $false }
        return $null
    }

    # -- Extract device profile -------------------------------------------------
    $model    = Fld '(?im)Model\s*(?:Number|Name)?\s*[:>\-]*\s*(CP-?[0-9A-Za-z]+)'
    if (-not $model) { $model = Fld '(?im)\b(CP-?\d{4}[A-Za-z0-9\-]*)' }
    $firmware = Sep '//loadInformation'
    if (-not $firmware) { $firmware = Fld '(?im)(?:App\s*Load\s*ID|Version|Load\s*File|Active\s*Load\s*ID)\s*[:>\-]*\s*([A-Za-z0-9._\-]{4,})' }
    $mac      = if ($manifest -and $manifest.Mac) { [string]$manifest.Mac } else { Fld '(?im)(?:MAC\s*Address|MACAddress)\D*((?:[0-9A-F]{2}[:\-\.]){5}[0-9A-F]{2}|[0-9A-F]{12})' }
    $hostName = Fld '(?im)Host\s*Name\s*[:>\-]*\s*([A-Za-z0-9._\-]+)'
    $serial   = Fld '(?im)Serial\s*Number\s*[:>\-]*\s*([A-Za-z0-9]+)'
    $ipAddr   = Fld '(?im)(?:IP\s*Address|IPv4\s*Address)\s*[:>\-]*\s*(\d{1,3}(?:\.\d{1,3}){3})'
    $domain   = Fld '(?im)Domain\s*Name\s*[:>\-]*\s*([A-Za-z0-9._\-]+)'
    $dhcp     = Fld '(?im)\bDHCP\b\s*[:>\-]*\s*(Enabled|Disabled|Yes|No)'
    $vlan     = Fld '(?im)(?:Operational\s*VLAN\s*ID|Admin\s*VLAN\s*ID|Voice\s*VLAN)\s*[:>\-]*\s*(\d{1,4})'

    $deviceHostname = if ($hostName) { $hostName } elseif ($mac) { "SEP$mac" } else { $target }

    $devProfile['Model']        = $model
    $devProfile['Firmware']     = $firmware
    $devProfile['MAC Address']  = $mac
    $devProfile['Host Name']    = $hostName
    $devProfile['Serial']       = $serial
    $devProfile['IP Address']   = $ipAddr
    $devProfile['Domain']       = $domain
    $devProfile['DHCP']         = $dhcp
    $devProfile['VLAN']         = $vlan
    $devProfile['Platform']     = $Platform
    $devProfile['Files parsed'] = "$($files.Count)"

    if ($firmware) { Add-Finding 'INFO' 'Firmware' "Firmware load: $firmware" "Cross-check against Cisco security advisories for this model/firmware for known CVEs." @('T1195.002') }
    if ($mac)      { Add-IOC 'MAC' $mac 'Phone hardware address' }
    if ($ipAddr)   { Add-IOC 'IP' $ipAddr 'Phone IP address' }

    # -- Provisioning servers: TFTP + CUCM (rogue-provisioning is the key attack)
    $tftpServers = New-Object System.Collections.Generic.List[string]
    foreach ($m in [regex]::Matches($plainText, '(?im)(?:Alternate\s*)?TFTP\s*Server\s*\d?\s*[:>\-]*\s*(\d{1,3}(?:\.\d{1,3}){3})')) {
        if ($m.Groups[1].Value -and $m.Groups[1].Value -ne '0.0.0.0') { [void]$tftpServers.Add($m.Groups[1].Value) }
    }
    $altTftp = Fld '(?im)Alternate\s*TFTP\s*[:>\-]*\s*(Yes|Enabled|True|1)'
    # CUCM / CallManager members (web page + SEP XML processNodeName elements)
    $cucmServers = New-Object System.Collections.Generic.List[string]
    foreach ($m in [regex]::Matches($plainText, '(?im)(?:Call\s*Manager|Unified\s*CM|CallManager)\s*\d?\s*[:>\-]*\s*(\d{1,3}(?:\.\d{1,3}){3})')) {
        [void]$cucmServers.Add($m.Groups[1].Value)
    }
    if ($sepXml) {
        try {
            foreach ($n in $sepXml.SelectNodes('//processNodeName')) {
                $v = ([string]$n.InnerText).Trim()
                if ($v) { [void]$cucmServers.Add($v) }
            }
        } catch { }
    }

    $tftpUnique = @($tftpServers | Select-Object -Unique)
    $cucmUnique = @($cucmServers | Select-Object -Unique)

    foreach ($t in $tftpUnique) {
        $rogue = ($ExpectedTftp.Count -gt 0 -and ($ExpectedTftp -notcontains $t))
        if ($rogue) {
            Add-Finding 'CRITICAL' 'Provisioning' "Unexpected TFTP provisioning server: $t" "The phone downloads its SEP<MAC>.cnf.xml (and firmware) from this TFTP server. It is NOT in the expected set ($($ExpectedTftp -join ', ')). A rogue TFTP server can push a tampered config (attacker CUCM, SSH creds, disabled security) or malicious firmware." @('T1542.005', 'T1601', 'T1195.002', 'T1557')
            Add-IOC 'IP' $t 'Rogue/unexpected TFTP provisioning server' 'Unexpected provisioning source'
        } else {
            Add-Finding 'INFO' 'Provisioning' "TFTP provisioning server: $t" "Review that this is a sanctioned CUCM/TFTP node. Pass -ExpectedTftp to auto-flag unknowns." @('T1542.005')
            Add-IOC 'IP' $t 'TFTP provisioning server'
        }
    }
    if ((Is-On $altTftp) -eq $true) {
        Add-Finding 'HIGH' 'Provisioning' 'Alternate TFTP server is ENABLED' 'An operator-set alternate TFTP overrides DHCP-provided provisioning. Attacker-controlled alternate TFTP is a classic phone-hijack persistence: verify the alternate TFTP address is sanctioned.' @('T1542.005', 'T1601')
    }
    foreach ($c in $cucmUnique) {
        $rogue = ($ExpectedCucm.Count -gt 0 -and ($ExpectedCucm -notcontains $c))
        if ($rogue) {
            Add-Finding 'HIGH' 'Provisioning' "Unexpected Call Manager (CUCM): $c" "The phone registers to this CUCM node, which is not in the expected set ($($ExpectedCucm -join ', ')). A rogue CUCM can intercept/redirect calls and re-provision the device." @('T1557', 'T1601')
            Add-IOC 'IP' $c 'Unexpected CUCM / CallManager' 'Unexpected call agent'
        } else {
            Add-IOC 'IP' $c 'CUCM / CallManager node'
        }
    }

    # -- Device security mode / signed config -----------------------------------
    $secMode = Sep '//deviceSecurityMode'
    if (-not $secMode) { $secMode = Fld '(?im)Device\s*Security\s*Mode\s*[:>\-]*\s*([A-Za-z\- ]+)' }
    if ($secMode) {
        $devProfile['Device Security Mode'] = $secMode
        if ($secMode -match '(?i)non.?secure|^0$') {
            Add-Finding 'HIGH' 'Integrity' 'Device Security Mode = Non-Secure' 'The phone accepts unsigned/unencrypted configuration and signaling (no CTL/ITL enforcement). Its SEP config can be tampered or spoofed in transit, enabling call interception and rogue re-provisioning.' @('T1557', 'T1601')
        }
    }
    $itl = Fld '(?im)(?:ITL|CTL)\s*(?:File|Signature)?\s*[:>\-]*\s*([A-Za-z0-9 ]+)'
    if ($itl) { $devProfile['ITL/CTL'] = $itl }

    # -- Remote access surface: SSH / Web / Settings ----------------------------
    $sshWeb  = Fld '(?im)SSH\s*Access\s*(?:Enabled)?\s*[:>\-]*\s*(Enabled|Disabled|Yes|No|0|1)'
    $sshSep  = Sep '//sshAccess'
    $sshOn   = Is-On $(if ($sshSep) { $sshSep } else { $sshWeb })
    if ($sshOn -eq $true) {
        Add-Finding 'HIGH' 'Access' 'SSH access is ENABLED on the phone' 'The phone exposes an SSH debug shell. Combined with default/pushed credentials this is a remote foothold on the voice VLAN and a live-forensics surface. Confirm it is intentional and credentialed.' @('T1021.004', 'T1078')
        Add-IOC 'Service' 'SSH enabled' 'Remote shell on phone'
    }
    $sshUserId = Sep '//sshUserId'
    $sshPwSet  = Sep '//sshPassword'
    if ($sshUserId) {
        Add-Finding 'MEDIUM' 'Credentials' "SSH username provisioned in config: $sshUserId" 'The SEP config carries an SSH user id (and, if present, a password) in cleartext XML - anyone who can read the TFTP config obtains these credentials.' @('T1552.001', 'T1078')
        $devProfile['SSH User (config)'] = $sshUserId
    }
    if ($sshPwSet) {
        Add-Finding 'HIGH' 'Credentials' 'SSH password present in SEP config (cleartext)' 'The provisioning config includes an SSH password in cleartext. Any read of the TFTP config (which is often unauthenticated) discloses it.' @('T1552.001')
    }

    $webAcc = Sep '//webAccess'
    if (-not $webAcc) { $webAcc = Fld '(?im)Web\s*Access\s*(?:Enabled)?\s*[:>\-]*\s*(Enabled|Disabled|Full|Read.?Only|0|1|2)' }
    $webOn = $null
    if ($webAcc) {
        # SEP webAccess: 0=Full/Enabled, 1=Read-Only, 2=Disabled. Web labels vary.
        if ($webAcc -match '(?i)disabled|^2$') { $webOn = $false } elseif ($webAcc -match '(?i)enabled|full|read|^0$|^1$') { $webOn = $true }
    }
    if ($webOn -eq $true) {
        Add-Finding 'MEDIUM' 'Access' 'Web access is ENABLED' 'The device web server exposes configuration, network topology and call statistics without authentication on many models - useful for reconnaissance and for confirming a compromise.' @('T1071.001', 'T1590')
        Add-IOC 'Service' 'Web access enabled' 'HTTP(S) device pages'
    }
    $setAcc = Sep '//settingsAccess'
    if (-not $setAcc) { $setAcc = Fld '(?im)Settings\s*Access\s*[:>\-]*\s*(Enabled|Disabled|Restricted|0|1|2)' }
    if ((Is-On $setAcc) -eq $true -or $setAcc -match '(?i)^0$') {
        Add-Finding 'MEDIUM' 'Access' 'Local Settings access is ENABLED' 'Physical access to the handset can change network/provisioning settings (TFTP, VLAN) from the keypad.' @('T1200')
    }

    # -- Switch/PC port: sniffing + VLAN hopping --------------------------------
    $pcPort   = Fld '(?im)(?:PC\s*Port|Switch\s*Port)\s*[:>\-]*\s*(Enabled|Disabled|Yes|No|0|1)'
    $spanPc   = Fld '(?im)Span\s*to\s*PC\s*Port\s*[:>\-]*\s*(Enabled|Disabled|Yes|No|0|1)'
    $gArp     = Fld '(?im)Gratuitous\s*ARP\s*[:>\-]*\s*(Enabled|Disabled|Yes|No|0|1)'
    $cdp      = Fld '(?im)\bCDP\b\s*[:>\-]*\s*(Enabled|Disabled|Yes|No|0|1)'
    $pcVlan   = Fld '(?im)(?:PC\s*VLAN|PC\s*Port\s*VLAN)\s*[:>\-]*\s*(\d{1,4})'
    if ((Is-On $spanPc) -eq $true) {
        Add-Finding 'HIGH' 'Network' 'Span-to-PC-Port is ENABLED' 'Voice-VLAN traffic is mirrored to the downstream PC port. A device plugged into the phone can passively capture call signaling/media - a turnkey sniffing position on the voice VLAN.' @('T1040', 'T1200')
    }
    if ((Is-On $gArp) -eq $true) {
        Add-Finding 'MEDIUM' 'Network' 'Gratuitous ARP is ENABLED' 'The phone accepts/emits gratuitous ARP, easing ARP-cache poisoning / adversary-in-the-middle on the voice segment.' @('T1557.002')
    }
    if ((Is-On $pcPort) -eq $true -and $pcVlan) {
        Add-Finding 'MEDIUM' 'Network' "PC port is on VLAN $pcVlan" 'A PC-port device shares/reaches this VLAN. If it bridges the voice VLAN, it enables VLAN hopping into voice infrastructure. Confirm data/voice VLAN separation.' @('T1200')
        $devProfile['PC Port VLAN'] = $pcVlan
    }
    if ((Is-On $cdp) -eq $true) {
        Add-Finding 'LOW' 'Recon' 'CDP is ENABLED' 'Cisco Discovery Protocol advertises the phone/switch topology (device id, VLAN, platform) to the local segment.' @('T1590')
    }

    # -- DNS / syslog destinations ----------------------------------------------
    foreach ($m in [regex]::Matches($plainText, '(?im)DNS\s*Server\s*\d?\s*[:>\-]*\s*(\d{1,3}(?:\.\d{1,3}){3})')) {
        $v = $m.Groups[1].Value
        if ($v -and $v -ne '0.0.0.0') { Add-IOC 'IP' $v 'DNS server' }
    }
    $syslog = Fld '(?im)(?:Remote\s*)?(?:Syslog|Log)\s*Server\s*[:>\-]*\s*(\d{1,3}(?:\.\d{1,3}){3})'
    if ($syslog -and $syslog -ne '0.0.0.0') {
        Add-Finding 'MEDIUM' 'Exfiltration' "Remote syslog destination: $syslog" 'Phone logs are forwarded off-box to this host. Confirm it is the sanctioned SIEM/collector and not an attacker sink.' @('T1048')
        Add-IOC 'IP' $syslog 'Remote syslog destination'
    }

    # -- Recent call activity from streaming statistics -> timeline -------------
    $rtpPeers = @{}
    foreach ($m in [regex]::Matches($plainText, '(?im)(?:Remote\s*Addr(?:ess)?|Rcvr\s*IP|Sender\s*IP)\s*[:>\-]*\s*(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?')) {
        $peer = $m.Groups[1].Value
        if ($peer -and $peer -ne '0.0.0.0' -and -not $rtpPeers.ContainsKey($peer)) {
            $rtpPeers[$peer] = $true
            Add-IOC 'IP' $peer 'RTP call peer (streaming statistics)'
            Add-Timeline (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') 'INFO' "Recent media stream with peer $peer (from streaming statistics)"
        }
    }

    # -- Data-source coverage note ----------------------------------------------
    if ($files.Count -eq 0) {
        Add-Finding 'INFO' 'Collection' 'No collected files found in the dump directory' 'The dump directory has no web pages, SSH output, or SEP config to analyze. Re-run Save-CiscoPhoneDump against a reachable phone.'
    } elseif (-not $sepXml) {
        Add-Finding 'INFO' 'Collection' 'No SEP<MAC>.cnf.xml in dump' 'The authoritative provisioning config was not collected (needs CUCM TFTP access + phone MAC). Web-page findings are best-effort; the SEP config is the ground truth for security mode, SSH/web access and CUCM members.'
    }

    # -- Severity tallies -------------------------------------------------------
    $critCount  = @($findings | Where-Object { $_.Severity -eq 'CRITICAL' }).Count
    $highCount  = @($findings | Where-Object { $_.Severity -eq 'HIGH' }).Count
    $medCount   = @($findings | Where-Object { $_.Severity -eq 'MEDIUM' }).Count
    $lowCount   = @($findings | Where-Object { $_.Severity -eq 'LOW' }).Count
    $totalCount = $findings.Count
    $reportDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    # Verdict
    if ($critCount -gt 0)      { $execSev = 'CRITICAL'; $execVerdict = 'Critical provisioning/integrity exposure - treat this phone as potentially hijacked pending review.' }
    elseif ($highCount -gt 0)  { $execSev = 'HIGH';     $execVerdict = 'High-risk access/network exposure on the phone - review and harden.' }
    elseif ($medCount -gt 0)   { $execSev = 'MEDIUM';   $execVerdict = 'Moderate misconfigurations present - hardening recommended.' }
    else                       { $execSev = 'INFO';     $execVerdict = 'No high-risk phone exposures detected in the collected data.' }

    # -- Build HTML report ------------------------------------------------------
    $html = [System.Text.StringBuilder]::new()
    [void]$html.AppendLine('<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">')
    [void]$html.AppendLine("<title>Cisco IP Phone Forensic Triage  -  $(Escape-Html $deviceHostname)</title>")
    [void]$html.AppendLine("<style>$script:LPP_CSS</style></head><body>")

    $modeBadge = if ($offlineMode) { "<span class='platform-badge'>OFFLINE</span>" } else { "<span class='live-badge'>LIVE</span>" }
    $platBadge = "<span class='platform-badge'>$(Escape-Html ($Platform.ToUpper()))</span>"
    [void]$html.AppendLine("<h1>CISCO IP PHONE FORENSIC TRIAGE $modeBadge$platBadge</h1>")
    [void]$html.AppendLine("<div class='meta'>Device: <b>$(Escape-Html $deviceHostname)</b> &nbsp;|&nbsp; Target: $(Escape-Html $target) &nbsp;|&nbsp; Model: <b>$(Escape-Html $model)</b> &nbsp;|&nbsp; Firmware: $(Escape-Html $firmware) &nbsp;|&nbsp; Collected: $reportDate &nbsp;|&nbsp; Engine: Loaded Potato Cisco Phone Triage v1.0</div>")

    [void]$html.AppendLine("<div class='section'><div class='summary-grid'>")
    [void]$html.AppendLine("<div class='summary-box'><span class='summary-num' style='color:#ff5533'>$critCount</span><div class='summary-lbl'>Critical</div></div>")
    [void]$html.AppendLine("<div class='summary-box'><span class='summary-num' style='color:#ffaa44'>$highCount</span><div class='summary-lbl'>High</div></div>")
    [void]$html.AppendLine("<div class='summary-box'><span class='summary-num' style='color:#ffe055'>$medCount</span><div class='summary-lbl'>Medium</div></div>")
    [void]$html.AppendLine("<div class='summary-box'><span class='summary-num' style='color:#55cc55'>$lowCount</span><div class='summary-lbl'>Low</div></div>")
    [void]$html.AppendLine("<div class='summary-box'><span class='summary-num' style='color:#5599cc'>$totalCount</span><div class='summary-lbl'>Total</div></div>")
    [void]$html.AppendLine('</div></div>')

    [void]$html.AppendLine("<div class='section'><h2>EXECUTIVE SUMMARY</h2>")
    [void]$html.AppendLine("<div class='finding f-$($execSev.ToLower())'>")
    [void]$html.AppendLine("<span class='sev-$execSev'>[$execSev]</span> <span class='cat'>[Verdict]</span> <span class='title'>$(Escape-Html $execVerdict)</span><br>")
    [void]$html.AppendLine("<span class='detail'>Read-only collection (HTTP GET / show commands / TFTP GET). Analysis of $($files.Count) collected file(s) at $reportDate.</span>")
    [void]$html.AppendLine('</div></div>')

    [void]$html.AppendLine("<div class='section'><h2>DEVICE PROFILE</h2>")
    [void]$html.AppendLine("<table class='kv-table'><tr><th>Property</th><th>Value</th></tr>")
    foreach ($kv in $devProfile.GetEnumerator()) {
        if ($kv.Value) { [void]$html.AppendLine("<tr><td>$(Escape-Html $kv.Key)</td><td>$(Escape-Html ([string]$kv.Value))</td></tr>") }
    }
    [void]$html.AppendLine('</table></div>')

    $sevOrder = @('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')
    [void]$html.AppendLine("<div class='section'><h2>FINDINGS</h2>")
    foreach ($sev in $sevOrder) {
        $sevFindings = @($findings | Where-Object { $_.Severity -eq $sev })
        if ($sevFindings.Count -eq 0) { continue }
        [void]$html.AppendLine("<h3>$sev ($($sevFindings.Count))</h3>")
        foreach ($f in $sevFindings) {
            $tecs = ($f.Techniques | Where-Object { $_ } | ForEach-Object { "<span class='technique'>[$_]</span>" }) -join ''
            [void]$html.AppendLine("<div class='finding f-$($f.Severity.ToLower())'>")
            [void]$html.AppendLine("<span class='sev-$($f.Severity)'>[$($f.Severity)]</span> <span class='cat'>[$(Escape-Html $f.Category)]</span> <span class='title'>$(Escape-Html $f.Title)</span>$tecs<br>")
            [void]$html.AppendLine("<span class='detail'>$(Escape-Html $f.Detail)</span></div>")
        }
    }
    [void]$html.AppendLine('</div>')

    if ($iocList.Count -gt 0) {
        [void]$html.AppendLine("<div class='section'><h2>INDICATORS OF INTEREST</h2>")
        [void]$html.AppendLine("<table class='kv-table'><tr><th>Type</th><th>Indicator</th><th>Context</th><th>Threat Match</th></tr>")
        foreach ($ioc in ($iocList | Sort-Object Type, Value)) {
            $typeClass = if ($ioc.Type -eq 'IP') { 'ioc-ip' } elseif ($ioc.Type -match 'Hash|MAC') { 'ioc-hash' } else { 'ioc-path' }
            $matchHtml = if ($ioc.ThreatMatch) { "<span class='match-hit'>$(Escape-Html $ioc.ThreatMatch)</span>" } else { "<span class='match-clean'> &mdash; </span>" }
            [void]$html.AppendLine("<tr><td>$(Escape-Html $ioc.Type)</td><td class='$typeClass'>$(Escape-Html $ioc.Value)</td><td>$(Escape-Html $ioc.Context)</td><td>$matchHtml</td></tr>")
        }
        [void]$html.AppendLine('</table></div>')
    }

    if ($mitreMap.Count -gt 0) {
        [void]$html.AppendLine("<div class='section'><h2>MITRE ATT&amp;CK COVERAGE</h2>")
        [void]$html.AppendLine("<table class='mitre-tbl'><tr><th>Technique ID</th><th>Name</th><th>Evidence (findings)</th></tr>")
        foreach ($tid in ($mitreMap.Keys | Sort-Object)) {
            $tname = if ($script:LPP_MITRE_NAMES.ContainsKey($tid)) { $script:LPP_MITRE_NAMES[$tid] } else { 'See MITRE ATT&amp;CK' }
            $tevid = ($mitreMap[$tid] | Select-Object -First 3) -join '; '
            [void]$html.AppendLine("<tr><td class='mitre-tid'>$tid</td><td class='mitre-name'>$(Escape-Html $tname)</td><td class='mitre-ev'>$(Escape-Html $tevid)</td></tr>")
        }
        [void]$html.AppendLine('</table></div>')
    }

    if ($timeline.Count -gt 0) {
        [void]$html.AppendLine("<div class='section'><h2>ACTIVITY TIMELINE</h2>")
        foreach ($te in ($timeline | Sort-Object Time)) {
            $tlClass = if ($te.Severity -eq 'CRITICAL') { 'tl-crit' } elseif ($te.Severity -eq 'HIGH') { 'tl-sus' } else { '' }
            [void]$html.AppendLine("<div class='tl-entry $tlClass'><span class='tl-time'>$(Escape-Html $te.Time)</span><span class='tl-event'>$(Escape-Html $te.Event)</span></div>")
        }
        [void]$html.AppendLine('</div>')
    }

    $modeLabel = if ($offlineMode) { "OFFLINE DUMP ANALYSIS ($(Escape-Html $DumpPath))" } else { "LIVE COLLECTION (read-only)" }
    [void]$html.AppendLine("<footer>Loaded Potato Cisco Phone Triage Engine v1.0 &nbsp;|&nbsp; $modeLabel &nbsp;|&nbsp; Device: $(Escape-Html $deviceHostname) &nbsp;|&nbsp; $reportDate</footer>")
    [void]$html.AppendLine('</body></html>')

    $safeHostname = $deviceHostname -replace '[\\/:*?"<>|]', '_'
    $reportName   = "CiscoPhoneTriage_${safeHostname}_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    $reportPath   = Join-Path $OutputPath $reportName
    $null = New-Item -ItemType Directory -Force -Path $OutputPath
    [System.IO.File]::WriteAllText($reportPath, $html.ToString(), [System.Text.Encoding]::UTF8)

    Write-Host "`n[LP-PHONE] ============================================================" -ForegroundColor Cyan
    Write-Host "[LP-PHONE] TRIAGE COMPLETE" -ForegroundColor Green
    Write-Host "[LP-PHONE] Device   : $deviceHostname ($model $firmware)" -ForegroundColor White
    Write-Host "[LP-PHONE] CRITICAL : $critCount  HIGH: $highCount  MEDIUM: $medCount  TOTAL: $totalCount" -ForegroundColor $(if ($critCount -gt 0) { 'Red' } else { 'White' })
    Write-Host "[LP-PHONE] Report   : $reportPath" -ForegroundColor Cyan
    Write-Host "[LP-PHONE] ============================================================" -ForegroundColor Cyan

    if ($OpenReport) { try { Start-Process $reportPath } catch { } }

    return [PSCustomObject]@{
        ReportPath = $reportPath
        DumpPath   = $DumpPath
        Critical   = $critCount
        High       = $highCount
        Medium     = $medCount
        Total      = $totalCount
        Findings   = $findings
    }
}

Export-ModuleMember -Function Save-CiscoPhoneDump, Invoke-CiscoPhoneTriage
