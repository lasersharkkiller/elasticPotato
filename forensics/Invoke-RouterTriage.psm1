<#
.SYNOPSIS
    Loaded Potato  -  APT-Level Router Forensic Triage Engine

.DESCRIPTION
    Performs expert-level live forensic triage of edge routers and OT switches
    via SSH (plink.exe or ssh.exe). Pulls running configuration, version data,
    process telemetry, routing tables, SPAN sessions, persistence mechanisms,
    and covert-channel indicators across nine platform families:

      - IOS-XE   (Cisco IOS XE)
      - NX-OS    (Cisco Nexus)
      - JunOS    (Juniper)
      - FortiOS  (Fortinet FortiGate)
      - PAN-OS   (Palo Alto Networks)
      - SEL      (Schweitzer Engineering Laboratories OT switches)
      - MikroTik (RouterOS)
      - Linksys  (OpenWrt / Linux-based firmware)
      - TP-Link  (OpenWrt / Linux-based firmware)
      - GL.iNet  (GL.iNet OpenWrt travel routers: Beryl / Slate / Flint / Brume / etc.)

    Generates a styled HTML report covering 15 modules:
      - Module 01: Device Profile & Integrity (SYNful Knock check, image hash)
      - Module 02: User Accounts & Authentication (priv-15 users, AAA servers)
      - Module 03: Active Sessions & Remote Access (VTY telnet, SSH v1)
      - Module 04: Traffic Interception  -  SPAN/RSPAN/ERSPAN, GRE tunnels, PBR
      - Module 05: Covert Channels & Exfil Infrastructure (GRE, IKE, BGP, NTP)
      - Module 06: Persistence Mechanisms (EEM, TCL, Kron, HTTP webshell path)
      - Module 07: ACL & Firewall Rule Analysis (permit any any, NAT backdoors)
      - Module 08: Routing Table Anomalies (host routes, BGP, static routes)
      - Module 09: Logging & Anti-Forensics (syslog, AAA accounting, timestamps)
      - Module 10: Process & Memory Anomalies / Guest Shell (IOS-XE)
      - Module 11: OT/SEL Specific Checks (SPAN mirror, SELOGIC, IT/OT VLAN)
      - Module 12: APT Indicator Patterns (Salt Typhoon, Volt Typhoon, SYNful Knock...)
      - Module 13: IOC Summary (deduplicated IPs, domains, file paths)
      - Module 14: Timeline Reconstruction (chronological config/login events)
      - Module 15: Initial Access Hypothesis (ranked CVE / credential / supply chain)

    Cross-references against known APT TTP fingerprints:
      Salt Typhoon, Volt Typhoon, SYNful Knock, UNC3886, APT28/29,
      Sandworm/VPFilter, Mirai/IoT Botnets

.PARAMETER Target
    Hostname or IP address of the router to triage.

.PARAMETER Credential
    PSCredential object for SSH authentication (username + password).
    Mutually exclusive with -SshKey for password-based auth.

.PARAMETER Platform
    Target platform. Default is 'auto' (detect from 'show version').
    Valid values: auto | ios-xe | nxos | junos | fortios | panos | sel | mikrotik | linksys | tplink | glinet

.PARAMETER OutputPath
    Directory to write the HTML report. Defaults to current directory.

.PARAMETER OpenReport
    If specified, opens the HTML report in the default browser on completion.

.PARAMETER SshKey
    Path to private key file for SSH key-based authentication (used with ssh.exe).

.EXAMPLE
    Import-Module .\forensics\Invoke-RouterTriage.psm1
    $cred = Get-Credential
    Invoke-RouterTriage -Target 192.168.1.1 -Credential $cred -OpenReport

.EXAMPLE
    Invoke-RouterTriage -Target edge-rtr-01.corp -Credential $cred `
                        -Platform ios-xe -OutputPath C:\reports
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

# --- INLINE CSS (matches Loaded Potato dark theme) ---------------------------
$script:LP_CSS = @'
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
.attr-bar{height:8px;background:#1a2d42;border-radius:4px;overflow:hidden;margin-top:4px}
.attr-fill{height:100%;border-radius:4px;transition:width .3s}
footer{color:#334455;font-size:8px;margin-top:20px;border-top:1px solid #1a2d42;padding-top:8px;text-align:center}
'@

# --- MITRE ATT&CK TECHNIQUE NAMES (Enterprise + ICS) -------------------------
$script:MITRE_NAMES = @{
    # Enterprise
    'T1078'     = 'Valid Accounts'
    'T1136'     = 'Create Account'
    'T1098'     = 'Account Manipulation'
    'T1110'     = 'Brute Force'
    'T1021.004' = 'Remote Services: SSH'
    'T1090'     = 'Proxy'
    'T1090.003' = 'Proxy: Multi-hop Proxy'
    'T1040'     = 'Network Sniffing'
    'T1557'     = 'Adversary-in-the-Middle'
    'T1071.001' = 'Application Layer Protocol: Web Protocols'
    'T1071.004' = 'Application Layer Protocol: DNS'
    'T1048'     = 'Exfiltration Over Alternative Protocol'
    'T1048.003' = 'Exfiltration Over Alternative Protocol: Non-C2 Protocol'
    'T1572'     = 'Protocol Tunneling'
    'T1133'     = 'External Remote Services'
    'T1190'     = 'Exploit Public-Facing Application'
    'T1195.002' = 'Supply Chain Compromise: Compromise Software Supply Chain'
    'T1542'     = 'Pre-OS Boot'
    'T1542.005' = 'Pre-OS Boot: TFTP Boot'
    'T1546'     = 'Event Triggered Execution'
    'T1053'     = 'Scheduled Task/Job'
    'T1505'     = 'Server Software Component'
    'T1505.003' = 'Server Software Component: Web Shell'
    'T1070'     = 'Indicator Removal on Host'
    'T1070.002' = 'Indicator Removal: Clear Linux/Mac System Logs'
    'T1562'     = 'Impair Defenses'
    'T1562.001' = 'Impair Defenses: Disable or Modify Tools'
    'T1205'     = 'Traffic Signaling'
    'T1205.001' = 'Traffic Signaling: Port Knocking'
    'T1018'     = 'Remote System Discovery'
    'T1082'     = 'System Information Discovery'
    'T1083'     = 'File and Directory Discovery'
    'T1046'     = 'Network Service Discovery'
    'T1049'     = 'System Network Connections Discovery'
    'T1590'     = 'Gather Victim Network Information'
    'T1036'     = 'Masquerading'
    'T1027'     = 'Obfuscated Files or Information'
    'T1059'     = 'Command and Scripting Interpreter'
    'T1059.006' = 'Command and Scripting Interpreter: Python'
    'T1014'     = 'Rootkit'
    'T1601'     = 'Modify System Image'
    'T1601.001' = 'Modify System Image: Patch System Image'
    'T1601.002' = 'Modify System Image: Downgrade System Image'
    'T1600'     = 'Weaken Encryption'
    'T1552'     = 'Unsecured Credentials'
    'T1552.001' = 'Unsecured Credentials: Credentials In Files'
    'T1020'     = 'Automated Exfiltration'
    # ICS (ATT&CK for ICS)
    'T0843'     = 'Program Upload'
    'T0846'     = 'Remote System Discovery'
    'T0857'     = 'System Firmware'
    'T0859'     = 'Valid Accounts'
    'T0860'     = 'Wireless Compromise'
    'T0862'     = 'Supply Chain Compromise'
    'T0869'     = 'Standard Application Layer Protocol'
    'T0886'     = 'Remote Services'
    'T0888'     = 'Remote System Information Discovery'
    'T0891'     = 'Hardcoded Credentials'
}

# ===============================================================================
# MAIN EXPORTED FUNCTION
# ===============================================================================
function Invoke-RouterTriage {
    [CmdletBinding(DefaultParameterSetName='Live')]
    param(
        [Parameter(Mandatory, ParameterSetName='Live', HelpMessage='Hostname or IP address of the router to triage')]
        [string]$Target,

        [Parameter(Mandatory, ParameterSetName='Offline', HelpMessage='Path to offline dump directory created by Save-RouterDump')]
        [string]$DumpPath,

        [Parameter(ParameterSetName='Live', HelpMessage='PSCredential for SSH login')]
        [System.Management.Automation.PSCredential]$Credential,

        [ValidateSet('auto','ios-xe','nxos','junos','fortios','panos','sel','mikrotik','linksys','tplink','glinet')]
        [string]$Platform = 'auto',

        [string]$OutputPath = (Get-Location).Path,

        [switch]$OpenReport,

        [Parameter(ParameterSetName='Live')]
        [string]$SshKey
    )

    $offlineMode = $PSCmdlet.ParameterSetName -eq 'Offline'

    # -- Resolve OutputPath to absolute ------------------------------------------
    if (-not [System.IO.Path]::IsPathRooted($OutputPath)) {
        $OutputPath = Join-Path (Get-Location).Path $OutputPath
    }

    # -- Resolve DumpPath and infer Target/Platform from manifest if offline -----
    if ($offlineMode) {
        if (-not (Test-Path -LiteralPath $DumpPath)) {
            Write-Host "[LP-RTR] DumpPath not found: $DumpPath" -ForegroundColor Red
            return
        }
        $manifestPath = Join-Path $DumpPath 'dump_manifest.json'
        if (Test-Path $manifestPath) {
            $manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
            if (-not $Target   -and $manifest.Target)   { $Target   = $manifest.Target }
            if ($Platform -eq 'auto' -and $manifest.Platform) { $Platform = $manifest.Platform }
        }
        if (-not $Target) { $Target = Split-Path $DumpPath -Leaf }
    }

    Write-Host "`n[LP-RTR] ============================================================" -ForegroundColor Cyan
    Write-Host "[LP-RTR] Loaded Potato  -  Router Forensic Triage Engine" -ForegroundColor Cyan
    if ($offlineMode) {
        Write-Host "[LP-RTR] Mode    : OFFLINE (dump directory)" -ForegroundColor Yellow
        Write-Host "[LP-RTR] Dump    : $DumpPath" -ForegroundColor White
    } else {
        Write-Host "[LP-RTR] Mode    : LIVE SSH" -ForegroundColor Green
        Write-Host "[LP-RTR] Target  : $Target" -ForegroundColor White
    }
    Write-Host "[LP-RTR] Platform: $Platform" -ForegroundColor White
    Write-Host "[LP-RTR] Output  : $OutputPath" -ForegroundColor White
    Write-Host "[LP-RTR] ============================================================" -ForegroundColor Cyan

    # -- Resolve credentials (live mode only) -----------------------------------
    $sshUser     = ''
    $sshPassword = ''
    if (-not $offlineMode -and $Credential) {
        $sshUser     = $Credential.UserName
        $sshPassword = $Credential.GetNetworkCredential().Password
    }

    # -- Findings accumulators ---------------------------------------------------
    $findings  = [System.Collections.Generic.List[PSCustomObject]]::new()
    $iocList   = [System.Collections.Generic.List[PSCustomObject]]::new()
    $timeline  = [System.Collections.Generic.List[PSCustomObject]]::new()
    $mitreMap  = [System.Collections.Generic.Dictionary[string,System.Collections.Generic.List[string]]]::new()

    # -- Nested helpers ----------------------------------------------------------

    function Add-Finding {
        param([string]$Sev, [string]$Cat, [string]$Title, [string]$Detail,
              [string[]]$Techniques = @(), [string]$Raw = '')
        $findings.Add([PSCustomObject]@{
            Severity   = $Sev
            Category   = $Cat
            Title      = $Title
            Detail     = $Detail
            Techniques = $Techniques
            Raw        = $Raw
        })
        foreach ($t in $Techniques) {
            if ($t) {
                if (-not $mitreMap.ContainsKey($t)) {
                    $mitreMap[$t] = [System.Collections.Generic.List[string]]::new()
                }
                if (-not $mitreMap[$t].Contains($Title)) { [void]$mitreMap[$t].Add($Title) }
            }
        }
    }

    function Add-IOC {
        param([string]$Type, [string]$Value, [string]$Context, [string]$ThreatMatch = '')
        # Deduplicate by Type+Value
        $exists = $iocList | Where-Object { $_.Type -eq $Type -and $_.Value -eq $Value }
        if (-not $exists) {
            $iocList.Add([PSCustomObject]@{
                Type        = $Type
                Value       = $Value
                Context     = $Context
                ThreatMatch = $ThreatMatch
            })
        }
    }

    function Add-Timeline {
        param([string]$Time, [string]$Severity, [string]$Event, [string]$Source = '')
        $timeline.Add([PSCustomObject]@{
            Time     = $Time
            Severity = $Severity
            Event    = $Event
            Source   = $Source
        })
    }

    function Escape-Html {
        param([string]$s)
        if (-not $s) { return '' }
        $s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;'
    }

    # -- Command execution helper (live SSH or offline file read) ----------------
    function Get-DumpFileName {
        param([string]$Cmd)
        # Sanitize command to a safe filename: keep alphanum/hyphen, collapse rest to _
        ($Cmd -replace '[^a-zA-Z0-9\-]','_' -replace '_+','_' -replace '^_|_$','') + '.txt'
    }

    function Invoke-RouterCommand {
        param(
            [string]$Cmd,
            [int]$TimeoutSec = 30
        )
        if (-not $Cmd) { return $null }

        # ---- OFFLINE MODE: read from dump directory ----------------------------
        if ($offlineMode) {
            $fileName = Get-DumpFileName $Cmd
            $filePath = Join-Path $DumpPath $fileName
            if (Test-Path -LiteralPath $filePath) {
                $content = Get-Content -LiteralPath $filePath -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
                return if ($content) { $content.Trim() } else { $null }
            }
            return $null
        }

        # ---- LIVE MODE: SSH via plink.exe or ssh.exe ---------------------------
        $stdout   = $null
        $plinkExe = Get-Command 'plink.exe' -ErrorAction SilentlyContinue
        $sshExe   = Get-Command 'ssh.exe'   -ErrorAction SilentlyContinue

        try {
            if ($plinkExe -and $sshPassword) {
                $plinkArgs = @('-ssh', '-batch', '-pw', $sshPassword, "$sshUser@$Target", $Cmd)
                $proc = Start-Process -FilePath $plinkExe.Source -ArgumentList $plinkArgs `
                    -NoNewWindow -PassThru -RedirectStandardOutput "$env:TEMP\lp_rtr_stdout.txt" `
                    -RedirectStandardError  "$env:TEMP\lp_rtr_stderr.txt"
                $proc.WaitForExit(($TimeoutSec * 1000)) | Out-Null
                if (-not $proc.HasExited) { $proc.Kill() }
                $stdout = Get-Content "$env:TEMP\lp_rtr_stdout.txt" -Raw -ErrorAction SilentlyContinue
                Remove-Item "$env:TEMP\lp_rtr_stdout.txt","$env:TEMP\lp_rtr_stderr.txt" -Force -ErrorAction SilentlyContinue

            } elseif ($sshExe -and $SshKey) {
                $sshArgs = @('-o','StrictHostKeyChecking=no','-o','BatchMode=yes',
                             '-i',$SshKey,'-o',"ConnectTimeout=$TimeoutSec",
                             "$sshUser@$Target", $Cmd)
                $proc = Start-Process -FilePath $sshExe.Source -ArgumentList $sshArgs `
                    -NoNewWindow -PassThru -RedirectStandardOutput "$env:TEMP\lp_rtr_stdout.txt" `
                    -RedirectStandardError  "$env:TEMP\lp_rtr_stderr.txt"
                $proc.WaitForExit(($TimeoutSec * 1000)) | Out-Null
                if (-not $proc.HasExited) { $proc.Kill() }
                $stdout = Get-Content "$env:TEMP\lp_rtr_stdout.txt" -Raw -ErrorAction SilentlyContinue
                Remove-Item "$env:TEMP\lp_rtr_stdout.txt","$env:TEMP\lp_rtr_stderr.txt" -Force -ErrorAction SilentlyContinue

            } elseif ($sshExe -and $sshPassword) {
                $env:SSH_ASKPASS_REQUIRE = 'force'
                $env:DISPLAY = ':0'
                $sshArgs = @('-o','StrictHostKeyChecking=no','-o',"ConnectTimeout=$TimeoutSec",
                             "$sshUser@$Target", $Cmd)
                $proc = Start-Process -FilePath $sshExe.Source -ArgumentList $sshArgs `
                    -NoNewWindow -PassThru -RedirectStandardOutput "$env:TEMP\lp_rtr_stdout.txt" `
                    -RedirectStandardError  "$env:TEMP\lp_rtr_stderr.txt"
                $proc.WaitForExit(($TimeoutSec * 1000)) | Out-Null
                if (-not $proc.HasExited) { $proc.Kill() }
                $stdout = Get-Content "$env:TEMP\lp_rtr_stdout.txt" -Raw -ErrorAction SilentlyContinue
                Remove-Item "$env:TEMP\lp_rtr_stdout.txt","$env:TEMP\lp_rtr_stderr.txt" -Force -ErrorAction SilentlyContinue
            } else {
                Write-Warning "[LP-RTR] No SSH client found (plink.exe or ssh.exe) or no credentials provided."
                return $null
            }
        } catch { return $null }

        if ($stdout) {
            $filtered = ($stdout -split "`n") | Where-Object {
                $_ -notmatch '(?i)(^WARNING:|^The authenticity|are you sure|REMOTE HOST IDENTIFICATION|StrictHostKeyChecking|plink:|^Using|^Allocated|^\s*$)' -or
                $_ -match '\S'
            }
            $stdout = ($filtered -join "`n").Trim()
            if ($stdout -match '(?i)(connection refused|no route to host|permission denied|authentication failed|timed out|command not found)') {
                return $null
            }
        }
        return if ($stdout) { $stdout } else { $null }
    }

    # -- Collect timestamp -------------------------------------------------------
    $collectionTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    # ==========================================================================
    # PLATFORM AUTO-DETECTION
    # ==========================================================================
    Write-Host "[LP-RTR] Module 0: Platform detection..." -ForegroundColor DarkCyan

    $showVersion = Invoke-RouterCommand 'show version'
    if (-not $showVersion) {
        # Try alternatives for platforms that don't understand 'show version'
        $showVersion = Invoke-RouterCommand 'get system status'
        if (-not $showVersion) {
            $showVersion = Invoke-RouterCommand 'show system information'
        }
        if (-not $showVersion) {
            # MikroTik RouterOS
            $showVersion = Invoke-RouterCommand '/system resource print'
        }
        if (-not $showVersion) {
            # MikroTik RouterBOARD identification
            $showVersion = Invoke-RouterCommand '/system routerboard print'
        }
        if (-not $showVersion) {
            # GL.iNet specific version file
            $showVersion = Invoke-RouterCommand 'cat /etc/glversion 2>/dev/null; cat /etc/openwrt_release 2>/dev/null'
        }
        if (-not $showVersion) {
            # OpenWrt (Linksys / TP-Link)
            $showVersion = Invoke-RouterCommand 'cat /etc/openwrt_release'
        }
        if (-not $showVersion) {
            # Generic Linux fallback
            $showVersion = Invoke-RouterCommand 'uname -a'
        }
    }

    $detectedPlatform = $Platform
    if ($Platform -eq 'auto') {
        if ($showVersion -match '(?i)cisco\s+ios\s+xe|ios-xe') {
            $detectedPlatform = 'ios-xe'
        } elseif ($showVersion -match '(?i)cisco\s+nexus|NX-OS|nxos') {
            $detectedPlatform = 'nxos'
        } elseif ($showVersion -match '(?i)JUNOS|Juniper') {
            $detectedPlatform = 'junos'
        } elseif ($showVersion -match '(?i)FortiGate|FortiOS|Fortinet') {
            $detectedPlatform = 'fortios'
        } elseif ($showVersion -match '(?i)PAN-OS|Palo Alto') {
            $detectedPlatform = 'panos'
        } elseif ($showVersion -match '(?i)\bSEL\b|Schweitzer|SELOGIC') {
            $detectedPlatform = 'sel'
        } elseif ($showVersion -match '(?i)RouterOS|MikroTik|RouterBOARD|mipsbe|tilegx|CRS\d|CCR\d|hAP|hEX') {
            $detectedPlatform = 'mikrotik'
        } elseif ($showVersion -match '(?i)GL\.?iNet|glinet|\bGL-(?:MT|AR|AX|B|E|X|MV|S)\w*|Beryl|Slate|Flint|Brume|Mango|Opal|Spitz|Convexa|Shadow|GL_VERSION') {
            $detectedPlatform = 'glinet'
        } elseif ($showVersion -match '(?i)Linksys|WRT\d|EA\d{4}|Velop|Belkin') {
            $detectedPlatform = 'linksys'
        } elseif ($showVersion -match '(?i)TP-?Link|Archer|Omada|JetStream|TL-\w+') {
            $detectedPlatform = 'tplink'
        } else {
            # Default guess
            $detectedPlatform = 'ios-xe'
            Add-Finding 'MEDIUM' 'Platform' 'Platform Auto-Detection Inconclusive' `
                "Could not determine platform from 'show version' output. Defaulting to ios-xe. Specify -Platform explicitly if incorrect." `
                @('T1082','T0888')
        }
    }

    Write-Host "[LP-RTR]   Detected platform: $detectedPlatform" -ForegroundColor White

    # Extract device hostname from show version
    $deviceHostname = $Target
    if ($showVersion -match '(?i)(?:hostname|^(\S+)\s+uptime|router\s+name[:\s]+(\S+))') {
        if ($Matches[2]) { $deviceHostname = $Matches[2] }
        elseif ($Matches[1]) { $deviceHostname = $Matches[1] }
    }
    if ($showVersion -match '^\s*(\S+[-\w]+)\s+uptime') { $deviceHostname = $Matches[1] }

    # Extract serial number
    $serialNumber = 'Unknown'
    if ($showVersion -match '(?i)(?:processor\s+board\s+id|serial\s+number|system\s+serial)[:\s]+(\S+)') {
        $serialNumber = $Matches[1]
    }

    # Extract software version
    $softwareVersion = 'Unknown'
    if ($showVersion -match '(?i)(?:cisco ios.*version|junos:|version:?)\s+([\d\.A-Za-z\-]+)') {
        $softwareVersion = $Matches[1]
    } elseif ($showVersion -match '(?i)version\s+([\d\.]+)') {
        $softwareVersion = $Matches[1]
    }

    # Extract uptime
    $deviceUptime = 'Unknown'
    if ($showVersion -match '(?i)uptime\s+is\s+(.+)') { $deviceUptime = $Matches[1].Trim() }
    elseif ($showVersion -match '(?i)system\s+uptime[:\s]+(.+)') { $deviceUptime = $Matches[1].Trim() }

    Add-Finding 'INFO' 'Device Profile' "Platform Identified: $detectedPlatform" `
        "Device: $deviceHostname | Version: $softwareVersion | Serial: $serialNumber | Uptime: $deviceUptime | Auto-detected: $($Platform -eq 'auto')" `
        @('T1082','T0888')
    Add-Timeline $collectionTime 'INFO' "Triage collection started on $deviceHostname ($detectedPlatform)" $Target

    # ==========================================================================
    # MODULE 01  -  DEVICE PROFILE & INTEGRITY
    # ==========================================================================
    Write-Host "[LP-RTR] Module 01: Device profile and integrity..." -ForegroundColor DarkCyan

    $deviceProfile = [ordered]@{
        Hostname        = $deviceHostname
        'Target IP/DNS' = $Target
        Platform        = $detectedPlatform
        'SW Version'    = $softwareVersion
        'Serial Number' = $serialNumber
        Uptime          = $deviceUptime
        'Triage Time'   = $collectionTime
    }

    # IOS-XE: Platform integrity (SYNful Knock indicator)
    if ($detectedPlatform -eq 'ios-xe') {
        $integrityOut = Invoke-RouterCommand 'show platform integrity sign nonce 12345'
        if ($integrityOut) {
            $deviceProfile['Integrity Check'] = 'Executed (see findings)'
            # Look for hash mismatch indicators
            if ($integrityOut -match '(?i)(mismatch|fail|invalid|error|not\s+match|corrupt)') {
                Add-Finding 'CRITICAL' 'Device Integrity' 'IOS-XE Platform Integrity Hash MISMATCH  -  Possible SYNful Knock Implant' `
                    "Command 'show platform integrity sign nonce 12345' returned indicators of hash mismatch. This is a primary diagnostic indicator of the SYNful Knock ROMMON-level IOS implant, which persists across reboots and patches. Full reimaging of flash is required. Evidence: $($integrityOut | Select-String -Pattern '(?i)(mismatch|fail|invalid)' | Select-Object -First 3 | ForEach-Object { $_.Line.Trim() } | Select-Object -First 3 )" `
                    @('T1601.001','T1542','T1014') $integrityOut
                Add-IOC 'Event' 'IOS-XE Integrity Hash Mismatch' 'SYNful Knock indicator  -  see Module 01'
                Add-Timeline $collectionTime 'CRITICAL' 'Platform integrity hash mismatch detected  -  SYNful Knock implant suspected' $Target
            } else {
                Add-Finding 'INFO' 'Device Integrity' 'IOS-XE Platform Integrity Check Passed' `
                    'show platform integrity sign returned no mismatch indicators.' `
                    @() $integrityOut
            }
        } else {
            Add-Finding 'MEDIUM' 'Device Integrity' 'IOS-XE Platform Integrity Check Unavailable' `
                "Command 'show platform integrity sign nonce 12345' returned no output or failed. Device may be running older IOS-XE without TPM-backed integrity, or command is not supported. Absence of integrity check data reduces assurance." `
                @('T1601.001','T1542')
        }

        # IOS-XE: Flash filesystem
        $dirFlash = Invoke-RouterCommand 'dir flash:'
        if ($dirFlash) {
            $suspFlashFiles = @($dirFlash -split "`n" | Where-Object {
                $_ -match '\S' -and $_ -notmatch '(?i)(\.bin|\.pkg|\.conf|\.log|\.tar|nvram|crashinfo|\.xml|certs|\.key|tracelogs|pnp)' -and
                $_ -match '^\s+\d+' -and $_ -notmatch '(?i)(directory|total|bytes)'
            })
            foreach ($sf in $suspFlashFiles) {
                $sfName = if ($sf -match '(\S+)$') { $Matches[1] } else { $sf.Trim() }
                Add-Finding 'HIGH' 'Device Integrity' "Unexpected File in flash:  -  $sfName" `
                    "File '$sfName' in flash: does not match expected extensions (.bin/.pkg/.conf). Unexpected files in flash may indicate dropper payloads, implant staging, or TCL backdoor scripts. Verify against known-good file manifest." `
                    @('T1601.001','T1083') $sf
                Add-IOC 'FilePath' "flash:/$sfName" 'Unexpected file in router flash storage'
            }
            $deviceProfile['Flash Files'] = "$(@($dirFlash -split "`n" | Where-Object { $_ -match '^\s+\d+' }).Count) files in flash:"
        }

        # IOS-XE: ROM Variables
        $romVar = Invoke-RouterCommand 'show rom-var'
        if ($romVar -and $romVar -match '(?i)(BOOT_PARAM|rommon_var|unexpected|MANUAL_BOOT)') {
            Add-Finding 'HIGH' 'Device Integrity' 'Unexpected ROMMON Variable(s) Detected' `
                "ROMMON variables contain potentially suspicious entries. Attackers modify ROMMON boot parameters as part of firmware-level persistence (SYNful Knock variant). Review: $($romVar | Select-String -Pattern '(?i)(BOOT_PARAM|MANUAL_BOOT)' | Select-Object -First 5 | ForEach-Object { $_.Line.Trim() })" `
                @('T1542','T1601.001') $romVar
        }

        # IOS-XE: Config diff (running vs startup)
        $runConfig   = Invoke-RouterCommand 'show running-config'
        $startConfig = Invoke-RouterCommand 'show startup-config'
        if ($runConfig -and $startConfig) {
            $runLines   = @($runConfig   -split "`n" | Where-Object { $_ -match '\S' -and $_ -notmatch '^!' } | ForEach-Object { $_.Trim() } | Sort-Object)
            $startLines = @($startConfig -split "`n" | Where-Object { $_ -match '\S' -and $_ -notmatch '^!' } | ForEach-Object { $_.Trim() } | Sort-Object)
            $runSet   = [System.Collections.Generic.HashSet[string]]::new($runLines)
            $startSet = [System.Collections.Generic.HashSet[string]]::new($startLines)
            $inRunNotStart = @($runLines | Where-Object { -not $startSet.Contains($_) } | Select-Object -First 10)
            $inStartNotRun = @($startLines | Where-Object { -not $runSet.Contains($_) } | Select-Object -First 10)
            if ($inRunNotStart.Count -gt 0 -or $inStartNotRun.Count -gt 0) {
                $deltaDetail = "Lines in running but NOT startup ($($inRunNotStart.Count)): $($inRunNotStart[0..4] -join ' | ') | Lines in startup but NOT running ($($inStartNotRun.Count)): $($inStartNotRun[0..4] -join ' | ')"
                Add-Finding 'HIGH' 'Device Integrity' 'Running Config Differs from Startup Config  -  Post-Boot Tampering Indicator' `
                    "A delta exists between running-config and startup-config. Any unsaved change after boot may indicate in-memory tampering. Adversaries modify running config without saving to avoid forensic detection. $deltaDetail" `
                    @('T1601.001','T1070') $deltaDetail
                Add-Timeline $collectionTime 'HIGH' 'Running/startup config delta detected  -  possible post-boot in-memory tampering' $Target
            }
        }

        # Last config change timestamp
        $archLog = Invoke-RouterCommand 'show archive log config all'
        if ($archLog) {
            $lastChange = ($archLog -split "`n" | Where-Object { $_ -match '\d{2}:\d{2}:\d{2}' } | Select-Object -Last 1)
            if ($lastChange) {
                $deviceProfile['Last Config Change'] = $lastChange.Trim()
                Add-Timeline ($lastChange -replace '.*?(\d{4}-\d{2}-\d{2}|\d{2}:\d{2}:\d{2}).*','$1') 'INFO' "Last config change: $($lastChange.Trim())" $Target
            }
        }
    }

    # NX-OS: System integrity
    if ($detectedPlatform -eq 'nxos') {
        $nxIntegrity = Invoke-RouterCommand 'show system integrity'
        if ($nxIntegrity -and $nxIntegrity -match '(?i)(fail|error|mismatch|tamper)') {
            Add-Finding 'CRITICAL' 'Device Integrity' 'NX-OS System Integrity Check Failure' `
                "show system integrity returned failure indicators. Evidence: $($nxIntegrity -split "`n" | Where-Object { $_ -match '(?i)(fail|error)' } | Select-Object -First 5 | ForEach-Object { $_.Trim() })" `
                @('T1601.001','T0857') $nxIntegrity
        }
    }

    # JunOS: Storage and version detail
    if ($detectedPlatform -eq 'junos') {
        $junStorage = Invoke-RouterCommand 'show system storage'
        $junVerDet  = Invoke-RouterCommand 'show version detail'
        if ($junStorage -and $junStorage -match '(?i)(flash|var|tmp)') {
            $deviceProfile['JunOS Storage'] = ($junStorage -split "`n" | Select-Object -First 5 | ForEach-Object { $_.Trim() }) -join ' | '
        }
    }

    # FortiOS: System status and flash
    if ($detectedPlatform -eq 'fortios') {
        $fortiStatus = Invoke-RouterCommand 'get system status'
        $fortiFlash  = Invoke-RouterCommand 'diagnose sys flash list'
        if ($fortiStatus) {
            $deviceProfile['FortiOS Status'] = ($fortiStatus -split "`n" | Where-Object { $_ -match ':' } | Select-Object -First 6 | ForEach-Object { $_.Trim() }) -join ' | '
        }
        if ($fortiFlash -and $fortiFlash -match '(?i)(error|corrupt|fail|invalid)') {
            Add-Finding 'HIGH' 'Device Integrity' 'FortiOS Flash Integrity Warning' `
                "diagnose sys flash list returned anomalous output. Evidence: $($fortiFlash -split "`n" | Where-Object { $_ -match '(?i)(error|corrupt)' } | Select-Object -First 3 | ForEach-Object { $_.Trim() })" `
                @('T0857','T1601.001') $fortiFlash
        }
    }

    # PAN-OS: System info and files
    if ($detectedPlatform -eq 'panos') {
        $panSysInfo = Invoke-RouterCommand 'show system info'
        $panFiles   = Invoke-RouterCommand 'show system files'
        if ($panSysInfo) {
            $deviceProfile['PAN-OS Info'] = ($panSysInfo -split "`n" | Where-Object { $_ -match ':' } | Select-Object -First 6 | ForEach-Object { $_.Trim() }) -join ' | '
        }
    }

    # SEL: Version and flash
    if ($detectedPlatform -eq 'sel') {
        $selVer   = Invoke-RouterCommand 'show version'
        $selFlash = Invoke-RouterCommand 'show flash'
        if ($selVer)   { $deviceProfile['SEL Version'] = ($selVer -split "`n" | Select-Object -First 3 | ForEach-Object { $_.Trim() }) -join ' | ' }
        if ($selFlash) { $deviceProfile['SEL Flash']   = ($selFlash -split "`n" | Select-Object -First 5 | ForEach-Object { $_.Trim() }) -join ' | ' }
    }

    # MikroTik: RouterOS resource, RouterBOARD, package integrity
    if ($detectedPlatform -eq 'mikrotik') {
        $mtResource = Invoke-RouterCommand '/system resource print'
        $mtBoard    = Invoke-RouterCommand '/system routerboard print'
        $mtPackages = Invoke-RouterCommand '/system package print'
        $mtFiles    = Invoke-RouterCommand '/file print detail'
        if ($mtResource) {
            $deviceProfile['MikroTik Resource'] = ($mtResource -split "`n" | Where-Object { $_ -match '(?i)(version|cpu|uptime|board)' } | Select-Object -First 6 | ForEach-Object { $_.Trim() }) -join ' | '
        }
        if ($mtBoard -and $mtBoard -match '(?i)current-firmware') {
            if ($mtBoard -match '(?i)current-firmware[:\s]+([\d\.]+)' -and $mtBoard -match '(?i)upgrade-firmware[:\s]+([\d\.]+)') {
                $curFw = $Matches[1]
                if ($mtBoard -match '(?i)current-firmware[:\s]+([\d\.]+)[\s\S]*?upgrade-firmware[:\s]+([\d\.]+)') {
                    $curFw = $Matches[1]; $upFw = $Matches[2]
                    if ($curFw -ne $upFw) {
                        Add-Finding 'MEDIUM' 'Device Integrity' "MikroTik RouterBOOT Firmware Out-of-Sync (current=$curFw upgrade=$upFw)" `
                            "RouterBOOT current-firmware differs from upgrade-firmware. Unpatched RouterBOOT has been targeted by VPNFilter/Chimay-Red persistence. Verify against vendor baseline." `
                            @('T1542','T1601.001') $mtBoard
                    }
                }
            }
            $deviceProfile['RouterBOARD'] = ($mtBoard -split "`n" | Where-Object { $_ -match '\S' } | Select-Object -First 4 | ForEach-Object { $_.Trim() }) -join ' | '
        }
        if ($mtFiles) {
            # MikroTik implants are often dropped as .npk, .scr, or unusual extensions in / (root of file system)
            $mtSuspFiles = @($mtFiles -split "`n" | Where-Object {
                $_ -match '(?i)\.(sh|pl|py|bin|elf|scr|rsc)\b' -or
                $_ -match '(?i)(chimay|vpnfilter|meris|brutalkangaroo)'
            })
            foreach ($mf in $mtSuspFiles) {
                Add-Finding 'HIGH' 'Device Integrity' "MikroTik Suspicious File: $($mf.Trim())" `
                    "Unexpected file found in MikroTik filesystem. MikroTik implants (VPNFilter, Chimay-Red, Meris botnet) drop scripts and binaries into the device filesystem for persistence." `
                    @('T1601.001','T1083') $mf
                Add-IOC 'FilePath' ($mf.Trim()) 'MikroTik filesystem suspicious entry'
            }
            $deviceProfile['MikroTik Files'] = "$(@($mtFiles -split "`n" | Where-Object { $_ -match '\S' }).Count) entries"
        }
        if ($mtPackages -and $mtPackages -match '(?i)(disabled|scheduled)') {
            $disabledPkgs = @($mtPackages -split "`n" | Where-Object { $_ -match '(?i)disabled' })
            if ($disabledPkgs.Count -gt 0) {
                Add-Finding 'MEDIUM' 'Device Integrity' "MikroTik Packages Disabled ($($disabledPkgs.Count))" `
                    "One or more RouterOS packages are disabled: $($disabledPkgs | Select-Object -First 3 | ForEach-Object { $_.Trim() }). Adversaries sometimes disable security-relevant packages (ipsec, firewall auditing) to weaken defenses." `
                    @('T1562.001') $mtPackages
            }
        }
    }

    # Linksys / TP-Link (OpenWrt-like Linux firmware): release, uci config, dropbear keys
    if ($detectedPlatform -in @('linksys','tplink','glinet')) {
        $owRelease = Invoke-RouterCommand 'cat /etc/openwrt_release'
        if (-not $owRelease) { $owRelease = Invoke-RouterCommand 'cat /etc/os-release' }
        $uname     = Invoke-RouterCommand 'uname -a'
        if ($owRelease) {
            $deviceProfile['OpenWrt Release'] = ($owRelease -split "`n" | Where-Object { $_ -match '\S' } | Select-Object -First 6 | ForEach-Object { $_.Trim() }) -join ' | '
        }
        if ($uname) { $deviceProfile['Kernel'] = $uname.Trim() }

        # Suspicious persistence files: /tmp, /etc/rc.local, /etc/init.d, /etc/crontabs
        $rcLocal = Invoke-RouterCommand 'cat /etc/rc.local'
        if ($rcLocal -and $rcLocal -match '(?i)(wget|curl|nc\s|netcat|/tmp/|bash\s+-i|python|perl)') {
            Add-Finding 'CRITICAL' 'Device Integrity' 'Suspicious /etc/rc.local Content  -  Boot-Time Persistence' `
                "rc.local contains suspicious commands indicative of attacker persistence on OpenWrt/Linux routers (wget/curl pulls, reverse shells, /tmp execution). Evidence: $($rcLocal -split "`n" | Where-Object { $_ -match '(?i)(wget|curl|nc\s|bash|python)' } | Select-Object -First 3 | ForEach-Object { $_.Trim() } | Out-String)" `
                @('T1037','T1543','T1546') $rcLocal
            Add-IOC 'FilePath' '/etc/rc.local' 'Modified boot script on router'
            Add-Timeline $collectionTime 'CRITICAL' '/etc/rc.local contains suspicious commands' $Target
        }

        $tmpLs = Invoke-RouterCommand 'ls -la /tmp'
        if ($tmpLs) {
            $suspTmp = @($tmpLs -split "`n" | Where-Object { $_ -match '(?i)\.(sh|pl|py|elf|bin)$' -or $_ -match '(?i)(busybox|httpd|telnetd|mirai|gafgyt|tsunami)' })
            foreach ($st in $suspTmp) {
                Add-Finding 'HIGH' 'Device Integrity' "Suspicious File in /tmp: $($st.Trim())" `
                    "Unexpected executable or script in /tmp. /tmp is writable and widely used by IoT botnet droppers (Mirai/Gafgyt variants) and VPNFilter-style implants on Linksys/TP-Link hardware." `
                    @('T1601.001','T1083','T1036') $st
                Add-IOC 'FilePath' "/tmp/$(($st -split '\s+' | Select-Object -Last 1))" 'Suspicious file in router /tmp'
            }
        }

        $initD = Invoke-RouterCommand 'ls /etc/init.d'
        if ($initD) {
            $deviceProfile['init.d Scripts'] = "$(@($initD -split "`s+" | Where-Object { $_ -match '\S' }).Count) scripts"
        }
    }

    # ==========================================================================
    # MODULE 02  -  USER ACCOUNTS & AUTHENTICATION
    # ==========================================================================
    Write-Host "[LP-RTR] Module 02: User accounts and authentication..." -ForegroundColor DarkCyan

    # Known legitimate administrative account patterns (customize per environment)
    $knownAdminPattern = '(?i)^(admin|administrator|netops|noc|sysadmin)$'

    $usersRaw = $null
    switch ($detectedPlatform) {
        'ios-xe'  { $usersRaw = Invoke-RouterCommand 'show running-config | section username' }
        'nxos'    { $usersRaw = Invoke-RouterCommand 'show user-account' }
        'junos'   { $usersRaw = Invoke-RouterCommand 'show configuration system login' }
        'fortios' { $usersRaw = Invoke-RouterCommand 'show system admin' }
        'panos'   { $usersRaw = Invoke-RouterCommand 'show admins' }
        'sel'     { $usersRaw = Invoke-RouterCommand 'show access' }
        'mikrotik'{ $usersRaw = Invoke-RouterCommand '/user print detail' }
        'linksys' { $usersRaw = Invoke-RouterCommand 'cat /etc/passwd' }
        'tplink'  { $usersRaw = Invoke-RouterCommand 'cat /etc/passwd' }
        'glinet'  { $usersRaw = Invoke-RouterCommand 'cat /etc/passwd; cat /etc/config/glconfig 2>/dev/null | grep -A2 -i user' }
    }

    if ($usersRaw) {
        # IOS-XE: Flag priv 15 accounts
        if ($detectedPlatform -eq 'ios-xe') {
            $priv15Lines = @($usersRaw -split "`n" | Where-Object { $_ -match '(?i)privilege\s+15' })
            foreach ($pl in $priv15Lines) {
                $uname = if ($pl -match '(?i)username\s+(\S+)') { $Matches[1] } else { 'Unknown' }
                if ($uname -notmatch $knownAdminPattern) {
                    Add-Finding 'HIGH' 'User Accounts' "Unexpected Privilege-15 User: $uname" `
                        "User '$uname' has privilege level 15 (full administrative access) and does not match known-good account patterns. Attackers create priv-15 accounts as backdoor persistence after gaining initial access." `
                        @('T1136','T1078','T0859') $pl
                    Add-IOC 'Username' $uname "Unexpected priv-15 account on router"
                    Add-Timeline $collectionTime 'HIGH' "Unexpected priv-15 user found: $uname" $Target
                }
            }

            # Flag unusual username characters (obfuscated backdoor accounts)
            $allUsers = @($usersRaw -split "`n" | Where-Object { $_ -match '(?i)^\s*username\s+\S+' } |
                ForEach-Object { if ($_ -match '(?i)username\s+(\S+)') { $Matches[1] } })
            foreach ($u in $allUsers) {
                if ($u -match '(?i)[\$\!\@\%\^\&\*\(\)\+\=\{\}\[\]\|\\:;"<>,\?\/]' -or
                    $u -match '(?i)^(service|daemon|sys|bin|nobody|www|ftp|mail)') {
                    Add-Finding 'HIGH' 'User Accounts' "Suspicious Username Detected: $u" `
                        "Username '$u' contains unusual characters or resembles a service account name. Attackers use service account names to blend in on routers." `
                        @('T1036','T1078') $u
                    Add-IOC 'Username' $u "Suspicious router username"
                }
            }
        }

        # Check for accounts in output across all platforms
        if ($usersRaw -match '(?i)(backdoor|hack|test123|admin123|r00t|toor|pwned)') {
            $suspUser = ($usersRaw | Select-String -Pattern '(?i)(backdoor|hack|test123|admin123|r00t|toor|pwned)' |
                Select-Object -First 3 | ForEach-Object { $_.Line.Trim() }) -join ' | '
            Add-Finding 'CRITICAL' 'User Accounts' 'Known-Bad Username Pattern Detected' `
                "User account output contains suspicious username patterns associated with attacker accounts: $suspUser" `
                @('T1136','T1078','T0859') $suspUser
        }
    } else {
        Add-Finding 'INFO' 'User Accounts' 'User Account Enumeration Unavailable' `
            "Could not retrieve user account list from device. This may indicate limited command access or platform incompatibility." `
            @()
    }

    # SSH authorized keys on device
    $sshKeyCmd = switch ($detectedPlatform) {
        'ios-xe'  { 'show running-config | include ip ssh pubkey' }
        'junos'   { 'show configuration system login | match ssh-rsa' }
        'mikrotik'{ '/user ssh-keys print detail' }
        'linksys' { 'cat /etc/dropbear/authorized_keys' }
        'tplink'  { 'cat /etc/dropbear/authorized_keys' }
        'glinet'  { 'cat /etc/dropbear/authorized_keys; cat /root/.ssh/authorized_keys 2>/dev/null' }
        default   { $null }
    }
    if ($sshKeyCmd) {
        $sshKeysOut = Invoke-RouterCommand $sshKeyCmd
        if ($sshKeysOut -and $sshKeysOut -match '(?i)(ssh-rsa|ssh-ed25519|ecdsa-sha2)') {
            $keyCount = @($sshKeysOut -split "`n" | Where-Object { $_ -match '(?i)(ssh-rsa|ssh-ed25519|ecdsa-sha2)' }).Count
            Add-Finding 'MEDIUM' 'User Accounts' "SSH Public Keys Stored on Device ($keyCount key(s))" `
                "SSH public key authentication is configured. Keys installed on the device provide persistent remote access without password. Verify all keys against authorized baseline." `
                @('T1098','T1021.004') $sshKeysOut
        }
    }

    # AAA server configuration
    $aaaCmd = switch ($detectedPlatform) {
        'ios-xe'  { 'show running-config | section aaa' }
        'nxos'    { 'show running-config | include tacacs' }
        'junos'   { 'show configuration system radius-server' }
        'fortios' { 'show system radius-server' }
        'panos'   { 'show config running | match radius' }
        'mikrotik'{ '/radius print detail' }
        'linksys' { 'uci show system | grep -iE "radius|tacacs"' }
        'tplink'  { 'uci show system | grep -iE "radius|tacacs"' }
        'glinet'  { 'uci show system | grep -iE "radius|tacacs"; uci show glconfig 2>/dev/null | grep -iE "radius|tacacs|cloud"' }
        default   { $null }
    }
    if ($aaaCmd) {
        $aaaOut = Invoke-RouterCommand $aaaCmd
        if ($aaaOut) {
            # Extract TACACS/RADIUS server IPs and flag any non-RFC1918
            $aaaIPs = @($aaaOut -split "`n" | ForEach-Object {
                if ($_ -match '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') { $Matches[1] }
            } | Sort-Object -Unique)
            foreach ($aip in $aaaIPs) {
                if ($aip -notmatch '^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)') {
                    Add-Finding 'HIGH' 'User Accounts' "AAA Server at Non-RFC1918 Address: $aip" `
                        "A TACACS/RADIUS authentication server is configured at non-private IP $aip. External authentication servers may be attacker-controlled, allowing credential capture or authentication bypass." `
                        @('T1078','T0859') $aip
                    Add-IOC 'IP' $aip "Non-RFC1918 AAA (TACACS/RADIUS) server"
                }
            }
        }
    }

    # Active sessions
    $sessCmd = switch ($detectedPlatform) {
        'ios-xe'  { 'show users' }
        'nxos'    { 'show users' }
        'junos'   { 'show system users' }
        'fortios' { 'get system admin' }
        'panos'   { 'show admins' }
        'mikrotik'{ '/user active print detail' }
        'linksys' { 'who; netstat -tn 2>/dev/null | grep -E ":22|:23"' }
        'tplink'  { 'who; netstat -tn 2>/dev/null | grep -E ":22|:23"' }
        'glinet'  { 'who; netstat -tn 2>/dev/null | grep -E ":22|:23|:80|:443|:83"' }
        default   { $null }
    }

    # ==========================================================================
    # MODULE 03  -  ACTIVE SESSIONS & REMOTE ACCESS
    # ==========================================================================
    Write-Host "[LP-RTR] Module 03: Active sessions and remote access..." -ForegroundColor DarkCyan

    $sessOut = $null
    if ($sessCmd) { $sessOut = Invoke-RouterCommand $sessCmd }

    if ($sessOut) {
        # Flag remote sessions from unexpected IPs
        $sessionIPs = @($sessOut -split "`n" | ForEach-Object {
            if ($_ -match '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') { $Matches[1] }
        } | Sort-Object -Unique | Where-Object { $_ -notmatch '^127\.' })

        foreach ($sip in $sessionIPs) {
            if ($sip -notmatch '^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)') {
                Add-Finding 'HIGH' 'Active Sessions' "Active Session from Non-RFC1918 IP: $sip" `
                    "An active session is established from public IP $sip. Unless this is a documented jump host or management network, this is a significant indicator of unauthorized remote access." `
                    @('T1021.004','T1078') $sip
                Add-IOC 'IP' $sip "Active router session source (non-RFC1918)"
                Add-Timeline $collectionTime 'HIGH' "Active session from public IP $sip" $Target
            }
        }
    }

    # VTY line config  -  telnet enabled, SSH version
    $vtyCmd = switch ($detectedPlatform) {
        'ios-xe'  { 'show running-config | section line vty' }
        'nxos'    { 'show running-config | include telnet' }
        'junos'   { 'show configuration system services' }
        'mikrotik'{ '/ip service print detail' }
        'linksys' { 'uci show dropbear; uci show network | grep -i telnet' }
        'tplink'  { 'uci show dropbear; uci show network | grep -i telnet' }
        'glinet'  { 'uci show dropbear; uci show network | grep -i telnet; uci show glconfig 2>/dev/null' }
        default   { $null }
    }
    if ($vtyCmd) {
        $vtyOut = Invoke-RouterCommand $vtyCmd
        if ($vtyOut) {
            if ($vtyOut -match '(?i)transport\s+input\s+(all|telnet)') {
                Add-Finding 'HIGH' 'Remote Access' 'Telnet Enabled on VTY Lines  -  Cleartext Protocol' `
                    "VTY line configuration allows Telnet transport. Telnet transmits credentials and session data in cleartext. Attacker positioned on the network can intercept router credentials with passive sniffing. Restrict to 'transport input ssh' immediately." `
                    @('T1040','T1557','T1600') $vtyOut
            }
            if ($vtyOut -match '(?i)ip\s+ssh\s+version\s+1') {
                Add-Finding 'HIGH' 'Remote Access' 'SSH Version 1 Enabled  -  Deprecated and Vulnerable Protocol' `
                    "SSH version 1 is configured. SSHv1 has multiple known vulnerabilities including CRC-32 compensation attack, blind session insertion, and client authentication vulnerabilities. Upgrade to SSH version 2 immediately." `
                    @('T1040','T1557') $vtyOut
            }
            if ($vtyOut -match '(?i)no\s+(?:ip\s+)?access-class') {
                Add-Finding 'MEDIUM' 'Remote Access' 'VTY Lines Lack Access-Class ACL Restriction' `
                    "VTY lines do not appear to have access-class restrictions. Without ACL restrictions on management access, any reachable IP can attempt authentication against management interfaces." `
                    @('T1078','T0886') $vtyOut
            }

            # MikroTik: /ip service print - check for enabled insecure services
            if ($detectedPlatform -eq 'mikrotik') {
                $mtInsecure = @($vtyOut -split "`n" | Where-Object {
                    $_ -match '(?i)\s*(telnet|ftp|www|api)\s' -and $_ -notmatch '(?i)disabled|X\s'
                })
                if ($mtInsecure.Count -gt 0) {
                    Add-Finding 'HIGH' 'Remote Access' 'MikroTik Insecure Services Enabled (telnet/ftp/www/api)' `
                        "Insecure services are enabled on the MikroTik: $($mtInsecure | Select-Object -First 5 | ForEach-Object { $_.Trim() } | Out-String). Telnet and FTP send credentials in cleartext; unauthenticated API exposure was abused by the Meris botnet and Chimay-Red exploit." `
                        @('T1040','T1557','T1133') $vtyOut
                }
                # Lack of address restriction (address="")
                if ($vtyOut -match '(?i)address=""') {
                    Add-Finding 'MEDIUM' 'Remote Access' 'MikroTik Service Without Address Restriction' `
                        "One or more /ip service entries have no address restriction (address=\"\"), meaning they accept connections from any IP. Restrict to management prefixes." `
                        @('T1078','T0886') $vtyOut
                }
            }

            # Linksys / TP-Link / GL.iNet (OpenWrt): dropbear/telnet exposure
            if ($detectedPlatform -in @('linksys','tplink','glinet')) {
                if ($vtyOut -match "(?i)dropbear\S*\.Interface='?'?\s*$" -or $vtyOut -match "(?i)Interface=''" -or $vtyOut -match "(?i)dropbear.*lan\b") {
                    Add-Finding 'MEDIUM' 'Remote Access' 'Dropbear SSH Listening on All Interfaces' `
                        "Dropbear SSH appears to be listening on all interfaces (no Interface restriction), exposing the management daemon to every reachable network. Restrict to LAN or mgmt interface only." `
                        @('T1133','T0886') $vtyOut
                }
                if ($vtyOut -match '(?i)telnet') {
                    Add-Finding 'HIGH' 'Remote Access' 'Telnet Enabled on OpenWrt/Linksys/TP-Link Device' `
                        "Telnet service appears enabled. Telnet is the primary infection vector for Mirai-family IoT botnets and transmits credentials in cleartext. Disable immediately." `
                        @('T1040','T1557','T1133') $vtyOut
                }
            }
        }
    }

    # ==========================================================================
    # MODULE 04  -  TRAFFIC INTERCEPTION (CRITICAL PRIORITY)
    # ==========================================================================
    Write-Host "[LP-RTR] Module 04: Traffic interception analysis..." -ForegroundColor DarkCyan

    # SPAN/RSPAN/ERSPAN sessions
    $spanCmd = switch ($detectedPlatform) {
        'ios-xe'  { 'show monitor session all' }
        'nxos'    { 'show monitor session all' }
        'junos'   { 'show interfaces terse | match gr-' }
        'mikrotik'{ '/interface ethernet switch port print' }
        'linksys' { 'tc qdisc show; tc filter show; iptables -t mangle -L -n' }
        'tplink'  { 'tc qdisc show; tc filter show; iptables -t mangle -L -n' }
        'glinet'  { 'tc qdisc show; tc filter show; iptables -t mangle -L -n' }
        default   { $null }
    }
    if ($spanCmd) {
        $spanOut = Invoke-RouterCommand $spanCmd
        if ($spanOut -and $spanOut -match '(?i)(session|source|destination|rspan|erspan|monitor)') {
            $spanSessions = @($spanOut -split "`n" | Where-Object { $_ -match '(?i)(session\s+\d|type:)' })
            Add-Finding 'CRITICAL' 'Traffic Interception' "SPAN/RSPAN/ERSPAN Traffic Mirror Session ACTIVE  -  Salt Typhoon TTP" `
                "Active traffic monitoring session(s) detected. This is the primary indicator of Salt Typhoon APT activity on ISP and carrier routers. SPAN/ERSPAN sessions enable passive capture of all traffic passing through the device, including unencrypted credentials and session content. Sessions: $($spanSessions | Select-Object -First 5 | ForEach-Object { $_.Trim() } | Select-Object -First 5)" `
                @('T1040','T1557','T0869') $spanOut
            Add-IOC 'Event' 'SPAN/RSPAN/ERSPAN session active' 'Salt Typhoon traffic interception TTP'
            Add-Timeline $collectionTime 'CRITICAL' "ACTIVE traffic mirror session detected (SPAN/RSPAN/ERSPAN)  -  Salt Typhoon indicator" $Target
            Write-Host "         [CRITICAL] SPAN/ERSPAN traffic mirror session detected!" -ForegroundColor Red
        } else {
            Add-Finding 'INFO' 'Traffic Interception' 'No Active SPAN/RSPAN/ERSPAN Sessions Detected' `
                'No traffic mirror sessions found. This does not rule out in-line interception via PBR or GRE tunneling.' `
                @()
        }
    }

    # GRE / IPIP / tunnel interfaces
    $tunnelCmd = switch ($detectedPlatform) {
        'ios-xe'  { 'show interfaces tunnel' }
        'nxos'    { 'show interface brief | include Tunnel' }
        'junos'   { 'show interfaces terse | match gr-' }
        'fortios' { 'show system interface | grep -i tunnel' }
        'mikrotik'{ '/interface print where type~"(gre|ipip|eoip|l2tp|pptp|sstp|ovpn|wireguard)"' }
        'linksys' { 'ip tunnel show; ip link show type gre; ip link show type wireguard' }
        'tplink'  { 'ip tunnel show; ip link show type gre; ip link show type wireguard' }
        'glinet'  { 'ip tunnel show; ip link show type gre; ip link show type wireguard; uci show wireguard 2>/dev/null; uci show openvpn 2>/dev/null' }
        default   { $null }
    }
    if ($tunnelCmd) {
        $tunnelOut = Invoke-RouterCommand $tunnelCmd
        if ($tunnelOut -and $tunnelOut -match '(?i)(tunnel|GRE|IPIP|ip.in.ip)') {
            $tunnelLines = @($tunnelOut -split "`n" | Where-Object { $_ -match '(?i)(tunnel|GRE|gr-)' } | Select-Object -First 10)
            Add-Finding 'CRITICAL' 'Traffic Interception' "GRE/IPIP Tunnel Interface(s) Detected  -  Possible Covert Exfiltration Channel" `
                "Tunnel interfaces found: $($tunnelLines | ForEach-Object { $_.Trim() } | Select-Object -First 5). GRE and IPIP tunnels are used by adversaries to encapsulate and exfiltrate traffic to external collection points while bypassing interface-level monitoring. Verify each tunnel endpoint against authorised design documents." `
                @('T1572','T1048','T0869') $tunnelOut
            # Extract tunnel destination IPs
            foreach ($tl in $tunnelLines) {
                if ($tl -match '(?i)destination\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') {
                    $tunnelDst = $Matches[1]
                    Add-IOC 'IP' $tunnelDst "GRE/IPIP tunnel destination  -  possible exfil endpoint"
                    if ($tunnelDst -notmatch '^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)') {
                        Add-Finding 'CRITICAL' 'Traffic Interception' "GRE Tunnel to Public IP: $tunnelDst" `
                            "GRE/IPIP tunnel endpoint $tunnelDst is a public (non-RFC1918) IP. Tunnels to external public IPs are high-confidence indicators of traffic exfiltration or covert C2 channel establishment." `
                            @('T1572','T1048.003') $tunnelDst
                        Add-Timeline $collectionTime 'CRITICAL' "GRE tunnel to public IP $tunnelDst" $Target
                    }
                }
            }
        }
    }

    # Policy-Based Routing (PBR)  -  traffic redirection
    $pbrCmd = switch ($detectedPlatform) {
        'ios-xe'  { 'show ip policy' }
        'nxos'    { 'show ip policy' }
        'mikrotik'{ '/ip route rule print; /ip firewall mangle print where chain=prerouting' }
        'linksys' { 'ip rule show; iptables -t mangle -L PREROUTING -n' }
        'tplink'  { 'ip rule show; iptables -t mangle -L PREROUTING -n' }
        'glinet'  { 'ip rule show; iptables -t mangle -L PREROUTING -n' }
        default   { $null }
    }
    if ($pbrCmd) {
        $pbrOut = Invoke-RouterCommand $pbrCmd
        if ($pbrOut -and $pbrOut -match '\S' -and $pbrOut -notmatch '(?i)(no\s+policy|not\s+configured|^$)') {
            Add-Finding 'CRITICAL' 'Traffic Interception' 'Policy-Based Routing (PBR) Active  -  Traffic Redirection Detected' `
                "Policy-Based Routing maps are applied to interfaces. PBR is used by adversaries to silently redirect traffic subsets (e.g., specific protocols, ports, or sources) to an attacker-controlled collection point while forwarding the remainder normally. Verify all route-maps against authorised traffic engineering design. Output: $($pbrOut -split "`n" | Select-Object -First 10 | ForEach-Object { $_.Trim() })" `
                @('T1040','T1557','T0869') $pbrOut
            Add-Timeline $collectionTime 'CRITICAL' 'Policy-Based Routing active  -  potential traffic redirection' $Target
        }
    }

    # Host routes (/32) with unexpected next-hops
    $ipRouteOut = Invoke-RouterCommand 'show ip route'
    if ($ipRouteOut) {
        $hostRoutes = @($ipRouteOut -split "`n" | Where-Object { $_ -match '/32\s|255\.255\.255\.255' -and $_ -match '\S' })
        if ($hostRoutes.Count -gt 0) {
            $hrSample = ($hostRoutes | Select-Object -First 8 | ForEach-Object { $_.Trim() }) -join ' | '
            Add-Finding 'HIGH' 'Traffic Interception' "Host Routes (/32) in Routing Table ($($hostRoutes.Count) entries)" `
                "Host-specific routes (/32) detected: $hrSample. Host routes injected by adversaries redirect specific traffic (e.g., traffic to management servers, authentication servers) through attacker-controlled next-hops for interception." `
                @('T1557','T0869') $ipRouteOut
        }
    }

    # NHRP (Next Hop Resolution Protocol  -  DMVPN tunnels)
    if ($detectedPlatform -in @('ios-xe','nxos')) {
        $nhrpOut = Invoke-RouterCommand 'show ip nhrp'
        if ($nhrpOut -and $nhrpOut -match '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}') {
            $nhrpIPs = @($nhrpOut -split "`n" | ForEach-Object {
                if ($_ -match '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') { $Matches[1] }
            } | Sort-Object -Unique)
            Add-Finding 'MEDIUM' 'Traffic Interception' "NHRP Entries Present ($($nhrpIPs.Count) next-hop(s))" `
                "NHRP (Next Hop Resolution Protocol) entries: $($nhrpIPs -join ', '). DMVPN/NHRP infrastructure may be leveraged for covert tunnel establishment if compromised. Verify all NHS and spoke endpoints." `
                @('T1572') $nhrpOut
        }
    }

    # JunOS: firewall filters and policy-options
    if ($detectedPlatform -eq 'junos') {
        $junFwFilter = Invoke-RouterCommand 'show firewall filter'
        $junPolicy   = Invoke-RouterCommand 'show policy-options'
        if ($junFwFilter -and $junFwFilter -match '(?i)(mirror|copy-to|sample)') {
            Add-Finding 'CRITICAL' 'Traffic Interception' 'JunOS Firewall Filter with Mirror/Copy Action Detected' `
                "Firewall filter contains mirror or copy-to actions, indicating traffic is being duplicated to a collection interface. This is functionally equivalent to SPAN and is a primary traffic interception technique." `
                @('T1040','T1557') $junFwFilter
        }
    }

    # FortiOS: mirror configuration
    if ($detectedPlatform -eq 'fortios') {
        $fortiMirror = Invoke-RouterCommand 'show full-configuration | grep -i mirror'
        if ($fortiMirror -and $fortiMirror -match '(?i)(mirror|set\s+inbandwidth|set\s+outbandwidth)') {
            Add-Finding 'CRITICAL' 'Traffic Interception' 'FortiOS Interface Mirror Configuration Detected' `
                "FortiOS configuration contains mirror settings. Traffic mirroring on FortiGate allows packet capture of all traversing traffic." `
                @('T1040','T1557') $fortiMirror
        }
    }

    # PAN-OS: Running security policy
    if ($detectedPlatform -eq 'panos') {
        $panSecPolicy = Invoke-RouterCommand 'show running security-policy'
        if ($panSecPolicy -and $panSecPolicy -match '(?i)(allow\s+any|permit\s+any\s+any|from\s+any\s+to\s+any)') {
            Add-Finding 'HIGH' 'Traffic Interception' 'PAN-OS: Overly Permissive Security Policy Detected' `
                "Security policy contains overly broad permit rules. Review all 'allow any' entries: $($panSecPolicy | Select-String -Pattern '(?i)(allow|permit)' | Select-Object -First 5 | ForEach-Object { $_.Line.Trim() })" `
                @('T1562.001') $panSecPolicy
        }
    }

    # ==========================================================================
    # MODULE 05  -  COVERT CHANNELS & EXFIL INFRASTRUCTURE
    # ==========================================================================
    Write-Host "[LP-RTR] Module 05: Covert channels and exfil infrastructure..." -ForegroundColor DarkCyan

    # IKE/IPSec SA  -  unknown VPN peers
    if ($detectedPlatform -in @('ios-xe','nxos')) {
        $isakmpSA = Invoke-RouterCommand 'show crypto isakmp sa'
        $ipsecSA  = Invoke-RouterCommand 'show crypto ipsec sa'

        if ($isakmpSA -and $isakmpSA -match '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}') {
            $vpnPeers = @($isakmpSA -split "`n" | ForEach-Object {
                if ($_ -match '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') { $Matches[1] }
            } | Sort-Object -Unique)
            foreach ($vp in $vpnPeers) {
                Add-IOC 'IP' $vp "IKE/ISAKMP VPN peer  -  verify against authorized VPN design"
            }
            Add-Finding 'MEDIUM' 'Covert Channels' "Active IKE/ISAKMP VPN SA ($($vpnPeers.Count) peer(s))" `
                "VPN peers: $($vpnPeers -join ', '). Verify all IKE/IPSec peers against the authorised VPN design. Unauthorized VPN tunnels are used for encrypted data exfiltration." `
                @('T1572','T1048') $isakmpSA
        }
    }

    # BGP peers  -  unexpected AS neighbors
    $bgpCmd = switch ($detectedPlatform) {
        'ios-xe'  { 'show bgp summary' }
        'nxos'    { 'show bgp summary' }
        'junos'   { 'show bgp summary' }
        'mikrotik'{ '/routing bgp peer print detail' }
        'linksys' { 'vtysh -c "show bgp summary" 2>/dev/null' }
        'tplink'  { 'vtysh -c "show bgp summary" 2>/dev/null' }
        'glinet'  { 'vtysh -c "show bgp summary" 2>/dev/null' }
        default   { $null }
    }
    if ($bgpCmd) {
        $bgpOut = Invoke-RouterCommand $bgpCmd
        if ($bgpOut -and $bgpOut -match '(?i)(neighbor|peer|AS)') {
            $bgpPeers = @($bgpOut -split "`n" | Where-Object { $_ -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' } |
                ForEach-Object { ($_ -split '\s+')[0] } | Sort-Object -Unique)
            if ($bgpPeers.Count -gt 0) {
                $bgpSample = ($bgpPeers | Select-Object -First 10) -join ', '
                Add-Finding 'MEDIUM' 'Covert Channels' "BGP Peers Enumerated ($($bgpPeers.Count) neighbor(s))" `
                    "BGP neighbors: $bgpSample. Adversaries with router access can inject BGP routes, modify communities, or establish unauthorized peering sessions to redirect traffic flows for interception or denial of service." `
                    @('T1557','T0869') $bgpOut
                foreach ($bp in $bgpPeers) { Add-IOC 'IP' $bp "BGP peer  -  verify against AS topology" }
            }
        }
    }

    # DNS server configuration  -  flag non-RFC1918 resolvers
    $dnsCmd = switch ($detectedPlatform) {
        'ios-xe'  { 'show running-config | include ip name-server' }
        'nxos'    { 'show running-config | include ip name-server' }
        'junos'   { 'show configuration system name-server' }
        'fortios' { 'show system dns' }
        'panos'   { 'show config running | match dns' }
        'mikrotik'{ '/ip dns print' }
        'linksys' { 'cat /tmp/resolv.conf.auto 2>/dev/null; cat /etc/resolv.conf' }
        'tplink'  { 'cat /tmp/resolv.conf.auto 2>/dev/null; cat /etc/resolv.conf' }
        'glinet'  { 'cat /tmp/resolv.conf.auto 2>/dev/null; cat /etc/resolv.conf; uci show glconfig.dns 2>/dev/null' }
        default   { $null }
    }
    if ($dnsCmd) {
        $dnsOut = Invoke-RouterCommand $dnsCmd
        if ($dnsOut) {
            $dnsServers = @($dnsOut -split "`n" | ForEach-Object {
                if ($_ -match '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') { $Matches[1] }
            } | Sort-Object -Unique)
            foreach ($ds in $dnsServers) {
                if ($ds -notmatch '^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|8\.8\.8\.|8\.8\.4\.|1\.1\.1\.|1\.0\.0\.)') {
                    Add-Finding 'HIGH' 'Covert Channels' "Unexpected DNS Resolver: $ds" `
                        "DNS server $ds is configured on the device and does not match expected corporate resolver or common public DNS ranges. Attacker-controlled DNS resolvers can redirect domain lookups for credential phishing, C2 communication, or data exfiltration via DNS tunneling." `
                        @('T1071.004','T1048') $ds
                    Add-IOC 'IP' $ds "Suspicious DNS resolver on router"
                }
            }
        }
    }

    # NTP servers  -  unexpected NTP = possible C2 timing channel
    $ntpCmd = switch ($detectedPlatform) {
        'ios-xe'  { 'show ntp status' }
        'nxos'    { 'show ntp peer-status' }
        'junos'   { 'show ntp associations' }
        'fortios' { 'show system ntp' }
        'mikrotik'{ '/system ntp client print; /system ntp server print' }
        'linksys' { 'uci show system | grep -i ntp' }
        'tplink'  { 'uci show system | grep -i ntp' }
        'glinet'  { 'uci show system | grep -i ntp' }
        default   { $null }
    }
    if ($ntpCmd) {
        $ntpOut = Invoke-RouterCommand $ntpCmd
        if ($ntpOut) {
            $ntpServers = @($ntpOut -split "`n" | ForEach-Object {
                if ($_ -match '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') { $Matches[1] }
            } | Sort-Object -Unique | Where-Object { $_ -notmatch '^(127\.|0\.)' })
            if ($ntpServers.Count -gt 0) {
                $deviceProfile['NTP Servers'] = $ntpServers -join ', '
            }
        }
    }

    # ICMP redirects check
    if ($detectedPlatform -in @('ios-xe','nxos')) {
        $icmpRedirect = Invoke-RouterCommand 'show running-config | include ip redirects'
        if ($icmpRedirect -and $icmpRedirect -notmatch '(?i)no\s+ip\s+redirects') {
            Add-Finding 'MEDIUM' 'Covert Channels' 'ICMP Redirects Not Explicitly Disabled' `
                "ICMP redirect messages may be enabled. While not directly an attacker technique, adversaries use ICMP redirect messages to silently reroute specific host traffic flows through an attacker-controlled next-hop for interception." `
                @('T1557') $icmpRedirect
        }
    }

    # ==========================================================================
    # MODULE 06  -  PERSISTENCE MECHANISMS
    # ==========================================================================
    Write-Host "[LP-RTR] Module 06: Persistence mechanisms..." -ForegroundColor DarkCyan

    if ($detectedPlatform -eq 'ios-xe') {
        # EEM applets
        $eemOut = Invoke-RouterCommand 'show event manager policy registered'
        if ($eemOut -and $eemOut -match '(?i)(applet|policy|registered)') {
            $eemEntries = @($eemOut -split "`n" | Where-Object { $_ -match '(?i)(applet|policy)' })
            if ($eemEntries.Count -gt 0) {
                Add-Finding 'HIGH' 'Persistence' "EEM (Embedded Event Manager) Applet(s) Registered ($($eemEntries.Count))" `
                    "EEM applets are registered on the device: $($eemEntries | Select-Object -First 5 | ForEach-Object { $_.Trim() }). EEM applets execute arbitrary IOS commands or Tcl/Python scripts triggered by system events. Adversaries use EEM for persistent post-exploitation automation (credential capture, re-backdooring after patch, exfil triggers)." `
                    @('T1546','T1053') $eemOut
                Add-IOC 'Event' 'EEM applet registered' 'Router persistence mechanism'
                Add-Timeline $collectionTime 'HIGH' "EEM applet(s) registered on device" $Target
            }
        }

        # TCL scripts
        $tclOut = Invoke-RouterCommand 'show tcl scripts'
        if ($tclOut -and $tclOut -match '(?i)(\.tcl|tclsh|script)') {
            Add-Finding 'HIGH' 'Persistence' 'TCL Script(s) Registered on Device' `
                "TCL scripts detected: $($tclOut -split "`n" | Where-Object { $_ -match '\S' } | Select-Object -First 5 | ForEach-Object { $_.Trim() }). TCL scripts on IOS-XE can be used for persistent backdoors, credential harvesting, or automated exfiltration. Verify each script against known-good baseline." `
                @('T1546','T1059.006') $tclOut
            Add-IOC 'Event' 'TCL scripts on IOS-XE device' 'Possible router persistence'
        }

        # Kron/scheduled jobs
        $kronOut = Invoke-RouterCommand 'show kron schedule'
        if ($kronOut -and $kronOut -match '(?i)(kron|schedule|job)') {
            Add-Finding 'HIGH' 'Persistence' 'Kron Scheduled Job(s) Configured' `
                "Kron policy/schedule entries: $($kronOut -split "`n" | Where-Object { $_ -match '\S' } | Select-Object -First 5 | ForEach-Object { $_.Trim() }). Kron is IOS's cron equivalent. Adversaries schedule recurring commands for periodic persistence actions (re-enable backdoor users, re-apply PBR, exfil config data)." `
                @('T1053') $kronOut
        }

        # Boot system statements  -  unexpected image
        $bootCmd = Invoke-RouterCommand 'show running-config | include boot system'
        if ($bootCmd -and $bootCmd -match '\S') {
            $unexpectedBoot = @($bootCmd -split "`n" | Where-Object {
                $_ -match '(?i)boot\s+system' -and $_ -notmatch '(?i)(flash:|bootflash:|tftp:.*\.bin)' -and $_ -match '\S'
            })
            if ($unexpectedBoot.Count -gt 0) {
                Add-Finding 'CRITICAL' 'Persistence' 'Unexpected Boot System Statement  -  Possible Malicious Image' `
                    "Boot system entries pointing to non-standard locations: $($unexpectedBoot -join ' | '). Adversaries modify boot system statements to load modified firmware images containing backdoors that survive reboots (SYNful Knock variant)." `
                    @('T1542','T1601.001') $bootCmd
                Add-Timeline $collectionTime 'CRITICAL' "Unexpected 'boot system' statement detected" $Target
            }
        }

        # HTTP/HTTPS server  -  CVE-2023-20198 webshell check
        $httpCmd = Invoke-RouterCommand 'show running-config | include ip http'
        if ($httpCmd -and $httpCmd -match '(?i)ip\s+http\s+server') {
            Add-Finding 'HIGH' 'Persistence' 'IOS-XE HTTP Server Enabled (CVE-2023-20198 Risk)' `
                "The IOS-XE HTTP server is enabled. CVE-2023-20198 (CVSS 10.0) allows unauthenticated remote code execution via the web UI, leading to privilege-15 account creation and subsequent implant deployment. Verify the webshell indicator path /webui/logoutconfirm.html?logon_hash=1." `
                @('T1190','T1505.003') $httpCmd

            # Check for CVE-2023-20198 webshell implant indicator
            $webshellCheck = Invoke-RouterCommand 'show running-config | include logoutconfirm'
            if ($webshellCheck -and $webshellCheck -match '(?i)(logoutconfirm|logon_hash)') {
                Add-Finding 'CRITICAL' 'Persistence' 'CVE-2023-20198 WebShell Implant Indicator Detected' `
                    "Indicator of CVE-2023-20198 (IOS-XE Web UI RCE) webshell found. The path /webui/logoutconfirm.html?logon_hash=1 is a known implant persistence artifact. This CVE has been actively exploited by threat actors to install privilege-15 backdoor accounts and HTTP-based implants." `
                    @('T1190','T1505.003','T1546') $webshellCheck
                Add-IOC 'URL' '/webui/logoutconfirm.html?logon_hash=1' 'CVE-2023-20198 IOS-XE webshell indicator'
                Add-Timeline $collectionTime 'CRITICAL' 'CVE-2023-20198 webshell implant indicator found' $Target
                Write-Host "         [CRITICAL] CVE-2023-20198 webshell indicator detected!" -ForegroundColor Red
            }
        }
    }

    # NX-OS: Scheduler jobs
    if ($detectedPlatform -eq 'nxos') {
        $nxScheduler = Invoke-RouterCommand 'show scheduler job'
        if ($nxScheduler -and $nxScheduler -match '(?i)(job|command|schedule)') {
            Add-Finding 'HIGH' 'Persistence' 'NX-OS Scheduler Job(s) Configured' `
                "Scheduler jobs: $($nxScheduler -split "`n" | Where-Object { $_ -match '\S' } | Select-Object -First 5 | ForEach-Object { $_.Trim() }). Verify all scheduled jobs against change management records." `
                @('T1053') $nxScheduler
        }
    }

    # JunOS: Cron and event-options
    if ($detectedPlatform -eq 'junos') {
        $junCron      = Invoke-RouterCommand 'show system cron'
        $junEventOpts = Invoke-RouterCommand 'show configuration event-options'
        if ($junEventOpts -and $junEventOpts -match '(?i)(policy|event|generate-event|execute)') {
            Add-Finding 'HIGH' 'Persistence' 'JunOS Event-Options Policy Configured' `
                "JunOS event-options policies can execute scripts upon system events, providing adversary persistence. Review: $($junEventOpts -split "`n" | Where-Object { $_ -match '\S' } | Select-Object -First 5 | ForEach-Object { $_.Trim() })" `
                @('T1546') $junEventOpts
        }
    }

    # FortiOS: Automation triggers
    if ($detectedPlatform -eq 'fortios') {
        $fortiTrigger = Invoke-RouterCommand 'show system automation-trigger'
        $fortiAction  = Invoke-RouterCommand 'show system automation-action'
        if ($fortiTrigger -and $fortiTrigger -match '(?i)(trigger|action|script)') {
            Add-Finding 'HIGH' 'Persistence' 'FortiOS Automation Trigger Configured' `
                "FortiOS automation triggers/actions allow persistent script execution. Review: $($fortiTrigger -split "`n" | Where-Object { $_ -match '\S' } | Select-Object -First 5 | ForEach-Object { $_.Trim() })" `
                @('T1546') $fortiTrigger
        }
    }

    # PAN-OS: Job queue
    if ($detectedPlatform -eq 'panos') {
        $panJobs = Invoke-RouterCommand 'show jobs all'
        if ($panJobs -and $panJobs -match '(?i)(install|upgrade|push|commit)') {
            $deviceProfile['PAN-OS Job History'] = ($panJobs -split "`n" | Select-Object -First 5 | ForEach-Object { $_.Trim() }) -join ' | '
        }
    }

    # MikroTik: Scheduler, Scripts, Netwatch (persistence)
    if ($detectedPlatform -eq 'mikrotik') {
        $mtScheduler = Invoke-RouterCommand '/system scheduler print detail'
        $mtScripts   = Invoke-RouterCommand '/system script print detail'
        $mtNetwatch  = Invoke-RouterCommand '/tool netwatch print detail'

        if ($mtScheduler -and $mtScheduler -match '(?i)(name=|on-event=)') {
            $schedEntries = @($mtScheduler -split "`r?`n" | Where-Object { $_ -match '(?i)(name=|on-event=)' })
            Add-Finding 'HIGH' 'Persistence' "MikroTik Scheduler Entry(s) Configured ($($schedEntries.Count))" `
                "RouterOS scheduler jobs detected: $($schedEntries | Select-Object -First 5 | ForEach-Object { $_.Trim() }). Scheduler entries execute scripts at intervals and are a primary MikroTik persistence mechanism (VPNFilter, Meris, Chimay-Red all used it). Verify every entry against change-control." `
                @('T1053','T1546') $mtScheduler
            Add-IOC 'Event' 'MikroTik scheduler job(s) present' 'RouterOS persistence vector'
        }
        if ($mtScripts -and $mtScripts -match '(?i)source=') {
            $suspScripts = @($mtScripts -split "`r?`n" | Where-Object {
                $_ -match '(?i)(fetch|tool fetch|download|wget|curl|resolve|dns|system shell|:execute|/file|/user add)'
            })
            if ($suspScripts.Count -gt 0) {
                Add-Finding 'HIGH' 'Persistence' "MikroTik Script(s) with Suspicious Actions ($($suspScripts.Count))" `
                    "Scripts contain suspicious actions (fetch/download/user-add/:execute): $($suspScripts | Select-Object -First 3 | ForEach-Object { $_.Trim() }). Attackers use RouterOS scripts for user creation, payload download, and credential harvesting." `
                    @('T1059','T1546') $mtScripts
            }
        }
        if ($mtNetwatch -and $mtNetwatch -match '(?i)(up-script|down-script)') {
            Add-Finding 'HIGH' 'Persistence' 'MikroTik Netwatch Hook Script(s) Configured' `
                "Netwatch entries with up-script or down-script defined. Netwatch hooks trigger arbitrary scripts when a monitored host changes state, giving adversaries a reactive execution primitive. Evidence: $($mtNetwatch -split "`n" | Where-Object { $_ -match '(?i)(script)' } | Select-Object -First 3)" `
                @('T1546') $mtNetwatch
        }
    }

    # Linksys / TP-Link (OpenWrt/Linux): cron, init.d, hotplug, rc.local
    if ($detectedPlatform -in @('linksys','tplink','glinet')) {
        $owCron = Invoke-RouterCommand 'cat /etc/crontabs/root 2>/dev/null; crontab -l 2>/dev/null'
        if ($owCron -and $owCron -match '\S' -and $owCron -notmatch '(?i)^#') {
            $suspCronLines = @($owCron -split "`n" | Where-Object {
                $_ -match '\S' -and $_ -notmatch '^#' -and
                $_ -match '(?i)(wget|curl|nc\s|/tmp/|bash|python|perl|base64|\.sh\b)'
            })
            if ($suspCronLines.Count -gt 0) {
                Add-Finding 'CRITICAL' 'Persistence' "Suspicious Cron Job(s) on Router ($($suspCronLines.Count))" `
                    "Cron jobs reference network download tools or /tmp execution: $($suspCronLines | Select-Object -First 3 | ForEach-Object { $_.Trim() }). This pattern is common to Mirai/Gafgyt/VPNFilter staging on consumer routers." `
                    @('T1053.003','T1546') $owCron
                Add-Timeline $collectionTime 'CRITICAL' 'Suspicious router cron entries detected' $Target
            } else {
                Add-Finding 'INFO' 'Persistence' 'Router Cron Table Reviewed' `
                    "Cron table retrieved and reviewed. No obviously suspicious commands present." `
                    @() $owCron
            }
        }

        $owInitD = Invoke-RouterCommand 'ls -la /etc/init.d 2>/dev/null'
        if ($owInitD) {
            $suspInit = @($owInitD -split "`n" | Where-Object {
                $_ -match '(?i)(miner|mirai|gafgyt|tsunami|botnet|kaiten|perl\s)' -or
                ($_ -match '\s\d{4}-' -and $_ -match '(?i)(\.tmp|\.bak)')
            })
            if ($suspInit.Count -gt 0) {
                Add-Finding 'HIGH' 'Persistence' "Suspicious /etc/init.d Entries ($($suspInit.Count))" `
                    "Unexpected init scripts in /etc/init.d: $($suspInit | Select-Object -First 3 | ForEach-Object { $_.Trim() }). Malicious init scripts survive reboot and are a standard OpenWrt persistence vector." `
                    @('T1543','T1037') $owInitD
            }
        }

        $owHotplug = Invoke-RouterCommand 'ls -la /etc/hotplug.d 2>/dev/null; find /etc/hotplug.d -type f 2>/dev/null'
        if ($owHotplug -and $owHotplug -match '(?i)\.sh') {
            $deviceProfile['hotplug.d Scripts'] = "$(@($owHotplug -split "`n" | Where-Object { $_ -match '(?i)\.sh' }).Count) scripts in /etc/hotplug.d"
        }

        # UCI system startup
        $owUci = Invoke-RouterCommand 'uci show system 2>/dev/null'
        if ($owUci -and $owUci -match '(?i)(script|exec|startup)') {
            $deviceProfile['UCI System'] = ($owUci -split "`n" | Select-Object -First 5 | ForEach-Object { $_.Trim() }) -join ' | '
        }
    }

    # GL.iNet-specific: glversion, glconfig, gl-cloud, gl-init scripts
    if ($detectedPlatform -eq 'glinet') {
        $glVer = Invoke-RouterCommand 'cat /etc/glversion 2>/dev/null'
        if ($glVer) { $deviceProfile['GL.iNet Version'] = $glVer.Trim() }

        $glModel = Invoke-RouterCommand 'cat /tmp/sysinfo/model 2>/dev/null; cat /proc/device-tree/model 2>/dev/null'
        if ($glModel) { $deviceProfile['GL.iNet Model'] = ($glModel -split "`n" | Where-Object { $_ -match '\S' } | Select-Object -First 1).Trim() }

        # GL.iNet cloud service: gl-cloud / goodcloud.xyz - legitimate vendor cloud but
        # worth flagging so the operator knows the device is phoning home.
        $glCloud = Invoke-RouterCommand 'uci show glconfig.cloud 2>/dev/null; ps w 2>/dev/null | grep -i "gl-cloud\|gl_cloud\|mqtt"'
        if ($glCloud -and $glCloud -match '(?i)(enable.*1|gl-cloud|gl_cloud|mqtt)' -and $glCloud -notmatch '(?i)enable.*0') {
            Add-Finding 'MEDIUM' 'Device Integrity' 'GL.iNet Cloud Service (goodcloud) Enabled' `
                "GL.iNet's cloud management service (gl-cloud / goodcloud.xyz, MQTT-based) appears enabled. This is legitimate vendor functionality but provides out-of-band remote management that bypasses local ACLs. On a forensic-sensitive deployment, confirm the account bound to the device and disable if not operationally required." `
                @('T1133','T1071.001') $glCloud
            Add-IOC 'Event' 'GL.iNet goodcloud MQTT client active' 'Vendor cloud management phone-home'
        }

        # GL.iNet-specific init scripts (gl_* naming convention)
        $glInit = Invoke-RouterCommand 'ls /etc/init.d 2>/dev/null | grep -i ^gl'
        if ($glInit) {
            $deviceProfile['GL Init Scripts'] = (@($glInit -split "`s+" | Where-Object { $_ -match '\S' }) -join ', ')
        }

        # GL.iNet plugin/package directory - adversaries may drop persistence here
        $glPlugins = Invoke-RouterCommand 'ls -la /usr/lib/lua/luci/controller/admin/ 2>/dev/null; ls -la /www/cgi-bin/ 2>/dev/null'
        if ($glPlugins) {
            $suspGlPlugins = @($glPlugins -split "`n" | Where-Object {
                $_ -match '(?i)\.(sh|py|pl)$' -or
                $_ -match '(?i)(backdoor|shell|cmd|rev|implant)'
            })
            if ($suspGlPlugins.Count -gt 0) {
                Add-Finding 'HIGH' 'Device Integrity' "GL.iNet Suspicious Plugin / CGI Script(s) ($($suspGlPlugins.Count))" `
                    "Unexpected executables in GL.iNet LuCI controller or /www/cgi-bin: $($suspGlPlugins | Select-Object -First 3 | ForEach-Object { $_.Trim() }). CGI-accessible scripts in /www/cgi-bin become remote command execution primitives if exposed on the WAN side." `
                    @('T1505.003','T1546') $glPlugins
            }
        }

        # WireGuard / OpenVPN client config (travel routers heavily use these)
        $glVpn = Invoke-RouterCommand 'uci show wireguard 2>/dev/null; uci show openvpn 2>/dev/null; ls /etc/openvpn 2>/dev/null'
        if ($glVpn -and $glVpn -match '(?i)(endpoint|remote|public_key|server)') {
            $vpnEndpoints = @($glVpn -split "`n" | ForEach-Object {
                if ($_ -match "(?i)(?:endpoint|remote)=?'?([\w\.\-:]+)") { $Matches[1] }
            } | Where-Object { $_ } | Sort-Object -Unique)
            if ($vpnEndpoints.Count -gt 0) {
                Add-Finding 'MEDIUM' 'Covert Channels' "GL.iNet VPN Client Endpoint(s) Configured ($($vpnEndpoints.Count))" `
                    "WireGuard/OpenVPN client endpoints: $($vpnEndpoints -join ', '). GL.iNet travel routers route all client traffic through these tunnels by default. Verify every endpoint against the expected provider  -  a rogue endpoint becomes a full-tunnel man-in-the-middle." `
                    @('T1572','T1048') $glVpn
                foreach ($ep in $vpnEndpoints) {
                    Add-IOC 'Endpoint' $ep 'GL.iNet VPN client endpoint  -  verify against provider'
                }
            }
        }

        # AdGuard Home / DNS-over-TLS (commonly enabled on newer GL.iNet firmware)
        $glAdg = Invoke-RouterCommand 'uci show adguardhome 2>/dev/null; ps w 2>/dev/null | grep -i adguard'
        if ($glAdg -and $glAdg -match '(?i)(enable.*1|adguardhome)') {
            $deviceProfile['AdGuard Home'] = 'Enabled'
        }

        # Tor service (some GL.iNet builds include Tor)
        $glTor = Invoke-RouterCommand 'ps w 2>/dev/null | grep -i "[t]or\b"; uci show tor 2>/dev/null'
        if ($glTor -and $glTor -match '(?i)\btor\b') {
            Add-Finding 'MEDIUM' 'Covert Channels' 'Tor Service Running on GL.iNet Device' `
                "A Tor process/service appears active. Legitimate on travel routers used for anonymization, but Tor on a compromised router provides adversaries with a pre-built anonymizing exit path. Confirm the operator enabled this intentionally." `
                @('T1090.003','T1572') $glTor
            Add-IOC 'Event' 'Tor service active on router' 'Anonymizing proxy infrastructure'
        }
    }

    # ==========================================================================
    # MODULE 07  -  ACL & FIREWALL RULE ANALYSIS
    # ==========================================================================
    Write-Host "[LP-RTR] Module 07: ACL and firewall rule analysis..." -ForegroundColor DarkCyan

    $aclCmd = switch ($detectedPlatform) {
        'ios-xe'  { 'show ip access-lists' }
        'nxos'    { 'show ip access-lists' }
        'junos'   { 'show configuration firewall' }
        'fortios' { 'show firewall policy' }
        'panos'   { 'show running security-policy' }
        'mikrotik'{ '/ip firewall filter print detail' }
        'linksys' { 'iptables -L -n -v; uci show firewall' }
        'tplink'  { 'iptables -L -n -v; uci show firewall' }
        'glinet'  { 'iptables -L -n -v; uci show firewall' }
        default   { $null }
    }

    if ($aclCmd) {
        $aclOut = Invoke-RouterCommand $aclCmd
        if ($aclOut) {
            # Flag permit any any
            $permAny = @($aclOut -split "`n" | Where-Object {
                $_ -match '(?i)(permit\s+any\s+any|permit\s+ip\s+any\s+any|allow\s+all|accept\s+all)' -and
                $_ -notmatch '(?i)deny'
            })
            foreach ($pa in $permAny) {
                Add-Finding 'HIGH' 'ACL Analysis' "Overly Broad ACL Rule: $($pa.Trim())" `
                    "Access list contains 'permit any any' or equivalent. This negates the security benefit of having access lists. Any source can reach any destination through this device. Review and restrict to minimum necessary flows." `
                    @('T1562.001') $pa
            }

            # Check for suspicious permit rules from external prefixes on management ACLs
            $mgmtPermit = @($aclOut -split "`n" | Where-Object {
                $_ -match '(?i)(permit|allow)' -and
                $_ -match '(?i)(22|23|80|443|8080|8443|telnet|ssh|http|https|management|access)' -and
                $_ -notmatch '(?i)(10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.|192\.168\.)'
            })
            if ($mgmtPermit.Count -gt 0) {
                Add-Finding 'HIGH' 'ACL Analysis' "ACL Permits Management Traffic from Non-RFC1918 Sources ($($mgmtPermit.Count) rule(s))" `
                    "Access list entries permit management protocols (SSH/Telnet/HTTP) from public sources: $($mgmtPermit | Select-Object -First 3 | ForEach-Object { $_.Trim() }). Management interfaces should only accept connections from documented management networks." `
                    @('T1078','T0886') ($mgmtPermit -join "`n")
            }
        }
    }

    # NAT rules  -  flag unexpected static NAT (port-forward backdoor)
    $natCmd = switch ($detectedPlatform) {
        'ios-xe'  { 'show ip nat translations' }
        'nxos'    { 'show ip nat translations' }
        'fortios' { 'show firewall vip' }
        'panos'   { 'show running nat-policy' }
        'mikrotik'{ '/ip firewall nat print detail' }
        'linksys' { 'iptables -t nat -L -n -v' }
        'tplink'  { 'iptables -t nat -L -n -v' }
        'glinet'  { 'iptables -t nat -L -n -v' }
        default   { $null }
    }
    if ($natCmd) {
        $natOut = Invoke-RouterCommand $natCmd
        if ($natOut -and $natOut -match '(?i)(static|vip|\-\->)') {
            $staticNatLines = @($natOut -split "`n" | Where-Object { $_ -match '(?i)(static|vip)' -and $_ -match '\S' })
            if ($staticNatLines.Count -gt 0) {
                Add-Finding 'MEDIUM' 'ACL Analysis' "Static NAT Translation(s) Present ($($staticNatLines.Count) entry/entries)" `
                    "Static NAT entries: $($staticNatLines | Select-Object -First 5 | ForEach-Object { $_.Trim() }). Adversaries add static NAT / port-forward entries to expose internal services or create persistent remote access paths bypassing perimeter controls." `
                    @('T1133','T1090') $natOut
            }
        }
    }

    # ==========================================================================
    # MODULE 08  -  ROUTING TABLE ANOMALIES
    # ==========================================================================
    Write-Host "[LP-RTR] Module 08: Routing table anomaly analysis..." -ForegroundColor DarkCyan

    # Full routing table already captured as $ipRouteOut above
    if ($ipRouteOut) {
        # Default route changes
        $defRoutes = @($ipRouteOut -split "`n" | Where-Object { $_ -match '^[S\*].*0\.0\.0\.0' -or $_ -match '(?i)default' })
        if ($defRoutes.Count -gt 1) {
            Add-Finding 'HIGH' 'Routing Anomaly' "Multiple Default Routes Detected ($($defRoutes.Count))" `
                "Multiple default routes may indicate floating static or policy-based routing manipulation: $($defRoutes | Select-Object -First 5 | ForEach-Object { $_.Trim() }). Verify against authorised routing design." `
                @('T1557','T0869') $ipRouteOut
        }

        # Static routes added unexpectedly
        $staticRoutes = @($ipRouteOut -split "`n" | Where-Object { $_ -match '^\s*S\s' -and $_ -notmatch '0\.0\.0\.0' })
        if ($staticRoutes.Count -gt 0) {
            Add-Finding 'MEDIUM' 'Routing Anomaly' "Static Routes Present ($($staticRoutes.Count))  -  Verify Against Change Management" `
                "Static routes: $($staticRoutes | Select-Object -First 8 | ForEach-Object { $_.Trim() }). Unauthorized static routes can redirect traffic flows or create attacker-accessible network paths." `
                @('T1557') ($staticRoutes -join "`n")
        }
    }

    # JunOS routing
    if ($detectedPlatform -eq 'junos') {
        $junRoute = Invoke-RouterCommand 'show route'
        if ($junRoute -and $junRoute -match '(?i)(static|direct)') {
            $junStaticRoutes = @($junRoute -split "`n" | Where-Object { $_ -match '(?i)static' })
            if ($junStaticRoutes.Count -gt 0) {
                Add-Finding 'MEDIUM' 'Routing Anomaly' "JunOS Static Routes ($($junStaticRoutes.Count))  -  Verify Against Design" `
                    "Static routes: $($junStaticRoutes | Select-Object -First 5 | ForEach-Object { $_.Trim() })" `
                    @('T1557') ($junStaticRoutes -join "`n")
            }
        }
    }

    # ==========================================================================
    # MODULE 09  -  LOGGING & ANTI-FORENSICS
    # ==========================================================================
    Write-Host "[LP-RTR] Module 09: Logging and anti-forensics analysis..." -ForegroundColor DarkCyan

    # Syslog destinations
    $syslogCmd = switch ($detectedPlatform) {
        'ios-xe'  { 'show running-config | include logging host' }
        'nxos'    { 'show running-config | include logging server' }
        'junos'   { 'show configuration system syslog' }
        'fortios' { 'show log syslogd setting' }
        'panos'   { 'show config running | match syslog' }
        'mikrotik'{ '/system logging action print detail' }
        'linksys' { 'uci show system | grep -iE "log_ip|log_port|log_proto|log_remote"' }
        'tplink'  { 'uci show system | grep -iE "log_ip|log_port|log_proto|log_remote"' }
        'glinet'  { 'uci show system | grep -iE "log_ip|log_port|log_proto|log_remote"' }
        default   { $null }
    }
    if ($syslogCmd) {
        $syslogOut = Invoke-RouterCommand $syslogCmd
        if ($syslogOut) {
            $syslogServers = @($syslogOut -split "`n" | ForEach-Object {
                if ($_ -match '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') { $Matches[1] }
            } | Sort-Object -Unique)
            foreach ($ss in $syslogServers) {
                Add-IOC 'IP' $ss "Configured syslog destination"
                if ($ss -notmatch '^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)') {
                    Add-Finding 'HIGH' 'Logging' "Syslog Destination at Non-RFC1918 IP: $ss" `
                        "Syslog is configured to send to $ss (public IP). Adversaries redirect syslog to attacker-controlled servers to receive device log data (credentials, session info) or to delete it from the legitimate SIEM." `
                        @('T1070','T1020') $ss
                    Add-IOC 'IP' $ss "Suspicious syslog destination (public IP)"
                    Add-Timeline $collectionTime 'HIGH' "Syslog to public IP $ss" $Target
                }
            }
            if ($syslogServers.Count -eq 0) {
                Add-Finding 'HIGH' 'Logging' 'No Syslog Destination Configured' `
                    "No remote syslog server is configured. Without remote syslog, an attacker can clear local logs ('clear logging') and leave no forensic trail. External log aggregation is a fundamental security control for network devices." `
                    @('T1070.002')
            }
        }
    }

    # AAA accounting  -  disabled is CRITICAL
    if ($detectedPlatform -in @('ios-xe','nxos')) {
        $aaaAcct = Invoke-RouterCommand 'show running-config | include aaa accounting'
        if (-not $aaaAcct -or $aaaAcct -notmatch '(?i)aaa\s+accounting') {
            Add-Finding 'CRITICAL' 'Logging' 'AAA Accounting Not Configured  -  Command Audit Trail Missing' `
                "No AAA accounting configuration found. Without command accounting, there is no audit trail of which administrator executed which commands. This is a significant anti-forensics gap  -  an attacker can modify the device configuration with no permanent record." `
                @('T1070','T1562.001')
            Add-Timeline $collectionTime 'CRITICAL' 'AAA accounting disabled  -  no command audit trail' $Target
        } else {
            Add-Finding 'INFO' 'Logging' 'AAA Accounting Configured' `
                "AAA command accounting is enabled: $($aaaAcct -split "`n" | Select-Object -First 3 | ForEach-Object { $_.Trim() })" `
                @() $aaaAcct
        }
    }

    # 'no service timestamps'  -  log manipulation indicator
    if ($detectedPlatform -in @('ios-xe','nxos')) {
        $tsCmd = Invoke-RouterCommand 'show running-config | include service timestamps'
        if ($tsCmd -and $tsCmd -match '(?i)no\s+service\s+timestamps') {
            Add-Finding 'HIGH' 'Logging' "Timestamps Disabled on Log/Debug Messages  -  Anti-Forensics Indicator" `
                "'no service timestamps' disables timestamps on syslog and debug messages. Without timestamps, it is impossible to correlate log entries to a timeline, severely hampering forensic reconstruction. This setting is rarely used in legitimate configurations." `
                @('T1070') $tsCmd
        }
    }

    # Local log buffer
    $logCmd = switch ($detectedPlatform) {
        'ios-xe'  { 'show logging' }
        'nxos'    { 'show logging' }
        'junos'   { 'show log messages | last 100' }
        'fortios' { 'show log memory filter' }
        'mikrotik'{ '/log print' }
        'linksys' { 'logread | tail -200' }
        'tplink'  { 'logread | tail -200' }
        'glinet'  { 'logread | tail -200' }
        default   { $null }
    }
    if ($logCmd) {
        $logOut = Invoke-RouterCommand $logCmd
        if ($logOut) {
            # Check for log clear indicator
            if ($logOut -match '(?i)(log\s+cleared|buffer\s+was\s+cleared|cleared\s+by)') {
                $clearLine = ($logOut | Select-String -Pattern '(?i)(cleared)' | Select-Object -First 1).Line
                Add-Finding 'HIGH' 'Logging' "Log Buffer Cleared  -  Anti-Forensics Event Detected" `
                    "The logging buffer shows evidence of having been cleared: $clearLine. Log clearing is a common anti-forensics technique to remove evidence of unauthorized access or configuration changes." `
                    @('T1070.002') $logOut
                Add-Timeline $collectionTime 'HIGH' "Log buffer cleared  -  anti-forensics event" $Target
            }

            # Check for timestamp gaps (missing minutes in sequence)
            $logTimes = @($logOut -split "`n" | ForEach-Object {
                if ($_ -match '(\w{3}\s+\d+\s+\d+:\d+:\d+)') { $Matches[1] }
            })
            if ($logTimes.Count -gt 3) {
                Add-Finding 'INFO' 'Logging' "Log Buffer Sampled ($($logTimes.Count) timestamped entries)" `
                    "Earliest log entry: $($logTimes | Select-Object -First 1). Latest: $($logTimes | Select-Object -Last 1). Review for unexpected timestamp gaps indicating log wipinge." `
                    @() ($logTimes -join ', ')
            }
        }
    }

    # Config archive
    if ($detectedPlatform -eq 'ios-xe') {
        $archiveLog = Invoke-RouterCommand 'show archive log config all'
        if ($archiveLog -and $archiveLog -match '\d+:\d+') {
            $archCount = @($archiveLog -split "`n" | Where-Object { $_ -match '\d+:\d+:\d+' }).Count
            Add-Finding 'INFO' 'Logging' "Config Archive: $archCount Timestamped Entries Found" `
                "Config archive log entries present. Review for gaps or unexpected changes." `
                @() $archiveLog
        }
    }

    # ==========================================================================
    # MODULE 10  -  PROCESS & MEMORY ANOMALIES (IOS-XE)
    # ==========================================================================
    Write-Host "[LP-RTR] Module 10: Process and memory analysis..." -ForegroundColor DarkCyan

    if ($detectedPlatform -eq 'ios-xe') {
        # CPU
        $cpuOut = Invoke-RouterCommand 'show processes cpu sorted'
        if ($cpuOut) {
            $highCpuProcs = @($cpuOut -split "`n" | Where-Object {
                $_ -match '^\s*\d+\s+\d+' -and $_ -match '\d{2,3}%'
            } | Select-Object -First 10)
            # Look for unexpected processes
            $knownProcPattern = '(?i)(Scheduler|IPC|IP Background|Exec|Net Background|OSPF|BGP|Interface|Ctrl|Memory|Interrupt|IP Input|TCP Timer|SSH|CEF|SPA|EEM|IOSd|XE|PUNT|HEOS|BSTUN|CPUHOG|CMTS|FPD)'
            $unexpCpuProcs = @($highCpuProcs | Where-Object { $_ -notmatch $knownProcPattern -and $_ -match '\S' })
            if ($unexpCpuProcs.Count -gt 0) {
                Add-Finding 'HIGH' 'Process Analysis' "Unexpected High-CPU Process(es)  -  Possible Implant Activity ($($unexpCpuProcs.Count))" `
                    "Processes consuming significant CPU that do not match known IOS-XE process names: $($unexpCpuProcs | Select-Object -First 5 | ForEach-Object { $_.Trim() }). Unexpected processes may indicate injected code or implant components." `
                    @('T1014','T1601.001') $cpuOut
            } else {
                Add-Finding 'INFO' 'Process Analysis' 'CPU Process List Reviewed  -  No Obvious Anomalies' `
                    "Top CPU consumers appear to match expected IOS-XE processes." `
                    @() ($highCpuProcs -join "`n")
            }
        }

        # Memory
        $memOut = Invoke-RouterCommand 'show processes memory sorted'
        if ($memOut) {
            $knownMemPattern = '(?i)(Scheduler|IPC|IP|Interface|Exec|Memory|OSPF|BGP|CEF|XE|SSH|Ctrl|Timer|EEM|IOSd|PUNT|BSTUN|Interrupt)'
            $highMemLines = @($memOut -split "`n" | Where-Object {
                $_ -match '^\s*\d+\s+\d+' -and $_ -match '\S'
            } | Select-Object -First 20)
            $unexpMemProcs = @($highMemLines | Where-Object { $_ -notmatch $knownMemPattern -and $_ -match '\S' })
            if ($unexpMemProcs.Count -gt 0) {
                Add-Finding 'HIGH' 'Process Analysis' "Unexpected Memory-Consuming Process(es) ($($unexpMemProcs.Count))" `
                    "High-memory processes not matching known IOS-XE patterns: $($unexpMemProcs | Select-Object -First 5 | ForEach-Object { $_.Trim() })" `
                    @('T1014') $memOut
            }
        }

        # Guest Shell
        $guestShellOut = Invoke-RouterCommand 'show guestshell'
        if ($guestShellOut -and $guestShellOut -match '(?i)(enabled|running|activated)') {
            Add-Finding 'HIGH' 'Process Analysis' 'IOS-XE Guest Shell Enabled  -  Containerized Linux Environment Active' `
                "Guest Shell is enabled and active. Guest Shell provides a Linux container environment inside IOS-XE that can run Python scripts, arbitrary binaries, and persist across reboots. Adversaries leverage Guest Shell for durable implant hosting, credential access, and network pivoting from within the device itself." `
                @('T1059.006','T1546') $guestShellOut
            Add-IOC 'Event' 'IOS-XE GuestShell enabled' 'Containerized persistence vector'
            Add-Timeline $collectionTime 'HIGH' "IOS-XE Guest Shell is enabled" $Target
        }
    }

    # MikroTik: CPU load and connections
    if ($detectedPlatform -eq 'mikrotik') {
        $mtRes = Invoke-RouterCommand '/system resource print'
        if ($mtRes -and $mtRes -match '(?i)cpu-load[:\s]+(\d+)') {
            $cpuPct = [int]$Matches[1]
            if ($cpuPct -gt 70) {
                Add-Finding 'HIGH' 'Process Analysis' "MikroTik Sustained High CPU Load: $cpuPct%" `
                    "RouterOS reports CPU load at $cpuPct%. Sustained high CPU on MikroTik is associated with crypto-mining implants, botnet payloads (Meris), or packet-interception scripts running in the background." `
                    @('T1496','T1059') $mtRes
            }
        }
        $mtConn = Invoke-RouterCommand '/ip firewall connection print count-only'
        if ($mtConn) { $deviceProfile['MikroTik Connections'] = $mtConn.Trim() }
        $mtSocks = Invoke-RouterCommand '/ip socks print; /ip proxy print'
        if ($mtSocks -and $mtSocks -match '(?i)enabled[:\s=]+(?:yes|true)') {
            Add-Finding 'HIGH' 'Process Analysis' 'MikroTik SOCKS/HTTP Proxy Enabled' `
                "Built-in SOCKS or HTTP proxy is enabled on MikroTik. Attackers use this to relay traffic through the compromised router (Volt Typhoon-style proxy-chaining). Disable unless required." `
                @('T1090','T1090.003') $mtSocks
            Add-IOC 'Event' 'MikroTik SOCKS/proxy enabled' 'Router proxy-chain infrastructure'
        }
    }

    # Linksys / TP-Link: Process listing, listening sockets, suspicious binaries
    if ($detectedPlatform -in @('linksys','tplink','glinet')) {
        $owPs = Invoke-RouterCommand 'ps w 2>/dev/null; ps -ef 2>/dev/null'
        if ($owPs) {
            $suspProcs = @($owPs -split "`n" | Where-Object {
                $_ -match '(?i)(/tmp/|\./|busybox\s+(nc|telnetd|httpd)|perl\s+-e|python\s+-c|base64\s+-d)' -or
                $_ -match '(?i)(mirai|gafgyt|tsunami|kaiten|xmrig|cryptonight|minerd)'
            })
            if ($suspProcs.Count -gt 0) {
                Add-Finding 'CRITICAL' 'Process Analysis' "Suspicious Running Process(es) ($($suspProcs.Count))" `
                    "Running processes match IoT botnet / cryptominer / reverse-shell patterns: $($suspProcs | Select-Object -First 3 | ForEach-Object { $_.Trim() }). This is a high-confidence indicator of router compromise." `
                    @('T1059','T1496','T1036') $owPs
                Add-Timeline $collectionTime 'CRITICAL' 'Suspicious processes running on router' $Target
                foreach ($sp in $suspProcs) {
                    Add-IOC 'Process' ($sp.Trim()) 'Suspicious process on router'
                }
            }
        }
        $owNet = Invoke-RouterCommand 'netstat -tlnp 2>/dev/null; netstat -tln 2>/dev/null'
        if ($owNet) {
            $extListen = @($owNet -split "`n" | Where-Object {
                $_ -match '(?i)LISTEN' -and $_ -match '0\.0\.0\.0:(\d+)' -and
                $_ -notmatch '0\.0\.0\.0:(22|53|67|68|80|443|8080|8443)\s'
            })
            if ($extListen.Count -gt 0) {
                Add-Finding 'HIGH' 'Process Analysis' "Unexpected Listening Port(s) on Router ($($extListen.Count))" `
                    "Router is listening on non-standard ports: $($extListen | Select-Object -First 5 | ForEach-Object { $_.Trim() }). Unexpected listeners are potential implant callback or backdoor shell ports." `
                    @('T1205','T1571') $owNet
            }
        }
    }

    # ==========================================================================
    # MODULE 11  -  OT/SEL SPECIFIC CHECKS
    # ==========================================================================
    Write-Host "[LP-RTR] Module 11: OT/SEL specific checks..." -ForegroundColor DarkCyan

    if ($detectedPlatform -eq 'sel') {
        # SEL port configuration
        $selPorts = Invoke-RouterCommand 'show port'
        if ($selPorts) {
            # Look for unexpected mirror ports
            if ($selPorts -match '(?i)(mirror|span|monitor)') {
                Add-Finding 'CRITICAL' 'OT/SEL Integrity' 'SEL Switch Port Mirror/SPAN Configuration Detected' `
                    "SEL switch has mirror or SPAN port configured. Traffic mirroring on OT switches creates a passive capture point for all substation communications. In ICS/OT environments, this could expose GOOSE, Sampled Values, DNP3, Modbus, and IEC 61850 MMS traffic to an adversary-controlled collection point." `
                    @('T1040','T0869') $selPorts
                Add-IOC 'Event' 'SEL switch port mirror active' 'OT traffic interception'
                Add-Timeline $collectionTime 'CRITICAL' "SEL port mirror/SPAN detected  -  OT traffic interception risk" $Target
            }
        }

        # SELOGIC equations
        $selLogic = Invoke-RouterCommand 'show access-control'
        if (-not $selLogic) { $selLogic = Invoke-RouterCommand 'show acl' }
        if ($selLogic -and $selLogic -match '(?i)(SELOGIC|equation|logic)') {
            Add-Finding 'HIGH' 'OT/SEL Integrity' 'SELOGIC Control Equation Configuration Present  -  Verify Against Baseline' `
                "SELOGIC control equations detected. Any modification to SELOGIC equations in a substation environment can alter protection relay logic, potentially preventing tripping on fault conditions or causing spurious operations. Verify against approved relay settings baseline." `
                @('T0843','T0857') $selLogic
        }

        # Protocol exposure check
        $selService = Invoke-RouterCommand 'show services'
        if (-not $selService) { $selService = Invoke-RouterCommand 'show running-config' }
        if ($selService) {
            $itFacingOTProtos = @($selService -split "`n" | Where-Object {
                $_ -match '(?i)(GOOSE|Sampled.Value|MMS|DNP3|Modbus|IEC.61850)' -and
                $_ -match '(?i)(it-facing|external|uplink|upstream|wan|internet)'
            })
            if ($itFacingOTProtos.Count -gt 0) {
                Add-Finding 'CRITICAL' 'OT/SEL Integrity' 'OT Protocols Exposed on IT-Facing Interface' `
                    "OT protocols (GOOSE/SV/MMS/DNP3/Modbus) appear to be enabled on IT-facing or external interfaces: $($itFacingOTProtos -join ' | '). This violates IT/OT segmentation and exposes real-time protection relay communications to IT networks where adversaries operate." `
                    @('T0869','T0860') $selService
            }

            # Time sync (IRIG-B / PTP)
            $timeSyncLine = @($selService -split "`n" | Where-Object { $_ -match '(?i)(IRIG|PTP|time.sync|GPS)' })
            if ($timeSyncLine.Count -gt 0) {
                Add-Finding 'INFO' 'OT/SEL Integrity' "Time Synchronization Protocol Detected: $($timeSyncLine -join ' | ')" `
                    "IRIG-B or PTP time sync configuration found. Tampering with time synchronization in OT environments causes protection relay miscoordination and can disable protective functions. Verify GPS/clock source integrity." `
                    @('T0857') ($timeSyncLine -join "`n")
            } elseif ($selService -match '\S') {
                Add-Finding 'MEDIUM' 'OT/SEL Integrity' 'Time Synchronization Configuration Not Identified' `
                    "Could not confirm IRIG-B or PTP time sync configuration. Missing time synchronization in ICS environments causes relay miscoordination and affects event logging accuracy." `
                    @('T0857')
            }
        }

        # SNMP trap destinations
        $selSNMP = Invoke-RouterCommand 'show snmp'
        if ($selSNMP -and $selSNMP -match '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') {
            $snmpTraps = @($selSNMP -split "`n" | ForEach-Object {
                if ($_ -match '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') { $Matches[1] }
            } | Sort-Object -Unique)
            foreach ($st in $snmpTraps) {
                if ($st -notmatch '^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)') {
                    Add-Finding 'HIGH' 'OT/SEL Integrity' "SNMP Trap to Non-RFC1918 Destination: $st" `
                        "SNMP trap target $st is a public IP. SNMP traps from OT devices to external IPs can leak operational status, topology data, and device identifiers to adversaries." `
                        @('T0869') $st
                    Add-IOC 'IP' $st "OT/SEL SNMP trap destination (public)"
                }
            }
        }
    }

    # For non-SEL platforms, brief OT check
    if ($detectedPlatform -ne 'sel') {
        Add-Finding 'INFO' 'OT/SEL Integrity' 'OT/SEL Module Skipped  -  Non-SEL Platform' `
            "Module 11 OT-specific checks apply to SEL switches. Platform detected: $detectedPlatform." `
            @()
    }

    # ==========================================================================
    # MODULE 12  -  KNOWN APT INDICATOR PATTERNS
    # ==========================================================================
    Write-Host "[LP-RTR] Module 12: APT indicator pattern analysis..." -ForegroundColor DarkCyan

    $attributionScores = [ordered]@{}

    # Helper: find findings matching pattern
    function Get-FindingMatch {
        param([string]$Pattern)
        @($findings | Where-Object { $_.Title -match $Pattern -or $_.Detail -match $Pattern -or $_.Category -match $Pattern })
    }

    # --- Salt Typhoon ---
    # Salt Typhoon: SPAN sessions on ISP/carrier, credential capture from passing traffic
    $saltTyphoonScore = 0
    $saltTyphoonEv = @()
    $spanFindings = Get-FindingMatch '(?i)(SPAN|RSPAN|ERSPAN|mirror|traffic\s+mirror)'
    $pbrFindings  = Get-FindingMatch '(?i)(policy.based\s+routing|PBR)'
    $priv15Findings = Get-FindingMatch '(?i)(privilege.15|priv.15)'

    if ($spanFindings.Count -gt 0) { $saltTyphoonScore += 50; $saltTyphoonEv += "Active SPAN/ERSPAN traffic mirror session ($($spanFindings.Count) finding(s))" }
    if ($pbrFindings.Count  -gt 0) { $saltTyphoonScore += 25; $saltTyphoonEv += "Policy-Based Routing active (traffic redirection)" }
    if ($priv15Findings.Count -gt 0) { $saltTyphoonScore += 15; $saltTyphoonEv += "Unexpected priv-15 account(s) present" }
    if (Get-FindingMatch '(?i)(AAA accounting|no.*accounting)') { $saltTyphoonScore += 10; $saltTyphoonEv += "AAA accounting disabled  -  covering tracks" }
    if ($saltTyphoonScore -gt 0) { $attributionScores['Salt Typhoon'] = @{ Score = [Math]::Min($saltTyphoonScore,100); Evidence = $saltTyphoonEv } }

    # --- Volt Typhoon ---
    # Volt Typhoon: SOHO/edge LOL, proxy chaining through compromised devices
    $voltTyphoonScore = 0
    $voltTyphoonEv = @()
    $tunnelFindings = Get-FindingMatch '(?i)(GRE|tunnel|IPIP)'
    $proxyChain = Get-FindingMatch '(?i)(proxy|NHRP|VPN peer)'
    $noLoggingFindings = Get-FindingMatch '(?i)(no syslog|no accounting|log.*cleared)'

    if ($detectedPlatform -in @('mikrotik','linksys','tplink','glinet')) { $voltTyphoonScore += 25; $voltTyphoonEv += "SOHO/edge platform ($detectedPlatform) matches Volt Typhoon LOL profile" }
    if ((Get-FindingMatch '(?i)(SOCKS|HTTP proxy|proxy-chain)').Count -gt 0) { $voltTyphoonScore += 20; $voltTyphoonEv += 'Built-in proxy (SOCKS/HTTP) enabled  -  pivot infrastructure' }
    if ($tunnelFindings.Count -gt 0)  { $voltTyphoonScore += 30; $voltTyphoonEv += "Tunnel interfaces (GRE/IPIP) active  -  proxy-chaining infrastructure" }
    if ($proxyChain.Count -gt 0)      { $voltTyphoonScore += 20; $voltTyphoonEv += "VPN/proxy infrastructure detected" }
    if ($noLoggingFindings.Count -gt 0) { $voltTyphoonScore += 20; $voltTyphoonEv += "Log reduction / no accounting (LOL anti-forensics)" }
    if (Get-FindingMatch '(?i)(BGP peer|routing anomal)') { $voltTyphoonScore += 15; $voltTyphoonEv += "BGP routing anomaly / unexpected peers" }
    if ($priv15Findings.Count -gt 0)  { $voltTyphoonScore += 15; $voltTyphoonEv += "Unauthorized privileged account  -  living-off-the-land persistence" }
    if ($voltTyphoonScore -gt 0) { $attributionScores['Volt Typhoon'] = @{ Score = [Math]::Min($voltTyphoonScore,100); Evidence = $voltTyphoonEv } }

    # --- SYNful Knock ---
    # SYNful Knock: IOS image size mismatch, phantom ROM modules, TCP sequence backdoor
    $synfulScore = 0
    $synfulEv = @()
    $integrityFindings = Get-FindingMatch '(?i)(integrity.*mismatch|hash.*mismatch|ROMMON|boot.system)'
    $flashAnomalies    = Get-FindingMatch '(?i)(unexpected.*flash|flash.*unexpected)'
    $eemFindings       = Get-FindingMatch '(?i)(EEM|event\s+manager)'

    if ($integrityFindings.Count -gt 0) { $synfulScore += 60; $synfulEv += "Platform integrity hash mismatch or ROMMON anomaly detected" }
    if ($flashAnomalies.Count -gt 0)    { $synfulScore += 25; $synfulEv += "Unexpected files in flash filesystem" }
    if ($eemFindings.Count -gt 0)       { $synfulScore += 10; $synfulEv += "EEM applets (could be SYNful trigger mechanism)" }
    if (Get-FindingMatch '(?i)(running.*startup|config.*delta|tamper)')  { $synfulScore += 20; $synfulEv += "Running/startup config delta (in-memory modification)" }
    if ($synfulScore -gt 0) { $attributionScores['SYNful Knock'] = @{ Score = [Math]::Min($synfulScore,100); Evidence = $synfulEv } }

    # --- UNC3886 ---
    # UNC3886: FortiGate/Juniper targeting, implants in non-standard paths
    $unc3886Score = 0
    $unc3886Ev = @()
    $fortiJunFindings = @()
    if ($detectedPlatform -in @('fortios','junos')) { $unc3886Score += 20; $unc3886Ev += "Platform matches UNC3886 targeting profile (FortiGate/JunOS)" }
    $persistFindings = Get-FindingMatch '(?i)(persistence|automation.trigger|event.option)'
    if ($persistFindings.Count -gt 0) { $unc3886Score += 30; $unc3886Ev += "Persistence mechanism in non-standard location" }
    if (Get-FindingMatch '(?i)(unexpected.*file|non.standard.*path)') { $unc3886Score += 30; $unc3886Ev += "Unexpected files in non-standard paths" }
    if ($integrityFindings.Count -gt 0) { $unc3886Score += 20; $unc3886Ev += "Device integrity finding present" }
    if ($unc3886Score -gt 0) { $attributionScores['UNC3886'] = @{ Score = [Math]::Min($unc3886Score,100); Evidence = $unc3886Ev } }

    # --- APT28/APT29 ---
    # Credential harvesting, lateral movement pivot
    $apt2829Score = 0
    $apt2829Ev = @()
    $credFindings = Get-FindingMatch '(?i)(credential|AAA server|non.RFC1918|username|priv.15)'
    $lateralFindings = Get-FindingMatch '(?i)(BGP|routing|pivot|VPN)'
    if ($credFindings.Count -gt 0)  { $apt2829Score += 30; $apt2829Ev += "Credential-related findings ($($credFindings.Count))" }
    if ($lateralFindings.Count -gt 0) { $apt2829Score += 25; $apt2829Ev += "Lateral movement infrastructure (BGP/routing/VPN)" }
    if ($spanFindings.Count -gt 0)  { $apt2829Score += 20; $apt2829Ev += "Traffic interception for credential capture" }
    if ((Get-FindingMatch '(?i)(telnet|ssh\s+version\s+1)').Count -gt 0) { $apt2829Score += 15; $apt2829Ev += "Weak remote access protocol enabled" }
    if ($apt2829Score -gt 0) { $attributionScores['APT28/APT29'] = @{ Score = [Math]::Min($apt2829Score,100); Evidence = $apt2829Ev } }

    # --- Sandworm/VPFilter ---
    # VPFilter-style modular implant, flash storage persistence
    $sandwormScore = 0
    $sandwormEv = @()
    if ($flashAnomalies.Count -gt 0)  { $sandwormScore += 40; $sandwormEv += "Flash storage anomaly  -  VPFilter-style persistence" }
    if ($integrityFindings.Count -gt 0) { $sandwormScore += 30; $sandwormEv += "Device integrity failure  -  image tampering" }
    if ($tunnelFindings.Count -gt 0)  { $sandwormScore += 20; $sandwormEv += "Covert tunnel interfaces present" }
    if ((Get-FindingMatch '(?i)(SNMP|no\s+logging|anti.forensic)').Count -gt 0) { $sandwormScore += 10; $sandwormEv += "Anti-forensics / SNMP exfil indicators" }
    if ($detectedPlatform -in @('mikrotik','linksys','tplink','glinet')) {
        $sandwormScore += 20; $sandwormEv += "SOHO/edge platform ($detectedPlatform) matches VPNFilter targeting profile"
    }
    if ((Get-FindingMatch '(?i)(scheduler|rc\.local|cron|init\.d|netwatch)').Count -gt 0) {
        $sandwormScore += 15; $sandwormEv += 'Persistence via scheduler/cron/rc.local (VPNFilter stage-1 TTP)'
    }
    if ($sandwormScore -gt 0) { $attributionScores['Sandworm/VPFilter'] = @{ Score = [Math]::Min($sandwormScore,100); Evidence = $sandwormEv } }

    # --- Mirai/IoT Botnets ---
    $miraiScore = 0
    $miraiEv = @()
    if ((Get-FindingMatch '(?i)(default.*credential|weak.*credential|admin123|test123)').Count -gt 0) { $miraiScore += 40; $miraiEv += "Default or weak credentials detected" }
    if ((Get-FindingMatch '(?i)(telnet)').Count -gt 0) { $miraiScore += 30; $miraiEv += "Telnet enabled  -  Mirai primary infection vector" }
    $unexpCpuFindings = Get-FindingMatch '(?i)(unexpected.*cpu|high.cpu.*process)'
    if ($unexpCpuFindings.Count -gt 0) { $miraiScore += 20; $miraiEv += "Unexpected high-CPU process  -  possible cryptominer/DDoS module" }
    if ((Get-FindingMatch '(?i)(outbound|C2|external.*connection)').Count -gt 0) { $miraiScore += 10; $miraiEv += "Suspicious outbound connection indicators" }
    if ($miraiScore -gt 0) { $attributionScores['Mirai/IoT Botnet'] = @{ Score = [Math]::Min($miraiScore,100); Evidence = $miraiEv } }

    # Report findings for top attributions
    $topActor      = $null
    $topActorScore = 0
    $aptConf       = 'LOW'
    foreach ($actor in $attributionScores.Keys) {
        $sc = $attributionScores[$actor].Score
        if ($sc -gt $topActorScore) {
            $topActorScore = $sc
            $topActor = $actor
            $aptConf  = if ($sc -ge 70) { 'HIGH' } elseif ($sc -ge 40) { 'MEDIUM' } else { 'LOW' }
        }
    }
    if ($topActor -and $topActorScore -ge 20) {
        $topActorEv = ($attributionScores[$topActor].Evidence | Select-Object -First 4) -join '; '
        $aptSev = if ($topActorScore -ge 70) { 'CRITICAL' } elseif ($topActorScore -ge 40) { 'HIGH' } else { 'MEDIUM' }
        Add-Finding $aptSev 'APT Attribution' "Top Attribution: $topActor ($aptConf confidence, $topActorScore/100)" `
            "Highest-scoring threat actor based on TTP overlap: $topActorEv" `
            @('T1082','T0888')
    }

    # ==========================================================================
    # MODULE 13  -  IOC SUMMARY (deduplicated  -  already built via Add-IOC calls)
    # ==========================================================================
    Write-Host "[LP-RTR] Module 13: IOC summary..." -ForegroundColor DarkCyan

    $iocCount = $iocList.Count
    Add-Finding 'INFO' 'IOC Summary' "Deduplicated IOC Count: $iocCount" `
        "Total unique indicators of compromise collected across all modules: $iocCount. See IOC table in report." `
        @()

    # ==========================================================================
    # MODULE 14  -  TIMELINE RECONSTRUCTION
    # ==========================================================================
    Write-Host "[LP-RTR] Module 14: Timeline reconstruction..." -ForegroundColor DarkCyan

    # Attempt to pull last config change timestamps from the device
    if ($detectedPlatform -eq 'ios-xe') {
        $archFull = Invoke-RouterCommand 'show archive log config all'
        if ($archFull) {
            $archLines = @($archFull -split "`n" | Where-Object { $_ -match '\d{2}:\d{2}:\d{2}' } | Select-Object -First 20)
            foreach ($al in $archLines) {
                if ($al -match '(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}|\d{2}:\d{2}:\d{2}\s+\w{3}\s+\d+\s+\d{4})') {
                    $ts = $Matches[1]
                    Add-Timeline $ts 'INFO' "Config change logged: $($al.Trim() | Select-Object -First 1)" $Target
                }
            }
        }

        # Login log from show log
        $loginLogOut = Invoke-RouterCommand 'show logging | include SSH|login|CONNECT'
        if ($loginLogOut) {
            foreach ($ll in ($loginLogOut -split "`n" | Where-Object { $_ -match '(?i)(login|SSH|connect)' } | Select-Object -First 20)) {
                if ($ll -match '(\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2})') {
                    Add-Timeline $Matches[1] 'INFO' $ll.Trim() $Target
                }
                if ($ll -match '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') {
                    Add-IOC 'IP' $Matches[1] "Login source IP from syslog"
                }
            }
        }
    }

    $timeline.Add([PSCustomObject]@{
        Time     = $collectionTime
        Severity = 'INFO'
        Event    = "Triage collection completed on $deviceHostname ($detectedPlatform)"
        Source   = $Target
    })

    # ==========================================================================
    # MODULE 15  -  INITIAL ACCESS HYPOTHESIS
    # ==========================================================================
    Write-Host "[LP-RTR] Module 15: Initial access hypothesis..." -ForegroundColor DarkCyan

    $accessHypotheses = [System.Collections.Generic.List[PSCustomObject]]::new()

    function Add-AccessHypothesis {
        param([string]$Vector, [int]$Score, [string[]]$Evidence, [string[]]$Techniques, [string]$Rationale)
        if ($Score -le 0) { return }
        $clamped = [Math]::Min([Math]::Max($Score,0),100)
        $conf    = if ($clamped -ge 70) { 'HIGH' } elseif ($clamped -ge 40) { 'MEDIUM' } else { 'LOW' }
        $accessHypotheses.Add([PSCustomObject]@{
            Vector     = $Vector
            Score      = $clamped
            Confidence = $conf
            Evidence   = @($Evidence | Where-Object { $_ -and $_.Trim() } | Select-Object -Unique)
            Techniques = @($Techniques | Where-Object { $_ })
            Rationale  = $Rationale
        })
    }

    # CVE-2023-20198: IOS-XE Web UI RCE
    $cve20198Score = 0; $cve20198Ev = @()
    if ($detectedPlatform -eq 'ios-xe') {
        if (Get-FindingMatch '(?i)(CVE.2023.20198|logoutconfirm|webshell.*implant)') { $cve20198Score += 60; $cve20198Ev += 'CVE-2023-20198 webshell indicator detected' }
        if (Get-FindingMatch '(?i)(ip\s+http\s+server|http\s+server\s+enabled)') { $cve20198Score += 25; $cve20198Ev += 'IOS-XE HTTP server enabled (attack surface present)' }
        if ($priv15Findings.Count -gt 0) { $cve20198Score += 15; $cve20198Ev += 'Unexpected priv-15 account (CVE-2023-20198 persistence TTP)' }
    }
    Add-AccessHypothesis 'CVE-2023-20198 (IOS-XE Web UI RCE)' $cve20198Score $cve20198Ev @('T1190','T1505.003','T1136') `
        'Active exploitation of CVE-2023-20198 allows unauthenticated creation of priv-15 accounts via HTTP API, followed by webshell implant deployment.'

    # CVE-2022-42475: FortiOS SSL-VPN heap overflow
    $cve42475Score = 0; $cve42475Ev = @()
    if ($detectedPlatform -eq 'fortios') {
        $cve42475Score += 30; $cve42475Ev += 'FortiOS platform (CVE-2022-42475 target)'
        if (Get-FindingMatch '(?i)(persistence|automation|trigger)') { $cve42475Score += 25; $cve42475Ev += 'FortiOS persistence mechanism detected' }
        if (Get-FindingMatch '(?i)(integrity|flash|unexpected)') { $cve42475Score += 20; $cve42475Ev += 'Device integrity anomaly on FortiGate' }
        if (Get-FindingMatch '(?i)(unexpected.*user|priv|admin)') { $cve42475Score += 15; $cve42475Ev += 'Suspicious admin account' }
        if (Get-FindingMatch '(?i)(syslog.*public|unexpected.*dns)') { $cve42475Score += 10; $cve42475Ev += 'Anomalous data exfil infrastructure' }
    }
    Add-AccessHypothesis 'CVE-2022-42475 (FortiOS SSL-VPN)' $cve42475Score $cve42475Ev @('T1190','T1133') `
        'FortiOS SSL-VPN heap overflow enabling unauthenticated remote code execution. Exploited by UNC3886 and other threat actors.'

    # Default/Weak Credentials
    $credScore = 0; $credEv = @()
    if (Get-FindingMatch '(?i)(telnet|SSH\s+version\s+1)')  { $credScore += 25; $credEv += 'Insecure remote access protocol (Telnet/SSHv1) enables credential sniffing' }
    if (Get-FindingMatch '(?i)(no\s+access.class|vty.*unrestricted)') { $credScore += 15; $credEv += 'VTY lines unrestricted to management network' }
    if (Get-FindingMatch '(?i)(unexpected.*user|suspicious.*user)') { $credScore += 25; $credEv += 'Suspicious user account(s) detected' }
    if (Get-FindingMatch '(?i)(AAA.*not|no.*tacacs|no.*radius)') { $credScore += 20; $credEv += 'No centralized authentication  -  local credentials only' }
    if ($credScore -gt 0) { $credEv += 'Default or weak local credentials are an extremely common initial access vector on network devices' }
    Add-AccessHypothesis 'Default or Weak Credentials' $credScore $credEv @('T1078','T0859','T1110') `
        'Network devices with default or weak credentials are trivially compromised via brute-force or credential stuffing, especially when exposed on insecure management protocols.'

    # Supply Chain / Firmware Tampering
    $scScore = 0; $scEv = @()
    if ($integrityFindings.Count -gt 0) { $scScore += 50; $scEv += 'Device integrity check failure  -  possible firmware modification' }
    if ($flashAnomalies.Count -gt 0)   { $scScore += 25; $scEv += 'Unexpected files in flash storage' }
    if (Get-FindingMatch '(?i)(boot.system|ROMMON)') { $scScore += 25; $scEv += 'Boot system or ROMMON anomaly' }
    Add-AccessHypothesis 'Supply Chain / Firmware Tampering' $scScore $scEv @('T1195.002','T0862','T0857') `
        'Device firmware or bootloader was modified either pre-delivery (supply chain) or post-deployment via remote exploitation, providing persistent low-level access.'

    # Insider Threat
    $insiderScore = 0; $insiderEv = @()
    if ($priv15Findings.Count -gt 0) { $insiderScore += 20; $insiderEv += 'Privileged account anomaly' }
    if (Get-FindingMatch '(?i)(config.*archive|change.*log)') { $insiderScore = [Math]::Max($insiderScore, 10); $insiderEv += 'Config changes logged' }
    if (Get-FindingMatch '(?i)(session from|active session)') { $insiderScore += 15; $insiderEv += 'Active or recent privileged sessions' }
    if (-not (Get-FindingMatch '(?i)(telnet|CVE|webshell|tunnel|SPAN)')) { $insiderScore += 20; $insiderEv += 'No external exploitation indicators  -  consistent with insider action' }
    Add-AccessHypothesis 'Insider Threat / Administrative Abuse' $insiderScore $insiderEv @('T1078','T0859') `
        'Changes may have been made by a rogue administrator or a compromised administrator account rather than through external exploitation.'

    # Physical Access (OT/SEL)
    $physScore = 0; $physEv = @()
    if ($detectedPlatform -eq 'sel') {
        $physScore += 20; $physEv += 'SEL OT switch  -  physical access is common in substation environments'
        if (Get-FindingMatch '(?i)(SELOGIC|equation|firmware)') { $physScore += 30; $physEv += 'SELOGIC or firmware modification detected  -  possible physical access' }
        if (Get-FindingMatch '(?i)(port.*mirror|SPAN.*SEL)') { $physScore += 25; $physEv += 'Port mirror on OT switch  -  installation requires physical proximity' }
    }
    Add-AccessHypothesis 'Physical Access (OT/SEL)' $physScore $physEv @('T0860','T0862') `
        'In OT/substation environments, physical access to switches and relays enables configuration changes, port mirroring, and firmware modification without leaving network-visible traces.'

    # Rank hypotheses
    $rankedHypotheses = @($accessHypotheses | Sort-Object Score -Descending)
    if ($rankedHypotheses.Count -gt 0 -and $rankedHypotheses[0].Score -gt 0) {
        $topIA = $rankedHypotheses[0]
        $iaSev = if ($topIA.Score -ge 70) { 'CRITICAL' } elseif ($topIA.Score -ge 40) { 'HIGH' } else { 'MEDIUM' }
        $iaEvText = ($topIA.Evidence | Select-Object -First 4) -join '; '
        Add-Finding $iaSev 'Initial Access' "Most Likely Access Vector: $($topIA.Vector) ($($topIA.Confidence) confidence, $($topIA.Score)/100)" `
            "$($topIA.Rationale) Evidence: $iaEvText" $topIA.Techniques
        Add-Timeline $collectionTime $iaSev "Likely initial access vector: $($topIA.Vector) ($($topIA.Score)/100)" $Target
        Write-Host ("         [LP-RTR] Top initial access hypothesis: {0} ({1} {2}/100)" -f $topIA.Vector, $topIA.Confidence, $topIA.Score) -ForegroundColor DarkYellow
    }

    # ==========================================================================
    # BUILD HTML REPORT
    # ==========================================================================
    Write-Host "[LP-RTR] Building HTML report..." -ForegroundColor DarkCyan

    $reportDate  = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $critCount   = ($findings | Where-Object { $_.Severity -eq 'CRITICAL' } | Measure-Object).Count
    $highCount   = ($findings | Where-Object { $_.Severity -eq 'HIGH'     } | Measure-Object).Count
    $medCount    = ($findings | Where-Object { $_.Severity -eq 'MEDIUM'   } | Measure-Object).Count
    $lowCount    = ($findings | Where-Object { $_.Severity -eq 'LOW'      } | Measure-Object).Count
    $totalCount  = $findings.Count

    # Executive verdict
    $hasSpan     = ($findings | Where-Object { $_.Title -match '(?i)(SPAN|ERSPAN|mirror)' } | Measure-Object).Count -gt 0
    $hasTunnel   = ($findings | Where-Object { $_.Title -match '(?i)(GRE|tunnel)' }         | Measure-Object).Count -gt 0
    $hasPBR      = ($findings | Where-Object { $_.Title -match '(?i)(PBR|policy.based)' }   | Measure-Object).Count -gt 0
    $hasIntegrity= ($findings | Where-Object { $_.Title -match '(?i)(integrity|ROMMON|boot)' } | Measure-Object).Count -gt 0
    $hasPersist  = ($findings | Where-Object { $_.Category -eq 'Persistence' } | Measure-Object).Count -gt 0
    $hasWebshell = ($findings | Where-Object { $_.Title -match '(?i)(webshell|CVE.2023.20198)' } | Measure-Object).Count -gt 0

    $execVerdict = if ($hasSpan -and ($hasPBR -or $hasTunnel)) {
        'Active traffic interception with covert exfiltration infrastructure  -  Salt Typhoon-pattern compromise highly suspected'
    } elseif ($hasSpan) {
        'Active traffic mirror session detected  -  passive network interception in progress'
    } elseif ($hasIntegrity -and $hasPersist) {
        'Device integrity failure with persistence mechanisms  -  possible firmware-level implant (SYNful Knock pattern)'
    } elseif ($hasWebshell) {
        'Web shell / CVE-2023-20198 exploitation indicators detected'
    } elseif ($hasTunnel -and $hasPBR) {
        'Covert tunnel and traffic redirection infrastructure detected'
    } elseif ($critCount -gt 0) {
        'Critical security anomalies detected requiring immediate investigation'
    } elseif ($highCount -gt 0) {
        'Significant security findings detected  -  device may be compromised'
    } else {
        'Routine anomalies detected  -  review recommended but no confirmed compromise indicators'
    }

    $execSevLabel = if ($critCount -ge 5) { 'CRITICAL' } elseif ($critCount -gt 0 -or $highCount -ge 5) { 'HIGH' } elseif ($highCount -gt 0 -or $medCount -gt 0) { 'MEDIUM' } else { 'LOW' }
    $execSevClass = $execSevLabel.ToLower()

    $execHighlights = [System.Collections.Generic.List[string]]::new()
    [void]$execHighlights.Add("Device: $deviceHostname | Platform: $detectedPlatform | Version: $softwareVersion | Serial: $serialNumber | Uptime: $deviceUptime")
    [void]$execHighlights.Add("Overall severity: $execSevLabel  -  Critical: $critCount | High: $highCount | Medium: $medCount | Low: $lowCount | Total: $totalCount")
    if ($topActor) { [void]$execHighlights.Add("Top APT attribution overlap: $topActor ($aptConf confidence, $topActorScore/100)") }
    if ($rankedHypotheses.Count -gt 0 -and $rankedHypotheses[0].Score -gt 0) {
        [void]$execHighlights.Add("Most likely initial access: $($rankedHypotheses[0].Vector) ($($rankedHypotheses[0].Confidence) confidence, $($rankedHypotheses[0].Score)/100)")
    }
    if ($hasSpan)     { [void]$execHighlights.Add("ACTIVE TRAFFIC INTERCEPTION: SPAN/RSPAN/ERSPAN session(s) detected  -  all traffic passing this device may be captured.") }
    if ($hasTunnel)   { [void]$execHighlights.Add("Covert tunnel interfaces (GRE/IPIP) present  -  possible encrypted exfiltration channels.") }
    if ($hasPBR)      { [void]$execHighlights.Add("Policy-Based Routing active  -  traffic flows may be silently redirected to attacker infrastructure.") }
    if ($hasIntegrity){ [void]$execHighlights.Add("Device integrity check anomalies  -  firmware or image may have been modified.") }
    if ($hasWebshell) { [void]$execHighlights.Add("Web shell / CVE-2023-20198 indicators present  -  unauthorized persistent remote access pathway exists.") }

    $execActions = [System.Collections.Generic.List[string]]::new()
    [void]$execActions.Add("IMMEDIATE: Isolate $deviceHostname from production network while preserving power-on state for memory forensics.")
    if ($hasSpan)  { [void]$execActions.Add("CRITICAL: Remove SPAN/ERSPAN monitor sessions. Document destination ports and capture PCAP from those destinations if possible.") }
    if ($hasPBR)   { [void]$execActions.Add("CRITICAL: Remove all Policy-Based Routing maps from interfaces. Log affected traffic flows.") }
    if ($hasTunnel){ [void]$execActions.Add("HIGH: Shut down all GRE/IPIP tunnel interfaces. Capture 'show interface tunnel' output before shutdown for forensic record.") }
    if ($hasIntegrity) { [void]$execActions.Add("HIGH: Do NOT reboot until memory forensics complete. Engage Cisco/vendor PSIRT. Verify IOS image hash against known-good distribution.") }
    [void]$execActions.Add("Rotate ALL credentials for accounts on this device and any downstream systems accessible from it.")
    [void]$execActions.Add("Review all IOCs in this report against SIEM/NetFlow records for lateral movement and data exfiltration scope.")
    [void]$execActions.Add("Preserve running-config, startup-config, 'show tech-support', and memory forensics before any remediation actions.")

    # Build HTML
    $html = [System.Text.StringBuilder]::new()
    [void]$html.AppendLine('<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">')
    [void]$html.AppendLine("<title>Router Forensic Triage  -  $(Escape-Html $deviceHostname)</title>")
    [void]$html.AppendLine("<style>$script:LP_CSS</style></head><body>")

    # Header
    $platformBadge = "<span class='platform-badge'>$($detectedPlatform.ToUpper())</span>"
    [void]$html.AppendLine("<h1>ROUTER FORENSIC TRIAGE REPORT <span class='live-badge'>LIVE SSH</span>$platformBadge</h1>")
    [void]$html.AppendLine("<div class='meta'>Device: <b>$(Escape-Html $deviceHostname)</b> &nbsp;|&nbsp; Target: $(Escape-Html $Target) &nbsp;|&nbsp; Platform: <b>$(Escape-Html $detectedPlatform)</b> &nbsp;|&nbsp; Version: $(Escape-Html $softwareVersion) &nbsp;|&nbsp; Collected: $reportDate &nbsp;|&nbsp; Engine: Loaded Potato Router Triage v1.0</div>")

    # Summary grid
    [void]$html.AppendLine("<div class='section'><div class='summary-grid'>")
    [void]$html.AppendLine("<div class='summary-box'><span class='summary-num' style='color:#ff5533'>$critCount</span><div class='summary-lbl'>Critical</div></div>")
    [void]$html.AppendLine("<div class='summary-box'><span class='summary-num' style='color:#ffaa44'>$highCount</span><div class='summary-lbl'>High</div></div>")
    [void]$html.AppendLine("<div class='summary-box'><span class='summary-num' style='color:#ffe055'>$medCount</span><div class='summary-lbl'>Medium</div></div>")
    [void]$html.AppendLine("<div class='summary-box'><span class='summary-num' style='color:#55cc55'>$lowCount</span><div class='summary-lbl'>Low</div></div>")
    [void]$html.AppendLine("<div class='summary-box'><span class='summary-num' style='color:#5599cc'>$totalCount</span><div class='summary-lbl'>Total</div></div>")
    [void]$html.AppendLine('</div></div>')

    # Executive summary
    [void]$html.AppendLine("<div class='section'><h2>EXECUTIVE SUMMARY</h2>")
    [void]$html.AppendLine("<div class='finding f-$execSevClass'>")
    [void]$html.AppendLine("<span class='sev-$execSevLabel'>[$execSevLabel]</span> <span class='cat'>[Verdict]</span> <span class='title'>$(Escape-Html $execVerdict)</span><br>")
    [void]$html.AppendLine("<span class='detail'>Generated from live SSH triage of $deviceHostname at $reportDate. All commands are read-only show commands  -  no changes were made to the device.</span>")
    [void]$html.AppendLine('</div>')
    foreach ($h in $execHighlights) {
        [void]$html.AppendLine("<div class='finding f-info'><span class='detail'>$(Escape-Html $h)</span></div>")
    }
    [void]$html.AppendLine("<h3>Immediate Actions</h3>")
    foreach ($a in $execActions) {
        [void]$html.AppendLine("<div class='finding f-high'><span class='detail'>$(Escape-Html $a)</span></div>")
    }
    [void]$html.AppendLine('</div>')

    # Device profile table
    [void]$html.AppendLine("<div class='section'><h2>DEVICE PROFILE</h2>")
    [void]$html.AppendLine("<table class='kv-table'><tr><th>Property</th><th>Value</th></tr>")
    foreach ($kv in $deviceProfile.GetEnumerator()) {
        [void]$html.AppendLine("<tr><td>$(Escape-Html $kv.Key)</td><td>$(Escape-Html $kv.Value)</td></tr>")
    }
    [void]$html.AppendLine('</table></div>')

    # APT Attribution section with confidence bars
    if ($attributionScores.Count -gt 0) {
        [void]$html.AppendLine("<div class='section'><h2>APT ATTRIBUTION</h2>")
        [void]$html.AppendLine("<div style='color:#557799;font-size:9px;margin-bottom:10px'>Scores reflect TTP overlap with known actor profiles based on observed findings. Score does not constitute definitive attribution.</div>")
        foreach ($actor in ($attributionScores.Keys | Sort-Object { $attributionScores[$_].Score } -Descending)) {
            $sc   = $attributionScores[$actor].Score
            if ($sc -lt 5) { continue }
            $ev_  = ($attributionScores[$actor].Evidence | Select-Object -First 4) -join ' &bull; '
            $barC = if ($sc -ge 70) { '#cc2200' } elseif ($sc -ge 40) { '#e07820' } else { '#c8a000' }
            $conf_= if ($sc -ge 70) { 'HIGH' } elseif ($sc -ge 40) { 'MEDIUM' } else { 'LOW' }
            [void]$html.AppendLine("<div style='margin:8px 0'>")
            [void]$html.AppendLine("<span style='color:#dde8f0;font-weight:bold'>$(Escape-Html $actor)</span> <span class='badge badge-$(($conf_).ToLower())'>$conf_ &mdash; $sc/100</span><br>")
            [void]$html.AppendLine("<div class='attr-bar' style='width:320px'><div class='attr-fill' style='width:$sc%;background:$barC'></div></div>")
            [void]$html.AppendLine("<div style='color:#9aaabb;font-size:9px;margin-top:3px'>$ev_</div>")
            [void]$html.AppendLine('</div>')
        }
        [void]$html.AppendLine('</div>')
    }

    # Initial access reconstruction
    if ($rankedHypotheses.Count -gt 0 -and $rankedHypotheses[0].Score -gt 0) {
        [void]$html.AppendLine("<div class='section'><h2>INITIAL ACCESS HYPOTHESIS (RANKED)</h2>")
        [void]$html.AppendLine("<table class='kv-table'><tr><th>Rank</th><th>Vector</th><th>Confidence</th><th>Score</th><th>Evidence Summary</th></tr>")
        $iaRank = 0
        foreach ($ia in ($rankedHypotheses | Where-Object { $_.Score -gt 0 } | Select-Object -First 6)) {
            $iaRank++
            $evText = ($ia.Evidence | Select-Object -First 3) -join ' | '
            $confBadge = if ($ia.Confidence -eq 'HIGH') { "<span class='badge badge-critical'>HIGH</span>" } `
                         elseif ($ia.Confidence -eq 'MEDIUM') { "<span class='badge badge-high'>MEDIUM</span>" } `
                         else { "<span class='badge badge-medium'>LOW</span>" }
            [void]$html.AppendLine("<tr><td>$iaRank</td><td>$(Escape-Html $ia.Vector)</td><td>$confBadge</td><td>$($ia.Score)/100</td><td>$(Escape-Html $evText)</td></tr>")
        }
        [void]$html.AppendLine('</table>')
        [void]$html.AppendLine("<div style='color:#9aaabb;font-size:9px;margin-top:6px'>Hypotheses are scored dynamically from observed findings. Scores are comparative confidence, not definitive attribution.</div>")
        [void]$html.AppendLine('</div>')
    }

    # Findings by severity
    $sevOrder = @('CRITICAL','HIGH','MEDIUM','LOW','INFO')
    [void]$html.AppendLine("<div class='section'><h2>FINDINGS</h2>")
    foreach ($sev in $sevOrder) {
        $sevFindings = @($findings | Where-Object { $_.Severity -eq $sev })
        if ($sevFindings.Count -eq 0) { continue }
        [void]$html.AppendLine("<h3>$sev ($($sevFindings.Count))</h3>")
        foreach ($f in $sevFindings) {
            $tecs = ($f.Techniques | Where-Object { $_ } | ForEach-Object { "<span class='technique'>[$_]</span>" }) -join ''
            [void]$html.AppendLine("<div class='finding f-$(($f.Severity).ToLower())'>")
            [void]$html.AppendLine("<span class='sev-$($f.Severity)'>[$($f.Severity)]</span> <span class='cat'>[$(Escape-Html $f.Category)]</span> <span class='title'>$(Escape-Html $f.Title)</span>$tecs<br>")
            [void]$html.AppendLine("<span class='detail'>$(Escape-Html $f.Detail)</span>")
            [void]$html.AppendLine('</div>')
        }
    }
    [void]$html.AppendLine('</div>')

    # IOC table
    if ($iocList.Count -gt 0) {
        [void]$html.AppendLine("<div class='section'><h2>INDICATORS OF COMPROMISE (MODULE 13)</h2>")
        [void]$html.AppendLine("<table class='kv-table'><tr><th>Type</th><th>Indicator</th><th>Context</th><th>Threat Match</th></tr>")
        foreach ($ioc in ($iocList | Sort-Object Type)) {
            $typeClass = switch -Regex ($ioc.Type) {
                'IP'       { 'ioc-ip'   }
                'Hash|MD5' { 'ioc-hash' }
                default    { 'ioc-path' }
            }
            $matchHtml = if ($ioc.ThreatMatch) {
                "<span class='match-hit'>$(Escape-Html $ioc.ThreatMatch)</span>"
            } else {
                "<span class='match-clean'> &mdash; </span>"
            }
            [void]$html.AppendLine("<tr><td>$(Escape-Html $ioc.Type)</td><td class='$typeClass'>$(Escape-Html $ioc.Value)</td><td>$(Escape-Html $ioc.Context)</td><td>$matchHtml</td></tr>")
        }
        [void]$html.AppendLine('</table></div>')
    }

    # MITRE ATT&CK table (Enterprise + ICS)
    if ($mitreMap.Count -gt 0) {
        [void]$html.AppendLine("<div class='section'><h2>MITRE ATT&amp;CK COVERAGE (ENTERPRISE + ICS)</h2>")
        [void]$html.AppendLine("<table class='mitre-tbl'><tr><th>Technique ID</th><th>Name</th><th>Framework</th><th>Evidence (findings)</th></tr>")
        foreach ($tid in ($mitreMap.Keys | Sort-Object)) {
            $tname  = if ($script:MITRE_NAMES.ContainsKey($tid)) { $script:MITRE_NAMES[$tid] } else { 'See MITRE ATT&amp;CK' }
            $tframe = if ($tid -match '^T0') { 'ICS' } else { 'Enterprise' }
            $tevid  = ($mitreMap[$tid] | Select-Object -First 3) -join '; '
            [void]$html.AppendLine("<tr><td class='mitre-tid'>$tid</td><td class='mitre-name'>$(Escape-Html $tname)</td><td style='color:#446688'>$tframe</td><td class='mitre-ev'>$(Escape-Html $tevid)</td></tr>")
        }
        [void]$html.AppendLine('</table></div>')
    }

    # Timeline (Module 14)
    if ($timeline.Count -gt 0) {
        [void]$html.AppendLine("<div class='section'><h2>FORENSIC TIMELINE (MODULE 14)</h2>")
        $sortedTl = @($timeline | Sort-Object Time)
        foreach ($te in $sortedTl) {
            $tlClass = if ($te.Severity -eq 'CRITICAL') { 'tl-crit' } elseif ($te.Severity -eq 'HIGH') { 'tl-sus' } else { '' }
            [void]$html.AppendLine("<div class='tl-entry $tlClass'><span class='tl-time'>$(Escape-Html $te.Time)</span><span class='tl-event'>$(Escape-Html $te.Event)</span></div>")
        }
        [void]$html.AppendLine('</div>')
    }

    # Footer
    $modeLabel = if ($offlineMode) { "OFFLINE DUMP ANALYSIS ($(Escape-Html $DumpPath))" } else { "LIVE SSH COLLECTION (Read-Only Show Commands)" }
    [void]$html.AppendLine("<footer>Loaded Potato Router Triage Engine v1.0 &nbsp;|&nbsp; $modeLabel &nbsp;|&nbsp; Platform: $detectedPlatform &nbsp;|&nbsp; Device: $(Escape-Html $deviceHostname) &nbsp;|&nbsp; $reportDate</footer>")
    [void]$html.AppendLine('</body></html>')

    # -- Write output ------------------------------------------------------------
    $safeHostname = $deviceHostname -replace '[\\/:*?"<>|]','_'
    $reportName   = "RouterTriage_${safeHostname}_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    $reportPath   = Join-Path $OutputPath $reportName

    $null = New-Item -ItemType Directory -Force -Path $OutputPath
    [System.IO.File]::WriteAllText($reportPath, $html.ToString(), [System.Text.Encoding]::UTF8)

    Write-Host "`n[LP-RTR] ============================================================" -ForegroundColor Cyan
    Write-Host "[LP-RTR] TRIAGE COMPLETE" -ForegroundColor Green
    Write-Host "[LP-RTR] Device   : $deviceHostname ($detectedPlatform $softwareVersion)" -ForegroundColor White
    Write-Host "[LP-RTR] CRITICAL : $critCount  HIGH: $highCount  MEDIUM: $medCount  TOTAL: $totalCount" -ForegroundColor $(if ($critCount -gt 0) { 'Red' } else { 'White' })
    if ($topActor) {
        Write-Host "[LP-RTR] Top APT  : $topActor ($aptConf, $topActorScore/100)" -ForegroundColor DarkYellow
    }
    Write-Host "[LP-RTR] IOCs     : $iocCount" -ForegroundColor White
    Write-Host "[LP-RTR] Report   : $reportPath" -ForegroundColor Cyan
    Write-Host "[LP-RTR] ============================================================" -ForegroundColor Cyan

    if ($OpenReport) { Start-Process $reportPath }

    return [PSCustomObject]@{
        ReportPath          = $reportPath
        Hostname            = $deviceHostname
        Platform            = $detectedPlatform
        Version             = $softwareVersion
        CriticalFindings    = $critCount
        HighFindings        = $highCount
        MediumFindings      = $medCount
        LowFindings         = $lowCount
        TotalFindings       = $totalCount
        TopAttribution      = $topActor
        AttributionConf     = $aptConf
        AttributionScore    = $topActorScore
        IOCCount            = $iocCount
        MITRETechniques     = ($mitreMap.Keys | Sort-Object)
        HasSpanSession      = $hasSpan
        HasGRETunnel        = $hasTunnel
        HasPBR              = $hasPBR
        HasIntegrityFailure = $hasIntegrity
    }
}

# ===============================================================================
# DUMP COLLECTION FUNCTION
# SSH-pulls all commands and saves them to a directory for offline analysis.
# Run this on a jump host with network access; then copy the dump to an
# air-gapped analysis machine and run Invoke-RouterTriage -DumpPath <dir>.
# ===============================================================================
function Save-RouterDump {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Target,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$Credential,

        [ValidateSet('auto','ios-xe','nxos','junos','fortios','panos','sel','mikrotik','linksys','tplink','glinet')]
        [string]$Platform = 'auto',

        [string]$OutputPath = (Get-Location).Path,

        [string]$SshKey,

        [int]$TimeoutSec = 30
    )

    $sshUser     = $Credential.UserName
    $sshPassword = $Credential.GetNetworkCredential().Password

    # Sanitize command to filename (same logic as Invoke-RouterTriage internals)
    function Get-DumpFileName { param([string]$Cmd)
        ($Cmd -replace '[^a-zA-Z0-9\-]','_' -replace '_+','_' -replace '^_|_$','') + '.txt'
    }

    function Run-Cmd {
        param([string]$Cmd)
        $plinkExe = Get-Command 'plink.exe' -ErrorAction SilentlyContinue
        $sshExe   = Get-Command 'ssh.exe'   -ErrorAction SilentlyContinue
        $stdout   = $null
        try {
            if ($plinkExe -and $sshPassword) {
                $args = @('-ssh','-batch','-pw',$sshPassword,"$sshUser@$Target",$Cmd)
                $proc = Start-Process $plinkExe.Source -ArgumentList $args -NoNewWindow -PassThru `
                    -RedirectStandardOutput "$env:TEMP\lp_dump_out.txt" `
                    -RedirectStandardError  "$env:TEMP\lp_dump_err.txt"
                $proc.WaitForExit($TimeoutSec * 1000) | Out-Null
                if (-not $proc.HasExited) { $proc.Kill() }
                $stdout = Get-Content "$env:TEMP\lp_dump_out.txt" -Raw -ErrorAction SilentlyContinue
                Remove-Item "$env:TEMP\lp_dump_out.txt","$env:TEMP\lp_dump_err.txt" -Force -ErrorAction SilentlyContinue
            } elseif ($sshExe -and $SshKey) {
                $args = @('-o','StrictHostKeyChecking=no','-o','BatchMode=yes','-i',$SshKey,
                          '-o',"ConnectTimeout=$TimeoutSec","$sshUser@$Target",$Cmd)
                $proc = Start-Process $sshExe.Source -ArgumentList $args -NoNewWindow -PassThru `
                    -RedirectStandardOutput "$env:TEMP\lp_dump_out.txt" `
                    -RedirectStandardError  "$env:TEMP\lp_dump_err.txt"
                $proc.WaitForExit($TimeoutSec * 1000) | Out-Null
                if (-not $proc.HasExited) { $proc.Kill() }
                $stdout = Get-Content "$env:TEMP\lp_dump_out.txt" -Raw -ErrorAction SilentlyContinue
                Remove-Item "$env:TEMP\lp_dump_out.txt","$env:TEMP\lp_dump_err.txt" -Force -ErrorAction SilentlyContinue
            }
        } catch {}
        return $stdout
    }

    # All commands executed by Invoke-RouterTriage, per platform
    $allCmds = @(
        # Universal
        'show version'
        'show running-config'
        'show startup-config'
        'show users'
        'show clock'
        'show logging'
        'show interfaces'
        # IOS-XE / NX-OS
        'show platform integrity sign nonce 12345'
        'show rom-var'
        'dir flash:'
        'show running-config | section username'
        'show running-config | section aaa'
        'show running-config | section event manager'
        'show running-config | section kron'
        'show running-config | section ip nat'
        'show running-config | section ip access-list'
        'show running-config | section route-map'
        'show running-config | section ip policy'
        'show running-config | section ntp'
        'show running-config | section logging'
        'show running-config | section snmp'
        'show running-config | include ip http'
        'show monitor session all'
        'show interfaces tunnel'
        'show ip policy'
        'show ip route'
        'show ip bgp neighbors'
        'show ip bgp summary'
        'show ip nhrp'
        'show crypto isakmp sa'
        'show crypto ipsec sa'
        'show ip nat translations'
        'show event manager policy registered'
        'show tcl scripts'
        'show kron schedule'
        'show guestshell'
        'show processes cpu sorted'
        'show processes memory sorted'
        'show archive log config all'
        'show user-account'
        'show scheduler job'
        'show system integrity'
        # JunOS
        'show system information'
        'show configuration system login'
        'show system users'
        'show system storage'
        'show version detail'
        'show route'
        'show bgp neighbor'
        'show interfaces terse'
        'show configuration event-options'
        'show firewall filter'
        'show security flow session'
        # FortiOS
        'get system status'
        'get system admin'
        'show system admin'
        'get system interface'
        'show system interface'
        'show full-configuration'
        'show router bgp'
        'show system automation-trigger'
        'show system automation-action'
        'diagnose sys flash list'
        'get router info routing-table all'
        # PAN-OS
        'show system info'
        'show system files'
        'show admins'
        'show interface all'
        'show running security-policy'
        'show jobs all'
        'show routing route'
        # SEL
        'show access'
        'show flash'
        'show port'
        'show vlan'
        'show mirror'
        'show snmp'
        'show time'
        'show log'
        # MikroTik RouterOS
        '/system resource print'
        '/system routerboard print'
        '/system package print'
        '/system clock print'
        '/file print detail'
        '/user print detail'
        '/user active print detail'
        '/user ssh-keys print detail'
        '/ip service print detail'
        '/ip address print'
        '/ip route print'
        '/ip route rule print'
        '/ip firewall filter print detail'
        '/ip firewall nat print detail'
        '/ip firewall mangle print detail'
        '/ip firewall connection print'
        '/ip dns print'
        '/ip proxy print'
        '/ip socks print'
        '/ip upnp print'
        '/ip neighbor print detail'
        '/interface print detail'
        '/interface ethernet switch port print'
        '/interface wireguard print'
        '/routing bgp peer print detail'
        '/routing ospf neighbor print'
        '/system scheduler print detail'
        '/system script print detail'
        '/system ntp client print'
        '/system ntp server print'
        '/system logging action print detail'
        '/system logging print'
        '/tool netwatch print detail'
        '/tool sniffer print'
        '/radius print detail'
        '/snmp print'
        '/log print'
        # Linksys / TP-Link / OpenWrt (Linux-based)
        'cat /etc/openwrt_release'
        'cat /etc/os-release'
        'uname -a'
        'cat /proc/version'
        'cat /proc/cpuinfo'
        'cat /etc/passwd'
        'cat /etc/shadow'
        'cat /etc/dropbear/authorized_keys'
        'cat /etc/rc.local'
        'cat /etc/crontabs/root'
        'crontab -l'
        'ls -la /etc/init.d'
        'ls -la /etc/hotplug.d'
        'ls -la /tmp'
        'ls -la /www'
        'ps w'
        'ps -ef'
        'netstat -tlnp'
        'netstat -an'
        'ss -tlnp'
        'ip addr'
        'ip route'
        'ip rule show'
        'ip tunnel show'
        'ip link show'
        'iptables -L -n -v'
        'iptables -t nat -L -n -v'
        'iptables -t mangle -L -n -v'
        'ip6tables -L -n -v'
        'tc qdisc show'
        'tc filter show'
        'cat /etc/resolv.conf'
        'cat /tmp/resolv.conf.auto'
        'uci show system'
        'uci show network'
        'uci show firewall'
        'uci show dropbear'
        'uci show wireless'
        'logread'
        'dmesg'
        'who'
        # GL.iNet-specific (Beryl / Slate / Flint / Brume travel routers)
        'cat /etc/glversion'
        'cat /tmp/sysinfo/model'
        'cat /proc/device-tree/model'
        'uci show glconfig'
        'uci show glconfig.cloud'
        'uci show glconfig.general'
        'uci show glconfig.ddns'
        'uci show glconfig.repeater'
        'uci show wireguard'
        'uci show openvpn'
        'ls -la /etc/openvpn'
        'ls -la /etc/wireguard'
        'ls /etc/init.d'
        'ls -la /usr/lib/lua/luci/controller/admin'
        'ls -la /www/cgi-bin'
        'ls -la /www'
        'uci show adguardhome'
        'uci show tor'
        'uci show ddns'
    )

    # Auto-detect platform for smarter collection
    $detectedPlatform = $Platform
    if ($detectedPlatform -eq 'auto') {
        $ver = Run-Cmd 'show version'
        if (-not $ver) { $ver = Run-Cmd 'get system status' }
        if (-not $ver) { $ver = Run-Cmd '/system resource print' }
        if (-not $ver) { $ver = Run-Cmd '/system routerboard print' }
        if (-not $ver) { $ver = Run-Cmd 'cat /etc/glversion 2>/dev/null' }
        if (-not $ver) { $ver = Run-Cmd 'cat /etc/openwrt_release' }
        if (-not $ver) { $ver = Run-Cmd 'uname -a' }
        if ($ver -match '(?i)IOS.XE')        { $detectedPlatform = 'ios-xe' }
        elseif ($ver -match '(?i)NX.OS|Nexus'){ $detectedPlatform = 'nxos'  }
        elseif ($ver -match '(?i)JUNOS')       { $detectedPlatform = 'junos' }
        elseif ($ver -match '(?i)FortiOS|FortiGate') { $detectedPlatform = 'fortios' }
        elseif ($ver -match '(?i)PAN.OS')      { $detectedPlatform = 'panos' }
        elseif ($ver -match '(?i)SEL|SELOGIC|Schweitzer') { $detectedPlatform = 'sel' }
        elseif ($ver -match '(?i)RouterOS|MikroTik|RouterBOARD|CCR\d|hAP|hEX') { $detectedPlatform = 'mikrotik' }
        elseif ($ver -match '(?i)GL\.?iNet|glinet|\bGL-(?:MT|AR|AX|B|E|X|MV|S)\w*|Beryl|Slate|Flint|Brume|Mango|Opal|Spitz|GL_VERSION') { $detectedPlatform = 'glinet' }
        elseif ($ver -match '(?i)Linksys|WRT\d|EA\d{4}|Velop') { $detectedPlatform = 'linksys' }
        elseif ($ver -match '(?i)TP-?Link|Archer|Omada|JetStream|TL-\w+') { $detectedPlatform = 'tplink' }
    }

    # Create dump directory
    $safeTarget = $Target -replace '[\\/:*?"<>|]','_'
    $dumpDir    = Join-Path $OutputPath "RouterDump_${safeTarget}_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    $null = New-Item -ItemType Directory -Force -Path $dumpDir

    Write-Host "`n[LP-DUMP] ============================================================" -ForegroundColor Cyan
    Write-Host "[LP-DUMP] Save-RouterDump  -  Loaded Potato" -ForegroundColor Cyan
    Write-Host "[LP-DUMP] Target   : $Target  ($detectedPlatform)" -ForegroundColor White
    Write-Host "[LP-DUMP] Dump dir : $dumpDir" -ForegroundColor White
    Write-Host "[LP-DUMP] Commands : $($allCmds.Count)" -ForegroundColor White
    Write-Host "[LP-DUMP] ============================================================" -ForegroundColor Cyan

    $saved  = 0
    $failed = 0
    foreach ($cmd in $allCmds) {
        Write-Host "[LP-DUMP] > $cmd" -ForegroundColor DarkGray -NoNewline
        $out = Run-Cmd $cmd
        if ($out -and $out.Trim()) {
            $fileName = Get-DumpFileName $cmd
            [System.IO.File]::WriteAllText((Join-Path $dumpDir $fileName), $out.Trim(), [System.Text.Encoding]::UTF8)
            $saved++
            Write-Host "  [OK]" -ForegroundColor Green
        } else {
            $failed++
            Write-Host "  [SKIP]" -ForegroundColor DarkGray
        }
    }

    # Write manifest
    $manifest = [ordered]@{
        Target           = $Target
        Platform         = $detectedPlatform
        CollectedBy      = $env:USERNAME
        CollectionTime   = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        CollectionHost   = $env:COMPUTERNAME
        CommandsSaved    = $saved
        CommandsSkipped  = $failed
    } | ConvertTo-Json
    [System.IO.File]::WriteAllText((Join-Path $dumpDir 'dump_manifest.json'), $manifest, [System.Text.Encoding]::UTF8)

    Write-Host "`n[LP-DUMP] Saved $saved commands ($failed skipped/unsupported)" -ForegroundColor Cyan
    Write-Host "[LP-DUMP] Dump : $dumpDir" -ForegroundColor Cyan
    Write-Host "[LP-DUMP] Run  : Invoke-RouterTriage -DumpPath '$dumpDir' -OpenReport" -ForegroundColor Yellow
    Write-Host "[LP-DUMP] ============================================================" -ForegroundColor Cyan

    return $dumpDir
}

Export-ModuleMember -Function Invoke-RouterTriage, Save-RouterDump
