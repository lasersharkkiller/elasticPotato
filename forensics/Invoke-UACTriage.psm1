<#
.SYNOPSIS
    Loaded Potato  -  Offline UAC (Unix Artifact Collector) Forensic Triage Engine

.DESCRIPTION
    Performs expert-level offline forensic analysis on a UAC dump directory.
    Cross-references all file hashes, IPs, and domains against local
    threat intelligence CSVs (no internet required).

    Generates a styled HTML report covering (19 modules):
      - Module 01: System profile, kernel integrity, dmesg LKM events, /etc/hosts tampering
      - Module 02: Rootkit / LD_PRELOAD detection, chkrootkit, kernel module anomalies
      - Module 03: Hidden process analysis, staging paths, high-entropy names, webshell spawns
      - Module 04: Network C2 (IPv4 + IPv6), miner ports, IRC, reverse shells, DoH, promiscuous mode
      - Module 05: Hash intel lookup (3M+ entries, MD5/SHA1/SHA256), domain & filename intel
      - Module 06: Persistence (cron, systemd, authorized_keys, profile.d, MOTD, PAM, sudoers, at jobs)
      - Module 07: Credential artifacts (PAM dumps, shell history, /etc/shadow)
      - Module 08: Filesystem timeline reconstruction (bodyfile)
      - Module 09: User account anomaly detection (UID 0 backdoors)
      - Module 10: Attribution (19 actor profiles)
      - Module 11: Webshell & dropper detection (web roots + staging paths)
      - Module 12: Binary integrity checks (trojanized system tools)
      - Module 13: SUID/SGID anomaly detection
      - Module 14: Log integrity, anti-forensics, iptables tampering, APT source manipulation
      - Module 15: Specialized implants (BPFDoor, Reptile LKM, Sysrv/DreamBus, XorDDoS, TinyShell)
      - Module 16: Container/Docker environment & escape vector detection
      - Module 17: Lateral movement (ARP, known_hosts, SSH keys, routing, rclone)
      - Module 18: Loki/Thor YARA & IOC scan (auto-detects scanner under .\tools\, scans [root] filesystem)
      - Module 19: Initial access reconstruction (ranked entry-vector hypotheses with confidence scoring)

      Attribution profiles: TeamTNT, Kinsing, Lazarus, Volt Typhoon, UNC3886, APT41,
                            Turla, Sandworm, APT34/OilRig, Carbanak/FIN7, Scattered Spider,
                            APT28/Fancy Bear, APT29/Cozy Bear, Kimsuky, APT32/OceanLotus,
                            Ransomware (Generic), Webshell/IAB, Mirai/IoT Botnet, Rocke/Iron Group

.PARAMETER UACPath
    Path to the root of the extracted UAC dump (e.g. C:\uac\uac-hostname-date)

.PARAMETER OutputPath
    Directory to write the HTML report. Defaults to current directory.

.PARAMETER IntelBasePath
    Path to the Loaded Potato 'apt' directory containing intel CSVs (3 schemas:
    *_Master_Intel.csv, dated IOC CSVs, Targeted_Analysis_Map.csv).
    If omitted, the script auto-detects by walking up from its own location.

.PARAMETER OpenReport
    If specified, opens the HTML report in the default browser on completion.

.EXAMPLE
    Import-Module .\forensics\Invoke-UACTriage.psm1
    Invoke-UACTriage -UACPath "C:\Downloads\uac-vbox-linux-20260324193807" -OpenReport

.EXAMPLE
    Invoke-UACTriage -UACPath "C:\uac\uac-webserver-20260101" `
                     -OutputPath "C:\reports" `
                     -IntelBasePath "D:\Loaded-Potato\apt"
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
.summary-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin:8px 0}
.summary-box{background:#0d1520;border:1px solid #1a2d42;border-radius:3px;padding:10px 12px;text-align:center}
.summary-num{font-size:28px;font-weight:bold;display:block;line-height:1}
.summary-lbl{color:#557799;font-size:8px;text-transform:uppercase;letter-spacing:1px;margin-top:3px}
.offline-badge{display:inline-block;background:#0a1f0a;border:1px solid #2a6a2a;color:#55cc55;padding:3px 10px;border-radius:2px;font-size:8px;font-weight:bold;letter-spacing:2px;margin-left:10px;vertical-align:middle}
.attr-bar{height:8px;background:#1a2d42;border-radius:4px;overflow:hidden;margin-top:4px}
.attr-fill{height:100%;border-radius:4px;transition:width .3s}
footer{color:#334455;font-size:8px;margin-top:20px;border-top:1px solid #1a2d42;padding-top:8px;text-align:center}
'@

# --- MITRE TECHNIQUE DESCRIPTIONS ---------------------------------------------
$script:MITRE_NAMES = @{
    'T1574.006' = 'Hijack Execution Flow: LD_PRELOAD'
    'T1564.001' = 'Hide Artifacts: Hidden Files and Directories'
    'T1496'     = 'Resource Hijacking'
    'T1556.003' = 'Modify Authentication Process: PAM'
    'T1059.004' = 'Command and Scripting Interpreter: Unix Shell'
    'T1036.005' = 'Masquerading: Match Legitimate Name/Location'
    'T1071.001' = 'Application Layer Protocol: Web Protocols'
    'T1078'     = 'Valid Accounts'
    'T1027'     = 'Obfuscated Files or Information'
    'T1053.003' = 'Scheduled Task/Job: Cron'
    'T1543.002' = 'Create or Modify System Process: Systemd Service'
    'T1098.004' = 'Account Manipulation: SSH Authorized Keys'
    'T1110'     = 'Brute Force'
    'T1552.003' = 'Unsecured Credentials: Shell History'
    'T1070.004' = 'Indicator Removal: File Deletion'
    'T1014'     = 'Rootkit'
    'T1082'     = 'System Information Discovery'
    'T1083'     = 'File and Directory Discovery'
    'T1057'     = 'Process Discovery'
    'T1049'     = 'System Network Connections Discovery'
    'T1505.003' = 'Server Software Component: Web Shell'
    'T1554'     = 'Compromise Host Software Binary'
    'T1548.001' = 'Abuse Elevation Control: Setuid/Setgid'
    'T1548.003' = 'Abuse Elevation Control: Sudo and Sudo Caching'
    'T1068'     = 'Exploitation for Privilege Escalation'
    'T1070.002' = 'Indicator Removal: Clear Linux/Mac System Logs'
    'T1070'     = 'Indicator Removal on Host'
    'T1090'     = 'Proxy'
    'T1071.003' = 'Application Layer Protocol: Mail Protocols'
    'T1071.004' = 'Application Layer Protocol: DNS'
    'T1003.008' = 'OS Credential Dumping: /etc/passwd and /etc/shadow'
    'T1588.002' = 'Obtain Capabilities: Tool'
    'T1072'     = 'Software Deployment Tools'
    'T1136'     = 'Create Account'
    'T1205.001' = 'Traffic Signaling: Port Knocking'
    'T1547.006' = 'Boot or Logon Autostart: Kernel Modules and Extensions'
    'T1546.004' = 'Event Triggered Execution: Unix Shell Configuration Modification'
    'T1546'     = 'Event Triggered Execution'
    'T1543'     = 'Create or Modify System Process'
    'T1611'     = 'Escape to Host'
    'T1610'     = 'Deploy Container'
    'T1210'     = 'Exploitation of Remote Services'
    'T1021.004' = 'Remote Services: SSH'
    'T1552.004' = 'Unsecured Credentials: Private Keys'
    'T1537'     = 'Transfer Data to Cloud Account'
    'T1567.002' = 'Exfiltration Over Web Service: Exfiltration to Cloud Storage'
    'T1557'     = 'Adversary-in-the-Middle'
    'T1018'     = 'Remote System Discovery'
    'T1036'     = 'Masquerading'
    'T1059'     = 'Command and Scripting Interpreter'
    'T1040'     = 'Network Sniffing'
    'T1562'     = 'Impair Defenses'
    'T1562.004' = 'Impair Defenses: Disable or Modify System Firewall'
    'T1053'     = 'Scheduled Task/Job'
    'T1053.001' = 'Scheduled Task/Job: At'
    'T1195.002' = 'Supply Chain Compromise: Compromise Software Supply Chain'
    'T1190'     = 'Exploit Public-Facing Application'
}

# --- HELPER: Safe file reader --------------------------------------------------
function script:Read-UACArtifact {
    param([string]$Base, [string]$Relative)
    $p = Join-Path $Base $Relative
    if (Test-Path -LiteralPath $p -PathType Leaf) { return (Get-Content -LiteralPath $p -Raw -Encoding UTF8) }
    return $null
}

function script:Read-UACArtifactLines {
    param([string]$Base, [string]$Relative)
    $p = Join-Path $Base $Relative
    if (Test-Path -LiteralPath $p -PathType Leaf) { return (Get-Content -LiteralPath $p -Encoding UTF8) }
    return @()
}

function script:Get-UACShellHistoryPaths {
    # Build a normalized list of shell history artifacts across root + all /home users.
    # Covers bash, zsh, ksh/mksh, ash/hush, fish, and byobu command history.
    param([string]$Base)

    $histRel = @(
        '.bash_history',
        '.zsh_history',
        '.zhistory',
        '.ksh_history',
        '.mksh_history',
        '.sh_history',
        '.ash_history',
        '.hush_history',
        '.local/share/fish/fish_history',
        '.config/fish/fish_history',
        '.config/fish/fish_history.txt',
        '.byobu/command-history'
    )

    $paths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($h in $histRel) {
        [void]$paths.Add("[root]/root/$h")
    }

    $homeBase = Join-Path $Base '[root]/home'
    if (Test-Path -LiteralPath $homeBase) {
        $homeDirs = Get-ChildItem -LiteralPath $homeBase -Directory -ErrorAction SilentlyContinue
        foreach ($hd in $homeDirs) {
            foreach ($h in $histRel) {
                [void]$paths.Add("[root]/home/$($hd.Name)/$h")
            }
        }
    }

    return @($paths)
}

# --- HELPER: HTML escape ------------------------------------------------------
function script:Escape-Html {
    param([string]$s)
    if (-not $s) { return '' }
    $s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;'
}

# --- HELPER: Convert hex IP (proc/net/tcp) to dotted notation -----------------
function script:Convert-HexToIP {
    param([string]$hex)
    try {
        if ($hex.Length -eq 8) {
            $b = [Convert]::ToInt64($hex, 16)
            $b1 = ($b -band 0xFF)
            $b2 = (($b -shr 8) -band 0xFF)
            $b3 = (($b -shr 16) -band 0xFF)
            $b4 = (($b -shr 24) -band 0xFF)
            return "$b1.$b2.$b3.$b4"
        }
    } catch {}
    return $null
}

function script:Convert-HexToPort {
    param([string]$hex)
    try { return [Convert]::ToInt32($hex, 16) } catch { return $null }
}

# /proc/net/tcp6 stores each IPv6 address as four little-endian 32-bit words
function script:Convert-HexToIPv6 {
    param([string]$hex)
    try {
        if ($hex.Length -ne 32) { return $null }
        $bytes = [byte[]]::new(16)
        for ($w = 0; $w -lt 4; $w++) {
            $word = $hex.Substring($w * 8, 8)
            $bytes[$w*4+0] = [Convert]::ToByte($word.Substring(6,2),16)
            $bytes[$w*4+1] = [Convert]::ToByte($word.Substring(4,2),16)
            $bytes[$w*4+2] = [Convert]::ToByte($word.Substring(2,2),16)
            $bytes[$w*4+3] = [Convert]::ToByte($word.Substring(0,2),16)
        }
        return [System.Net.IPAddress]::new($bytes).ToString()
    } catch { return $null }
}

# --- HELPER: Resolve proc/net/tcp state code ----------------------------------
function script:Resolve-TCPState {
    param([string]$code)
    @{ '01'='ESTABLISHED';'02'='SYN_SENT';'03'='SYN_RECV';'04'='FIN_WAIT1';
       '05'='FIN_WAIT2';'06'='TIME_WAIT';'07'='CLOSE';'08'='CLOSE_WAIT';
       '09'='LAST_ACK';'0A'='LISTEN';'0B'='CLOSING' }[$code.ToUpper()]
}

# ===============================================================================
# MAIN EXPORTED FUNCTION
# ===============================================================================
function Invoke-UACTriage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, HelpMessage='Path to extracted UAC dump root directory')]
        [string]$UACPath,

        [string]$OutputPath = (Get-Location).Path,

        [string]$IntelBasePath,

        [switch]$OpenReport
    )

    # -- Resolve paths to absolute so .NET File I/O matches PS working dir -------
    if (-not [System.IO.Path]::IsPathRooted($OutputPath)) {
        $OutputPath = Join-Path (Get-Location).Path $OutputPath
    }
    if (-not [System.IO.Path]::IsPathRooted($UACPath)) {
        $UACPath = Join-Path (Get-Location).Path $UACPath
    }

    # -- Validate input ----------------------------------------------------------
    if (-not (Test-Path -LiteralPath $UACPath -PathType Container)) {
        Write-Error "UAC path not found: $UACPath"
        return
    }
    $uac = $UACPath.TrimEnd('\','/')

    # -- Auto-detect Intel base path ---------------------------------------------
    if (-not $IntelBasePath) {
        $search = $PSScriptRoot
        for ($i = 0; $i -lt 4; $i++) {
            $candidate = Join-Path $search 'apt'
            if (Test-Path $candidate) { $IntelBasePath = $candidate; break }
            $search = Split-Path $search -Parent
        }
        if (-not $IntelBasePath) {
            Write-Warning 'Could not locate apt/ intel directory. Hash lookup will be skipped.'
        }
    }

    Write-Host "`n[LP-UAC] Starting offline forensic triage..." -ForegroundColor Cyan
    Write-Host "[LP-UAC] Target: $uac" -ForegroundColor Gray

    # -- Findings accumulator ----------------------------------------------------
    $findings  = [System.Collections.Generic.List[PSCustomObject]]::new()
    $iocList   = [System.Collections.Generic.List[PSCustomObject]]::new()
    $timeline  = [System.Collections.Generic.List[PSCustomObject]]::new()
    $mitreMap  = [System.Collections.Generic.Dictionary[string,System.Collections.Generic.List[string]]]::new()

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
                if (-not $mitreMap.ContainsKey($t)) { $mitreMap[$t] = [System.Collections.Generic.List[string]]::new() }
                if (-not $mitreMap[$t].Contains($Title)) { [void]$mitreMap[$t].Add($Title) }
            }
        }
    }

    function Add-IOC {
        param([string]$Type, [string]$Value, [string]$Context, [string]$ThreatMatch = '')
        $iocList.Add([PSCustomObject]@{
            Type       = $Type
            Value      = $Value
            Context    = $Context
            ThreatMatch= $ThreatMatch
        })
    }

    function Add-Timeline {
        param([string]$Time, [string]$Severity, [string]$Event, [string]$Path = '')
        $timeline.Add([PSCustomObject]@{
            Time     = $Time
            Severity = $Severity
            Event    = $Event
            Path     = $Path
        })
    }

    # ==========================================================================
    # MODULE 1  -  SYSTEM PROFILE
    # ==========================================================================
    Write-Host "[LP-UAC] Module 1: System profiling..." -ForegroundColor DarkCyan

    $sysProfile = @{}

    $unameLine = (Read-UACArtifact $uac 'live_response/system/uname_-a.txt') -replace '\s+$',''
    $hostname  = (Read-UACArtifact $uac 'live_response/network/hostname.txt') -replace '\s+',''
    $taintRaw  = (Read-UACArtifact $uac 'live_response/system/cat_proc_sys_kernel_tainted.txt') -replace '\s+',''
    $uptime    = (Read-UACArtifact $uac 'live_response/system/uptime.txt') -replace '\s+$',''
    $collDate  = (Split-Path $uac -Leaf) -replace '^uac-[^-]+-[^-]+-',''

    # Parse OS release (try multiple sources)
    $osRelease = Read-UACArtifact $uac '[root]/etc/os-release'
    if (-not $osRelease) { $osRelease = Read-UACArtifact $uac '[root]/etc/debian_version' }
    $osName = if ($osRelease -match 'PRETTY_NAME="([^"]+)"') {
        $Matches[1]
    } elseif ($unameLine -match '\+deb(\d+)\+') {
        "Debian GNU/Linux $($Matches[1])"
    } elseif ($unameLine -match '(ubuntu|fedora|centos|arch|suse|rhel|alpine)' ) {
        (Get-Culture).TextInfo.ToTitleCase($Matches[1].ToLower()) + ' Linux'
    } elseif ($osRelease -and $osRelease.Trim()) {
        "Debian $($osRelease.Trim())"
    } else {
        'Linux (see uname)'
    }

    # Kernel arch from uname
    $kernelFull = if ($unameLine) { $unameLine } else { 'Unknown' }
    $arch = if ($unameLine -match '\b(x86_64|aarch64|arm64|armv7)\b') { $Matches[1] } else { 'Unknown' }

    # Taint flag analysis
    $taintVal = [int]($taintRaw -replace '[^0-9]','0')
    $taintFlags = @()
    if ($taintVal -band 1)    { $taintFlags += 'Proprietary module loaded' }
    if ($taintVal -band 2)    { $taintFlags += 'Module with GPL-incompatible license' }
    if ($taintVal -band 4)    { $taintFlags += 'Forced module load (--force)' }
    if ($taintVal -band 8)    { $taintFlags += 'Tainted by SMP kernel' }
    if ($taintVal -band 16)   { $taintFlags += 'Module was force-unloaded' }
    if ($taintVal -band 32)   { $taintFlags += 'Machine check error occurred' }
    if ($taintVal -band 64)   { $taintFlags += 'Bad page referenced' }
    if ($taintVal -band 512)  { $taintFlags += 'Kernel died recently (OOPS)' }
    if ($taintVal -band 1024) { $taintFlags += 'ACPI table overridden by user' }

    $sysProfile = [ordered]@{
        Hostname       = $hostname
        OS             = $osName
        Kernel         = $kernelFull
        Architecture   = $arch
        'Kernel Taint' = if ($taintVal -gt 0) { "$taintVal  -  $($taintFlags -join '; ')" } else { '0 (Clean)' }
        Uptime         = $uptime
        'Collection ID'= Split-Path $uac -Leaf
    }

    if ($taintVal -band 4) {
        Add-Finding 'HIGH' 'Kernel Integrity' 'Kernel Taint Flag 4  -  Forced Module Load' `
            "Kernel taint value $taintVal includes bit 4 (forced module load). A kernel module was loaded with --force, bypassing signature verification. This may indicate a kernel-mode rootkit component beyond userspace LD_PRELOAD hooks. Audit /proc/modules and /sys/module for unsigned modules." `
            @('T1014') "taint=$taintVal"
    }

    # Login history
    $lastLines = Read-UACArtifactLines $uac 'live_response/system/last_-a_-F.txt'
    $suspiciousLogins = @($lastLines | Where-Object { $_ -match '\d+\.\d+' -and $_ -notmatch 'reboot|wtmp' })
    if ($suspiciousLogins.Count -gt 0) {
        $loginSrc = @($suspiciousLogins | ForEach-Object {
            if ($_ -match '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') { $Matches[1] }
        } | Sort-Object -Unique)
        if ($loginSrc.Count -gt 0) {
            foreach ($src in $loginSrc) { Add-IOC 'IP' $src 'SSH source IP (login history)' }
            Add-Finding 'INFO' 'Authentication' 'SSH Login Activity Detected' `
                "Login source(s): $($loginSrc -join ', '). Review for brute-force or unauthorized access." `
                @('T1078','T1110')
        }
    }

    # 1b. dmesg kernel ring buffer - LKM load events, OOM kills of security tools
    $dmesgContent = Read-UACArtifact $uac 'live_response/system/dmesg.txt'
    if ($dmesgContent) {
        $lkmLoads = @($dmesgContent -split "`n" | Where-Object {
            $_ -match '(?i)(insmod|rmmod|loading.*module|module.*verif|taint.*module|Oops:|BUG:|kernel.*panic|segfault.*kernel)' -and
            $_ -notmatch '(?i)(bluetooth|wifi|wireless|usb|sound|audio|video|nvidia|nouveau|i915|vboxdrv|vboxnet|vmw_)'
        })
        if ($lkmLoads.Count -gt 0) {
            Add-Finding 'HIGH' 'Kernel Integrity' `
                "Suspicious Kernel Messages in dmesg ($($lkmLoads.Count) line(s))" `
                "Kernel ring buffer contains module load/verify events or kernel fault messages: $($lkmLoads | Select-Object -First 3 | ForEach-Object { $_.Trim() })" `
                @('T1014','T1547.006')
        }
        $oomKills = @($dmesgContent -split "`n" | Where-Object {
            $_ -match '(?i)(Out of memory.*Kill|oom.*killed)' -and
            $_ -match '(?i)(auditd|syslog|rsyslog|ossec|snort|fail2ban|crowdstrike|falcon|carbon|defender|sentinel)'
        })
        if ($oomKills.Count -gt 0) {
            Add-Finding 'HIGH' 'Anti-Forensics' `
                "Security Tool OOM-Killed in dmesg  -  Possible Memory Pressure Attack" `
                "Kernel OOM killer terminated security/monitoring processes: $($oomKills | Select-Object -First 2 | ForEach-Object { $_.Trim() })" `
                @('T1562')
        }
    }

    # 1c. /etc/hosts tampering - suspicious domain redirections
    $hostsContent = Read-UACArtifact $uac '[root]/etc/hosts'
    if ($hostsContent) {
        $hostsNonLocal = @($hostsContent -split "`n" | Where-Object {
            $_ -match '^\d' -and $_ -notmatch '^\s*#' -and
            $_ -notmatch '^127\.' -and $_ -notmatch '^::1' -and $_ -notmatch '^0\.0\.0\.0'
        })
        $suspHosts = @($hostsNonLocal | Where-Object {
            $_ -match '(?i)(security|update|apt\.|pypi|docker|github|google|cloudflare|azure|amazonaws|metadata\.google|169\.254\.169\.254|grafana|prometheus|elastic|splunk|defender|crowdstrike|sentinelone|carbonblack|falconsensor|vsphere|vcenter)'
        })
        if ($suspHosts.Count -gt 0) {
            Add-Finding 'HIGH' 'DNS Hijack' `
                "/etc/hosts Redirect for Security/Service Domain ($($suspHosts.Count) entry/entries)" `
                "Legitimate service/security domains redirected in /etc/hosts: $($suspHosts | ForEach-Object { $_.Trim() } | Select-Object -First 5). Can intercept package updates, cloud metadata, or auth flows." `
                @('T1557','T1071.004')
            foreach ($sh in $suspHosts) {
                if ($sh -match '^(\d[\d.]+)\s+(.+)') { Add-IOC 'IP' $Matches[1] "/etc/hosts redirect - $($Matches[2].Trim())" }
            }
        }
        if ($hostsNonLocal.Count -gt 0) {
            Add-Finding 'INFO' 'Network' `
                "/etc/hosts Non-Default Entries ($($hostsNonLocal.Count))" `
                "Non-loopback /etc/hosts entries (verify manually): $($hostsNonLocal | Select-Object -First 8 | ForEach-Object { $_.Trim() })" `
                @()
        }
    }

    Write-Host "         Hostname: $hostname | OS: $osName | Taint: $taintVal" -ForegroundColor Gray

    # ==========================================================================
    # MODULE 2  -  ROOTKIT DETECTION
    # ==========================================================================
    Write-Host "[LP-UAC] Module 2: Rootkit detection..." -ForegroundColor DarkCyan

    # 2a. Check /etc/ld.so.preload via chkrootkit output
    $ldPreloadChkrootkit = Read-UACArtifact $uac 'chkrootkit/etc_ld_so_preload.txt'
    $ldPreloadDirect     = Read-UACArtifact $uac '[root]/etc/ld.so.preload'
    $preloadLibs = @()

    if ($ldPreloadChkrootkit -and $ldPreloadChkrootkit.Trim()) {
        $preloadLibs = @($ldPreloadChkrootkit -split "`n" | Where-Object { $_.Trim() -and $_ -notmatch '^\s*#' } | ForEach-Object { $_.Trim() })
    } elseif ($ldPreloadDirect -and $ldPreloadDirect.Trim()) {
        $preloadLibs = @($ldPreloadDirect -split "`n" | Where-Object { $_.Trim() -and $_ -notmatch '^\s*#' } | ForEach-Object { $_.Trim() })
    }

    if ($preloadLibs.Count -gt 0) {
        foreach ($lib in $preloadLibs) {
            Add-IOC 'FilePath' $lib '/etc/ld.so.preload  -  injected library'
            Add-Finding 'CRITICAL' 'Rootkit' 'LD_PRELOAD Rootkit  -  /etc/ld.so.preload Active' `
                "/etc/ld.so.preload is populated with: $lib  -  This forces the library to load into every dynamically-linked process, enabling syscall hooking (e.g. readdir for process hiding, pam_authenticate for credential theft). Technique matches TeamTNT xmrig.so / bash.so LD_PRELOAD pattern." `
                @('T1574.006','T1014') $lib

            Add-Timeline '(Rootkit active at collection time)' 'CRITICAL' `
                "/etc/ld.so.preload populated  -  $lib injected into all processes" '/etc/ld.so.preload'
        }
        Write-Host "         [CRITICAL] LD_PRELOAD rootkit confirmed: $($preloadLibs -join ', ')" -ForegroundColor Red
    }

    # 2b. Check if the rootkit .so file exists on disk
    foreach ($lib in $preloadLibs) {
        # Normalise path to find in [root] tree
        $libRelative = $lib.TrimStart('/') -replace '/','\'
        $libInRoot   = Join-Path $uac "[root]\$libRelative"
        if (Test-Path -LiteralPath $libInRoot) {
            $libInfo = Get-Item -LiteralPath $libInRoot
            Add-Finding 'CRITICAL' 'Rootkit' "Rootkit Library Present on Disk: $lib" `
                "File confirmed at $libInRoot  -  Size: $($libInfo.Length) bytes. Compile-on-victim pattern: library built specifically for this host to evade hash-based detection." `
                @('T1574.006','T1027')
        } else {
            Add-Finding 'HIGH' 'Anti-Forensics' "LD_PRELOAD Library Missing from Disk: $lib" `
                "Library path in /etc/ld.so.preload does not currently exist on disk ($lib). This pattern is consistent with attacker cleanup or deleted-on-exec behavior after rootkit injection." `
                @('T1070.004','T1574.006')
            Add-IOC 'FilePath' $lib 'Referenced by /etc/ld.so.preload but missing from extracted filesystem'
        }
    }

    # 2c. Scan chkrootkit output for any INFECTED markers
    $chkrootkitFiles = Get-ChildItem -LiteralPath (Join-Path $uac 'chkrootkit') -File -ErrorAction SilentlyContinue
    foreach ($ckf in $chkrootkitFiles) {
        $ckContent = Get-Content -LiteralPath $ckf.FullName -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
        if ($ckContent -match 'INFECTED|Susp\. files found|suspicious') {
            $chkMatches = [regex]::Matches($ckContent, '(?m)^.*(INFECTED|Susp\. files found|suspicious).*$')
            $hits = ($chkMatches | Select-Object -First 10 | ForEach-Object { $_.Value.Trim() }) -join '; '
            Add-Finding 'HIGH' 'Rootkit' "chkrootkit Infection Marker: $($ckf.Name)" `
                $hits @('T1014')
        }
    }

    # 2d. Kernel modules  -  look for unsigned or suspicious names
    $lsmodLines = Read-UACArtifactLines $uac 'live_response/system/lsmod.txt'
    $suspModules = @($lsmodLines | Where-Object {
        $_ -match '^\w' -and
        $_ -notmatch '^Module' -and
        $_ -match '(?i)(rootkit|hide|hook|inject|stealth|spy|back|implant|priv|esc|ring0|bypass)'
    })
    if ($suspModules.Count -gt 0) {
        Add-Finding 'CRITICAL' 'Rootkit' 'Suspicious Kernel Module Name Detected' `
            ($suspModules -join '; ') @('T1014')
    }

    # ==========================================================================
    # MODULE 3  -  HIDDEN PROCESS ANALYSIS
    # ==========================================================================
    Write-Host "[LP-UAC] Module 3: Hidden process analysis..." -ForegroundColor DarkCyan

    $hiddenPidLines = Read-UACArtifactLines $uac 'live_response/process/hidden_pids_for_ps_command.txt'
    $hiddenPids = @($hiddenPidLines | Where-Object { $_ -match '^\d+' } | ForEach-Object { $_.Trim() })
    $runningProcPathLines = Read-UACArtifactLines $uac 'live_response/process/running_processes_full_paths.txt'
    $hiddenPidExeMap = @{}
    foreach ($rpl in $runningProcPathLines) {
        if ($rpl -match '/proc/(\d+)/exe\s*->\s*(.+)$') {
            $hiddenPidExeMap[$Matches[1]] = $Matches[2].Trim()
        }
    }

    # Visible process list
    $psFile = @(
        'live_response/process/ps_-axo_pid_user_etime_args.txt',
        'live_response/process/date_before_ps_-axo_pid_user_etime_args.txt',
        'live_response/process/ps_-ef.txt'
    ) | Where-Object { Test-Path -LiteralPath (Join-Path $uac $_) } | Select-Object -First 1
    $psLines = if ($psFile) { Read-UACArtifactLines $uac $psFile } else { @() }
    $visiblePids = @($psLines | Where-Object { $_ -match '^\s*(\d+)' } | ForEach-Object {
        if ($_ -match '^\s*(\d+)') { $Matches[1] }
    })

    if ($hiddenPids.Count -gt 0) {
        Add-Finding 'CRITICAL' 'Process Hiding' `
            "$($hiddenPids.Count) Process(es) Hidden from Standard Tools (ps/top)" `
            "Hidden PIDs: $($hiddenPids -join ', ')  -  These PIDs exist in /proc (confirmed by direct enumeration) but are invisible to ps/top/htop because the LD_PRELOAD rootkit hooks libc readdir() and silently drops entries for processes whose GID matches the rootkit's magic value. This is how the miner consumes ~100% CPU while appearing absent from process lists." `
            @('T1564.001','T1014')

        foreach ($pid in $hiddenPids) {
            # Try to get process details from proc/PID/comm and cmdline
            $comm    = Read-UACArtifact $uac "live_response/process/proc/$pid/comm.txt"
            $cmdline = Read-UACArtifact $uac "live_response/process/proc/$pid/cmdline.txt"
            $env_    = Read-UACArtifact $uac "live_response/process/proc/$pid/environ.txt"
            $exePath = if ($hiddenPidExeMap.ContainsKey($pid)) { $hiddenPidExeMap[$pid] } else { '' }
            $comm    = if ($comm)    { $comm.Trim()    } else { 'unknown' }
            $cmdline = if ($cmdline) { ($cmdline -replace '\x00',' ').Trim() } else { '' }

            # Check for LD_PRELOAD in environment
            if ($env_ -match 'LD_PRELOAD') {
                Add-Finding 'CRITICAL' 'Process Hiding' "Hidden PID $pid has LD_PRELOAD Set in Environment" `
                    "Process $pid ($comm) has LD_PRELOAD active in its environment  -  confirms rootkit injection." `
                    @('T1574.006')
            }

            if ($exePath) {
                Add-IOC 'FilePath' $exePath "Hidden PID $pid executable path"
                if ($exePath -match '\(deleted\)') {
                    Add-Finding 'CRITICAL' 'Anti-Forensics' "Hidden PID $pid Executing Deleted Binary" `
                        "Hidden PID $pid points to a deleted executable ($exePath). This fileless pattern is commonly used to evade on-disk detection while continuing execution from memory." `
                        @('T1070.004','T1027')
                }
                if ($exePath -match '(?i)^/(dev/shm|tmp|var/tmp|run/shm)/') {
                    Add-Finding 'CRITICAL' 'Staging' "Hidden PID $pid Running from Volatile Path" `
                        "Hidden PID $pid executable path is $exePath. Execution from volatile staging paths strongly indicates malicious payload staging." `
                        @('T1059.004','T1036.005')
                }
            }

            Add-IOC 'PID' $pid "Hidden process at collection time  -  $comm $cmdline".Trim()
            Add-Timeline '(At collection time)' 'CRITICAL' "Hidden PID $pid ($comm) invisible to ps" "/proc/$pid"
        }
        $hiddenWithExe = @($hiddenPids | Where-Object { $hiddenPidExeMap.ContainsKey($_) } | ForEach-Object { "$_ -> $($hiddenPidExeMap[$_])" })
        if ($hiddenWithExe.Count -gt 0) {
            $hiddenExeSample = ($hiddenWithExe | Select-Object -First 5) -join ' | '
            Add-Finding 'CRITICAL' 'Process Hiding' `
                'Hidden Processes Mapped to Executables via /proc Symlinks' `
                "Executable symlink evidence for hidden PIDs: $hiddenExeSample" `
                @('T1564.001','T1014')
        }
        Write-Host "         [CRITICAL] $($hiddenPids.Count) hidden PIDs: $($hiddenPids -join ', ')" -ForegroundColor Red
    }

    # 3b. Correlate hidden PIDs with UAC collector /proc access failures (anti-forensics signal)
    $uacLogLines = Read-UACArtifactLines $uac 'uac.log'
    if ($hiddenPids.Count -gt 0 -and $uacLogLines.Count -gt 0) {
        $hiddenPidRegex = ($hiddenPids | ForEach-Object { [regex]::Escape($_) }) -join '|'
        $hiddenProcErrors = @($uacLogLines | Where-Object {
            $_ -match "/proc/($hiddenPidRegex)/" -and $_ -match 'No such file or directory'
        })
        if ($hiddenProcErrors.Count -gt 0) {
            $errSample = ($hiddenProcErrors | Select-Object -First 5 | ForEach-Object { $_.Trim() }) -join ' | '
            Add-Finding 'CRITICAL' 'Anti-Forensics' `
                "Collector Could Not Access Hidden PID /proc Entries ($($hiddenProcErrors.Count) event(s))" `
                "UAC collector repeatedly failed to read /proc data for hidden PIDs with 'No such file or directory'. This supports active process concealment/interference during live response. Sample: $errSample" `
                @('T1564.001','T1070')
            Add-Timeline '(At collection)' 'CRITICAL' 'UAC /proc reads failed for hidden PIDs (active concealment suspected)' '/proc'
        }
    }

    # Check load average for miner activity indicator
    if ($uptime -match 'load average:\s*([\d.]+)') {
        $load1 = [double]$Matches[1]
        if ($load1 -ge 2.0) {
            Add-Finding 'HIGH' 'Resource Hijacking' `
                "Elevated Load Average Consistent with Cryptominer ($load1)" `
                "1-minute load average of $load1 is anomalously high. Combined with hidden processes, this strongly indicates active CPU mining." `
                @('T1496')
        }
    }

    # 3c. Scan lsof for /dev/shm staging or deleted executables
    $lsofLines = Read-UACArtifactLines $uac 'live_response/process/lsof_-nPl.txt'
    $devShmHits = @($lsofLines | Where-Object { $_ -match '/dev/shm' -and $_ -notmatch 'lttng|pipewire|pulse' })
    if ($devShmHits.Count -gt 0) {
        Add-Finding 'CRITICAL' 'Staging' '/dev/shm Used as Malware Staging Area' `
            "Processes have file handles to /dev/shm objects (volatile memory staging  -  survives only until reboot): $($devShmHits[0..2] -join ' | ')" `
            @('T1059.004','T1070.004')
    }
    $deletedExe = @($lsofLines | Where-Object { $_ -match '\(deleted\)' -and $_ -match '\bREG\b' -and $_ -notmatch 'memfd:pipewire|lttng|pulse' })
    if ($deletedExe.Count -gt 0) {
        Add-Finding 'HIGH' 'Anti-Forensics' 'Running Processes with Deleted Executable on Disk' `
            "Executables running from deleted inodes (file-less execution pattern): $($deletedExe[0..2] -join ' | ')" `
            @('T1070.004','T1027')
    }

    # 3d. Processes running from volatile/staging paths
    $suspProcPaths = @($psLines | Where-Object {
        $_ -match '(?i)(/tmp/\S|/dev/shm/\S|/var/tmp/\S|/run/shm/\S)' -and
        $_ -notmatch '(?i)(lttng|pipewire|pulse|dbus-|chrome-|firefox|snap\.|\.snap)'
    })
    if ($suspProcPaths.Count -gt 0) {
        $spSample = ($suspProcPaths | Select-Object -First 3 | ForEach-Object { $_.Trim() }) -join ' | '
        Add-Finding 'CRITICAL' 'Staging' `
            "$($suspProcPaths.Count) Process(es) Executing from Volatile Staging Path" `
            "Legitimate OS processes never run from /tmp, /dev/shm, or /var/tmp. Found: $spSample" `
            @('T1059.004','T1036.005')
        foreach ($sp in ($suspProcPaths | Select-Object -First 10)) {
            $spPath = if ($sp -match '(/(?:tmp|dev/shm|var/tmp|run/shm)/\S+)') { $Matches[1] -replace '\s.*$','' } else { '' }
            if ($spPath) { Add-IOC 'FilePath' $spPath "Process executing from staging path" }
        }
        Write-Host "         [CRITICAL] $($suspProcPaths.Count) process(es) running from staging paths" -ForegroundColor Red
    }

    # 3e. High-entropy / random-looking executable names (hex strings, base64 fragments)
    $randomNameProcs = @($psLines | Where-Object {
        $_ -match '\s/\S*/[a-f0-9]{10,}(\s|$)' -or $_ -match '\s/\S*/[A-Za-z0-9+/]{20,}={0,2}(\s|$)'
    } | Where-Object { $_ -notmatch '(?i)(kernel|kthread|udev|systemd|dbus|irq/)' })
    if ($randomNameProcs.Count -gt 0) {
        Add-Finding 'HIGH' 'Masquerading' `
            "$($randomNameProcs.Count) Process(es) with High-Entropy Executable Name" `
            "Hex-string or base64-like executable names indicate malware using randomized names to evade static detection: $($randomNameProcs | Select-Object -First 3 | ForEach-Object { $_.Trim() })" `
            @('T1036','T1027')
    }

    # 3f. Web/app server processes that have spawned a shell (webshell execution signature)
    # Includes shell wrappers and common renamed shell-copy patterns.
    $shellSpawnProcs = @($psLines | Where-Object {
        $_ -match '(?i)(apache2|nginx|httpd|tomcat|www-data|php-fpm|lighttpd|node\b|gunicorn|uwsgi)' -and
        $_ -match '(?i)(\bbash\b|\bsh\b|\bdash\b|\bzsh\b|\bksh\b|\bmksh\b|\bpdksh\b|\byash\b|\bash\b|\bhush\b|\bfish\b|\bbuyobu\b|\btmux\b|\bscreen\b|\bpython\b|\bperl\b|\bruby\b|\bnc\b|\bncat\b|\bsocat\b|/(?:tmp|dev/shm|var/tmp|run/shm)/\S*(?:bash|dash|zsh|ksh|mksh|pdksh|yash|ash|hush|fish|sh)\S*)'
    })
    if ($shellSpawnProcs.Count -gt 0) {
        Add-Finding 'CRITICAL' 'Webshell' `
            "Web Server Process Spawning Shell  -  Webshell Execution Indicator" `
            "Web/app server running an interactive shell/wrapper/interpreter: $($shellSpawnProcs | Select-Object -First 3 | ForEach-Object { $_.Trim() }). This is the runtime signature of active webshell post-exploitation (including shell wrappers or copied shell binaries)." `
            @('T1505.003','T1059.004')
        Write-Host "         [CRITICAL] Web server spawning shell - webshell execution indicator" -ForegroundColor Red
    }

    # ==========================================================================
    # MODULE 4  -  NETWORK ANALYSIS
    # ==========================================================================
    Write-Host "[LP-UAC] Module 4: Network analysis..." -ForegroundColor DarkCyan

    $ssLines     = Read-UACArtifactLines $uac 'live_response/network/ss_-tanp.txt'
    $lsofNetLines= Read-UACArtifactLines $uac 'live_response/network/lsof_-nPli.txt'
    $procNetTcp  = Read-UACArtifactLines $uac 'live_response/network/proc_net_tcp.txt'

    # Parse ss -tanp for established connections
    $connections = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($line in $ssLines) {
        if ($line -match '^ESTAB') {
            # State  Recv-Q Send-Q  LocalAddr:Port  PeerAddr:Port  Process
            if ($line -match 'ESTAB\s+\d+\s+\d+\s+(\S+)\s+(\S+)(.*)') {
                $local  = $Matches[1]
                $remote = $Matches[2]
                $procSection = $Matches[3]
                $proc   = if ($procSection -match 'users:\(\("([^"]+)"') { $Matches[1] } else { '' }
                $procPid= if ($procSection -match 'pid=(\d+)') { $Matches[1] } else { '' }
                $connections.Add([PSCustomObject]@{
                    Local      = $local
                    Remote     = $remote
                    Process    = $proc
                    ProcessPid = $procPid
                    Raw        = $line
                })
            }
        }
    }

    # Supplement with proc/net/tcp hex parsing
    $procTcpConns = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($line in $procNetTcp) {
        if ($line -match '^\s*\d+:') {
            $parts = $line.Trim() -split '\s+'
            if ($parts.Count -ge 10) {
                $localHex  = $parts[1]; $remHex = $parts[2]; $state = $parts[3]
                if ($localHex -match '^([a-fA-F0-9]{8}):([a-fA-F0-9]{4})$') {
                    $localIP   = Convert-HexToIP $Matches[1]
                    $localPort = Convert-HexToPort $Matches[2]
                    if ($remHex -match '^([a-fA-F0-9]{8}):([a-fA-F0-9]{4})$') {
                        $remIP    = Convert-HexToIP $Matches[1]
                        $remPort  = Convert-HexToPort $Matches[2]
                        $stateStr = Resolve-TCPState $state
                        $uid      = $parts[7]
                        $inode    = $parts[9]
                        if ($stateStr) {
                            $procTcpConns.Add([PSCustomObject]@{
                                LocalIP    = $localIP
                                LocalPort  = $localPort
                                RemoteIP   = $remIP
                                RemotePort = $remPort
                                State      = $stateStr
                                UID        = $uid
                                Inode      = $inode
                                Raw        = $line
                            })
                        }
                    }
                }
            }
        }
    }

    # C2 / suspicious connection analysis
    $suspiciousRemotes  = [System.Collections.Generic.List[string]]::new()
    $loopback           = @('127\.','::1')
    $stratum3333Flagged = $false

    # Also scan LISTEN lines for port 3333 (XMRig stratum)
    foreach ($rawLine in $ssLines) {
        if ($rawLine -match '^LISTEN' -and $rawLine -match ':3333\s') {
            if (-not $stratum3333Flagged) {
                $stratum3333Flagged = $true
                Add-Finding 'CRITICAL' 'Cryptominer' `
                    'Port 3333 Listening  -  XMRig Stratum Mining Proxy' `
                    "LISTEN on port 3333 detected. Port 3333 is the default XMRig Monero stratum mining port. Active ESTABLISHED loopback connections on this port confirm a running miner routing traffic through a local proxy." `
                    @('T1496')
                Add-IOC 'Port' '3333' 'XMRig stratum mining proxy'
                Add-Timeline '(At collection)' 'CRITICAL' 'XMRig stratum proxy LISTENING on port 3333' ''
            }
        }
    }

    # ss lines with no owning process can indicate hidden sockets/rootkit interference
    $estabNoOwner = @($connections | Where-Object { -not $_.Process })
    if ($estabNoOwner.Count -gt 0) {
        $noOwnerSample = ($estabNoOwner | Select-Object -First 4 | ForEach-Object { $_.Raw.Trim() }) -join ' | '
        Add-Finding 'HIGH' 'Process Hiding' `
            "$($estabNoOwner.Count) ESTABLISHED Network Connection(s) Without Owning Process in ss" `
            "ESTABLISHED sockets are present but `ss -p` did not provide process ownership. This is suspicious when combined with hidden PIDs/rootkit activity. Sample: $noOwnerSample" `
            @('T1564.001','T1049')
    }

    $unattributedOutboundSSH = @($estabNoOwner | Where-Object {
        $_.Remote -match ':(22)$' -and $_.Local -match ':(\d+)$' -and [int]$Matches[1] -gt 1024
    })
    if ($unattributedOutboundSSH.Count -gt 0) {
        foreach ($ua in $unattributedOutboundSSH) {
            if ($ua.Remote -match '^([\d.]+):22$') {
                Add-IOC 'IP:Port' "$($Matches[1]):22" 'Outbound SSH without owning process in ss'
                [void]$suspiciousRemotes.Add($Matches[1])
            }
        }
        $uaSample = ($unattributedOutboundSSH | Select-Object -First 3 | ForEach-Object { $_.Raw.Trim() }) -join ' | '
        Add-Finding 'CRITICAL' 'C2 Communication' `
            'Outbound SSH Session(s) Without Process Owner  -  Hidden C2 Likely' `
            "Outbound ESTABLISHED SSH from ephemeral local ports appears in ss output without process attribution. This is strong evidence of hidden C2 tunneling. Sample: $uaSample" `
            @('T1071.001','T1564.001')
    }

    # Corroborate with proc/net/tcp ownership metadata (UID/inode)
    $procRootListen3333 = @($procTcpConns | Where-Object {
        $_.State -eq 'LISTEN' -and $_.LocalPort -eq 3333 -and $_.UID -eq '0'
    })
    if ($procRootListen3333.Count -gt 0) {
        $inodeList = ($procRootListen3333 | Select-Object -ExpandProperty Inode | Select-Object -Unique) -join ', '
        Add-Finding 'CRITICAL' 'Cryptominer' `
            'Root-Owned Port 3333 Listener in /proc/net/tcp' `
            "Port 3333 LISTEN socket is owned by UID 0 in /proc/net/tcp (inode(s): $inodeList). This corroborates an active root-level stratum/miner proxy even when process mapping is missing." `
            @('T1496','T1014')
        Add-IOC 'Port' '3333' "Root-owned LISTEN in /proc/net/tcp (inode: $inodeList)"
    }

    $procRootOutboundSSH = @($procTcpConns | Where-Object {
        $_.State -eq 'ESTABLISHED' -and $_.RemotePort -eq 22 -and $_.LocalPort -gt 1024 -and
        $_.UID -eq '0' -and $_.RemoteIP -and $_.RemoteIP -ne '0.0.0.0' -and $_.RemoteIP -notmatch '^127\.'
    })
    if ($procRootOutboundSSH.Count -gt 0) {
        $rbSample = ($procRootOutboundSSH | Select-Object -First 3 | ForEach-Object {
            "$($_.LocalIP):$($_.LocalPort) -> $($_.RemoteIP):$($_.RemotePort) (uid=$($_.UID), inode=$($_.Inode))"
        }) -join ' | '
        Add-Finding 'CRITICAL' 'C2 Communication' `
            'Root-Owned Outbound SSH Connection in /proc/net/tcp' `
            "Root-owned ESTABLISHED outbound SSH socket(s) detected directly in /proc/net/tcp: $rbSample" `
            @('T1071.001','T1021.004')
        foreach ($rb in $procRootOutboundSSH) {
            Add-IOC 'IP:Port' "$($rb.RemoteIP):$($rb.RemotePort)" "Root-owned outbound SSH socket (inode $($rb.Inode))"
            [void]$suspiciousRemotes.Add($rb.RemoteIP)
        }
    }

    foreach ($conn in $connections) {
        $remote = $conn.Remote
        if ($remote -eq '0.0.0.0:*' -or $remote -eq '[::]:*') { continue }

        # Extract IP and port
        $remIP = $remPort = ''
        if ($remote -match '^([\d.]+):(\d+)$') {
            $remIP = $Matches[1]; $remPort = $Matches[2]
        } elseif ($remote -match '^\[(.+)\]:(\d+)$') {
            $remIP = $Matches[1]; $remPort = $Matches[2]
        }

        if (-not $remIP) { continue }

        # Port 22 outbound (any non-loopback, including RFC1918 - common in lab/enterprise C2)
        if ($remPort -eq '22' -and -not ($loopback | Where-Object { $remIP -match $_ })) {
            # Determine if this is same-host incoming (sshd serving a client) or outgoing C2
            # Outgoing: Local port is ephemeral (>1024 and not 22)
            $localPort = if ($conn.Local -match ':(\d+)$') { [int]$Matches[1] } else { 0 }
            if ($localPort -gt 1024) {
                Add-Finding 'CRITICAL' 'C2 Communication' `
                    "Outbound SSH Tunnel to ${remIP}:22  -  Likely Miner C2" `
                    "ESTABLISHED outbound SSH from ephemeral port $localPort to ${remIP}:22. Process: $($conn.Process). Port 22 outbound from a non-SSH-daemon process is a documented TeamTNT/cryptominer C2 technique to tunnel mining traffic through SSH and blend with legitimate traffic." `
                    @('T1071.001')
                Add-IOC 'IP:Port' "${remIP}:22" 'Outbound SSH  -  likely miner C2'
                [void]$suspiciousRemotes.Add($remIP)
                Add-Timeline '(At collection)' 'CRITICAL' "Outbound SSH C2 to ${remIP}:22 (src port $localPort)" ''
            }
        }

        # Stratum loopback ESTAB also confirms active mining
        if ($conn.Local -match ':3333$' -and -not $stratum3333Flagged) {
            $stratum3333Flagged = $true
            Add-Finding 'CRITICAL' 'Cryptominer' `
                'XMRig Stratum ESTABLISHED on Loopback:3333' `
                "Active ESTABLISHED connection on 127.0.0.1:3333 confirms XMRig miner is actively submitting work to its stratum proxy." `
                @('T1496')
        }
    }

    # 4b. Miner pool port detection (broad stratum port range + common C2 ports)
    $minerPorts = @(3333,3334,3335,4444,5555,7777,8888,9999,14444,14433,45700,2222,1080)
    $highRiskPorts = @(4444,1234,31337,6666,6667,6668,6669,8080,8443,9001,9050)  # also covers IRC C2 / Tor
    $allListenLines = @($ssLines | Where-Object { $_ -match '^LISTEN' })
    $allEstabLines  = @($ssLines | Where-Object { $_ -match '^ESTAB'  })

    foreach ($port in $minerPorts) {
        $listenHit = $allListenLines | Where-Object { $_ -match ":$port\s" }
        $estabHit  = $allEstabLines  | Where-Object { $_ -match ":$port\b" }
        if (($listenHit -or $estabHit) -and $port -ne 3333) {  # 3333 already handled
            Add-Finding 'HIGH' 'Cryptominer' `
                "Known Miner Stratum Port $port Active" `
                "Port $port is in the known stratum/mining-pool port list. LISTEN or ESTABLISHED connection detected. Verify the owning process is not an XMRig variant or mining pool proxy." `
                @('T1496')
            Add-IOC 'Port' "$port" "Known miner stratum port"
        }
    }

    # 4c. IRC / botnet C2 port detection
    $ircPorts = @(6667,6668,6669,6697)
    foreach ($port in $ircPorts) {
        if ($allEstabLines | Where-Object { $_ -match ":$port\b" }) {
            Add-Finding 'HIGH' 'C2 Communication' `
                "IRC Botnet C2 Port $port Active" `
                "ESTABLISHED outbound connection on port $port — standard IRC bot C2 channel (Mirai, Tsunami, generic IRC bots). Investigate owning process." `
                @('T1071.003')
            Add-IOC 'Port' "$port" "IRC botnet C2 port"
        }
    }

    # 4d. DNS-over-non-53 (DoH evasion) and suspicious listening services
    $dohHits = @($allEstabLines | Where-Object { $_ -match ':443\b' -and $_ -match '127\.' })
    if ($dohHits.Count -gt 0) {
        Add-Finding 'MEDIUM' 'C2 Communication' `
            'HTTPS Traffic on Loopback  -  Possible DoH/Encrypted Tunnel Proxy' `
            "ESTABLISHED HTTPS (443) connections on loopback interface may indicate a local proxy routing C2 traffic through encrypted DNS-over-HTTPS or HTTPS tunnels to evade detection." `
            @('T1071.004','T1090')
    }

    # 4e. Reverse shell indicator — any outbound non-standard port from unknown process
    $revShellHits = @($allEstabLines | Where-Object {
        $_ -notmatch 'sshd|ssh-session|cupsd|avahi|NetworkMa|wireplumb|pipewire|firefox|chrome' -and
        $_ -match 'ESTAB' -and
        $_ -notmatch ':22\b' -and $_ -notmatch ':443\b' -and $_ -notmatch ':80\b' -and
        $_ -notmatch '127\.' -and $_ -notmatch '0\.0\.0\.0'
    })
    if ($revShellHits.Count -gt 0) {
        $sample = ($revShellHits | Select-Object -First 3 | ForEach-Object { $_.Trim() }) -join ' | '
        Add-Finding 'MEDIUM' 'C2 Communication' `
            "$($revShellHits.Count) Unexplained Outbound Connection(s)  -  Possible Reverse Shell" `
            "Outbound ESTABLISHED connections on non-standard ports from unrecognized processes: $sample" `
            @('T1059.004','T1071.001')
    }

    # Extract all unique remote IPs for intel lookup (done in module 5)
    $allRemoteIPs = @(
        $connections | ForEach-Object {
            if ($_.Remote -match '^([\d.]+):\d+') { $Matches[1] }
        }
        $procTcpConns | Where-Object {
            $_.State -eq 'ESTABLISHED' -and $_.RemoteIP -and $_.RemoteIP -ne '0.0.0.0'
        } | Select-Object -ExpandProperty RemoteIP
    ) | Sort-Object -Unique | Where-Object { $_ -and $_ -ne '0.0.0.0' }

    # 4f. IPv6 connections from /proc/net/tcp6
    $procNetTcp6 = Read-UACArtifactLines $uac 'live_response/network/proc_net_tcp6.txt'
    $ipv6EstabCount = 0
    foreach ($line in $procNetTcp6) {
        if ($line -match '^\s*\d+:') {
            $parts = $line.Trim() -split '\s+'
            if ($parts.Count -ge 4) {
                $remHex6 = $parts[2]; $state6 = $parts[3]
                if ($remHex6 -match '^([a-fA-F0-9]{32}):([a-fA-F0-9]{4})$') {
                    $remIP6   = Convert-HexToIPv6 $Matches[1]
                    $remPort6 = Convert-HexToPort $Matches[2]
                    $stateStr6 = Resolve-TCPState $state6
                    if ($stateStr6 -eq 'ESTABLISHED' -and $remIP6 -and
                        $remIP6 -ne '::1' -and $remIP6 -ne '::' -and $remIP6 -notmatch '^::ffff:127\.' ) {
                        $ipv6EstabCount++
                        Add-IOC 'IPv6' $remIP6 "IPv6 ESTABLISHED connection (port $remPort6)"
                        # Intel check
                        $hit6 = Test-IntelHit $remIP6
                        if ($hit6) {
                            Add-Finding 'CRITICAL' 'Intel Hit' `
                                "IPv6 Connection to Known Threat Actor IP: $remIP6 (port $remPort6)" `
                                "IPv6 $remIP6 matches Actor: $($hit6.Actor) | Source: $($hit6.Source) | Context: $($hit6.Context)" `
                                @('T1071.001')
                            Add-IOC 'IPv6' $remIP6 "Intel-matched C2 IPv6" $hit6.Actor
                        }
                        # Miner port check
                        if ($minerPorts -contains $remPort6) {
                            Add-Finding 'HIGH' 'Cryptominer' `
                                "Miner Stratum Port $remPort6 Active (IPv6: $remIP6)" `
                                "IPv6 ESTABLISHED connection on known stratum/mining port $remPort6." `
                                @('T1496')
                        }
                    }
                }
            }
        }
    }
    if ($ipv6EstabCount -gt 0) {
        Add-Finding 'MEDIUM' 'C2 Communication' `
            "$ipv6EstabCount IPv6 ESTABLISHED Connection(s) Detected" `
            "Active IPv6 connections found in /proc/net/tcp6. IPv6 is frequently overlooked in network monitoring. Review Add-IOC entries for details." `
            @('T1071.001')
        Write-Host "         $ipv6EstabCount IPv6 ESTABLISHED connection(s) found in tcp6" -ForegroundColor DarkYellow
    }

    # 4g. Promiscuous mode detection (passive packet sniffer / Penquin Turla / BPFDoor indicator)
    $ifconfigRaw = Read-UACArtifact $uac 'live_response/network/ifconfig.txt'
    if (-not $ifconfigRaw) { $ifconfigRaw = Read-UACArtifact $uac 'live_response/network/ifconfig_-a.txt' }
    $ipAddrRaw   = Read-UACArtifact $uac 'live_response/network/ip_address.txt'
    $promiscSrc  = ''
    if      ($ifconfigRaw -and $ifconfigRaw -match '\bPROMISC\b') { $promiscSrc = 'ifconfig' }
    elseif  ($ipAddrRaw   -and $ipAddrRaw   -match '\bPROMISC\b') { $promiscSrc = 'ip addr'  }
    if ($promiscSrc) {
        $srcRaw = if ($promiscSrc -eq 'ifconfig') { $ifconfigRaw } else { $ipAddrRaw }
        $promiscIfaces = @($srcRaw -split '\n' | Where-Object { $_ -match '\bPROMISC\b' } |
            ForEach-Object { if ($_ -match '^(\S+)') { $Matches[1] } })
        $promiscStr = if ($promiscIfaces.Count -gt 0) { $promiscIfaces -join ', ' } else { "(see $promiscSrc)" }
        Add-Finding 'HIGH' 'Rootkit' `
            "Network Interface in Promiscuous Mode: $promiscStr" `
            "PROMISC flag detected via $promiscSrc on interface(s): $promiscStr. Promiscuous mode indicates an active raw packet sniffer. This is the passive C2 mechanism for Penquin Turla (raw TCP packet magic knock) and a secondary indicator for BPFDoor. No open port is required - invisible to ss/netstat/lsof." `
            @('T1040','T1014')
        Add-IOC 'Network' $promiscStr 'Promiscuous mode - passive sniffer active'
        Write-Host "         [HIGH] Promiscuous mode: $promiscStr ($promiscSrc)" -ForegroundColor Yellow
    }

    # 4h. Multi-signal compromise correlation for higher-confidence triage output
    $hasCovertNetSignal = ($procRootOutboundSSH.Count -gt 0) -or ($unattributedOutboundSSH.Count -gt 0) -or
                          ($stratum3333Flagged) -or ($procRootListen3333.Count -gt 0)
    if ($preloadLibs.Count -gt 0 -and $hiddenPids.Count -gt 0 -and $hasCovertNetSignal) {
        Add-Finding 'CRITICAL' 'Correlation' `
            'LD_PRELOAD Rootkit + Hidden PIDs + Covert Network Activity (High-Confidence Active Compromise)' `
            "Independent signals converge: /etc/ld.so.preload rootkit, hidden process set ($($hiddenPids -join ', ')), and covert/unattributed network behavior (SSH tunneling and/or local stratum proxy). This is a high-confidence active compromise pattern." `
            @('T1014','T1564.001','T1071.001','T1496')
        Add-Timeline '(At collection)' 'CRITICAL' 'Rootkit + hidden processes + covert sockets correlated' '/etc/ld.so.preload'
    }

    # ==========================================================================
    # MODULE 5  -  HASH INTEL LOOKUP (OFFLINE)
    # ==========================================================================
    Write-Host "[LP-UAC] Module 5: Hash intel lookup (offline)..." -ForegroundColor DarkCyan

    # 5a. Build intel index — single flat hashtable, all IOC types, three source passes
    # NOTE: Previously domains/filenames were routed to separate dead indexes ($domainIndex/$fileNameIndex)
    #       and never matched. Fixed: everything goes into $intelIndex, lookup functions use $intelIndex.
    $intelIndex = @{}   # key: IOC value (hash/IP/domain/filename) -> PSCustomObject
    $intelCount = 0

    # Country/region folder names — used to infer actor name from filename when file is at country level
    $regionFolders = @('Russia','China','NorthKorea','Iran','eCrime','Vietnam','SouthAmerica','Picus','APTs','Malware Families')

    if ($IntelBasePath -and (Test-Path $IntelBasePath)) {

        # ---- PASS 1: *_Master_Intel.csv  (Date,Source,Actor,IOCType,IOCValue,Context,Link) ---------------
        $masterFiles = @(Get-ChildItem $IntelBasePath -Recurse -Filter '*_Master_Intel.csv' -ErrorAction SilentlyContinue)
        Write-Host "         Pass 1 of 3: $($masterFiles.Count) Master_Intel CSVs..." -ForegroundColor DarkGray
        foreach ($csvFile in $masterFiles) {
            try {
                $rows = Import-Csv $csvFile.FullName -Encoding UTF8 -ErrorAction SilentlyContinue
                foreach ($row in $rows) {
                    $iocType  = if ($row.IOCType)  { $row.IOCType  -replace '\s','' } else { '' }
                    $iocValue = if ($row.IOCValue) { $row.IOCValue -replace '\s','' } else { '' }
                    if (-not $iocValue) { continue }
                    $key = $iocValue.ToLower()
                    if (-not $intelIndex.ContainsKey($key)) {
                        $intelIndex[$key] = [PSCustomObject]@{
                            IOCType  = $iocType; IOCValue = $iocValue
                            Actor    = $row.Actor; Source = $row.Source
                            Context  = $row.Context; Date = $row.Date
                        }
                        $intelCount++
                    }
                    # For URL entries also index the bare hostname so Test-IntelDomain finds them
                    if ($iocType -match '(?i)^url$' -and $iocValue -match '(?i)(?:https?://)?([a-z0-9][a-z0-9\-\.]+\.[a-z]{2,})') {
                        $hkey = $Matches[1].ToLower()
                        if (-not $intelIndex.ContainsKey($hkey)) {
                            $intelIndex[$hkey] = [PSCustomObject]@{
                                IOCType  = 'Domain'; IOCValue = $Matches[1]
                                Actor    = $row.Actor; Source = $row.Source
                                Context  = $row.Context; Date = $row.Date
                            }
                            $intelCount++
                        }
                    }
                }
            } catch { }
        }
        $countAfterPass1 = $intelCount
        Write-Host "         Pass 1 done: $countAfterPass1 entries" -ForegroundColor DarkGray

        # ---- PASS 2: Dated IOC CSVs  (IOC,Type,Sources,Max confidence,Last Seen,Detection count) ---------
        # e.g. apt28_2025-11-08.csv, lazarus_IOCs_2025-11-07.csv — not matched by *_Master_Intel filter
        $iocFiles = @(Get-ChildItem $IntelBasePath -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -eq '.csv' -and $_.Name -match '\d{4}-\d{2}-\d{2}' -and
                           $_.Name -notmatch '_Master_Intel' -and $_.Name -notmatch 'Targeted_Analysis_Map' })
        Write-Host "         Pass 2 of 3: $($iocFiles.Count) supplemental IOC CSVs..." -ForegroundColor DarkGray
        foreach ($iocFile in $iocFiles) {
            try {
                $parentFolder = Split-Path (Split-Path $iocFile.FullName -Parent) -Leaf
                $actorName = if ($regionFolders -notcontains $parentFolder) {
                    $parentFolder
                } else {
                    ($iocFile.BaseName -replace '(?i)_IOCs?$','' -replace '(?i)_\d{4}-\d{2}-\d{2}.*$','' `
                                       -replace '(?i)_deduplicated$','' -replace '_',' ').Trim()
                }
                $rows = Import-Csv $iocFile.FullName -Encoding UTF8 -ErrorAction SilentlyContinue
                foreach ($row in $rows) {
                    $iocVal = if ($row.IOC) { $row.IOC.Trim() } else { '' }
                    if (-not $iocVal) { continue }
                    $key = $iocVal.ToLower()
                    if (-not $intelIndex.ContainsKey($key)) {
                        $iocType2 = if ($row.Type) { $row.Type.Trim() } else { 'Unknown' }
                        $ctx2 = "Confidence:$($row.'Max confidence') | Detections:$($row.'Detection count')"
                        $intelIndex[$key] = [PSCustomObject]@{
                            IOCType  = $iocType2; IOCValue = $iocVal
                            Actor    = $actorName; Source = $row.Sources
                            Context  = $ctx2; Date = $row.'Last Seen'
                        }
                        $intelCount++
                    }
                }
            } catch { }
        }
        $countAfterPass2 = $intelCount
        Write-Host "         Pass 2 done: $($countAfterPass2 - $countAfterPass1) new entries from $($iocFiles.Count) files" -ForegroundColor DarkGray

        # ---- PASS 3: Targeted_Analysis_Map.csv  (Indicator_Type,Unique_Item,File_Hash,Malware_Family,Meaningful_Name,Last_Observation_Date) ---
        # One per actor folder. Potentially 3M+ SHA256 hashes total.
        # Uses fast line-reader + regex instead of Import-Csv to avoid multi-minute parse time.
        $tamFiles = @(Get-ChildItem $IntelBasePath -Recurse -Filter 'Targeted_Analysis_Map.csv' -ErrorAction SilentlyContinue)
        Write-Host "         Pass 3 of 3: $($tamFiles.Count) Targeted_Analysis_Map files (large dataset, please wait)..." -ForegroundColor DarkGray
        $tamFileNum = 0
        foreach ($tamFile in $tamFiles) {
            $tamFileNum++
            if ($tamFileNum % 25 -eq 0) {
                Write-Host "           [$tamFileNum/$($tamFiles.Count)] $intelCount entries indexed..." -ForegroundColor DarkGray
            }
            try {
                $actorFolder = Split-Path (Split-Path $tamFile.FullName -Parent) -Leaf
                $rawLines = [System.IO.File]::ReadAllLines($tamFile.FullName, [System.Text.Encoding]::UTF8)
                foreach ($rawLine in $rawLines) {
                    # Quick length gate before regex (64-char hex in quotes = at least 66 chars on line)
                    if ($rawLine.Length -lt 66) { continue }
                    if ($rawLine -notmatch '"([a-fA-F0-9]{64})"') { continue }
                    $hash = $Matches[1].ToLower()
                    if ($intelIndex.ContainsKey($hash)) { continue }
                    # Extract Malware_Family (col 4) and Meaningful_Name (col 5) with a full-line regex
                    $actor2 = $actorFolder
                    $ctx3   = ''
                    if ($rawLine -match '"[^"]*","[^"]*","[a-fA-F0-9]{64}","([^"]*?)","([^"]*?)"') {
                        $mf = $Matches[1]; $mn = $Matches[2]
                        if ($mf -and $mf -ne 'Unknown') { $actor2 = $mf }
                        $ctx3 = $mn
                    }
                    $intelIndex[$hash] = [PSCustomObject]@{
                        IOCType  = 'SHA256'; IOCValue = $hash
                        Actor    = $actor2; Source = 'Targeted_Analysis_Map'
                        Context  = $ctx3; Date = ''
                    }
                    $intelCount++
                }
            } catch { }
        }
        $countTAM = $intelCount - $countAfterPass2
        Write-Host "         Pass 3 done: $countTAM new entries from $($tamFiles.Count) files" -ForegroundColor DarkGray
        Write-Host ("         Intel index ready: {0:N0} total entries  [Master:{1:N0} | IOC:{2:N0} | TAM:{3:N0}]" -f `
            $intelCount, $countAfterPass1, ($countAfterPass2 - $countAfterPass1), $countTAM) -ForegroundColor Gray
    }

    function Test-IntelHit {
        param([string]$Value)
        if (-not $Value) { return $null }
        return $intelIndex[$Value.ToLower().Trim()]
    }

    # Domain intel lookup - handles subdomain stripping (uses same $intelIndex)
    function Test-IntelDomain {
        param([string]$Value)
        if (-not $Value) { return $null }
        $v = $Value.ToLower().Trim() -replace '^https?://','' -replace '/.*$','' -replace ':\d+$',''
        $hit = $intelIndex[$v]
        if ($hit) { return $hit }
        # Strip one subdomain level and retry (e.g. c2.evil.com -> evil.com)
        if ($v -match '^[^.]+\.(.+\..+)$') { $hit = $intelIndex[$Matches[1]]; if ($hit) { return $hit } }
        return $null
    }

    # Filename intel lookup - matches by basename, min 5 chars to reduce false positives
    function Test-IntelFileName {
        param([string]$Value)
        if (-not $Value) { return $null }
        $bname = ($Value -split '[/\\]')[-1].ToLower().Trim()
        if ($bname.Length -lt 5) { return $null }
        return $intelIndex[$bname]
    }

    # 5b. Hash running processes
    $runProcHashes = Read-UACArtifactLines $uac 'live_response/process/hash_running_processes.md5'
    $runProcHitCount = 0
    foreach ($line in $runProcHashes) {
        if ($line -match '^([a-fA-F0-9]{32})\s+(.+)') {
            $hash = $Matches[1].ToLower()
            $path = $Matches[2].Trim()
            $hit  = Test-IntelHit $hash
            if ($hit) {
                $runProcHitCount++
                Add-Finding 'CRITICAL' 'Intel Hit' `
                    "Running Process Hash MATCHES Threat Intel: $path" `
                    "MD5 $hash for $path matches Actor: $($hit.Actor) | Source: $($hit.Source) | Context: $($hit.Context)" `
                    @('T1027')
                Add-IOC 'MD5' $hash "Running process match  -  $path" $hit.Actor
                Add-Timeline "(At collection)" 'CRITICAL' "Intel-matched process running: $path ($($hit.Actor))" $path
            }
        }
    }

    # 5c. Executable hashes (hash_executables)
    $exeHashLines = Read-UACArtifactLines $uac 'hash_executables/hash_executables.md5'
    $exeHitCount  = 0
    foreach ($line in $exeHashLines) {
        if ($line -match '^([a-fA-F0-9]{32})\s+(.+)') {
            $hash = $Matches[1].ToLower()
            $path = $Matches[2].Trim()
            $hit  = Test-IntelHit $hash
            if ($hit) {
                $exeHitCount++
                Add-Finding 'CRITICAL' 'Intel Hit' `
                    "Executable Hash MATCHES Threat Intel: $path" `
                    "MD5 $hash for $path  -  Actor: $($hit.Actor) | Source: $($hit.Source) | Context: $($hit.Context)" `
                    @('T1027')
                Add-IOC 'MD5' $hash "Executable match  -  $path" $hit.Actor
            }
        }
    }

    # 5d. SHA1 hashes for running processes
    $runProcSHA1 = Read-UACArtifactLines $uac 'live_response/process/hash_running_processes.sha1'
    foreach ($line in $runProcSHA1) {
        if ($line -match '^([a-fA-F0-9]{40})\s+(.+)') {
            $hash = $Matches[1].ToLower()
            $path = $Matches[2].Trim()
            $hit  = Test-IntelHit $hash
            if ($hit) {
                $runProcHitCount++
                Add-Finding 'CRITICAL' 'Intel Hit' `
                    "Running Process SHA1 MATCHES Threat Intel: $path" `
                    "SHA1 $hash for $path  -  Actor: $($hit.Actor) | Context: $($hit.Context)" `
                    @('T1027')
                Add-IOC 'SHA1' $hash "Running process SHA1 match  -  $path" $hit.Actor
            }
        }
    }

    # 5d2. SHA256 hashes for executables on disk
    $exeSHA256Lines = Read-UACArtifactLines $uac 'hash_executables/hash_executables.sha256'
    foreach ($line in $exeSHA256Lines) {
        if ($line -match '^([a-fA-F0-9]{64})\s+(.+)') {
            $hash = $Matches[1].ToLower()
            $path = $Matches[2].Trim()
            $hit  = Test-IntelHit $hash
            if ($hit) {
                $exeHitCount++
                Add-Finding 'CRITICAL' 'Intel Hit' `
                    "Executable SHA256 MATCHES Threat Intel: $path" `
                    "SHA256 $hash for $path  -  Actor: $($hit.Actor) | Source: $($hit.Source) | Context: $($hit.Context)" `
                    @('T1027')
                Add-IOC 'SHA256' $hash "Executable SHA256 match  -  $path" $hit.Actor
            }
        }
    }

    # 5d3. SHA256 hashes for running processes
    $runProcSHA256 = Read-UACArtifactLines $uac 'live_response/process/hash_running_processes.sha256'
    foreach ($line in $runProcSHA256) {
        if ($line -match '^([a-fA-F0-9]{64})\s+(.+)') {
            $hash = $Matches[1].ToLower()
            $path = $Matches[2].Trim()
            $hit  = Test-IntelHit $hash
            if ($hit) {
                $runProcHitCount++
                Add-Finding 'CRITICAL' 'Intel Hit' `
                    "Running Process SHA256 MATCHES Threat Intel: $path" `
                    "SHA256 $hash for $path  -  Actor: $($hit.Actor) | Context: $($hit.Context)" `
                    @('T1027')
                Add-IOC 'SHA256' $hash "Running process SHA256 match  -  $path" $hit.Actor
                Add-Timeline '(At collection)' 'CRITICAL' "Intel-matched process (SHA256): $path ($($hit.Actor))" $path
            }
        }
    }

    # 5e. IP intel lookup
    foreach ($ip in $allRemoteIPs) {
        $hit = Test-IntelHit $ip
        if ($hit) {
            Add-Finding 'CRITICAL' 'Intel Hit' `
                "Network Connection to Known Threat Actor IP: $ip" `
                "IP $ip matches Actor: $($hit.Actor) | Source: $($hit.Source) | Context: $($hit.Context)" `
                @('T1071.001')
            Add-IOC 'IP' $ip "Intel-matched C2 IP" $hit.Actor
        }
    }

    $totalHits = $runProcHitCount + $exeHitCount
    if ($totalHits -gt 0) {
        Write-Host "         [CRITICAL] $totalHits intel hits found!" -ForegroundColor Red
    } else {
        Write-Host "         No direct hash matches (compile-on-victim evasion expected)" -ForegroundColor DarkGray
        $totalExeChecked  = $exeHashLines.Count  + $exeSHA256Lines.Count
        $totalProcChecked = $runProcHashes.Count + $runProcSHA256.Count
        Add-Finding 'INFO' 'Intel Lookup' 'No Direct Hash Matches  -  Compile-On-Victim Evasion Likely' `
            "All $totalExeChecked executable and $totalProcChecked running-process hashes (MD5/SHA1/SHA256) were checked against $intelCount intel entries with no direct matches. This is consistent with the TeamTNT pattern of compiling rootkit libraries on the victim to produce unique hashes that defeat hash-based detection. Look for behavioral TTP matches instead." `
            @()
    }

    # 5f. Domain intel lookup (process cmdlines + shell history)
    Write-Host "         Checking domain intel..." -ForegroundColor DarkGray
    $domainPattern   = '[a-z0-9][a-z0-9\-\.]{4,}\.[a-z]{2,6}'
    $domainSafeList  = '(?i)(ubuntu\.com|debian\.org|github\.com|githubusercontent|pypi\.org|docker\.io|snap\.io|security\.ubuntu|archive\.ubuntu|packages\.|mirrors\.|apt\.|snapcraft\.io|nodejs\.org|npmjs\.com|cloudflare\.com|1\.1\.1\.1|8\.8\.8\.8)'
    $domainCandidates = [System.Collections.Generic.List[string]]::new()

    # Extract from process cmdlines
    $procCmdlineRoot = Join-Path $uac 'live_response/process/proc'
    if (Test-Path -LiteralPath $procCmdlineRoot) {
        $cmdlineFiles = Get-ChildItem -LiteralPath $procCmdlineRoot -Recurse -Filter 'cmdline.txt' -ErrorAction SilentlyContinue
        foreach ($clf in $cmdlineFiles) {
            $cmdContent = Get-Content -LiteralPath $clf.FullName -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
            if ($cmdContent) {
                $cmdContent = $cmdContent -replace '\x00',' '
                foreach ($m in [regex]::Matches($cmdContent, $domainPattern)) { [void]$domainCandidates.Add($m.Value) }
            }
        }
    }
    # Extract from shell histories (bash/zsh/ksh/mksh/ash/hush/fish/byobu) - all users
    $histPathsForDomains = Get-UACShellHistoryPaths -Base $uac
    foreach ($histPath in $histPathsForDomains) {
        $hist = Read-UACArtifact $uac $histPath
        if ($hist) {
            foreach ($m in [regex]::Matches($hist, 'https?://(' + $domainPattern + ')')) {
                [void]$domainCandidates.Add($m.Groups[1].Value)
            }
            foreach ($m in [regex]::Matches($hist, $domainPattern)) {
                [void]$domainCandidates.Add($m.Value)
            }
        }
    }

    $uniqueDomains = @($domainCandidates | ForEach-Object { $_.ToLower() } | Sort-Object -Unique |
        Where-Object { $_ -and $_ -notmatch $domainSafeList })
    $domainHitCount = 0
    foreach ($domain in $uniqueDomains) {
        $hit = Test-IntelDomain $domain
        if ($hit) {
            $domainHitCount++
            Add-Finding 'CRITICAL' 'Intel Hit' `
                "Domain Matches Threat Intel: $domain" `
                "Domain '$domain' seen in process cmdlines/shell history matches Actor: $($hit.Actor) | Source: $($hit.Source) | Context: $($hit.Context)" `
                @('T1071.001','T1071.004')
            Add-IOC 'Domain' $domain "Intel-matched C2 domain" $hit.Actor
            Add-Timeline '(At collection)' 'CRITICAL' "Intel-matched domain contacted: $domain ($($hit.Actor))" ''
        }
    }
    if ($domainHitCount -gt 0) {
        Write-Host "         [CRITICAL] $domainHitCount domain intel hit(s)!" -ForegroundColor Red
    } else {
        Write-Host "         $($uniqueDomains.Count) unique domain(s) checked - no matches" -ForegroundColor DarkGray
    }

    # 5g. Filename intel lookup (disk executables + running processes)
    Write-Host "         Checking filename intel..." -ForegroundColor DarkGray
    $fileNameSeen    = @{}
    $fileNameHitCount = 0
    $allExePaths = @($exeHashLines | ForEach-Object {
        if ($_ -match '^[a-fA-F0-9]{32}\s+(.+)') { $Matches[1].Trim() }
    }) + @($runProcHashes | ForEach-Object {
        if ($_ -match '^[a-fA-F0-9]{32}\s+(.+)') { $Matches[1].Trim() }
    })
    foreach ($exePath in $allExePaths) {
        if (-not $exePath) { continue }
        $bn = ($exePath -split '[/\\]')[-1].ToLower().Trim()
        if (-not $bn -or $fileNameSeen.ContainsKey($bn)) { continue }
        $fileNameSeen[$bn] = $true
        $hit = Test-IntelFileName $bn
        if ($hit) {
            $fileNameHitCount++
            Add-Finding 'HIGH' 'Intel Hit' `
                "Executable Filename Matches Threat Intel: $bn" `
                "File '$bn' at path '$exePath' matches Actor: $($hit.Actor) | Source: $($hit.Source) | Context: $($hit.Context)" `
                @('T1036','T1027')
            Add-IOC 'FileName' $bn "Intel-matched filename: $exePath" $hit.Actor
        }
    }
    if ($fileNameHitCount -gt 0) {
        Write-Host "         [HIGH] $fileNameHitCount filename intel hit(s)!" -ForegroundColor Yellow
    } else {
        Write-Host "         $($fileNameSeen.Count) unique filename(s) checked - no matches" -ForegroundColor DarkGray
    }

    # ==========================================================================
    # MODULE 6  -  PERSISTENCE ANALYSIS
    # ==========================================================================
    Write-Host "[LP-UAC] Module 6: Persistence analysis..." -ForegroundColor DarkCyan

    $persistenceFound = $false

    # 6a. ld.so.preload (already found in module 2  -  flag here for completeness)
    if ($preloadLibs.Count -gt 0) {
        $persistenceFound = $true
        Add-Finding 'CRITICAL' 'Persistence' '/etc/ld.so.preload Persistence (Boot-Surviving Rootkit Load)' `
            "/etc/ld.so.preload ensures $($preloadLibs -join ', ') is injected into every process every boot. Survives reboots indefinitely until explicitly removed by root." `
            @('T1574.006')
    }

    # 6b. Cron jobs
    $cronPaths = @(
        '[root]/etc/crontab',
        '[root]/etc/anacrontab'
    )
    $cronDirs = @('[root]/etc/cron.d','[root]/etc/cron.daily','[root]/etc/cron.hourly',
                  '[root]/etc/cron.weekly','[root]/etc/cron.monthly')

    foreach ($cp in $cronPaths) {
        $content = Read-UACArtifact $uac $cp
        if ($content -and $content -match '(?i)(wget|curl|bash|sh|python|perl|nc |ncat|/dev/shm|/tmp)') {
            $persistenceFound = $true
            Add-Finding 'HIGH' 'Persistence' "Suspicious Command in Crontab: $cp" `
                ($content -split "`n" | Where-Object { $_ -match '(?i)(wget|curl|bash|/dev/shm|/tmp)' } | Select-Object -First 5 | ForEach-Object { $_.Trim() }) `
                @('T1053.003')
        }
    }
    foreach ($cd in $cronDirs) {
        $cdPath = Join-Path $uac $cd
        if (Test-Path -LiteralPath $cdPath) {
            $cronFiles = Get-ChildItem -LiteralPath $cdPath -File -ErrorAction SilentlyContinue
            foreach ($cf in $cronFiles) {
                $cc = Get-Content -LiteralPath $cf.FullName -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
                if ($cc -and $cc -match '(?i)(wget|curl|bash|sh|python|/dev/shm|/tmp)') {
                    $persistenceFound = $true
                    Add-Finding 'HIGH' 'Persistence' "Suspicious Cron File: $($cf.Name)" `
                        ($cc -split "`n" | Where-Object { $_.Trim() -and $_ -notmatch '^\s*#' } | Select-Object -First 5 | ForEach-Object { $_.Trim() }) `
                        @('T1053.003')
                }
            }
        }
    }

    # 6c. Systemd service anomalies (non-standard service names)
    $systemdPath = Join-Path $uac '[root]/etc/systemd/system'
    if (Test-Path -LiteralPath $systemdPath) {
        $customUnits = Get-ChildItem -LiteralPath $systemdPath -Filter '*.service' -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notmatch '(getty|network|ssh|cron|dbus|udev|systemd|avahi|bluetooth|cups)' }
        foreach ($unit in $customUnits) {
            $uc = Get-Content -LiteralPath $unit.FullName -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
            if ($uc -and $uc -match '(?i)(ExecStart|ExecStartPre).*(/tmp|/dev/shm|curl|wget|bash)') {
                $persistenceFound = $true
                Add-Finding 'CRITICAL' 'Persistence' "Suspicious Systemd Service: $($unit.Name)" `
                    ($uc -split "`n" | Where-Object { $_ -match 'Exec' } | Select-Object -First 3 | ForEach-Object { $_.Trim() }) `
                    @('T1543.002')
                Add-IOC 'FilePath' $unit.FullName "Suspicious systemd unit"
            }
        }
    }

    # 6d. SSH authorized_keys
    $homeBase = Join-Path $uac '[root]/home'
    if (Test-Path -LiteralPath $homeBase) {
        $authKeyFiles = Get-ChildItem -LiteralPath $homeBase -Recurse -Name 'authorized_keys' -ErrorAction SilentlyContinue
        foreach ($akf in $authKeyFiles) {
            $akPath = Join-Path $homeBase $akf
            $akContent = Get-Content -LiteralPath $akPath -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
            if ($akContent -and $akContent.Trim()) {
                $keyCount = ($akContent -split "`n" | Where-Object { $_ -match 'ssh-' }).Count
                $persistenceFound = $true
                Add-Finding 'MEDIUM' 'Persistence' "SSH Authorized Keys Present: $akf ($keyCount key(s))" `
                    "Authorized key file at $akPath contains $keyCount key(s). Review for unauthorized additions." `
                    @('T1098.004')
            }
        }
    }
    # root authorized_keys
    $rootAK = Read-UACArtifact $uac '[root]/root/.ssh/authorized_keys'
    if ($rootAK -and $rootAK.Trim()) {
        $keyCount = ($rootAK -split "`n" | Where-Object { $_ -match 'ssh-' }).Count
        $persistenceFound = $true
        Add-Finding 'HIGH' 'Persistence' "SSH Authorized Keys in /root/.ssh ($keyCount key(s))" `
            "Root account has $keyCount authorized key(s). Attacker may have added backdoor SSH access." `
            @('T1098.004','T1078')
    }

    # 6e. .bashrc / .profile persistence
    foreach ($shellRc in @('[root]/root/.bashrc','[root]/root/.profile','[root]/home/worker/.bashrc')) {
        $rcContent = Read-UACArtifact $uac $shellRc
        if ($rcContent -and $rcContent -match '(?i)(wget|curl|/dev/shm|/tmp/[a-z0-9]{4,}|nohup|&\s*$)') {
            $persistenceFound = $true
            Add-Finding 'HIGH' 'Persistence' "Shell RC Persistence: $shellRc" `
                ($rcContent -split "`n" | Where-Object { $_ -match '(?i)(wget|curl|/dev/shm|nohup)' } | Select-Object -First 3 | ForEach-Object { $_.Trim() }) `
                @('T1059.004')
        }
    }

    # 6f. /etc/profile.d/ - system-wide shell init, runs for all users on login
    $profileDPath = Join-Path $uac '[root]/etc/profile.d'
    if (Test-Path -LiteralPath $profileDPath) {
        $profFiles = Get-ChildItem -LiteralPath $profileDPath -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '\.(sh|bash)$' }
        foreach ($pf in $profFiles) {
            $pfContent = Get-Content -LiteralPath $pf.FullName -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
            if ($pfContent -and $pfContent -match '(?i)(wget|curl|nc\b|ncat|/tmp/|/dev/shm|/var/tmp|base64.*decode|eval\s|bash.*-[eci]\s)') {
                $persistenceFound = $true
                $pfLines = @($pfContent -split "`n" | Where-Object { $_ -match '(?i)(wget|curl|nc\b|/tmp|/dev/shm|base64|eval)' } | Select-Object -First 3 | ForEach-Object { $_.Trim() })
                Add-Finding 'HIGH' 'Persistence' `
                    "Suspicious Script in /etc/profile.d/: $($pf.Name)" `
                    "profile.d script executes for all users at login shell start: $($pfLines -join ' | ')" `
                    @('T1546.004')
                Add-IOC 'FilePath' "/etc/profile.d/$($pf.Name)" "Suspicious profile.d persistence script"
            }
        }
    }

    # 6g. /etc/update-motd.d/ - runs as root on every SSH login
    $motdPath = Join-Path $uac '[root]/etc/update-motd.d'
    if (Test-Path -LiteralPath $motdPath) {
        $motdFiles = Get-ChildItem -LiteralPath $motdPath -File -ErrorAction SilentlyContinue
        foreach ($mf in $motdFiles) {
            $mfContent = Get-Content -LiteralPath $mf.FullName -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
            if ($mfContent -and $mfContent -match '(?i)(wget|curl|nc\b|ncat|/tmp/|/dev/shm|base64.*decode|eval\s|bash.*-[eci]\s)') {
                $persistenceFound = $true
                $mfLines = @($mfContent -split "`n" | Where-Object { $_ -match '(?i)(wget|curl|/tmp|/dev/shm|base64)' } | Select-Object -First 3 | ForEach-Object { $_.Trim() })
                Add-Finding 'CRITICAL' 'Persistence' `
                    "MOTD Backdoor Script: /etc/update-motd.d/$($mf.Name)" `
                    "MOTD scripts execute as root on every interactive login. Backdoor content: $($mfLines -join ' | ')" `
                    @('T1546.004')
                Add-IOC 'FilePath' "/etc/update-motd.d/$($mf.Name)" "MOTD backdoor"
                Write-Host "         [CRITICAL] MOTD backdoor: /etc/update-motd.d/$($mf.Name)" -ForegroundColor Red
            }
        }
    }

    # 6h. /etc/pam.d/ - PAM config tampering (pam_exec backdoor, pam_permit auth bypass)
    $pamPath = Join-Path $uac '[root]/etc/pam.d'
    if (Test-Path -LiteralPath $pamPath) {
        $pamFiles = Get-ChildItem -LiteralPath $pamPath -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '(?i)(sshd|login|common-auth|sudo|su|passwd)' }
        foreach ($pamf in $pamFiles) {
            $pamContent = Get-Content -LiteralPath $pamf.FullName -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
            if (-not $pamContent) { continue }
            if ($pamContent -match '(?i)pam_exec\.so.*(wget|curl|/tmp|/dev/shm|bash|python|perl)') {
                $persistenceFound = $true
                Add-Finding 'CRITICAL' 'Persistence' `
                    "PAM Exec Backdoor in /etc/pam.d/$($pamf.Name)" `
                    "pam_exec.so in PAM config runs an attacker-controlled command at every authentication event: $($pamContent -split '`n' | Where-Object { $_ -match 'pam_exec' } | Select-Object -First 2 | ForEach-Object { $_.Trim() })" `
                    @('T1556.003','T1546')
                Add-IOC 'FilePath' "/etc/pam.d/$($pamf.Name)" "PAM exec backdoor"
                Write-Host "         [CRITICAL] PAM exec backdoor: /etc/pam.d/$($pamf.Name)" -ForegroundColor Red
            }
            if ($pamContent -match '(?m)^\s*auth\s+(required|sufficient)\s+pam_permit\.so') {
                $persistenceFound = $true
                Add-Finding 'CRITICAL' 'Persistence' `
                    "PAM Authentication Bypass (pam_permit.so) in /etc/pam.d/$($pamf.Name)" `
                    "pam_permit.so in the auth chain allows login with any password. This is a trivial rootkit backdoor that completely nullifies authentication for the affected service." `
                    @('T1556.003')
                Write-Host "         [CRITICAL] PAM auth bypass: /etc/pam.d/$($pamf.Name)" -ForegroundColor Red
            }
        }
    }

    # 6i. User-level crontabs (/var/spool/cron/crontabs/)
    $userCronPath = Join-Path $uac '[root]/var/spool/cron/crontabs'
    if (Test-Path -LiteralPath $userCronPath) {
        $userCronFiles = Get-ChildItem -LiteralPath $userCronPath -File -ErrorAction SilentlyContinue
        foreach ($ucf in $userCronFiles) {
            $ucContent = Get-Content -LiteralPath $ucf.FullName -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
            if ($ucContent -and $ucContent -match '(?i)(wget|curl|bash|sh|python|perl|nc\b|ncat|/dev/shm|/tmp)') {
                $persistenceFound = $true
                $ucLines = @($ucContent -split "`n" | Where-Object { $_ -match '(?i)(wget|curl|bash|/dev/shm|/tmp)' -and $_ -notmatch '^\s*#' } | Select-Object -First 5 | ForEach-Object { $_.Trim() })
                Add-Finding 'HIGH' 'Persistence' `
                    "Suspicious User Crontab: /var/spool/cron/crontabs/$($ucf.Name)" `
                    "User '$($ucf.Name)' has suspicious crontab entries: $($ucLines -join ' | ')" `
                    @('T1053.003')
                Add-IOC 'FilePath' "/var/spool/cron/crontabs/$($ucf.Name)" "Suspicious user crontab"
            }
        }
    }

    # 6k. /etc/sudoers + /etc/sudoers.d/ - NOPASSWD and wildcard privilege escalation
    $sudoersSources = [System.Collections.Generic.List[hashtable]]::new()
    $sudoersMain = Read-UACArtifact $uac '[root]/etc/sudoers'
    if ($sudoersMain) { [void]$sudoersSources.Add(@{Content=$sudoersMain; Name='etc/sudoers'}) }
    $sudoersDPath = Join-Path $uac '[root]/etc/sudoers.d'
    if (Test-Path -LiteralPath $sudoersDPath) {
        $sudoersDFiles = Get-ChildItem -LiteralPath $sudoersDPath -File -ErrorAction SilentlyContinue
        foreach ($sdf in $sudoersDFiles) {
            $sdc = Get-Content -LiteralPath $sdf.FullName -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
            if ($sdc) { [void]$sudoersSources.Add(@{Content=$sdc; Name="etc/sudoers.d/$($sdf.Name)"}) }
        }
    }
    foreach ($se in $sudoersSources) {
        $seLines = @($se.Content -split "`n" | Where-Object { $_ -match '\S' -and $_ -notmatch '^\s*#' })
        # NOPASSWD entries
        $nopasswd = @($seLines | Where-Object { $_ -match 'NOPASSWD' })
        if ($nopasswd.Count -gt 0) {
            $persistenceFound = $true
            $sev6k = if ($nopasswd | Where-Object { $_ -match '(?i)NOPASSWD.*\bALL\b.*\bALL\b|\bALL\b.*NOPASSWD.*\bALL\b' }) { 'HIGH' } else { 'MEDIUM' }
            Add-Finding $sev6k 'Persistence' `
                "Sudoers NOPASSWD Entry: /$($se.Name)" `
                "Password-free sudo access configured (T1548.003): $($nopasswd | Select-Object -First 3 | ForEach-Object { $_.Trim() })" `
                @('T1548.003','T1078')
        }
        # Wildcard all-access for non-standard accounts
        $allAll = @($seLines | Where-Object { $_ -match '^\s*\S+\s+ALL\s*=\s*(\(ALL\)|ALL)' -and $_ -notmatch '(?i)^\s*(%sudo|%wheel|%admin|root|\s*#)' })
        if ($allAll.Count -gt 0) {
            $persistenceFound = $true
            Add-Finding 'HIGH' 'Persistence' `
                "Sudoers All-Access Grant for Non-Standard Account: /$($se.Name)" `
                "Unrestricted sudo access to non-standard user/group: $($allAll | Select-Object -First 3 | ForEach-Object { $_.Trim() })" `
                @('T1548.003','T1136')
        }
    }

    # 6l. at jobs (/var/spool/at/ and /var/spool/cron/atjobs/) - one-shot scheduled task persistence
    $atSpoolPaths = @('[root]/var/spool/at','[root]/var/spool/cron/atjobs')
    foreach ($atSpool in $atSpoolPaths) {
        $atSpoolFull = Join-Path $uac $atSpool
        if (-not (Test-Path -LiteralPath $atSpoolFull)) { continue }
        $atFiles = Get-ChildItem -LiteralPath $atSpoolFull -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notmatch '(?i)(^\.sema|^\.running)' }
        foreach ($atf in $atFiles) {
            $atContent = Get-Content -LiteralPath $atf.FullName -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
            if ($atContent -and $atContent -match '(?i)(wget|curl|bash|sh -[ci]|python|perl|nc\b|ncat|/tmp/|/dev/shm|/var/tmp|base64.*decode|chmod.*\+x)') {
                $persistenceFound = $true
                $atLines = @($atContent -split "`n" | Where-Object { $_ -match '(?i)(wget|curl|bash|/tmp|/dev/shm|base64|chmod)' -and $_ -notmatch '^\s*#' } | Select-Object -First 3 | ForEach-Object { $_.Trim() })
                Add-Finding 'HIGH' 'Persistence' `
                    "Suspicious at Job: $atSpool/$($atf.Name)" `
                    "One-shot at job contains suspicious commands: $($atLines -join ' | ')" `
                    @('T1053.001')
                Add-IOC 'FilePath' "/$atSpool/$($atf.Name)" "Suspicious at job"
            }
        }
    }

    # 6j. Persistence absence narrative
    if (-not $persistenceFound) {
        $hasCritical = ($findings | Where-Object { $_.Severity -eq 'CRITICAL' } | Measure-Object).Count -gt 0
        if ($hasCritical) {
            Add-Finding 'MEDIUM' 'Persistence' 'No Additional Persistence Mechanisms Confirmed in Collection' `
                "Checked: cron (system + user-level), systemd units, shell RC files, profile.d scripts, MOTD scripts, PAM configuration, sudoers, at jobs, and authorized SSH keys. No suspicious entries found beyond what is already reported. The absence of redundant persistence is consistent with a targeted, low-noise deployment." `
                @()
        }
    }

    # ==========================================================================
    # MODULE 7  -  CREDENTIAL ARTIFACTS
    # ==========================================================================
    Write-Host "[LP-UAC] Module 7: Credential artifact detection..." -ForegroundColor DarkCyan

    # 7a. Scan /tmp for suspicious files
    $tmpPath = Join-Path $uac '[root]/tmp'
    if (Test-Path -LiteralPath $tmpPath) {
        $tmpFiles = Get-ChildItem -LiteralPath $tmpPath -File -ErrorAction SilentlyContinue
        foreach ($tf in $tmpFiles) {
            $tfContent = Get-Content -LiteralPath $tf.FullName -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
            # PAM dump pattern: uid:gid:type:username
            if ($tfContent -and $tfContent -match '^\d+:\d+:\w+:\w+') {
                Add-Finding 'CRITICAL' 'Credential Theft' `
                    "PAM Credential Dump Detected: /tmp/$($tf.Name)" `
                    "File /tmp/$($tf.Name) contains credential-dump formatted data: $($tfContent.Trim()). Pattern UID:GID:CredType:Username is consistent with a PAM hook in the LD_PRELOAD rootkit capturing authentication events and writing them to disk." `
                    @('T1556.003')
                Add-IOC 'FilePath' "/tmp/$($tf.Name)" "PAM credential dump"
                Add-Timeline '(At collection)' 'CRITICAL' "PAM credential dump at /tmp/$($tf.Name): $($tfContent.Trim())" "/tmp/$($tf.Name)"
                Write-Host "         [CRITICAL] Credential dump: /tmp/$($tf.Name) = $($tfContent.Trim())" -ForegroundColor Red
            }
        }
    }

    # 7b. Check shell history for sensitive commands - all users (multi-shell coverage)
    $histPathsForCreds = Get-UACShellHistoryPaths -Base $uac
    foreach ($histPath in $histPathsForCreds) {
        $hist = Read-UACArtifact $uac $histPath
        if ($hist) {
            $suspCmds = @($hist -split "`n" | Where-Object {
                $_ -match '(?i)(passwd|sudo su|base64|curl.*sh|wget.*sh|chmod.*777|/dev/shm|ld\.so\.preload|ldpreload|nc -e|ncat -e|bash -i|python.*pty|openssl.*s_client)'
            })
            if ($suspCmds.Count -gt 0) {
                Add-Finding 'HIGH' 'Credential Theft' "Suspicious Commands in Shell History: $histPath" `
                    "Suspicious history entries ($($suspCmds.Count)): $($suspCmds[0..4] -join ' | ')" `
                    @('T1552.003')
            }
        }
    }

    # 7c. Shadow file accessibility (if readable in UAC collection, check for weak hashes)
    $shadowContent = Read-UACArtifact $uac '[root]/etc/shadow'
    if ($shadowContent) {
        $shadowLines = @($shadowContent -split "`n" | Where-Object { $_ -match '^[^:]+:[^!*]' })
        if ($shadowLines.Count -gt 0) {
            Add-Finding 'HIGH' 'Credential Theft' "/etc/shadow Readable  -  $($shadowLines.Count) Hashed Password(s) Available" `
                "Account(s) with password hashes: $(($shadowLines | ForEach-Object { ($_ -split ':')[0] } | Select-Object -First 5) -join ', '). Assess for offline cracking." `
                @('T1003.008')
        }
    }

    # ==========================================================================
    # MODULE 8  -  FILESYSTEM TIMELINE (BODYFILE)
    # ==========================================================================
    Write-Host "[LP-UAC] Module 8: Filesystem timeline analysis..." -ForegroundColor DarkCyan

    $bodyfilePath = Join-Path $uac 'bodyfile/bodyfile.txt'
    $suspiciousBodyEntries = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Bodyfile format: MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime
    # Focus on suspicious paths: /etc/ld.so.preload, /lib, /usr/lib, /tmp, /dev/shm, /root
    $suspPathRx = '(?i)ld\.so\.preload|/tmp/|/dev/shm|libymv|\.so\.\d|/root/\.|\.bashrc|authorized_keys'

    if (Test-Path $bodyfilePath) {
        $bodyLines = Get-Content $bodyfilePath -Encoding UTF8 -ErrorAction SilentlyContinue
        Write-Host "         Parsing $($bodyLines.Count) bodyfile entries..." -ForegroundColor DarkGray

        foreach ($bl in $bodyLines) {
            if ($bl -match $suspPathRx) {
                $parts = $bl -split '\|'
                if ($parts.Count -ge 11) {
                    $hash   = $parts[0]
                    $name   = $parts[1]
                    $size   = $parts[6]
                    $mtime  = if ($parts[8] -match '^\d+$') {
                        try { [DateTimeOffset]::FromUnixTimeSeconds([long]$parts[8]).ToString('yyyy-MM-dd HH:mm:ss UTC') } catch { $parts[8] }
                    } else { $parts[8] }

                    $suspiciousBodyEntries.Add([PSCustomObject]@{
                        Hash  = $hash
                        Name  = $name
                        Size  = $size
                        MTime = $mtime
                    })

                    # Add to timeline
                    $tlSev = if ($name -match 'ld\.so\.preload|libymv') { 'CRITICAL' } else { 'HIGH' }
                    Add-Timeline $mtime $tlSev "File modified/created: $name (${size}B)" $name

                    # Hash intel check for bodyfile entries
                    if ($hash -and $hash -notmatch '^0+$') {
                        $hit = Test-IntelHit $hash
                        if ($hit) {
                            Add-Finding 'CRITICAL' 'Intel Hit' `
                                "Bodyfile Entry Hash Matches Threat Intel: $name" `
                                "MD5 $hash  -  Actor: $($hit.Actor) | Context: $($hit.Context)" `
                                @('T1027')
                        }
                    }
                }
            }
        }

        if ($suspiciousBodyEntries.Count -gt 0) {
            Add-Finding 'HIGH' 'Timeline' `
                "$($suspiciousBodyEntries.Count) Suspicious Filesystem Events in Bodyfile Timeline" `
                "Suspicious paths modified: $(($suspiciousBodyEntries[0..4] | ForEach-Object { "$($_.Name) @ $($_.MTime)" }) -join ' | ')" `
                @('T1070.004')
        }
    }

    # ==========================================================================
    # MODULE 9  -  USER ACCOUNT ANALYSIS
    # ==========================================================================
    Write-Host "[LP-UAC] Module 9: User account analysis..." -ForegroundColor DarkCyan

    $passwdContent = Read-UACArtifact $uac '[root]/etc/passwd'
    $interactiveUsers = @()
    $uid0Backdoors    = @()

    if ($passwdContent) {
        foreach ($line in ($passwdContent -split "`n")) {
            if ($line -match '^([^:]+):([^:]*):(\d+):(\d+):([^:]*):([^:]*):(.*)') {
                $uname  = $Matches[1]
                $uid    = [int]$Matches[3]
                $shell  = $Matches[7]
                # Interactive accounts (non-system, real shell)
                if ($uid -ge 1000 -and $shell -notmatch '(nologin|false|sync)') {
                    $interactiveUsers += $uname
                }
                # UID 0 non-root accounts = backdoor
                if ($uid -eq 0 -and $uname -ne 'root') {
                    $uid0Backdoors += $uname
                    Add-Finding 'CRITICAL' 'Backdoor Account' `
                        "UID 0 Backdoor Account Detected: $uname" `
                        "Account '$uname' has UID 0 (root equivalent) in /etc/passwd. This is a classic attacker backdoor." `
                        @('T1078','T1136')
                }
            }
        }
    }

    # ==========================================================================
    # MODULE 10  -  ATTRIBUTION
    # ==========================================================================
    Write-Host "[LP-UAC] Module 10: Attribution analysis..." -ForegroundColor DarkCyan

    # Score TTPs against known actor profiles
    $attributionScores = [ordered]@{}

    # TeamTNT TTP fingerprint
    $teamTNTScore = 0
    $teamTNTEvidence = @()
    if ($preloadLibs.Count -gt 0)                                          { $teamTNTScore += 25; $teamTNTEvidence += 'LD_PRELOAD rootkit via .so file' }
    if ($hiddenPids.Count -gt 0)                                            { $teamTNTScore += 20; $teamTNTEvidence += 'GID-based process hiding' }
    if ($findings | Where-Object { $_.Detail -match '3333|stratum' })       { $teamTNTScore += 20; $teamTNTEvidence += 'XMRig stratum port 3333' }
    if ($findings | Where-Object { $_.Detail -match '/dev/shm' })           { $teamTNTScore += 15; $teamTNTEvidence += '/dev/shm staging' }
    if ($findings | Where-Object { $_.Category -eq 'Credential Theft' })   { $teamTNTScore += 10; $teamTNTEvidence += 'PAM credential hooking' }
    if ($findings | Where-Object { $_.Detail -match 'compile.on.victim|unique.*hash|hash.*unique' }) { $teamTNTScore += 10; $teamTNTEvidence += 'Compile-on-victim evasion' }
    if ($teamTNTScore -gt 0) { $attributionScores['TeamTNT'] = @{Score=$teamTNTScore; Evidence=$teamTNTEvidence} }

    # Kinsing TTP fingerprint (similar cryptominer, targets k8s/Docker)
    $kinsingScore = 0
    $kinsingEvidence = @()
    if ($preloadLibs.Count -gt 0)                                                     { $kinsingScore += 15; $kinsingEvidence += 'LD_PRELOAD injection' }
    if ($hiddenPids.Count -gt 0)                                                       { $kinsingScore += 10; $kinsingEvidence += 'Process hiding' }
    if ($findings | Where-Object { $_.Category -eq 'Cryptominer' })                   { $kinsingScore += 20; $kinsingEvidence += 'XMRig deployment' }
    if ($findings | Where-Object { $_.Detail -match 'kinsing|kdevtmpfsi' })            { $kinsingScore += 30; $kinsingEvidence += 'Kinsing binary name' }
    if ($findings | Where-Object { $_.Detail -match '/tmp/kinsing|/dev/shm/kinsing' }) { $kinsingScore += 25; $kinsingEvidence += 'Kinsing staging path' }
    if ($kinsingScore -gt 0) { $attributionScores['Kinsing'] = @{Score=$kinsingScore; Evidence=$kinsingEvidence} }

    # Lazarus Group (Linux) - Nation-state DPRK, targets fintech/crypto exchanges
    $lazarusScore = 0
    $lazarusEvidence = @()
    if ($findings | Where-Object { $_.Detail -match 'BLINDINGCAN|COPPERHEDGE|ELECTRICFISH|MATA|DTrack|Manuscrypt' }) { $lazarusScore += 40; $lazarusEvidence += 'Known Lazarus tool name' }
    if ($findings | Where-Object { $_.Category -eq 'Intel Hit' -and $_.Detail -match 'Lazarus' })                   { $lazarusScore += 40; $lazarusEvidence += 'Intel CSV hash match (Lazarus)' }
    if ($findings | Where-Object { $_.Category -eq 'Backdoor Account' })                                            { $lazarusScore += 15; $lazarusEvidence += 'Backdoor UID-0 account' }
    if ($findings | Where-Object { $_.Detail -match '\.onion|tor2web|torproject' })                                  { $lazarusScore += 20; $lazarusEvidence += 'Tor C2 infrastructure' }
    if ($hiddenPids.Count -gt 0 -and ($findings | Where-Object { $_.Category -eq 'Intel Hit' }))                    { $lazarusScore += 10; $lazarusEvidence += 'Hidden processes + intel hit' }
    if ($lazarusScore -gt 0) { $attributionScores['Lazarus Group'] = @{Score=[Math]::Min($lazarusScore,100); Evidence=$lazarusEvidence} }

    # Volt Typhoon (China) - living-off-the-land, SOHO/VPN focus
    $voltScore = 0
    $voltEvidence = @()
    if ($findings | Where-Object { $_.Category -eq 'Intel Hit' -and $_.Detail -match 'Volt Typhoon|BRONZE SILHOUETTE' }) { $voltScore += 40; $voltEvidence += 'Intel CSV hash match (Volt Typhoon)' }
    if ($findings | Where-Object { $_.Detail -match 'ntdsutil|netsh|wmic|csvde|ldifde|vssadmin' })                        { $voltScore += 20; $voltEvidence += 'LOLBin credential/recon commands' }
    if ($findings | Where-Object { $_.Detail -match ':8443|:1443|:8080' -and $_.Category -match 'C2' })                   { $voltScore += 15; $voltEvidence += 'Non-standard HTTPS port C2' }
    if (-not ($findings | Where-Object { $_.Category -eq 'Cryptominer' }) -and $findings.Count -gt 3)                     { $voltScore += 10; $voltEvidence += 'No miner (LOTL pattern)' }
    if ($voltScore -gt 0) { $attributionScores['Volt Typhoon'] = @{Score=[Math]::Min($voltScore,100); Evidence=$voltEvidence} }

    # Generic Ransomware TTPs
    $ransomScore = 0
    $ransomEvidence = @()
    if ($findings | Where-Object { $_.Detail -match 'ransom|\.locked|\.encrypted|\.enc\b|\.crypt\b|README|DECRYPT|HOW_TO' }) { $ransomScore += 35; $ransomEvidence += 'Ransom note or encrypted file extension' }
    if ($findings | Where-Object { $_.Detail -match 'vssadmin|shadow|wbadmin|bcdedit' })                                      { $ransomScore += 25; $ransomEvidence += 'Shadow copy / backup deletion' }
    if ($findings | Where-Object { $_.Category -eq 'Intel Hit' -and $_.Detail -match 'ransomware|ransom|locker' })            { $ransomScore += 30; $ransomEvidence += 'Intel hash match (ransomware family)' }
    if ($findings | Where-Object { $_.Detail -match 'chmod.*777|find.*-exec.*rm|wipe|shred' })                                { $ransomScore += 10; $ransomEvidence += 'Mass file operation' }
    if ($ransomScore -gt 0) { $attributionScores['Ransomware (Generic)'] = @{Score=[Math]::Min($ransomScore,100); Evidence=$ransomEvidence} }

    # Webshell / Initial Access Broker
    $webshellScore = 0
    $webshellEvidence = @()
    if ($findings | Where-Object { $_.Category -eq 'Webshell' })                                      { $webshellScore += 40; $webshellEvidence += 'Webshell file detected' }
    if ($findings | Where-Object { $_.Detail -match 'eval.*base64|base64_decode.*eval|assert.*_GET' }) { $webshellScore += 30; $webshellEvidence += 'Webshell eval/base64 pattern' }
    if ($findings | Where-Object { $_.Detail -match '/var/www|/srv/www|/opt.*www|/htdocs' })           { $webshellScore += 15; $webshellEvidence += 'Artifact in web root' }
    if ($findings | Where-Object { $_.Category -eq 'Intel Hit' -and $_.Detail -match 'webshell|chopper|caidao|godzilla' }) { $webshellScore += 30; $webshellEvidence += 'Intel hash match (webshell family)' }
    if ($webshellScore -gt 0) { $attributionScores['Webshell / IAB'] = @{Score=[Math]::Min($webshellScore,100); Evidence=$webshellEvidence} }

    # Mirai / Tsunami / IoT Botnet
    $miraiScore = 0
    $miraiEvidence = @()
    if ($findings | Where-Object { $_.Detail -match 'mirai|tsunami|bashlite|qbot|gafgyt|mozi' }) { $miraiScore += 40; $miraiEvidence += 'Known botnet binary name' }
    if ($findings | Where-Object { $_.Category -eq 'C2 Communication' -and $_.Detail -match '6667|6668|6669' }) { $miraiScore += 25; $miraiEvidence += 'IRC C2 port active' }
    if ($findings | Where-Object { $_.Detail -match '/dev/shm|/tmp' -and $_.Category -match 'Staging' })         { $miraiScore += 10; $miraiEvidence += '/tmp or /dev/shm staging' }
    if ($findings | Where-Object { $_.Category -eq 'Intel Hit' -and $_.Detail -match 'Mirai|Tsunami|Gafgyt' })   { $miraiScore += 30; $miraiEvidence += 'Intel hash match (botnet family)' }
    if ($miraiScore -gt 0) { $attributionScores['Mirai / IoT Botnet'] = @{Score=[Math]::Min($miraiScore,100); Evidence=$miraiEvidence} }

    # Rocke / Iron Group (Chinese cryptominer APT, similar TTPs to TeamTNT)
    $rockeScore = 0
    $rockeEvidence = @()
    if ($findings | Where-Object { $_.Detail -match 'rocke|iron group|kerberods|kworker\b' })    { $rockeScore += 40; $rockeEvidence += 'Rocke binary/process name' }
    if ($findings | Where-Object { $_.Category -eq 'Cryptominer' })                              { $rockeScore += 15; $rockeEvidence += 'Cryptominer deployment' }
    if ($findings | Where-Object { $_.Category -eq 'Intel Hit' -and $_.Detail -match 'Rocke' }) { $rockeScore += 35; $rockeEvidence += 'Intel hash match (Rocke)' }
    if ($preloadLibs.Count -gt 0)                                                                 { $rockeScore += 10; $rockeEvidence += 'LD_PRELOAD rootkit' }
    if ($rockeScore -gt 0) { $attributionScores['Rocke / Iron Group'] = @{Score=[Math]::Min($rockeScore,100); Evidence=$rockeEvidence} }

    # UNC3886 (China) - targets VMware ESXi/Linux hypervisors; VirtualPita, VirtualPie, VirtualGate, MOPSLED
    $unc3886Score = 0
    $unc3886Evidence = @()
    if ($findings | Where-Object { $_.Detail -match '(?i)(vmci|esxi|vsphere|vcenter|VirtualPita|VirtualPie|VirtualGate|vmsyslog|vmware|vmkernel)' }) { $unc3886Score += 40; $unc3886Evidence += 'VMware/ESXi artifact' }
    if ($findings | Where-Object { $_.Category -eq 'Intel Hit' -and $_.Detail -match '(?i)(UNC3886|unc3886)' })                                       { $unc3886Score += 45; $unc3886Evidence += 'Intel match (UNC3886)' }
    if ($findings | Where-Object { $_.Detail -match '(?i)(MOPSLED|VIRTUALPITA|BRICKSTORM|ROADRUNNER|VMTUNNEL)' })                                     { $unc3886Score += 35; $unc3886Evidence += 'UNC3886 tool name' }
    if ($lsmodLines | Where-Object { $_ -match '(?i)(vmci|vmxnet|vmhgfs)' })                                                                          { $unc3886Score += 15; $unc3886Evidence += 'VMware kernel modules loaded' }
    if ($unc3886Score -gt 0) { $attributionScores['UNC3886'] = @{Score=[Math]::Min($unc3886Score,100); Evidence=$unc3886Evidence} }

    # APT41 (China) - dual-use espionage + eCrime; MESSAGETAP, SPEARHINT, LOWKEY, DUSTPAN, Winnti lineage
    $apt41Score = 0
    $apt41Evidence = @()
    if ($findings | Where-Object { $_.Detail -match '(?i)(MESSAGETAP|SPEARHINT|LOWKEY|DUSTPAN|HIGHNOON|POISONPLUG|CROSSWALK|DEADEYE|KEYPLUG)' }) { $apt41Score += 40; $apt41Evidence += 'APT41 tool name' }
    if ($findings | Where-Object { $_.Category -eq 'Intel Hit' -and $_.Detail -match '(?i)(APT41|BARIUM|WINNTI|Double Dragon)' })                { $apt41Score += 45; $apt41Evidence += 'Intel match (APT41)' }
    if ($findings | Where-Object { $_.Detail -match '(?i)(winnti|PlugX|ShadowPad|Derusbi|CROSSWALK)' })                                           { $apt41Score += 30; $apt41Evidence += 'APT41 shared toolset (Winnti/PlugX/ShadowPad)' }
    if (($findings | Where-Object { $_.Category -eq 'Webshell' }) -and ($findings | Where-Object { $_.Category -eq 'Intel Hit' }))               { $apt41Score += 15; $apt41Evidence += 'Webshell + intel match (dual-use pattern)' }
    if ($apt41Score -gt 0) { $attributionScores['APT41'] = @{Score=[Math]::Min($apt41Score,100); Evidence=$apt41Evidence} }

    # Turla (Russia) - Penquin Turla Linux rootkit; Uroburos/Snake; uses raw packet sniffer C2
    $turlaScore = 0
    $turlaEvidence = @()
    if ($findings | Where-Object { $_.Detail -match '(?i)(penquin|uroburos|kazuar|carbon.*turla|SNAKE|JVELOCE|KOPILUWAK|CRUTCH)' })                 { $turlaScore += 45; $turlaEvidence += 'Turla Linux tool name' }
    if ($findings | Where-Object { $_.Category -eq 'Intel Hit' -and $_.Detail -match '(?i)(Turla|Waterbug|VENOMOUS BEAR|KRYPTON)' })               { $turlaScore += 45; $turlaEvidence += 'Intel match (Turla)' }
    if ($findings | Where-Object { $_.Detail -match ':6789|raw.*socket|packet.*sniff' })                                                            { $turlaScore += 20; $turlaEvidence += 'Raw socket/Penquin Turla C2 port pattern' }
    if (($preloadLibs.Count -eq 0) -and ($findings | Where-Object { $_.Category -eq 'Intel Hit' -and $_.Detail -match '(?i)Turla' }))              { $turlaScore += 10; $turlaEvidence += 'No LD_PRELOAD (Turla uses kernel-mode implant)' }
    if ($turlaScore -gt 0) { $attributionScores['Turla'] = @{Score=[Math]::Min($turlaScore,100); Evidence=$turlaEvidence} }

    # Sandworm (Russia) - destructive; Industroyer2, CaddyWiper, AcidRain, Cyclops Blink, NotPetya
    $sandwormScore = 0
    $sandwormEvidence = @()
    if ($findings | Where-Object { $_.Detail -match '(?i)(industroyer|caddywiper|acidrain|notpetya|exaramel|cyclops.blink|prestige|awfulshred|soloshred)' }) { $sandwormScore += 45; $sandwormEvidence += 'Sandworm destructive tool name' }
    if ($findings | Where-Object { $_.Category -eq 'Intel Hit' -and $_.Detail -match '(?i)(Sandworm|ELECTRUM|VOODOO.BEAR|IRIDIUM|UAC-0082)' })             { $sandwormScore += 45; $sandwormEvidence += 'Intel match (Sandworm)' }
    if ($findings | Where-Object { $_.Detail -match '(?i)(shred.*-z|dd.*if=/dev/zero|wipe|secure-delete|find.*-exec.*shred)' })                            { $sandwormScore += 25; $sandwormEvidence += 'Destructive wipe command' }
    if (($findings | Where-Object { $_.Category -eq 'Anti-Forensics' }) -and ($findings | Where-Object { $_.Category -eq 'Intel Hit' }))                   { $sandwormScore += 10; $sandwormEvidence += 'Anti-forensics + intel match' }
    if ($sandwormScore -gt 0) { $attributionScores['Sandworm'] = @{Score=[Math]::Min($sandwormScore,100); Evidence=$sandwormEvidence} }

    # APT34 / OilRig (Iran) - Tonedeaf, ValueVault, RDAT, Marlin (Linux variants), DNS tunneling
    $apt34Score = 0
    $apt34Evidence = @()
    if ($findings | Where-Object { $_.Detail -match '(?i)(tonedeaf|valuevault|RDAT|marlin|samplecheck|karkoff|HYPERSCRAPE|GRAMDOOR|SIESTAGRAPH)' }) { $apt34Score += 45; $apt34Evidence += 'APT34/OilRig Linux tool name' }
    if ($findings | Where-Object { $_.Category -eq 'Intel Hit' -and $_.Detail -match '(?i)(APT34|OilRig|HELIX.KITTEN|CRAMBUS|HAZEL.SANDSTORM)' })  { $apt34Score += 45; $apt34Evidence += 'Intel match (APT34/OilRig)' }
    if (($findings | Where-Object { $_.Category -eq 'Webshell' }) -and ($findings | Where-Object { $_.Detail -match '(?i)(dns.*tunnel|TXT.*record|doh)' })) { $apt34Score += 20; $apt34Evidence += 'Webshell + DNS tunneling (OilRig pattern)' }
    if ($findings | Where-Object { $_.Detail -match '(?i)(oilrig|apt34|helix)' })                                                                          { $apt34Score += 20; $apt34Evidence += 'APT34/OilRig direct reference' }
    if ($apt34Score -gt 0) { $attributionScores['APT34 / OilRig'] = @{Score=[Math]::Min($apt34Score,100); Evidence=$apt34Evidence} }

    # Carbanak / FIN7 (eCrime) - banking, POS, may use Linux as persistent pivot
    $carbanakScore = 0
    $carbanakEvidence = @()
    if ($findings | Where-Object { $_.Category -eq 'Intel Hit' -and $_.Detail -match '(?i)(Carbanak|FIN7|SANGRIA.TEMPEST|ANUNAK|Carbon Spider)' }) { $carbanakScore += 50; $carbanakEvidence += 'Intel match (Carbanak/FIN7)' }
    if ($findings | Where-Object { $_.Detail -match '(?i)(carbanak|fin7|anunak|tirion|griffon|bateleur)' })                                         { $carbanakScore += 35; $carbanakEvidence += 'Carbanak/FIN7 tool name' }
    if (($findings | Where-Object { $_.Category -eq 'C2 Communication' }) -and ($findings | Where-Object { $_.Category -eq 'Credential Theft' }))  { $carbanakScore += 10; $carbanakEvidence += 'Active C2 + credential theft' }
    if ($carbanakScore -gt 0) { $attributionScores['Carbanak / FIN7'] = @{Score=[Math]::Min($carbanakScore,100); Evidence=$carbanakEvidence} }

    # Scattered Spider (eCrime) - social engineering, MFA fatigue, uses tunneling tools on Linux pivots
    $scatteredScore = 0
    $scatteredEvidence = @()
    if ($findings | Where-Object { $_.Category -eq 'Intel Hit' -and $_.Detail -match '(?i)(Scattered.Spider|OCTO.TEMPEST|0ktapus|Roasted 0ktapus|UNC3944)' }) { $scatteredScore += 50; $scatteredEvidence += 'Intel match (Scattered Spider)' }
    if ($findings | Where-Object { $_.Detail -match '(?i)(ngrok|cloudflared|tailscale|frp\b|ligolo|chisel|bore\.sh|localhost\.run)' })                         { $scatteredScore += 30; $scatteredEvidence += 'Tunneling tool (Scattered Spider LOTL)' }
    if ($findings | Where-Object { $_.Detail -match '(?i)(okta|azure.*ad|entra|0ktapus|mfa.*push|smishing)' })                                                 { $scatteredScore += 20; $scatteredEvidence += 'Identity provider / SSO artifact' }
    if (($findings | Where-Object { $_.Category -eq 'Intel Hit' }) -and ($findings | Where-Object { $_.Detail -match '(?i)(ngrok|cloudflared)' }))             { $scatteredScore += 10; $scatteredEvidence += 'Intel match + tunneling tool' }
    if ($scatteredScore -gt 0) { $attributionScores['Scattered Spider'] = @{Score=[Math]::Min($scatteredScore,100); Evidence=$scatteredEvidence} }

    # APT28 / Fancy Bear (Russia) - Sofacy, SEDNIT, Forest Blizzard, Strontium
    $apt28Score = 0
    $apt28Evidence = @()
    if ($findings | Where-Object { $_.Category -eq 'Intel Hit' -and $_.Detail -match '(?i)(APT28|Fancy.Bear|SOFACY|SEDNIT|Forest.Blizzard|Strontium|IRON.TWILIGHT|Fighting.Ursa)' }) { $apt28Score += 45; $apt28Evidence += 'Intel match (APT28/Fancy Bear)' }
    if ($findings | Where-Object { $_.Detail -match '(?i)(XAgent|Sofacy|EVILTOSS|GAMEFISH|Zebrocy|Cannon\b|CHOPSTICK|CORESHELL|GO-RAT|MASEPIE|OCEANMAP|HEADLACE)' })                { $apt28Score += 40; $apt28Evidence += 'APT28 tool name' }
    if (($findings | Where-Object { $_.Category -eq 'Webshell' }) -and ($findings | Where-Object { $_.Category -eq 'Intel Hit' }))                                                  { $apt28Score += 10; $apt28Evidence += 'Webshell + intel hit (APT28 initial access)' }
    if (($findings | Where-Object { $_.Category -eq 'C2 Communication' }) -and ($findings | Where-Object { $_.Category -eq 'Intel Hit' -and $_.Detail -match '(?i)APT28' }))         { $apt28Score += 10; $apt28Evidence += 'Active C2 + APT28 intel match' }
    if ($apt28Score -gt 0) { $attributionScores['APT28 / Fancy Bear'] = @{Score=[Math]::Min($apt28Score,100); Evidence=$apt28Evidence} }

    # APT29 / Cozy Bear (Russia) - NOBELIUM, The Dukes, Midnight Blizzard, Yttrium
    $apt29Score = 0
    $apt29Evidence = @()
    if ($findings | Where-Object { $_.Category -eq 'Intel Hit' -and $_.Detail -match '(?i)(APT29|Cozy.Bear|NOBELIUM|Midnight.Blizzard|The.Dukes|IRON.HEMLOCK|YTTRIUM)' })                  { $apt29Score += 45; $apt29Evidence += 'Intel match (APT29/Cozy Bear)' }
    if ($findings | Where-Object { $_.Detail -match '(?i)(WellMess|WellMail|TrailBlazer|GoldMax|GoldFinder|Sibot|SUNBURST|TEARDROP|GoldZilla|MagicWeb|SkinnyBoy|EnvyScout|BEATDROP|BoomBox)' }) { $apt29Score += 40; $apt29Evidence += 'APT29 tool name' }
    if (($preloadLibs.Count -eq 0) -and ($findings | Where-Object { $_.Category -eq 'Intel Hit' -and $_.Detail -match '(?i)(APT29|Cozy.Bear)' }))                                          { $apt29Score += 10; $apt29Evidence += 'No LD_PRELOAD (APT29 uses clean compiled implants)' }
    if (($findings | Where-Object { $_.Category -eq 'C2 Communication' }) -and ($findings | Where-Object { $_.Category -eq 'Intel Hit' -and $_.Detail -match '(?i)(APT29|nobelium)' }))     { $apt29Score += 10; $apt29Evidence += 'Active C2 + APT29 intel match' }
    if ($apt29Score -gt 0) { $attributionScores['APT29 / Cozy Bear'] = @{Score=[Math]::Min($apt29Score,100); Evidence=$apt29Evidence} }

    # Kimsuky (North Korea) - Velvet Chollima, Thallium, Black Banshee, TA427
    $kimsukyScore = 0
    $kimsukyEvidence = @()
    if ($findings | Where-Object { $_.Category -eq 'Intel Hit' -and $_.Detail -match '(?i)(Kimsuky|Velvet.Chollima|Thallium|Black.Banshee|STOLEN.PENCIL|TA427)' }) { $kimsukyScore += 45; $kimsukyEvidence += 'Intel match (Kimsuky)' }
    if ($findings | Where-Object { $_.Detail -match '(?i)(GoldDragon|AppleSeed|BabyShark|FlowerPower|NAUTILUS|RandomQuery|Rekon|SMOKEDHAM|SHARPEXT|xRAT\b)' })     { $kimsukyScore += 40; $kimsukyEvidence += 'Kimsuky tool name' }
    if ($findings | Where-Object { $_.Category -eq 'Webshell' })                                                                                                    { $kimsukyScore += 15; $kimsukyEvidence += 'Webshell present (Kimsuky initial access pattern)' }
    if ($findings | Where-Object { $_.Category -eq 'Credential Theft' })                                                                                            { $kimsukyScore += 10; $kimsukyEvidence += 'Credential theft (Kimsuky espionage focus)' }
    if ($kimsukyScore -gt 0) { $attributionScores['Kimsuky'] = @{Score=[Math]::Min($kimsukyScore,100); Evidence=$kimsukyEvidence} }

    # APT32 / OceanLotus (Vietnam) - Canvas Cyclone, Ocean Buffalo, BISMUTH
    $apt32Score = 0
    $apt32Evidence = @()
    if ($findings | Where-Object { $_.Category -eq 'Intel Hit' -and $_.Detail -match '(?i)(APT32|OceanLotus|Canvas.Cyclone|BISMUTH|Ocean.Buffalo|SeaLotus)' }) { $apt32Score += 45; $apt32Evidence += 'Intel match (APT32/OceanLotus)' }
    if ($findings | Where-Object { $_.Detail -match '(?i)(KERRDOWN|Ratsnif|Denis\b|METALJACK|PACEMAKER|WINDSHIELD|Komodo|cobalt.strike.*apt32)' })             { $apt32Score += 40; $apt32Evidence += 'APT32 tool name' }
    if (($findings | Where-Object { $_.Category -eq 'Webshell' }) -and ($findings | Where-Object { $_.Category -eq 'Intel Hit' }))                             { $apt32Score += 15; $apt32Evidence += 'Webshell + intel hit (APT32 pattern)' }
    if (($findings | Where-Object { $_.Category -eq 'C2 Communication' }) -and ($findings | Where-Object { $_.Category -eq 'Intel Hit' -and $_.Detail -match '(?i)(APT32|oceanlotus)' })) { $apt32Score += 10; $apt32Evidence += 'Active C2 + APT32 intel match' }
    if ($apt32Score -gt 0) { $attributionScores['APT32 / OceanLotus'] = @{Score=[Math]::Min($apt32Score,100); Evidence=$apt32Evidence} }

    $sortedActors = @($attributionScores.Keys | Sort-Object { $attributionScores[$_].Score } -Descending)
    $topActor     = if ($sortedActors.Count -gt 0) { $sortedActors[0] } else { '' }
    $topScore     = if ($topActor) { $attributionScores[$topActor].Score } else { 0 }
    $confidence   = if ($topScore -ge 70) { 'HIGH' } elseif ($topScore -ge 40) { 'MEDIUM' } else { 'LOW' }

    if ($topActor) {
        $ev = $attributionScores[$topActor].Evidence -join '; '
        Add-Finding 'HIGH' 'Attribution' `
            "Top Attribution: $topActor ($confidence Confidence - $topScore/100)" `
            "Evidence supporting $topActor attribution: $ev. Score is based on TTP overlap, not direct binary attribution." `
            @()
        Write-Host "         Top Attribution: $topActor  -  $confidence confidence ($topScore/100)" -ForegroundColor Yellow
    }

    # Secondary actors (score >= 20, excluding top)
    $secondaryActors = $sortedActors | Select-Object -Skip 1 | Where-Object { $attributionScores[$_].Score -ge 20 }
    foreach ($actor in $secondaryActors) {
        $sc    = $attributionScores[$actor].Score
        $conf2 = if ($sc -ge 70) { 'HIGH' } elseif ($sc -ge 40) { 'MEDIUM' } else { 'LOW' }
        $sev2  = if ($sc -ge 50) { 'MEDIUM' } else { 'LOW' }
        $ev2   = $attributionScores[$actor].Evidence -join '; '
        Add-Finding $sev2 'Attribution' `
            "Secondary Attribution Signal: $actor ($conf2 Confidence - $sc/100)" `
            "Evidence supporting $actor attribution: $ev2. Score is based on TTP overlap, not direct binary attribution." `
            @()
        Write-Host "         Secondary: $actor  -  $conf2 confidence ($sc/100)" -ForegroundColor DarkYellow
    }

    # Full score table as INFO finding
    if ($sortedActors.Count -gt 0) {
        $scoreTable = ($sortedActors | ForEach-Object {
            "$_ : $($attributionScores[$_].Score)/100 [$($attributionScores[$_].Evidence -join ', ')]"
        }) -join ' | '
        Add-Finding 'INFO' 'Attribution' `
            "Full Attribution Scores ($($sortedActors.Count) actor(s) evaluated)" `
            $scoreTable `
            @()
    }

    # ==========================================================================
    # MODULE 11  -  WEBSHELL & DROPPER DETECTION
    # ==========================================================================
    Write-Host "[LP-UAC] Module 11: Webshell and dropper detection..." -ForegroundColor DarkCyan

    # Common web roots and staging paths to scan
    $webRoots = @(
        '[root]/var/www',
        '[root]/srv/www', '[root]/srv/http', '[root]/srv/https',
        '[root]/opt/app', '[root]/opt/tomcat', '[root]/opt/jboss',
        '[root]/usr/share/nginx', '[root]/usr/share/apache2',
        '[root]/var/lib/tomcat9/webapps', '[root]/var/lib/tomcat8/webapps'
    )
    # Webshell patterns — high confidence indicators
    $webshellPatterns = @(
        '(?i)eval\s*\(\s*(base64_decode|gzinflate|str_rot13|gzuncompress|rawurldecode)',
        '(?i)(system|exec|passthru|shell_exec|popen|proc_open)\s*\(\s*(\$_(GET|POST|REQUEST|COOKIE)',
        '(?i)assert\s*\(\s*\$_(GET|POST|REQUEST)',
        '(?i)<\?php.*\$_(GET|POST|REQUEST|COOKIE).*system|exec|passthru',
        '(?i)Runtime\.exec|ProcessBuilder.*cmd|getRuntime.*exec',   # JSP
        '(?i)import os.*popen|import subprocess.*call.*shell=True',  # Python
        '(?i)FSO\.CreateTextFile|WScript\.Shell.*Exec',              # ASPX/VBScript
        '(?i)chopper|caidao|godzilla|behinder|ice scorpion',         # known webshell names
        '(?i)cmd\.exe.*&&|powershell.*-enc|-nop|-w hidden'           # Win cmd embedded in web file
    )
    $webshellExtensions = @('\.php$','\.php\d$','\.phtml$','\.php5$','\.shtml$',
                            '\.jsp$','\.jspx$','\.aspx$','\.ashx$','\.asmx$',
                            '\.cgi$','\.pl$','\.py$','\.rb$')
    $suspWebExts = '(?i)' + ($webshellExtensions -join '|')

    $webshellCount = 0
    foreach ($root in $webRoots) {
        $rootPath = Join-Path $uac $root
        if (-not (Test-Path -LiteralPath $rootPath)) { continue }
        $webFiles = Get-ChildItem -LiteralPath $rootPath -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match $suspWebExts -or $_.Length -lt 50000 }
        foreach ($wf in $webFiles) {
            $wfContent = Get-Content -LiteralPath $wf.FullName -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
            if (-not $wfContent) { continue }
            foreach ($pat in $webshellPatterns) {
                if ($wfContent -match $pat) {
                    $webshellCount++
                    $matchLine = ($wfContent -split "`n" | Where-Object { $_ -match $pat } | Select-Object -First 1)
                    $matchLine = if ($matchLine) { $matchLine.Trim() } else { '' }
                    Add-Finding 'CRITICAL' 'Webshell' `
                        "Webshell Pattern Detected: $($wf.FullName -replace [regex]::Escape($uac))" `
                        "File: $($wf.Name) ($($wf.Length) bytes) | Match: $($matchLine[0..200] -join '')" `
                        @('T1505.003','T1059')
                    Add-IOC 'FilePath' ($wf.FullName -replace [regex]::Escape($uac),'') "Webshell candidate"
                    Add-Timeline "($($wf.LastWriteTime.ToString('yyyy-MM-dd HH:mm')))" 'CRITICAL' "Webshell candidate: $($wf.Name)" $wf.FullName
                    break  # one finding per file
                }
            }
        }
    }

    # Also scan /tmp and /dev/shm for script droppers
    $stagingPaths = @('[root]/tmp','[root]/dev/shm','[root]/var/tmp','[root]/run/shm')
    foreach ($sp in $stagingPaths) {
        $spPath = Join-Path $uac $sp
        if (-not (Test-Path -LiteralPath $spPath)) { continue }
        $stageFiles = Get-ChildItem -LiteralPath $spPath -File -ErrorAction SilentlyContinue
        foreach ($sf in $stageFiles) {
            # Flag any executable or script in staging directories
            if ($sf.Name -match '(?i)\.(sh|py|pl|rb|elf|bin|out|x86|x64|arm)$' -or
                $sf.Extension -eq '' ) {
                Add-Finding 'HIGH' 'Staging' `
                    "Executable/Script in Volatile Staging Path: $($sf.FullName -replace [regex]::Escape($uac))" `
                    "File $($sf.Name) ($($sf.Length) bytes) found in volatile staging area. Files here do not survive reboot and are used to evade disk forensics." `
                    @('T1059.004','T1070.004')
                Add-IOC 'FilePath' ($sf.FullName -replace [regex]::Escape($uac),'') "Executable in staging path"
            }
        }
    }

    if ($webshellCount -gt 0) {
        Write-Host "         [CRITICAL] $webshellCount webshell pattern(s) detected" -ForegroundColor Red
    }

    # ==========================================================================
    # MODULE 12  -  BINARY INTEGRITY (TROJANIZED SYSTEM TOOLS)
    # ==========================================================================
    Write-Host "[LP-UAC] Module 12: Binary integrity checks..." -ForegroundColor DarkCyan

    # Known-clean hash baseline for critical system binaries.
    # Populate this table with MD5 hashes from verified, unmodified packages for your target distro.
    # Use: md5sum /bin/ls /bin/ps /bin/bash /usr/bin/sudo /usr/sbin/sshd on a clean reference system.
    # Leave empty to rely solely on intel-feed matches (recommended until populated with verified values).
    $knownCleanHashes = @{
        # '/bin/ls'       = @('hash_from_your_verified_debian12_system','hash_ubuntu2204_variant')
        # '/bin/ps'       = @('...')
        # '/bin/bash'     = @('...')
        # '/usr/bin/sudo' = @('...')
        # '/usr/sbin/sshd'= @('...')
    }

    # Extract system binary hashes from bodyfile and hash_executables for intel cross-check
    # (This runs regardless of whether $knownCleanHashes is populated)
    $sysBinPaths = @('/bin/ls','/bin/ps','/bin/bash','/usr/bin/sudo','/usr/sbin/sshd',
                     '/bin/netstat','/usr/bin/find','/usr/bin/id','/usr/bin/passwd')
    $bodyfileHashes = @{}
    if (Test-Path -LiteralPath $bodyfilePath) {
        $critRx = ($sysBinPaths | ForEach-Object { [regex]::Escape($_) }) -join '|'
        $critLines = @(Get-Content -LiteralPath $bodyfilePath -Encoding UTF8 -ErrorAction SilentlyContinue |
            Where-Object { $_ -match "($critRx)" })
        foreach ($cl in $critLines) {
            $parts = $cl -split '\|'
            if ($parts.Count -ge 2 -and $parts[0] -match '^[a-fA-F0-9]{32}$') {
                $bodyfileHashes[$parts[1]] = $parts[0].ToLower()
            }
        }
    }
    foreach ($line in $exeHashLines) {
        if ($line -match '^([a-fA-F0-9]{32})\s+(.+)') {
            $h = $Matches[1].ToLower(); $p = $Matches[2].Trim()
            if ($sysBinPaths -contains $p) { $bodyfileHashes[$p] = $h }
        }
    }

    # Intel-based check: flag any system binary whose hash hits the threat feed
    foreach ($binPath in $sysBinPaths) {
        $observedHash = $bodyfileHashes[$binPath]
        if (-not $observedHash) { continue }
        $intelHit = Test-IntelHit $observedHash
        if ($intelHit) {
            Add-Finding 'CRITICAL' 'Binary Integrity' `
                "System Binary Hash MATCHES Threat Intel: $binPath" `
                "MD5 $observedHash for $binPath matches Actor: $($intelHit.Actor) | Context: $($intelHit.Context). This binary is a confirmed malicious replacement." `
                @('T1554','T1014')
            Add-IOC 'MD5' $observedHash "Intel-matched system binary $binPath" $intelHit.Actor
            Write-Host "         [CRITICAL] System binary intel hit: $binPath ($observedHash)" -ForegroundColor Red
        }
    }

    # Known-clean comparison (only runs if table is populated above)
    foreach ($binPath in $knownCleanHashes.Keys) {
        $observedHash = $bodyfileHashes[$binPath]
        if (-not $observedHash) { continue }
        $isClean = $knownCleanHashes[$binPath] | Where-Object { $_ -eq $observedHash }
        if (-not $isClean) {
            Add-Finding 'HIGH' 'Binary Integrity' `
                "System Binary Hash Differs from Verified Baseline: $binPath" `
                "MD5 $observedHash for $binPath does not match the known-clean baseline. Manual verification required — could indicate trojanized binary or unexpected package update." `
                @('T1554','T1014')
            Add-IOC 'MD5' $observedHash "Unexpected hash for $binPath"
            Write-Host "         [HIGH] Binary hash mismatch: $binPath" -ForegroundColor Yellow
        }
    }

    # Flag system binaries that appear in non-standard locations (masquerading)
    $sysToolNames = @('ls','ps','netstat','ifconfig','id','whoami','find','cat','bash','sh','python','python3','curl','wget')
    foreach ($line in $exeHashLines) {
        if ($line -match '^([a-fA-F0-9]{32})\s+(/tmp/|/dev/shm/|/run/|/var/tmp/)(\S+)') {
            $h = $Matches[1]; $stagePath = $Matches[2] + $Matches[3]; $fname = $Matches[3]
            if ($sysToolNames | Where-Object { $fname -match "^$_$" -or $fname -match "^$_\." }) {
                Add-Finding 'HIGH' 'Masquerading' `
                    "System Tool Name in Staging Path: $stagePath" `
                    "Binary named '$fname' found at $stagePath (MD5: $h). System tool names in volatile paths indicate masquerading — attacker using trusted binary names for their malware." `
                    @('T1036.005','T1059.004')
            }
        }
    }

    # ==========================================================================
    # MODULE 13  -  SUID/SGID ANOMALY DETECTION
    # ==========================================================================
    Write-Host "[LP-UAC] Module 13: SUID/SGID anomaly detection..." -ForegroundColor DarkCyan

    # Known-safe SUID binaries (standard Debian/Ubuntu installations)
    $knownSafeSetuid = @(
        '/usr/bin/sudo','/usr/bin/sudoedit','/usr/bin/su','/bin/su',
        '/usr/bin/passwd','/bin/passwd','/usr/bin/chfn','/usr/bin/chsh',
        '/usr/bin/gpasswd','/usr/bin/newgrp','/usr/bin/expiry',
        '/bin/ping','/bin/ping6','/usr/bin/ping','/usr/bin/ping6',
        '/bin/mount','/bin/umount','/usr/bin/mount','/usr/bin/umount',
        '/usr/lib/openssh/ssh-keysign',
        '/usr/lib/dbus-1.0/dbus-daemon-launch-helper',
        '/usr/lib/eject/dmcrypt-get-device',
        '/usr/sbin/unix_chkpwd','/sbin/unix_chkpwd',
        '/usr/bin/pkexec','/usr/lib/policykit-1/polkit-agent-helper-1',
        '/usr/bin/at','/usr/bin/wall','/usr/bin/write','/usr/bin/crontab',
        '/bin/fusermount','/usr/bin/fusermount3',
        '/usr/bin/ssh-agent','/usr/bin/X','/usr/bin/Xorg'
    )

    # Parse bodyfile for SUID/SGID bits (mode field — position 3 in bodyfile)
    # Mode format in bodyfile: e.g. '100755' or '-rwsr-xr-x'
    $setuidFindings = [System.Collections.Generic.List[string]]::new()
    if (Test-Path -LiteralPath $bodyfilePath) {
        $suidLines = @(Get-Content -LiteralPath $bodyfilePath -Encoding UTF8 -ErrorAction SilentlyContinue |
            Where-Object {
                # SUID bit: mode has 's' in owner execute position, or octal mode 4xxx
                ($_ -match '\|[d-][rwxs-]{2}s') -or ($_ -match '\|4[0-7]{3}[0-7]')
            } | Select-Object -First 200)

        foreach ($sl in $suidLines) {
            $parts = $sl -split '\|'
            if ($parts.Count -ge 2) {
                $bfPath = $parts[1]
                # Strip leading [root] or rootfs prefix
                $normalPath = $bfPath -replace '^\[root\]','' -replace '^/rootfs',''
                $isSafe = $knownSafeSetuid | Where-Object { $_ -eq $normalPath }
                if (-not $isSafe -and $normalPath -match '^/') {
                    [void]$setuidFindings.Add($normalPath)
                }
            }
        }
    }

    if ($setuidFindings.Count -gt 0) {
        $setuidSample = ($setuidFindings | Select-Object -First 10) -join ', '
        $sev = if ($setuidFindings | Where-Object { $_ -match '/tmp/|/dev/shm/|/var/tmp/' }) { 'CRITICAL' } else { 'HIGH' }
        Add-Finding $sev 'Privilege Escalation' `
            "$($setuidFindings.Count) Unexpected SUID/SGID Binary/Binaries Detected" `
            "Non-standard setuid binaries found: $setuidSample — Unexpected SUID binaries are a primary Linux privilege escalation technique. Binaries in /tmp or /dev/shm are almost always attacker-planted." `
            @('T1548.001','T1068')
        foreach ($sb in ($setuidFindings | Where-Object { $_ -match '/tmp/|/dev/shm/' })) {
            Add-IOC 'FilePath' $sb "SUID binary in staging path"
        }
        Write-Host "         [$sev] $($setuidFindings.Count) unexpected SUID binary/binaries" -ForegroundColor $(if($sev -eq 'CRITICAL'){'Red'}else{'Yellow'})
    }

    # ==========================================================================
    # MODULE 14  -  LOG INTEGRITY & ANTI-FORENSICS DETECTION
    # ==========================================================================
    Write-Host "[LP-UAC] Module 14: Log integrity analysis..." -ForegroundColor DarkCyan

    # 14a. Check auth.log for suspicious patterns
    $authLogPaths = @('[root]/var/log/auth.log','[root]/var/log/secure','[root]/var/log/auth.log.1')
    $authLogFound = $false
    foreach ($alp in $authLogPaths) {
        $authContent = Read-UACArtifact $uac $alp
        if (-not $authContent) { continue }
        $authLogFound = $true

        # Brute force detection: many failures from same IP
        $failLines = @($authContent -split "`n" | Where-Object { $_ -match 'Failed password|authentication failure|FAILED LOGIN' })
        if ($failLines.Count -ge 10) {
            $failSources = @($failLines | ForEach-Object {
                if ($_ -match 'from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') { $Matches[1] }
            } | Group-Object | Sort-Object Count -Descending | Select-Object -First 5)
            $topSrc = ($failSources | ForEach-Object { "$($_.Name) x$($_.Count)" }) -join ', '
            Add-Finding 'HIGH' 'Brute Force' `
                "$($failLines.Count) Authentication Failures in auth.log" `
                "Top source IPs: $topSrc. Volume of failures is consistent with SSH brute-force." `
                @('T1110')
        }

        # Root login via SSH (unusual, often disabled)
        $rootLogins = @($authContent -split "`n" | Where-Object { $_ -match 'Accepted.*root@|for root from' })
        if ($rootLogins.Count -gt 0) {
            Add-Finding 'HIGH' 'Authentication' `
                "Direct Root SSH Login Detected ($($rootLogins.Count) occurrence(s))" `
                ($rootLogins | Select-Object -First 3 | ForEach-Object { $_.Trim() }) `
                @('T1078')
        }

        # Privilege escalation events
        $sudoHits = @($authContent -split "`n" | Where-Object { $_ -match 'sudo.*COMMAND|su\[' })
        if ($sudoHits.Count -gt 0) {
            $suspSudo = @($sudoHits | Where-Object { $_ -match '(?i)(bash|sh|python|perl|ruby|chmod|chown|cp /bin|mv /bin|dd |install )' })
            if ($suspSudo.Count -gt 0) {
                Add-Finding 'HIGH' 'Privilege Escalation' `
                    "Suspicious sudo Commands in auth.log" `
                    ($suspSudo | Select-Object -First 5 | ForEach-Object { $_.Trim() }) `
                    @('T1548.003')
            }
        }
    }

    # 14b. Detect truncated or missing logs (anti-forensics)
    $criticalLogs = @(
        '[root]/var/log/auth.log',
        '[root]/var/log/syslog',
        '[root]/var/log/kern.log',
        '[root]/var/log/dpkg.log',
        '[root]/var/log/apt/history.log'
    )
    $missingLogs = @()
    $emptyLogs   = @()
    foreach ($cl in $criticalLogs) {
        $clPath = Join-Path $uac $cl
        if (-not (Test-Path -LiteralPath $clPath)) {
            $missingLogs += $cl -replace '^\[root\]',''
        } else {
            $clInfo = Get-Item -LiteralPath $clPath -ErrorAction SilentlyContinue
            if ($clInfo -and $clInfo.Length -lt 100) {
                $emptyLogs += $cl -replace '^\[root\]',''
            }
        }
    }
    if ($missingLogs.Count -gt 0) {
        Add-Finding 'HIGH' 'Anti-Forensics' `
            "Critical Log Files Missing ($($missingLogs.Count))" `
            "Missing: $($missingLogs -join ', '). Attacker may have deleted logs to cover tracks." `
            @('T1070.002')
    }
    if ($emptyLogs.Count -gt 0) {
        Add-Finding 'HIGH' 'Anti-Forensics' `
            "Critical Log Files Truncated/Empty ($($emptyLogs.Count))" `
            "Zero or near-zero byte log files: $($emptyLogs -join ', '). Consistent with 'echo > /var/log/auth.log' log clearing technique." `
            @('T1070.002')
    }

    # 14c. Check wtmp/btmp for manipulation (via last output gaps)
    $lastOutput = Read-UACArtifactLines $uac 'live_response/system/last_-a_-F.txt'
    if ($lastOutput.Count -gt 0) {
        # Look for reboot records that suggest crashed/forced reboots
        $rebootLines = @($lastOutput | Where-Object { $_ -match 'reboot' })
        $crashReboots = @($rebootLines | Where-Object { $_ -match 'crash' })
        if ($crashReboots.Count -ge 2) {
            Add-Finding 'MEDIUM' 'Anti-Forensics' `
                "$($crashReboots.Count) System Crash/Forced Reboots in Login History" `
                "Multiple crash reboots detected in wtmp. Forced reboots can be used to clear volatile evidence, terminate rootkits for re-implantation, or evade memory-resident detections." `
                @('T1070')
        }
    }

    # 14d. Installed package anomalies (recently installed unusual tools)
    $dpkgLog = Read-UACArtifact $uac '[root]/var/log/dpkg.log'
    if ($dpkgLog) {
        $suspPkgs = @($dpkgLog -split "`n" | Where-Object {
            $_ -match ' installed ' -and
            $_ -match '(?i)(ncat|netcat|nc\b|nmap|masscan|hydra|john|hashcat|socat|proxychains|tor\b|torsocks|chisel|ligolo|revsocks|pwncat)'
        })
        if ($suspPkgs.Count -gt 0) {
            Add-Finding 'HIGH' 'Offensive Tool' `
                "Offensive/Dual-Use Packages Installed ($($suspPkgs.Count))" `
                "dpkg.log shows installation of tools commonly used by attackers: $($suspPkgs[0..4] | ForEach-Object { $_.Trim() } | Select-Object -First 5)" `
                @('T1588.002','T1072')
        }
    }

    # 14e. iptables/nftables firewall rule analysis
    $iptablesContent = $null
    foreach ($itPath in @('live_response/network/iptables.txt','live_response/network/iptables_-L_-nv.txt',
                           'live_response/network/iptables_-L_-nvx.txt','live_response/network/iptables-save.txt',
                           'live_response/network/iptables_-L_-n_-v.txt')) {
        $iptablesContent = Read-UACArtifact $uac $itPath
        if ($iptablesContent) { break }
    }
    if (-not $iptablesContent) {
        $netDir14 = Join-Path $uac 'live_response/network'
        if (Test-Path -LiteralPath $netDir14) {
            $itFile = Get-ChildItem -LiteralPath $netDir14 -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '^iptables' } | Select-Object -First 1
            if ($itFile) { $iptablesContent = Get-Content -LiteralPath $itFile.FullName -Raw -Encoding UTF8 -ErrorAction SilentlyContinue }
        }
    }
    if ($iptablesContent) {
        # Default DROP input (self-protecting malware or blocking security infra)
        if ($iptablesContent -match '(?m)INPUT.*policy\s+DROP|-P\s+INPUT\s+DROP') {
            Add-Finding 'HIGH' 'Anti-Forensics' `
                "iptables Default INPUT Policy: DROP" `
                "Default INPUT chain policy is DROP. Attackers set this after implanting to block competitor malware, prevent AV callbacks, or isolate the host from security infrastructure. Review explicit ACCEPT rules for backdoor port permits." `
                @('T1562.004')
        }
        # Port-forwarding / NAT (lateral movement relay)
        $dnatRules = @($iptablesContent -split "`n" | Where-Object { $_ -match '(?i)DNAT.*--to' })
        if ($dnatRules.Count -gt 0) {
            Add-Finding 'MEDIUM' 'Lateral Movement' `
                "iptables DNAT/Port-Forward Rules ($($dnatRules.Count))  -  Possible Traffic Relay" `
                "NAT forwarding rules suggest this host is relaying traffic for lateral movement: $($dnatRules | Select-Object -First 3 | ForEach-Object { $_.Trim() })" `
                @('T1090','T1562.004')
        }
        # Miner competitor port blocks (cryptominer self-defense)
        $suspDropPorts = @($iptablesContent -split "`n" | Where-Object {
            $_ -match '(?i)(DROP|REJECT)' -and $_ -match ':?(3333|4444|5555|6666|7777|8888|9999)\b'
        })
        if ($suspDropPorts.Count -gt 0) {
            Add-Finding 'MEDIUM' 'Cryptominer' `
                "iptables Rules Blocking Miner Stratum Port(s)  -  Competitor Defense" `
                "Firewall DROP rules on known mining ports prevent competing miners: $($suspDropPorts | Select-Object -First 3 | ForEach-Object { $_.Trim() }). Cryptominers commonly add these rules to monopolize host resources." `
                @('T1562.004','T1496')
        }
        # Unconditional ACCEPT rules (disabling firewall entirely)
        if ($iptablesContent -match '(?m)-P\s+(FORWARD|OUTPUT)\s+ACCEPT' -and $iptablesContent -match '(?m)-P\s+INPUT\s+ACCEPT') {
            Add-Finding 'INFO' 'Network' `
                "iptables All-ACCEPT Default Policies (Firewall Effectively Disabled)" `
                "All iptables chains have ACCEPT default policy  -  no firewall filtering active. Normal for many Linux servers, but worth noting alongside other indicators." `
                @('T1562.004')
        }
        Write-Host "         iptables rules analysed" -ForegroundColor DarkGray
    }

    # Also check nftables
    $nftablesContent = Read-UACArtifact $uac 'live_response/network/nftables.txt'
    if (-not $nftablesContent) { $nftablesContent = Read-UACArtifact $uac 'live_response/network/nft_list_ruleset.txt' }
    if ($nftablesContent -and $nftablesContent -match '(?i)(dnat|redirect|drop)') {
        $nftDnat = @($nftablesContent -split "`n" | Where-Object { $_ -match '(?i)(dnat|redirect)' })
        if ($nftDnat.Count -gt 0) {
            Add-Finding 'MEDIUM' 'Lateral Movement' `
                "nftables DNAT/Redirect Rules ($($nftDnat.Count))  -  Possible Traffic Relay" `
                "nftables NAT/redirect rules: $($nftDnat | Select-Object -First 3 | ForEach-Object { $_.Trim() })" `
                @('T1090','T1562.004')
        }
    }

    # 14f. APT sources.list - attacker-added malicious package repositories
    $aptSourcesContents = [System.Collections.Generic.List[string]]::new()
    $srcMain = Read-UACArtifact $uac '[root]/etc/apt/sources.list'
    if ($srcMain) { [void]$aptSourcesContents.Add($srcMain) }
    $srcListD = Join-Path $uac '[root]/etc/apt/sources.list.d'
    if (Test-Path -LiteralPath $srcListD) {
        $srcDFiles = Get-ChildItem -LiteralPath $srcListD -File -ErrorAction SilentlyContinue
        foreach ($sdf2 in $srcDFiles) {
            $sdc2 = Get-Content -LiteralPath $sdf2.FullName -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
            if ($sdc2) { [void]$aptSourcesContents.Add($sdc2) }
        }
    }
    if ($aptSourcesContents.Count -gt 0) {
        $allSrcText = $aptSourcesContents -join "`n"
        # IP-based repos (bypass DNS filtering)
        $ipSources = @($allSrcText -split "`n" | Where-Object { $_ -match '^\s*deb\s+https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' -and $_ -notmatch '^\s*#' })
        if ($ipSources.Count -gt 0) {
            Add-Finding 'HIGH' 'Persistence' `
                "APT Repository with IP-Based URL ($($ipSources.Count) entry/entries)" `
                "APT sources configured with direct IP addresses (bypasses DNS filtering): $($ipSources | ForEach-Object { $_.Trim() } | Select-Object -First 3). Can deliver malicious packages that survive reboots." `
                @('T1195.002','T1072')
            foreach ($ips2 in $ipSources) {
                if ($ips2 -match 'https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') {
                    $srcIP = $Matches[1]
                    Add-IOC 'IP' $srcIP 'APT repository IP - potential malicious package source'
                    $srcIPHit = Test-IntelHit $srcIP
                    if ($srcIPHit) {
                        Add-Finding 'CRITICAL' 'Intel Hit' `
                            "APT Repository IP Matches Threat Intel: $srcIP" `
                            "Package repository IP $srcIP matches Actor: $($srcIPHit.Actor) | Context: $($srcIPHit.Context)" `
                            @('T1195.002')
                    }
                }
            }
        }
        # Non-standard domain repos - intel check
        $nonStdSources = @($allSrcText -split "`n" | Where-Object {
            $_ -match '^\s*deb\s+https?://' -and $_ -notmatch '^\s*#' -and
            $_ -notmatch '(?i)(ubuntu\.com|debian\.org|security\.ubuntu|archive\.ubuntu|ppa\.launchpad|packages\.microsoft|download\.docker|packages\.gitlab|apt\.kubernetes|download\.opensuse|centos\.org|fedoraproject|epel|remi\.fromrpms|mariadb\.org|postgresql\.org|download\.virtualbox)'
        })
        foreach ($nss in $nonStdSources) {
            if ($nss -match 'https?://([a-z0-9][a-z0-9\.\-]+\.[a-z]{2,})') {
                $srcDomain = $Matches[1]
                $srcDomHit = Test-IntelDomain $srcDomain
                if ($srcDomHit) {
                    Add-Finding 'CRITICAL' 'Intel Hit' `
                        "APT Repository Domain Matches Threat Intel: $srcDomain" `
                        "Package source domain '$srcDomain' matches Actor: $($srcDomHit.Actor). Malicious package delivery via attacker-controlled APT repo." `
                        @('T1195.002')
                    Add-IOC 'Domain' $srcDomain "Intel-matched APT repository domain" $srcDomHit.Actor
                }
            }
        }
    }

    # ==========================================================================
    # MODULE 15  -  SPECIALIZED LINUX IMPLANT DETECTION
    # ==========================================================================
    Write-Host "[LP-UAC] Module 15: Specialized implant detection (BPFDoor/Reptile/Sysrv/XorDDoS/TinyShell)..." -ForegroundColor DarkCyan

    # 15a. BPFDoor - raw BPF socket backdoor, no open port, magic packet activation
    $bpdoorLockPath = Join-Path $uac '[root]/var/run/initd.lock'
    if (Test-Path -LiteralPath $bpdoorLockPath) {
        Add-Finding 'CRITICAL' 'BPFDoor' `
            'BPFDoor Magic Packet Lock File: /var/run/initd.lock' `
            '/var/run/initd.lock is the lock file used by the BPFDoor backdoor (attributed to China-nexus UNC2841/Red Menshen). BPFDoor attaches a BPF filter to a raw socket to intercept magic packets without opening any TCP/UDP port - invisible to netstat/ss/lsof. National security advisories from CISA, NCSC, and NSA have all documented this implant.' `
            @('T1014','T1205.001')
        Add-IOC 'FilePath' '/var/run/initd.lock' 'BPFDoor magic packet lock file'
        Add-Timeline '(At collection)' 'CRITICAL' 'BPFDoor lock file present - raw BPF socket backdoor' '/var/run/initd.lock'
        Write-Host '         [CRITICAL] BPFDoor lock file detected!' -ForegroundColor Red
    }
    # BPFDoor known masquerade names
    $bpdoorMasquerades = @('bpfdoor','/usr/libexec/postfix/master','kdevtmpfsi','rc.local.x')
    foreach ($bpm in $bpdoorMasquerades) {
        if ($psLines | Where-Object { $_ -match [regex]::Escape($bpm) -and $_ -notmatch '^\s*#' }) {
            Add-Finding 'HIGH' 'BPFDoor' `
                "BPFDoor Masquerade Process Name: $bpm" `
                "Process name '$bpm' matches known BPFDoor masquerade identity. BPFDoor disguises itself as standard system daemons to evade process-based detection." `
                @('T1014','T1036.005')
        }
    }

    # 15b. Reptile LKM rootkit
    foreach ($reptPath in @('[root]/reptile')) {
        $reptFull = Join-Path $uac $reptPath
        if (Test-Path -LiteralPath $reptFull) {
            Add-Finding 'CRITICAL' 'Rootkit' `
                "Reptile Rootkit Directory: $reptPath" `
                "$reptPath is the installation directory of the Reptile kernel-mode rootkit (open-source LKM rootkit). Reptile hides processes, files, network connections, and its own kernel module. It is substantially more capable than LD_PRELOAD userspace rootkits." `
                @('T1014','T1547.006')
            Add-IOC 'FilePath' $reptPath 'Reptile rootkit installation directory'
            Write-Host "         [CRITICAL] Reptile rootkit directory: $reptPath" -ForegroundColor Red
        }
    }
    $reptileKmod = $lsmodLines | Where-Object { $_ -match '(?i)\breptile\b|hide_by_file' }
    if ($reptileKmod) {
        Add-Finding 'CRITICAL' 'Rootkit' 'Reptile Kernel Module Loaded in lsmod' `
            "lsmod output contains Reptile rootkit module: $($reptileKmod | Select-Object -First 1)" `
            @('T1014','T1547.006')
    }
    $reptileProc = $psLines | Where-Object { $_ -match 'reptile_cmd' }
    if ($reptileProc) {
        Add-Finding 'CRITICAL' 'Rootkit' 'Reptile Control Process (reptile_cmd) Running' `
            "'reptile_cmd' is the userspace control channel process for the Reptile LKM rootkit." `
            @('T1014')
    }

    # 15c. Sysrv / DreamBus self-propagating cryptominer worm
    $sysrvPaths = @('/tmp/sysrv','/tmp/sysrv0','/tmp/xmrig','/tmp/dreambus','/tmp/dream','/var/tmp/sysrv','/tmp/kdevtmpfsi')
    foreach ($srp in $sysrvPaths) {
        $srpFull = Join-Path $uac ('[root]' + $srp)
        if (Test-Path -LiteralPath $srpFull) {
            Add-Finding 'CRITICAL' 'Cryptominer' `
                "Sysrv/DreamBus Worm Staging Path: $srp" `
                "$srp is a staging path for the Sysrv/DreamBus self-propagating cryptominer worm. These worms exploit SSH key reuse, Redis AUTH bypass, Hadoop YARN RCE, Jenkins Script Console, and known CVEs to spread laterally across enterprise infrastructure." `
                @('T1496','T1210','T1021.004')
            Add-IOC 'FilePath' $srp 'Sysrv/DreamBus worm staging path'
            Write-Host "         [CRITICAL] Sysrv/DreamBus staging path: $srp" -ForegroundColor Red
        }
    }

    # 15d. XorDDoS - dropper in /boot/, randomized hourly cron, XOR-encrypted C2
    $bootPath = Join-Path $uac '[root]/boot'
    if (Test-Path -LiteralPath $bootPath) {
        $bootUnknown = Get-ChildItem -LiteralPath $bootPath -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notmatch '(?i)(vmlinuz|initrd|grub|config|system\.map|abi-|memtest|efi|\.old|\.bak|\.cfg|\.lst|splash)' }
        foreach ($bu in $bootUnknown) {
            Add-Finding 'CRITICAL' 'Rootkit' `
                "Non-Standard File in /boot/: $($bu.Name)" `
                "/boot/$($bu.Name) ($($bu.Length) bytes) is not a recognised boot component. XorDDoS DDoS malware drops its rootkit loader in /boot/ to persist across reboots and evade security tools that skip the boot partition." `
                @('T1543','T1036.005')
            Add-IOC 'FilePath' "/boot/$($bu.Name)" 'Suspicious file in /boot/ - XorDDoS pattern'
            Write-Host "         [CRITICAL] Unknown file in /boot/: $($bu.Name)" -ForegroundColor Red
        }
    }
    $hourlyPath = Join-Path $uac '[root]/etc/cron.hourly'
    if (Test-Path -LiteralPath $hourlyPath) {
        $suspHourly = Get-ChildItem -LiteralPath $hourlyPath -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^[a-zA-Z0-9]{6,12}$' -and $_.Name -notmatch '(?i)(anacron|sysstat|0hourly)' }
        foreach ($sh in $suspHourly) {
            $shContent = Get-Content -LiteralPath $sh.FullName -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
            if ($shContent -and $shContent -match '(?i)(wget|curl|/tmp|/var/tmp|xorddos|ddos|flood|/dev/shm)') {
                Add-Finding 'CRITICAL' 'Persistence' `
                    "XorDDoS-Style Hourly Cron Dropper: /etc/cron.hourly/$($sh.Name)" `
                    "Randomized-name hourly cron entry downloading/executing from volatile path. Characteristic XorDDoS persistence mechanism." `
                    @('T1053.003','T1496')
                Add-IOC 'FilePath' "/etc/cron.hourly/$($sh.Name)" 'XorDDoS-style hourly cron dropper'
            }
        }
    }

    # 15e. TinyShell (tsh/tshd) - encrypted reverse shell used by China-nexus APT groups
    $tshNames = @('tsh','tshd','tshrc','.tshrc')
    foreach ($hashLine in $exeHashLines) {
        if ($hashLine -match '^([a-fA-F0-9]{32})\s+(.+)') {
            $tshPath = $Matches[2].Trim()
            $tshBase = ($tshPath -split '[/\\]')[-1].ToLower()
            if ($tshNames -contains $tshBase) {
                Add-Finding 'CRITICAL' 'Backdoor' `
                    "TinyShell (tsh) Backdoor Binary: $tshPath" `
                    "Binary named '$tshBase' is the TinyShell encrypted reverse shell backdoor. TinyShell (tsh/tshd) is a lightweight Linux backdoor providing encrypted remote shell access, frequently deployed by China-nexus actors (APT1, APT10, APT41) for persistent access." `
                    @('T1059.004','T1543')
                Add-IOC 'FilePath' $tshPath 'TinyShell (tsh) backdoor binary'
                Write-Host "         [CRITICAL] TinyShell binary: $tshPath" -ForegroundColor Red
            }
        }
    }

    # ==========================================================================
    # MODULE 16  -  CONTAINER & DOCKER ENVIRONMENT DETECTION
    # ==========================================================================
    Write-Host "[LP-UAC] Module 16: Container/Docker analysis..." -ForegroundColor DarkCyan

    $dockerSockPath = Join-Path $uac '[root]/var/run/docker.sock'
    $dockerEnvPath  = Join-Path $uac '[root]/.dockerenv'

    if (Test-Path -LiteralPath $dockerSockPath) {
        Add-Finding 'HIGH' 'Container' `
            'Docker Daemon Socket Present: /var/run/docker.sock' `
            '/var/run/docker.sock provides root-equivalent control of the Docker daemon. Any process (or attacker) with access to this socket can spawn a privileged container mounting the host filesystem, achieving full host escape. This is T1611 Container Escape.' `
            @('T1611','T1610')
        Add-IOC 'FilePath' '/var/run/docker.sock' 'Docker daemon socket - container escape path'
    }
    if (Test-Path -LiteralPath $dockerEnvPath) {
        Add-Finding 'MEDIUM' 'Container' `
            'UAC Collection Ran Inside a Docker Container (/.dockerenv Present)' `
            '/.dockerenv confirms collection ran inside a container. Evaluate whether the attacker has escaped to the host via docker.sock, privileged mode, or kernel namespace escape techniques.' `
            @('T1611')
    }

    $cgroupContent = Read-UACArtifact $uac '[root]/proc/1/cgroup'
    if ($cgroupContent -and $cgroupContent -match '(?i)(docker|lxc|kubepods|containerd)') {
        $cgroupSample = ($cgroupContent -split "`n" | Select-Object -First 3 | ForEach-Object { $_.Trim() }) -join ' | '
        Add-Finding 'MEDIUM' 'Container' `
            'cgroup Hierarchy Indicates Container Runtime' `
            "PID 1 cgroup confirms container environment: $cgroupSample. Assess whether attacker pivoted to host via container escape." `
            @('T1611')
    }

    $nsenterHits = @($lsofLines | Where-Object { $_ -match '(?i)(nsenter|unshare|pivot_root)' })
    if ($nsenterHits.Count -gt 0) {
        Add-Finding 'HIGH' 'Container' `
            "Namespace Escape Tool Active: $($nsenterHits.Count) reference(s) in lsof" `
            "nsenter/unshare/pivot_root detected in open file handles. These tools are used for Linux namespace escape and container breakout." `
            @('T1611')
    }

    # Check UAC container artifact directory (Docker inspect, container list)
    $uacContainerPath = Join-Path $uac 'live_response/containers'
    if (Test-Path -LiteralPath $uacContainerPath) {
        $contFiles = Get-ChildItem -LiteralPath $uacContainerPath -File -ErrorAction SilentlyContinue
        foreach ($cf in $contFiles) {
            $cfContent = Get-Content -LiteralPath $cf.FullName -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
            if (-not $cfContent) { continue }
            # Flag any privileged containers
            if ($cfContent -match '"Privileged":\s*true') {
                Add-Finding 'HIGH' 'Container' `
                    "Privileged Container Detected in Docker Inventory: $($cf.Name)" `
                    "Docker inventory shows a container running with --privileged flag. Privileged containers have full access to host devices and can trivially escape to the host kernel." `
                    @('T1611')
            }
            # Flag containers with docker.sock mounted
            if ($cfContent -match '/var/run/docker\.sock') {
                Add-Finding 'HIGH' 'Container' `
                    "Container with docker.sock Bind-Mount: $($cf.Name)" `
                    "A container has /var/run/docker.sock mounted, providing host-level Docker API access from within the container - a common lateral movement and escape vector." `
                    @('T1611')
            }
        }
    }

    # ==========================================================================
    # MODULE 17  -  LATERAL MOVEMENT ARTIFACTS
    # ==========================================================================
    Write-Host "[LP-UAC] Module 17: Lateral movement artifact analysis..." -ForegroundColor DarkCyan

    # 17a. ARP cache - reveals LAN hosts communicated with
    $arpLines = Read-UACArtifactLines $uac 'live_response/network/arp.txt'
    $arpHosts = [System.Collections.Generic.List[string]]::new()
    foreach ($arpLine in $arpLines) {
        if ($arpLine -match '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') {
            $arpIP = $Matches[1]
            if ($arpIP -notmatch '^(127\.|255\.|0\.0\.)') {
                [void]$arpHosts.Add($arpIP)
                $hit = Test-IntelHit $arpIP
                if ($hit) {
                    Add-Finding 'CRITICAL' 'Intel Hit' `
                        "ARP Cache Entry Matches Threat Intel: $arpIP" `
                        "Host $arpIP in ARP cache matches Actor: $($hit.Actor) | Context: $($hit.Context). Direct layer-2 communication with a known-malicious host." `
                        @('T1018','T1071.001')
                    Add-IOC 'IP' $arpIP "ARP-cached intel-matched host" $hit.Actor
                }
            }
        }
    }
    if ($arpHosts.Count -gt 0) {
        $arpSample = ($arpHosts | Sort-Object -Unique | Select-Object -First 15) -join ', '
        Add-Finding 'INFO' 'Lateral Movement' `
            "ARP Cache: $($arpHosts.Count) Host(s) Recently Communicated With" `
            "ARP-cached hosts (potential pivot sources or lateral movement targets): $arpSample" `
            @('T1018')
    }

    # 17b. SSH known_hosts - reveals hosts victim has SSHed to
    foreach ($khPath in @('[root]/root/.ssh/known_hosts','[root]/home/worker/.ssh/known_hosts')) {
        $khContent = Read-UACArtifact $uac $khPath
        if (-not $khContent) { continue }
        $khHosts = @($khContent -split "`n" | Where-Object { $_ -match '^\S' -and $_ -notmatch '^#' -and $_ -notmatch '^\[' } |
            ForEach-Object { ($_ -split '[\s,]')[0] } | Where-Object { $_ })
        if ($khHosts.Count -gt 0) {
            Add-Finding 'MEDIUM' 'Lateral Movement' `
                "SSH known_hosts: $($khHosts.Count) Previously-Connected Host(s) ($khPath)" `
                "Hosts in known_hosts represent prior outbound SSH connections - evidence of lateral movement or pivot activity: $($khHosts | Select-Object -First 10 | ForEach-Object { $_ } )" `
                @('T1021.004','T1078')
            foreach ($kh in ($khHosts | Select-Object -First 20)) { Add-IOC 'Hostname' $kh "SSH known_hosts entry" }
        }
    }

    # 17c. SSH private keys accessible in collection (exfiltration + lateral movement risk)
    foreach ($keyPath in @('[root]/root/.ssh/id_rsa','[root]/root/.ssh/id_ed25519','[root]/root/.ssh/id_ecdsa',
                           '[root]/home/worker/.ssh/id_rsa','[root]/home/worker/.ssh/id_ed25519')) {
        $keyContent = Read-UACArtifact $uac $keyPath
        if ($keyContent -and $keyContent -match 'BEGIN.{0,20}PRIVATE KEY') {
            Add-Finding 'HIGH' 'Credential Theft' `
                "SSH Private Key Readable in UAC Collection: $keyPath" `
                "Private SSH key at $keyPath was collected by UAC. An attacker with equivalent filesystem access can exfiltrate this key for lateral movement and persistence across infrastructure." `
                @('T1552.004','T1021.004')
            Add-IOC 'FilePath' $keyPath 'Accessible SSH private key'
        }
    }

    # 17d. Routing table anomalies (added routes for traffic interception/redirection)
    $routeLines = Read-UACArtifactLines $uac 'live_response/network/route.txt'
    if ($routeLines.Count -gt 3) {
        $gateways = @($routeLines | Where-Object {
            $_ -match '^\d' -and $_ -notmatch '(^0\.0\.0\.0|^169\.254\.|^127\.|^255\.)' -and $_ -match '\bUG\b'
        })
        if ($gateways.Count -gt 3) {
            Add-Finding 'MEDIUM' 'Lateral Movement' `
                "$($gateways.Count) Non-Default Gateway Route(s) in Routing Table" `
                "Multiple explicit gateway routes detected. Attackers add routes to redirect traffic through compromised hosts for MitM attacks or to reach isolated network segments: $($gateways | Select-Object -First 5 | ForEach-Object { $_.Trim() })" `
                @('T1090','T1557')
        }
    }

    # 17e. Rclone / data exfiltration tool detection (used by ransomware groups and APTs for staging)
    $rcloneHits = @($exeHashLines | Where-Object { $_ -match '\brclone\b' })
    $rcloneHits += @($psLines      | Where-Object { $_ -match '\brclone\b' })
    if ($rcloneHits.Count -gt 0) {
        Add-Finding 'HIGH' 'Exfiltration' `
            "Rclone Data Exfiltration Tool Detected" `
            "rclone is a cloud-sync tool widely used by ransomware groups (RansomHub, BlackCat, Akira, Clop, LockBit) and APTs for bulk data exfiltration to cloud storage before encryption. Evidence: $($rcloneHits | Select-Object -First 2 | ForEach-Object { $_.Trim() })" `
            @('T1537','T1567.002')
        Add-IOC 'FileName' 'rclone' 'Data exfiltration tool - pre-ransomware or APT staging'
    }

    # ==========================================================================
    # MODULE 18  -  LOKI / THOR YARA & IOC SCAN
    # ==========================================================================
    Write-Host "[LP-UAC] Module 18: Loki/Thor YARA & IOC scan..." -ForegroundColor DarkCyan

    $rootScanPath18 = Join-Path $uac '[root]'
    if (Test-Path -LiteralPath $rootScanPath18) {

        # Auto-detect scanner under .\tools\ (relative to module): prefer Thor, then Loki
        $m18Exe  = $null
        $m18Type = $null   # 'thor' or 'loki'
        $m18Tools = Join-Path $PSScriptRoot '..\tools'

        if (Test-Path $m18Tools) {
            $thorCands = Get-ChildItem -Path $m18Tools -Recurse -ErrorAction SilentlyContinue |
                         Where-Object { $_.Extension -eq '.exe' -and $_.BaseName -match '(?i)^thor' }
            $thorFound = $thorCands | Select-Object -First 1
            if ($thorFound) {
                $m18Exe  = $thorFound.FullName
                $m18Type = 'thor'
            } else {
                $lokiFound = Get-ChildItem -Path $m18Tools -Recurse -ErrorAction SilentlyContinue |
                             Where-Object { $_.Name -match '(?i)^loki\.(exe|py)$' } |
                             Select-Object -First 1
                if ($lokiFound) {
                    $m18Exe  = $lokiFound.FullName
                    $m18Type = 'loki'
                }
            }
        }

        if (-not $m18Exe) {
            Add-Finding 'INFO' 'YARA/IOC Scanner' `
                'Loki/Thor Not Available - YARA Scan Skipped' `
                "No Thor or Loki binary found under .\tools\. Place thor-lite.exe or loki.exe there to enable YARA/IOC scanning of the UAC dump root filesystem." `
                @()
            Write-Host "         No scanner found under .\tools\ - skipping" -ForegroundColor DarkGray
        } else {
            Write-Host ("         Scanner : {0} ({1})" -f (Split-Path $m18Exe -Leaf), $m18Type) -ForegroundColor DarkGray
            Write-Host "         Target  : $rootScanPath18" -ForegroundColor DarkGray

            $m18Alerts   = [System.Collections.Generic.List[string]]::new()
            $m18Warnings = [System.Collections.Generic.List[string]]::new()
            $m18Ok       = $false

            try {
                if ($m18Type -eq 'thor') {
                    # Thor: capture stdout+stderr, filter ALERT/WARNING lines
                    $thorOut = & $m18Exe '-p', $rootScanPath18, '--fsonly', '--nolog' 2>&1
                    foreach ($tLine in $thorOut) {
                        $tl = "$tLine"
                        if     ($tl -match '(?i)\bALERT\b')   { [void]$m18Alerts.Add($tl.Trim()) }
                        elseif ($tl -match '(?i)\bWARNING\b') { [void]$m18Warnings.Add($tl.Trim()) }
                    }
                    $m18Ok = $true
                } else {
                    # Loki: CSV output to temp file, then parse
                    $lokiTmp  = Join-Path $env:TEMP ("lp_loki_" + (Get-Date -Format 'yyyyMMdd_HHmmss') + ".csv")
                    $lokiArgs = @('-p', $rootScanPath18, '--csv', '--noprocscan', '--noindicator', '--dontwait', '--intense', '--logfile', $lokiTmp)
                    if ($m18Exe -match '\.py$') {
                        $pyCmd = Get-Command python -ErrorAction SilentlyContinue
                        if (-not $pyCmd) { $pyCmd = Get-Command python3 -ErrorAction SilentlyContinue }
                        if ($pyCmd) { & $pyCmd.Source $m18Exe @lokiArgs | Out-Null; $m18Ok = $true }
                    } else {
                        & $m18Exe @lokiArgs | Out-Null
                        $m18Ok = $true
                    }
                    if ($m18Ok -and (Test-Path $lokiTmp)) {
                        $lokiRows = Import-Csv -Path $lokiTmp -ErrorAction SilentlyContinue
                        if (-not $lokiRows) {
                            $lokiRows = @(Get-Content $lokiTmp -ErrorAction SilentlyContinue | ForEach-Object {
                                $c = $_ -split ','
                                if ($c.Count -ge 5) {
                                    [PSCustomObject]@{ EVENTTYPE = $c[2].Trim('"'); MESSAGE = ($c[4..($c.Count-1)] -join ',').Trim('"') }
                                }
                            })
                        }
                        foreach ($lr in @($lokiRows)) {
                            $let = if ($lr.EVENTTYPE) { $lr.EVENTTYPE.Trim() } else { '' }
                            $lmg = if ($lr.MESSAGE)   { $lr.MESSAGE.Trim()   } else { '' }
                            if     ($let -eq 'ALERT')   { [void]$m18Alerts.Add($lmg) }
                            elseif ($let -eq 'WARNING') { [void]$m18Warnings.Add($lmg) }
                        }
                        Remove-Item $lokiTmp -Force -ErrorAction SilentlyContinue
                    }
                }
            } catch {
                Add-Finding 'INFO' 'YARA/IOC Scanner' 'YARA Scanner Error' `
                    "Scanner ($m18Type) encountered an error: $($_.Exception.Message)" @()
            }

            if ($m18Ok) {
                # ALERT-level hits -> CRITICAL findings (first 20 individually, remainder as one overflow)
                $alertArr = @($m18Alerts)
                foreach ($al in ($alertArr | Select-Object -First 20)) {
                    $alTitle = if ($al.Length -gt 120) { $al.Substring(0,120) + '...' } else { $al }
                    Add-Finding 'CRITICAL' 'YARA/IOC Scanner' `
                        "YARA ALERT: $alTitle" `
                        $al `
                        @('T1027','T1059')
                }
                if ($alertArr.Count -gt 20) {
                    Add-Finding 'CRITICAL' 'YARA/IOC Scanner' `
                        "YARA ALERT: $($alertArr.Count - 20) additional alert(s) truncated" `
                        "Scanner produced $($alertArr.Count) total ALERT hits. Only first 20 shown individually." `
                        @()
                }

                # WARNING-level hits -> single HIGH finding with sample
                if ($m18Warnings.Count -gt 0) {
                    $wSample = ($m18Warnings | Select-Object -First 5 | ForEach-Object {
                        if ($_.Length -gt 200) { $_.Substring(0,200) + '...' } else { $_ }
                    }) -join ' | '
                    Add-Finding 'HIGH' 'YARA/IOC Scanner' `
                        "YARA/IOC Warnings: $($m18Warnings.Count) suspicious match(es)" `
                        "Sample: $wSample" `
                        @('T1027')
                }

                # Summary INFO finding
                $m18Name = Split-Path $m18Exe -Leaf
                Add-Finding 'INFO' 'YARA/IOC Scanner' `
                    "YARA/IOC Scan Complete ($m18Name): $($m18Alerts.Count) alert(s), $($m18Warnings.Count) warning(s)" `
                    "Scanned: $rootScanPath18" `
                    @()

                $m18Color = if ($m18Alerts.Count -gt 0) { 'Red' } elseif ($m18Warnings.Count -gt 0) { 'Yellow' } else { 'Green' }
                Write-Host ("         Scan complete: {0} alert(s), {1} warning(s)" -f $m18Alerts.Count, $m18Warnings.Count) -ForegroundColor $m18Color
            }
        }
    }

    # ==========================================================================
    # MODULE 19  -  INITIAL ACCESS RECONSTRUCTION
    # ==========================================================================
    Write-Host "[LP-UAC] Module 19: Initial access reconstruction..." -ForegroundColor DarkCyan

    $initialAccessHypotheses = [System.Collections.Generic.List[PSCustomObject]]::new()
    $initialAccessRanked = @()
    $initialAccessTopVector = 'Unknown'
    $initialAccessConfidence = 'LOW'
    $initialAccessScore = 0

    function Add-InitialAccessHypothesis {
        param(
            [string]$Vector,
            [int]$Score,
            [string[]]$Evidence,
            [string[]]$Techniques,
            [string]$Rationale
        )
        if ($Score -le 0) { return }
        $clamped = [Math]::Min([Math]::Max($Score, 0), 100)
        $confIA = if ($clamped -ge 70) { 'HIGH' } elseif ($clamped -ge 40) { 'MEDIUM' } else { 'LOW' }
        $initialAccessHypotheses.Add([PSCustomObject]@{
            Vector     = $Vector
            Score      = $clamped
            Confidence = $confIA
            Evidence   = @($Evidence | Where-Object { $_ -and $_.Trim() } | Select-Object -Unique)
            Techniques = @($Techniques | Where-Object { $_ } | Select-Object -Unique)
            Rationale  = $Rationale
        })
    }

    # 19a. Gather authentication and entry telemetry
    $lastLinesIA = Read-UACArtifactLines $uac 'live_response/system/last_-a_-F.txt'
    $remoteLoginLines = @($lastLinesIA | Where-Object { $_ -match '\d{1,3}(?:\.\d{1,3}){3}' -and $_ -notmatch 'reboot|wtmp' })
    $remoteLoginIps = @($remoteLoginLines | ForEach-Object {
        if ($_ -match '(\d{1,3}(?:\.\d{1,3}){3})') { $Matches[1] }
    } | Sort-Object -Unique)
    $remoteLoginUsers = @($remoteLoginLines | ForEach-Object {
        if ($_ -match '^\s*(\S+)') { $Matches[1] }
    } | Sort-Object -Unique)

    $authFailTotal = 0
    $authSuccessTotal = 0
    $authInvalidUserTotal = 0
    $failByIP = @{}
    $successByIP = @{}
    foreach ($alpIA in @('[root]/var/log/auth.log','[root]/var/log/secure','[root]/var/log/auth.log.1')) {
        $authLinesIA = Read-UACArtifactLines $uac $alpIA
        foreach ($alIA in $authLinesIA) {
            if ($alIA -match 'Failed password|authentication failure|FAILED LOGIN') {
                $authFailTotal++
                if ($alIA -match '(?i)invalid user') { $authInvalidUserTotal++ }
                if ($alIA -match 'from\s+([0-9a-fA-F\.:]+)') {
                    $fip = $Matches[1]
                    if ($failByIP.ContainsKey($fip)) { $failByIP[$fip]++ } else { $failByIP[$fip] = 1 }
                }
            }
            if ($alIA -match 'Accepted\s+(password|publickey|keyboard-interactive/pam)\s+for\s+\S+\s+from\s+([0-9a-fA-F\.:]+)') {
                $authSuccessTotal++
                $sip = $Matches[2]
                if ($successByIP.ContainsKey($sip)) { $successByIP[$sip]++ } else { $successByIP[$sip] = 1 }
            }
        }
    }
    $failIPs = @($failByIP.Keys)
    $successIPs = @($successByIP.Keys)
    $ipsWithFailThenSuccess = @($successIPs | Where-Object { $failByIP.ContainsKey($_) })
    $maxFailPerIP = 0
    if ($failByIP.Count -gt 0) {
        $maxFailPerIP = (($failByIP.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1).Value)
    }

    # 19b. Gather externally reachable service exposure
    $listenLinesIA = Read-UACArtifactLines $uac 'live_response/network/ss_-tlnp.txt'
    if ($listenLinesIA.Count -eq 0) { $listenLinesIA = Read-UACArtifactLines $uac 'live_response/network/ss_-tanp.txt' }
    $publicListenPortsList = [System.Collections.Generic.List[int]]::new()
    foreach ($llIA in $listenLinesIA) {
        if ($llIA -match '^LISTEN\s+\d+\s+\d+\s+(\S+)') {
            $localIA = $Matches[1]
            if ($localIA -match '^127\.|^\[::1\]|^::1') { continue }
            if ($localIA -match ':(\d+)$') {
                [void]$publicListenPortsList.Add([int]$Matches[1])
            }
        }
    }
    $publicListenPorts = @($publicListenPortsList | Sort-Object -Unique)
    $publicWebPorts = @($publicListenPorts | Where-Object { $_ -in @(80,443,8080,8443,8000,8888,3000,5000,9000) })
    $publicContainerPorts = @($publicListenPorts | Where-Object { $_ -in @(2375,2376,4243,6443) })

    # 19c. Reuse already-derived behavioral findings for scenario scoring
    $webshellFindingsIA = @($findings | Where-Object { $_.Category -eq 'Webshell' -or $_.Title -match 'Web Server Process Spawning Shell' })
    $containerFindingsIA = @($findings | Where-Object { $_.Category -eq 'Container' })
    $supplyFindingsIA = @($findings | Where-Object {
        ($_.Techniques -contains 'T1195.002') -or $_.Category -eq 'DNS Hijack' -or $_.Title -match 'APT Repository'
    })
    $nopassFindingsIA = @($findings | Where-Object { $_.Title -match 'Sudoers NOPASSWD|All-Access Grant' })
    $pamBypassFindingsIA = @($findings | Where-Object { $_.Title -match 'PAM Authentication Bypass' })
    $webshellIOCCountIA = (@($iocList | Where-Object { $_.Context -match 'Webshell candidate' })).Count
    $loginctlWorkerIA = Read-UACArtifact $uac 'live_response/system/loginctl_user-status_worker.txt'
    $hasSshSessionChainIA = $false
    if ($loginctlWorkerIA -and $loginctlWorkerIA -match 'sshd-session') { $hasSshSessionChainIA = $true }

    # Vector 1: Valid SSH credentials / account abuse
    $scoreV1 = 0
    $evV1 = [System.Collections.Generic.List[string]]::new()
    if ($remoteLoginIps.Count -gt 0) {
        $scoreV1 += 35
        [void]$evV1.Add("Remote SSH logins seen from: $($remoteLoginIps -join ', ')")
    }
    if ($remoteLoginLines.Count -ge 2) {
        $scoreV1 += 10
        [void]$evV1.Add("Repeated remote SSH sessions observed ($($remoteLoginLines.Count) entries)")
    }
    if ($successIPs.Count -gt 0) {
        $scoreV1 += 30
        [void]$evV1.Add("Successful SSH authentication in auth logs from: $($successIPs -join ', ')")
    }
    if ($hasSshSessionChainIA) {
        $scoreV1 += 20
        [void]$evV1.Add('loginctl session tree confirms sshd-session chain with interactive sudo escalation')
    }
    if ($authSuccessTotal -gt 0 -and $ipsWithFailThenSuccess.Count -eq 0) {
        $scoreV1 += 10
        [void]$evV1.Add('Success events not preceded by high-volume failures (credentialed access pattern)')
    }
    if ($authFailTotal -gt 0 -and $authFailTotal -lt 10) {
        $scoreV1 += 10
        [void]$evV1.Add("Low failed-auth volume ($authFailTotal) before access")
    }
    if ($nopassFindingsIA.Count -gt 0) {
        $scoreV1 += 10
        [void]$evV1.Add('NOPASSWD sudo rule enabled rapid root escalation post-login')
    }
    if ($pamBypassFindingsIA.Count -gt 0) {
        $scoreV1 += 5
        [void]$evV1.Add('PAM auth-chain tampering present (may be post-compromise hardening/backdoor)')
    }
    Add-InitialAccessHypothesis `
        'Valid SSH Credentials / Account Abuse' `
        $scoreV1 `
        @($evV1) `
        @('T1078','T1021.004') `
        'Most consistent with attacker obtaining/using valid credentials for remote SSH access, then escalating privileges locally.'

    # Vector 2: SSH brute-force / password spray
    $scoreV2 = 0
    $evV2 = [System.Collections.Generic.List[string]]::new()
    if ($authFailTotal -ge 20) {
        $scoreV2 += 25
        [void]$evV2.Add("$authFailTotal failed authentication event(s) in auth logs")
    }
    if ($maxFailPerIP -ge 10) {
        $scoreV2 += 25
        [void]$evV2.Add("Single-source failure concentration observed (max per IP: $maxFailPerIP)")
    }
    if ($ipsWithFailThenSuccess.Count -gt 0) {
        $scoreV2 += 25
        [void]$evV2.Add("Failure-to-success transition for source(s): $($ipsWithFailThenSuccess -join ', ')")
    }
    if ($authInvalidUserTotal -ge 5) {
        $scoreV2 += 10
        [void]$evV2.Add("$authInvalidUserTotal invalid-user auth attempt(s)")
    }
    if ($remoteLoginIps.Count -gt 0) {
        $scoreV2 += 10
        [void]$evV2.Add('Remote SSH sessions were established after auth activity')
    }
    if ($successIPs.Count -gt 0) {
        $scoreV2 += 10
        [void]$evV2.Add('At least one successful auth event exists in same artifact set')
    }
    Add-InitialAccessHypothesis `
        'SSH Brute Force / Password Spray' `
        $scoreV2 `
        @($evV2) `
        @('T1110','T1078','T1021.004') `
        'Pattern indicates password guessing followed by successful authentication.'

    # Vector 3: Public-facing app exploit leading to webshell
    $scoreV3 = 0
    $evV3 = [System.Collections.Generic.List[string]]::new()
    if ($webshellFindingsIA.Count -gt 0) {
        $scoreV3 += 45
        [void]$evV3.Add("$($webshellFindingsIA.Count) webshell execution/file indicator(s)")
    }
    if ($publicWebPorts.Count -gt 0) {
        $scoreV3 += 20
        [void]$evV3.Add("Public web-facing listener(s): $($publicWebPorts -join ', ')")
    }
    if ($webshellFindingsIA | Where-Object { $_.Title -match 'Web Server Process Spawning Shell' }) {
        $scoreV3 += 20
        [void]$evV3.Add('Runtime shell spawned by web/app server process')
    }
    if ($webshellIOCCountIA -gt 0) {
        $scoreV3 += 10
        [void]$evV3.Add("$webshellIOCCountIA webshell IOC candidate(s) recorded")
    }
    Add-InitialAccessHypothesis `
        'Exploit of Public-Facing Application (Webshell Path)' `
        $scoreV3 `
        @($evV3) `
        @('T1190','T1505.003','T1059.004') `
        'Compromise may have begun through internet-facing application exploitation with subsequent webshell execution.'

    # Vector 4: Package/repository or update-channel compromise
    $scoreV4 = 0
    $evV4 = [System.Collections.Generic.List[string]]::new()
    if ($supplyFindingsIA.Count -gt 0) {
        $scoreV4 += 45
        [void]$evV4.Add("$($supplyFindingsIA.Count) supply-chain / repository tampering signal(s)")
    }
    if (@($findings | Where-Object { $_.Category -eq 'DNS Hijack' }).Count -gt 0) {
        $scoreV4 += 20
        [void]$evV4.Add('/etc/hosts redirection/DNS hijack indicators present')
    }
    if (@($findings | Where-Object { $_.Title -match 'Offensive/Dual-Use Packages Installed' }).Count -gt 0) {
        $scoreV4 += 10
        [void]$evV4.Add('Suspicious package install activity observed')
    }
    if (@($supplyFindingsIA | Where-Object { $_.Category -eq 'Intel Hit' }).Count -gt 0) {
        $scoreV4 += 15
        [void]$evV4.Add('Repository IOC matched threat intelligence')
    }
    Add-InitialAccessHypothesis `
        'Supply Chain / Malicious Repository Path' `
        $scoreV4 `
        @($evV4) `
        @('T1195.002','T1072') `
        'Initial compromise may have occurred through manipulated package sources, malicious repos, or update-channel abuse.'

    # Vector 5: Container control-plane exposure / breakout path
    $scoreV5 = 0
    $evV5 = [System.Collections.Generic.List[string]]::new()
    if ($containerFindingsIA.Count -gt 0) {
        $scoreV5 += 20
        [void]$evV5.Add("$($containerFindingsIA.Count) container-risk finding(s) present")
    }
    if (@($containerFindingsIA | Where-Object { $_.Title -match 'docker\.sock|Privileged|Namespace Escape' }).Count -gt 0) {
        $scoreV5 += 35
        [void]$evV5.Add('Privileged container / docker.sock / namespace-escape telemetry observed')
    }
    if ($publicContainerPorts.Count -gt 0) {
        $scoreV5 += 20
        [void]$evV5.Add("Container-management port(s) reachable: $($publicContainerPorts -join ', ')")
    }
    if (@($containerFindingsIA | Where-Object { $_.Title -match 'Docker Container|cgroup' }).Count -gt 0) {
        $scoreV5 += 10
        [void]$evV5.Add('Host appears containerized or container-adjacent')
    }
    Add-InitialAccessHypothesis `
        'Container Control-Plane Abuse / Escape' `
        $scoreV5 `
        @($evV5) `
        @('T1611','T1210') `
        'Compromise may have originated from container exposure and then escaped/pivoted to host context.'

    # Vector 6: Local interactive abuse / insider / pre-existing foothold
    $scoreV6 = 0
    $evV6 = [System.Collections.Generic.List[string]]::new()
    $hasRemoteAuthEvidenceIA = ($remoteLoginIps.Count -gt 0) -or ($successIPs.Count -gt 0) -or $hasSshSessionChainIA
    if (-not $hasRemoteAuthEvidenceIA) {
        $scoreV6 += 25
        [void]$evV6.Add('No clear remote authentication source observed in available artifacts')
        if ($nopassFindingsIA.Count -gt 0) {
            $scoreV6 += 20
            [void]$evV6.Add('Local privilege escalation path via sudoers NOPASSWD')
        }
        if ($pamBypassFindingsIA.Count -gt 0) {
            $scoreV6 += 20
            [void]$evV6.Add('Authentication bypass configured in PAM stack')
        }
        if (@($findings | Where-Object { $_.Category -eq 'Credential Theft' -and $_.Detail -match '/tmp/' }).Count -gt 0) {
            $scoreV6 += 10
            [void]$evV6.Add('Credential dump artifact in local staging path suggests interactive local abuse')
        }
    }
    Add-InitialAccessHypothesis `
        'Local Interactive Access / Insider / Prior Foothold' `
        $scoreV6 `
        @($evV6) `
        @('T1078','T1548.003','T1556.003') `
        'Initial foothold may predate collected logs or have occurred via local/interactive access prior to current telemetry window.'

    # 19d. Rank hypotheses and produce triage findings
    $initialAccessRanked = @($initialAccessHypotheses | Sort-Object Score -Descending)
    if ($initialAccessRanked.Count -gt 0 -and $initialAccessRanked[0].Score -gt 0) {
        $topIA = $initialAccessRanked[0]
        $initialAccessTopVector = $topIA.Vector
        $initialAccessConfidence = $topIA.Confidence
        $initialAccessScore = $topIA.Score

        $iaSev = if ($topIA.Score -ge 70) { 'CRITICAL' } elseif ($topIA.Score -ge 40) { 'HIGH' } else { 'MEDIUM' }
        $iaEvidence = ($topIA.Evidence | Select-Object -First 6) -join '; '
        Add-Finding $iaSev 'Initial Access' `
            "Most Likely Initial Access Vector: $($topIA.Vector) ($($topIA.Confidence) confidence, $($topIA.Score)/100)" `
            "$($topIA.Rationale) Evidence: $iaEvidence" `
            $topIA.Techniques
        Add-Timeline '(Reconstruction)' $iaSev "Likely initial access path: $($topIA.Vector) ($($topIA.Score)/100)" ''

        $altIA = @($initialAccessRanked | Select-Object -Skip 1 -First 2)
        if ($altIA.Count -gt 0) {
            $altText = ($altIA | ForEach-Object {
                $altEv = ($_.Evidence | Select-Object -First 2) -join '; '
                "$($_.Vector) [$($_.Confidence) $($_.Score)/100] - $altEv"
            }) -join ' | '
            Add-Finding 'INFO' 'Initial Access' `
                'Alternative Initial Access Hypotheses (ranked)' `
                $altText `
                @()
        }

        foreach ($rip in $remoteLoginIps) {
            Add-IOC 'IP' $rip 'Potential initial-access source IP (ranked hypothesis)'
        }

        Write-Host ("         Top initial-access hypothesis: {0} ({1} {2}/100)" -f $initialAccessTopVector, $initialAccessConfidence, $initialAccessScore) -ForegroundColor DarkYellow
    } else {
        Add-Finding 'INFO' 'Initial Access' `
            'Initial Access Vector Not Confidently Reconstructed' `
            'Available artifacts were insufficient to rank an initial entry path with confidence. Expand telemetry collection (full auth/web logs, edge/WAF/load balancer logs, IDS, EDR, cloud control-plane logs).' `
            @()
        Write-Host "         Initial access vector could not be confidently reconstructed from available artifacts" -ForegroundColor DarkGray
    }

    # ==========================================================================
    # BUILD HTML REPORT
    # ==========================================================================
    Write-Host "[LP-UAC] Building HTML report..." -ForegroundColor DarkCyan

    $collId      = Split-Path $uac -Leaf
    $reportDate  = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $critCount   = ($findings | Where-Object { $_.Severity -eq 'CRITICAL' } | Measure-Object).Count
    $highCount   = ($findings | Where-Object { $_.Severity -eq 'HIGH'     } | Measure-Object).Count
    $medCount    = ($findings | Where-Object { $_.Severity -eq 'MEDIUM'   } | Measure-Object).Count
    $totalCount  = $findings.Count

    # Executive summary model (plain-language high-level reconstruction)
    $hasRootkitSummary = @($findings | Where-Object { $_.Category -eq 'Rootkit' -or $_.Title -match 'LD_PRELOAD|Rootkit' }).Count -gt 0
    $hasHiddenSummary  = @($findings | Where-Object { $_.Category -eq 'Process Hiding' -or $_.Title -match 'Hidden PID|Hidden Process' }).Count -gt 0
    $hasC2Summary      = @($findings | Where-Object { $_.Category -eq 'C2 Communication' }).Count -gt 0
    $hasCredSummary    = @($findings | Where-Object { $_.Category -eq 'Credential Theft' -or $_.Title -match 'PAM Authentication Bypass' }).Count -gt 0
    $hasMinerSummary   = @($findings | Where-Object { $_.Category -eq 'Cryptominer' -or $_.Title -match 'stratum|Port 3333|XMRig' }).Count -gt 0
    $hasWebshellSummary= @($findings | Where-Object { $_.Category -eq 'Webshell' }).Count -gt 0
    $hasRansomSummary  = @($findings | Where-Object { $_.Title -match '(?i)ransom|encrypted|decrypt|locked' }).Count -gt 0

    $execVerdict = if ($hasRansomSummary) {
        'Potential ransomware/extortion activity detected'
    } elseif ($hasRootkitSummary -and $hasHiddenSummary -and $hasC2Summary) {
        'Active stealth compromise detected (rootkit + hidden execution + covert network activity)'
    } elseif ($hasRootkitSummary -and $hasHiddenSummary) {
        'High-confidence host compromise detected (rootkit-backed process concealment)'
    } elseif ($hasWebshellSummary) {
        'Likely web-application compromise path detected'
    } elseif ($hasC2Summary) {
        'Suspicious command-and-control communication detected'
    } elseif ($critCount -gt 0) {
        'Critical malicious behavior detected'
    } else {
        'Suspicious activity detected (no single dominant kill-chain confirmed)'
    }

    $execSeverityLabel = if ($critCount -ge 10) { 'CRITICAL' } elseif ($critCount -gt 0 -or $highCount -ge 8) { 'HIGH' } elseif ($highCount -gt 0 -or $medCount -gt 0) { 'MEDIUM' } else { 'LOW' }
    $execSeverityClass = $execSeverityLabel.ToLower()
    $execHighlights = [System.Collections.Generic.List[string]]::new()
    [void]$execHighlights.Add("Overall verdict: $execVerdict.")
    [void]$execHighlights.Add("Impact level: $execSeverityLabel (Critical: $critCount, High: $highCount, Medium: $medCount, Total findings: $totalCount).")

    if ($initialAccessTopVector -and $initialAccessTopVector -ne 'Unknown') {
        [void]$execHighlights.Add("Most likely initial access vector: $initialAccessTopVector ($initialAccessConfidence confidence, score $initialAccessScore/100).")
    }
    if ($hasRootkitSummary) {
        [void]$execHighlights.Add('Rootkit behavior is present (execution-flow hijack indicators and/or kernel/userland concealment signals).')
    }
    if ($hasHiddenSummary) {
        [void]$execHighlights.Add('Process concealment indicators are present, reducing trust in standard live process visibility.')
    }
    if ($hasMinerSummary) {
        [void]$execHighlights.Add('Resource hijacking/cryptominer traits are present (including stratum-style network behavior).')
    }
    if ($hasCredSummary) {
        [void]$execHighlights.Add('Credential risk is elevated due to credential-theft or authentication-stack tampering artifacts.')
    }
    if ($hasC2Summary) {
        $c2Iocs = @($iocList | Where-Object { $_.Type -eq 'IP:Port' -and $_.Context -match '(?i)c2|ssh|outbound' } |
            Select-Object -ExpandProperty Value -Unique | Select-Object -First 4)
        if ($c2Iocs.Count -gt 0) {
            [void]$execHighlights.Add("Potential command-and-control endpoints observed: $($c2Iocs -join ', ').")
        } else {
            [void]$execHighlights.Add('Potential command-and-control communication observed in network telemetry.')
        }
    }
    if ($topActor) {
        [void]$execHighlights.Add("Top attribution overlap: $topActor ($confidence confidence).")
    }

    $execActions = [System.Collections.Generic.List[string]]::new()
    [void]$execActions.Add('Immediate priority: isolate host from network while preserving forensic evidence.')
    if ($remoteLoginUsers.Count -gt 0) {
        [void]$execActions.Add("Credential containment: rotate credentials/keys for impacted account(s): $($remoteLoginUsers -join ', ').")
    } else {
        [void]$execActions.Add('Credential containment: rotate all privileged and remotely accessible account credentials.')
    }
    if ($hasC2Summary) {
        [void]$execActions.Add('Network containment: block observed C2-like destination IPs/ports and hunt for same IOCs environment-wide.')
    }
    if ($hasRootkitSummary -or $hasHiddenSummary) {
        [void]$execActions.Add('Recovery guidance: favor rebuild/reimage over in-place cleanup when rootkit/process-hiding is confirmed.')
    }

    $html = [System.Text.StringBuilder]::new()
    [void]$html.AppendLine('<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">')
    [void]$html.AppendLine("<title>UAC Forensic Triage  -  $hostname</title>")
    [void]$html.AppendLine("<style>$script:LP_CSS</style></head><body>")

    # Title
    [void]$html.AppendLine("<h1>UAC FORENSIC TRIAGE REPORT <span class='offline-badge'>OFFLINE</span></h1>")
    [void]$html.AppendLine("<div class='meta'>Collection: $(Escape-Html $collId) &nbsp;|&nbsp; Host: <b>$(Escape-Html $hostname)</b> &nbsp;|&nbsp; OS: $(Escape-Html $osName) &nbsp;|&nbsp; Analysed: $reportDate &nbsp;|&nbsp; Engine: Loaded Potato UAC Triage v1.0</div>")

    # Summary grid
    [void]$html.AppendLine("<div class='section'><div class='summary-grid'>")
    [void]$html.AppendLine("<div class='summary-box'><span class='summary-num' style='color:#ff5533'>$critCount</span><div class='summary-lbl'>Critical</div></div>")
    [void]$html.AppendLine("<div class='summary-box'><span class='summary-num' style='color:#ffaa44'>$highCount</span><div class='summary-lbl'>High</div></div>")
    [void]$html.AppendLine("<div class='summary-box'><span class='summary-num' style='color:#ffe055'>$medCount</span><div class='summary-lbl'>Medium</div></div>")
    [void]$html.AppendLine("<div class='summary-box'><span class='summary-num' style='color:#5599cc'>$totalCount</span><div class='summary-lbl'>Total Findings</div></div>")
    [void]$html.AppendLine('</div></div>')

    # Executive summary (placed at beginning for fast human triage)
    [void]$html.AppendLine("<div class='section'><h2>EXECUTIVE SUMMARY</h2>")
    [void]$html.AppendLine("<div class='finding f-$execSeverityClass'>")
    [void]$html.AppendLine("<span class='sev-$execSeverityLabel'>[$execSeverityLabel]</span> <span class='cat'>[Summary]</span> <span class='title'>$(Escape-Html $execVerdict)</span><br>")
    [void]$html.AppendLine("<span class='detail'>Generated automatically from observed artifacts, ranked hypotheses, and correlation findings.</span>")
    [void]$html.AppendLine('</div>')
    foreach ($h in $execHighlights) {
        [void]$html.AppendLine("<div class='finding f-info'><span class='detail'>$(Escape-Html $h)</span></div>")
    }
    [void]$html.AppendLine("<h3>Immediate Actions</h3>")
    foreach ($a in $execActions) {
        [void]$html.AppendLine("<div class='finding f-high'><span class='detail'>$(Escape-Html $a)</span></div>")
    }
    [void]$html.AppendLine('</div>')

    # System profile
    [void]$html.AppendLine("<div class='section'><h2>SYSTEM PROFILE</h2>")
    [void]$html.AppendLine("<table class='kv-table'><tr><th>Property</th><th>Value</th></tr>")
    foreach ($kv in $sysProfile.GetEnumerator()) {
        [void]$html.AppendLine("<tr><td>$(Escape-Html $kv.Key)</td><td>$(Escape-Html $kv.Value)</td></tr>")
    }
    [void]$html.AppendLine("</table></div>")

    # Initial access reconstruction
    if ($initialAccessRanked.Count -gt 0) {
        [void]$html.AppendLine("<div class='section'><h2>INITIAL ACCESS RECONSTRUCTION</h2>")
        [void]$html.AppendLine("<table class='kv-table'><tr><th>Rank</th><th>Vector</th><th>Confidence</th><th>Score</th><th>Evidence</th></tr>")
        $iaRank = 0
        foreach ($ia in ($initialAccessRanked | Select-Object -First 5)) {
            $iaRank++
            $evText = ($ia.Evidence | Select-Object -First 3) -join ' | '
            $confBadge = if ($ia.Confidence -eq 'HIGH') { "<span class='badge badge-critical'>HIGH</span>" } elseif ($ia.Confidence -eq 'MEDIUM') { "<span class='badge badge-high'>MEDIUM</span>" } else { "<span class='badge badge-medium'>LOW</span>" }
            [void]$html.AppendLine("<tr><td>$iaRank</td><td>$(Escape-Html $ia.Vector)</td><td>$confBadge</td><td>$($ia.Score)/100</td><td>$(Escape-Html $evText)</td></tr>")
        }
        [void]$html.AppendLine('</table>')
        [void]$html.AppendLine("<div style='color:#9aaabb;font-size:9px;margin-top:6px'>Hypotheses are generated dynamically from authentication logs, service exposure, and behavioral findings. Scores are comparative confidence, not definitive proof.</div>")
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

    # Network connections
    if ($connections.Count -gt 0) {
        [void]$html.AppendLine("<div class='section'><h2>NETWORK CONNECTIONS</h2>")
        [void]$html.AppendLine("<table class='kv-table'><tr><th>State</th><th>Local</th><th>Remote</th><th>Process</th></tr>")
        foreach ($c in $ssLines | Where-Object { $_ -match '^(ESTAB|LISTEN)' } | Select-Object -First 30) {
            if ($c -match '^(ESTAB|LISTEN)\s+\d+\s+\d+\s+(\S+)\s+(\S+)(.*)') {
                $state = $Matches[1]; $loc = $Matches[2]; $rem = $Matches[3]
                $pr = if ($Matches[4] -match 'users:\("([^"]+)"') { $Matches[1] } else { '' }
                $rowClass = if ($state -eq 'ESTAB' -and $rem -notmatch '0\.0\.0\.0|\*|\[:') { " style='background:rgba(224,120,32,.05)'" } else { '' }
                [void]$html.AppendLine("<tr$rowClass><td>$(Escape-Html $state)</td><td class='ioc-ip'>$(Escape-Html $loc)</td><td class='ioc-ip'>$(Escape-Html $rem)</td><td>$(Escape-Html $pr)</td></tr>")
            }
        }
        [void]$html.AppendLine('</table></div>')
    }

    # IOC table
    if ($iocList.Count -gt 0) {
        [void]$html.AppendLine("<div class='section'><h2>INDICATORS OF COMPROMISE</h2>")
        [void]$html.AppendLine("<table class='kv-table'><tr><th>Type</th><th>Indicator</th><th>Context</th><th>Threat Match</th></tr>")
        foreach ($ioc in ($iocList | Sort-Object Type)) {
            $typeClass = switch -Regex ($ioc.Type) {
                'MD5|SHA|Hash' { 'ioc-hash' }
                'IP'           { 'ioc-ip'   }
                default        { 'ioc-path' }
            }
            $matchHtml = if ($ioc.ThreatMatch) { "<span class='match-hit'>$($ioc.ThreatMatch | Escape-Html)</span>" } else { "<span class='match-clean'> - </span>" }
            [void]$html.AppendLine("<tr><td>$(Escape-Html $ioc.Type)</td><td class='$typeClass'>$(Escape-Html $ioc.Value)</td><td>$(Escape-Html $ioc.Context)</td><td>$matchHtml</td></tr>")
        }
        [void]$html.AppendLine('</table></div>')
    }

    # MITRE ATT&CK table
    if ($mitreMap.Count -gt 0) {
        [void]$html.AppendLine("<div class='section'><h2>MITRE ATT&CK COVERAGE</h2>")
        [void]$html.AppendLine("<table class='mitre-tbl'><tr><th>Technique ID</th><th>Name</th><th>Evidence</th></tr>")
        foreach ($tid in ($mitreMap.Keys | Sort-Object)) {
            $tname = if ($script:MITRE_NAMES.ContainsKey($tid)) { $script:MITRE_NAMES[$tid] } else { 'See MITRE ATT&CK' }
            $tevid = ($mitreMap[$tid] | Select-Object -First 3) -join '; '
            [void]$html.AppendLine("<tr><td class='mitre-tid'>$tid</td><td class='mitre-name'>$(Escape-Html $tname)</td><td class='mitre-ev'>$(Escape-Html $tevid)</td></tr>")
        }
        [void]$html.AppendLine('</table></div>')
    }

    # Timeline
    if ($timeline.Count -gt 0) {
        [void]$html.AppendLine("<div class='section'><h2>FORENSIC TIMELINE</h2>")
        $sortedTl = @($timeline | Sort-Object Time)
        foreach ($te in $sortedTl) {
            $tlClass = if ($te.Severity -eq 'CRITICAL') { 'tl-crit' } elseif ($te.Severity -eq 'HIGH') { 'tl-sus' } else { '' }
            [void]$html.AppendLine("<div class='tl-entry $tlClass'><span class='tl-time'>$(Escape-Html $te.Time)</span><span class='tl-event'>$(Escape-Html $te.Event)</span></div>")
        }
        [void]$html.AppendLine('</div>')
    }

    # Attribution
    if ($attributionScores.Count -gt 0) {
        [void]$html.AppendLine("<div class='section'><h2>ATTRIBUTION</h2>")
        foreach ($actor in $attributionScores.Keys) {
            $sc  = $attributionScores[$actor].Score
            $ev_ = $attributionScores[$actor].Evidence -join ' &bull; '
            $barColor = if ($sc -ge 70) { '#cc2200' } elseif ($sc -ge 40) { '#e07820' } else { '#c8a000' }
            $conf_ = if ($sc -ge 70) { 'HIGH' } elseif ($sc -ge 40) { 'MEDIUM' } else { 'LOW' }
            [void]$html.AppendLine("<div style='margin:8px 0'>")
            [void]$html.AppendLine("<span style='color:#dde8f0;font-weight:bold'>$(Escape-Html $actor)</span> <span class='badge badge-$(($conf_).ToLower())'>$conf_ CONFIDENCE  -  $sc/100</span><br>")
            [void]$html.AppendLine("<div class='attr-bar' style='width:260px'><div class='attr-fill' style='width:$sc%;background:$barColor'></div></div>")
            [void]$html.AppendLine("<div style='color:#9aaabb;font-size:9px;margin-top:3px'>$ev_</div>")
            [void]$html.AppendLine('</div>')
        }
        [void]$html.AppendLine('</div>')
    }

    # Bodyfile suspicious entries
    if ($suspiciousBodyEntries.Count -gt 0) {
        [void]$html.AppendLine("<div class='section'><h2>SUSPICIOUS FILESYSTEM EVENTS (BODYFILE)</h2>")
        [void]$html.AppendLine("<table class='kv-table'><tr><th>Path</th><th>MD5</th><th>Size</th><th>MTime</th></tr>")
        foreach ($be in ($suspiciousBodyEntries | Select-Object -First 50)) {
            [void]$html.AppendLine("<tr><td class='ioc-path'>$(Escape-Html $be.Name)</td><td class='ioc-hash'>$(Escape-Html $be.Hash)</td><td>$(Escape-Html $be.Size)</td><td>$(Escape-Html $be.MTime)</td></tr>")
        }
        [void]$html.AppendLine('</table></div>')
    }

    # Footer
    $totalCsvCount = if ($IntelBasePath) { (Get-ChildItem $IntelBasePath -Recurse -Include '*.csv' -ErrorAction SilentlyContinue).Count } else { 0 }
    [void]$html.AppendLine("<footer>Loaded Potato UAC Triage Engine v1.0 &nbsp;|&nbsp; OFFLINE  -  No Internet Required &nbsp;|&nbsp; Intel: $intelCount entries from $totalCsvCount CSVs (3-pass: Master/IOC/TAM) &nbsp;|&nbsp; $reportDate</footer>")
    [void]$html.AppendLine('</body></html>')

    # -- Write output ------------------------------------------------------------
    $reportName = "UAC_Triage_${hostname}_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    $reportPath = Join-Path $OutputPath $reportName

    $null = New-Item -ItemType Directory -Force -Path $OutputPath
    [System.IO.File]::WriteAllText($reportPath, $html.ToString(), [System.Text.Encoding]::UTF8)

    Write-Host "`n[LP-UAC] -----------------------------------------------------" -ForegroundColor Cyan
    Write-Host "[LP-UAC] TRIAGE COMPLETE" -ForegroundColor Green
    Write-Host "[LP-UAC] Host:     $hostname ($osName)" -ForegroundColor White
    Write-Host "[LP-UAC] CRITICAL: $critCount  HIGH: $highCount  MEDIUM: $medCount  TOTAL: $totalCount" -ForegroundColor $(if($critCount -gt 0){'Red'}else{'White'})
    Write-Host "[LP-UAC] Report:   $reportPath" -ForegroundColor Cyan
    Write-Host "[LP-UAC] -----------------------------------------------------" -ForegroundColor Cyan

    if ($OpenReport) { Start-Process $reportPath }

    return [PSCustomObject]@{
        ReportPath             = $reportPath
        Hostname               = $hostname
        OS                     = $osName
        CriticalFindings       = $critCount
        HighFindings           = $highCount
        MediumFindings         = $medCount
        TotalFindings          = $totalCount
        TopAttribution         = $topActor
        Confidence             = $confidence
        SecondaryAttributions  = @($secondaryActors | ForEach-Object { "$_($($attributionScores[$_].Score))" })
        InitialAccessVector    = $initialAccessTopVector
        InitialAccessConfidence= $initialAccessConfidence
        InitialAccessScore     = $initialAccessScore
        IOCCount               = $iocList.Count
        MITRETechniques        = $mitreMap.Keys | Sort-Object
    }
}

Export-ModuleMember -Function Invoke-UACTriage
