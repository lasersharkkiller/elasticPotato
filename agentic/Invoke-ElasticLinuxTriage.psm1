function Invoke-ElasticLinuxTriage {
    <#
    .SYNOPSIS
        Linux Elastic/Elastic Defend log triage - offline forensic analysis.
    .DESCRIPTION
        Parses offline NDJSON event files exported from Elastic Defend (Linux),
        filebeat, or auditbeat and produces a prioritised HTML forensic report.

        Expected input files in DetonationLogsDir (all optional):
          alerts.ndjson, process_events.ndjson, network_events.ndjson,
          file_events.ndjson, auth_events.ndjson / authentication_events.ndjson

        Detection modules:
          - Module 1: Elastic Security alert summary
          - Module 2: Suspicious process chains (reverse shells, LOLBins, /tmp exec, sudo GTFOBins)
          - Module 3: Network C2 (APT IOC lookup via 3-pass intel, miner ports)
          - Module 4: File system events (sensitive writes, executable drops, LD_PRELOAD, cron, systemd)
          - Module 5: Credential access (/etc/shadow, /proc/*/mem, auth brute-force)
          - Module 6: Persistence summary (crontab, systemctl, bashrc, authorized_keys)
          - Module 7: Hash attribution (3-pass intel: Master / dated IOC / Targeted_Analysis_Map)
          - Module 8: Multi-actor attribution (top + secondary actors + full score table)

        Intel loading: 3-pass identical to UAC triage and ElasticAlertAgent:
          Pass 1 - *_Master_Intel.csv  (Date,Source,Actor,IOCType,IOCValue,Context,Link)
          Pass 2 - dated IOC CSVs      (IOC,Type,Sources,Max confidence,Last Seen,Detection count)
          Pass 3 - Targeted_Analysis_Map.csv  (SHA256 hashes, ~3M entries, fast regex reader)

    .PARAMETER DetonationLogsDir
        Path to directory containing NDJSON log files exported from Elastic.
    .PARAMETER OutputPath
        Directory to write the HTML report. Default: .\reports\alertTriage
    .PARAMETER IntelBasePath
        Path to the apt intel directory. Auto-detected from script location if omitted.
    .PARAMETER OpenReport
        If specified, opens the HTML report in the default browser after generation.
    #>
    [CmdletBinding()]
    param(
        [string]$DetonationLogsDir = "",
        [string]$OutputPath        = ".\reports\alertTriage",
        [string]$IntelBasePath     = "",
        [switch]$OpenReport
    )

    # =========================================================================
    # VALIDATION
    # =========================================================================
    if (-not $DetonationLogsDir -or -not (Test-Path $DetonationLogsDir)) {
        Write-Host "[LP-ELX] ERROR: DetonationLogsDir not found: $DetonationLogsDir" -ForegroundColor Red
        return $null
    }
    if (-not $IntelBasePath) { $IntelBasePath = Join-Path $PSScriptRoot "..\apt" }
    if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

    # =========================================================================
    # HELPERS
    # =========================================================================
    $findings   = [System.Collections.Generic.List[PSCustomObject]]::new()
    $mitreTechs = [System.Collections.Generic.List[PSCustomObject]]::new()

    function Add-FindingL {
        param([string]$Severity, [string]$Category, [string]$Title, [string]$Detail, [string[]]$Mitre)
        $findings.Add([PSCustomObject]@{
            Severity = $Severity; Category = $Category; Title = $Title; Detail = $Detail
            Mitre    = ($Mitre | Where-Object { $_ }) -join ' | '
        })
        foreach ($t in ($Mitre | Where-Object { $_ -match '^T\d{4}' })) {
            if (-not ($mitreTechs | Where-Object { $_.Id -eq $t })) {
                $mitreTechs.Add([PSCustomObject]@{ Id = $t; Evidence = $Title })
            }
        }
    }

    function Escape-HtmlL {
        param([string]$s)
        if (-not $s) { return '' }
        $s.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;')
    }

    function Read-NdjsonFile {
        param([string]$Path)
        $results = [System.Collections.Generic.List[object]]::new()
        if (-not (Test-Path -LiteralPath $Path)) { return @() }
        $lines = [System.IO.File]::ReadAllLines($Path, [System.Text.Encoding]::UTF8)
        foreach ($line in $lines) {
            $t = $line.Trim()
            if (-not $t) { continue }
            try { [void]$results.Add(($t | ConvertFrom-Json -ErrorAction Stop)) } catch {}
        }
        return @($results)
    }

    function Get-Field {
        # Traverses a dot-notation path on a deserialized JSON object.
        # Tries flat property name first (e.g. "kibana.alert.rule.name" as literal key),
        # then walks nested objects segment by segment.
        param($Obj, [string]$Path)
        if ($null -eq $Obj) { return $null }
        try {
            $flat = $Obj.PSObject.Properties[$Path]
            if ($null -ne $flat) { return $flat.Value }
        } catch {}
        $parts = $Path -split '\.'
        $cur   = $Obj
        foreach ($p in $parts) {
            if ($null -eq $cur) { return $null }
            try { $cur = $cur.$p } catch { return $null }
        }
        return $cur
    }

    function To-Str {
        # Safely convert a value that may be an array to a single string.
        param($v)
        if ($null -eq $v) { return '' }
        if ($v -is [System.Array]) { return $v -join ' ' }
        return "$v"
    }

    function Get-BaseNameLowerL {
        # Extract lowercase basename from a path or process name.
        param([string]$v)
        if (-not $v) { return '' }
        $leaf = [System.IO.Path]::GetFileName(($v -replace '\\','/'))
        if (-not $leaf) { $leaf = $v }
        return $leaf.ToLowerInvariant()
    }

    function Test-IsLinuxShellLikeProcess {
        # Detect classic shells, shell wrappers, and renamed/copied shell binaries.
        param(
            [string]$ProcessName,
            [string]$ProcessExe,
            [string]$ProcessCmd
        )
        $knownShells = @('bash','rbash','sh','dash','zsh','ksh','mksh','pdksh','yash','ash','hush','fish','csh','tcsh')
        $shellWrappers = @('buyobu','tmux','screen')
        $containerShellHosts = @('busybox','toybox')

        $nName = Get-BaseNameLowerL $ProcessName
        $nExe  = Get-BaseNameLowerL $ProcessExe
        $cmdL  = (To-Str $ProcessCmd).ToLowerInvariant()

        if (($knownShells -contains $nName) -or ($knownShells -contains $nExe)) { return $true }
        if (($shellWrappers -contains $nName) -or ($shellWrappers -contains $nExe)) { return $true }

        if (($containerShellHosts -contains $nName -or $containerShellHosts -contains $nExe) -and
            $cmdL -match '\b(sh|ash|hush|bash|dash|zsh|ksh|mksh|pdksh|yash|fish)\b') {
            return $true
        }

        # Renamed copies often keep shell-like names (e.g., bash.copy, ksh.old, shell-sh)
        if ($nName -match '(?i)(^|[._-])(r?bash|dash|zsh|ksh|mksh|pdksh|yash|ash|hush|fish|sh)([._-]|$)' -or
            $nExe  -match '(?i)(^|[._-])(r?bash|dash|zsh|ksh|mksh|pdksh|yash|ash|hush|fish|sh)([._-]|$)') {
            return $true
        }

        if ($ProcessExe -and $ProcessExe -match '(?i)/(?:bin|sbin|usr/bin|usr/sbin|usr/local/bin|usr/local/sbin|opt/.+?/bin)/[^/\s]*(?:r?bash|dash|zsh|ksh|mksh|pdksh|yash|ash|hush|fish|sh)[^/\s]*$') {
            return $true
        }

        # BusyBox-style invocation or explicit shell token in commandline
        if ($cmdL -match '(?i)(^|\s|/)(?:r?bash|dash|zsh|ksh|mksh|pdksh|yash|ash|hush|fish|sh)(\s|$|/)') {
            return $true
        }
        return $false
    }

    # =========================================================================
    # INTEL LOADING (3-pass, same schema as UAC triage + ElasticAlertAgent)
    # =========================================================================
    Write-Host "[LP-ELX] Loading intel database (3-pass)..." -ForegroundColor DarkCyan

    $netIOCMap  = @{}   # IP/Domain key -> @{Actor; Context; Type}
    $hashIOCMap = @{}   # SHA256 hex    -> @{Actor; Context; Source}
    $intelCount = 0

    $regionFolders = @('Russia','China','NorthKorea','Iran','eCrime','Vietnam','SouthAmerica','Picus','APTs','Malware Families')

    if ($IntelBasePath -and (Test-Path $IntelBasePath)) {

        # -- PASS 1: *_Master_Intel.csv  (Date,Source,Actor,IOCType,IOCValue,Context,Link) ------
        $masterCsvs = @(Get-ChildItem $IntelBasePath -Recurse -Filter '*_Master_Intel.csv' -ErrorAction SilentlyContinue)
        Write-Host "         Pass 1 of 3: $($masterCsvs.Count) master intel files..." -ForegroundColor DarkGray
        foreach ($mc in $masterCsvs) {
            try {
                $mcRows = Import-Csv $mc.FullName -ErrorAction Stop
                foreach ($r in $mcRows) {
                    $iType = ($r.IOCType  -replace '"','').Trim()
                    $iVal  = ($r.IOCValue -replace '"','').Trim().ToLower()
                    if (-not $iVal) { continue }
                    $iActor = ($r.Actor   -replace '"','').Trim()
                    if (-not $iActor) { $iActor = $mc.Directory.Name }
                    $iCtx = ($r.Context  -replace '"','').Trim()
                    $tNorm = switch -Regex ($iType.ToLower()) {
                        '^domain$|^hostname$|^fqdn$' { 'Domain'; break }
                        '^ipv4$|^ipv6$|^ip$|^ip:port$' { 'IP'; break }
                        '^url$' { 'URL'; break }
                        '^sha256$' { 'SHA256'; break }
                        default { $null }
                    }
                    if (-not $tNorm) { continue }
                    if ($tNorm -eq 'SHA256') {
                        if ($iVal -match '^[0-9a-f]{64}$' -and -not $hashIOCMap.ContainsKey($iVal)) {
                            $hashIOCMap[$iVal] = @{ Actor=$iActor; Context=$iCtx; Source=$mc.Directory.Name }; $intelCount++
                        }
                    } else {
                        if ($tNorm -eq 'IP' -and $iVal -match '^(.+):\d+$') { $iVal = $Matches[1] }
                        if ($tNorm -eq 'URL') { try { $h = ([System.Uri]$iVal).Host; if ($h) { $iVal = $h } } catch {} }
                        if (-not $netIOCMap.ContainsKey($iVal)) {
                            $netIOCMap[$iVal] = @{ Actor=$iActor; Context=$iCtx; Type=$tNorm }; $intelCount++
                        }
                    }
                }
            } catch {}
        }
        $countP1 = $intelCount
        Write-Host "         Pass 1 done: $countP1 entries" -ForegroundColor DarkGray

        # -- PASS 2: dated IOC CSVs  (IOC,Type,Sources,Max confidence,Last Seen,Detection count) --
        $iocFiles = @(Get-ChildItem $IntelBasePath -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -eq '.csv' -and $_.Name -match '\d{4}-\d{2}-\d{2}' -and
                           $_.Name -notmatch '_Master_Intel' -and $_.Name -notmatch 'Targeted_Analysis_Map' })
        Write-Host "         Pass 2 of 3: $($iocFiles.Count) dated IOC files..." -ForegroundColor DarkGray
        foreach ($iocF in $iocFiles) {
            try {
                $iocParent = Split-Path (Split-Path $iocF.FullName -Parent) -Leaf
                $iocActor  = if ($regionFolders -notcontains $iocParent) {
                    $iocParent
                } else {
                    ($iocF.BaseName -replace '(?i)_IOCs?$','' -replace '(?i)_\d{4}-\d{2}-\d{2}.*$','' `
                                    -replace '(?i)_deduplicated$','' -replace '_',' ').Trim()
                }
                $iocRows = Import-Csv $iocF.FullName -Encoding UTF8 -ErrorAction SilentlyContinue
                foreach ($r2 in $iocRows) {
                    $v2 = if ($r2.IOC) { $r2.IOC.Trim().ToLower() } else { '' }
                    if (-not $v2) { continue }
                    $t2raw  = if ($r2.Type) { $r2.Type.Trim() } else { '' }
                    $t2norm = switch -Regex ($t2raw.ToLower()) {
                        '^domain$|^hostname$|^fqdn$' { 'Domain'; break }
                        '^ipv4$|^ipv6$|^ip$|^ip:port$' { 'IP'; break }
                        '^url$' { 'URL'; break }
                        '^sha256$' { 'SHA256'; break }
                        default { $null }
                    }
                    if (-not $t2norm) { continue }
                    $ctx2 = "Confidence:$($r2.'Max confidence') | Detections:$($r2.'Detection count')"
                    if ($t2norm -eq 'SHA256') {
                        if ($v2 -match '^[0-9a-f]{64}$' -and -not $hashIOCMap.ContainsKey($v2)) {
                            $hashIOCMap[$v2] = @{ Actor=$iocActor; Context=$ctx2; Source=$iocF.Name }; $intelCount++
                        }
                    } else {
                        if ($t2norm -eq 'IP' -and $v2 -match '^(.+):\d+$') { $v2 = $Matches[1] }
                        if (-not $netIOCMap.ContainsKey($v2)) {
                            $netIOCMap[$v2] = @{ Actor=$iocActor; Context=$ctx2; Type=$t2norm }; $intelCount++
                        }
                    }
                }
            } catch {}
        }
        $countP2 = $intelCount - $countP1
        Write-Host "         Pass 2 done: $countP2 new entries" -ForegroundColor DarkGray

        # -- PASS 3: Targeted_Analysis_Map.csv (fast regex reader, ~3M SHA256 hashes) ------------
        $tamFiles = @(Get-ChildItem $IntelBasePath -Recurse -Filter 'Targeted_Analysis_Map.csv' -ErrorAction SilentlyContinue)
        Write-Host "         Pass 3 of 3: $($tamFiles.Count) TAM files (large dataset, please wait)..." -ForegroundColor DarkGray
        foreach ($tamF in $tamFiles) {
            try {
                $tamActor = Split-Path (Split-Path $tamF.FullName -Parent) -Leaf
                $tamLines = [System.IO.File]::ReadAllLines($tamF.FullName, [System.Text.Encoding]::UTF8)
                foreach ($tl in $tamLines) {
                    if ($tl.Length -lt 66) { continue }
                    if ($tl -notmatch '"([a-fA-F0-9]{64})"') { continue }
                    $h3 = $Matches[1].ToLower()
                    if ($hashIOCMap.ContainsKey($h3)) { continue }
                    $a3 = $tamActor; $c3 = ''
                    if ($tl -match '"[^"]*","[^"]*","[a-fA-F0-9]{64}","([^"]*?)","([^"]*?)"') {
                        $mf3 = $Matches[1]; $mn3 = $Matches[2]
                        if ($mf3 -and $mf3 -ne 'Unknown') { $a3 = $mf3 }
                        $c3 = $mn3
                    }
                    $hashIOCMap[$h3] = @{ Actor=$a3; Context=$c3; Source='Targeted_Analysis_Map' }
                    $intelCount++
                }
            } catch {}
        }
        $countP3 = $intelCount - $countP1 - $countP2
        Write-Host ("         Intel ready: {0:N0} total  [Master:{1:N0} | IOC:{2:N0} | TAM:{3:N0}]" -f $intelCount, $countP1, $countP2, $countP3) -ForegroundColor Gray
    } else {
        Write-Host "         Intel path not found - running without IOC database" -ForegroundColor Yellow
    }

    # =========================================================================
    # LOAD NDJSON FILES
    # =========================================================================
    Write-Host "[LP-ELX] Loading event files from: $DetonationLogsDir" -ForegroundColor DarkCyan

    $procEvents = Read-NdjsonFile (Join-Path $DetonationLogsDir 'process_events.ndjson')
    $netEvents  = Read-NdjsonFile (Join-Path $DetonationLogsDir 'network_events.ndjson')
    $fileEvts   = Read-NdjsonFile (Join-Path $DetonationLogsDir 'file_events.ndjson')
    $alertEvts  = Read-NdjsonFile (Join-Path $DetonationLogsDir 'alerts.ndjson')
    $authEvts   = @(Read-NdjsonFile (Join-Path $DetonationLogsDir 'auth_events.ndjson')) +
                  @(Read-NdjsonFile (Join-Path $DetonationLogsDir 'authentication_events.ndjson'))

    $hostname = To-Str (Get-Field ($procEvents | Select-Object -First 1) 'host.name')
    if (-not $hostname) { $hostname = To-Str (Get-Field ($netEvents | Select-Object -First 1) 'host.name') }
    if (-not $hostname) { $hostname = 'unknown-host' }
    $osName = To-Str (Get-Field ($procEvents | Select-Object -First 1) 'host.os.name')
    if (-not $osName) { $osName = 'Linux' }

    Write-Host ("         Events: {0} proc  {1} net  {2} file  {3} alert  {4} auth" -f `
        $procEvents.Count, $netEvents.Count, $fileEvts.Count, $alertEvts.Count, $authEvts.Count) -ForegroundColor Gray

    # Running set of all observed SHA256 hashes (for Module 7)
    $allObsHashes = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    # ==========================================================================
    # MODULE 1: ELASTIC SECURITY ALERT SUMMARY
    # ==========================================================================
    Write-Host "[LP-ELX] Module 1: Elastic Security alert summary..." -ForegroundColor DarkCyan

    if ($alertEvts.Count -gt 0) {
        $alertsBySev = @{}
        foreach ($a in $alertEvts) {
            $sev = To-Str (Get-Field $a 'kibana.alert.severity')
            if (-not $sev) { $sev = To-Str (Get-Field $a 'signal.rule.severity') }
            if (-not $sev) { $sev = 'unknown' }
            $sev = $sev.ToLower()
            if (-not $alertsBySev.ContainsKey($sev)) { $alertsBySev[$sev] = [System.Collections.Generic.List[object]]::new() }
            $alertsBySev[$sev].Add($a)
        }

        foreach ($sev in @('critical','high','medium','low','unknown')) {
            if (-not $alertsBySev.ContainsKey($sev)) { continue }
            $lpSev = switch ($sev) { 'critical'{'CRITICAL'} 'high'{'HIGH'} 'medium'{'MEDIUM'} default{'INFO'} }
            foreach ($alrt in ($alertsBySev[$sev] | Select-Object -First 10)) {
                $ruleName = To-Str (Get-Field $alrt 'kibana.alert.rule.name')
                if (-not $ruleName) { $ruleName = To-Str (Get-Field $alrt 'signal.rule.name') }
                if (-not $ruleName) { $ruleName = 'Unknown Rule' }
                $procName = To-Str (Get-Field $alrt 'process.name')
                $procCmd  = To-Str (Get-Field $alrt 'process.command_line')
                $detail   = "Rule: $ruleName"
                if ($procName) { $detail += " | Process: $procName" }
                if ($procCmd -and $procCmd.Length -le 300) { $detail += " | Cmd: $procCmd" }
                $mitreIds = [System.Collections.Generic.List[string]]::new()
                $threat   = Get-Field $alrt 'kibana.alert.rule.threat'
                if ($threat) {
                    foreach ($thr in @($threat)) {
                        $tid = To-Str (Get-Field $thr 'technique.id')
                        if ($tid) { [void]$mitreIds.Add($tid) }
                    }
                }
                Add-FindingL $lpSev 'Elastic Alert' "Elastic Alert ($sev): $ruleName" $detail @($mitreIds)
            }
            if ($alertsBySev[$sev].Count -gt 10) {
                Add-FindingL 'INFO' 'Elastic Alert' "... $($alertsBySev[$sev].Count - 10) more $sev alerts truncated" "" @()
            }
        }
        $sevSummary = ($alertsBySev.GetEnumerator() | Sort-Object Key | ForEach-Object { "$($_.Key):$($_.Value.Count)" }) -join ' | '
        Add-FindingL 'INFO' 'Elastic Alert' "Total Elastic Alerts: $($alertEvts.Count)  [$sevSummary]" "" @()
    } else {
        Add-FindingL 'INFO' 'Elastic Alert' 'No Elastic Security Alerts in alerts.ndjson' 'Running behavioral analysis only.' @()
    }

    # ==========================================================================
    # MODULE 2: SUSPICIOUS PROCESS CHAINS
    # ==========================================================================
    Write-Host "[LP-ELX] Module 2: Suspicious process chains..." -ForegroundColor DarkCyan

    $webProcs   = @('nginx','apache2','httpd','php','php-fpm','php7.4','php8.0','php8.1','php8.2','tomcat','java','node','nodejs','uwsgi','gunicorn','lighttpd','caddy')
    $shellProcs = @('bash','rbash','sh','dash','zsh','ksh','mksh','pdksh','yash','ash','hush','fish','csh','tcsh')
    $shellWrappers = @('buyobu','tmux','screen')
    $containerShellHosts = @('busybox','toybox')
    $interpProcs = @('python','python3','python2','perl','ruby','lua','node','nodejs','php','tclsh','awk','gawk')
    $shellObsByProc = @{}
    $renamedShellCandidates = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($pe in $procEvents) {
        $pName   = To-Str (Get-Field $pe 'process.name')
        $pExe    = To-Str (Get-Field $pe 'process.executable')
        $pCmd    = To-Str (Get-Field $pe 'process.command_line')
        $parent  = To-Str (Get-Field $pe 'process.parent.name')
        $pUser   = To-Str (Get-Field $pe 'process.user.name')
        $pHash   = To-Str (Get-Field $pe 'process.hash.sha256')

        if ($pHash -match '^[0-9a-f]{64}$') { [void]$allObsHashes.Add($pHash) }
        if (-not $pName) { continue }
        $pNL  = $pName.ToLower()
        $parL = $parent.ToLower()
        $pExeBase = Get-BaseNameLowerL $pExe
        $isShellLike = Test-IsLinuxShellLikeProcess -ProcessName $pName -ProcessExe $pExe -ProcessCmd $pCmd

        if ($isShellLike) {
            $shellKey = if ($pExeBase) { $pExeBase } else { $pNL }
            if (-not $shellObsByProc.ContainsKey($shellKey)) { $shellObsByProc[$shellKey] = 0 }
            $shellObsByProc[$shellKey]++
        }

        # 2a. Web/app server spawning a shell (RCE / web shell indicator)
        if ($webProcs -contains $parL -and ($isShellLike -or $interpProcs -contains $pNL -or $interpProcs -contains $pExeBase)) {
            Add-FindingL 'CRITICAL' 'Process' `
                "Web/App Server Spawned Shell: $parent -> $pName" `
                "Parent '$parent' is a web/app process and spawned '$pName'. Strong indicator of RCE or web shell. User: $pUser. Cmd: $pCmd" `
                @('T1059.004','T1505.003')
        }

        # 2a.1 Shell wrappers (buyobu/tmux/screen) from web process are also suspicious
        if ($webProcs -contains $parL -and (($shellWrappers -contains $pNL) -or ($shellWrappers -contains $pExeBase))) {
            Add-FindingL 'CRITICAL' 'Process' `
                "Web/App Server Spawned Shell Wrapper: $parent -> $pName" `
                "Parent '$parent' spawned shell-wrapper '$pName' (buyobu/tmux/screen). This often indicates an interactive post-exploitation session bootstrap. User: $pUser. Cmd: $pCmd" `
                @('T1059.004','T1505.003')
        }

        # 2a.2 Renamed/copied shell binaries (e.g., bash.copy, sh.old, ksh.tmp)
        $isCanonicalShellName = ($shellProcs -contains $pNL) -or ($shellProcs -contains $pExeBase) -or
                                 ($shellWrappers -contains $pNL) -or ($shellWrappers -contains $pExeBase) -or
                                 ($containerShellHosts -contains $pNL) -or ($containerShellHosts -contains $pExeBase)
        if ($isShellLike -and -not $isCanonicalShellName) {
            $renamedKey = if ($pExe) { $pExe } else { $pName }
            if ($renamedShellCandidates.Add($renamedKey)) {
                Add-FindingL 'HIGH' 'Process' `
                    "Potential Renamed Shell Binary Execution: $pName" `
                    "Shell-like behavior detected from non-canonical process name/executable '$renamedKey'. This can indicate copied/renamed shells used to evade shell-name-based detection. User: $pUser. Parent: $parent. Cmd: $($pCmd.Substring(0,[Math]::Min(300,$pCmd.Length)))" `
                    @('T1036','T1059.004')
            }
        }

        # 2b. Reverse shell command-line patterns
        if ($pCmd -match '/dev/tcp|/dev/udp|mkfifo.*\|.*nc|ncat\s+-e|nc\s+-e|(?:ba|z|k|mk|pd)?sh\s+-i\b|socat.*EXEC|busybox\s+(?:sh|ash|hush)\b') {
            Add-FindingL 'CRITICAL' 'Process' `
                "Reverse Shell Pattern: $pName" `
                "Command line contains reverse shell indicators. Process: $pName, User: $pUser. Cmd: $($pCmd.Substring(0,[Math]::Min(400,$pCmd.Length)))" `
                @('T1059.004')
        }

        # 2c. Python/perl pty spawn (interactive shell upgrade from reverse shell)
        if ($pCmd -match 'pty\.spawn|import pty|os\.system\(.*/bin/sh|subprocess.*shell=True.*bin') {
            Add-FindingL 'CRITICAL' 'Process' `
                "Shell Upgrade via Interpreter: $pName" `
                "Interpreter used to spawn an interactive shell - classic post-exploitation technique after obtaining a reverse shell. Cmd: $($pCmd.Substring(0,[Math]::Min(400,$pCmd.Length)))" `
                @('T1059.004')
        }

        # 2d. Base64-encoded payload execution
        if ($pCmd -match 'base64\s+-d|base64\s+--decode|echo\s+[A-Za-z0-9+/=]{40,}\s*\|') {
            Add-FindingL 'HIGH' 'Process' `
                "Base64 Payload Execution: $pName" `
                "Base64 decode in command line - common dropper/stager technique. Cmd: $($pCmd.Substring(0,[Math]::Min(400,$pCmd.Length)))" `
                @('T1059.004','T1027')
        }

        # 2e. Execution from staging/temp paths
        if ($pExe -match '^/(tmp|dev/shm|var/tmp|run/user)/') {
            Add-FindingL 'HIGH' 'Process' `
                "Execution from Staging Path: $pExe" `
                "Process executed from temp/staging path commonly used by malware to avoid /usr/bin detection. User: $pUser" `
                @('T1059.004')
        }

        # 2f. Sudo GTFOBins (privilege escalation via allowed binaries)
        if ($pNL -eq 'sudo' -and $pCmd -match '(?i)\s(bash|sh|python\d?|perl|ruby|vi|vim|less|more|man|awk|find|cp|mv|chmod|chown|env|install|make|nmap|tcpdump|openssl)\b') {
            Add-FindingL 'HIGH' 'Process' `
                "Sudo GTFOBins Abuse: $pCmd" `
                "sudo used to run a binary known for privilege escalation (GTFOBins). User: $pUser." `
                @('T1548.003')
        }

        # 2g. Crontab modification
        if ($pNL -eq 'crontab' -and $pCmd -match '-[le]') {
            Add-FindingL 'HIGH' 'Persistence' `
                "Crontab Modified/Listed: $pCmd" `
                "crontab called with -e (edit) or -l (list). User: $pUser" `
                @('T1053.003')
        }

        # 2h. Systemctl service registration
        if ($pNL -eq 'systemctl' -and $pCmd -match '\s(enable|start|daemon-reload)\s') {
            Add-FindingL 'MEDIUM' 'Persistence' `
                "Systemctl Service Operation: $pCmd" `
                "systemctl called with enable/start/daemon-reload - potential persistence installation. User: $pUser" `
                @('T1543.002')
        }

        # 2i. chmod +x on /tmp or /dev/shm files
        if ($pNL -eq 'chmod' -and $pCmd -match '\+x\s.+/(tmp|dev/shm|var/tmp)') {
            Add-FindingL 'MEDIUM' 'Process' `
                "chmod +x on Staging Path File" `
                "File made executable in staging/temp directory. Cmd: $pCmd" `
                @('T1059')
        }

        # 2j. curl/wget piped to shell (dropper pattern)
        if (($pNL -eq 'curl' -or $pNL -eq 'wget') -and $pCmd -match '\|\s*(bash|sh|dash|zsh|ksh|mksh|pdksh|ash|hush|fish|python\d*|perl|ruby|busybox\s+(?:sh|ash|hush))\b') {
            Add-FindingL 'CRITICAL' 'Process' `
                "Curl/Wget Pipe to Shell (Dropper): $pCmd" `
                "Downloaded content piped directly to shell interpreter - classic one-liner dropper pattern. User: $pUser" `
                @('T1059.004','T1105')
        }
    }

    if ($shellObsByProc.Count -gt 0) {
        $shellSummary = ($shellObsByProc.GetEnumerator() |
            Sort-Object Value -Descending |
            Select-Object -First 8 |
            ForEach-Object { "$($_.Name):$($_.Value)" }) -join ', '
        Add-FindingL 'INFO' 'Process' `
            "Shell Activity Coverage: $($shellObsByProc.Count) shell/shell-wrapper executable type(s) observed" `
            "Tracked shell activity across bash/sh/dash/zsh/ksh/mksh/pdksh/yash/ash/hush/fish/csh/tcsh plus buyobu/tmux/screen and busybox/toybox shell invocations. Top observed: $shellSummary" `
            @('T1059.004')
    }

    # ==========================================================================
    # MODULE 3: NETWORK / C2 ANALYSIS
    # ==========================================================================
    Write-Host "[LP-ELX] Module 3: Network C2 analysis..." -ForegroundColor DarkCyan

    $minerPorts   = @(3333,4444,5555,7777,9999,14433,14444,45560,3032,45700,8080,18081,3357,5756)
    $netActorHits = @{}
    $minerConns   = [System.Collections.Generic.List[string]]::new()

    foreach ($ne in $netEvents) {
        $dstIp   = To-Str (Get-Field $ne 'destination.ip')
        if (-not $dstIp) { $dstIp = To-Str (Get-Field $ne 'network.destination.ip') }
        $dstPort = Get-Field $ne 'destination.port'
        if (-not $dstPort) { $dstPort = Get-Field $ne 'network.destination.port' }
        $dstHost = To-Str (Get-Field $ne 'dns.question.name')
        if (-not $dstHost) { $dstHost = To-Str (Get-Field $ne 'network.destination.hostname') }
        $procN   = To-Str (Get-Field $ne 'process.name')

        # Intel lookup: IP
        if ($dstIp) {
            $ipKey = $dstIp.ToLower()
            if ($netIOCMap.ContainsKey($ipKey)) {
                $hit = $netIOCMap[$ipKey]
                if (-not $netActorHits.ContainsKey($hit.Actor)) { $netActorHits[$hit.Actor] = [System.Collections.Generic.List[string]]::new() }
                $netActorHits[$hit.Actor].Add("IP:$dstIp [$($hit.Context)]")
            }
        }

        # Intel lookup: domain
        if ($dstHost) {
            $domKey = $dstHost.ToLower()
            if ($netIOCMap.ContainsKey($domKey)) {
                $hit = $netIOCMap[$domKey]
                if (-not $netActorHits.ContainsKey($hit.Actor)) { $netActorHits[$hit.Actor] = [System.Collections.Generic.List[string]]::new() }
                $netActorHits[$hit.Actor].Add("Domain:$dstHost [$($hit.Context)]")
            }
        }

        # Miner ports
        if ($dstPort) {
            try {
                $dstPortInt = [int]$dstPort
                if ($minerPorts -contains $dstPortInt) {
                    $minerConns.Add("$procN -> ${dstIp}:${dstPort}")
                }
            } catch {}
        }
    }

    foreach ($actor in ($netActorHits.Keys | Sort-Object)) {
        $actorHitCount = $netActorHits[$actor].Count
        $hitSample     = ($netActorHits[$actor] | Select-Object -Unique | Select-Object -First 5) -join ' | '
        Add-FindingL 'CRITICAL' 'Network/Attribution' `
            "Known APT Network IOC Matched: $actor ($actorHitCount hits)" `
            "Network events matched $actor intel. Indicators: $hitSample" `
            @('T1071','T1583')
    }

    if ($minerConns.Count -gt 0) {
        Add-FindingL 'HIGH' 'Network' `
            "Cryptominer Port Connections: $($minerConns.Count) connections" `
            "Outbound connections to known mining pool ports. Sample: $(($minerConns | Select-Object -First 3) -join ' | ')" `
            @('T1496')
    }

    # ==========================================================================
    # MODULE 4: FILE SYSTEM EVENTS
    # ==========================================================================
    Write-Host "[LP-ELX] Module 4: File system events..." -ForegroundColor DarkCyan

    $sensitivePaths = [ordered]@{
        '/etc/passwd'            = @('T1098','T1136')
        '/etc/shadow'            = @('T1003.008')
        '/etc/gshadow'           = @('T1003.008')
        '/etc/sudoers'           = @('T1548.003')
        '/etc/crontab'           = @('T1053.003')
        '/etc/ssh/sshd_config'   = @('T1098.004')
        '/.ssh/authorized_keys'  = @('T1098.004')
        '/etc/ld.so.preload'     = @('T1574.006')
        '/etc/ld.so.conf'        = @('T1574.006')
        '/etc/pam.d'             = @('T1556.003')
        '/etc/rc.local'          = @('T1037.004')
        '/.bashrc'               = @('T1546.004')
        '/.profile'              = @('T1546.004')
        '/etc/profile'           = @('T1546.004')
        '/etc/profile.d'         = @('T1546.004')
    }

    foreach ($fe in $fileEvts) {
        $fPath   = To-Str (Get-Field $fe 'file.path')
        if (-not $fPath) { $fPath = To-Str (Get-Field $fe 'file.target_path') }
        $fEvtRaw = Get-Field $fe 'event.type'
        $fEvtStr = To-Str $fEvtRaw
        $fHash   = To-Str (Get-Field $fe 'file.hash.sha256')
        $fProc   = To-Str (Get-Field $fe 'process.name')

        if ($fHash -match '^[0-9a-f]{64}$') { [void]$allObsHashes.Add($fHash) }
        if (-not $fPath) { continue }

        # 4a. Sensitive config writes
        foreach ($sp in $sensitivePaths.Keys) {
            if ($fPath -like "*$sp*") {
                Add-FindingL 'HIGH' 'File' `
                    "Sensitive File Write: $fPath" `
                    "File '$fPath' created/modified. Event: $fEvtStr. Process: $fProc" `
                    $sensitivePaths[$sp]
                break
            }
        }

        # 4b. Executable created in staging/temp paths
        if ($fPath -match '^/(tmp|dev/shm|var/tmp|run/user)/' -and $fEvtStr -match 'creat') {
            Add-FindingL 'HIGH' 'File' `
                "File Created in Staging Path: $fPath" `
                "New file in common malware staging path. Process: $fProc" `
                @('T1059')
        }

        # 4c. LD_PRELOAD hijack
        if ($fPath -match 'ld\.so\.preload') {
            Add-FindingL 'CRITICAL' 'Defense Evasion' `
                "LD_PRELOAD Hijack: $fPath modified" `
                "Dynamic linker preload config touched - used by rootkits to intercept all process library loads. Process: $fProc" `
                @('T1574.006')
        }

        # 4d. Cron file modification
        if ($fPath -match '^/etc/cron\.|^/var/spool/cron/' -and $fEvtStr -match 'creat|change') {
            Add-FindingL 'HIGH' 'Persistence' `
                "Cron File Modified: $fPath" `
                "Cron config file was created or changed. Process: $fProc" `
                @('T1053.003')
        }

        # 4e. Systemd service file creation
        if ($fPath -match '\.(service|timer|socket)$' -and $fEvtStr -match 'creat') {
            Add-FindingL 'HIGH' 'Persistence' `
                "Systemd Service File Created: $fPath" `
                "New systemd unit file - potential persistence mechanism. Process: $fProc" `
                @('T1543.002')
        }
    }

    # ==========================================================================
    # MODULE 5: CREDENTIAL ACCESS
    # ==========================================================================
    Write-Host "[LP-ELX] Module 5: Credential access..." -ForegroundColor DarkCyan

    # 5a. Authentication failures (brute-force / password spray)
    $authFails = @($authEvts | Where-Object { (To-Str (Get-Field $_ 'event.outcome')) -eq 'failure' })
    if ($authFails.Count -gt 10) {
        $failUsers = ($authFails | ForEach-Object { To-Str (Get-Field $_ 'user.name') } |
            Where-Object { $_ } | Sort-Object -Unique | Select-Object -First 5) -join ', '
        Add-FindingL 'HIGH' 'Credential Access' `
            "Authentication Failures: $($authFails.Count) failed attempt(s)" `
            "Possible brute-force or credential stuffing. Targeted users: $failUsers" `
            @('T1110')
    }

    # 5b. /proc/<pid>/mem access (in-memory credential dumping: mimipenguin, etc.)
    foreach ($pe in $procEvents) {
        $pCmd  = To-Str (Get-Field $pe 'process.command_line')
        $pName = To-Str (Get-Field $pe 'process.name')
        if ($pCmd -match '/proc/\d+/mem|/proc/\d+/maps|/proc/kcore') {
            Add-FindingL 'CRITICAL' 'Credential Access' `
                "Process Memory Read: $pName" `
                "Process read /proc/<pid>/mem or /proc/kcore - used by Linux credential dumpers (mimipenguin, linpeas). Cmd: $pCmd" `
                @('T1003')
        }
    }

    # 5c. /etc/shadow access in file events
    foreach ($fe in $fileEvts) {
        $fPath = To-Str (Get-Field $fe 'file.path')
        if ($fPath -match '^/etc/(g?shadow)$') {
            Add-FindingL 'CRITICAL' 'Credential Access' `
                "Shadow Password File Accessed: $fPath" `
                "Hashed credential file accessed. Process: $(To-Str (Get-Field $fe 'process.name'))" `
                @('T1003.008')
        }
    }

    # ==========================================================================
    # MODULE 6: PERSISTENCE SUMMARY
    # ==========================================================================
    Write-Host "[LP-ELX] Module 6: Persistence summary..." -ForegroundColor DarkCyan

    $persistCmds = @($procEvents | Where-Object {
        $c = To-Str (Get-Field $_ 'process.command_line')
        $c -and $c -match '(crontab|at\s+|systemctl.*enable|rc\.local|\.bashrc|\.bash_profile|\.bash_login|\.profile|\.zshrc|\.zprofile|\.zlogin|\.kshrc|\.mkshrc|fish_history|config\.fish|update-rc\.d|chkconfig|insserv)'
    })
    if ($persistCmds.Count -gt 5) {
        $pSample = ($persistCmds | Select-Object -First 3 | ForEach-Object {
            $c = To-Str (Get-Field $_ 'process.command_line')
            if ($c.Length -gt 150) { $c.Substring(0,150) + '...' } else { $c }
        }) -join ' | '
        Add-FindingL 'HIGH' 'Persistence' `
            "High Volume of Persistence Commands: $($persistCmds.Count)" `
            "Elevated count of commands associated with persistence mechanisms. Sample: $pSample" `
            @('T1053','T1543','T1546')
    }

    # ==========================================================================
    # MODULE 7: HASH ATTRIBUTION (3-pass)
    # ==========================================================================
    Write-Host "[LP-ELX] Module 7: Hash attribution ($($allObsHashes.Count) unique hash(es))..." -ForegroundColor DarkCyan

    # Also collect hashes from file events
    foreach ($fe in $fileEvts) {
        $fh = To-Str (Get-Field $fe 'file.hash.sha256')
        if ($fh -match '^[0-9a-f]{64}$') { [void]$allObsHashes.Add($fh) }
    }

    $hashActorHits = @{}
    foreach ($h in $allObsHashes) {
        $hKey = $h.ToLower()
        if ($hashIOCMap.ContainsKey($hKey)) {
            $actor = $hashIOCMap[$hKey].Actor
            if (-not $hashActorHits.ContainsKey($actor)) { $hashActorHits[$actor] = [System.Collections.Generic.List[string]]::new() }
            $ctx    = $hashIOCMap[$hKey].Context
            $ctxStr = if ($ctx) { " ($ctx)" } else { '' }
            $hashActorHits[$actor].Add("$hKey$ctxStr")
        }
    }

    if ($hashActorHits.Count -gt 0) {
        foreach ($actor in ($hashActorHits.Keys | Sort-Object { -$hashActorHits[$_].Count })) {
            $hCount  = $hashActorHits[$actor].Count
            $samples = ($hashActorHits[$actor] | Select-Object -First 3) -join ' | '
            Add-FindingL 'CRITICAL' 'Hash Attribution' `
                "Direct Hash Match: $actor ($hCount sample(s))" `
                "Observed hash(es) matched $actor intel database. Samples: $samples" `
                @()
        }
    }

    # ==========================================================================
    # MODULE 8: MULTI-ACTOR ATTRIBUTION
    # ==========================================================================
    Write-Host "[LP-ELX] Module 8: Multi-actor attribution..." -ForegroundColor DarkCyan

    # Score: network IOC hit = 10 pts each, hash match = 15 pts each (hash is higher confidence)
    $attrScores = @{}
    foreach ($actor in $netActorHits.Keys) {
        if (-not $attrScores.ContainsKey($actor)) { $attrScores[$actor] = 0 }
        $attrScores[$actor] += ($netActorHits[$actor].Count * 10)
    }
    foreach ($actor in $hashActorHits.Keys) {
        if (-not $attrScores.ContainsKey($actor)) { $attrScores[$actor] = 0 }
        $attrScores[$actor] += ($hashActorHits[$actor].Count * 15)
    }

    if ($attrScores.Count -gt 0) {
        $sortedActors = @($attrScores.Keys | Sort-Object { $attrScores[$_] } -Descending)
        $topActor     = $sortedActors[0]
        $topScore     = [Math]::Min($attrScores[$topActor], 100)
        $attrConf     = if ($topScore -ge 70) { 'HIGH' } elseif ($topScore -ge 30) { 'MEDIUM' } else { 'LOW' }

        $topNetEv   = if ($netActorHits.ContainsKey($topActor))  { @($netActorHits[$topActor])  } else { @() }
        $topHashEv  = if ($hashActorHits.ContainsKey($topActor)) { @($hashActorHits[$topActor]) } else { @() }
        $topEvStr   = ((@($topNetEv) + @($topHashEv)) | Select-Object -First 3) -join '; '

        Add-FindingL 'HIGH' 'Attribution' `
            "Top Attribution: $topActor ($attrConf Confidence - $topScore pts)" `
            "Evidence (network IOC + hash matches): $topEvStr. Score reflects indicator volume, not definitive attribution." `
            @()
        Write-Host ("         Top Attribution: {0}  -  {1} confidence ({2} pts)" -f $topActor, $attrConf, $topScore) -ForegroundColor Yellow

        $secActors = $sortedActors | Select-Object -Skip 1 | Where-Object { $attrScores[$_] -ge 15 }
        foreach ($sa in $secActors) {
            $saScore = [Math]::Min($attrScores[$sa], 100)
            $saConf  = if ($saScore -ge 70) { 'HIGH' } elseif ($saScore -ge 30) { 'MEDIUM' } else { 'LOW' }
            $saNet   = if ($netActorHits.ContainsKey($sa))  { @($netActorHits[$sa])  } else { @() }
            $saHash  = if ($hashActorHits.ContainsKey($sa)) { @($hashActorHits[$sa]) } else { @() }
            $saEv    = ((@($saNet) + @($saHash)) | Select-Object -First 2) -join '; '
            Add-FindingL 'MEDIUM' 'Attribution' `
                "Secondary Attribution Signal: $sa ($saConf Confidence - $saScore pts)" `
                "Evidence: $saEv" `
                @()
            Write-Host ("         Secondary: {0}  -  {1} confidence ({2} pts)" -f $sa, $saConf, $saScore) -ForegroundColor DarkYellow
        }

        $scoreTable = ($sortedActors | ForEach-Object {
            "$_ : $([Math]::Min($attrScores[$_],100)) pts"
        }) -join ' | '
        Add-FindingL 'INFO' 'Attribution' `
            "Full Attribution Scores ($($sortedActors.Count) actor(s) evaluated)" `
            $scoreTable `
            @()
    } else {
        Add-FindingL 'INFO' 'Attribution' 'No Attribution Matches' `
            'No network IOC or hash matches found in the intel database for observed indicators.' @()
    }

    # ==========================================================================
    # BUILD HTML REPORT
    # ==========================================================================
    Write-Host "[LP-ELX] Building HTML report..." -ForegroundColor DarkCyan

    $collId     = Split-Path $DetonationLogsDir -Leaf
    $reportDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $critCount  = ($findings | Where-Object { $_.Severity -eq 'CRITICAL' } | Measure-Object).Count
    $highCount  = ($findings | Where-Object { $_.Severity -eq 'HIGH' }     | Measure-Object).Count
    $medCount   = ($findings | Where-Object { $_.Severity -eq 'MEDIUM' }   | Measure-Object).Count
    $totalCount = $findings.Count

    $sevColor = @{ CRITICAL='#ff5533'; HIGH='#ffaa44'; MEDIUM='#ffe055'; LOW='#88cc88'; INFO='#5599cc' }
    $sevBg    = @{ CRITICAL='#2d0800'; HIGH='#2d1800'; MEDIUM='#2d2800'; LOW='#1a2d1a'; INFO='#0d1a2d' }

    $html = [System.Text.StringBuilder]::new()
    [void]$html.AppendLine('<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">')
    [void]$html.AppendLine("<title>Linux Elastic Triage - $(Escape-HtmlL $hostname)</title>")
    [void]$html.AppendLine('<style>
body{background:#0d1117;color:#c9d1d9;font-family:Consolas,monospace;font-size:13px;margin:0;padding:20px}
h1{color:#58a6ff;font-size:1.4em;margin:0 0 4px}
h2{color:#79c0ff;font-size:1.1em;border-bottom:1px solid #30363d;padding-bottom:4px;margin-top:24px}
h3{color:#e3b341;font-size:1em;margin:12px 0 4px}
.meta{color:#8b949e;font-size:11px;margin-bottom:20px}
.badge{padding:2px 8px;font-size:10px;border-radius:3px;margin-left:6px}
.offline-badge{background:#1f3c1f;color:#56d364;border:1px solid #238636}
.linux-badge{background:#1a1f3a;color:#79c0ff;border:1px solid #388bfd}
.section{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:16px;margin:12px 0}
.summary-grid{display:flex;gap:12px;flex-wrap:wrap}
.summary-box{background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:12px 20px;text-align:center;min-width:80px}
.summary-num{font-size:2em;font-weight:bold;display:block}
.summary-lbl{font-size:10px;color:#8b949e;margin-top:4px}
.finding{border-left:3px solid #30363d;padding:8px 12px;margin:6px 0;border-radius:0 4px 4px 0}
.sev-label{font-size:10px;font-weight:bold;padding:2px 6px;border-radius:3px;margin-right:8px;color:#000}
.cat-label{font-size:10px;color:#8b949e;margin-right:6px}
.finding-title{font-weight:bold;color:#f0f6fc}
.finding-detail{color:#8b949e;font-size:11px;margin-top:4px;padding-left:4px;white-space:pre-wrap;word-break:break-all}
.mitre-tag{display:inline-block;background:#1c2128;border:1px solid #388bfd;color:#79c0ff;font-size:10px;padding:1px 5px;border-radius:3px;margin:2px 2px 0 0}
table.kv-table{border-collapse:collapse;width:100%;font-size:12px}
table.kv-table th{background:#1c2128;color:#79c0ff;text-align:left;padding:4px 8px;border:1px solid #30363d}
table.kv-table td{padding:4px 8px;border:1px solid #21262d;vertical-align:top}
table.kv-table tr:nth-child(even){background:#161b22}
footer{color:#484f58;font-size:10px;margin-top:24px;border-top:1px solid #21262d;padding-top:8px}
</style></head><body>')

    [void]$html.AppendLine("<h1>LINUX ELASTIC TRIAGE REPORT <span class='badge offline-badge'>OFFLINE</span><span class='badge linux-badge'>LINUX</span></h1>")
    [void]$html.AppendLine("<div class='meta'>Logs: $(Escape-HtmlL $collId) &nbsp;|&nbsp; Host: <b>$(Escape-HtmlL $hostname)</b> &nbsp;|&nbsp; OS: $(Escape-HtmlL $osName) &nbsp;|&nbsp; Analysed: $reportDate &nbsp;|&nbsp; Engine: Loaded Potato Linux Elastic Triage v1.0</div>")

    # Summary grid
    [void]$html.AppendLine("<div class='section'><div class='summary-grid'>")
    [void]$html.AppendLine("<div class='summary-box'><span class='summary-num' style='color:#ff5533'>$critCount</span><div class='summary-lbl'>Critical</div></div>")
    [void]$html.AppendLine("<div class='summary-box'><span class='summary-num' style='color:#ffaa44'>$highCount</span><div class='summary-lbl'>High</div></div>")
    [void]$html.AppendLine("<div class='summary-box'><span class='summary-num' style='color:#ffe055'>$medCount</span><div class='summary-lbl'>Medium</div></div>")
    [void]$html.AppendLine("<div class='summary-box'><span class='summary-num' style='color:#5599cc'>$totalCount</span><div class='summary-lbl'>Total Findings</div></div>")
    [void]$html.AppendLine("<div class='summary-box'><span class='summary-num' style='color:#8b949e'>$($procEvents.Count)</span><div class='summary-lbl'>Proc Events</div></div>")
    [void]$html.AppendLine("<div class='summary-box'><span class='summary-num' style='color:#8b949e'>$($netEvents.Count)</span><div class='summary-lbl'>Net Events</div></div>")
    [void]$html.AppendLine("<div class='summary-box'><span class='summary-num' style='color:#8b949e'>$($fileEvts.Count)</span><div class='summary-lbl'>File Events</div></div>")
    [void]$html.AppendLine('</div></div>')

    # Findings by severity
    $sevOrder = @('CRITICAL','HIGH','MEDIUM','LOW','INFO')
    [void]$html.AppendLine("<div class='section'><h2>FINDINGS</h2>")
    foreach ($sev in $sevOrder) {
        $sevF = @($findings | Where-Object { $_.Severity -eq $sev })
        if ($sevF.Count -eq 0) { continue }
        [void]$html.AppendLine("<h3>$sev ($($sevF.Count))</h3>")
        foreach ($f in $sevF) {
            $col = $sevColor[$sev]; $bg = $sevBg[$sev]
            [void]$html.AppendLine("<div class='finding' style='border-left-color:$col;background:$bg'>")
            [void]$html.AppendLine("<span class='sev-label' style='background:$col'>$($f.Severity)</span><span class='cat-label'>[$($f.Category)]</span><span class='finding-title'>$(Escape-HtmlL $f.Title)</span>")
            if ($f.Detail) {
                [void]$html.AppendLine("<div class='finding-detail'>$(Escape-HtmlL $f.Detail)</div>")
            }
            if ($f.Mitre) {
                foreach ($tid in ($f.Mitre -split '\s*\|\s*' | Where-Object { $_ })) {
                    $tidLink = $tid -replace '\.','/'
                    [void]$html.AppendLine("<span class='mitre-tag'><a href='https://attack.mitre.org/techniques/$tidLink' style='color:#79c0ff;text-decoration:none' target='_blank'>$tid</a></span>")
                }
            }
            [void]$html.AppendLine("</div>")
        }
    }
    [void]$html.AppendLine("</div>")

    # MITRE techniques table
    if ($mitreTechs.Count -gt 0) {
        [void]$html.AppendLine("<div class='section'><h2>MITRE ATT&amp;CK TECHNIQUES OBSERVED</h2>")
        [void]$html.AppendLine("<table class='kv-table'><tr><th>Technique ID</th><th>First Evidence</th></tr>")
        foreach ($t in ($mitreTechs | Sort-Object Id)) {
            $tidLink = $t.Id -replace '\.','//'
            [void]$html.AppendLine("<tr><td><a href='https://attack.mitre.org/techniques/$tidLink' style='color:#79c0ff' target='_blank'>$($t.Id)</a></td><td>$(Escape-HtmlL $t.Evidence)</td></tr>")
        }
        [void]$html.AppendLine("</table></div>")
    }

    # Footer
    $totalCsvCount = if ($IntelBasePath -and (Test-Path $IntelBasePath)) {
        (Get-ChildItem $IntelBasePath -Recurse -Include '*.csv' -ErrorAction SilentlyContinue).Count
    } else { 0 }
    [void]$html.AppendLine("<footer>Loaded Potato Linux Elastic Triage v1.0 &nbsp;|&nbsp; OFFLINE - No Internet Required &nbsp;|&nbsp; Intel: $intelCount entries from $totalCsvCount CSVs (3-pass: Master/IOC/TAM) &nbsp;|&nbsp; $reportDate</footer>")
    [void]$html.AppendLine('</body></html>')

    # Write report
    $rStamp     = Get-Date -Format 'yyyyMMdd_HHmmss'
    $safeHost   = $hostname -replace '[^\w\-]','_'
    $reportName = "ElasticLinux_${safeHost}_${rStamp}.html"
    $reportPath = Join-Path $OutputPath $reportName
    [System.IO.File]::WriteAllText($reportPath, $html.ToString(), [System.Text.Encoding]::UTF8)

    Write-Host "[LP-ELX] Report  : $reportPath" -ForegroundColor Green
    Write-Host ("[LP-ELX] Results : {0} CRITICAL  {1} HIGH  {2} MEDIUM  {3} total findings" -f $critCount, $highCount, $medCount, $totalCount) `
        -ForegroundColor $(if ($critCount -gt 0) { 'Red' } elseif ($highCount -gt 0) { 'Yellow' } else { 'Cyan' })

    if ($OpenReport -and (Test-Path $reportPath)) { Start-Process $reportPath }

    return [PSCustomObject]@{
        ReportPath       = $reportPath
        CriticalFindings = $critCount
        HighFindings     = $highCount
        MediumFindings   = $medCount
        TotalFindings    = $totalCount
        TopAttribution   = if ($attrScores.Count -gt 0) {
            $attrScores.Keys | Sort-Object { $attrScores[$_] } -Descending | Select-Object -First 1
        } else { '' }
        MITRETechniques  = @($mitreTechs | Sort-Object Id | ForEach-Object { $_.Id })
    }
}
