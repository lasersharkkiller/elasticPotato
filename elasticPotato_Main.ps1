#Requirements
#Install-Module -Name powershell-yaml -Scope CurrentUser -Force
#Install-Module -Scope CurrentUser Microsoft.PowerShell.SecretManagement, Microsoft.Powershell.SecretStore -Force
#Register-SecretVault -Name LocalSecrets -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault
#Free or Potentially Free
#Set-Secret -Name 'ThreatFox_AuthKey' -Secret 'API_Key_Here'
#Set-Secret -Name 'MalwareBazaar_AuthKey' -Secret 'API_Key_Here'
#Set-Secret -Name 'HybridAnalysis_API_Key' -Secret 'API_Key_Here'
#Set-Secret -Name 'URLhaus_AuthKey' -Secret 'API_Key_Here'
#Set-Secret -Name 'OTX_API_Key' -Secret 'API_Key_Here'
#Set-Secret -Name 'Github_Access_Token' -Secret 'API_Key_Here'
#Set-Secret -Name 'VT_API_Key_1' -Secret 'API_Key_Here'
#Set-Secret -Name 'VT_API_Key_2' -Secret 'API_Key_Here'
#Set-Secret -Name 'Elastic_URL' -Secret 'API_Key_Here'  # e.g. https://192.168.71.10/elasticsearch  or  https://elasticsearch.lab:9200
#Set-Secret -Name 'Kibana_URL'  -Secret 'API_Key_Here'  # e.g. https://192.168.71.10/kibana       or  https://kibana.lab:5601
#
# Auth precedence (first available wins) for both Elasticsearch and Kibana:
#   1. ApiKey  -  vault secret Elastic_ApiKey / Kibana_ApiKey  (PREFERRED;
#                 required for Security Onion 3.0 + similar nginx-proxied
#                 stacks that redirect unauthenticated Basic requests to a
#                 SOC login page). Value may be either raw 'id:api_key' (we
#                 base64-encode at request time) or the pre-encoded base64.
#   2. Basic   -  vault secrets Elastic_User+Elastic_Pass / Kibana_User+Kibana_Pass
#                 (vanilla Elasticsearch native auth, or any stack that
#                 exposes :9200 / :5601 with Basic enabled)
#   3. Prompt  -  if neither is set, the module prompts at run time.
#
#Set-Secret -Name 'Elastic_ApiKey' -Secret 'API_Key_Here'  # preferred; raw 'id:api_key' or pre-encoded base64
#Set-Secret -Name 'Kibana_ApiKey'  -Secret 'API_Key_Here'  # preferred for Kibana; same format as Elastic_ApiKey
#Set-Secret -Name 'Elastic_User' -Secret 'API_Key_Here'   # fallback Basic auth
#Set-Secret -Name 'Elastic_Pass' -Secret 'API_Key_Here'   # fallback Basic auth
#Set-Secret -Name 'Kibana_User'  -Secret 'API_Key_Here'   # fallback Basic auth (Kibana)
#Set-Secret -Name 'Kibana_Pass'  -Secret 'API_Key_Here'   # fallback Basic auth (Kibana)
#Set-Secret -Name 'TORCH_SSH_Host'    -Secret 'API_Key_Here'  # e.g. 192.168.71.10
#Set-Secret -Name 'TORCH_SSH_User'    -Secret 'API_Key_Here'  # e.g. secon
#Set-Secret -Name 'TORCH_SSH_Pass'    -Secret 'API_Key_Here'  # OR set TORCH_SSH_KeyPath instead
#Set-Secret -Name 'TORCH_SSH_KeyPath' -Secret 'API_Key_Here'  # absolute path to OpenSSH private key
#Paid Vendors (optional - used by baseline enrichment)
#Set-Secret -Name 'APIVoid_API_Key' -Secret 'API_Key_Here'
#Set-Secret -Name 'Intezer_API_Key' -Secret 'API_Key_Here'
#Set-Secret -Name 'ThreatGrid_API_Key' -Secret 'API_Key_Here'
#Install-Module -Name PSSQLite -Scope CurrentUser -Force
#pip install sigma-cli
#sigma plugin install elasticsearch


# Baseline / enrichment
Import-Module -Name ".\baseline\NsrlEnrichment.psm1" -ErrorAction SilentlyContinue
Import-Module -Name ".\baseline\NsrlTools.psm1" -ErrorAction SilentlyContinue

# Agentic Elastic triage (Group 4)
# -Force on the Group 4 modules so hot fixes to the actively-iterated
# triage / pull / orchestrator code take effect on every script run
# without requiring a fresh PowerShell session. The cost is a one-time
# re-parse per .\elasticPotato_Main.ps1 invocation - negligible.
Import-Module -Name ".\agentic\ElasticAlertAgent.psm1"          -Force
Import-Module -Name ".\agentic\Invoke-ElasticLinuxTriage.psm1"  -Force

# Forensic triage (Groups 2d, 3)
Import-Module -Name ".\forensics\Invoke-UACTriage.psm1"
Import-Module -Name ".\forensics\Invoke-RouterTriage.psm1"

# Group 5 (Elastic Baseline) -- remaining enrichment deps
Import-Module -Name ".\NewProcsModules\CheckAgainstVT.psm1"
Import-Module -Name ".\NewProcsModules\CheckApiVoid.psm1"
Import-Module -Name ".\NewProcsModules\CheckSuspiciousASNs.psm1"
Import-Module -Name ".\NewProcsModules\DomainCleanup.psm1"
Import-Module -Name ".\NewProcsModules\elasticProcessBaseline.psm1"

# Elastic detonation logs used by Group 4 (4d pull + SO 3.0 SSH connector)
# -Force here matches the Group 4 triage modules above so cache-stale
# hot fixes never silently regress against a long-lived session.
Import-Module -Name ".\purpleTeaming\GetElasticDetonationLogs.psm1" -Force -ErrorAction SilentlyContinue
Import-Module -Name ".\purpleTeaming\Invoke-TorchElasticQuery.psm1" -Force -ErrorAction SilentlyContinue

# Detection cache refreshers (called by 4f and as standalone 4g/4h)
Import-Module -Name ".\detections\Update-LolDriversCache.psm1"
Import-Module -Name ".\detections\Update-ElasticYaraRules.psm1"

# Push + enable local NDJSON detection rules into the Kibana SIEM (4i)
Import-Module -Name ".\detections\Sync-ElasticDetections.psm1"

# Thor/Loki IOC + YARA scanner (4e)
Import-Module -Name ".\baseline\Invoke-LokiScan.psm1"

# Connectivity check
try {
    $ping = Test-Connection -ComputerName "8.8.8.8" -Count 1 -Quiet
    if (-not $ping) { Write-Host "Unable to reach 8.8.8.8 - network connectivity may be limited" }
} catch {
    Write-Host "Unable to reach 8.8.8.8 - network connectivity may be limited"
}

Write-Host "elasticPotato - Elastic triage toolkit"
Write-Host "Choose which function you would like to use:"
Write-Host ""

# -- GROUP 1: Dependencies / Offline Setup -----------------------------------
Write-Host "  $([char]27)[4m+-------------------------------------------------------+$([char]27)[24m" -ForegroundColor DarkGreen
Write-Host "  $([char]27)[4m|    Dependencies  /  Offline Setup   (run me first)    |$([char]27)[24m" -ForegroundColor DarkGreen
Write-Host "  $([char]27)[4m+-------------------------------------------------------+$([char]27)[24m" -ForegroundColor DarkGreen
Write-Host "1a) Download Dependencies (offline PS modules, pip packages, tools)" -ForegroundColor DarkGreen
Write-Host "     -> Run on an INTERNET host, then carry the tree to the offline VM" -ForegroundColor DarkGray
Write-Host ""

# -- GROUP 2: Remote Collection Tool Deployment -------------------------------
Write-Host "  $([char]27)[4m+----------------------------------------------------------+$([char]27)[24m" -ForegroundColor DarkYellow
Write-Host "  $([char]27)[4m|   Remote Collection Tool Deployment (Offline Packages)    |$([char]27)[24m" -ForegroundColor DarkYellow
Write-Host "  $([char]27)[4m+----------------------------------------------------------+$([char]27)[24m" -ForegroundColor DarkYellow
Write-Host "2a) Deploy UAC Collector to Remote Host(s)" -ForegroundColor DarkYellow
Write-Host "2b) Deploy KAPE to Remote Windows Host(s)" -ForegroundColor DarkYellow
Write-Host "2c) Deploy DFIR-ORC to Remote Windows Host(s)" -ForegroundColor DarkYellow
Write-Host "     -> Requires offline packages already staged under .\tools\" -ForegroundColor DarkGray
Write-Host "2d) [Live SSH] Collect Router Forensic Dump (Save-RouterDump)" -ForegroundColor DarkYellow
Write-Host "     -> Pulls ~75 forensic commands from a live router; saves files for offline 3c analysis" -ForegroundColor DarkGray
Write-Host ""

# -- GROUP 3: Linux / UAC Forensic Triage (Offline) ---------------------------
Write-Host "  $([char]27)[4m+----------------------------------------------+$([char]27)[24m" -ForegroundColor DarkYellow
Write-Host "  $([char]27)[4m|        Linux / UAC Forensic Triage            |$([char]27)[24m" -ForegroundColor DarkYellow
Write-Host "  $([char]27)[4m+----------------------------------------------+$([char]27)[24m" -ForegroundColor DarkYellow
Write-Host "3a) [Offline] UAC Dump Triage - Full Expert Analysis (Rootkit/C2/Creds/Timeline/Attribution)" -ForegroundColor DarkYellow
Write-Host "3b) [Live SSH] Edge Router APT Triage - Full Expert Analysis" -ForegroundColor DarkYellow
Write-Host "3c) [Offline] Edge Router APT Triage - Analyze offline dump directory" -ForegroundColor DarkYellow
Write-Host ""

# -- GROUP 4: Elastic Alerts ---------------------------------------------------
Write-Host "  $([char]27)[4m+----------------------------------------------+$([char]27)[24m" -ForegroundColor DarkRed
Write-Host "  $([char]27)[4m|  (Elastic env) Analyze Artifacts for An Alert |$([char]27)[24m" -ForegroundColor DarkRed
Write-Host "  $([char]27)[4m+----------------------------------------------+$([char]27)[24m" -ForegroundColor DarkRed
Write-Host "4a) [AI Agent] Pull + Triage - runs 4d to pull logs, then auto-dispatches to 4b (Windows) or 4c (Linux) based on what was pulled" -ForegroundColor DarkRed
Write-Host "4b) [AI Agent] Elastic Alert Triage (Windows) - Offline Forensic Analysis" -ForegroundColor DarkRed
Write-Host "4c) [AI Agent] Elastic Alert Triage (Linux)   - Offline Forensic Analysis" -ForegroundColor DarkRed
Write-Host "4d) Pull Elastic Logs from Detonation Window" -ForegroundColor DarkRed
Write-Host "4e) Run IOC/YARA Scanner Against Downloaded Malicious Files (Thor/Loki auto-detect)" -ForegroundColor DarkRed
Write-Host "4f) [AI Agent] Offline Analysis + IOC/YARA Scan (Windows)" -ForegroundColor DarkRed
Write-Host "4g) Update LOL Drivers Cache (loldrivers.io + LOLDrivers Sigma + SigmaHQ)" -ForegroundColor DarkRed
Write-Host "4h) Update Elastic YARA Rules (elastic/protections-artifacts -> detections\yara\)" -ForegroundColor DarkRed
Write-Host "4i) Push + Enable Detection Rules to Kibana SIEM (GTFOBins/Adaptix/persistence/Signal)" -ForegroundColor DarkRed
Write-Host ""

# -- GROUP 5: Elastic Baseline (was Group 12 in Loaded-Potato) ----------------
Write-Host "  $([char]27)[4m+----------------------------------------------------------+$([char]27)[24m" -ForegroundColor DarkCyan
Write-Host "  $([char]27)[4m|  (Elastic env) Baseline New Processes in the Environment  |$([char]27)[24m" -ForegroundColor DarkCyan
Write-Host "  $([char]27)[4m+----------------------------------------------------------+$([char]27)[24m" -ForegroundColor DarkCyan
Write-Host "5a) Specific Processes Name" -ForegroundColor DarkCyan
Write-Host "5b) New Drivers in the Env" -ForegroundColor DarkCyan
Write-Host "5c) New Unverified Processes" -ForegroundColor DarkCyan
Write-Host "5d) New Unsigned Windows Processes" -ForegroundColor DarkCyan
Write-Host "5e) New Unsigned Linux Processes" -ForegroundColor DarkCyan
Write-Host ""


$functionChoice = (Read-Host "Please enter an option").Trim().ToLowerInvariant()

# Group 2 deploy sub-handlers
if ($functionChoice -eq "2a") { $functionChoice = "__deploy_uac__" }
elseif ($functionChoice -eq "2b") { $functionChoice = "__deploy_kape__" }
elseif ($functionChoice -eq "2c") { $functionChoice = "__deploy_dfirorc__" }

# -- GROUP 1: Dependencies / Offline Setup -----------------------------------
# Dispatch starts here. Selecting 1a stages the toolkit's OWN dependencies
# (PS modules, pip packages, redistributable tools) for air-gapped use.
if ($functionChoice -eq "1a") {
    $depScript = Join-Path $PSScriptRoot "tools\deps\Get-Dependencies-Offline.ps1"
    if (Test-Path -LiteralPath $depScript) { & $depScript } else { Write-Host "Dependency downloader not found: $depScript" -ForegroundColor Red }
}

# -- GROUP 2: Remote Collection Tool Deployment -------------------------------
# NOTE: the dispatch chain begins at the 1a `if` above and every branch here is
# `elseif`, kept SEPARATE from the 2a/2b/2c rewrite block (which only rewrites
# $functionChoice into a __deploy_*__ token). Chaining the rewrite into the
# dispatch is what caused the earlier 1a/1b/1c deploy no-op bug - do not merge.
elseif ($functionChoice -eq "__deploy_uac__") {
    $deployScript = Join-Path $PSScriptRoot "tools\deploy\Deploy-UAC.ps1"
    if (Test-Path -LiteralPath $deployScript) { & $deployScript } else { Write-Host "Deploy script not found: $deployScript" -ForegroundColor Red }
}
elseif ($functionChoice -eq "__deploy_kape__") {
    $deployScript = Join-Path $PSScriptRoot "tools\deploy\Deploy-KAPE.ps1"
    if (Test-Path -LiteralPath $deployScript) { & $deployScript } else { Write-Host "Deploy script not found: $deployScript" -ForegroundColor Red }
}
elseif ($functionChoice -eq "__deploy_dfirorc__") {
    $deployScript = Join-Path $PSScriptRoot "tools\deploy\Deploy-DFIR-ORC.ps1"
    if (Test-Path -LiteralPath $deployScript) { & $deployScript } else { Write-Host "Deploy script not found: $deployScript" -ForegroundColor Red }
}
elseif ($functionChoice -eq "2d") {
    $target = (Read-Host "[?] Router hostname or IP").Trim()
    if ($target) {
        $user   = (Read-Host "[?] SSH username").Trim()
        $secPw  = Read-Host "[?] SSH password (leave blank to use key)" -AsSecureString
        $pwPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secPw))
        if (-not $pwPlain) {
            $sshKey  = (Read-Host "[?] Path to SSH private key").Trim()
            $secPw   = ConvertTo-SecureString 'x' -AsPlainText -Force
            $pwPlain = 'x'
        } else { $sshKey = $null }
        $cred = [PSCredential]::new($user, $secPw)
        $outPath = (Read-Host "[?] Output directory for dump files [default: .\output\routerDumps]").Trim()
        if (-not $outPath) { $outPath = ".\output\routerDumps" }
        $platform = (Read-Host "[?] Platform (auto/ios-xe/nxos/junos/fortios/panos/sel/mikrotik/linksys/tplink/glinet) [default: auto]").Trim()
        if (-not $platform) { $platform = 'auto' }
        $dumpParams = @{ Target = $target; Credential = $cred; OutputPath = $outPath; Platform = $platform }
        if ($sshKey) { $dumpParams['SshKey'] = $sshKey }
        $savedDir = Save-RouterDump @dumpParams
        if ($savedDir) {
            Write-Host "[+] Dump saved to: $savedDir" -ForegroundColor Green
            Write-Host "    Copy this directory to an air-gapped machine and run option 3c to analyze." -ForegroundColor DarkGray
        }
    } else {
        Write-Host "No target specified." -ForegroundColor Red
    }
}

# -- GROUP 3: Linux / UAC Forensic Triage (Offline) ---------------------------
elseif ($functionChoice -eq "3a") {
    $uacPath = (Read-Host "[?] Enter full path to extracted UAC dump directory").Trim()
    if ($uacPath -and (Test-Path -LiteralPath $uacPath)) {
        $outPath = (Read-Host "[?] Output directory for HTML report [default: .\reports\alertTriage]").Trim()
        if (-not $outPath) { $outPath = ".\reports\alertTriage" }
        Invoke-UACTriage -UACPath $uacPath -OutputPath $outPath -IntelBasePath ".\apt" -OpenReport
    } else {
        Write-Host "Path not found or not specified: $uacPath" -ForegroundColor Red
    }
}
elseif ($functionChoice -eq "3b") {
    $target = (Read-Host "[?] Router hostname or IP").Trim()
    if ($target) {
        $user   = (Read-Host "[?] SSH username").Trim()
        $secPw  = Read-Host "[?] SSH password (leave blank to use key)" -AsSecureString
        $pwPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secPw))
        $cred   = if ($pwPlain) { [PSCredential]::new($user, $secPw) } else { $null }
        $sshKey = if (-not $pwPlain) { (Read-Host "[?] Path to SSH private key").Trim() } else { $null }
        $outPath = (Read-Host "[?] Output directory for HTML report [default: .\reports\routerTriage]").Trim()
        if (-not $outPath) { $outPath = ".\reports\routerTriage" }
        $platform = (Read-Host "[?] Platform (auto/ios-xe/nxos/junos/fortios/panos/sel/mikrotik/linksys/tplink/glinet) [default: auto]").Trim()
        if (-not $platform) { $platform = 'auto' }
        $invokeParams = @{ Target = $target; OutputPath = $outPath; Platform = $platform; OpenReport = $true }
        if ($cred)   { $invokeParams['Credential'] = $cred }
        if ($sshKey) { $invokeParams['SshKey'] = $sshKey }
        Invoke-RouterTriage @invokeParams
    } else {
        Write-Host "No target specified." -ForegroundColor Red
    }
}
elseif ($functionChoice -eq "3c") {
    $dumpDir = (Read-Host "[?] Path to offline router dump directory (created by Save-RouterDump)").Trim()
    if ($dumpDir -and (Test-Path -LiteralPath $dumpDir)) {
        $outPath = (Read-Host "[?] Output directory for HTML report [default: .\reports\routerTriage]").Trim()
        if (-not $outPath) { $outPath = ".\reports\routerTriage" }
        Invoke-RouterTriage -DumpPath $dumpDir -OutputPath $outPath -OpenReport
    } else {
        Write-Host "Path not found or not specified: $dumpDir" -ForegroundColor Red
    }
}

# -- GROUP 4: Elastic Alerts ---------------------------------------------------
elseif ($functionChoice -eq "4a") {
    # 4a is a thin orchestrator: pull, then analyze. No parallel live-mode
    # codepath to maintain - every improvement to 4d / 4b / 4c lands in 4a
    # automatically.
    #   1. Call Get-ElasticDetonationLogs (4d) to pull a detonation window.
    #      4d auto-routes to the SSH connector when SO 3.0 / Kratos is
    #      detected (HTTP 302 on /_cluster/health), and returns the
    #      output directory path either way.
    #   2. Inspect the pulled NDJSON filenames to decide whether the host
    #      was Windows (windows.* / system.security|application|system /
    #      sysmon* files) or Linux (linux.* / auditd* / auth_events*).
    #   3. Dispatch to 4b (Invoke-ElasticAlertAgentAnalysis) for Windows or
    #      4c (Invoke-ElasticLinuxTriage) for Linux. If both signatures are
    #      present (mixed window), prompt the user.
    $outDir = Get-ElasticDetonationLogs
    if (-not $outDir -or -not (Test-Path -LiteralPath $outDir)) {
        Write-Host "[4a] Pull did not produce an output directory - nothing to analyze." -ForegroundColor Yellow
        return
    }

    # Two pull paths produce two different filename schemes:
    #   - SSH/TORCH pull writes DATASET-named files (windows.sysmon_operational.ndjson,
    #     linux.auditd.ndjson, etc.) matching the source event.dataset.
    #   - Vanilla HTTP pull via Get-ElasticDetonationLogs writes CATEGORY-named files
    #     (process_events.ndjson, network_events.ndjson, registry_events.ndjson, etc.)
    #     - the topical buckets 4b/4c consume natively.
    # Detection cascades: dataset-name regex first, then category-name signal, then a
    # doc-shape probe (host.os.type) on the first non-empty file to break ties.
    $allFiles = @(Get-ChildItem -Path $outDir -Filter '*.ndjson' -File -ErrorAction SilentlyContinue |
                  Where-Object { $_.Length -gt 0 })

    $winRegex = '^(windows\.|system\.(security|application|system)|sysmon|winlog\.)'
    $linRegex = '^(linux\.|auditd|auth_events|authentication_events|filebeat-linux|system\.auth|system\.syslog)'
    $winFiles = @($allFiles | Where-Object { $_.Name -match $winRegex })
    $linFiles = @($allFiles | Where-Object { $_.Name -match $linRegex })

    # Category-named files (Elastic Defend / Get-ElasticDetonationLogs output).
    # Some categories are OS-specific signal; others are ambiguous.
    $winCategoryNames = @('registry_events.ndjson','driver_and_pipe.ndjson',
                          'image_load.ndjson','injection_events.ndjson','api_events.ndjson')
    $linCategoryNames = @('auth_events.ndjson','authentication_events.ndjson')
    $ambiguousCategoryNames = @('process_events.ndjson','network_events.ndjson',
                                'file_events.ndjson','dns_events.ndjson','alerts.ndjson')

    $winCategoryFiles  = @($allFiles | Where-Object { $winCategoryNames -contains $_.Name })
    $linCategoryFiles  = @($allFiles | Where-Object { $linCategoryNames -contains $_.Name })
    $ambigCategoryFiles = @($allFiles | Where-Object { $ambiguousCategoryNames -contains $_.Name })

    # Doc-shape probe for the ambiguous case: read host.os.type from the first
    # non-empty file. host.os.type values from Elastic Defend: 'windows' / 'linux'.
    # Cheap (one Get-Content + one ConvertFrom-Json call) and definitive.
    $probedOs = $null
    $probeFile = $allFiles | Select-Object -First 1
    if ($probeFile) {
        try {
            $firstLine = (Get-Content -LiteralPath $probeFile.FullName -TotalCount 1 -ErrorAction Stop)
            if ($firstLine) {
                $doc = $firstLine | ConvertFrom-Json -ErrorAction Stop
                $osType = $null
                if ($doc.host -and $doc.host.os -and $doc.host.os.type) { $osType = "$($doc.host.os.type)".ToLowerInvariant() }
                elseif ($doc.host -and $doc.host.os -and $doc.host.os.family) { $osType = "$($doc.host.os.family)".ToLowerInvariant() }
                elseif ($doc._source -and $doc._source.host -and $doc._source.host.os -and $doc._source.host.os.type) { $osType = "$($doc._source.host.os.type)".ToLowerInvariant() }
                if ($osType -in 'windows','win','linux','lin','macos','darwin') { $probedOs = $osType }
            }
        } catch {}
    }

    Write-Host ""
    Write-Host "[4a] Pull complete: $outDir" -ForegroundColor DarkCyan
    Write-Host "     Windows datasets w/ events : $($winFiles.Count) file(s)" -ForegroundColor DarkGray
    Write-Host "     Linux   datasets w/ events : $($linFiles.Count) file(s)" -ForegroundColor DarkGray
    Write-Host "     Windows-specific categories : $($winCategoryFiles.Count) file(s)  (registry, driver+pipe, image_load, injection, api)" -ForegroundColor DarkGray
    Write-Host "     Linux-specific categories   : $($linCategoryFiles.Count) file(s)  (auth_events, authentication_events)" -ForegroundColor DarkGray
    Write-Host "     Ambiguous categories        : $($ambigCategoryFiles.Count) file(s)  (process, network, file, dns, alerts)" -ForegroundColor DarkGray
    if ($probedOs) {
        Write-Host "     Doc-shape probe (host.os)   : $probedOs" -ForegroundColor DarkGray
    }

    # Aggregate signals: any of (a) dataset-named match, (b) OS-specific category,
    # (c) ambiguous-category presence broken by doc-shape probe.
    $winFiles = @($winFiles) + @($winCategoryFiles)
    $linFiles = @($linFiles) + @($linCategoryFiles)
    if ($ambigCategoryFiles.Count -gt 0 -and $winFiles.Count -eq 0 -and $linFiles.Count -eq 0) {
        # Pure-ambiguous-category case (e.g. only process_events.ndjson). Let the probe decide.
        if ($probedOs -in 'windows','win')  { $winFiles = $ambigCategoryFiles }
        elseif ($probedOs -in 'linux','lin') { $linFiles = $ambigCategoryFiles }
    } elseif ($ambigCategoryFiles.Count -gt 0) {
        # Ambiguous files plus OS-specific signal - attribute the ambiguous bucket to the
        # OS the specific signal indicates. If both OSes specific-signal, attribute to both.
        if ($winFiles.Count -gt 0) { $winFiles = @($winFiles) + @($ambigCategoryFiles) }
        if ($linFiles.Count -gt 0) { $linFiles = @($linFiles) + @($ambigCategoryFiles) }
    }

    if ($winFiles.Count -gt 0 -and $linFiles.Count -eq 0) {
        Write-Host "[4a] -> Dispatching to 4b (Invoke-ElasticAlertAgentAnalysis, Windows)" -ForegroundColor DarkCyan
        Invoke-ElasticAlertAgentAnalysis -DetonationLogsDir $outDir
    } elseif ($linFiles.Count -gt 0 -and $winFiles.Count -eq 0) {
        Write-Host "[4a] -> Dispatching to 4c (Invoke-ElasticLinuxTriage, Linux)" -ForegroundColor DarkCyan
        Invoke-ElasticLinuxTriage -DetonationLogsDir $outDir
    } elseif ($winFiles.Count -gt 0 -and $linFiles.Count -gt 0) {
        Write-Host "[4a] Both Windows and Linux signatures present in pulled data." -ForegroundColor Yellow
        $os = (Read-Host "     Run (W)indows analysis, (L)inux analysis, or (B)oth? [B]").Trim().ToUpper()
        if ([string]::IsNullOrWhiteSpace($os)) { $os = 'B' }
        if ($os -eq 'W' -or $os -eq 'B') {
            Write-Host "[4a] -> Dispatching to 4b (Windows)" -ForegroundColor DarkCyan
            Invoke-ElasticAlertAgentAnalysis -DetonationLogsDir $outDir
        }
        if ($os -eq 'L' -or $os -eq 'B') {
            Write-Host "[4a] -> Dispatching to 4c (Linux)" -ForegroundColor DarkCyan
            Invoke-ElasticLinuxTriage -DetonationLogsDir $outDir
        }
    } else {
        Write-Host "[4a] No Windows or Linux dataset files (>0 bytes) were detected in the pulled directory." -ForegroundColor Yellow
        Write-Host "     Inspect the contents and run 4b or 4c manually with -DetonationLogsDir against:" -ForegroundColor DarkGray
        Write-Host "       $outDir" -ForegroundColor DarkGray
    }
}
elseif ($functionChoice -eq "4b") {
    $detonationLogPath = Read-Host "[?] Path to detonation log directory (NDJSON files)"
    if ($detonationLogPath -and (Test-Path -LiteralPath $detonationLogPath)) {
        Invoke-ElasticAlertAgentAnalysis -DetonationLogsDir $detonationLogPath
    } else {
        Write-Host "Invalid path: $detonationLogPath" -ForegroundColor Red
    }
}
elseif ($functionChoice -eq "4c") {
    $detonationLogPath = Read-Host "[?] Path to detonation log directory (NDJSON files)"
    if ($detonationLogPath -and (Test-Path -LiteralPath $detonationLogPath)) {
        Invoke-ElasticLinuxTriage -DetonationLogsDir $detonationLogPath
    } else {
        Write-Host "Invalid path: $detonationLogPath" -ForegroundColor Red
    }
}
elseif ($functionChoice -eq "4d") {
    Get-ElasticDetonationLogs
}
elseif ($functionChoice -eq "4e") {
    Invoke-LokiScan
}
elseif ($functionChoice -eq "4f") {
    $chosenDir = (Read-Host "[?] Enter full path to detonation log directory").Trim()
    if ($chosenDir -and (Test-Path $chosenDir)) {
        Update-ElasticYaraRules
        Update-LolDriversCache
        Invoke-ElasticAlertAgentAnalysis -DetonationLogsDir $chosenDir
    } else {
        Write-Host "Path not found or not specified: $chosenDir" -ForegroundColor Red
    }
}
elseif ($functionChoice -eq "4g") {
    Update-LolDriversCache
}
elseif ($functionChoice -eq "4h") {
    Update-ElasticYaraRules
}
elseif ($functionChoice -eq "4i") {
    # Push local NDJSON rule bundles to the Kibana SIEM and enable them.
    # Prompts for Kibana URL + auth (or reads Kibana_URL / Kibana_ApiKey secrets).
    Sync-ElasticDetections -Enable
}

# -- GROUP 5: Elastic Baseline (was Group 12 in Loaded-Potato) ----------------
elseif ($functionChoice -eq "5a") {
    $procToQuery = Read-Host -Prompt "Enter process name (i.e. lsass.exe)"
    Invoke-ElasticProcessSurvey -Mode SpecificProc -ProcName $procToQuery
}
elseif ($functionChoice -eq "5b") {
    Invoke-ElasticProcessSurvey -Mode Drivers -QueryDays -30
}
elseif ($functionChoice -eq "5c") {
    Invoke-ElasticProcessSurvey -Mode UnverifiedProcs
}
elseif ($functionChoice -eq "5d") {
    Invoke-ElasticProcessSurvey -Mode UnsignedWin -QueryDays -2
}
elseif ($functionChoice -eq "5e") {
    Invoke-ElasticProcessSurvey -Mode UnsignedLinux
}
else {
    Write-Host "Unknown option: $functionChoice" -ForegroundColor Red
}
