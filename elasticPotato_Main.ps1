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
#Set-Secret -Name 'Elastic_URL' -Secret 'API_Key_Here'  # e.g. https://elasticsearch.yourdomain:9200
#Set-Secret -Name 'Kibana_URL'  -Secret 'API_Key_Here'  # e.g. https://kibana.yourdomain:5601
#Set-Secret -Name 'Elastic_User' -Secret 'API_Key_Here'
#Set-Secret -Name 'Elastic_Pass' -Secret 'API_Key_Here'
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

# Agentic Elastic triage (Group 3)
Import-Module -Name ".\agentic\ElasticAlertAgent.psm1"
Import-Module -Name ".\agentic\Invoke-ElasticLinuxTriage.psm1"

# Forensic triage (Groups 1d, 2)
Import-Module -Name ".\forensics\Invoke-UACTriage.psm1"
Import-Module -Name ".\forensics\Invoke-RouterTriage.psm1"

# Group 4 (Elastic Baseline) -- remaining enrichment deps
Import-Module -Name ".\NewProcsModules\CheckAgainstVT.psm1"
Import-Module -Name ".\NewProcsModules\CheckApiVoid.psm1"
Import-Module -Name ".\NewProcsModules\CheckSuspiciousASNs.psm1"
Import-Module -Name ".\NewProcsModules\DomainCleanup.psm1"
Import-Module -Name ".\NewProcsModules\elasticProcessBaseline.psm1"

# Elastic detonation logs used by Group 3
Import-Module -Name ".\purpleTeaming\GetElasticDetonationLogs.psm1" -ErrorAction SilentlyContinue

# Detection cache refreshers (called by 3f and as standalone 3g/3h)
Import-Module -Name ".\detections\Update-LolDriversCache.psm1"
Import-Module -Name ".\detections\Update-ElasticYaraRules.psm1"

# Thor/Loki IOC + YARA scanner (3e)
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

# -- GROUP 1: Remote Collection Tool Deployment -------------------------------
Write-Host "  $([char]27)[4m+----------------------------------------------------------+$([char]27)[24m" -ForegroundColor DarkYellow
Write-Host "  $([char]27)[4m|   Remote Collection Tool Deployment (Offline Packages)    |$([char]27)[24m" -ForegroundColor DarkYellow
Write-Host "  $([char]27)[4m+----------------------------------------------------------+$([char]27)[24m" -ForegroundColor DarkYellow
Write-Host "1a) Deploy UAC Collector to Remote Host(s)" -ForegroundColor DarkYellow
Write-Host "1b) Deploy KAPE to Remote Windows Host(s)" -ForegroundColor DarkYellow
Write-Host "1c) Deploy DFIR-ORC to Remote Windows Host(s)" -ForegroundColor DarkYellow
Write-Host "     -> Requires offline packages already staged under .\tools\" -ForegroundColor DarkGray
Write-Host "1d) [Live SSH] Collect Router Forensic Dump (Save-RouterDump)" -ForegroundColor DarkYellow
Write-Host "     -> Pulls ~75 forensic commands from a live router; saves files for offline 2c analysis" -ForegroundColor DarkGray
Write-Host ""

# -- GROUP 2: Linux / UAC Forensic Triage (Offline) ---------------------------
Write-Host "  $([char]27)[4m+----------------------------------------------+$([char]27)[24m" -ForegroundColor DarkYellow
Write-Host "  $([char]27)[4m|        Linux / UAC Forensic Triage            |$([char]27)[24m" -ForegroundColor DarkYellow
Write-Host "  $([char]27)[4m+----------------------------------------------+$([char]27)[24m" -ForegroundColor DarkYellow
Write-Host "2a) [Offline] UAC Dump Triage - Full Expert Analysis (Rootkit/C2/Creds/Timeline/Attribution)" -ForegroundColor DarkYellow
Write-Host "2b) [Live SSH] Edge Router APT Triage - Full Expert Analysis" -ForegroundColor DarkYellow
Write-Host "2c) [Offline] Edge Router APT Triage - Analyze offline dump directory" -ForegroundColor DarkYellow
Write-Host ""

# -- GROUP 3: Elastic Alerts ---------------------------------------------------
Write-Host "  $([char]27)[4m+----------------------------------------------+$([char]27)[24m" -ForegroundColor DarkRed
Write-Host "  $([char]27)[4m|  (Elastic env) Analyze Artifacts for An Alert |$([char]27)[24m" -ForegroundColor DarkRed
Write-Host "  $([char]27)[4m+----------------------------------------------+$([char]27)[24m" -ForegroundColor DarkRed
Write-Host "3b) [AI Agent] Elastic Alert Triage (Windows) - Offline VT Enrichment" -ForegroundColor DarkRed
Write-Host "3c) [AI Agent] Elastic Alert Triage (Linux)   - Offline Forensic Analysis" -ForegroundColor DarkRed
Write-Host "3d) Pull Elastic Logs from Detonation Window" -ForegroundColor DarkRed
Write-Host "3e) Run IOC/YARA Scanner Against Downloaded Malicious Files (Thor/Loki auto-detect)" -ForegroundColor DarkRed
Write-Host "3f) [AI Agent] Offline Analysis + IOC/YARA Scan (Windows)" -ForegroundColor DarkRed
Write-Host "3g) Update LOL Drivers Cache (loldrivers.io + LOLDrivers Sigma + SigmaHQ)" -ForegroundColor DarkRed
Write-Host "3h) Update Elastic YARA Rules (elastic/protections-artifacts -> detections\yara\)" -ForegroundColor DarkRed
Write-Host ""

# -- GROUP 4: Elastic Baseline (was Group 12 in Loaded-Potato) ----------------
Write-Host "  $([char]27)[4m+----------------------------------------------------------+$([char]27)[24m" -ForegroundColor DarkCyan
Write-Host "  $([char]27)[4m|  (Elastic env) Baseline New Processes in the Environment  |$([char]27)[24m" -ForegroundColor DarkCyan
Write-Host "  $([char]27)[4m+----------------------------------------------------------+$([char]27)[24m" -ForegroundColor DarkCyan
Write-Host "4a) Specific Processes Name" -ForegroundColor DarkCyan
Write-Host "4b) New Drivers in the Env" -ForegroundColor DarkCyan
Write-Host "4c) New Unverified Processes" -ForegroundColor DarkCyan
Write-Host "4d) New Unsigned Windows Processes" -ForegroundColor DarkCyan
Write-Host "4e) New Unsigned Linux Processes" -ForegroundColor DarkCyan
Write-Host ""


$functionChoice = (Read-Host "Please enter an option").Trim().ToLowerInvariant()

# Group 1 deploy sub-handlers
if ($functionChoice -eq "1a") { $functionChoice = "__deploy_uac__" }
elseif ($functionChoice -eq "1b") { $functionChoice = "__deploy_kape__" }
elseif ($functionChoice -eq "1c") { $functionChoice = "__deploy_dfirorc__" }

# -- GROUP 1: Remote Collection Tool Deployment -------------------------------
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
elseif ($functionChoice -eq "1d") {
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
            Write-Host "    Copy this directory to an air-gapped machine and run option 2c to analyze." -ForegroundColor DarkGray
        }
    } else {
        Write-Host "No target specified." -ForegroundColor Red
    }
}

# -- GROUP 2: Linux / UAC Forensic Triage (Offline) ---------------------------
elseif ($functionChoice -eq "2a") {
    $uacPath = (Read-Host "[?] Enter full path to extracted UAC dump directory").Trim()
    if ($uacPath -and (Test-Path -LiteralPath $uacPath)) {
        $outPath = (Read-Host "[?] Output directory for HTML report [default: .\reports\alertTriage]").Trim()
        if (-not $outPath) { $outPath = ".\reports\alertTriage" }
        Invoke-UACTriage -UACPath $uacPath -OutputPath $outPath -IntelBasePath ".\apt" -OpenReport
    } else {
        Write-Host "Path not found or not specified: $uacPath" -ForegroundColor Red
    }
}
elseif ($functionChoice -eq "2b") {
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
elseif ($functionChoice -eq "2c") {
    $dumpDir = (Read-Host "[?] Path to offline router dump directory (created by Save-RouterDump)").Trim()
    if ($dumpDir -and (Test-Path -LiteralPath $dumpDir)) {
        $outPath = (Read-Host "[?] Output directory for HTML report [default: .\reports\routerTriage]").Trim()
        if (-not $outPath) { $outPath = ".\reports\routerTriage" }
        Invoke-RouterTriage -DumpPath $dumpDir -OutputPath $outPath -OpenReport
    } else {
        Write-Host "Path not found or not specified: $dumpDir" -ForegroundColor Red
    }
}

# -- GROUP 3: Elastic Alerts ---------------------------------------------------
elseif ($functionChoice -eq "3b") {
    $detonationLogPath = Read-Host "[?] Path to detonation log directory (NDJSON files)"
    if ($detonationLogPath -and (Test-Path -LiteralPath $detonationLogPath)) {
        Invoke-ElasticAlertAgentAnalysis -DetonationLogsDir $detonationLogPath
    } else {
        Write-Host "Invalid path: $detonationLogPath" -ForegroundColor Red
    }
}
elseif ($functionChoice -eq "3c") {
    $detonationLogPath = Read-Host "[?] Path to detonation log directory (NDJSON files)"
    if ($detonationLogPath -and (Test-Path -LiteralPath $detonationLogPath)) {
        Invoke-ElasticLinuxTriage -DetonationLogsDir $detonationLogPath
    } else {
        Write-Host "Invalid path: $detonationLogPath" -ForegroundColor Red
    }
}
elseif ($functionChoice -eq "3d") {
    Get-ElasticDetonationLogs
}
elseif ($functionChoice -eq "3e") {
    Invoke-LokiScan
}
elseif ($functionChoice -eq "3f") {
    $chosenDir = (Read-Host "[?] Enter full path to detonation log directory").Trim()
    if ($chosenDir -and (Test-Path $chosenDir)) {
        Update-ElasticYaraRules
        Update-LolDriversCache
        Invoke-ElasticAlertAgentAnalysis -DetonationLogsDir $chosenDir
    } else {
        Write-Host "Path not found or not specified: $chosenDir" -ForegroundColor Red
    }
}
elseif ($functionChoice -eq "3g") {
    Update-LolDriversCache
}
elseif ($functionChoice -eq "3h") {
    Update-ElasticYaraRules
}

# -- GROUP 4: Elastic Baseline (was Group 12 in Loaded-Potato) ----------------
elseif ($functionChoice -eq "4a") {
    $procToQuery = Read-Host -Prompt "Enter process name (i.e. lsass.exe)"
    Invoke-ElasticProcessSurvey -Mode SpecificProc -ProcName $procToQuery
}
elseif ($functionChoice -eq "4b") {
    Invoke-ElasticProcessSurvey -Mode Drivers -QueryDays -30
}
elseif ($functionChoice -eq "4c") {
    Invoke-ElasticProcessSurvey -Mode UnverifiedProcs
}
elseif ($functionChoice -eq "4d") {
    Invoke-ElasticProcessSurvey -Mode UnsignedWin -QueryDays -2
}
elseif ($functionChoice -eq "4e") {
    Invoke-ElasticProcessSurvey -Mode UnsignedLinux
}
else {
    Write-Host "Unknown option: $functionChoice" -ForegroundColor Red
}
