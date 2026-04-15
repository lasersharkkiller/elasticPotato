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

# Agentic Elastic triage (Group 4)
Import-Module -Name ".\agentic\ElasticAlertAgent.psm1"
Import-Module -Name ".\agentic\Invoke-ElasticLinuxTriage.psm1"

# Forensic triage (Groups 2d, 3)
Import-Module -Name ".\forensics\Invoke-UACTriage.psm1"
Import-Module -Name ".\forensics\Invoke-RouterTriage.psm1"

# Group 5 (Elastic Baseline) -- remaining enrichment deps
Import-Module -Name ".\NewProcsModules\CheckAgainstVT.psm1"
Import-Module -Name ".\NewProcsModules\CheckApiVoid.psm1"
Import-Module -Name ".\NewProcsModules\CheckSuspiciousASNs.psm1"
Import-Module -Name ".\NewProcsModules\DomainCleanup.psm1"
Import-Module -Name ".\NewProcsModules\elasticProcessBaseline.psm1"

# Elastic detonation logs used by Group 4
Import-Module -Name ".\purpleTeaming\GetElasticDetonationLogs.psm1" -ErrorAction SilentlyContinue

# Hardening modules (Group 1)
Import-Module -Name ".\Hardening\ComplianceScan\ComplianceScan.psd1"
Import-Module -Name ".\Hardening\HardenedGPO\HardenedGPO.psd1"

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

# -- GROUP 1: Windows Hardening & Compliance -----------------------------------
Write-Host "  $([char]27)[4m+------------------------------------------------------------+$([char]27)[24m" -ForegroundColor DarkCyan
Write-Host "  $([char]27)[4m|           Windows Hardening & Compliance                   |$([char]27)[24m" -ForegroundColor DarkCyan
Write-Host "  $([char]27)[4m+------------------------------------------------------------+$([char]27)[24m" -ForegroundColor DarkCyan
Write-Host "  -- NIST 800-53 --" -ForegroundColor DarkCyan
Write-Host "1a) NIST 800-53 Scan - Auto Detect Profile (Workstation / Server / DC)" -ForegroundColor DarkCyan
Write-Host "1b) NIST 800-53 Scan - Workstation" -ForegroundColor DarkCyan
Write-Host "1c) NIST 800-53 Scan - Server" -ForegroundColor DarkCyan
Write-Host "1d) NIST 800-53 Scan - Domain Controller" -ForegroundColor DarkCyan
Write-Host "1e) Export NIST 800-53 Report (HTML + CSV)" -ForegroundColor DarkCyan
Write-Host "  -- CIS Benchmarks --" -ForegroundColor DarkCyan
Write-Host "1f) Run CIS Benchmark Scan - Level 1" -ForegroundColor DarkCyan
Write-Host "1g) Run CIS Benchmark Scan - Level 1 + Level 2" -ForegroundColor DarkCyan
Write-Host "1h) Export CIS Scan Report (HTML + CSV)" -ForegroundColor DarkCyan
Write-Host "  -- CMMC --" -ForegroundColor DarkCyan
Write-Host "1i) Run CMMC Level 1 Assessment (57 Practices)" -ForegroundColor DarkCyan
Write-Host "1j) Run CMMC Level 2 Assessment (110 Practices)" -ForegroundColor DarkCyan
Write-Host "1k) Export CMMC Assessment Report (HTML + CSV)" -ForegroundColor DarkCyan
Write-Host "  -- NIST 800-171 --" -ForegroundColor DarkCyan
Write-Host "1l) Run NIST 800-171 Assessment (110 Controls)" -ForegroundColor DarkCyan
Write-Host "1m) Export NIST 800-171 Report (HTML + CSV)" -ForegroundColor DarkCyan
Write-Host "  -- GPO Generation & Hardening --" -ForegroundColor DarkCyan
Write-Host "1n) Generate Hardened GPO - Workstation" -ForegroundColor DarkCyan
Write-Host "1o) Generate Hardened GPO - Server" -ForegroundColor DarkCyan
Write-Host "1p) Generate Hardened GPO - Domain Controller" -ForegroundColor DarkCyan
Write-Host "1q) Generate Hardened GPO - ALL Profiles (Workstation + Server + DC)" -ForegroundColor DarkCyan
Write-Host "1r) Import Hardened GPO into Active Directory" -ForegroundColor DarkCyan
Write-Host "1s) Apply Local Hardening Directly (secedit + auditpol + registry)" -ForegroundColor DarkCyan
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
Write-Host "4b) [AI Agent] Elastic Alert Triage (Windows) - Offline VT Enrichment" -ForegroundColor DarkRed
Write-Host "4c) [AI Agent] Elastic Alert Triage (Linux)   - Offline Forensic Analysis" -ForegroundColor DarkRed
Write-Host "4d) Pull Elastic Logs from Detonation Window" -ForegroundColor DarkRed
Write-Host "4e) Run IOC/YARA Scanner Against Downloaded Malicious Files (Thor/Loki auto-detect)" -ForegroundColor DarkRed
Write-Host "4f) [AI Agent] Offline Analysis + IOC/YARA Scan (Windows)" -ForegroundColor DarkRed
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

# -- GROUP 1: Windows Hardening & Compliance -----------------------------------
if ($functionChoice -eq "1a") {
    $results = Invoke-ComplianceScan
    $out = Read-Host -Prompt "Output path for report [default: .\ComplianceScan_Output]"
    if (-not $out) { $out = ".\ComplianceScan_Output" }
    $results | Export-ScanReport -OutputPath $out
    $failCount = ($results | Where-Object { $_.Status -eq "FAIL" }).Count
    if ($failCount -gt 0) {
        Write-Host ""
        Write-Host "  $failCount check(s) failed." -ForegroundColor Yellow
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isAdmin) {
            Write-Host "  [!] Re-run elasticPotato_Main.ps1 as Administrator to apply hardening." -ForegroundColor Red
        } else {
            $fix = Read-Host -Prompt "Apply local hardening? (y/N)"
            if ($fix -match "^[yY]$") { Invoke-LocalHardening -Profile Auto -Force }
        }
    }
}
elseif ($functionChoice -eq "1b") {
    $results = Invoke-ComplianceScan -Profile Workstation
    $out = Read-Host -Prompt "Output path for report [default: .\ComplianceScan_Output]"
    if (-not $out) { $out = ".\ComplianceScan_Output" }
    $results | Export-ScanReport -OutputPath $out
}
elseif ($functionChoice -eq "1c") {
    $results = Invoke-ComplianceScan -Profile Server
    $out = Read-Host -Prompt "Output path for report [default: .\ComplianceScan_Output]"
    if (-not $out) { $out = ".\ComplianceScan_Output" }
    $results | Export-ScanReport -OutputPath $out
}
elseif ($functionChoice -eq "1d") {
    $results = Invoke-ComplianceScan -Profile DomainController
    $out = Read-Host -Prompt "Output path for report [default: .\ComplianceScan_Output]"
    if (-not $out) { $out = ".\ComplianceScan_Output" }
    $results | Export-ScanReport -OutputPath $out
}
elseif ($functionChoice -eq "1e") {
    $out = Read-Host -Prompt "Output path for report [default: .\ComplianceScan_Output]"
    if (-not $out) { $out = ".\ComplianceScan_Output" }
    Invoke-ComplianceScan -Quiet | Export-ScanReport -OutputPath $out -Format All
}
elseif ($functionChoice -eq "1f") { $global:lastCISScan = Invoke-CISScan -Level 1 }
elseif ($functionChoice -eq "1g") { $global:lastCISScan = Invoke-CISScan -Level 2 }
elseif ($functionChoice -eq "1h") {
    $findings = $global:lastCISScan
    $outPath  = Read-Host -Prompt "Output path for CIS report [default: .\CISScan_Output]"
    if ([string]::IsNullOrWhiteSpace($outPath)) { $outPath = ".\CISScan_Output" }
    if ($null -ne $findings -and @($findings).Count -gt 0) {
        Export-CISScanReport -Findings $findings -OutputPath $outPath
    } else {
        $global:lastCISScan = Invoke-CISScan -Level 1
        Export-CISScanReport -Findings $global:lastCISScan -OutputPath $outPath
    }
}
elseif ($functionChoice -eq "1i") { $global:lastCMMCScan = Invoke-CMMCScan -Level 1 }
elseif ($functionChoice -eq "1j") { $global:lastCMMCScan = Invoke-CMMCScan -Level 2 }
elseif ($functionChoice -eq "1k") {
    $findings = $global:lastCMMCScan
    $outPath  = Read-Host -Prompt "Output path for CMMC report [default: .\CMMCScan_Output]"
    if ([string]::IsNullOrWhiteSpace($outPath)) { $outPath = ".\CMMCScan_Output" }
    if ($null -ne $findings -and @($findings).Count -gt 0) {
        Export-CMMCScanReport -Findings $findings -OutputPath $outPath
    } else {
        $global:lastCMMCScan = Invoke-CMMCScan -Level 1
        Export-CMMCScanReport -Findings $global:lastCMMCScan -OutputPath $outPath
    }
}
elseif ($functionChoice -eq "1l") { $global:lastNIST171Scan = Invoke-NIST800171Scan }
elseif ($functionChoice -eq "1m") {
    $findings = $global:lastNIST171Scan
    $outPath  = Read-Host -Prompt "Output path for NIST 800-171 report [default: .\NIST171Scan_Output]"
    if ([string]::IsNullOrWhiteSpace($outPath)) { $outPath = ".\NIST171Scan_Output" }
    if ($null -ne $findings -and @($findings).Count -gt 0) {
        Export-NIST800171Report -Findings $findings -OutputPath $outPath
    } else {
        $global:lastNIST171Scan = Invoke-NIST800171Scan
        Export-NIST800171Report -Findings $global:lastNIST171Scan -OutputPath $outPath
    }
}
elseif ($functionChoice -eq "1n") {
    $out = Read-Host -Prompt "Output path [default: .\HardenedGPO_Output]"
    if (-not $out) { $out = ".\HardenedGPO_Output" }
    New-HardenedGPO -Profile Workstation -OutputPath $out
}
elseif ($functionChoice -eq "1o") {
    $out = Read-Host -Prompt "Output path [default: .\HardenedGPO_Output]"
    if (-not $out) { $out = ".\HardenedGPO_Output" }
    New-HardenedGPO -Profile Server -OutputPath $out
}
elseif ($functionChoice -eq "1p") {
    $out = Read-Host -Prompt "Output path [default: .\HardenedGPO_Output]"
    if (-not $out) { $out = ".\HardenedGPO_Output" }
    New-HardenedGPO -Profile DomainController -OutputPath $out
    Write-Host "REMINDER: Link the DC GPO to the Domain Controllers OU ONLY." -ForegroundColor Yellow
}
elseif ($functionChoice -eq "1q") {
    $out = Read-Host -Prompt "Output path [default: .\HardenedGPO_Output]"
    if (-not $out) { $out = ".\HardenedGPO_Output" }
    New-HardenedGPO -Profile All -OutputPath $out
    Write-Host "REMINDER: Link the DC GPO to the Domain Controllers OU ONLY." -ForegroundColor Yellow
}
elseif ($functionChoice -eq "1r") {
    $backupPath = Read-Host -Prompt "GPO BackupPath"
    $gpoName    = Read-Host -Prompt "GPO Name"
    $targetOU   = Read-Host -Prompt "Target OU DN"
    $enforced   = Read-Host -Prompt "Enforced? [y/N]"
    if ($enforced -match "^[yY]") {
        Import-HardenedGPO -BackupPath $backupPath -GPOName $gpoName -TargetOU $targetOU -Enforced
    } else {
        Import-HardenedGPO -BackupPath $backupPath -GPOName $gpoName -TargetOU $targetOU
    }
}
elseif ($functionChoice -eq "1s") {
    Invoke-LocalHardening -Profile Auto -Force
}

# -- GROUP 2: Remote Collection Tool Deployment -------------------------------
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
    Write-Host "Option 4e is unavailable (Invoke-LokiScan module removed)." -ForegroundColor Yellow
}
elseif ($functionChoice -eq "4f") {
    Write-Host "Option 4f is unavailable (detection-pack refresh modules removed)." -ForegroundColor Yellow
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
