function Invoke-LocalHardening {
<#
.SYNOPSIS
    Applies CIS/STIG-aligned hardening settings directly to the local machine.
.DESCRIPTION
    Three-phase local hardening without requiring Active Directory or GPMC:
      Phase 1 - secedit   : Account policies, user rights, basic audit policy
      Phase 2 - auditpol  : Advanced audit subcategories (CIS 17.x)
      Phase 3 - registry  : UAC, LSA/NTLM, SMB signing, WinRM, RDP, Defender,
                            Firewall, PowerShell logging, Event Log sizes, screen lock
    Requires an elevated (Administrator) session.
.PARAMETER Profile
    Auto | Workstation | Server | DomainController
    Auto detects the local role (DC -> DomainController, otherwise Workstation).
.PARAMETER SkipSecedit   Skip Phase 1 (secedit).
.PARAMETER SkipAuditPol  Skip Phase 2 (auditpol advanced audit subcategories).
.PARAMETER SkipRegistry  Skip Phase 3 (registry hardening).
.PARAMETER Force         Suppress confirmation prompt.
.EXAMPLE
    Invoke-LocalHardening
.EXAMPLE
    Invoke-LocalHardening -Profile Workstation -SkipSecedit -Force
.NOTES
    Run from an elevated PowerShell session.
#>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [ValidateSet("Auto","Workstation","Server","DomainController")]
        [string]$Profile = "Auto",
        [switch]$SkipSecedit,
        [switch]$SkipAuditPol,
        [switch]$SkipRegistry,
        [switch]$Force
    )

    function Write-Pass   ($m) { Write-Host "  [PASS] $m" -ForegroundColor Green  }
    function Write-Fail   ($m) { Write-Host "  [FAIL] $m" -ForegroundColor Red    }
    function Write-Warn   ($m) { Write-Host "  [WARN] $m" -ForegroundColor Yellow }
    function Write-Info   ($m) { Write-Host "  [INFO] $m" -ForegroundColor DarkCyan   }
    function Write-Section($m) { Write-Host "`n--- $m ---" -ForegroundColor Magenta }

    $script:applied = 0; $script:warned = 0; $script:failed = 0

    function Apply-Reg {
        param([string]$Path,[string]$Name,[string]$Type,[object]$Value)
        try {
            if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
            Set-ItemProperty -Path $Path -Name $Name -Type $Type -Value $Value -Force
            Write-Pass "$Name = $Value"
            $script:applied++
        } catch {
            Write-Fail "$Name : $_"
            $script:failed++
        }
    }

    function Set-Audit {
        param([string]$Subcategory,[string]$Setting)
        $sEnable = if ($Setting -match "Success|Both") { "enable" } else { "disable" }
        $fEnable = if ($Setting -match "Failure|Both") { "enable" } else { "disable" }
        $out = & auditpol /set /subcategory:"$Subcategory" /success:$sEnable /failure:$fEnable 2>&1
        if ($LASTEXITCODE -eq 0) { Write-Pass "$Subcategory : $Setting"; $script:applied++ }
        else                     { Write-Fail "$Subcategory : $out";     $script:failed++  }
    }

    # Elevation check
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "Invoke-LocalHardening requires an elevated (Administrator) session."
        return
    }

    # Profile auto-detect
    if ($Profile -eq "Auto") {
        $role    = (Get-WmiObject Win32_ComputerSystem -ErrorAction SilentlyContinue).DomainRole
        $Profile = if ($role -ge 4) { "DomainController" } else { "Workstation" }
        Write-Info "Auto-detected profile: $Profile"
    }

    # Confirmation
    if (-not $Force) {
        Write-Host "`nThis will apply CIS/STIG-aligned hardening to this machine ($Profile profile)." -ForegroundColor Yellow
        $ans = Read-Host "Continue? (y/N)"
        if ($ans -notmatch "^[yY]$") { Write-Info "Aborted."; return }
    }

    # ===== PHASE 1: secedit =====
    if (-not $SkipSecedit) {
        Write-Section "Phase 1 - secedit (Account Policies / User Rights / Basic Audit)"
        $profilesDir = Join-Path $PSScriptRoot "..\Profiles"
        $defFile     = Join-Path $profilesDir "$Profile.ps1"
        if (-not (Test-Path $defFile)) {
            Write-Warn "Profile definition not found: $defFile - skipping secedit phase."
            $script:warned++
        } else {
            $def     = . $defFile
            $infPath = Join-Path $env:TEMP "HardenedBaseline_$Profile.inf"
            try {
                [System.IO.File]::WriteAllText($infPath, $def.GptTmpl, [System.Text.Encoding]::Unicode)
                Write-Info "GptTmpl.inf written to $infPath"
            } catch {
                Write-Fail "Failed to write GptTmpl.inf: $_"; $script:failed++; $infPath = $null
            }
            if ($infPath) {
                $backupPath = Join-Path $env:TEMP "secedit_backup_$(Get-Date -Format yyyyMMdd_HHmmss).inf"
                & secedit /export /cfg $backupPath /quiet 2>&1 | Out-Null
                Write-Info "Backed up current policy to $backupPath"
                $logPath = Join-Path $env:TEMP "secedit_apply.log"
                & secedit /configure /db "$env:TEMP\secedit_tmp.sdb" /cfg $infPath /areas SECURITYPOLICY PRIVILEGES AUDITPOLICY /log $logPath /quiet 2>&1 | Out-Null
                if ($LASTEXITCODE -eq 0) { Write-Pass "secedit applied (log: $logPath)"; $script:applied++ }
                else { Write-Warn "secedit exit code $LASTEXITCODE - review $logPath"; $script:warned++ }
            }
        }
    }

    # ===== PHASE 2: auditpol =====
    if (-not $SkipAuditPol) {
        Write-Section "Phase 2 - auditpol (CIS 17.x Advanced Audit Subcategories)"
        # CIS 17.1 - Account Logon
        Set-Audit "Credential Validation"                 "Both"
        # CIS 17.2 - Account Management
        Set-Audit "Application Group Management"          "Both"
        Set-Audit "Computer Account Management"           "Both"
        Set-Audit "Distribution Group Management"         "Both"
        Set-Audit "Other Account Management Events"       "Both"
        Set-Audit "Security Group Management"             "Both"
        Set-Audit "User Account Management"               "Both"
        # CIS 17.3 - Detailed Tracking
        Set-Audit "PNP Activity"                          "Success"
        Set-Audit "Process Creation"                      "Success"
        # CIS 17.4 - DS Access (DC only)
        if ($Profile -eq "DomainController") {
            Set-Audit "Directory Service Access"          "Failure"
            Set-Audit "Directory Service Changes"         "Both"
        }
        # CIS 17.5 - Logon/Logoff
        Set-Audit "Account Lockout"                       "Failure"
        Set-Audit "Group Membership"                      "Success"
        Set-Audit "Logoff"                                "Success"
        Set-Audit "Logon"                                 "Both"
        Set-Audit "Other Logon/Logoff Events"             "Both"
        Set-Audit "Special Logon"                         "Both"
        # CIS 17.6 - Object Access
        Set-Audit "Detailed File Share"                   "Failure"
        Set-Audit "File Share"                            "Both"
        Set-Audit "Other Object Access Events"            "Both"
        Set-Audit "Removable Storage"                     "Both"
        Set-Audit "SAM"                                   "Failure"
        # CIS 17.7 - Policy Change
        Set-Audit "Audit Policy Change"                   "Both"
        Set-Audit "Authentication Policy Change"          "Both"
        Set-Audit "Authorization Policy Change"           "Both"
        Set-Audit "MPSSVC Rule-Level Policy Change"       "Both"
        Set-Audit "Other Policy Change Events"            "Failure"
        # CIS 17.8 - Privilege Use
        Set-Audit "Sensitive Privilege Use"               "Both"
        # CIS 17.9 - System
        Set-Audit "IPsec Driver"                          "Both"
        Set-Audit "Other System Events"                   "Both"
        Set-Audit "Security State Change"                 "Both"
        Set-Audit "Security System Extension"             "Both"
        Set-Audit "System Integrity"                      "Both"
    }

    # ===== PHASE 3: registry =====
    if (-not $SkipRegistry) {
        Write-Section "Phase 3 - Registry Hardening"

        Write-Info "UAC"
        $polSys = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Apply-Reg $polSys "EnableLUA"                        DWord 1
        Apply-Reg $polSys "ConsentPromptBehaviorAdmin"       DWord 2
        Apply-Reg $polSys "ConsentPromptBehaviorUser"        DWord 0
        Apply-Reg $polSys "PromptOnSecureDesktop"            DWord 1
        Apply-Reg $polSys "EnableVirtualization"             DWord 1
        Apply-Reg $polSys "FilterAdministratorToken"         DWord 1

        Write-Info "WDigest"
        Apply-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "UseLogonCredential" DWord 0

        Write-Info "LSA / NTLM"
        $lsa = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Apply-Reg $lsa "RunAsPPL"             DWord 1
        Apply-Reg $lsa "RestrictAnonymous"    DWord 1
        Apply-Reg $lsa "RestrictAnonymousSAM" DWord 1
        Apply-Reg $lsa "LmCompatibilityLevel" DWord 5
        Apply-Reg $lsa "NoLMHash"             DWord 1
        Apply-Reg $lsa "DisableDomainCreds"   DWord 1
        $msv = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
        Apply-Reg $msv "NTLMMinClientSec"             DWord 537395200
        Apply-Reg $msv "NTLMMinServerSec"             DWord 537395200
        Apply-Reg $msv "RestrictSendingNTLMTraffic"   DWord 2
        Apply-Reg $msv "RestrictReceivingNTLMTraffic" DWord 2

        Write-Info "SMB Signing"
        $wks = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
        Apply-Reg $wks "RequireSecuritySignature" DWord 1
        Apply-Reg $wks "EnableSecuritySignature"  DWord 1
        $srv = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        Apply-Reg $srv "RequireSecuritySignature" DWord 1
        Apply-Reg $srv "EnableSecuritySignature"  DWord 1
        Apply-Reg $srv "RestrictNullSessAccess"   DWord 1

        Write-Info "Kerberos"
        Apply-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" "SupportedEncryptionTypes" DWord 2147483640

        Write-Info "LDAP Signing"
        Apply-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP" "LDAPClientIntegrity" DWord 2

        Write-Info "WinRM"
        $wmrs = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
        Apply-Reg $wmrs "AllowBasic"              DWord 0
        Apply-Reg $wmrs "AllowUnencryptedTraffic" DWord 0
        Apply-Reg $wmrs "DisableRunAs"            DWord 1
        $wmrc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
        Apply-Reg $wmrc "AllowBasic"              DWord 0
        Apply-Reg $wmrc "AllowUnencryptedTraffic" DWord 0
        Apply-Reg $wmrc "AllowDigest"             DWord 0

        Write-Info "RDP"
        $rdp = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        Apply-Reg $rdp "fEncryptRPCTraffic" DWord 1
        Apply-Reg $rdp "MinEncryptionLevel" DWord 3
        Apply-Reg $rdp "fDisableCdm"        DWord 1
        Apply-Reg $rdp "fPromptForPassword" DWord 1
        Apply-Reg $rdp "SecurityLayer"      DWord 2

        Write-Info "Windows Defender"
        Apply-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"                       "DisableAntiSpyware"                  DWord 0
        Apply-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableRealtimeMonitoring"           DWord 0
        Apply-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableBehaviorMonitoring"           DWord 0
        Apply-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableIOAVProtection"               DWord 0
        Apply-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"               "SpynetReporting"                    DWord 2
        Apply-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"               "SubmitSamplesConsent"               DWord 1
        Apply-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine"             "MpCloudBlockLevel"                  DWord 2
        Apply-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"                 "CheckForSignaturesBeforeRunningScan" DWord 1

        Write-Info "AutoRun / AutoPlay"
        $exp = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        Apply-Reg $exp "NoDriveTypeAutoRun" DWord 255
        Apply-Reg $exp "NoAutorun"          DWord 1
        Apply-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoAutoplayfornonVolume" DWord 1

        Write-Info "Windows Firewall"
        foreach ($fwp in @("Domain","Private","Public")) {
            $fb = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\${fwp}Profile"
            Apply-Reg $fb "EnableFirewall"        DWord 1
            Apply-Reg $fb "DefaultInboundAction"  DWord 1
            Apply-Reg $fb "DefaultOutboundAction" DWord 0
        }

        Write-Info "PowerShell Logging"
        Apply-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging"           DWord 1
        Apply-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockInvocationLogging" DWord 1
        Apply-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"      "EnableModuleLogging"               DWord 1
        Apply-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"      "EnableTranscripting"               DWord 1
        Apply-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"      "EnableInvocationHeader"            DWord 1

        Write-Info "Event Log Sizes"
        Apply-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" "MaxSize" DWord 32768
        Apply-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"    "MaxSize" DWord 196608
        Apply-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System"      "MaxSize" DWord 32768

        Write-Info "Screen Lock"
        Apply-Reg $polSys "InactivityTimeoutSecs" DWord 900
        Apply-Reg "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" "ScreenSaverIsSecure" String "1"
        Apply-Reg "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" "ScreenSaveTimeOut"   String "900"
    }

    # ===== Summary =====
    Write-Host ""
    Write-Host ("-" * 89) -ForegroundColor White
    Write-Host " LOCAL HARDENING COMPLETE  ($Profile)" -ForegroundColor White
    Write-Host ("-" * 89) -ForegroundColor White
    Write-Host ("  Applied : {0,4}" -f $script:applied) -ForegroundColor Green
    Write-Host ("  Warned  : {0,4}" -f $script:warned)  -ForegroundColor Yellow
    $fc = if ($script:failed -gt 0) { "Red" } else { "Green" }
    Write-Host ("  Failed  : {0,4}" -f $script:failed)  -ForegroundColor $fc
    Write-Host ""
    if ($script:failed -gt 0) { Write-Warn "Some settings could not be applied. Re-run elevated, or check OS compatibility." }
    Write-Info "A reboot is recommended to ensure all settings take effect."
    Write-Info "Re-run your compliance scan to verify remediation."

    [PSCustomObject]@{ Profile = $Profile; Applied = $script:applied; Warned = $script:warned; Failed = $script:failed }
}
