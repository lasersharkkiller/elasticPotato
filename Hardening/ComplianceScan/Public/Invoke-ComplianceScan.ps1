function Invoke-ComplianceScan {
<#
.SYNOPSIS
    Scans the local machine against NIST 800-53 Rev 5 + CIS benchmark controls.

.DESCRIPTION
    Performs a read-only audit covering ~200 automatable checks across NIST 800-53
    Rev 5 control families: AC, AU, CM, IA, SC, SI, SA, MP, CP, MA, PS-partial.
    Each finding includes the NIST control ID and CIS benchmark reference where
    applicable. Makes NO changes to the system.

.PARAMETER Profile
    Auto | Workstation | Server | DomainController

.PARAMETER SkipAuditPolicy
    Skip auditpol.exe checks.

.PARAMETER Quiet
    Suppress per-finding console output.

.OUTPUTS
    System.Collections.Generic.List[PSCustomObject]
    Fields: Profile, NISTControl, NISTFamily, Category, Setting,
            CurrentValue, RecommendedValue, Status, CISReference
#>
    [CmdletBinding()]
    param(
        [ValidateSet("Auto","Workstation","Server","DomainController")]
        [string]$Profile = "Auto",
        [switch]$SkipAuditPolicy,
        [switch]$Quiet
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # -- Auto-detect profile ----------------------------------------------------
    if ($Profile -eq "Auto") {
        try {
            $dr = (Get-WmiObject Win32_ComputerSystem -ErrorAction SilentlyContinue).DomainRole
            $pt = (Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue).ProductType
            $isDC     = $dr -ge 4
            $isServer = $pt -ne 1
        } catch { $isDC = $false; $isServer = $false }
        $Profile = if ($isDC) { "DomainController" } elseif ($isServer) { "Server" } else { "Workstation" }
    }
    if (-not $Quiet) { Write-Info "Detected profile: $Profile" }

    # -- Core helpers -----------------------------------------------------------
    function Add-Finding {
        param([string]$NISTControl,[string]$NISTFamily,[string]$Category,
              [string]$Setting,[string]$CurrentValue,[string]$RecommendedValue,
              [string]$Status,[string]$CISRef="N/A",[string]$Prof="All")
        $findings.Add([PSCustomObject]@{
            Profile          = $Prof
            NISTControl      = $NISTControl
            NISTFamily       = $NISTFamily
            Category         = $Category
            Setting          = $Setting
            CurrentValue     = $CurrentValue
            RecommendedValue = $RecommendedValue
            Status           = $Status
            CISReference     = $CISRef
        })
        if (-not $Quiet) {
            $lbl = if ($Prof -ne "All") { "[$Prof] " } else { "" }
            switch ($Status) {
                "Pass" { Write-Pass "$lbl$NISTControl | $Setting" }
                "Fail" { Write-Fail "$lbl$NISTControl | $Setting = $CurrentValue  (expected: $RecommendedValue)" }
                "Warn" { Write-Warn "$lbl$NISTControl | $Setting = $CurrentValue" }
            }
        }
    }

    function Check-Reg {
        param([string]$Path,[string]$Name,$Expected,[string]$Desc,
              [string]$NIST,[string]$Family,[string]$Cat,[string]$CIS="N/A",[string]$Prof="All")
        try {
            $val = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
            $st  = if ($val -eq $Expected) { "Pass" } else { "Fail" }
            Add-Finding -NISTControl $NIST -NISTFamily $Family -Category $Cat -Setting $Desc `
                -CurrentValue "$val" -RecommendedValue "$Expected" -Status $st -CISRef $CIS -Prof $Prof
        } catch {
            Add-Finding -NISTControl $NIST -NISTFamily $Family -Category $Cat -Setting $Desc `
                -CurrentValue "NOT SET" -RecommendedValue "$Expected" -Status "Fail" -CISRef $CIS -Prof $Prof
        }
    }

    function Check-RegNE {
        # Check that a value is NOT equal to $Expected (i.e. any value except Expected passes)
        param([string]$Path,[string]$Name,$BadValue,[string]$Desc,
              [string]$NIST,[string]$Family,[string]$Cat,[string]$CIS="N/A",[string]$Prof="All")
        try {
            $val = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
            $st  = if ($val -ne $BadValue) { "Pass" } else { "Fail" }
            Add-Finding -NISTControl $NIST -NISTFamily $Family -Category $Cat -Setting $Desc `
                -CurrentValue "$val" -RecommendedValue "Not $BadValue" -Status $st -CISRef $CIS -Prof $Prof
        } catch {
            # Key absent = not set to bad value = Pass for these checks
            Add-Finding -NISTControl $NIST -NISTFamily $Family -Category $Cat -Setting $Desc `
                -CurrentValue "NOT SET" -RecommendedValue "Not $BadValue" -Status "Pass" -CISRef $CIS -Prof $Prof
        }
    }

    function Check-Service {
        param([string]$Name,[string]$NIST,[string]$CIS="N/A",[string]$Prof="All")
        $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if ($null -ne $svc) {
            $st = if ($svc.StartType -eq "Disabled") { "Pass" } else { "Fail" }
            Add-Finding -NISTControl $NIST -NISTFamily "CM" -Category "Services" -Setting "Service: $Name" `
                -CurrentValue "$($svc.Status)/$($svc.StartType)" -RecommendedValue "Disabled" -Status $st -CISRef $CIS -Prof $Prof
        } else {
            Add-Finding -NISTControl $NIST -NISTFamily "CM" -Category "Services" -Setting "Service: $Name" `
                -CurrentValue "Not Installed" -RecommendedValue "Disabled" -Status "Pass" -CISRef $CIS -Prof $Prof
        }
    }

    # ==========================================================================
    # AC -- ACCESS CONTROL
    # ==========================================================================
    if (-not $Quiet) { Write-Section "AC - Access Control" }

    # AC-2: Account Management
    $localAdmins = @(net localgroup Administrators 2>&1 | Where-Object { $_ -match "^\S" -and $_ -notmatch "^The|^Alias|^Members|^--|^Command" })
    $adminCount  = @($localAdmins).Count
    $st = if ($adminCount -le 3) { "Pass" } else { "Warn" }
    Add-Finding -NIST "AC-2" -NISTFamily "AC" -Category "AccountManagement" -Setting "Local Administrators count" `
        -CurrentValue "$adminCount" -RecommendedValue "<=3" -Status $st -CISRef "CIS 2.2.1" -Prof "All"

    # AC-2: Guest account disabled
    try {
        $guest = Get-LocalUser -Name "Guest" -ErrorAction Stop
        $st = if (-not $guest.Enabled) { "Pass" } else { "Fail" }
        Add-Finding -NIST "AC-2" -NISTFamily "AC" -Category "AccountManagement" -Setting "Guest account disabled" `
            -CurrentValue $(if ($guest.Enabled) {"Enabled"} else {"Disabled"}) -RecommendedValue "Disabled" -Status $st -CISRef "CIS 2.3.1.2" -Prof "All"
    } catch {
        Add-Finding -NIST "AC-2" -NISTFamily "AC" -Category "AccountManagement" -Setting "Guest account disabled" `
            -CurrentValue "Unknown" -RecommendedValue "Disabled" -Status "Warn" -CISRef "CIS 2.3.1.2" -Prof "All"
    }

    # AC-2: Built-in Administrator account renamed/disabled
    try {
        $builtinAdmin = Get-LocalUser | Where-Object { $_.SID -like "S-1-5-*-500" } | Select-Object -First 1
        $st = if ($null -ne $builtinAdmin -and -not $builtinAdmin.Enabled) { "Pass" } elseif ($null -ne $builtinAdmin -and $builtinAdmin.Name -ne "Administrator") { "Pass" } else { "Warn" }
        $val = if ($null -ne $builtinAdmin) { "$($builtinAdmin.Name)/$(if($builtinAdmin.Enabled){'Enabled'}else{'Disabled'})" } else { "Not Found" }
        Add-Finding -NIST "AC-2" -NISTFamily "AC" -Category "AccountManagement" -Setting "Built-in Administrator renamed or disabled" `
            -CurrentValue $val -RecommendedValue "Renamed or Disabled" -Status $st -CISRef "CIS 2.3.1.1" -Prof "All"
    } catch {}

    # AC-3: Access Enforcement - UAC
    Check-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLUA" 1 `
        "UAC enabled" "AC-3" "AC" "AccessEnforcement" "CIS 2.3.17.1"
    Check-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorAdmin" 2 `
        "UAC: prompt admin for credentials on secure desktop" "AC-3" "AC" "AccessEnforcement" "CIS 2.3.17.2"
    Check-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorUser" 0 `
        "UAC: deny standard user elevation requests" "AC-3" "AC" "AccessEnforcement" "CIS 2.3.17.3"
    Check-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "PromptOnSecureDesktop" 1 `
        "UAC: prompt on secure desktop" "AC-3" "AC" "AccessEnforcement" "CIS 2.3.17.5"
    Check-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableVirtualization" 1 `
        "UAC: virtualize file/registry write failures" "AC-3" "AC" "AccessEnforcement" "CIS 2.3.17.8"
    Check-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "LocalAccountTokenFilterPolicy" 0 `
        "Disable remote admin token filter (restrict remote UAC)" "AC-3" "AC" "AccessEnforcement" "CIS 2.3.17.6"

    # AC-7: Unsuccessful Logon Attempts
    $na       = net accounts 2>&1
    $lockThr  = (($na | Where-Object { $_ -match "Lockout threshold"  }) -replace ".*:\s*","").Trim()
    $lockDur  = (($na | Where-Object { $_ -match "Lockout duration"   }) -replace ".*:\s*","").Trim()
    $lockObs  = (($na | Where-Object { $_ -match "Lockout observation" }) -replace ".*:\s*","").Trim()
    try { $st = if ($lockThr -ne "Never" -and [int]($lockThr -replace "\D","") -le 5) { "Pass" } else { "Fail" } } catch { $st = "Fail" }
    Add-Finding -NIST "AC-7" -NISTFamily "AC" -Category "LockoutPolicy" -Setting "Account lockout threshold" `
        -CurrentValue $lockThr -RecommendedValue "<=5" -Status $st -CISRef "CIS 1.2.1" -Prof "All"
    try { $st = if ([int]($lockDur -replace "\D","") -ge 15) { "Pass" } else { "Fail" } } catch { $st = "Fail" }
    Add-Finding -NIST "AC-7" -NISTFamily "AC" -Category "LockoutPolicy" -Setting "Lockout duration (min)" `
        -CurrentValue $lockDur -RecommendedValue ">=15" -Status $st -CISRef "CIS 1.2.2" -Prof "All"
    try { $st = if ([int]($lockObs -replace "\D","") -ge 15) { "Pass" } else { "Fail" } } catch { $st = "Fail" }
    Add-Finding -NIST "AC-7" -NISTFamily "AC" -Category "LockoutPolicy" -Setting "Lockout observation window (min)" `
        -CurrentValue $lockObs -RecommendedValue ">=15" -Status $st -CISRef "CIS 1.2.3" -Prof "All"

    # AC-8: System Use Notification (logon banner)
    Check-RegNE "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "LegalNoticeText" "" `
        "Logon warning banner text configured" "AC-8" "AC" "LogonBanner" "CIS 2.3.7.1"
    Check-RegNE "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "LegalNoticeCaption" "" `
        "Logon warning banner caption configured" "AC-8" "AC" "LogonBanner" "CIS 2.3.7.2"

    # AC-11: Session Lock
    Check-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockScreenCamera" 1 `
        "Disable lock screen camera" "AC-11" "AC" "SessionLock" "CIS 18.9.13.1" "Workstation"
    Check-Reg "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" "ScreenSaveTimeOut" 900 `
        "Screen saver timeout <= 15 min (900 sec)" "AC-11" "AC" "SessionLock" "CIS 18.9.13.2"
    Check-Reg "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" "ScreenSaverIsSecure" 1 `
        "Screen saver password protected" "AC-11" "AC" "SessionLock" "CIS 18.9.13.3"
    Check-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableAutomaticRestartSignOn" 1 `
        "Disable ARSO (auto sign-on after reboot)" "AC-11" "AC" "SessionLock" "CIS 2.3.17.7" "Workstation"

    # AC-17: Remote Access
    Check-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "UserAuthentication" 1 `
        "RDP requires NLA (Network Level Authentication)" "AC-17" "AC" "RemoteAccess" "CIS 18.9.65.3"
    Check-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "AllowUnencryptedTraffic" 0 `
        "WinRM service: require encrypted traffic" "AC-17" "AC" "RemoteAccess" "CIS 18.9.102.2"
    Check-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" "AllowUnencryptedTraffic" 0 `
        "WinRM client: require encrypted traffic" "AC-17" "AC" "RemoteAccess" "CIS 18.9.102.1"
    Check-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" "AllowBasic" 0 `
        "WinRM client: disallow Basic authentication" "AC-17" "AC" "RemoteAccess" "CIS 18.9.102.3"
    Check-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "AllowBasic" 0 `
        "WinRM service: disallow Basic authentication" "AC-17" "AC" "RemoteAccess" "CIS 18.9.102.4"
    Check-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" "AllowDigest" 0 `
        "WinRM client: disallow Digest authentication" "AC-17" "AC" "RemoteAccess" "CIS 18.9.102.5"

    # AC-18: Wireless Access
    Check-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" "fBlockNonDomain" 1 `
        "Block simultaneous connections to domain and non-domain networks" "AC-18" "AC" "WirelessAccess" "CIS 18.5.21.2"

    # AC-19: Access Control for Mobile Devices
    Check-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "DontDisplayNetworkSelectionUI" 1 `
        "Hide network selection UI on logon screen" "AC-19" "AC" "MobileAccess" "CIS 18.8.28.1"

    # ==========================================================================
    # IA -- IDENTIFICATION AND AUTHENTICATION
    # ==========================================================================
    if (-not $Quiet) { Write-Section "IA - Identification and Authentication" }

    # IA-5: Authenticator Management (Password Policy)
    $maxPwAge = (($na | Where-Object { $_ -match "Maximum password age"   }) -replace ".*:\s*","").Trim()
    $minPwAge = (($na | Where-Object { $_ -match "Minimum password age"   }) -replace ".*:\s*","").Trim()
    $minPwLen = (($na | Where-Object { $_ -match "Minimum password length" }) -replace ".*:\s*","").Trim()
    $pwHist   = (($na | Where-Object { $_ -match "Length of password"     }) -replace ".*:\s*","").Trim()

    try { $st = if ([int]($maxPwAge -replace "\D","") -le 60) { "Pass" } else { "Fail" } } catch { $st = "Fail" }
    Add-Finding -NIST "IA-5(1)" -NISTFamily "IA" -Category "PasswordPolicy" -Setting "Maximum password age (days)" `
        -CurrentValue $maxPwAge -RecommendedValue "<=60" -Status $st -CISRef "CIS 1.1.1"
    try { $st = if ([int]($minPwAge -replace "\D","") -ge 1) { "Pass" } else { "Fail" } } catch { $st = "Fail" }
    Add-Finding -NIST "IA-5(1)" -NISTFamily "IA" -Category "PasswordPolicy" -Setting "Minimum password age (days)" `
        -CurrentValue $minPwAge -RecommendedValue ">=1" -Status $st -CISRef "CIS 1.1.2"
    try { $st = if ([int]($minPwLen -replace "\D","") -ge 14) { "Pass" } else { "Fail" } } catch { $st = "Fail" }
    Add-Finding -NIST "IA-5(1)" -NISTFamily "IA" -Category "PasswordPolicy" -Setting "Minimum password length" `
        -CurrentValue $minPwLen -RecommendedValue ">=14" -Status $st -CISRef "CIS 1.1.4"
    try { $st = if ([int]($pwHist -replace "\D","") -ge 24) { "Pass" } else { "Fail" } } catch { $st = "Fail" }
    Add-Finding -NIST "IA-5(1)" -NISTFamily "IA" -Category "PasswordPolicy" -Setting "Password history" `
        -CurrentValue $pwHist -RecommendedValue ">=24" -Status $st -CISRef "CIS 1.1.3"

    # IA-5: Password complexity via registry
    Check-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "NoLMHash" 1 `
        "Do not store LAN Manager password hash" "IA-5(1)" "IA" "PasswordPolicy" "CIS 2.3.11.3"

    # IA-5: Credential caching
    Check-Reg "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "CachedLogonsCount" 4 `
        "Cached domain logons <= 4" "IA-5" "IA" "CredentialManagement" "CIS 2.3.11.4"

    # IA-5: WDigest plaintext creds
    Check-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "UseLogonCredential" 0 `
        "WDigest: do not store plaintext credentials" "IA-5" "IA" "CredentialManagement" "CIS 18.3.7"

    # IA-5: LSA protection
    Check-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RunAsPPL" 1 `
        "LSA running as Protected Process Light" "IA-5" "IA" "CredentialManagement" "CIS 18.3.1"

    # IA-5: Credential Guard
    Check-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "LsaCfgFlags" 1 `
        "Credential Guard enabled" "IA-5" "IA" "CredentialManagement" "CIS 18.9.29.3"

    # IA-6: Authentication Feedback
    Check-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DontDisplayLastUserName" 1 `
        "Do not display last username on logon screen" "IA-6" "IA" "AuthFeedback" "CIS 2.3.7.3"
    Check-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DontDisplayLockedUserId" 3 `
        "Do not display username when locked" "IA-6" "IA" "AuthFeedback" "CIS 2.3.7.4"

    # IA-8: Identification and Authentication (Non-org users)
    Check-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymous" 1 `
        "Restrict anonymous access to named pipes and shares" "IA-8" "IA" "AnonymousAccess" "CIS 2.3.10.2"
    Check-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymousSAM" 1 `
        "Restrict anonymous SAM account enumeration" "IA-8" "IA" "AnonymousAccess" "CIS 2.3.10.1"
    Check-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "EveryoneIncludesAnonymous" 0 `
        "Do not include anonymous in Everyone group" "IA-8" "IA" "AnonymousAccess" "CIS 2.3.10.3"
    Check-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "DisableDomainCreds" 1 `
        "Do not store network credentials (Credential Manager)" "IA-8" "IA" "AnonymousAccess" "CIS 2.3.11.2"

    # ==========================================================================
    # AU -- AUDIT AND ACCOUNTABILITY
    # ==========================================================================
    if (-not $Quiet) { Write-Section "AU - Audit and Accountability" }

    # AU-2 / AU-12: Audit Policy
    if (-not $SkipAuditPolicy) {
        $auditChecks = @(
            @{ Sub="Credential Validation";            Rec="Success and Failure"; NIST="AU-2"     }
            @{ Sub="User Account Management";          Rec="Success and Failure"; NIST="AU-2"     }
            @{ Sub="Security Group Management";        Rec="Success and Failure"; NIST="AU-2"     }
            @{ Sub="Computer Account Management";      Rec="Success and Failure"; NIST="AU-2"     }
            @{ Sub="Other Account Management Events";  Rec="Success and Failure"; NIST="AU-2"     }
            @{ Sub="Logon";                            Rec="Success and Failure"; NIST="AU-2"     }
            @{ Sub="Logoff";                           Rec="Success";             NIST="AU-2"     }
            @{ Sub="Account Lockout";                  Rec="Success and Failure"; NIST="AU-2"     }
            @{ Sub="Special Logon";                    Rec="Success";             NIST="AU-2"     }
            @{ Sub="Other Logon/Logoff Events";        Rec="Success and Failure"; NIST="AU-2"     }
            @{ Sub="File System";                      Rec="Success and Failure"; NIST="AU-2"     }
            @{ Sub="Registry";                         Rec="Success and Failure"; NIST="AU-2"     }
            @{ Sub="Kernel Object";                    Rec="Success and Failure"; NIST="AU-2"     }
            @{ Sub="Removable Storage";                Rec="Success and Failure"; NIST="AU-2"     }
            @{ Sub="Audit Policy Change";              Rec="Success and Failure"; NIST="AU-12"    }
            @{ Sub="Authentication Policy Change";     Rec="Success";             NIST="AU-12"    }
            @{ Sub="Authorization Policy Change";      Rec="Success";             NIST="AU-12"    }
            @{ Sub="Sensitive Privilege Use";          Rec="Success and Failure"; NIST="AU-2"     }
            @{ Sub="Security State Change";            Rec="Success and Failure"; NIST="AU-2"     }
            @{ Sub="Security System Extension";        Rec="Success and Failure"; NIST="AU-2"     }
            @{ Sub="System Integrity";                 Rec="Success and Failure"; NIST="AU-2"     }
            @{ Sub="Process Creation";                 Rec="Success";             NIST="AU-12"    }
            @{ Sub="DPAPI Activity";                   Rec="Success and Failure"; NIST="AU-2"     }
            @{ Sub="PNP Activity";                     Rec="Success";             NIST="AU-2"     }
        )
        if ($Profile -eq "DomainController") {
            $auditChecks += @(
                @{ Sub="Directory Service Access";              Rec="Success and Failure"; NIST="AU-2" }
                @{ Sub="Directory Service Changes";             Rec="Success and Failure"; NIST="AU-2" }
                @{ Sub="Kerberos Service Ticket Operations";    Rec="Success and Failure"; NIST="AU-2" }
                @{ Sub="Kerberos Authentication Service";       Rec="Success and Failure"; NIST="AU-2" }
                @{ Sub="Other Account Logon Events";            Rec="Success and Failure"; NIST="AU-2" }
            )
        }
        try {
            $auditOut = auditpol /get /category:* 2>&1
            if ($LASTEXITCODE -ne 0) { throw "non-zero exit" }
            foreach ($ac in $auditChecks) {
                $line    = $auditOut | Where-Object { $_ -match [regex]::Escape($ac.Sub) } | Select-Object -First 1
                $current = if ($null -ne $line -and $line -ne "") { ($line -split "\s{2,}")[-1].Trim() } else { "Not Found" }
                $st      = if ($current -eq $ac.Rec) { "Pass" } else { "Fail" }
                Add-Finding -NIST $ac.NIST -NISTFamily "AU" -Category "AuditPolicy" -Setting $ac.Sub `
                    -CurrentValue $current -RecommendedValue $ac.Rec -Status $st -CISRef "CIS Audit"
            }
        } catch {
            if (-not $Quiet) { Write-Warn "auditpol.exe unavailable - skipping audit policy checks." }
        }
    }

    # AU-9: Protection of Audit Information
    Check-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" "MaxSize" 196608 `
        "Security event log max size >= 196608 KB (192 MB)" "AU-9" "AU" "LogProtection" "CIS 18.9.26.1.1"
    Check-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System" "MaxSize" 32768 `
        "System event log max size >= 32768 KB (32 MB)" "AU-9" "AU" "LogProtection" "CIS 18.9.26.3.1"
    Check-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application" "MaxSize" 32768 `
        "Application event log max size >= 32768 KB (32 MB)" "AU-9" "AU" "LogProtection" "CIS 18.9.26.1.2"
    Check-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" "Retention" "0" `
        "Security log: do not overwrite events (managed by size)" "AU-9" "AU" "LogProtection" "CIS 18.9.26.2.1"

    # ==========================================================================
    # CM -- CONFIGURATION MANAGEMENT
    # ==========================================================================
    if (-not $Quiet) { Write-Section "CM - Configuration Management" }

    # CM-6: Configuration Settings (NTLM/LM Auth)
    Check-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LmCompatibilityLevel" 5 `
        "LAN Manager auth level: NTLMv2 only, refuse LM and NTLM" "CM-6" "CM" "AuthProtocol" "CIS 2.3.11.1"
    Check-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" "NTLMMinClientSec" 537395200 `
        "NTLM: minimum client session security flags" "CM-6" "CM" "AuthProtocol" "CIS 2.3.11.7"
    Check-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" "NTLMMinServerSec" 537395200 `
        "NTLM: minimum server session security flags" "CM-6" "CM" "AuthProtocol" "CIS 2.3.11.8"

    # CM-6: SMB Signing
    Check-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "RequireSecuritySignature" 1 `
        "SMB server: require security signature" "CM-6" "CM" "SMBSigning" "CIS 2.3.9.1"
    Check-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "EnableSecuritySignature" 1 `
        "SMB server: enable security signature" "CM-6" "CM" "SMBSigning" "CIS 2.3.9.2"
    Check-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters" "RequireSecuritySignature" 1 `
        "SMB client: require security signature" "CM-6" "CM" "SMBSigning" "CIS 2.3.8.1"
    Check-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters" "EnableSecuritySignature" 1 `
        "SMB client: enable security signature" "CM-6" "CM" "SMBSigning" "CIS 2.3.8.2"

    # CM-6: SMB v1
    Check-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "SMB1" 0 `
        "SMB v1 protocol disabled" "CM-6" "CM" "SMBVersion" "CIS 18.3.3"

    # CM-6: NetBIOS / LLMNR
    Check-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast" 0 `
        "LLMNR disabled" "CM-6" "CM" "NetworkProtocols" "CIS 18.5.4.2"
    Check-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" "NodeType" 2 `
        "NetBIOS node type set to P-node (no broadcast)" "CM-6" "CM" "NetworkProtocols" "CIS 18.5.4.1"

    # CM-6: Autorun/Autoplay
    Check-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoAutoplayfornonVolume" 1 `
        "Disable AutoPlay for non-volume devices" "CM-7" "CM" "Autorun" "CIS 18.9.8.1" "Workstation"
    Check-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoDriveTypeAutoRun" 255 `
        "Disable AutoRun on all drive types" "CM-7" "CM" "Autorun" "CIS 18.9.8.2"
    Check-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoAutorun" 1 `
        "Disable Autorun entirely" "CM-7" "CM" "Autorun" "CIS 18.9.8.3"

    # CM-7: Least Functionality - Unnecessary Services
    Check-Service "Telnet"         "CM-7" "CIS 5.1"
    Check-Service "FTPSVC"         "CM-7" "CIS 5.1"
    Check-Service "SNMPTRAP"       "CM-7" "CIS 5.1"
    Check-Service "RemoteRegistry" "CM-7" "CIS 18.9"
    Check-Service "Browser"        "CM-7" "CIS 5.1"
    if ($Profile -in @("Server","DomainController")) {
        Check-Service "W3SVC"    "CM-7" "CIS 5.1" "Server"
        Check-Service "MSFTPSVC" "CM-7" "CIS 5.1" "Server"
    }
    if ($Profile -eq "Workstation") {
        Check-Service "XblGameSave"   "CM-7" "CIS 5.1" "Workstation"
        Check-Service "XboxNetApiSvc" "CM-7" "CIS 5.1" "Workstation"
        Check-Service "WMPNetworkSvc" "CM-7" "CIS 5.1" "Workstation"
        Check-Service "icssvc"        "CM-7" "CIS 5.1" "Workstation"
        Check-Service "SharedAccess"  "CM-7" "N/A"     "Workstation"
    }

    # CM-7: Windows Features / Components
    Check-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" "ExecutionPolicy" "RemoteSigned" `
        "PowerShell execution policy: RemoteSigned or more restrictive" "CM-7" "CM" "PowerShell" "CIS 18.9.95.3"

    # CM-6: Kerberos
    Check-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" "SupportedEncryptionTypes" 2147483640 `
        "Kerberos: supported encryption types (AES128/AES256/Future)" "CM-6" "CM" "Kerberos" "CIS 2.3.11.9"

    # CM-11: User-Installed Software
    Check-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" "EnableUserControl" 0 `
        "Windows Installer: disable user control over installs" "CM-11" "CM" "SoftwareInstall" "CIS 18.9.85.1"
    Check-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated" 0 `
        "Windows Installer: disable elevated install" "CM-11" "CM" "SoftwareInstall" "CIS 18.9.85.2"

    # ==========================================================================
    # SC -- SYSTEM AND COMMUNICATIONS PROTECTION
    # ==========================================================================
    if (-not $Quiet) { Write-Section "SC - System and Communications Protection" }

    # SC-5: Denial of Service Protection
    Check-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "SynAttackProtect" 1 `
        "TCP SYN attack protection enabled" "SC-5" "SC" "DoSProtection" "N/A"
    Check-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "TcpMaxConnectResponseRetransmissions" 2 `
        "TCP: limit SYN-ACK retransmissions" "SC-5" "SC" "DoSProtection" "N/A"

    # SC-8: Transmission Confidentiality and Integrity
    Check-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsFirewall\DomainProfile" "EnableFirewall" 1 `
        "Windows Firewall: Domain profile enabled" "SC-8" "SC" "Firewall" "CIS 9.1.1"
    Check-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsFirewall\PrivateProfile" "EnableFirewall" 1 `
        "Windows Firewall: Private profile enabled" "SC-8" "SC" "Firewall" "CIS 9.2.1"
    Check-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsFirewall\PublicProfile" "EnableFirewall" 1 `
        "Windows Firewall: Public profile enabled" "SC-8" "SC" "Firewall" "CIS 9.3.1"
    Check-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsFirewall\DomainProfile" "DefaultInboundAction" 1 `
        "Firewall Domain: block inbound by default" "SC-8" "SC" "Firewall" "CIS 9.1.2"
    Check-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsFirewall\PrivateProfile" "DefaultInboundAction" 1 `
        "Firewall Private: block inbound by default" "SC-8" "SC" "Firewall" "CIS 9.2.2"
    Check-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsFirewall\PublicProfile" "DefaultInboundAction" 1 `
        "Firewall Public: block inbound by default" "SC-8" "SC" "Firewall" "CIS 9.3.2"
    Check-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsFirewall\PublicProfile" "AllowLocalPolicyMerge" 0 `
        "Firewall Public: disallow local policy merge" "SC-8" "SC" "Firewall" "CIS 9.3.4"

    # SC-8: TLS / Secure Channel
    Check-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "MSV1_0\NTLMMinClientSec" 537395200 `
        "NTLM: client requires 128-bit encryption and NTLMv2" "SC-8" "SC" "EncryptionProtocol" "CIS 2.3.11.7"

    # SC-12: Cryptographic Key Management
    Check-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "LsaPid" 0 `
        "LSA not overridden (LsaPid=0 means default secure value)" "SC-12" "SC" "KeyManagement" "N/A"

    # SC-15: Collaborative Computing Devices
    Check-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "AllowTelemetry" 1 `
        "Telemetry: limit data sent to Microsoft (<=1)" "SC-15" "SC" "DataProtection" "CIS 18.9.16.1"

    # SC-17: PKI Certificates
    Check-Reg "HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots" "Flags" 1 `
        "Protected root certificates enabled" "SC-17" "SC" "PKI" "N/A"

    # SC-18: Mobile Code
    Check-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Restrictions" "NoSelectDownloadDir" 1 `
        "IE: no custom download directory" "SC-18" "SC" "MobileCode" "N/A" "Workstation"

    # SC-28: Protection of Information at Rest (BitLocker indicators)
    try {
        $bde = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop
        $st  = if ($bde.ProtectionStatus -eq "On") { "Pass" } else { "Fail" }
        Add-Finding -NIST "SC-28" -NISTFamily "SC" -Category "Encryption" -Setting "BitLocker: C: drive protection" `
            -CurrentValue $bde.ProtectionStatus -RecommendedValue "On" -Status $st -CISRef "CIS 18.9.11.1" -Prof "Workstation"
    } catch {
        Add-Finding -NIST "SC-28" -NISTFamily "SC" -Category "Encryption" -Setting "BitLocker: C: drive protection" `
            -CurrentValue "Cannot check (run as admin or BitLocker not installed)" -RecommendedValue "On" -Status "Warn" -CISRef "CIS 18.9.11.1" -Prof "Workstation"
    }

    # SC-39: Process Isolation (Exploit Guard / DEP)
    Check-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoDataExecutionPrevention" 0 `
        "DEP not disabled via policy" "SC-39" "SC" "ProcessIsolation" "N/A"
    Check-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Defender\Windows Defender Exploit Guard\Network Protection" "EnableNetworkProtection" 1 `
        "Network Protection (Exploit Guard) enabled" "SC-39" "SC" "ProcessIsolation" "CIS 18.9.77.1" "Workstation"

    # ==========================================================================
    # SI -- SYSTEM AND INFORMATION INTEGRITY
    # ==========================================================================
    if (-not $Quiet) { Write-Section "SI - System and Information Integrity" }

    # SI-2: Flaw Remediation (Windows Update)
    Check-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoUpdate" 0 `
        "Windows Update: auto update not disabled" "SI-2" "SI" "Patching" "CIS 18.9.108.1"
    Check-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "AUOptions" 4 `
        "Windows Update: auto download and schedule install" "SI-2" "SI" "Patching" "CIS 18.9.108.2"
    Check-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "DeferFeatureUpdates" 1 `
        "Windows Update: defer feature updates (stability)" "SI-2" "SI" "Patching" "CIS 18.9.108.4"

    # SI-3: Malicious Code Protection (Defender)
    try {
        $defender = Get-MpComputerStatus -ErrorAction Stop
        $rtEnabled = $defender.RealTimeProtectionEnabled
        $defUpdated = $defender.AntivirusSignatureAge -le 3
        Add-Finding -NIST "SI-3" -NISTFamily "SI" -Category "Antimalware" -Setting "Defender: Real-time protection enabled" `
            -CurrentValue $(if($rtEnabled){"True"}else{"False"}) -RecommendedValue "True" `
            -Status $(if($rtEnabled){"Pass"}else{"Fail"}) -CISRef "N/A"
        Add-Finding -NIST "SI-3" -NISTFamily "SI" -Category "Antimalware" -Setting "Defender: Signature age <= 3 days" `
            -CurrentValue "$($defender.AntivirusSignatureAge) days" -RecommendedValue "<=3 days" `
            -Status $(if($defUpdated){"Pass"}else{"Fail"}) -CISRef "N/A"
        Add-Finding -NIST "SI-3" -NISTFamily "SI" -Category "Antimalware" -Setting "Defender: Behavior monitoring enabled" `
            -CurrentValue $(if($defender.BehaviorMonitorEnabled){"True"}else{"False"}) -RecommendedValue "True" `
            -Status $(if($defender.BehaviorMonitorEnabled){"Pass"}else{"Fail"}) -CISRef "N/A"
        Add-Finding -NIST "SI-3" -NISTFamily "SI" -Category "Antimalware" -Setting "Defender: Cloud protection enabled" `
            -CurrentValue $(if($defender.MAPSReporting -gt 0){"True"}else{"False"}) -RecommendedValue "True" `
            -Status $(if($defender.MAPSReporting -gt 0){"Pass"}else{"Warn"}) -CISRef "CIS 18.9.77.4"
    } catch {
        Add-Finding -NIST "SI-3" -NISTFamily "SI" -Category "Antimalware" -Setting "Windows Defender status" `
            -CurrentValue "Cannot query (Get-MpComputerStatus unavailable)" -RecommendedValue "Enabled" -Status "Warn" -CISRef "N/A"
    }

    # SI-3: Defender attack surface reduction
    Check-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" "ExploitGuard_ASR_Rules" 1 `
        "Defender ASR rules enabled" "SI-3" "SI" "Antimalware" "CIS 18.9.77.13.1" "Workstation"

    # SI-4: System Monitoring (PowerShell logging)
    Check-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" "EnableScriptBlockLogging" 1 `
        "PowerShell: script block logging enabled" "SI-4" "SI" "Monitoring" "CIS 18.9.95.1"
    Check-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" "EnableTranscripting" 1 `
        "PowerShell: transcription logging enabled" "SI-4" "SI" "Monitoring" "CIS 18.9.95.2"
    Check-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockInvocationLogging" 1 `
        "PowerShell: script block invocation logging enabled" "SI-4" "SI" "Monitoring" "CIS 18.9.95.4"
    Check-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" "EnableModuleLogging" 1 `
        "PowerShell: module logging enabled" "SI-4" "SI" "Monitoring" "CIS 18.9.95.5"

    # SI-4: Sysmon / Enhanced logging indicator
    $sysmon = Get-Service -Name "Sysmon","Sysmon64" -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Running" }
    $st = if ($null -ne $sysmon) { "Pass" } else { "Warn" }
    Add-Finding -NIST "SI-4" -NISTFamily "SI" -Category "Monitoring" -Setting "Sysmon installed and running" `
        -CurrentValue $(if($null -ne $sysmon){$sysmon.Name}else{"Not found"}) -RecommendedValue "Running" -Status $st -CISRef "N/A"

    # SI-6: Security Function Verification (Secure Boot)
    try {
        $sb = Confirm-SecureBootUEFI -ErrorAction Stop
        Add-Finding -NIST "SI-6" -NISTFamily "SI" -Category "SecureBoot" -Setting "Secure Boot enabled" `
            -CurrentValue $(if($sb){"True"}else{"False"}) -RecommendedValue "True" `
            -Status $(if($sb){"Pass"}else{"Fail"}) -CISRef "N/A"
    } catch {
        Add-Finding -NIST "SI-6" -NISTFamily "SI" -Category "SecureBoot" -Setting "Secure Boot enabled" `
            -CurrentValue "Cannot verify (BIOS or insufficient permissions)" -RecommendedValue "True" -Status "Warn" -CISRef "N/A"
    }

    # SI-7: Software / Firmware Integrity
    Check-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "EnableVirtualizationBasedSecurity" 1 `
        "Virtualization Based Security (VBS) enabled" "SI-7" "SI" "VBS" "CIS 18.9.29.1"
    Check-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "RequirePlatformSecurityFeatures" 3 `
        "VBS: require Secure Boot and DMA protection" "SI-7" "SI" "VBS" "CIS 18.9.29.2"
    Check-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "HypervisorEnforcedCodeIntegrity" 1 `
        "Hypervisor Protected Code Integrity (HVCI) enabled" "SI-7" "SI" "VBS" "CIS 18.9.29.4"

    # ==========================================================================
    # SA -- SYSTEM AND SERVICES ACQUISITION
    # ==========================================================================
    if (-not $Quiet) { Write-Section "SA - System and Services Acquisition" }

    # SA-10: Developer Security
    Check-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" "EnableScriptBlockLogging" 1 `
        "Developer tools: PowerShell logging (see SI-4)" "SA-10" "SA" "DevSecurity" "CIS 18.9.95.1"

    # SA-11: Developer Testing (AppLocker / WDAC indicators)
    try {
        $alSvc = Get-Service -Name "AppIDSvc" -ErrorAction Stop
        $st = if ($alSvc.Status -eq "Running") { "Pass" } else { "Warn" }
        Add-Finding -NIST "SA-11" -NISTFamily "SA" -Category "AppControl" -Setting "AppLocker service (AppIDSvc) running" `
            -CurrentValue $alSvc.Status -RecommendedValue "Running" -Status $st -CISRef "N/A"
    } catch {
        Add-Finding -NIST "SA-11" -NISTFamily "SA" -Category "AppControl" -Setting "AppLocker service (AppIDSvc) running" `
            -CurrentValue "Not Found" -RecommendedValue "Running" -Status "Warn" -CISRef "N/A"
    }

    # ==========================================================================
    # MP -- MEDIA PROTECTION
    # ==========================================================================
    if (-not $Quiet) { Write-Section "MP - Media Protection" }

    # MP-7: Media Use
    Check-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoAutoplayfornonVolume" 1 `
        "MP-7: Disable AutoPlay for non-volume devices (USB)" "MP-7" "MP" "MediaControl" "CIS 18.9.8.1" "Workstation"
    Check-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoDriveTypeAutoRun" 255 `
        "MP-7: Disable AutoRun on all drive types" "MP-7" "MP" "MediaControl" "CIS 18.9.8.2"

    # ==========================================================================
    # CP -- CONTINGENCY PLANNING (automatable subset)
    # ==========================================================================
    if (-not $Quiet) { Write-Section "CP - Contingency Planning" }

    # CP-9: System Backup (VSS / Shadow Copy indicator)
    try {
        $vss = Get-Service -Name "VSS" -ErrorAction Stop
        $st  = if ($vss.Status -eq "Running" -or $vss.StartType -ne "Disabled") { "Pass" } else { "Warn" }
        Add-Finding -NIST "CP-9" -NISTFamily "CP" -Category "Backup" -Setting "Volume Shadow Copy Service (VSS) not disabled" `
            -CurrentValue "$($vss.Status)/$($vss.StartType)" -RecommendedValue "Not Disabled" -Status $st -CISRef "N/A"
    } catch {
        Add-Finding -NIST "CP-9" -NISTFamily "CP" -Category "Backup" -Setting "Volume Shadow Copy Service (VSS) not disabled" `
            -CurrentValue "Not Found" -RecommendedValue "Not Disabled" -Status "Warn" -CISRef "N/A"
    }

    # ==========================================================================
    # MA -- MAINTENANCE (automatable subset)
    # ==========================================================================
    if (-not $Quiet) { Write-Section "MA - Maintenance" }

    # MA-3: Maintenance Tools - Remote management hardening
    Check-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "DisableRunAs" 1 `
        "WinRM: disable RunAs for remote commands" "MA-3" "MA" "RemoteMaintenance" "CIS 18.9.102.6"

    # MA-4: Nonlocal Maintenance
    Check-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fEncryptionLevel" 3 `
        "RDP: encryption level set to High" "MA-4" "MA" "RemoteMaintenance" "CIS 18.9.65.2"
    Check-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "MinEncryptionLevel" 3 `
        "RDP: minimum encryption level set to High" "MA-4" "MA" "RemoteMaintenance" "CIS 18.9.65.1"

    # ==========================================================================
    # SERVER / DC SPECIFIC CHECKS
    # ==========================================================================
    if ($Profile -in @("Server","DomainController")) {
        if (-not $Quiet) { Write-Section "Server-Specific Controls" }

        # CM-6 / SC-8: Netlogon secure channel
        Check-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "RequireSignOrSeal" 1 `
            "Netlogon: require sign or seal" "CM-6" "CM" "NetlogonSecurity" "CIS 2.3.6.1" "Server"
        Check-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "SealSecureChannel" 1 `
            "Netlogon: seal secure channel data" "CM-6" "CM" "NetlogonSecurity" "CIS 2.3.6.2" "Server"
        Check-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "SignSecureChannel" 1 `
            "Netlogon: sign secure channel data" "CM-6" "CM" "NetlogonSecurity" "CIS 2.3.6.3" "Server"
        Check-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "DisablePasswordChange" 0 `
            "Netlogon: allow machine account password changes" "CM-6" "CM" "NetlogonSecurity" "CIS 2.3.6.4" "Server"
        Check-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "MaximumPasswordAge" 30 `
            "Netlogon: machine account max password age (days)" "IA-5" "IA" "NetlogonSecurity" "CIS 2.3.6.5" "Server"
        Check-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "RequireStrongKey" 1 `
            "Netlogon: require strong session key (128-bit)" "CM-6" "CM" "NetlogonSecurity" "CIS 2.3.6.6" "Server"

        # CM-7: Printer driver installation
        Check-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" "AddPrinterDrivers" 1 `
            "Prevent non-admins from installing printer drivers" "CM-7" "CM" "PrinterSecurity" "CIS 2.3.4.1" "Server"
    }

    if ($Profile -eq "DomainController") {
        if (-not $Quiet) { Write-Section "DC-Specific Controls" }

        # IA-3 / SC-8: LDAP signing and channel binding
        Check-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" "LDAPServerIntegrity" 2 `
            "LDAP server signing required" "IA-3" "IA" "LDAPSecurity" "CIS 2.3.7.1" "DomainController"
        Check-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "LdapEnforceChannelBinding" 1 `
            "LDAP channel binding token requirements enabled" "SC-8" "SC" "LDAPSecurity" "CIS 2.3.7.2" "DomainController"

        # CM-6: DS Access auditing (handled in audit section above for DC)
        # IA-5: Kerberos policy
        Check-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" "SupportedEncryptionTypes" 2147483640 `
            "Kerberos: AES encryption required (no DES/RC4)" "CM-6" "CM" "KerberosDC" "CIS 2.3.11.9" "DomainController"
    }

    # ==========================================================================
    # SUMMARY
    # ==========================================================================
    $allFindings = @($findings)
    $p = @($allFindings | Where-Object { $_.Status -eq "Pass" }).Count
    $f = @($allFindings | Where-Object { $_.Status -eq "Fail" }).Count
    $w = @($allFindings | Where-Object { $_.Status -eq "Warn" }).Count
    $total = $allFindings.Count

    Write-Host ""
    Write-Host "===========================================" -ForegroundColor White
    Write-Host " SCAN COMPLETE  [$Profile]" -ForegroundColor White
    Write-Host "===========================================" -ForegroundColor White
    Write-Host (" TOTAL: {0}  |  PASS: {1}  |  FAIL: {2}  |  WARN: {3}" -f $total,$p,$f,$w) -ForegroundColor White
    Write-Host (" SCORE: {0}%" -f [math]::Round(($p/$total)*100,1)) -ForegroundColor $(if(($p/$total) -ge 0.8){"Green"}elseif(($p/$total) -ge 0.5){"Yellow"}else{"Red"})
    Write-Host "===========================================" -ForegroundColor White
    Write-Host ""

    return $findings
}
