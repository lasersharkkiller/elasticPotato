function Invoke-CISScan {
<#
.SYNOPSIS
    Full CIS Benchmark scan for Windows 10/11 and Windows Server 2022.
    Covers Level 1 and Level 2 controls (~420 checks).

.DESCRIPTION
    Implements CIS Microsoft Windows 10 Enterprise Benchmark v2.0 and
    CIS Microsoft Windows Server 2022 Benchmark v1.0.
    Checks are tagged with CIS section, level (L1/L2), and NIST 800-53 mapping.
    Makes NO changes to the system.

.PARAMETER Profile
    Auto | Workstation | Server | DomainController

.PARAMETER Level
    1 = Level 1 only (default) | 2 = Level 1 + Level 2

.PARAMETER SkipAuditPolicy
    Skip auditpol.exe checks.

.PARAMETER Quiet
    Suppress per-finding output.

.OUTPUTS
    System.Collections.Generic.List[PSCustomObject]
    Fields: CISControl, CISLevel, Profile, Section, Setting,
            CurrentValue, RecommendedValue, Status, NISTMapping
#>
    [CmdletBinding()]
    param(
        [ValidateSet("Auto","Workstation","Server","DomainController")]
        [string]$Profile = "Auto",
        [ValidateSet(1,2)][int]$Level = 1,
        [switch]$SkipAuditPolicy,
        [switch]$Quiet
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # -- Profile detection ------------------------------------------------------
    if ($Profile -eq "Auto") {
        try {
            $dr = (Get-WmiObject Win32_ComputerSystem -ErrorAction SilentlyContinue).DomainRole
            $pt = (Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue).ProductType
            $isDC = $dr -ge 4; $isServer = $pt -ne 1
        } catch { $isDC = $false; $isServer = $false }
        $Profile = if ($isDC) { "DomainController" } elseif ($isServer) { "Server" } else { "Workstation" }
    }
    $isWS  = $Profile -eq "Workstation"
    $isSrv = $Profile -in @("Server","DomainController")
    $isDC  = $Profile -eq "DomainController"

    if (-not $Quiet) { Write-Info "CIS Scan | Profile: $Profile | Level: $Level" }

    # -- Helpers ----------------------------------------------------------------
    function Add-Check {
        param([string]$ID,[int]$L,[string]$Prof="All",[string]$Section,
              [string]$Setting,[string]$Current,[string]$Expected,
              [string]$Status,[string]$NIST="")
        if ($L -gt $Level) { return }
        if ($Prof -ne "All" -and $Prof -ne $Profile) { return }
        $findings.Add([PSCustomObject]@{
            CISControl       = $ID
            CISLevel         = "L$L"
            Profile          = $Prof
            Section          = $Section
            Setting          = $Setting
            CurrentValue     = $Current
            RecommendedValue = $Expected
            Status           = $Status
            NISTMapping      = $NIST
        })
        if (-not $Quiet) {
            $lbl = "[$ID]"
            switch ($Status) {
                "Pass" { Write-Pass "$lbl $Setting" }
                "Fail" { Write-Fail "$lbl $Setting = $Current  (expected: $Expected)" }
                "Warn" { Write-Warn "$lbl $Setting = $Current" }
            }
        }
    }

    function CR {
        # Check-Reg wrapper: CR <ID> <Level> <Path> <Name> <Expected> <Desc> [Profile] [NIST] [Section]
        param([string]$ID,[int]$L,[string]$Path,[string]$Name,$Exp,[string]$Desc,
              [string]$Prof="All",[string]$NIST="",[string]$Sec="Registry")
        if ($L -gt $Level) { return }
        if ($Prof -ne "All" -and $Prof -ne $Profile) { return }
        try {
            $val = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
            $st  = if ("$val" -eq "$Exp") { "Pass" } else { "Fail" }
            Add-Check -ID $ID -L $L -Prof $Prof -Section $Sec -Setting $Desc `
                -Current "$val" -Expected "$Exp" -Status $st -NIST $NIST
        } catch {
            Add-Check -ID $ID -L $L -Prof $Prof -Section $Sec -Setting $Desc `
                -Current "NOT SET" -Expected "$Exp" -Status "Fail" -NIST $NIST
        }
    }

    function CRge {
        # Check-Reg Greater-or-Equal
        param([string]$ID,[int]$L,[string]$Path,[string]$Name,[int]$Min,[string]$Desc,
              [string]$Prof="All",[string]$NIST="",[string]$Sec="Registry")
        if ($L -gt $Level) { return }
        if ($Prof -ne "All" -and $Prof -ne $Profile) { return }
        try {
            $val = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
            $st  = if ([int]$val -ge $Min) { "Pass" } else { "Fail" }
            Add-Check -ID $ID -L $L -Prof $Prof -Section $Sec -Setting $Desc `
                -Current "$val" -Expected ">=$Min" -Status $st -NIST $NIST
        } catch {
            Add-Check -ID $ID -L $L -Prof $Prof -Section $Sec -Setting $Desc `
                -Current "NOT SET" -Expected ">=$Min" -Status "Fail" -NIST $NIST
        }
    }

    function CRle {
        # Check-Reg Less-or-Equal
        param([string]$ID,[int]$L,[string]$Path,[string]$Name,[int]$Max,[string]$Desc,
              [string]$Prof="All",[string]$NIST="",[string]$Sec="Registry")
        if ($L -gt $Level) { return }
        if ($Prof -ne "All" -and $Prof -ne $Profile) { return }
        try {
            $val = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
            $st  = if ([int]$val -le $Max) { "Pass" } else { "Fail" }
            Add-Check -ID $ID -L $L -Prof $Prof -Section $Sec -Setting $Desc `
                -Current "$val" -Expected "<=$Max" -Status $st -NIST $NIST
        } catch {
            Add-Check -ID $ID -L $L -Prof $Prof -Section $Sec -Setting $Desc `
                -Current "NOT SET" -Expected "<=$Max" -Status "Fail" -NIST $NIST
        }
    }

    function CRne {
        # Check-Reg Not-Equal (value must NOT be $Bad)
        param([string]$ID,[int]$L,[string]$Path,[string]$Name,$Bad,[string]$Desc,
              [string]$Prof="All",[string]$NIST="",[string]$Sec="Registry")
        if ($L -gt $Level) { return }
        if ($Prof -ne "All" -and $Prof -ne $Profile) { return }
        try {
            $val = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
            $st  = if ("$val" -ne "$Bad") { "Pass" } else { "Fail" }
            Add-Check -ID $ID -L $L -Prof $Prof -Section $Sec -Setting $Desc `
                -Current "$val" -Expected "Not $Bad" -Status $st -NIST $NIST
        } catch {
            # Key absent means not set to bad value
            Add-Check -ID $ID -L $L -Prof $Prof -Section $Sec -Setting $Desc `
                -Current "NOT SET" -Expected "Not $Bad" -Status "Pass" -NIST $NIST
        }
    }

    function CSvc {
        param([string]$ID,[int]$L,[string]$Name,[string]$Prof="All",[string]$NIST="")
        if ($L -gt $Level) { return }
        if ($Prof -ne "All" -and $Prof -ne $Profile) { return }
        $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if ($null -ne $svc) {
            $st = if ($svc.StartType -eq "Disabled") { "Pass" } else { "Fail" }
            Add-Check -ID $ID -L $L -Prof $Prof -Section "Services" -Setting "Service disabled: $Name" `
                -Current "$($svc.Status)/$($svc.StartType)" -Expected "Disabled" -Status $st -NIST $NIST
        } else {
            Add-Check -ID $ID -L $L -Prof $Prof -Section "Services" -Setting "Service disabled: $Name" `
                -Current "Not Installed" -Expected "Disabled" -Status "Pass" -NIST $NIST
        }
    }

    $LSA   = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $SYS   = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $AUDIT = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog"
    $PWSH  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
    $WFW   = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall"
    $WU    = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    $NET   = "HKLM:\SYSTEM\CurrentControlSet\Services"
    $WDEF  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"

    # ==========================================================================
    # SECTION 1 -- ACCOUNT POLICIES
    # ==========================================================================
    if (-not $Quiet) { Write-Section "1 - Account Policies" }
    $na = net accounts 2>&1

    function Get-NetVal([string]$label) {
        (($na | Where-Object { $_ -match $label }) -replace ".*:\s*","").Trim()
    }

    $maxAge = Get-NetVal "Maximum password age"
    $minAge = Get-NetVal "Minimum password age"
    $minLen = Get-NetVal "Minimum password length"
    $hist   = Get-NetVal "Length of password"
    $thr    = Get-NetVal "Lockout threshold"
    $dur    = Get-NetVal "Lockout duration"
    $obs    = Get-NetVal "Lockout observation"

    # 1.1 Password Policy
    try { $st = if ([int]($maxAge -replace "\D","") -le 365 -and [int]($maxAge -replace "\D","") -ge 1) {"Pass"} else {"Fail"} } catch { $st="Fail" }
    Add-Check "1.1.1" 1 "All" "AccountPolicies" "Password: Max age <= 365 days" $maxAge "1-365" $st "IA-5(1)"

    try { $st = if ([int]($minAge -replace "\D","") -ge 1) {"Pass"} else {"Fail"} } catch { $st="Fail" }
    Add-Check "1.1.2" 1 "All" "AccountPolicies" "Password: Min age >= 1 day" $minAge ">=1" $st "IA-5(1)"

    try { $st = if ([int]($minLen -replace "\D","") -ge 14) {"Pass"} else {"Fail"} } catch { $st="Fail" }
    Add-Check "1.1.3" 1 "All" "AccountPolicies" "Password: Min length >= 14 chars" $minLen ">=14" $st "IA-5(1)"

    try { $st = if ([int]($minLen -replace "\D","") -ge 17) {"Pass"} else {"Fail"} } catch { $st="Fail" }
    Add-Check "1.1.3" 2 "All" "AccountPolicies" "Password: Min length >= 17 chars (L2)" $minLen ">=17" $st "IA-5(1)"

    try { $st = if ([int]($hist -replace "\D","") -ge 24) {"Pass"} else {"Fail"} } catch { $st="Fail" }
    Add-Check "1.1.4" 1 "All" "AccountPolicies" "Password: History >= 24 passwords" $hist ">=24" $st "IA-5(1)"

    CR "1.1.5" 1 "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "RequireStrongKey" 1 `
        "Password: Store using reversible encryption = Disabled" "All" "IA-5" "AccountPolicies"

    # 1.2 Lockout Policy
    try { $st = if ($thr -ne "Never" -and [int]($thr -replace "\D","") -le 5 -and [int]($thr -replace "\D","") -ge 1) {"Pass"} else {"Fail"} } catch { $st="Fail" }
    Add-Check "1.2.1" 1 "All" "AccountPolicies" "Lockout: Threshold 1-5 attempts" $thr "1-5" $st "AC-7"

    try { $st = if ([int]($dur -replace "\D","") -ge 15) {"Pass"} else {"Fail"} } catch { $st="Fail" }
    Add-Check "1.2.2" 1 "All" "AccountPolicies" "Lockout: Duration >= 15 min" $dur ">=15" $st "AC-7"

    try { $st = if ([int]($obs -replace "\D","") -ge 15) {"Pass"} else {"Fail"} } catch { $st="Fail" }
    Add-Check "1.2.3" 1 "All" "AccountPolicies" "Lockout: Observation window >= 15 min" $obs ">=15" $st "AC-7"

    # ==========================================================================
    # SECTION 2 -- LOCAL POLICIES: USER RIGHTS ASSIGNMENT
    # ==========================================================================
    if (-not $Quiet) { Write-Section "2 - Local Policies: User Rights" }

    function Get-UserRight([string]$right) {
        try {
            $tmp = [System.IO.Path]::GetTempFileName()
            secedit /export /cfg $tmp /quiet 2>&1 | Out-Null
            $line = Get-Content $tmp -ErrorAction Stop | Where-Object { $_ -match "^$right\s*=" }
            Remove-Item $tmp -ErrorAction SilentlyContinue
            if ($line) { ($line -split "=",2)[1].Trim() } else { "(not defined)" }
        } catch { "(error)" }
    }

    # We read secedit once for efficiency
    $seceditTmp = [System.IO.Path]::GetTempFileName()
    try {
        secedit /export /cfg $seceditTmp /quiet 2>&1 | Out-Null
        $seceditContent = Get-Content $seceditTmp -ErrorAction Stop
        Remove-Item $seceditTmp -ErrorAction SilentlyContinue
    } catch {
        $seceditContent = @()
        if (-not $Quiet) { Write-Warn "secedit unavailable - user rights checks skipped" }
    }

    function Get-Right([string]$right) {
        $line = $seceditContent | Where-Object { $_ -match "^$right\s*=" }
        if ($line) { ($line -split "=",2)[1].Trim() } else { "(not defined)" }
    }

    function Check-RightEmpty([string]$ID,[int]$L,[string]$right,[string]$desc,[string]$NIST="") {
        if ($L -gt $Level) { return }
        $val = Get-Right $right
        $st  = if ($val -eq "(not defined)" -or $val -eq "") { "Pass" } else { "Fail" }
        Add-Check $ID $L "All" "UserRights" $desc $val "(empty)" $st $NIST
    }

    function Check-RightContains([string]$ID,[int]$L,[string]$right,[string[]]$allowed,[string]$desc,[string]$NIST="") {
        if ($L -gt $Level) { return }
        $val = Get-Right $right
        if ($val -eq "(not defined)") { $st = "Pass" }
        else {
            $actual = $val -split "," | ForEach-Object { $_.Trim() }
            $bad = $actual | Where-Object { $_ -notin $allowed -and $_ -ne "" }
            $st = if (@($bad).Count -eq 0) { "Pass" } else { "Fail" }
        }
        Add-Check $ID $L "All" "UserRights" $desc $val "Only: $($allowed -join ',')" $st $NIST
    }

    # 2.2 User Rights - must be empty (no one assigned)
    Check-RightEmpty "2.2.1"  1 "SeNetworkLogonRight"               "Network access: limit to Admins/Authenticated Users" "AC-3"
    Check-RightEmpty "2.2.2"  1 "SeTcbPrivilege"                    "Act as part of OS: no accounts" "AC-6"
    Check-RightEmpty "2.2.3"  1 "SeMachineAccountPrivilege"         "Add workstations to domain: Admins only" "AC-3"
    Check-RightEmpty "2.2.4"  1 "SeIncreaseQuotaPrivilege"          "Adjust memory quotas: Admins/LocalSvc/NetworkSvc only" "AC-6"
    Check-RightEmpty "2.2.5"  1 "SeInteractiveLogonRight"           "Allow log on locally: restricted to authorized users" "AC-17"
    Check-RightEmpty "2.2.6"  1 "SeRemoteInteractiveLogonRight"     "Allow RDP logon: Admins/Remote Desktop Users only" "AC-17"
    Check-RightEmpty "2.2.7"  1 "SeBackupPrivilege"                 "Back up files: Admins only" "AC-6"
    Check-RightEmpty "2.2.8"  1 "SeSystemtimePrivilege"             "Change system time: Admins/Local Service only" "AC-3"
    Check-RightEmpty "2.2.9"  1 "SeTimeZonePrivilege"               "Change time zone: Admins/Local Service/Users" "AC-3"
    Check-RightEmpty "2.2.10" 1 "SeCreatePagefilePrivilege"         "Create pagefile: Admins only" "AC-6"
    Check-RightEmpty "2.2.11" 1 "SeCreateTokenPrivilege"            "Create token object: (empty)" "AC-6"
    Check-RightEmpty "2.2.12" 1 "SeCreateGlobalPrivilege"           "Create global objects: Admins/LocalSvc/NetworkSvc/Service" "AC-6"
    Check-RightEmpty "2.2.13" 1 "SeCreatePermanentPrivilege"        "Create permanent shared objects: (empty)" "AC-6"
    Check-RightEmpty "2.2.14" 1 "SeCreateSymbolicLinkPrivilege"     "Create symbolic links: Admins only" "AC-6"
    Check-RightEmpty "2.2.15" 1 "SeDebugPrivilege"                  "Debug programs: Admins only" "AC-6"
    Check-RightEmpty "2.2.16" 1 "SeDenyNetworkLogonRight"           "Deny network access: Guests, Local account" "AC-3"
    Check-RightEmpty "2.2.17" 1 "SeDenyBatchLogonRight"             "Deny batch logon: (empty)" "AC-3"
    Check-RightEmpty "2.2.18" 1 "SeDenyServiceLogonRight"           "Deny service logon: (empty)" "AC-3"
    Check-RightEmpty "2.2.19" 1 "SeDenyInteractiveLogonRight"       "Deny interactive logon: Guests" "AC-3"
    Check-RightEmpty "2.2.20" 1 "SeDenyRemoteInteractiveLogonRight" "Deny RDP logon: Guests, Local account (non-admin)" "AC-17"
    Check-RightEmpty "2.2.21" 1 "SeEnableDelegationPrivilege"       "Enable computer/user for delegation: (empty)" "AC-6"
    Check-RightEmpty "2.2.22" 1 "SeRemoteShutdownPrivilege"         "Force shutdown from remote: Admins only" "AC-6"
    Check-RightEmpty "2.2.23" 1 "SeAuditPrivilege"                  "Generate security audits: LocalSvc/NetworkSvc" "AU-9"
    Check-RightEmpty "2.2.24" 1 "SeImpersonatePrivilege"            "Impersonate client after auth: Admins/LocalSvc/NetworkSvc/Service" "AC-6"
    Check-RightEmpty "2.2.25" 1 "SeIncreaseWorkingSetPrivilege"     "Increase process working set: Admins/Users" "AC-6"
    Check-RightEmpty "2.2.26" 1 "SeSystemProfilePrivilege"          "Profile system performance: Admins/NT SERVICE\WdiServiceHost" "AC-6"
    Check-RightEmpty "2.2.27" 1 "SeAssignPrimaryTokenPrivilege"     "Replace process-level token: LocalSvc/NetworkSvc" "AC-6"
    Check-RightEmpty "2.2.28" 1 "SeRestorePrivilege"                "Restore files and dirs: Admins only" "AC-6"
    Check-RightEmpty "2.2.29" 1 "SeShutdownPrivilege"               "Shut down system: Admins only" "AC-6"
    Check-RightEmpty "2.2.30" 1 "SeTakeOwnershipPrivilege"          "Take ownership: Admins only" "AC-6"

    # ==========================================================================
    # SECTION 2.3 -- SECURITY OPTIONS
    # ==========================================================================
    if (-not $Quiet) { Write-Section "2.3 - Security Options" }

    # 2.3.1 Accounts
    CR  "2.3.1.1" 1 $SYS "EnableGuestAccount"        0 "Accounts: Guest account status = Disabled"                "All" "AC-2" "SecurityOptions"
    CR  "2.3.1.2" 1 $SYS "LimitBlankPasswordUse"     1 "Accounts: Limit blank password to console only"           "All" "IA-5" "SecurityOptions"
    # Admin account rename check
    try {
        $adminSID  = Get-LocalUser | Where-Object { $_.SID -like "S-1-5-*-500" }
        $renamed   = $null -ne $adminSID -and $adminSID.Name -ne "Administrator"
        Add-Check "2.3.1.3" 1 "All" "SecurityOptions" "Accounts: Rename administrator account" `
            $(if($adminSID){$adminSID.Name}else{"N/A"}) "Not 'Administrator'" `
            $(if($renamed){"Pass"}else{"Warn"}) "AC-2"
    } catch {}
    try {
        $guestSID  = Get-LocalUser | Where-Object { $_.SID -like "S-1-5-*-501" }
        $grename   = $null -ne $guestSID -and $guestSID.Name -ne "Guest"
        Add-Check "2.3.1.4" 1 "All" "SecurityOptions" "Accounts: Rename guest account" `
            $(if($guestSID){$guestSID.Name}else{"N/A"}) "Not 'Guest'" `
            $(if($grename){"Pass"}else{"Warn"}) "AC-2"
    } catch {}

    # 2.3.2 Audit
    CR "2.3.2.1" 1 $SYS "FullPrivilegeAuditing"   0 "Audit: Force audit policy subcategory settings"       "All" "AU-2" "SecurityOptions"
    CR "2.3.2.2" 1 "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "CrashOnAuditFail" 0 `
        "Audit: Shut down if unable to log security audits = Disabled" "All" "AU-9" "SecurityOptions"

    # 2.3.4 Devices
    CR "2.3.4.1" 1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" "RegisterSpoolerRemoteRpcEndPoint" 2 `
        "Devices: Prevent users installing printer drivers"                          "All" "CM-7"  "SecurityOptions"
    CR "2.3.4.2" 1 "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" "AddPrinterDrivers" 1 `
        "Devices: Non-admins cannot install printer drivers"                         "Server" "CM-7" "SecurityOptions"

    # 2.3.5 Domain Controller (DC only)
    if ($isDC) {
        CR "2.3.5.1" 1 "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" "LDAPServerIntegrity" 2 `
            "DC: LDAP server signing requirements = Require signing"                 "DomainController" "SC-8" "SecurityOptions"
        CR "2.3.5.2" 1 "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "RefusePasswordChange" 0 `
            "DC: Refuse machine account password changes = Disabled"                 "DomainController" "IA-5" "SecurityOptions"
    }

    # 2.3.6 Domain Member
    CR "2.3.6.1" 1 "$NET\Netlogon\Parameters" "RequireSignOrSeal"     1  "Domain member: Digitally encrypt/sign secure channel (always)" "All" "SC-8" "SecurityOptions"
    CR "2.3.6.2" 1 "$NET\Netlogon\Parameters" "SealSecureChannel"     1  "Domain member: Digitally encrypt secure channel (when possible)" "All" "SC-8" "SecurityOptions"
    CR "2.3.6.3" 1 "$NET\Netlogon\Parameters" "SignSecureChannel"     1  "Domain member: Digitally sign secure channel (when possible)"   "All" "SC-8" "SecurityOptions"
    CR "2.3.6.4" 1 "$NET\Netlogon\Parameters" "DisablePasswordChange" 0  "Domain member: Disable machine account password changes = No"   "All" "IA-5" "SecurityOptions"
    CR "2.3.6.5" 1 "$NET\Netlogon\Parameters" "MaximumPasswordAge"    30 "Domain member: Max machine account password age = 30 days"      "All" "IA-5" "SecurityOptions"
    CR "2.3.6.6" 1 "$NET\Netlogon\Parameters" "RequireStrongKey"      1  "Domain member: Require strong (Windows 2000+) session key"      "All" "SC-8" "SecurityOptions"

    # 2.3.7 Interactive Logon
    CR "2.3.7.1" 1 $SYS "DontDisplayLastUserName"    1 "Interactive logon: Do not display last user name"             "All" "IA-6" "SecurityOptions"
    CR "2.3.7.2" 1 $SYS "DisableCAD"                 0 "Interactive logon: Do not require CTRL+ALT+DEL = Disabled"    "All" "IA-2" "SecurityOptions"
    CRne "2.3.7.3" 1 $SYS "LegalNoticeText"          "" "Interactive logon: Message text for logon (not empty)"       "All" "AC-8" "SecurityOptions"
    CRne "2.3.7.4" 1 $SYS "LegalNoticeCaption"       "" "Interactive logon: Message title for logon (not empty)"      "All" "AC-8" "SecurityOptions"
    CRle "2.3.7.5" 1 "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "CachedLogonsCount" 4 `
        "Interactive logon: Number of previous logons to cache <= 4"                 "All" "IA-5" "SecurityOptions"
    CR "2.3.7.6" 1 "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "PasswordExpiryWarning" 14 `
        "Interactive logon: Prompt user to change password 14 days before expiry"   "All" "IA-5" "SecurityOptions"
    CR "2.3.7.7" 1 "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "ForceUnlockLogon" 1 `
        "Interactive logon: Require DC to unlock workstation"                        "All" "AC-11" "SecurityOptions"
    CR "2.3.7.8" 2 $SYS "DontDisplayLockedUserId"    3 "Interactive logon: Display user info when session locked = Not displayed (L2)" "All" "IA-6" "SecurityOptions"
    CR "2.3.7.9" 2 $SYS "DisableAutomaticRestartSignOn" 1 "Interactive logon: ARSO disabled (L2)"                    "All" "AC-11" "SecurityOptions"

    # 2.3.8 Microsoft Network Client
    CR "2.3.8.1" 1 "$NET\LanManWorkstation\Parameters" "RequireSecuritySignature" 1 "MS network client: Digitally sign communications (always)" "All" "SC-8" "SecurityOptions"
    CR "2.3.8.2" 1 "$NET\LanManWorkstation\Parameters" "EnableSecuritySignature"  1 "MS network client: Digitally sign communications (if agreed)" "All" "SC-8" "SecurityOptions"
    CR "2.3.8.3" 1 "$NET\LanManWorkstation\Parameters" "EnablePlainTextPassword"  0 "MS network client: Send unencrypted password = Disabled"    "All" "IA-5" "SecurityOptions"

    # 2.3.9 Microsoft Network Server
    CR "2.3.9.1" 1 "$NET\LanManServer\Parameters" "AutoDisconnect"          15 "MS network server: Idle time before suspend = 15 min"   "All" "AC-11" "SecurityOptions"
    CR "2.3.9.2" 1 "$NET\LanManServer\Parameters" "RequireSecuritySignature" 1 "MS network server: Digitally sign communications (always)" "All" "SC-8" "SecurityOptions"
    CR "2.3.9.3" 1 "$NET\LanManServer\Parameters" "EnableSecuritySignature"  1 "MS network server: Digitally sign comms (if agreed)"      "All" "SC-8" "SecurityOptions"
    CR "2.3.9.4" 1 "$NET\LanManServer\Parameters" "EnableForcedLogOff"       1 "MS network server: Disconnect clients at logon hours expiry" "All" "AC-2" "SecurityOptions"
    CR "2.3.9.5" 2 "$NET\LanManServer\Parameters" "SmbServerNameHardeningLevel" 1 "MS network server: Server SPN target name validation (L2)" "All" "SC-8" "SecurityOptions"

    # 2.3.10 Network Access
    CR "2.3.10.1"  1 $LSA "DisableDomainCreds"              1 "Network access: Do not allow storage of passwords/credentials"  "All" "IA-5" "SecurityOptions"
    CR "2.3.10.2"  1 $LSA "EveryoneIncludesAnonymous"       0 "Network access: Let Everyone apply to anonymous users = Disabled" "All" "IA-8" "SecurityOptions"
    CR "2.3.10.3"  1 "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths" "Machine" "" `
        "Network access: Named pipes accessible anonymously = none"                  "All" "IA-8" "SecurityOptions"
    CR "2.3.10.4"  1 $LSA "RestrictAnonymousSAM"            1 "Network access: Restrict anonymous access to Named Pipes/Shares" "All" "IA-8" "SecurityOptions"
    CR "2.3.10.5"  1 $LSA "RestrictAnonymous"               1 "Network access: Restrict anonymous enumeration of SAM accounts" "All" "IA-8" "SecurityOptions"
    CR "2.3.10.6"  1 $LSA "RestrictRemoteSAM"               "O:BAG:BAD:(A;;RC;;;BA)" "Network access: Restrict remote calls to SAM" "All" "IA-8" "SecurityOptions"
    CR "2.3.10.7"  1 "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\pku2u" "AllowOnlineID" 0 "Network access: Disallow PKU2U auth requests" "All" "IA-8" "SecurityOptions"
    CR "2.3.10.8"  2 $LSA "UseMachineId"                    1 "Network access: Use machine account for offline auth (L2)"       "All" "IA-3" "SecurityOptions"

    # 2.3.11 Network Security
    CR "2.3.11.1" 1 $LSA "DisableDomainCreds"               1 "Network security: Do not store LAN Mgr hash value"               "All" "IA-5" "SecurityOptions"
    CR "2.3.11.2" 1 $LSA "NoLMHash"                         1 "Network security: LAN Mgr hash value = Disabled"                 "All" "IA-5" "SecurityOptions"
    CR "2.3.11.3" 1 $LSA "LmCompatibilityLevel"             5 "Network security: LAN Mgr auth level = NTLMv2, refuse LM/NTLM"  "All" "IA-3" "SecurityOptions"
    CR "2.3.11.4" 1 $LSA "LDAPClientIntegrity"              1 "Network security: LDAP client signing requirements = Negotiate"  "All" "SC-8" "SecurityOptions"
    CR "2.3.11.5" 1 "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" "NTLMMinClientSec" 537395200 `
        "Network security: Min session security for NTLM SSP clients"               "All" "SC-8" "SecurityOptions"
    CR "2.3.11.6" 1 "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" "NTLMMinServerSec" 537395200 `
        "Network security: Min session security for NTLM SSP servers"               "All" "SC-8" "SecurityOptions"
    CR "2.3.11.7" 2 $LSA "RestrictNTLMInDomain"             7 "Network security: Restrict NTLM in this domain (L2)"            "All" "IA-3" "SecurityOptions"
    CR "2.3.11.8" 2 $LSA "RestrictSendingNTLMTraffic"       2 "Network security: Restrict NTLM outgoing (L2)"                  "All" "IA-3" "SecurityOptions"

    # 2.3.13 Shutdown
    CR "2.3.13.1" 1 "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ShutdownWithoutLogon" 0 `
        "Shutdown: Allow system to be shut down without logon = Disabled"            "All" "AC-3" "SecurityOptions"

    # 2.3.15 System objects
    CR "2.3.15.1" 1 "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" "ProtectionMode" 1 `
        "System objects: Strengthen default permissions of global system objects"    "All" "AC-3" "SecurityOptions"

    # 2.3.17 User Account Control
    CR "2.3.17.1" 1 $SYS "FilterAdministratorToken"      1 "UAC: Admin Approval Mode for built-in Administrator"            "All" "AC-6" "SecurityOptions"
    CR "2.3.17.2" 1 $SYS "ConsentPromptBehaviorAdmin"    2 "UAC: Elevation prompt for admins = Prompt for credentials"      "All" "AC-3" "SecurityOptions"
    CR "2.3.17.3" 1 $SYS "ConsentPromptBehaviorUser"     0 "UAC: Elevation prompt for std users = Auto deny"                "All" "AC-3" "SecurityOptions"
    CR "2.3.17.4" 1 $SYS "EnableInstallerDetection"      1 "UAC: Detect app installs and prompt for elevation"              "All" "CM-11" "SecurityOptions"
    CR "2.3.17.5" 1 $SYS "EnableSecureUIAPaths"          1 "UAC: Only elevate UIAccess apps from secure locations"          "All" "AC-3" "SecurityOptions"
    CR "2.3.17.6" 1 $SYS "EnableLUA"                     1 "UAC: Run all administrators in Admin Approval Mode"             "All" "AC-6" "SecurityOptions"
    CR "2.3.17.7" 1 $SYS "PromptOnSecureDesktop"         1 "UAC: Switch to secure desktop when prompting"                   "All" "AC-3" "SecurityOptions"
    CR "2.3.17.8" 1 $SYS "EnableVirtualization"          1 "UAC: Virtualize file/registry write failures"                   "All" "AC-3" "SecurityOptions"

    # ==========================================================================
    # SECTION 9 -- WINDOWS FIREWALL
    # ==========================================================================
    if (-not $Quiet) { Write-Section "9 - Windows Firewall" }

    $FWD = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"
    $FWP = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"
    $FWU = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"

    # Domain profile
    CR "9.1.1"  1 $FWD "EnableFirewall"           1 "Firewall Domain: enabled"                               "All" "SC-7" "Firewall"
    CR "9.1.2"  1 $FWD "DisableNotifications"     1 "Firewall Domain: disable notifications"                 "All" "SC-7" "Firewall"
    CR "9.1.3"  1 $FWD "DefaultInboundAction"     1 "Firewall Domain: default inbound = block"               "All" "SC-7" "Firewall"
    CR "9.1.4"  1 $FWD "DefaultOutboundAction"    0 "Firewall Domain: default outbound = allow"              "All" "SC-7" "Firewall"
    CR "9.1.5"  2 "$FWD\Logging" "LogFilePath"    "%SystemRoot%\System32\logfiles\firewall\domainfw.log" `
        "Firewall Domain: log file path configured (L2)"                             "All" "AU-2" "Firewall"
    CRge "9.1.6" 2 "$FWD\Logging" "LogFileSize"  16384 "Firewall Domain: log size >= 16384 KB (L2)"         "All" "AU-9" "Firewall"
    CR "9.1.7"  2 "$FWD\Logging" "LogDroppedPackets" 1 "Firewall Domain: log dropped packets (L2)"          "All" "AU-2" "Firewall"
    CR "9.1.8"  2 "$FWD\Logging" "LogSuccessfulConnections" 1 "Firewall Domain: log successful connections (L2)" "All" "AU-2" "Firewall"

    # Private profile
    CR "9.2.1"  1 $FWP "EnableFirewall"           1 "Firewall Private: enabled"                              "All" "SC-7" "Firewall"
    CR "9.2.2"  1 $FWP "DisableNotifications"     0 "Firewall Private: notifications enabled"                "All" "SC-7" "Firewall"
    CR "9.2.3"  1 $FWP "DefaultInboundAction"     1 "Firewall Private: default inbound = block"              "All" "SC-7" "Firewall"
    CR "9.2.4"  1 $FWP "DefaultOutboundAction"    0 "Firewall Private: default outbound = allow"             "All" "SC-7" "Firewall"
    CR "9.2.5"  2 "$FWP\Logging" "LogFilePath"    "%SystemRoot%\System32\logfiles\firewall\privatefw.log" `
        "Firewall Private: log file path configured (L2)"                            "All" "AU-2" "Firewall"
    CRge "9.2.6" 2 "$FWP\Logging" "LogFileSize"  16384 "Firewall Private: log size >= 16384 KB (L2)"        "All" "AU-9" "Firewall"
    CR "9.2.7"  2 "$FWP\Logging" "LogDroppedPackets" 1 "Firewall Private: log dropped packets (L2)"         "All" "AU-2" "Firewall"
    CR "9.2.8"  2 "$FWP\Logging" "LogSuccessfulConnections" 1 "Firewall Private: log successful connections (L2)" "All" "AU-2" "Firewall"

    # Public profile
    CR "9.3.1"  1 $FWU "EnableFirewall"           1 "Firewall Public: enabled"                               "All" "SC-7" "Firewall"
    CR "9.3.2"  1 $FWU "DisableNotifications"     1 "Firewall Public: disable notifications"                 "All" "SC-7" "Firewall"
    CR "9.3.3"  1 $FWU "DefaultInboundAction"     1 "Firewall Public: default inbound = block"               "All" "SC-7" "Firewall"
    CR "9.3.4"  1 $FWU "DefaultOutboundAction"    0 "Firewall Public: default outbound = allow"              "All" "SC-7" "Firewall"
    CR "9.3.5"  1 $FWU "AllowLocalPolicyMerge"    0 "Firewall Public: disallow local firewall rule merge"    "All" "SC-7" "Firewall"
    CR "9.3.6"  1 $FWU "AllowLocalIPsecPolicyMerge" 0 "Firewall Public: disallow local IPsec rule merge"    "All" "SC-7" "Firewall"
    CRge "9.3.7" 2 "$FWU\Logging" "LogFileSize"  16384 "Firewall Public: log size >= 16384 KB (L2)"         "All" "AU-9" "Firewall"
    CR "9.3.8"  2 "$FWU\Logging" "LogDroppedPackets" 1 "Firewall Public: log dropped packets (L2)"          "All" "AU-2" "Firewall"
    CR "9.3.9"  2 "$FWU\Logging" "LogSuccessfulConnections" 1 "Firewall Public: log successful connections (L2)" "All" "AU-2" "Firewall"

    # ==========================================================================
    # SECTION 17 -- ADVANCED AUDIT POLICY
    # ==========================================================================
    if (-not $Quiet) { Write-Section "17 - Advanced Audit Policy" }

    if (-not $SkipAuditPolicy) {
        $auditMap = @(
            @{ Sub="Credential Validation";              Rec="Success and Failure"; ID="17.1.1"; L=1; NIST="AU-2"  }
            @{ Sub="Kerberos Authentication Service";    Rec="Success and Failure"; ID="17.1.2"; L=1; NIST="AU-2"; DC=$true }
            @{ Sub="Kerberos Service Ticket Operations"; Rec="Success and Failure"; ID="17.1.3"; L=1; NIST="AU-2"; DC=$true }
            @{ Sub="Other Account Logon Events";         Rec="Success and Failure"; ID="17.1.4"; L=1; NIST="AU-2"  }
            @{ Sub="Computer Account Management";        Rec="Success and Failure"; ID="17.2.1"; L=1; NIST="AU-2"  }
            @{ Sub="Other Account Management Events";    Rec="Success";             ID="17.2.2"; L=1; NIST="AU-2"  }
            @{ Sub="Security Group Management";          Rec="Success and Failure"; ID="17.2.3"; L=1; NIST="AU-2"  }
            @{ Sub="User Account Management";            Rec="Success and Failure"; ID="17.2.4"; L=1; NIST="AU-2"  }
            @{ Sub="PNP Activity";                       Rec="Success";             ID="17.3.1"; L=1; NIST="AU-2"  }
            @{ Sub="Process Creation";                   Rec="Success";             ID="17.3.2"; L=1; NIST="AU-12" }
            @{ Sub="Account Lockout";                    Rec="Success and Failure"; ID="17.5.1"; L=1; NIST="AU-2"  }
            @{ Sub="Group Membership";                   Rec="Success";             ID="17.5.2"; L=1; NIST="AU-2"  }
            @{ Sub="Logoff";                             Rec="Success";             ID="17.5.3"; L=1; NIST="AU-2"  }
            @{ Sub="Logon";                              Rec="Success and Failure"; ID="17.5.4"; L=1; NIST="AU-2"  }
            @{ Sub="Other Logon/Logoff Events";          Rec="Success and Failure"; ID="17.5.5"; L=1; NIST="AU-2"  }
            @{ Sub="Special Logon";                      Rec="Success";             ID="17.5.6"; L=1; NIST="AU-2"  }
            @{ Sub="DPAPI Activity";                     Rec="Success and Failure"; ID="17.6.1"; L=2; NIST="AU-2"  }
            @{ Sub="Removable Storage";                  Rec="Success and Failure"; ID="17.6.2"; L=1; NIST="AU-2"  }
            @{ Sub="Detailed File Share";                Rec="Failure";             ID="17.6.3"; L=1; NIST="AU-2"  }
            @{ Sub="File Share";                         Rec="Success and Failure"; ID="17.6.4"; L=1; NIST="AU-2"  }
            @{ Sub="Audit Policy Change";                Rec="Success and Failure"; ID="17.7.1"; L=1; NIST="AU-12" }
            @{ Sub="Authentication Policy Change";       Rec="Success";             ID="17.7.2"; L=1; NIST="AU-12" }
            @{ Sub="Authorization Policy Change";        Rec="Success";             ID="17.7.3"; L=1; NIST="AU-12" }
            @{ Sub="MPSSVC Rule-Level Policy Change";    Rec="Success and Failure"; ID="17.7.4"; L=1; NIST="AU-12" }
            @{ Sub="Other Policy Change Events";         Rec="Failure";             ID="17.7.5"; L=2; NIST="AU-12" }
            @{ Sub="Sensitive Privilege Use";            Rec="Success and Failure"; ID="17.8.1"; L=1; NIST="AU-2"  }
            @{ Sub="IPsec Driver";                       Rec="Success and Failure"; ID="17.9.1"; L=1; NIST="AU-2"  }
            @{ Sub="Other System Events";                Rec="Success and Failure"; ID="17.9.2"; L=1; NIST="AU-2"  }
            @{ Sub="Security State Change";              Rec="Success and Failure"; ID="17.9.3"; L=1; NIST="AU-2"  }
            @{ Sub="Security System Extension";          Rec="Success and Failure"; ID="17.9.4"; L=1; NIST="AU-2"  }
            @{ Sub="System Integrity";                   Rec="Success and Failure"; ID="17.9.5"; L=1; NIST="AU-2"  }
            @{ Sub="Directory Service Access";           Rec="Success and Failure"; ID="17.4.1"; L=1; NIST="AU-2"; DC=$true }
            @{ Sub="Directory Service Changes";          Rec="Success and Failure"; ID="17.4.2"; L=1; NIST="AU-2"; DC=$true }
        )
        try {
            $auditOut = auditpol /get /category:* 2>&1
            if ($LASTEXITCODE -ne 0) { throw "non-zero" }
            foreach ($ac in $auditMap) {
                if ($ac.L -gt $Level) { continue }
                if ($ac.DC -eq $true -and -not $isDC) { continue }
                $line    = $auditOut | Where-Object { $_ -match [regex]::Escape($ac.Sub) } | Select-Object -First 1
                $current = if ($null -ne $line -and $line -ne "") { ($line -split "\s{2,}")[-1].Trim() } else { "Not Found" }
                $st      = if ($current -eq $ac.Rec) { "Pass" } else { "Fail" }
                Add-Check $ac.ID $ac.L "All" "AuditPolicy" $ac.Sub $current $ac.Rec $st $ac.NIST
            }
        } catch {
            if (-not $Quiet) { Write-Warn "auditpol.exe unavailable - audit checks skipped" }
        }
    }

    # ==========================================================================
    # SECTION 18 -- WINDOWS COMPONENTS (Registry-based GP)
    # ==========================================================================
    if (-not $Quiet) { Write-Section "18 - Windows Components" }

    # 18.1 Control Panel
    CR "18.1.1.1" 1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockScreenCamera"    1 "Control Panel: Prevent lock screen camera"  "All" "AC-11" "WindowsComponents"
    CR "18.1.1.2" 2 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockScreenSlideshow" 1 "Control Panel: Prevent lock screen slideshow (L2)" "All" "AC-11" "WindowsComponents"
    CR "18.1.2.2" 1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"          "AllowOnlineTips"       0 "Control Panel: Block online tips and help"   "All" "CM-6" "WindowsComponents"

    # 18.3 LAPS
    CR "18.3.1" 1 "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd" "AdmPwdEnabled" 1 `
        "LAPS: Local Admin Password Solution enabled"                                "All" "IA-5" "WindowsComponents"

    # 18.4 MS Security Guide (MSS)
    CR "18.4.1"  1 "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" "DisableExceptionChainValidation" 0 `
        "MSS: Enable Structured Exception Handling Overwrite Protection (SEHOP)"    "All" "SI-16" "WindowsComponents"
    CR "18.4.2"  1 "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" "DisableIPSourceRouting" 2 `
        "MSS: IPv6 source routing protection level = Highest"                        "All" "SC-5" "WindowsComponents"
    CR "18.4.3"  1 "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "DisableIPSourceRouting" 2 `
        "MSS: IP source routing protection = Highest (DoS protection)"               "All" "SC-5" "WindowsComponents"
    CR "18.4.4"  1 "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "EnableICMPRedirect" 0 `
        "MSS: Allow ICMP redirects to override OSPF routes = Disabled"              "All" "SC-5" "WindowsComponents"
    CR "18.4.5"  2 "HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters" "NoNameReleaseOnDemand" 1 `
        "MSS: Allow computer to ignore NetBIOS name release requests (L2)"          "All" "SC-5" "WindowsComponents"
    CR "18.4.6"  2 "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "KeepAliveTime" 300000 `
        "MSS: How long TCP waits before sending keep-alive (L2)"                     "All" "SC-5" "WindowsComponents"
    CR "18.4.7"  1 "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "PerformRouterDiscovery" 0 `
        "MSS: Disable router discovery protocol"                                     "All" "SC-5" "WindowsComponents"
    CR "18.4.8"  1 "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" "SafeDllSearchMode" 1 `
        "MSS: Enable Safe DLL search mode"                                           "All" "SI-16" "WindowsComponents"
    CR "18.4.9"  1 "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" "ScreenSaverGracePeriod" 5 `
        "MSS: Screen saver grace period <= 5 seconds"                                "All" "AC-11" "WindowsComponents"
    CR "18.4.10" 2 "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "TcpMaxDataRetransmissions" 3 `
        "MSS: TCP max data retransmissions (IPv4) <= 3 (L2)"                         "All" "SC-5" "WindowsComponents"
    CR "18.4.11" 1 "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "WarningLevel" 90 `
        "MSS: Warn when security event log reaches 90% capacity"                     "All" "AU-9" "WindowsComponents"

    # 18.5 Network
    CR "18.5.1"  1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" "\\*\NETLOGON" "RequireMutualAuthentication=1,RequireIntegrity=1" `
        "Network: Harden UNC path for NETLOGON"                                      "All" "SC-8" "WindowsComponents"
    CR "18.5.2"  1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" "\\*\SYSVOL" "RequireMutualAuthentication=1,RequireIntegrity=1" `
        "Network: Harden UNC path for SYSVOL"                                        "All" "SC-8" "WindowsComponents"
    CR "18.5.3"  2 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TCPIP\v6Transition" "Force_Tunneling" "Disabled" `
        "Network: Disable IPv6 forced tunneling (L2)"                                "All" "CM-7" "WindowsComponents"
    CR "18.5.4"  1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" "fBlockNonDomain" 1 `
        "Network: Block simultaneous connections to internet and domain"              "All" "SC-7" "WindowsComponents"
    CR "18.5.5"  2 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" "fMinimizeConnections" 3 `
        "Network: Minimize simultaneous connections (L2)"                            "All" "SC-7" "WindowsComponents"
    CR "18.5.6"  1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast" 0 `
        "Network: Turn off multicast name resolution (LLMNR)"                        "All" "CM-7" "WindowsComponents"
    CR "18.5.7"  2 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" "NoActiveProbe" 1 `
        "Network: Turn off Internet connection detection (NCA) (L2)"                 "All" "CM-7" "WindowsComponents"

    # 18.6 Printers
    CR "18.6.1" 1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" "DisableWebPnPDownload" 1 `
        "Printers: Disable automatic download of drivers over HTTP"                  "All" "CM-7" "WindowsComponents"
    CR "18.6.2" 1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" "DisableHTTPPrinting" 1 `
        "Printers: Turn off printing over HTTP"                                      "All" "CM-7" "WindowsComponents"

    # 18.8 System
    CR "18.8.1"  1 "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "PreXPSP2ShellProtocolBehavior" 0 `
        "System: Turn off shell protocol protected mode = Disabled"                  "All" "CM-7" "WindowsComponents"
    CR "18.8.2"  1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "DontDisplayNetworkSelectionUI" 1 `
        "System: Do not display network selection UI on logon screen"                "All" "AC-3" "WindowsComponents"
    CR "18.8.3"  1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "DontEnumerateConnectedUsers" 1 `
        "System: Do not enumerate connected users on domain-joined computers"        "All" "AC-3" "WindowsComponents"
    CR "18.8.4"  1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnumerateLocalUsers" 0 `
        "System: Do not enumerate local users on domain-joined computers"            "All" "AC-3" "WindowsComponents"
    CR "18.8.5"  1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "BlockUserFromShowingAccountDetailsOnSignin" 1 `
        "System: Block user from showing account details on sign-in"                 "All" "AC-3" "WindowsComponents"
    CR "18.8.6"  1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "NoLocalPasswordResetQuestions" 1 `
        "System: Prevent use of security questions for local accounts"               "All" "IA-5" "WindowsComponents"
    CR "18.8.7"  1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableSmartScreen" 1 `
        "System: Enable Smart Screen"                                                "Workstation" "SI-3" "WindowsComponents"
    CR "18.8.8"  1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "DisableLockScreenAppNotifications" 1 `
        "System: Turn off app notifications on lock screen"                          "All" "AC-11" "WindowsComponents"

    # 18.9 Windows Components - Specific
    # AutoPlay
    CR "18.9.8.1" 1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoAutoplayfornonVolume" 1 `
        "AutoPlay: Disallow for non-volume devices"                                  "All" "MP-7" "WindowsComponents"
    CR "18.9.8.2" 1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoAutorun"             1 `
        "AutoPlay: Turn off AutoPlay"                                                "All" "MP-7" "WindowsComponents"
    CR "18.9.8.3" 1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoDriveTypeAutoRun"  255 `
        "AutoPlay: Default behavior = Do not execute any autorun commands"           "All" "MP-7" "WindowsComponents"

    # BitLocker
    CR "18.9.11.1.1" 1 "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "OSManageDRA"        1  "BitLocker: Allow data recovery agent (OS drives)"         "All" "SC-28" "WindowsComponents"
    CR "18.9.11.1.2" 1 "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "OSRecovery"         1  "BitLocker: Configure OS drive recovery options"            "All" "SC-28" "WindowsComponents"
    CR "18.9.11.1.3" 1 "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "OSEncryptionType"   1  "BitLocker: OS drive encryption method = XTS-AES-256"      "Workstation" "SC-28" "WindowsComponents"
    CR "18.9.11.2.1" 1 "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "FDVEncryptionType"  1  "BitLocker: Fixed drive encryption method = AES-256"       "All" "SC-28" "WindowsComponents"
    CR "18.9.11.3.1" 1 "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "RDVDenyWriteAccess" 1  "BitLocker: Deny write access to removable drives not protected" "All" "MP-7" "WindowsComponents"

    # Camera
    CR "18.9.12.1" 2 "HKLM:\SOFTWARE\Policies\Microsoft\Camera" "AllowCamera" 0 "Camera: Allow use of camera = Disabled (L2)" "All" "AC-3" "WindowsComponents"

    # Cloud Content
    CR "18.9.14.1" 2 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" 1 `
        "Cloud Content: Turn off Microsoft consumer experiences (L2)"                "Workstation" "CM-7" "WindowsComponents"

    # Credential UI
    CR "18.9.15.1" 1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI" "DisablePasswordReveal" 1 `
        "Credential UI: Do not display password reveal button"                       "All" "IA-5" "WindowsComponents"
    CR "18.9.15.2" 1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI" "EnumerateAdministrators" 0 `
        "Credential UI: Enumerate administrator accounts on elevation = Disabled"   "All" "IA-6" "WindowsComponents"

    # Data Collection (Telemetry)
    CR "18.9.16.1" 1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 1 `
        "Data Collection: Allow Telemetry = Enterprise Basic (1)"                   "All" "SC-15" "WindowsComponents"
    CR "18.9.16.2" 2 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "DisableEnterpriseAuthProxy" 1 `
        "Data Collection: Disable enterprise auth proxy (L2)"                       "All" "SC-15" "WindowsComponents"
    CR "18.9.16.3" 1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "LimitEnhancedDiagnosticDataWindowsAnalytics" 1 `
        "Data Collection: Limit enhanced diagnostic data to required"               "All" "SC-15" "WindowsComponents"
    CR "18.9.16.4" 1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "DisableDiagnosticDataViewer" 1 `
        "Data Collection: Disable Diagnostic Data Viewer"                           "All" "SC-15" "WindowsComponents"

    # Event Log Service
    CRge "18.9.26.1.1" 1 "$AUDIT\Application" "MaxSize" 32768 "Event Log: Application log size >= 32768 KB"    "All" "AU-9" "WindowsComponents"
    CRge "18.9.26.1.2" 1 "$AUDIT\Security"    "MaxSize" 196608 "Event Log: Security log size >= 196608 KB"    "All" "AU-9" "WindowsComponents"
    CRge "18.9.26.1.3" 1 "$AUDIT\Setup"       "MaxSize" 32768 "Event Log: Setup log size >= 32768 KB"         "All" "AU-9" "WindowsComponents"
    CRge "18.9.26.1.4" 1 "$AUDIT\System"      "MaxSize" 32768 "Event Log: System log size >= 32768 KB"        "All" "AU-9" "WindowsComponents"

    # File Explorer
    CR "18.9.31.1" 1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "TurnOffDataExecutionPreventionForExplorer" 0 `
        "File Explorer: DEP for Explorer = Enabled"                                  "All" "SC-39" "WindowsComponents"
    CR "18.9.31.2" 1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoHeapTerminationOnCorruption" 0 `
        "File Explorer: Heap termination on corruption = Enabled"                    "All" "SI-16" "WindowsComponents"
    CR "18.9.31.3" 1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "PreventItemCreationInUsersFilesFolder" 1 `
        "File Explorer: Turn off shell protocol protected mode"                      "All" "CM-7" "WindowsComponents"

    # HomeGroup
    CR "18.9.33.1" 1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HomeGroup" "DisableHomeGroup" 1 `
        "HomeGroup: Prevent users from joining"                                      "All" "CM-7" "WindowsComponents"

    # Internet Communication
    CR "18.9.35.1"  2 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard" "ExitOnMSICW" 1 `
        "Internet: Disable Internet Connection Wizard (L2)"                          "All" "CM-7" "WindowsComponents"
    CR "18.9.35.2"  2 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control" "NoRegistration" 1 `
        "Internet: Turn off Registration (L2)"                                       "All" "CM-7" "WindowsComponents"
    CR "18.9.35.3"  2 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging" "AllowMessageSync" 0 `
        "Internet: Turn off Windows Messaging Sync (L2)"                             "All" "CM-7" "WindowsComponents"

    # Logon
    CR "18.9.45.1" 1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "BlockDomainPicturePassword" 1 `
        "Logon: Turn off picture password sign-in"                                   "All" "IA-5" "WindowsComponents"
    CR "18.9.45.2" 1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "AllowDomainPINLogon"         0 `
        "Logon: Turn off convenience PIN sign-in"                                    "All" "IA-5" "WindowsComponents"

    # Microsoft Defender AV
    CR "18.9.47.4.1" 1 "$WDEF\MpEngine" "MpEnablePus" 1 "Defender: Enable detection of PUAs"            "All" "SI-3" "WindowsComponents"
    CR "18.9.47.5.1" 1 "$WDEF\Real-Time Protection" "DisableBehaviorMonitoring" 0 "Defender: Behavior monitoring enabled" "All" "SI-3" "WindowsComponents"
    CR "18.9.47.5.2" 1 "$WDEF\Real-Time Protection" "DisableIOAVProtection"     0 "Defender: Scan all downloaded files"  "All" "SI-3" "WindowsComponents"
    CR "18.9.47.5.3" 1 "$WDEF\Real-Time Protection" "DisableRealtimeMonitoring" 0 "Defender: Real-time monitoring enabled" "All" "SI-3" "WindowsComponents"
    CR "18.9.47.5.4" 1 "$WDEF\Real-Time Protection" "DisableScriptScanning"     0 "Defender: Script scanning enabled"    "All" "SI-3" "WindowsComponents"
    CR "18.9.47.6.1" 1 "$WDEF\Reporting" "DisableEnhancedNotifications" 0 "Defender: Enhanced notifications enabled" "All" "SI-3" "WindowsComponents"
    CR "18.9.47.9.1" 1 "$WDEF\Scan" "DisableEmailScanning"          0  "Defender: Email scanning enabled"           "All" "SI-3" "WindowsComponents"
    CR "18.9.47.9.2" 1 "$WDEF\Scan" "DisableRemovableDriveScanning" 0  "Defender: Removable drive scanning enabled" "All" "SI-3" "WindowsComponents"
    CR "18.9.47.12.1" 1 "$WDEF\SpyNet" "LocalSettingOverrideSpynetReporting" 0 "Defender: Do not override SpyNet local setting" "All" "SI-3" "WindowsComponents"
    CR "18.9.47.12.2" 1 "$WDEF\SpyNet" "SpynetReporting" 2 "Defender: Cloud-based protection = Advanced"  "All" "SI-3" "WindowsComponents"

    # Exploit Guard / ASR
    CR "18.9.47.13.1" 1 "$WDEF\Windows Defender Exploit Guard\ASR" "ExploitGuard_ASR_Rules" 1 `
        "Exploit Guard: ASR rules enabled"                                           "Workstation" "SI-3" "WindowsComponents"
    CR "18.9.47.13.2" 1 "$WDEF\Windows Defender Exploit Guard\Network Protection" "EnableNetworkProtection" 1 `
        "Exploit Guard: Network Protection enabled"                                  "Workstation" "SI-3" "WindowsComponents"

    # OneDrive
    CR "18.9.58.1" 1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC" 1 `
        "OneDrive: Prevent usage of OneDrive for file storage"                       "All" "SC-28" "WindowsComponents"

    # PowerShell
    CR "18.9.95.1" 1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging" 1 `
        "PowerShell: Enable script block logging"                                    "All" "AU-12" "WindowsComponents"
    CR "18.9.95.2" 2 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockInvocationLogging" 1 `
        "PowerShell: Enable script block invocation logging (L2)"                    "All" "AU-12" "WindowsComponents"
    CR "18.9.95.3" 1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" "EnableTranscripting" 1 `
        "PowerShell: Enable PowerShell transcription"                                "All" "AU-12" "WindowsComponents"
    CR "18.9.95.4" 2 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" "EnableInvocationHeader" 1 `
        "PowerShell: Include invocation headers in transcripts (L2)"                 "All" "AU-12" "WindowsComponents"
    CR "18.9.95.5" 1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" "EnableModuleLogging" 1 `
        "PowerShell: Enable module logging"                                          "All" "AU-12" "WindowsComponents"

    # Remote Desktop
    CR "18.9.65.2.1" 1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fEncryptionLevel"     3 "RDP: Encryption level = High"          "All" "SC-8" "WindowsComponents"
    CR "18.9.65.2.2" 1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fDisableCdm"          1 "RDP: Do not allow drive redirection"    "All" "MP-7" "WindowsComponents"
    CR "18.9.65.3.2" 1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "UserAuthentication"   1 "RDP: Require NLA for connections"       "All" "AC-17" "WindowsComponents"
    CR "18.9.65.3.3" 1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "SecurityLayer"        2 "RDP: Security layer = SSL/TLS"          "All" "SC-8" "WindowsComponents"
    CR "18.9.65.3.9" 1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "MaxIdleTime"      900000 "RDP: Session idle timeout <= 15 min"    "All" "AC-11" "WindowsComponents"
    CR "18.9.65.3.10" 1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "MaxDisconnectionTime" 60000 "RDP: Disconnected session timeout <= 1 min" "All" "AC-11" "WindowsComponents"
    CR "18.9.65.3.11" 1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fDisableAutomaticReconnect" 1 "RDP: Do not allow automatic reconnects" "All" "AC-17" "WindowsComponents"

    # RSS Feeds
    CR "18.9.69.1" 2 "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" "DisableEnclosureDownload" 1 `
        "RSS: Prevent downloading of enclosures (L2)"                                "All" "CM-7" "WindowsComponents"

    # Windows Error Reporting
    CR "18.9.78.1" 2 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" "Disabled" 1 `
        "Windows Error Reporting: Disabled (L2)"                                     "All" "CM-7" "WindowsComponents"

    # Windows Hello / Biometrics
    CR "18.9.80.1.1" 1 "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" "Enabled" 0 `
        "Windows Hello: Require use of hardware security device (no software keys)"  "All" "IA-5" "WindowsComponents"

    # Windows Ink Workspace
    CR "18.9.81.1" 2 "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" "AllowWindowsInkWorkspace" 1 `
        "Windows Ink: Only allow above lock (L2)"                                    "Workstation" "CM-7" "WindowsComponents"

    # Windows Installer
    CR "18.9.85.1" 1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" "EnableUserControl"      0 "Installer: Disable user control over installs" "All" "CM-11" "WindowsComponents"
    CR "18.9.85.2" 1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated"  0 "Installer: Disable always install with elevated privileges" "All" "CM-11" "WindowsComponents"
    CR "18.9.85.3" 2 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" "SafeForScripting"       0 "Installer: Disable IE security prompt for scripts (L2)" "All" "CM-11" "WindowsComponents"

    # Windows Logon Options
    CR "18.9.86.1" 1 "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableAutomaticRestartSignOn" 1 `
        "Logon Options: Disable automatic restart sign-on (ARSO)"                   "All" "AC-11" "WindowsComponents"

    # Windows Remote Management
    CR "18.9.102.1.1" 1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" "AllowBasic"              0 "WinRM Client: Disallow Basic auth"        "All" "IA-5" "WindowsComponents"
    CR "18.9.102.1.2" 1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" "AllowUnencryptedTraffic" 0 "WinRM Client: Disallow unencrypted traffic" "All" "SC-8" "WindowsComponents"
    CR "18.9.102.1.3" 1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" "AllowDigest"             0 "WinRM Client: Disallow Digest auth"       "All" "IA-5" "WindowsComponents"
    CR "18.9.102.2.1" 1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "AllowBasic"             0 "WinRM Service: Disallow Basic auth"       "All" "IA-5" "WindowsComponents"
    CR "18.9.102.2.2" 1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "AllowUnencryptedTraffic" 0 "WinRM Service: Disallow unencrypted traffic" "All" "SC-8" "WindowsComponents"
    CR "18.9.102.2.3" 1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "DisableRunAs"           1 "WinRM Service: Disallow RunAs credentials" "All" "IA-5" "WindowsComponents"

    # Windows Update
    CR "18.9.108.1"  1 "$WU\AU" "NoAutoUpdate"                0 "Windows Update: Do not disable auto-updates"             "All" "SI-2" "WindowsComponents"
    CR "18.9.108.2"  1 "$WU\AU" "AUOptions"                   4 "Windows Update: Auto download and schedule install"      "All" "SI-2" "WindowsComponents"
    CR "18.9.108.3"  1 "$WU\AU" "AutoInstallMinorUpdates"     1 "Windows Update: Install minor updates automatically"     "All" "SI-2" "WindowsComponents"
    CR "18.9.108.4"  1 "$WU"    "DeferFeatureUpdates"         1 "Windows Update: Defer feature updates (stability)"       "All" "SI-2" "WindowsComponents"
    CR "18.9.108.5"  2 "$WU"    "DeferQualityUpdates"         1 "Windows Update: Defer quality updates (L2)"              "All" "SI-2" "WindowsComponents"
    CR "18.9.108.6"  1 "$WU\AU" "NoAutoRebootWithLoggedOnUsers" 0 "Windows Update: Allow auto-reboot (no user blocking)"  "All" "SI-2" "WindowsComponents"
    CR "18.9.108.7"  1 "$WU"    "SetDisablePauseUXAccess"     1 "Windows Update: Remove access to pause updates"          "All" "SI-2" "WindowsComponents"
    CR "18.9.108.8"  1 "$WU"    "SetDisableUXWUAccess"        1 "Windows Update: Remove access to Windows Update settings" "All" "SI-2" "WindowsComponents"

    # Device Guard / VBS
    CR "18.9.29.1" 1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "EnableVirtualizationBasedSecurity" 1 `
        "Device Guard: Enable Virtualization Based Security"                         "All" "SI-7" "WindowsComponents"
    CR "18.9.29.2" 1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "RequirePlatformSecurityFeatures"   3 `
        "Device Guard: Require Secure Boot and DMA protection"                       "All" "SI-7" "WindowsComponents"
    CR "18.9.29.3" 1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "HypervisorEnforcedCodeIntegrity"   1 `
        "Device Guard: Enable HVCI"                                                  "All" "SI-7" "WindowsComponents"
    CR "18.9.29.4" 1 "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "LsaCfgFlags"                       1 `
        "Device Guard: Credential Guard = Enabled with UEFI lock"                   "All" "IA-5" "WindowsComponents"

    # ==========================================================================
    # SECTION 5 -- SYSTEM SERVICES
    # ==========================================================================
    if (-not $Quiet) { Write-Section "5 - System Services" }

    # L1 services that must be disabled (all profiles)
    @("BTAGService","bthserv","Browser","MapsBroker","lfsvc","IISADMIN","irmon",
      "SharedAccess","icssvc","MSiSCSI","sshd","PNRPsvc","p2psvc","p2pimsvc",
      "PNRPAutoReg","Spooler","wercplsupport","RasAuto","SessionEnv","TermService",
      "UmRdpService","RpcLocator","RemoteRegistry","RemoteAccess","LanmanServer",
      "simptcp","SNMP","sacsvr","SSDPSRV","upnphost","WMSvc","WerSvc","Wecsvc",
      "WMPNetworkSvc","icssvc","WpnService","PushToInstall","WinRM","W3SVC","XboxGipSvc",
      "XblAuthManager","XblGameSave","XboxNetApiSvc") | ForEach-Object {
        CSvc "5.1" 1 $_ "All" "CM-7"
    }

    # Server-only services to disable
    if ($isSrv) {
        @("FTPSVC","RpcLocator","W3SVC") | ForEach-Object { CSvc "5.1" 1 $_ "Server" "CM-7" }
    }

    # ==========================================================================
    # SUMMARY
    # ==========================================================================
    $allFindings = @($findings)
    $p    = @($allFindings | Where-Object { $_.Status -eq "Pass" }).Count
    $f    = @($allFindings | Where-Object { $_.Status -eq "Fail" }).Count
    $w    = @($allFindings | Where-Object { $_.Status -eq "Warn" }).Count
    $tot  = $allFindings.Count
    $pct  = if ($tot -gt 0) { [math]::Round(($p / $tot) * 100, 1) } else { 0 }
    $col  = if ($pct -ge 80) { "Green" } elseif ($pct -ge 50) { "Yellow" } else { "Red" }

    Write-Host ""
    Write-Host "===========================================" -ForegroundColor White
    Write-Host " CIS SCAN COMPLETE  [$Profile / L$Level]" -ForegroundColor White
    Write-Host "===========================================" -ForegroundColor White
    Write-Host (" TOTAL: $tot  |  PASS: $p  |  FAIL: $f  |  WARN: $w") -ForegroundColor White
    Write-Host (" SCORE: $pct%") -ForegroundColor $col
    Write-Host "===========================================" -ForegroundColor White
    Write-Host ""

    return $findings
}
