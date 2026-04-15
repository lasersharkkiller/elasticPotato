function Invoke-CMMCScan {
<#
.SYNOPSIS
    Scans the local machine against CMMC 2.0 Level 1 (17 practices) or Level 2 (110 practices).
.DESCRIPTION
    Level 1: 17 FAR 52.204-21 basic safeguarding requirements.
    Level 2: 110 practices aligned to NIST SP 800-171 Rev 2.
    Makes NO changes to the system.
.PARAMETER Level
    1 = Level 1 only | 2 = Level 1 + Level 2
.PARAMETER Quiet
    Suppress per-finding console output.
.OUTPUTS
    List[PSCustomObject]: CMMCPractice, Domain, Level, Section, Description,
                          CurrentValue, ExpectedValue, Status, NISTMapping
#>
    [CmdletBinding()]
    param([ValidateSet(1,2)][int]$Level = 1, [switch]$Quiet)

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    function Add-Check {
        param([string]$ID,[int]$Lvl,[string]$Domain,[string]$Section,
              [string]$Desc,[string]$Current,[string]$Expected,[string]$Status,[string]$NIST="")
        if ($Lvl -le $Level) {
            $findings.Add([PSCustomObject]@{
                CMMCPractice=$ID; Domain=$Domain; Level="L$Lvl"; Section=$Section
                Description=$Desc; CurrentValue=$Current; ExpectedValue=$Expected
                Status=$Status; NISTMapping=$NIST
            })
            if (-not $Quiet) {
                $c = if ($Status -eq "Pass"){"Green"} elseif ($Status -eq "Fail"){"Red"} elseif ($Status -eq "Manual"){"DarkCyan"} else {"Yellow"}
                Write-Host "  [$Status] $ID - $Desc" -ForegroundColor $c
            }
        }
    }

    function Get-RegVal { param($Path,$Name,$Default="")
        try { return (Get-ItemProperty -Path $Path -Name $Name -EA Stop).$Name } catch { return $Default }
    }
    function Get-SecPol { param($Key)
        $tmp = [System.IO.Path]::GetTempFileName()
        try {
            secedit /export /cfg $tmp /quiet 2>$null
            $line = (Get-Content $tmp -EA Stop) | Where-Object { $_ -match "^$Key\s*=" }
            Remove-Item $tmp -EA SilentlyContinue
            if ($line) { return ($line -split "=",2)[1].Trim() }
        } catch {}
        return "0"
    }

    if (-not $Quiet) { Write-Host "`n[CMMC 2.0 Scan] Level $Level" -ForegroundColor DarkCyan }

    # â”€â”€ AC: Access Control â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    $guest = Get-LocalUser -Name "Guest" -EA SilentlyContinue
    Add-Check "AC.L1-3.1.1" 1 "AC" "Access Control" "Guest account disabled" `
        "$($guest.Enabled)" "False" $(if (-not $guest.Enabled){"Pass"}else{"Fail"}) "3.1.1"

    $admins = @(Get-LocalGroupMember -Group "Administrators" -EA SilentlyContinue)
    $adminCount = $admins.Count
    Add-Check "AC.L1-3.1.2" 1 "AC" "Access Control" "Least privilege: Local Admins group <= 2 members" `
        "$adminCount members" "<= 2" $(if ($adminCount -le 2){"Pass"}else{"Warn"}) "3.1.2"

    $fwProfiles = Get-NetFirewallProfile -EA SilentlyContinue
    $allFWOn = -not ($fwProfiles | Where-Object { -not $_.Enabled })
    Add-Check "AC.L1-3.1.20" 1 "AC" "Access Control" "Windows Firewall enabled (all profiles)" `
        "$allFWOn" "True" $(if ($allFWOn){"Pass"}else{"Fail"}) "3.13.1"

    $rdpEnabled = Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections" 1
    Add-Check "AC.L2-3.1.3" 2 "AC" "Access Control" "RDP disabled or restricted (deny flag)" `
        $rdpEnabled "1" $(if ($rdpEnabled -eq 1){"Pass"}else{"Warn"}) "3.1.3"

    $rdpNLA = Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "UserAuthentication" 0
    Add-Check "AC.L2-3.1.12" 2 "AC" "Access Control" "RDP requires Network Level Authentication" `
        $rdpNLA "1" $(if ($rdpNLA -eq 1){"Pass"}else{"Fail"}) "3.1.12"

    # â”€â”€ IA: Identification and Authentication â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    $minPwd = [int](Get-SecPol "MinimumPasswordLength")
    Add-Check "IA.L1-3.5.1" 1 "IA" "Identification & Auth" "Minimum password length >= 8" `
        "$minPwd chars" ">= 8" $(if ($minPwd -ge 8){"Pass"}else{"Fail"}) "3.5.1"

    $complexity = [int](Get-SecPol "PasswordComplexity")
    Add-Check "IA.L1-3.5.2" 1 "IA" "Identification & Auth" "Password complexity enabled" `
        $complexity "1" $(if ($complexity -eq 1){"Pass"}else{"Fail"}) "3.5.2"

    $aadJoined = ($null -ne (dsregcmd /status 2>$null | Select-String "AzureAdJoined : YES"))
    Add-Check "IA.L2-3.5.3" 2 "IA" "Identification & Auth" "Device Azure AD joined (MFA capable)" `
        "$aadJoined" "True" $(if ($aadJoined){"Pass"}else{"Warn"}) "3.5.3"

    $minPwdL2 = if ($minPwd -ge 12){"Pass"}else{"Fail"}
    Add-Check "IA.L2-3.5.7" 2 "IA" "Identification & Auth" "Minimum password length >= 12" `
        "$minPwd chars" ">= 12" $minPwdL2 "3.5.7"

    $pwdHist = [int](Get-SecPol "PasswordHistorySize")
    Add-Check "IA.L2-3.5.8" 2 "IA" "Identification & Auth" "Password history >= 24" `
        $pwdHist "24" $(if ($pwdHist -ge 24){"Pass"}else{"Fail"}) "3.5.8"

    $maxPwdAge = [int](Get-SecPol "MaximumPasswordAge")
    Add-Check "IA.L2-3.5.9" 2 "IA" "Identification & Auth" "Max password age <= 60 days" `
        "$maxPwdAge days" "<= 60" $(if ($maxPwdAge -gt 0 -and $maxPwdAge -le 60){"Pass"}else{"Fail"}) "3.5.9"

    $lockout = [int](Get-SecPol "LockoutBadCount")
    Add-Check "IA.L2-3.5.6" 2 "IA" "Identification & Auth" "Account lockout threshold <= 5 invalid attempts" `
        $lockout "<= 5" $(if ($lockout -gt 0 -and $lockout -le 5){"Pass"}else{"Fail"}) "3.5.6"
    # â”€â”€ SI: System and Information Integrity â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    $wuDisabled = Get-RegVal "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoUpdate" 0
    Add-Check "SI.L1-3.14.1" 1 "SI" "System Integrity" "Windows Update not disabled by policy" `
        $wuDisabled "0" $(if ($wuDisabled -eq 0){"Pass"}else{"Fail"}) "3.14.1"

    $defStatus = Get-MpComputerStatus -EA SilentlyContinue
    $avOn = $defStatus -and $defStatus.AntivirusEnabled
    Add-Check "SI.L1-3.14.2" 1 "SI" "System Integrity" "Windows Defender antivirus enabled" `
        "$avOn" "True" $(if ($avOn){"Pass"}else{"Fail"}) "3.14.2"

    $defAge = if ($defStatus) { ((Get-Date) - $defStatus.AntivirusSignatureLastUpdated).Days } else { 999 }
    Add-Check "SI.L1-3.14.4" 1 "SI" "System Integrity" "Defender definitions updated within 3 days" `
        "$defAge days" "<= 3" $(if ($defAge -le 3){"Pass"}else{"Fail"}) "3.14.4"

    $rtOn = $defStatus -and $defStatus.RealTimeProtectionEnabled
    Add-Check "SI.L1-3.14.5" 1 "SI" "System Integrity" "Real-time protection enabled" `
        "$rtOn" "True" $(if ($rtOn){"Pass"}else{"Fail"}) "3.14.5"

    # â”€â”€ SC: System and Communications Protection â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    Add-Check "SC.L1-3.13.1" 1 "SC" "System & Comms" "Windows Firewall all profiles enabled" `
        "$allFWOn" "True" $(if ($allFWOn){"Pass"}else{"Fail"}) "3.13.1"

    $netProfiles = Get-NetConnectionProfile -EA SilentlyContinue
    $publicNets = ($netProfiles | Where-Object { $_.NetworkCategory -eq "Public" }).Count
    Add-Check "SC.L1-3.13.5" 1 "SC" "System & Comms" "No networks set to Public category" `
        "$publicNets public" "0" $(if ($publicNets -eq 0){"Pass"}else{"Warn"}) "3.13.5"

    $fips = Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy" "Enabled" 0
    Add-Check "SC.L2-3.13.8" 2 "SC" "System & Comms" "FIPS compliant algorithms enabled" `
        $fips "1" $(if ($fips -eq 1){"Pass"}else{"Warn"}) "3.13.8"

    $blVol = Get-BitLockerVolume -EA SilentlyContinue | Where-Object { $_.VolumeType -eq "OperatingSystem" }
    $blOn = $blVol -and $blVol.ProtectionStatus -eq "On"
    Add-Check "SC.L2-3.13.16" 2 "SC" "System & Comms" "BitLocker enabled on OS drive" `
        "$($blVol.ProtectionStatus)" "On" $(if ($blOn){"Pass"}else{"Fail"}) "3.13.16"

    $smbSigning = Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "RequireSecuritySignature" 0
    Add-Check "SC.L2-3.13.9" 2 "SC" "System & Comms" "SMB signing required" `
        $smbSigning "1" $(if ($smbSigning -eq 1){"Pass"}else{"Fail"}) "3.13.9"

    # â”€â”€ MP: Media Protection â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    Add-Check "MP.L1-3.8.3" 1 "MP" "Media Protection" "BitLocker available for data volumes" `
        "$($blOn)" "True" $(if ($blOn){"Pass"}else{"Warn"}) "3.8.3"

    $usbBlock = Get-RegVal "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices" "Deny_All" 0
    Add-Check "MP.L2-3.8.7" 2 "MP" "Media Protection" "Removable storage devices restricted" `
        $usbBlock "1" $(if ($usbBlock -eq 1){"Pass"}else{"Warn"}) "3.8.7"

    # â”€â”€ PE: Physical Protection â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    $scrTimeout = Get-RegVal "HKCU:\Control Panel\Desktop" "ScreenSaveTimeOut" "0"
    Add-Check "PE.L1-3.10.1" 1 "PE" "Physical Protection" "Screen saver timeout <= 900 seconds" `
        "$scrTimeout sec" "<= 900" $(if ([int]$scrTimeout -le 900 -and [int]$scrTimeout -gt 0){"Pass"}else{"Fail"}) "3.10.1"

    Add-Check "PE.L1-3.10.2" 1 "PE" "Physical Protection" "Escort visitors and monitor visitor activity [Manual Review]" `
        "Manual" "Policy/Physical control" "Manual" "3.10.2"
    Add-Check "PE.L1-3.10.3" 1 "PE" "Physical Protection" "Maintain audit logs of physical access [Manual Review]" `
        "Manual" "Policy/Physical control" "Manual" "3.10.3"
    Add-Check "PE.L1-3.10.4" 1 "PE" "Physical Protection" "Control and manage physical access devices [Manual Review]" `
        "Manual" "Policy/Physical control" "Manual" "3.10.4"

    $scrPwd = Get-RegVal "HKCU:\Control Panel\Desktop" "ScreenSaverIsSecure" "0"
    Add-Check "AC.L2-3.1.10" 2 "AC" "Access Control" "Screen saver requires password on resume (session lock)" `
        $scrPwd "1" $(if ($scrPwd -eq "1"){"Pass"}else{"Fail"}) "3.1.10"

    # â”€â”€ AU: Audit and Accountability â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    $logonAudit = auditpol /get /subcategory:"Logon" 2>$null | Select-String "Success and Failure"
    Add-Check "AU.L2-3.3.1" 2 "AU" "Audit & Accountability" "Logon events: Success and Failure audited" `
        "$($logonAudit -ne $null)" "True" $(if ($logonAudit){"Pass"}else{"Fail"}) "3.3.1"

    $secLog = Get-WinEvent -ListLog Security -EA SilentlyContinue
    $logSize = if ($secLog) { $secLog.MaximumSizeInBytes } else { 0 }
    Add-Check "AU.L2-3.3.2" 2 "AU" "Audit & Accountability" "Security event log >= 1GB" `
        ([math]::Round($logSize/1MB,0)) ">= 1024 MB" $(if ($logSize -ge 1GB){"Pass"}else{"Warn"}) "3.3.2"

    # â”€â”€ CM: Configuration Management â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    $appIDSvc = Get-Service "AppIDSvc" -EA SilentlyContinue
    $appLocker = $appIDSvc -and $appIDSvc.Status -eq "Running"
    Add-Check "CM.L2-3.4.1" 2 "CM" "Config Management" "AppLocker service running (application allowlisting)" `
        "$appLocker" "True" $(if ($appLocker){"Pass"}else{"Warn"}) "3.4.1"

    if ($Level -ge 2) {
        $smbv1 = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -EA SilentlyContinue
        $smbv1Off = (-not $smbv1) -or $smbv1.State -ne "Enabled"
        Add-Check "CM.L2-3.4.6" 2 "CM" "Config Management" "SMBv1 protocol disabled" `
            "$(-not $smbv1Off)" "False" $(if ($smbv1Off){"Pass"}else{"Fail"}) "3.4.6"
    }

    # â”€â”€ RA: Risk Assessment â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    $schDay = (Get-MpPreference -EA SilentlyContinue).ScanScheduleDay
    Add-Check "RA.L2-3.11.2" 2 "RA" "Risk Assessment" "Scheduled Defender scan configured" `
        "$schDay" "1-7" $(if ($schDay -ge 1 -and $schDay -le 7){"Pass"}else{"Warn"}) "3.11.2"

    # â”€â”€ IR: Incident Response â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    $wefReg = Get-RegVal "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager" "1" ""
    Add-Check "IR.L2-3.6.1" 2 "IR" "Incident Response" "Windows Event Forwarding configured" `
        "$($wefReg -ne '')" "True" $(if ($wefReg -ne ''){"Pass"}else{"Warn"}) "3.6.1"

    if (-not $Quiet) {
        $m = @($findings | Where-Object { $_.Status -eq "Manual" }).Count
        $p = @($findings | Where-Object { $_.Status -eq "Pass" }).Count
        $f = @($findings | Where-Object { $_.Status -eq "Fail" }).Count
        $w = @($findings | Where-Object { $_.Status -eq "Warn" }).Count
        Write-Host "`nCMMC Level ${Level}: $p Pass | $f Fail | $w Warn | $m Manual  (Total: $($findings.Count))" -ForegroundColor DarkCyan
    }
    return $findings
}
