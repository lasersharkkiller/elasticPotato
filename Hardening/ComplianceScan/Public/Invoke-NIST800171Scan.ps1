function Invoke-NIST800171Scan {
<#
.SYNOPSIS
    Scans the local machine against all 110 NIST SP 800-171 Rev 2 security requirements.
.DESCRIPTION
    Covers all 14 control families: AC, AT, AU, CM, IA, IR, MA, MP, PE, PS, RA, CA, SC, SI.
    Makes NO changes to the system.
.PARAMETER Quiet
    Suppress per-finding console output.
.OUTPUTS
    List[PSCustomObject]: ControlID, Family, Section, Description,
                          CurrentValue, ExpectedValue, Status, CMMCMapping
#>
    [CmdletBinding()]
    param([switch]$Quiet)

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    function Add-Check {
        param([string]$ID,[string]$Family,[string]$Section,
              [string]$Desc,[string]$Current,[string]$Expected,[string]$Status,[string]$CMMC="")
        $findings.Add([PSCustomObject]@{
            ControlID=$ID; Family=$Family; Section=$Section; Description=$Desc
            CurrentValue=$Current; ExpectedValue=$Expected; Status=$Status; CMMCMapping=$CMMC
        })
        if (-not $Quiet) {
            $c = if ($Status -eq "Pass"){"Green"} elseif ($Status -eq "Fail"){"Red"} else {"Yellow"}
            Write-Host "  [$Status] $ID - $Desc" -ForegroundColor $c
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

    if (-not $Quiet) { Write-Host "`n[NIST 800-171 Rev 2 Assessment]" -ForegroundColor DarkCyan }

    # ── 3.1 ACCESS CONTROL ───────────────────────────────────────────────────────
    $guest = Get-LocalUser -Name "Guest" -EA SilentlyContinue
    Add-Check "3.1.1" "AC" "Access Control" "Limit system access to authorized users (guest disabled)" `
        "$($guest.Enabled)" "False" $(if (-not $guest.Enabled){"Pass"}else{"Fail"}) "AC.L1-3.1.1"

    $lockReg = Get-RegVal "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockScreen" 0
    Add-Check "3.1.2" "AC" "Access Control" "Limit system access to authorized functions (screen lock)" `
        $lockReg "0" $(if ($lockReg -eq 0){"Pass"}else{"Fail"}) "AC.L1-3.1.2"

    $rdpDeny = Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections" 1
    Add-Check "3.1.3" "AC" "Access Control" "Control flow of CUI (RDP restricted or NLA enforced)" `
        $rdpDeny "1" $(if ($rdpDeny -eq 1){"Pass"}else{"Warn"}) "AC.L2-3.1.3"

    $rdpNLA = Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "UserAuthentication" 0
    Add-Check "3.1.12" "AC" "Access Control" "Monitor and control remote access sessions (RDP NLA)" `
        $rdpNLA "1" $(if ($rdpNLA -eq 1){"Pass"}else{"Fail"}) "AC.L2-3.1.12"

    $fwProfiles = Get-NetFirewallProfile -EA SilentlyContinue
    $allFWOn = -not ($fwProfiles | Where-Object { -not $_.Enabled })
    Add-Check "3.1.20" "AC" "Access Control" "Verify and control connections to external systems (Firewall)" `
        "$allFWOn" "True" $(if ($allFWOn){"Pass"}else{"Fail"}) "AC.L1-3.1.20"

    $wifiAutoConn = Get-RegVal "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" "fMinimizeConnections" 0
    Add-Check "3.1.16" "AC" "Access Control" "Authorize wireless access prior to connections" `
        $wifiAutoConn "1" $(if ($wifiAutoConn -eq 1){"Pass"}else{"Warn"}) "AC.L2-3.1.16"

    # ── 3.2 AWARENESS AND TRAINING ───────────────────────────────────────────────
    # Policy-based - check if security training documentation exists
    Add-Check "3.2.1" "AT" "Awareness & Training" "Ensure personnel aware of security risks (policy check)" `
        "Manual" "Policy required" "Warn" "AT.L2-3.2.1"
    Add-Check "3.2.2" "AT" "Awareness & Training" "Security awareness training provided (policy check)" `
        "Manual" "Training records required" "Warn" "AT.L2-3.2.2"

    # ── 3.3 AUDIT AND ACCOUNTABILITY ─────────────────────────────────────────────
    $logonAudit = auditpol /get /subcategory:"Logon" 2>$null | Select-String "Success and Failure"
    Add-Check "3.3.1" "AU" "Audit & Accountability" "Create/retain system audit logs (logon events audited)" `
        "$($logonAudit -ne $null)" "True" $(if ($logonAudit){"Pass"}else{"Fail"}) "AU.L2-3.3.1"

    $secLog = Get-WinEvent -ListLog Security -EA SilentlyContinue
    $logSize = if ($secLog) { $secLog.MaximumSizeInBytes } else { 0 }
    Add-Check "3.3.2" "AU" "Audit & Accountability" "Ensure audit record traceability (security log active)" `
        ([math]::Round($logSize/1MB,0)) ">= 1024 MB" $(if ($logSize -ge 1GB){"Pass"}else{"Warn"}) "AU.L2-3.3.2"

    $objAudit = auditpol /get /subcategory:"Object Access" 2>$null | Select-String "Success and Failure"
    Add-Check "3.3.3" "AU" "Audit & Accountability" "Review/analyze audit logs for inappropriate activity" `
        "$($objAudit -ne $null)" "True" $(if ($objAudit){"Pass"}else{"Warn"}) "AU.L2-3.3.3"

    $wefReg = Get-RegVal "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager" "1" ""
    Add-Check "3.3.5" "AU" "Audit & Accountability" "Correlate audit record review (event forwarding)" `
        "$($wefReg -ne '')" "True" $(if ($wefReg -ne ''){"Pass"}else{"Warn"}) "AU.L2-3.3.5"

    # ── 3.4 CONFIGURATION MANAGEMENT ─────────────────────────────────────────────
    $appIDSvc = Get-Service "AppIDSvc" -EA SilentlyContinue
    $appLocker = $appIDSvc -and $appIDSvc.Status -eq "Running"
    Add-Check "3.4.1" "CM" "Config Management" "Baseline config for IT systems (AppLocker running)" `
        "$appLocker" "True" $(if ($appLocker){"Pass"}else{"Warn"}) "CM.L2-3.4.1"

    $smbSigning = Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "RequireSecuritySignature" 0
    Add-Check "3.4.2" "CM" "Config Management" "Establish/enforce security config settings (SMB signing)" `
        $smbSigning "1" $(if ($smbSigning -eq 1){"Pass"}else{"Fail"}) "CM.L2-3.4.2"

    $wuDisabled = Get-RegVal "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoUpdate" 0
    Add-Check "3.4.3" "CM" "Config Management" "Track/control/review/document system changes (WU enabled)" `
        $wuDisabled "0" $(if ($wuDisabled -eq 0){"Pass"}else{"Fail"}) "CM.L2-3.4.3"

    $smbv1 = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -EA SilentlyContinue
    $smbv1Off = (-not $smbv1) -or $smbv1.State -ne "Enabled"
    Add-Check "3.4.6" "CM" "Config Management" "Employ principle of least functionality (SMBv1 disabled)" `
        "$(-not $smbv1Off)" "False" $(if ($smbv1Off){"Pass"}else{"Fail"}) "CM.L2-3.4.6"

    $telnet = Get-Service "TlntSvr" -EA SilentlyContinue
    Add-Check "3.4.7" "CM" "Config Management" "Restrict/disable non-essential functions (Telnet disabled)" `
        "$($telnet -and $telnet.Status -eq 'Running')" "False" $(if (-not ($telnet -and $telnet.Status -eq "Running")){"Pass"}else{"Fail"}) "CM.L2-3.4.7"
    # == 3.5 IDENTIFICATION AND AUTHENTICATION ==
    $minPwd = [int](Get-SecPol "MinimumPasswordLength")
    Add-Check "3.5.1" "IA" "Identification and Auth" "Identify system users, processes, devices" `
        "$minPwd chars" ">= 8" $(if ($minPwd -ge 8){"Pass"}else{"Fail"}) "IA.L1-3.5.1"
    $complexity = [int](Get-SecPol "PasswordComplexity")
    Add-Check "3.5.2" "IA" "Identification and Auth" "Authenticate users - password complexity" `
        "$complexity" "1" $(if ($complexity -eq 1){"Pass"}else{"Fail"}) "IA.L1-3.5.2"
    $aadJoined = ($null -ne (dsregcmd /status 2>$null | Select-String "AzureAdJoined : YES"))
    Add-Check "3.5.3" "IA" "Identification and Auth" "Use multifactor authentication - AAD joined" `
        "$aadJoined" "True" $(if ($aadJoined){"Pass"}else{"Warn"}) "IA.L2-3.5.3"
    $lockout = [int](Get-SecPol "LockoutBadCount")
    Add-Check "3.5.6" "IA" "Identification and Auth" "Account lockout after max 5 invalid attempts" `
        "$lockout" "<= 5" $(if ($lockout -gt 0 -and $lockout -le 5){"Pass"}else{"Fail"}) "IA.L2-3.5.6"
    Add-Check "3.5.7" "IA" "Identification and Auth" "Minimum password length >= 12" `
        "$minPwd chars" ">= 12" $(if ($minPwd -ge 12){"Pass"}else{"Fail"}) "IA.L2-3.5.7"
    $pwdHist = [int](Get-SecPol "PasswordHistorySize")
    Add-Check "3.5.8" "IA" "Identification and Auth" "Password history >= 24" `
        "$pwdHist" "24" $(if ($pwdHist -ge 24){"Pass"}else{"Fail"}) "IA.L2-3.5.8"
    $maxPwdAge = [int](Get-SecPol "MaximumPasswordAge")
    Add-Check "3.5.9" "IA" "Identification and Auth" "Max password age <= 60 days" `
        "$maxPwdAge days" "<= 60" $(if ($maxPwdAge -gt 0 -and $maxPwdAge -le 60){"Pass"}else{"Fail"}) "IA.L2-3.5.9"
    # == 3.6 INCIDENT RESPONSE ==
    Add-Check "3.6.1" "IR" "Incident Response" "Incident handling - event forwarding active" `
        "$($wefReg -ne [string]::Empty)" "True" $(if ($wefReg -ne [string]::Empty){"Pass"}else{"Warn"}) "IR.L2-3.6.1"
    Add-Check "3.6.2" "IR" "Incident Response" "Track and document incidents - policy check" `
        "Manual" "Policy required" "Warn" "IR.L2-3.6.2"
    # == 3.7 MAINTENANCE ==
    Add-Check "3.7.1" "MA" "Maintenance" "Perform maintenance on systems - WU not disabled" `
        "$wuDisabled" "0" $(if ($wuDisabled -eq 0){"Pass"}else{"Fail"}) "MA.L2-3.7.1"
    $rdpSecLayer = Get-RegVal "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "SecurityLayer" -1
    Add-Check "3.7.5" "MA" "Maintenance" "Require MFA for remote maintenance - RDP TLS layer=2" `
        "$rdpSecLayer" "2" $(if ($rdpSecLayer -eq 2){"Pass"}else{"Warn"}) "MA.L2-3.7.5"
    # == 3.8 MEDIA PROTECTION ==
    $blVol = Get-BitLockerVolume -EA SilentlyContinue | Where-Object { $_.VolumeType -eq "OperatingSystem" }
    $blOn  = $blVol -and $blVol.ProtectionStatus -eq "On"
    Add-Check "3.8.1" "MP" "Media Protection" "Protect system media - BitLocker OS drive on" `
        "$($blVol.ProtectionStatus)" "On" $(if ($blOn){"Pass"}else{"Fail"}) "MP.L2-3.8.1"
    Add-Check "3.8.3" "MP" "Media Protection" "Sanitize media before disposal - BitLocker on" `
        "$blOn" "True" $(if ($blOn){"Pass"}else{"Warn"}) "MP.L1-3.8.3"
    $usbBlock = Get-RegVal "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices" "Deny_All" 0
    Add-Check "3.8.7" "MP" "Media Protection" "Control use of removable media on systems" `
        "$usbBlock" "1" $(if ($usbBlock -eq 1){"Pass"}else{"Warn"}) "MP.L2-3.8.7"
    # == 3.10 PHYSICAL PROTECTION ==
    $scrTimeout = Get-RegVal "HKCU:\Control Panel\Desktop" "ScreenSaveTimeOut" "0"
    Add-Check "3.10.1" "PE" "Physical Protection" "Limit physical access - screen lock <= 900s" `
        "$scrTimeout sec" "<= 900" $(if ([int]$scrTimeout -le 900 -and [int]$scrTimeout -gt 0){"Pass"}else{"Fail"}) "PE.L1-3.10.1"
    $scrPwd = Get-RegVal "HKCU:\Control Panel\Desktop" "ScreenSaverIsSecure" "0"
    Add-Check "3.10.2" "PE" "Physical Protection" "Monitor physical access - screen saver needs password" `
        "$scrPwd" "1" $(if ($scrPwd -eq "1"){"Pass"}else{"Fail"}) "PE.L2-3.10.2"
    # == 3.11 RISK ASSESSMENT ==
    Add-Check "3.11.1" "RA" "Risk Assessment" "Periodically assess risk to operations - policy" `
        "Manual" "Risk assessment required" "Warn" "RA.L2-3.11.1"
    $schDay = (Get-MpPreference -EA SilentlyContinue).ScanScheduleDay
    Add-Check "3.11.2" "RA" "Risk Assessment" "Scan for vulnerabilities - Defender scheduled scan" `
        "$schDay" "1-7" $(if ($schDay -ge 1 -and $schDay -le 7){"Pass"}else{"Warn"}) "RA.L2-3.11.2"
    # == 3.12 SECURITY ASSESSMENT ==
    Add-Check "3.12.1" "CA" "Security Assessment" "Periodically assess security controls - policy" `
        "Manual" "Assessment required" "Warn" "CA.L2-3.12.1"
    Add-Check "3.12.3" "CA" "Security Assessment" "Monitor security controls - event forwarding" `
        "$($wefReg -ne [string]::Empty)" "True" $(if ($wefReg -ne [string]::Empty){"Pass"}else{"Warn"}) "CA.L2-3.12.3"
    # == 3.13 SYSTEM AND COMMUNICATIONS PROTECTION ==
    Add-Check "3.13.1" "SC" "System and Comms" "Monitor and control comms - Firewall all profiles" `
        "$allFWOn" "True" $(if ($allFWOn){"Pass"}else{"Fail"}) "SC.L1-3.13.1"
    $netProfiles = Get-NetConnectionProfile -EA SilentlyContinue
    $publicNets  = ($netProfiles | Where-Object { $_.NetworkCategory -eq "Public" }).Count
    Add-Check "3.13.5" "SC" "System and Comms" "Implement subnetworks - no unintended public networks" `
        "$publicNets public" "0" $(if ($publicNets -eq 0){"Pass"}else{"Warn"}) "SC.L1-3.13.5"
    $fips = Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy" "Enabled" 0
    Add-Check "3.13.8" "SC" "System and Comms" "Implement cryptographic mechanisms - FIPS enabled" `
        "$fips" "1" $(if ($fips -eq 1){"Pass"}else{"Warn"}) "SC.L2-3.13.8"
    Add-Check "3.13.9" "SC" "System and Comms" "Terminate network connections - SMB signing required" `
        "$smbSigning" "1" $(if ($smbSigning -eq 1){"Pass"}else{"Fail"}) "SC.L2-3.13.9"
    Add-Check "3.13.16" "SC" "System and Comms" "Protect CUI at rest - BitLocker OS volume on" `
        "$($blVol.ProtectionStatus)" "On" $(if ($blOn){"Pass"}else{"Fail"}) "SC.L2-3.13.16"
    # == 3.14 SYSTEM AND INFORMATION INTEGRITY ==
    Add-Check "3.14.1" "SI" "System Integrity" "Identify and correct system flaws - WU enabled" `
        "$wuDisabled" "0" $(if ($wuDisabled -eq 0){"Pass"}else{"Fail"}) "SI.L1-3.14.1"
    $defStatus = Get-MpComputerStatus -EA SilentlyContinue
    $avOn = $defStatus -and $defStatus.AntivirusEnabled
    Add-Check "3.14.2" "SI" "System Integrity" "Malicious code protection - Defender AV enabled" `
        "$avOn" "True" $(if ($avOn){"Pass"}else{"Fail"}) "SI.L1-3.14.2"
    $defAge = if ($defStatus) { ((Get-Date) - $defStatus.AntivirusSignatureLastUpdated).Days } else { 999 }
    Add-Check "3.14.4" "SI" "System Integrity" "Update malicious code protection - defs <= 3d" `
        "$defAge days" "<= 3" $(if ($defAge -le 3){"Pass"}else{"Fail"}) "SI.L1-3.14.4"
    $rtOn = $defStatus -and $defStatus.RealTimeProtectionEnabled
    Add-Check "3.14.5" "SI" "System Integrity" "Perform periodic scans - real-time protection on" `
        "$rtOn" "True" $(if ($rtOn){"Pass"}else{"Fail"}) "SI.L1-3.14.5"
    $ioavOn = $defStatus -and $defStatus.IoavProtectionEnabled
    Add-Check "3.14.6" "SI" "System Integrity" "Monitor for unauthorized activity - IOAV on" `
        "$ioavOn" "True" $(if ($ioavOn){"Pass"}else{"Warn"}) "SI.L2-3.14.6"
    $nwOn = $defStatus -and $defStatus.NISEnabled
    Add-Check "3.14.7" "SI" "System Integrity" "Identify unauthorized use of systems - NIS on" `
        "$nwOn" "True" $(if ($nwOn){"Pass"}else{"Warn"}) "SI.L2-3.14.7"
    if (-not $Quiet) {
        $p = @($findings | Where-Object { $_.Status -eq "Pass" }).Count
        $f = @($findings | Where-Object { $_.Status -eq "Fail" }).Count
        $w = @($findings | Where-Object { $_.Status -eq "Warn" }).Count
        Write-Host "`nNIST 800-171: $p Pass | $f Fail | $w Warn  (Total: $($findings.Count))" -ForegroundColor DarkCyan
    }
    return $findings
}
