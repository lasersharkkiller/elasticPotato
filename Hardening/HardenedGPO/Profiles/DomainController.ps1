# Profile: DomainController (Windows Server 2022 - AD DC)
# CIS Microsoft Windows Server 2022 Benchmark v1.0 - Level 1 + Level 2
# WARNING: Link ONLY to OU=Domain Controllers,DC=<domain>

@{
    ProfileName = "DomainController"
    Description = "Full CIS L1+L2 hardened baseline for Active Directory Domain Controllers. Link ONLY to the Domain Controllers OU."

    GptTmpl = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1

; ==============================================================================
; ACCOUNT POLICIES
; ==============================================================================
[System Access]
MinimumPasswordAge = 1
MaximumPasswordAge = 365
MinimumPasswordLength = 14
PasswordComplexity = 1
PasswordHistorySize = 24
ClearTextPassword = 0
LockoutBadCount = 5
ResetLockoutCount = 15
LockoutDuration = 15
RequireLogonToChangePassword = 0
ForceLogoffWhenHourExpire = 1
NewAdministratorName = "DomainAdmin"
NewGuestName = "DomainGuest"
EnableAdminAccount = 0
EnableGuestAccount = 0

[Event Audit]
AuditSystemEvents = 3
AuditLogonEvents = 3
AuditObjectAccess = 3
AuditPrivilegeUse = 3
AuditPolicyChange = 3
AuditAccountManage = 3
AuditProcessTracking = 1
AuditDSAccess = 3
AuditAccountLogon = 3

; ==============================================================================
; USER RIGHTS ASSIGNMENT
; ==============================================================================
[Privilege Rights]
SeTcbPrivilege =
SeBackupPrivilege = *S-1-5-32-544
SeCreatePagefilePrivilege = *S-1-5-32-544
SeCreateTokenPrivilege =
SeCreatePermanentPrivilege =
SeDebugPrivilege = *S-1-5-32-544
; DC: Deny network logon = Guests only (DCs need broader network access)
SeDenyNetworkLogonRight = *S-1-5-32-546
SeDenyBatchLogonRight = *S-1-5-32-546
SeDenyServiceLogonRight = *S-1-5-32-546
SeDenyInteractiveLogonRight = *S-1-5-32-546
SeDenyRemoteInteractiveLogonRight = *S-1-5-32-546
SeEnableDelegationPrivilege = *S-1-5-32-544
SeRemoteShutdownPrivilege = *S-1-5-32-544
SeAuditPrivilege = *S-1-5-19,*S-1-5-20
SeImpersonatePrivilege = *S-1-5-32-544,*S-1-5-19,*S-1-5-20,*S-1-5-6
SeShutdownPrivilege = *S-1-5-32-544
SeTakeOwnershipPrivilege = *S-1-5-32-544
SeRemoteInteractiveLogonRight = *S-1-5-32-544
SeCreateSymbolicLinkPrivilege = *S-1-5-32-544
SeRestorePrivilege = *S-1-5-32-544
; DC: Add workstations to domain - Admins only
SeMachineAccountPrivilege = *S-1-5-32-544

; ==============================================================================
; REGISTRY VALUES
; ==============================================================================
[Registry Values]

; --- Accounts ---
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableGuestAccount=4,0
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LimitBlankPasswordUse=4,1

; --- Audit ---
MACHINE\System\CurrentControlSet\Control\Lsa\CrashOnAuditFail=4,0

; --- DC-specific: LDAP signing and channel binding ---
MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity=4,2
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\LdapEnforceChannelBinding=4,1
; DC: Refuse machine account password changes = Disabled (allow changes)
MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\RefusePasswordChange=4,0

; --- DC-specific: Printer driver install ---
MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\AddPrinterDrivers=4,1

; --- Domain Member / Netlogon ---
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal=4,1
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel=4,1
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SignSecureChannel=4,1
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange=4,0
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge=4,30
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey=4,1

; --- Interactive Logon ---
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableCAD=4,0
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount=1,"4"
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordExpiryWarning=4,14
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ForceUnlockLogon=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLockedUserId=4,3
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableAutomaticRestartSignOn=4,1

; --- MS Network Client ---
MACHINE\System\CurrentControlSet\Services\LanManWorkstation\Parameters\RequireSecuritySignature=4,1
MACHINE\System\CurrentControlSet\Services\LanManWorkstation\Parameters\EnableSecuritySignature=4,1
MACHINE\System\CurrentControlSet\Services\LanManWorkstation\Parameters\EnablePlainTextPassword=4,0

; --- MS Network Server ---
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\AutoDisconnect=4,15
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature=4,1
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature=4,1
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableForcedLogOff=4,1
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\SmbServerNameHardeningLevel=4,1

; --- Network Access ---
MACHINE\System\CurrentControlSet\Control\Lsa\DisableDomainCreds=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\pku2u\AllowOnlineID=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\RestrictRemoteSAM=1,"O:BAG:BAD:(A;;RC;;;BA)"

; --- Network Security / NTLM ---
MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel=4,5
MACHINE\System\CurrentControlSet\Control\Lsa\LDAPClientIntegrity=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec=4,537395200
MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec=4,537395200
MACHINE\System\CurrentControlSet\Control\Lsa\RestrictSendingNTLMTraffic=4,2
MACHINE\System\CurrentControlSet\Control\Lsa\RestrictNTLMInDomain=4,7

; --- Kerberos encryption (DC: require AES, no DES/RC4) ---
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\SupportedEncryptionTypes=4,2147483640

; --- Shutdown ---
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ShutdownWithoutLogon=4,0

; --- System Objects ---
MACHINE\System\CurrentControlSet\Control\Session Manager\ProtectionMode=4,1

; --- UAC ---
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin=4,2
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser=4,0
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization=4,1

; --- Windows Firewall ---
MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\EnableFirewall=4,1
MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\DisableNotifications=4,1
MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultInboundAction=4,1
MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultOutboundAction=4,0
MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\EnableFirewall=4,1
MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\DefaultInboundAction=4,1
MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\DefaultOutboundAction=4,0
MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\EnableFirewall=4,1
MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\DefaultInboundAction=4,1
MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\DefaultOutboundAction=4,0
MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\AllowLocalPolicyMerge=4,0
MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogDroppedPackets=4,1
MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogSuccessfulConnections=4,1
MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogFileSize=4,16384
MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogDroppedPackets=4,1
MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogSuccessfulConnections=4,1
MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogFileSize=4,16384
MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogDroppedPackets=4,1
MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogSuccessfulConnections=4,1
MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogFileSize=4,16384

; --- MSS ---
MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel\DisableExceptionChainValidation=4,0
MACHINE\System\CurrentControlSet\Services\Tcpip6\Parameters\DisableIPSourceRouting=4,2
MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting=4,2
MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters\EnableICMPRedirect=4,0
MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters\PerformRouterDiscovery=4,0
MACHINE\System\CurrentControlSet\Control\Session Manager\SafeDllSearchMode=4,1
MACHINE\System\CurrentControlSet\Control\Session Manager\ScreenSaverGracePeriod=1,"5"
MACHINE\System\CurrentControlSet\Control\Lsa\WarningLevel=4,90
MACHINE\System\CurrentControlSet\Services\Netbt\Parameters\NoNameReleaseOnDemand=4,1
MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters\KeepAliveTime=4,300000
MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters\TcpMaxDataRetransmissions=4,3

; --- Network ---
MACHINE\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\\\*\NETLOGON=1,"RequireMutualAuthentication=1,RequireIntegrity=1"
MACHINE\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\\\*\SYSVOL=1,"RequireMutualAuthentication=1,RequireIntegrity=1"
MACHINE\Software\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast=4,0
MACHINE\Software\Policies\Microsoft\Windows NT\Printers\DisableWebPnPDownload=4,1
MACHINE\Software\Policies\Microsoft\Windows NT\Printers\DisableHTTPPrinting=4,1

; --- System ---
MACHINE\Software\Policies\Microsoft\Windows\System\DontDisplayNetworkSelectionUI=4,1
MACHINE\Software\Policies\Microsoft\Windows\System\DontEnumerateConnectedUsers=4,1
MACHINE\Software\Policies\Microsoft\Windows\System\EnumerateLocalUsers=4,0
MACHINE\Software\Policies\Microsoft\Windows\System\BlockUserFromShowingAccountDetailsOnSignin=4,1
MACHINE\Software\Policies\Microsoft\Windows\System\DisableLockScreenAppNotifications=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\PreXPSP2ShellProtocolBehavior=4,0

; --- AutoPlay ---
MACHINE\Software\Policies\Microsoft\Windows\Explorer\NoAutoplayfornonVolume=4,1
MACHINE\Software\Policies\Microsoft\Windows\Explorer\NoAutorun=4,1
MACHINE\Software\Policies\Microsoft\Windows\Explorer\NoDriveTypeAutoRun=4,255

; --- Credential UI ---
MACHINE\Software\Policies\Microsoft\Windows\CredUI\DisablePasswordReveal=4,1
MACHINE\Software\Policies\Microsoft\Windows\CredUI\EnumerateAdministrators=4,0

; --- Data Collection ---
MACHINE\Software\Policies\Microsoft\Windows\DataCollection\AllowTelemetry=4,1
MACHINE\Software\Policies\Microsoft\Windows\DataCollection\LimitEnhancedDiagnosticDataWindowsAnalytics=4,1
MACHINE\Software\Policies\Microsoft\Windows\DataCollection\DisableDiagnosticDataViewer=4,1

; --- Event Log ---
MACHINE\Software\Policies\Microsoft\Windows\EventLog\Application\MaxSize=4,32768
MACHINE\Software\Policies\Microsoft\Windows\EventLog\Security\MaxSize=4,196608
MACHINE\Software\Policies\Microsoft\Windows\EventLog\Setup\MaxSize=4,32768
MACHINE\Software\Policies\Microsoft\Windows\EventLog\System\MaxSize=4,32768

; --- Device Guard / VBS ---
MACHINE\Software\Policies\Microsoft\Windows\DeviceGuard\EnableVirtualizationBasedSecurity=4,1
MACHINE\Software\Policies\Microsoft\Windows\DeviceGuard\RequirePlatformSecurityFeatures=4,3
MACHINE\Software\Policies\Microsoft\Windows\DeviceGuard\HypervisorEnforcedCodeIntegrity=4,1
MACHINE\Software\Policies\Microsoft\Windows\DeviceGuard\LsaCfgFlags=4,1

; --- PowerShell ---
MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging=4,1
MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockInvocationLogging=4,1
MACHINE\Software\Policies\Microsoft\Windows\PowerShell\Transcription\EnableTranscripting=4,1
MACHINE\Software\Policies\Microsoft\Windows\PowerShell\Transcription\EnableInvocationHeader=4,1
MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\EnableModuleLogging=4,1

; --- RDP ---
MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services\fEncryptionLevel=4,3
MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services\fDisableCdm=4,1
MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services\UserAuthentication=4,1
MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services\SecurityLayer=4,2
MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services\MaxIdleTime=4,900000
MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services\MaxDisconnectionTime=4,60000
MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services\fDisableAutomaticReconnect=4,1

; --- WinRM ---
MACHINE\Software\Policies\Microsoft\Windows\WinRM\Client\AllowBasic=4,0
MACHINE\Software\Policies\Microsoft\Windows\WinRM\Client\AllowUnencryptedTraffic=4,0
MACHINE\Software\Policies\Microsoft\Windows\WinRM\Client\AllowDigest=4,0
MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service\AllowBasic=4,0
MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service\AllowUnencryptedTraffic=4,0
MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service\DisableRunAs=4,1

; --- Windows Installer ---
MACHINE\Software\Policies\Microsoft\Windows\Installer\EnableUserControl=4,0
MACHINE\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated=4,0

; --- Windows Update ---
MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoUpdate=4,0
MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\AUOptions=4,4
MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\AutoInstallMinorUpdates=4,1
MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\DeferFeatureUpdates=4,1
MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\SetDisablePauseUXAccess=4,1
MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\SetDisableUXWUAccess=4,1

; --- Credential Guard / WDigest ---
MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\RunAsPPL=4,1

; --- SMB v1 ---
MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters\SMB1=4,0

; ==============================================================================
; SERVICES
; (Note: Spooler left as-is on DCs - disabling breaks DC functionality)
; ==============================================================================
[Service General Setting]
Browser,4,"D:AR"
irmon,4,"D:AR"
MSiSCSI,4,"D:AR"
PNRPsvc,4,"D:AR"
p2psvc,4,"D:AR"
p2pimsvc,4,"D:AR"
PNRPAutoReg,4,"D:AR"
wercplsupport,4,"D:AR"
RasAuto,4,"D:AR"
RemoteRegistry,4,"D:AR"
RemoteAccess,4,"D:AR"
simptcp,4,"D:AR"
SNMPTRAP,4,"D:AR"
SSDPSRV,4,"D:AR"
upnphost,4,"D:AR"
WerSvc,4,"D:AR"
WMPNetworkSvc,4,"D:AR"
WpnService,4,"D:AR"
Telnet,4,"D:AR"
FTPSVC,4,"D:AR"
IISADMIN,4,"D:AR"
W3SVC,4,"D:AR"
MSFTPSVC,4,"D:AR"
"@
}
