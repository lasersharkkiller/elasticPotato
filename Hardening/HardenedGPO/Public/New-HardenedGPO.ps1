function New-HardenedGPO {
<#
.SYNOPSIS
    Generates a ready-to-import hardened GPO backup for a given environment profile.

.DESCRIPTION
    Builds a complete GPO backup folder structure (GptTmpl.inf, gpt.ini, bkupInfo.xml,
    manifest.xml, registry.pol) from a pre-built CIS/STIG-aligned security template.
    No scanning required. Output can be imported directly with Import-GPO on a DC.

    Profiles available:
      Workstation     - Windows 10/11 endpoints
      Server          - Windows Server member servers
      DomainController- Active Directory Domain Controllers (link to Domain Controllers OU only)
      All             - Generates one GPO backup per profile in a single run

.PARAMETER Profile
    Target environment. Workstation | Server | DomainController | All

.PARAMETER OutputPath
    Root output directory. A subfolder per profile will be created inside.
    Defaults to .\HardenedGPO_Output

.PARAMETER GPONamePrefix
    Prefix for the GPO display name. Profile name is appended automatically.
    Default: "Hardened-Baseline"  ---  e.g. "Hardened-Baseline-Workstation"

.EXAMPLE
    New-HardenedGPO -Profile Workstation -OutputPath C:\GPOExport

.EXAMPLE
    New-HardenedGPO -Profile All -OutputPath C:\GPOExport -GPONamePrefix "Corp"

.OUTPUTS
    PSCustomObject[] - one per profile generated, with: Profile, GPOName, GPOGuid, BackupPath

.NOTES
    To import on a Domain Controller (GPMC RSAT required):

        Import-GPO `
          -BackupGpoName "Hardened-Baseline-Workstation" `
          -Path "C:\GPOExport\Workstation\GPOBackup" `
          -TargetName "Hardened-Baseline-Workstation" `
          -CreateIfNeeded

    Link to OU:
        New-GPLink -Name "Hardened-Baseline-Workstation" `
                   -Target "OU=Workstations,DC=corp,DC=example,DC=com" `
                   -Enforced Yes

    --- NEVER link the DomainController GPO to regular computer OUs.
      Link it only to: "OU=Domain Controllers,DC=corp,DC=example,DC=com"
#>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet("Workstation","Server","DomainController","All")]
        [string]$Profile,

        [string]$OutputPath     = ".\HardenedGPO_Output",
        [string]$GPONamePrefix  = "Hardened-Baseline"
    )

    # Load all profile definitions from the Profiles folder
    $profilesDir = Join-Path $PSScriptRoot "..\Profiles"
    $profileDefs = @{}
    foreach ($f in (Get-ChildItem "$profilesDir\*.ps1" -ErrorAction SilentlyContinue)) {
        $def = . $f.FullName
        $profileDefs[$def.ProfileName] = $def
    }

    $profilesToBuild = if ($Profile -eq "All") {
        @("Workstation","Server","DomainController")
    } else {
        @($Profile)
    }

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($prof in $profilesToBuild) {
        $def = $profileDefs[$prof]
        if (-not $def) {
            Write-Warn "Profile definition not found for '$prof' - skipping."
            continue
        }

        $gpoName    = "$GPONamePrefix-$prof"
        $gpoGuid    = [System.Guid]::NewGuid().ToString("B").ToUpper()
        $backupGuid = [System.Guid]::NewGuid().ToString("B").ToUpper()
        $profRoot   = Join-Path $OutputPath $prof
        $backupRoot = Join-Path $profRoot "GPOBackup"
        $gpoDir     = Join-Path $backupRoot $gpoGuid
        $sysvolDir  = Join-Path $gpoDir "DomainSysvol\GPO\Machine\Microsoft\Windows NT\SecEdit"
        $machineDir = Join-Path $gpoDir "DomainSysvol\GPO\Machine"
        $gpoIniDir  = Join-Path $gpoDir "DomainSysvol\GPO"

        foreach ($d in @($sysvolDir, $machineDir, $gpoIniDir)) {
            New-Item -ItemType Directory -Path $d -Force | Out-Null
        }

        Write-Host "`n--------- Building GPO: $gpoName ---------" -ForegroundColor Magenta

        # ------ GptTmpl.inf ------------------------------------------------------------------------------------------------------------------------------------------------------------------
        [System.IO.File]::WriteAllText(
            (Join-Path $sysvolDir "GptTmpl.inf"),
            $def.GptTmpl,
            [System.Text.Encoding]::Unicode
        )
        Write-Info "  GptTmpl.inf written  ($prof)"

        # ------ gpt.ini ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
        @"
[General]
Version=65537
displayName=$gpoName
"@ | Set-Content -Path (Join-Path $gpoIniDir "gpt.ini") -Encoding UTF8
        Write-Info "  gpt.ini written"

        # ------ bkupInfo.xml ------------------------------------------------------------------------------------------------------------------------------------------------------------------
        @"
<?xml version="1.0" encoding="utf-8"?>
<BackupInst xmlns="http://www.microsoft.com/GroupPolicy/GPOOperations/Manifest">
  <GPOGuid>$gpoGuid</GPOGuid>
  <GPODomain></GPODomain>
  <GPODomainGuid></GPODomainGuid>
  <GPOBackupID>$backupGuid</GPOBackupID>
  <GPODisplayName>$gpoName</GPODisplayName>
  <BackupTime>$(Get-Date -Format "yyyy-MM-ddTHH:mm:ss")</BackupTime>
  <GPOType>0</GPOType>
</BackupInst>
"@ | Set-Content -Path (Join-Path $gpoDir "bkupInfo.xml") -Encoding UTF8
        Write-Info "  bkupInfo.xml written"

        # ------ manifest.xml ------------------------------------------------------------------------------------------------------------------------------------------------------------------
        @"
<?xml version="1.0" encoding="utf-8"?>
<Backups xmlns="http://www.microsoft.com/GroupPolicy/GPOOperations/Manifest">
  <BackupInst>
    <GPOGuid>$gpoGuid</GPOGuid>
    <GPOBackupID>$backupGuid</GPOBackupID>
    <GPODisplayName>$gpoName</GPODisplayName>
    <BackupTime>$(Get-Date -Format "yyyy-MM-ddTHH:mm:ss")</BackupTime>
  </BackupInst>
</Backups>
"@ | Set-Content -Path (Join-Path $backupRoot "manifest.xml") -Encoding UTF8
        Write-Info "  manifest.xml written"

        # ------ registry.pol (PReg header placeholder) ------------------------------------------------------------------------------------
        [System.IO.File]::WriteAllBytes(
            (Join-Path $machineDir "registry.pol"),
            [byte[]](0x50,0x52,0x65,0x67,0x01,0x00,0x00,0x00)
        )
        Write-Info "  registry.pol written"

        Write-Pass "GPO '$gpoName' ready  ---  $backupRoot"

        $results.Add([PSCustomObject]@{
            Profile    = $prof
            GPOName    = $gpoName
            GPOGuid    = $gpoGuid
            BackupPath = $backupRoot
        })
    }

    # ------ Summary ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    Write-Host ""
    Write-Host "---------------------------------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor White
    Write-Host " GPO GENERATION COMPLETE" -ForegroundColor White
    Write-Host "---------------------------------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor White
    foreach ($r in $results) {
        Write-Host ("  {0,-20} {1}" -f $r.GPOName, $r.BackupPath) -ForegroundColor DarkCyan
    }
    Write-Host ""
    Write-Host " Import instructions:" -ForegroundColor Gray
    foreach ($r in $results) {
        $dcWarn = if ($r.Profile -eq "DomainController") { "  # --- Link to Domain Controllers OU ONLY" } else { "" }
        Write-Host @"
  # $($r.Profile)$dcWarn
  Import-GPO -BackupGpoName "$($r.GPOName)" -Path "$($r.BackupPath)" -TargetName "$($r.GPOName)" -CreateIfNeeded
"@ -ForegroundColor Gray
    }

    return $results.ToArray()
}
