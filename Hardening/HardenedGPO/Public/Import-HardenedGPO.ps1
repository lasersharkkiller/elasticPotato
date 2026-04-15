function Import-HardenedGPO {
<#
.SYNOPSIS
    Imports a HardenedGPO backup into Active Directory and optionally links it to an OU.

.DESCRIPTION
    Wraps Import-GPO and (optionally) New-GPLink. Must run on a Domain Controller
    or a machine with GPMC RSAT installed and domain connectivity.
    Accepts pipeline input from New-HardenedGPO.

.PARAMETER BackupPath
    Path to the GPOBackup folder produced by New-HardenedGPO.

.PARAMETER GPOName
    The GPO display name to use in AD. Will be created if it doesn't exist.

.PARAMETER TargetOU
    Distinguished name of the OU to link to after import (optional).

.PARAMETER Enforced
    Set the GPO link as Enforced. Default: false.

.PARAMETER InputObject
    Accepts pipeline input from New-HardenedGPO (PSCustomObject with BackupPath and GPOName).

.EXAMPLE
    Import-HardenedGPO -BackupPath "C:\GPOExport\Workstation\GPOBackup" `
                       -GPOName "Hardened-Baseline-Workstation" `
                       -TargetOU "OU=Workstations,DC=corp,DC=example,DC=com"

.EXAMPLE
    New-HardenedGPO -Profile All -OutputPath C:\GPOExport | Import-HardenedGPO

.NOTES
    Requires RSAT GroupPolicy module:
      Add-WindowsCapability -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0 -Online
    --- DomainController profile must ONLY be linked to the Domain Controllers OU.
#>
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName="Explicit")]
    param(
        [Parameter(Mandatory, ParameterSetName="Explicit")]
        [string]$BackupPath,

        [Parameter(Mandatory, ParameterSetName="Explicit")]
        [string]$GPOName,

        [Parameter(ValueFromPipeline, ParameterSetName="Pipeline")]
        [PSCustomObject]$InputObject,

        [string]$TargetOU,
        [switch]$Enforced
    )

    process {
        # Resolve parameters from pipeline or explicit
        if ($PSCmdlet.ParameterSetName -eq "Pipeline" -and $InputObject) {
            $BackupPath = $InputObject.BackupPath
            $GPOName    = $InputObject.GPOName
            $prof       = $InputObject.Profile
        } else {
            $prof = ""
        }

        if ($prof -eq "DomainController" -and -not $TargetOU) {
            Write-Warn "DomainController profile: ensure you link this only to 'OU=Domain Controllers,DC=...' - not regular OUs."
        }

        # Verify RSAT module
        if (-not (Get-Module -Name GroupPolicy -ListAvailable -ErrorAction SilentlyContinue)) {
            throw "GroupPolicy RSAT module not found. Run: Add-WindowsCapability -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0 -Online"
        }
        Import-Module GroupPolicy -ErrorAction Stop

        if (-not (Test-Path $BackupPath)) {
            throw "BackupPath not found: $BackupPath"
        }

        Write-Info "Importing '$GPOName' from $BackupPath ..."

        if ($PSCmdlet.ShouldProcess($GPOName, "Import-GPO")) {
            $gpo = Import-GPO `
                -BackupGpoName $GPOName `
                -Path          $BackupPath `
                -TargetName    $GPOName `
                -CreateIfNeeded `
                -ErrorAction Stop
            Write-Pass "Imported: '$($gpo.DisplayName)'  [ID: $($gpo.Id)]"
        }

        if ($TargetOU) {
            Write-Info "Linking to: $TargetOU  (Enforced: $($Enforced.IsPresent))"
            if ($PSCmdlet.ShouldProcess($TargetOU, "New-GPLink")) {
                New-GPLink -Name $GPOName -Target $TargetOU -Enforced:($Enforced.IsPresent) -ErrorAction Stop | Out-Null
                Write-Pass "Linked to $TargetOU"
            }
        }

        Write-Info "Force update: Invoke-GPUpdate -Computer HOSTNAME -Force"
    }
}
