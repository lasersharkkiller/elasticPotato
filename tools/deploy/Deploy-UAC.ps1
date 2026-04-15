[CmdletBinding()]
param(
    [ValidateSet('Linux','Windows')] [string]$Platform,
    [string[]]$Targets,
    [string]$TargetsFile,
    [string]$PackagePath,
    [string]$RemoteRoot,
    [string]$SshUser,
    [int]$SshPort = 22,
    [switch]$AutoExtractArchive,
    [switch]$ExpandZip,
    [pscredential]$Credential
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath 'Deploy-Common.ps1')

$toolsRoot = Split-Path -Path $PSScriptRoot -Parent
$candidatePaths = @(
    (Join-Path -Path $toolsRoot -ChildPath 'uac'),
    (Join-Path -Path $toolsRoot -ChildPath 'UAC'),
    (Join-Path -Path $toolsRoot -ChildPath 'uac.tar.gz'),
    (Join-Path -Path $toolsRoot -ChildPath 'uac.tgz'),
    (Join-Path -Path $toolsRoot -ChildPath 'uac.zip')
)

if (-not $PSBoundParameters.ContainsKey('PackagePath')) {
    try {
        $PackagePath = Resolve-LPPackagePath -CandidatePaths $candidatePaths -ToolName 'UAC'
    }
    catch {
        Write-LPDeployStatus -Level Warn -Message $_.Exception.Message
        $PackagePath = (Read-Host 'Enter full path to offline UAC package (folder or archive)').Trim()
    }
}

if (-not $PSBoundParameters.ContainsKey('Platform')) {
    $platformInput = (Read-Host 'Deploy UAC to Linux or Windows targets? [Linux/Windows, default Linux]').Trim()
    if ([string]::IsNullOrWhiteSpace($platformInput)) {
        $Platform = 'Linux'
    } else {
        $Platform = ($platformInput.Substring(0,1).ToUpper() + $platformInput.Substring(1).ToLower())
    }
}

if (-not $PSBoundParameters.ContainsKey('Targets') -and -not $PSBoundParameters.ContainsKey('TargetsFile')) {
    $Targets = Prompt-LPTargetInput -Prompt "Enter remote $Platform targets for UAC deployment (comma separated)"
}

$resolvedTargets = Resolve-LPTargets -Targets $Targets -TargetsFile $TargetsFile
if (-not $resolvedTargets -or $resolvedTargets.Count -eq 0) {
    throw 'No targets were provided for UAC deployment.'
}

if ($Platform -eq 'Linux') {
    if (-not $PSBoundParameters.ContainsKey('SshUser') -or [string]::IsNullOrWhiteSpace($SshUser)) {
        $SshUser = (Read-Host 'Linux SSH username for deployment').Trim()
    }

    if ([string]::IsNullOrWhiteSpace($SshUser)) {
        throw 'SSH username is required for Linux deployment.'
    }

    if (-not $PSBoundParameters.ContainsKey('RemoteRoot') -or [string]::IsNullOrWhiteSpace($RemoteRoot)) {
        $RemoteRoot = '/opt/irtools'
    }

    if (-not $PSBoundParameters.ContainsKey('AutoExtractArchive')) {
        $extractChoice = (Read-Host 'Auto-extract archives on Linux host (if tools available)? [Y/n]').Trim()
        if ($extractChoice -match '^[nN]') {
            $AutoExtractArchive = $false
        } else {
            $AutoExtractArchive = $true
        }
    }

    Write-LPDeployStatus -Level Info -Message "Deploying UAC to Linux targets from $PackagePath"
    $results = Invoke-LPLinuxSshDeployment -ToolName 'UAC' -PackagePath $PackagePath -Targets $resolvedTargets -SshUser $SshUser -RemotePath $RemoteRoot -SshPort $SshPort -AutoExtractArchive:$AutoExtractArchive
    Show-LPDeploymentSummary -Results $results

    Write-Host ''
    Write-Host "Suggested next step: execute the UAC collection command on each host from '$RemoteRoot/UAC'." -ForegroundColor DarkCyan
}
else {
    if (-not $PSBoundParameters.ContainsKey('RemoteRoot') -or [string]::IsNullOrWhiteSpace($RemoteRoot)) {
        $RemoteRoot = 'C:\IRTools'
    }

    if (-not $PSBoundParameters.ContainsKey('Credential')) {
        $credPrompt = (Read-Host 'Use alternate credential for SMB copy? [y/N]').Trim()
        if ($credPrompt -match '^[yY]') {
            $Credential = Get-Credential -Message 'Credential for remote admin share (example: DOMAIN\User)'
        }
    }

    $zipFlag = $ExpandZip
    if (-not $PSBoundParameters.ContainsKey('ExpandZip')) {
        $autoExpandPrompt = (Read-Host 'Expand ZIP package before copy? [Y/n]').Trim()
        if ($autoExpandPrompt -match '^[nN]') {
            $zipFlag = $false
        } else {
            $zipFlag = $true
        }
    }

    Write-LPDeployStatus -Level Info -Message "Deploying UAC package to Windows targets from $PackagePath"
    $results = Invoke-LPWindowsDeployment -ToolName 'UAC' -PackagePath $PackagePath -Targets $resolvedTargets -RemoteRoot $RemoteRoot -ToolSubFolder 'UAC' -ExpandZip:$zipFlag -Credential $Credential
    Show-LPDeploymentSummary -Results $results

    Write-Host ''
    Write-Host "Suggested next step: run the UAC collector from '$RemoteRoot\UAC' on each target." -ForegroundColor DarkCyan
}
