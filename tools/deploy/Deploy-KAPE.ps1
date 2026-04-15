[CmdletBinding()]
param(
    [string[]]$Targets,
    [string]$TargetsFile,
    [string]$PackagePath,
    [string]$RemoteRoot = 'C:\IRTools',
    [switch]$ExpandZip,
    [pscredential]$Credential
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath 'Deploy-Common.ps1')

$toolsRoot = Split-Path -Path $PSScriptRoot -Parent
$candidatePaths = @(
    (Join-Path -Path $toolsRoot -ChildPath 'kape'),
    (Join-Path -Path $toolsRoot -ChildPath 'KAPE'),
    (Join-Path -Path $toolsRoot -ChildPath 'kape.zip'),
    (Join-Path -Path $toolsRoot -ChildPath 'KAPE.zip')
)

if (-not $PSBoundParameters.ContainsKey('PackagePath')) {
    try {
        $PackagePath = Resolve-LPPackagePath -CandidatePaths $candidatePaths -ToolName 'KAPE'
    }
    catch {
        Write-LPDeployStatus -Level Warn -Message $_.Exception.Message
        $PackagePath = (Read-Host 'Enter full path to offline KAPE package (folder or .zip)').Trim()
    }
}

if (-not $PSBoundParameters.ContainsKey('Targets') -and -not $PSBoundParameters.ContainsKey('TargetsFile')) {
    $Targets = Prompt-LPTargetInput -Prompt 'Enter remote Windows targets for KAPE (comma separated)'
}

$resolvedTargets = Resolve-LPTargets -Targets $Targets -TargetsFile $TargetsFile
if (-not $resolvedTargets -or $resolvedTargets.Count -eq 0) {
    throw 'No targets were provided for KAPE deployment.'
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

Write-LPDeployStatus -Level Info -Message "Deploying KAPE from $PackagePath"
$results = Invoke-LPWindowsDeployment -ToolName 'KAPE' -PackagePath $PackagePath -Targets $resolvedTargets -RemoteRoot $RemoteRoot -ToolSubFolder 'KAPE' -ExpandZip:$zipFlag -Credential $Credential
Show-LPDeploymentSummary -Results $results

Write-Host ''
Write-Host "Suggested next step: run KAPE remotely from '$RemoteRoot\KAPE' with your triage target set." -ForegroundColor DarkCyan
