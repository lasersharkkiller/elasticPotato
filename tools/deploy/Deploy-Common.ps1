Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-LPDeployStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Message,
        [ValidateSet('Info','Warn','Error','Success')] [string]$Level = 'Info'
    )

    $color = switch ($Level) {
        'Info'    { 'Cyan' }
        'Warn'    { 'Yellow' }
        'Error'   { 'Red' }
        'Success' { 'Green' }
    }

    Write-Host "[Deploy] $Message" -ForegroundColor $color
}

function Get-LPFirstExistingPath {
    [CmdletBinding()]
    param([string[]]$CandidatePaths)

    foreach ($candidate in @($CandidatePaths)) {
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
        if (Test-Path -LiteralPath $candidate) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }

    return $null
}

function Resolve-LPPackagePath {
    [CmdletBinding()]
    param(
        [string]$PreferredPath,
        [string[]]$CandidatePaths,
        [string]$ToolName = 'Package'
    )

    if (-not [string]::IsNullOrWhiteSpace($PreferredPath)) {
        if (-not (Test-Path -LiteralPath $PreferredPath)) {
            throw "Specified package path not found: $PreferredPath"
        }

        return (Resolve-Path -LiteralPath $PreferredPath).Path
    }

    $resolved = Get-LPFirstExistingPath -CandidatePaths $CandidatePaths
    if ($resolved) { return $resolved }

    $pathsText = if ($CandidatePaths) { ($CandidatePaths -join ', ') } else { '<none>' }
    throw "Could not locate an offline package for $ToolName. Checked: $pathsText"
}

function Resolve-LPTargets {
    [CmdletBinding()]
    param(
        [string[]]$Targets,
        [string]$TargetsFile
    )

    $resolved = @()

    foreach ($entry in @($Targets)) {
        if ([string]::IsNullOrWhiteSpace($entry)) { continue }
        $resolved += ($entry -split ',')
    }

    if (-not [string]::IsNullOrWhiteSpace($TargetsFile)) {
        if (-not (Test-Path -LiteralPath $TargetsFile)) {
            throw "Targets file not found: $TargetsFile"
        }

        $resolved += Get-Content -LiteralPath $TargetsFile -ErrorAction Stop |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    }

    $resolved |
        ForEach-Object { $_.Trim() } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Select-Object -Unique
}

function Prompt-LPTargetInput {
    [CmdletBinding()]
    param([string]$Prompt = 'Enter target hosts (comma separated)')

    $inputTargets = (Read-Host $Prompt).Trim()
    if ([string]::IsNullOrWhiteSpace($inputTargets)) {
        throw 'No targets specified.'
    }

    return ($inputTargets -split ',') |
        ForEach-Object { $_.Trim() } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Select-Object -Unique
}

function Invoke-LPWindowsDeployment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$ToolName,
        [Parameter(Mandatory)] [string]$PackagePath,
        [Parameter(Mandatory)] [string[]]$Targets,
        [string]$RemoteRoot = 'C:\IRTools',
        [string]$ToolSubFolder,
        [switch]$ExpandZip,
        [pscredential]$Credential
    )

    if ([string]::IsNullOrWhiteSpace($ToolSubFolder)) {
        $ToolSubFolder = $ToolName
    }

    if ($RemoteRoot -notmatch '^(?<drive>[A-Za-z]):\\?(?<rest>.*)$') {
        throw "RemoteRoot must be a local drive path like C:\IRTools. Received: $RemoteRoot"
    }

    $driveLetter = $Matches['drive'].ToUpper()
    $rootRemainder = $Matches['rest'].TrimStart('\\')

    $resolvedPackage = (Resolve-Path -LiteralPath $PackagePath).Path
    $isDirectory = (Get-Item -LiteralPath $resolvedPackage).PSIsContainer

    $preparedSource = $resolvedPackage
    $temporaryExtract = $null

    if (-not $isDirectory -and $ExpandZip -and [System.IO.Path]::GetExtension($resolvedPackage).ToLowerInvariant() -eq '.zip') {
        $temporaryExtract = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ("LPDeploy_{0}" -f ([Guid]::NewGuid().ToString('N')))
        New-Item -Path $temporaryExtract -ItemType Directory -Force | Out-Null
        Expand-Archive -LiteralPath $resolvedPackage -DestinationPath $temporaryExtract -Force
        $preparedSource = $temporaryExtract
        $isDirectory = $true
        Write-LPDeployStatus -Level Info -Message "Expanded ZIP package locally for deployment: $resolvedPackage"
    }

    $results = @()

    foreach ($target in $Targets) {
        if ([string]::IsNullOrWhiteSpace($target)) { continue }

        $remoteToolPath = if ([string]::IsNullOrWhiteSpace($rootRemainder)) {
            "$driveLetter`:\$ToolSubFolder"
        } else {
            "$driveLetter`:\$rootRemainder\$ToolSubFolder"
        }

        $uncRoot = "\\$target\$($driveLetter)$"
        $driveName = "LP{0}" -f ([Guid]::NewGuid().ToString('N').Substring(0, 6))

        try {
            if ($Credential) {
                New-PSDrive -Name $driveName -PSProvider FileSystem -Root $uncRoot -Credential $Credential -Scope Script | Out-Null
                $shareRoot = "$driveName`:"
            } else {
                $shareRoot = $uncRoot
            }

            $shareTarget = if ([string]::IsNullOrWhiteSpace($rootRemainder)) {
                Join-Path -Path $shareRoot -ChildPath $ToolSubFolder
            } else {
                Join-Path -Path $shareRoot -ChildPath (Join-Path -Path $rootRemainder -ChildPath $ToolSubFolder)
            }

            New-Item -Path $shareTarget -ItemType Directory -Force | Out-Null

            if ($isDirectory) {
                Get-ChildItem -LiteralPath $preparedSource -Force | ForEach-Object {
                    Copy-Item -LiteralPath $_.FullName -Destination $shareTarget -Recurse -Force
                }
            } else {
                Copy-Item -LiteralPath $preparedSource -Destination $shareTarget -Force
            }

            $results += [pscustomobject]@{
                Tool       = $ToolName
                Target     = $target
                Status     = 'Success'
                RemotePath = $remoteToolPath
                Notes      = if ($isDirectory) { 'Directory package copied.' } else { 'File package copied.' }
            }

            Write-LPDeployStatus -Level Success -Message "$ToolName copied to $target at $remoteToolPath"
        }
        catch {
            $results += [pscustomobject]@{
                Tool       = $ToolName
                Target     = $target
                Status     = 'Failed'
                RemotePath = $remoteToolPath
                Notes      = $_.Exception.Message
            }

            Write-LPDeployStatus -Level Error -Message "$ToolName failed on ${target}: $($_.Exception.Message)"
        }
        finally {
            if (Get-PSDrive -Name $driveName -ErrorAction SilentlyContinue) {
                Remove-PSDrive -Name $driveName -Force -ErrorAction SilentlyContinue
            }
        }
    }

    if ($temporaryExtract -and (Test-Path -LiteralPath $temporaryExtract)) {
        Remove-Item -LiteralPath $temporaryExtract -Recurse -Force -ErrorAction SilentlyContinue
    }

    return $results
}

function Invoke-LPLinuxSshDeployment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$ToolName,
        [Parameter(Mandatory)] [string]$PackagePath,
        [Parameter(Mandatory)] [string[]]$Targets,
        [Parameter(Mandatory)] [string]$SshUser,
        [string]$RemotePath = '/opt/irtools',
        [int]$SshPort = 22,
        [switch]$AutoExtractArchive
    )

    $scpCmd = Get-Command scp.exe -ErrorAction SilentlyContinue
    if (-not $scpCmd) { $scpCmd = Get-Command scp -ErrorAction SilentlyContinue }

    $sshCmd = Get-Command ssh.exe -ErrorAction SilentlyContinue
    if (-not $sshCmd) { $sshCmd = Get-Command ssh -ErrorAction SilentlyContinue }

    if (-not $scpCmd -or -not $sshCmd) {
        throw 'OpenSSH client tools were not found (ssh/scp). Install OpenSSH client or deploy Linux packages manually.'
    }

    $resolvedPackage = (Resolve-Path -LiteralPath $PackagePath).Path
    $isDirectory = (Get-Item -LiteralPath $resolvedPackage).PSIsContainer
    $archiveExtensions = @('.zip', '.tar', '.gz', '.tgz', '.tar.gz')

    $results = @()

    foreach ($target in $Targets) {
        if ([string]::IsNullOrWhiteSpace($target)) { continue }

        $remoteEndpoint = "$SshUser@$target"
        $remoteToolPath = ($RemotePath.TrimEnd('/')) + '/' + $ToolName

        try {
            & $sshCmd.Source '-p' $SshPort $remoteEndpoint "mkdir -p '$remoteToolPath'"
            if ($LASTEXITCODE -ne 0) {
                throw "SSH pre-check failed while creating $remoteToolPath"
            }

            if ($isDirectory) {
                & $scpCmd.Source '-P' $SshPort '-r' $resolvedPackage "${remoteEndpoint}:$remoteToolPath"
                if ($LASTEXITCODE -ne 0) {
                    throw 'SCP directory transfer failed.'
                }

                $note = 'Directory copied with scp -r. Verify final directory nesting on host.'
            }
            else {
                $leaf = Split-Path -Path $resolvedPackage -Leaf
                $remoteFile = "$remoteToolPath/$leaf"

                & $scpCmd.Source '-P' $SshPort $resolvedPackage "${remoteEndpoint}:$remoteFile"
                if ($LASTEXITCODE -ne 0) {
                    throw 'SCP file transfer failed.'
                }

                $note = 'Package file copied.'

                if ($AutoExtractArchive) {
                    $ext = [System.IO.Path]::GetExtension($leaf).ToLowerInvariant()
                    if ($leaf.ToLowerInvariant().EndsWith('.tar.gz') -or $ext -eq '.tgz') {
                        & $sshCmd.Source '-p' $SshPort $remoteEndpoint "tar -xzf '$remoteFile' -C '$remoteToolPath'"
                        if ($LASTEXITCODE -eq 0) { $note = 'Package copied and extracted with tar.' }
                    }
                    elseif ($archiveExtensions -contains $ext -or $leaf.ToLowerInvariant().EndsWith('.zip')) {
                        & $sshCmd.Source '-p' $SshPort $remoteEndpoint "command -v unzip >/dev/null 2>&1 && unzip -o '$remoteFile' -d '$remoteToolPath'"
                        if ($LASTEXITCODE -eq 0) { $note = 'Package copied and extracted with unzip.' }
                    }
                }
            }

            $results += [pscustomobject]@{
                Tool       = $ToolName
                Target     = $target
                Status     = 'Success'
                RemotePath = $remoteToolPath
                Notes      = $note
            }

            Write-LPDeployStatus -Level Success -Message "$ToolName copied to Linux target $target at $remoteToolPath"
        }
        catch {
            $results += [pscustomobject]@{
                Tool       = $ToolName
                Target     = $target
                Status     = 'Failed'
                RemotePath = $remoteToolPath
                Notes      = $_.Exception.Message
            }

            Write-LPDeployStatus -Level Error -Message "$ToolName failed on Linux target ${target}: $($_.Exception.Message)"
        }
    }

    return $results
}

function Show-LPDeploymentSummary {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object[]]$Results)

    Write-Host ''
    Write-Host 'Deployment Summary:' -ForegroundColor Cyan
    $Results | Format-Table Tool, Target, Status, RemotePath, Notes -AutoSize

    $failed = @($Results | Where-Object { $_.Status -ne 'Success' }).Count
    if ($failed -gt 0) {
        Write-LPDeployStatus -Level Warn -Message "$failed target(s) had deployment issues."
    } else {
        Write-LPDeployStatus -Level Success -Message 'All targets completed successfully.'
    }
}
