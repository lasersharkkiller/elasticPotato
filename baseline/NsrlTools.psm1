$script:ModuleRoot = $PSScriptRoot

function Get-PlatformClassification {
    param([string] $OsName)
    if ([string]::IsNullOrWhiteSpace($OsName)) { return 'Other' }
    if ($OsName -match '(?i)windows') { return 'Windows' }
    if ($OsName -match '(?i)linux|ubuntu|debian|centos|rhel|red\s*hat|fedora|suse|alpine|arch') { return 'Linux' }
    return 'Other'
}

function Install-Sqlite3Tool {
    [CmdletBinding()]
    param()

    $toolsDir = Join-Path $script:ModuleRoot 'tools/sqlite'
    $exePath  = Join-Path $toolsDir 'sqlite3.exe'

    if (Test-Path -LiteralPath $exePath) { return $exePath }

    if (-not (Test-Path -LiteralPath $toolsDir)) {
        New-Item -ItemType Directory -Force -Path $toolsDir | Out-Null
    }

    $downloadPage = 'https://www.sqlite.org/download.html'
    try {
        $page = Invoke-WebRequest -Uri $downloadPage -UseBasicParsing -ErrorAction Stop
    } catch {
        throw "Failed to fetch sqlite.org download page: $($_.Exception.Message)"
    }

    $rel = $null
    if ($page.Content -match 'href="(?<u>\d{4}/sqlite-tools-win(?:-x64)?-[0-9]+\.zip)"') {
        $rel = $Matches['u']
    }
    if (-not $rel) {
        throw "Could not locate sqlite tools archive in download page."
    }
    $zipUrl = "https://www.sqlite.org/$rel"
    $zipPath = Join-Path $env:TEMP ("sqlite-tools-{0}.zip" -f ([Guid]::NewGuid().ToString('N')))

    try {
        Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -UseBasicParsing -ErrorAction Stop
        $extractDir = Join-Path $env:TEMP ("sqlite-extract-{0}" -f ([Guid]::NewGuid().ToString('N')))
        New-Item -ItemType Directory -Force -Path $extractDir | Out-Null
        Expand-Archive -LiteralPath $zipPath -DestinationPath $extractDir -Force
        $found = Get-ChildItem -Path $extractDir -Filter 'sqlite3.exe' -Recurse | Select-Object -First 1
        if (-not $found) { throw "sqlite3.exe not found in downloaded archive." }
        Copy-Item -LiteralPath $found.FullName -Destination $exePath -Force
    } finally {
        if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force -ErrorAction SilentlyContinue }
        if ($extractDir -and (Test-Path -LiteralPath $extractDir)) {
            Remove-Item -LiteralPath $extractDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    return $exePath
}

function Get-NsrlDbPath {
    param([string] $InstallPath)
    if (-not (Test-Path -LiteralPath $InstallPath)) { return $null }
    $db = Get-ChildItem -Path $InstallPath -Filter '*.db' -File -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($db) { return $db.FullName }
    return $null
}

function Invoke-Sqlite {
    param(
        [string] $Sqlite,
        [string] $DbPath,
        [string] $Query
    )
    $output = & $Sqlite -separator "`t" $DbPath $Query
    if ($LASTEXITCODE -ne 0) {
        throw "sqlite3 query failed (exit $LASTEXITCODE): $Query"
    }
    return $output
}

function Initialize-NsrlCatalog {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string] $InstallPath = './tools/nsrl/',
        [switch] $Force
    )

    if (-not (Test-Path -LiteralPath $InstallPath)) {
        New-Item -ItemType Directory -Force -Path $InstallPath | Out-Null
    }

    $existing = Get-NsrlDbPath -InstallPath $InstallPath
    if ($existing -and -not $Force) {
        Install-Sqlite3Tool | Out-Null
        return $existing
    }

    $archiveListing = 'https://s3.amazonaws.com/rds.nsrl.nist.gov/'
    try {
        $listing = Invoke-WebRequest -Uri $archiveListing -UseBasicParsing -ErrorAction Stop
    } catch {
        throw "Failed to list NSRL S3 bucket: $($_.Exception.Message)"
    }

    $candidates = [regex]::Matches($listing.Content, '<Key>([^<]+modern[^<]*minimal[^<]*\.zip)</Key>', 'IgnoreCase') |
        ForEach-Object { $_.Groups[1].Value } |
        Sort-Object -Descending

    $archiveKey = $candidates | Select-Object -First 1
    if (-not $archiveKey) {
        throw "Could not locate current NSRL Modern Minimal archive in S3 listing."
    }

    $zipUrl = "$archiveListing$archiveKey"
    $zipPath = Join-Path $env:TEMP ("nsrl-{0}.zip" -f ([Guid]::NewGuid().ToString('N')))
    $extractDir = Join-Path $env:TEMP ("nsrl-extract-{0}" -f ([Guid]::NewGuid().ToString('N')))

    if (-not $PSCmdlet.ShouldProcess($InstallPath, "Download and install NSRL DB")) {
        return $null
    }

    try {
        Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -UseBasicParsing -ErrorAction Stop
        New-Item -ItemType Directory -Force -Path $extractDir | Out-Null
        try {
            Expand-Archive -LiteralPath $zipPath -DestinationPath $extractDir -Force -ErrorAction Stop
        } catch {
            throw "NSRL archive is corrupt or not readable: $($_.Exception.Message)"
        }
        $db = Get-ChildItem -Path $extractDir -Filter '*.db' -Recurse -File | Select-Object -First 1
        if (-not $db) { throw "No .db file found inside NSRL archive." }
        $destPath = Join-Path $InstallPath $db.Name
        Move-Item -LiteralPath $db.FullName -Destination $destPath -Force
        $installed = (Resolve-Path -LiteralPath $destPath).Path
    } finally {
        if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force -ErrorAction SilentlyContinue }
        if (Test-Path -LiteralPath $extractDir) { Remove-Item -LiteralPath $extractDir -Recurse -Force -ErrorAction SilentlyContinue }
    }

    Install-Sqlite3Tool | Out-Null
    return $installed
}

function Resolve-DbPath {
    param([string] $DbPath)
    if ($DbPath) {
        if (-not (Test-Path -LiteralPath $DbPath)) {
            throw "NSRL database not found at '$DbPath'. Run Initialize-NsrlCatalog first."
        }
        return (Resolve-Path -LiteralPath $DbPath).Path
    }
    $auto = Get-NsrlDbPath -InstallPath './tools/nsrl/'
    if (-not $auto) {
        throw "NSRL database not located. Run Initialize-NsrlCatalog first."
    }
    return $auto
}

function Get-NsrlPlatformSummary {
    [CmdletBinding()]
    param(
        [string] $DbPath
    )

    $db = Resolve-DbPath -DbPath $DbPath
    $sqlite = Install-Sqlite3Tool

    $totalRaw = Invoke-Sqlite -Sqlite $sqlite -DbPath $db -Query "SELECT COUNT(DISTINCT sha1) FROM FILE;"
    $total = [int64] ($totalRaw | Select-Object -First 1)

    $osQuery = @'
SELECT o.OpSystemName, COUNT(DISTINCT f.sha1)
FROM FILE f
JOIN OS o ON f.OpSystemCode = o.OpSystemCode
GROUP BY o.OpSystemName
ORDER BY COUNT(DISTINCT f.sha1) DESC;
'@
    $rows = Invoke-Sqlite -Sqlite $sqlite -DbPath $db -Query $osQuery

    $windows = 0L; $linux = 0L; $other = 0L
    $breakdown = @()
    foreach ($row in $rows) {
        if ([string]::IsNullOrWhiteSpace($row)) { continue }
        $parts = $row -split "`t", 2
        if ($parts.Count -lt 2) { continue }
        $osName = $parts[0]
        $count  = [int64] $parts[1]
        $plat   = Get-PlatformClassification -OsName $osName
        switch ($plat) {
            'Windows' { $windows += $count }
            'Linux'   { $linux   += $count }
            default   { $other   += $count }
        }
        $breakdown += [pscustomobject]@{ OsName = $osName; HashCount = $count }
    }

    [pscustomobject]@{
        TotalHashes    = $total
        WindowsHashes  = $windows
        LinuxHashes    = $linux
        OtherHashes    = $other
        TopOsBreakdown = ($breakdown | Select-Object -First 20)
    }
}

function Export-NsrlHashManifest {
    [CmdletBinding()]
    param(
        [string] $DbPath,
        [string] $OutputDir = './output/',
        [int] $MaxHashes = 0
    )

    $db = Resolve-DbPath -DbPath $DbPath
    $sqlite = Install-Sqlite3Tool

    if (-not (Test-Path -LiteralPath $OutputDir)) {
        New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
    }

    $limitClause = ''
    if ($MaxHashes -gt 0) { $limitClause = " LIMIT $MaxHashes" }

    $query = @"
SELECT DISTINCT UPPER(f.sha1), f.FileName, o.OpSystemCode, o.OpSystemName
FROM FILE f
JOIN OS o ON f.OpSystemCode = o.OpSystemCode$limitClause;
"@

    $rows = Invoke-Sqlite -Sqlite $sqlite -DbPath $db -Query $query

    $winRows = [System.Collections.Generic.List[object]]::new()
    $lnxRows = [System.Collections.Generic.List[object]]::new()
    $othRows = [System.Collections.Generic.List[object]]::new()

    foreach ($row in $rows) {
        if ([string]::IsNullOrWhiteSpace($row)) { continue }
        $parts = $row -split "`t", 4
        if ($parts.Count -lt 4) { continue }
        $obj = [pscustomobject]@{
            FileHash = $parts[0]
            FileName = $parts[1]
            OsCode   = $parts[2]
            OsName   = $parts[3]
            Platform = Get-PlatformClassification -OsName $parts[3]
        }
        switch ($obj.Platform) {
            'Windows' { $winRows.Add($obj) }
            'Linux'   { $lnxRows.Add($obj) }
            default   { $othRows.Add($obj) }
        }
    }

    $winPath = Join-Path $OutputDir 'nsrl_input_windows.csv'
    $lnxPath = Join-Path $OutputDir 'nsrl_input_linux.csv'
    $othPath = Join-Path $OutputDir 'nsrl_input_other.csv'

    $winRows | Export-Csv -LiteralPath $winPath -NoTypeInformation -Encoding UTF8
    $lnxRows | Export-Csv -LiteralPath $lnxPath -NoTypeInformation -Encoding UTF8
    $othRows | Export-Csv -LiteralPath $othPath -NoTypeInformation -Encoding UTF8

    [pscustomobject]@{
        WindowsRows = $winRows.Count
        LinuxRows   = $lnxRows.Count
        OtherRows   = $othRows.Count
        WindowsFile = $winPath
        LinuxFile   = $lnxPath
        OtherFile   = $othPath
    }
}

Export-ModuleMember -Function Initialize-NsrlCatalog, Get-NsrlPlatformSummary, Export-NsrlHashManifest
