# NsrlTools.psm1
# Setup and OS-filtered extraction for the NIST NSRL RDS SQLite database.
# Uses sqlite3.exe (auto-downloaded from sqlite.org) - no PSSQLite module required.
#
# Workflow:
#   1. Install-NsrlDatabase   -- download NSRL RDS SQLite DB + sqlite3.exe
#   2. Get-NsrlOsSummary      -- inspect OS categories in the DB
#   3. Export-NsrlHashList    -- extract hashes filtered by OS, excluding offensive distros
#      -> outputs CSVs ready to feed into Update-NsrlBaseline (NsrlEnrichment.psm1)

$script:DefaultOffensivePatterns = @(
    'Kali', 'BlackArch', 'Parrot', 'BackBox', 'Pentoo',
    'DEFT', 'REMnux', 'Tails', 'Whonix', 'Offensive Security',
    'ArchStrike', 'Demon Linux', 'Dragon OS', 'Cyborg',
    'Network Security Toolkit', 'NST', 'Fedora Security'
)

# ── SQLITE3.EXE MANAGEMENT ────────────────────────────────────────────────────

function Install-Sqlite3 {
    <#
    .SYNOPSIS
        Downloads sqlite3.exe from sqlite.org into the NSRL directory.
        Returns the full path to sqlite3.exe, or $null on failure.
    #>
    [CmdletBinding()]
    param([string]$DestinationPath = ".\NSRL")

    if (-not (Test-Path $DestinationPath)) {
        New-Item -ItemType Directory -Path $DestinationPath -Force | Out-Null
    }

    $exe = Join-Path (Resolve-Path $DestinationPath).Path "sqlite3.exe"
    if (Test-Path $exe) {
        Write-Host "sqlite3.exe already present." -ForegroundColor DarkGray
        return $exe
    }

    Write-Host "Fetching sqlite3.exe download link from sqlite.org..." -ForegroundColor DarkCyan
    try {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        $page = (New-Object System.Net.WebClient).DownloadString("https://www.sqlite.org/download.html")
        # Page footer has: PRODUCT,3.51.3,2026/sqlite-tools-win-x64-3510300.zip,...
        if ($page -match 'PRODUCT,[^,]+,((\d{4})/sqlite-tools-win-x64-\d+\.zip)') {
            $zipUrl = "https://www.sqlite.org/$($matches[1])"
            Write-Host "  Downloading: $zipUrl" -ForegroundColor DarkGray
        } elseif ($page -match 'PRODUCT,[^,]+,((\d{4})/sqlite-tools-win32-x86-\d+\.zip)') {
            $zipUrl = "https://www.sqlite.org/$($matches[1])"
            Write-Host "  Downloading (x86 fallback): $zipUrl" -ForegroundColor DarkGray
        } else {
            throw "Could not find sqlite-tools-win link on sqlite.org/download.html"
        }
    } catch {
        Write-Warning "Auto-detect failed: $_"
        Write-Host @"

Manual steps:
  1. Browse to: https://www.sqlite.org/download.html
  2. Under 'Precompiled Binaries for Windows', download 'sqlite-tools-win-x64-*.zip'
  3. Extract sqlite3.exe to: $DestinationPath
  4. Re-run Install-NsrlDatabase -SkipDownload
"@ -ForegroundColor Yellow
        return $null
    }

    $zipPath = Join-Path (Resolve-Path $DestinationPath).Path "sqlite-tools.zip"
    try {
        $wc = [System.Net.WebClient]::new()
        $wc.DownloadFile($zipUrl, $zipPath)
    } catch {
        Write-Error "Download failed: $_"; return $null
    }

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $tmpDir = Join-Path (Resolve-Path $DestinationPath).Path "sqlite_tmp"
    if (Test-Path $tmpDir) { Remove-Item $tmpDir -Recurse -Force }
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $tmpDir)

    $foundExe = Get-ChildItem $tmpDir -Filter "sqlite3.exe" -Recurse | Select-Object -First 1
    if ($foundExe) {
        Copy-Item $foundExe.FullName $exe -Force
        Write-Host "sqlite3.exe installed: $exe" -ForegroundColor Green
    } else {
        Write-Error "sqlite3.exe not found in downloaded archive."
        $exe = $null
    }

    Remove-Item $zipPath -ErrorAction SilentlyContinue
    Remove-Item $tmpDir  -Recurse -ErrorAction SilentlyContinue
    return $exe
}

function Resolve-Sqlite3 {
    param([string]$NsrlDir = ".\NSRL")

    # 1. NSRL directory
    $nsrlFull = if (Test-Path $NsrlDir) { (Resolve-Path $NsrlDir).Path } else { $null }
    if ($nsrlFull) {
        $local = Join-Path $nsrlFull "sqlite3.exe"
        if (Test-Path $local) { return $local }
    }

    # 2. PATH
    $inPath = Get-Command "sqlite3.exe" -ErrorAction SilentlyContinue
    if ($inPath) { return $inPath.Source }

    # 3. Auto-download
    return Install-Sqlite3 -DestinationPath $NsrlDir
}

function Invoke-Sqlite3Query {
    <#
    .SYNOPSIS
        Runs a SQL query against a SQLite DB file via sqlite3.exe.
        Writes results to a CSV file (via sqlite3 .output directive).
        Returns imported PSObjects, or $null if DirectOutputCsv is specified (caller reads file).
    #>
    param(
        [string]$Sqlite3,
        [string]$DbPath,
        [string]$Query,
        [string]$DirectOutputCsv = ""    # if non-empty, write here and return $null
    )

    # sqlite3 prefers forward slashes on Windows
    $dbFwd  = $DbPath.Replace('\','/')
    $sqlTmp = [System.IO.Path]::ChangeExtension([System.IO.Path]::GetTempFileName(), ".sql")
    $useDirectOut = $DirectOutputCsv -ne ""
    $csvOut = if ($useDirectOut) { $DirectOutputCsv } `
              else { [System.IO.Path]::ChangeExtension([System.IO.Path]::GetTempFileName(), ".csv") }
    $csvFwd = $csvOut.Replace('\','/')
    $errTmp = [System.IO.Path]::ChangeExtension([System.IO.Path]::GetTempFileName(), ".err")

    try {
        # ASCII encoding avoids the UTF-8 BOM that PowerShell 5 adds with -Encoding UTF8
        # (sqlite3 rejects BOM as a parse error on line 1)
        [System.IO.File]::WriteAllText($sqlTmp,
            ".mode csv`n.headers on`n.output $csvFwd`n$Query`n.quit`n",
            [System.Text.Encoding]::ASCII)

        # Redirect stdin from the SQL file so sqlite3 runs in batch mode (no interactive prompt)
        $proc = Start-Process -FilePath $Sqlite3 `
                              -ArgumentList @($dbFwd) `
                              -NoNewWindow -Wait -PassThru `
                              -RedirectStandardInput  $sqlTmp `
                              -RedirectStandardError  $errTmp

        if ($proc.ExitCode -ne 0) {
            $errMsg = Get-Content $errTmp -Raw -ErrorAction SilentlyContinue
            Write-Warning "sqlite3 exited $($proc.ExitCode): $($errMsg.Trim())"
        }

        if ($useDirectOut) { return $null }
        if (Test-Path $csvOut) { return Import-Csv -Path $csvOut -Encoding UTF8 }
        return @()
    }
    finally {
        Remove-Item $sqlTmp -ErrorAction SilentlyContinue
        Remove-Item $errTmp -ErrorAction SilentlyContinue
        if (-not $useDirectOut) { Remove-Item $csvOut -ErrorAction SilentlyContinue }
    }
}

# ── PUBLIC FUNCTIONS ──────────────────────────────────────────────────────────

function Install-NsrlDatabase {
    <#
    .SYNOPSIS
        Downloads sqlite3.exe and the NIST NSRL RDS Modern SQLite database.

    .PARAMETER DestinationPath
        Folder for the .db file and sqlite3.exe. Default: .\NSRL

    .PARAMETER IncludeLegacy
        Also download the Legacy RDS (Win9x/XP era - much larger).

    .PARAMETER SkipDownload
        Skip the download step; only extract an already-present ZIP.

    .PARAMETER ZipPath
        Full path to an already-downloaded NSRL ZIP (e.g. C:\Downloads\RDS_2026.03.1_modern.zip).
        Implies -SkipDownload. The file is read in-place; nothing is copied.
    #>
    [CmdletBinding()]
    param(
        [string]$DestinationPath = ".\NSRL",
        [switch]$IncludeLegacy,
        [switch]$SkipDownload,
        [string]$ZipPath
    )

    if ($ZipPath) { $SkipDownload = $true }

    if (-not (Test-Path $DestinationPath)) {
        New-Item -ItemType Directory -Path $DestinationPath -Force | Out-Null
    }

    # Always ensure sqlite3.exe is present
    $null = Install-Sqlite3 -DestinationPath $DestinationPath

    # NSRL moved to versioned release paths. URL format:
    #   https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/rds_YYYY.MM.V/RDS_YYYY.MM.V_modern.zip
    # Update these when NIST publishes a new quarterly release.
    $urls = @{
        Modern = "https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/rds_2026.03.1/RDS_2026.03.1_modern.zip"
        Legacy = "https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/rds_2026.03.1/RDS_2026.03.1_legacy.zip"
    }

    $toDownload = @("Modern")
    if ($IncludeLegacy) { $toDownload += "Legacy" }

    foreach ($edition in $toDownload) {
        $url = $urls[$edition]

        # Accept any zip in the destination that looks like an NSRL modern/legacy archive
        $zipPattern  = if ($edition -eq "Modern") { "*modern*", "*modernm*" } else { "*legacy*" }
        $destFull    = (Resolve-Path $DestinationPath).Path
        $autoZipPath = Get-ChildItem -Path $destFull -Filter "*.zip" |
                           Where-Object { foreach ($p in $zipPattern) { if ($_.Name -like $p) { return $true } } } |
                           Select-Object -First 1 -ExpandProperty FullName

        if (-not $autoZipPath) {
            $autoZipPath = Join-Path $destFull "rds_$($edition.ToLower()).zip"
        }

        if (-not $SkipDownload) {
            Write-Host "Downloading NSRL RDS $edition from NIST..." -ForegroundColor DarkCyan
            Write-Host "  URL : $url"           -ForegroundColor DarkGray
            Write-Host "  Dest: $autoZipPath"   -ForegroundColor DarkGray
            Write-Host "  (Several GB - may take a while)" -ForegroundColor DarkYellow

            try {
                [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
                $wc = [System.Net.WebClient]::new()
                $wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
                $wc.DownloadFile($url, $autoZipPath)
                Write-Host "Download complete." -ForegroundColor Green
            } catch {
                Write-Error "Download failed: $_"
                Write-Host @"

Manual download:
  Browse: https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/
  Find the latest rds_YYYY.MM.V folder and download RDS_YYYY.MM.V_modern.zip
  Save it anywhere inside: $destFull
  Then re-run: Install-NsrlDatabase -SkipDownload
"@ -ForegroundColor Yellow
                continue
            }
        }

        # Resolve zip: explicit -ZipPath wins, then auto-detected path
        $resolvedZip = if ($PSBoundParameters.ContainsKey('ZipPath') -and (Test-Path $ZipPath)) {
            $ZipPath
        } elseif (Test-Path $autoZipPath) {
            $autoZipPath
        } else {
            $null
        }

        if (-not $resolvedZip) {
            Write-Warning "No $edition ZIP found. Use -ZipPath 'C:\path\to\RDS_modern.zip' or place it in $destFull and re-run with -SkipDownload."
            continue
        }

        # Extract only .db files  -  avoids unpacking the full 100+ GB archive
        Write-Host "Extracting .db from $resolvedZip ..." -ForegroundColor DarkCyan
        Write-Host "  (Scanning zip entries  -  this may take a moment on large archives)" -ForegroundColor DarkGray
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $destDb = Join-Path $destFull "$($edition)_RDS.db"
        $found  = $false
        $zf     = [System.IO.Compression.ZipFile]::OpenRead($resolvedZip)
        try {
            foreach ($entry in $zf.Entries) {
                if ($entry.Name -like "*.db") {
                    Write-Host "  Found: $($entry.FullName)  ($([math]::Round($entry.Length/1GB,2)) GB uncompressed)" -ForegroundColor DarkGray
                    $stream = $entry.Open()
                    $fs     = [System.IO.File]::Create($destDb)
                    try   { $stream.CopyTo($fs) }
                    finally { $fs.Close(); $stream.Close() }
                    $found = $true
                    break
                }
            }
        } finally { $zf.Dispose() }

        if ($found) {
            Write-Host "Database ready: $destDb" -ForegroundColor Green
        } else {
            Write-Warning "No .db file found inside $resolvedZip"
        }
    }
}

function Get-NsrlOsSummary {
    <#
    .SYNOPSIS
        Shows OS categories and hash counts in the NSRL database.
        Run after Install-NsrlDatabase to review OS names before Export-NsrlHashList.
    #>
    [CmdletBinding()]
    param(
        [string]$DbPath,
        [int]$TopN = 50
    )

    $DbPath  = Resolve-NsrlDb -DbPath $DbPath;   if (-not $DbPath)  { return }
    $sqlite3 = Resolve-Sqlite3;                   if (-not $sqlite3) { return }

    $query = @"
SELECT
    operating_system_id AS ID,
    name                AS OS,
    version             AS Version,
    architecture        AS Architecture
FROM OPERATING_SYSTEM
ORDER BY name
LIMIT $TopN;
"@

    $results = Invoke-Sqlite3Query -Sqlite3 $sqlite3 -DbPath $DbPath -Query $query

    Write-Host "`nNSRL OS Summary (Top $TopN by hash count):" -ForegroundColor DarkCyan
    Write-Host "─────────────────────────────────────────────────────" -ForegroundColor DarkGray
    $results | Format-Table -AutoSize

    Write-Host "`nCurrent offensive exclusion patterns:" -ForegroundColor Yellow
    $script:DefaultOffensivePatterns | ForEach-Object { Write-Host "  - $_" -ForegroundColor DarkYellow }
    Write-Host "`nTo customize, pass -OffensiveOsPatterns to Export-NsrlHashList" -ForegroundColor DarkGray
}

function Export-NsrlHashList {
    <#
    .SYNOPSIS
        Exports OS-categorized, offensive-filtered hash CSVs from the NSRL DB.

    .DESCRIPTION
        Produces three CSV files (columns: Hash, FileName, OsCode, OsName, OsCategory):
          nsrl_input_windows.csv   -- Windows / MS-DOS hashes
          nsrl_input_linux.csv     -- Linux, Unix, BSD, macOS, Android (non-offensive)
          nsrl_input_other.csv     -- Everything else not classified above

        Offensive OS images (Kali, BlackArch, etc.) are excluded from all outputs.
        These CSVs feed directly into Update-NsrlBaseline (NsrlEnrichment.psm1).

    .PARAMETER MaxHashesPerCategory
        Row cap per output file. -1 = unlimited. Default 50000.

    .PARAMETER OffensiveOsPatterns
        Overrides the default offensive OS exclusion list.
    #>
    [CmdletBinding()]
    param(
        [string]$DbPath,
        [string]$OutputDir              = ".\output",
        [int]$MaxHashesPerCategory      = 50000,
        [string[]]$OffensiveOsPatterns  = $script:DefaultOffensivePatterns
    )

    $DbPath  = Resolve-NsrlDb -DbPath $DbPath;   if (-not $DbPath)  { return }
    $sqlite3 = Resolve-Sqlite3;                   if (-not $sqlite3) { return }

    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }
    $outFull = (Resolve-Path $OutputDir).Path

    # ── Build SQL fragments ───────────────────────────────────────────────────

    # Offensive exclusion on os.name
    $offExclude = ($OffensiveOsPatterns | ForEach-Object {
        $p = $_.Replace("'", "''")
        "  AND COALESCE(os.name,'') NOT LIKE '%$p%'"
    }) -join "`n"

    $limitClause = if ($MaxHashesPerCategory -gt 0) { "LIMIT $MaxHashesPerCategory" } else { "" }

    # Schema: FILE.package_id -> PKG.operating_system_id -> OPERATING_SYSTEM.name
    $selectBase = @"
SELECT DISTINCT
    lower(f.sha256)          AS Hash,
    f.file_name              AS FileName,
    os.operating_system_id   AS OsCode,
    os.name                  AS OsName,
    '{CAT}'                  AS OsCategory
FROM FILE f
JOIN PKG              p  ON f.package_id          = p.package_id
JOIN OPERATING_SYSTEM os ON p.operating_system_id = os.operating_system_id
WHERE f.sha256 IS NOT NULL
$offExclude
"@

    # Windows patterns
    $winInclude = @"
  AND (
       COALESCE(os.name,'') LIKE '%Windows%'
    OR COALESCE(os.name,'') LIKE '%MS-DOS%'
    OR COALESCE(os.name,'') LIKE '%Microsoft DOS%'
  )
"@

    # Linux/Unix patterns
    $linuxPatterns = @(
        'Linux','Ubuntu','Debian','Fedora','CentOS','RedHat','RHEL',
        'SUSE','Arch','Gentoo','Mint','Alpine','Android','UNIX',
        'BSD','FreeBSD','OpenBSD','NetBSD','Solaris','macOS','MacOSX','Darwin'
    )
    $linuxOr = ($linuxPatterns | ForEach-Object {
        $p = $_.Replace("'","''")
        "COALESCE(os.name,'') LIKE '%$p%'"
    }) -join "`n    OR "
    $linuxInclude = @"
  AND (
    $linuxOr
  )
  AND COALESCE(os.name,'') NOT LIKE '%Windows%'
  AND COALESCE(os.name,'') NOT LIKE '%MS-DOS%'
"@

    # "Other" = not Windows, not Linux
    $notWin = @"
  AND COALESCE(os.name,'') NOT LIKE '%Windows%'
  AND COALESCE(os.name,'') NOT LIKE '%MS-DOS%'
  AND COALESCE(os.name,'') NOT LIKE '%Microsoft DOS%'
"@
    $notLinux = ($linuxPatterns | ForEach-Object {
        $p = $_.Replace("'","''")
        "  AND COALESCE(os.name,'') NOT LIKE '%$p%'"
    }) -join "`n"

    # ── Run queries ───────────────────────────────────────────────────────────

    $categories = @(
        @{ Name = "Windows"; File = "nsrl_input_windows.csv"; Where = $winInclude }
        @{ Name = "Linux";   File = "nsrl_input_linux.csv";   Where = $linuxInclude }
        @{ Name = "Unknown"; File = "nsrl_input_other.csv";   Where = "$notWin`n$notLinux" }
    )

    $counts = @{}
    foreach ($cat in $categories) {
        Write-Host "Exporting $($cat.Name) hashes..." -ForegroundColor DarkCyan
        $outCsv = Join-Path $outFull $cat.File
        $sql    = ($selectBase.Replace('{CAT}', $cat.Name)) + $cat.Where + "`n$limitClause;"

        Invoke-Sqlite3Query -Sqlite3 $sqlite3 -DbPath $DbPath `
                            -Query $sql -DirectOutputCsv $outCsv

        $count = if (Test-Path $outCsv) {
            # Count lines minus header row (fast - no full Import-Csv)
            [System.IO.File]::ReadAllLines($outCsv).Count - 1
        } else { 0 }
        $counts[$cat.Name] = $count
        Write-Host "  -> $count rows : $outCsv" -ForegroundColor Green
    }

    Write-Host "`nNSRL export complete." -ForegroundColor DarkCyan
    Write-Host ("  Windows : {0,7}"  -f $counts['Windows']) -ForegroundColor White
    Write-Host ("  Linux   : {0,7}"  -f $counts['Linux'])   -ForegroundColor White
    Write-Host ("  Other   : {0,7}"  -f $counts['Unknown']) -ForegroundColor White
    Write-Host "`nNext: Update-NsrlBaseline -InputCsv (NsrlEnrichment.psm1)" -ForegroundColor DarkCyan
}

# ── PRIVATE HELPERS ───────────────────────────────────────────────────────────

function Resolve-NsrlDb {
    param([string]$DbPath)
    if ($DbPath -and (Test-Path $DbPath)) { return (Resolve-Path $DbPath).Path }
    $found = Get-ChildItem -Path ".\NSRL" -Filter "*.db" -Recurse -ErrorAction SilentlyContinue |
             Select-Object -First 1
    if (-not $found) {
        Write-Error "NSRL .db not found. Run Install-NsrlDatabase first."
        return $null
    }
    return $found.FullName
}

Export-ModuleMember -Function Install-NsrlDatabase, Get-NsrlOsSummary, Export-NsrlHashList