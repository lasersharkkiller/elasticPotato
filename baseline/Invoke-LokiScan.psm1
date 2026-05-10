function Invoke-LokiScan {
    <#
    .SYNOPSIS
        Runs Florian Roth's Loki IOC/YARA scanner against downloaded malicious files.
    .DESCRIPTION
        Wraps loki.exe (or loki.py) to scan a target directory, parses the CSV output,
        and displays a colour-coded summary of ALERTs, WARNINGs, and NOTICEs.
        Full results are saved to output\loki_results\.
    .NOTES
        Download Loki from: https://github.com/Neo23x0/Loki/releases
        Place loki.exe (and its signature folder) at .\tools\loki\loki.exe
        or specify a custom path when prompted.
    #>
    param (
        [string]$LokiPath       = "tools\loki\loki.exe",
        [string]$ScanTargetPath = "output-baseline\VirusTotal-main\malicious",
        [string]$ResultsPath    = "output\loki_results"
    )

    $CurrentDir = Get-Location
    function Get-Abs ($p) { if ([System.IO.Path]::IsPathRooted($p)) { return $p } return Join-Path $CurrentDir $p }

    $LokiPath       = Get-Abs $LokiPath
    $ScanTargetPath = Get-Abs $ScanTargetPath
    $ResultsPath    = Get-Abs $ResultsPath

    # --- Resolve Loki executable ---
    if (-not (Test-Path $LokiPath)) {
        Write-Host "Loki not found at default path: $LokiPath" -ForegroundColor Yellow
        $customPath = Read-Host "Enter full path to loki.exe (or loki.py)"
        if ([string]::IsNullOrWhiteSpace($customPath) -or -not (Test-Path $customPath)) {
            Write-Host "Loki executable not found. Aborting." -ForegroundColor Red
            Write-Host "Download from: https://github.com/Neo23x0/Loki/releases" -ForegroundColor DarkGray
            return
        }
        $LokiPath = $customPath
    }

    # --- Resolve scan target ---
    if (-not (Test-Path $ScanTargetPath)) {
        Write-Host "Default scan target not found: $ScanTargetPath" -ForegroundColor Yellow
        $customTarget = Read-Host "Enter path to scan"
        if ([string]::IsNullOrWhiteSpace($customTarget) -or -not (Test-Path $customTarget)) {
            Write-Host "Scan target not found. Aborting." -ForegroundColor Red
            return
        }
        $ScanTargetPath = $customTarget
    }

    # --- Count files to give user context ---
    $fileCount = (Get-ChildItem -Path $ScanTargetPath -File -Recurse -ErrorAction SilentlyContinue).Count
    Write-Host ""
    Write-Host "Loki Scanner" -ForegroundColor Cyan
    Write-Host "  Executable : $LokiPath" -ForegroundColor DarkGray
    Write-Host "  Scan target: $ScanTargetPath ($fileCount files)" -ForegroundColor DarkGray

    # --- Prepare output ---
    if (-not (Test-Path $ResultsPath)) { New-Item -ItemType Directory -Path $ResultsPath -Force | Out-Null }
    $timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
    $logFile    = Join-Path $ResultsPath "loki_$timestamp.csv"

    # --- Determine if Python wrapper needed ---
    $isPython = $LokiPath -match "\.py$"
    if ($isPython) {
        $python = Get-Command python -ErrorAction SilentlyContinue
        if (-not $python) { $python = Get-Command python3 -ErrorAction SilentlyContinue }
        if (-not $python) {
            Write-Host "Python not found on PATH. Cannot run loki.py." -ForegroundColor Red
            return
        }
    }

    Write-Host "  Log file   : $logFile" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "Starting scan..." -ForegroundColor Cyan

    # --- Build argument list ---
    # --csv        : machine-parseable CSV output
    # --noprocscan : skip live process scan (we're scanning files)
    # --noindicator: suppress progress indicator noise
    # --dontwait   : don't pause for keypress at end
    # --intense    : enable intense scan mode (checks all file types)
    # --logfile    : write results to file
    # --nolog      not used  -  we want the log
    $lokiArgs = @(
        "-p", $ScanTargetPath,
        "--csv",
        "--noprocscan",
        "--noindicator",
        "--dontwait",
        "--intense",
        "--logfile", $logFile
    )

    $startTime = Get-Date

    if ($isPython) {
        & $python.Source $LokiPath @lokiArgs
    } else {
        & $LokiPath @lokiArgs
    }

    $elapsed = (Get-Date) - $startTime
    Write-Host ""
    Write-Host ("Scan completed in {0:mm}m {0:ss}s" -f $elapsed) -ForegroundColor DarkGray

    # --- Parse results ---
    if (-not (Test-Path $logFile)) {
        Write-Host "Log file not created  -  Loki may have failed to run or produced no output." -ForegroundColor Yellow
        return
    }

    $rows    = Import-Csv -Path $logFile -ErrorAction SilentlyContinue
    if (-not $rows) {
        # Loki CSV sometimes has non-standard headers  -  try raw parse
        $raw  = Get-Content $logFile -ErrorAction SilentlyContinue
        $rows = $raw | ForEach-Object {
            $cols = $_ -split ","
            if ($cols.Count -ge 4) {
                [PSCustomObject]@{ TIME=$cols[0]; HOSTNAME=$cols[1]; EVENTTYPE=$cols[2]; MODULE=$cols[3]; MESSAGE=($cols[4..($cols.Count-1)] -join ",") }
            }
        }
    }

    $alerts   = @($rows | Where-Object { $_.EVENTTYPE -eq "ALERT"   -or $_ -match "ALERT" })
    $warnings = @($rows | Where-Object { $_.EVENTTYPE -eq "WARNING" -or $_ -match "WARNING" })
    $notices  = @($rows | Where-Object { $_.EVENTTYPE -eq "NOTICE"  -or $_ -match "NOTICE" })

    Write-Host ""
    Write-Host "==============================" -ForegroundColor DarkGray
    Write-Host "  Loki Scan Summary" -ForegroundColor Cyan
    Write-Host "==============================" -ForegroundColor DarkGray
    Write-Host ("  ALERT   : {0,5}" -f $alerts.Count)   -ForegroundColor $(if ($alerts.Count   -gt 0) { "Red"    } else { "DarkGray" })
    Write-Host ("  WARNING : {0,5}" -f $warnings.Count) -ForegroundColor $(if ($warnings.Count -gt 0) { "Yellow" } else { "DarkGray" })
    Write-Host ("  NOTICE  : {0,5}" -f $notices.Count)  -ForegroundColor $(if ($notices.Count  -gt 0) { "Cyan"   } else { "DarkGray" })
    Write-Host ""

    # --- Print ALERTs ---
    if ($alerts.Count -gt 0) {
        Write-Host "--- ALERTS ---" -ForegroundColor Red
        foreach ($a in $alerts) {
            $msg = if ($a.MESSAGE) { $a.MESSAGE } else { $a }
            Write-Host "  [ALERT] $msg" -ForegroundColor Red
        }
        Write-Host ""
    }

    # --- Print WARNINGs ---
    if ($warnings.Count -gt 0) {
        Write-Host "--- WARNINGS ---" -ForegroundColor Yellow
        foreach ($w in ($warnings | Select-Object -First 20)) {
            $msg = if ($w.MESSAGE) { $w.MESSAGE } else { $w }
            Write-Host "  [WARN]  $msg" -ForegroundColor Yellow
        }
        if ($warnings.Count -gt 20) {
            Write-Host "  ... and $($warnings.Count - 20) more. See: $logFile" -ForegroundColor DarkGray
        }
        Write-Host ""
    }

    if ($alerts.Count -eq 0 -and $warnings.Count -eq 0 -and $notices.Count -eq 0) {
        Write-Host "  No findings. Full log: $logFile" -ForegroundColor DarkGray
    } else {
        Write-Host "  Full log saved to: $logFile" -ForegroundColor DarkGray
    }
    Write-Host ""
}
