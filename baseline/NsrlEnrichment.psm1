# NsrlEnrichment.psm1
# Enriches NSRL hashes with VirusTotal metadata and categorizes by OS.
# UPDATED: Accepts pre-filtered CSV from Export-NsrlHashList (NsrlTools.psm1)
#          as an alternative input source to the SQLite DB query.
#
# Workflow A (SQLite direct):
#   Update-NsrlBaseline
#
# Workflow B (pre-filtered CSV from NsrlTools):
#   Update-NsrlBaseline -InputCsv ".\output\nsrl_input_windows.csv"
#   Update-NsrlBaseline -InputCsv ".\output\nsrl_input_linux.csv"
#   Update-NsrlBaseline -InputCsv ".\output\nsrl_input_windows.csv" -AppendToExisting

function Update-NsrlBaseline {
    <#
    .SYNOPSIS
        Enriches NSRL hashes with VirusTotal metadata and writes categorized baselines.

    .DESCRIPTION
        Two input modes:
          1. SQLite (default) : queries .\NSRL\*.db directly (requires PSSQLite).
          2. CSV (-InputCsv)  : reads a pre-filtered CSV produced by Export-NsrlHashList.
                                No SQLite dependency needed in this mode.

        VT results are cached under BaselineRootPath\NSRL\ so re-runs skip
        already-downloaded hashes. 404s are cached as placeholders.

        Outputs three JSON files per run (merged if run multiple times with -AppendToExisting):
          nsrlSignedVerifiedBaseline.json  -- Windows, VT-confirmed signed
          nsrlUnsignedWinBaseline.json     -- Windows, not VT-signed
          nsrlUnsignedLinuxBaseline.json   -- Linux/Unix

        With -AppendToExisting, results are also merged (deduped by hash) into:
          signedVerifiedProcsBaseline.json
          unsignedWinProcsBaseline.json
          unsignedLinuxProcsBaseline.json

    .PARAMETER InputCsv
        Path to a CSV from Export-NsrlHashList (columns: Hash, FileName, OsCode, OsName, OsCategory).
        When supplied the SQLite DB is not required.

    .PARAMETER AppendToExisting
        Merge enriched entries into the main baseline files after completing the run.

    .PARAMETER MaxHashes
        Cap on hashes to process this run (-1 = all). Default 1000.
    #>
    [CmdletBinding()]
    param (
        [string]$InputCsv,
        [string]$BaselineRootPath  = "output-baseline\VirusTotal-main",
        [string]$OutputDir         = "output",
        [int]$MaxHashes            = 1000,
        [int]$MaliciousThreshold   = 5,
        [switch]$AppendToExisting
    )

    # ── 1. AUTHENTICATION ─────────────────────────────────────────────────────
    if (-not (Get-Module -Name "Microsoft.PowerShell.SecretManagement")) {
        Import-Module Microsoft.PowerShell.SecretManagement -ErrorAction SilentlyContinue
    }
    try {
        $VTApi = Get-Secret -Name 'VT_API_Key_3' -AsPlainText
        if (-not $VTApi) { throw "Secret 'VT_API_Key_3' not found." }
    } catch {
        Write-Error "Authentication Failed: $_"; return
    }
    $VT_headers = @{ "x-apikey" = $VTApi; "Content-Type" = "application/json" }

    # ── 2. FOLDER SETUP ───────────────────────────────────────────────────────
    $NsrlDir      = Join-Path $BaselineRootPath "NSRL"
    $MaliciousDir = Join-Path $BaselineRootPath "malicious"
    $BothDir      = Join-Path $BaselineRootPath "existsInBoth"
    foreach ($p in @($NsrlDir, $MaliciousDir, $BothDir, $OutputDir)) {
        if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
    }

    # ── 3. LOAD INPUT ROWS ────────────────────────────────────────────────────
    # Each row needs: Hash, FileName, OsCategory
    $InputRows = $null

    if ($InputCsv) {
        # ── Mode B: CSV from Export-NsrlHashList ──
        if (-not (Test-Path $InputCsv)) { Write-Error "InputCsv not found: $InputCsv"; return }
        $raw = Import-Csv -Path $InputCsv -Encoding UTF8
        if (-not ($raw | Get-Member -Name 'OsCategory' -ErrorAction SilentlyContinue)) {
            Write-Error "CSV is missing OsCategory column. Generate it with Export-NsrlHashList from NsrlTools.psm1."
            return
        }
        $InputRows = $raw | Select-Object Hash, FileName, OsCategory
        Write-Host "Source    : CSV ($($InputRows.Count) rows) - $InputCsv" -ForegroundColor Green
    }
    else {
        # ── Mode A: SQLite DB ──
        $PotentialDb = Get-ChildItem -Path ".\NSRL" -Filter "*.db" -Recurse -ErrorAction SilentlyContinue |
                       Select-Object -First 1
        if (-not $PotentialDb) { Write-Error "NSRL Database not found. Run Install-NsrlDatabase or use -InputCsv."; return }
        if (-not (Get-Module -ListAvailable -Name PSSQLite)) { Write-Error "PSSQLite module required."; return }
        Import-Module PSSQLite

        Write-Host "Source    : SQLite DB - $($PotentialDb.Name)" -ForegroundColor Green
        $LimitClause = if ($MaxHashes -gt 0) { "LIMIT $MaxHashes" } else { "" }
        $Query = "SELECT DISTINCT sha256 AS Hash, file_name AS FileName FROM FILE WHERE sha256 IS NOT NULL $LimitClause"
        $dbRows = Invoke-SqliteQuery -DataSource $PotentialDb.FullName -Query $Query
        # SQLite mode has no OS info - all rows land as OsCategory "Unknown"
        $InputRows = $dbRows | Select-Object Hash, FileName, @{N='OsCategory';E={'Unknown'}}
        Write-Host "  (No OS filtering in SQLite mode - run Export-NsrlHashList for OS-aware extraction)" -ForegroundColor DarkYellow
    }

    # Apply MaxHashes cap when using CSV (SQLite already limits via SQL)
    if ($InputCsv -and $MaxHashes -gt 0 -and $InputRows.Count -gt $MaxHashes) {
        $InputRows = $InputRows | Select-Object -First $MaxHashes
        Write-Host "  Capped at $MaxHashes hashes (MaxHashes parameter)" -ForegroundColor DarkYellow
    }

    # ── 4. PROCESSING LOOP ────────────────────────────────────────────────────
    $SignedVerifiedList = [System.Collections.Generic.List[PSCustomObject]]::new()
    $UnsignedWinList    = [System.Collections.Generic.List[PSCustomObject]]::new()
    $UnsignedLinuxList  = [System.Collections.Generic.List[PSCustomObject]]::new()
    $ProcessedHashes    = [System.Collections.Generic.HashSet[string]]::new()

    $downloaded = 0; $cached = 0; $conflicts = 0

    foreach ($Row in $InputRows) {
        $Hash       = $Row.Hash.ToLower()
        $DbFileName = $Row.FileName
        $OsCategory = $Row.OsCategory   # Windows | Linux | Unknown (from CSV or SQLite fallback)

        if ($ProcessedHashes.Contains($Hash)) { continue }

        $PathNsrl      = Join-Path $NsrlDir      "$Hash.json"
        $PathRoot      = Join-Path $BaselineRootPath "$Hash.json"
        $PathMalicious = Join-Path $MaliciousDir "$Hash.json"
        $PathBoth      = Join-Path $BothDir      "$Hash.json"

        $JsonContent = $null

        # ── STEP A: CHECK LOCAL CACHE ──────────────────────────────────────
        if (Test-Path $PathBoth) {
            $JsonContent = Get-Content $PathBoth -Raw | ConvertFrom-Json
            $cached++
        }
        elseif (Test-Path $PathNsrl) {
            $JsonContent = Get-Content $PathNsrl -Raw | ConvertFrom-Json
            $cached++
        }
        elseif (Test-Path $PathRoot) {
            $JsonContent = Get-Content $PathRoot -Raw | ConvertFrom-Json
            $Score = [int]($JsonContent.data.attributes.last_analysis_stats.malicious)
            if ($Score -ge $MaliciousThreshold) {
                Copy-Item $PathRoot $PathBoth -Force
                if (-not (Test-Path $PathMalicious)) { Copy-Item $PathBoth $PathMalicious -Force }
                Write-Host "  Conflict: $Hash (score $Score) -> existsInBoth" -ForegroundColor Magenta
                $conflicts++
            }
            $cached++
        }
        elseif (Test-Path $PathMalicious) {
            Copy-Item $PathMalicious $PathBoth -Force
            $JsonContent = Get-Content $PathBoth -Raw | ConvertFrom-Json
            Write-Host "  Conflict: $Hash (from malicious) -> existsInBoth" -ForegroundColor Red
            $conflicts++
            $cached++
        }
        else {
            # ── STEP B: DOWNLOAD FROM VT ───────────────────────────────────
            Write-Host "  Downloading [$OsCategory] $Hash ..." -ForegroundColor DarkCyan
            try {
                $r     = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files/$Hash" `
                                           -Headers $VT_headers -Method Get
                $Score = [int]($r.data.attributes.last_analysis_stats.malicious)

                if ($Score -ge $MaliciousThreshold) {
                    $r | ConvertTo-Json -Depth 10 | Set-Content $PathBoth     -Force
                    $r | ConvertTo-Json -Depth 10 | Set-Content $PathMalicious -Force
                    Write-Host "    -> existsInBoth + malicious (score $Score)" -ForegroundColor Magenta
                    $conflicts++
                } else {
                    $r | ConvertTo-Json -Depth 10 | Set-Content $PathNsrl -Force
                }
                $JsonContent = $r
                $downloaded++
                Start-Sleep -Milliseconds 500
            }
            catch {
                $code = $_.Exception.Response.StatusCode.value__
                if ($code -eq 429) { Write-Warning "VT quota exceeded - stopping."; break }
                if ($code -eq 404) {
                    Write-Host "    [404] Not in VT - caching placeholder" -ForegroundColor DarkGray
                    $Placeholder = [PSCustomObject]@{
                        data = @{
                            id = $Hash
                            attributes = @{
                                meaningful_name     = $DbFileName
                                last_analysis_stats = @{ malicious = 0 }
                                signature_info      = @{ verified = $false }
                                tags                = @("nsrl_only", "vt_missing")
                            }
                        }
                    }
                    $Placeholder | ConvertTo-Json -Depth 10 | Set-Content $PathNsrl -Force
                    $JsonContent = $Placeholder
                    $downloaded++
                } else {
                    Write-Warning "  VT error ($code) for $Hash - skipping"
                    continue
                }
            }
        }

        if ($null -eq $JsonContent) { continue }

        # ── STEP C: BUILD BASELINE ENTRY ───────────────────────────────────
        $Attr = $JsonContent.data.attributes

        $Name = $DbFileName
        if ($Attr.meaningful_name) { $Name = $Attr.meaningful_name }
        elseif ($Attr.names)       { $Name = $Attr.names[0] }

        $IsSigned  = ($Attr.signature_info -and $Attr.signature_info.verified -eq $true)

        # value array matches existing baseline format: Name, Status, Hash, Publisher?, Count
        # Publisher comes from VT signature_info.signers if available
        $Publisher = if ($Attr.signature_info.signers) { $Attr.signature_info.signers } else { "" }
        $Entry = [PSCustomObject]@{
            value = @($Name, $null, $Hash, $Publisher, 1)
        }

        switch ($OsCategory) {
            "Windows" {
                if ($IsSigned) {
                    $Entry.value[1] = "SignedVerified"
                    $SignedVerifiedList.Add($Entry)
                } else {
                    $Entry.value[1] = "UnsignedWin"
                    $UnsignedWinList.Add($Entry)
                }
            }
            "Linux" {
                $Entry.value[1] = "UnsignedLinux"
                $UnsignedLinuxList.Add($Entry)
            }
            default {
                # Unknown OS (SQLite mode or unclassified): use VT signature to decide
                if ($IsSigned) {
                    $Entry.value[1] = "SignedVerified"
                    $SignedVerifiedList.Add($Entry)
                } else {
                    $Entry.value[1] = "UnsignedWin"
                    $UnsignedWinList.Add($Entry)
                }
            }
        }

        [void]$ProcessedHashes.Add($Hash)
    }

    # ── 5. SAVE NSRL-SPECIFIC OUTPUT FILES ───────────────────────────────────
    $nsrlOutputs = @{
        "nsrlSignedVerifiedBaseline.json" = $SignedVerifiedList
        "nsrlUnsignedWinBaseline.json"    = $UnsignedWinList
        "nsrlUnsignedLinuxBaseline.json"  = $UnsignedLinuxList
    }
    foreach ($kv in $nsrlOutputs.GetEnumerator()) {
        if ($kv.Value.Count -eq 0) { continue }
        $outPath = Join-Path $OutputDir $kv.Key

        # If the file already exists, merge (dedup by hash position [2])
        if (Test-Path $outPath) {
            $existing = Get-Content $outPath -Raw | ConvertFrom-Json
            $existingHashes = [System.Collections.Generic.HashSet[string]](
                @($existing) | ForEach-Object { $_.value[2] }
            )
            $newEntries = @($kv.Value | Where-Object { -not $existingHashes.Contains($_.value[2]) })
            $merged = @($existing) + $newEntries
            $merged | ConvertTo-Json -Depth 5 | Set-Content $outPath -Force
            Write-Host "Merged $($newEntries.Count) new entries into $outPath (total $($merged.Count))" -ForegroundColor Green
        } else {
            $kv.Value | ConvertTo-Json -Depth 5 | Set-Content $outPath -Force
            Write-Host "Saved $($kv.Value.Count) entries -> $outPath" -ForegroundColor Green
        }
    }

    # ── 6. OPTIONAL: APPEND TO EXISTING MAIN BASELINES ───────────────────────
    if ($AppendToExisting) {
        Write-Host "`nAppending to existing baseline files..." -ForegroundColor DarkCyan
        $mergeMap = @(
            @{ Source = $SignedVerifiedList; Target = Join-Path $OutputDir "signedVerifiedProcsBaseline.json" }
            @{ Source = $UnsignedWinList;    Target = Join-Path $OutputDir "unsignedWinProcsBaseline.json" }
            @{ Source = $UnsignedLinuxList;  Target = Join-Path $OutputDir "unsignedLinuxProcsBaseline.json" }
        )
        foreach ($m in $mergeMap) {
            if ($m.Source.Count -eq 0) { continue }
            $tgt = $m.Target

            if (Test-Path $tgt) {
                $existing = Get-Content $tgt -Raw | ConvertFrom-Json
                $existingHashes = [System.Collections.Generic.HashSet[string]](
                    @($existing) | ForEach-Object { $_.value[2] }
                )
                $newEntries = @($m.Source | Where-Object { -not $existingHashes.Contains($_.value[2]) })
                if ($newEntries.Count -gt 0) {
                    $merged = @($existing) + $newEntries
                    $merged | ConvertTo-Json -Depth 5 | Set-Content $tgt -Force
                    Write-Host "  +$($newEntries.Count) new -> $tgt (total $($merged.Count))" -ForegroundColor Green
                } else {
                    Write-Host "  No new entries for $tgt (all already present)" -ForegroundColor DarkGray
                }
            } else {
                $m.Source | ConvertTo-Json -Depth 5 | Set-Content $tgt -Force
                Write-Host "  Created $tgt ($($m.Source.Count) entries)" -ForegroundColor Green
            }
        }
    }

    # ── 7. SUMMARY ────────────────────────────────────────────────────────────
    Write-Host "`nNSRL Enrichment complete." -ForegroundColor DarkCyan
    Write-Host ("  Processed     : {0}" -f $ProcessedHashes.Count)     -ForegroundColor White
    Write-Host ("  SignedVerified: {0}" -f $SignedVerifiedList.Count)   -ForegroundColor Green
    Write-Host ("  UnsignedWin   : {0}" -f $UnsignedWinList.Count)     -ForegroundColor Yellow
    Write-Host ("  UnsignedLinux : {0}" -f $UnsignedLinuxList.Count)   -ForegroundColor DarkCyan
    Write-Host ("  Conflicts(VT) : {0}  |  VT downloads: {1}  |  Cached: {2}" -f $conflicts, $downloaded, $cached) -ForegroundColor DarkGray
}

Export-ModuleMember -Function Update-NsrlBaseline