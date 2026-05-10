# Update-ElasticYaraRules.psm1
# Downloads YARA detection rules from elastic/protections-artifacts (GitHub) and
# stores them in detections\yara\elastic-protections\ (separate from community rules).
# Also syncs to any Thor custom-signatures\yara\elastic-protections\ directories
# found under tools\ so Thor picks them up automatically.
#
# Best-effort: if offline or download fails, cached rules are used silently.
# Intended to be called at the start of alert triage workflows (4b, 4c, 4f).

function Update-ElasticYaraRules {
    [CmdletBinding()]
    param(
        # Override destination. Defaults to detections\yara\elastic-protections\ relative
        # to this module's directory.
        [string]$OutputPath,

        # When set, suppress all output except hard errors (no internet = silent).
        [switch]$Quiet
    )

    # ---- Resolve paths -----------------------------------------------------------
    $modRoot = $PSScriptRoot
    if (-not $modRoot) {
        $modRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
    }

    if (-not $OutputPath) {
        $OutputPath = Join-Path $modRoot 'yara\elastic-protections'
    }

    $projectRoot = Split-Path $modRoot -Parent   # D:\Loaded-Potato

    if (-not (Test-Path -LiteralPath $OutputPath)) {
        [void](New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction SilentlyContinue)
    }

    $metaPath    = Join-Path $OutputPath '_elastic_meta.json'
    $downloadUrl = 'https://github.com/elastic/protections-artifacts/archive/refs/heads/main.zip'
    $zipPrefix   = 'protections-artifacts-main/yara/rules/'

    # ---- Read cached metadata ----------------------------------------------------
    $lastUpdated = $null
    $cachedCount = 0
    if (Test-Path -LiteralPath $metaPath) {
        try {
            $metaTxt = [System.IO.File]::ReadAllText($metaPath)
            $meta    = ConvertFrom-Json $metaTxt
            $lastUpdated = $meta.last_updated
            $cachedCount = [int]$meta.rule_count
        } catch { }
    }

    # ---- Attempt download --------------------------------------------------------
    $tempZip    = Join-Path $env:TEMP ("elastic_protections_" + (Get-Random) + ".zip")
    $downloaded = $false

    try {
        $wc = [System.Net.WebClient]::new()
        $wc.Headers.Add('User-Agent', 'LoadedPotato-SecurityTool')

        # Use GitHub token if available (avoids rate limiting on repeated runs)
        try {
            $ghToken = Get-Secret -Name 'Github_Access_Token' -AsPlainText -ErrorAction SilentlyContinue
            if ($ghToken) {
                $wc.Headers.Add('Authorization', "token $ghToken")
            }
        } catch { }

        $wc.DownloadFile($downloadUrl, $tempZip)
        $downloaded = $true

    } catch {
        # Offline or network error - fall back to cached rules
        $cachedYar = @(Get-ChildItem -LiteralPath $OutputPath -Filter '*.yar' -File -ErrorAction SilentlyContinue)
        if (-not $Quiet) {
            if ($cachedYar.Count -gt 0) {
                $dateStr = if ($lastUpdated) { " (last updated $lastUpdated)" } else { '' }
                Write-Host "[*] Elastic YARA rules: offline - using $($cachedYar.Count) cached rules$dateStr" -ForegroundColor DarkGray
            } else {
                Write-Host "[!] Elastic YARA rules: offline and no cached rules found - Elastic rule context unavailable" -ForegroundColor Yellow
            }
        }
        if (Test-Path -LiteralPath $tempZip -ErrorAction SilentlyContinue) {
            Remove-Item -LiteralPath $tempZip -Force -ErrorAction SilentlyContinue
        }
        return
    }

    # ---- Extract yara/rules/*.yar from zip ---------------------------------------
    $ruleCount = 0
    $extractErr = $null

    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem

        $zip = [System.IO.Compression.ZipFile]::OpenRead($tempZip)
        try {
            foreach ($entry in $zip.Entries) {
                $entryPath = $entry.FullName

                # Only direct .yar children of yara/rules/ (no subdirectories)
                if (-not $entryPath.StartsWith($zipPrefix))         { continue }
                if (-not $entryPath.EndsWith('.yar'))                { continue }
                if ($entryPath.Length -le $zipPrefix.Length)         { continue }
                $remainder = $entryPath.Substring($zipPrefix.Length)
                if ($remainder.IndexOf('/') -ge 0)                   { continue }

                $destFile  = Join-Path $OutputPath $entry.Name
                $entStream = $entry.Open()
                try {
                    $fs = [System.IO.File]::Create($destFile)
                    try {
                        $entStream.CopyTo($fs)
                    } finally {
                        $fs.Close()
                    }
                } finally {
                    $entStream.Close()
                }
                $ruleCount++
            }
        } finally {
            $zip.Dispose()
        }
    } catch {
        $extractErr = $_
    } finally {
        Remove-Item -LiteralPath $tempZip -Force -ErrorAction SilentlyContinue
    }

    if ($extractErr) {
        if (-not $Quiet) {
            Write-Host "[!] Elastic YARA rules: extraction failed - $extractErr" -ForegroundColor Yellow
        }
        return
    }

    if ($ruleCount -eq 0) {
        if (-not $Quiet) {
            Write-Host "[!] Elastic YARA rules: zip downloaded but no .yar files extracted (path layout may have changed)" -ForegroundColor Yellow
        }
        return
    }

    # ---- Write metadata ----------------------------------------------------------
    $nowStr  = Get-Date -Format 'yyyy-MM-dd HH:mm'
    $metaObj = [ordered]@{
        last_updated = $nowStr
        rule_count   = $ruleCount
        source       = 'https://github.com/elastic/protections-artifacts/tree/main/yara/rules'
    }
    try {
        [System.IO.File]::WriteAllText($metaPath, (ConvertTo-Json $metaObj))
    } catch { }

    if (-not $Quiet) {
        Write-Host "[+] Elastic YARA rules: updated $ruleCount rules -> $OutputPath" -ForegroundColor Green
    }

    # ---- Sync to Thor custom-signatures directories (best-effort) ----------------
    $toolsRoot = Join-Path $projectRoot 'tools'
    if (Test-Path -LiteralPath $toolsRoot) {
        $thorYaraDirs = @(
            Get-ChildItem -LiteralPath $toolsRoot -Recurse -Directory -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Name -eq 'yara' -and
                $_.Parent -and
                $_.Parent.Name -eq 'custom-signatures'
            }
        )

        foreach ($thorYaraDir in $thorYaraDirs) {
            $thorElasticDir = Join-Path $thorYaraDir.FullName 'elastic-protections'
            if (-not (Test-Path -LiteralPath $thorElasticDir)) {
                [void](New-Item -ItemType Directory -Path $thorElasticDir -Force -ErrorAction SilentlyContinue)
            }

            $syncCount = 0
            $srcFiles  = @(Get-ChildItem -LiteralPath $OutputPath -Filter '*.yar' -File -ErrorAction SilentlyContinue)
            foreach ($srcFile in $srcFiles) {
                $dest = Join-Path $thorElasticDir $srcFile.Name
                try {
                    Copy-Item -LiteralPath $srcFile.FullName -Destination $dest -Force -ErrorAction SilentlyContinue
                    $syncCount++
                } catch { }
            }

            if (-not $Quiet -and $syncCount -gt 0) {
                $relThor = $thorElasticDir.Replace($projectRoot, '').TrimStart('\/')
                Write-Host "    Synced $syncCount rules to Thor: $relThor" -ForegroundColor DarkGray
            }
        }
    }
}

Export-ModuleMember -Function Update-ElasticYaraRules
