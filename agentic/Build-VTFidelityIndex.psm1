function Build-VTFidelityIndex {
    <#
    .SYNOPSIS
        Pre-builds a fidelity index from the entire VT offline behavior baseline.

    .DESCRIPTION
        Phase 1 - VT Behavior Baseline:
        Reads EVERY behavior JSON file across all VT baseline categories (malicious,
        SignedVerified, unsignedWin, unsignedLinux, unverified, drivers) and extracts
        typed indicators (IPs, domains, process names, file names, registry keys).

        Phase 2 - APT Differential Merge:
        Merges all Targeted*DifferentialAnalysis.json files from the APT folder tree.
        Merge rule: LOWEST GoodCount wins (most conservative / most suspicious value
        is always used).

        Output files in BaselineRoot:
          fidelity-index.json   - indicator lookup table (used by ElasticAlertAgent)
          process-baseline.json - per-process signer + execution path table

    .PARAMETER BaselineRoot
        Root of the offline VT baseline. Default: output-baseline.

    .PARAMETER AptRoot
        Root of the APT differential analysis folder tree. Default: apt\APTs.
        Set to "" to skip the APT merge phase.

    .PARAMETER MaxLegitNames
        Max number of legitimate product names stored per indicator. Default: 5.

    .EXAMPLE
        Build-VTFidelityIndex
        Build-VTFidelityIndex -BaselineRoot "D:\MyBaseline" -AptRoot "D:\MyApts"
    #>
    param(
        [string]$BaselineRoot  = "output-baseline",
        [string]$AptRoot       = "apt\APTs",
        [int]   $MaxLegitNames = 5
    )

    if (-not [System.IO.Path]::IsPathRooted($BaselineRoot)) {
        $BaselineRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\$BaselineRoot"))
    }
    if ($AptRoot -and -not [System.IO.Path]::IsPathRooted($AptRoot)) {
        $AptRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\$AptRoot"))
    }
    $behRoot  = Join-Path $BaselineRoot "VirusTotal-behaviors"
    $mainRoot = Join-Path $BaselineRoot "VirusTotal-main"
    $outFile  = Join-Path $BaselineRoot "fidelity-index.json"

    if (-not (Test-Path $behRoot)) {
        Write-Error "Behavior root not found: $behRoot"
        return
    }

    Write-Host "`n[Build-VTFidelityIndex] Building fidelity index from $behRoot" -ForegroundColor DarkCyan
    $startTime = Get-Date

    # --- Flat integer hashmaps stored at module scope so nested helper functions
    #     can reliably modify them (PS5.1 nested function scoping quirk: $hash[$k]=v
    #     inside a nested function may silently shadow the outer variable instead of
    #     modifying it; $script: prefix guarantees the module-level object is used).
    $script:_vtfi_mal   = @{}
    $script:_vtfi_good  = @{}
    $script:_vtfi_legit = @{}
    $script:_vtfi_keys  = [System.Collections.Generic.HashSet[string]]::new(
                               [System.StringComparer]::OrdinalIgnoreCase)
    $script:_vtfi_procG       = @{}   # name -> good-file count (int)
    $script:_vtfi_procM       = @{}   # name -> malicious-file count (int)
    $script:_vtfi_procSigners = @{}   # name -> pipe-separated signer list (string)
    $script:_vtfi_procDirs    = @{}   # name -> pipe-separated dir list (string)
    $script:_vtfi_maxLN       = $MaxLegitNames

    function Update-ProcBaseline {
        param([string]$Name, [string]$FullPath, [bool]$IsMalicious, [string]$Signer)
        if (-not $Name -or $Name.Length -lt 2) { return }
        if ($IsMalicious) {
            $script:_vtfi_procM[$Name] = [int]($script:_vtfi_procM[$Name]) + 1
        } else {
            $script:_vtfi_procG[$Name] = [int]($script:_vtfi_procG[$Name]) + 1
            # Store dirs as pipe-separated string (avoids PS5.1 bug: $script:ht[$k]=@{nested}
            # inside doubly-nested function corrupts the hashtable by using the value as a key)
            if ($FullPath -and $FullPath -match '\\') {
                $dir = [System.IO.Path]::GetDirectoryName($FullPath).ToLower().TrimEnd('\')
                if ($dir -and $dir.Length -gt 2) {
                    $existing = $script:_vtfi_procDirs[$Name]
                    $parts = if ($existing) { $existing -split '\|' } else { @() }
                    if ($parts.Count -lt 10 -and $dir -notin $parts) {
                        $script:_vtfi_procDirs[$Name] = ($parts + $dir) -join '|'
                    }
                }
            }
            if ($Signer) {
                $existing = $script:_vtfi_procSigners[$Name]
                $parts = if ($existing) { $existing -split '\|' } else { @() }
                if ($parts.Count -lt 5 -and $Signer -notin $parts) {
                    $script:_vtfi_procSigners[$Name] = ($parts + $Signer) -join '|'
                }
            }
        }
    }

    function Update-Index {
        param([string]$Value, [bool]$IsMalicious, [string]$LegitName)
        if ([string]::IsNullOrWhiteSpace($Value) -or $Value.Length -lt 3) { return }
        $v = $Value.Trim()
        [void]$script:_vtfi_keys.Add($v)
        if ($IsMalicious) {
            $script:_vtfi_mal[$v] = [int]($script:_vtfi_mal[$v]) + 1
        } else {
            $script:_vtfi_good[$v] = [int]($script:_vtfi_good[$v]) + 1
            if ($LegitName) {
                if (-not $script:_vtfi_legit.ContainsKey($v)) {
                    $script:_vtfi_legit[$v] = [System.Collections.Generic.List[string]]::new()
                }
                $ln = $script:_vtfi_legit[$v]
                if ($ln.Count -lt $script:_vtfi_maxLN -and -not $ln.Contains($LegitName)) {
                    [void]$ln.Add($LegitName)
                }
            }
        }
    }

    # Local aliases for outer-scope code (Phase 2 and scoring)
    $malCount   = $script:_vtfi_mal
    $goodCount  = $script:_vtfi_good
    $legitNames = $script:_vtfi_legit
    $allKeys    = $script:_vtfi_keys
    $procIdx    = $script:_vtfi_procIdx
    $procG      = $script:_vtfi_procG
    $procM      = $script:_vtfi_procM

    $malCats  = @("malicious")
    $goodCats = @("SignedVerified","unsignedWin","unsignedLinux","unverified","drivers")
    $allCats  = $malCats + $goodCats

    $totalFiles = 0; $totalProcessed = 0

    foreach ($cat in $allCats) {
        $catPath = Join-Path $behRoot $cat
        if (-not (Test-Path $catPath)) { Write-Host "  [skip] $cat (not found)" -ForegroundColor DarkGray; continue }
        $files = Get-ChildItem $catPath -Filter "*.json" -ErrorAction SilentlyContinue
        $totalFiles += $files.Count
        $isMalicious = $malCats -contains $cat
        $processed = 0

        Write-Host "  Processing $cat ($($files.Count) files)..." -ForegroundColor DarkGray

        foreach ($f in $files) {
            $processed++; $totalProcessed++
            if ($processed % 1000 -eq 0) {
                $elapsed = (Get-Date) - $startTime
                Write-Host "    ${cat}: $processed / $($files.Count) ($([Math]::Round($elapsed.TotalSeconds))s elapsed, index size: $($allKeys.Count))" -ForegroundColor DarkGray
            }

            try {
                $raw = Get-Content $f.FullName -Raw
                $j = $raw | ConvertFrom-Json
                $d = $j.data

                $legitName = ""; $legitSigner = ""
                if (-not $isMalicious) {
                    $mainPath = Join-Path $mainRoot "$cat\$($f.BaseName).json"
                    if (Test-Path $mainPath) {
                        try {
                            $mj   = Get-Content $mainPath -Raw | ConvertFrom-Json
                            $attr = $mj.data.attributes
                            $legitName = if ($attr.meaningful_name) { $attr.meaningful_name }
                                         elseif ($attr.names)       { $attr.names[0] }
                                         else                       { "" }
                            if ($attr.signature_info -and $attr.signature_info.subject) {
                                $legitSigner = $attr.signature_info.subject
                            } elseif ($attr.code_signing_results) {
                                $vr = $attr.code_signing_results |
                                      Where-Object { $_.result -eq "valid" -or $_.result -eq "signed" } |
                                      Select-Object -First 1
                                if ($vr -and $vr.subject) { $legitSigner = $vr.subject }
                            }
                            # Register the sample's own filename as a known-good process
                            if ($legitName) {
                                $pn = [System.IO.Path]::GetFileName($legitName).ToLower()
                                if ($pn -and $pn.Length -gt 2) {
                                    Update-ProcBaseline -Name $pn -FullPath $legitName -IsMalicious $false -Signer $legitSigner
                                }
                            }
                        } catch {}
                    }
                } else {
                    # Malicious files: extract Sigma + YARA rule names from VT main metadata
                    $mainPath = Join-Path $mainRoot "$cat\$($f.BaseName).json"
                    if (Test-Path $mainPath) {
                        try {
                            $mj   = Get-Content $mainPath -Raw | ConvertFrom-Json
                            $attr = $mj.data.attributes
                            if ($attr.sigma_analysis_results) {
                                $attr.sigma_analysis_results | ForEach-Object {
                                    if ($_.rule_title) { Update-Index -Value $_.rule_title -IsMalicious $true -LegitName "" }
                                }
                            }
                            if ($attr.crowdsourced_yara_results) {
                                $attr.crowdsourced_yara_results | ForEach-Object {
                                    if ($_.rule_name) { Update-Index -Value $_.rule_name -IsMalicious $true -LegitName "" }
                                }
                            }
                        } catch {}
                    }
                }

                # Network IPs
                if ($d.ip_traffic) {
                    $d.ip_traffic | ForEach-Object {
                        if ($_.destination_ip) { Update-Index -Value $_.destination_ip -IsMalicious $isMalicious -LegitName $legitName }
                    }
                }
                # DNS / hostnames
                if ($d.dns_lookups) {
                    $d.dns_lookups | ForEach-Object {
                        if ($_.hostname) { Update-Index -Value $_.hostname -IsMalicious $isMalicious -LegitName $legitName }
                    }
                }
                # Processes created
                if ($d.processes_created) {
                    $d.processes_created | ForEach-Object {
                        # VT behavior_summary wraps some entries in extra escaped quotes,
                        # e.g. '"C:\path\prog.exe"' (outer " are actual chars, not JSON syntax).
                        # Strip them before GetFileName so keys are consistent (no trailing ").
                        $cleanPath = $_.Trim('"')
                        $pn = [System.IO.Path]::GetFileName($cleanPath)
                        if ($pn) {
                            Update-Index        -Value $pn.ToLower() -IsMalicious $isMalicious -LegitName $legitName
                            Update-ProcBaseline -Name  $pn.ToLower() -FullPath $cleanPath -IsMalicious $isMalicious -Signer $legitSigner
                        }
                    }
                }
                # Files written
                if ($d.files_written) {
                    $d.files_written | ForEach-Object {
                        $fn = [System.IO.Path]::GetFileName($_)
                        if ($fn -and $fn -notmatch '^\.' -and $fn.Length -gt 3) {
                            Update-Index -Value $fn.ToLower() -IsMalicious $isMalicious -LegitName $legitName
                        }
                    }
                }
                # Registry keys (suspicious paths only, leaf component)
                if ($d.registry_keys_set) {
                    $d.registry_keys_set | Where-Object { $_ -match "Run|RunOnce|Services|Winlogon|AppInit|Shell|Policies" } |
                        ForEach-Object {
                            $leaf = ($_ -split '\\')[-1]
                            if ($leaf -and $leaf.Length -gt 2) {
                                Update-Index -Value $leaf.ToLower() -IsMalicious $isMalicious -LegitName $legitName
                            }
                        }
                }
                # Mutex names
                if ($d.mutexes_created) {
                    $d.mutexes_created | Where-Object { $_ -and $_.Length -gt 4 -and $_ -notmatch '^[\w]{1,4}$' } |
                        ForEach-Object { Update-Index -Value $_ -IsMalicious $isMalicious -LegitName $legitName }
                }
                # MITRE technique IDs
                if ($d.mitre_attack_techniques) {
                    $d.mitre_attack_techniques | ForEach-Object {
                        $tid = $_.id -replace '\.\d+$',''
                        if ($tid -match '^T\d{4}') { Update-Index -Value $tid -IsMalicious $isMalicious -LegitName $legitName }
                    }
                }
                # High-severity behavior signatures
                if ($d.signatures) {
                    $d.signatures | Where-Object { $_.severity -ge 7 } | ForEach-Object {
                        if ($_.name) { Update-Index -Value $_.name -IsMalicious $isMalicious -LegitName $legitName }
                    }
                }
                # VT-highlighted API calls (e.g. CreateRemoteThread, VirtualAllocEx)
                if ($d.calls_highlighted) {
                    $d.calls_highlighted | Where-Object { $_ -and $_.Length -gt 3 } | ForEach-Object {
                        Update-Index -Value "api:$_" -IsMalicious $isMalicious -LegitName $legitName
                    }
                }
                # DLL modules loaded (basename, .dll only) - maps to Sysmon EID 7
                if ($d.modules_loaded) {
                    $d.modules_loaded | ForEach-Object {
                        $dll = [System.IO.Path]::GetFileName("$_").ToLower()
                        if ($dll -match '\.dll$' -and $dll.Length -gt 4) {
                            Update-Index -Value $dll -IsMalicious $isMalicious -LegitName $legitName
                        }
                    }
                }
                # Processes injected into - maps to Sysmon EID 8/10 TargetImage
                if ($d.processes_injected) {
                    $d.processes_injected | ForEach-Object {
                        $pn = [System.IO.Path]::GetFileName("$_").ToLower()
                        if ($pn -and $pn.Length -gt 3) {
                            Update-Index -Value $pn -IsMalicious $isMalicious -LegitName $legitName
                        }
                    }
                }

            } catch { <# skip malformed files #> }
        }

        Write-Host "    $cat complete: $processed files, index now $($allKeys.Count) entries" -ForegroundColor DarkGray
    }

    # -----------------------------------------------------------------------
    # Phase 2: Merge APT differential analysis files
    # Rule: LOWEST GoodCount wins. Phase 2 entries with Baseline_Count=0 force
    # GoodCount=0 even if the VT baseline had GoodCount>0 (unique to malware).
    # -----------------------------------------------------------------------
    if ($AptRoot -and (Test-Path $AptRoot)) {
        Write-Host "`n  [Phase 2] Merging APT differential analysis from $AptRoot ..." -ForegroundColor DarkCyan
        $aptFiles = Get-ChildItem $AptRoot -Recurse -Filter "Targeted*DifferentialAnalysis.json" -ErrorAction SilentlyContinue
        Write-Host "    Found $($aptFiles.Count) APT differential files" -ForegroundColor DarkGray

        $aptUpdated = 0; $aptAdded = 0
        foreach ($af in $aptFiles) {
            try {
                $entries = Get-Content $af.FullName -Raw | ConvertFrom-Json
                foreach ($entry in $entries) {
                    $key = if ($entry.Item_Name) { $entry.Item_Name.Trim() } else { $null }
                    if (-not $key -or $key.Length -lt 3) { continue }
                    $mc = [int]($entry.Malicious_Count -as [int])
                    if (-not $mc) { $mc = 1 }
                    $gc = [int]($entry.Baseline_Count -as [int])

                    if ($allKeys.Contains($key)) {
                        # Existing Phase 1 entry: lowest GoodCount wins, highest MalCount wins
                        if ($gc -lt [int]($goodCount[$key])) { $goodCount[$key] = $gc; $aptUpdated++ }
                        if ($mc -gt [int]($malCount[$key]))  { $malCount[$key]  = $mc }
                    } else {
                        # New APT-only entry
                        $malCount[$key]  = $mc
                        $goodCount[$key] = $gc
                        [void]$allKeys.Add($key)
                        $aptAdded++
                    }
                }
            } catch { <# skip malformed #> }
        }
        Write-Host "    APT merge complete: $aptUpdated indicators updated (lower GoodCount), $aptAdded new indicators added" -ForegroundColor DarkGray
    } elseif ($AptRoot) {
        Write-Host "`n  [Phase 2] APT root not found at $AptRoot - skipping" -ForegroundColor DarkYellow
    }

    # Compute fidelity scores - iterate only indicators seen in malware
    Write-Host "`n  Computing fidelity scores for $($malCount.Count) malware indicators (of $($allKeys.Count) total)..." -ForegroundColor DarkCyan

    # DEBUG: sample first 3 entries to verify values are non-zero
    $dbgSample = @($malCount.GetEnumerator() | Select-Object -First 3)
    foreach ($dbg in $dbgSample) {
        Write-Host "  [DEBUG] Key='$($dbg.Key)'  Value=$($dbg.Value)  Type=$($dbg.Value.GetType().Name)" -ForegroundColor Magenta
    }

    $uniqueCount = 0; $rareCount = 0

    $out = @{}
    foreach ($kvp in $malCount.GetEnumerator()) {
        $key = $kvp.Key
        $mc  = [int]$kvp.Value
        if ($mc -eq 0) { continue }
        $gc = [int]($goodCount[$key])   # 0 if indicator never seen in good files

        $score = if   ($gc -eq 0)  { 100 }
                 elseif ($gc -le 3) {  95 }
                 else { [Math]::Max(30, 95 - ([Math]::Log($gc + 1, 2) * 15)) }

        $unique = $score -eq 100
        $rare   = $score -eq 95
        if ($unique) { $uniqueCount++ }
        if ($rare)   { $rareCount++ }

        $legit = if ($legitNames.ContainsKey($key)) { @($legitNames[$key]) } else { @() }

        $out[$key] = [PSCustomObject]@{
            M = $mc
            G = $gc
            S = [Math]::Round($score, 1)
            U = $unique
            R = $rare
            L = $legit
        }
    }

    $elapsed = (Get-Date) - $startTime
    Write-Host "`n  Index complete:" -ForegroundColor Green
    Write-Host "    Total behavior files scanned : $totalProcessed"
    Write-Host "    Indicators with malware hits : $($out.Count)"
    Write-Host "    Unique to malware (score=100): $uniqueCount"
    Write-Host "    Rare       (score=95)        : $rareCount"
    Write-Host "    Build time                   : $([Math]::Round($elapsed.TotalMinutes, 1)) minutes"

    Write-Host "`n  Saving fidelity index to $outFile ..." -ForegroundColor DarkCyan
    ([PSCustomObject]$out) | ConvertTo-Json -Depth 4 -Compress | Set-Content $outFile -Encoding UTF8
    Write-Host "  Saved. ($([Math]::Round((Get-Item $outFile).Length / 1MB, 1)) MB)" -ForegroundColor Green

    # Process baseline  -  iterate $procG keys directly (processes seen in known-good files)
    $procOutFile = Join-Path $BaselineRoot "process-baseline.json"
    Write-Host "`n  Building process baseline from $($script:_vtfi_procG.Count) known-good process names..." -ForegroundColor DarkCyan
    $procOut = @{}
    foreach ($pn in $script:_vtfi_procG.Keys) {
        $gVal = [int]($script:_vtfi_procG[$pn])
        if ($gVal -eq 0) { continue }
        $signers = @($script:_vtfi_procSigners[$pn] -split '\|' | Where-Object { $_ })
        $dirs    = @($script:_vtfi_procDirs[$pn]    -split '\|' | Where-Object { $_ })
        $procOut[$pn] = [PSCustomObject]@{
            G = $gVal
            M = [int]($script:_vtfi_procM[$pn])
            S = $signers
            D = $dirs
        }
    }
    Write-Host "    Process baseline entries (known-good): $($procOut.Count)"
    ([PSCustomObject]$procOut) | ConvertTo-Json -Depth 4 -Compress | Set-Content $procOutFile -Encoding UTF8
    Write-Host "  Process baseline saved. ($([Math]::Round((Get-Item $procOutFile).Length / 1MB, 2)) MB)" -ForegroundColor Green

    # Clean up module-scope working variables
    $script:_vtfi_mal = $null; $script:_vtfi_good = $null; $script:_vtfi_legit = $null
    $script:_vtfi_keys = $null
    $script:_vtfi_procG = $null; $script:_vtfi_procM = $null
    $script:_vtfi_procSigners = $null; $script:_vtfi_procDirs = $null
    $script:_vtfi_maxLN = $null

    return [PSCustomObject]@{
        IndexPath    = $outFile
        Entries      = $out.Count
        UniqueCount  = $uniqueCount
        RareCount    = $rareCount
        FilesScanned = $totalProcessed
        BuildSeconds = [Math]::Round($elapsed.TotalSeconds)
    }
}
