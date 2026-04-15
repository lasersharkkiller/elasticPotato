function Invoke-ElasticAlertAgentAnalysis {
    <#
    .SYNOPSIS
        Offline cybersecurity alert triage agent - no external AI or network callouts.

    .DESCRIPTION
        Accepts an Elastic Security alert context and surrounding host forensics
        (from Get-ElasticAlertsAndThreats or entered interactively), enriches each
        process hash against tens of thousands of offline VirusTotal baseline JSON
        files (SignedVerified, unsignedWin, unsignedLinux, unverified, drivers,
        malicious), then runs a deterministic local scoring engine to produce a
        FP/TP/SUSPICIOUS verdict with MITRE-aligned findings and recommended next steps.
        All analysis is 100% offline - no API keys, no internet access required.

    .PARAMETER AlertContext
        Hashtable with alert and Know Normal data. Keys:
          RuleName, RuleType, HostName, OS,
          ProcessName, ProcessPath, ProcessHash, ParentProcess,
          ProcessSigner, ProcessSigned (bool), ProcessTrusted (bool),
          ParentFrequencyPct (double), ParentUniqueParentCount (int),
          PathFrequencyPct (double), PathUniqueCount (int),
          UnsignedPct (double),
          MasqueradeMatches (PSCustomObject[] with LegitSigner/Count),
          AnomalousPorts (string[]), AnomalousIPs (string[]),
          AnomalousDNS (string[]), AnomalousIndicators (string[]),
          AdditionalHashes (string[])  -- extra hashes to enrich (child procs, DLLs, etc.)
        If omitted the function prompts interactively.

    .PARAMETER BaselineMainRoot
        Root folder for VirusTotal-main subfolders. Default: output-baseline\VirusTotal-main

    .PARAMETER BaselineBehaviorsRoot
        Root folder for VirusTotal-behaviors subfolders. Default: output-baseline\VirusTotal-behaviors

    .EXAMPLE
        # Standalone interactive mode
        Invoke-ElasticAlertAgentAnalysis

    .EXAMPLE
        # Programmatic mode after running Get-ElasticAlertsAndThreats
        $ctx = @{
            RuleName = "Suspicious PowerShell"; RuleType = "eql"
            HostName = "WORKSTATION-01"; OS = "windows"
            ProcessName = "powershell.exe"; ProcessPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
            ProcessHash = "abc123..."; ParentProcess = "cmd.exe"
            ProcessSigned = $true; ProcessTrusted = $true; ProcessSigner = "Microsoft Corporation"
            ParentFrequencyPct = 2.1; ParentUniqueParentCount = 15
            PathFrequencyPct = 98.5; PathUniqueCount = 1
            UnsignedPct = 0.0
            AnomalousPorts = @(4444); AnomalousIPs = @("185.234.1.50"); AnomalousDNS = @()
            MasqueradeMatches = @(); AnomalousIndicators = @()
            AdditionalHashes = @()
        }
        Invoke-ElasticAlertAgentAnalysis -AlertContext $ctx
    #>
    param(
        [hashtable]$AlertContext              = $null,
        [string]$DetonationLogsDir           = "",
        [string]$BaselineMainRoot             = "output-baseline\VirusTotal-main",
        [string]$BaselineBehaviorsRoot        = "output-baseline\VirusTotal-behaviors"
    )

    # Resolve baseline paths to absolute (relative defaults only work from repo root)
    if (-not [System.IO.Path]::IsPathRooted($BaselineMainRoot)) {
        $BaselineMainRoot = Join-Path $PSScriptRoot "..\$BaselineMainRoot"
    }
    if (-not [System.IO.Path]::IsPathRooted($BaselineBehaviorsRoot)) {
        $BaselineBehaviorsRoot = Join-Path $PSScriptRoot "..\$BaselineBehaviorsRoot"
    }

    # ---- BASELINE CATEGORY FOLDERS ----
    $Categories = @("SignedVerified","unsignedWin","unsignedLinux","unverified","drivers","malicious")

    # -----------------------------------------------------------------------
    # HELPER: Find-VTHashBaseline
    # Returns @{ Category; MainFile; BehaviorFile } or $null if not cached.
    # -----------------------------------------------------------------------
    function Find-VTHashBaseline {
        param([string]$Hash)
        if ([string]::IsNullOrWhiteSpace($Hash)) { return $null }
        $h = $Hash.Trim().ToLower()
        foreach ($cat in $Categories) {
            $mainPath = Join-Path $BaselineMainRoot "$cat\$h.json"
            if (Test-Path $mainPath) {
                $behPath = Join-Path $BaselineBehaviorsRoot "$cat\$h.json"
                return @{
                    Category     = $cat
                    MainFile     = $mainPath
                    BehaviorFile = if (Test-Path $behPath) { $behPath } else { $null }
                }
            }
        }
        return $null
    }

    # -----------------------------------------------------------------------
    # HELPER: Get-VTMainSummary
    # Extracts key fields from a VT main JSON file into a plain hashtable.
    # -----------------------------------------------------------------------
    function Get-VTMainSummary {
        param([string]$Path)
        if (-not $Path -or -not (Test-Path $Path)) { return $null }
        try {
            $j = Get-Content $Path -Raw | ConvertFrom-Json
            $a = $j.data.attributes
            $stats    = $a.last_analysis_stats
            $detMal   = if ($stats) { $stats.malicious }   else { 0 }
            $detSusp  = if ($stats) { $stats.suspicious }  else { 0 }
            $detTotal = if ($stats) { ($stats.malicious + $stats.suspicious + $stats.undetected + $stats.harmless) } else { 0 }
            $sigInfo  = $a.signature_info
            $threat   = $a.popular_threat_classification

            return @{
                MeaningfulName    = $a.meaningful_name
                Names             = if ($a.names) { ($a.names | Select-Object -First 5) -join ", " } else { "" }
                FileType          = $a.type_description
                Tags              = if ($a.type_tags) { $a.type_tags -join ", " } else { "" }
                SizeByes          = $a.size
                DetectionRatio    = "$detMal malicious + $detSusp suspicious / $detTotal engines"
                DetectionsMal     = $detMal
                Signer            = if ($sigInfo) { $sigInfo.product } else { "" }
                SignerStatus      = if ($sigInfo) { $sigInfo.verified } else { "unsigned" }
                ThreatLabel       = if ($threat) { $threat.suggested_threat_label } else { "" }
                ThreatCategory    = if ($threat -and $threat.popular_threat_category) {
                                        ($threat.popular_threat_category | Select-Object -First 3 | ForEach-Object { $_.value }) -join ", "
                                    } else { "" }
                FirstSeen         = if ($a.first_submission_date) {
                                        [DateTimeOffset]::FromUnixTimeSeconds($a.first_submission_date).ToString("yyyy-MM-dd")
                                    } else { "" }
                LastAnalysis      = if ($a.last_analysis_date) {
                                        [DateTimeOffset]::FromUnixTimeSeconds($a.last_analysis_date).ToString("yyyy-MM-dd")
                                    } else { "" }
                Reputation        = $a.reputation
            }
        } catch {
            return $null
        }
    }

    # -----------------------------------------------------------------------
    # HELPER: Get-VTBehaviorSummary
    # Extracts key behavioral fields from a VT behaviors JSON file.
    # -----------------------------------------------------------------------
    function Get-VTBehaviorSummary {
        param([string]$Path)
        if (-not $Path -or -not (Test-Path $Path)) { return $null }
        try {
            $j = Get-Content $Path -Raw | ConvertFrom-Json
            $d = $j.data

            # MITRE ATT&CK techniques (deduplicated)
            $mitre = @()
            if ($d.mitre_attack_techniques) {
                $mitre = $d.mitre_attack_techniques | ForEach-Object {
                    "$($_.id) $($_.signature_description)"
                } | Select-Object -Unique | Select-Object -First 20
            }

            # MBC (Malware Behavior Catalog) - key behaviors only
            $mbc = @()
            if ($d.mbc) {
                $mbc = $d.mbc | ForEach-Object {
                    $m = $_
                    $method = if ($m.method) { " ($($m.method))" } else { "" }
                    "$($m.id) [$($m.objective)] $($m.behavior)$method"
                } | Select-Object -First 15
            }

            # High-severity behavior signatures
            $sigs = @()
            if ($d.signatures) {
                $sigs = $d.signatures | Where-Object { $_.severity -ge 5 } |
                    Sort-Object severity -Descending |
                    ForEach-Object { "[$($_.severity)/10] $($_.name)" } |
                    Select-Object -First 10
            }

            # Network connections (external only, deduplicated)
            $netConns = @()
            if ($d.ip_traffic) {
                $netConns = $d.ip_traffic | ForEach-Object {
                    "$($_.destination_ip):$($_.destination_port) ($($_.transport_layer_protocol))"
                } | Select-Object -Unique | Select-Object -First 10
            }

            # DNS lookups
            $dnsLookups = @()
            if ($d.dns_lookups) {
                $dnsLookups = $d.dns_lookups | ForEach-Object { $_.hostname } |
                    Select-Object -Unique | Select-Object -First 15
            }

            # Files written (suspicious paths only)
            $filesWritten = @()
            if ($d.files_written) {
                $filesWritten = $d.files_written | Where-Object {
                    $_ -match "\\Temp\\|\\AppData\\|\\ProgramData\\|\\Windows\\System32\\|\.bat|\.ps1|\.vbs|\.exe|\.dll"
                } | Select-Object -First 10
            }

            # Processes created
            $procsCreated = @()
            if ($d.processes_created) {
                $procsCreated = $d.processes_created | Select-Object -First 10
            }

            # Registry keys set (suspicious)
            $regKeys = @()
            if ($d.registry_keys_set) {
                $regKeys = $d.registry_keys_set | Where-Object {
                    $_ -match "Run|RunOnce|Services|CurrentVersion\\Policies|Winlogon|Shell|AppInit"
                } | Select-Object -First 8
            }

            return @{
                MitreAttack     = $mitre
                MBC             = $mbc
                HighSigsBehavior = $sigs
                NetworkConns    = $netConns
                DNSLookups      = $dnsLookups
                FilesWritten    = $filesWritten
                ProcessesCreated = $procsCreated
                RegistryKeys    = $regKeys
            }
        } catch {
            return $null
        }
    }

    # -----------------------------------------------------------------------
    # HELPER: Format-HashEnrichment
    # Builds a human-readable VT enrichment block for one hash.
    # -----------------------------------------------------------------------
    function Format-HashEnrichment {
        param(
            [string]$Hash,
            [string]$Label = ""
        )
        $result = Find-VTHashBaseline -Hash $Hash
        if (-not $result) {
            return "Hash $Hash ($Label): NOT IN OFFLINE BASELINE (never seen or not yet pulled from VT)"
        }

        $main = Get-VTMainSummary -Path $result.MainFile
        $beh  = Get-VTBehaviorSummary -Path $result.BehaviorFile

        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.AppendLine("Hash $Hash ($Label):")
        [void]$sb.AppendLine("  Baseline Category : $($result.Category)")

        # Detection ratio - parse malicious count to decide whether to show MITRE
        $malDetections = 0
        if ($main) {
            [void]$sb.AppendLine("  Detection Ratio   : $($main.DetectionRatio)")
            $ratioMatch = [regex]::Match($main.DetectionRatio, '^(\d+)/')
            if ($ratioMatch.Success) { $malDetections = [int]$ratioMatch.Groups[1].Value }
        }

        # MITRE ATT&CK - only when explicitly malicious or detections > 0
        $isMalCat = $result.Category -eq 'malicious'
        if ($beh -and $beh.MitreAttack.Count -gt 0 -and ($isMalCat -or $malDetections -gt 0)) {
            [void]$sb.AppendLine("  MITRE ATT&CK:")
            $beh.MitreAttack | ForEach-Object { [void]$sb.AppendLine("    - $_") }
        }

        return $sb.ToString()
    }

    # -----------------------------------------------------------------------
    # HELPER: Get-IndicatorFidelity
    # Checks whether an indicator (IP, domain, process name, etc.) appears in
    # known-good VT behavior files. Returns a score mirroring the API matrix:
    #   100 = Unique to Malware (zero presence in any known-good sample)
    #    95 = Rare (1-3 known-good appearances, likely legit use is incidental)
    #   <95 = Common (more than 3 known-good appearances)
    # Also returns up to 5 legitimate file/product names so the analyst knows
    # what benign software uses this indicator.
    # -----------------------------------------------------------------------
    function Get-IndicatorFidelity {
        param([string]$Indicator, [int]$SampleLimit = 300)
        if ([string]::IsNullOrWhiteSpace($Indicator)) { return @{ Score=50; Found=0; LegitUses=@(); Unique=$false; Rare=$false } }

        $goodCats  = @("SignedVerified","unsignedWin","unverified","drivers")
        $legitNames = [System.Collections.Generic.List[string]]::new()
        $found = 0

        foreach ($cat in $goodCats) {
            $catPath = Join-Path $BaselineBehaviorsRoot $cat
            if (-not (Test-Path $catPath)) { continue }
            $files = Get-ChildItem $catPath -Filter "*.json" -ErrorAction SilentlyContinue | Select-Object -First $SampleLimit
            foreach ($f in $files) {
                try {
                    $content = [System.IO.File]::ReadAllText($f.FullName)
                    if ($content.IndexOf($Indicator, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                        $found++
                        if ($legitNames.Count -lt 5) {
                            $mainPath = Join-Path $BaselineMainRoot "$cat\$($f.BaseName).json"
                            if (Test-Path $mainPath) {
                                $mj   = Get-Content $mainPath -Raw | ConvertFrom-Json
                                $attr = $mj.data.attributes
                                $name = if ($attr.meaningful_name) { $attr.meaningful_name }
                                        elseif ($attr.names)       { $attr.names[0] }
                                        else                       { $f.BaseName.Substring(0,12) }
                                if ($name -and -not $legitNames.Contains($name)) { $legitNames.Add($name) }
                            }
                        }
                    }
                } catch {}
                if ($found -ge 10) { break }   # Enough to classify as common
            }
            if ($found -ge 10) { break }
        }

        $score = if ($found -eq 0)              { 100 }
                 elseif ($found -le 3)          {  95 }
                 else { [Math]::Max(50, 95 - ($found * 5)) }

        return @{
            Score     = $score
            Found     = $found
            LegitUses = $legitNames.ToArray()
            Unique    = $found -eq 0
            Rare      = $found -gt 0 -and $found -le 3
        }
    }

    # -----------------------------------------------------------------------
    # HELPER: Invoke-BatchFidelityScan
    # Looks up indicators against the pre-built fidelity index (built once by
    # Build-VTFidelityIndex.psm1 which scans the ENTIRE offline database).
    # Falls back to a live partial scan if the index does not exist, and warns
    # the user to build the index for full coverage.
    # -----------------------------------------------------------------------
    function Invoke-BatchFidelityScan {
        param([string[]]$Indicators, [int]$SamplePerCategory = 1000)

        $fidMap = @{}
        $cleanInds = $Indicators | Where-Object { $_ -and $_.Length -ge 3 } | Select-Object -Unique
        if (-not $cleanInds) { return $fidMap }

        # ---- PRIMARY: use pre-built index (full database coverage) ----
        $indexPath = Join-Path $PSScriptRoot "..\output-baseline\fidelity-index.json"
        if (-not [System.IO.Path]::IsPathRooted($indexPath)) {
            $indexPath = Join-Path $PSScriptRoot "..\output-baseline\fidelity-index.json"
        }

        if (Test-Path $indexPath) {
            Write-Host "    Loading pre-built fidelity index..." -ForegroundColor DarkGray
            try {
                $index = Get-Content $indexPath -Raw | ConvertFrom-Json
                foreach ($ind in $cleanInds) {
                    $key = $ind.ToLower().Trim()
                    $entry = $index.$key
                    if (-not $entry) { $entry = $index.$ind }   # try original casing too
                    if ($entry) {
                        $fidMap[$ind] = @{
                            MalCount   = $entry.M
                            GoodCount  = $entry.G
                            Score      = $entry.S
                            Unique     = [bool]$entry.U
                            Rare       = [bool]$entry.R
                            LegitNames = @($entry.L)
                        }
                    } else {
                        # Not in index = not seen in any malware in our entire database
                        $fidMap[$ind] = @{ MalCount=0; GoodCount=0; Score=0; Unique=$false; Rare=$false; LegitNames=@() }
                    }
                }
                $hits = @($fidMap.Values | Where-Object { $_.MalCount -gt 0 }).Count
                Write-Host "    Index lookup complete: $($cleanInds.Count) artifacts, $hits with malware association" -ForegroundColor DarkGray
                return $fidMap
            } catch {
                Write-Host "    [!] Index load failed: $($_.Exception.Message) -- falling back to live scan" -ForegroundColor Yellow
            }
        } else {
            Write-Host "    [!] No fidelity index found at: $indexPath" -ForegroundColor Yellow
            Write-Host "    [!] Run Build-VTFidelityIndex once for full database coverage." -ForegroundColor Yellow
            Write-Host "    [!] Falling back to partial live scan ($SamplePerCategory files/category)..." -ForegroundColor Yellow
        }

        # ---- FALLBACK: live partial scan (limited coverage, warns user) ----
        foreach ($ind in $cleanInds) {
            $fidMap[$ind] = @{ MalCount=0; GoodCount=0; Score=0; Unique=$false; Rare=$false; LegitNames=[System.Collections.Generic.List[string]]::new() }
        }

        $malPath = Join-Path $BaselineBehaviorsRoot "malicious"
        if (Test-Path $malPath) {
            foreach ($f in (Get-ChildItem $malPath -Filter "*.json" -ErrorAction SilentlyContinue | Select-Object -First $SamplePerCategory)) {
                try {
                    $content = [System.IO.File]::ReadAllText($f.FullName)
                    foreach ($ind in $fidMap.Keys) {
                        if ($content.IndexOf($ind, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { $fidMap[$ind].MalCount++ }
                    }
                } catch {}
            }
        }
        foreach ($cat in @("SignedVerified","unsignedWin","unverified","drivers")) {
            $catPath = Join-Path $BaselineBehaviorsRoot $cat
            if (-not (Test-Path $catPath)) { continue }
            foreach ($f in (Get-ChildItem $catPath -Filter "*.json" -ErrorAction SilentlyContinue | Select-Object -First $SamplePerCategory)) {
                try {
                    $content = [System.IO.File]::ReadAllText($f.FullName)
                    $nameLoaded = $false; $legitName = ""
                    foreach ($ind in $fidMap.Keys) {
                        if ($content.IndexOf($ind, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                            $fidMap[$ind].GoodCount++
                            if ($fidMap[$ind].LegitNames.Count -lt 3) {
                                if (-not $nameLoaded) {
                                    $mp = Join-Path $BaselineMainRoot "$cat\$($f.BaseName).json"
                                    if (Test-Path $mp) {
                                        try { $mj = Get-Content $mp -Raw | ConvertFrom-Json
                                              $attr = $mj.data.attributes
                                              $legitName = if ($attr.meaningful_name) { $attr.meaningful_name } elseif ($attr.names) { $attr.names[0] } else { "" }
                                        } catch {}
                                    }
                                    $nameLoaded = $true
                                }
                                if ($legitName -and -not $fidMap[$ind].LegitNames.Contains($legitName)) { [void]$fidMap[$ind].LegitNames.Add($legitName) }
                            }
                        }
                    }
                } catch {}
            }
        }
        foreach ($ind in $fidMap.Keys) {
            $r = $fidMap[$ind]
            if ($r.MalCount -gt 0 -and $r.GoodCount -eq 0)    { $r.Score = 100; $r.Unique = $true }
            elseif ($r.MalCount -gt 0 -and $r.GoodCount -le 3) { $r.Score = 95;  $r.Rare   = $true }
            elseif ($r.MalCount -gt 0)                          { $r.Score = [Math]::Max(50, 95 - ($r.GoodCount * 5)) }
        }
        return $fidMap
    }

    # -----------------------------------------------------------------------
    # HOST-MODE: Query Elastic directly OR read offline NDJSON detonation logs
    # Use -DetonationLogsDir <path> (output of Get-ElasticDetonationLogs) for
    # fully offline analysis  -  no Elastic connection required.
    # -----------------------------------------------------------------------
    if (-not $AlertContext) {
        $offlineMode  = ($DetonationLogsDir -ne "" -and (Test-Path $DetonationLogsDir))
        $mlHits       = @()  # populated in offline mode from ML alert data; live mode extracts below
        $deepAnalysis = $null
        $lokiResult   = $null
        $shellCmdEvents  = @()
        $shellCmds       = @()
        $shellCmdsByProc = @()
        $nonPsShellCmds  = @()
        $shellExecNames  = @(
            'cmd.exe','powershell.exe','pwsh.exe','wscript.exe','cscript.exe',
            'mshta.exe','rundll32.exe','regsvr32.exe','wmic.exe',
            'bash.exe','sh.exe','zsh.exe','ksh.exe','fish.exe'
        )

        # =====================================================================
        # OFFLINE NDJSON MODE
        # Reads the NDJSON files saved by Get-ElasticDetonationLogs and
        # populates the same variable set as the live Elastic mode, so the
        # shared fidelity-scan / verdict / HTML report pipeline runs unchanged.
        # =====================================================================
        if ($offlineMode) {
            Write-Host "`n[Elastic Alert Agent] Offline NDJSON Detonation Analysis" -ForegroundColor DarkCyan
            Write-Host "  Source : $DetonationLogsDir" -ForegroundColor DarkGray

            # Helper: stream-parse an NDJSON file into an array of PSCustomObjects
            function Read-Ndjson {
                param([string]$Path)
                if (-not (Test-Path $Path)) { return @() }
                @(Get-Content $Path | Where-Object { $_.TrimStart().StartsWith('{') } | ForEach-Object {
                    try { $_ | ConvertFrom-Json -ErrorAction Stop } catch {}
                })
            }

            # Helper: build a minimal mock ES aggregation result that satisfies the
            # null-safe  $var?.aggregations.by_xxx.buckets  pattern used throughout
            function New-MockAgg {
                param([hashtable]$Fields)
                $aggHash = [ordered]@{}
                foreach ($k in $Fields.Keys) {
                    $buckets = @($Fields[$k] | Where-Object { $_ } | Select-Object -Unique | ForEach-Object {
                        [PSCustomObject]@{ key = "$_"; doc_count = 1 }
                    })
                    $aggHash[$k] = [PSCustomObject]@{ buckets = $buckets }
                }
                [PSCustomObject]@{
                    hits         = [PSCustomObject]@{ total = [PSCustomObject]@{ value = 0 }; hits = @() }
                    aggregations = [PSCustomObject]$aggHash
                }
            }

            # -----------------------------------------------------------------------
            # OFFLINE DEEP BEHAVIORAL ANALYSIS ENGINE
            # Replicates expert analyst process: API patterns -> process chain ->
            # PE masquerade -> network C2 -> file entropy -> registry persistence ->
            # DLL evasion -> MITRE mapping -> narrative verdict.
            # All detection is deterministic from in-memory NDJSON doc arrays.
            # -----------------------------------------------------------------------
            function Get-OfflineDeepAnalysis {
                param($ProcDocs,$ApiDocs,$AlertDocs,$FileDocs,$NetDocs,$RegDocs,$ImgDocs,$LokiResult)

                $findings   = [System.Collections.Generic.List[PSCustomObject]]::new()
                $mitreTechs = [System.Collections.Generic.List[PSCustomObject]]::new()

                # -----------------------------------------------------------------------
                # Load network IOCs (Domain, IP, URL) from all *_Master_Intel.csv files.
                # This makes domain/IP attribution data-driven rather than hardcoded.
                # Any row with IOCType=Domain|IP|URL is indexed here at function start
                # so all modules below can look up observed indicators against it.
                # -----------------------------------------------------------------------
                $netActorMap = @{}  # IOCValue.ToLower() -> @{Actor; Context; Type; Source}
                # Benign domains that appear in some APT intel CSVs as collateral
                # (e.g. kimsuky sheets list google.com, bing.com). Excluding them
                # prevents false "Confirmed C2" findings for legitimate infrastructure.
                $aptDomainExclusions = [System.Collections.Generic.HashSet[string]]::new(
                    [System.StringComparer]::OrdinalIgnoreCase)
                @('google.com','www.google.com','accounts.google.com','mail.google.com',
                  'drive.google.com','docs.google.com','play.google.com','googleapis.com',
                  'bing.com','www.bing.com','login.live.com','live.com','outlook.com',
                  'microsoft.com','office.com','windows.com','apple.com','icloud.com',
                  'amazon.com','cloudflare.com','github.com','youtube.com','facebook.com',
                  'twitter.com','linkedin.com','yahoo.com','dropbox.com','onedrive.live.com'
                ) | ForEach-Object { [void]$aptDomainExclusions.Add($_) }
                $aptNetCsvRoot = Join-Path $PSScriptRoot "..\apt"
                if (Test-Path $aptNetCsvRoot) {
                    $netCsvFiles = Get-ChildItem -Path $aptNetCsvRoot -Filter "*_Master_Intel.csv" -Recurse -ErrorAction SilentlyContinue
                    foreach ($nc in $netCsvFiles) {
                        try {
                            $ncRows = Import-Csv $nc.FullName -ErrorAction Stop
                            foreach ($nr in $ncRows) {
                                $nType = ($nr.IOCType -replace '"','').Trim()
                                # Accept canonical types written by aptIocs.psm1 normalization.
                                # Also accept any legacy/un-normalized variants still in older CSVs.
                                $nTypeNorm = switch -Regex ($nType.ToLower()) {
                                    '^domain$|^hostname$|^fqdn$' { 'Domain'; break }
                                    '^ipv4$|^ipv6$|^ip$|^ip:port$' { 'IP'; break }
                                    '^url$' { 'URL'; break }
                                    default { $null }
                                }
                                if (-not $nTypeNorm) { continue }

                                $nVal = ($nr.IOCValue -replace '"','').Trim().ToLower()
                                if (-not $nVal) { continue }
                                # Skip benign domains that appear in some APT sheets as collateral
                                if ($nTypeNorm -eq 'Domain' -and $aptDomainExclusions.Contains($nVal)) { continue }

                                # For ip:port values strip the port so lookup matches bare IPs
                                if ($nTypeNorm -eq 'IP' -and $nVal -match '^(.+):\d+$') {
                                    $nVal = $Matches[1]
                                }
                                # For URLs extract the hostname for DNS-based matching
                                if ($nTypeNorm -eq 'URL') {
                                    try {
                                        $uriHost = ([System.Uri]$nVal).Host
                                        if ($uriHost) { $nVal = $uriHost }
                                    } catch {}
                                }

                                if ($netActorMap.ContainsKey($nVal)) { continue }
                                $nActor = ($nr.Actor -replace '"','').Trim()
                                if (-not $nActor) { $nActor = $nc.Directory.Name }
                                $netActorMap[$nVal] = @{
                                    Actor   = $nActor
                                    Context = ($nr.Context -replace '"','').Trim()
                                    Type    = $nTypeNorm
                                    Source  = ($nc.Name -replace '_Master_Intel\.csv','')
                                }
                            }
                        } catch {}
                    }
                }

                # Pass 2 -- dated IOC CSVs (IOC,Type,Sources,Max confidence,Last Seen,Detection count)
                $netRegionFolders = @('Russia','China','NorthKorea','Iran','eCrime','Vietnam','SouthAmerica','Picus','APTs','Malware Families')
                if (Test-Path $aptNetCsvRoot) {
                    $netIocFiles = @(Get-ChildItem -Path $aptNetCsvRoot -Recurse -File -ErrorAction SilentlyContinue |
                        Where-Object { $_.Extension -eq '.csv' -and $_.Name -match '\d{4}-\d{2}-\d{2}' -and
                                       $_.Name -notmatch '_Master_Intel' -and $_.Name -notmatch 'Targeted_Analysis_Map' })
                    foreach ($nif in $netIocFiles) {
                        try {
                            $nifParent = Split-Path (Split-Path $nif.FullName -Parent) -Leaf
                            $nifActor = if ($netRegionFolders -notcontains $nifParent) {
                                $nifParent
                            } else {
                                ($nif.BaseName -replace '(?i)_IOCs?$','' -replace '(?i)_\d{4}-\d{2}-\d{2}.*$','' `
                                               -replace '(?i)_deduplicated$','' -replace '_',' ').Trim()
                            }
                            $nifRows = Import-Csv $nif.FullName -Encoding UTF8 -ErrorAction SilentlyContinue
                            foreach ($nifRow in $nifRows) {
                                $nifVal = if ($nifRow.IOC) { $nifRow.IOC.Trim().ToLower() } else { '' }
                                if (-not $nifVal) { continue }
                                # Skip benign domains appearing as collateral in APT IOC sheets
                                $nifTypeRaw = if ($nifRow.Type) { $nifRow.Type.Trim() } else { '' }
                                $nifTypeNorm = switch -Regex ($nifTypeRaw.ToLower()) {
                                    '^domain$|^hostname$|^fqdn$' { 'Domain'; break }
                                    '^ipv4$|^ipv6$|^ip$|^ip:port$' { 'IP'; break }
                                    '^url$' { 'URL'; break }
                                    default { $null }
                                }
                                if (-not $nifTypeNorm) { continue }
                                if ($nifTypeNorm -eq 'Domain' -and $aptDomainExclusions.Contains($nifVal)) { continue }
                                if ($nifTypeNorm -eq 'IP' -and $nifVal -match '^(.+):\d+$') { $nifVal = $Matches[1] }
                                if ($nifTypeNorm -eq 'URL') {
                                    try { $nifHost = ([System.Uri]$nifVal).Host; if ($nifHost) { $nifVal = $nifHost } } catch {}
                                }
                                if ($netActorMap.ContainsKey($nifVal)) { continue }
                                $netActorMap[$nifVal] = @{
                                    Actor   = $nifActor
                                    Context = "Confidence:$($nifRow.'Max confidence') | Detections:$($nifRow.'Detection count')"
                                    Type    = $nifTypeNorm
                                    Source  = $nif.Name
                                }
                            }
                        } catch {}
                    }
                }

                function Add-DA-Finding {
                    param([string]$Severity,[string]$Category,[string]$Title,[string]$Detail,[string]$Mitre)
                    $findings.Add([PSCustomObject]@{Severity=$Severity;Category=$Category;Title=$Title;Detail=$Detail;Mitre=$Mitre})
                    if ($Mitre) {
                        foreach ($tp in ($Mitre -split '\s*\|\s*')) {
                            if ($tp -match '^T\d{4}' -and -not ($mitreTechs | Where-Object { $_.Id -eq $tp.Trim() })) {
                                $mitreTechs.Add([PSCustomObject]@{Id=$tp.Trim();Evidence=$Title})
                            }
                        }
                    }
                }

                # ==== MODULE 1: API / Behavioral Analysis ====

                # 1a. NTDLL Userland Unhooking
                $ntdllUnhooks = @($ApiDocs | Where-Object {
                    $_.process.Ext.api.name -eq 'WriteProcessMemory' -and
                    ($_.process.Ext.api.behaviors -match 'hook_api') -and
                    ($_.process.Ext.api.summary    -match 'ntdll\.dll' -or
                     $_.process.Ext.memory_region.mapped_path -match 'ntdll\.dll')
                })
                if ($ntdllUnhooks.Count -gt 0) {
                    $ntdllUnhooks | Group-Object { $_.process.name } | ForEach-Object {
                        $srcProc = $_.Name
                        $samp    = $_.Group[0]
                        $fn      = if ($samp.process.Ext.api.summary -match 'ntdll\.dll!(\S+)') { $Matches[1] } else { 'ntdll function' }
                        $sz      = $samp.process.Ext.memory_region.region_size
                        $addr    = $samp.process.Ext.api.parameters.address
                        $szNote  = if ($sz -eq 5) { '5-byte x86 JMP patch' } elseif ($sz -eq 8) { '8-byte x64 JMP patch' } else { "$sz bytes" }
                        $det = "$srcProc wrote $szNote to ntdll.dll!$fn (addr $addr)  -  removes EDR userland hook on this syscall stub, bypassing memory-protection and API monitoring. Technique: replace in-memory NTDLL stub with original syscall sequence so EDR callbacks are never reached."
                        Add-DA-Finding 'CRITICAL' 'Defense Evasion' "NTDLL Userland Hook Removal: $fn" $det 'T1562.001 | T1055'
                    }
                }

                # 1b. Process Hollowing (hollow_image behavior)
                $hollowEvts = @($ApiDocs | Where-Object { $_.process.Ext.api.behaviors -match 'hollow_image' -and $_.Target.process.name })
                if ($hollowEvts.Count -gt 0) {
                    $hollowEvts | Group-Object { "$($_.process.name)->$($_.Target.process.name)" } | ForEach-Object {
                        $parts = $_.Name -split '->'
                        $tgt   = $_.Group[0].process.Ext.memory_region.mapped_path
                        $tgtNote = if ($tgt) { " targeting $tgt" } else { "" }
                        Add-DA-Finding 'CRITICAL' 'Defense Evasion' "Process Image Tampering: $($parts[0]) → $($parts[1])" "$($parts[0]) overwrote image memory of $($parts[1])$tgtNote (hollow_image)  -  indicates process hollowing or in-memory PE replacement" 'T1055.012'
                    }
                }

                # 1c. Cross-process injection (non-startup WriteProcessMemory)
                $crossWrites = @($ApiDocs | Where-Object {
                    $_.process.Ext.api.name -eq 'WriteProcessMemory' -and
                    ($_.process.Ext.api.behaviors -match 'cross-process') -and
                    ($_.process.Ext.api.behaviors -notmatch 'hook_api') -and
                    ($_.process.Ext.api.summary   -notmatch 'ProcessStartupInfo')
                })
                if ($crossWrites.Count -gt 0) {
                    $crossWrites | Group-Object { "$($_.process.name)->$($_.Target.process.name)" } | ForEach-Object {
                        $parts = $_.Name -split '->'
                        $ct    = $_.Count
                        $sizes = ($_.Group | ForEach-Object { $_.process.Ext.memory_region.region_size } | Where-Object { $_ } | Select-Object -Unique -First 3) -join ', '
                        $det   = "$($parts[0]) performed $ct cross-process WriteProcessMemory call(s) into $($parts[1]) (sizes: $sizes bytes)  -  potential shellcode or payload injection"
                        Add-DA-Finding 'CRITICAL' 'Process Injection' "Cross-Process Memory Write: $($parts[0]) → $($parts[1])" $det 'T1055'
                    }
                }

                # 1d. Shellcode / allocate_shellcode behaviors
                $scEvts = @($ApiDocs | Where-Object { $_.process.Ext.api.behaviors -match 'shellcode|allocate_shellcode' })
                if ($scEvts.Count -gt 0) {
                    $scEvts | Group-Object { $_.process.name } | ForEach-Object {
                        $bstr = ($_.Group | ForEach-Object { $_.process.Ext.api.behaviors } | Where-Object { $_ } | Select-Object -Unique) -join ', '
                        Add-DA-Finding 'CRITICAL' 'Code Injection' "Shellcode Behavior: $($_.Name)" "$($_.Name): API event flagged with shellcode-related behaviors ($bstr)" 'T1055 | T1059'
                    }
                }

                # ==== MODULE 2: Process Chain Analysis ====

                # 2a. Unsigned blank-cmdline samples from Explorer (detonated/launched malware)
                $detonated = @($ProcDocs | Where-Object {
                    $_.process.parent.name -match '^explorer\.exe$' -and
                    [string]::IsNullOrWhiteSpace($_.process.command_line) -and
                    $_.process.code_signature.exists -eq $false -and
                    $_.event.type -match 'start'
                })
                if ($detonated.Count -gt 0) {
                    $dList = ($detonated | ForEach-Object {
                        $n = $_.process.name
                        $h = if ($_.process.hash.sha256) { " [$($_.process.hash.sha256.Substring(0,16))...]" } else { "" }
                        $s = if ($_.process.Ext.created_suspended -eq $true) { " [created-suspended]" } else { "" }
                        "$n$h$s"
                    } | Select-Object -Unique) -join '; '
                    Add-DA-Finding 'HIGH' 'Execution' 'Unsigned Malware Samples Launched from Explorer' "Explorer launched $($detonated.Count) unsigned process(es) with blank command lines: $dList" 'T1204.002'
                }

                # 2b. In-memory .NET compilation (Add-Type / csc.exe from PowerShell)
                $cscFromPS = @($ProcDocs | Where-Object {
                    $_.process.name -match '^(csc|cvtres)\.exe$' -and
                    $_.process.parent.name -match '^(powershell|pwsh)\.exe$' -and
                    $_.event.type -match 'start'
                })
                if ($cscFromPS.Count -gt 0) {
                    $cscCmds = ($cscFromPS | ForEach-Object { $_.process.command_line } | Where-Object { $_ } | Select-Object -Unique -First 2) -join ' | '
                    Add-DA-Finding 'MEDIUM' 'Defense Evasion' 'In-Memory .NET Compilation (Add-Type / csc.exe from PowerShell)' "PowerShell invoked csc.exe/cvtres.exe to compile inline C# to a temporary assembly, minimizing disk footprint. Command(s): $cscCmds" 'T1620 | T1059.001'
                }

                # 2c. Processes created suspended (injection/hollowing setup)
                $suspProcs = @($ProcDocs | Where-Object { $_.process.Ext.created_suspended -eq $true -and $_.event.type -match 'start' })
                if ($suspProcs.Count -gt 0) {
                    $sList = ($suspProcs | ForEach-Object {
                        $h = if ($_.process.hash.sha256) { " [$($_.process.hash.sha256.Substring(0,16))...]" } else { "" }
                        "$($_.process.name)$h"
                    } | Select-Object -Unique) -join ', '
                    Add-DA-Finding 'HIGH' 'Process Injection' 'Processes Created in Suspended State' "$($suspProcs.Count) process(es) started suspended  -  standard setup for process injection/hollowing before resume: $sList" 'T1055'
                }

                # 2d. LOLBin execution from suspicious parents
                $lolBinNames = @('mshta.exe','wscript.exe','cscript.exe','regsvr32.exe','regasm.exe','regsvcs.exe','certutil.exe','bitsadmin.exe','installutil.exe','ieexec.exe')
                $lolEvts = @($ProcDocs | Where-Object {
                    $pn = $_.process.name
                    ($lolBinNames -contains $pn) -and ($_.event.type -match 'start')
                })
                if ($lolEvts.Count -gt 0) {
                    $lolEvts | Group-Object { "$($_.process.parent.name)->$($_.process.name)" } | ForEach-Object {
                        $parts = $_.Name -split '->'
                        $cmd   = ($_.Group | ForEach-Object { $_.process.command_line } | Where-Object { $_ } | Select-Object -First 1)
                        $cmdNote = if ($cmd) { ": $cmd" } else { "" }
                        Add-DA-Finding 'HIGH' 'Defense Evasion' "LOLBin Execution: $($parts[0]) → $($parts[1])" "Living-off-the-land binary $($parts[1]) spawned from $($parts[0])$cmdNote" 'T1218'
                    }
                }

                # ==== NEW: Process Name Masquerading Detector (2x) ====
                # Detects legitimate Windows binary names executing from suspicious user-writable paths
                Write-Host "       [+] Scanning for process name masquerading..." -ForegroundColor DarkGray

                $sysProcs = @(
                    'system32.exe', 'services.exe', 'lsass.exe', 'svchost.exe', 'rundll32.exe',
                    'explorer.exe', 'winlogon.exe', 'csrss.exe', 'smss.exe', 'wininit.exe'
                )

                $masqueradeProcs = @($ProcDocs | Where-Object {
                    $_.process.name -and $_.process.executable -and
                    ($_.process.name.ToLower() -in $sysProcs) -and
                    ($_.process.executable -match '\\AppData\\' -or
                     $_.process.executable -match '\\Temp\\' -or
                     $_.process.executable -match '\\Roaming\\' -or
                     $_.process.executable -match '\\ProgramData\\[^\\]*\\') -and
                    $_.process.executable -notmatch '\\System32\\|\\SysWOW64\\'
                })

                if ($masqueradeProcs.Count -gt 0) {
                    $masqProcs = $masqueradeProcs | Group-Object { "$($_.process.name)|$($_.process.executable)" }
                    foreach ($mp in $masqProcs) {
                        $parts = $mp.Name -split '\|'
                        $name = $parts[0]
                        $exe = $parts[1]
                        $count = $mp.Count

                        $masqDetails = @"
Process name masquerading detected (system binary from user-writable path):
  Binary Name: $name (legitimate Windows system binary)
  Actual Path: $exe
  Occurrences: $count

Significance: Legitimate system binary names executed from AppData/Temp/Roaming/ProgramData paths indicate name-match masquerading. Attacker impersonates trusted binary name to evade inspection.
"@
                        Add-DA-Finding 'HIGH' 'Defense Evasion' "Process Name Masquerading: $name" $masqDetails 'T1036.005'
                    }
                }

                # ==== MODULE 3: PE Metadata / Masquerade ====

                # 3a. PE original_file_name mismatch (process_events)
                $peMasqProcs = @($ProcDocs | Where-Object {
                    $_.process.pe.original_file_name -and $_.process.name -and
                    ($_.process.pe.original_file_name -ne $_.process.name) -and
                    ($_.process.pe.original_file_name -notmatch '^\?$|^\.exe$') -and
                    $_.event.type -match 'start'
                })
                if ($peMasqProcs.Count -gt 0) {
                    $mList = ($peMasqProcs | ForEach-Object {
                        "$($_.process.name) (PE original: $($_.process.pe.original_file_name))"
                    } | Select-Object -Unique) -join '; '
                    Add-DA-Finding 'HIGH' 'Defense Evasion' 'PE Original Filename Masquerade' "On-disk filename differs from PE header original_file_name: $mList  -  deliberate renaming to evade name-based detection" 'T1036.005'
                }

                # 3b. Fabricated Microsoft PE metadata (unsigned, outside Windows paths)
                $fakeMsProcs = @($ProcDocs | Where-Object {
                    ($_.process.pe.company -match 'Microsoft' -or $_.process.code_signature.subject_name -match 'Microsoft') -and
                    $_.process.code_signature.exists -ne $true -and
                    $_.process.executable -and
                    ($_.process.executable -notmatch 'System32|SysWOW64|WindowsApps|Program Files\\Windows|Microsoft\.NET') -and
                    $_.event.type -match 'start'
                })
                if ($fakeMsProcs.Count -gt 0) {
                    $fList = ($fakeMsProcs | ForEach-Object {
                        $desc = if ($_.process.pe.file_description) { " ($($_.process.pe.file_description))" } else { "" }
                        "$($_.process.name)$desc @ $($_.process.executable)"
                    } | Select-Object -Unique -First 5) -join '; '
                    Add-DA-Finding 'HIGH' 'Defense Evasion' 'Fabricated Microsoft PE Metadata' "Unsigned process(es) claim Microsoft authorship outside Windows system paths: $fList" 'T1036.005'
                }

                # ==== MODULE 4: Network / C2 Analysis ====

                # 4a. Known APT C2 domains and IPs (loaded from *_Master_Intel.csv files)
                # Grouped by actor so a single finding is emitted per attributed group.
                $confirmedC2Doms = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                $confirmedC2IPs  = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                if ($netActorMap.Count -gt 0) {
                    $aptDomHits = @{}   # Actor -> List[string] of matched domains
                    $aptIPHits  = @{}   # Actor -> List[string] of matched IPs
                    foreach ($nd in $NetDocs) {
                        $qname = $nd.dns.question.name
                        if ($qname) {
                            $nKey = $qname.ToLower()
                            if ($netActorMap.ContainsKey($nKey)) {
                                $nActor = $netActorMap[$nKey].Actor
                                if (-not $aptDomHits.ContainsKey($nActor)) { $aptDomHits[$nActor] = [System.Collections.Generic.List[string]]::new() }
                                if ($aptDomHits[$nActor] -notcontains $qname) { $aptDomHits[$nActor].Add($qname) }
                                [void]$confirmedC2Doms.Add($qname)
                            }
                        }
                        $destIP = $nd.destination.ip
                        if ($destIP -and $destIP -match '\d') {
                            $iKey = $destIP.ToLower()
                            if ($netActorMap.ContainsKey($iKey)) {
                                $iActor = $netActorMap[$iKey].Actor
                                if (-not $aptIPHits.ContainsKey($iActor)) { $aptIPHits[$iActor] = [System.Collections.Generic.List[string]]::new() }
                                if ($aptIPHits[$iActor] -notcontains $destIP) { $aptIPHits[$iActor].Add($destIP) }
                                [void]$confirmedC2IPs.Add($destIP)
                            }
                        }
                    }
                    foreach ($actor in ($aptDomHits.Keys | Sort-Object)) {
                        $dList  = $aptDomHits[$actor] -join ', '
                        $srcLbl = $netActorMap[($aptDomHits[$actor][0]).ToLower()].Source
                        Add-DA-Finding 'CRITICAL' 'Threat Attribution' "Confirmed $actor C2 Domain" "KNOWN APT INFRASTRUCTURE  -  domain(s) matched $actor intel ($srcLbl): $dList" 'T1583.001 | T1071.001'
                    }
                    foreach ($actor in ($aptIPHits.Keys | Sort-Object)) {
                        $ipList = $aptIPHits[$actor] -join ', '
                        $srcLbl = $netActorMap[($aptIPHits[$actor][0]).ToLower()].Source
                        Add-DA-Finding 'CRITICAL' 'Threat Attribution' "Confirmed $actor C2 IP" "KNOWN APT INFRASTRUCTURE  -  IP(s) matched $actor intel ($srcLbl): $ipList" 'T1071.001 | T1571'
                    }
                }

                # 4b. DDNS-based C2 domains
                $ddnsRx = '\.bounceme\.net|\.serveminecraft\.net|\.ddns\.net|\.hopto\.org|\.zapto\.org|\.no-ip\.org|\.no-ip\.biz|\.dyndns\.org|\.afraid\.org|\.changeip\.com|\.3utilities\.com|\.myftp\.org|\.myftp\.biz|\.publicvm\.com|\.linkpc\.net|\.redirectme\.net'
                $ddnsDomains = @($NetDocs | Where-Object { $_.dns.question.name -match $ddnsRx } |
                    ForEach-Object { $_.dns.question.name } | Select-Object -Unique)
                if ($ddnsDomains.Count -gt 0) {
                    $dList = $ddnsDomains -join ', '
                    Add-DA-Finding 'HIGH' 'Command and Control' 'Dynamic DNS (DDNS) C2 Infrastructure' "DDNS provider domains queried  -  threat actors use DDNS to rapidly change C2 IPs and evade IP-based blocklists: $dList" 'T1568.002 | T1071.001'
                }

                # 4c. C2 beaconing (repeated DNS from same process to same domain >= 5x)
                $beaconHits = @($NetDocs | Where-Object { $_.dns.question.name -and $_.process.name } |
                    Group-Object { "$($_.process.name)|$($_.dns.question.name)" } |
                    Where-Object { $_.Count -ge 5 } | ForEach-Object {
                        $parts = $_.Name -split '\|'
                        [PSCustomObject]@{Proc=$parts[0];Domain=$parts[1];Count=$_.Count}
                    })
                if ($beaconHits.Count -gt 0) {
                    $bList = ($beaconHits | Sort-Object Count -Descending | ForEach-Object { "$($_.Proc) queried $($_.Domain) $($_.Count)x" }) -join '; '
                    Add-DA-Finding 'HIGH' 'Command and Control' 'C2 Beaconing Pattern (Repeated DNS Queries)' "Same process repeatedly queried same domain  -  characteristic of C2 polling with domain-failover: $bList" 'T1071.001 | T1568'
                }

                # 4d. Large downloads by external process
                $lgDown = @($NetDocs | Where-Object { $_.source.bytes -and [long]$_.source.bytes -gt 500000 -and $_.process.name } |
                    Group-Object { $_.process.name } | ForEach-Object {
                        $mb = [math]::Round(($_.Group | ForEach-Object { [long]$_.source.bytes } | Measure-Object -Sum).Sum / 1MB, 1)
                        [PSCustomObject]@{Proc=$_.Name;MB=$mb}
                    } | Where-Object { $_.MB -gt 0.5 })
                if ($lgDown.Count -gt 0) {
                    $lList = ($lgDown | Sort-Object MB -Descending | ForEach-Object { "$($_.Proc): $($_.MB) MB received" }) -join '; '
                    Add-DA-Finding 'MEDIUM' 'Command and Control' 'Large Network Download (Tool/Payload Staging)' "High-volume inbound transfer by process(es)  -  may indicate remote payload staging or tool delivery: $lList" 'T1105'
                }

                # 4e. Per-process DNS query attribution
                $perProcDnsRows = [System.Collections.Generic.List[PSCustomObject]]::new()
                $NetDocs | Where-Object { $_.dns.question.name -and $_.process.name } |
                    Group-Object { $_.process.name } | Sort-Object Count -Descending | ForEach-Object {
                        $pn   = $_.Name
                        $doms = @($_.Group | Group-Object { $_.dns.question.name } | Sort-Object Count -Descending | Select-Object -First 6 |
                            ForEach-Object { "$($_.Name) ×$($_.Count)" })
                        if ($doms.Count -gt 0) {
                            $perProcDnsRows.Add([PSCustomObject]@{Proc=$pn;Domains=$doms;Total=$_.Count})
                        }
                    }
                if ($perProcDnsRows.Count -gt 0) {
                    $perProcStr = ($perProcDnsRows | ForEach-Object { "$($_.Proc): $($_.Domains -join ', ')" }) -join '  |  '
                    Add-DA-Finding 'INFO' 'Network Activity' 'Per-Process DNS Query Attribution' "DNS queries by process (sorted by volume): $perProcStr" 'T1071.001'
                }

                # 4f. Full network traffic classification (Confirmed C2 / DDNS / Benign / Unknown)
                # Benign domains include: OS vendors, CDNs, certificate authorities, OCSP responders, package repositories
                $benignClassRx  = "(?i)microsoft\.com|windows\.com|office365|azure\.|akamai|google|apple\.com|amazon\.com|cloudflare|github|githubusercontent|windowsupdate|digicert|symantec|live\.com|bing\.com|msftncsi|skype|msecnd|msn\.com|hotmail|msauth|msoidentity|abuse\.ch|malwarebazaar|threatfox|urlhaus|ocsp\.|sectigo\.com|verisign\.com|godaddy\.com|comodo\.com|globalsign\.com|letsencrypt\.org|isrg\.x3\.letsencrypt|crt\.sh|crl\.|pki\.|ntp\.org|time\.nist\.gov|pool\.ntp\.org|chromeupdate|gvt1\.com|gstatic\.com|googleapis\.com|packages\.ubuntu\.com|archive\.ubuntu\.com|deb\.debian\.org|security\.debian\.org|fedoraproject\.org|dl\.fedoraproject\.org|mirror\.centos\.org|yum\.baseurl"
                $allObsDomains  = @($NetDocs | Where-Object { $_.dns.question.name } | ForEach-Object { $_.dns.question.name } | Select-Object -Unique | Sort-Object)
                if ($allObsDomains.Count -gt 0) {
                    $netCatC2      = [System.Collections.Generic.List[string]]::new()
                    $netCatDdns    = [System.Collections.Generic.List[string]]::new()
                    $netCatBenign  = [System.Collections.Generic.List[string]]::new()
                    $netCatUnknown = [System.Collections.Generic.List[string]]::new()
                    foreach ($dom in $allObsDomains) {
                        $cnt     = ($NetDocs | Where-Object { $_.dns.question.name -eq $dom } | Measure-Object).Count
                        $srcProc = ($NetDocs | Where-Object { $_.dns.question.name -eq $dom } |
                            ForEach-Object { $_.process.name } | Where-Object { $_ } | Select-Object -Unique) -join '/'
                        $entry   = "$dom (×$cnt | $srcProc)"
                        if     ($confirmedC2Doms.Contains($dom))  { $netCatC2.Add($entry) }
                        elseif ($dom -match $ddnsRx)               { $netCatDdns.Add($entry) }
                        elseif ($dom -match $benignClassRx)        { $netCatBenign.Add($entry) }
                        else                                       { $netCatUnknown.Add($entry) }
                    }
                    $parts = [System.Collections.Generic.List[string]]::new()
                    if ($netCatC2.Count -gt 0)      { $parts.Add("CONFIRMED C2 ($($netCatC2.Count)): $($netCatC2 -join '; ')") }
                    if ($netCatDdns.Count -gt 0)    { $parts.Add("DDNS/SUSPICIOUS ($($netCatDdns.Count)): $($netCatDdns -join '; ')") }
                    if ($netCatUnknown.Count -gt 0) { $parts.Add("UNKNOWN/UNCLASSIFIED ($($netCatUnknown.Count)): $($netCatUnknown -join '; ')") }
                    if ($netCatBenign.Count -gt 0)  { $parts.Add("BENIGN/FRAMEWORK ($($netCatBenign.Count)): $($netCatBenign -join '; ')") }
                    if ($parts.Count -gt 0) {
                        $sev4f = if ($netCatC2.Count -gt 0 -or $netCatDdns.Count -gt 0) { 'HIGH' } else { 'INFO' }
                        Add-DA-Finding $sev4f 'Network Activity' 'Network Traffic Classification (C2 / DDNS / Unknown / Benign)' ($parts -join '  ||  ') 'T1071.001 | T1568.002'
                    }
                }

                # ==== NEW: C2 Persistence Infrastructure Tracking (4g) ====
                # Detects domains queried by multiple processes (shared infrastructure indicator)
                if ($NetDocs.Count -gt 0) {
                    $dnsGroups  = @($NetDocs | Where-Object { $_.dns.question.name } | Group-Object { $_.dns.question.name })
                    $c2PersistenceInfra = @($dnsGroups | Where-Object {
                        # Filter: domains queried by multiple distinct processes OR high query volume
                        $domain = $_.Name
                        $sourceProcesses = @($_.Group | ForEach-Object { $_.process.name } | Select-Object -Unique)
                        $queryCount = $_.Group.Count

                        # Infrastructure indicator: same domain across multiple processes or high volume
                        ($sourceProcesses.Count -ge 2 -or $queryCount -ge 15) -and
                        # Exclude benign high-volume domains
                        $domain -notmatch 'microsoft|windows|office365|google|apple|amazon|cloudflare|cdn|akamai'
                    } | ForEach-Object {
                        [PSCustomObject]@{
                            Domain = $_.Name
                            SourceProcesses = @($_.Group | ForEach-Object { $_.process.name } | Select-Object -Unique)
                            QueryCount = $_.Group.Count
                            FirstSeen = [datetime]($_.Group | Sort-Object -Property @{Expression={$_.event.created}} | Select-Object -First 1).event.created
                            LastSeen = [datetime]($_.Group | Sort-Object -Property @{Expression={$_.event.created}} -Descending | Select-Object -First 1).event.created
                        }
                    } | Sort-Object -Property QueryCount -Descending)

                    if ($c2PersistenceInfra.Count -gt 0) {
                        foreach ($infra in $c2PersistenceInfra) {
                            $domain = $infra.Domain
                            $procs = $infra.SourceProcesses -join ', '
                            $qcount = $infra.QueryCount
                            $timespan = ($infra.LastSeen - $infra.FirstSeen).TotalSeconds

                            $c2InfraDetails = @"
Persistent C2 infrastructure detected (queried by multiple processes):
  Domain: $domain
  Source Processes: $procs
  Total Queries: $qcount
  Time Window: $timespan seconds ($(($infra.FirstSeen).ToString('HH:mm:ss')) - $(($infra.LastSeen).ToString('HH:mm:ss')) UTC)

Significance: Domains queried by multiple malware processes indicate shared C2 infrastructure. This pattern suggests attacker's central command-and-control server accessed by different implants/tools.
"@
                            Add-DA-Finding 'HIGH' 'Command and Control' "Persistent C2 Infrastructure: $domain" $c2InfraDetails 'T1071.001 | T1568'
                        }
                    }
                }

                # ==== NEW: Bulk File Timestomping Detector (4g-File) ====
                # Detects mass file timestamp modifications (anti-forensics indicator)
                if ($FileDocs.Count -gt 0) {
                    $timestompActivity = @($FileDocs | Where-Object {
                        # Look for files where creation time was modified (forensic evasion)
                        $_.file.created -and $_.file.mtime_modified -and
                        ([datetime]$_.file.created -lt [datetime]$_.file.mtime_modified) -and
                        $_.event.action -match 'modification|metadata'
                    })

                    if ($timestompActivity.Count -gt 10) {
                        # Group by process and time window
                        $timestompByProc = @($timestompActivity | Group-Object { "$($_.process.name)|$(([datetime]$_.event.created).ToString('yyyy-MM-dd HH:mm'))" })

                        foreach ($group in $timestompByProc) {
                            $parts = $group.Name -split '\|'
                            $proc = $parts[0]
                            $timeWindow = $parts[1]
                            $count = $group.Count

                            if ($count -gt 10) {
                                # Extract 5 example files
                                $examples = ($group.Group | Select-Object -First 5 | ForEach-Object { $_.file.name }) -join ', '

                                $tsDetails = @"
Bulk file timestamp modification detected (anti-forensics):
  Process: $proc
  Time Window: $timeWindow UTC
  Files Affected: $count
  Examples: $examples

Significance: Mass timestamp modification is used to make malware appear older than actual compromise date, defeating timeline-based forensic analysis. Observed in post-exploitation frameworks (Mimikatz, Empire, Metasploit).
"@
                                Add-DA-Finding 'CRITICAL' 'Defense Evasion' "Bulk File Timestomping ($count files)" $tsDetails 'T1070.006'
                            }
                        }
                    }
                }

                # ==== NEW: Root Certificate Installation Detector (5-Registry) ====
                # Detects rogue root certificate installation (MITM/interception capability)
                if ($RegDocs.Count -gt 0) {
                    $rootCertInstalls = @($RegDocs | Where-Object {
                        ($_.registry.key -match 'SystemCertificates\\Root' -or
                         $_.registry.key -match 'HKLM.*ROOT.*Certificates' -or
                         $_.registry.key -match 'Microsoft\\SystemCertificates\\Root') -and
                        ($_.event.action -match 'creation|modification') -and
                        # Exclude legitimate system processes
                        ($_.process.name -notmatch '^(TrustedInstaller|services\.exe|svchost\.exe|explorer\.exe)$')
                    })

                    if ($rootCertInstalls.Count -gt 0) {
                        $certInstalls = $rootCertInstalls | Group-Object { $_.process.name }
                        foreach ($ci in $certInstalls) {
                            $proc = $ci.Name
                            $certCount = $ci.Count
                            $certKeys = ($ci.Group | ForEach-Object { $_.registry.key } | Select-Object -Unique -First 3) -join '; '

                            $certDetails = @"
Unauthorized root certificate installation detected (rogue CA):
  Process: $proc
  Target: HKLM\SOFTWARE\Microsoft\SystemCertificates\Root
  Certificate Entries: $certCount
  Registry Keys: $certKeys

Significance: Installation of rogue root certificates enables MITM attacks and TLS interception without browser warnings. Used by sophisticated APT groups for persistent network compromiseof HTTPS traffic.
"@
                            Add-DA-Finding 'CRITICAL' 'Defense Evasion' 'Unauthorized Root Certificate Installation (Rogue CA)' $certDetails 'T1556.004'
                        }
                    }
                }

                # ==== MODULE 5: File System Analysis ====

                # 5a. High-entropy file writes (packed/encrypted payloads)
                $hiEnt = @($FileDocs | Where-Object {
                    $_.file.Ext.entropy -and [double]$_.file.Ext.entropy -gt 7.0 -and
                    $_.event.action -match 'creation|modification|overwrite'
                })
                if ($hiEnt.Count -gt 0) {
                    $heList = ($hiEnt | Sort-Object { [double]$_.file.Ext.entropy } -Descending | Select-Object -First 6 | ForEach-Object {
                        $ent = [math]::Round([double]$_.file.Ext.entropy, 2)
                        "$($_.file.name) (entropy=$ent, writer=$($_.process.name))"
                    }) -join '; '
                    Add-DA-Finding 'HIGH' 'Defense Evasion' 'High-Entropy File Writes  -  Packed/Encrypted Payloads' "File entropy >7.0/8.0 indicates compressed, encrypted, or packed content (random = 8.0, text = ~4.5): $heList" 'T1027'
                }

                # 5b. Elastic Defend ML malware scores
                $mlFiles = @($AlertDocs | Where-Object { $_.file.Ext.malware_classification.score -and [double]$_.file.Ext.malware_classification.score -gt 0.5 } |
                    Sort-Object { [double]$_.file.Ext.malware_classification.score } -Descending |
                    Group-Object { if ($_.file.hash.sha256) { $_.file.hash.sha256 } else { $_.file.name } } |
                    ForEach-Object { $_.Group[0] } | Select-Object -First 8)
                if ($mlFiles.Count -gt 0) {
                    $msDetails = ($mlFiles | ForEach-Object {
                        $pct   = [math]::Round([double]$_.file.Ext.malware_classification.score * 100, 4)
                        $fname = if ($_.file.name) { $_.file.name } else { '?' }
                        $origFn = if ($_.file.Ext.original_file_name -and $_.file.Ext.original_file_name -ne $fname) { " [PE: $($_.file.Ext.original_file_name)]" } else { "" }
                        "$fname$origFn = $pct%"
                    }) -join '; '
                    Add-DA-Finding 'CRITICAL' 'Malware' "Elastic Defend ML Malware Confidence ($($mlFiles.Count) samples)" "endpointpe-v4-model confidence scores: $msDetails" 'T1204.002'
                }

                # 5c. Executable drops to user-writable paths
                $exeDrops = @($FileDocs | Where-Object {
                    $_.file.extension -match '^(exe|dll|ps1|bat|vbs|js|hta)$' -and
                    $_.event.action -match 'creation' -and
                    $_.file.path -match 'AppData|\\Temp\\|Downloads|ProgramData|\\Public\\'
                })
                if ($exeDrops.Count -gt 0) {
                    $dropList = ($exeDrops | Select-Object -First 6 | ForEach-Object { "$($_.file.name) → $($_.file.directory) (by $($_.process.name))" }) -join '; '
                    Add-DA-Finding 'HIGH' 'Persistence' 'Executable/Script Dropped to User-Writable Path' "Executable files created in user-writable locations outside Program Files: $dropList" 'T1105 | T1574'
                }

                # ==== MODULE 6: Registry Persistence Analysis ====

                # 6a. Run/RunOnce persistence
                $persistenceFound = $false
                $runKeyWrites = @($RegDocs | Where-Object {
                    $_.registry.key -match 'CurrentVersion\\Run(Once)?($|\\)' -and
                    $_.event.action -match 'creation|modification'
                })
                if ($runKeyWrites.Count -gt 0) {
                    $rkList = ($runKeyWrites | ForEach-Object {
                        $val = if ($_.registry.data.strings) { " = $($_.registry.data.strings)" } else { "" }
                        "$($_.registry.key)$val (by $($_.process.name))"
                    } | Select-Object -First 5) -join '; '
                    Add-DA-Finding 'CRITICAL' 'Persistence' 'Registry Run Key Persistence' "Run/RunOnce key(s) written  -  will execute payload at next user logon: $rkList" 'T1547.001'
                    $persistenceFound = $true
                }

                # 6b. Service registry key creation by non-system process
                $svcKeyWrites = @($RegDocs | Where-Object {
                    $_.registry.key -match '\\Services\\[^\\]+($|\\(Parameters|Security|ImagePath))' -and
                    $_.event.action -match 'creation' -and
                    $_.process.name -notmatch '^(services|svchost|MsiExec|msiexec|TrustedInstaller|sc)\.exe$'
                })
                if ($svcKeyWrites.Count -gt 0) {
                    $skList = ($svcKeyWrites | ForEach-Object { "$($_.registry.key) (by $($_.process.name))" } | Select-Object -Unique -First 5) -join '; '
                    Add-DA-Finding 'HIGH' 'Persistence' 'Service Registry Key Created by Non-System Process' "Service configuration key(s) written outside of normal service manager context: $skList" 'T1543.003'
                    $persistenceFound = $true
                }

                # 6c. IFEO debugger hijack
                $ifeoWrites = @($RegDocs | Where-Object { $_.registry.key -match 'Image File Execution Options\\[^\\]+\\Debugger' })
                if ($ifeoWrites.Count -gt 0) {
                    $iList = ($ifeoWrites | ForEach-Object { $_.registry.key } | Select-Object -Unique) -join '; '
                    Add-DA-Finding 'CRITICAL' 'Persistence' 'IFEO Debugger Hijack (Image File Execution Options)' "Debugger value written under IFEO  -  causes malware to run in place of the targeted executable: $iList" 'T1546.012'
                    $persistenceFound = $true
                }

                # 6d. Persistence absence analysis
                if (-not $persistenceFound) {
                    $confirmedMalware = ($findings | Where-Object { $_.Severity -eq 'CRITICAL' } | Measure-Object).Count -gt 0
                    if ($confirmedMalware) {
                        Add-DA-Finding 'INFO' 'Persistence' 'No Persistence Mechanisms Confirmed in Capture Window' "No Run/RunOnce key writes, service binary creation, IFEO debugger hijacks, or startup folder drops detected in this telemetry window. With malware confirmed active, likely explanations: (1) EDR/AV terminated malicious processes before the persistence phase was reached; (2) persistence operates via COM/CLSID filter registration (HKCR\CLSID or audio/video filter registry paths) not captured as standard registry telemetry; (3) persistence is deferred to a subsequent execution stage not in this capture window; (4) the sample is a reconnaissance/staging tool that relies on a separate dropper for persistence." ''
                    }
                }

                # ==== NEW: Post-Exploitation Hardening Sequence Detector ====
                # Detects coordinated anti-forensics & persistence hardening:
                # Timeline: PS logging disable → Bulk timestomp → Root cert install
                # This is a smoking gun for post-exploitation framework activity

                Write-Host "       [+] Analyzing coordinated hardening sequences..." -ForegroundColor DarkGray

                # Step 1: Find PowerShell logging disable events
                $psDisables = @($RegDocs | Where-Object {
                    $_.registry.key -match 'PowerShell.*EnableScriptBlockLogging|HKLM.*Policies.*PowerShell' -and
                    $_.registry.data.strings -match 'false|0|disable' -and
                    $_.event.action -match 'creation|modification'
                } | Sort-Object -Property @{Expression={$_.event.created}} )

                foreach ($psEvent in $psDisables) {
                    $psTime = [datetime]$psEvent.event.created
                    $psUser = $psEvent.user.id
                    $psProc = $psEvent.process.name

                    # Step 2: Within 5 minutes, look for bulk timestomping by same/related process
                    $timestompEvents = @($FileDocs | Where-Object {
                        $eTime = [datetime]$_.event.created
                        ($eTime -gt $psTime) -and ($eTime -lt $psTime.AddMinutes(5)) -and
                        ($_.event.action -match 'metadata.*change|SetFileTime' -or
                         ($_.file.created -and [datetime]$_.file.created -lt [datetime]$_.file.modified))
                    })

                    # Step 3: Within 5 minutes, look for root cert installation by same user
                    $certEvents = @($RegDocs | Where-Object {
                        $eTime = [datetime]$_.event.created
                        ($eTime -gt $psTime) -and ($eTime -lt $psTime.AddMinutes(5)) -and
                        ($_.registry.key -match 'SystemCertificates\\Root' -or $_.registry.key -match 'ROOT.*Certificates') -and
                        ($_.user.id -eq $psUser -or $_.user.id -match 'SYSTEM|TrustedInstaller' -eq $false)
                    })

                    # If all three phases detected, it's a hardening sequence
                    if ($timestompEvents.Count -ge 10 -and $certEvents.Count -gt 0) {
                        $tsCount = $timestompEvents.Count
                        $tsProcs = ($timestompEvents | ForEach-Object { $_.process.name } | Select-Object -Unique) -join ', '
                        $certDomains = ($certEvents | ForEach-Object { $_.registry.key } | Select-Object -Unique -First 3) -join '; '
                        $timelineStr = "$($psTime.ToString('yyyy-MM-dd HH:mm:ss')) UTC"

                        $hardeningDetails = @"
Post-exploitation hardening framework detected:
  [Phase 1] PowerShell Script Block Logging disabled ($(($psTime).ToString('HH:mm:ss')) UTC)
  [Phase 2] Bulk file timestomping: $tsCount files modified (by $tsProcs)
  [Phase 3] Root certificate installation: $($certEvents.Count) cert entries written ($(($certEvents[0].event.created -split 'T')[1].substring(0,8)) UTC)

Timeline: $($psTime.ToString('yyyy-MM-dd HH:mm:ss')) - $($certEvents[-1].event.created.Substring(0,19)) UTC

Significance: This coordinated sequence is indicative of a post-exploitation framework (Mimikatz, Empire, etc.) hardening the compromised system for persistent covert access. Attacker is preparing for long-term dwelling and evading forensic timeline analysis.
"@

                        Add-DA-Finding 'CRITICAL' 'Defense Evasion' 'Post-Exploitation Hardening Sequence (PS Disable → Timestomp → Cert Install)' $hardeningDetails 'T1562.002 | T1070.006 | T1556.004'
                    }
                }

                # ==== MODULE 6e: WDigest Credential Harvesting (T1003.001) ====
                # Detects reg add ... WDigest\UseLogonCredential /d 1  -  forces cleartext
                # password caching so Mimikatz/sekurlsa can dump them from LSASS.
                $wdigestHits = @($ProcDocs | Where-Object {
                    $cmd = $_.process.command_line
                    $cmd -and $cmd -match 'WDigest' -and $cmd -match 'UseLogonCredential' -and
                    ($cmd -match '/d\s+1' -or $cmd -match 'Set-ItemProperty|New-ItemProperty|reg\s+add')
                })
                if ($wdigestHits.Count -gt 0) {
                    $wdProcs = ($wdigestHits | ForEach-Object { $_.process.name } | Select-Object -Unique) -join ', '
                    $wdCmds  = ($wdigestHits | ForEach-Object { $_.process.command_line } | Select-Object -Unique -First 3) -join '  |  '
                    Add-DA-Finding 'CRITICAL' 'Credential Access' "WDigest Credential Caching Enabled (UseLogonCredential=1)" "Process(es) $wdProcs enabled WDigest cleartext password caching by setting HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential to 1. This forces Windows to store plaintext passwords in LSASS memory, making them extractable by Mimikatz sekurlsa::wdigest. Commands: $wdCmds" 'T1003.001 | T1112'
                }
                # Also check registry events for the same pattern
                $wdigestRegHits = @($RegDocs | Where-Object {
                    $_.registry.key -match 'WDigest' -and $_.registry.key -match 'UseLogonCredential' -and
                    $_.registry.data.strings -match '1' -and
                    $_.event.action -match 'creation|modification'
                })
                if ($wdigestRegHits.Count -gt 0 -and $wdigestHits.Count -eq 0) {
                    $wdRegProcs = ($wdigestRegHits | ForEach-Object { $_.process.name } | Select-Object -Unique) -join ', '
                    Add-DA-Finding 'CRITICAL' 'Credential Access' "WDigest Credential Caching Enabled via Registry (UseLogonCredential=1)" "Registry write detected enabling WDigest cleartext credential storage. Process: $wdRegProcs. Key: $($wdigestRegHits[0].registry.key). This forces LSASS to cache plaintext passwords, enabling extraction via Mimikatz sekurlsa::wdigest." 'T1003.001 | T1112'
                }

                # ==== MODULE 6f: Firewall Rules Blocking EDR/AV (T1562.004) ====
                # Detects New-NetFirewallRule or netsh commands that block security tool processes.
                $edrBlockNames = @('MsMpEng','MsSense','SenseCncProxy','SenseIR','MpCmdRun',
                                   'MsMpEngCP','NisSrv','SecurityHealthService','wsctrlsvc',
                                   'CylanceSvc','CylanceUI','cb','CbDefense','SentinelAgent',
                                   'SentinelServiceHost','CSFalconService','CSFalconContainer')
                $edrBlockRx = ($edrBlockNames | ForEach-Object { [regex]::Escape($_) }) -join '|'
                $fwBlockHits = @($ProcDocs | Where-Object {
                    $cmd = $_.process.command_line
                    $cmd -and ($cmd -match 'New-NetFirewallRule|netsh\s+advfirewall') -and
                    ($cmd -match $edrBlockRx) -and ($cmd -match 'Block|Deny|block|deny')
                })
                if ($fwBlockHits.Count -gt 0) {
                    $fwProcs = ($fwBlockHits | ForEach-Object { $_.process.name } | Select-Object -Unique) -join ', '
                    $fwCmds  = ($fwBlockHits | ForEach-Object { $_.process.command_line } | Select-Object -Unique -First 3) -join '  |  '
                    $fwTargets = @()
                    foreach ($edrN in $edrBlockNames) {
                        if ($fwCmds -match $edrN) { $fwTargets += $edrN }
                    }
                    $fwTgtStr = $fwTargets -join ', '
                    Add-DA-Finding 'CRITICAL' 'Defense Evasion' "Firewall Rules Blocking EDR/AV Processes ($fwTgtStr)" "Firewall rules created to block outbound communication from security tools: $fwTgtStr. This isolates endpoint protection from its cloud management console, preventing signature updates, policy enforcement, and alert forwarding. Process: $fwProcs. Commands: $fwCmds" 'T1562.004 | T1562.001'
                }

                # ==== MODULE 6g: SharpEventPersist / SharpEventLoader (Fileless Persistence via EventLog) ====
                # T1546 - Event-log-based fileless persistence: shellcode stored in Windows Event Log entries.
                $sharpEventProcs = @($ProcDocs | Where-Object {
                    $_.process.name -match '(?i)^(SharpEventPersist|SharpEventLoader|EventLogPersist|EventLogLoader)\.exe$' -and
                    $_.event.type -match 'start'
                })
                if ($sharpEventProcs.Count -gt 0) {
                    $seNames = ($sharpEventProcs | ForEach-Object { $_.process.name } | Select-Object -Unique) -join ', '
                    $seCmds  = ($sharpEventProcs | ForEach-Object { $_.process.command_line } | Where-Object { $_ } | Select-Object -Unique -First 3) -join '  |  '
                    $seCmdNote = if ($seCmds) { " Commands: $seCmds" } else { "" }
                    $isPersist = $seNames -match 'Persist'
                    $isLoader  = $seNames -match 'Loader'
                    $roleDesc  = if ($isPersist -and $isLoader) {
                        'Both persistence writer and loader detected  -  complete fileless persistence chain'
                    } elseif ($isPersist) {
                        'Persistence writer detected  -  shellcode is being embedded into Event Log entries'
                    } else {
                        'Loader detected  -  shellcode is being extracted from Event Log entries and executed'
                    }
                    Add-DA-Finding 'CRITICAL' 'Persistence' "Fileless Persistence via Windows Event Log ($seNames)" "SharpEventPersist/Loader tooling detected: $roleDesc. These tools store encoded shellcode payloads inside Windows Event Log entries (e.g., Key Management Service log), then retrieve and execute them from memory  -  leaving no files on disk. $seCmdNote" 'T1546 | T1027.011'
                }

                # ==== MODULE 6h: ServiceDll Registry Persistence (T1543.003) ====
                # Detects registration of malicious ServiceDll entries for svchost-hosted services.
                $svcDllRegHits = @($RegDocs | Where-Object {
                    $_.registry.key -match '\\Services\\[^\\]+\\Parameters$' -and
                    $_.registry.data.strings -match '\.dll' -and
                    $_.event.action -match 'creation|modification' -and
                    $_.process.name -notmatch '^(services|svchost|MsiExec|TrustedInstaller)\.exe$'
                })
                $svcDllCmdHits = @($ProcDocs | Where-Object {
                    $cmd = $_.process.command_line
                    $cmd -and $cmd -match 'ServiceDll' -and
                    ($cmd -match 'reg\s+add|Set-ItemProperty|New-ItemProperty') -and
                    $cmd -match '\\Services\\'
                })
                # Also detect SvcHost group registration (adding fake service names to svchost netsvcs group)
                $svcHostGroupHits = @($RegDocs | Where-Object {
                    $_.registry.key -match '\\SvcHost$' -and
                    $_.registry.data.strings -match 'MPSEvtMan|StorSyncSvc|SvcHostDemo' -and
                    $_.event.action -match 'creation|modification'
                })
                $totalSvcDll = $svcDllRegHits.Count + $svcDllCmdHits.Count + $svcHostGroupHits.Count
                if ($totalSvcDll -gt 0) {
                    $svcDllDetails = @()
                    if ($svcDllRegHits.Count -gt 0) {
                        $svcKeys = ($svcDllRegHits | ForEach-Object { "$($_.registry.key) = $($_.registry.data.strings) (by $($_.process.name))" } | Select-Object -Unique -First 3) -join '; '
                        $svcDllDetails += "ServiceDll registry writes: $svcKeys"
                    }
                    if ($svcDllCmdHits.Count -gt 0) {
                        $svcCmds = ($svcDllCmdHits | ForEach-Object { $_.process.command_line } | Select-Object -Unique -First 2) -join '  |  '
                        $svcDllDetails += "ServiceDll commands: $svcCmds"
                    }
                    if ($svcHostGroupHits.Count -gt 0) {
                        $svcGrpNames = ($svcHostGroupHits | ForEach-Object { $_.registry.data.strings } | Select-Object -Unique) -join ', '
                        $svcDllDetails += "SvcHost group registration with fake service names: $svcGrpNames"
                    }
                    Add-DA-Finding 'CRITICAL' 'Persistence' "ServiceDll Persistence: Svchost-Hosted Malicious Service" "Malicious DLL registered as a svchost-hosted service via ServiceDll parameter. This technique creates a service that runs inside a shared svchost.exe process, making it blend with legitimate Windows services and survive reboots. $($svcDllDetails -join '  ||  ')" 'T1543.003 | T1574.001'
                }

                # ==== MODULE 6i: DCOM Lateral Movement Tools (T1021.003) ====
                # Surfaces specific offensive DCOM tools by name (CheeseDCOM, CsDCOM, etc.)
                $dcomToolNames = @('CheeseDCOM','CsDCOM','dcomexec','dcom_exec','Invoke-DCOM','SharpDCOM')
                $dcomToolRx = ($dcomToolNames | ForEach-Object { [regex]::Escape($_) }) -join '|'
                $dcomToolHits = @($ProcDocs | Where-Object {
                    ($_.process.name -match "(?i)($dcomToolRx)" -or
                     $_.process.command_line -match "(?i)($dcomToolRx)") -and
                    $_.event.type -match 'start'
                })
                if ($dcomToolHits.Count -eq 0) {
                    # Also check for DCOM object abuse patterns in command lines
                    $dcomToolHits = @($ProcDocs | Where-Object {
                        $cmd = $_.process.command_line
                        $cmd -and ($cmd -match 'MMC20\.Application|ShellWindows|ShellBrowserWindow|Excel\.Application|Outlook\.Application') -and
                        ($cmd -match 'DCOM|Activator|InteropServices|lateralm|remote')
                    })
                }
                if ($dcomToolHits.Count -gt 0) {
                    $dcomNames = ($dcomToolHits | ForEach-Object { $_.process.name } | Select-Object -Unique) -join ', '
                    $dcomCmds  = ($dcomToolHits | ForEach-Object { $_.process.command_line } | Where-Object { $_ } | Select-Object -Unique -First 3) -join '  |  '
                    $dcomCmdNote = if ($dcomCmds) { " Commands: $dcomCmds" } else { "" }
                    Add-DA-Finding 'CRITICAL' 'Lateral Movement' "DCOM Lateral Movement Tool Execution ($dcomNames)" "Offensive DCOM lateral movement tools detected: $dcomNames. These tools abuse COM objects (MMC20.Application, ShellWindows, ShellBrowserWindow) to execute commands on remote hosts via DCOM, bypassing traditional remote execution monitoring that focuses on PsExec/WMI/WinRM.$dcomCmdNote" 'T1021.003 | T1559.001'
                }

                # ==== MODULE 6j: Windows API Callback Shellcode Execution (T1106) ====
                # Groups the 45+ tools that use legitimate Windows API callbacks to execute shellcode.
                $callbackToolRx = '(?i)^(EnumWindows|FlsAlloc|CertEnumSystemStore|CertEnumSystemStoreLocation|EnumChildWindows|EnumDesktopWindows|EnumDesktops|EnumDateFormats|EnumDisplayMonitors|EnumFontFamilies|EnumFonts|EnumICMProfiles|EnumLanguageGroupLocales|EnumObjects|EnumPageFiles|EnumPwrSchemes|EnumResourceTypes|EnumSystemCodePages|EnumSystemGeoID|EnumSystemLanguageGroups|EnumSystemLocales|EnumThreadWindows|EnumTimeFormats|EnumUILanguages|EnumWindowStations|FiberContextEdit|FiberLocal|FlsAlloc|GrayString|LineDDA|InitOnceExecuteOnce|ImmEnumInputContext|NotifyIpInterfaceChange|PerfStartProvider|CBT_|SetupCommitFileQueue|SymEnumProcesses|VerifierEnumerateResource|EnumCalendarInfo|CreateThreadPoolWait|CopyFile2|CreateTimerQueueTimer|CertFindChainInStore|CallWindowProc|SetWindowsHookEx|ImageGetDigestStream)\.exe$'
                $callbackHits = @($ProcDocs | Where-Object {
                    $_.process.name -match $callbackToolRx -and $_.event.type -match 'start'
                })
                if ($callbackHits.Count -gt 0) {
                    $cbNames  = ($callbackHits | ForEach-Object { $_.process.name } | Select-Object -Unique | Sort-Object) -join ', '
                    $cbCount  = ($callbackHits | ForEach-Object { $_.process.name } | Select-Object -Unique).Count
                    $cbSample = ($callbackHits | ForEach-Object { $_.process.name } | Select-Object -Unique | Select-Object -First 8) -join ', '
                    $cbMore   = if ($cbCount -gt 8) { " ... and $($cbCount - 8) more" } else { "" }
                    Add-DA-Finding 'HIGH' 'Code Injection' "Windows API Callback Shellcode Execution ($cbCount tools)" "Detected $cbCount tool(s) that abuse legitimate Windows API callback mechanisms to execute shellcode: $cbSample$cbMore. Each tool calls a benign Windows API (e.g. EnumWindows, CertEnumSystemStoreLocation, FlsAlloc) that accepts a user-defined callback function pointer, redirecting execution to attacker-controlled shellcode. This technique bypasses security tools that monitor common injection APIs (CreateRemoteThread, NtQueueApcThread) because the shellcode runs within a trusted API call context." 'T1106 | T1055'
                }

                # ==== MODULE 6k: Ransomware Pre-Encryption Kill Chain (T1490 | T1486) ====
                # Consolidates shadow copy deletion, recovery disable, and encryption prep into one finding.
                $ransomIndicators = [System.Collections.Generic.List[PSCustomObject]]::new()

                # Shadow copy deletion (vssadmin, wmic, PowerShell)
                $vssCmds = @($ProcDocs | Where-Object {
                    $cmd = $_.process.command_line
                    $cmd -and (
                        ($cmd -match 'vssadmin.*delete\s+shadows') -or
                        ($cmd -match 'wmic.*shadowcopy.*delete') -or
                        ($cmd -match 'Get-WmiObject.*ShadowCopy.*Delete') -or
                        ($cmd -match 'wbadmin\s+delete\s+(catalog|systemstatebackup|backup)') -or
                        ($cmd -match '-shadowops')
                    )
                })
                if ($vssCmds.Count -gt 0) {
                    $vssList = ($vssCmds | ForEach-Object { $_.process.command_line } | Select-Object -Unique -First 3) -join '  |  '
                    $ransomIndicators.Add([PSCustomObject]@{Phase='Shadow Copy / Backup Deletion';Count=$vssCmds.Count;Detail=$vssList})
                }

                # Recovery disable (bcdedit)
                $bcdeditCmds = @($ProcDocs | Where-Object {
                    $cmd = $_.process.command_line
                    $cmd -and $cmd -match 'bcdedit' -and
                    ($cmd -match 'recoveryenabled.*no' -or $cmd -match 'bootstatuspolicy.*ignoreallfailures')
                })
                if ($bcdeditCmds.Count -gt 0) {
                    $bcdList = ($bcdeditCmds | ForEach-Object { $_.process.command_line } | Select-Object -Unique -First 2) -join '  |  '
                    $ransomIndicators.Add([PSCustomObject]@{Phase='Recovery Mode Disabled (bcdedit)';Count=$bcdeditCmds.Count;Detail=$bcdList})
                }

                # IOCTL_VOLSNAP manipulation
                $volsnapProcs = @($ProcDocs | Where-Object {
                    $_.process.name -match '(?i)IOCTL_VOLSNAP|VolSnap' -or
                    ($_.process.command_line -and $_.process.command_line -match 'VOLSNAP|SET_MAX_DIFF_AREA_SIZE')
                })
                if ($volsnapProcs.Count -gt 0) {
                    $volNames = ($volsnapProcs | ForEach-Object { $_.process.name } | Select-Object -Unique) -join ', '
                    $ransomIndicators.Add([PSCustomObject]@{Phase='Volume Shadow Copy Size Manipulation (IOCTL_VOLSNAP)';Count=$volsnapProcs.Count;Detail="Tool: $volNames"})
                }

                # Known ransomware tool names
                $ransomToolRx = '(?i)(ContiRansomware|BlackByteEncryptor|RansomEXX|BianLian|BianMain|LockBit|REvil|DarkSide|Ryuk|Hive|ALPHV|BlackCat|Royal|Akira|Play|Clop|Phobos|Medusa|MedusaLocker|Cuba|Vice|Trigona|NoEscape|Rhysida|Cactus|INC|Hunters|Qilin)'
                $ransomToolHits = @($ProcDocs | Where-Object {
                    ($_.process.name -match $ransomToolRx -or
                     ($_.process.command_line -and $_.process.command_line -match $ransomToolRx)) -and
                    $_.event.type -match 'start'
                })
                if ($ransomToolHits.Count -gt 0) {
                    $rtNames = ($ransomToolHits | ForEach-Object { $_.process.name } | Select-Object -Unique) -join ', '
                    $ransomIndicators.Add([PSCustomObject]@{Phase='Ransomware Encryptor Execution';Count=$ransomToolHits.Count;Detail="Binaries: $rtNames"})
                }

                # Service stop / taskkill of security tools (pre-encryption)
                $killSvcCmds = @($ProcDocs | Where-Object {
                    $cmd = $_.process.command_line
                    $cmd -and (
                        ($cmd -match 'sc\s+stop\s+(MpsSvc|WinDefend|wscsvc|Sense|SecurityHealthService|CylanceSvc)') -or
                        ($cmd -match 'taskkill.*(/im|/f)\s*(MsMpEng|MsSense|SecurityHealth|CylanceUI|SentinelAgent)') -or
                        ($cmd -match 'net\s+stop\s+(MpsSvc|WinDefend|wscsvc|Sense|SecurityHealthService)')
                    )
                })
                if ($killSvcCmds.Count -gt 0) {
                    $killList = ($killSvcCmds | ForEach-Object { $_.process.command_line } | Select-Object -Unique -First 3) -join '  |  '
                    $ransomIndicators.Add([PSCustomObject]@{Phase='Security Service Termination (Pre-Encryption)';Count=$killSvcCmds.Count;Detail=$killList})
                }

                if ($ransomIndicators.Count -ge 2) {
                    $rkDetails = ($ransomIndicators | ForEach-Object {
                        "[$($_.Phase)] ($($_.Count) event(s)): $($_.Detail)"
                    }) -join '  ||  '
                    Add-DA-Finding 'CRITICAL' 'Impact' "Ransomware Pre-Encryption Kill Chain ($($ransomIndicators.Count) phases detected)" "RANSOMWARE KILL CHAIN  -  Multiple pre-encryption preparation phases detected in sequence, indicating imminent or active ransomware deployment: $rkDetails. This coordinated activity  -  combining backup destruction, recovery prevention, security tool neutralization, and/or encryptor execution  -  constitutes a complete ransomware operations sequence." 'T1490 | T1486 | T1489 | T1562.001'
                } elseif ($ransomIndicators.Count -eq 1) {
                    $ri = $ransomIndicators[0]
                    Add-DA-Finding 'HIGH' 'Impact' "Ransomware Indicator: $($ri.Phase)" "Single ransomware preparation indicator detected ($($ri.Count) event(s)): $($ri.Detail). Monitor for additional ransomware kill chain phases (shadow deletion, recovery disable, service termination, encryption)." 'T1490 | T1486'
                }

                # ==== MODULE 6l: Credential Access Tool Recognition (T1003) ====
                # Identifies known credential harvesting tools by process name patterns.
                Write-Host "       [+] Scanning for credential access tools..." -ForegroundColor DarkGray
                $credToolPatterns = @(
                    @{ Rx='(?i)lazagne';           Name='LaZagne';           Desc='multi-protocol credential harvester (browsers, mail, wifi, databases)' }
                    @{ Rx='(?i)(^wce\.exe$|wce64)'; Name='WCE';             Desc='Windows Credential Editor - NTLM hash/token extraction' }
                    @{ Rx='(?i)InternalMonologue';  Name='InternalMonologue'; Desc='NTLM downgrade attack - coerces NTLMv1 hashes without touching LSASS' }
                    @{ Rx='(?i)SharpDPAPI';         Name='SharpDPAPI';       Desc='DPAPI master key and credential blob decryption' }
                    @{ Rx='(?i)SharpRDPDump';       Name='SharpRDPDump';     Desc='RDP saved credential extraction from registry' }
                    @{ Rx='(?i)SharpChromium';       Name='SharpChromium';    Desc='Chromium browser credential/cookie extraction' }
                    @{ Rx='(?i)SharpWeb';            Name='SharpWeb';         Desc='browser credential extraction (Chrome, Firefox, Edge)' }
                    @{ Rx='(?i)(mimi(katz|x)|katz\.packed|dkatz|huanMimi|ObfuscatedSharpKatz|SharpKatzNim|go_mimikatz|AtomPePacker_Mimi|inceptormimi|Doge.*SharpKatz|SafetyKatz)'; Name='Mimikatz variant'; Desc='LSASS credential dumping tool (renamed/packed/ported variant)' }
                    @{ Rx='(?i)NetRipper';           Name='NetRipper';        Desc='post-exploitation tool that intercepts network traffic and captures credentials' }
                )
                $credToolHits = [System.Collections.Generic.List[PSCustomObject]]::new()
                foreach ($ct in $credToolPatterns) {
                    $hits = @($ProcDocs | Where-Object { $_.process.name -match $ct.Rx -and $_.event.type -match 'start' })
                    if ($hits.Count -gt 0) {
                        $names = ($hits | ForEach-Object { $_.process.name } | Select-Object -Unique) -join ', '
                        $credToolHits.Add([PSCustomObject]@{Tool=$ct.Name;Count=$hits.Count;Procs=$names;Desc=$ct.Desc})
                    }
                }
                if ($credToolHits.Count -gt 0) {
                    $credList = ($credToolHits | ForEach-Object { "$($_.Tool) ($($_.Count)x: $($_.Procs))" }) -join '  |  '
                    $credDescs = ($credToolHits | ForEach-Object { "$($_.Tool): $($_.Desc)" }) -join '; '
                    Add-DA-Finding 'CRITICAL' 'Credential Access' "Credential Harvesting Tools Detected ($($credToolHits.Count) tool families)" "Known credential access tools executed: $credList. Tool descriptions: $credDescs" 'T1003 | T1555 | T1552'
                }

                # ==== MODULE 6m: AD Reconnaissance / Enumeration Tools (T1087 | T1482) ====
                $adReconPatterns = @(
                    @{ Rx='(?i)^adfind\.exe$';           Name='AdFind' }
                    @{ Rx='(?i)^ADExplorer';              Name='ADExplorer' }
                    @{ Rx='(?i)^ADCollector';             Name='ADCollector' }
                    @{ Rx='(?i)^ldaputility';             Name='LDAPUtility' }
                    @{ Rx='(?i)^Certify\.exe$';           Name='Certify (AD CS abuse)' }
                    @{ Rx='(?i)^Rubeus';                  Name='Rubeus (Kerberos abuse)' }
                    @{ Rx='(?i)^standin\.exe$';           Name='StandIn' }
                    @{ Rx='(?i)^winpeas\.exe$';           Name='WinPEAS' }
                    @{ Rx='(?i)^PowerLine\.exe$';         Name='PowerLine' }
                    @{ Rx='(?i)^Group3r\.exe$';           Name='Group3r (GPO audit)' }
                    @{ Rx='(?i)^SitRep\.exe$';            Name='SitRep' }
                    @{ Rx='(?i)^SharpAwareness';          Name='SharpAwareness' }
                    @{ Rx='(?i)^SharpEnumSuccessor';      Name='SharpEnumSuccessor' }
                    @{ Rx='(?i)^InvisibleSeatbelt';       Name='InvisibleSeatbelt' }
                    @{ Rx='(?i)^SharpUp\.exe$';           Name='SharpUp (privesc check)' }
                    @{ Rx='(?i)^adalanche';               Name='Adalanche (AD path analysis)' }
                    @{ Rx='(?i)^SharpAttack\.exe$';       Name='SharpAttack' }
                    @{ Rx='(?i)^Reconerator';             Name='Reconerator' }
                    @{ Rx='(?i)^SessionSearcher';         Name='SessionSearcher' }
                    @{ Rx='(?i)^SharpADUserIP';           Name='SharpADUserIP' }
                    @{ Rx='(?i)^ADIDNS_RECON';            Name='ADIDNS Recon' }
                )
                $adReconHits = [System.Collections.Generic.List[string]]::new()
                foreach ($ar in $adReconPatterns) {
                    $hits = @($ProcDocs | Where-Object { $_.process.name -match $ar.Rx -and $_.event.type -match 'start' })
                    if ($hits.Count -gt 0) { $adReconHits.Add("$($ar.Name) ($($hits.Count)x)") }
                }
                if ($adReconHits.Count -gt 0) {
                    $adList = $adReconHits -join ', '
                    Add-DA-Finding 'HIGH' 'Discovery' "AD Reconnaissance / Enumeration Tools ($($adReconHits.Count) tools)" "Active Directory enumeration and privilege escalation reconnaissance tools detected: $adList. This toolset maps AD structure, trusts, GPOs, certificate services, and privilege escalation paths - standard pre-lateral-movement reconnaissance." 'T1087.002 | T1482 | T1069.002'
                }

                # ==== MODULE 6n: Named Injection Technique Detection ====
                # Surfaces injection tool names when the process name explicitly reveals the technique.
                $injToolPatterns = @(
                    @{ Rx='(?i)ProcessHollowing';          Name='Process Hollowing';           Mitre='T1055.012' }
                    @{ Rx='(?i)SuspendedThreadInj';        Name='Suspended Thread Injection';   Mitre='T1055' }
                    @{ Rx='(?i)ReflectiveInject';          Name='Reflective DLL Injection';     Mitre='T1055.001' }
                    @{ Rx='(?i)ImportDLLInj';              Name='Import DLL Injection';         Mitre='T1055.001' }
                    @{ Rx='(?i)PillowMintInj';             Name='PillowMint Injection';         Mitre='T1055' }
                    @{ Rx='(?i)EtwInjection';              Name='ETW-based Injection';          Mitre='T1055 | T1562.001' }
                    @{ Rx='(?i)BRC4Inj';                   Name='Brute Ratel C4 Injection';     Mitre='T1055' }
                    @{ Rx='(?i)KernelCallbackProcess';     Name='Kernel Callback Injection';    Mitre='T1055' }
                    @{ Rx='(?i)com_inject';                 Name='COM Object Injection';         Mitre='T1055' }
                    @{ Rx='(?i)NoWPMShInj';                Name='Injection without WPM';        Mitre='T1055' }
                    @{ Rx='(?i)wowInjector';               Name='WoW64 Cross-Arch Injection';   Mitre='T1055' }
                    @{ Rx='(?i)WriteProcessMemoryAPC';     Name='APC Queue Injection';          Mitre='T1055.004' }
                    @{ Rx='(?i)ProcEnvInj';                Name='Process Environment Injection'; Mitre='T1055' }
                    @{ Rx='(?i)SetProcessInj';             Name='Set Process Injection';        Mitre='T1055' }
                    @{ Rx='(?i)DllProxyLoad';              Name='DLL Proxy Loading';            Mitre='T1574.002' }
                    @{ Rx='(?i)AlternativeDLLHollow';      Name='Alternative DLL Hollowing';    Mitre='T1055.001' }
                    @{ Rx='(?i)dllhollow';                  Name='DLL Hollowing';                Mitre='T1055.001' }
                    @{ Rx='(?i)transacted_hollowing';       Name='Transacted Hollowing (TxF)';   Mitre='T1055.012' }
                    @{ Rx='(?i)BreadManModuleStomping';    Name='Module Stomping';              Mitre='T1055.001' }
                    @{ Rx='(?i)modulestomping';             Name='Module Stomping';              Mitre='T1055.001' }
                    @{ Rx='(?i)process_overwriting';        Name='Process Overwriting';          Mitre='T1055.012' }
                    @{ Rx='(?i)module_overloader';          Name='Module Overloading';           Mitre='T1055.001' }
                    @{ Rx='(?i)SharedMemorySubversion';    Name='Shared Memory Subversion';     Mitre='T1055' }
                )
                $injTechHits = [System.Collections.Generic.List[string]]::new()
                foreach ($ij in $injToolPatterns) {
                    $hits = @($ProcDocs | Where-Object { $_.process.name -match $ij.Rx -and $_.event.type -match 'start' })
                    if ($hits.Count -gt 0) {
                        $names = ($hits | ForEach-Object { $_.process.name } | Select-Object -Unique) -join ', '
                        $injTechHits.Add("$($ij.Name): $names ($($hits.Count)x) [$($ij.Mitre)]")
                    }
                }
                if ($injTechHits.Count -gt 0) {
                    $injList = $injTechHits -join '  |  '
                    Add-DA-Finding 'CRITICAL' 'Process Injection' "Named Injection Techniques ($($injTechHits.Count) variants)" "Process names reveal specific injection techniques being tested: $injList. Multiple injection variants suggest systematic security control testing or red team exercise." 'T1055'
                }

                # ==== MODULE 6o: C2 Framework / Loader Recognition ====
                $c2LoaderPatterns = @(
                    @{ Rx='(?i)^coffloader';       Name='COFFLoader (Cobalt Strike BOF)';  Desc='Beacon Object File loader - executes Cobalt Strike modules' }
                    @{ Rx='(?i)^ChaiLdr';          Name='ChaiLdr';                         Desc='stealthy shellcode loader with EDR evasion' }
                    @{ Rx='(?i)^HollowLoader';     Name='HollowLoader';                    Desc='process hollowing-based payload loader' }
                    @{ Rx='(?i)^NetLoader';         Name='NetLoader';                       Desc='.NET assembly loader from URL/pipe' }
                    @{ Rx='(?i)^rloader';           Name='RLoader';                         Desc='reflective loader' }
                    @{ Rx='(?i)^SigLoader';         Name='SigLoader';                       Desc='signed binary proxy loader' }
                    @{ Rx='(?i)^shhhLoad';          Name='ShhhLoader';                      Desc='quiet shellcode loader with sleep evasion' }
                    @{ Rx='(?i)^GoPurple';          Name='GoPurple';                        Desc='Go shellcode runner with multiple execution methods' }
                    @{ Rx='(?i)^Stracciatella';     Name='Stracciatella';                   Desc='PowerShell runspace without powershell.exe (AMSI/CLM bypass)' }
                    @{ Rx='(?i)^MATA_Plug';         Name='MATA Framework (Lazarus)';        Desc='Lazarus group modular C2 plugin' }
                    @{ Rx='(?i)^Cronos\.exe$';      Name='Cronos';                          Desc='C2 implant' }
                    @{ Rx='(?i)^Melkor\.exe$';      Name='Melkor';                          Desc='ELF/PE injector/loader' }
                    @{ Rx='(?i)^TRILLCLIENT';       Name='TRILLCLIENT';                     Desc='data exfiltration tool' }
                    @{ Rx='(?i)^ExecuteAssembly';    Name='ExecuteAssembly';                 Desc='in-memory .NET assembly execution (Cobalt Strike pattern)' }
                    @{ Rx='(?i)^SharperCradle';      Name='SharperCradle';                   Desc='download and execute .NET assemblies from URL' }
                    @{ Rx='(?i)^HeapCryptBeacon';    Name='HeapCrypt Beacon';                Desc='Cobalt Strike beacon with heap encryption sleep' }
                    @{ Rx='(?i)^ThreadStackSpoofer'; Name='ThreadStackSpoofer';              Desc='Cobalt Strike call stack spoofing' }
                    @{ Rx='(?i)^ShellcodeFluctuation'; Name='ShellcodeFluctuation';          Desc='RX<->RW memory protection toggling for shellcode evasion' }
                    @{ Rx='(?i)^NimShellcodeFluctuation'; Name='NimShellcodeFluctuation';    Desc='Nim port of shellcode fluctuation technique' }
                    @{ Rx='(?i)^SnapLoader';          Name='SnapLoader';                     Desc='stealthy loader using snapshot-based injection' }
                    @{ Rx='(?i)^DarkLoadLibrary';     Name='DarkLoadLibrary';                Desc='manual DLL mapping without LoadLibrary API' }
                    @{ Rx='(?i)^MemoryModuleLoader';  Name='MemoryModuleLoader';             Desc='in-memory DLL loading without disk artifacts' }
                    @{ Rx='(?i)^DropFromResource';    Name='DropFromResource';               Desc='drops embedded payload from PE resource section' }
                    @{ Rx='(?i)^DecompressExecute';   Name='DecompressExecute';              Desc='compressed shellcode decompression and execution' }
                )
                $c2Hits = [System.Collections.Generic.List[string]]::new()
                foreach ($c2 in $c2LoaderPatterns) {
                    $hits = @($ProcDocs | Where-Object { $_.process.name -match $c2.Rx -and $_.event.type -match 'start' })
                    if ($hits.Count -gt 0) {
                        $names = ($hits | ForEach-Object { $_.process.name } | Select-Object -Unique) -join ', '
                        $c2Hits.Add("$($c2.Name) ($($hits.Count)x): $($c2.Desc)")
                    }
                }
                if ($c2Hits.Count -gt 0) {
                    $c2List = $c2Hits -join '  |  '
                    Add-DA-Finding 'CRITICAL' 'Execution' "C2 Frameworks / Payload Loaders ($($c2Hits.Count) tools)" "Known C2 frameworks and payload delivery tools detected: $c2List" 'T1059 | T1106 | T1620'
                }

                # ==== MODULE 6p: Direct Syscall / Unhooking Tool Recognition ====
                $syscallPatterns = @(
                    @{ Rx='(?i)NtdllUnhook';        Name='NTDLL Unhooker' }
                    @{ Rx='(?i)NtdllPipe';           Name='NTDLL Pipe (fresh NTDLL load)' }
                    @{ Rx='(?i)SuspendedUnhook';     Name='Suspended Unhook' }
                    @{ Rx='(?i)HellsGate';           Name='Hells Gate (dynamic syscall)' }
                    @{ Rx='(?i)TartarusGate';        Name='Tartarus Gate (syscall variant)' }
                    @{ Rx='(?i)ParallelSyscall';     Name='Parallel Syscalls' }
                    @{ Rx='(?i)SyscallTrampoline';   Name='Syscall Trampoline' }
                    @{ Rx='(?i)RefleXXion';           Name='RefleXXion (reflective unhooking)' }
                    @{ Rx='(?i)VehApiResolve';       Name='VEH API Resolve' }
                    @{ Rx='(?i)SyscallNumberExtract'; Name='Syscall Number Extractor' }
                    @{ Rx='(?i)SharpCall';            Name='SharpCall (C# syscall)' }
                    @{ Rx='(?i)NimGetSyscallStub';   Name='NimGetSyscallStub' }
                    @{ Rx='(?i)DInvokeLazyImport';   Name='D/Invoke Lazy Import' }
                    @{ Rx='(?i)PerunsFart';           Name='Perun''s Fart (NTDLL unhooking)' }
                    @{ Rx='(?i)dogePerunsFart';       Name='Doge Perun''s Fart' }
                    @{ Rx='(?i)GolangInSharp';        Name='GolangInSharp (Go syscalls in C#)' }
                    @{ Rx='(?i)EDR.Freeze';           Name='EDR-Freeze' }
                    @{ Rx='(?i)^Evasor\.exe$';        Name='Evasor (AV/EDR evasion framework)' }
                )
                $syscallHits = [System.Collections.Generic.List[string]]::new()
                foreach ($sc in $syscallPatterns) {
                    $hits = @($ProcDocs | Where-Object { $_.process.name -match $sc.Rx -and $_.event.type -match 'start' })
                    if ($hits.Count -gt 0) {
                        $names = ($hits | ForEach-Object { $_.process.name } | Select-Object -Unique) -join ', '
                        $syscallHits.Add("$($sc.Name): $names ($($hits.Count)x)")
                    }
                }
                if ($syscallHits.Count -gt 0) {
                    $scList = $syscallHits -join '  |  '
                    Add-DA-Finding 'CRITICAL' 'Defense Evasion' "Direct Syscall / EDR Unhooking Tools ($($syscallHits.Count) variants)" "Tools that bypass EDR userland hooks via direct syscalls or NTDLL remapping: $scList. These tools resolve syscall numbers at runtime and invoke NT functions directly, completely bypassing any EDR hooks on ntdll.dll stubs." 'T1562.001 | T1106'
                }

                # ==== MODULE 6q: UUID / Alternate Shellcode Staging (T1027) ====
                $uuidShellcodeRx = '(?i)(UUIDExec|goUUID|NinjaUUIDDropper|ExecScUUID|UuidShellcode|mac2binGo|ip2binGo)'
                $uuidHits = @($ProcDocs | Where-Object { $_.process.name -match $uuidShellcodeRx -and $_.event.type -match 'start' })
                if ($uuidHits.Count -gt 0) {
                    $uuidNames = ($uuidHits | ForEach-Object { $_.process.name } | Select-Object -Unique) -join ', '
                    Add-DA-Finding 'HIGH' 'Defense Evasion' "Alternate Shellcode Staging: UUID/MAC/IP Encoding ($($uuidHits.Count) events)" "Shellcode staged via non-traditional encoding to evade signature detection: $uuidNames. These tools encode shellcode as UUID strings, MAC addresses, or IP addresses, then reconstruct the payload at runtime via UuidFromString/RtlEthernetStringToAddress/RtlIpv4StringToAddress API calls - bypassing byte-pattern scanners." 'T1027 | T1140'
                }

                # ==== MODULE 6r: Screen Capture / Keylogging / Collection (T1113 | T1056) ====
                $collectionPatterns = @(
                    @{ Rx='(?i)(Screenshooter|ScreenCapture|ScreenshotCapture|ScreenRecorder)'; Name='Screen Capture'; Mitre='T1113' }
                    @{ Rx='(?i)(KeyloggerSetWindowsHookEx|getasynckeystate)';                    Name='Keylogger';      Mitre='T1056.001' }
                    @{ Rx='(?i)(WiretapKey|WireTap\.exe$)';                                     Name='Keystroke/Audio Capture'; Mitre='T1056.001 | T1123' }
                )
                $collHits = [System.Collections.Generic.List[string]]::new()
                $collMitre = [System.Collections.Generic.List[string]]::new()
                foreach ($cl in $collectionPatterns) {
                    $hits = @($ProcDocs | Where-Object { $_.process.name -match $cl.Rx -and $_.event.type -match 'start' })
                    if ($hits.Count -gt 0) {
                        $names = ($hits | ForEach-Object { $_.process.name } | Select-Object -Unique) -join ', '
                        $collHits.Add("$($cl.Name): $names ($($hits.Count)x)")
                        $collMitre.Add($cl.Mitre)
                    }
                }
                if ($collHits.Count -gt 0) {
                    $collList = $collHits -join '  |  '
                    $collMitreStr = ($collMitre | Select-Object -Unique) -join ' | '
                    Add-DA-Finding 'HIGH' 'Collection' "Screen Capture / Keylogging Tools ($($collHits.Count) categories)" "Data collection tools for surveillance and credential theft: $collList" $collMitreStr
                }

                # ==== MODULE 6s: Primary C2 Domain by Process Fan-Out ====
                # Identifies the domain queried by the most distinct malware processes — the C2 hub.
                if ($NetDocs.Count -gt 0) {
                    $domProcFan = @($NetDocs | Where-Object { $_.dns.question.name } |
                        Group-Object { $_.dns.question.name } | ForEach-Object {
                            $procs = @($_.Group | ForEach-Object { $_.process.name } | Where-Object { $_ } | Select-Object -Unique)
                            [PSCustomObject]@{Domain=$_.Name; ProcCount=$procs.Count; QueryCount=$_.Count; Procs=$procs}
                        } | Where-Object {
                            $_.ProcCount -ge 5 -and
                            $_.Domain -notmatch $benignClassRx
                        } | Sort-Object ProcCount -Descending)
                    if ($domProcFan.Count -gt 0) {
                        $topC2 = $domProcFan[0]
                        $procSample = ($topC2.Procs | Select-Object -First 10) -join ', '
                        $procMore = if ($topC2.ProcCount -gt 10) { " ... and $($topC2.ProcCount - 10) more" } else { "" }
                        Add-DA-Finding 'CRITICAL' 'Command and Control' "Primary C2 Hub: $($topC2.Domain) ($($topC2.ProcCount) tools, $($topC2.QueryCount) queries)" "Domain $($topC2.Domain) was queried by $($topC2.ProcCount) distinct malware processes ($($topC2.QueryCount) total queries) - the highest process fan-out of any non-benign domain. This identifies it as the primary command-and-control infrastructure. Source processes: $procSample$procMore" 'T1071.001 | T1102'
                        # Surface additional high-fanout domains
                        $otherC2 = @($domProcFan | Select-Object -Skip 1 -First 3 | Where-Object { $_.ProcCount -ge 3 })
                        if ($otherC2.Count -gt 0) {
                            $otherList = ($otherC2 | ForEach-Object { "$($_.Domain) ($($_.ProcCount) procs, $($_.QueryCount) queries)" }) -join '; '
                            Add-DA-Finding 'HIGH' 'Command and Control' "Additional High-Fanout C2 Domains" "Other domains queried by multiple malware processes: $otherList" 'T1071.001'
                        }
                    }
                }

                # ==== MODULE 6t: Accessibility Feature Backdoor (T1546.008) ====
                # Detects IFEO Debugger hijacks targeting accessibility binaries (sticky keys etc.)
                $accessBins = @('sethc.exe','utilman.exe','osk.exe','magnify.exe','narrator.exe','DisplaySwitch.exe','AtBroker.exe')
                $accessBinRx = ($accessBins | ForEach-Object { [regex]::Escape($_) }) -join '|'
                $stickyKeysReg = @($RegDocs | Where-Object {
                    $_.registry.key -match "Image File Execution Options\\($accessBinRx)" -and
                    ($_.registry.key -match 'Debugger' -or $_.registry.data.strings -match 'cmd\.exe|powershell|pwsh')
                })
                $stickyKeysCmds = @($ProcDocs | Where-Object {
                    $cmd = $_.process.command_line
                    $cmd -and $cmd -match 'Image File Execution Options' -and $cmd -match "($accessBinRx)" -and
                    ($cmd -match 'Debugger' -or $cmd -match '/d\s+.*cmd|/d\s+.*powershell')
                })
                $totalSticky = $stickyKeysReg.Count + $stickyKeysCmds.Count
                if ($totalSticky -gt 0) {
                    $stickyDetails = @()
                    if ($stickyKeysReg.Count -gt 0) {
                        $stickyRegKeys = ($stickyKeysReg | ForEach-Object {
                            $target = if ($_.registry.key -match 'Options\\([^\\]+)') { $Matches[1] } else { 'unknown' }
                            $val = $_.registry.data.strings
                            "$target -> $val (by $($_.process.name))"
                        } | Select-Object -Unique) -join '; '
                        $stickyDetails += "Registry: $stickyRegKeys"
                    }
                    if ($stickyKeysCmds.Count -gt 0) {
                        $stickyCmds = ($stickyKeysCmds | ForEach-Object { $_.process.command_line } | Select-Object -Unique -First 3) -join '  |  '
                        $stickyDetails += "Commands: $stickyCmds"
                    }
                    Add-DA-Finding 'CRITICAL' 'Persistence' "Accessibility Feature Backdoor (Sticky Keys / IFEO Debugger)" "Image File Execution Options Debugger set for Windows accessibility binary - provides unauthenticated RDP/lock-screen shell access. Pressing Shift 5x (sethc) or Win+U (utilman) at the login screen launches cmd.exe instead of the accessibility tool. $($stickyDetails -join '  ||  ')" 'T1546.008'
                }

                # ==== MODULE 7: DLL / Image-Load Analysis ====

                # 7a. DLL defense evasion flags
                $evDlls = @($ImgDocs | Where-Object { $_.dll.Ext.defense_evasions })
                if ($evDlls.Count -gt 0) {
                    $evList = ($evDlls | Select-Object -First 8 | ForEach-Object {
                        $dn = if ($_.dll.path) { Split-Path $_.dll.path -Leaf } else { '?' }
                        "$dn [evasion: $($_.dll.Ext.defense_evasions)] (by $($_.process.name))"
                    } | Select-Object -Unique) -join '; '
                    Add-DA-Finding 'HIGH' 'Defense Evasion' 'DLL Loaded with Defense Evasion Flags' "Elastic Defend flagged DLL load(s) with evasion indicators: $evList" 'T1036 | T1562'
                }

                # 7b. Confirmed-executed processes with zero DLL load telemetry (manual mapping)
                $executedNames = @($ProcDocs | Where-Object { $_.event.type -match 'start' -and $_.process.name } |
                    ForEach-Object { $_.process.name } | Select-Object -Unique)
                $loadedNames   = @($ImgDocs | Where-Object { $_.process.name } | ForEach-Object { $_.process.name } | Select-Object -Unique)
                $noDllProcs    = @($executedNames | Where-Object {
                    $pn = $_
                    ($loadedNames -notcontains $pn) -and
                    ($pn -notmatch '^(conhost|ctfmon|dllhost|svchost|services|lsass|wininit|csrss|smss|taskhost|taskhostw|sihost|fontdrvhost|dwm|wermgr|WerFault|SearchIndexer)\.exe$')
                })
                if ($noDllProcs.Count -gt 0) {
                    $nList = $noDllProcs -join ', '
                    Add-DA-Finding 'HIGH' 'Defense Evasion' 'Zero DLL Load Telemetry for Executed Process(es)  -  Manual Mapping' "Process(es) ran with no image-load callbacks recorded: $nList  -  when combined with NTDLL unhooking, indicates manual DLL mapping (NtMapViewOfSection / LdrLoadDll direct call) to stay invisible to EDR hook-based DLL monitoring" 'T1055.001 | T1562.001'
                }

                # ==== MODULE 8: IOC/YARA Scanner Results (Thor/Loki, cross-referenced into findings) ====
                if ($LokiResult -and $LokiResult.Available) {
                    $scanLbl = if ($LokiResult.ScannerLabel) { $LokiResult.ScannerLabel } else { 'IOC/YARA Scanner' }

                    # Build a lookup: file path fragment → alert object (for process chain cross-ref)
                    $lokiFileMap = @{}
                    foreach ($a in $LokiResult.Alerts) {
                        if ($a.File) { $lokiFileMap[$a.File.ToLower()] = $a }
                    }

                    # 8a. Each ALERT becomes a CRITICAL finding with full detail
                    foreach ($a in $LokiResult.Alerts) {
                        $ruleStr  = if ($a.Rule)        { $a.Rule }        else { 'Unknown rule' }
                        $fileStr  = if ($a.File)        { " | File: $($a.File)" }        else { '' }
                        $descStr  = if ($a.Description) { " | $($a.Description)" }       else { '' }
                        $scoreStr = if ($a.Score -gt 0) { " | Score: $($a.Score)/100" }  else { '' }
                        $det = "$scanLbl YARA/IOC match  -  Rule: $ruleStr$fileStr$scoreStr$descStr"
                        Add-DA-Finding 'CRITICAL' "$scanLbl IOC/YARA" "YARA/IOC Match: $ruleStr" $det 'T1204.002'
                    }

                    # 8b. WARNINGs → HIGH findings
                    foreach ($w in $LokiResult.Warnings) {
                        $ruleStr = if ($w.Rule) { $w.Rule } else { 'filename/hash match' }
                        $fileStr = if ($w.File) { " | File: $($w.File)" } else { '' }
                        Add-DA-Finding 'HIGH' "$scanLbl IOC/YARA" "$scanLbl Warning: $ruleStr" "$scanLbl WARNING  -  Rule: $ruleStr$fileStr" ''
                    }

                    # 8c. Cross-reference: ALERT files vs. process executables in the chain
                    $lokiAlertFilesLc = @($LokiResult.Alerts | ForEach-Object { $_.File } | Where-Object { $_ } | ForEach-Object { $_.ToLower() })
                    if ($lokiAlertFilesLc.Count -gt 0) {
                        $hitProcs = @($ProcDocs | Where-Object {
                            $exe = ($_.process.executable -replace '/','\\').ToLower()
                            $exe -and ($lokiAlertFilesLc | Where-Object { $exe -eq $_ -or $exe.EndsWith("\$_") }).Count -gt 0
                        } | ForEach-Object { $_.process.name } | Select-Object -Unique)
                        if ($hitProcs.Count -gt 0) {
                            $pList = $hitProcs -join ', '
                            Add-DA-Finding 'CRITICAL' "$scanLbl IOC/YARA" "Confirmed-Malicious Process(es) in Chain  -  $scanLbl YARA Hit" "$scanLbl matched a YARA/IOC rule against the executable of active process(es): $pList  -  binary confirmed malicious, not just heuristic" 'T1204.002 | T1055'
                        }
                    }

                    # 8d. Attribution boost: rule names that reference known APT families
                    $aptRx = 'Tick|BronzeButler|APT10|RedBaldKnight|NOOPDOOR|GHOSTSPIDER|MySnake|Minzen|msfltr|Daserf|Xxmm|Aveo'
                    $aptRuleHits = @($LokiResult.Alerts | Where-Object { $_.Rule -match $aptRx })
                    if ($aptRuleHits.Count -gt 0) {
                        $ruleNames = ($aptRuleHits | ForEach-Object { $_.Rule } | Select-Object -Unique) -join ', '
                        Add-DA-Finding 'CRITICAL' 'Threat Attribution' "$scanLbl YARA Confirms APT Attribution" "$scanLbl matched APT-family-specific YARA rule(s): $ruleNames  -  this is the highest-confidence attribution signal available (binary-level match against curated threat intel signatures)" 'T1583.001'
                    }
                }

                # ==== MODULE 9: Adversary Authorship, OPSEC & Kill Chain Analysis ====

                # 9a. Code-page switching (chcp.com/chcp.exe) - Chinese authorship signal
                # Malware compiled on Chinese-language Windows systems frequently runs chcp to
                # set GBK (936) or Big5 (950) encoding. High volume has no legitimate explanation.
                $chcpEvts = @($ProcDocs | Where-Object {
                    $_.process.name -match '^chcp\.(com|exe)$' -and $_.event.type -match 'start'
                })
                if ($chcpEvts.Count -ge 5) {
                    $chcpParents = ($chcpEvts | ForEach-Object { $_.process.parent.name } | Where-Object { $_ } |
                        Group-Object | Sort-Object Count -Descending | Select-Object -First 3 |
                        ForEach-Object { "$($_.Name) x$($_.Count)" }) -join ', '
                    $chcpCmds = ($chcpEvts | ForEach-Object { $_.process.command_line } | Where-Object { $_ } |
                        Select-Object -Unique -First 4) -join ', '
                    $chcpArgNote    = if ($chcpCmds)    { " Args: $chcpCmds." }       else { '' }
                    $chcpParentNote = if ($chcpParents) { " Parents: $chcpParents." } else { '' }
                    Add-DA-Finding 'HIGH' 'Threat Attribution' "Chinese Authorship Signal: chcp.com Executed $($chcpEvts.Count) Times" "chcp (console code page switch) executed $($chcpEvts.Count) times.$chcpArgNote$chcpParentNote  Malware compiled on Chinese-language Windows systems frequently switches the code page to GBK (936) or Big5 (950) for expected string encoding. This volume is inconsistent with any legitimate workflow. Treat as a soft indicator of Chinese-authored tooling - APT10, Tick, APT27, APT41 all exhibit this pattern." 'T1614'
                }

                # 9b. OPSEC anomaly - operationally-revealing staging path names
                # Adversaries sometimes use folder names that expose their intent or tradecraft.
                # \SubDir\ is documented APT10/menuPass staging tradecraft across multiple campaigns.
                $opSecPatterns9 = @('\malware\','\Backdoor\','\payload\','\shellcode\','\implant\',
                                    '\stager\','\dropper\','\loader\','\rat\','\stage\',
                                    '\SubDir\','\Trojan\','\inject\')
                $opSecHits9 = [System.Collections.Generic.List[PSCustomObject]]::new()
                foreach ($pd9 in $ProcDocs) {
                    $exe9 = $pd9.process.executable
                    if (-not $exe9) { continue }
                    $exeLower9 = $exe9.ToLower()
                    foreach ($pat9 in $opSecPatterns9) {
                        if ($exeLower9.IndexOf($pat9.ToLower(), [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                            $opSecHits9.Add([PSCustomObject]@{Name=$pd9.process.name;Exe=$exe9;Pat=$pat9})
                            break
                        }
                    }
                }
                if ($opSecHits9.Count -gt 0) {
                    $opList9 = ($opSecHits9 | Select-Object -First 6 |
                        ForEach-Object { "$($_.Name) @ $($_.Exe)" } | Select-Object -Unique) -join '; '
                    Add-DA-Finding 'HIGH' 'Defense Evasion' 'OPSEC Anomaly: Operationally-Revealing Staging Path' "Process(es) executed from paths whose folder names expose adversary intent: $opList9  -  \SubDir\ is documented APT10/menuPass staging tradecraft. Execution from \malware\ or \payload\ directories reflects poor operator OPSEC or controlled detonation." 'T1036'
                }

                # 9c. External IP geolocation pre-check (APT victim profiling)
                # APT10, Tick, APT27, APT41 query geolocation APIs immediately before deploying
                # primary payloads to verify the victim is not in their home country, avoiding
                # law enforcement exposure and preventing C2 infrastructure from being burned on sandboxes.
                $geoCheckDomains9 = @(
                    'ip-api.com','l2.io','api.ipify.org','ipinfo.io','checkip.amazonaws.com',
                    'myexternalip.com','icanhazip.com','wtfismyip.com','api.my-ip.io',
                    '4.ifconfig.co','ifconfig.me','ip.sb','ipecho.net','api.ipgeolocation.io',
                    'www.ip.cn','ip.cn','myip.com'
                )
                $geoHits9 = [System.Collections.Generic.List[PSCustomObject]]::new()
                foreach ($nd9 in $NetDocs) {
                    $qname9 = $nd9.dns.question.name
                    if (-not $qname9) { continue }
                    $qLower9 = $qname9.ToLower()
                    foreach ($gd9 in $geoCheckDomains9) {
                        if ($qLower9 -eq $gd9 -or $qLower9.EndsWith(".$gd9")) {
                            $geoHits9.Add([PSCustomObject]@{Domain=$qname9;Process=$nd9.process.name})
                            break
                        }
                    }
                }
                if ($geoHits9.Count -gt 0) {
                    $geoList9 = ($geoHits9 | Group-Object { "$($_.Process)|$($_.Domain)" } |
                        ForEach-Object {
                            $grpCt9 = $_.Count
                            "$($_.Group[0].Process) -> $($_.Group[0].Domain) x$grpCt9"
                        }) -join '; '
                    Add-DA-Finding 'HIGH' 'Threat Attribution' 'Geolocation Pre-Check: APT Victim Profiling Pattern' "External IP geolocation service queried: $geoList9  -  APT10/menuPass, Tick, and APT27 query ip-api.com or similar services immediately before deploying their primary payload to verify the victim host is NOT in their home country. Avoids burning C2 infrastructure on sandboxes and reduces law enforcement exposure. Strong behavioral APT10 attribution indicator when combined with SubDir staging and Pulsar RAT findings." 'T1614 | T1082'
                }

                # 9d. WerFault.exe used as injection vehicle
                # WerFault is a trusted signed Windows binary that many AV/EDR tools whitelist.
                # When it is the SOURCE of cross-process WriteProcessMemory calls it indicates
                # abuse of the Windows Error Reporting handle-duplication path to inject from a
                # trusted context, bypassing injector-based detection that excludes WER from monitoring.
                $werInjSrc9 = @($ApiDocs | Where-Object {
                    $_.process.name -match '^WerFault(Secure)?\.exe$' -and
                    $_.process.Ext.api.name -eq 'WriteProcessMemory' -and
                    ($_.process.Ext.api.behaviors -match 'cross-process') -and
                    ($_.process.Ext.api.behaviors -notmatch 'ProcessStartupInfo')
                })
                if ($werInjSrc9.Count -gt 0) {
                    $werTargets9 = ($werInjSrc9 | ForEach-Object { $_.Target.process.name } |
                        Where-Object { $_ } | Select-Object -Unique) -join ', '
                    $werCt9 = $werInjSrc9.Count
                    Add-DA-Finding 'CRITICAL' 'Process Injection' "WerFault.exe Used as Injection Vehicle ($werCt9 cross-process writes)" "WerFault.exe performed $werCt9 cross-process WriteProcessMemory calls targeting: $werTargets9  -  Windows Error Reporting can inherit process handles during crash analysis. Abusing this lets an attacker inject from a trusted signed binary that many security tools whitelist, bypassing injector-based detection that excludes WER from monitoring." 'T1055 | T1562.001'
                }

                # 9e. Kill chain temporal sequence reconstruction
                # Identifies attack phases present and their relative order from event timestamps.
                $kcPhases9 = [System.Collections.Generic.List[PSCustomObject]]::new()

                $kcUac9 = @($AlertDocs | Where-Object { $_.'kibana.alert.rule.name' -match 'UAC Bypass' })
                if ($kcUac9.Count -gt 0) {
                    $kcT9 = ($kcUac9 | Sort-Object '@timestamp' | Select-Object -First 1).'@timestamp'
                    $kcPhases9.Add([PSCustomObject]@{Phase='Privilege Escalation';Time=$kcT9;Detail="UAC bypass ($($kcUac9.Count) alerts)"})
                }

                $kcDef9 = @($AlertDocs | Where-Object { $_.'kibana.alert.rule.name' -match 'Defender|MpPreference|Tamper|Exclusion' })
                if ($kcDef9.Count -gt 0) {
                    $kcT9 = ($kcDef9 | Sort-Object '@timestamp' | Select-Object -First 1).'@timestamp'
                    $kcPhases9.Add([PSCustomObject]@{Phase='Defense Evasion (AV Disable)';Time=$kcT9;Detail="Defender disable ($($kcDef9.Count) alerts)"})
                }

                $kcRun9 = @($RegDocs | Where-Object { $_.registry.key -match 'CurrentVersion\\Run' -and $_.event.action -match 'creation|modification' })
                if ($kcRun9.Count -gt 0) {
                    $kcT9 = ($kcRun9 | Sort-Object '@timestamp' | Select-Object -First 1).'@timestamp'
                    $kcPhases9.Add([PSCustomObject]@{Phase='Persistence';Time=$kcT9;Detail="Run key writes ($($kcRun9.Count))"})
                }

                $kcInj9 = @($ApiDocs | Where-Object {
                    $_.process.Ext.api.name -eq 'WriteProcessMemory' -and
                    $_.process.Ext.api.behaviors -match 'cross-process'
                })
                if ($kcInj9.Count -gt 0) {
                    $kcT9 = ($kcInj9 | Sort-Object '@timestamp' | Select-Object -First 1).'@timestamp'
                    $kcPhases9.Add([PSCustomObject]@{Phase='Process Injection';Time=$kcT9;Detail="Cross-process writes ($($kcInj9.Count))"})
                }

                if ($confirmedC2Doms.Count -gt 0 -or $confirmedC2IPs.Count -gt 0) {
                    $kcC29 = @($NetDocs | Where-Object {
                        ($_.dns.question.name -and $confirmedC2Doms.Contains($_.dns.question.name)) -or
                        ($_.destination.ip   -and $confirmedC2IPs.Contains($_.destination.ip))
                    })
                    if ($kcC29.Count -gt 0) {
                        $kcT9 = ($kcC29 | Sort-Object '@timestamp' | Select-Object -First 1).'@timestamp'
                        $kcPhases9.Add([PSCustomObject]@{Phase='C2 Beacon';Time=$kcT9;Detail="Known C2 contact ($($kcC29.Count) events)"})
                    }
                }

                if ($kcPhases9.Count -ge 2) {
                    $kcSorted9   = @($kcPhases9 | Sort-Object { $_.Time })
                    $kcChainStr9 = ($kcSorted9 | ForEach-Object {
                        $tStr9 = if ($_.Time) { " [$(($_.Time -replace 'T',' ') -replace '\.\d+Z',' UTC')]" } else { '' }
                        "$($_.Phase)$($tStr9): $($_.Detail)"
                    }) -join '  ->  '
                    Add-DA-Finding 'INFO' 'Kill Chain' 'Attack Phase Sequence Reconstructed from Event Timestamps' "Temporal kill chain: $kcChainStr9  -  Use this sequence to determine dwell time per phase and identify where containment could have interrupted the attack." 'T1078 | T1055 | T1547 | T1071'
                }

                # ==== Build HTML output ====
                $sevOrd = @{CRITICAL=0;HIGH=1;MEDIUM=2;LOW=3;INFO=4}
                $html   = [System.Text.StringBuilder]::new()
                $sorted = @($findings | Sort-Object { $sevOrd[$_.Severity] })

                # Alert breakdown table (prepended before findings)
                $alertRuleGrps = @($AlertDocs | Where-Object { $_.'kibana.alert.rule.name' } |
                    Group-Object { $_.'kibana.alert.rule.name' } | Sort-Object Count -Descending)
                if ($alertRuleGrps.Count -gt 0) {
                    [void]$html.AppendLine("<div class='da-cat'><div class='da-cat-hdr'>ALERT BREAKDOWN</div><table class='da-tbl'><tr><th>Rule</th><th>Count</th><th>Severity</th><th>Max Risk</th></tr>")
                    foreach ($rg in $alertRuleGrps) {
                        $sev4t  = ($rg.Group | ForEach-Object { $_.'kibana.alert.severity' } | Where-Object { $_ } | Select-Object -Unique | Sort-Object | Select-Object -First 1)
                        $risk4t = ($rg.Group | ForEach-Object { [int]$_.'kibana.alert.risk_score' } | Where-Object { $_ } | Measure-Object -Maximum).Maximum
                        $sc4t   = if ($sev4t -match 'critical') { 'da-crit' } elseif ($sev4t -match 'high') { 'da-high' } elseif ($sev4t -match 'medium') { 'da-med' } else { 'da-low' }
                        $rn4t   = ($rg.Name -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;')
                        [void]$html.AppendLine("<tr class='$sc4t'><td>$rn4t</td><td>$($rg.Count)</td><td>$(if($sev4t){$sev4t}else{'—'})</td><td>$(if($risk4t){$risk4t}else{'—'})</td></tr>")
                    }
                    [void]$html.AppendLine("</table></div>")
                }

                if ($sorted.Count -gt 0) {
                    foreach ($cat in ($sorted | Group-Object Category)) {
                        $catTtl = $cat.Name.ToUpper()
                        [void]$html.AppendLine("<div class='da-cat'><div class='da-cat-hdr'>$catTtl</div>")
                        foreach ($f in ($cat.Group | Sort-Object { $sevOrd[$_.Severity] })) {
                            $sc = switch ($f.Severity) {'CRITICAL'{'da-crit'} 'HIGH'{'da-high'} 'MEDIUM'{'da-med'} default{'da-low'}}
                            $mb = if ($f.Mitre) {
                                $badges = ($f.Mitre -split '\s*\|\s*' | Where-Object { $_ -match '^T\d' } |
                                    ForEach-Object { "<span class='da-mbadge'>$_</span>" }) -join ''
                                "<div class='da-mitre'>$badges</div>"
                            } else { "" }
                            $htitle  = $f.Title  -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;'
                            $hdetail = $f.Detail -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;'
                            [void]$html.AppendLine("<div class='da-finding $sc'><span class='da-sev-badge'>$($f.Severity)</span><div class='da-title'>$htitle</div><div class='da-detail'>$hdetail</div>$mb</div>")
                        }
                        [void]$html.AppendLine("</div>")
                    }
                } else {
                    [void]$html.AppendLine("<div class='art info'>No behavioral detections from offline analysis engine.</div>")
                }

                [PSCustomObject]@{
                    Findings      = $sorted
                    MitreTechs    = @($mitreTechs)
                    Html          = $html.ToString()
                    FindingCount  = $findings.Count
                    CriticalCount = ($findings | Where-Object { $_.Severity -eq 'CRITICAL' }).Count
                    HighCount     = ($findings | Where-Object { $_.Severity -eq 'HIGH' }).Count
                }
            }
            # -----------------------------------------------------------------------

            # --- Session metadata from session_info.txt ---
            $siLines   = if (Test-Path (Join-Path $DetonationLogsDir "session_info.txt")) {
                             Get-Content (Join-Path $DetonationLogsDir "session_info.txt")
                         } else { @() }
            $agentHost = ($siLines | Where-Object { $_ -match '^\s*Session\s*:' } |
                          ForEach-Object { ($_ -split ':\s*',2)[1].Trim() } | Select-Object -First 1)
            if ([string]::IsNullOrWhiteSpace($agentHost)) { $agentHost = Split-Path $DetonationLogsDir -Leaf }
            $fromTs = ($siLines | Where-Object { $_ -match '^\s*Start\s*:' } | ForEach-Object {
                if ($_ -match '(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)') { $Matches[1] }
            } | Select-Object -First 1)
            $toTs   = ($siLines | Where-Object { $_ -match '^\s*End\s*:' } | ForEach-Object {
                if ($_ -match '(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)') { $Matches[1] }
            } | Select-Object -First 1)
            Write-Host "  Session: $agentHost  |  $fromTs --> $toTs" -ForegroundColor DarkCyan

            # --- [1/8] Alerts ---
            Write-Host "[1/8] Alerts (offline: alerts.ndjson)..." -ForegroundColor DarkGray
            $alertDocs     = Read-Ndjson (Join-Path $DetonationLogsDir "alerts.ndjson")
            $alertHitList  = @($alertDocs | ForEach-Object { [PSCustomObject]@{ _source = $_ } })
            $ruleGroups    = @($alertDocs | Where-Object { $_.'kibana.alert.rule.name' } |
                               Group-Object { $_.'kibana.alert.rule.name' })
            $alertRules     = @($ruleGroups | ForEach-Object { "($($_.Count)x) $($_.Name)" })
            $alertRuleNames = @($ruleGroups | ForEach-Object { $_.Name })
            $alertTechIds  = @($alertDocs | ForEach-Object {
                $thr = $_.'kibana.alert.rule.threat'
                if ($thr) { $thr | ForEach-Object { if ($_.technique) { $_.technique | ForEach-Object { $_.id } } } }
            } | Where-Object { $_ } | Select-Object -Unique)
            $alertTechStr  = $alertTechIds -join ', '

            # Elastic Defend behavior / memory alerts (NTDLL unhooking, shellcode, etc.)
            $behaviorAlertDocs = @($alertDocs | Where-Object {
                $_.'kibana.alert.rule.name' -match 'Behavior|NTDLL|Memory|Injection|Shellcode'
            })
            $idActions = @($behaviorAlertDocs | Where-Object { $_.event.action } |
                Group-Object { $_.event.action } | ForEach-Object { "($($_.Count)x) $($_.Name)" })
            $idRules   = @($behaviorAlertDocs | ForEach-Object { $_.'kibana.alert.rule.name' } |
                Where-Object { $_ } | Select-Object -Unique)
            $idTotal   = $behaviorAlertDocs.Count

            Write-Host "       -> $($alertHitList.Count) alert hits, $($alertRules.Count) unique rules" -ForegroundColor DarkGray
            if ($idTotal -gt 0) {
                $idRuleStr = ($idRules | Select-Object -First 3) -join ' | '
                Write-Host "       -> $idTotal behavior/memory alert(s): $idRuleStr" -ForegroundColor Red
            }

            # ML model confidence scores  -  surface per-sample Elastic Defend verdict
            $mlHits = @($alertDocs | Where-Object { $_.file.Ext.malware_classification.score -and $_.process.name } |
                Select-Object @{N='Proc';E={$_.process.name}},
                              @{N='Score';E={$_.file.Ext.malware_classification.score}},
                              @{N='Hash';E={$_.file.hash.sha256}} |
                Group-Object Proc | ForEach-Object { $_.Group | Sort-Object Score -Descending | Select-Object -First 1 } |
                Sort-Object Score -Descending)
            if ($mlHits.Count -gt 0) {
                Write-Host "       -> Elastic Defend ML scores (endpointpe-v4-model):" -ForegroundColor DarkGray
                $mlHits | Select-Object -First 6 | ForEach-Object {
                    $pct = [math]::Round($_.Score * 100, 5)
                    $col = if ($_.Score -ge 0.99) { 'Red' } elseif ($_.Score -ge 0.95) { 'Yellow' } else { 'White' }
                    Write-Host "          $pct% -- $($_.Proc)" -ForegroundColor $col
                }
            }

            # --- [2/8] Processes ---
            Write-Host "[2/8] Processes (offline: process_events.ndjson)..." -ForegroundColor DarkGray
            $procDocs     = Read-Ndjson (Join-Path $DetonationLogsDir "process_events.ndjson")
            $privateRx    = '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.)'
            $procNameGrps = @($procDocs | Where-Object { $_.process.name } | Group-Object { $_.process.name })
            $procNames    = @($procNameGrps | ForEach-Object { "($($_.Count)x) $($_.Name)" })
            $procHashes   = @($procDocs | ForEach-Object { $_.process.hash.sha256 } |
                Where-Object { $_ -match '^[a-fA-F0-9]{64}$' } | Select-Object -Unique)
            $procTotal    = ($procDocs | Measure-Object).Count
            # Deduplicated process records for SANS 508 metadata analysis
            $procDetails  = @($procDocs | Where-Object { $_.process.executable } |
                Group-Object { "$($_.process.name)|$($_.process.executable)" } |
                ForEach-Object { $_.Group[0] })
            $procCmdRecords = @($procDocs | ForEach-Object {
                $pn = ''
                if ($_.process -and $_.process.name) { $pn = [string]$_.process.name }
                elseif ($_.'process.name') { $pn = [string]$_.'process.name' }

                $cmd = ''
                if ($_.process -and $_.process.command_line) { $cmd = [string]$_.process.command_line }
                elseif ($_.'process.command_line') { $cmd = [string]$_.'process.command_line' }
                elseif ($_.winlog -and $_.winlog.event_data -and $_.winlog.event_data.CommandLine) { $cmd = [string]$_.winlog.event_data.CommandLine }
                elseif ($_.'winlog.event_data.CommandLine') { $cmd = [string]$_.'winlog.event_data.CommandLine' }
                elseif ($_.process -and $_.process.args) { $cmd = (@($_.process.args) -join ' ') }

                [PSCustomObject]@{
                    ProcessName = if ($pn) { $pn.ToLowerInvariant() } else { '' }
                    CommandLine = if ($cmd) { $cmd.Trim() } else { '' }
                }
            })

            $shellCmdEvents = @($procCmdRecords | Where-Object {
                $_.ProcessName -and ($shellExecNames -contains $_.ProcessName) -and -not [string]::IsNullOrWhiteSpace($_.CommandLine)
            })
            $shellCmds = @($shellCmdEvents | ForEach-Object { $_.CommandLine } | Select-Object -Unique)
            $shellCmdsByProc = @($shellCmdEvents | Group-Object ProcessName | Sort-Object Count -Descending | ForEach-Object { "($($_.Count)x) $($_.Name)" })
            $nonPsShellCmds = @($shellCmdEvents | Where-Object { $_.ProcessName -notmatch '^(powershell|pwsh)\.exe$' } | ForEach-Object { $_.CommandLine } | Select-Object -Unique)

            $psCmds  = @($procCmdRecords | Where-Object { $_.ProcessName -match '^(powershell|pwsh)\.exe$' } |
                ForEach-Object { $_.CommandLine } | Where-Object { $_ } | Select-Object -Unique)
            $taskCmds = @($procCmdRecords | Where-Object { $_.ProcessName -eq 'schtasks.exe' } |
                ForEach-Object { $_.CommandLine } | Where-Object { $_ } | Select-Object -Unique)
            Write-Host "       -> $procTotal process events, $($procNameGrps.Count) unique names, $($procHashes.Count) SHA256 hashes" -ForegroundColor DarkGray
            if ($psCmds.Count  -gt 0) { Write-Host "       -> $($psCmds.Count) PowerShell command(s)" -ForegroundColor DarkGray }
            if ($taskCmds.Count -gt 0) { Write-Host "       -> $($taskCmds.Count) schtasks execution(s)" -ForegroundColor DarkGray }
            if ($shellCmds.Count -gt 0) { Write-Host "       -> $($shellCmds.Count) shell/CLI command(s) across $($shellCmdsByProc.Count) executable(s)" -ForegroundColor DarkGray }
            if ($nonPsShellCmds.Count -gt 0) { Write-Host "       -> $($nonPsShellCmds.Count) non-PowerShell shell command(s)" -ForegroundColor DarkGray }

            # Build $ptR mock so the shared process-tree building code (lines below) works
            $ptBuckets = @($procNameGrps | ForEach-Object {
                $grp = $_; $smp = $grp.Group[0]
                [PSCustomObject]@{
                    key       = $grp.Name
                    doc_count = $grp.Count
                    by_parent = [PSCustomObject]@{ buckets = @(
                        $grp.Group | ForEach-Object { $_.process.parent.name } | Where-Object { $_ } | Select-Object -Unique |
                        ForEach-Object { [PSCustomObject]@{ key = "$_"; doc_count = 1 } }
                    ) }
                    by_exe    = [PSCustomObject]@{ buckets = @(
                        [PSCustomObject]@{ key = if ($smp.process.executable) { $smp.process.executable } else { "" }; doc_count = 1 }
                    ) }
                    by_hash   = [PSCustomObject]@{ buckets = @(
                        [PSCustomObject]@{ key = if ($smp.process.hash.sha256) { $smp.process.hash.sha256 } else { "" }; doc_count = 1 }
                    ) }
                    by_cmd    = [PSCustomObject]@{ buckets = @(
                        $grp.Group | ForEach-Object { $_.process.command_line } | Where-Object { $_ } | Select-Object -Unique |
                        Select-Object -First 3 | ForEach-Object { [PSCustomObject]@{ key = "$_"; doc_count = 1 } }
                    ) }
                    by_integrity = [PSCustomObject]@{ buckets = @(
                        $grp.Group | ForEach-Object { $_.process.Ext.token.integrity_level_name } |
                        Where-Object { $_ } | Group-Object | Sort-Object Count -Descending |
                        Select-Object -First 3 | ForEach-Object { [PSCustomObject]@{ key = $_.Name; doc_count = $_.Count } }
                    ) }
                    by_suspended = [PSCustomObject]@{ doc_count = (
                        $grp.Group | Where-Object { $_.process.Ext.created_suspended -eq $true } | Measure-Object
                    ).Count }
                }
            })
            $ptR = [PSCustomObject]@{ aggregations = [PSCustomObject]@{ by_name = [PSCustomObject]@{ buckets = $ptBuckets } } }
            $pR  = New-MockAgg @{ by_name = @($procNameGrps | ForEach-Object { $_.Name }) }

            # --- [3/8] Network ---
            Write-Host "[3/8] Network (offline: network_events.ndjson)..." -ForegroundColor DarkGray
            $netDocs    = Read-Ndjson (Join-Path $DetonationLogsDir "network_events.ndjson")
            $extIPList  = @($netDocs | Where-Object { $_.destination.ip -and $_.destination.ip -notmatch $privateRx } |
                ForEach-Object { $_.destination.ip } | Where-Object { $_ } | Select-Object -Unique)
            $extIPs     = @($netDocs | Where-Object { $_.destination.ip -and $_.destination.ip -notmatch $privateRx } |
                Group-Object { $_.destination.ip } | ForEach-Object { "($($_.Count)x) $($_.Name)" })
            $extPortStr = ($netDocs | ForEach-Object { $_.destination.port } | Where-Object { $_ } |
                Select-Object -Unique | Sort-Object) -join ', '
            $netProcStr = ($netDocs | ForEach-Object { $_.process.name } | Where-Object { $_ } | Select-Object -Unique) -join ', '
            $dnsGroups  = @($netDocs | Where-Object { $_.dns.question.name } | Group-Object { $_.dns.question.name })
            $dnsNames   = @($dnsGroups | ForEach-Object { "($($_.Count)x) $($_.Name)" })
            # Surface suspicious non-Microsoft DNS  -  potential C2 beaconing
            # Whitelisted benign domains include: OS vendors, CDNs, CAs, OCSP, package repos, time services
            $c2DNS = @($dnsGroups | Where-Object {
                $_.Name -notmatch "microsoft|windows|office365|azure|akamai|google|apple|amazon|cloudflare|github|githubusercontent|wns\.windows|windowsupdate|digicert|symantec|live\.com|bing\.com|msftncsi|skype|msecnd|msn\.com|hotmail|msauth|msoidentity|ocsp\.|sectigo\.com|verisign\.com|godaddy\.com|comodo\.com|globalsign\.com|letsencrypt\.org|isrg\.x3\.letsencrypt|crt\.sh|crl\.|pki\.|ntp\.org|time\.nist\.gov|pool\.ntp\.org|chromeupdate|gvt1\.com|gstatic\.com|googleapis\.com|packages\.ubuntu\.com|archive\.ubuntu\.com|deb\.debian\.org|security\.debian\.org|fedoraproject\.org|dl\.fedoraproject\.org|mirror\.centos\.org|yum\.baseurl"
            } | ForEach-Object { $_.Name })
            Write-Host "       -> $($extIPs.Count) external IPs, $($dnsNames.Count) DNS queries" -ForegroundColor DarkGray
            if ($c2DNS.Count -gt 0) {
                $c2Str = $c2DNS -join ' | '
                Write-Host "       -> Suspicious DNS (potential C2): $c2Str" -ForegroundColor Red
            }

            $nR = New-MockAgg @{
                by_ip   = $extIPList
                by_port = @($netDocs | ForEach-Object { $_.destination.port } | Where-Object { $_ } | Select-Object -Unique)
                by_proc = @($netDocs | ForEach-Object { $_.process.name }     | Where-Object { $_ } | Select-Object -Unique)
            }
            $dR = New-MockAgg @{ by_domain = @($dnsGroups | ForEach-Object { $_.Name }) }

            # --- [4/8] Files ---
            Write-Host "[4/8] Files (offline: file_events.ndjson)..." -ForegroundColor DarkGray
            $fileDocs     = Read-Ndjson (Join-Path $DetonationLogsDir "file_events.ndjson")
            $fileNameGrps = @($fileDocs | Where-Object { $_.file.name } | Group-Object { $_.file.name })
            $fileNames    = @($fileNameGrps | ForEach-Object { "($($_.Count)x) $($_.Name)" })
            $fileHashes   = @($fileDocs | ForEach-Object { $_.file.hash.sha256 } |
                Where-Object { $_ -match '^[a-fA-F0-9]{64}$' } | Select-Object -Unique)
            $fileExtStr   = ($fileDocs | ForEach-Object { $_.file.extension } | Where-Object { $_ } | Select-Object -Unique) -join ', '
            $fR = New-MockAgg @{
                by_name = @($fileNameGrps | ForEach-Object { $_.Name })
                by_hash = $fileHashes
                by_ext  = @($fileDocs | ForEach-Object { $_.file.extension } | Where-Object { $_ } | Select-Object -Unique)
            }
            Write-Host "       -> $($fileNames.Count) unique file names, $($fileHashes.Count) SHA256 hashes" -ForegroundColor DarkGray

            # --- [5/8] Registry ---
            Write-Host "[5/8] Registry (offline: registry_events.ndjson)..." -ForegroundColor DarkGray
            $regDocs   = Read-Ndjson (Join-Path $DetonationLogsDir "registry_events.ndjson")
            $regGroups = @($regDocs | Where-Object { $_.registry.key } | Group-Object { $_.registry.key })
            $regKeys   = @($regGroups | ForEach-Object { "($($_.Count)x) $($_.Name)" })
            $rR = New-MockAgg @{ by_key = @($regGroups | ForEach-Object { $_.Name }) }
            Write-Host "       -> $($regKeys.Count) unique registry keys" -ForegroundColor DarkGray

            # --- [6/8] API events ---
            Write-Host "[6/8] API events (offline: api_events.ndjson)..." -ForegroundColor DarkGray
            $apiDocs      = Read-Ndjson (Join-Path $DetonationLogsDir "api_events.ndjson")
            $apiBehaviors = @($apiDocs | ForEach-Object { $_.process.Ext.api.behaviors } | Where-Object { $_ } | Select-Object -Unique)
            $apiNames     = @($apiDocs | ForEach-Object { $_.process.Ext.api.name }      | Where-Object { $_ } | Select-Object -Unique)
            $apiProcs     = @($apiDocs | Where-Object { $_.process.name } | Group-Object { $_.process.name } |
                ForEach-Object { "($($_.Count)x) $($_.Name)" })
            $apiTotal     = ($apiDocs | Measure-Object).Count
            Write-Host "       -> $apiTotal API events, $($apiBehaviors.Count) unique behaviors, $($apiNames.Count) unique calls" -ForegroundColor DarkGray

            # --- [7/8] Image loads ---
            Write-Host "[7/8] Image loads (offline: image_load.ndjson)..." -ForegroundColor DarkGray
            $imgDocs         = Read-Ndjson (Join-Path $DetonationLogsDir "image_load.ndjson")
            $sysmonImages    = @($imgDocs | ForEach-Object { $_.dll.path } | Where-Object { $_ } | Select-Object -Unique)
            $sysmonSrcProcs  = @(); $sysmonTgtProcs  = @(); $sysmonEventIds  = @()
            $sysmonRules     = @(); $sysmonAccess    = @(); $sysmonUnknownCt = 0
            $syRA = $null; $syRB = $null
            $syPairs = [System.Collections.Generic.List[string]]::new()
            Write-Host "       -> $($sysmonImages.Count) unique DLL load paths" -ForegroundColor DarkGray

            # Driver load events (Sysmon EID 6 + Elastic Defend driver category)
            $drvPipeDocs    = Read-Ndjson (Join-Path $DetonationLogsDir "driver_and_pipe.ndjson")
            $driverLoadDocs = @($drvPipeDocs | Where-Object {
                "$($_.winlog.event_id)" -eq '6' -or $_.event.category -eq 'driver'
            })
            Write-Host "       -> $($driverLoadDocs.Count) driver load event(s) (EID 6 / Elastic Defend)" -ForegroundColor DarkGray

            # --- [8/8] Sigma scan: skipped  -  no live Elastic in offline mode ---
            Write-Host "[8/8] Sigma scan: skipped (offline mode)" -ForegroundColor DarkGray
            $sigmaResult = $null
            $script:agentQueryErrors = 0

            Write-Host "[+] Process metadata: $($procDetails.Count) deduplicated record(s) ready for SANS 508 analysis." -ForegroundColor DarkGray

        } else {
        # =====================================================================
        # LIVE ELASTIC MODE (original behavior)
        # =====================================================================
            Write-Host "`n[Elastic Alert Agent] Host forensic mode" -ForegroundColor DarkCyan
            Write-Host "Connects to Elastic and pulls all forensic categories for a host + time window.`n" -ForegroundColor DarkGray

        # Elastic connectivity (same pattern as GetElasticDetonationLogs)
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        if ($PSVersionTable.PSVersion.Major -lt 6) {
            [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        }
        $esRestArgs = if ($PSVersionTable.PSVersion.Major -ge 6) { @{ SkipCertificateCheck = $true } } else { @{} }

        $esUrl  = (Get-Secret -Name 'Elastic_URL'  -AsPlainText -ErrorAction SilentlyContinue).Trim().TrimEnd('/')
        $esUser = (Get-Secret -Name 'Elastic_User' -AsPlainText -ErrorAction SilentlyContinue).Trim()
        $esPass = (Get-Secret -Name 'Elastic_Pass' -AsPlainText -ErrorAction SilentlyContinue).Trim()
        if ([string]::IsNullOrWhiteSpace($esUrl)) { $esUrl = (Read-Host "[?] Elastic URL (e.g. https://192.168.1.10:9200)").TrimEnd('/') }
        if ($esUrl -notmatch '^https?://') { $esUrl = "https://$esUrl" }
        if ($esUrl -match '^http://') {
            $httpsUrl = $esUrl -replace '^http://','https://'
            try { [void](Invoke-RestMethod -Uri "$httpsUrl/_cluster/health" -Headers @{ Authorization="Basic $([Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${esUser}:${esPass}")))" } -Method Get @esRestArgs -ErrorAction Stop); $esUrl = $httpsUrl } catch {}
        }
        $esB64 = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${esUser}:${esPass}"))
        $esHdr = @{ 'Authorization'="Basic $esB64"; 'Content-Type'='application/json' }

        $agentHost = Read-Host "Enter the Endpoint Name"
        if ($agentHost -eq "") { $agentHost = $env:COMPUTERNAME }

        # Timezone-aware time parser  -  handles PDT/EST/CDT/etc. that Get-Date cannot parse
        function ConvertTo-AgentUtc {
            param([string]$Raw, [string]$Label, [datetime]$Fallback)
            $Raw = $Raw.Trim()
            $tzMap = @{
                "EST" = -5; "EDT" = -4
                "CST" = -6; "CDT" = -5
                "MST" = -7; "MDT" = -6
                "PST" = -8; "PDT" = -7
                "UTC" = 0;  "GMT" = 0
            }
            $tzOffset = $null
            foreach ($tz in $tzMap.Keys) {
                if ($Raw -match "\b$tz\b") {
                    $tzOffset = $tzMap[$tz]
                    $Raw = ($Raw -replace "\b$tz\b", "" -replace "\s{2,}", " ").Trim()
                    break
                }
            }
            $parsed = $null
            $formats = @(
                "yyyy-MM-dd HH:mm:ss", "yyyy-MM-dd HH:mm", "yyyy-MM-dd h:mm tt",
                "M/d/yyyy HH:mm:ss",   "M/d/yyyy HH:mm",   "M/d/yyyy h:mm tt",
                "HH:mm:ss", "HH:mm", "h:mm tt", "h tt", "htt"
            )
            foreach ($fmt in $formats) {
                try { $parsed = [datetime]::ParseExact($Raw, $fmt, [System.Globalization.CultureInfo]::InvariantCulture); break } catch {}
            }
            if (-not $parsed) { try { $parsed = [datetime]::Parse($Raw) } catch {} }
            if (-not $parsed) {
                Write-Host "  [!] Could not parse $Label time '$Raw'  -  using fallback." -ForegroundColor Yellow
                return $Fallback.ToUniversalTime()
            }
            # If only a time was parsed (no date), attach today's date
            if ($parsed.Year -eq 1 -or $parsed.Year -eq 1899) {
                $today = Get-Date
                $parsed = [datetime]::new($today.Year, $today.Month, $today.Day, $parsed.Hour, $parsed.Minute, $parsed.Second)
            }
            if ($null -ne $tzOffset) { return $parsed.AddHours(-$tzOffset) }
            else                     { return $parsed.ToUniversalTime() }
        }

        $sStart = Read-Host "Start date/time (e.g. 2026-03-18 08:00 PDT -- blank = yesterday)"
        $sEnd   = Read-Host "End date/time   (e.g. 2026-03-19 20:00 PDT -- blank = now)"
        $dtStart = if ($sStart) { ConvertTo-AgentUtc -Raw $sStart -Label "start" -Fallback (Get-Date).AddDays(-1) } else { (Get-Date).AddDays(-1).ToUniversalTime() }
        $dtEnd   = if ($sEnd)   { ConvertTo-AgentUtc -Raw $sEnd   -Label "end"   -Fallback (Get-Date)             } else { (Get-Date).ToUniversalTime() }
        $fromTs  = $dtStart.ToString("yyyy-MM-ddTHH:mm:ssZ")
        $toTs    = $dtEnd.ToString("yyyy-MM-ddTHH:mm:ssZ")

        Write-Host "`nHost: $agentHost  |  $fromTs --> $toTs" -ForegroundColor DarkCyan

        $script:agentQueryErrors = 0
        function Invoke-AgentESQuery {
            param([string]$Index, [hashtable]$Body, [int]$Size = 0)
            $Body['size'] = $Size
            $uri = "$esUrl/$Index/_search"
            try { return Invoke-RestMethod -Uri $uri -Headers $esHdr -Method Post -Body ($Body | ConvertTo-Json -Depth 20 -Compress) @esRestArgs }
            catch {
                $script:agentQueryErrors++
                $code = $null; try { $code = $_.Exception.Response.StatusCode.value__ } catch {}
                Write-Host "    [!] Query error (HTTP $code): $($_.Exception.Message)" -ForegroundColor DarkRed
                return $null
            }
        }

        $tF = @{ range = @{ "@timestamp" = @{ gte=$fromTs; lte=$toTs } } }
        # Try host.name, agent.name, and host.hostname  - field varies by agent type
        $hF = @{ bool = @{ should = @(
            @{ term = @{ "host.name"     = $agentHost } }
            @{ term = @{ "agent.name"    = $agentHost } }
            @{ term = @{ "host.hostname" = $agentHost } }
        ); minimum_should_match = 1 } }

        Write-Host "[1/8] Alerts..." -ForegroundColor DarkGray
        $aR = Invoke-AgentESQuery -Index ".alerts-security.alerts-default" -Body @{ query=@{ bool=@{ must=@($tF,$hF) } }; aggs=@{ by_rule=@{ terms=@{ field="kibana.alert.rule.name"; size=50 } }; by_tech=@{ terms=@{ field="kibana.alert.rule.threat.technique.id"; size=30 } } }; sort=@(@{"@timestamp"="desc"}) } -Size 100
        $alertHitList  = if ($aR) { $aR.hits.hits } else { @() }
        $alertRules    = if ($aR) { $aR.aggregations.by_rule.buckets | ForEach-Object { "($($_.doc_count)x) $($_.key)" } } else { @() }
        $alertRuleNames = if ($aR) { @($aR.aggregations.by_rule.buckets | ForEach-Object { $_.key }) } else { @() }  # raw names for fidelity lookup
        $alertTechStr  = if ($aR -and $aR.aggregations.by_tech.buckets) { ($aR.aggregations.by_tech.buckets | ForEach-Object { $_.key }) -join ', ' } else { "" }
        Write-Host "       -> $($alertHitList.Count) alert hits, $($alertRules.Count) unique rules" -ForegroundColor DarkGray
        # Extract ML classification hits from live alert docs
        $mlHits = @($alertHitList | Where-Object {
            $_._source.'file.Ext.malware_classification.score' -or
            ($_._source.file -and $_._source.file.Ext -and $_._source.file.Ext.malware_classification -and $_._source.file.Ext.malware_classification.score)
        } | ForEach-Object {
            $src = $_._source
            [PSCustomObject]@{
                'process.name'                          = if ($src.'process.name') { $src.'process.name' } else { $src.process.name }
                'file.Ext.malware_classification.score' = if ($src.'file.Ext.malware_classification.score') { $src.'file.Ext.malware_classification.score' } else { $src.file.Ext.malware_classification.score }
            }
        })

        Write-Host "[2/8] Processes..." -ForegroundColor DarkGray
        # Also try process.pe.original_file_name aggregation and Sysmon hash field
        $pR = Invoke-AgentESQuery -Index "*" -Body @{ query=@{ bool=@{ must=@($tF,$hF); filter=@(@{ bool=@{ should=@(@{ term=@{ "event.category"="process" } },@{ term=@{ "winlog.event_id"=1 } }); minimum_should_match=1 } }) } }; aggs=@{ by_name=@{ terms=@{ field="process.name"; size=100 } }; by_hash=@{ terms=@{ field="process.hash.sha256"; size=300 } }; by_hash2=@{ terms=@{ field="process.pe.imphash"; size=50 } }; by_path=@{ terms=@{ field="process.executable"; size=100 } } } }
        $procNames  = if ($pR) { $pR.aggregations.by_name.buckets | ForEach-Object { "($($_.doc_count)x) $($_.key)" } } else { @() }
        $procHashes = if ($pR) { $pR.aggregations.by_hash.buckets | ForEach-Object { $_.key } | Where-Object { $_ -match '^[a-fA-F0-9]{64}$' } } else { @() }
        $procTotal = if ($pR -and $pR.hits) { $pR.hits.total.value } else { 0 }
        Write-Host "       -> $procTotal process events, $($procNames.Count) unique names, $($procHashes.Count) SHA256 hashes" -ForegroundColor DarkGray

        # Process tree query  -  parent/child aggregation for HTML chain visualization (risk-colored after fidMap is ready)
        $ptR = Invoke-AgentESQuery -Index "*" -Body @{ query=@{ bool=@{ must=@($tF,$hF); filter=@(@{ bool=@{ should=@(@{ term=@{ "event.category"="process" } },@{ term=@{ "winlog.event_id"=1 } }); minimum_should_match=1 } }) } }; aggs=@{ by_name=@{ terms=@{ field="process.name"; size=150; order=@{"_count"="desc"} }; aggs=@{ by_parent=@{ terms=@{ field="process.parent.name"; size=5 } }; by_exe=@{ terms=@{ field="process.executable"; size=1 } }; by_hash=@{ terms=@{ field="process.hash.sha256"; size=1 } }; by_cmd=@{ terms=@{ field="process.command_line"; size=3 } }; by_integrity=@{ terms=@{ field="process.Ext.token.integrity_level_name"; size=3 } }; by_suspended=@{ filter=@{ term=@{ "process.Ext.created_suspended"=$true } } } } } } }

        Write-Host "[3/8] Network..." -ForegroundColor DarkGray
        # Private IP filter done client-side (CIDR term queries require ip-typed ES field, not keyword)
        $privateRx = '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.)'
        $nR = Invoke-AgentESQuery -Index "*" -Body @{ query=@{ bool=@{ must=@($tF,$hF); filter=@(@{ bool=@{ should=@(@{ term=@{ "event.category"="network" } },@{ term=@{ "winlog.event_id"=3 } }); minimum_should_match=1 } }) } }; aggs=@{ by_ip=@{ terms=@{ field="destination.ip"; size=200 } }; by_port=@{ terms=@{ field="destination.port"; size=50 } }; by_proc=@{ terms=@{ field="process.name"; size=50 } } } }
        $extIPs    = if ($nR) { $nR.aggregations.by_ip.buckets | Where-Object { $_.key -notmatch $privateRx } | ForEach-Object { "($($_.doc_count)x) $($_.key)" } } else { @() }
        $extPortStr = if ($nR -and $nR.aggregations.by_port.buckets) { ($nR.aggregations.by_port.buckets | ForEach-Object { $_.key }) -join ', ' } else { "" }
        $netProcStr = if ($nR -and $nR.aggregations.by_proc.buckets) { ($nR.aggregations.by_proc.buckets | ForEach-Object { $_.key }) -join ', ' } else { "" }
        Write-Host "       -> $($extIPs.Count) external IPs" -ForegroundColor DarkGray

        Write-Host "[4/8] DNS..." -ForegroundColor DarkGray
        $dR = Invoke-AgentESQuery -Index "*" -Body @{ query=@{ bool=@{ must=@($tF,$hF); filter=@(@{ bool=@{ should=@(@{ term=@{ "event.category"="dns" } },@{ term=@{ "winlog.event_id"=22 } }); minimum_should_match=1 } }) } }; aggs=@{ by_domain=@{ terms=@{ field="dns.question.name"; size=100 } } } }
        $dnsNames = if ($dR) { $dR.aggregations.by_domain.buckets | ForEach-Object { "($($_.doc_count)x) $($_.key)" } } else { @() }
        Write-Host "       -> $($dnsNames.Count) domains" -ForegroundColor DarkGray

        Write-Host "[5/8] Files..." -ForegroundColor DarkGray
        $fR = Invoke-AgentESQuery -Index "*" -Body @{ query=@{ bool=@{ must=@($tF,$hF); filter=@(@{ bool=@{ should=@(@{ term=@{ "event.category"="file" } },@{ terms=@{ "winlog.event_id"=@(2,11,15) } }); minimum_should_match=1 } }) } }; aggs=@{ by_name=@{ terms=@{ field="file.name"; size=5000 } }; by_ext=@{ terms=@{ field="file.extension"; size=30 } }; by_hash=@{ terms=@{ field="file.hash.sha256"; size=300 } } } }
        $fileNames  = if ($fR) { $fR.aggregations.by_name.buckets | ForEach-Object { "($($_.doc_count)x) $($_.key)" } } else { @() }
        $fileHashes = if ($fR) { $fR.aggregations.by_hash.buckets | ForEach-Object { $_.key } | Where-Object { $_ -match '^[a-fA-F0-9]{64}$' } } else { @() }
        $fileExtStr = if ($fR -and $fR.aggregations.by_ext.buckets) { ($fR.aggregations.by_ext.buckets | ForEach-Object { $_.key }) -join ', ' } else { "" }
        Write-Host "       -> $($fileNames.Count) unique file creations, $($fileHashes.Count) SHA256 hashes" -ForegroundColor DarkGray

        Write-Host "[6/8] Registry..." -ForegroundColor DarkGray
        $rR = Invoke-AgentESQuery -Index "*" -Body @{ query=@{ bool=@{ must=@($tF,$hF); filter=@(@{ bool=@{ should=@(@{ term=@{ "event.category"="registry" } },@{ terms=@{ "winlog.event_id"=@(12,13,14) } }); minimum_should_match=1 } }) } }; aggs=@{ by_key=@{ terms=@{ field="registry.key"; size=10000 } } } }
        $regKeys = if ($rR) { $rR.aggregations.by_key.buckets | ForEach-Object { "($($_.doc_count)x) $($_.key)" } } else { @() }
        Write-Host "       -> $($regKeys.Count) unique registry keys" -ForegroundColor DarkGray

        Write-Host "[7/8] PowerShell..." -ForegroundColor DarkGray
        $psR = Invoke-AgentESQuery -Index "*" -Body @{ query=@{ bool=@{ must=@($tF,$hF); filter=@(@{ bool=@{ should=@(@{ term=@{ "event.category"="process" } },@{ term=@{ "winlog.event_id"=1 } }); minimum_should_match=1 } },@{ bool=@{ should=@(@{ terms=@{ "process.name"=@("powershell.exe","pwsh.exe") } },@{ terms=@{ "winlog.event_data.Image"=@("powershell.exe","pwsh.exe") } }); minimum_should_match=1 } }) } }; aggs=@{ by_cmd=@{ terms=@{ field="process.command_line"; size=50 } } } }
        $psCmds = if ($psR) { $psR.aggregations.by_cmd.buckets | ForEach-Object { $_.key } } else { @() }
        Write-Host "       -> $($psCmds.Count) PowerShell commands" -ForegroundColor DarkGray

        Write-Host "[8/9] Scheduled tasks..." -ForegroundColor DarkGray
        $tR = Invoke-AgentESQuery -Index "*" -Body @{ query=@{ bool=@{ must=@($tF,$hF,@{ term=@{ "event.category"="process" } },@{ term=@{ "process.name"="schtasks.exe" } }) } }; aggs=@{ by_cmd=@{ terms=@{ field="process.command_line"; size=50 } } } }
        $taskCmds = if ($tR) { $tR.aggregations.by_cmd.buckets | ForEach-Object { $_.key } } else { @() }
        Write-Host "       -> $($taskCmds.Count) schtasks executions" -ForegroundColor DarkGray

        Write-Host "[+] Shell/CLI command coverage (cmd + script hosts + launchers)..." -ForegroundColor DarkGray
        $shR = Invoke-AgentESQuery -Index "*" -Body @{
            query=@{
                bool=@{
                    must=@($tF,$hF)
                    filter=@(
                        @{ bool=@{
                            should=@(
                                @{ term=@{ "event.category"="process" } },
                                @{ term=@{ "winlog.event_id"=1 } }
                            )
                            minimum_should_match=1
                        } }
                    )
                }
            }
            _source=@("process.name","process.command_line","process.args","winlog.event_data.Image","winlog.event_data.CommandLine")
            sort=@(@{ "@timestamp"="desc" })
        } -Size 2000
        $shellProcDocs = if ($shR -and $shR.hits -and $shR.hits.hits) { @($shR.hits.hits | ForEach-Object { $_._source }) } else { @() }
        $shellCmdEvents = @($shellProcDocs | ForEach-Object {
            $pn = ''
            if ($_.'process.name') { $pn = [string]$_.'process.name' }
            elseif ($_.process -and $_.process.name) { $pn = [string]$_.process.name }
            elseif ($_.'winlog.event_data.Image') {
                $pn = Split-Path -Leaf ([string]$_.'winlog.event_data.Image')
            }

            $cmd = ''
            if ($_.'process.command_line') { $cmd = [string]$_.'process.command_line' }
            elseif ($_.process -and $_.process.command_line) { $cmd = [string]$_.process.command_line }
            elseif ($_.'winlog.event_data.CommandLine') { $cmd = [string]$_.'winlog.event_data.CommandLine' }
            elseif ($_.winlog -and $_.winlog.event_data -and $_.winlog.event_data.CommandLine) { $cmd = [string]$_.winlog.event_data.CommandLine }
            elseif ($_.process -and $_.process.args) { $cmd = (@($_.process.args) -join ' ') }

            [PSCustomObject]@{
                ProcessName = if ($pn) { $pn.ToLowerInvariant() } else { '' }
                CommandLine = if ($cmd) { $cmd.Trim() } else { '' }
            }
        } | Where-Object { $_.ProcessName -and ($shellExecNames -contains $_.ProcessName) -and -not [string]::IsNullOrWhiteSpace($_.CommandLine) })
        $shellCmds = @($shellCmdEvents | ForEach-Object { $_.CommandLine } | Select-Object -Unique)
        $shellCmdsByProc = @($shellCmdEvents | Group-Object ProcessName | Sort-Object Count -Descending | ForEach-Object { "($($_.Count)x) $($_.Name)" })
        $nonPsShellCmds = @($shellCmdEvents | Where-Object { $_.ProcessName -notmatch '^(powershell|pwsh)\.exe$' } | ForEach-Object { $_.CommandLine } | Select-Object -Unique)
        Write-Host "       -> $($shellCmds.Count) shell/CLI command(s), $($nonPsShellCmds.Count) non-PowerShell" -ForegroundColor DarkGray

        Write-Host "[9/11] Elastic Defend API call telemetry (process.Ext.api)..." -ForegroundColor DarkGray
        $apiR = Invoke-AgentESQuery -Index "*" -Body @{ query=@{ bool=@{ must=@($tF,$hF); filter=@(@{ bool=@{ should=@(@{ term=@{ "event.category"="api" } },@{ term=@{ "event.dataset"="endpoint.events.api" } }); minimum_should_match=1 } }) } }; aggs=@{ by_name=@{ terms=@{ field="process.Ext.api.name"; size=100 } }; by_behavior=@{ terms=@{ field="process.Ext.api.behaviors"; size=50 } }; by_proc=@{ terms=@{ field="process.name"; size=50 } } } }
        $apiBehaviors = if ($apiR) { $apiR.aggregations.by_behavior.buckets | ForEach-Object { $_.key } } else { @() }
        $apiNames     = if ($apiR) { $apiR.aggregations.by_name.buckets     | ForEach-Object { $_.key } } else { @() }
        $apiProcs     = if ($apiR) { $apiR.aggregations.by_proc.buckets     | ForEach-Object { "($($_.doc_count)x) $($_.key)" } } else { @() }
        $apiTotal     = if ($apiR -and $apiR.hits) { $apiR.hits.total.value } else { 0 }
        Write-Host "       -> $apiTotal API events, $($apiBehaviors.Count) unique behaviors, $($apiNames.Count) unique calls" -ForegroundColor DarkGray
        if ($apiBehaviors.Count -gt 0) { Write-Host "       -> Behaviors: $($apiBehaviors -join ', ')" -ForegroundColor $(if ($apiBehaviors -match 'shellcode|inject|hollow|tamper') { 'Red' } else { 'DarkYellow' }) }

        Write-Host "[10/11] Elastic Defend memory/intrusion detections..." -ForegroundColor DarkGray
        $idR = Invoke-AgentESQuery -Index "*" -Body @{ query=@{ bool=@{ must=@($tF,$hF); filter=@(@{ bool=@{ should=@(@{ term=@{ "event.category"="intrusion_detection" } },@{ term=@{ "event.dataset"="endpoint.events.memory" } },@{ term=@{ "event.dataset"="endpoint.events.security" } }); minimum_should_match=1 } }) } }; aggs=@{ by_action=@{ terms=@{ field="event.action"; size=30 } }; by_proc=@{ terms=@{ field="process.name"; size=30 } }; by_rule=@{ terms=@{ field="rule.name"; size=30 } } } }
        $idActions = if ($idR) { $idR.aggregations.by_action.buckets | ForEach-Object { "($($_.doc_count)x) $($_.key)" } } else { @() }
        $idRules   = if ($idR) { $idR.aggregations.by_rule.buckets   | ForEach-Object { $_.key } } else { @() }
        $idTotal   = if ($idR -and $idR.hits) { $idR.hits.total.value } else { 0 }
        Write-Host "       -> $idTotal intrusion detection events: $($idActions -join ', ')" -ForegroundColor $(if ($idTotal -gt 0) { 'Red' } else { 'DarkGray' })

        Write-Host "[11/11] Sysmon API/injection events (ProcessAccess, CreateRemoteThread, ImageLoad)..." -ForegroundColor DarkGray
        # Split into two queries to stay under ES search.max_buckets=10000 per response
        # Query A: EID 8+10 (CreateRemoteThread, ProcessAccess) -- source/target process images
        $syRA = Invoke-AgentESQuery -Index "logs-*,winlogbeat-*" -Body @{
            query=@{ bool=@{ must=@($tF,$hF,@{ terms=@{ "winlog.event_id"=@(8,10) } }) } }
            aggs=@{
                by_eid=@{         terms=@{  field="winlog.event_id";                size=5  } }
                by_rule=@{        terms=@{  field="winlog.event_data.RuleName";      size=50 } }
                by_access=@{      terms=@{  field="winlog.event_data.GrantedAccess"; size=20 } }
                unknown_trace=@{  filter=@{ wildcard=@{ "winlog.event_data.CallTrace"=@{ value="*UNKNOWN(*" } } } }
                by_src=@{ terms=@{ field="winlog.event_data.SourceImage"; size=100 }
                          aggs=@{ tgts=@{ terms=@{ field="winlog.event_data.TargetImage"; size=10 }
                                          aggs=@{
                                              by_access=@{ terms=@{ field="winlog.event_data.GrantedAccess"; size=1 } }
                                              by_rule=@{   terms=@{ field="winlog.event_data.RuleName";      size=1 } }
                                          }
                                  }
                          }
                }
                by_tgt=@{ terms=@{ field="winlog.event_data.TargetImage"; size=4000 } }
            }
        } -Size 0
        # Query B: EID 7 (ImageLoad) -- loaded module paths
        $syRB = Invoke-AgentESQuery -Index "logs-*,winlogbeat-*" -Body @{
            query=@{ bool=@{ must=@($tF,$hF,@{ term=@{ "winlog.event_id"=7 } }) } }
            aggs=@{ by_img=@{ terms=@{ field="winlog.event_data.ImageLoaded"; size=9000 } } }
        } -Size 0
        $eidTotal       = if ($syRA) { ($syRA.aggregations.by_eid.buckets | Measure-Object doc_count -Sum).Sum } else { 0 }
        $imgTotal       = if ($syRB) { ($syRB.aggregations.by_img.buckets | Measure-Object doc_count -Sum).Sum } else { 0 }
        $sysmonTotal    = ([int]$eidTotal + [int]$imgTotal)
        $sysmonSrcProcs = if ($syRA) { @($syRA.aggregations.by_src.buckets | ForEach-Object { $_.key }) } else { @() }
        $sysmonTgtProcs = if ($syRA) { @($syRA.aggregations.by_tgt.buckets | ForEach-Object { $_.key }) } else { @() }
        $sysmonImages   = if ($syRB) { @($syRB.aggregations.by_img.buckets | ForEach-Object { $_.key }) } else { @() }
        $sysmonEventIds = if ($syRA) { @($syRA.aggregations.by_eid.buckets | ForEach-Object { "EID$($_.key)($($_.doc_count))" }) } else { @() }
        $sysmonRules       = if ($syRA) { @($syRA.aggregations.by_rule.buckets   | Where-Object { $_.key } | ForEach-Object { $_.key }) } else { @() }
        $sysmonAccess      = if ($syRA) { @($syRA.aggregations.by_access.buckets | ForEach-Object { "$($_.key) ($($_.doc_count)x)" }) } else { @() }
        $sysmonUnknownCt   = if ($syRA) { [int]$syRA.aggregations.unknown_trace.doc_count } else { 0 }
        Write-Host "       -> $sysmonTotal Sysmon injection/API events: $($sysmonEventIds -join ', ')" -ForegroundColor DarkGray
        if ($sysmonRules.Count  -gt 0) { Write-Host "       -> MITRE rules : $($sysmonRules  | Select-Object -First 5 | ForEach-Object { if ($_ -match 'technique_name=([^,]+)') { $Matches[1] } else { $_ } } | Join-String -Separator ', ')" -ForegroundColor DarkGray }
        if ($sysmonAccess.Count -gt 0) { Write-Host "       -> Access masks: $($sysmonAccess -join ', ')" -ForegroundColor DarkGray }

        # [Sigma] Run translated APT-linked Sigma rules against the same host/timeframe
        $sigmaBaselineRoot = Split-Path $BaselineMainRoot -Parent  # output-baseline, not VirusTotal-main
        $sigmaResult = Invoke-SigmaElasticScan -EsUrl $esUrl -EsHeaders $esHdr `
            -TimeFilter $tF -HostFilter $hF -BaselineRoot $sigmaBaselineRoot

        if ($script:agentQueryErrors -gt 0) {
            Write-Host "`n[!] $($script:agentQueryErrors) Elastic query error(s) above  - check URL, credentials, and index names." -ForegroundColor Red
        }
        if ($alertHitList.Count -eq 0 -and $procNames.Count -eq 0 -and $extIPs.Count -eq 0) {
            Write-Host "`n[!] ALL queries returned 0 results. Likely causes:" -ForegroundColor Yellow
            Write-Host "    1. Host name mismatch  - Elastic may store it as FQDN or different case." -ForegroundColor Yellow
            Write-Host "       Entered: '$agentHost'  - check Kibana Discover with: host.name : *" -ForegroundColor Yellow
            Write-Host "    2. Time window outside event data  - check your start/end times." -ForegroundColor Yellow
            Write-Host "    3. Elastic endpoint agent not sending to these indices." -ForegroundColor Yellow
        }

        # -----------------------------------------------------------------------
        # PROCESS METADATA: signing status, parent-child, command lines
        # -----------------------------------------------------------------------
        Write-Host "[+] Process metadata (signing, parent, command line)..." -ForegroundColor DarkGray
        $pmR = Invoke-AgentESQuery -Index "*" -Body @{
            query = @{ bool = @{ must = @($tF, $hF, @{ term=@{ "event.category"="process" } }, @{ term=@{ "event.type"="start" } }) } }
            _source = @("process.name","process.executable","process.hash.sha256","process.code_signature.trusted","process.code_signature.subject_name","process.parent.name","process.command_line","process.args","user.name","@timestamp")
            sort = @(@{ "@timestamp" = "desc" })
        } -Size 200
        $procDetails = if ($pmR) { $pmR.hits.hits | ForEach-Object { $_._source } } else { @() }
        Write-Host "       -> $($procDetails.Count) process event detail(s)" -ForegroundColor DarkGray

        # Driver load events: Sysmon EID 6 + Elastic Defend driver category
        $drvSysR = Invoke-AgentESQuery -Index "logs-*,winlogbeat-*" -Body @{
            query    = @{ bool = @{ must = @($tF, $hF, @{ term=@{ "winlog.event_id"=6 } }) } }
            _source  = @("winlog.event_data.ImageLoaded","winlog.event_data.Hashes","winlog.event_data.Signed","winlog.event_data.Signature")
        } -Size 500
        $drvEdR  = Invoke-AgentESQuery -Index "*" -Body @{
            query    = @{ bool = @{ must = @($tF, $hF, @{ term=@{ "event.category"="driver" } }) } }
            _source  = @("driver.path","driver.name","driver.code_signature.trusted","driver.code_signature.subject_name")
        } -Size 500
        $driverLoadDocs  = @()
        if ($drvSysR)  { $driverLoadDocs += @($drvSysR.hits.hits  | ForEach-Object { $_._source }) }
        if ($drvEdR)   { $driverLoadDocs += @($drvEdR.hits.hits    | ForEach-Object { $_._source }) }
        Write-Host "       -> $($driverLoadDocs.Count) driver load event(s) (Sysmon EID 6 / Elastic Defend)" -ForegroundColor DarkGray
    } # end live Elastic mode

    # -----------------------------------------------------------------------
    # SANS 508 PROCESS ANALYSIS: masquerading, path, signer, parent anomalies
    # -----------------------------------------------------------------------
        $unsignedProcs   = [System.Collections.Generic.List[string]]::new()
        $suspParentChild = [System.Collections.Generic.List[string]]::new()
        $lolBinsFound    = [System.Collections.Generic.List[string]]::new()
        $lolDriversFound = [System.Collections.Generic.List[string]]::new()
        $pathAnomalies   = [System.Collections.Generic.List[string]]::new()
        $signerAnomalies = [System.Collections.Generic.List[string]]::new()
        $parentAnomalies = [System.Collections.Generic.List[string]]::new()
        $suspPathExec    = [System.Collections.Generic.List[string]]::new()

        $lolBins = @("certutil.exe","regsvr32.exe","rundll32.exe","mshta.exe","wscript.exe","cscript.exe","bitsadmin.exe","installutil.exe","regasm.exe","regsvcs.exe","msiexec.exe","odbcconf.exe","ieexec.exe","msconfig.exe","dnscmd.exe","xwizard.exe","syncappvpublishingserver.exe","appsyncpublishingserver.exe","presentationhost.exe","infdefaultinstall.exe","cmstp.exe","esentutl.exe","expand.exe","extrac32.exe","findstr.exe","hh.exe","makecab.exe","mavinject.exe","microsoft.workflow.compiler.exe","msdeploy.exe","msdt.exe","nltest.exe","pcalua.exe","pcwrun.exe","scriptrunner.exe","sfc.exe","mmc.exe","wmic.exe","forfiles.exe","runscripthelper.exe","aspnet_compiler.exe","bash.exe","at.exe","schtasks.exe")

        # LOLDrivers list: loaded from loldrivers.io cache (Update-LolDriversCache), with
        # hardcoded fallback for the highest-confidence EDR killers.
        # Cache: detections\loldrivers\loldrivers_cache.json  (Update-LolDriversCache writes this)
        $lolDriversFallback = @(
            "rtcore64.sys","rtcore32.sys","gmer.sys","gmer64.sys",
            "procexp.sys","procexp152.sys","mhyprot.sys","mhyprot2.sys","mhyprotect.sys",
            "dbutil_2_3.sys","dbutil.sys","gdrv.sys","iqvw64e.sys",
            "zamguard64.sys","zam64.sys","winring0.sys","winring0x64.sys",
            "iomap64.sys","msio64.sys","msio32.sys","winio64.sys","winio.sys",
            "inpoutx64.sys","kprocesshacker.sys","vboxdrv.sys","ene.sys"
        )
        $lolDriversCachePath = Join-Path $PSScriptRoot "..\detections\loldrivers\loldrivers_cache.json"
        $lolDrivers = $lolDriversFallback
        if (Test-Path $lolDriversCachePath) {
            try {
                $cacheEntries = Get-Content $lolDriversCachePath -Raw | ConvertFrom-Json
                $cacheNames   = @($cacheEntries | ForEach-Object { $_.n } | Where-Object { $_ })
                if ($cacheNames.Count -gt 0) {
                    # Merge cache with fallback; deduplicate
                    $merged = @($lolDriversFallback) + @($cacheNames) | Select-Object -Unique
                    $lolDrivers = $merged
                    Write-Host "       -> LOLDrivers: $($cacheNames.Count) from loldrivers.io cache + $($lolDriversFallback.Count) fallback = $($lolDrivers.Count) total" -ForegroundColor DarkGray
                }
            } catch {
                Write-Host "       -> LOLDrivers cache load failed; using $($lolDriversFallback.Count) hardcoded fallback drivers" -ForegroundColor DarkYellow
            }
        } else {
            Write-Host "       -> LOLDrivers cache not found (run Update-LolDriversCache); using $($lolDriversFallback.Count) hardcoded fallback drivers" -ForegroundColor DarkYellow
        }
        $suspParents = @("winword.exe","excel.exe","powerpnt.exe","outlook.exe","mspub.exe","onenote.exe","msaccess.exe","visio.exe","acrord32.exe","notepad.exe","wordpad.exe","iexplore.exe","chrome.exe","firefox.exe","msedge.exe","opera.exe","safari.exe")
        $suspChildren = @("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","certutil.exe","bitsadmin.exe","regsvr32.exe","rundll32.exe","msiexec.exe","wmic.exe","net.exe","net1.exe","schtasks.exe","at.exe","whoami.exe","ipconfig.exe","nslookup.exe","ping.exe","nltest.exe")

        # Hardcoded parent table for critical Windows processes (SANS 508 Hunt Evil poster)
        # Covers parent checks only - signer/path validation is fully data-driven via process-baseline.json
        $criticalParents = @{
            "lsass.exe"    = @("wininit.exe")
            "services.exe" = @("wininit.exe")
            "wininit.exe"  = @("smss.exe","")
            "winlogon.exe" = @("smss.exe")
            "csrss.exe"    = @("smss.exe")
            "smss.exe"     = @("System","")
            "svchost.exe"  = @("services.exe")
            "spoolsv.exe"  = @("services.exe")
            "userinit.exe" = @("winlogon.exe")
            "dwm.exe"      = @("winlogon.exe")
            "runtimebroker.exe" = @("svchost.exe")
        }

        # Load data-driven process baseline built by Build-VTFidelityIndex
        # Covers ALL process names observed across tens of thousands of VT behavior files
        $procBaselineMap = $null
        $procBaselinePath = Join-Path $PSScriptRoot "..\output-baseline\process-baseline.json"
        if (Test-Path $procBaselinePath) {
            try {
                $procBaselineMap = Get-Content $procBaselinePath -Raw | ConvertFrom-Json
                Write-Host "       -> process baseline loaded ($([Math]::Round((Get-Item $procBaselinePath).Length / 1MB, 1)) MB, data-driven)" -ForegroundColor DarkGray
            } catch {
                Write-Host "       -> process baseline load failed; signer/path checks limited" -ForegroundColor DarkYellow
            }
        } else {
            Write-Host "       -> process-baseline.json not found; run Build-VTFidelityIndex for full coverage" -ForegroundColor DarkYellow
        }

        # Execution from user-writable / staging paths: strong dropper/implant indicator
        $suspExecPaths = @("\Temp\","\tmp\","\Downloads\","\Desktop\","\AppData\Local\Temp\","\AppData\Roaming\","\Public\","\Users\Public\","\`$Recycle.Bin\","\ProgramData\","C:\Intel\","C:\AMD\","\Windows\Temp\")

        foreach ($pd in $procDetails) {
            $pn      = if ($pd.process.name)            { $pd.process.name.ToLower() }            else { "" }
            $exe     = if ($pd.process.executable)      { $pd.process.executable }                else { "" }
            $parent  = if ($pd.process.parent.name)     { $pd.process.parent.name.ToLower() }     else { "" }
            $trusted = $pd.process.code_signature.trusted
            $signer  = if ($pd.process.code_signature.subject_name) { $pd.process.code_signature.subject_name } else { "" }
            $cmd     = if ($pd.process.command_line)    { $pd.process.command_line }               else { ($pd.process.args -join " ") }

            # Unsigned/untrusted binary
            if ($pn -and $trusted -eq $false -and $pn -notin @("conhost.exe","dllhost.exe","taskhost.exe")) {
                [void]$unsignedProcs.Add("$pn (parent: $parent, signer: $(if ($signer) { $signer } else { 'NONE' }))")
            }
            # Suspicious parent -> execution chain (Office/browser spawning shells)
            if ($parent -and ($suspParents -contains $parent) -and ($suspChildren -contains $pn)) {
                [void]$suspParentChild.Add("$parent -> $pn | cmd: $($cmd | Select-Object -First 1)")
            }
            # LOLBin execution
            if ($pn -and $lolBins -contains $pn) {
                $entry = "$pn (parent: $parent)"
                if (-not $lolBinsFound.Contains($entry)) { [void]$lolBinsFound.Add($entry) }
            }

            # --- SANS 508: data-driven process integrity checks (all processes in VT database) ---
            if ($pn) {
                $procEntry = if ($procBaselineMap) { $procBaselineMap.$pn } else { $null }

                if ($procEntry) {
                    # Path masquerading: process running from a directory not seen in known-good baseline
                    if ($exe -and $procEntry.D -and $procEntry.D.Count -gt 0) {
                        $exeDir = [System.IO.Path]::GetDirectoryName($exe).ToLower().TrimEnd('\')
                        # Strip sandbox artifact tokens from each baseline dir entry and collect real Windows paths.
                        # VT sandbox records paths like "%samplepath%c:\windows\system32" or
                        # "%samplepath%c:\users\user\desktop%samplepath%..." - split and discard sandbox tokens.
                        $sandboxOnlyTokens = @('%samplepath%', 'c:\users\user\desktop', 'c:\users\user\appdata\local\temp')
                        $realBaseDirs = [System.Collections.Generic.List[string]]::new()
                        foreach ($kd in $procEntry.D) {
                            foreach ($part in ($kd -split '%samplepath%')) {
                                $p = $part.ToLower().Trim().TrimEnd('\')
                                if ([string]::IsNullOrWhiteSpace($p)) { continue }
                                $isSandbox = $false
                                foreach ($tok in $sandboxOnlyTokens) { if ($p -like "*$tok*") { $isSandbox = $true; break } }
                                if (-not $isSandbox) { [void]$realBaseDirs.Add($p) }
                            }
                        }
                        # If only sandbox-path evidence exists and the exe lives under Program Files,
                        # the VT baseline simply has no real-world install data - suppress the alert.
                        $inProgramFiles = $exeDir -like 'c:\program files*'
                        if ($realBaseDirs.Count -eq 0 -and $inProgramFiles) {
                            # Baseline only knows sandbox paths; legitimate install - skip
                        } else {
                            $pathOk = $false
                            $checkDirs = if ($realBaseDirs.Count -gt 0) { $realBaseDirs } else { @($procEntry.D | ForEach-Object { $_.ToLower().TrimEnd('\') }) }
                            foreach ($kd in $checkDirs) {
                                if ($exeDir -like "$kd*" -or $kd -like "$exeDir*") { $pathOk = $true; break }
                            }
                            if (-not $pathOk) {
                                $sample = ($checkDirs | Select-Object -First 2) -join '; '
                                [void]$pathAnomalies.Add("MASQUERADE: $pn from '$exe' (baseline dirs: $sample)")
                            }
                        }
                    }

                    # Signer anomaly: signed by unexpected entity, or unsigned when baseline shows signed
                    if ($procEntry.S -and $procEntry.S.Count -gt 0) {
                        $signerOk = $false
                        foreach ($ks in $procEntry.S) {
                            if ($signer -and ($signer -like "*$ks*" -or $ks -like "*$signer*")) { $signerOk = $true; break }
                        }
                        if (-not $signerOk -and $signer) {
                            [void]$signerAnomalies.Add("SIGNER MISMATCH: $pn signed by '$signer' (baseline: '$($procEntry.S[0])')")
                        } elseif (-not $signerOk -and $trusted -eq $false) {
                            [void]$signerAnomalies.Add("SIGNER MISMATCH: $pn UNSIGNED but baseline shows signed by '$($procEntry.S[0])'")
                        }
                    }
                }

                # Wrong parent for critical system processes (hardcoded - process_tree not in VT behaviors)
                if ($criticalParents.ContainsKey($pn) -and $parent -and $criticalParents[$pn] -notcontains $parent) {
                    [void]$parentAnomalies.Add("WRONG PARENT: $pn spawned by '$parent' (expected: $($criticalParents[$pn] -join ' or '))")
                }
            }

            # Suspicious execution path (any process, not just known ones)
            if ($exe) {
                foreach ($sp in $suspExecPaths) {
                    if ($exe -like "*$sp*") {
                        [void]$suspPathExec.Add("$pn from '$exe'")
                        break
                    }
                }
            }
        }

        # LOL Driver check: scan driver load events against known vulnerable driver list (BYOVD)
        if ($driverLoadDocs.Count -gt 0) {
            foreach ($dld in $driverLoadDocs) {
                $drvPath = if ($dld.'winlog.event_data.ImageLoaded') { $dld.'winlog.event_data.ImageLoaded' }
                           elseif ($dld.driver.path)                  { $dld.driver.path }
                           else { '' }
                if (-not $drvPath) { continue }
                $drvName = [System.IO.Path]::GetFileName($drvPath).ToLower()
                if ($lolDrivers -contains $drvName) {
                    $signed = if ($dld.'winlog.event_data.Signed' -ne $null) { $dld.'winlog.event_data.Signed' }
                              elseif ($dld.driver.code_signature.trusted -ne $null) { $dld.driver.code_signature.trusted }
                              else { 'unknown' }
                    $signer = if ($dld.'winlog.event_data.Signature') { " [$($dld.'winlog.event_data.Signature')]" }
                              elseif ($dld.driver.code_signature.subject_name) { " [$($dld.driver.code_signature.subject_name)]" }
                              else { '' }
                    $entry = "$drvName | signed:$signed$signer"
                    if (-not $lolDriversFound.Contains($drvName)) { [void]$lolDriversFound.Add($entry) }
                }
            }
        }

        if ($pathAnomalies.Count -gt 0)   { Write-Host "       -> $($pathAnomalies.Count) PATH MASQUERADE anomaly(ies)" -ForegroundColor Red }
        if ($signerAnomalies.Count -gt 0) { Write-Host "       -> $($signerAnomalies.Count) SIGNER anomaly(ies) on system process(es)" -ForegroundColor Red }
        if ($parentAnomalies.Count -gt 0) { Write-Host "       -> $($parentAnomalies.Count) PARENT anomaly(ies) on critical process(es)" -ForegroundColor Yellow }
        if ($suspPathExec.Count -gt 0)    { Write-Host "       -> $($suspPathExec.Count) execution(s) from suspicious path(s)" -ForegroundColor Yellow }
        if ($unsignedProcs.Count -gt 0)   { Write-Host "       -> $($unsignedProcs.Count) unsigned/untrusted process(es)" -ForegroundColor Yellow }
        if ($suspParentChild.Count -gt 0) { Write-Host "       -> $($suspParentChild.Count) suspicious parent-child chain(s)" -ForegroundColor Red }
        if ($lolBinsFound.Count -gt 0)    { Write-Host "       -> $($lolBinsFound.Count) LOLBin execution(s)" -ForegroundColor Yellow }
        if ($lolDriversFound.Count -gt 0) { Write-Host "       -> $($lolDriversFound.Count) LOL Driver(s) loaded - BYOVD risk [T1068]" -ForegroundColor Red }

        # -----------------------------------------------------------------------
        # BATCH FIDELITY SCAN: all forensic artifacts against VT behavior files
        # -----------------------------------------------------------------------
        $artifactIPList     = @($nR?.aggregations.by_ip.buckets     | ForEach-Object { $_.key })
        $artifactDomainList = @($dR?.aggregations.by_domain.buckets | ForEach-Object { $_.key })
        $artifactProcList   = @($pR?.aggregations.by_name.buckets   | ForEach-Object { $_.key })
        $artifactFileList   = @($fR?.aggregations.by_name.buckets   | ForEach-Object { $_.key })
        $artifactRegList    = @($rR?.aggregations.by_key.buckets    | ForEach-Object { ($_.key -split '\\')[-1] })  # leaf key only
        # Alert rule names (Sigma/YARA) - checked against fidelity index built from VT sigma_analysis_results
        # and APT TargetedSigma/YaraDifferentialAnalysis.json files
        $artifactRuleList   = $alertRuleNames

        # Sysmon EID 7: DLL basenames loaded by the process
        $artifactDllList = @($sysmonImages |
            ForEach-Object { [System.IO.Path]::GetFileName($_).ToLower() } |
            Where-Object { $_ -match '\.dll$' -and $_.Length -gt 4 })
        # Sysmon EID 8/10: injection target process basenames
        $artifactInjList = @(($sysmonTgtProcs + $sysmonSrcProcs) |
            ForEach-Object { [System.IO.Path]::GetFileName($_).ToLower() } |
            Where-Object { $_ -and $_.Length -gt 3 } | Select-Object -Unique)

        $allArtifacts = ($artifactIPList + $artifactDomainList + $artifactProcList + $artifactFileList + $artifactRegList + $artifactRuleList + $artifactDllList + $artifactInjList) |
            Where-Object { $_ -and $_.Length -gt 3 } | Select-Object -Unique

        Write-Host "`n[+] Batch fidelity scan: $($allArtifacts.Count) unique artifacts across VT offline baseline..." -ForegroundColor DarkCyan
        $fidMap = Invoke-BatchFidelityScan -Indicators $allArtifacts

        # Summarize direct artifact fidelity hits
        $directUnique = @($fidMap.Keys | Where-Object { $fidMap[$_].Unique })
        $directRare   = @($fidMap.Keys | Where-Object { $fidMap[$_].Rare })
        Write-Host "    Direct artifact fidelity: UNIQUE=$($directUnique.Count)  RARE=$($directRare.Count)" -ForegroundColor $(if ($directUnique.Count -gt 0) { "Red" } elseif ($directRare.Count -gt 0) { "Yellow" } else { "Cyan" })

        # Per-process artifact summary: file / network / registry / alert counts
        Write-Host "[+] Per-process artifact breakdown..." -ForegroundColor DarkGray
        $perProcArt = @{}

        if ($offlineMode) {
            # ---- Offline: compute $perProcArt from in-memory NDJSON doc arrays ----

            # Files per process
            $fileDocs | Where-Object { $_.process.name } | Group-Object { $_.process.name } | ForEach-Object {
                $pn = $_.Name
                if (-not $perProcArt[$pn]) { $perProcArt[$pn] = @{} }
                $perProcArt[$pn].files    = $_.Count
                $perProcArt[$pn].topFiles = @($_.Group | ForEach-Object { $_.file.name } | Where-Object { $_ } | Select-Object -Unique -First 5)
                $mlScores  = @($_.Group | ForEach-Object { $_.file.Ext.malware_classification.score } | Where-Object { $_ })
                $entScores = @($_.Group | ForEach-Object { $_.file.Ext.entropy }                      | Where-Object { $_ -gt 0 })
                $perProcArt[$pn].maxMlScore = if ($mlScores.Count  -gt 0) { [Math]::Round(($mlScores  | Measure-Object -Maximum).Maximum * 100, 1) } else { $null }
                $perProcArt[$pn].maxEntropy = if ($entScores.Count -gt 0) { [Math]::Round(($entScores | Measure-Object -Maximum).Maximum, 2)      } else { $null }
            }

            # Network per process
            $netDocs | Where-Object { $_.process.name } | Group-Object { $_.process.name } | ForEach-Object {
                $pn = $_.Name
                if (-not $perProcArt[$pn]) { $perProcArt[$pn] = @{} }
                $perProcArt[$pn].net    = $_.Count
                $perProcArt[$pn].topIPs = @($_.Group | ForEach-Object { $_.destination.ip }     | Where-Object { $_ } | Select-Object -Unique -First 5)
                $perProcArt[$pn].topDNS = @($_.Group | ForEach-Object { $_.destination.domain } | Where-Object { $_ } | Select-Object -Unique -First 5)
            }

            # Registry per process
            $regDocs | Where-Object { $_.process.name } | Group-Object { $_.process.name } | ForEach-Object {
                $pn = $_.Name
                if (-not $perProcArt[$pn]) { $perProcArt[$pn] = @{} }
                $perProcArt[$pn].reg     = $_.Count
                $perProcArt[$pn].topKeys = @($_.Group | ForEach-Object { $_.registry.key } | Where-Object { $_ } | Select-Object -Unique -First 8)
            }

            # Alerts per process
            $alertDocs | Where-Object { $_.process.name } | Group-Object { $_.process.name } | ForEach-Object {
                $pn = $_.Name
                if (-not $perProcArt[$pn]) { $perProcArt[$pn] = @{} }
                $perProcArt[$pn].alerts      = $_.Count
                $perProcArt[$pn].topSeverity = @($_.Group | ForEach-Object { $_.'kibana.alert.severity' } |
                    Where-Object { $_ } | Group-Object | Sort-Object Count -Descending |
                    Select-Object -First 4 | ForEach-Object { "($($_.Count)x) $($_.Name)" })
                $riskVals = @($_.Group | ForEach-Object { $_.'kibana.alert.risk_score' } | Where-Object { $_ })
                $perProcArt[$pn].maxRisk = if ($riskVals.Count -gt 0) { [int]($riskVals | Measure-Object -Maximum).Maximum } else { 0 }
            }

            # DLL / image-load events per process (image_load.ndjson)
            $imgDocs | Where-Object { $_.process.name } | Group-Object { $_.process.name } | ForEach-Object {
                $pn = $_.Name
                if (-not $perProcArt[$pn]) { $perProcArt[$pn] = @{} }
                $perProcArt[$pn].dll = $_.Count
                $rawPaths = @($_.Group | ForEach-Object { if ($_.dll.path) { $_.dll.path } elseif ($_.file.path) { $_.file.path } } | Where-Object { $_ } | Select-Object -Unique -First 8)
                $perProcArt[$pn].topDlls = @($rawPaths | ForEach-Object { if ($_ -match '[/\\]([^/\\]+)$') { $Matches[1] } else { $_ } })
                # defense_evasions is an array field - flatten explicitly
                $dllEvas = [System.Collections.Generic.List[string]]::new()
                foreach ($d in $_.Group) { foreach ($ev in @($d.dll.Ext.defense_evasions)) { if ($ev -and $ev -is [string]) { $dllEvas.Add($ev) } } }
                $perProcArt[$pn].topDllEvasions = @($dllEvas | Select-Object -Unique | Select-Object -First 5)
            }

            # API events per process (api_events.ndjson)
            # process.Ext.api may be a single object OR an array; behaviors is always an array.
            # Use explicit loops to flatten correctly rather than member-access enumeration.
            $apiDocs | Where-Object { $_.process.name } | Group-Object { $_.process.name } | ForEach-Object {
                $pn = $_.Name
                if (-not $perProcArt[$pn]) { $perProcArt[$pn] = @{} }
                $perProcArt[$pn].api = $_.Count

                $allApiNames  = [System.Collections.Generic.List[string]]::new()
                $allBehaviors = [System.Collections.Generic.List[string]]::new()
                $allSummaries = [System.Collections.Generic.List[string]]::new()
                $allTargets   = [System.Collections.Generic.List[string]]::new()
                $allMemProt   = [System.Collections.Generic.List[string]]::new()
                $allMemPaths  = [System.Collections.Generic.List[string]]::new()

                foreach ($doc in $_.Group) {
                    # Handle api as object or array of objects
                    $apiObjs = @($doc.process.Ext.api)
                    foreach ($a in $apiObjs) {
                        if (-not $a) { continue }
                        if ($a.name    -and $a.name    -is [string]) { $allApiNames.Add($a.name) }
                        if ($a.summary -and $a.summary -is [string]) { $allSummaries.Add($a.summary) }
                        foreach ($beh in @($a.behaviors)) { if ($beh -and $beh -is [string]) { $allBehaviors.Add($beh) } }
                    }
                    if ($doc.Target.process.name                   -is [string]) { $allTargets.Add($doc.Target.process.name) }
                    if ($doc.process.Ext.memory_region.protection  -is [string]) { $allMemProt.Add($doc.process.Ext.memory_region.protection) }
                    if ($doc.process.Ext.memory_region.mapped_path -is [string]) { $allMemPaths.Add($doc.process.Ext.memory_region.mapped_path) }
                }

                # If api.name was absent, extract function name from summary (e.g. "WriteProcessMemory(...)")
                if ($allApiNames.Count -eq 0) {
                    foreach ($s in $allSummaries) {
                        if ($s -match '^(\w+)\(') { $allApiNames.Add($Matches[1]) }
                    }
                }

                $perProcArt[$pn].topApis      = @($allApiNames  | Select-Object -Unique | Select-Object -First 5)
                $perProcArt[$pn].topBehaviors = @($allBehaviors | Select-Object -Unique | Select-Object -First 5)
                $perProcArt[$pn].topSummaries = @($allSummaries | Select-Object -Unique | Select-Object -First 5)
                $perProcArt[$pn].topTargets   = @($allTargets   | Select-Object -Unique | Select-Object -First 5)
                $perProcArt[$pn].topMemProt   = @($allMemProt   | Select-Object -Unique | Select-Object -First 5)
                $perProcArt[$pn].topMemPaths  = @($allMemPaths  | Select-Object -Unique | Select-Object -First 3)
            }

            Write-Host "       -> Offline perProcArt: $($perProcArt.Count) processes with artifact data" -ForegroundColor DarkGray

            # ---- IOC/YARA Scanner: SKIPPED in offline mode ----
            # Thor/Loki scan PE binaries for YARA signature matches. In offline mode
            # the detonation directory contains only NDJSON telemetry logs (JSON text),
            # not the original PE/DLL artifacts from the sandbox. Every PE-header YARA
            # rule (uint16(0)==0x5A4D) is guaranteed to miss, producing a misleading
            # "clean scan". The scanner is only useful in live mode or when pointed at
            # actual sample files.
            Write-Host "[+] IOC/YARA scanner: skipped (offline mode  -  NDJSON logs are not PE artifacts)" -ForegroundColor DarkGray
            # ---- Run deep behavioral analysis engine ----
            Write-Host "[+] Offline deep behavioral analysis..." -ForegroundColor DarkGray
            $deepAnalysis = Get-OfflineDeepAnalysis `
                -ProcDocs  $procDocs  -ApiDocs   $apiDocs   -AlertDocs $alertDocs `
                -FileDocs  $fileDocs  -NetDocs   $netDocs   -RegDocs   $regDocs   `
                -ImgDocs   $imgDocs   -LokiResult $lokiResult
            Write-Host "       -> $($deepAnalysis.FindingCount) findings ($($deepAnalysis.CriticalCount) CRITICAL, $($deepAnalysis.HighCount) HIGH)" -ForegroundColor $(if ($deepAnalysis.CriticalCount -gt 0) { 'Red' } else { 'DarkGray' })

        } else {

        $fpR = Invoke-AgentESQuery -Index "*" -Body @{
            query = @{ bool = @{ must = @($tF,$hF,@{ term=@{ "event.category"="file" } }) } }
            aggs  = @{ by_proc = @{ terms = @{ field="process.name"; size=100 }
                        aggs = @{ top_files   = @{ terms = @{ field="file.name"; size=5 } }
                                  max_ml      = @{ max   = @{ field="file.Ext.malware_classification.score" } }
                                  max_entropy = @{ max   = @{ field="file.Ext.entropy" } } } } }
            size = 0 }
        if ($fpR) { foreach ($b in $fpR.aggregations.by_proc.buckets) {
            if (-not $perProcArt[$b.key]) { $perProcArt[$b.key] = @{} }
            $perProcArt[$b.key].files    = $b.doc_count
            $perProcArt[$b.key].topFiles = @($b.top_files.buckets | ForEach-Object { $_.key } | Select-Object -First 5)
            $mlVal  = $b.max_ml.value;      $perProcArt[$b.key].maxMlScore  = if ($mlVal)       { [Math]::Round($mlVal * 100, 1) }  else { $null }
            $entVal = $b.max_entropy.value; $perProcArt[$b.key].maxEntropy  = if ($entVal -gt 0) { [Math]::Round($entVal, 2) }       else { $null }
        }}

        $npR = Invoke-AgentESQuery -Index "*" -Body @{
            query = @{ bool = @{ must = @($tF,$hF,@{ term=@{ "event.category"="network" } }) } }
            aggs  = @{ by_proc = @{ terms = @{ field="process.name"; size=100 }
                        aggs = @{ top_ips  = @{ terms = @{ field="destination.ip";     size=5 } }
                                  top_dns  = @{ terms = @{ field="destination.domain"; size=5 } } } } }
            size = 0 }
        if ($npR) { foreach ($b in $npR.aggregations.by_proc.buckets) {
            if (-not $perProcArt[$b.key]) { $perProcArt[$b.key] = @{} }
            $perProcArt[$b.key].net  = $b.doc_count
            $perProcArt[$b.key].topIPs  = @($b.top_ips.buckets  | ForEach-Object { $_.key } | Select-Object -First 5)
            $perProcArt[$b.key].topDNS  = @($b.top_dns.buckets  | ForEach-Object { $_.key } | Select-Object -First 5)
        }}

        $rpR = Invoke-AgentESQuery -Index "*" -Body @{
            query = @{ bool = @{ must = @($tF,$hF,@{ term=@{ "event.category"="registry" } }) } }
            aggs  = @{ by_proc = @{ terms = @{ field="process.name"; size=100 }
                        aggs = @{ top_keys = @{ terms = @{ field="registry.key"; size=8 } } } } }
            size = 0 }
        if ($rpR) { foreach ($b in $rpR.aggregations.by_proc.buckets) {
            if (-not $perProcArt[$b.key]) { $perProcArt[$b.key] = @{} }
            $perProcArt[$b.key].reg     = $b.doc_count
            $perProcArt[$b.key].topKeys = @($b.top_keys.buckets | ForEach-Object { $_.key } | Select-Object -First 8)
        }}

        $apR = Invoke-AgentESQuery -Index ".alerts-security.alerts-default" -Body @{
            query = @{ bool = @{ must = @($tF,$hF) } }
            aggs  = @{ by_proc = @{ terms = @{ field="process.name"; size=100 }
                        aggs = @{ top_severity = @{ terms = @{ field="kibana.alert.severity";  size=5 } }
                                  max_risk     = @{ max   = @{ field="kibana.alert.risk_score" } } } } }
            size = 0 }
        if ($apR) { foreach ($b in $apR.aggregations.by_proc.buckets) {
            if (-not $perProcArt[$b.key]) { $perProcArt[$b.key] = @{} }
            $perProcArt[$b.key].alerts      = $b.doc_count
            $perProcArt[$b.key].topSeverity = @($b.top_severity.buckets | ForEach-Object { "($($_.doc_count)x) $($_.key)" } | Select-Object -First 4)
            $riskVal = $b.max_risk.value;   $perProcArt[$b.key].maxRisk = if ($riskVal) { [int]$riskVal } else { 0 }
        }}

        # DLL / library load events per process
        # Elastic Defend: event.category=library, dll.path (full path)
        # Sysmon EID 7: winlog.event_data.ImageLoaded (fallback)
        $dlR = Invoke-AgentESQuery -Index "*" -Body @{
            query = @{ bool = @{ must = @($tF,$hF); filter = @(@{ bool = @{ should = @(
                @{ term = @{ "event.category" = "library" } }
                @{ term = @{ "winlog.event_id" = 7 } }
            ); minimum_should_match = 1 } }) } }
            aggs  = @{ by_proc = @{ terms = @{ field="process.name"; size=100 }
                        aggs = @{ top_dlls         = @{ terms = @{ field="dll.path";                     size=8 } }
                                  top_dlls_sysmon   = @{ terms = @{ field="winlog.event_data.ImageLoaded"; size=8 } }
                                  top_evasions      = @{ terms = @{ field="dll.Ext.defense_evasions";      size=5 } } } } }
            size = 0 }
        if ($dlR) { foreach ($b in $dlR.aggregations.by_proc.buckets) {
            if (-not $perProcArt[$b.key]) { $perProcArt[$b.key] = @{} }
            $perProcArt[$b.key].dll = $b.doc_count
            # Merge Elastic Defend (dll.path) and Sysmon (ImageLoaded) results; extract filename from path
            $dllPaths = @(
                @($b.top_dlls.buckets        | ForEach-Object { $_.key })
                @($b.top_dlls_sysmon.buckets | ForEach-Object { $_.key })
            ) | Select-Object -Unique | Select-Object -First 8
            $perProcArt[$b.key].topDlls    = @($dllPaths | ForEach-Object {
                if ($_ -match '[/\\]([^/\\]+)$') { $Matches[1] } else { $_ }
            })
            $perProcArt[$b.key].topDllEvasions = @($b.top_evasions.buckets | ForEach-Object { $_.key } | Select-Object -First 5)
        }}

        # API / intrusion-detection events per process (Elastic Defend process.Ext.api.*)
        # These appear in endpoint.alerts dataset with process.Ext.api.name present.
        # Also covers endpoint.events.api if present as a separate telemetry stream.
        # API / intrusion-detection events per process (Elastic Defend process.Ext.api.*)
        # endpoint.alerts behavioral detections carry process.Ext.api.name (e.g. WriteProcessMemory)
        # and process.Ext.api.summary (e.g. "WriteProcessMemory( Self, ntdll.dll!NtProtectVirtualMemory, 0x5 )")
        # NOTE: injection_events (Sysmon EID 8/10) cover cross-process injection only.
        #       Self-patching/NTDLL-unhooking appears here via Elastic Defend API monitoring, not Sysmon.
        $aaR = Invoke-AgentESQuery -Index "*" -Body @{
            query = @{ bool = @{ must = @($tF,$hF); filter = @(
                @{ bool = @{ should = @(
                    @{ term   = @{ "event.category"    = "api" } }
                    @{ term   = @{ "event.dataset"     = "endpoint.events.api" } }
                    @{ exists = @{ field               = "process.Ext.api.name" } }
                ); minimum_should_match = 1 } }
            ) } }
            aggs  = @{ by_proc = @{ terms = @{ field="process.name"; size=100 }
                        aggs = @{ top_apis      = @{ terms = @{ field="process.Ext.api.name";                          size=5 } }
                                  top_behaviors = @{ terms = @{ field="process.Ext.api.behaviors";                    size=5 } }
                                  top_summaries = @{ terms = @{ field="process.Ext.api.summary";                      size=5 } }
                                  top_targets   = @{ terms = @{ field="process.Ext.api.metadata.target_address_name"; size=5 } }
                                  top_mem_prot  = @{ terms = @{ field="process.Ext.memory_region.allocation_protection"; size=5 } }
                                  top_mem_paths = @{ terms = @{ field="process.Ext.memory_region.mapped_path";        size=3 } } } } }
            size = 0 }
        if ($aaR) { foreach ($b in $aaR.aggregations.by_proc.buckets) {
            if (-not $perProcArt[$b.key]) { $perProcArt[$b.key] = @{} }
            $perProcArt[$b.key].api          = $b.doc_count
            $perProcArt[$b.key].topApis      = @($b.top_apis.buckets      | ForEach-Object { $_.key } | Select-Object -First 5)
            $perProcArt[$b.key].topBehaviors = @($b.top_behaviors.buckets | ForEach-Object { $_.key } | Select-Object -First 5)
            $perProcArt[$b.key].topSummaries = @($b.top_summaries.buckets | ForEach-Object { $_.key } | Select-Object -First 5)
            $perProcArt[$b.key].topTargets   = @($b.top_targets.buckets   | ForEach-Object { $_.key } | Select-Object -First 5)
            $perProcArt[$b.key].topMemProt   = @($b.top_mem_prot.buckets  | ForEach-Object { $_.key } | Select-Object -First 5)
            $perProcArt[$b.key].topMemPaths  = @($b.top_mem_paths.buckets | ForEach-Object { $_.key } | Select-Object -First 3)
        }}

        } # end if ($offlineMode) { ... } else { ... }

        # Build process tree nodes with fidelity risk coloring (fidMap now available)
        $ptNodes = [System.Collections.Generic.List[hashtable]]::new()
        if ($ptR -and $ptR.aggregations.by_name.buckets) {
            foreach ($b in $ptR.aggregations.by_name.buckets) {
                $pn = $b.key; $pnl = $pn.ToLower()
                $prisk = "clean"
                if ($fidMap -and $fidMap.ContainsKey($pnl)) {
                    $pfe = $fidMap[$pnl]
                    if ($pfe.Unique) { $prisk = "unique" } elseif ($pfe.Rare) { $prisk = "rare" }
                }
                if ($prisk -eq "clean" -and ($unsignedProcs | Where-Object { $_ -match [regex]::Escape($pn) })) { $prisk = "suspicious" }
                $pa    = if ($perProcArt.ContainsKey($pn)) { $perProcArt[$pn] } else { @{} }
                $integ = if ($b.by_integrity.buckets.Count -gt 0) { $b.by_integrity.buckets[0].key } else { "" }
                $susp  = if ($b.by_suspended.doc_count -gt 0)     { $true }                          else { $false }
                $ptNodes.Add(@{
                    n        = $pn
                    c        = $b.doc_count
                    r        = $prisk
                    p        = @($b.by_parent.buckets | ForEach-Object { $_.key })
                    e        = if ($b.by_exe.buckets.Count -gt 0) { $b.by_exe.buckets[0].key } else { "" }
                    h        = if ($b.by_hash.buckets.Count -gt 0) { $b.by_hash.buckets[0].key } else { "" }
                    cmds     = @($b.by_cmd.buckets | ForEach-Object { $_.key } | Select-Object -First 3)
                    integ    = $integ
                    susp     = $susp
                    alerts       = if ($pa.alerts)       { [int]$pa.alerts }       else { 0 }
                    maxRisk      = if ($pa.maxRisk)      { [int]$pa.maxRisk }      else { 0 }
                    topSeverity  = if ($pa.topSeverity)  { @($pa.topSeverity) }    else { @() }
                    files        = if ($pa.files)        { [int]$pa.files }        else { 0 }
                    maxMlScore   = if ($pa.maxMlScore)   { $pa.maxMlScore }        else { $null }
                    maxEntropy   = if ($pa.maxEntropy)   { $pa.maxEntropy }        else { $null }
                    net          = if ($pa.net)          { [int]$pa.net }          else { 0 }
                    reg          = if ($pa.reg)          { [int]$pa.reg }          else { 0 }
                    topKeys      = if ($pa.topKeys)      { @($pa.topKeys) }        else { @() }
                    dll          = if ($pa.dll)          { [int]$pa.dll }          else { 0 }
                    topDllEvasions = if ($pa.topDllEvasions) { @($pa.topDllEvasions) } else { @() }
                    api          = if ($pa.api)          { [int]$pa.api }          else { 0 }
                    topFiles     = if ($pa.topFiles)     { @($pa.topFiles) }       else { @() }
                    topIPs       = if ($pa.topIPs)       { @($pa.topIPs) }         else { @() }
                    topDNS       = if ($pa.topDNS)       { @($pa.topDNS) }         else { @() }
                    topDlls      = if ($pa.topDlls)      { @($pa.topDlls) }        else { @() }
                    topApis      = if ($pa.topApis)      { @($pa.topApis) }        else { @() }
                    topBehaviors = if ($pa.topBehaviors) { @($pa.topBehaviors) }   else { @() }
                    topSummaries = if ($pa.topSummaries) { @($pa.topSummaries) }   else { @() }
                    topTargets   = if ($pa.topTargets)   { @($pa.topTargets) }     else { @() }
                    topMemProt   = if ($pa.topMemProt)   { @($pa.topMemProt) }     else { @() }
                    topMemPaths  = if ($pa.topMemPaths)  { @($pa.topMemPaths) }    else { @() }
                })
            }
        }

        # Sigma / YARA rule fidelity: which fired alert rules are malware-unique or rare in the baseline
        $ruleUnique = @($artifactRuleList | Where-Object { $fidMap.ContainsKey($_) -and $fidMap[$_].Unique })
        $ruleRare   = @($artifactRuleList | Where-Object { $fidMap.ContainsKey($_) -and $fidMap[$_].Rare })
        if ($ruleUnique.Count -gt 0) {
            Write-Host "    [!!] SIGMA/YARA rules UNIQUE to malware fired: $($ruleUnique -join ' | ')" -ForegroundColor Red
        }
        if ($ruleRare.Count -gt 0) {
            Write-Host "    [!]  SIGMA/YARA rules RARE in good baseline fired: $($ruleRare -join ' | ')" -ForegroundColor Yellow
        }

        # Sysmon EID 7: DLLs loaded that score high in VT malware baseline
        $dllUnique = @($artifactDllList | Where-Object { $fidMap.ContainsKey($_) -and $fidMap[$_].Unique })
        $dllRare   = @($artifactDllList | Where-Object { $fidMap.ContainsKey($_) -and $fidMap[$_].Rare })
        if ($dllUnique.Count -gt 0) {
            Write-Host "    [!!] DLLs loaded UNIQUE to malware (EID 7): $($dllUnique -join ' | ')" -ForegroundColor Red
        }
        if ($dllRare.Count -gt 0) {
            Write-Host "    [!]  DLLs loaded RARE in good baseline (EID 7): $($dllRare -join ' | ')" -ForegroundColor Yellow
        }

        # Sysmon EID 8/10: injection targets that score high
        $injUnique = @($artifactInjList | Where-Object { $fidMap.ContainsKey($_) -and $fidMap[$_].Unique })
        $injRare   = @($artifactInjList | Where-Object { $fidMap.ContainsKey($_) -and $fidMap[$_].Rare })
        # Build src/tgt name sets for role annotation
        $sysmonSrcNames = @($sysmonSrcProcs | ForEach-Object { [System.IO.Path]::GetFileName($_).ToLower() } | Select-Object -Unique)
        $sysmonTgtNames = @($sysmonTgtProcs | ForEach-Object { [System.IO.Path]::GetFileName($_).ToLower() } | Select-Object -Unique)
        if ($injUnique.Count -gt 0) {
            Write-Host "    [!!] Sysmon EID 8/10 -- processes UNIQUE TO MALWARE in injection events:" -ForegroundColor Red
            foreach ($inj in $injUnique) {
                $isSrc = $sysmonSrcNames -contains $inj
                $isTgt = $sysmonTgtNames -contains $inj
                $role  = if ($isSrc -and $isTgt) { "INJECTOR + VICTIM" } elseif ($isSrc) { "INJECTOR (source)" } else { "VICTIM (target)" }
                $malC  = if ($fidMap[$inj]) { "$($fidMap[$inj].MalCount) malware samples" } else { "" }
                $detail = (@($role, $malC) | Where-Object { $_ }) -join ' | '
                Write-Host "          $inj  -- $detail" -ForegroundColor Red
            }
        }
        if ($injRare.Count -gt 0) {
            Write-Host "    [!]  Sysmon EID 8/10 -- processes RARE in good baseline in injection events:" -ForegroundColor Yellow
            foreach ($inj in $injRare) {
                $isSrc = $sysmonSrcNames -contains $inj
                $isTgt = $sysmonTgtNames -contains $inj
                $role  = if ($isSrc -and $isTgt) { "INJECTOR + VICTIM" } elseif ($isSrc) { "INJECTOR (source)" } else { "VICTIM (target)" }
                $malC  = if ($fidMap[$inj]) { "$($fidMap[$inj].MalCount) malware samples | $($fidMap[$inj].Found) legit" } else { "" }
                $detail = (@($role, $malC) | Where-Object { $_ }) -join ' | '
                Write-Host "          $inj  -- $detail" -ForegroundColor Yellow
            }
        }

        # Build src→tgt pair strings for the HTML report panel
        $syPairs = [System.Collections.Generic.List[string]]::new()
        if ($syRA) {
            $injUniqueSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            $injRareSet   = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            $injUnique | ForEach-Object { [void]$injUniqueSet.Add($_) }
            $injRare   | ForEach-Object { [void]$injRareSet.Add($_) }
            foreach ($srcBkt in $syRA.aggregations.by_src.buckets) {
                $srcBase = [System.IO.Path]::GetFileName($srcBkt.key).ToLower()
                $srcName = [System.IO.Path]::GetFileName($srcBkt.key)
                foreach ($tgtBkt in $srcBkt.tgts.buckets) {
                    $tgtBase = [System.IO.Path]::GetFileName($tgtBkt.key).ToLower()
                    $tgtName = [System.IO.Path]::GetFileName($tgtBkt.key)
                    $tag = if ($injUniqueSet.Contains($srcBase) -or $injUniqueSet.Contains($tgtBase)) { "[UNIQUE] " }
                           elseif ($injRareSet.Contains($srcBase) -or $injRareSet.Contains($tgtBase)) { "[RARE] " }
                           else { "" }
                    $topAccess = if ($tgtBkt.by_access.buckets.Count -gt 0) { " | $($tgtBkt.by_access.buckets[0].key)" } else { "" }
                    $topRule   = ""
                    if ($tgtBkt.by_rule.buckets.Count -gt 0) {
                        $rn = $tgtBkt.by_rule.buckets[0].key
                        $topRule = if ($rn -match "technique_name=([^,]+)") { " | $($Matches[1])" } elseif ($rn) { " | $rn" } else { "" }
                    }
                    $syPairs.Add("${tag}${srcName} -> ${tgtName} ($($tgtBkt.doc_count)x)${topAccess}${topRule}")
                }
            }
        }

        # -----------------------------------------------------------------------
        # Collect hashes from alert hits  - try multiple ECS / winlogbeat / Sysmon field paths
        $alertSourceHashes = $alertHitList | ForEach-Object {
            $s = $_._source
            $h = $s.process.hash.sha256                                      # ECS nested
            if (-not $h) { $h = $s.hash.sha256 }                            # flat hash obj
            if (-not $h) {
                $raw = $s.winlog.event_data.Hashes                           # Sysmon "SHA256=..."
                if ($raw -match 'SHA256=([a-fA-F0-9]{64})') { $h = $Matches[1] }
            }
            if (-not $h -and $_._source.PSObject.Properties['process.hash.sha256']) {
                $h = $_._source.'process.hash.sha256'                        # flat-mapped _source
            }
            $h
        } | Where-Object { $_ -match '^[a-fA-F0-9]{64}$' }

        $alertHashSet = ($alertSourceHashes + $procHashes + $fileHashes) | Select-Object -Unique | Where-Object { $_ -match '^[a-fA-F0-9]{64}$' }

        # Build host indicator sets for cross-reference (raw values, no count prefix)
        $hostIPSet     = @($nR?.aggregations.by_ip.buckets     | ForEach-Object { $_.key })
        $hostDomainSet = @($dR?.aggregations.by_domain.buckets | ForEach-Object { $_.key })
        $hostProcSet   = @($pR?.aggregations.by_name.buckets   | ForEach-Object { $_.key })
        $hostFileSet   = @($fR?.aggregations.by_name.buckets   | ForEach-Object { $_.key })
        $hostRegSet    = @($rR?.aggregations.by_key.buckets    | ForEach-Object { $_.key })
        $hostMitreSet  = @($alertTechStr -split ',\s*' | Where-Object { $_ -match '^T\d' } | ForEach-Object { ($_ -split '\.')[0] })  # T1055 not sub-technique

        # Single-pass VT enrichment + behavioral cross-reference
        Write-Host "`n[Elastic Alert Agent] Enriching $($alertHashSet.Count) hashes + behavioral cross-reference..." -ForegroundColor DarkCyan
        Write-Host "  VT baseline path: $BaselineMainRoot" -ForegroundColor DarkGray
        $vtEnrichment  = [System.Text.StringBuilder]::new()
        $behaviorOverlap = [System.Text.StringBuilder]::new()
        # Per-indicator overlap counters for proportional scoring
        $oc = @{ IP=0; Domain=0; Process=0; File=0; Registry=0; MITRE=0; Name=0 }
        # Fidelity band counters  - parallel to the API matrix rarity bands
        $uniqueMatches = [System.Collections.Generic.List[string]]::new()  # Score 100: zero legit presence
        $rareMatches   = [System.Collections.Generic.List[string]]::new()  # Score 95:  1-3 legit appearances

        $vtUnknownHashes = [System.Collections.Generic.List[string]]::new()
        $vtCache = @{}
        foreach ($h in $alertHashSet) {
            $vtRes = Find-VTHashBaseline -Hash $h
            $vtCache[$h] = $vtRes
            $isMal = $vtRes -and $vtRes.Category -eq 'malicious'

            # --- Enrichment text ---
            $block = Format-HashEnrichment -Hash $h -Label $h.Substring(0,12)
            if ($block -match 'NOT IN OFFLINE') {
                [void]$vtUnknownHashes.Add($h)
            } else {
                $cat = if ($isMal) { 'MALICIOUS' } else { [regex]::Match($block,'Category\s*:\s*(\S+)').Groups[1].Value }
                Write-Host "  $($h.Substring(0,12))...: $cat" -ForegroundColor $(if ($isMal) { 'Red' } else { 'Green' })
                [void]$vtEnrichment.AppendLine($block)
            }

            # --- Behavioral cross-reference (only for hashes found in baseline) ---
            if (-not $vtRes) { continue }
            $beh  = Get-VTBehaviorSummary -Path $vtRes.BehaviorFile
            $main = Get-VTMainSummary     -Path $vtRes.MainFile
            $hits = [System.Collections.Generic.List[string]]::new()

            # 1. Known malware file names (VT main .names) vs host processes and files
            if ($main -and $main.Names) {
                foreach ($n in ($main.Names -split ',\s*' | Where-Object { $_.Trim() })) {
                    $fn = $n.Trim()
                    if ($hostProcSet | Where-Object { $_ -ieq $fn }) {
                        [void]$hits.Add("[Name-Match] Process '$fn' matches known malware filename in VT")
                        $oc.Name++
                    }
                    if ($hostFileSet | Where-Object { $_ -ieq $fn }) {
                        [void]$hits.Add("[Name-Match] File '$fn' matches known malware filename in VT")
                        $oc.Name++
                    }
                }
            }

            # Helper: annotate one indicator hit with its fidelity band
            # Uses pre-computed $fidMap from batch scan; falls back to per-indicator scan
            function Add-FidelityHit {
                param([string]$Label, [string]$Value, [string]$TypeKey)
                $fid = if ($fidMap.ContainsKey($Value)) { $fidMap[$Value] }
                       else { Get-IndicatorFidelity -Indicator $Value }
                if ($fid.Unique) {
                    $tag = "[UNIQUE] $Label $Value -- UNIQUE TO MALWARE (0 legit appearances in known-good baseline)"
                    [void]$uniqueMatches.Add("$Label $Value")
                } elseif ($fid.Rare) {
                    $legit = if ($fid.LegitUses.Count -gt 0) { " | Legitimate uses: $($fid.LegitUses -join ', ')" } else { "" }
                    $tag = "[RARE-95] $Label $Value -- RARE ($($fid.Found) legit appearance(s))$legit"
                    [void]$rareMatches.Add("$Label $Value")
                } else {
                    $legit = if ($fid.LegitUses.Count -gt 0) { " | Common in: $($fid.LegitUses -join ', ')" } else { "" }
                    $tag = "[COMMON] $Label $Value (score $($fid.Score))$legit"
                }
                [void]$hits.Add($tag)
                $oc[$TypeKey]++
            }

            if ($beh) {
                # 2. Network C2 IP overlaps
                foreach ($conn in $beh.NetworkConns) {
                    $ip = ($conn -split ':')[0]
                    if ($ip -and $hostIPSet -contains $ip) { Add-FidelityHit -Label "C2-IP:" -Value $ip -TypeKey "IP" }
                }
                # 3. DNS domain overlaps
                foreach ($domain in $beh.DNSLookups) {
                    if ($domain -and ($hostDomainSet | Where-Object { $_ -like "*$domain*" -or $domain -like "*$_*" })) {
                        Add-FidelityHit -Label "DNS:" -Value $domain -TypeKey "Domain"
                    }
                }
                # 4. Spawned process name overlaps
                foreach ($proc in $beh.ProcessesCreated) {
                    $pn = if ($proc -match '[/\\]([^/\\]+)$') { $Matches[1] } else { $proc }
                    if ($pn -and ($hostProcSet | Where-Object { $_ -ieq $pn })) {
                        Add-FidelityHit -Label "Process:" -Value $pn -TypeKey "Process"
                    }
                }
                # 5. Written file name overlaps
                foreach ($f2 in $beh.FilesWritten) {
                    $fn = if ($f2 -match '[/\\]([^/\\]+)$') { $Matches[1] } else { $f2 }
                    if ($fn -and ($hostFileSet | Where-Object { $_ -ieq $fn })) {
                        Add-FidelityHit -Label "File:" -Value $fn -TypeKey "File"
                    }
                }
                # 6. Registry key overlaps (last key component match)
                foreach ($reg in $beh.RegistryKeys) {
                    $leaf = ($reg -split '\\')[-1]
                    if ($leaf -and ($hostRegSet | Where-Object { $_ -like "*$leaf*" })) {
                        Add-FidelityHit -Label "Registry:" -Value $leaf -TypeKey "Registry"
                    }
                }
                # 7. MITRE technique overlaps
                foreach ($tech in $beh.MitreAttack) {
                    $tid = ($tech -split '[\. ]')[0]
                    if ($tid -and $hostMitreSet -contains $tid) {
                        Add-FidelityHit -Label "MITRE:" -Value $tech -TypeKey "MITRE"
                    }
                }
            }

            if ($hits.Count -gt 0) {
                $hasUnique   = @($hits | Where-Object { $_ -match '^\[UNIQUE\]' })
                $hasRare     = @($hits | Where-Object { $_ -match '^\[RARE' })
                $bandSummary = if ($hasUnique.Count -gt 0) { ' *** UNIQUE-TO-MALWARE HITS ***' } elseif ($hasRare.Count -gt 0) { ' [RARE indicators]' } else { '' }
                [void]$behaviorOverlap.AppendLine("  $($h.Substring(0,12))... [$($vtRes.Category)] - $($hits.Count) overlap(s)$bandSummary")
                $hits | ForEach-Object {
                    $lineColor = if ($_ -match '^\[UNIQUE\]') { 'Red' } elseif ($_ -match '^\[RARE') { 'Yellow' } else { 'DarkGray' }
                    [void]$behaviorOverlap.AppendLine("    $_")
                    Write-Host "    $_" -ForegroundColor $lineColor
                }
            }
        }

        # Threat attribution from IPs, domains, alert rule names
        Write-Host "[Elastic Alert Agent] Running threat attribution..." -ForegroundColor DarkCyan
        # Attribution observations ordered by pyramid of pain (TTPs first, hashes last)
        $attrObs = [System.Collections.Generic.List[string]]::new()
        # Tier 1 - TTPs: MITRE technique IDs and behavioral detections (hardest to change)
        if ($alertTechStr) { foreach ($x in ($alertTechStr -split ',\s*' | Where-Object { $_ })) { [void]$attrObs.Add($x.Trim()) } }
        foreach ($x in $apiBehaviors) { [void]$attrObs.Add($x) }
        foreach ($x in $apiNames)     { [void]$attrObs.Add($x) }
        foreach ($x in $idRules)      { [void]$attrObs.Add($x) }
        # Tier 2 - Tools/artifacts: alert rule names, intrusion detection actions
        foreach ($x in $alertRules)   { [void]$attrObs.Add(($x -replace '^\(\d+x\) ','')) }
        foreach ($x in $idActions)    { [void]$attrObs.Add(($x -replace '^\(\d+x\) ','')) }
        # Tier 3 - Network indicators
        foreach ($x in ($nR?.aggregations.by_ip.buckets     | ForEach-Object { $_.key })) { [void]$attrObs.Add($x) }
        foreach ($x in ($dR?.aggregations.by_domain.buckets | ForEach-Object { $_.key })) { [void]$attrObs.Add($x) }
        # Tier 4 - Process hashes only (file hashes excluded from attribution  -  too numerous, bottom of pyramid)
        foreach ($x in $procHashes)  { [void]$attrObs.Add($x) }

        $attributionText = "THREAT ATTRIBUTION: Insufficient indicators."
        $topActors = @()
        if ($attrObs.Count -gt 0) {
            try {
                $attrResults = Get-ThreatAttribution -Observations $attrObs.ToArray() -PassThru -MinRarityScore 90 -ErrorAction Stop
                $tier1 = @($attrResults | Where-Object { $_.MatchCount -gt 1 } | Sort-Object MatchCount -Descending | Select-Object -First 5)
                if ($tier1.Count -gt 0) {
                    $topActors = @($tier1 | ForEach-Object { $_.Actor } | Select-Object -Unique)
                    $sb2 = [System.Text.StringBuilder]::new()
                    [void]$sb2.AppendLine("THREAT ATTRIBUTION (MinRarityScore=90, multi-indicator matches):")
                    foreach ($r2 in $tier1) {
                        [void]$sb2.AppendLine("  [$($r2.Type)] $($r2.Actor) -- $($r2.MatchCount) match(es):")
                        foreach ($m in $r2.Matches) { [void]$sb2.AppendLine("    - [$($m.Source)] $($m.Indicator)") }
                    }
                    $attributionText = $sb2.ToString()
                    Write-Host "  Attribution: $($tier1.Count) Tier-1 match(es)" -ForegroundColor Yellow
                } else {
                    $attributionText = "THREAT ATTRIBUTION: No high-confidence multi-indicator matches."
                }
            } catch { $attributionText = "THREAT ATTRIBUTION: Unavailable." }
        }

        # -----------------------------------------------------------------------
        # DIRECT HASH ATTRIBUTION  -  cross-reference observed hashes against
        # all *_Master_Intel.csv files in the apt folder.  This provides the
        # highest-confidence attribution signal (direct sample match).
        # -----------------------------------------------------------------------
        $aptRoot = Join-Path $PSScriptRoot "..\apt"
        if (Test-Path $aptRoot) {
            $hashActorMap = @{}  # SHA256 → @(actor, context, source)
            $masterCsvs = Get-ChildItem -Path $aptRoot -Filter "*_Master_Intel.csv" -Recurse -ErrorAction SilentlyContinue
            foreach ($csv in $masterCsvs) {
                try {
                    $rows = Import-Csv $csv.FullName -ErrorAction Stop
                    foreach ($row in $rows) {
                        $iocType = ($row.IOCType -replace '"','').Trim()
                        $iocVal  = ($row.IOCValue -replace '"','').Trim().ToLower()
                        if ($iocType -match '^SHA256$' -and $iocVal -match '^[0-9a-f]{64}$') {
                            if (-not $hashActorMap.ContainsKey($iocVal)) {
                                $actorName = ($row.Actor -replace '"','').Trim()
                                if (-not $actorName) { $actorName = $csv.Directory.Name }
                                $context = ($row.Context -replace '"','').Trim()
                                $hashActorMap[$iocVal] = @{ Actor=$actorName; Context=$context; Source=$csv.Directory.Name }
                            }
                        }
                    }
                } catch {}
            }

            # Pass 2 -- dated IOC CSVs: SHA256 rows (IOC,Type,Sources,Max confidence,Last Seen,Detection count)
            $hashRegionFolders = @('Russia','China','NorthKorea','Iran','eCrime','Vietnam','SouthAmerica','Picus','APTs','Malware Families')
            $hashIocFiles = @(Get-ChildItem -Path $aptRoot -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -eq '.csv' -and $_.Name -match '\d{4}-\d{2}-\d{2}' -and
                               $_.Name -notmatch '_Master_Intel' -and $_.Name -notmatch 'Targeted_Analysis_Map' })
            foreach ($hif in $hashIocFiles) {
                try {
                    $hifParent = Split-Path (Split-Path $hif.FullName -Parent) -Leaf
                    $hifActor = if ($hashRegionFolders -notcontains $hifParent) {
                        $hifParent
                    } else {
                        ($hif.BaseName -replace '(?i)_IOCs?$','' -replace '(?i)_\d{4}-\d{2}-\d{2}.*$','' `
                                       -replace '(?i)_deduplicated$','' -replace '_',' ').Trim()
                    }
                    $hifRows = Import-Csv $hif.FullName -Encoding UTF8 -ErrorAction SilentlyContinue
                    foreach ($hifRow in $hifRows) {
                        $hifType = if ($hifRow.Type) { $hifRow.Type.Trim() } else { '' }
                        if ($hifType -notmatch '(?i)^SHA256$|^hash$') { continue }
                        $hifVal = if ($hifRow.IOC) { $hifRow.IOC.Trim().ToLower() } else { '' }
                        if ($hifVal -notmatch '^[0-9a-f]{64}$') { continue }
                        if (-not $hashActorMap.ContainsKey($hifVal)) {
                            $hashActorMap[$hifVal] = @{
                                Actor   = $hifActor
                                Context = "Confidence:$($hifRow.'Max confidence')"
                                Source  = $hif.Name
                            }
                        }
                    }
                } catch {}
            }

            # Pass 3 -- Targeted_Analysis_Map.csv: SHA256 hashes (3M+ entries, fast regex reader)
            $tamFiles2 = @(Get-ChildItem -Path $aptRoot -Recurse -Filter 'Targeted_Analysis_Map.csv' -ErrorAction SilentlyContinue)
            foreach ($tamFile2 in $tamFiles2) {
                try {
                    $tamActorFolder = Split-Path (Split-Path $tamFile2.FullName -Parent) -Leaf
                    $rawLines2 = [System.IO.File]::ReadAllLines($tamFile2.FullName, [System.Text.Encoding]::UTF8)
                    foreach ($rawLine2 in $rawLines2) {
                        if ($rawLine2.Length -lt 66) { continue }
                        if ($rawLine2 -notmatch '"([a-fA-F0-9]{64})"') { continue }
                        $hash2 = $Matches[1].ToLower()
                        if ($hashActorMap.ContainsKey($hash2)) { continue }
                        $actor3 = $tamActorFolder
                        $ctx4   = ''
                        if ($rawLine2 -match '"[^"]*","[^"]*","[a-fA-F0-9]{64}","([^"]*?)","([^"]*?)"') {
                            $mf2 = $Matches[1]; $mn2 = $Matches[2]
                            if ($mf2 -and $mf2 -ne 'Unknown') { $actor3 = $mf2 }
                            $ctx4 = $mn2
                        }
                        $hashActorMap[$hash2] = @{ Actor=$actor3; Context=$ctx4; Source='Targeted_Analysis_Map' }
                    }
                } catch {}
            }

            if ($hashActorMap.Count -gt 0) {
                # Check all observed hashes (process tree + alert hashes)
                $allObsHashes = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                foreach ($h in $alertHashSet)  { [void]$allObsHashes.Add($h.ToLower()) }
                foreach ($h in $procHashes)    { [void]$allObsHashes.Add($h.ToLower()) }

                $hashHits = @{}  # Actor → list of matched hashes
                foreach ($h in $allObsHashes) {
                    if ($hashActorMap.ContainsKey($h)) {
                        $actor = $hashActorMap[$h].Actor
                        if (-not $hashHits.ContainsKey($actor)) { $hashHits[$actor] = [System.Collections.Generic.List[string]]::new() }
                        $ctx = $hashActorMap[$h].Context
                        $ctxStr = if ($ctx) { " ($ctx)" } else { "" }
                        $hashHits[$actor].Add("$h$ctxStr")
                    }
                }

                if ($hashHits.Count -gt 0) {
                    $sb3 = [System.Text.StringBuilder]::new()
                    [void]$sb3.AppendLine("DIRECT HASH ATTRIBUTION (highest confidence  -  sample database match):")
                    foreach ($actor in ($hashHits.Keys | Sort-Object { -$hashHits[$_].Count })) {
                        [void]$sb3.AppendLine("  [HASH-MATCH] $actor -- $($hashHits[$actor].Count) sample(s) matched:")
                        foreach ($hLine in ($hashHits[$actor] | Select-Object -First 5)) {
                            [void]$sb3.AppendLine("    - $hLine")
                        }
                    }
                    # Prepend hash attribution (it's the most definitive signal)
                    if ($attributionText -match "Insufficient indicators|No high-confidence|Unavailable") {
                        $attributionText = $sb3.ToString()
                    } else {
                        $attributionText = $sb3.ToString() + "`n" + $attributionText
                    }
                    # Merge hash-match actors into topActors (for badge display)
                    $hashActors = @($hashHits.Keys)
                    $topActors  = @(@($hashActors) + @($topActors) | Select-Object -Unique | Select-Object -First 5)
                    Write-Host "  Direct hash attribution: $($hashHits.Count) actor(s) matched via sample database" -ForegroundColor Green
                }
            }
        }

        # -------------------------------------------------------------------
        # OFFLINE VERDICT ENGINE  - rule-based per-indicator scoring
        # -------------------------------------------------------------------
        $score     = 0
        $findings  = [System.Collections.Generic.List[string]]::new()
        $nextSteps = [System.Collections.Generic.List[string]]::new()

        # Known-malicious hashes: 15 pts each, no cap (every sample counts)
        $malHashes = @($alertHashSet | Where-Object { $vtCache[$_] -and $vtCache[$_].Category -eq 'malicious' })
        if ($malHashes.Count -gt 0) {
            $malScore = $malHashes.Count * 15
            $score += $malScore
            $findings.Add("CRITICAL: $($malHashes.Count) confirmed-malicious hash(es) in VT offline baseline (+$malScore pts)")
            $nextSteps.Add("Isolate host immediately  - confirmed malware hash(es) present")
        }
        # Retroactively upgrade process tree risk for confirmed-malicious hashes
        $malHashSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($mh in $malHashes) { [void]$malHashSet.Add($mh) }
        # Build per-process alert counts from alertHitList
        $procAlertCounts = @{}
        foreach ($hit in $alertHitList) {
            $pn = if ($hit._source) { "$($hit._source.process.name)" } else { "" }
            if ($pn -and $pn -ne '') {
                if ($procAlertCounts.ContainsKey($pn)) { $procAlertCounts[$pn]++ } else { $procAlertCounts[$pn] = 1 }
            }
        }
        foreach ($pt in $ptNodes) {
            if ($pt.r -eq 'clean' -and $pt.h -and $malHashSet.Contains($pt.h)) { $pt.r = 'unique' }
            $pt['alerts'] = if ($procAlertCounts.ContainsKey($pt.n)) { $procAlertCounts[$pt.n] } else { 0 }
        }

        # Unclassified hashes with alerts
        $unknownHashes = @($alertHashSet | Where-Object { -not $vtCache[$_] })
        if ($unknownHashes.Count -gt 0 -and $alertHitList.Count -gt 0) {
            $score += 10
            $findings.Add("$($unknownHashes.Count) hash(es) not in VT offline baseline  - unclassified binaries")
        }

        # Security alert count: 2 pts each, cap 30
        if ($alertHitList.Count -gt 0) {
            $aScore = [Math]::Min(30, $alertHitList.Count * 2)
            $score += $aScore
            $findings.Add("$($alertHitList.Count) security alert(s) fired: $(($alertRules | Select-Object -First 3) -join ' | ')")
            $nextSteps.Add("Review triggered alert rules in Kibana Security for triage context")
        }

        # -----------------------------------------------------------------------
        # DIRECT ARTIFACT FIDELITY (from batch scan - all IPs, domains, procs, files)
        # -----------------------------------------------------------------------
        # Unique-to-malware artifacts seen directly on the host (not via hash lookup)
        if ($directUnique.Count -gt 0 -and $score -lt 100) {
            $score = 100
            $top3 = $directUnique | Select-Object -First 3
            $findings.Add("CRITICAL: $($directUnique.Count) artifact(s) UNIQUE TO MALWARE observed directly on host: $($top3 -join '; ')")
            $nextSteps.Add("Direct unique-to-malware artifacts observed  - host is almost certainly compromised")
        }
        if ($directRare.Count -gt 0 -and $score -lt 100) {
            $rareDirectBonus = [Math]::Min(50, $directRare.Count * 15)
            $score += $rareDirectBonus
            $rareList = $directRare | Select-Object -First 3 | ForEach-Object {
                $legit = if ($fidMap[$_].LegitNames.Count -gt 0) { " (legit: $($fidMap[$_].LegitNames -join ','))" } else { "" }
                "$_$legit"
            }
            $findings.Add("$($directRare.Count) RARE artifact(s) observed on host (fidelity ~95): $($rareList -join '; ')")
            $nextSteps.Add("Review RARE artifacts  - confirm whether listed legitimate software justifies this activity")
        }

        # Sigma / YARA rule fidelity findings (informational - scoring already captured above via direct artifacts)
        if ($ruleUnique.Count -gt 0) {
            $findings.Add("SIGMA/YARA: $($ruleUnique.Count) alert rule(s) UNIQUE TO MALWARE fired: $($ruleUnique -join ' | ')")
            $nextSteps.Add("Triggered Sigma/YARA rules confirmed unique to malware  - cross-reference with APT differential analysis for threat actor attribution")
        }
        if ($ruleRare.Count -gt 0) {
            $ruleRareStr = $ruleRare | Select-Object -First 5 | ForEach-Object {
                $malC = if ($fidMap[$_]) { $fidMap[$_].MalCount } else { "?" }
                "$_ ($malC malware samples)"
            }
            $findings.Add("SIGMA/YARA: $($ruleRare.Count) alert rule(s) RARE in good baseline fired: $($ruleRareStr -join ' | ')")
        }

        # -----------------------------------------------------------------------
        # PROCESS METADATA SCORING (SANS 508 methodology)
        # -----------------------------------------------------------------------
        # Path masquerading: system process from wrong directory (e.g. lsass.exe from %TEMP%)
        if ($pathAnomalies.Count -gt 0) {
            $paScore = [Math]::Min(100, $pathAnomalies.Count * 40)
            $score   = [Math]::Min(100, $score + $paScore)
            $findings.Add("CRITICAL: $($pathAnomalies.Count) process masquerading anomaly(ies) (+$paScore pts): $($pathAnomalies -join ' | ')")
            $nextSteps.Add("Process masquerading confirmed  - system binary running from unexpected path is a primary IoC; isolate host")
        }
        # Wrong or missing signer on a critical Windows process
        if ($signerAnomalies.Count -gt 0) {
            $saScore = [Math]::Min(60, $signerAnomalies.Count * 30)
            $score  += $saScore
            $findings.Add("CRITICAL: $($signerAnomalies.Count) signer anomaly(ies) on critical system process(es) (+$saScore pts): $($signerAnomalies -join ' | ')")
            $nextSteps.Add("Verify signing on flagged processes  - legitimate Windows system binaries must be signed by Microsoft Windows Publisher")
        }
        # Wrong parent for a critical system process (possible process injection/hollowing)
        if ($parentAnomalies.Count -gt 0) {
            $parentScore = [Math]::Min(40, $parentAnomalies.Count * 20)
            $score      += $parentScore
            $findings.Add("$($parentAnomalies.Count) parent anomaly(ies) on critical process(es) (+$parentScore pts): $($parentAnomalies -join ' | ')")
            $nextSteps.Add("Investigate unexpected parent processes  - may indicate process injection, hollowing, or living-off-the-land pivoting")
        }
        # Execution from user-writable/staging directories (dropper behavior)
        if ($suspPathExec.Count -gt 0) {
            $spScore = [Math]::Min(30, $suspPathExec.Count * 10)
            $score  += $spScore
            $findings.Add("$($suspPathExec.Count) execution(s) from suspicious path(s) (+$spScore pts): $(($suspPathExec | Select-Object -First 5) -join '; ')")
            $nextSteps.Add("Investigate processes run from Temp/Downloads/AppData paths  - common dropper staging behavior")
        }
        if ($unsignedProcs.Count -gt 0) {
            $unScore = [Math]::Min(25, $unsignedProcs.Count * 8)
            $score  += $unScore
            $findings.Add("$($unsignedProcs.Count) unsigned/untrusted process(es) executed (+$unScore pts): $(($unsignedProcs | Select-Object -First 3) -join '; ')")
            $nextSteps.Add("Investigate unsigned binaries  - check if they are expected in this environment")
        }
        if ($suspParentChild.Count -gt 0) {
            $pcScore = [Math]::Min(30, $suspParentChild.Count * 15)
            $score  += $pcScore
            $findings.Add("SUSPICIOUS parent-child chain(s) (+$pcScore pts): $(($suspParentChild | Select-Object -First 3) -join ' | ')")
            $nextSteps.Add("Investigate Office/browser spawning shells  - strong initial access/macro indicator")
        }
        if ($lolBinsFound.Count -gt 0) {
            $lolScore = [Math]::Min(20, $lolBinsFound.Count * 5)
            $score   += $lolScore
            $findings.Add("LOLBin execution(s) observed (+$lolScore pts): $(($lolBinsFound | Select-Object -First 5) -join ', ')")
            $nextSteps.Add("Review LOLBin usage for defense evasion / living-off-the-land attack patterns")
        }
        if ($lolDriversFound.Count -gt 0) {
            $drvScore = [Math]::Min(40, $lolDriversFound.Count * 40)
            $score   += $drvScore
            $findings.Add("LOL DRIVER(S) loaded - BYOVD attack technique (+$drvScore pts): $(($lolDriversFound | Select-Object -First 5) -join ' | ')")
            $nextSteps.Add("Investigate vulnerable driver load - BYOVD used to disable EDR/AV or escalate kernel privileges [T1068/T1543.003]. Verify driver is expected in this environment.")
        }

        # -----------------------------------------------------------------------
        # BEHAVIORAL OVERLAP (hash-matched VT sandbox vs host activity)
        # -----------------------------------------------------------------------
        $totalOverlaps = $oc.IP + $oc.Domain + $oc.Process + $oc.File + $oc.Registry + $oc.MITRE + $oc.Name

        # UNIQUE indicators from hash-based behavioral overlay
        if ($uniqueMatches.Count -gt 0 -and $score -lt 100) {
            $score = 100
            $findings.Add("CRITICAL: $($uniqueMatches.Count) UNIQUE-TO-MALWARE behavioral overlap(s)  - zero presence in known-good baseline: $(($uniqueMatches | Select-Object -First 3) -join '; ')")
            $nextSteps.Add("Behavioral indicators confirmed unique to malware  - isolate and escalate immediately")
        }

        # RARE indicators from hash-based behavioral overlay
        if ($rareMatches.Count -gt 0 -and $score -lt 100) {
            $rareBonus = [Math]::Min(40, $rareMatches.Count * 20)
            $score += $rareBonus
            $findings.Add("$($rareMatches.Count) RARE indicator(s) (fidelity ~95, minimal legitimate presence): $(($rareMatches | Select-Object -First 3) -join '; ')")
            $nextSteps.Add("Review RARE indicators  - check if the listed legitimate processes justify this activity")
        }

        # Common indicators: proportional per-type scoring (only if score not already forced to 100)
        if ($totalOverlaps -gt 0 -and $score -lt 100) {
            $ipScore   = [Math]::Min(40, $oc.IP       * 10)
            $dnsScore  = [Math]::Min(30, $oc.Domain   * 8)
            $procScore = [Math]::Min(25, $oc.Process  * 6)
            $fileScore = [Math]::Min(20, $oc.File      * 5)
            $regScore  = [Math]::Min(20, $oc.Registry  * 5)
            $mitScore  = [Math]::Min(25, $oc.MITRE    * 8)
            $namScore  = [Math]::Min(30, $oc.Name     * 12)
            $bScore    = $ipScore + $dnsScore + $procScore + $fileScore + $regScore + $mitScore + $namScore
            $score    += $bScore
            if ($bScore -gt 0) {
                $findings.Add("$totalOverlaps behavioral indicator overlap(s) with VT sandbox data (+$bScore pts): IP:$($oc.IP) DNS:$($oc.Domain) Process:$($oc.Process) File:$($oc.File) Registry:$($oc.Registry) MITRE:$($oc.MITRE) NameMatch:$($oc.Name)")
                $nextSteps.Add("Investigate behavioral overlaps  - host activity matches known malware sandbox behavior")
            }
        }

        # Scheduled tasks  - persistence indicator
        if ($taskCmds.Count -gt 0) {
            $score += 15
            $findings.Add("Scheduled task creation observed: $($taskCmds.Count) schtasks.exe execution(s)")
            $nextSteps.Add("Audit host scheduled tasks for persistence mechanisms")
        }

        # PowerShell activity
        if ($psCmds.Count -gt 0) {
            $score += 5
            $findings.Add("PowerShell activity: $($psCmds.Count) command(s) executed in window")
        }

        # Shell/CLI activity across all shell-capable executables (not just PowerShell)
        if ($shellCmds.Count -gt 0) {
            $shellScore = [Math]::Min(10, [Math]::Max(3, [int]([Math]::Ceiling($shellCmds.Count / 8.0) * 2)))
            $score += $shellScore
            $shellTop = if ($shellCmdsByProc.Count -gt 0) { ($shellCmdsByProc | Select-Object -First 4) -join ', ' } else { 'N/A' }
            if ($nonPsShellCmds.Count -gt 0) {
                $findings.Add("Shell/CLI activity (all shells): $($shellCmds.Count) command(s), including $($nonPsShellCmds.Count) non-PowerShell command(s) (+$shellScore pts). Breakdown: $shellTop")
                $nextSteps.Add("Review non-PowerShell shell usage (cmd/wscript/cscript/mshta/rundll32/regsvr32/wmic) for execution and evasion behavior")
            } else {
                $findings.Add("Shell/CLI activity (all shells): $($shellCmds.Count) command(s) observed (+$shellScore pts). Breakdown: $shellTop")
            }
        }

        # Elevated external connectivity
        if ($extIPs.Count -gt 15) {
            $score += 10
            $findings.Add("Elevated external connectivity: $($extIPs.Count) unique destination IPs")
        }

        # Elevated registry modifications
        if ($regKeys.Count -gt 20) {
            $score += 5
            $findings.Add("Elevated registry modifications: $($regKeys.Count) unique keys touched")
        }

        # Threat intelligence attribution match
        if ($attributionText -match "Tier-1") {
            $score += 20
            $findings.Add("Threat intelligence: multi-indicator attribution match (see below)")
            $nextSteps.Add("Escalate to threat intelligence team for actor attribution review")
        }

        # -----------------------------------------------------------------------
        # SIGMA RULE SCAN SCORING (translated APT-linked rules run against live logs)
        # -----------------------------------------------------------------------
        if ($sigmaResult -and $sigmaResult.HitCount -gt 0) {
            # Each fired rule is malware-unique (Baseline_Count=0 from APT differential)
            # Treat as equivalent to a unique direct artifact - force score=100
            if ($score -lt 100) { $score = 100 }
            $sigmaActors = ($sigmaResult.Hits | ForEach-Object { $_.Actors } | Where-Object { $_ } | Select-Object -Unique | Sort-Object) -join ', '
            $sigmaRuleList = ($sigmaResult.Hits | Select-Object -First 5 | ForEach-Object { "$($_.RuleName) ($($_.HitCount) event(s))" }) -join ' | '
            $findings.Add("CRITICAL: $($sigmaResult.HitCount) APT-linked Sigma rule(s) FIRED against host logs: $sigmaRuleList")
            $findings.Add("  Threat actors linked to fired rules: $sigmaActors")
            $nextSteps.Add("Sigma rules unique to targeted malware fired  - review each hit event; escalate and isolate host")
        } elseif ($sigmaResult -and $sigmaResult.Tested -gt 0) {
            $findings.Add("Sigma rule scan: $($sigmaResult.Tested) APT-linked rules tested  - 0 fired (negative evidence)")
        }

        # -----------------------------------------------------------------------
        # BEHAVIORAL TTP DETECTION (offline, deterministic)
        # -----------------------------------------------------------------------

        # 1. DDNS C2 beacon detection (T1568.002 / T1071.004)
        #    Known DDNS providers abused by APT groups (Tick/Bronze Butler, APT33, etc.)
        $ddnsPatterns = @(
            '\.bounceme\.net$', '\.serveminecraft\.net$', '\.no-ip\.biz$', '\.no-ip\.org$',
            '\.no-ip\.info$',   '\.no-ip\.co\.uk$',      '\.ddns\.net$',   '\.hopto\.org$',
            '\.sytes\.net$',    '\.zapto\.org$',          '\.myftp\.biz$',  '\.myftp\.org$',
            '\.dyn\.com$',      '\.dyndns\.org$',         '\.changeip\.com$'
        )
        $ddnsHits = @($dnsNames | Where-Object {
            $d = $_
            $ddnsPatterns | Where-Object { $d -match $_ }
        })
        if ($ddnsHits.Count -gt 0) {
            $ddnsScore = [Math]::Min(40, $ddnsHits.Count * 20)
            $score     = [Math]::Min(100, $score + $ddnsScore)
            $findings.Add("CRITICAL: DDNS C2 beacon detected - $($ddnsHits.Count) DDNS domain(s) queried [T1568.002/T1071.004]: $($ddnsHits -join ', ') (+$ddnsScore pts)")
            $nextSteps.Add("Block DDNS beacon domain(s) at DNS/firewall and trace all traffic to: $($ddnsHits -join ', ')")
        }

        # 2. Defense evasion / memory manipulation alert detection (T1562.001)
        #    Fired alert rules containing NTDLL/memory-write/hook-bypass keywords
        $defEvadeHits = @(($alertRuleNames + $idRules) | Select-Object -Unique | Where-Object {
            $a = $_.ToLower()
            $a -match 'ntdll|memory.?write|memory.?tamper|unhook|hook.?bypass|shellcode|reflective|hollow|inject'
        })
        if ($defEvadeHits.Count -gt 0) {
            $deScore = [Math]::Min(40, $defEvadeHits.Count * 20)
            $score   = [Math]::Min(100, $score + $deScore)
            $findings.Add("CRITICAL: Defense evasion - EDR hook bypass / memory manipulation detected [T1562.001]: $($defEvadeHits -join ' | ') (+$deScore pts)")
            $nextSteps.Add("Defense evasion confirmed - NTDLL/hook bypass indicates advanced malware; consider memory forensics on affected process(es)")
        }

        # 3. Malware Detection alert (Elastic Defend ML classifier)
        $mlAlertRules = @($alertRuleNames | Where-Object { $_ -match 'Malware Detection Alert|endpointpe|malware.classif' })
        if ($mlAlerts.Count -gt 0 -or $mlAlertRules.Count -gt 0) {
            $mlCount = if ($mlAlerts.Count -gt 0) { $mlAlerts.Count } else { $mlAlertRules.Count }
            if ($score -lt 100) { $score = [Math]::Min(100, $score + 30) }
            $findings.Add("CRITICAL: Elastic Defend ML classifier (endpointpe-v4-model) flagged $mlCount file(s) as malicious - high-confidence PE malware detection (+30 pts)")
            $nextSteps.Add("Quarantine ML-flagged executable(s) and submit to sandbox for full behavioral analysis")
        }

        # 4. In-memory .NET compilation via PowerShell Add-Type → csc.exe (T1059.001 / T1027.010)
        $cscFromPS = @($procDetails | Where-Object {
            $_.'process.name' -eq 'csc.exe' -and $_.'process.parent.name' -match 'powershell'
        })
        if ($cscFromPS.Count -eq 0 -and $procDetails.Count -gt 0) {
            # try nested object access
            $cscFromPS = @($procDetails | Where-Object {
                $_.process.name -eq 'csc.exe' -and $_.process.parent.name -match 'powershell'
            })
        }
        if ($cscFromPS.Count -gt 0 -or ($lolBinsFound -contains 'csc.exe' -and $psCmds.Count -gt 0)) {
            $score = [Math]::Min(100, $score + 20)
            $findings.Add("In-memory .NET compilation detected: PowerShell spawned csc.exe indicating Add-Type C# compilation [T1059.001/T1027.010] - DLL likely loaded directly into process memory (+20 pts)")
            $nextSteps.Add("Inspect PowerShell command line(s) for Add-Type usage; check %TEMP% for .cmdline/.0.cs artifacts (auto-deleted after load)")
        }

        # 5. Suspicious behavior alert cluster (Elastic Defend behavioral detections)
        $behaviorAlerts = @($alertRuleNames | Where-Object { $_ -match 'Malicious Behavior Detection|Behavior:' })
        if ($behaviorAlerts.Count -gt 0) {
            $baScore = [Math]::Min(30, $behaviorAlerts.Count * 10)
            $score   = [Math]::Min(100, $score + $baScore)
            $findings.Add("Elastic Defend behavioral detection(s) fired ($($behaviorAlerts.Count) rule(s)) [T1055/T1059]: $($behaviorAlerts -join ' | ') (+$baScore pts)")
        }

        # 6. High-volume chcp.com execution (Chinese authorship signal)
        if ($procDocs -and $procDocs.Count -gt 0) {
            $chcpLg = @($procDocs | Where-Object { $_.process.name -match '^chcp\.(com|exe)$' -and $_.event.type -match 'start' })
            if ($chcpLg.Count -ge 5) {
                $score = [Math]::Min(100, $score + 15)
                $chcpLgCt = $chcpLg.Count
                $findings.Add("Chinese authorship signal: chcp.com executed $chcpLgCt times [T1614]  -  code-page switching to GBK/Big5 is characteristic of APT10, Tick, APT27, APT41 tooling (+15 pts)")
                $nextSteps.Add("Investigate chcp.com parent process chain  -  high-volume code-page switching correlates with Chinese APT tooling")
            }
        }

        # 7. External IP geolocation pre-check (APT victim profiling)
        $geoDomsLg = @('ip-api.com','l2.io','api.ipify.org','ipinfo.io','checkip.amazonaws.com',
                        'myexternalip.com','icanhazip.com','www.ip.cn','ip.cn','wtfismyip.com')
        $geoLgHits = @($dnsNames | Where-Object {
            $rawDom = ($_ -replace '^\(\d+x\)\s*','').ToLower()
            $found = $false
            foreach ($gd in $geoDomsLg) { if ($rawDom -eq $gd -or $rawDom.EndsWith(".$gd")) { $found = $true; break } }
            $found
        })
        if ($geoLgHits.Count -gt 0) {
            $score = [Math]::Min(100, $score + 20)
            $findings.Add("Geolocation pre-check detected [T1614/T1082]: $($geoLgHits -join ', ')  -  APT10/menuPass, Tick, APT27 query IP geolocation APIs before payload deployment to avoid sandboxes and law enforcement (+20 pts)")
            $nextSteps.Add("Geolocation pre-check is a strong APT10/Tick behavioral indicator  -  correlate with Run key persistence and UAC bypass events in the timeline")
        }

        # 8. OPSEC folder anomaly - staging paths exposing adversary intent
        if ($procDocs -and $procDocs.Count -gt 0) {
            $opSecPatsLg = @('\malware\','\SubDir\','\Backdoor\','\payload\','\shellcode\','\implant\','\stager\','\dropper\','\rat\','\inject\')
            $opSecLgHits = @($procDocs | Where-Object {
                $exe = $_.process.executable
                if (-not $exe) { return $false }
                $exeLower = $exe.ToLower()
                $hit = $false
                foreach ($pat in $opSecPatsLg) { if ($exeLower.IndexOf($pat.ToLower()) -ge 0) { $hit = $true; break } }
                $hit
            })
            if ($opSecLgHits.Count -gt 0) {
                $score = [Math]::Min(100, $score + 15)
                $opLgList = ($opSecLgHits | ForEach-Object { $_.process.executable } | Where-Object { $_ } | Select-Object -Unique -First 4) -join '; '
                $findings.Add("OPSEC anomaly: execution from operationally-revealing staging path [T1036]: $opLgList  -  \SubDir\ is documented APT10 staging tradecraft (+15 pts)")
                $nextSteps.Add("Investigate processes running from \malware\, \SubDir\, or similar paths  -  these folder names are a strong APT10/menuPass attribution indicator")
            }
        }

        if ($findings.Count -eq 0)  { $findings.Add("No significant indicators found in the specified time window.") }
        if ($nextSteps.Count -eq 0) { $nextSteps.Add("No immediate action required  - continue baseline monitoring.") }

        # Verdict thresholds:
        #   score=100 OR unique-to-malware indicator OR confirmed malicious hash → COMPROMISED HIGH
        #   score ≥ 60 or malicious hash → COMPROMISED
        #   score ≥ 25 → SUSPICIOUS
        $verdict      = if ($uniqueMatches.Count -gt 0 -or $directUnique.Count -gt 0 -or $malHashes.Count -gt 0 -or $suspParentChild.Count -gt 0 -or $score -ge 60) { "COMPROMISED" }
                        elseif ($score -ge 25) { "SUSPICIOUS" }
                        else { "CLEAN" }
        $confidence   = if ($uniqueMatches.Count -gt 0 -or $directUnique.Count -gt 0 -or $score -ge 100 -or $malHashes.Count -gt 0 -or $suspParentChild.Count -gt 0) { "HIGH" }
                        elseif ($rareMatches.Count -gt 0 -or $directRare.Count -gt 0 -or $score -ge 40 -or $alertHitList.Count -gt 2) { "MEDIUM" }
                        else { "LOW" }
        $verdictColor = switch ($verdict) { "COMPROMISED" { "Red" } "SUSPICIOUS" { "Yellow" } default { "Green" } }

        # --- Display ---
        Write-Host "`n`n======================================================" -ForegroundColor DarkCyan
        Write-Host "  ELASTIC ALERT AGENT  - FORENSIC VERDICT (OFFLINE)" -ForegroundColor DarkCyan
        Write-Host "  Host: $agentHost  |  Window: $fromTs --> $toTs" -ForegroundColor DarkCyan
        Write-Host "======================================================`n" -ForegroundColor DarkCyan

        Write-Host "OVERALL VERDICT  : $verdict" -ForegroundColor $verdictColor
        Write-Host "CONFIDENCE       : $confidence  (Risk Score: $score  |  Unique-to-Malware: $($uniqueMatches.Count)  Rare: $($rareMatches.Count)  Common: $($totalOverlaps - $uniqueMatches.Count - $rareMatches.Count))" -ForegroundColor $verdictColor

        if ($behaviorOverlap.Length -gt 0) {
            Write-Host "`nBEHAVIORAL INDICATOR OVERLAPS (host activity vs VT sandbox behavior):" -ForegroundColor Yellow
            Write-Host $behaviorOverlap.ToString() -ForegroundColor Yellow
        }

        Write-Host "`nRECOMMENDED NEXT STEPS:" -ForegroundColor DarkCyan
        $i = 1; $nextSteps | ForEach-Object { Write-Host "  $i. $_"; $i++ }

        Write-Host "`nFORENSIC SUMMARY:" -ForegroundColor DarkCyan
        Write-Host "  Alerts  : $($alertHitList.Count)   Processes: $($procNames.Count)   Ext IPs: $($extIPs.Count)   DNS: $($dnsNames.Count)"
        Write-Host "  Files   : $($fileNames.Count)   Registry: $($regKeys.Count)   Sched Tasks: $($taskCmds.Count)   PS Cmds: $($psCmds.Count)   All Shell Cmds: $($shellCmds.Count)   Non-PS Shell: $($nonPsShellCmds.Count)"
        Write-Host "  Unsigned: $($unsignedProcs.Count)   SuspParent-Child: $($suspParentChild.Count)   LOLBins: $($lolBinsFound.Count)"
        Write-Host "  Direct Fidelity: UNIQUE=$($directUnique.Count)  RARE=$($directRare.Count)"
        if ($sysmonTotal -gt 0) {
            Write-Host "  Sysmon API/Injection Events: $sysmonTotal  ($($sysmonEventIds -join ', '))" -ForegroundColor $(if ($sysmonTotal -gt 5) { "Yellow" } else { "White" })
            if ($sysmonSrcProcs.Count -gt 0) { Write-Host "    Source procs : $(($sysmonSrcProcs | Select-Object -First 5) -join ', ')" -ForegroundColor DarkGray }
            if ($sysmonTgtProcs.Count -gt 0) { Write-Host "    Target procs : $(($sysmonTgtProcs | Select-Object -First 5) -join ', ')" -ForegroundColor DarkGray }
            if ($sysmonImages.Count  -gt 0)  { Write-Host "    Images loaded: $(($sysmonImages  | Select-Object -First 5) -join ', ')" -ForegroundColor DarkGray }
        }
        if ($alertTechStr) {
            Write-Host "  MITRE Techniques :" -NoNewline
            $alertTechs = $alertTechStr -split ',\s*' | Where-Object { $_ }
            foreach ($tech in $alertTechs) {
                $tid = ($tech -split '[\. ]')[0].Trim()
                if ($fidMap -and $fidMap.ContainsKey($tid)) {
                    $fidEntry = $fidMap[$tid]
                    if ($fidEntry.Unique) {
                        Write-Host " [$tech UNIQUE]" -ForegroundColor Red -NoNewline
                    } elseif ($fidEntry.Rare) {
                        Write-Host " [$tech RARE]" -ForegroundColor Yellow -NoNewline
                    } else {
                        $sc = [Math]::Round($fidEntry.Score, 0)
                        Write-Host " [$tech fid:$sc]" -ForegroundColor DarkYellow -NoNewline
                    }
                } else {
                    Write-Host " $tech" -NoNewline
                }
            }
            Write-Host ""
            if ($ruleUnique.Count -gt 0) {
                Write-Host "    [HIGH FIDELITY] Unique-to-malware rules fired: $(($ruleUnique | Select-Object -First 5) -join ', ')" -ForegroundColor Red
            }
            if ($ruleRare.Count -gt 0) {
                Write-Host "    [ELEVATED]       Rare rules fired            : $(($ruleRare | Select-Object -First 5) -join ', ')" -ForegroundColor Yellow
            }
        }
        if ($extPortStr)    { Write-Host "  Dest Ports       : $extPortStr" }
        if ($netProcStr)    { Write-Host "  Network Processes: $netProcStr" }
        if ($fileExtStr)    { Write-Host "  File Extensions  : $fileExtStr" }
        if ($unsignedProcs.Count -gt 0) {
            Write-Host "`nUNSIGNED/UNTRUSTED PROCESSES:" -ForegroundColor Yellow
            $unsignedProcs | Select-Object -First 10 | ForEach-Object { Write-Host "  [!] $_" -ForegroundColor Yellow }
        }
        if ($suspParentChild.Count -gt 0) {
            Write-Host "`nSUSPICIOUS PARENT-CHILD CHAINS:" -ForegroundColor Red
            $suspParentChild | ForEach-Object { Write-Host "  [!!] $_" -ForegroundColor Red }
        }
        if ($directUnique.Count -gt 0) {
            Write-Host "`nDIRECT ARTIFACT FIDELITY - UNIQUE TO MALWARE:" -ForegroundColor Red
            $directUnique | Select-Object -First 10 | ForEach-Object { Write-Host "  [UNIQUE] $_" -ForegroundColor Red }
        }
        if ($directRare.Count -gt 0) {
            Write-Host "`nDIRECT ARTIFACT FIDELITY - RARE (score 95):" -ForegroundColor Yellow
            $directRare | Select-Object -First 10 | ForEach-Object {
                $legit = if ($fidMap[$_].LegitNames.Count -gt 0) { " | Legit: $($fidMap[$_].LegitNames -join ', ')" } else { "" }
                Write-Host "  [RARE] $_$legit" -ForegroundColor Yellow
            }
        }

        # Load fidelity index for MITRE T-code color scoring
        $mitreFidIdx = $null
        $fidIdxPath  = Join-Path $BaselineMainRoot "..\fidelity-index.json"
        if (Test-Path $fidIdxPath) {
            try { $mitreFidIdx = Get-Content $fidIdxPath -Raw | ConvertFrom-Json } catch {}
        }

        Write-Host "`nVT HASH ENRICHMENT (offline baseline):" -ForegroundColor DarkCyan
        if ($vtEnrichment.Length -gt 0) {
            foreach ($line in ($vtEnrichment.ToString() -split "`n")) {
                if ($line -match "Baseline Category\s*:.*[Mm]alicious") {
                    Write-Host $line -ForegroundColor Red
                } elseif ($line -match "Category\s*:\s*") {
                    Write-Host $line -ForegroundColor Green
                } elseif ($line -match "^\s+-\s+(T\d{4})") {
                    $tid    = $Matches[1]
                    $fe     = if ($mitreFidIdx) { $mitreFidIdx.PSObject.Properties[$tid] } else { $null }
                    $tScore = if ($fe) { [double]$fe.Value.S } else { -1 }
                    if ($tScore -ge 95) {
                        Write-Host "  [UNIQUE] $line" -ForegroundColor Red
                    } elseif ($tScore -ge 70) {
                        Write-Host "  [RARE]   $line" -ForegroundColor Yellow
                    } elseif ($tScore -ge 0) {
                        Write-Host "  [LOW]    $line" -ForegroundColor DarkYellow
                    } else {
                        Write-Host $line
                    }
                } elseif ($line -match "Detection Ratio\s*:\s*(\d+)/") {
                    if ([int]$Matches[1] -gt 0) {
                        Write-Host $line -ForegroundColor Red
                    } else {
                        Write-Host $line -ForegroundColor Green
                    }
                } elseif ($line -match "MITRE ATT&CK") {
                    Write-Host $line -ForegroundColor Yellow
                } else {
                    Write-Host $line
                }
            }
        } else {
            Write-Host "  No SHA-256 hashes collected from Elastic for this host/window." -ForegroundColor DarkGray
            Write-Host "  (Elastic index may not have process.hash.sha256 populated  - check your agent config)" -ForegroundColor DarkGray
        }
        if ($vtUnknownHashes -and $vtUnknownHashes.Count -gt 0) {
            Write-Host "  NOT IN OFFLINE BASELINE ($($vtUnknownHashes.Count) hash(es) - never seen or not yet pulled from VT):" -ForegroundColor DarkGray
            $vtUnknownHashes | ForEach-Object { Write-Host "    - $_" -ForegroundColor DarkGray }
        }

        Write-Host $attributionText -ForegroundColor $(if ($attributionText -match "Tier-1") { "Yellow" } else { "DarkGray" })

        Write-Host "`nKEY FINDINGS:" -ForegroundColor DarkCyan
        $findings | ForEach-Object {
            $c = if ($_ -match "^CRITICAL|malicious|overlap") { "Red" }
                 elseif ($_ -match "alert|task|PowerShell|attribution|unclassified") { "Yellow" }
                 else { "White" }
            Write-Host "  - $_" -ForegroundColor $c
        }

        Write-Host "`n======================================================`n" -ForegroundColor DarkCyan

        # --- HTML Report ---
        try {
            function _He([string]$s) { $s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' }
            function _JsArr([object[]]$arr) {
                if (-not $arr -or $arr.Count -eq 0) { return "[]" }
                $items = $arr | ForEach-Object {
                    $s = "$_" -replace '\\','\\' -replace '"','\"' -replace "`r`n",' ' -replace "`n",' ' -replace "`r",''
                    "`"$s`""
                }
                return "[" + ($items -join ",") + "]"
            }
            $rpDir = Join-Path $PSScriptRoot "..\reports\alertTriage"
            if (-not (Test-Path $rpDir)) { New-Item -ItemType Directory -Path $rpDir -Force | Out-Null }
            $safeH  = ($agentHost -replace '[^a-zA-Z0-9_-]','_')
            $rpFile = Join-Path $rpDir "${safeH}_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
            $hvc  = switch ($verdict)    { "COMPROMISED"{"#e74c3c"} "SUSPICIOUS"{"#c0a020"} default{"#2ecc71"} }
            $hcc  = switch ($confidence) { "HIGH"{"#e74c3c"} "MEDIUM"{"#c0a020"} default{"#2ecc71"} }
            $sBarW = [Math]::Min(100,[Math]::Max(0,$score))
            $sBcl  = if($score-ge 60){"#e74c3c"}elseif($score-ge 30){"#c0a020"}else{"#2ecc71"}

            # Serialize process tree nodes to JS
            $jsProcTree = if ($ptNodes -and $ptNodes.Count -gt 0) {
                $ptItems = $ptNodes | ForEach-Object {
                    $pArr = ($_.p | ForEach-Object { $s = $_ -replace '\\','\\' -replace '"','\"'; "`"$s`"" }) -join ","
                    $cArr = ($_.cmds | ForEach-Object {
                        $s = ($_ -replace '\\','\\' -replace '"','\"' -replace "`r`n",' ' -replace "`n",' ')
                        $s = $s.Substring(0, [Math]::Min(200, $s.Length))
                        "`"$s`""
                    }) -join ","
                    $nn = $_.n -replace '\\','\\' -replace '"','\"'
                    $ee = $_.e -replace '\\','\\' -replace '"','\"'
                    $hh = if ($_.h) { "$($_.h.Substring(0,[Math]::Min(16,$_.h.Length)))..." } else { "" }
                    $mlStr = if ($_.maxMlScore -ne $null) { "$($_.maxMlScore)" } else { "null" }
                    $enStr = if ($_.maxEntropy -ne $null) { "$($_.maxEntropy)" } else { "null" }
                    $fArr  = ($_.topFiles        | ForEach-Object { $f  = $_ -replace '\\','\\' -replace '"','\"'; "`"$f`"" })  -join ","
                    $iArr  = ($_.topIPs          | ForEach-Object { $ip = $_ -replace '"','\"'; "`"$ip`"" })                    -join ","
                    $dArr  = ($_.topDNS          | ForEach-Object { $dn = $_ -replace '"','\"'; "`"$dn`"" })                    -join ","
                    $kArr  = ($_.topKeys         | ForEach-Object { $k  = $_ -replace '\\','\\' -replace '"','\"'; "`"$k`"" })  -join ","
                    $lArr  = ($_.topDlls         | ForEach-Object { $l  = $_ -replace '"','\"'; "`"$l`"" })                     -join ","
                    $evArr = ($_.topDllEvasions  | ForEach-Object { $ev = $_ -replace '"','\"'; "`"$ev`"" })                    -join ","
                    $aArr  = ($_.topApis         | ForEach-Object { $ap = $_ -replace '"','\"'; "`"$ap`"" })                    -join ","
                    $bArr  = ($_.topBehaviors    | ForEach-Object { $bv = $_ -replace '"','\"'; "`"$bv`"" })                    -join ","
                    $sArr  = ($_.topSummaries    | ForEach-Object { $sv = $_ -replace '\\','\\' -replace '"','\"'; "`"$sv`"" })  -join ","
                    $tArr  = ($_.topTargets      | ForEach-Object { $tv = $_ -replace '"','\"'; "`"$tv`"" })                    -join ","
                    $prArr = ($_.topMemProt      | ForEach-Object { $pv = $_ -replace '"','\"'; "`"$pv`"" })                    -join ","
                    $mArr  = ($_.topMemPaths     | ForEach-Object { $mv = $_ -replace '\\','\\' -replace '"','\"'; "`"$mv`"" }) -join ","
                    $svArr = ($_.topSeverity     | ForEach-Object { $sv2= $_ -replace '"','\"'; "`"$sv2`"" })                   -join ","
                    $inStr = $_.integ -replace '"','\"'
                    "{`"n`":`"$nn`",`"c`":$($_.c),`"r`":`"$($_.r)`",`"p`":[$pArr],`"e`":`"$ee`",`"h`":`"$hh`",`"cmds`":[$cArr],`"integ`":`"$inStr`",`"susp`":$(if($_.susp){'true'}else{'false'}),`"alerts`":$($_.alerts),`"maxRisk`":$($_.maxRisk),`"topSeverity`":[$svArr],`"files`":$($_.files),`"maxMlScore`":$mlStr,`"maxEntropy`":$enStr,`"net`":$($_.net),`"reg`":$($_.reg),`"topKeys`":[$kArr],`"dll`":$($_.dll),`"topDllEvasions`":[$evArr],`"api`":$($_.api),`"topFiles`":[$fArr],`"topIPs`":[$iArr],`"topDNS`":[$dArr],`"topDlls`":[$lArr],`"topApis`":[$aArr],`"topBehaviors`":[$bArr],`"topSummaries`":[$sArr],`"topTargets`":[$tArr],`"topMemProt`":[$prArr],`"topMemPaths`":[$mArr]}"
                }
                "[" + ($ptItems -join ",") + "]"
            } else { "[]" }

            # Build JS data arrays (full, no caps)
            $jsAlerts   = _JsArr @($alertRules)  # "(Nx) RuleName" format from deduped rule groups
            $jsProcs    = _JsArr @($procNames | ForEach-Object {
                $raw = ($_ -replace '^\(\d+x\)\s+','').ToLower()
                if ($fidMap -and $fidMap.ContainsKey($raw)) {
                    if ($fidMap[$raw].Unique) { "[UNIQUE] $_" }
                    elseif ($fidMap[$raw].Rare) { "[RARE] $_" }
                    else { $_ }
                } else { $_ }
            })
            $jsIPs      = _JsArr @($extIPs)
            $jsDns      = _JsArr @($dnsNames)
            $jsFiles    = _JsArr @($fileNames)
            $jsReg      = _JsArr @($regKeys)
            $jsTasks    = _JsArr @($taskCmds)
            $jsPS       = _JsArr @($psCmds | ForEach-Object { $_.Substring(0,[Math]::Min(300,$_.Length)) })
            $jsShell    = _JsArr @($shellCmds | ForEach-Object { $_.Substring(0,[Math]::Min(300,$_.Length)) })
            $jsNonPsShell = _JsArr @($nonPsShellCmds | ForEach-Object { $_.Substring(0,[Math]::Min(300,$_.Length)) })
            $jsShellByProc = _JsArr @($shellCmdsByProc)
            $jsUnsigned = _JsArr @($unsignedProcs)
            $jsSuspPC   = _JsArr @($suspParentChild)
            $jsLolbins    = _JsArr @($lolBinsFound)
            $jsLolDrivers = _JsArr @($lolDriversFound)
            $jsSrcProcs   = _JsArr @($sysmonSrcProcs)
            $jsTgtProcs = _JsArr @($sysmonTgtProcs)
            $jsImages   = _JsArr @($sysmonImages)
            $jsPairs    = _JsArr @($syPairs)
            $jsRules    = _JsArr @($sysmonRules)
            $jsAccess   = _JsArr @($sysmonAccess)
            $jsUnique   = _JsArr @($directUnique | ForEach-Object { "[UNIQUE] $_" })
            $jsRareArt  = _JsArr @($directRare | ForEach-Object { $leg=if($fidMap-and $fidMap[$_]-and $fidMap[$_].LegitNames.Count-gt 0){" | Legit: $($fidMap[$_].LegitNames -join ', ')"}else{""}; "[RARE] $_$leg" })
            $jsUnknown  = _JsArr @($vtUnknownHashes)

            # Behavioral TTP panel data
            $behaviorItems = [System.Collections.Generic.List[string]]::new()
            # DDNS C2
            if ($ddnsHits.Count -gt 0) {
                $behaviorItems.Add("[UNIQUE] DDNS C2 BEACON [T1568.002/T1071.004]: $($ddnsHits -join ', ')")
            }
            # Defense evasion
            foreach ($dea in $defEvadeHits) { $behaviorItems.Add("[UNIQUE] DEF EVASION - EDR hook bypass [T1562.001]: $dea") }
            # ML malware detections
            foreach ($ml in $mlHits) {
                $mlScore = if ($ml.'file.Ext.malware_classification.score') { " score=$($ml.'file.Ext.malware_classification.score')" } else { "" }
                $behaviorItems.Add("[UNIQUE] ML MALWARE CLASSIFIER [Elastic Defend]: $($ml.'process.name')$mlScore")
            }
            # Elastic Defend behavior detections
            foreach ($ba in $idRules) { $behaviorItems.Add("BEHAVIOR ALERT [T1059/T1055]: $ba") }
            # In-memory compilation
            if ($cscFromPS.Count -gt 0 -or ($lolBinsFound -contains 'csc.exe' -and $psCmds.Count -gt 0)) {
                $behaviorItems.Add("[RARE] IN-MEMORY .NET COMPILATION [T1059.001/T1027.010]: PowerShell -> csc.exe (Add-Type pattern)")
            }
            # All behavior alerts from alert rule names
            foreach ($ba in ($alertRuleNames | Where-Object { $_ -match 'Malicious Behavior|Behavior:' })) {
                if (-not ($behaviorItems | Where-Object { $_ -match [regex]::Escape($ba) })) {
                    $behaviorItems.Add("ELASTIC BEHAVIOR ALERT: $ba")
                }
            }
            $jsBehavior = _JsArr @($behaviorItems.ToArray())

            # Stat boxes with click handlers
            function _Sb([int]$v,[string]$lbl,[string]$key,[string]$c="") {
                $cc = if($c){$c}elseif($v-ge 10){"hot"}elseif($v-ge 1){"warm"}else{""}
                $cur = if($v-gt 0){"cursor:pointer;"}else{""}
                "<div class='sb' style='${cur}' onclick=`"showPanel('$key','$lbl','$c')`"><div class='sv $cc'>$v</div><div class='sl'>$lbl</div></div>"
            }
            $statsHtml = "<div class='sg'>" +
                (_Sb $alertHitList.Count   "ALERTS"      "alerts") +
                (_Sb $procNames.Count      "PROCESSES"   "procs") +
                (_Sb $extIPs.Count         "EXT IPS"     "ips") +
                (_Sb $dnsNames.Count       "DNS"         "dns") +
                (_Sb $fileNames.Count      "FILES"       "files") +
                (_Sb $regKeys.Count        "REGISTRY"    "reg") +
                (_Sb $taskCmds.Count       "SCHED TASKS" "tasks") +
                (_Sb $psCmds.Count         "PS CMDS"     "pscmds") +
                (_Sb $shellCmds.Count      "ALL SHELL CMDS" "shellcmds" $(if($nonPsShellCmds.Count-gt 0){"warm"}else{""})) +
                (_Sb $nonPsShellCmds.Count "NON-PS SHELL" "npshell" $(if($nonPsShellCmds.Count-gt 0){"hot"}else{""})) +
                (_Sb $unsignedProcs.Count  "UNSIGNED"    "unsigned"  $(if($unsignedProcs.Count-gt 0){"hot"}else{""})) +
                (_Sb $suspParentChild.Count "SUSP P-C"   "susppc"    $(if($suspParentChild.Count-gt 0){"hot"}else{""})) +
                (_Sb $lolBinsFound.Count   "LOLBINS"     "lolbins"   $(if($lolBinsFound.Count-gt 0){"warm"}else{""})) +
                (_Sb $lolDriversFound.Count "LOLDRIVERS" "loldrivers" $(if($lolDriversFound.Count-gt 0){"hot"}else{""})) +
                (_Sb $sysmonTotal          "SYSMON"      "sysmon"    $(if($sysmonTotal-gt 5){"warm"}else{""})) +
                (_Sb $behaviorItems.Count  "BEHAVIOR"    "behavior"  $(if($behaviorItems.Count-gt 0){"hot"}else{""})) +
                "</div>"

            $fHtml = ($findings | ForEach-Object {
                $cls=if($_-match "CRITICAL|confirmed-malicious"){"critical"}elseif($_-match "WARNING|unsigned|Sigma"){"warning"}else{"info"}
                "<div class='finding $cls'>$(_He $_)</div>"
            }) -join "`n"

            $mitreHtml = ""
            if ($alertTechStr) {
                foreach ($tech in ($alertTechStr -split ',\s*' | Where-Object { $_ })) {
                    $tid2 = ($tech -split '[\. ]')[0].Trim()
                    $cls2 = if ($fidMap -and $fidMap.ContainsKey($tid2)) { $fe2=$fidMap[$tid2]; if($fe2.Unique){"unique"}elseif($fe2.Rare){"rare"}else{"low"} } else { "plain" }
                    $mitreHtml += "<span class='mt $cls2'>$(_He $tech)</span>"
                }
            }
            # Augment MITRE with T-codes found in findings + behavioral detections
            $extraTechs = [System.Collections.Generic.HashSet[string]]::new()
            foreach ($f in $findings) {
                foreach ($m in ([regex]::Matches($f, 'T\d{4}(?:\.\d{3})?'))) { [void]$extraTechs.Add($m.Value) }
            }
            foreach ($b in $behaviorItems) {
                foreach ($m in ([regex]::Matches($b, 'T\d{4}(?:\.\d{3})?'))) { [void]$extraTechs.Add($m.Value) }
            }
            # Add any already-in-mitreHtml techs so we don't lose them
            foreach ($m in ([regex]::Matches($mitreHtml, 'T\d{4}(?:\.\d{3})?'))) { [void]$extraTechs.Add($m.Value) }
            if ($extraTechs.Count -gt 0) {
                $extraMitreHtml = ($extraTechs | Sort-Object | ForEach-Object {
                    $t = $_
                    $cls = if ($t -match 'T1562|T1027|T1055') { 'unique' } elseif ($t -match 'T1059|T1568|T1071|T1071') { 'rare' } else { 'plain' }
                    "<span class='mt $cls'>$t</span>"
                }) -join ""
                $mitreHtml = $extraMitreHtml  # replace with the full augmented set
            }

            $fidHtml  = ($directUnique | ForEach-Object { "<div class='art unique'>[UNIQUE] $(_He $_)</div>" }) -join "`n"
            $fidHtml += ($directRare   | ForEach-Object { $leg=if($fidMap-and $fidMap[$_]-and $fidMap[$_].LegitNames.Count-gt 0){" | Legit: $($fidMap[$_].LegitNames -join ', ')"}else{""}; "<div class='art rare'>[RARE] $(_He "$_$leg")</div>" }) -join "`n"

            $vtHtml = ""; $curBlk = $false
            foreach ($ln in ($vtEnrichment.ToString() -split "`n")) {
                if     ($ln -match "^\s*Hash:")                      { if($curBlk){$vtHtml+="</div>`n"}; $vtHtml+="<div class='hb'><div class='hi'>$(_He $ln.Trim())</div>`n"; $curBlk=$true }
                elseif ($ln -match "Baseline Category.*[Mm]alicious") { $vtHtml+="<div class='hl malicious'>$(_He $ln.Trim())</div>`n" }
                elseif ($ln -match "Detection Ratio.*[1-9]")          { $vtHtml+="<div class='hl dr-hot'>$(_He $ln.Trim())</div>`n" }
                elseif ($ln -match "Detection Ratio")                 { $vtHtml+="<div class='hl good'>$(_He $ln.Trim())</div>`n" }
                elseif ($ln -match "MITRE ATT&CK|T\d{4}")             { $vtHtml+="<div class='hl tech'>$(_He $ln.Trim())</div>`n" }
                elseif ($ln.Trim())                                    { $vtHtml+="<div class='hl'>$(_He $ln.Trim())</div>`n" }
            }
            if ($curBlk) { $vtHtml += "</div>`n" }
            if (-not $vtHtml) { $vtHtml = "<div class='art info'>No SHA-256 hashes in this window.</div>" }

            # Build scanner HTML section (Thor/Loki)
            $lokiHtml = ""
            if ($lokiResult -and $lokiResult.Available) {
                $lkAlerts  = @($lokiResult.Alerts)
                $lkWarns   = @($lokiResult.Warnings)
                $lkNotices = @($lokiResult.Notices)
                $lkTotal   = $lkAlerts.Count + $lkWarns.Count + $lkNotices.Count
                $lkScanStr = $lokiResult.ScanDirs -join '; '
                $lkScannerLabel = if ($lokiResult.ScannerLabel) { $lokiResult.ScannerLabel } else { 'IOC/YARA Scanner' }
                $lokiHtml  = "<div class='loki-meta'>[$lkScannerLabel] Scanned $($lokiResult.FileCount) file(s) in: $(_He $lkScanStr)</div>"
                $lokiHtml += "<div class='loki-summary'>"
                $lokiHtml += "<span class='loki-cnt $(if($lkAlerts.Count -gt 0){"loki-alert"}else{"loki-ok"})'>ALERT $($lkAlerts.Count)</span>"
                $lokiHtml += "<span class='loki-cnt $(if($lkWarns.Count  -gt 0){"loki-warn" }else{"loki-ok"})'>WARNING $($lkWarns.Count)</span>"
                $lokiHtml += "<span class='loki-cnt loki-ok'>NOTICE $($lkNotices.Count)</span>"
                $lokiHtml += "</div>"
                if ($lkAlerts.Count -gt 0) {
                    $lokiHtml += "<div class='loki-grp'><div class='loki-grp-hdr'>ALERTS</div>"
                    foreach ($a in $lkAlerts) {
                        $ruleTxt = if ($a.Rule) { "<span class='loki-rule'>$(_He $a.Rule)</span>" } else { "" }
                        $scoreTxt = if ($a.Score -gt 0) { " <span class='loki-score'>score:$($a.Score)</span>" } else { "" }
                        $fileTxt  = if ($a.File) { "<div class='loki-file'>$(_He $a.File)</div>" } else { "" }
                        $descTxt  = if ($a.Description) { "<div class='loki-desc'>$(_He $a.Description)</div>" } else { "" }
                        $lokiHtml += "<div class='loki-row loki-row-alert'>$ruleTxt$scoreTxt$fileTxt$descTxt</div>"
                    }
                    $lokiHtml += "</div>"
                }
                if ($lkWarns.Count -gt 0) {
                    $lokiHtml += "<div class='loki-grp'><div class='loki-grp-hdr loki-grp-warn'>WARNINGS</div>"
                    foreach ($w in ($lkWarns | Select-Object -First 20)) {
                        $ruleTxt  = if ($w.Rule) { "<span class='loki-rule'>$(_He $w.Rule)</span>" } else { "" }
                        $scoreTxt = if ($w.Score -gt 0) { " <span class='loki-score'>score:$($w.Score)</span>" } else { "" }
                        $fileTxt  = if ($w.File) { "<div class='loki-file'>$(_He $w.File)</div>" } else { "" }
                        $lokiHtml += "<div class='loki-row loki-row-warn'>$ruleTxt$scoreTxt$fileTxt</div>"
                    }
                    if ($lkWarns.Count -gt 20) { $lokiHtml += "<div class='loki-more'>... and $($lkWarns.Count - 20) more. See: $(_He $lokiResult.LogFile)</div>" }
                    $lokiHtml += "</div>"
                }
                if ($lkTotal -eq 0) {
                    $lokiHtml += "<div class='art info'>No $lkScannerLabel findings  -  clean scan.</div>"
                }
                $logNote = if ($lokiResult.LogFile) { " &nbsp;<span style='font-size:8px;color:#445566'>log: $(_He $lokiResult.LogFile)</span>" } else { "" }
                $lokiHtml += $logNote
            } elseif ($offlineMode) {
                $lokiHtml = "<div class='art info'>IOC/YARA scan skipped  -  offline mode analyzes NDJSON telemetry logs, not PE/DLL artifacts. Thor/Loki YARA rules target binary headers (MZ/PE) and cannot match JSON text. To scan actual malware samples, run Thor/Loki directly against the original binaries or extracted artifacts.</div>"
            }

            $stepsHtml = ""; $si2=1
            foreach ($st in $nextSteps) { $stepsHtml += "<div class='step'><span class='step-n'>$si2.</span>$(_He $st)</div>`n"; $si2++ }
            $attrHtml = if ($attributionText -and $attributionText.Trim() -notmatch "^No Threat|^$") { "<div class='ablock'>$(_He $attributionText)</div>" } else { "<div class='art info'>No Tier-1 attribution from current indicators.</div>" }
            $actorBadgeHtml = if ($topActors -and $topActors.Count -gt 0) {
                $badges = ($topActors | ForEach-Object { "<span class='actbadge'>$(_He $_)</span>" }) -join ""
                "<div class='actarea'><div class='slbl'>POSSIBLE THREAT ATTRIBUTION</div><div class='actlist'>$badges</div></div>"
            } else { "" }

            $sysmonHtml = ""
            if ($sysmonTotal -gt 0) {
                $sysmonHtml  = "<div class='sec'><div class='stitle'>SYSMON API / INJECTION EVENTS</div>"
                $sysmonHtml += "<div class='finding warning'>$sysmonTotal total events &nbsp;($(_He ($sysmonEventIds -join ', ')))"
                if ($sysmonSrcProcs.Count-gt 0) { $sysmonHtml += " &nbsp;<button class='dp-btn' onclick=`"showPanel('srcprocs','SOURCE PROCS')`">$($sysmonSrcProcs.Count) src procs</button>" }
                if ($sysmonTgtProcs.Count-gt 0) { $sysmonHtml += " &nbsp;<button class='dp-btn hot' onclick=`"showPanel('tgtprocs','TARGET PROCS')`">$($sysmonTgtProcs.Count) tgt procs</button>" }
                if ($sysmonImages.Count -gt 0)  { $sysmonHtml += " &nbsp;<button class='dp-btn' onclick=`"showPanel('images','IMAGES LOADED')`">$($sysmonImages.Count) images</button>" }
                if ($syPairs.Count -gt 0)        { $sysmonHtml += " &nbsp;<button class='dp-btn hot' onclick=`"showPanel('pairs','SRC-TGT PAIRS','hot')`">$($syPairs.Count) src-tgt pairs</button>" }
                if ($sysmonRules.Count -gt 0)   { $sysmonHtml += " &nbsp;<button class='dp-btn' onclick=`"showPanel('rules','MITRE RULES')`">$($sysmonRules.Count) MITRE rules</button>" }
                if ($sysmonAccess.Count -gt 0)  { $sysmonHtml += " &nbsp;<button class='dp-btn warm' onclick=`"showPanel('access','GRANTED ACCESS')`">$($sysmonAccess.Count) access masks</button>" }
                $sysmonHtml += "</div>"
                if ($sysmonUnknownCt -gt 0) { $sysmonHtml += "<div class='finding critical'>[KERNEL-UNKNOWN] $sysmonUnknownCt injection event(s) with unresolved kernel-mode addresses in CallTrace -- possible rootkit or kernel exploit</div>" }
                foreach ($inj in $injUnique) {
                    $isSrc  = $sysmonSrcNames -contains $inj
                    $isTgt  = $sysmonTgtNames -contains $inj
                    $role   = if ($isSrc -and $isTgt) { "INJECTOR + VICTIM" } elseif ($isSrc) { "INJECTOR (source)" } else { "VICTIM (target)" }
                    $malC   = if ($fidMap[$inj]) { "$($fidMap[$inj].MalCount) malware samples" } else { "" }
                    $detail = (@($role, $malC) | Where-Object { $_ }) -join " | "
                    $sysmonHtml += "<div class='finding critical'>[UNIQUE] $(_He $inj) -- $(_He $detail)</div>"
                }
                foreach ($inj in $injRare) {
                    $isSrc  = $sysmonSrcNames -contains $inj
                    $isTgt  = $sysmonTgtNames -contains $inj
                    $role   = if ($isSrc -and $isTgt) { "INJECTOR + VICTIM" } elseif ($isSrc) { "INJECTOR (source)" } else { "VICTIM (target)" }
                    $malC   = if ($fidMap[$inj]) { "$($fidMap[$inj].MalCount) malware samples | $($fidMap[$inj].Found) legit" } else { "" }
                    $detail = (@($role, $malC) | Where-Object { $_ }) -join " | "
                    $sysmonHtml += "<div class='finding warning'>[RARE] $(_He $inj) -- $(_He $detail)</div>"
                }
                $sysmonHtml += "</div>"
            }

            $unknownSec = if ($vtUnknownHashes -and $vtUnknownHashes.Count -gt 0) {
                "<div class='sec'><div class='stitle'>NOT IN OFFLINE BASELINE</div><div class='art info' style='cursor:pointer' onclick=`"showPanel('unknown','UNKNOWN HASHES')`">$($vtUnknownHashes.Count) hash(es) - click to view</div></div>"
            } else { "" }

            $tsNow  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            $lpIcon = "&#128293;"
            $html = @"
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>LP Verdict: $agentHost</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0a0a14;font-family:'Courier New',monospace;color:#e0e0e0;height:100vh;display:flex;flex-direction:column;overflow:hidden}
#hdr{padding:12px 28px 8px;border-bottom:1px solid #1e3a5f;flex-shrink:0}
#hdr .sub{font-size:10px;color:#4a7a9b;letter-spacing:4px;margin-bottom:3px}
#hdr h1{font-size:17px;font-weight:bold;color:#7ec8e3}
#hdr .meta{font-size:10px;color:#445566;margin-top:2px}
#vbar{padding:10px 28px;display:flex;align-items:center;gap:20px;border-bottom:1px solid #1e3a5f;background:rgba(0,0,0,.25);flex-shrink:0}
.vbadge{font-size:16px;font-weight:bold;padding:5px 16px;border-radius:4px;border:2px solid $hvc;color:$hvc;background:rgba(0,0,0,.3)}
.cbadge{font-size:11px;padding:3px 10px;border-radius:3px;border:1px solid $hcc;color:$hcc}
.actarea{display:flex;flex-direction:column;gap:4px;max-width:380px}
.actlist{display:flex;flex-wrap:wrap;gap:5px}
.actbadge{font-size:10px;font-weight:bold;padding:2px 8px;border-radius:3px;border:1px solid #c4a000;color:#ffe066;background:rgba(255,200,0,.08);letter-spacing:1px}
.sarea{flex:1;max-width:280px}
.slbl{font-size:8px;color:#4a7a9b;letter-spacing:2px;margin-bottom:3px}
.sbarbg{background:#111;height:5px;border-radius:3px}
.sbar{height:5px;border-radius:3px;background:$sBcl;width:$($sBarW)%}
.snum{font-size:22px;font-weight:bold;color:$sBcl;margin-top:2px}
#layout{display:flex;flex:1;overflow:hidden}
#main{flex:1;overflow-y:auto;padding:18px 28px}
#detail{width:0;overflow:hidden;background:#0d1117;border-left:1px solid #1e3a5f;transition:width .2s ease;display:flex;flex-direction:column;flex-shrink:0}
#detail.open{width:360px}
#dp-hdr{padding:12px 14px;border-bottom:1px solid #1e3a5f;display:flex;justify-content:space-between;align-items:center;flex-shrink:0}
#dp-title{font-size:10px;color:#7ec8e3;letter-spacing:2px;font-weight:bold}
#dp-meta{font-size:9px;color:#445566}
#dp-close{background:none;border:1px solid #1e3a5f;color:#4a7a9b;padding:2px 8px;cursor:pointer;font-family:'Courier New',monospace;font-size:9px;border-radius:3px}
#dp-close:hover{border-color:#7ec8e3;color:#7ec8e3}
#dp-body{flex:1;overflow-y:auto;padding:10px 14px}
.dp-row{font-size:10px;padding:4px 6px;margin-bottom:2px;border-radius:2px;border-left:2px solid #1e3a5f;color:#99aabb;word-break:break-all;line-height:1.4}
.dp-row.hot{border-color:#e74c3c;color:#ff9999;background:rgba(231,76,60,.06)}
.dp-row.warm{border-color:#c0a020;color:#f0d060;background:rgba(192,160,32,.06)}
.dp-row:hover{background:rgba(255,255,255,.04)}
.sec{margin-bottom:20px}
.stitle{font-size:9px;color:#4a7a9b;letter-spacing:3px;border-bottom:1px solid #1e3a5f;padding-bottom:4px;margin-bottom:10px}
.finding{font-size:10px;padding:6px 10px;margin-bottom:4px;border-left:3px solid;border-radius:2px;background:rgba(255,255,255,.02);line-height:1.5}
.finding.critical{border-color:#e74c3c;color:#ff9999}
.finding.warning{border-color:#c0a020;color:#f0d060}
.finding.info{border-color:#1e3a5f;color:#99aabb}
.sg{display:grid;grid-template-columns:repeat(4,1fr);gap:7px}
.sb{background:#0d1117;border:1px solid #1e3a5f;border-radius:4px;padding:8px;text-align:center;transition:border-color .15s}
.sb:hover{border-color:#7ec8e3}
.sv{font-size:20px;font-weight:bold;color:#7ec8e3}
.sv.hot{color:#e74c3c}.sv.warm{color:#c0a020}
.sl{font-size:7px;color:#445566;margin-top:2px;letter-spacing:1px}
.art{font-size:10px;padding:4px 8px;margin-bottom:3px;border-radius:2px;line-height:1.4}
.art.unique{color:#ff6666;background:rgba(231,76,60,.08);border-left:2px solid #e74c3c}
.art.rare{color:#f0d060;background:rgba(192,160,32,.08);border-left:2px solid #c0a020}
.art.info{color:#99aabb;background:rgba(30,58,95,.2);border-left:2px solid #1e3a5f}
.hb{background:#0d1117;border:1px solid #1e3a5f;border-radius:4px;padding:10px;margin-bottom:7px}
.hi{color:#7ec8e3;font-size:10px;font-weight:bold;margin-bottom:5px}
.hl{font-size:9px;padding:2px 0;color:#99aabb}
.hl.malicious{color:#ff6666}.hl.good{color:#66cc88}.hl.tech{color:#f0d060}.hl.dr-hot{color:#ff6666}
.mt{display:inline-block;padding:2px 7px;margin:2px;border-radius:3px;font-size:9px}
.mt.unique{background:rgba(231,76,60,.2);color:#ff6666;border:1px solid #e74c3c}
.mt.rare{background:rgba(192,160,32,.2);color:#f0d060;border:1px solid #c0a020}
.mt.low{background:rgba(192,160,32,.1);color:#ddaa44;border:1px solid #886600}
.mt.plain{background:rgba(30,58,95,.3);color:#99aabb;border:1px solid #1e3a5f}
.step{font-size:10px;padding:5px 8px;margin-bottom:5px;border-left:2px solid #1e3a5f;color:#99aabb;line-height:1.5}
#ptree{overflow:auto;padding:8px 0;min-height:120px;max-height:none}
.pt-branch{display:flex;flex-direction:column}
.pt-children{display:flex;flex-direction:column;margin-left:14px;padding-left:10px;border-left:1px solid #1a2a3a}
.pt-row{display:flex;align-items:center;padding:3px 0}
.pnode{display:inline-flex;align-items:center;gap:5px;padding:4px 9px;border-radius:3px;border:1px solid #1e3a5f;background:#0d1117;cursor:pointer;transition:border-color .15s;max-width:280px;overflow:hidden}
.pnode:hover{border-color:#4a7a9b;background:#111827}
.pnode.unique{border-color:#e74c3c;background:rgba(231,76,60,.12)}
.pnode.rare,.pnode.suspicious{border-color:#c0a020;background:rgba(192,160,32,.08)}
.pn-name{font-size:10px;font-weight:bold;color:#7ec8e3;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:165px}
.pnode.unique .pn-name{color:#ff6666}
.pnode.rare .pn-name,.pnode.suspicious .pn-name{color:#f0d060}
.pn-cnt{font-size:8px;padding:1px 5px;border-radius:2px;background:#0a1428;color:#4a7a9b;flex-shrink:0}
.pn-risk{font-size:7px;padding:1px 4px;border-radius:2px;font-weight:bold;flex-shrink:0;letter-spacing:.5px}
.pn-risk.unique{background:#e74c3c;color:#fff}
.pn-risk.rare{background:#c0a020;color:#000}
.pn-risk.suspicious{background:#7a4010;color:#f0c070;border:1px solid #c08020}
.step-n{color:#4a7a9b;margin-right:6px;font-weight:bold}
.ablock{font-size:10px;color:#c0a020;background:rgba(192,160,32,.05);border:1px solid rgba(192,160,32,.2);border-radius:4px;padding:10px;line-height:1.6;white-space:pre-wrap}
.dp-btn{background:rgba(30,58,95,.4);border:1px solid #1e3a5f;color:#7ec8e3;padding:2px 8px;cursor:pointer;font-family:'Courier New',monospace;font-size:9px;border-radius:3px;margin-left:4px}
.dp-btn:hover{border-color:#7ec8e3}.dp-btn.hot{border-color:#e74c3c;color:#ff9999}
.two-col{display:grid;grid-template-columns:1fr 1fr;gap:0}
.col-l{padding-right:20px;border-right:1px solid #0d1117}
.col-r{padding-left:20px}
#ftr{font-size:8px;color:#1e3a5f;text-align:right;padding:6px 28px;border-top:1px solid #0d1117;flex-shrink:0}
.brand{color:#7ec8e3;font-weight:bold}
.da-cat{margin-bottom:10px}
.da-cat-hdr{font-size:9px;font-weight:bold;letter-spacing:1px;color:#4a7a9b;text-transform:uppercase;border-bottom:1px solid #0d1117;padding-bottom:3px;margin-bottom:5px}
.da-finding{display:grid;grid-template-columns:70px 1fr;grid-template-rows:auto auto;gap:1px 8px;padding:5px 8px;margin-bottom:4px;border-radius:2px;border-left:3px solid #333}
.da-crit{background:rgba(231,76,60,.08);border-left-color:#e74c3c}
.da-high{background:rgba(230,126,34,.07);border-left-color:#e67e22}
.da-med{background:rgba(241,196,15,.06);border-left-color:#f1c40f}
.da-low{background:rgba(52,152,219,.06);border-left-color:#3498db}
.da-sev-badge{font-size:8px;font-weight:bold;text-transform:uppercase;grid-row:1;grid-column:1;align-self:start;padding:1px 4px;border-radius:2px;white-space:nowrap}
.da-crit .da-sev-badge{color:#ff9999;background:rgba(231,76,60,.2)}
.da-high .da-sev-badge{color:#ffb366;background:rgba(230,126,34,.2)}
.da-med  .da-sev-badge{color:#ffe066;background:rgba(241,196,15,.2)}
.da-low  .da-sev-badge{color:#7ec8e3;background:rgba(52,152,219,.2)}
.da-title{font-size:9.5px;font-weight:bold;color:#c5d8e8;grid-row:1;grid-column:2}
.da-detail{font-size:8.5px;color:#7a9ab0;grid-row:2;grid-column:2;line-height:1.4;word-break:break-word}
.da-mitre{grid-row:3;grid-column:2;margin-top:2px}
.da-mbadge{font-size:7.5px;background:rgba(52,152,219,.15);color:#7ec8e3;border:1px solid #1e3a5f;padding:1px 5px;border-radius:2px;margin-right:3px;font-family:'Courier New',monospace}
.da-tbl{width:100%;border-collapse:collapse;font-size:9px;margin:5px 0 8px}
.da-tbl th{background:rgba(30,58,95,.4);color:#4a7a9b;padding:4px 8px;text-align:left;font-weight:bold;letter-spacing:1px;border-bottom:1px solid #1e3a5f}
.da-tbl td{padding:3px 8px;color:#99aabb;border-bottom:1px solid #0d1117;word-break:break-word}
.da-tbl tr.da-crit td{color:#ff9999;background:rgba(231,76,60,.05)}
.da-tbl tr.da-high td{color:#ffb366;background:rgba(230,126,34,.04)}
.da-tbl tr.da-med td{color:#ffe066;background:rgba(241,196,15,.03)}
.loki-meta{font-size:8px;color:#445566;margin-bottom:6px;word-break:break-all}
.loki-summary{display:flex;gap:10px;margin-bottom:8px}
.loki-cnt{font-size:8px;font-weight:bold;letter-spacing:1px;padding:2px 8px;border-radius:2px}
.loki-alert{background:rgba(231,76,60,.15);color:#ff9999;border:1px solid #e74c3c}
.loki-warn{background:rgba(230,126,34,.15);color:#ffb366;border:1px solid #e67e22}
.loki-ok{background:rgba(52,152,219,.1);color:#7a9ab0;border:1px solid #1e3a5f}
.loki-grp{margin-bottom:8px}
.loki-grp-hdr{font-size:8px;font-weight:bold;letter-spacing:1px;color:#ff9999;border-bottom:1px solid #1e3a5f;padding-bottom:2px;margin-bottom:4px}
.loki-grp-warn .loki-grp-hdr,.loki-grp-hdr.loki-grp-warn{color:#ffb366}
.loki-row{padding:4px 8px;margin-bottom:3px;border-radius:2px;border-left:3px solid #333}
.loki-row-alert{background:rgba(231,76,60,.06);border-left-color:#e74c3c}
.loki-row-warn{background:rgba(230,126,34,.05);border-left-color:#e67e22}
.loki-rule{font-size:9px;font-weight:bold;color:#c5d8e8;font-family:'Courier New',monospace}
.loki-score{font-size:8px;color:#7a9ab0;margin-left:6px}
.loki-file{font-size:8px;color:#7a9ab0;word-break:break-all;margin-top:2px}
.loki-desc{font-size:8px;color:#556677;font-style:italic;margin-top:1px}
.loki-more{font-size:8px;color:#445566;padding:2px 8px}
</style>
</head>
<body>
<div id="hdr">
  <div class="sub">LOADED-POTATO &nbsp;|&nbsp; ELASTIC ALERT AGENT &nbsp;|&nbsp; FORENSIC VERDICT</div>
  <h1>$lpIcon $agentHost</h1>
  <div class="meta">Window: $fromTs &nbsp; to &nbsp; $toTs</div>
</div>
<div id="vbar">
  <div class="vbadge">$verdict</div>
  <div class="cbadge">$confidence CONFIDENCE</div>
  <div class="sarea">
    <div class="slbl">RISK SCORE</div>
    <div class="sbarbg"><div class="sbar"></div></div>
    <div class="snum">$score</div>
  </div>
  <div style="font-size:10px;color:#445566">Unique-to-Malware: $($directUnique.Count + $uniqueMatches.Count) &nbsp;|&nbsp; Rare: $($directRare.Count + $rareMatches.Count) &nbsp;|&nbsp; <span style="color:#4a7a9b">Click any stat to drill down</span></div>
  $actorBadgeHtml
</div>
<div id="layout">
  <div id="main">
    <div class="sec"><div class="stitle">FORENSIC SUMMARY &nbsp;<span style="font-size:8px;color:#445566;letter-spacing:0;font-weight:normal">click any box to see full list</span></div>$statsHtml</div>
    $(if($fHtml.Trim()){"<div class='sec'><div class='stitle'>KEY FINDINGS</div>$fHtml</div>"}else{""})
    $(if($ptNodes -and $ptNodes.Count-gt 0){"<div class='sec'><div class='stitle'>PROCESS CHAIN &nbsp;<span style='font-size:8px;color:#445566;letter-spacing:0;font-weight:normal'>click any node to view details</span></div><div id='ptree'></div></div>"}else{""})
    $sysmonHtml
    $(if($mitreHtml){"<div class='sec'><div class='stitle'>MITRE ATT&amp;CK TECHNIQUES</div>$mitreHtml</div>"}else{""})
    $(if($deepAnalysis -and $deepAnalysis.Html){"<div class='sec'><div class='stitle'>BEHAVIORAL DEEP ANALYSIS <span style='font-size:8px;color:#445566;letter-spacing:0;font-weight:normal'>$($deepAnalysis.CriticalCount) critical &nbsp;|&nbsp; $($deepAnalysis.HighCount) high &nbsp;|&nbsp; $($deepAnalysis.FindingCount) total findings</span></div>$($deepAnalysis.Html)</div>"}else{""})
    $(if($lokiHtml){"<div class='sec'><div class='stitle'>IOC/YARA SCAN <span style='font-size:8px;color:#445566;letter-spacing:0;font-weight:normal'>$(if($lokiResult -and $lokiResult.ScannerLabel){$(_He $lokiResult.ScannerLabel)}else{'Thor / Loki'})</span></div>$lokiHtml</div>"}else{""})
    <div class="two-col">
      <div class="col-l">
        $(if($fidHtml.Trim()){"<div class='sec'><div class='stitle'>DIRECT ARTIFACT FIDELITY</div>$fidHtml</div>"}else{""})
        $(if($unsignedProcs.Count-gt 0){"<div class='sec'><div class='stitle'>UNSIGNED / UNTRUSTED PROCESSES</div><div class='art info' style='cursor:pointer' onclick=`"showPanel('unsigned','UNSIGNED PROCS')`">$($unsignedProcs.Count) process(es) - click to view</div></div>"}else{""})
        $(if($suspParentChild.Count-gt 0){"<div class='sec'><div class='stitle'>SUSPICIOUS PARENT-CHILD CHAINS</div>" + ($suspParentChild | ForEach-Object {"<div class='art unique'>$(_He $_)</div>"}) -join "`n" + "</div>"}else{""})
        <div class="sec"><div class="stitle">THREAT ATTRIBUTION</div>$attrHtml</div>
      </div>
      <div class="col-r">
        <div class="sec"><div class="stitle">RECOMMENDED NEXT STEPS</div>$stepsHtml</div>
      </div>
    </div>
    <div class="sec"><div class="stitle">VT HASH ENRICHMENT</div>$vtHtml</div>
    $unknownSec
  </div>
  <div id="detail">
    <div id="dp-hdr">
      <div><div id="dp-title"></div><div id="dp-meta"></div></div>
      <button id="dp-close" onclick="closePanel()">CLOSE</button>
    </div>
    <div id="dp-body"></div>
  </div>
</div>
<div id="ftr">Generated by <span class="brand">Loaded-Potato</span> &nbsp;|&nbsp; $tsNow</div>
<script>
var D = {
  alerts:$jsAlerts,
  procs:$jsProcs,
  ips:$jsIPs,
  dns:$jsDns,
  files:$jsFiles,
  reg:$jsReg,
  tasks:$jsTasks,
  pscmds:$jsPS,
  shellcmds:$jsShell,
  npshell:$jsNonPsShell,
  shellbyproc:$jsShellByProc,
  unsigned:$jsUnsigned,
  susppc:$jsSuspPC,
  lolbins:$jsLolbins,
  loldrivers:$jsLolDrivers,
  srcprocs:$jsSrcProcs,
  tgtprocs:$jsTgtProcs,
  images:$jsImages,
  pairs:$jsPairs,
  rules:$jsRules,
  access:$jsAccess,
  unique_art:$jsUnique,
  rare_art:$jsRareArt,
  unknown:$jsUnknown,
  sysmon:$jsSrcProcs,
  behavior:$jsBehavior
};
var procTree=$jsProcTree;
function esc(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function showPanel(key,title,defaultCls){
  var items=D[key]||[];
  document.getElementById('dp-title').textContent=title;
  document.getElementById('dp-meta').textContent=items.length+' items';
  var html='';
  for(var i=0;i<items.length;i++){
    var s=items[i];
    var cls=s.indexOf('[UNIQUE]')>=0?'hot':s.indexOf('[RARE]')>=0?'warm':(defaultCls||'');
    html+='<div class="dp-row'+(cls?' '+cls:'')+'">' +esc(s)+'</div>';
  }
  if(!html){html='<div class="dp-row" style="color:#445566">No items</div>';}
  document.getElementById('dp-body').innerHTML=html;
  document.getElementById('detail').className='open';
}
function closePanel(){document.getElementById('detail').className='';}
function showArtPanel(evt,type,title,procName){
  evt.stopPropagation();
  var node=null;
  for(var i=0;i<procTree.length;i++){if(procTree[i].n===procName){node=procTree[i];break;}}
  document.getElementById('dp-title').textContent=procName+' \u2014 '+title;
  var items=[],html='';
  if(type==='alerts'){
    // Prepend per-process risk/severity header, then show rule list
    var sevLine=(node&&node.topSeverity&&node.topSeverity.length)?'Severity: '+node.topSeverity.join(' | '):'';
    var riskLine=(node&&node.maxRisk>0)?'Max risk score: '+node.maxRisk:'';
    var hdr=[];if(sevLine)hdr.push(sevLine);if(riskLine)hdr.push(riskLine);
    items=hdr.concat(D['alerts']||[]);
  } else if(type==='net'&&node){
    items=(node.topIPs||[]).concat(node.topDNS||[]);
    if(items.length===0&&node.net>0)items=['('+node.net+' connections - top destinations not captured in aggregation)'];
  } else if(type==='files'&&node){
    var hdr2=[];
    if(node.maxMlScore!=null&&node.maxMlScore>0)hdr2.push('[ML SCORE] '+node.maxMlScore+'% malware confidence (endpointpe-v4)');
    if(node.maxEntropy!=null&&node.maxEntropy>0)hdr2.push('[ENTROPY] max '+node.maxEntropy+' (>7.0 = packed/encrypted)');
    items=hdr2.concat(node.topFiles||[]);
    if(items.length===0&&node.files>0)items=['('+node.files+' file events - top names not captured in aggregation)'];
  } else if(type==='reg'&&node){
    items=node.topKeys||[];
    if(items.length===0&&node.reg>0)items=(D['reg']||[]).slice(0,20);
    if(items.length===0&&node.reg>0)items=['('+node.reg+' registry events - top keys not captured in aggregation)'];
  } else if(type==='dll'&&node){
    var evas=(node.topDllEvasions||[]).map(function(ev){return '[EVASION] '+ev;});
    items=evas.concat(node.topDlls||[]);
    if(items.length===0&&node.dll>0)items=['('+node.dll+' library loads - top DLL names not captured in aggregation)'];
  } else if(type==='api'&&node){
    // Show summaries first, then behaviors, targets, memory protection, memory regions
    var summ=(node.topSummaries||[]).map(function(s){return '[CALL] '+s;});
    var tgts=(node.topTargets||[]).filter(function(t){
      return !(node.topSummaries||[]).some(function(s){return s.indexOf(t)>=0;});
    }).map(function(t){return '[TARGET] '+t;});
    var beh=(node.topBehaviors||[]).map(function(b){return '[BEHAVIOR] '+b;});
    var prot=(node.topMemProt||[]).map(function(p){return '[MEM PROT] '+p+(p==='RCX'||p==='RWX'?' \u26a0 suspicious':'');});
    var mem=(node.topMemPaths||[]).map(function(m){return '[MEM REGION] '+m;});
    var apis=(node.topApis||[]).filter(function(a){
      return !(node.topSummaries||[]).some(function(s){return s.indexOf(a)>=0;});
    }).map(function(a){return '[API] '+a;});
    items=summ.concat(tgts).concat(beh).concat(prot).concat(mem).concat(apis);
    if(items.length===0&&node.api>0)items=['('+node.api+' API/behavioral events)'];
  }
  document.getElementById('dp-meta').textContent=items.length+' items';
  for(var i=0;i<items.length;i++){
    var s=items[i];
    var cls=s.indexOf('[UNIQUE]')>=0?'hot':s.indexOf('[RARE]')>=0?'warm':'';
    html+='<div class="dp-row'+(cls?' '+cls:'')+'">' +esc(s)+'</div>';
  }
  if(!html)html='<div class="dp-row" style="color:#445566">No items captured</div>';
  document.getElementById('dp-body').innerHTML=html;
  document.getElementById('detail').className='open';
}
function showProcPanel(n){
  var node=null;
  for(var i=0;i<procTree.length;i++){if(procTree[i].n===n){node=procTree[i];break;}}
  if(!node)return;
  document.getElementById('dp-title').textContent=node.n;
  var metaParts=['count: '+node.c];
  if(node.r&&node.r!=='clean')metaParts.push('risk: '+node.r.toUpperCase());
  if(node.integ)metaParts.push('integrity: '+node.integ.toUpperCase());
  document.getElementById('dp-meta').textContent=metaParts.join(' | ');
  var html='';
  if(node.susp)html+='<div class="dp-row hot">&#9888; Created suspended  -  process hollowing / UAC bypass indicator</div>';
  if(node.e){html+='<div class="dp-row"><span style="color:#445566">exe:</span> '+esc(node.e)+'</div>';}
  if(node.h){html+='<div class="dp-row"><span style="color:#445566">sha256:</span> '+esc(node.h)+'</div>';}
  if(node.p&&node.p.length){html+='<div class="dp-row"><span style="color:#445566">parent(s):</span> '+esc(node.p.join(', '))+'</div>';}
  if(node.cmds&&node.cmds.length){
    html+='<div class="dp-row" style="color:#445566;margin-top:4px">command lines:</div>';
    for(var j=0;j<node.cmds.length;j++){html+='<div class="dp-row" style="font-family:monospace;font-size:9px;word-break:break-all">'+esc(node.cmds[j])+'</div>';}
  }
  if(!html){html='<div class="dp-row" style="color:#445566">No details</div>';}
  document.getElementById('dp-body').innerHTML=html;
  document.getElementById('detail').className='open';
}
(function buildProcTree(){
  var el=document.getElementById('ptree');
  if(!el||!procTree||!procTree.length)return;
  var byName={};
  for(var i=0;i<procTree.length;i++){byName[procTree[i].n]=procTree[i];}
  // Add stub nodes for referenced parents not in the tree
  for(var i=0;i<procTree.length;i++){
    for(var pi=0;pi<procTree[i].p.length;pi++){
      var par=procTree[i].p[pi];
      if(par&&!byName[par]){
        byName[par]={n:par,c:0,r:'clean',p:[],e:'',h:'',cmds:[],integ:'',susp:false,alerts:0,maxRisk:0,topSeverity:[],files:0,maxMlScore:null,maxEntropy:null,net:0,reg:0,topKeys:[],dll:0,topDllEvasions:[],api:0,topFiles:[],topIPs:[],topDNS:[],topDlls:[],topApis:[],topBehaviors:[],topSummaries:[],topTargets:[],topMemProt:[],topMemPaths:[],stub:true};
      }
    }
  }
  var allNodes=Object.keys(byName).map(function(k){return byName[k];});
  var children={},hasParent={};
  for(var i=0;i<allNodes.length;i++){
    var node=allNodes[i];
    for(var pi=0;pi<node.p.length;pi++){
      var par=node.p[pi];
      if(byName[par]&&par!==node.n){
        if(!children[par])children[par]=[];
        if(children[par].indexOf(node.n)<0)children[par].push(node.n);
        hasParent[node.n]=true;break;
      }
    }
  }
  var riskRank={unique:0,suspicious:1,rare:2,clean:3};
  function subtreeHasRisk(name,vis){
    if(vis[name])return false;vis[name]=true;
    var node=byName[name];if(!node)return false;
    if(node.r==='unique'||node.r==='rare'||node.r==='suspicious')return true;
    var kids=children[name]||[];
    for(var k=0;k<kids.length;k++){if(subtreeHasRisk(kids[k],vis))return true;}
    return false;
  }
  var roots=[];
  var names=Object.keys(byName);
  for(var i=0;i<names.length;i++){if(!hasParent[names[i]])roots.push(names[i]);}
  var rr=roots.filter(function(r){return subtreeHasRisk(r,{});});
  if(rr.length>0)roots=rr;
  roots.sort(function(a,b){return (riskRank[byName[a].r]||3)-(riskRank[byName[b].r]||3)||byName[b].c-byName[a].c;});

  // BFS layout
  var depth={},row={},depthCount={};
  function layout(name,d){
    if(depth[name]!==undefined)return;
    depth[name]=d;
    if(!depthCount[d])depthCount[d]=0;
    row[name]=depthCount[d]++;
    var kids=(children[name]||[]).slice().sort(function(a,b){
      return (riskRank[(byName[a]||{}).r]||3)-(riskRank[(byName[b]||{}).r]||3);
    });
    for(var k=0;k<kids.length;k++)layout(kids[k],d+1);
  }
  for(var r=0;r<roots.length;r++)layout(roots[r],0);

  var BW=220,BH=110,HG=80,VG=14;
  var layoutNames=Object.keys(depth);
  var maxD=0,maxR=0;
  for(var i=0;i<layoutNames.length;i++){
    if(depth[layoutNames[i]]>maxD)maxD=depth[layoutNames[i]];
    if(row[layoutNames[i]]>maxR)maxR=row[layoutNames[i]];
  }
  var W=(maxD+1)*(BW+HG)+20,H=(maxR+1)*(BH+VG)+20;
  function nx(n){return depth[n]*(BW+HG)+8;}
  function ny(n){return row[n]*(BH+VG)+8;}

  // SVG connectors
  var svg='';
  for(var i=0;i<layoutNames.length;i++){
    var nm=layoutNames[i],kids=children[nm]||[];
    var isHot=byName[nm]&&(byName[nm].r==='unique'||byName[nm].r==='suspicious');
    for(var k=0;k<kids.length;k++){
      var kid=kids[k];
      if(depth[kid]===undefined)continue;
      var x1=nx(nm)+BW,y1=ny(nm)+BH/2,x2=nx(kid),y2=ny(kid)+BH/2,mx=(x1+x2)/2;
      var childHot=byName[kid]&&(byName[kid].r==='unique'||byName[kid].r==='suspicious');
      var sc=(isHot||childHot)?'#e74c3c':'#1e3a5f';
      var sw=(isHot||childHot)?'2':'1.5';
      svg+='<path d="M'+x1+','+y1+' C'+mx+','+y1+' '+mx+','+y2+' '+x2+','+y2
          +'" stroke="'+sc+'" stroke-width="'+sw+'" fill="none" stroke-dasharray="'+(isHot&&childHot?'none':'4,3')+'"/>';
      svg+='<polygon points="'+x2+','+y2+' '+(x2-7)+','+(y2-3)+' '+(x2-7)+','+(y2+3)+'" fill="'+sc+'"/>';
    }
  }

  // Node boxes
  var nodes='';
  function rCol(r){
    if(r==='unique')    return{b:'#e74c3c',bg:'rgba(231,76,60,.18)',nm:'#ff8888',badge:'<span style="font-size:7px;background:#e74c3c;color:#fff;padding:1px 5px;border-radius:2px;font-weight:bold;margin-left:3px;letter-spacing:.5px">MALWARE</span>'};
    if(r==='rare')      return{b:'#c0a020',bg:'rgba(192,160,32,.12)',nm:'#f0d060',badge:'<span style="font-size:7px;background:#c0a020;color:#000;padding:1px 5px;border-radius:2px;font-weight:bold;margin-left:3px">RARE</span>'};
    if(r==='suspicious')return{b:'#7a4010',bg:'rgba(122,64,16,.12)',nm:'#f0c070',badge:'<span style="font-size:7px;background:#7a4010;color:#f0c070;padding:1px 5px;border-radius:2px;font-weight:bold;margin-left:3px;border:1px solid #c08020">SUSP</span>'};
    return{b:'#1e3a5f',bg:'rgba(13,17,23,.85)',nm:'#7ec8e3',badge:''};
  }
  for(var i=0;i<layoutNames.length;i++){
    var nm=layoutNames[i],node=byName[nm];if(!node)continue;
    var c=rCol(node.r||'clean');
    var x=nx(nm),y=ny(nm);
    var sn=nm.length>26?nm.substring(0,24)+'..':nm;
    var sh=node.h?node.h.substring(0,14)+'...':'';
    var exeDir=node.e?(node.e.length>30?'..'+node.e.slice(-28):node.e):'';
    // Artifact chips
    var chips='';
    if(node.alerts&&node.alerts>0) chips+='<span style="font-size:7px;color:#ff8888;background:rgba(231,76,60,.15);border:1px solid #e74c3c;padding:1px 5px;border-radius:10px;margin-right:3px;cursor:pointer" onclick="showArtPanel(event,\'alerts\',\'ALERTS\',\''+nm.replace(/\\/g,'\\\\').replace(/'/g,"\\'")+'\')">&#9888; '+node.alerts+'</span>';
    if(node.net&&node.net>0)     chips+='<span style="font-size:7px;color:#7ec8e3;background:rgba(30,58,95,.3);border:1px solid #1e3a5f;padding:1px 5px;border-radius:10px;margin-right:3px;cursor:pointer" onclick="showArtPanel(event,\'net\',\'NETWORK\',\''+nm.replace(/\\/g,'\\\\').replace(/'/g,"\\'")+'\')">&#127760; '+node.net+'</span>';
    if(node.files&&node.files>0) chips+='<span style="font-size:7px;color:#99aabb;background:rgba(30,58,95,.2);border:1px solid #1e3a5f;padding:1px 5px;border-radius:10px;margin-right:3px;cursor:pointer" onclick="showArtPanel(event,\'files\',\'FILES\',\''+nm.replace(/\\/g,'\\\\').replace(/'/g,"\\'")+'\')">&#128196; '+node.files+'</span>';
    if(node.reg&&node.reg>0)     chips+='<span style="font-size:7px;color:#99aabb;background:rgba(30,58,95,.2);border:1px solid #1e3a5f;padding:1px 5px;border-radius:10px;margin-right:3px;cursor:pointer" onclick="showArtPanel(event,\'reg\',\'REGISTRY\',\''+nm.replace(/\\/g,'\\\\').replace(/'/g,"\\'")+'\')">&#128273; '+node.reg+'</span>';
    if(node.dll&&node.dll>0)     chips+='<span style="font-size:7px;color:#c39ef0;background:rgba(80,30,120,.25);border:1px solid #7b3fa0;padding:1px 5px;border-radius:10px;margin-right:3px;cursor:pointer" onclick="showArtPanel(event,\'dll\',\'LIBRARIES\',\''+nm.replace(/\\/g,'\\\\').replace(/'/g,"\\'")+'\')">&#128218; '+node.dll+'</span>';
    if(node.api&&node.api>0)     chips+='<span style="font-size:7px;color:#f0c060;background:rgba(90,60,0,.25);border:1px solid #8a6000;padding:1px 5px;border-radius:10px;margin-right:3px;cursor:pointer" onclick="showArtPanel(event,\'api\',\'API CALLS\',\''+nm.replace(/\\/g,'\\\\').replace(/'/g,"\\'")+'\')">&#9881; '+node.api+'</span>';
    var safeN=nm.replace(/\\/g,'\\\\').replace(/'/g,"\\'");
    var stubStyle=node.stub?'opacity:0.55;border-style:dashed;':'';
    nodes+='<div style="position:absolute;left:'+x+'px;top:'+y+'px;width:'+BW+'px;height:'+BH+'px;'
      +'border:1px solid '+c.b+';border-radius:5px;background:'+c.bg+';'
      +stubStyle+'cursor:pointer;padding:7px 9px;box-sizing:border-box;transition:box-shadow .15s" '
      +'onclick="showProcPanel(\''+safeN+'\')" '
      +'onmouseover="this.style.boxShadow=\'0 0 0 2px '+c.b+'\'" '
      +'onmouseout="this.style.boxShadow=\'none\'">';
    // Row 1: name + badge + count + integrity + suspended
    var integBadge='';
    if(node.integ==='system') integBadge='<span style="font-size:6px;background:#8b0000;color:#fff;padding:1px 4px;border-radius:2px;margin-left:3px;font-weight:bold;letter-spacing:.3px">SYSTEM</span>';
    else if(node.integ==='high') integBadge='<span style="font-size:6px;background:#7a4010;color:#ffa040;padding:1px 4px;border-radius:2px;margin-left:3px;font-weight:bold">HIGH</span>';
    var suspBadge=node.susp?'<span style="font-size:6px;background:#2a0060;color:#c080ff;padding:1px 4px;border-radius:2px;margin-left:3px;font-weight:bold" title="Created suspended (process hollowing/UAC bypass indicator)">SUSP&#8599;</span>':'';
    nodes+='<div style="display:flex;align-items:center;margin-bottom:3px">'
      +'<span style="font-size:10px;font-weight:bold;color:'+c.nm+';overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:130px" title="'+esc(nm)+'">'+esc(sn)+'</span>'
      +c.badge+integBadge+suspBadge
      +(node.c>0?'<span style="font-size:8px;background:#0a1428;color:#4a7a9b;padding:1px 5px;border-radius:2px;margin-left:auto;flex-shrink:0">'+node.c+'x</span>':'')
      +'</div>';
    // Row 2: exe path
    if(exeDir) nodes+='<div style="font-size:7px;color:#2a4060;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-bottom:2px" title="'+esc(node.e)+'">'+esc(exeDir)+'</div>';
    // Row 3: hash
    if(sh) nodes+='<div style="font-size:7px;font-family:monospace;color:'+(node.r==='unique'?'#882222':'#1e3a5f')+';margin-bottom:4px">'+esc(sh)+'</div>';
    // Row 4: artifact chips
    if(chips) nodes+='<div style="display:flex;flex-wrap:wrap;gap:2px">'+chips+'</div>';
    nodes+='</div>';
  }

  el.innerHTML='<div style="position:relative;min-width:'+W+'px;min-height:'+H+'px">'
    +'<svg style="position:absolute;top:0;left:0;pointer-events:none;overflow:visible" width="'+W+'" height="'+H+'"><g>'+svg+'</g></svg>'
    +nodes+'</div>';
})();
document.addEventListener('keydown',function(e){if(e.key==='Escape')closePanel();});
</script>
</body></html>
"@
            $html | Out-File -FilePath $rpFile -Encoding UTF8
            Write-Host "  HTML report: $rpFile" -ForegroundColor DarkCyan
        } catch {
            Write-Host "  [warn] HTML report failed: $_" -ForegroundColor DarkGray
        }

        return [PSCustomObject]@{
            Verdict    = $verdict
            Confidence = $confidence
            RiskScore  = $score
            Host       = $agentHost
            Window     = "$fromTs --> $toTs"
            Findings   = $findings.ToArray()
            NextSteps  = $nextSteps.ToArray()
        }

    } else {
        # -----------------------------------------------------------------------
        # LEGACY ALERT-CONTEXT MODE (programmatic callers passing $AlertContext)
        # -----------------------------------------------------------------------
        foreach ($k in @('AnomalousPorts','AnomalousIPs','AnomalousDNS','AnomalousIndicators','AdditionalHashes','MasqueradeMatches')) {
            if (-not $AlertContext.ContainsKey($k)) { $AlertContext[$k] = @() }
        }

        Write-Host "`n[Elastic Alert Agent] Looking up hashes in offline VT baseline..." -ForegroundColor DarkCyan
        $vtEnrichment   = [System.Text.StringBuilder]::new()
        $vtUnknownCtx   = [System.Collections.Generic.List[string]]::new()
        if (-not [string]::IsNullOrWhiteSpace($AlertContext.ProcessHash)) {
            $block = Format-HashEnrichment -Hash $AlertContext.ProcessHash -Label "Alert Process: $($AlertContext.ProcessName)"
            if ($block -match "NOT IN OFFLINE BASELINE") {
                [void]$vtUnknownCtx.Add($AlertContext.ProcessHash)
            } else {
                Write-Host "  $($AlertContext.ProcessName) ($($AlertContext.ProcessHash.Substring(0,16))...):" -NoNewline
                if ($block -match "Category\s*:\s*malicious") { Write-Host " MALICIOUS" -ForegroundColor Red }
                else { $catMatch = [regex]::Match($block,'Category\s*:\s*(\S+)'); Write-Host " $($catMatch.Groups[1].Value)" -ForegroundColor Green }
                [void]$vtEnrichment.AppendLine($block)
            }
        }
        $idx = 1
        foreach ($h in $AlertContext.AdditionalHashes) {
            if ([string]::IsNullOrWhiteSpace($h)) { continue }
            $block = Format-HashEnrichment -Hash $h -Label "Additional Hash #$idx"
            if ($block -match "NOT IN OFFLINE BASELINE") {
                [void]$vtUnknownCtx.Add($h)
            } else {
                Write-Host "  Additional[$idx] ($($h.Substring(0,[Math]::Min(16,$h.Length)))...):" -NoNewline
                if ($block -match "Category\s*:\s*malicious") { Write-Host " MALICIOUS" -ForegroundColor Red }
                else { $catMatch = [regex]::Match($block,'Category\s*:\s*(\S+)'); Write-Host " $($catMatch.Groups[1].Value)" -ForegroundColor Green }
                [void]$vtEnrichment.AppendLine($block)
            }
            $idx++
        }
        if ($vtUnknownCtx.Count -gt 0) {
            Write-Host "  NOT IN OFFLINE BASELINE ($($vtUnknownCtx.Count) hash(es) - never seen or not yet pulled from VT):" -ForegroundColor DarkGray
            $vtUnknownCtx | ForEach-Object { Write-Host "    - $_" -ForegroundColor DarkGray }
        }

        $attrObs = [System.Collections.Generic.List[string]]::new()
        if (-not [string]::IsNullOrWhiteSpace($AlertContext.RuleName)) { [void]$attrObs.Add($AlertContext.RuleName) }
        foreach ($x in $AlertContext.AnomalousDNS)        { if ($x) { [void]$attrObs.Add($x) } }
        foreach ($x in $AlertContext.AnomalousIPs)        { if ($x) { [void]$attrObs.Add($x) } }
        foreach ($x in $AlertContext.AnomalousIndicators) { if ($x) { [void]$attrObs.Add($x) } }
        $attributionText = "THREAT ATTRIBUTION: Insufficient indicators."
        if ($attrObs.Count -gt 0) {
            Write-Host "[Elastic Alert Agent] Running threat attribution..." -ForegroundColor DarkCyan
            try {
                $attrResults = Get-ThreatAttribution -Observations $attrObs.ToArray() -PassThru -MinRarityScore 90 -ErrorAction Stop
                $tier1 = @($attrResults | Where-Object { $_.MatchCount -gt 1 } | Sort-Object MatchCount -Descending | Select-Object -First 5)
                if ($tier1.Count -gt 0) {
                    $sb2 = [System.Text.StringBuilder]::new()
                    [void]$sb2.AppendLine("THREAT ATTRIBUTION (high-rarity indicator matches, MinRarityScore=90):")
                    foreach ($r in $tier1) {
                        [void]$sb2.AppendLine("  [$($r.Type)] $($r.Actor) -- $($r.MatchCount) matched indicator(s):")
                        foreach ($m in $r.Matches) { [void]$sb2.AppendLine("    - [$($m.Source)] $($m.Indicator)") }
                    }
                    $attributionText = $sb2.ToString()
                    Write-Host "  Attribution: $($tier1.Count) Tier-1 match(es)" -ForegroundColor Yellow
                } else { $attributionText = "THREAT ATTRIBUTION: No high-confidence multi-indicator matches." }
            } catch { $attributionText = "THREAT ATTRIBUTION: Unavailable." }
        }

        $sigStatus = if ($AlertContext.ProcessSigned) { if ($AlertContext.ProcessTrusted) { "Signed + Verified" } else { "Signed but NOT Verified" } } else { "UNSIGNED" }
    }

    # -----------------------------------------------------------------------
    # LOCAL VERDICT ENGINE  - deterministic scoring (no external callouts)
    # -----------------------------------------------------------------------
    Write-Host "`n[Elastic Alert Agent] Running local verdict engine..." -ForegroundColor DarkCyan

    $lScore    = 0
    $lFindings = [System.Collections.Generic.List[string]]::new()
    $lSteps    = [System.Collections.Generic.List[string]]::new()

    # VT baseline outcome flags
    $vtText      = $vtEnrichment.ToString()
    $vtMalicious = $vtText -match "Baseline Category\s*:.*[Mm]alicious"
    $vtUnknown   = $vtUnknownCtx.Count -gt 0

    if ($vtMalicious) {
        $lScore += 50
        $lFindings.Add("CRITICAL: Hash confirmed malicious in VT offline baseline (+50 pts)")
        $lSteps.Add("Immediately isolate host - confirmed malware binary")
        $lSteps.Add("Collect full memory dump and volatile artifacts before remediation")
    }
    if ($vtUnknown -and -not $vtMalicious) {
        $lScore += 10
        $lFindings.Add("$($vtUnknownCtx.Count) hash(es) not in VT offline baseline - unclassified binary (+10 pts)")
        $lSteps.Add("Submit unknown hash(es) to VirusTotal and internal sandboxing for manual review")
    }

    # Masquerade detection (unsigned process sharing name with known-signed binary)
    if ($AlertContext.MasqueradeMatches -and $AlertContext.MasqueradeMatches.Count -gt 0) {
        $lScore += 40
        $matchStr = ($AlertContext.MasqueradeMatches | ForEach-Object { "'$($_.LegitSigner)' ($($_.Count)x)" }) -join ", "
        $lFindings.Add("CRITICAL: Masquerade detected - unsigned '$($AlertContext.ProcessName)' impersonates: $matchStr (+40 pts)")
        $lSteps.Add("Quarantine masquerading binary and trace execution chain back to delivery mechanism")
    }

    # Signature status
    if (-not $AlertContext.ProcessSigned) {
        $lScore += 5
        $lFindings.Add("Process is unsigned: $($AlertContext.ProcessName) (+5 pts)")
    } elseif (-not $AlertContext.ProcessTrusted) {
        $lScore += 3
        $lFindings.Add("Process is signed but certificate is NOT verified/trusted (+3 pts)")
    }

    # Know Normal - parent frequency
    if ($AlertContext.ContainsKey('ParentFrequencyPct')) {
        if ($AlertContext.ParentFrequencyPct -lt 2) {
            $lScore += 15
            $lFindings.Add("Very rare parent-child: '$($AlertContext.ParentProcess)' -> '$($AlertContext.ProcessName)' (env freq=$($AlertContext.ParentFrequencyPct)%) (+15 pts)")
            $lSteps.Add("Investigate rare execution chain: '$($AlertContext.ParentProcess)' spawning '$($AlertContext.ProcessName)'")
        } elseif ($AlertContext.ParentFrequencyPct -lt 10) {
            $lScore += 8
            $lFindings.Add("Unusual parent-child: '$($AlertContext.ParentProcess)' -> '$($AlertContext.ProcessName)' (env freq=$($AlertContext.ParentFrequencyPct)%) (+8 pts)")
        }
    }

    # Know Normal - path frequency
    if ($AlertContext.ContainsKey('PathFrequencyPct') -and $AlertContext.PathFrequencyPct -lt 5 -and $AlertContext.ProcessPath) {
        $lScore += 10
        $lFindings.Add("Rare execution path (env freq=$($AlertContext.PathFrequencyPct)%): $($AlertContext.ProcessPath) (+10 pts)")
    }

    # Network anomalies
    if ($AlertContext.AnomalousIPs -and $AlertContext.AnomalousIPs.Count -gt 0) {
        $ipScore = [Math]::Min(20, $AlertContext.AnomalousIPs.Count * 5)
        $lScore += $ipScore
        $lFindings.Add("$($AlertContext.AnomalousIPs.Count) anomalous external IP(s): $($AlertContext.AnomalousIPs -join ', ') (+$ipScore pts)")
        $lSteps.Add("Block and investigate anomalous external IPs: $($AlertContext.AnomalousIPs -join ', ')")
    }
    if ($AlertContext.AnomalousDNS -and $AlertContext.AnomalousDNS.Count -gt 0) {
        $dnsScore = [Math]::Min(20, $AlertContext.AnomalousDNS.Count * 5)
        $lScore += $dnsScore
        $lFindings.Add("$($AlertContext.AnomalousDNS.Count) anomalous DNS query(s): $($AlertContext.AnomalousDNS -join ', ') (+$dnsScore pts)")
        $lSteps.Add("Review DNS/C2 traffic and block resolution for: $($AlertContext.AnomalousDNS -join ', ')")
    }
    if ($AlertContext.AnomalousPorts -and $AlertContext.AnomalousPorts.Count -gt 0) {
        $portScore = [Math]::Min(10, $AlertContext.AnomalousPorts.Count * 3)
        $lScore += $portScore
        $lFindings.Add("$($AlertContext.AnomalousPorts.Count) anomalous port(s): $($AlertContext.AnomalousPorts -join ', ') (+$portScore pts)")
    }
    if ($AlertContext.AnomalousIndicators -and $AlertContext.AnomalousIndicators.Count -gt 0) {
        $indScore = [Math]::Min(15, $AlertContext.AnomalousIndicators.Count * 5)
        $lScore += $indScore
        $lFindings.Add("$($AlertContext.AnomalousIndicators.Count) additional anomalous indicator(s): $($AlertContext.AnomalousIndicators -join ', ') (+$indScore pts)")
    }

    # Threat attribution (multi-indicator match from local threat intel DB)
    if ($attributionText -match "Tier-1") {
        $lScore += 20
        $lFindings.Add("Multi-indicator threat attribution match - see attribution detail (+20 pts)")
        $lSteps.Add("Review threat attribution details and cross-reference with threat intelligence team")
    }

    # Elevated environment unsigned rate
    if ($AlertContext.ContainsKey('UnsignedPct') -and $AlertContext.UnsignedPct -gt 20) {
        $lScore += 5
        $lFindings.Add("High environment unsigned execution rate ($($AlertContext.UnsignedPct)%) - elevated baseline risk (+5 pts)")
    }

    # Verdict thresholds (aligned with host forensic mode)
    $lVerdict    = if ($vtMalicious -or ($AlertContext.MasqueradeMatches -and $AlertContext.MasqueradeMatches.Count -gt 0) -or $lScore -ge 60) { "TRUE POSITIVE" }
                   elseif ($lScore -ge 25) { "SUSPICIOUS" }
                   else { "FALSE POSITIVE" }
    $lConfidence = if ($vtMalicious -or $lScore -ge 80 -or ($AlertContext.MasqueradeMatches -and $AlertContext.MasqueradeMatches.Count -gt 0)) { "HIGH" }
                   elseif ($lScore -ge 40 -or $vtUnknown) { "MEDIUM" }
                   else { "LOW" }

    if ($lFindings.Count -eq 0) { $lFindings.Add("No significant indicators found - likely false positive.") }
    if ($lSteps.Count   -eq 0)  { $lSteps.Add("No immediate action required - continue baseline monitoring.") }

    # Build structured verdict text
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine("VERDICT: $lVerdict")
    [void]$sb.AppendLine("CONFIDENCE: $lConfidence  (Risk Score: $lScore / 100)")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("REASONING:")
    [void]$sb.AppendLine("  Rule      : $($AlertContext.RuleName) ($($AlertContext.RuleType))")
    [void]$sb.AppendLine("  Host      : $($AlertContext.HostName) ($($AlertContext.OS))")
    [void]$sb.AppendLine("  Process   : $($AlertContext.ProcessName)  Parent: $($AlertContext.ParentProcess)")
    [void]$sb.AppendLine("  Path      : $($AlertContext.ProcessPath)")
    [void]$sb.AppendLine("  Signature : $sigStatus  Signer: $(if ($AlertContext.ProcessSigner) { $AlertContext.ProcessSigner } else { '(none)' })")
    [void]$sb.AppendLine("  Know Normal: ParentFreq=$($AlertContext.ParentFrequencyPct)%  PathFreq=$($AlertContext.PathFrequencyPct)%  UnsignedRate=$($AlertContext.UnsignedPct)%")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("KEY INDICATORS:")
    foreach ($f in $lFindings) { [void]$sb.AppendLine("  - $f") }
    [void]$sb.AppendLine("")
    if ($attributionText -and $attributionText -notmatch "Insufficient indicators|No high-confidence") {
        [void]$sb.AppendLine($attributionText)
        [void]$sb.AppendLine("")
    }
    if ($vtText.Length -gt 0) {
        [void]$sb.AppendLine("VIRUSTOTAL ENRICHMENT:")
        [void]$sb.AppendLine($vtText)
    }
    [void]$sb.AppendLine("RECOMMENDED NEXT STEPS:")
    $n = 1; foreach ($s in $lSteps) { [void]$sb.AppendLine("  $n. $s"); $n++ }
    $verdictText = $sb.ToString()

    # -----------------------------------------------------------------------
    # DISPLAY RESULTS
    # -----------------------------------------------------------------------
    Write-Host "`n`n======================================================" -ForegroundColor DarkCyan
    Write-Host "  ELASTIC ALERT AGENT - TRIAGE VERDICT" -ForegroundColor DarkCyan
    Write-Host "  Host: $($AlertContext.HostName)  |  Rule: $($AlertContext.RuleName)" -ForegroundColor DarkCyan
    Write-Host "  Process: $($AlertContext.ProcessName)" -ForegroundColor DarkCyan
    Write-Host "======================================================`n" -ForegroundColor DarkCyan

    $verdictIsComp = $lVerdict -match "TRUE POSITIVE"
    foreach ($line in $verdictText -split "`n") {
        if     ($line -match "^VERDICT.*FALSE POSITIVE") { Write-Host $line -ForegroundColor Green }
        elseif ($line -match "^VERDICT.*TRUE POSITIVE")  { Write-Host $line -ForegroundColor Red }
        elseif ($line -match "^VERDICT.*SUSPICIOUS")     { Write-Host $line -ForegroundColor Yellow }
        elseif ($line -match "^CONFIDENCE")              { Write-Host $line -ForegroundColor $(if ($verdictIsComp) { "Red" } else { "Cyan" }) }
        elseif ($line -match "^REASONING|^KEY INDICATORS|^RECOMMENDED|^VIRUSTOTAL") { Write-Host $line -ForegroundColor DarkCyan }
        elseif ($line -match "CRITICAL:")                { Write-Host $line -ForegroundColor Red }
        elseif ($line -match "Tier-1|multi-indicator")   { Write-Host $line -ForegroundColor Yellow }
        elseif ($line -match "Baseline Category.*[Mm]alicious") { Write-Host $line -ForegroundColor Red }
        elseif ($line -match "Category\s*:\s*")          { Write-Host $line -ForegroundColor Green }
        else                                             { Write-Host $line }
    }

    Write-Host "`n======================================================`n" -ForegroundColor DarkCyan

    return [PSCustomObject]@{
        Verdict      = if ($lVerdict -match "FALSE POSITIVE") { "FP" }
                       elseif ($lVerdict -match "TRUE POSITIVE") { "TP" }
                       else { "SUSPICIOUS" }
        FullResponse = $verdictText
        AlertContext = $AlertContext
        TokensUsed   = $null
    }
}

Export-ModuleMember -Function Invoke-ElasticAlertAgentAnalysis
