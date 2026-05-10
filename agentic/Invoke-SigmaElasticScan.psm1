function Build-SigmaElasticIndex {
    <#
    .SYNOPSIS
        One-time build: translates high-fidelity APT-linked Sigma rules to Elasticsearch queries.

    .DESCRIPTION
        1. Scans all TargetedSigmaDifferentialAnalysis.json files in the APT folder tree and
           collects rule titles with Baseline_Count=0 (unique to targeted malware).
        2. Indexes every YAML file in the SigmaHQ rules repo by its 'title' field.
        3. For each matched title, translates the rule using sigma-cli to Elasticsearch DSL.
        4. Saves the translated queries to output-baseline\sigma-elastic-queries.json.

        Run once after cloning the SigmaHQ/sigma repo and installing sigma-cli:
            git clone https://github.com/SigmaHQ/sigma.git
            pip install sigma-cli
            sigma plugin install elasticsearch

    .PARAMETER SigmaRulesPath
        Path to the sigma rules directory. Defaults to detections\sigma (output of 8d).
        Example: "D:\Loaded-Potato\detections\sigma"

    .PARAMETER AptRoot
        Root of the APT differential analysis folder tree.
        Default: apt\APTs (resolved relative to this script's location).

    .PARAMETER BaselineRoot
        Root of the offline baseline. Default: output-baseline.

    .PARAMETER MinMaliciousCount
        Minimum Malicious_Count an APT differential entry must have to be included.
        Default: 1.

    .EXAMPLE
        Build-SigmaElasticIndex -SigmaRulesPath "C:\tools\sigma\rules"
    #>
    param(
        [string]$SigmaRulesPath = "",
        [string]$AptRoot      = "apt\APTs",
        [string]$BaselineRoot = "output-baseline",
        [int]   $MinMaliciousCount = 1
    )

    # Resolve SigmaRulesPath - default to detections\sigma (output of 8d)
    if ([string]::IsNullOrWhiteSpace($SigmaRulesPath)) {
        $defaultSigmaPath = Join-Path $PSScriptRoot "..\detections\sigma"
        $defaultSigmaPath = [System.IO.Path]::GetFullPath($defaultSigmaPath)
        if (Test-Path $defaultSigmaPath) {
            $SigmaRulesPath = $defaultSigmaPath
            Write-Host "  [Sigma] Using default rules path: $SigmaRulesPath" -ForegroundColor DarkGray
        } else {
            $SigmaRulesPath = Read-Host "Sigma rules path not found at '$defaultSigmaPath'. Enter path to sigma rules directory"
        }
    }

    if (-not [System.IO.Path]::IsPathRooted($AptRoot)) {
        $AptRoot = Join-Path $PSScriptRoot "..\$AptRoot"
    }
    if (-not [System.IO.Path]::IsPathRooted($BaselineRoot)) {
        $BaselineRoot = Join-Path $PSScriptRoot "..\$BaselineRoot"
    }
    $outFile = Join-Path $BaselineRoot "sigma-elastic-queries.json"

    # Check sigma-cli availability - also search common pip user-install locations
    $sigmaBin = Get-Command sigma -ErrorAction SilentlyContinue
    if (-not $sigmaBin) { $sigmaBin = Get-Command sigma.exe -ErrorAction SilentlyContinue }
    if (-not $sigmaBin) {
        # pip --user installs land in AppData\Roaming\Python\PythonXXX\Scripts
        $pyScripts = Get-ChildItem "$env:APPDATA\Python" -Filter "Scripts" -Recurse -Directory -ErrorAction SilentlyContinue |
                     Sort-Object FullName -Descending
        foreach ($sd in $pyScripts) {
            $candidate = Join-Path $sd.FullName "sigma.exe"
            if (Test-Path $candidate) {
                $sigmaBin = [PSCustomObject]@{ Source = $candidate }
                Write-Host "  [Sigma] Found sigma-cli at $candidate" -ForegroundColor DarkGray
                break
            }
        }
    }
    if (-not $sigmaBin) {
        Write-Error "sigma-cli not found. Install it with:`n  pip install sigma-cli`n  sigma plugin install elasticsearch"
        return
    }
    Write-Host "`n[Build-SigmaElasticIndex] sigma-cli found at $($sigmaBin.Source)" -ForegroundColor DarkCyan

    # Verify elasticsearch backend is installed - check site-packages (both system and roaming layouts)
    $sigmaScriptsDir = Split-Path $sigmaBin.Source
    $pythonRoot      = Split-Path $sigmaScriptsDir
    $sitePackages    = @("$pythonRoot\Lib\site-packages", "$pythonRoot\site-packages") |
                       Where-Object { Test-Path $_ } | Select-Object -First 1
    $backendFound    = $false
    if ($sitePackages) {
        $backendFound = (Test-Path "$sitePackages\sigma\backends\elasticsearch") -or
                        ($null -ne (Get-ChildItem $sitePackages -Filter "pySigma_backend_elasticsearch*" -ErrorAction SilentlyContinue | Select-Object -First 1))
    }
    if (-not $backendFound) {
        Write-Error "Elasticsearch backend not installed. Run:`n  & '$($sigmaBin.Source)' plugin install elasticsearch"
        return
    }

    # -----------------------------------------------------------------------
    # Step 1: Collect high-fidelity Sigma rule titles from APT differentials
    # -----------------------------------------------------------------------
    Write-Host "  [1/3] Collecting high-fidelity rule titles from APT differentials..." -ForegroundColor DarkGray
    $targetRules = @{}   # title -> @{ MalCount; Actors }

    if (-not (Test-Path $AptRoot)) {
        Write-Error "APT root not found: $AptRoot"
        return
    }

    Get-ChildItem $AptRoot -Recurse -Filter "TargetedSigmaDifferentialAnalysis.json" | ForEach-Object {
        $actor = $_.Directory.Name
        try {
            $entries = Get-Content $_.FullName -Raw | ConvertFrom-Json
            foreach ($e in ($entries | Where-Object { $_.Baseline_Count -eq 0 -and $_.Malicious_Count -ge $MinMaliciousCount })) {
                $title = $e.Item_Name.Trim()
                if (-not $title) { continue }
                if (-not $targetRules.ContainsKey($title)) {
                    $targetRules[$title] = @{
                        MalCount = [int]$e.Malicious_Count
                        Actors   = [System.Collections.Generic.List[string]]::new()
                    }
                } else {
                    if ([int]$e.Malicious_Count -gt $targetRules[$title].MalCount) {
                        $targetRules[$title].MalCount = [int]$e.Malicious_Count
                    }
                }
                if (-not $targetRules[$title].Actors.Contains($actor)) {
                    $targetRules[$title].Actors.Add($actor)
                }
            }
        } catch {}
    }
    Write-Host "    $($targetRules.Count) unique high-fidelity rule titles collected" -ForegroundColor DarkGray

    # -----------------------------------------------------------------------
    # Step 2: Index Sigma YAML files by title
    # -----------------------------------------------------------------------
    Write-Host "  [2/3] Indexing Sigma YAML files from $SigmaRulesPath ..." -ForegroundColor DarkGray
    if (-not (Test-Path $SigmaRulesPath)) {
        Write-Error "Sigma rules path not found: $SigmaRulesPath"
        return
    }

    $sigmaIndex = @{}   # title -> full yaml path
    Get-ChildItem $SigmaRulesPath -Recurse -Filter "*.yml" -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            # Read only the first 20 lines to find the title quickly
            $head = Get-Content $_.FullName -TotalCount 20
            $titleLine = $head | Where-Object { $_ -match '^title:\s*(.+)$' } | Select-Object -First 1
            if ($titleLine -match '^title:\s*(.+)$') {
                $ruleTitle = $Matches[1].Trim()
                if (-not $sigmaIndex.ContainsKey($ruleTitle)) {
                    $sigmaIndex[$ruleTitle] = $_.FullName
                }
            }
        } catch {}
    }
    Write-Host "    $($sigmaIndex.Count) Sigma rules indexed by title" -ForegroundColor DarkGray

    # -----------------------------------------------------------------------
    # Step 3: Translate matched rules via sigma-cli
    # -----------------------------------------------------------------------
    Write-Host "  [3/3] Translating matched rules to Elasticsearch DSL..." -ForegroundColor DarkGray

    $out = @{}
    $matched = 0; $notFound = 0; $failed = 0
    $sampleErrors = [System.Collections.Generic.List[string]]::new()

    foreach ($title in $targetRules.Keys) {
        if (-not $sigmaIndex.ContainsKey($title)) { $notFound++; continue }
        $ruleFile = $sigmaIndex[$title]

        try {
            # sigma-cli lucene output is plain text (not JSON); exit code 1 is normal (progress on stderr)
            # Try ecs_windows pipeline first (ECS-compliant fields, works with Elastic Agent)
            $rawOut = & $sigmaBin.Source convert -t lucene -p ecs_windows $ruleFile 2>$null
            $queryStr = ($rawOut | Where-Object { $_ -and $_ -notmatch '^Usage:|^Error:|^Parsing|^sigma' }) -join ' '
            $ok = -not [string]::IsNullOrWhiteSpace($queryStr)

            if (-not $ok) {
                # Fallback: winlogbeat pipeline
                $rawOut = & $sigmaBin.Source convert -t lucene -p winlogbeat $ruleFile 2>$null
                $queryStr = ($rawOut | Where-Object { $_ -and $_ -notmatch '^Usage:|^Error:|^Parsing|^sigma' }) -join ' '
                $ok = -not [string]::IsNullOrWhiteSpace($queryStr)
            }

            if ($ok) {
                $out[$title] = @{
                    Query    = $queryStr.Trim()
                    Language = 'lucene'
                    MalCount = $targetRules[$title].MalCount
                    Actors   = @($targetRules[$title].Actors)
                    RuleFile = $ruleFile
                }
                $matched++
            } else {
                $failed++
                if ($sampleErrors.Count -lt 3) {
                    $errLine = ($rawOut | Where-Object { $_ -match '\S' } | Select-Object -First 1)
                    if ($errLine) { $sampleErrors.Add("[$title]: $errLine") }
                }
            }
        } catch {
            $failed++
        }
    }

    Write-Host "`n  Results:" -ForegroundColor Green
    Write-Host "    Matched and translated : $matched"
    Write-Host "    Not found in Sigma repo: $notFound  (rule exists in APT diff but not in local Sigma clone)"
    Write-Host "    Translation failed     : $failed"
    if ($sampleErrors.Count -gt 0) {
        Write-Host "    Sample failure reasons (first 3):" -ForegroundColor DarkYellow
        $sampleErrors | ForEach-Object { Write-Host "      $_" -ForegroundColor DarkYellow }
    }

    Write-Host "`n  Saving to $outFile ..." -ForegroundColor DarkCyan
    $out | ConvertTo-Json -Depth 20 -Compress | Set-Content $outFile -Encoding UTF8
    Write-Host "  Saved. ($([Math]::Round((Get-Item $outFile).Length / 1KB, 0)) KB)" -ForegroundColor Green

    return [PSCustomObject]@{
        OutputPath = $outFile
        Translated = $matched
        NotFound   = $notFound
        Failed     = $failed
        Total      = $targetRules.Count
    }
}


function Invoke-SigmaElasticScan {
    <#
    .SYNOPSIS
        Runs pre-translated high-fidelity Sigma rules against Elastic for a specific host/timeframe.

    .DESCRIPTION
        Loads sigma-elastic-queries.json (built by Build-SigmaElasticIndex), wraps each
        translated query with the host and timeframe filters, executes it against Elasticsearch,
        and returns a summary of hits with rule name, hit count, malware fidelity, and linked
        threat actors.

        Called automatically by Invoke-ElasticAlertAgentAnalysis when sigma-elastic-queries.json
        is present. Returns $null if the index file is missing.

    .PARAMETER EsUrl
        Elasticsearch base URL (e.g. https://elastic.yourdomain:9200).

    .PARAMETER EsHeaders
        Hashtable of HTTP headers (Authorization, Content-Type) for Elastic requests.

    .PARAMETER TimeFilter
        Elasticsearch range filter hashtable for @timestamp.

    .PARAMETER HostFilter
        Elasticsearch bool/should filter for host.name / agent.name / host.hostname.

    .PARAMETER BaselineRoot
        Root of the offline baseline. Default: output-baseline.

    .PARAMETER IndexPattern
        Elastic index pattern to query. Default covers common log indices.
    #>
    param(
        [Parameter(Mandatory=$true)] [string]   $EsUrl,
        [Parameter(Mandatory=$true)] [hashtable]$EsHeaders,
        [Parameter(Mandatory=$true)] [hashtable]$TimeFilter,
        [Parameter(Mandatory=$true)] [hashtable]$HostFilter,
        [string]$BaselineRoot  = "output-baseline",
        [string]$IndexPattern  = "logs-*,winlogbeat-*,filebeat-*,endgame-*"
    )

    if (-not [System.IO.Path]::IsPathRooted($BaselineRoot)) {
        $BaselineRoot = Join-Path $PSScriptRoot "..\$BaselineRoot"
    }
    $indexFile = Join-Path $BaselineRoot "sigma-elastic-queries.json"

    if (-not (Test-Path $indexFile)) {
        Write-Host "  [Sigma scan] sigma-elastic-queries.json not found." -ForegroundColor DarkYellow
        Write-Host "  [Sigma scan] Run Build-SigmaElasticIndex -SigmaRulesPath <path to sigma/rules>" -ForegroundColor DarkYellow
        return $null
    }

    $sigmaQueries = $null
    try {
        $sigmaQueries = Get-Content $indexFile -Raw | ConvertFrom-Json
    } catch {
        Write-Host "  [Sigma scan] Failed to load sigma-elastic-queries.json: $_" -ForegroundColor Red
        return $null
    }

    $ruleNames = $sigmaQueries.PSObject.Properties.Name
    Write-Host "`n[+] Sigma rule scan: running $($ruleNames.Count) translated rules against $IndexPattern..." -ForegroundColor DarkCyan

    $hits       = [System.Collections.Generic.List[PSCustomObject]]::new()
    $errCount   = 0
    $hitCount   = 0
    $esRestArgs = @{ ContentType='application/json'; UseBasicParsing=$true }

    foreach ($ruleName in $ruleNames) {
        $entry = $sigmaQueries.$ruleName

        # Compose the rule's translated query with host + time scope
        $sigmaQuery = $entry.Query
        $body = @{
            size  = 5   # just enough to confirm a hit; full forensics already done above
            query = @{
                bool = @{
                    must = @(
                        $TimeFilter,
                        $HostFilter,
                        $sigmaQuery
                    )
                }
            }
            _source = @("@timestamp","host.name","process.name","process.command_line","event.action","kibana.alert.rule.name")
        }

        try {
            $uri  = "$EsUrl/$IndexPattern/_search"
            $resp = Invoke-RestMethod -Uri $uri -Headers $EsHeaders -Method Post `
                        -Body ($body | ConvertTo-Json -Depth 20 -Compress) @esRestArgs
            $total = if ($resp -and $resp.hits) { $resp.hits.total.value } else { 0 }

            if ($total -gt 0) {
                $hitCount++
                $actors = if ($entry.Actors) { $entry.Actors -join ', ' } else { "unknown" }
                Write-Host "    [HIT] $ruleName  ($total event(s))  |  Actors: $actors  |  MalCount: $($entry.MalCount)" -ForegroundColor Red
                [void]$hits.Add([PSCustomObject]@{
                    RuleName  = $ruleName
                    HitCount  = $total
                    MalCount  = $entry.MalCount
                    Actors    = $entry.Actors
                    TopHit    = if ($resp.hits.hits.Count -gt 0) { $resp.hits.hits[0]._source } else { $null }
                })
            }
        } catch {
            $errCount++
        }
    }

    Write-Host "    Sigma scan complete: $hitCount / $($ruleNames.Count) rules fired  ($errCount query errors)" `
        -ForegroundColor $(if ($hitCount -gt 0) { "Red" } else { "Green" })

    return [PSCustomObject]@{
        Hits      = $hits.ToArray()
        HitCount  = $hitCount
        Tested    = $ruleNames.Count
        Errors    = $errCount
    }
}


# ---------------------------------------------------------------------------
# Private helpers for Export-SigmaKibanaRules
# ---------------------------------------------------------------------------
$script:SigmaEcsMap = @{
    CommandLine         = 'process.command_line'
    Image               = 'process.executable'
    ParentImage         = 'process.parent.executable'
    ParentCommandLine   = 'process.parent.command_line'
    OriginalFileName    = 'process.pe.original_file_name'
    TargetFilename      = 'file.path'
    TargetObject        = 'registry.path'
    Details             = 'registry.value'
    EventID             = 'event.code'
    Channel             = 'winlog.channel'
    User                = 'user.name'
    ProcessName         = 'process.name'
    Imphash             = 'process.pe.imphash'
    ParentProcessName   = 'process.parent.name'
    QueryName           = 'dns.question.name'
    DestinationPort     = 'destination.port'
    DestinationIp       = 'destination.ip'
    SourceIp            = 'source.ip'
    Computer            = 'host.hostname'
    ServiceName         = 'service.name'
    Hashes              = 'process.hash.md5'
    sha256              = 'file.hash.sha256'
    md5                 = 'file.hash.md5'
    WorkstationName     = 'source.domain'
    IntegrityLevel      = 'process.token.integrity_level_name'
}

function script:Resolve-SigmaEcsField([string]$F) {
    if ($script:SigmaEcsMap.ContainsKey($F)) { return $script:SigmaEcsMap[$F] }
    return ($F -creplace '([A-Z])', '.$1').TrimStart('.').ToLower()
}

function script:Format-SigmaKqlValue([string]$v, [string]$mod) {
    $v = $v.Trim().Trim("'").Trim('"')
    if ($mod -match 'contains\|all|contains') { return "*$v*" }
    if ($mod -match 'startswith') { return "$v*" }
    if ($mod -match 'endswith')   { return "*$v" }
    # Escape backslashes only for quoted values
    $v = $v -replace '\\', '\\\\'
    return "`"$v`""
}

function script:Convert-SigmaBlockToKql([string[]]$BlockLines) {
    # Returns a KQL string fragment for one named detection block (selection/filter/etc.)
    $parts  = [System.Collections.Generic.List[string]]::new()
    $isListType = ($BlockLines.Count -gt 0 -and $BlockLines[0] -match '^\s+-\s')
    $i = 0

    if ($isListType) {
        # List-type: each "- field: val" item is one OR branch
        $orGroups = [System.Collections.Generic.List[string]]::new()
        while ($i -lt $BlockLines.Count) {
            $line = $BlockLines[$i]
            if ($line -match '^\s+-\s+(\w+)(\|[^:]+)?:\s*(.*)$') {
                $field = Resolve-SigmaEcsField $Matches[1]
                $mod   = if ($Matches[2]) { $Matches[2] } else { '' }
                $val   = $Matches[3].Trim()
                if ($mod -match '\|all') {
                    $ap = [System.Collections.Generic.List[string]]::new()
                    if ($val) { $ap.Add("${field}: $(Format-SigmaKqlValue $val $mod)") }
                    $i++
                    while ($i -lt $BlockLines.Count -and $BlockLines[$i] -match '^\s+-\s+(.+)$') {
                        $ap.Add("${field}: $(Format-SigmaKqlValue $Matches[1] $mod)")
                        $i++
                    }
                    if ($ap.Count -gt 0) { $orGroups.Add("($($ap -join ' AND '))") }
                    continue
                } elseif (-not $val) {
                    $vp = [System.Collections.Generic.List[string]]::new()
                    $i++
                    while ($i -lt $BlockLines.Count -and $BlockLines[$i] -match '^\s+-\s+(.+)$') {
                        $vp.Add("${field}: $(Format-SigmaKqlValue $Matches[1] $mod)")
                        $i++
                    }
                    if ($vp.Count -eq 1) { $orGroups.Add($vp[0]) }
                    elseif ($vp.Count -gt 1) { $orGroups.Add("($($vp -join ' OR '))") }
                    continue
                } else {
                    $orGroups.Add("${field}: $(Format-SigmaKqlValue $val $mod)")
                }
            }
            $i++
        }
        if ($orGroups.Count -eq 0) { return $null }
        if ($orGroups.Count -eq 1) { return $orGroups[0] } else { return "($($orGroups -join ' OR '))" }
    } else {
        # Dict-type: each field is AND'd together
        while ($i -lt $BlockLines.Count) {
            $line = $BlockLines[$i]
            if ($line -match '^\s+(\w+)(\|[^:]+)?:\s*(.*)$') {
                $field = Resolve-SigmaEcsField $Matches[1]
                $mod   = if ($Matches[2]) { $Matches[2] } else { '' }
                $val   = $Matches[3].Trim()
                if ($mod -match '\|all') {
                    $ap = [System.Collections.Generic.List[string]]::new()
                    if ($val) { $ap.Add("${field}: $(Format-SigmaKqlValue $val $mod)") }
                    $i++
                    while ($i -lt $BlockLines.Count -and $BlockLines[$i] -match '^\s+-\s+(.+)$') {
                        $ap.Add("${field}: $(Format-SigmaKqlValue $Matches[1] $mod)")
                        $i++
                    }
                    if ($ap.Count -gt 0) { $parts.Add("($($ap -join ' AND '))") }
                    continue
                } elseif (-not $val) {
                    $vp = [System.Collections.Generic.List[string]]::new()
                    $i++
                    while ($i -lt $BlockLines.Count -and $BlockLines[$i] -match '^\s+-\s+(.+)$') {
                        $vp.Add("${field}: $(Format-SigmaKqlValue $Matches[1] $mod)")
                        $i++
                    }
                    if ($vp.Count -eq 1) { $parts.Add($vp[0]) }
                    elseif ($vp.Count -gt 1) { $parts.Add("($($vp -join ' OR '))") }
                    continue
                } elseif ($val -in @('null', "''", '""')) {
                    $parts.Add("NOT ${field}: *")
                } else {
                    $parts.Add("${field}: $(Format-SigmaKqlValue $val $mod)")
                }
            }
            $i++
        }
        if ($parts.Count -eq 0) { return $null }
        if ($parts.Count -eq 1) { return $parts[0] } else { return "($($parts -join ' AND '))" }
    }
}

function script:Convert-SigmaYamlToKql([string]$Content) {
    # Returns a KQL string, or $null if detection block cannot be parsed

    # --- extract detection block (everything indented under "detection:") ---
    $allLines = $Content -split "`n"
    $detStart = -1
    for ($li = 0; $li -lt $allLines.Count; $li++) {
        if ($allLines[$li] -match '^detection:\s*$') { $detStart = $li + 1; break }
    }
    if ($detStart -lt 0) { return $null }

    # Collect lines until next top-level key (no leading space) or EOF
    $detLines = [System.Collections.Generic.List[string]]::new()
    for ($li = $detStart; $li -lt $allLines.Count; $li++) {
        $l = $allLines[$li]
        if ($l -match '^[a-zA-Z]' -and $l -notmatch '^\s') { break }
        $detLines.Add($l)
    }

    # --- parse named sub-blocks ---
    $condition = 'selection'
    $blocks    = @{}   # name -> [string[]]

    $curName  = $null
    $curLines = $null
    foreach ($line in $detLines) {
        if ($line -match '^    (\w+):\s*(.*)$') {
            $kname = $Matches[1]; $kval = $Matches[2].Trim()
            if ($kname -eq 'condition') {
            if ($curName) { $blocks[$curName] = $curLines.ToArray(); $curName = $null }
            $condition = $kval; continue
        }
            if ($curName) { $blocks[$curName] = $curLines.ToArray() }
            $curName  = $kname
            $curLines = [System.Collections.Generic.List[string]]::new()
            if ($kval) { $curLines.Add("        $kval") }
        } elseif ($curName -and $line -match '^        ') {
            $curLines.Add($line)
        }
    }
    if ($curName) { $blocks[$curName] = $curLines.ToArray() }

    if ($blocks.Count -eq 0) { return $null }

    # --- convert each block to KQL ---
    $kqlBlocks = @{}
    foreach ($name in $blocks.Keys) {
        $kql = Convert-SigmaBlockToKql $blocks[$name]
        if ($kql) { $kqlBlocks[$name] = $kql }
    }
    if ($kqlBlocks.Count -eq 0) { return $null }

    # --- apply condition logic ---
    # Normalise common patterns: "1 of selection*", "all of filter_*", "not filter*"
    $cond = $condition.Trim()

    # Expand "1 of X*" -> OR of matching blocks
    $cond = [regex]::Replace($cond, '1 of (\w+)\*', {
        param($m)
        $prefix = $m.Groups[1].Value
        $matched = $kqlBlocks.Keys | Where-Object { $_ -like "$prefix*" }
        if (-not $matched) { return 'false' }
        $parts = $matched | ForEach-Object { $kqlBlocks[$_] }
        "($($parts -join ' OR '))"
    })
    # Expand "all of X*" -> AND of matching blocks
    $cond = [regex]::Replace($cond, 'all of (\w+)\*', {
        param($m)
        $prefix = $m.Groups[1].Value
        $matched = $kqlBlocks.Keys | Where-Object { $_ -like "$prefix*" }
        if (-not $matched) { return 'false' }
        $parts = $matched | ForEach-Object { $kqlBlocks[$_] }
        "($($parts -join ' AND '))"
    })
    # Replace bare block names with their KQL
    foreach ($name in ($kqlBlocks.Keys | Sort-Object { $_.Length } -Descending)) {
        $cond = $cond -replace "\b$([regex]::Escape($name))\b", $kqlBlocks[$name]
    }
    # Translate sigma condition operators to KQL
    $cond = $cond -replace '\band\b', 'AND' -replace '\bor\b', 'OR' -replace '\bnot\b', 'NOT'
    return $cond.Trim()
}

# ---------------------------------------------------------------------------
function Export-SigmaKibanaRules {
    <#
    .SYNOPSIS
        Converts high-fidelity Sigma YAML rules from detections\sigma\ to a
        Kibana-importable NDJSON file (output-baseline\sigma-kibana.ndjson).

    .DESCRIPTION
        Reads each .yml file downloaded by Get-HighFidelitySigmaYaraRules (option 8d),
        parses the sigma detection logic, converts it to KQL, and wraps it in a
        Kibana Detection Engine rule object.  All rules are prefixed "[Loaded Potato]".

        Import the output file via:
            Kibana -> Security -> Rules -> Detection rules -> Import rules

    .EXAMPLE
        Export-SigmaKibanaRules
        # Writes output-baseline\sigma-kibana.ndjson
    #>
    param(
        [string]$SigmaDir     = ".\detections\sigma",
        [string]$BaselineRoot = "output-baseline",
        [string]$DefaultIndex = "logs-*,winlogbeat-*,filebeat-*,endgame-*,.siem-signals-*"
    )

    if (-not [System.IO.Path]::IsPathRooted($SigmaDir)) {
        $SigmaDir = Join-Path $PSScriptRoot "..\$SigmaDir"
    }
    $kibanaDir = Join-Path $PSScriptRoot "..\detections\kibanaImport"
    if (-not (Test-Path $kibanaDir)) { New-Item -ItemType Directory -Path $kibanaDir -Force | Out-Null }
    $outFile = Join-Path $kibanaDir "sigma-kibana.ndjson"

    if (-not (Test-Path $SigmaDir)) {
        Write-Error "Sigma rules directory not found: $SigmaDir`nRun option 8d first to download high-fidelity sigma rules."
        return
    }
    $yamlFiles = Get-ChildItem $SigmaDir -Filter "*.yml" -ErrorAction SilentlyContinue
    if ($yamlFiles.Count -eq 0) {
        Write-Warning "No .yml files found in $SigmaDir. Run option 8d first."
        return
    }

    Write-Host "`n[Export-SigmaKibanaRules] Converting $($yamlFiles.Count) rules from $SigmaDir ..." -ForegroundColor DarkCyan

    $indexArr  = $DefaultIndex -split ',' | ForEach-Object { $_.Trim() }
    $outLines  = [System.Collections.Generic.List[string]]::new()
    $exported  = 0
    $skipped   = 0

    $sha256 = [System.Security.Cryptography.SHA256]::Create()

    foreach ($file in $yamlFiles) {
        try {
            $content = Get-Content $file.FullName -Raw -Encoding UTF8

            # --- parse scalar header fields ---
            $title       = if ($content -match '(?m)^title:\s*(.+)$')       { $Matches[1].Trim() } else { $file.BaseName }
            $ruleId      = if ($content -match '(?m)^id:\s*([a-f0-9-]{36})') { $Matches[1].Trim() } else {
                               $bytes    = [System.Text.Encoding]::UTF8.GetBytes($title)
                               $hash     = $sha256.ComputeHash($bytes)
                               $gb       = $hash[0..15]
                               $gb[6]    = ($gb[6] -band 0x0F) -bor 0x40
                               $gb[8]    = ($gb[8] -band 0x3F) -bor 0x80
                               [guid]::new([byte[]]$gb).ToString()
                           }
            $description = if ($content -match '(?m)^description:\s*(.+)$') { $Matches[1].Trim() } else { $title }
            $level       = if ($content -match '(?m)^level:\s*(\w+)')        { $Matches[1].Trim() } else { 'medium' }

            # --- severity / risk score ---
            $severity  = switch ($level) {
                'critical'      { 'critical' }
                'high'          { 'high' }
                'medium'        { 'medium' }
                'low'           { 'low' }
                'informational' { 'low' }
                default         { 'medium' }
            }
            $riskScore = switch ($severity) {
                'critical' { 99 }; 'high' { 73 }; 'medium' { 47 }; 'low' { 21 }; default { 47 }
            }

            # --- tags (MITRE ATT&CK + Loaded Potato marker) ---
            $kbTags = [System.Collections.Generic.List[string]]::new()
            $kbTags.Add('Loaded Potato')
            foreach ($m in [regex]::Matches($content, '(?m)^\s+-\s+(attack\.\S+)')) {
                $kbTags.Add($m.Groups[1].Value)
            }

            # --- convert sigma detection to KQL ---
            $kqlQuery = Convert-SigmaYamlToKql $content
            if ([string]::IsNullOrWhiteSpace($kqlQuery)) {
                $skipped++
                Write-Host "  [Skip] $title (no parseable detection)" -ForegroundColor DarkGray
                continue
            }

            $ruleObj = [ordered]@{
                id          = $ruleId
                rule_id     = $ruleId
                name        = "[Loaded Potato] $title"
                description = $description
                enabled     = $false
                type        = 'query'
                language    = 'kuery'
                query       = $kqlQuery
                index       = $indexArr
                risk_score  = $riskScore
                severity    = $severity
                tags        = @($kbTags)
                author      = @('Loaded Potato')
                from        = 'now-24h'
                interval    = '5m'
                max_signals = 100
                version     = 1
            }

            $outLines.Add(($ruleObj | ConvertTo-Json -Depth 5 -Compress))
            $exported++
        } catch {
            $skipped++
            Write-Warning "  [Skip] $($file.BaseName): $_"
        }
    }

    $sha256.Dispose()

    if ($outLines.Count -eq 0) {
        Write-Host "  [!] No rules exported." -ForegroundColor Yellow
        return
    }

    [System.IO.File]::WriteAllText($outFile, ($outLines -join "`n"), [System.Text.Encoding]::UTF8)

    Write-Host "  Exported : $exported rules" -ForegroundColor Green
    if ($skipped -gt 0) {
        Write-Host "  Skipped  : $skipped rules (no parseable detection)" -ForegroundColor DarkYellow
    }
    Write-Host "  Output   : $outFile" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Import via: Kibana -> Security -> Rules -> Detection rules -> Import rules" -ForegroundColor DarkCyan
    if ($exported -gt 1000) {
        Write-Host "  [!] $exported rules exceeds Kibana's 1000-rule import limit - split the file into batches." -ForegroundColor Yellow
    }

    return [PSCustomObject]@{ OutputPath = $outFile; Exported = $exported; Skipped = $skipped }
}
