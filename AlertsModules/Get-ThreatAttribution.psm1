function Get-ThreatAttribution {
    <#
    .SYNOPSIS
        Attribution Engine: Correlates observed TTPs against the known APT/Malware database.
    .EXAMPLE
        Get-ThreatAttribution -Observations @("T1027", "Delete Volume Shadow Copies")
    #>
    param (
        [Parameter(Mandatory=$true)]
        [string[]]$Observations,

        [string]$RootPath = ".\apt",
        [string]$OutputHtmlPath = ".\output\Attribution_Report.html",
        [int]$MinRarityScore = 90,
        [switch]$PassThru
    )

    if (-not $PassThru) { Write-Host "Starting Threat Attribution Analysis..." -ForegroundColor DarkCyan }
    if (-not $PassThru) { Write-Host "Searching for: $($Observations -join ', ')" -ForegroundColor Yellow }

    if (-not (Test-Path $RootPath)) { Write-Error "Root path not found: $RootPath"; return }
    $AbsRoot = (Resolve-Path $RootPath).Path
    
    # --- 1. BUILD THE SEARCH INDEX ---
    # Dictionary<string, List<object>> avoids array-copy-on-append (@{} += copies on every add)
    $GlobalIndex   = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.List[object]]]::new(
                         [System.StringComparer]::OrdinalIgnoreCase)
    $ActorProfiles = @{}
    $ActorJsonFiles = @{}

    if (-not $PassThru) { Write-Host "  Building Threat Index from Repository..." -NoNewline }

    $JsonFiles    = Get-ChildItem -Path $AbsRoot -Filter "Targeted*DifferentialAnalysis.json" -Recurse
    $TotalIndexed = 0

    foreach ($File in $JsonFiles) {
        $Parent      = $File.Directory.Name
        $GrandParent = $File.Directory.Parent.Name
        $ActorName   = $Parent
        $ActorType   = "Malware"
        if ($GrandParent -ne "Malware Families" -and $GrandParent -ne "APTs") {
            if ($File.FullName -match "\\APTs\\") { $ActorType = "APT" }
        }

        $Category = $File.BaseName -replace '^Targeted_?','' -replace '_?DifferentialAnalysis$','' -replace '_',' '
        $FileUri  = "file:///" + $File.FullName.Replace('\','/')

        if (-not $ActorJsonFiles.ContainsKey($ActorName)) { $ActorJsonFiles[$ActorName] = @{} }
        if (-not $ActorJsonFiles[$ActorName].ContainsKey($Category)) {
            $ActorJsonFiles[$ActorName][$Category] = $FileUri
        }

        try {
            # [System.IO.File]::ReadAllText avoids PowerShell pipeline overhead vs Get-Content -Raw
            $Data  = [System.IO.File]::ReadAllText($File.FullName) | ConvertFrom-Json
            if (-not $Data) { continue }

            foreach ($Row in @($Data)) {
                $Score = [double]$Row.Baseline_Rarity_Score
                if ($Score -lt $MinRarityScore) { continue }

                $Key = $Row.Item_Name -replace '"','' -replace '^\s+','' -replace '\s+$',''

                if (-not $GlobalIndex.ContainsKey($Key)) {
                    $GlobalIndex[$Key] = [System.Collections.Generic.List[object]]::new()
                }
                [void]$GlobalIndex[$Key].Add([PSCustomObject]@{
                    Actor    = $ActorName
                    Type     = $ActorType
                    Source   = $Row.Type
                    Score    = $Score
                    Category = $Category
                })

                # ActorProfiles only needed for HTML output  -  skip in PassThru mode
                if (-not $PassThru) {
                    if (-not $ActorProfiles.ContainsKey($ActorName)) { $ActorProfiles[$ActorName] = [System.Collections.Generic.List[object]]::new() }
                    [void]([System.Collections.Generic.List[object]]$ActorProfiles[$ActorName]).Add([PSCustomObject]@{
                        Name = $Key; Type = $Row.Type; Score = $Score; Category = $Category
                    })
                }

                $TotalIndexed++
            }
        } catch {}
    }
    if (-not $PassThru) { Write-Host " [Done] ($TotalIndexed high-rarity artifacts indexed)" -ForegroundColor Green }

    # --- 2. EXECUTE QUERY ---
    # Pre-compile every observation as a Compiled+IgnoreCase Regex (IL bytecode  -  avoids
    # re-parsing the pattern on each -match call).  Then do ONE pass through the index
    # checking all observations per key, rather than one full index scan per observation.
    $compiledObs = [System.Collections.Generic.List[object]]::new()
    foreach ($term in $Observations) {
        try {
            [void]$compiledObs.Add([PSCustomObject]@{
                Term    = $term
                Pattern = [System.Text.RegularExpressions.Regex]::new(
                    [System.Text.RegularExpressions.Regex]::Escape($term),
                    [System.Text.RegularExpressions.RegexOptions]::Compiled -bor
                    [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
                )
            })
        } catch {}
    }

    $CandidateMeta    = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $CandidateMatches = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $CandidateCount   = [System.Collections.Generic.Dictionary[string,int]]::new([System.StringComparer]::OrdinalIgnoreCase)
    # HashSet for O(1) dedup ("Actor|Term")  -  replaces the per-actor Where-Object linear scan
    $SeenHits         = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($kvp in $GlobalIndex.GetEnumerator()) {
        $indexKey = $kvp.Key
        foreach ($cp in $compiledObs) {
            if ($cp.Pattern.IsMatch($indexKey)) {
                foreach ($hit in $kvp.Value) {
                    $dedupeKey = "$($hit.Actor)|$($cp.Term)"
                    if ($SeenHits.Add($dedupeKey)) {
                        $name = $hit.Actor
                        if (-not $CandidateMeta.ContainsKey($name)) {
                            $CandidateMeta[$name]    = [PSCustomObject]@{ Actor = $name; Type = $hit.Type }
                            $CandidateMatches[$name] = [System.Collections.Generic.List[PSCustomObject]]::new()
                            $CandidateCount[$name]   = 0
                        }
                        [void]([System.Collections.Generic.List[PSCustomObject]]$CandidateMatches[$name]).Add(
                            [PSCustomObject]@{ Term = $cp.Term; Indicator = $indexKey; Source = $hit.Source })
                        $CandidateCount[$name]++
                    }
                }
            }
        }
    }

    # Reassemble into result objects
    $Results = [System.Collections.Generic.List[object]]::new()
    foreach ($name in $CandidateMeta.Keys) {
        [void]$Results.Add([PSCustomObject]@{
            Actor      = ([PSCustomObject]$CandidateMeta[$name]).Actor
            Type       = ([PSCustomObject]$CandidateMeta[$name]).Type
            Matches    = @([System.Collections.Generic.List[PSCustomObject]]$CandidateMatches[$name])
            MatchCount = [int]$CandidateCount[$name]
        })
    }
    $Results = @($Results | Sort-Object MatchCount -Descending)

    # -----------------------------------------------------------------------
    # HELPER: Given an actor + artifact category string, return a file:// URI
    # We do a best-effort fuzzy match against the known JSON files for that actor.
    # -----------------------------------------------------------------------
    function Get-JsonLink {
        param($ActorName, $ArtifactCategory)
        if (-not $ActorJsonFiles.ContainsKey($ActorName)) { return $null }
        $Map = $ActorJsonFiles[$ActorName]

        # Exact match first
        if ($Map.ContainsKey($ArtifactCategory)) { return $Map[$ArtifactCategory] }

        # Fuzzy: find a key that contains any word from the category
        $Words = $ArtifactCategory -split '\s+'
        foreach ($Word in $Words) {
            $FuzzyKey = $Map.Keys | Where-Object { $_ -match $Word } | Select-Object -First 1
            if ($FuzzyKey) { return $Map[$FuzzyKey] }
        }
        return $null
    }

    # -----------------------------------------------------------------------
    # 4. BUILD HTML
    # -----------------------------------------------------------------------

    # --- Summary Table Data ---
    # Each side: sorted by MatchCount descending, then rendered in a compact multi-column grid
    # We pack 4 entries per row (2 APT cols + 2 Malware cols)
    $AptRows = @($Results | Where-Object { $_.Type -eq "APT"     } | Sort-Object MatchCount -Descending)
    $MalRows = @($Results | Where-Object { $_.Type -ne "APT"     } | Sort-Object MatchCount -Descending)

    # Build cell HTML for one side
    function Build-SummaryCells {
        param($Entries, [string]$PillClass)
        $html = ""
        foreach ($e in $Entries) {
            $html += "<div class='sum-cell'><span class='actor-name'>$($e.Actor)</span><span class='hit-pill $PillClass'>$($e.MatchCount)</span></div>"
        }
        return $html
    }

    $AptCells = Build-SummaryCells -Entries $AptRows -PillClass "apt-pill"
    $MalCells = Build-SummaryCells -Entries $MalRows -PillClass "mal-pill"

    $HtmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Attribution Analysis</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css" rel="stylesheet">
    <style>
        :root {
            --bg-deep:    #0f1117;
            --bg-card:    #1a1d27;
            --bg-card2:   #22263a;
            --border:     #2e334d;
            --text:       #d4d8f0;
            --muted:      #6b7280;
            --green:      #4ade80;
            --yellow:     #facc15;
            --red:        #f87171;
            --orange:     #fb923c;
            --blue:       #60a5fa;
            --teal:       #2dd4bf;
        }
        * { box-sizing: border-box; }
        body {
            background-color: var(--bg-deep);
            color: var(--text);
            font-family: 'Segoe UI', 'Consolas', monospace;
            padding: 30px;
            font-size: 0.9rem;
        }
        h2 { color: var(--teal); letter-spacing: 2px; text-transform: uppercase; font-size: 1.2rem; }
        h4 { font-size: 0.95rem; letter-spacing: 1px; text-transform: uppercase; }

        /* ---- Summary Table ---- */
        .summary-outer {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 12px;
            margin-bottom: 2rem;
        }
        .summary-half {
            border: 1px solid var(--border);
            border-radius: 6px;
            overflow: hidden;
        }
        .summary-col-header {
            padding: 8px 14px;
            font-size: 0.72rem;
            letter-spacing: 2px;
            text-transform: uppercase;
            font-weight: 700;
            border-bottom: 1px solid var(--border);
        }
        .summary-col-header.apt { background: rgba(220,53,69,0.15); color: var(--red); }
        .summary-col-header.mal { background: rgba(251,146,60,0.10); color: var(--orange); }
        .sum-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
            gap: 0;
        }
        .sum-cell {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 5px 12px;
            border-bottom: 1px solid #1a1e2e;
            border-right: 1px solid #1a1e2e;
        }
        .actor-name { font-weight: 600; color: var(--text); font-size: 0.82rem; }
        .hit-pill {
            display: inline-block;
            font-size: 0.68rem;
            padding: 1px 6px;
            border-radius: 10px;
            margin-left: 6px;
            font-weight: 700;
            flex-shrink: 0;
        }
        .apt-pill { background: rgba(220,53,69,0.2); color: var(--red); }
        .mal-pill { background: rgba(251,146,60,0.2); color: var(--orange); }

        /* ---- Cards ---- */
        .card { background-color: var(--bg-card); border: 1px solid var(--border); margin-bottom: 20px; border-radius: 6px; overflow: hidden; }
        .card-header { font-weight: bold; padding: 10px 16px; font-size: 0.85rem; display: flex; justify-content: space-between; align-items: center; }
        .card-header.tier1-apt { background: rgba(220,53,69,0.18); border-bottom: 1px solid rgba(220,53,69,0.3); }
        .card-header.tier1-mal { background: rgba(251,146,60,0.15); border-bottom: 1px solid rgba(251,146,60,0.3); }
        .card-header.tier2     { background: var(--bg-card2); border-bottom: 1px solid var(--border); }
        .card-body { padding: 14px 16px; }
        .badge-apt { background-color: rgba(220,53,69,0.25); color: var(--red); border: 1px solid rgba(220,53,69,0.4); font-size: 0.7rem; padding: 2px 8px; border-radius: 4px; }
        .badge-mal { background-color: rgba(251,146,60,0.2); color: var(--orange); border: 1px solid rgba(251,146,60,0.3); font-size: 0.7rem; padding: 2px 8px; border-radius: 4px; }
        h6 { font-size: 0.75rem; letter-spacing: 1px; text-transform: uppercase; color: var(--muted); margin-bottom: 8px; }
        ul { padding-left: 1.2rem; margin-bottom: 0; }
        li { margin-bottom: 4px; }
        .match-highlight { color: var(--green); font-family: 'Consolas', monospace; font-size: 0.82rem; }
        .source-tag { color: var(--muted); font-size: 0.75rem; margin-right: 4px; }
        hr { border-color: var(--border); margin: 12px 0; }

        /* ---- Recommendations  -  links only ---- */
        .rec-links { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 4px; }
        .rec-link {
            font-size: 0.75rem;
            color: var(--blue);
            text-decoration: none;
            background: rgba(96,165,250,0.1);
            border: 1px solid rgba(96,165,250,0.25);
            border-radius: 4px;
            padding: 3px 9px;
        }
        .rec-link:hover { background: rgba(96,165,250,0.2); text-decoration: none; }

        .alert-secondary { background: var(--bg-card2); border: 1px solid var(--border); color: var(--muted); font-size: 0.85rem; }
        .section-header { font-size: 0.75rem; letter-spacing: 2px; text-transform: uppercase; padding: 6px 0 6px 0; margin: 2rem 0 1rem 0; border-bottom: 1px solid var(--border); }
        .section-header.t1 { color: var(--green); }
        .section-header.t2 { color: var(--yellow); }
    </style>
</head>
<body>
<div class="container-fluid" style="max-width:1400px">

    <h2 class="mb-3 text-center">Attribution Analysis Report</h2>
    <div class="alert alert-secondary mb-4">
        <strong>Observations Analyzed:</strong> $($Observations -join " &nbsp;|&nbsp; ")
    </div>

    <!-- ===== SUMMARY TABLE ===== -->
    <div class="section-header t1">Hit Summary</div>
    <div class="summary-outer mb-4">
        <div class="summary-half">
            <div class="summary-col-header apt">APT Groups</div>
            <div class="sum-grid">$AptCells</div>
        </div>
        <div class="summary-half">
            <div class="summary-col-header mal">Malware Families</div>
            <div class="sum-grid">$MalCells</div>
        </div>
    </div>

    <!-- ===== TIER 1 ===== -->
    <div class="section-header t1">Tier 1 -- Multi-Indicator Matches (High Confidence)</div>
    <div class="row">
"@

    $Tier1Count = 0
    foreach ($Res in $Results) {
        if ($Res.MatchCount -gt 1) {
            $Tier1Count++

            $HeaderClass = if($Res.Type -eq "APT"){"tier1-apt"}else{"tier1-mal"}
            $TypeBadge   = if($Res.Type -eq "APT"){"badge-apt"}else{"badge-mal"}
            
            $HtmlContent += @"
        <div class="col-xl-4 col-lg-6">
            <div class="card h-100">
                <div class="card-header $HeaderClass">
                    <span>$($Res.Actor)</span>
                    <span class="$TypeBadge">$($Res.Type)</span>
                </div>
                <div class="card-body">
                    <h6>Matched Indicators</h6>
                    <ul>
"@
            foreach ($m in $Res.Matches) {
                $HtmlContent += "                        <li><span class='source-tag'>[$($m.Source)]</span><span class='match-highlight'>$($m.Indicator)</span></li>`n"
            }

            $HtmlContent += @"
                    </ul>
                    <hr>
                    <h6>Hunting Recommendations -- Pivot</h6>
                    <p class="small" style="color:var(--muted);margin-bottom:8px">If this is $($Res.Actor), pivot into these artifact categories:</p>
                    <div class="rec-links">
"@
            # Collect all unique categories for this actor and emit one link per category
            $AllCategories = $ActorJsonFiles[$Res.Actor]
            if ($AllCategories) {
                foreach ($Cat in ($AllCategories.Keys | Sort-Object)) {
                    $Link = $AllCategories[$Cat]
                    $HtmlContent += "                        <a class='rec-link' href='$Link'>$Cat</a>`n"
                }
            } else {
                $HtmlContent += "                        <span style='color:var(--muted);font-size:0.8rem'>No category files found</span>`n"
            }

            $HtmlContent += @"
                    </div>
                </div>
            </div>
        </div>
"@
        }
    }

    if ($Tier1Count -eq 0) { $HtmlContent += "        <p class='text-muted ps-2'>No multi-indicator matches found.</p>" }

    $HtmlContent += @"
    </div>

    <!-- ===== TIER 2 ===== -->
    <div class="section-header t2">Tier 2 -- Single Indicator Matches (Leads)</div>
    <div class="row">
"@

    foreach ($Res in $Results) {
        if ($Res.MatchCount -eq 1) {
            $TypeBadge = if($Res.Type -eq "APT"){"badge-apt"}else{"badge-mal"}
            $HtmlContent += @"
        <div class="col-xl-3 col-lg-4 col-md-6">
            <div class="card h-100">
                <div class="card-header tier2">
                    <span>$($Res.Actor)</span>
                    <span class="$TypeBadge">$($Res.Type)</span>
                </div>
                <div class="card-body">
                    <span class='source-tag'>[$($Res.Matches[0].Source)]</span><br>
                    <span class='match-highlight'>$($Res.Matches[0].Indicator)</span>
                </div>
            </div>
        </div>
"@
        }
    }

    $HtmlContent += @"
    </div>
</div>
</body>
</html>
"@

    if ($PassThru) {
        return $Results
    } else {
        $HtmlContent | Set-Content -Path $OutputHtmlPath -Encoding UTF8
        Write-Host "Analysis Complete. Report: $OutputHtmlPath" -ForegroundColor Green
    }
}