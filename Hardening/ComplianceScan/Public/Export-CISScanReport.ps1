function Export-CISScanReport {
<#
.SYNOPSIS
    Exports CIS scan findings to HTML and CSV reports.
#>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        $Findings,
        [string]$OutputPath = ".\CISScan_Output",
        [ValidateSet("All","HTML","CSV")][string]$Format = "All",
        [ValidateSet("All","Pass","Fail","Warn")][string]$Status = "All",
        [ValidateSet("All","L1","L2")][string]$Level = "All"
    )

    process {
        if ($null -eq $Findings -or @($Findings).Count -eq 0) {
            $Findings = Invoke-CISScan -Level 1 -Quiet
        }

        $allRows  = @($Findings)
        $filtered = $allRows
        if ($Status -ne "All") { $filtered = @($filtered | Where-Object { $_.Status -eq $Status }) }
        if ($Level  -ne "All") { $filtered = @($filtered | Where-Object { $_.CISLevel -eq $Level  }) }

        if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

        $stamp   = Get-Date -Format "yyyyMMdd_HHmmss"
        $csvPath = Join-Path $OutputPath "CISReport_$stamp.csv"
        $htmPath = Join-Path $OutputPath "CISReport_$stamp.html"

        if ($Format -in @("All","CSV")) {
            $filtered | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
            Write-Info "CSV  : $csvPath"
        }

        if ($Format -in @("All","HTML")) {
            $p     = @($allRows | Where-Object { $_.Status -eq "Pass" }).Count
            $f     = @($allRows | Where-Object { $_.Status -eq "Fail" }).Count
            $w     = @($allRows | Where-Object { $_.Status -eq "Warn" }).Count
            $l1    = @($allRows | Where-Object { $_.CISLevel -eq "L1" }).Count
            $l2    = @($allRows | Where-Object { $_.CISLevel -eq "L2" }).Count
            $total = $allRows.Count
            $score = if ($total -gt 0) { [math]::Round(($p / $total) * 100, 1) } else { 0 }
            $sc    = if ($score -ge 80) { "#4ade80" } elseif ($score -ge 50) { "#facc15" } else { "#f87171" }

            # Section breakdown for sidebar
            $sections = $allRows | Group-Object Section | Sort-Object Name
            $sectionRows = $sections | ForEach-Object {
                $sec = $_.Name
                $sp  = @($_.Group | Where-Object { $_.Status -eq "Pass" }).Count
                $sf  = @($_.Group | Where-Object { $_.Status -eq "Fail" }).Count
                $sw  = @($_.Group | Where-Object { $_.Status -eq "Warn" }).Count
                $st  = $_.Count
                $pct = if ($st -gt 0) { [math]::Round(($sp/$st)*100) } else { 0 }
                $bc  = if ($pct -ge 80) { "#4ade80" } elseif ($pct -ge 50) { "#facc15" } else { "#f87171" }
                @"
<div class="sec-row" onclick="filterSection('$sec')">
  <div class="sec-name">$sec</div>
  <div class="bar-wrap"><div class="bar" style="width:$pct%;background:$bc"></div></div>
  <div class="sec-meta">$pct% &nbsp; <span style="color:#4ade80">$sp</span>/<span style="color:#f87171">$sf</span>/<span style="color:#fb923c">$sw</span></div>
</div>
"@
            }

            $rows = $filtered | ForEach-Object {
                $item = $_
                $bg = switch ($item.Status) {
                    "Pass" { "#0d2018" } "Fail" { "#2a0a0a" } "Warn" { "#2a2000" } default { "#111" }
                }
                $badge = switch ($item.Status) {
                    "Pass" { '<span class="badge pass">PASS</span>' }
                    "Fail" { '<span class="badge fail">FAIL</span>' }
                    "Warn" { '<span class="badge warn">WARN</span>' }
                    default{ '<span class="badge info">INFO</span>' }
                }
                $lvlBadge = if ($item.CISLevel -eq "L2") { '<span class="l2tag">L2</span>' } else { '<span class="l1tag">L1</span>' }
                "<tr style='background:$bg' data-section='$($item.Section)' data-status='$($item.Status)' data-level='$($item.CISLevel)'>
                   <td><span class='cis-id'>$($item.CISControl)</span></td>
                   <td>$lvlBadge</td>
                   <td><span class='prof-tag'>$($item.Profile)</span></td>
                   <td>$($item.Section)</td>
                   <td>$($item.Setting)</td>
                   <td class='mono'>$($item.CurrentValue)</td>
                   <td class='mono'>$($item.RecommendedValue)</td>
                   <td>$badge</td>
                   <td class='nist'>$($item.NISTMapping)</td>
                 </tr>"
            }

            $rowsJ    = $rows -join "`n"
            $sectionsJ= $sectionRows -join "`n"
            $genDate  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            $hostName = $env:COMPUTERNAME

            $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>CIS Benchmark Report</title>
  <style>
    * { box-sizing:border-box; margin:0; padding:0; }
    body { background:#0d0d1a; color:#cbd5e1; font-family:'Segoe UI',system-ui,sans-serif; display:flex; min-height:100vh; }
    .sidebar { width:260px; min-width:260px; background:#08080f; border-right:1px solid #1a1a30; padding:1.2rem .8rem; position:sticky; top:0; height:100vh; overflow-y:auto; }
    .sidebar h2 { color:#818cf8; font-size:.9rem; margin-bottom:.8rem; letter-spacing:.06em; text-transform:uppercase; }
    .sec-row { padding:.45rem .4rem; border-radius:5px; cursor:pointer; margin-bottom:.3rem; transition:background .15s; }
    .sec-row:hover,.sec-row.selected { background:#1a1a2e; border-left:3px solid #6366f1; padding-left:.5rem; }
    .sec-name { font-size:.75rem; font-weight:600; color:#a5b4fc; margin-bottom:.25rem; }
    .bar-wrap { background:#1e1e3a; border-radius:3px; height:5px; margin-bottom:.2rem; }
    .bar { height:5px; border-radius:3px; }
    .sec-meta { font-size:.7rem; color:#64748b; }
    .main { flex:1; padding:1.8rem; overflow-x:auto; }
    h1 { color:#818cf8; font-size:1.6rem; margin-bottom:.2rem; }
    .sub { color:#64748b; font-size:.85rem; margin-bottom:1.2rem; }
    .stats { display:flex; gap:.8rem; flex-wrap:wrap; margin-bottom:1.2rem; }
    .stat { background:#111124; border:1px solid #1e1e3a; border-radius:8px; padding:.7rem 1.1rem; min-width:100px; }
    .stat .lbl { color:#64748b; font-size:.7rem; text-transform:uppercase; letter-spacing:.07em; }
    .stat .val { font-size:1.6rem; font-weight:700; margin-top:.1rem; }
    table { width:100%; border-collapse:collapse; font-size:.78rem; }
    thead tr { background:#1a1a2e; position:sticky; top:0; z-index:1; }
    th { color:#a5b4fc; padding:.55rem .65rem; text-align:left; font-weight:600; white-space:nowrap; border-bottom:2px solid #1e1e3a; }
    td { padding:.38rem .65rem; border-bottom:1px solid #13132a; vertical-align:middle; }
    tr:hover td { filter:brightness(1.25); }
    .badge { display:inline-block; padding:.1rem .4rem; border-radius:3px; font-size:.7rem; font-weight:700; }
    .pass { background:#14532d; color:#4ade80; }
    .fail { background:#450a0a; color:#f87171; }
    .warn { background:#422006; color:#fb923c; }
    .info { background:#0c2044; color:#38bdf8; }
    .cis-id { font-family:monospace; color:#a5b4fc; background:#1e1e3a; padding:.1rem .35rem; border-radius:3px; font-size:.72rem; white-space:nowrap; }
    .l1tag { background:#1e3a1e; color:#4ade80; padding:.1rem .3rem; border-radius:3px; font-size:.68rem; font-weight:700; }
    .l2tag { background:#2a1e00; color:#facc15; padding:.1rem .3rem; border-radius:3px; font-size:.68rem; font-weight:700; }
    .prof-tag { background:#0f172a; color:#94a3b8; border-radius:3px; padding:.1rem .35rem; font-size:.7rem; }
    .mono { font-family:monospace; color:#94a3b8; font-size:.75rem; max-width:180px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
    .nist { color:#4b5563; font-size:.72rem; }
    .filter-bar { display:flex; gap:.4rem; flex-wrap:wrap; margin-bottom:.8rem; align-items:center; }
    .fbtn { background:#1a1a2e; border:1px solid #1e1e3a; color:#94a3b8; padding:.28rem .7rem; border-radius:5px; cursor:pointer; font-size:.78rem; }
    .fbtn:hover,.fbtn.active { background:#3730a3; border-color:#6366f1; color:#fff; }
    .cbtn { background:transparent; border:1px solid #374151; color:#6b7280; padding:.28rem .7rem; border-radius:5px; cursor:pointer; font-size:.78rem; margin-left:auto; }
    .cbtn:hover { border-color:#9ca3af; color:#d1d5db; }
  </style>
</head>
<body>
  <div class="sidebar">
    <h2>CIS Sections</h2>
    <div class="sec-row selected" id="sec-all" onclick="filterSection('all')">
      <div class="sec-name">All Sections</div>
      <div class="sec-meta"><span style="color:#4ade80">$p pass</span> / <span style="color:#f87171">$f fail</span> / <span style="color:#fb923c">$w warn</span></div>
    </div>
$sectionsJ
  </div>

  <div class="main">
    <h1>CIS Benchmark Compliance Report</h1>
    <p class="sub">Host: <strong>$hostName</strong> &nbsp;|&nbsp; Generated: $genDate &nbsp;|&nbsp; Filters: Status=$Status, Level=$Level</p>

    <div class="stats">
      <div class="stat"><div class="lbl">Score</div><div class="val" style="color:$sc">$score%</div></div>
      <div class="stat"><div class="lbl">Total</div><div class="val" style="color:#cbd5e1">$total</div></div>
      <div class="stat"><div class="lbl">Pass</div><div class="val" style="color:#4ade80">$p</div></div>
      <div class="stat"><div class="lbl">Fail</div><div class="val" style="color:#f87171">$f</div></div>
      <div class="stat"><div class="lbl">Warn</div><div class="val" style="color:#fb923c">$w</div></div>
      <div class="stat"><div class="lbl">L1 Checks</div><div class="val" style="color:#4ade80">$l1</div></div>
      <div class="stat"><div class="lbl">L2 Checks</div><div class="val" style="color:#facc15">$l2</div></div>
    </div>

    <div class="filter-bar">
      <button class="fbtn active" onclick="filterStatus('all',this)">All</button>
      <button class="fbtn" onclick="filterStatus('Pass',this)">Pass</button>
      <button class="fbtn" onclick="filterStatus('Fail',this)">Fail</button>
      <button class="fbtn" onclick="filterStatus('Warn',this)">Warn</button>
      <span style="color:#4b5563;margin:0 .3rem;">|</span>
      <button class="fbtn" onclick="filterLevel('all',this)">All Levels</button>
      <button class="fbtn" onclick="filterLevel('L1',this)">L1 Only</button>
      <button class="fbtn" onclick="filterLevel('L2',this)">L2 Only</button>
      <button class="cbtn" onclick="clearAll()">Clear Filters</button>
    </div>

    <table id="results">
      <thead><tr>
        <th>CIS ID</th><th>Level</th><th>Profile</th><th>Section</th><th>Setting</th>
        <th>Current</th><th>Expected</th><th>Status</th><th>NIST</th>
      </tr></thead>
      <tbody>
$rowsJ
      </tbody>
    </table>
  </div>

  <script>
    var aStatus = 'all', aSection = 'all', aLevel = 'all';
    function apply() {
      document.querySelectorAll('#results tbody tr').forEach(function(r) {
        var s = r.dataset.status, sec = r.dataset.section, lv = r.dataset.level;
        var ok = (aStatus==='all'||s===aStatus) && (aSection==='all'||sec===aSection) && (aLevel==='all'||lv===aLevel);
        r.style.display = ok ? '' : 'none';
      });
    }
    function filterStatus(v,b) {
      aStatus=v;
      document.querySelectorAll('.fbtn').forEach(function(x){ if(x.onclick.toString().includes('filterStatus')) x.classList.remove('active'); });
      b.classList.add('active'); apply();
    }
    function filterLevel(v,b) {
      aLevel=v;
      document.querySelectorAll('.fbtn').forEach(function(x){ if(x.onclick.toString().includes('filterLevel')) x.classList.remove('active'); });
      b.classList.add('active'); apply();
    }
    function filterSection(v) {
      aSection=v;
      document.querySelectorAll('.sec-row').forEach(function(r){ r.classList.remove('selected'); });
      var el = (v==='all') ? document.getElementById('sec-all') : null;
      if (!el) document.querySelectorAll('.sec-name').forEach(function(n){ if(n.textContent===v) el=n.parentElement; });
      if (el) el.classList.add('selected');
      apply();
    }
    function clearAll() {
      aStatus='all'; aSection='all'; aLevel='all';
      document.querySelectorAll('.fbtn').forEach(function(b,i){ b.classList.toggle('active',i===0||i===4); });
      document.querySelectorAll('.sec-row').forEach(function(r){ r.classList.remove('selected'); });
      document.getElementById('sec-all').classList.add('selected');
      apply();
    }
  </script>
</body>
</html>
"@
            $html | Set-Content -Path $htmPath -Encoding UTF8
            Write-Info "HTML : $htmPath"
        }

        return [PSCustomObject]@{ CsvPath = $csvPath; HtmlPath = $htmPath }
    }
}
