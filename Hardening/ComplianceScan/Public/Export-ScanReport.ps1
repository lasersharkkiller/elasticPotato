function Export-ScanReport {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        $Findings,
        [string]$OutputPath = ".\ComplianceScan_Output",
        [ValidateSet("All","HTML","CSV")][string]$Format = "All",
        [ValidateSet("All","Pass","Fail","Warn")][string]$Status = "All",
        [ValidateSet("Auto","Workstation","Server","DomainController")][string]$Profile = "Auto"
    )

    process {
        if ($null -eq $Findings -or @($Findings).Count -eq 0) {
            $Findings = Invoke-ComplianceScan -Profile $Profile -Quiet
        }

        $allRows  = @($Findings)
        $filtered = if ($Status -eq "All") { $allRows } else { @($allRows | Where-Object { $_.Status -eq $Status }) }

        if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

        $stamp   = Get-Date -Format "yyyyMMdd_HHmmss"
        $csvPath = Join-Path $OutputPath "ComplianceReport_$stamp.csv"
        $htmPath = Join-Path $OutputPath "ComplianceReport_$stamp.html"

        # CSV
        if ($Format -in @("All","CSV")) {
            $filtered | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
            Write-Info "CSV  : $csvPath"
        }

        # HTML
        if ($Format -in @("All","HTML")) {
            $p     = @($allRows | Where-Object { $_.Status -eq "Pass" }).Count
            $f     = @($allRows | Where-Object { $_.Status -eq "Fail" }).Count
            $w     = @($allRows | Where-Object { $_.Status -eq "Warn" }).Count
            $total = $allRows.Count
            $score = if ($total -gt 0) { [math]::Round(($p / $total) * 100, 1) } else { 0 }
            $scoreColor = if ($score -ge 80) { "#4ade80" } elseif ($score -ge 50) { "#facc15" } else { "#f87171" }

            # Build NIST family breakdown for sidebar
            $families = $allRows | Group-Object NISTFamily | Sort-Object Name
            $familyRows = $families | ForEach-Object {
                $fam  = $_.Name
                $fp   = @($_.Group | Where-Object { $_.Status -eq "Pass" }).Count
                $ff   = @($_.Group | Where-Object { $_.Status -eq "Fail" }).Count
                $fw   = @($_.Group | Where-Object { $_.Status -eq "Warn" }).Count
                $ftot = $_.Count
                $fpct = if ($ftot -gt 0) { [math]::Round(($fp/$ftot)*100) } else { 0 }
                $barColor = if ($fpct -ge 80) { "#4ade80" } elseif ($fpct -ge 50) { "#facc15" } else { "#f87171" }
                @"
<div class="fam-row" onclick="filterFamily('$fam')">
  <div class="fam-name">$fam</div>
  <div class="fam-bar-wrap"><div class="fam-bar" style="width:$fpct%;background:$barColor"></div></div>
  <div class="fam-pct">$fpct%</div>
  <div class="fam-counts"><span style="color:#4ade80">$fp</span>/<span style="color:#f87171">$ff</span>/<span style="color:#fb923c">$fw</span></div>
</div>
"@
            }

            $rows = $filtered | ForEach-Object {
                $item = $_
                $rowBg = switch ($item.Status) {
                    "Pass" { "#0d2018" } "Fail" { "#2a0a0a" } "Warn" { "#2a2000" } default { "#111" }
                }
                $badge = switch ($item.Status) {
                    "Pass" { '<span class="badge pass">PASS</span>' }
                    "Fail" { '<span class="badge fail">FAIL</span>' }
                    "Warn" { '<span class="badge warn">WARN</span>' }
                    default{ '<span class="badge info">INFO</span>' }
                }
                "<tr style='background:$rowBg' data-family='$($item.NISTFamily)' data-status='$($item.Status)'>
                   <td><span class='nist-tag'>$($item.NISTControl)</span></td>
                   <td><span class='fam-tag'>$($item.NISTFamily)</span></td>
                   <td><span class='profile-tag'>$($item.Profile)</span></td>
                   <td>$($item.Category)</td>
                   <td>$($item.Setting)</td>
                   <td class='mono'>$($item.CurrentValue)</td>
                   <td class='mono'>$($item.RecommendedValue)</td>
                   <td>$badge</td>
                   <td class='ref'>$($item.CISReference)</td>
                 </tr>"
            }

            $rowsJoined   = $rows -join "`n"
            $familyJoined = $familyRows -join "`n"
            $genDate      = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            $hostName     = $env:COMPUTERNAME

            $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>NIST 800-53 Rev 5 Compliance Report</title>
  <style>
    * { box-sizing:border-box; margin:0; padding:0; }
    body { background:#0d0d1a; color:#cbd5e1; font-family:'Segoe UI',system-ui,sans-serif; display:flex; min-height:100vh; }
    .sidebar { width:280px; min-width:280px; background:#0a0a16; border-right:1px solid #1e1e3a; padding:1.5rem 1rem; position:sticky; top:0; height:100vh; overflow-y:auto; }
    .sidebar h2 { color:#818cf8; font-size:1rem; margin-bottom:1rem; letter-spacing:.05em; }
    .fam-row { padding:.5rem .4rem; border-radius:6px; cursor:pointer; margin-bottom:.4rem; transition:background .15s; }
    .fam-row:hover { background:#1e1e3a; }
    .fam-name { font-size:.78rem; font-weight:600; color:#a5b4fc; margin-bottom:.3rem; }
    .fam-bar-wrap { background:#1e1e3a; border-radius:4px; height:6px; margin-bottom:.2rem; }
    .fam-bar { height:6px; border-radius:4px; transition:width .3s; }
    .fam-pct { font-size:.72rem; color:#64748b; }
    .fam-counts { font-size:.72rem; margin-top:.1rem; }
    .fam-row.selected { background:#1e1e3a; border-left:3px solid #6366f1; padding-left:.6rem; }
    .main { flex:1; padding:2rem; overflow-x:auto; }
    h1 { color:#818cf8; font-size:1.8rem; margin-bottom:.25rem; }
    .sub { color:#64748b; font-size:.88rem; margin-bottom:1.5rem; }
    .stats { display:flex; gap:1rem; flex-wrap:wrap; margin-bottom:1.5rem; }
    .stat { background:#151528; border:1px solid #2d2d50; border-radius:10px; padding:.9rem 1.3rem; min-width:110px; }
    .stat .label { color:#64748b; font-size:.72rem; text-transform:uppercase; letter-spacing:.08em; }
    .stat .value { font-size:1.8rem; font-weight:700; margin-top:.1rem; }
    .score-value { color:$scoreColor; }
    table { width:100%; border-collapse:collapse; font-size:.8rem; }
    thead tr { background:#1e1e3a; position:sticky; top:0; z-index:1; }
    th { color:#a5b4fc; padding:.6rem .7rem; text-align:left; font-weight:600; white-space:nowrap; border-bottom:2px solid #2d2d50; }
    td { padding:.4rem .7rem; border-bottom:1px solid #1a1a30; vertical-align:middle; }
    tr:hover td { filter:brightness(1.3); }
    .badge { display:inline-block; padding:.12rem .45rem; border-radius:4px; font-size:.72rem; font-weight:700; letter-spacing:.05em; }
    .pass { background:#14532d; color:#4ade80; }
    .fail { background:#450a0a; color:#f87171; }
    .warn { background:#422006; color:#fb923c; }
    .info { background:#0c2044; color:#38bdf8; }
    .nist-tag { background:#1e293b; color:#a5b4fc; border-radius:4px; padding:.1rem .4rem; font-size:.72rem; font-family:monospace; white-space:nowrap; }
    .fam-tag  { background:#1e1e3a; color:#818cf8; border-radius:4px; padding:.1rem .4rem; font-size:.72rem; font-weight:600; }
    .profile-tag { background:#0f172a; color:#94a3b8; border-radius:4px; padding:.1rem .4rem; font-size:.72rem; }
    .mono { font-family:'Cascadia Code','Consolas',monospace; color:#94a3b8; font-size:.78rem; }
    .ref  { color:#4b5563; font-size:.74rem; }
    .filter-bar { display:flex; gap:.5rem; margin-bottom:1rem; flex-wrap:wrap; align-items:center; }
    .filter-btn { background:#1e1e3a; border:1px solid #2d2d50; color:#94a3b8; padding:.3rem .8rem;
                  border-radius:6px; cursor:pointer; font-size:.8rem; transition:all .15s; }
    .filter-btn:hover, .filter-btn.active { background:#3730a3; border-color:#6366f1; color:#fff; }
    .clear-btn { background:transparent; border:1px solid #374151; color:#6b7280; padding:.3rem .8rem;
                 border-radius:6px; cursor:pointer; font-size:.8rem; margin-left:auto; }
    .clear-btn:hover { border-color:#9ca3af; color:#d1d5db; }
  </style>
</head>
<body>
  <div class="sidebar">
    <h2>NIST 800-53 Families</h2>
    <div class="fam-row selected" id="fam-all" onclick="filterFamily('all')">
      <div class="fam-name">All Families</div>
      <div class="fam-counts" style="margin-top:.2rem"><span style="color:#4ade80">$p pass</span> / <span style="color:#f87171">$f fail</span> / <span style="color:#fb923c">$w warn</span></div>
    </div>
$familyJoined
  </div>

  <div class="main">
    <h1>NIST 800-53 Rev 5 Compliance Scan</h1>
    <p class="sub">Host: <strong>$hostName</strong> &nbsp;|&nbsp; Generated: $genDate &nbsp;|&nbsp; Filter: $Status</p>

    <div class="stats">
      <div class="stat"><div class="label">Score</div><div class="value score-value">$score%</div></div>
      <div class="stat"><div class="label">Total</div><div class="value" style="color:#cbd5e1">$total</div></div>
      <div class="stat"><div class="label">Pass</div><div class="value" style="color:#4ade80">$p</div></div>
      <div class="stat"><div class="label">Fail</div><div class="value" style="color:#f87171">$f</div></div>
      <div class="stat"><div class="label">Warn</div><div class="value" style="color:#fb923c">$w</div></div>
    </div>

    <div class="filter-bar">
      <button class="filter-btn active" onclick="filterStatus('all',this)">All</button>
      <button class="filter-btn" onclick="filterStatus('Pass',this)">Pass</button>
      <button class="filter-btn" onclick="filterStatus('Fail',this)">Fail</button>
      <button class="filter-btn" onclick="filterStatus('Warn',this)">Warn</button>
      <button class="clear-btn" onclick="clearFilters()">Clear Filters</button>
    </div>

    <table id="results">
      <thead><tr>
        <th>Control</th><th>Family</th><th>Profile</th><th>Category</th><th>Setting</th>
        <th>Current</th><th>Expected</th><th>Status</th><th>CIS Ref</th>
      </tr></thead>
      <tbody>
$rowsJoined
      </tbody>
    </table>
  </div>

  <script>
    var activeStatus = 'all';
    var activeFamily = 'all';

    function applyFilters() {
      document.querySelectorAll('#results tbody tr').forEach(function(row) {
        var fam    = row.getAttribute('data-family') || '';
        var status = row.getAttribute('data-status') || '';
        var showFam    = (activeFamily === 'all' || fam === activeFamily);
        var showStatus = (activeStatus === 'all' || status === activeStatus);
        row.style.display = (showFam && showStatus) ? '' : 'none';
      });
    }

    function filterStatus(s, btn) {
      activeStatus = s;
      document.querySelectorAll('.filter-btn').forEach(function(b){ b.classList.remove('active'); });
      btn.classList.add('active');
      applyFilters();
    }

    function filterFamily(f) {
      activeFamily = f;
      document.querySelectorAll('.fam-row').forEach(function(r){ r.classList.remove('selected'); });
      var el = (f === 'all') ? document.getElementById('fam-all') : null;
      if (!el) {
        document.querySelectorAll('.fam-row').forEach(function(r){
          if (r.querySelector('.fam-name') && r.querySelector('.fam-name').textContent === f) el = r;
        });
      }
      if (el) el.classList.add('selected');
      applyFilters();
    }

    function clearFilters() {
      activeStatus = 'all';
      activeFamily = 'all';
      document.querySelectorAll('.filter-btn').forEach(function(b){ b.classList.remove('active'); });
      document.querySelector('.filter-btn').classList.add('active');
      document.querySelectorAll('.fam-row').forEach(function(r){ r.classList.remove('selected'); });
      document.getElementById('fam-all').classList.add('selected');
      applyFilters();
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
