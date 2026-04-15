function Export-CMMCScanReport {
<#
.SYNOPSIS
    Exports CMMC 2.0 scan findings to HTML and CSV reports.
#>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)] $Findings,
        [string]$OutputPath = ".\CMMCScan_Output",
        [ValidateSet("All","HTML","CSV")][string]$Format = "All",
        [ValidateSet("All","Pass","Fail","Warn")][string]$Status = "All",
        [ValidateSet("All","L1","L2")][string]$Level = "All"
    )

    process {
        if ($null -eq $Findings -or @($Findings).Count -eq 0) {
            $Findings = Invoke-CMMCScan -Level 1 -Quiet
        }
        $allRows  = @($Findings)
        $filtered = $allRows
        if ($Status -ne "All") { $filtered = @($filtered | Where-Object { $_.Status   -eq $Status }) }
        if ($Level  -ne "All") { $filtered = @($filtered | Where-Object { $_.Level    -eq $Level  }) }

        if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
        $stamp   = Get-Date -Format "yyyyMMdd_HHmmss"
        $csvPath = Join-Path $OutputPath "CMMCReport_$stamp.csv"
        $htmPath = Join-Path $OutputPath "CMMCReport_$stamp.html"

        if ($Format -in @("All","CSV")) {
            $filtered | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
            Write-Info "CSV  : $csvPath"
        }

        if ($Format -in @("All","HTML")) {
            $m      = @($allRows | Where-Object { $_.Status -eq "Manual" }).Count
            $p      = @($allRows | Where-Object { $_.Status -eq "Pass"   }).Count
            $f      = @($allRows | Where-Object { $_.Status -eq "Fail"   }).Count
            $w      = @($allRows | Where-Object { $_.Status -eq "Warn"   }).Count
            $total  = $allRows.Count
            $scored = $total - $m
            $score  = if ($scored -gt 0) { [math]::Round(($p / $scored) * 100, 1) } else { 0 }
            $circ   = 339.3
            $filled = [math]::Round($score / 100 * $circ, 1)
            $empty  = [math]::Round($circ - $filled, 1)
            $sc     = if ($score -ge 80) { '#22c55e' } elseif ($score -ge 50) { '#f59e0b' } else { '#ef4444' }

            $domainCards = ($allRows | Group-Object Domain | Sort-Object Name | ForEach-Object {
                $dn    = $_.Name; $dt = $_.Count
                $dp    = @($_.Group | Where-Object { $_.Status -eq "Pass"   }).Count
                $df    = @($_.Group | Where-Object { $_.Status -eq "Fail"   }).Count
                $dw    = @($_.Group | Where-Object { $_.Status -eq "Warn"   }).Count
                $dm    = @($_.Group | Where-Object { $_.Status -eq "Manual" }).Count
                $dsc   = $dt - $dm
                $dpct  = if ($dsc -gt 0) { [math]::Round($dp / $dsc * 100) } else { 100 }
                $dfpct = if ($dsc -gt 0) { [math]::Round($df / $dsc * 100) } else { 0 }
                $dwpct = if ($dsc -gt 0) { [math]::Round($dw / $dsc * 100) } else { 0 }
                $mn    = if ($dm -gt 0) { " <span class='m'>$dm Manual</span>" } else { "" }
                "<div class='dc'><div class='dn'>$dn</div>" +
                "<div class='bt'><div class='bp' style='width:${dpct}%'></div></div>" +
                "<div class='bt'><div class='bfl' style='width:${dfpct}%'></div></div>" +
                "<div class='bt'><div class='bw' style='width:${dwpct}%'></div></div>" +
                "<div class='ds'><span class='p'>$dp Pass</span> <span class='f'>$df Fail</span> <span class='ww'>$dw Warn</span>$mn</div></div>"
            }) -join ""

            $tableRows = ($filtered | ForEach-Object {
                $sc2 = switch ($_.Status) { "Pass"{"pass"} "Fail"{"fail"} "Warn"{"warn"} "Manual"{"manual"} default{"warn"} }
                $lc  = if ($_.Level -eq "L1") { "l1" } else { "l2" }
                "<tr data-s='$($_.Status)'>" +
                "<td><span class='pid'>$($_.CMMCPractice)</span></td>" +
                "<td><span class='badge bdomain'>$($_.Domain)</span></td>" +
                "<td><span class='badge b$lc'>$($_.Level)</span></td>" +
                "<td class='desc'>$($_.Description)</td>" +
                "<td class='mono dim'>$($_.CurrentValue)</td>" +
                "<td class='mono muted'>$($_.ExpectedValue)</td>" +
                "<td><span class='badge b$sc2'>$($_.Status)</span></td>" +
                "<td class='mono muted'>$($_.NISTMapping)</td></tr>"
            }) -join "`n"

            $gd = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            $hn = $env:COMPUTERNAME; $un = $env:USERNAME

            $html  = "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>"
            $html += "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            $html += "<title>CMMC 2.0 Assessment - $hn</title><style>"
            $html += ":root{--bg:#07090f;--s1:#0d1117;--s2:#161b27;--bdr:#1e3a5f;--txt:#e2e8f0;"
            $html += "--dim:#94a3b8;--muted:#475569;--pass:#22c55e;--fail:#ef4444;--warn:#f59e0b;"
            $html += "--manual:#22d3ee;--accent:#3b82f6;--cyan:#06b6d4}"
            $html += "*{box-sizing:border-box;margin:0;padding:0}"
            $html += "body{background:var(--bg);color:var(--txt);font-family:'Segoe UI',system-ui,sans-serif;font-size:14px}"
            $html += ".hdr{background:linear-gradient(135deg,#060d1a 0%,#0d1f3c 60%,#0f2650 100%);padding:28px 36px;border-bottom:1px solid var(--bdr)}"
            $html += ".hdr h1{font-size:1.5rem;color:#60a5fa;letter-spacing:2px;font-weight:300}"
            $html += ".hdr h1 strong{font-weight:700;color:#93c5fd}"
            $html += ".sub{color:var(--dim);font-size:.82rem;margin-top:6px}.sub span{margin-right:18px}"
            $html += ".sw{display:flex;align-items:center;gap:32px;padding:24px 36px;background:var(--s1);border-bottom:1px solid var(--bdr);flex-wrap:wrap}"
            $html += ".gauge{position:relative;width:110px;height:110px;flex-shrink:0}"
            $html += ".gauge svg{transform:rotate(-90deg)}"
            $html += ".gt{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;line-height:1}"
            $html += ".gp{font-size:1.4rem;font-weight:700}.gl{font-size:.62rem;color:var(--dim);text-transform:uppercase;letter-spacing:1px;margin-top:3px}"
            $html += ".cards{display:flex;gap:12px;flex-wrap:wrap}"
            $html += ".card{background:var(--s2);border:1px solid var(--bdr);border-radius:10px;padding:14px 20px;min-width:88px;text-align:center}"
            $html += ".card .n{font-size:1.8rem;font-weight:700;line-height:1}.card .l{font-size:.68rem;color:var(--dim);text-transform:uppercase;letter-spacing:1px;margin-top:5px}"
            $html += ".cp .n{color:var(--pass)}.cf .n{color:var(--fail)}.cw .n{color:var(--warn)}.cm .n{color:var(--manual)}"
            $html += ".sec{padding:20px 36px}"
            $html += ".st{font-size:.78rem;color:var(--cyan);text-transform:uppercase;letter-spacing:2px;border-bottom:1px solid var(--bdr);padding-bottom:8px;margin-bottom:14px}"
            $html += ".dgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:10px}"
            $html += ".dc{background:var(--s1);border:1px solid var(--bdr);border-radius:8px;padding:12px 14px}"
            $html += ".dn{font-weight:600;font-size:.85rem;margin-bottom:7px}"
            $html += ".bt{background:#0a0e18;border-radius:3px;height:5px;margin:3px 0;overflow:hidden}"
            $html += ".bp{background:var(--pass);height:100%;border-radius:3px}.bfl{background:var(--fail);height:100%;border-radius:3px}.bw{background:var(--warn);height:100%;border-radius:3px}"
            $html += ".ds{font-size:.7rem;margin-top:7px}.ds span{margin-right:8px}"
            $html += ".ds .p{color:var(--pass)}.ds .f{color:var(--fail)}.ds .ww{color:var(--warn)}.ds .m{color:var(--manual)}"
            $html += ".tb{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:12px}"
            $html += ".fb{background:var(--s2);border:1px solid var(--bdr);color:var(--dim);padding:5px 14px;border-radius:16px;cursor:pointer;font-size:.76rem;transition:all .2s;font-family:inherit}"
            $html += ".fb:hover{border-color:var(--accent);color:var(--txt)}"
            $html += ".fb.on{background:var(--accent);border-color:var(--accent);color:#fff}"
            $html += ".fb.fp.on{background:var(--pass);border-color:var(--pass)}.fb.ff.on{background:var(--fail);border-color:var(--fail)}"
            $html += ".fb.fw.on{background:var(--warn);border-color:var(--warn);color:#000}.fb.fm.on{background:var(--manual);border-color:var(--manual);color:#000}"
            $html += ".srch{background:var(--s2);border:1px solid var(--bdr);color:var(--txt);padding:5px 12px;border-radius:6px;font-size:.8rem;width:220px;margin-left:auto;font-family:inherit}"
            $html += ".srch:focus{outline:none;border-color:var(--accent)}"
            $html += "table{width:100%;border-collapse:collapse}"
            $html += "thead th{background:var(--s2);color:var(--dim);font-size:.68rem;text-transform:uppercase;letter-spacing:1px;padding:9px 10px;border-bottom:2px solid var(--bdr);text-align:left;white-space:nowrap}"
            $html += "tbody tr{border-bottom:1px solid #0d1117;transition:background .15s}tbody tr:hover{background:#111d30}"
            $html += "td{padding:7px 10px;vertical-align:middle}"
            $html += ".badge{display:inline-block;padding:2px 9px;border-radius:10px;font-size:.68rem;font-weight:600;text-transform:uppercase;letter-spacing:.4px;white-space:nowrap}"
            $html += ".bpass{background:rgba(34,197,94,.12);color:var(--pass);border:1px solid rgba(34,197,94,.25)}"
            $html += ".bfail{background:rgba(239,68,68,.12);color:var(--fail);border:1px solid rgba(239,68,68,.25)}"
            $html += ".bwarn{background:rgba(245,158,11,.12);color:var(--warn);border:1px solid rgba(245,158,11,.25)}"
            $html += ".bmanual{background:rgba(34,211,238,.12);color:var(--manual);border:1px solid rgba(34,211,238,.25)}"
            $html += ".bl1{background:rgba(99,102,241,.12);color:#818cf8;border:1px solid rgba(99,102,241,.25)}"
            $html += ".bl2{background:rgba(168,85,247,.12);color:#c084fc;border:1px solid rgba(168,85,247,.25)}"
            $html += ".bdomain{background:rgba(59,130,246,.1);color:#60a5fa;border:1px solid rgba(59,130,246,.2)}"
            $html += ".pid{font-family:monospace;font-weight:700;color:var(--cyan);font-size:.8rem}"
            $html += ".desc{max-width:260px}.mono{font-family:monospace;font-size:.76rem}.dim{color:var(--dim)}.muted{color:var(--muted)}"
            $html += "tr.hide{display:none}"
            $html += ".ft{text-align:center;padding:20px 36px;color:var(--muted);font-size:.75rem;border-top:1px solid var(--bdr);margin-top:16px}"
            $html += "@keyframes ring{from{stroke-dasharray:0 339.3}}.ring{animation:ring 1s ease-out forwards}"
            $html += "</style></head><body>"
            $html += "<div class='hdr'><h1>CMMC 2.0 <strong>Assessment Report</strong></h1>"
            $html += "<div class='sub'><span>&#128197; $gd</span><span>&#128421; $hn</span><span>&#128100; $un</span></div></div>"
            $html += "<div class='sw'><div class='gauge'><svg width='110' height='110' viewBox='0 0 110 110'>"
            $html += "<circle cx='55' cy='55' r='46' fill='none' stroke='#1e293b' stroke-width='10'/>"
            $html += "<circle cx='55' cy='55' r='46' fill='none' stroke='$sc' stroke-width='10' stroke-linecap='round' class='ring' stroke-dasharray='$filled $empty'/>"
            $html += "</svg><div class='gt'><div class='gp' style='color:$sc'>$score%</div><div class='gl'>Score</div></div></div>"
            $html += "<div class='cards'>"
            $html += "<div class='card cp'><div class='n'>$p</div><div class='l'>Pass</div></div>"
            $html += "<div class='card cf'><div class='n'>$f</div><div class='l'>Fail</div></div>"
            $html += "<div class='card cw'><div class='n'>$w</div><div class='l'>Warn</div></div>"
            $html += "<div class='card cm'><div class='n'>$m</div><div class='l'>Manual</div></div>"
            $html += "<div class='card'><div class='n'>$total</div><div class='l'>Total</div></div>"
            $html += "</div></div>"
            $html += "<div class='sec'><div class='st'>Domain Breakdown</div><div class='dgrid'>$domainCards</div></div>"
            $html += "<div class='sec'><div class='st'>Findings</div><div class='tb'>"
            $html += "<button class='fb on'  data-s='All'   >All ($total)</button>"
            $html += "<button class='fb fp'  data-s='Pass'  >Pass ($p)</button>"
            $html += "<button class='fb ff'  data-s='Fail'  >Fail ($f)</button>"
            $html += "<button class='fb fw'  data-s='Warn'  >Warn ($w)</button>"
            $html += "<button class='fb fm'  data-s='Manual'>Manual ($m)</button>"
            $html += "<input class='srch' type='text' placeholder='Search...' oninput='srch(this.value)'>"
            $html += "</div><table><thead><tr>"
            $html += "<th>Practice</th><th>Domain</th><th>Lvl</th><th>Description</th>"
            $html += "<th>Current</th><th>Expected</th><th>Status</th><th>NIST</th>"
            $html += "</tr></thead><tbody>$tableRows</tbody></table></div>"
            $html += "<div class='ft'>CMMC 2.0 Assessment &bull; $hn &bull; $gd &bull; KnowNormal</div>"
            $html += "<script>var cur='All';"
            $html += "document.querySelectorAll('.fb').forEach(function(b){"
            $html += "b.addEventListener('click',function(){filter(this);});});"
            $html += "function filter(b){cur=b.dataset.s;"
            $html += "document.querySelectorAll('.fb').forEach(function(x){x.classList.remove('on');});"
            $html += "b.classList.add('on');apply();}"
            $html += "function srch(q){q=q.toLowerCase();"
            $html += "document.querySelectorAll('tbody tr').forEach(function(r){"
            $html += "r.classList.toggle('hide',r.textContent.toLowerCase().indexOf(q)<0);});}"
            $html += "function apply(){document.querySelectorAll('tbody tr').forEach(function(r){"
            $html += "r.classList.toggle('hide',cur!=='All'&&r.dataset.s!==cur);});}"
            $html += "</script></body></html>"

            [System.IO.File]::WriteAllText($htmPath, $html, [System.Text.Encoding]::UTF8)
            Write-Host "HTML : $htmPath"
        }
        Write-Host "CMMC Report complete. Score: $score% ($p/$scored passed, $m manual)"
    }
}
