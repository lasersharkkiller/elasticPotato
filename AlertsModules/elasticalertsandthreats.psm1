function Get-ElasticAlertsAndThreats {
    <#
    .SYNOPSIS
        Queries Elastic Security alerts for an endpoint and shows a breakdown
        by severity (Critical / High / Medium / Low) with rule names.
    #>

    # --- API SETUP ---
    $esUrl  = (Get-Secret -Name 'Elastic_URL'  -AsPlainText -ErrorAction SilentlyContinue).Trim().TrimEnd('/')
    $esUser = (Get-Secret -Name 'Elastic_User' -AsPlainText -ErrorAction SilentlyContinue).Trim()
    $esPass = (Get-Secret -Name 'Elastic_Pass' -AsPlainText -ErrorAction SilentlyContinue).Trim()

    $b64Auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${esUser}:${esPass}"))
    $headers = @{ 'Authorization' = "Basic $b64Auth"; 'Content-Type' = 'application/json' }

    function Invoke-ES {
        param([string]$Path, [hashtable]$Body)
        $uri  = "$esUrl/$Path"
        $json = if ($Body) { $Body | ConvertTo-Json -Depth 20 -Compress } else { $null }
        try {
            if ($json) { return Invoke-RestMethod -Uri $uri -Headers $headers -Method Post -Body $json }
            else       { return Invoke-RestMethod -Uri $uri -Headers $headers -Method Get }
        } catch {
            $code = try { $_.Exception.Response.StatusCode.value__ } catch { "?" }
            Write-Host "  [ERROR] $Path  HTTP $code : $($_.Exception.Message)" -ForegroundColor Red
            return $null
        }
    }

    # --- INPUT ---
    $hostName = (Read-Host "Enter the Endpoint Name").Trim()
    if ($hostName -eq "") { $hostName = $env:COMPUTERNAME }

    $s = Read-Host "Enter date or leave blank for today (Ex: 2024-02-24)"
    if ($s) {
        try   { $result = Get-Date $s.Trim() }
        catch { Write-Host "Invalid date, using today." -ForegroundColor Yellow; $result = Get-Date }
    } else {
        $result = Get-Date
    }

    $fromTime = $result.Date.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $toTime   = $result.Date.AddDays(1).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

    Write-Host "`nQuerying alerts for '$hostName' on $($result.ToString('yyyy-MM-dd'))..." -ForegroundColor DarkCyan

    # --- FIND ALERT INDICES ---
    $catResp = Invoke-ES -Path "_cat/indices/.alerts-security*,.siem-signals*?h=index&s=index"
    $alertIndices = @()
    if ($catResp) {
        $alertIndices = ($catResp -split "`n" | Where-Object { $_.Trim() }) -join ","
    }
    if (-not $alertIndices) {
        # fallback to known defaults
        $alertIndices = ".alerts-security.alerts-default"
    }
    Write-Host "  Using indices: $alertIndices" -ForegroundColor DarkGray

    # --- MAIN QUERY: alerts only, no process/network/dns events ---
    $alertQuery = @{
        size  = 1000
        query = @{
            bool = @{
                must = @(
                    @{ range = @{ "@timestamp" = @{ gte = $fromTime; lt = $toTime } } }
                    @{ match = @{ "host.name" = $hostName } }
                )
                # must have a rule name - ensures we only get detection alerts, not raw events
                filter = @(
                    @{ exists = @{ field = "kibana.alert.rule.name" } }
                )
            }
        }
        _source = @("kibana.alert.rule.name", "kibana.alert.severity",
                    "kibana.alert.rule.severity", "@timestamp", "host.name")
        sort = @( @{ "@timestamp" = "asc" } )
    }

    $resp  = Invoke-ES -Path "$alertIndices/_search" -Body $alertQuery
    $hits  = if ($resp) { $resp.hits.hits } else { @() }
    $total = if ($resp -and $resp.hits.total) {
        if ($resp.hits.total -is [int]) { $resp.hits.total } else { $resp.hits.total.value }
    } else { 0 }

    # --- DIAGNOSTICS ON 0 RESULTS ---
    if ($total -eq 0) {
        Write-Host "  No alerts found. Running diagnostics..." -ForegroundColor Yellow

        # Check: any alerts at all in this index (no host/date filter)?
        $anyResp = Invoke-ES -Path "$alertIndices/_search" -Body @{
            size  = 0
            query = @{ bool = @{ filter = @( @{ exists = @{ field = "kibana.alert.rule.name" } } ) } }
            aggs  = @{ hosts = @{ terms = @{ field = "host.name"; size = 10 } } }
        }
        $anyTotal = if ($anyResp -and $anyResp.hits.total) {
            if ($anyResp.hits.total -is [int]) { $anyResp.hits.total } else { $anyResp.hits.total.value }
        } else { 0 }

        Write-Host "  Total alerts in index (all time, all hosts): $anyTotal" -ForegroundColor DarkGray

        if ($anyTotal -gt 0 -and $anyResp.aggregations.hosts.buckets) {
            Write-Host "  Host names found in alert index:" -ForegroundColor DarkGray
            foreach ($b in $anyResp.aggregations.hosts.buckets) {
                Write-Host "    '$($b.key)'  ($($b.doc_count) alerts)" -ForegroundColor DarkGray
            }
            Write-Host "  --> You entered: '$hostName'" -ForegroundColor Yellow
        } elseif ($anyTotal -eq 0) {
            Write-Host "  --> Alert index exists but contains no detection alerts." -ForegroundColor Yellow
            Write-Host "  --> Check that Elastic Security detection rules are enabled and have fired." -ForegroundColor Yellow
        }
        return
    }

    # --- GROUP BY SEVERITY ---
    $severityOrder  = @("critical","high","medium","low","unknown")
    $severityColors = @{ critical="Red"; high="DarkYellow"; medium="Yellow"; low="Cyan"; unknown="Gray" }
    $groups = @{}

    foreach ($h in $hits) {
        $src = $h._source
        $sev = $src.'kibana.alert.severity'
        if (-not $sev) { $sev = $src.'kibana.alert.rule.severity' }
        if (-not $sev) { $sev = "unknown" }
        $sev = $sev.ToLower()

        $ruleName = $src.'kibana.alert.rule.name'
        $ts       = $src.'@timestamp'

        if (-not $groups.ContainsKey($sev)) { $groups[$sev] = @() }
        $groups[$sev] += [PSCustomObject]@{ Rule = $ruleName; Time = $ts }
    }

    # --- OUTPUT ---
    Write-Host "`n==========================================" -ForegroundColor DarkCyan
    Write-Host "  ALERT SUMMARY" -ForegroundColor White
    Write-Host "  Host : $hostName"
    Write-Host "  Date : $($result.ToString('yyyy-MM-dd'))"
    Write-Host "  Total: $total alert(s)"
    Write-Host "==========================================" -ForegroundColor DarkCyan

    foreach ($sev in $severityOrder) {
        if (-not $groups.ContainsKey($sev)) { continue }
        $items = $groups[$sev]
        $color = $severityColors[$sev]
        Write-Host "`n  [$($sev.ToUpper())] - $($items.Count) alert(s)" -ForegroundColor $color
        foreach ($item in $items) {
            $timeStr = try { ([datetime]$item.Time).ToLocalTime().ToString("HH:mm:ss") } catch { $item.Time }
            Write-Host "    $timeStr  $($item.Rule)" -ForegroundColor $color
        }
    }

    Write-Host "`n==========================================" -ForegroundColor DarkCyan
}

Export-ModuleMember -Function Get-ElasticAlertsAndThreats
