function Get-ElasticPullIpsForProcess {
    <#
    .SYNOPSIS
        Elastic equivalent of Get-S1PullIpsForProcess.
        Queries outbound destination IPs for a given process name (or its
        children) over the last 14 days, excludes RFC1918/link-local/known
        Microsoft ranges, then runs the full ApiVoid bulk IP enrichment.

    .NOTES
        Requires vault secrets: Elastic_URL, Elastic_User, Elastic_Pass, APIVoid_API_Key
        Optional: CheckBlockedCountries.psm1, CheckSuspiciousASNs.psm1 in .\NewProcsModules\
    #>

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # --- LOAD OPTIONAL ENRICHMENT MODULES ---
    Import-Module -Name ".\NewProcsModules\CheckBlockedCountries.psm1" -ErrorAction SilentlyContinue
    Import-Module -Name ".\NewProcsModules\CheckSuspiciousASNs.psm1"   -ErrorAction SilentlyContinue

    # --- API SETUP ---
    $esUrl  = Get-Secret -Name 'Elastic_URL'  -AsPlainText
    $esUser = Get-Secret -Name 'Elastic_User' -AsPlainText
    $esPass = Get-Secret -Name 'Elastic_Pass' -AsPlainText

    $b64Auth  = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${esUser}:${esPass}"))
    $esHeaders = @{ 'Authorization' = "Basic $b64Auth"; 'Content-Type' = 'application/json' }

    $ApiVoidApi = Get-Secret -Name 'APIVoid_API_Key' -AsPlainText
    if ([string]::IsNullOrWhiteSpace($ApiVoidApi)) {
        Write-Error "STOPPING: APIVoid_API_Key is null or empty. Check your SecretStore."
        return
    }

    $eventsIndex = "logs-*,winlogbeat-*,filebeat-*,endgame-*"

    if (-not (Test-Path "output")) { New-Item -Path "output" -ItemType Directory | Out-Null }
    if (-not (Test-Path "nsm"))    { New-Item -Path "nsm"    -ItemType Directory | Out-Null }

    # --- INPUT ---
    $process = Read-Host "What process would you like to query outbound IPs for"
    if ([string]::IsNullOrWhiteSpace($process)) { Write-Error "Process name required."; return }

    $now         = Get-Date
    $currentTime = $now.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $fromTime    = $now.AddDays(-14).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

    Write-Host "`nQuerying outbound IPs for process: $process" -ForegroundColor DarkCyan
    Write-Host "Window: $fromTime -> $currentTime"

    # --- ELASTIC QUERY ---
    # Mirrors S1: src.process.name = '$process' or src.process.parent.name = '$process'
    # Excludes RFC1918, loopback, link-local, and the Microsoft Azure/O365 ranges
    # that S1 version explicitly excluded (20.190.*, 40.126.*)
    $esQuery = @{
        query = @{
            bool = @{
                must = @(
                    @{ range = @{ "@timestamp" = @{ gte = $fromTime; lte = $currentTime } } },
                    @{ term  = @{ "event.category" = "network" } },
                    @{ bool  = @{
                        should = @(
                            @{ term = @{ "process.name"        = $process } },
                            @{ term = @{ "process.parent.name" = $process } }
                        )
                        minimum_should_match = 1
                    }}
                )
                must_not = @(
                    # RFC1918 + loopback + link-local
                    @{ regexp = @{ "destination.ip" = "^10\\..*" } },
                    @{ regexp = @{ "destination.ip" = "^192\\.168\\..*" } },
                    @{ regexp = @{ "destination.ip" = "^172\\.(1[6-9]|2[0-9]|3[0-1])\\..*" } },
                    @{ regexp = @{ "destination.ip" = "^127\\..*" } },
                    @{ regexp = @{ "destination.ip" = "^169\\.254\\..*" } },
                    # Microsoft Azure/O365 ranges (matching S1 exclusions)
                    @{ regexp = @{ "destination.ip" = "^20\\.190\\..*" } },
                    @{ regexp = @{ "destination.ip" = "^40\\.126\\..*" } }
                )
            }
        }
        aggs = @{
            dst_ips = @{
                terms = @{
                    field = "destination.ip"
                    size  = 5000
                    order = @{ "_count" = "asc" }  # sort +count matching S1
                }
            }
        }
        size = 0
    }

    $bodyJson = $esQuery | ConvertTo-Json -Depth 20 -Compress
    $uri      = "$esUrl/$eventsIndex/_search"

    Write-Host "Sending query to Elasticsearch..." -ForegroundColor DarkGray
    try {
        $response = Invoke-RestMethod -Uri $uri -Headers $esHeaders -Method Post -Body $bodyJson
    } catch {
        $code = $null
        try { $code = $_.Exception.Response.StatusCode.value__ } catch {}
        Write-Host "[ERROR] ES query failed (HTTP $code): $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    $buckets = $response.aggregations.dst_ips.buckets
    if (-not $buckets -or $buckets.Count -eq 0) {
        Write-Host "No external outbound IPs found for process '$process' in the last 14 days." -ForegroundColor Yellow
        return
    }

    Write-Host "Found $($buckets.Count) unique external destination IPs." -ForegroundColor Green

    # Build the IP list in the format Get-CheckBulkIpsApiVoid expects
    # (array of objects with 'dst.ip.address' property - matching S1 output format)
    $ipList = $buckets | ForEach-Object {
        [PSCustomObject]@{ 'dst.ip.address' = $_.key; count = $_.doc_count }
    }

    # Save to the same temp file path the S1 version used
    $tempFile = "output\$process-dstIps.json"
    $ipList | ConvertTo-Json | Out-File $tempFile
    Write-Host "IP list saved to $tempFile" -ForegroundColor DarkGray

    # --- APIVOID BULK ENRICHMENT ---
    # Inline equivalent of Get-CheckBulkIpsApiVoid, consuming the same temp file
    $apivoidUrl     = 'https://api.apivoid.com/v2/ip-reputation'
    $apivoidHeaders = @{ "X-API-Key" = $ApiVoidApi; "Content-Type" = "application/json" }
    $outputCsv      = "nsm\$process-dstIps_apivoid.csv"
    $privateIpRegex = '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|127\.|169\.254\.)'

    $results  = @()
    $counter  = 0
    $totalIps = $ipList.Count

    Write-Host "`nStarting ApiVoid check on $totalIps IPs..." -ForegroundColor DarkCyan
    Write-Host "Output CSV: $outputCsv" -ForegroundColor Gray

    foreach ($item in $ipList) {
        $counter++
        $targetIp = $item.'dst.ip.address'
        if ([string]::IsNullOrWhiteSpace($targetIp)) { continue }

        $percent = ($counter / $totalIps) * 100
        Write-Progress -Activity "Checking IP Reputation" `
                       -Status "Processing $targetIp ($counter/$totalIps)" `
                       -PercentComplete $percent

        # Defaults
        $riskScore = 0; $countryCode = ""; $countryName = "Unknown"
        $isp = "Unknown"; $asn = "Unknown"; $asnOrg = "Unknown"
        $isProxy = $false; $isWebProxy = $false; $isVpn = $false
        $isHosting = $false; $isTor = $false; $isResidential = $false; $isRelay = $false
        $existsInCountryBlockList = $false; $existsInASNList = $false

        if ($targetIp -match $privateIpRegex) {
            $isp = "Private/Local Network"; $countryName = "Local"
            $asn = "Private"; $asnOrg = "Internal"
        } else {
            try {
                $body     = @{ ip = $targetIp } | ConvertTo-Json -Depth 3
                $avResp   = Invoke-RestMethod -Method "POST" -Uri $apivoidUrl `
                                              -Headers $apivoidHeaders -Body $body -ErrorAction Stop

                if ($avResp -and $avResp.information) {
                    $countryCode = if ($avResp.information.country_code) { $avResp.information.country_code } else { "" }
                    $countryName = if ($avResp.information.country_name) { $avResp.information.country_name } else { "Unknown" }
                    $asn         = if ($avResp.information.asn)          { $avResp.information.asn }          else { "Unknown" }
                    $isp         = if ($avResp.information.isp)          { $avResp.information.isp }          else { "Unknown" }
                    $riskScore   = if ($avResp.risk_score.result)        { $avResp.risk_score.result }        else { 0 }

                    if ($avResp.information.asn_organization)  { $asnOrg = $avResp.information.asn_organization }
                    elseif ($avResp.information.owner_name)    { $asnOrg = $avResp.information.owner_name }

                    if ($avResp.anonymity) {
                        $isProxy       = [bool]$avResp.anonymity.is_proxy
                        $isWebProxy    = [bool]$avResp.anonymity.is_webproxy
                        $isVpn         = [bool]$avResp.anonymity.is_vpn
                        $isHosting     = [bool]$avResp.anonymity.is_hosting
                        $isTor         = [bool]$avResp.anonymity.is_tor
                        $isResidential = [bool]$avResp.anonymity.is_residential_proxy
                        $isRelay       = [bool]$avResp.anonymity.is_relay
                    }
                }
            } catch {
                Write-Warning "ApiVoid error for ${targetIp}: $($_.Exception.Message)"
            }

            try {
                if ($countryName -ne "Unknown" -and (Get-Command Get-CheckBlockedCountries -ErrorAction SilentlyContinue)) {
                    $existsInCountryBlockList = Get-CheckBlockedCountries -country $countryName.Trim().ToLower()
                }
                if ($asn -ne "Unknown" -and (Get-Command Get-CheckSuspiciousASNs -ErrorAction SilentlyContinue)) {
                    $existsInASNList = Get-CheckSuspiciousASNs -asn $asn
                }
            } catch {}
        }

        $output = [PSCustomObject]@{
            ip                  = $targetIp
            ConnectionCount     = $item.count
            RiskScore           = $riskScore
            Country             = $countryCode
            CountryName         = $countryName
            IsGeoBlocked        = $existsInCountryBlockList
            ISP                 = $isp
            ASN                 = $asn
            ASN_Org             = $asnOrg
            IsASNSuspicious     = $existsInASNList
            IsProxy             = $isProxy
            IsWebProxy          = $isWebProxy
            IsVPN               = $isVpn
            IsHosting           = $isHosting
            IsTor               = $isTor
            IsResidential       = $isResidential
            IsRelay             = $isRelay
        }

        if ($riskScore -ge 90) {
            Write-Host "`n[HIGH RISK] $targetIp (Score: $riskScore)" -ForegroundColor Red
        }
        if ($existsInCountryBlockList) {
            Write-Host "`n[GEO BLOCK] $targetIp ($countryName) is in your Blocked Country list!" -ForegroundColor Red
        }

        $results += $output
    }

    Write-Progress -Activity "Checking IP Reputation" -Completed

    # --- EXPORT ---
    $results | Export-Csv -Path $outputCsv -NoTypeInformation
    Write-Host "`nResults saved to: $outputCsv" -ForegroundColor Green

    # --- SUMMARY ---
    $geoBlockedHits = $results | Where-Object { $_.IsGeoBlocked -eq $true }
    if ($geoBlockedHits) {
        Write-Host "`n--- Geo-Blocked Country Hits ---" -ForegroundColor Red
        $geoBlockedHits | Group-Object CountryName | Sort-Object Count -Descending |
            ForEach-Object { [PSCustomObject]@{ Country=$_.Name; Count=$_.Count } } | Format-Table -AutoSize
    }

    Write-Host "`n--- Anonymity Category Counts ---" -ForegroundColor DarkCyan
    @(
        [PSCustomObject]@{ Category='Proxy';              Count=($results | Where-Object IsProxy       -eq $true).Count },
        [PSCustomObject]@{ Category='Web Proxy';          Count=($results | Where-Object IsWebProxy    -eq $true).Count },
        [PSCustomObject]@{ Category='VPN';                Count=($results | Where-Object IsVPN         -eq $true).Count },
        [PSCustomObject]@{ Category='Hosting/DataCenter'; Count=($results | Where-Object IsHosting     -eq $true).Count },
        [PSCustomObject]@{ Category='Tor Node';           Count=($results | Where-Object IsTor         -eq $true).Count },
        [PSCustomObject]@{ Category='Residential Proxy';  Count=($results | Where-Object IsResidential -eq $true).Count },
        [PSCustomObject]@{ Category='Relay';              Count=($results | Where-Object IsRelay       -eq $true).Count }
    ) | Format-Table -AutoSize

    Write-Host "`n--- ISP / ASN Distribution (Top 20) ---" -ForegroundColor DarkCyan
    $ispGroups = $results |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_.ISP) -and $_.ISP -ne "Unknown" } |
        Group-Object ISP | Sort-Object Count -Descending | Select-Object -First 20

    $fmt = "{0,-40} {1,-10} {2,-30} {3,5}"
    Write-Host ($fmt -f "ISP Name", "ASN", "Organization", "Count") -ForegroundColor DarkCyan
    Write-Host ("-" * 90) -ForegroundColor DarkCyan
    foreach ($grp in $ispGroups) {
        $line = $fmt -f $grp.Name, $grp.Group[0].ASN, $grp.Group[0].ASN_Org, $grp.Count
        if ($grp.Group[0].IsASNSuspicious) { Write-Host $line -ForegroundColor Yellow }
        else { Write-Host $line -ForegroundColor Gray }
    }

    # --- CLEANUP TEMP FILE (matching S1 version behavior) ---
    Remove-Item -Path $tempFile -ErrorAction SilentlyContinue
}

Export-ModuleMember -Function Get-ElasticPullIpsForProcess