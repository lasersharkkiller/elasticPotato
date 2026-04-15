$script:PrivateIpPatterns = @(
    '^10\.',
    '^127\.',
    '^192\.168\.',
    '^172\.(1[6-9]|2[0-9]|3[0-1])\.',
    '^169\.254\.',
    '^0\.0\.0\.0$',
    '^255\.255\.255\.255$'
)

function Test-IsPrivateIpApiVoid {
    param([string] $Ip)
    foreach ($p in $script:PrivateIpPatterns) {
        if ($Ip -match $p) { return $true }
    }
    return $false
}

function Invoke-ApiVoidReputation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]] $Artifacts,

        [Parameter(Mandatory)]
        [ValidateSet('IPAddress', 'DomainName')]
        [string] $Type
    )

    $apiKey = Get-Secret -Name 'APIVoid_API_Key' -AsPlainText -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($apiKey)) {
        throw "APIVoid secret 'APIVoid_API_Key' is missing or empty."
    }

    $headers = @{
        'X-API-Key'    = $apiKey
        'Content-Type' = 'application/json'
    }

    $lastResponse = $null

    foreach ($artifact in $Artifacts) {
        if ([string]::IsNullOrWhiteSpace($artifact)) { continue }
        $a = $artifact.Trim()

        if ($Type -eq 'IPAddress' -and (Test-IsPrivateIpApiVoid -Ip $a)) {
            Write-Host "Skipping private/bogon IP: $a"
            continue
        }

        $url = if ($Type -eq 'IPAddress') {
            'https://api.apivoid.com/v2/ip-reputation'
        } else {
            'https://api.apivoid.com/v2/domain-reputation'
        }

        $body = if ($Type -eq 'IPAddress') {
            @{ ip = $a } | ConvertTo-Json -Compress
        } else {
            @{ host = $a } | ConvertTo-Json -Compress
        }

        try {
            $resp = Invoke-RestMethod -Uri $url -Headers $headers -Method Post -Body $body -ErrorAction Stop
        } catch {
            Write-Error "APIVoid lookup failed for '$a': $($_.Exception.Message)" -ErrorAction Continue
            continue
        }

        $lastResponse = $resp
        $response = $resp.response

        if ($Type -eq 'IPAddress') {
            $info      = $response.information
            $anonymity = $response.anonymity
            $risk      = $response.risk_score

            $asnRaw = [string] $info.asn
            $isWatch = $false
            if (-not [string]::IsNullOrWhiteSpace($asnRaw)) {
                $isWatch = Test-AsnWatchlist -Asn $asnRaw
            }
            $color = if ($isWatch) { 'Yellow' } else { [System.ConsoleColor]::Gray }

            Write-Host ("Country: {0}" -f $info.country_name)
            Write-Host ("ISP: {0}" -f $info.isp) -ForegroundColor $color
            Write-Host ("ASN: {0}" -f $info.asn) -ForegroundColor $color

            foreach ($flag in 'is_proxy','is_webproxy','is_vpn','is_hosting','is_tor') {
                if ($anonymity.$flag) {
                    $label = ($flag -replace '^is_', '') -replace '_', ' '
                    $label = (Get-Culture).TextInfo.ToTitleCase($label)
                    Write-Host ("Is {0}: true" -f $label) -ForegroundColor Yellow
                }
            }

            $score = [int] $risk.result
            $scoreColor = if ($score -eq 0) { 'Green' } elseif ($score -lt 50) { 'Yellow' } else { 'Red' }
            Write-Host ("ApiVoid Risk Score: {0}" -f $score) -ForegroundColor $scoreColor
        }
        else {
            $srv   = $response.server_details
            $cat   = $response.category
            $risk  = $response.risk_score

            $asnRaw = [string] $srv.asn
            $isWatch = $false
            if (-not [string]::IsNullOrWhiteSpace($asnRaw)) {
                $isWatch = Test-AsnWatchlist -Asn $asnRaw
            }
            $color = if ($isWatch) { 'Yellow' } else { [System.ConsoleColor]::Gray }

            Write-Host ("Country: {0}" -f $srv.country_name)
            Write-Host ("ISP: {0}" -f $srv.isp) -ForegroundColor $color
            Write-Host ("ASN: {0}" -f $srv.asn) -ForegroundColor $color

            foreach ($flag in 'is_free_hosting','is_anonymizer','is_url_shortener','is_free_dynamic_dns','is_code_sandbox','is_form_builder','is_free_file_sharing','is_pastebin') {
                if ($cat.$flag) {
                    $label = ($flag -replace '^is_', '') -replace '_', ' '
                    $label = (Get-Culture).TextInfo.ToTitleCase($label)
                    Write-Host ("Is {0}: true" -f $label) -ForegroundColor Yellow
                }
            }

            $score = [int] $risk.result
            $scoreColor = if ($score -eq 0) { 'Green' } elseif ($score -lt 50) { 'Yellow' } else { 'Red' }
            Write-Host ("ApiVoid Risk Score: {0}" -f $score) -ForegroundColor $scoreColor
        }
    }

    return $lastResponse
}

Export-ModuleMember -Function Invoke-ApiVoidReputation
