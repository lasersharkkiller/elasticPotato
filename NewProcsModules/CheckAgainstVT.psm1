$script:PrivateIpPatterns = @(
    '^10\.',
    '^127\.',
    '^192\.168\.',
    '^172\.(1[6-9]|2[0-9]|3[0-1])\.',
    '^169\.254\.',
    '^0\.0\.0\.0$',
    '^255\.255\.255\.255$'
)

function Test-IsPrivateIp {
    param([string] $Ip)
    foreach ($p in $script:PrivateIpPatterns) {
        if ($Ip -match $p) { return $true }
    }
    return $false
}

function Invoke-VtArtifactLookup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]] $Artifacts,

        [Parameter(Mandatory)]
        [ValidateSet('IPAddress', 'DomainName')]
        [string] $Type
    )

    $apiKey = Get-Secret -Name 'VT_API_Key_1' -AsPlainText -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($apiKey)) {
        throw "VirusTotal API secret 'VT_API_Key_1' is missing or empty."
    }

    $headers = @{ 'x-apikey' = $apiKey }

    $effective = @()
    if ($Type -eq 'IPAddress') {
        foreach ($a in $Artifacts) {
            if ([string]::IsNullOrWhiteSpace($a)) { continue }
            $ip = $a.Trim()
            if (Test-IsPrivateIp -Ip $ip) {
                Write-Verbose "Skipping private/bogon IP: $ip"
                continue
            }
            $effective += $ip
        }
    } else {
        $extractorAvailable = Get-Command -Name ConvertFrom-UrlDomainExtract -ErrorAction SilentlyContinue
        foreach ($a in $Artifacts) {
            if ([string]::IsNullOrWhiteSpace($a)) { continue }
            if ($extractorAvailable) {
                $extracted = ConvertFrom-UrlDomainExtract -InputText $a
                foreach ($d in $extracted) { $effective += $d }
            } else {
                $effective += $a.Trim().ToLowerInvariant()
            }
        }
        $effective = $effective | Sort-Object -Unique
    }

    $results = foreach ($artifact in $effective) {
        $url = if ($Type -eq 'IPAddress') {
            "https://www.virustotal.com/api/v3/ip_addresses/$artifact"
        } else {
            "https://www.virustotal.com/api/v3/domains/$artifact"
        }

        try {
            $resp = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -ErrorAction Stop
        } catch {
            Write-Warning "VT lookup failed for '$artifact': $($_.Exception.Message)"
            continue
        }

        $attrs = $resp.data.attributes
        $stats = $attrs.last_analysis_stats

        [pscustomobject]@{
            Artifact   = $artifact
            Malicious  = [int] ($stats.malicious  | ForEach-Object { $_ })
            Suspicious = [int] ($stats.suspicious | ForEach-Object { $_ })
            Undetected = [int] ($stats.undetected | ForEach-Object { $_ })
            Harmless   = [int] ($stats.harmless   | ForEach-Object { $_ })
            ASN        = if ($Type -eq 'IPAddress') { $attrs.asn } else { '' }
            ASN_Owner  = if ($Type -eq 'IPAddress') { $attrs.as_owner } else { '' }
            Country    = [string] $attrs.country
        }
    }

    return $results
}

Export-ModuleMember -Function Invoke-VtArtifactLookup
