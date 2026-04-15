function Test-AsnWatchlist {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string] $Asn
    )

    $watchlistPath = Join-Path -Path (Get-Location) -ChildPath 'output/suspiciousASNs.txt'

    $normalize = {
        param([string] $value)
        if ([string]::IsNullOrWhiteSpace($value)) { return $null }
        $trimmed = $value.Trim()
        if ($trimmed.StartsWith('#')) { return $null }
        $stripped = ($trimmed -replace '^(?i)AS', '').Trim()
        if ($stripped -match '^\d+$') { return [int64] $stripped }
        return $null
    }

    $needle = & $normalize $Asn
    if ($null -eq $needle) { return $false }

    if (-not (Test-Path -LiteralPath $watchlistPath)) {
        Write-Warning "ASN watchlist not found at '$watchlistPath'."
        return $false
    }

    try {
        $lines = Get-Content -LiteralPath $watchlistPath -ErrorAction Stop
    } catch {
        Write-Warning "Failed to read ASN watchlist: $($_.Exception.Message)"
        return $false
    }

    foreach ($line in $lines) {
        $entry = & $normalize $line
        if ($null -ne $entry -and $entry -eq $needle) {
            return $true
        }
    }

    return $false
}

Export-ModuleMember -Function Test-AsnWatchlist
