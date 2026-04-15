function Sync-NsrlReferenceSet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $InputCsv,

        [string] $BaselineRootPath = './baseline/',
        [string] $OutputDir = './output/',
        [int]    $MaxHashes = 0,
        [int]    $MaliciousThreshold = 3,
        [switch] $AppendToExisting
    )

    if (-not (Test-Path -LiteralPath $InputCsv)) {
        throw "Input CSV not found: $InputCsv"
    }

    $apiKey = Get-Secret -Name 'VT_API_Key_1' -AsPlainText -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($apiKey)) {
        throw "VirusTotal API secret 'VT_API_Key_1' is missing or empty."
    }
    $headers = @{ 'x-apikey' = $apiKey }

    if (-not (Test-Path -LiteralPath $OutputDir)) {
        New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
    }

    $signedFile   = 'nsrlSignedVerifiedBaseline.json'
    $winFile      = 'nsrlUnsignedWinBaseline.json'
    $linuxFile    = 'nsrlUnsignedLinuxBaseline.json'

    $loadBaseline = {
        param([string] $name)
        $p = Join-Path $BaselineRootPath $name
        if ($AppendToExisting -and (Test-Path -LiteralPath $p)) {
            try {
                $raw = Get-Content -LiteralPath $p -Raw -ErrorAction Stop
                if ([string]::IsNullOrWhiteSpace($raw)) { return @{} }
                $obj = $raw | ConvertFrom-Json -AsHashtable -ErrorAction Stop
                if ($null -eq $obj) { return @{} }
                return $obj
            } catch {
                Write-Warning "Failed to load baseline '$p': $($_.Exception.Message)"
                return @{}
            }
        }
        return @{}
    }

    $signed = & $loadBaseline $signedFile
    $unWin  = & $loadBaseline $winFile
    $unLnx  = & $loadBaseline $linuxFile

    $rows = Import-Csv -LiteralPath $InputCsv
    if ($MaxHashes -gt 0) {
        $rows = $rows | Select-Object -First $MaxHashes
    }

    $processed = 0
    $addSigned = 0
    $addWin = 0
    $addLnx = 0
    $excluded = 0
    $unknown = 0
    $skipped = 0

    foreach ($row in $rows) {
        $processed++
        $hash = $row.FileHash
        $platform = $row.Platform
        $fileName = $row.FileName

        $vtUrl = "https://www.virustotal.com/api/v3/files/$hash"
        $resp = $null
        $attempt = 0
        $delay = 15
        $maxAttempts = 5
        $failed = $false

        while ($attempt -lt $maxAttempts -and -not $resp -and -not $failed) {
            $attempt++
            try {
                $resp = Invoke-RestMethod -Uri $vtUrl -Headers $headers -Method Get -ErrorAction Stop
            } catch {
                $status = $_.Exception.Response.StatusCode.value__
                if ($status -eq 429) {
                    Start-Sleep -Seconds $delay
                    $delay = [Math]::Min($delay * 2, 240)
                    continue
                }
                if ($status -eq 404) {
                    Write-Warning "unknown to VT: $hash"
                    $unknown++
                    $failed = $true
                    break
                }
                Write-Warning "VT lookup failed for ${hash}: $($_.Exception.Message)"
                $failed = $true
                break
            }
        }

        if ($failed -or -not $resp) { continue }

        $attrs = $resp.data.attributes
        $stats = $attrs.last_analysis_stats
        $mal = [int] $stats.malicious

        if ($mal -ge $MaliciousThreshold) {
            $label = ''
            if ($attrs.popular_threat_classification) {
                $label = [string] $attrs.popular_threat_classification.suggested_threat_label
            }
            Write-Warning "Excluding malicious hash $hash (VT malicious=$mal, label='$label')"
            $excluded++
            continue
        }

        $sigInfo = $attrs.signature_info
        $isSigned = $false
        $isVerified = $false
        $signer = ''
        if ($sigInfo) {
            $verified = [string] $sigInfo.verified
            if ($verified -match '(?i)signed|valid|true') { $isVerified = $true }
            if ($sigInfo.signers) {
                $first = ($sigInfo.signers -split ';')[0].Trim()
                if ($first) { $signer = $first; $isSigned = $true }
            }
            if ($sigInfo.PSObject.Properties['signers detail'] -and -not $isSigned) {
                $isSigned = $true
            }
        }
        $trulyTrusted = $isSigned -and $isVerified -and -not [string]::IsNullOrWhiteSpace($signer)

        if ($trulyTrusted) {
            $key = $hash.ToUpperInvariant()
            if ($signed.ContainsKey($key)) {
                $existing = $signed[$key]
                if ($existing.entry -and $existing.entry.Count -ge 5) {
                    $existing.entry[4] = [int] $existing.entry[4] + 1
                }
            } else {
                $signed[$key] = @{ entry = @($fileName, 'Signed', $key, $signer, 1) }
            }
            $addSigned++
            continue
        }

        if ($platform -eq 'Windows') {
            $key = $hash.ToUpperInvariant()
            if ($unWin.ContainsKey($key)) {
                $existing = $unWin[$key]
                if ($existing.entry -and $existing.entry.Count -ge 5) {
                    $existing.entry[4] = [int] $existing.entry[4] + 1
                }
            } else {
                $unWin[$key] = @{ entry = @($fileName, 'Unsigned', $key, '', 1) }
            }
            $addWin++
        }
        elseif ($platform -eq 'Linux') {
            $key = $hash.ToUpperInvariant()
            if ($unLnx.ContainsKey($key)) {
                $existing = $unLnx[$key]
                if ($existing.entry -and $existing.entry.Count -ge 5) {
                    $existing.entry[4] = [int] $existing.entry[4] + 1
                }
            } else {
                $unLnx[$key] = @{ entry = @($fileName, 'Unsigned', $key, '', 1) }
            }
            $addLnx++
        }
        else {
            $skipped++
        }
    }

    $writeJson = {
        param([object] $data, [string] $name)
        $outPath = Join-Path $OutputDir $name
        $json = $data | ConvertTo-Json -Depth 8
        $utf8 = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($outPath, $json, $utf8)
    }

    try {
        & $writeJson $signed $signedFile
        & $writeJson $unWin  $winFile
        & $writeJson $unLnx  $linuxFile
    } catch {
        throw "Failed to write baseline JSON: $($_.Exception.Message)"
    }

    [pscustomobject]@{
        Processed          = $processed
        AddedToTrusted     = $addSigned
        AddedToUnsignedWin = $addWin
        AddedToUnsignedLinux = $addLnx
        Excluded           = $excluded
        Unknown            = $unknown
        Skipped            = $skipped
    }
}

Export-ModuleMember -Function Sync-NsrlReferenceSet
