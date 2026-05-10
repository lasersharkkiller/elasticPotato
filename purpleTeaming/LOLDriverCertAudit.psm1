<#
.Module Name
    LOLDriverCertAudit
.SYNOPSIS
    LOLDriver certificate validation pen test toolkit.
.DESCRIPTION
    Tests whether an EDR independently validates driver certificate expiry and
    revocation, or blindly trusts Windows Code Integrity.

    Phase 1 (Find-LOLDriverCandidates):
        Pulls the LOLDrivers.io catalog and lists test candidates — drivers with
        expired certs, pre-2015 timestamps, or revoked certs that are NOT on
        Microsoft's blocklist.

    Phase 2 (Test-DriverCertificate):
        For a given .sys binary: inspects its Authenticode signature, performs
        independent CRL/OCSP revocation checking, compares against Windows CI
        verdict, identifies gaps.

    Phase 3 (Invoke-LOLDriverAudit):
        Full pen test: cert analysis + optional kernel load + Elastic SIEM
        detection query.  Outputs structured CSV for reporting.

    The core finding this module validates: most EDRs (including Elastic Defend)
    trust Windows CI for driver signature validation.  Windows CI honours a
    "timestamp exception" for pre-July-2015 cross-signed drivers, meaning expired
    and even revoked certificates are accepted if the Authenticode timestamp
    predates the cross-signing deadline.
#>

# ==================== Internal helpers ====================

function Get-ElasticApiKeyInternal {
    param([string]$ApiKeyFromParam)

    if ($ApiKeyFromParam) { return $ApiKeyFromParam }

    try {
        $k = Get-Secret -Name 'Elastic_API_Key' -AsPlainText
        if ($k) { return $k }
    } catch { }

    if ($env:ELASTIC_API_KEY) { return $env:ELASTIC_API_KEY }

    return $null
}

# ==================== Public functions ====================

function Get-AuthenticodeDetail {
    <#
    .SYNOPSIS
        Returns detailed Authenticode signature info for a driver file,
        including cert subject, issuer, expiry, timestamp, and
        revocation status via .NET X509Chain with online CRL/OCSP.
    .PARAMETER FilePath
        Path to the .sys driver file.
    .EXAMPLE
        Get-AuthenticodeDetail -FilePath C:\test\RTCore64.sys
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )

    if (-not (Test-Path $FilePath)) {
        Write-Error "File not found: $FilePath"
        return
    }

    $result = [ordered]@{
        FilePath            = $FilePath
        FileName            = Split-Path $FilePath -Leaf
        SHA256              = (Get-FileHash $FilePath -Algorithm SHA256).Hash
        SignatureStatus     = "Unknown"
        CertSubject         = ""
        CertIssuer          = ""
        CertNotBefore       = ""
        CertNotAfter        = ""
        CertExpired         = $false
        CertThumbprint      = ""
        TimestampDate       = ""
        TimestampPreJul2015 = $false
        RevocationStatus    = "Unknown"
        ChainStatus         = ""
        WindowsCIVerdict    = ""
    }

    $sig = Get-AuthenticodeSignature -FilePath $FilePath
    $result.WindowsCIVerdict = $sig.Status.ToString()

    if ($sig.SignerCertificate) {
        $cert = $sig.SignerCertificate
        $result.SignatureStatus = $sig.Status.ToString()
        $result.CertSubject    = $cert.Subject
        $result.CertIssuer     = $cert.Issuer
        $result.CertNotBefore  = $cert.NotBefore.ToString("yyyy-MM-dd")
        $result.CertNotAfter   = $cert.NotAfter.ToString("yyyy-MM-dd")
        $result.CertExpired    = ($cert.NotAfter -lt (Get-Date))
        $result.CertThumbprint = $cert.Thumbprint

        # Independent revocation check via X509Chain (online CRL + OCSP)
        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.RevocationMode =
            [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
        $chain.ChainPolicy.RevocationFlag =
            [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::EntireChain
        $chain.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::FromSeconds(10)
        $chain.ChainPolicy.VerificationFlags =
            [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag

        try {
            $chainBuilt = $chain.Build($cert)
            $statuses = $chain.ChainStatus | ForEach-Object { $_.Status.ToString() }
            $result.ChainStatus = ($statuses -join "; ")

            if ($statuses -contains "Revoked") {
                $result.RevocationStatus = "REVOKED"
            } elseif ($statuses -contains "RevocationStatusUnknown") {
                $result.RevocationStatus = "UNKNOWN (CRL/OCSP unreachable)"
            } elseif ($chainBuilt) {
                $result.RevocationStatus = "NOT_REVOKED"
            } else {
                $result.RevocationStatus = "CHAIN_ERROR"
            }
        } catch {
            $result.RevocationStatus = "ERROR: $($_.Exception.Message)"
        } finally {
            $chain.Dispose()
        }

        # Extract timestamp countersignature date
        if ($sig.TimeStamperCertificate) {
            try {
                $tsOutput = & signtool.exe verify /v /pa $FilePath 2>&1 |
                    Select-String "Timestamp:"
                if ($tsOutput) {
                    $tsStr = ($tsOutput -replace ".*Timestamp:\s*", "").Trim()
                    $tsDate = [DateTime]::Parse($tsStr)
                    $result.TimestampDate = $tsDate.ToString("yyyy-MM-dd")
                    $result.TimestampPreJul2015 = ($tsDate -lt [DateTime]"2015-07-29")
                }
            } catch {
                $result.TimestampDate = "(signtool unavailable)"
            }
        }
    }

    return [PSCustomObject]$result
}


function Test-DriverCertificate {
    <#
    .SYNOPSIS
        Analyses a driver's Authenticode certificate and identifies EDR
        detection gaps caused by Windows CI trust.
    .PARAMETER FilePath
        Path to the .sys driver file.
    .EXAMPLE
        Test-DriverCertificate -FilePath C:\test\RTCore64.sys
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )

    $detail = Get-AuthenticodeDetail -FilePath $FilePath
    if (-not $detail) { return }

    $gaps = @()

    if ($detail.CertExpired -and $detail.WindowsCIVerdict -eq "Valid") {
        $gaps += "CERT EXPIRED but Windows CI says Valid -- EDRs trusting CI will miss this"
    }
    if ($detail.TimestampPreJul2015 -and $detail.CertExpired) {
        $gaps += "PRE-2015 TIMESTAMP + EXPIRED -- stockpiled cert scenario, timestamp exception active"
    }
    if ($detail.RevocationStatus -eq "REVOKED" -and $detail.WindowsCIVerdict -eq "Valid") {
        $gaps += "CERT REVOKED but Windows CI says Valid -- CRL not cached, EDRs trusting CI will miss this"
    }
    if ($detail.RevocationStatus -eq "UNKNOWN (CRL/OCSP unreachable)") {
        $gaps += "REVOCATION STATUS UNKNOWN -- air-gapped or CRL unreachable, EDRs cannot verify"
    }

    Write-Host "`n  ===== Certificate Analysis: $($detail.FileName) =====" -ForegroundColor Cyan
    Write-Host "  SHA256:            $($detail.SHA256)"
    Write-Host "  Cert Subject:      $($detail.CertSubject)"
    Write-Host "  Cert Issuer:       $($detail.CertIssuer)"
    Write-Host "  Cert Valid:        $($detail.CertNotBefore) to $($detail.CertNotAfter)"
    Write-Host "  Cert Expired:      $($detail.CertExpired)" -ForegroundColor $(
        if ($detail.CertExpired) { "Red" } else { "Green" })
    Write-Host "  Timestamp:         $($detail.TimestampDate)"
    Write-Host "  Pre-Jul-2015 TS:   $($detail.TimestampPreJul2015)" -ForegroundColor $(
        if ($detail.TimestampPreJul2015) { "Red" } else { "Green" })
    Write-Host "  Revocation:        $($detail.RevocationStatus)" -ForegroundColor $(
        if ($detail.RevocationStatus -eq "REVOKED") { "Red" }
        elseif ($detail.RevocationStatus -eq "NOT_REVOKED") { "Green" }
        else { "Yellow" })
    Write-Host "  Windows CI Verdict:$($detail.WindowsCIVerdict)" -ForegroundColor $(
        if ($detail.WindowsCIVerdict -eq "Valid") { "Yellow" } else { "Green" })
    Write-Host ""

    if ($gaps.Count -eq 0) {
        Write-Host "  [+] No certificate validation gaps detected." -ForegroundColor Green
    } else {
        foreach ($gap in $gaps) {
            Write-Host "  [GAP] $gap" -ForegroundColor Red
        }
    }
    Write-Host ""

    return [PSCustomObject]@{
        Detail = $detail
        Gaps   = $gaps
    }
}


function Find-LOLDriverCandidates {
    <#
    .SYNOPSIS
        Pulls the LOLDrivers.io catalog and lists drivers suitable for
        certificate validation pen testing.
    .DESCRIPTION
        Identifies drivers that are NOT on Microsoft's blocklist and categorises
        them as test candidates.  Use SHA256 hashes to download samples from
        VirusTotal or MalwareBazaar, then run Test-DriverCertificate on each.
    .PARAMETER Top
        Number of candidates to display per category (default 15).
    .EXAMPLE
        Find-LOLDriverCandidates -Top 20
    #>
    [CmdletBinding()]
    param(
        [int]$Top = 15
    )

    Write-Host "[*] Fetching LOLDrivers.io catalog..." -ForegroundColor Yellow

    $json = Invoke-RestMethod -Uri "https://www.loldrivers.io/api/drivers.json"

    $candidates = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($driver in $json) {
        $tags = ($driver.Tags -join ", ")
        $category = $driver.Category

        $onBlocklist = $false
        if ($driver.Commands.DriverBlocklistEntry) { $onBlocklist = $true }

        foreach ($sample in $driver.KnownVulnerableSamples) {
            $sha256 = $sample.SHA256
            if (-not $sha256) { continue }
            if ($onBlocklist) { continue }

            $candidates.Add([PSCustomObject]@{
                SHA256      = $sha256
                DriverName  = if ($sample.OriginalFilename) { $sample.OriginalFilename } else { "(unknown)" }
                Publisher   = if ($sample.Publisher) { $sample.Publisher } else { "(unknown)" }
                Tags        = $tags
                Category    = $category
            })
        }
    }

    Write-Host "`n[*] LOLDrivers.io catalog: $($json.Count) drivers total" -ForegroundColor Cyan
    Write-Host "[*] Not on MS blocklist:   $($candidates.Count) samples" -ForegroundColor Cyan

    Write-Host "`n--- Top $Top candidates (not blocklisted) ---" -ForegroundColor Yellow
    $candidates | Select-Object -First $Top |
        Format-Table DriverName, Publisher, Category, SHA256 -AutoSize

    Write-Host @"

[*] Next steps:
    1. Download candidate .sys files by SHA256 from VirusTotal or MalwareBazaar:
         Get-VTZippedSamplesFromList  (from this repo)
         or: https://bazaar.abuse.ch/browse/

    2. Inspect each driver's certificate:
         Test-DriverCertificate -FilePath <path_to_sys>

    3. Look for these gap indicators:
         CertExpired = True  AND  WindowsCIVerdict = Valid   --> timestamp exception bypass
         TimestampPreJul2015 = True                          --> stockpiled pre-cross-signing cert
         RevocationStatus = REVOKED  AND  WindowsCIVerdict = Valid  --> CRL cache miss

    4. Full pen test with load + Elastic verification:
         Invoke-LOLDriverAudit -DriverPath <path> -ElasticUrl <url> -ElasticApiKey <key>

    Known good starting samples:
      RTCore64.sys    -- MSI Afterburner, CVE-2019-16098
      WinRing0x64.sys -- CPU-Z/HWMonitor, widely abused
      dbutil_2_3.sys  -- Dell, CVE-2021-21551

"@ -ForegroundColor Gray

    return $candidates
}


function Invoke-LOLDriverAudit {
    <#
    .SYNOPSIS
        Full LOLDriver certificate pen test: cert analysis, optional kernel load,
        and Elastic SIEM detection verification.
    .DESCRIPTION
        For a given driver binary:
          1. Authenticode signature analysis (subject, issuer, expiry, timestamp)
          2. Independent CRL/OCSP revocation check via X509Chain
          3. Gap analysis (Windows CI verdict vs. actual cert status)
          4. Optional kernel driver load test (with confirmation prompt)
          5. Optional Elastic SIEM query for detection events
          6. Structured CSV output for reporting
    .PARAMETER DriverPath
        Path to the .sys driver file to test.
    .PARAMETER ElasticUrl
        (Optional) Elastic SIEM base URL (e.g., https://elastic.lab:9200).
    .PARAMETER ElasticApiKey
        (Optional) Elastic API key for querying detections.
    .PARAMETER OutputCsv
        Path for the results CSV (default: LOLDriverAudit_results.csv).
    .PARAMETER SkipLoad
        Skip the kernel driver load test (cert analysis only).
    .EXAMPLE
        Invoke-LOLDriverAudit -DriverPath C:\test\RTCore64.sys

    .EXAMPLE
        Invoke-LOLDriverAudit -DriverPath C:\test\RTCore64.sys `
            -ElasticUrl https://elastic:9200 -ElasticApiKey "base64key"

    .EXAMPLE
        # Batch test all .sys files in a directory
        Get-ChildItem C:\test\drivers\*.sys | ForEach-Object {
            Invoke-LOLDriverAudit -DriverPath $_.FullName -SkipLoad -OutputCsv batch_results.csv
        }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$DriverPath,

        [string]$ElasticUrl,
        [string]$ElasticApiKey,
        [string]$OutputCsv = "LOLDriverAudit_results.csv",
        [switch]$SkipLoad
    )

    if (-not (Test-Path $DriverPath)) {
        Write-Error "File not found: $DriverPath"
        return
    }

    Write-Host @"

  ================================================================
   LOLDriver Certificate Validation Pen Test
   Tests EDR independent cert checking vs. Windows CI trust
  ================================================================

"@ -ForegroundColor Cyan

    # --- Step 1-3: Certificate analysis + gap identification ---
    Write-Host "[1/4] Certificate analysis + gap identification..." -ForegroundColor Cyan
    $testResult = Test-DriverCertificate -FilePath $DriverPath
    if (-not $testResult) { return }

    $detail = $testResult.Detail
    $gaps   = $testResult.Gaps

    # --- Step 4: Optional driver load test ---
    $loadSuccess = "NOT_TESTED"
    $loadError   = ""

    if (-not $SkipLoad) {
        Write-Host "[2/4] Driver load test..." -ForegroundColor Cyan

        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
            ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isAdmin) {
            Write-Warning "Driver load requires Administrator. Run as admin or use -SkipLoad."
        } else {
            $confirm = Read-Host "  Load this driver into the kernel? Type 'YES' to proceed"
            if ($confirm -eq "YES") {
                $svcName = "LOLDrvTest"
                $targetPath = Join-Path $env:TEMP "$svcName.sys"
                Copy-Item $DriverPath $targetPath -Force

                try {
                    $createOut = & sc.exe create $svcName binPath= $targetPath type= kernel 2>&1
                    if ($LASTEXITCODE -ne 0) {
                        $loadSuccess = $false
                        $loadError = "sc create failed: $createOut"
                        Write-Host "  [+] Service creation failed: $createOut" -ForegroundColor Green
                    } else {
                        $startOut = & sc.exe start $svcName 2>&1
                        if ($LASTEXITCODE -eq 0) {
                            $loadSuccess = $true
                            Write-Host "  [!] DRIVER LOADED SUCCESSFULLY" -ForegroundColor Red
                        } else {
                            $loadSuccess = $false
                            $loadError = "sc start failed: $startOut"
                            Write-Host "  [+] Driver load blocked: $startOut" -ForegroundColor Green
                        }
                    }
                } finally {
                    & sc.exe stop $svcName 2>&1 | Out-Null
                    & sc.exe delete $svcName 2>&1 | Out-Null
                    Remove-Item $targetPath -Force -ErrorAction SilentlyContinue
                }

                if ($loadSuccess -eq $true) {
                    Write-Host "  Waiting 10s for EDR detections..." -ForegroundColor Yellow
                    Start-Sleep -Seconds 10
                }
            }
        }
    } else {
        Write-Host "[2/4] Driver load: SKIPPED (-SkipLoad)" -ForegroundColor Gray
    }

    # --- Step 5: Elastic SIEM query ---
    $elasticDetections = @()
    $apiKey = Get-ElasticApiKeyInternal -ApiKeyFromParam $ElasticApiKey

    if ($ElasticUrl -and $apiKey) {
        Write-Host "[3/4] Querying Elastic SIEM..." -ForegroundColor Cyan

        $headers = @{
            "Authorization" = "ApiKey $apiKey"
            "Content-Type"  = "application/json"
        }

        $driverName = Split-Path $DriverPath -Leaf
        $query = @{
            query = @{
                bool = @{
                    must = @(
                        @{ range = @{ "@timestamp" = @{ gte = "now-5m" } } }
                        @{ bool = @{
                            should = @(
                                @{ match_phrase = @{ "dll.name" = $driverName } }
                                @{ match_phrase = @{ "file.name" = $driverName } }
                                @{ match_phrase = @{ "process.name" = "sc.exe" } }
                            )
                            minimum_should_match = 1
                        }}
                    )
                }
            }
            size = 50
            sort = @( @{ "@timestamp" = "desc" } )
        } | ConvertTo-Json -Depth 10

        try {
            $response = Invoke-RestMethod -Uri "$ElasticUrl/.ds-logs-*/_search" `
                -Method Post -Headers $headers -Body $query -SkipCertificateCheck

            $elasticDetections = $response.hits.hits | ForEach-Object {
                [PSCustomObject]@{
                    Timestamp        = $_._source.'@timestamp'
                    EventCategory    = $_._source.event.category
                    RuleName         = $_._source.rule.name
                    SignatureStatus  = $_._source.dll.code_signature.status
                    SignatureTrusted = $_._source.dll.code_signature.trusted
                    SignatureSubject = $_._source.dll.code_signature.subject_name
                }
            }

            if ($elasticDetections.Count -eq 0) {
                Write-Host "  [GAP] No Elastic detections found!" -ForegroundColor Red
                $gaps += "ELASTIC: No detection events for this driver load"
            } else {
                Write-Host "  Elastic detections found: $($elasticDetections.Count)" -ForegroundColor Green
                $elasticDetections | Format-Table -AutoSize
            }
        } catch {
            Write-Warning "Elastic query failed: $($_.Exception.Message)"
        }
    } else {
        Write-Host "[3/4] Elastic SIEM query: SKIPPED (no URL/key)" -ForegroundColor Gray
    }

    # --- Step 6: CSV output ---
    Write-Host "[4/4] Writing results..." -ForegroundColor Cyan

    $record = [PSCustomObject][ordered]@{
        Timestamp        = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        FileName         = $detail.FileName
        SHA256           = $detail.SHA256
        CertSubject      = $detail.CertSubject
        CertIssuer       = $detail.CertIssuer
        CertNotAfter     = $detail.CertNotAfter
        CertExpired      = $detail.CertExpired
        TimestampDate    = $detail.TimestampDate
        PreJul2015       = $detail.TimestampPreJul2015
        RevocationStatus = $detail.RevocationStatus
        WindowsCIVerdict = $detail.WindowsCIVerdict
        Gaps             = ($gaps -join " | ")
        DriverLoaded     = $loadSuccess
        LoadError        = $loadError
        ElasticHits      = $elasticDetections.Count
    }

    $record | Export-Csv -Path $OutputCsv -Append -NoTypeInformation
    Write-Host "  Results appended to $OutputCsv" -ForegroundColor Green

    # --- Summary ---
    Write-Host "`n  ========== SUMMARY ==========" -ForegroundColor Cyan
    Write-Host "  Driver:            $($detail.FileName)"
    Write-Host "  Cert Expired:      $($detail.CertExpired)" -ForegroundColor $(
        if ($detail.CertExpired) { "Red" } else { "Green" })
    Write-Host "  Pre-2015 Timestamp:$($detail.TimestampPreJul2015)" -ForegroundColor $(
        if ($detail.TimestampPreJul2015) { "Red" } else { "Green" })
    Write-Host "  Revocation:        $($detail.RevocationStatus)" -ForegroundColor $(
        if ($detail.RevocationStatus -eq "REVOKED") { "Red" }
        elseif ($detail.RevocationStatus -eq "NOT_REVOKED") { "Green" }
        else { "Yellow" })
    Write-Host "  Windows CI:        $($detail.WindowsCIVerdict)"
    Write-Host "  Gaps Found:        $($gaps.Count)" -ForegroundColor $(
        if ($gaps.Count -gt 0) { "Red" } else { "Green" })
    Write-Host "  Driver Loaded:     $loadSuccess" -ForegroundColor $(
        if ($loadSuccess -eq $true) { "Red" }
        elseif ($loadSuccess -eq $false) { "Green" }
        else { "Gray" })
    Write-Host "  Elastic Hits:      $($elasticDetections.Count)"
    Write-Host "  ==============================`n" -ForegroundColor Cyan

    return $record
}


# ==================== Module exports ====================

Export-ModuleMember -Function @(
    'Get-AuthenticodeDetail',
    'Test-DriverCertificate',
    'Find-LOLDriverCandidates',
    'Invoke-LOLDriverAudit'
)
