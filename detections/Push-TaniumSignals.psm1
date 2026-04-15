function Push-TaniumSignals {
    <#
    .SYNOPSIS
    Pushes custom Tanium Threat Response signals to a Tanium server

    .DESCRIPTION
    Reads all JSON signal files from detections/tanium-picus/ and pushes them to a
    Tanium server via REST API. Requires Tanium server URL and API token in secret vault.

    .EXAMPLE
    Push-TaniumSignals -TaniumUrl "https://tanium.yourdomain.com" -ApiToken "your-api-token"

    .EXAMPLE
    Push-TaniumSignals  # Uses values from PowerShell secret vault
    #>
    param(
        [string]$TaniumUrl,
        [string]$ApiToken,
        [string]$SignalDir = ".\detections\tanium-picus"
    )

    # Get credentials from secret vault if not provided
    if (-not $TaniumUrl) {
        try {
            $TaniumUrl = Get-Secret -Name 'Tanium_URL' -AsPlainText -ErrorAction Stop
            Write-Host "[+] Loaded Tanium URL from secret vault" -ForegroundColor Green
        } catch {
            Write-Host "[-] Tanium_URL not found in secret vault. Please provide -TaniumUrl parameter or set secret:" -ForegroundColor Red
            Write-Host "    Set-Secret -Name 'Tanium_URL' -Secret 'https://tanium.yourdomain.com'" -ForegroundColor Yellow
            return
        }
    }

    if (-not $ApiToken) {
        try {
            $ApiToken = Get-Secret -Name 'Tanium_API_Token' -AsPlainText -ErrorAction Stop
            Write-Host "[+] Loaded Tanium API token from secret vault" -ForegroundColor Green
        } catch {
            Write-Host "[-] Tanium_API_Token not found in secret vault. Please provide -ApiToken parameter or set secret:" -ForegroundColor Red
            Write-Host "    Set-Secret -Name 'Tanium_API_Token' -Secret 'your-api-token'" -ForegroundColor Yellow
            return
        }
    }

    # Validate signal directory
    if (-not (Test-Path $SignalDir)) {
        Write-Host "[-] Signal directory not found: $SignalDir" -ForegroundColor Red
        return
    }

    # Get all JSON signal files
    $signalFiles = Get-ChildItem -Path $SignalDir -Filter "*.json" -ErrorAction Stop

    if ($signalFiles.Count -eq 0) {
        Write-Host "[-] No JSON signal files found in $SignalDir" -ForegroundColor Red
        return
    }

    Write-Host "[*] Found $($signalFiles.Count) signal files to push" -ForegroundColor Cyan
    Write-Host ""

    # Setup headers for API requests (Tanium uses 'session' header with 'token-' prefix)
    $headers = @{
        "session"       = "token-$ApiToken"
        "Content-Type"  = "application/json"
    }

    # Track results
    $results = @{
        Success = 0
        Failed  = 0
        Errors  = @()
    }

    # Process each signal file
    foreach ($file in $signalFiles) {
        try {
            # Read and validate JSON
            $signalContent = Get-Content -Path $file.FullName -Raw
            $signal = $signalContent | ConvertFrom-Json

            if (-not $signal.data.id) {
                Write-Host "[!] Skipping $($file.Name) - missing 'data.id'" -ForegroundColor Yellow
                $results.Failed++
                continue
            }

            # Prepare API payload
            $payload = @{
                type        = $signal.type
                typeVersion = $signal.typeVersion
                data        = $signal.data
            } | ConvertTo-Json -Depth 10

            # Push to Tanium
            $uri = "$TaniumUrl/api/v2/threat_response/signals"

            Write-Host "[*] Pushing: $($signal.data.id)" -ForegroundColor Cyan

            $response = Invoke-RestMethod -Uri $uri `
                -Method Post `
                -Headers $headers `
                -Body $payload `
                -SkipCertificateCheck `
                -ErrorAction Stop

            Write-Host "    [+] Success: $($response.data.id)" -ForegroundColor Green
            $results.Success++

        } catch {
            Write-Host "    [-] Failed: $($file.Name)" -ForegroundColor Red
            Write-Host "        Error: $($_.Exception.Message)" -ForegroundColor DarkRed
            $results.Failed++
            $results.Errors += @{
                File  = $file.Name
                Error = $_.Exception.Message
            }
        }
    }

    # Summary
    Write-Host ""
    Write-Host "=" * 60 -ForegroundColor Cyan
    Write-Host "PUSH SUMMARY" -ForegroundColor Cyan
    Write-Host "=" * 60 -ForegroundColor Cyan
    Write-Host "Total Processed:  $($results.Success + $results.Failed)" -ForegroundColor White
    Write-Host "Successful:       $($results.Success)" -ForegroundColor Green
    Write-Host "Failed:           $($results.Failed)" -ForegroundColor Red

    if ($results.Errors.Count -gt 0) {
        Write-Host ""
        Write-Host "FAILED SIGNALS:" -ForegroundColor Red
        foreach ($err in $results.Errors) {
            Write-Host "  - $($err.File): $($err.Error)" -ForegroundColor DarkRed
        }
    }

    Write-Host ""
    Write-Host "Next Steps:" -ForegroundColor Cyan
    Write-Host "  1. Verify signals in Tanium Console -> Threat Response -> Signals Manager" -ForegroundColor DarkCyan
    Write-Host "  2. Enable/validate signal rules as needed" -ForegroundColor DarkCyan
    Write-Host "  3. Monitor alert generation from detection endpoints" -ForegroundColor DarkCyan
}

Export-ModuleMember -Function Push-TaniumSignals
