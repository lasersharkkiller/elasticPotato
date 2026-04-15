function Get-FreeSamplesFromList {
<#
.SYNOPSIS
  Free Malware Sample Downloader - Cascading Source Edition.
  Tries MalwareBazaar first per hash; falls back to Hybrid Analysis if not found.
  - INPUT: Accepts Files (CSV/TXT), Comma-Separated Strings, or Interactive Input.
  - SMART CSV: Auto-detects 'IOC', 'IOCValue', 'Hash', 'SHA256', 'FileHash' columns.
  - Reports source for every sample downloaded.
  - Generates 'file_map.csv' compatible with the Detonator.
  - MalwareBazaar zips use password: infected
  - Hybrid Analysis returns raw file (gzip-wrapped); saved as-is.
  NOTE: Hybrid Analysis requires a free API key from hybrid-analysis.com.
        Sample downloads require "trusted" account status (earned by submitting samples).
        If HA returns 403, it will be skipped gracefully.
#>

param(
    [Parameter(Mandatory=$false, ValueFromPipeline=$true)]
    [object]$Targets,

    [string]$OutDir = ".\FreeSamples",

    [int]$Threads = 5
)

# ---------- 1. FLEXIBLE INPUT HANDLER ----------
$hashes = @()

if ([string]::IsNullOrWhiteSpace($Targets)) {
    $InputStr = Read-Host "[?] Enter Targets (File Path OR Comma-Separated SHA256 Hashes)"
    if ([string]::IsNullOrWhiteSpace($InputStr)) { Write-Error "No targets provided."; return }
    $Targets = $InputStr
}

$IsFile = $false
try {
    if ($Targets -is [string] -and (Test-Path $Targets -ErrorAction SilentlyContinue)) {
        $IsFile = $true
    }
} catch {}

if ($IsFile) {
    $FilePath = (Resolve-Path $Targets).Path
    Write-Host "Reading input from file: $FilePath" -ForegroundColor DarkCyan
    $ext = [IO.Path]::GetExtension($FilePath).ToLowerInvariant()

    if ($ext -eq ".csv") {
        $CsvData = Import-Csv $FilePath
        if ($CsvData.Count -gt 0) {
            $Props = $CsvData[0].PSObject.Properties.Name
            $Col = ($Props | Where-Object { $_ -match '^(IOC|IOCValue|Hash|SHA256|FileHash)$' } | Select-Object -First 1)
            if ($Col) {
                Write-Host " -> Detected hash column: '$Col'" -ForegroundColor DarkGray
                $hashes = $CsvData | ForEach-Object { $_.$Col.Trim() }
            } else {
                Write-Error "CSV must contain a column named 'IOC', 'IOCValue', 'Hash', or 'SHA256'."
                return
            }
        }
    } else {
        $hashes = Get-Content $FilePath | ForEach-Object { $_.Trim() }
    }
} else {
    Write-Host "Reading input from provided list/string..." -ForegroundColor DarkCyan
    if ($Targets -is [array]) {
        $hashes = $Targets
    } elseif ($Targets -is [string]) {
        $hashes = $Targets -split ","
    }
}

# ---------- 2. KEYS ----------
try { $MBKey = (Get-Secret -Name 'MalwareBazaar_AuthKey' -AsPlainText -ErrorAction Stop).Trim() } catch { $MBKey = "" }
if ([string]::IsNullOrWhiteSpace($MBKey)) {
    $MBKey = Read-Host "[?] MalwareBazaar API key not found in vault. Enter it now (or press Enter to skip MB)"
}

try { $HAKey = (Get-Secret -Name 'HybridAnalysis_API_Key' -AsPlainText -ErrorAction Stop).Trim() } catch { $HAKey = "" }
if ([string]::IsNullOrWhiteSpace($HAKey)) {
    $HAKey = Read-Host "[?] Hybrid Analysis API key not found in vault. Enter it now (or press Enter to skip HA fallback)"
}

if ([string]::IsNullOrWhiteSpace($MBKey) -and [string]::IsNullOrWhiteSpace($HAKey)) {
    Write-Error "No API keys available. Cannot proceed."
    return
}

$hashes = $hashes | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" } | Select-Object -Unique

# Bucket by hash type
$sha256s = @($hashes | Where-Object { $_ -match '^[A-Fa-f0-9]{64}$' })
$sha1s   = @($hashes | Where-Object { $_ -match '^[A-Fa-f0-9]{40}$' })
$md5s    = @($hashes | Where-Object { $_ -match '^[A-Fa-f0-9]{32}$' })
$other   = @($hashes | Where-Object { $_ -notmatch '^[A-Fa-f0-9]{32,64}$' })

if ($other.Count -gt 0) {
    Write-Host "  [~] Skipping $($other.Count) non-hash IOCs (IPs, domains, etc.)" -ForegroundColor DarkGray
}

# Resolve MD5/SHA1 -> SHA256 via MalwareBazaar get_info
$toResolve = @($sha1s) + @($md5s)
if ($toResolve.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($MBKey)) {
    Write-Host "Resolving $($toResolve.Count) MD5/SHA1 hashes to SHA256 via MalwareBazaar..." -ForegroundColor DarkCyan
    $resolved = 0
    foreach ($h in $toResolve) {
        try {
            $resp = Invoke-RestMethod -Method Post -Uri "https://mb-api.abuse.ch/api/v1/" `
                        -Headers @{ "Auth-Key" = $MBKey } `
                        -Body "query=get_info&hash=$h" `
                        -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
            if ($resp.query_status -eq "ok" -and $resp.data -and $resp.data[0].sha256_hash) {
                $sha256 = $resp.data[0].sha256_hash
                if ($sha256 -notin $sha256s) { $sha256s += $sha256; $resolved++ }
            }
        } catch {}
        Start-Sleep -Milliseconds 200
    }
    Write-Host "  -> Resolved $resolved of $($toResolve.Count) to SHA256." -ForegroundColor Green
} elseif ($toResolve.Count -gt 0) {
    Write-Host "  [!] No MalwareBazaar key - cannot resolve $($toResolve.Count) MD5/SHA1 hashes. They will be skipped." -ForegroundColor Yellow
}

$hashes = @($sha256s | Select-Object -Unique)

if ($hashes.Count -eq 0) { Write-Error "No valid SHA256 hashes found in input."; return }

# ---------- 3. OUTPUT DIRS ----------
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }
$OutDir    = (Resolve-Path $OutDir).Path
$ReviewDir = Join-Path $OutDir "_Review"
New-Item -ItemType Directory -Force -Path $ReviewDir | Out-Null

Write-Host "Output: $OutDir" -ForegroundColor DarkCyan
Write-Host "Loaded $($hashes.Count) valid hashes. Starting cascade download (MalwareBazaar -> Hybrid Analysis)..." -ForegroundColor Yellow
if ([string]::IsNullOrWhiteSpace($MBKey))  { Write-Host "  [!] MalwareBazaar key missing - skipping MB"  -ForegroundColor Yellow }
if ([string]::IsNullOrWhiteSpace($HAKey))  { Write-Host "  [!] Hybrid Analysis key missing - skipping HA fallback" -ForegroundColor Yellow }

# ---------- 4. WORKER (per-hash cascade) ----------
$WorkerScript = {
    param($HashList, $MBApiKey, $HAApiKey, $DestDir, $ReviewDir)

    Add-Type -AssemblyName System.Net.Http

    function Invoke-MBDownload {
        param($Client, $Hash, $ApiKey, $DestDir)

        if ([string]::IsNullOrWhiteSpace($ApiKey)) { return $null }

        $Uri  = "https://mb-api.abuse.ch/api/v1/"
        $Body = "query=get_file&sha256_hash=$Hash"

        try {
            $Req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Post, $Uri)
            $Req.Headers.Add("Auth-Key", $ApiKey)
            $Req.Content = [System.Net.Http.StringContent]::new($Body, [System.Text.Encoding]::UTF8, "application/x-www-form-urlencoded")

            $Resp = $Client.SendAsync($Req).Result

            if (-not $Resp.IsSuccessStatusCode) { return $null }

            $Bytes = $Resp.Content.ReadAsByteArrayAsync().Result

            # MalwareBazaar returns JSON with query_status on not-found, zip binary on success
            # Detect JSON error response (starts with '{')
            if ($Bytes.Count -gt 0 -and $Bytes[0] -eq 0x7B) {
                $Text = [System.Text.Encoding]::UTF8.GetString($Bytes)
                if ($Text -match '"query_status"') { return $null }  # not found or error
            }

            # Looks like a real file - save it
            $FilePath = Join-Path $DestDir "$Hash.zip"
            [System.IO.File]::WriteAllBytes($FilePath, $Bytes)
            return $FilePath
        } catch {
            return $null
        }
    }

    function Invoke-HADownload {
        param($Client, $Hash, $ApiKey, $DestDir)

        if ([string]::IsNullOrWhiteSpace($ApiKey)) { return $null }

        $Uri = "https://www.hybrid-analysis.com/api/v2/overview/$Hash/sample"

        try {
            $Req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get, $Uri)
            $Req.Headers.Add("api-key", $ApiKey)
            $Req.Headers.Add("User-Agent", "Falcon Sandbox")
            $Req.Headers.Add("accept", "application/gzip")

            $Resp = $Client.SendAsync($Req).Result

            # 403 = not trusted yet, 404 = not found, anything else non-2xx = skip
            if (-not $Resp.IsSuccessStatusCode) { return $null }

            $Bytes = $Resp.Content.ReadAsByteArrayAsync().Result
            if ($Bytes.Count -eq 0) { return $null }

            # Save as .gz (raw HA download is gzip-wrapped)
            $FilePath = Join-Path $DestDir "$Hash.gz"
            [System.IO.File]::WriteAllBytes($FilePath, $Bytes)
            return $FilePath
        } catch {
            return $null
        }
    }

    function Get-FileTypeMagic {
        param([byte[]]$Bytes)
        if ($Bytes.Count -lt 4) { return "bin" }
        $h = ($Bytes[0..3] | ForEach-Object { $_.ToString("X2") }) -join " "
        if ($h -match "^4D 5A")          { return "exe" }
        if ($h -match "^7F 45 4C 46")    { return "elf" }
        if ($h -match "^50 4B")          { return "zip" }
        if ($h -match "^1F 8B")          { return "gz"  }
        if ($h -match "^25 50 44 46")    { return "pdf" }
        return "bin"
    }

    $Client = [System.Net.Http.HttpClient]::new()
    $Client.Timeout = [TimeSpan]::FromMinutes(3)

    $Results = @()

    foreach ($Hash in $HashList) {
        $Source    = "NotFound"
        $FilePath  = $null
        $FileType  = "Unknown"

        # --- Try MalwareBazaar first ---
        $FilePath = Invoke-MBDownload -Client $Client -Hash $Hash -ApiKey $MBApiKey -DestDir $DestDir
        if ($FilePath) { $Source = "MalwareBazaar" }

        # --- Fallback: Hybrid Analysis ---
        if (-not $FilePath) {
            $FilePath = Invoke-HADownload -Client $Client -Hash $Hash -ApiKey $HAApiKey -DestDir $DestDir
            if ($FilePath) { $Source = "HybridAnalysis" }
            # HA free tier = 200 req/min. At 5 threads each sleeping 1500ms:
            # 5 * (1000/1500) = 3.3 req/sec = 200 req/min - right at the limit.
            Start-Sleep -Milliseconds 1500
        }

        # --- Determine file type ---
        if ($FilePath -and (Test-Path $FilePath)) {
            try {
                $Bytes = [System.IO.File]::ReadAllBytes($FilePath)
                $FileType = Get-FileTypeMagic -Bytes $Bytes
            } catch {}
        }

        $Results += [PSCustomObject]@{
            Hash         = $Hash
            Status       = if ($FilePath) { "OK" } else { "NotFound" }
            Source       = $Source
            DetectedType = $FileType
            FilePath     = $FilePath
        }

        Start-Sleep -Milliseconds 300
    }

    $Client.Dispose()
    return $Results
}

# ---------- 5. EXECUTE THREADED ----------
$RunspacePool = [runspacefactory]::CreateRunspacePool(1, $Threads)
$RunspacePool.Open()
$Jobs      = @()
$ChunkSize = [Math]::Ceiling($hashes.Count / $Threads)
$Idx       = 0

for ($i = 0; $i -lt $Threads; $i++) {
    if ($Idx -ge $hashes.Count) { break }
    $Subset = $hashes | Select-Object -Skip $Idx -First $ChunkSize
    $Idx   += $ChunkSize
    if ($Subset) {
        $PsCmd = [PowerShell]::Create().AddScript($WorkerScript)
        [void]$PsCmd.AddArgument($Subset)
        [void]$PsCmd.AddArgument($MBKey)
        [void]$PsCmd.AddArgument($HAKey)
        [void]$PsCmd.AddArgument($OutDir)
        [void]$PsCmd.AddArgument($ReviewDir)
        $PsCmd.RunspacePool = $RunspacePool
        $Jobs += [PSCustomObject]@{ Pipe = $PsCmd; Handle = $PsCmd.BeginInvoke(); Id = $i }
    }
}

while (($Jobs | Where-Object { $_.Handle.IsCompleted -eq $false }).Count -gt 0) {
    Start-Sleep -Seconds 1
}

$AllResults = @()
foreach ($Job in $Jobs) {
    try { $AllResults += $Job.Pipe.EndInvoke($Job.Handle) } catch {}
    $Job.Pipe.Dispose()
}
$RunspacePool.Dispose()

# ---------- 6. REPORT ----------
$OK       = $AllResults | Where-Object { $_.Status -eq "OK" }
$FromMB   = $OK | Where-Object { $_.Source -eq "MalwareBazaar" }
$FromHA   = $OK | Where-Object { $_.Source -eq "HybridAnalysis" }
$NotFound = $AllResults | Where-Object { $_.Status -eq "NotFound" }

Write-Host "`n[Download Summary]" -ForegroundColor DarkCyan
Write-Host "  Total requested : $($hashes.Count)"
Write-Host "  Downloaded OK   : $($OK.Count)"            -ForegroundColor Green
Write-Host "    - MalwareBazaar : $($FromMB.Count)"      -ForegroundColor Green
Write-Host "    - HybridAnalysis: $($FromHA.Count)"      -ForegroundColor Green
Write-Host "  Not found       : $($NotFound.Count)"      -ForegroundColor Yellow

if ($NotFound.Count -gt 0) {
    $MissPath = Join-Path $OutDir "not_found.txt"
    $NotFound.Hash | Set-Content -Path $MissPath -Encoding UTF8
    Write-Host "  Not-found hashes saved to: $MissPath" -ForegroundColor DarkYellow
}

# Write file_map.csv (compatible with Detonator)
$MapPath = Join-Path $OutDir "file_map.csv"
$OK | Select-Object Hash,
    @{N='Extension';    E={ $_.DetectedType }},
    @{N='Source';       E={ $_.Source }},
    @{N='TypeDescription'; E={ if ($_.Source -eq "MalwareBazaar") { "MB zip (password: infected)" } else { "HA raw/gz" } }} |
    Export-Csv -Path $MapPath -NoTypeInformation -Encoding UTF8

Write-Host "File map: $MapPath" -ForegroundColor Gray
Write-Host ""
Write-Host "NOTE: MalwareBazaar zips require password 'infected' to extract." -ForegroundColor DarkCyan
Write-Host "NOTE: Hybrid Analysis files are gzip-wrapped (.gz) - extract before detonation." -ForegroundColor DarkCyan
}
