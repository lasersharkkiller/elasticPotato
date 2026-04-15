$script:ModuleRoot = $PSScriptRoot

function Get-ToolsDir {
    $p = Join-Path $script:ModuleRoot 'tools'
    if (-not (Test-Path -LiteralPath $p)) {
        New-Item -ItemType Directory -Force -Path $p | Out-Null
    }
    return $p
}

function Install-FromGitHubRelease {
    param(
        [string] $RepoApiUrl,
        [string] $AssetPattern,
        [string] $DestinationExe,
        [string] $ExeInsideArchive
    )

    if (Test-Path -LiteralPath $DestinationExe) { return $DestinationExe }

    try {
        $rel = Invoke-RestMethod -Uri $RepoApiUrl -Headers @{ 'User-Agent' = 'elasticPotato' } -ErrorAction Stop
    } catch {
        throw "Failed to query GitHub releases ($RepoApiUrl): $($_.Exception.Message)"
    }

    $asset = $rel.assets | Where-Object { $_.name -match $AssetPattern } | Select-Object -First 1
    if (-not $asset) {
        throw "No asset matching '$AssetPattern' in latest release at $RepoApiUrl"
    }

    $tmp = Join-Path $env:TEMP $asset.name
    try {
        Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $tmp -UseBasicParsing -ErrorAction Stop
        if ($asset.name -match '\.zip$') {
            $extractDir = Join-Path $env:TEMP ("rel-{0}" -f ([Guid]::NewGuid().ToString('N')))
            New-Item -ItemType Directory -Force -Path $extractDir | Out-Null
            Expand-Archive -LiteralPath $tmp -DestinationPath $extractDir -Force
            $exe = Get-ChildItem -Path $extractDir -Filter $ExeInsideArchive -Recurse -File | Select-Object -First 1
            if (-not $exe) { throw "Expected '$ExeInsideArchive' not found inside $($asset.name)" }
            Copy-Item -LiteralPath $exe.FullName -Destination $DestinationExe -Force
            Remove-Item -LiteralPath $extractDir -Recurse -Force -ErrorAction SilentlyContinue
        } else {
            Copy-Item -LiteralPath $tmp -Destination $DestinationExe -Force
        }
    } finally {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }

    return $DestinationExe
}

function Install-ScorecardTool {
    $dir = Get-ToolsDir
    $exe = Join-Path $dir 'scorecard.exe'
    try {
        return Install-FromGitHubRelease -RepoApiUrl 'https://api.github.com/repos/ossf/scorecard/releases/latest' `
            -AssetPattern 'windows.*amd64\.exe$' `
            -DestinationExe $exe `
            -ExeInsideArchive 'scorecard*.exe'
    } catch {
        throw "Scorecard install failed: $($_.Exception.Message)"
    }
}

function Install-YaraTool {
    $dir = Get-ToolsDir
    $exe = Join-Path $dir 'yara64.exe'
    try {
        return Install-FromGitHubRelease -RepoApiUrl 'https://api.github.com/repos/VirusTotal/yara/releases/latest' `
            -AssetPattern 'win64.*\.zip$' `
            -DestinationExe $exe `
            -ExeInsideArchive 'yara64.exe'
    } catch {
        throw "YARA install failed: $($_.Exception.Message)"
    }
}

function ConvertTo-RiskLabel {
    param([double] $Score)
    if ($Score -ge 7.5) { return 'Low' }
    if ($Score -ge 5.0) { return 'Medium' }
    return 'High'
}

function Invoke-RepoSupplyChainAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $GitHubUrl
    )

    if ($GitHubUrl -notmatch '^(?<proto>https?)://(?<host>[^/]+)/(?<owner>[^/]+)/(?<repo>[^/]+?)(?:\.git)?/?$') {
        throw "Invalid GitHub URL: $GitHubUrl"
    }
    $urlHost = $Matches['host']
    $owner = $Matches['owner']
    $repoName = $Matches['repo']
    $repoSlug = "$owner/$repoName"

    $scorecardExe = Install-ScorecardTool
    $yaraExe = $null
    try { $yaraExe = Install-YaraTool } catch { Write-Warning $_.Exception.Message }

    $score = $null
    try {
        $api = "https://api.securityscorecards.dev/projects/github.com/$owner/$repoName"
        $resp = Invoke-RestMethod -Uri $api -ErrorAction Stop
        $score = [double] $resp.score
    } catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        if ($statusCode -eq 404) {
            try {
                $raw = & $scorecardExe --repo="$GitHubUrl" --format=json 2>$null
                if ($LASTEXITCODE -eq 0 -and $raw) {
                    $obj = $raw | ConvertFrom-Json
                    $score = [double] $obj.score
                }
            } catch {
                Write-Warning "Scorecard CLI failed: $($_.Exception.Message)"
            }
        } else {
            Write-Warning "Scorecard API failed: $($_.Exception.Message)"
        }
    }

    $risk = 'Unknown'
    $scoreVal = -1.0
    if ($null -ne $score) {
        $scoreVal = [double] $score
        $risk = ConvertTo-RiskLabel -Score $scoreVal
    }

    $outputDir = Join-Path (Get-Location) 'output'
    if (-not (Test-Path -LiteralPath $outputDir)) {
        New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
    }

    $scorecardCsv = Join-Path $outputDir 'scorecardScanResults.csv'
    $yaraCsv      = Join-Path $outputDir 'yaraScanResults.csv'
    $timestamp = (Get-Date).ToString('o')

    if (-not (Test-Path -LiteralPath $scorecardCsv)) {
        Set-Content -LiteralPath $scorecardCsv -Value 'Timestamp,Repo,Domain,Score,Risk,URL' -Encoding UTF8
    }
    $scRow = [pscustomobject]@{
        Timestamp = $timestamp
        Repo      = $repoSlug
        Domain    = $urlHost
        Score     = $scoreVal
        Risk      = $risk
        URL       = $GitHubUrl
    }
    $scRow | Export-Csv -LiteralPath $scorecardCsv -NoTypeInformation -Append -Encoding UTF8

    $yaraMatches = @()
    $yaraMatchCount = 0
    $cloneDir = Join-Path $env:TEMP ("repoaudit-{0}" -f ([Guid]::NewGuid().ToString('N')))
    $cloneOk = $false
    try {
        git clone --depth 1 $GitHubUrl $cloneDir 2>$null
        if ($LASTEXITCODE -eq 0) { $cloneOk = $true }
    } catch {
        Write-Warning "git clone failed: $($_.Exception.Message)"
    }

    if (-not $cloneOk) {
        Write-Warning "Skipping YARA pass - clone failed for $GitHubUrl"
    } else {
        $rulesDir = Join-Path (Get-Location) 'detections/yara'
        if (-not (Test-Path -LiteralPath $rulesDir)) {
            Write-Warning "YARA rules directory '$rulesDir' missing - skipping YARA scan."
        } elseif (-not $yaraExe -or -not (Test-Path -LiteralPath $yaraExe)) {
            Write-Warning "yara64.exe not available - skipping YARA scan."
        } else {
            try {
                $yaraOut = & $yaraExe -r $rulesDir $cloneDir 2>$null
                foreach ($line in @($yaraOut)) {
                    if ([string]::IsNullOrWhiteSpace($line)) { continue }
                    $parts = ($line -split '\s+', 2)
                    if ($parts.Count -ge 1 -and $parts[0]) {
                        $yaraMatches += $parts[0]
                    }
                }
                $yaraMatches = @($yaraMatches | Sort-Object -Unique)
                $yaraMatchCount = $yaraMatches.Count
            } catch {
                Write-Warning "yara scan failed: $($_.Exception.Message)"
            }

            if (-not (Test-Path -LiteralPath $yaraCsv)) {
                Set-Content -LiteralPath $yaraCsv -Value 'Timestamp,Repo,Domain,YaraMatches,URL' -Encoding UTF8
            }
            $yaraRow = [pscustomobject]@{
                Timestamp   = $timestamp
                Repo        = $repoSlug
                Domain      = $urlHost
                YaraMatches = ($yaraMatches -join ';')
                URL         = $GitHubUrl
            }
            $yaraRow | Export-Csv -LiteralPath $yaraCsv -NoTypeInformation -Append -Encoding UTF8
        }
    }

    if (Test-Path -LiteralPath $cloneDir) {
        Remove-Item -LiteralPath $cloneDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    [pscustomobject]@{
        Repo           = $repoSlug
        Score          = $scoreVal
        Risk           = $risk
        YaraMatchCount = $yaraMatchCount
        YaraMatches    = [string[]] $yaraMatches
    }
}

Export-ModuleMember -Function Invoke-RepoSupplyChainAudit
