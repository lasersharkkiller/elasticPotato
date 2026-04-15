$script:ModeConfig = @{
    'UnverifiedProcs'   = @{ BaselineFile = 'unverifiedProcsBaseline.json';    RecentFile = 'unverifiedProcsRecent.json' }
    'UnsignedWin'       = @{ BaselineFile = 'unsignedWinProcsBaseline.json';   RecentFile = 'unsignedProcsRecent.json' }
    'UnsignedLinux'     = @{ BaselineFile = 'unsignedLinuxProcsBaseline.json'; RecentFile = 'unsignedProcsRecent.json' }
    'NewWinPublishers'  = @{ BaselineFile = 'signedVerifiedProcsBaseline.json';RecentFile = 'winPublishersRecent.json' }
    'Drivers'           = @{ BaselineFile = 'driversBaseline.json';            RecentFile = 'driversRecent.json' }
    'SpecificProc'      = @{ BaselineFile = $null;                             RecentFile = $null }
}

function Get-PlatformFromEvent {
    param($Event)
    $os = [string] $Event.host.os.type
    if ($os -match '(?i)windows') { return 'Windows' }
    if ($os -match '(?i)linux')   { return 'Linux' }
    return 'Other'
}

function Build-EsQuery {
    param(
        [string] $Mode,
        [string] $ProcName,
        [int] $QueryDays
    )

    $baseFilters = @(
        @{ term = @{ 'event.category' = 'process' } }
        @{ range = @{ '@timestamp' = @{ gte = "now-${QueryDays}d"; lte = 'now' } } }
    )

    switch ($Mode) {
        'UnverifiedProcs' {
            $baseFilters += @{ exists = @{ field = 'process.code_signature.subject_name' } }
            $mustNot = @(@{ term = @{ 'process.code_signature.trusted' = $true } })
        }
        'UnsignedWin' {
            $baseFilters += @{ term = @{ 'host.os.type' = 'windows' } }
            $baseFilters += @{ term = @{ 'process.code_signature.signed' = $false } }
            $mustNot = @()
        }
        'UnsignedLinux' {
            $baseFilters += @{ term = @{ 'host.os.type' = 'linux' } }
            $baseFilters += @{ term = @{ 'process.code_signature.signed' = $false } }
            $mustNot = @()
        }
        'NewWinPublishers' {
            $baseFilters += @{ term = @{ 'host.os.type' = 'windows' } }
            $baseFilters += @{ term = @{ 'process.code_signature.signed'  = $true } }
            $baseFilters += @{ term = @{ 'process.code_signature.trusted' = $true } }
            $mustNot = @()
        }
        'Drivers' {
            $baseFilters += @{
                bool = @{
                    should = @(
                        @{ terms = @{ 'event.code' = @('6','7','DriverLoad') } }
                        @{ wildcard = @{ 'file.name' = '*.sys' } }
                        @{ wildcard = @{ 'process.name' = '*.sys' } }
                    )
                    minimum_should_match = 1
                }
            }
            $mustNot = @()
        }
        'SpecificProc' {
            if ([string]::IsNullOrWhiteSpace($ProcName)) {
                throw "ProcName is required for Mode=SpecificProc."
            }
            $baseFilters += @{ term = @{ 'process.name' = $ProcName } }
            $mustNot = @()
        }
    }

    $query = @{
        size  = 1000
        sort  = @(@{ '@timestamp' = 'asc' }, @{ '_id' = 'asc' })
        query = @{ bool = @{ filter = $baseFilters; must_not = $mustNot } }
    }
    return $query
}

function Invoke-VtFileLookup {
    param(
        [string] $Hash,
        [hashtable] $Headers
    )
    $url = "https://www.virustotal.com/api/v3/files/$Hash"
    $attempt = 0
    $delay = 15
    while ($attempt -lt 5) {
        $attempt++
        try {
            return Invoke-RestMethod -Uri $url -Headers $Headers -Method Get -ErrorAction Stop
        } catch {
            $code = $_.Exception.Response.StatusCode.value__
            if ($code -eq 429) {
                Start-Sleep -Seconds $delay
                $delay = [Math]::Min($delay * 2, 240)
                continue
            }
            if ($code -eq 404) { return $null }
            throw
        }
    }
    throw "VT request exceeded retry budget for $Hash"
}

function Invoke-ElasticProcessSurvey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('UnverifiedProcs','UnsignedWin','UnsignedLinux','NewWinPublishers','Drivers','SpecificProc')]
        [string] $Mode,

        [string] $ProcName,
        [int]    $QueryDays = 1,
        [int]    $BaselineDays = 30
    )

    if ($Mode -eq 'SpecificProc' -and [string]::IsNullOrWhiteSpace($ProcName)) {
        throw "ProcName is required when Mode=SpecificProc."
    }

    $elasticUrl  = Get-Secret -Name 'Elastic_URL'  -AsPlainText -ErrorAction Stop
    $elasticUser = Get-Secret -Name 'Elastic_User' -AsPlainText -ErrorAction Stop
    $elasticPass = Get-Secret -Name 'Elastic_Pass' -AsPlainText -ErrorAction Stop
    $vtKey       = Get-Secret -Name 'VT_API_Key_1' -AsPlainText -ErrorAction Stop

    foreach ($pair in @(@('Elastic_URL',$elasticUrl),@('Elastic_User',$elasticUser),@('Elastic_Pass',$elasticPass),@('VT_API_Key_1',$vtKey))) {
        if ([string]::IsNullOrWhiteSpace($pair[1])) {
            throw "Required secret '$($pair[0])' is missing or empty."
        }
    }

    $pair = "${elasticUser}:${elasticPass}"
    $basic = 'Basic ' + [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($pair))
    $esHeaders = @{ Authorization = $basic; 'Content-Type' = 'application/json' }
    $vtHeaders = @{ 'x-apikey' = $vtKey }

    $query = Build-EsQuery -Mode $Mode -ProcName $ProcName -QueryDays $QueryDays
    $searchUrl = ($elasticUrl.TrimEnd('/')) + '/_search'

    $maxEvents = 50000
    $eventsQueried = 0
    $distinct = @{}
    $searchAfter = $null
    $capped = $false

    while ($true) {
        if ($searchAfter) {
            $query['search_after'] = $searchAfter
        }
        $body = $query | ConvertTo-Json -Depth 12 -Compress

        try {
            $resp = Invoke-RestMethod -Uri $searchUrl -Method Post -Headers $esHeaders -Body $body -ErrorAction Stop
        } catch {
            throw "Elasticsearch query failed: $($_.Exception.Message)"
        }

        $hits = $resp.hits.hits
        if (-not $hits -or $hits.Count -eq 0) { break }

        foreach ($hit in $hits) {
            $eventsQueried++
            $src = $hit._source
            $hash = $null
            if ($src.process -and $src.process.hash) { $hash = [string] $src.process.hash.sha256 }
            if (-not $hash -and $src.file -and $src.file.hash) { $hash = [string] $src.file.hash.sha256 }
            if ([string]::IsNullOrWhiteSpace($hash)) { continue }
            $hash = $hash.ToLowerInvariant()
            if (-not $distinct.ContainsKey($hash)) { $distinct[$hash] = $src }

            if ($eventsQueried -ge $maxEvents) { $capped = $true; break }
        }
        if ($capped) { break }

        $last = $hits[-1]
        if (-not $last.sort) { break }
        $searchAfter = $last.sort
    }

    if ($capped) {
        Write-Warning "Elasticsearch result capped at $maxEvents events."
    }

    $uniqueCount = $distinct.Keys.Count
    $newHashes = 0
    $suspiciousHashes = 0

    $modeCfg = $script:ModeConfig[$Mode]
    $outputDir = Join-Path (Get-Location) 'output'
    if (-not (Test-Path -LiteralPath $outputDir)) {
        New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
    }

    $baselinePath = $null
    $recentPath   = $null
    $baseline = @{}

    if ($Mode -ne 'SpecificProc') {
        $baselinePath = Join-Path $outputDir $modeCfg.BaselineFile
        $recentPath   = Join-Path $outputDir $modeCfg.RecentFile

        if (Test-Path -LiteralPath $baselinePath) {
            try {
                $raw = Get-Content -LiteralPath $baselinePath -Raw -ErrorAction Stop
                if (-not [string]::IsNullOrWhiteSpace($raw)) {
                    $baseline = $raw | ConvertFrom-Json -AsHashtable -ErrorAction Stop
                    if ($null -eq $baseline) { $baseline = @{} }
                }
            } catch {
                Write-Warning "Malformed baseline JSON at '$baselinePath' - treating as empty."
                $baseline = @{}
            }
        }
    }

    $recent = @{}
    $specificResults = @()

    foreach ($hash in $distinct.Keys) {
        $src = $distinct[$hash]

        $procName = ''
        if ($src.process) { $procName = [string] $src.process.name }
        if (-not $procName -and $src.file) { $procName = [string] $src.file.name }

        $sigState = 'Unsigned'; $sigTrust = 'Unsigned'; $signer = ''
        if ($src.process -and $src.process.code_signature) {
            $cs = $src.process.code_signature
            if ($cs.signed) {
                $sigState = 'Signed'
                if ($cs.trusted) { $sigTrust = 'Trusted' } else { $sigTrust = 'Unverified' }
                $signer = [string] $cs.subject_name
            }
        }

        $platform = Get-PlatformFromEvent -Event $src

        if ($Mode -ne 'SpecificProc' -and $baseline.ContainsKey($hash)) {
            continue
        }

        $vtResp = $null
        try {
            $vtResp = Invoke-VtFileLookup -Hash $hash -Headers $vtHeaders
        } catch {
            Write-Warning "VT lookup failed for ${hash}: $($_.Exception.Message)"
        }

        $vtMal = -1; $vtSus = -1; $vtEng = -1; $vtClass = ''
        if ($vtResp) {
            $attrs = $vtResp.data.attributes
            $stats = $attrs.last_analysis_stats
            $vtMal = [int] $stats.malicious
            $vtSus = [int] $stats.suspicious
            $vtEng = [int] ($stats.malicious + $stats.suspicious + $stats.undetected + $stats.harmless + $stats.timeout)
            if ($attrs.popular_threat_classification) {
                $vtClass = [string] $attrs.popular_threat_classification.suggested_threat_label
            }
        }

        $entry = [pscustomobject]@{
            ProcessName      = $procName
            FileHash         = $hash
            SignatureState   = $sigState
            SignatureTrust   = $sigTrust
            Platform         = $platform
            Signer           = $signer
            VtMalCount       = $vtMal
            VtSusCount       = $vtSus
            VtEngineCount    = $vtEng
            VtClassification = $vtClass
            FirstSeen        = (Get-Date).ToString('o')
        }

        if ($vtMal -ge 3) {
            $suspiciousHashes++
            Write-Host ("SUSPICIOUS: {0} {1} (VT malicious={2}, label={3})" -f $procName, $hash, $vtMal, $vtClass) -ForegroundColor Red
        }

        if ($Mode -eq 'SpecificProc') {
            $specificResults += $entry
        } else {
            $baseline[$hash] = $entry
            $recent[$hash]   = $entry
            $newHashes++
        }
    }

    $writeJson = {
        param([object] $data, [string] $path)
        $json = $data | ConvertTo-Json -Depth 8
        $utf8 = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($path, $json, $utf8)
    }

    if ($Mode -ne 'SpecificProc') {
        & $writeJson $baseline $baselinePath
        & $writeJson $recent   $recentPath
    } else {
        foreach ($r in $specificResults) {
            $line = "{0} hash={1} VT(mal={2}, sus={3}, engines={4}) class={5}" -f $r.ProcessName, $r.FileHash, $r.VtMalCount, $r.VtSusCount, $r.VtEngineCount, $r.VtClassification
            Write-Host $line
        }
    }

    [pscustomobject]@{
        Mode             = $Mode
        EventsQueried    = $eventsQueried
        UniqueHashes     = $uniqueCount
        NewHashes        = $newHashes
        SuspiciousHashes = $suspiciousHashes
        BaselineFile     = $baselinePath
        RecentFile       = $recentPath
    }
}

Export-ModuleMember -Function Invoke-ElasticProcessSurvey
