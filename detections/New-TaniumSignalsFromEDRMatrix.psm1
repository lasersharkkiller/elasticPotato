<#
.SYNOPSIS
    Generates Tanium Threat Response signals (JSON intel documents) from the
    EDR Evasion & Gap Matrix crossed with APIDifferentialAnalysis.json.

.DESCRIPTION
    Reads APIDifferentialAnalysis.json, filters to Baseline_Rarity_Score = 100
    (APIs never seen in the clean process baseline), and groups them into
    high-fidelity detection families targeting observable artifacts that
    Tanium Recorder captures:

      - image_load   : DLL/module load events (samlib, cryptdll, mscoree, etc.)
      - cross_process: cross-process handle operations (injection, hijacking)
      - process      : process start events from suspicious staging paths
      - driver       : kernel driver loads (LOLDrivers, credential-access drivers)

    Each family produces one JSON signal file importable into Tanium Threat
    Response as an intel document (Console > Threat Response > Intel > Import).
    Also emits copy-paste Trace search queries and a summary CSV.

.NOTES
    Data sources:
      - baseline\APIDifferentialAnalysis.json  (Score + MalCount per API)
      - tools\api_call_matrix.ps1 $ApiDefs     (tier, tactic, EDR coverage)
#>

function New-TaniumSignalsFromEDRMatrix {
    [CmdletBinding()]
    param(
        [string]$DifferentialJsonPath = ".\baseline\APIDifferentialAnalysis.json",
        [string]$OutDir              = ".\detections\tanium"
    )

    # ================================================================
    # 1. LOAD DIFFERENTIAL DATA
    # ================================================================
    if (-not (Test-Path $DifferentialJsonPath)) {
        Write-Error "APIDifferentialAnalysis.json not found at $DifferentialJsonPath"
        return
    }
    $diffData = Get-Content -Path $DifferentialJsonPath -Raw | ConvertFrom-Json
    $score100 = $diffData | Where-Object { $_.Baseline_Rarity_Score -eq 100 -and $_.Malicious_Count -ge 1 } |
                Sort-Object Malicious_Count -Descending
    Write-Host "[*] Loaded $($score100.Count) Score=100 APIs from differential analysis." -ForegroundColor DarkCyan

    # Build lookup: lowercase function base name -> item
    $apiLookup = @{}
    foreach ($item in $score100) {
        $raw = $item.Item_Name
        $fn  = if ($raw -match '!(.+)$') { $Matches[1] } else { $raw }
        $fn  = $fn.ToLower().Trim()
        $dll = if ($raw -match '^([^!]+)!') { $Matches[1].ToLower() } else { '' }
        if (-not $apiLookup.ContainsKey($fn)) {
            $apiLookup[$fn] = @{ Dll=$dll; MalCount=[int]$item.Malicious_Count; FullName=$raw }
        }
    }

    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

    # ================================================================
    # 2. DEFINE SIGNAL FAMILIES
    # ================================================================
    # Each family groups related Score=100 APIs into one actionable signal.
    # Tanium Recorder event sources used:
    #   image_load    = DLL/module loaded into a process (highest fidelity)
    #   cross_process = cross-process handle open / remote thread creation
    #   process       = process start event (path, cmdline, parent)
    #   driver        = kernel driver load event

    $signalFamilies = @(
        @{
            Id          = 'TR-CRED-001'
            Name        = 'Credential Dumping via SAM/LSA Library Load'
            Severity    = 'critical'
            Description = 'Detects samlib.dll or cryptdll.dll loaded by a process other than lsass.exe, services.exe, or svchost.exe. Score=100 APIs from this library family (SamConnect, SamOpenDomain, SamQueryInformationUser, LsaOpenSecret, LsaQuerySecret, CDLocateCheckSum, MD5Init) appear exclusively in malicious samples and never in the clean baseline.'
            MitreTactic = 'Credential Access'
            MitreId     = 'T1003.001'
            MitreName   = 'OS Credential Dumping: LSASS Memory'
            DetectionType = 'moduleLoad'
            TargetDlls  = @('samlib.dll','cryptdll.dll')
            ExcludeProcs = @('lsass.exe','services.exe','svchost.exe','csrss.exe','smss.exe','wininit.exe')
            ApiMembers  = @('samconnect','samopendomain','samlookupdomaininsamserver',
                            'samqueryinformationuser','samridtosid','samopenalias',
                            'samgetmembersinalias','samgetmembersingroup','samopengroup',
                            'samfreememory','samopenuser',
                            'lsaopensecret','lsaquerysecret',
                            'cdlocatechecksum','md5init','md5update','md5final')
        },
        @{
            Id          = 'TR-CRED-002'
            Name        = 'NTLM Hash Computation / RC4 Encryption Primitives'
            Severity    = 'critical'
            Description = 'Detects processes that load advapi32.dll from outside normal system paths, indicating potential use of SystemFunction006 (DES-based NTLM OWF hash computation) or SystemFunction032 (RC4 stream cipher). These are the core primitives used by Mimikatz, secretsdump, and similar credential-theft tools. Score=100 with 12 malicious samples each. Observable via cross-process access to LSASS or process execution from staging paths.'
            MitreTactic = 'Credential Access'
            MitreId     = 'T1003'
            MitreName   = 'OS Credential Dumping'
            DetectionType = 'crossProcess'
            TargetDlls  = @('advapi32.dll')
            CrossProcessTarget = 'lsass.exe'
            ExcludeProcs = @('lsass.exe','services.exe','svchost.exe','csrss.exe','wininit.exe','MsMpEng.exe')
            ApiMembers  = @('systemfunction006','systemfunction032')
        },
        @{
            Id          = 'TR-EXEC-001'
            Name        = 'Callback-Based Shellcode Execution via Process from Staging Path'
            Severity    = 'high'
            Description = 'Detects processes launched from common attacker staging paths that are known to abuse callback-based shellcode execution (EnumSystemLanguageGroupsA/W). The callback parameter is set to a shellcode address in allocated memory, and the OS dispatches execution through it. Score=100, 16 malicious samples, zero baseline. No EDR hooks this callback dispatch. Observable when the process originates from Temp, AppData, Downloads, ProgramData, or Public directories.'
            MitreTactic = 'Defense Evasion'
            MitreId     = 'T1055.004'
            MitreName   = 'Process Injection: Asynchronous Procedure Call'
            DetectionType = 'processPath'
            TargetDlls  = @('kernel32.dll')
            StagingPaths = @('\Temp\','\AppData\Local\Temp\','\Downloads\','\ProgramData\','\Public\','\Users\Public\')
            ExcludeProcs = @()
            ApiMembers  = @('enumsystemlanguagegroupsa','enumsystemlanguagegroupsw',
                            'enumsystemlanguagegroups')
        },
        @{
            Id          = 'TR-EXEC-002'
            Name        = 'CLR Hosting in Native Process (.NET In-Memory Execution)'
            Severity    = 'high'
            Description = 'Detects mscoree.dll loaded by a native (non-.NET) process, or imports of CLRCreateInstance / _CorDllMain. This is the primary mechanism for execute-assembly, Cobalt Strike BOF .NET execution, and SharpPick-style attacks. _CorDllMain: Score=100, MalCount=15. CLRCreateInstance: Score=100.'
            MitreTactic = 'Defense Evasion'
            MitreId     = 'T1620'
            MitreName   = 'Reflective Code Loading'
            DetectionType = 'moduleLoad'
            TargetDlls  = @('mscoree.dll','clrjit.dll')
            ExcludeProcs = @('powershell.exe','pwsh.exe','msbuild.exe','csc.exe','vbc.exe',
                             'devenv.exe','dotnet.exe','w3wp.exe','iisexpress.exe')
            ApiMembers  = @('_cordllmain','clrcreateinstance','corexemain','iclrmetahost')
        },
        @{
            Id          = 'TR-INJECT-001'
            Name        = 'Remote Thread Injection / Cross-Process Access'
            Severity    = 'critical'
            Description = 'Detects cross-process operations indicative of process injection via RtlCreateUserThread / NtSetContextThread / CreateRemoteThreadEx. These are the preferred injection primitives for Cobalt Strike, Meterpreter, and custom loaders. Score=100, MalCount=12. Observable via Tanium Recorder cross_process events (process handle open with PROCESS_ALL_ACCESS or thread creation into a remote process) and image_load of ntdll.dll by processes from staging paths.'
            MitreTactic = 'Defense Evasion'
            MitreId     = 'T1055.003'
            MitreName   = 'Process Injection: Thread Execution Hijacking'
            DetectionType = 'crossProcess'
            TargetDlls  = @('ntdll.dll')
            CrossProcessTarget = '*'
            ExcludeProcs = @('svchost.exe','services.exe','lsass.exe','csrss.exe','smss.exe',
                             'wininit.exe','MsMpEng.exe','SecurityHealthService.exe')
            ApiMembers  = @('rtlcreateuserthread','ntsetcontextthread','ntresumethread',
                            'createremotethreadex')
        },
        @{
            Id          = 'TR-RECON-001'
            Name        = 'LDAP Reconnaissance via WLDAP32 Ordinals'
            Severity    = 'medium'
            Description = 'Detects wldap32.dll loaded by processes outside normal LDAP consumers. Multiple WLDAP32 ordinals (309, 304, 310, 77, 157) appear at Score=100 with MalCount 12-15, indicating Active Directory enumeration by credential-dumping or lateral-movement tools (BloodHound, ADFind, SharpHound).'
            MitreTactic = 'Discovery'
            MitreId     = 'T1018'
            MitreName   = 'Remote System Discovery'
            DetectionType = 'moduleLoad'
            TargetDlls  = @('wldap32.dll')
            ExcludeProcs = @('lsass.exe','svchost.exe','dsac.exe','mmc.exe','ldp.exe',
                             'adsiedit.msc','outlook.exe','explorer.exe','searchindexer.exe')
            ApiMembers  = @('ord(309)','ord(304)','ord(310)','ord(77)','ord(157)')
        },
        @{
            Id          = 'TR-RECON-002'
            Name        = 'Kerberos Time Sync Reconnaissance (NetRemoteTOD via netapi32.dll)'
            Severity    = 'medium'
            Description = 'Detects netapi32.dll loaded by a process other than expected system services. NetRemoteTOD is used by attackers to synchronize time with the domain controller before Kerberoasting or Golden Ticket forging. Score=100, MalCount=15. Legitimate use is extremely rare outside w32time service. Observable via image_load of netapi32.dll by non-system processes.'
            MitreTactic = 'Discovery'
            MitreId     = 'T1124'
            MitreName   = 'System Time Discovery'
            DetectionType = 'moduleLoad'
            TargetDlls  = @('netapi32.dll')
            ExcludeProcs = @('svchost.exe','w32tm.exe','net.exe','net1.exe','lsass.exe',
                             'services.exe','explorer.exe','ServerManager.exe')
            ApiMembers  = @('netremotetod')
        },
        @{
            Id          = 'TR-PERSIST-001'
            Name        = 'RPC Serialization DLL Load (Lateral Movement Infrastructure)'
            Severity    = 'medium'
            Description = 'Detects rpcrt4.dll loaded by a process from a suspicious staging path. A cluster of RPC serialization APIs (NdrMesTypeFree2, NdrMesTypeDecode2, MesDecodeIncrementalHandleCreate, MesIncrementalHandleReset, MesHandleFree) at Score=100 with MalCount=14 indicates credential-dumping and lateral-movement tools that use DCE/RPC for remote service manipulation (secretsdump, SCM-based lateral). Since rpcrt4.dll is common in legitimate software, detection focuses on process origin path.'
            MitreTactic = 'Lateral Movement'
            MitreId     = 'T1021.002'
            MitreName   = 'Remote Services: SMB/Windows Admin Shares'
            DetectionType = 'processPath'
            TargetDlls  = @('rpcrt4.dll')
            StagingPaths = @('\Temp\','\AppData\Local\Temp\','\Downloads\','\ProgramData\',
                             '\Public\','\Users\Public\','\Recycle','\Windows\Temp\')
            ExcludeProcs = @('svchost.exe','services.exe','lsass.exe','csrss.exe','wmiprvse.exe')
            ApiMembers  = @('ndrmestypefree2','ndrmestypedecode2',
                            'mesdecodeincrementalhandlecreate','mesincrementalhandlereset',
                            'meshandlefree')
        },
        @{
            Id          = 'TR-EVASION-001'
            Name        = 'Process from Staging Path Loading ntdll Directly (PEB Walking)'
            Severity    = 'high'
            Description = 'Detects processes launched from attacker staging paths that directly import ntdll functions like RtlGetCurrentPeb. Attackers use PEB walking to resolve API addresses without calling GetProcAddress (avoiding IAT-based detection). Core technique in shellcode loaders, Cobalt Strike beacons, and position-independent code. Score=100, MalCount=13. Observable via process start events from Temp, AppData, Downloads, ProgramData, or Public directories.'
            MitreTactic = 'Defense Evasion'
            MitreId     = 'T1106'
            MitreName   = 'Native API'
            DetectionType = 'processPath'
            TargetDlls  = @('ntdll.dll')
            StagingPaths = @('\Temp\','\AppData\Local\Temp\','\Downloads\','\ProgramData\',
                             '\Public\','\Users\Public\','\Recycle')
            ExcludeProcs = @()
            ApiMembers  = @('rtlgetcurrentpeb')
        }
    )

    # ================================================================
    # 3. GENERATE TANIUM SIGNALS (tanium-signal v1.0 JSON)
    # ================================================================
    # Format matches Tanium Threat Response export schema:
    #   type: "tanium-signal", typeVersion: "1.0"
    #   data.contents:  signal query expression
    #   data.syntax_version: 1
    #   data.mitreAttack.techniques: [{id, name}]
    #   data.platforms: ["windows"]
    #   data.labels: [string]

    $generated  = [System.Collections.Generic.List[PSCustomObject]]::new()
    $timestamp  = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss.fffZ')
    $fileCount  = 0
    $allSignals = [System.Collections.Generic.List[object]]::new()

    foreach ($sig in $signalFamilies) {
        # Match signal's ApiMembers against Score=100 lookup to get actual MalCounts
        $matchedApis = @()
        $totalMal    = 0
        foreach ($api in $sig.ApiMembers) {
            $key = $api.ToLower()
            $fb  = $key -replace '[aw]$',''
            $hit = if ($apiLookup.ContainsKey($key)) { $apiLookup[$key] }
                   elseif ($apiLookup.ContainsKey($fb)) { $apiLookup[$fb] }
                   else { $null }
            if ($hit) {
                $matchedApis += [PSCustomObject]@{ Name=$hit.FullName; MalCount=$hit.MalCount; Dll=$hit.Dll }
                $totalMal += $hit.MalCount
            }
        }

        if ($matchedApis.Count -eq 0) {
            Write-Host "  [SKIP] $($sig.Id) - no Score=100 APIs matched." -ForegroundColor DarkGray
            continue
        }

        Write-Host "  [GEN] $($sig.Id): $($sig.Name) ($($matchedApis.Count) APIs, $totalMal total malicious hits)" -ForegroundColor Cyan

        # Build the signal query expression (data.contents)
        $queryParts = @()

        switch ($sig.DetectionType) {
            'moduleLoad' {
                # image_load: DLL path match
                if ($sig.TargetDlls.Count -eq 1) {
                    $queryParts += "process.modules contains '$($sig.TargetDlls[0])'"
                } else {
                    $dllOr = ($sig.TargetDlls | ForEach-Object { "process.modules contains '$_'" }) -join ' OR '
                    $queryParts += "($dllOr)"
                }
                # Process exclusions
                foreach ($excl in $sig.ExcludeProcs) {
                    $queryParts += "process.name != '$excl'"
                }
            }
            'crossProcess' {
                # Cross-process access
                if ($sig.CrossProcessTarget -and $sig.CrossProcessTarget -ne '*') {
                    $queryParts += "process.target.path ends with '\\$($sig.CrossProcessTarget)'"
                }
                foreach ($excl in $sig.ExcludeProcs) {
                    $queryParts += "process.name != '$excl'"
                }
                # Also catch staging path origins
                $queryParts += "(process.path contains '\\Temp\\' OR process.path contains '\\AppData\\' OR process.path contains '\\Downloads\\' OR process.path contains '\\ProgramData\\' OR process.path contains '\\Public\\')"
            }
            'processPath' {
                # Process from staging paths
                $pathOr = @('\Temp\','\AppData\Local\Temp\','\Downloads\','\ProgramData\','\Public\') |
                    ForEach-Object { "process.path contains '$_'" }
                $queryParts += "($($pathOr -join ' OR '))"
                foreach ($excl in $sig.ExcludeProcs) {
                    $queryParts += "process.name != '$excl'"
                }
            }
        }

        $contentsQuery = $queryParts -join ' AND '

        # Derive MITRE technique labels
        $mitreLabels = @('Windows')
        switch ($sig.MitreTactic) {
            'Credential Access'  { $mitreLabels += 'Credential Access' }
            'Defense Evasion'    { $mitreLabels += 'Defense Evasion' }
            'Discovery'          { $mitreLabels += 'Discovery' }
            'Lateral Movement'   { $mitreLabels += 'Lateral Movement' }
        }

        $signal = [ordered]@{
            type         = 'tanium-signal'
            typeVersion  = '1.0'
            isSchemaValid = $true
            createdAt    = $timestamp
            updatedAt    = $timestamp
            data         = [ordered]@{
                id          = "$($sig.Id): $($sig.Name)"
                name        = "$($sig.Id): $($sig.Name)"
                description = $sig.Description
                contents    = $contentsQuery
                syntax_version = 1
                mitreAttack = @{
                    techniques = @(
                        @{ id = $sig.MitreId; name = $sig.MitreName }
                    )
                }
                platforms   = @('windows')
                labels      = $mitreLabels
            }
        }

        $allSignals.Add($signal)
        $fileCount++

        # Track for CSV
        foreach ($apiObj in $matchedApis) {
            $generated.Add([PSCustomObject]@{
                SignalId      = $sig.Id
                SignalName    = $sig.Name
                Severity      = $sig.Severity
                MitreTactic   = $sig.MitreTactic
                MitreId       = $sig.MitreId
                MitreName     = $sig.MitreName
                API           = $apiObj.Name
                MalCount      = $apiObj.MalCount
                DLL           = $apiObj.Dll
                DetectionType = $sig.DetectionType
                Contents      = $contentsQuery
                OutputFile    = 'TaniumSignals_Import.json'
            })
        }
    }

    # Write all signals into a single importable file (same schema as Tanium export)
    $exportBundle = [ordered]@{
        signals = @($allSignals)
        labels  = @(
            @{ name = 'Windows';           description = 'Signals built for Windows hosts.' }
            @{ name = 'Credential Access'; description = 'MITRE ATT&CK: Credential Access' }
            @{ name = 'Defense Evasion';   description = 'MITRE ATT&CK: Defense Evasion' }
            @{ name = 'Discovery';         description = 'MITRE ATT&CK: Discovery' }
            @{ name = 'Lateral Movement';  description = 'MITRE ATT&CK: Lateral Movement' }
            @{ name = 'LoadedPotato';      description = 'Auto-generated from Loaded-Potato EDR Gap Matrix (Score=100 APIs)' }
        )
    }

    $importFile = Join-Path $OutDir "TaniumSignals_Import.json"
    $exportBundle | ConvertTo-Json -Depth 8 -Compress | Set-Content -Path $importFile -Encoding UTF8

    # Also write individual signal files for reference
    foreach ($sig in $allSignals) {
        $safeName = $sig.data.id -replace '[^a-zA-Z0-9\-]','_' -replace '__+','_'
        $outFile = Join-Path $OutDir "$safeName.json"
        $sig | ConvertTo-Json -Depth 6 | Set-Content -Path $outFile -Encoding UTF8
    }

    # ================================================================
    # 4. GENERATE TANIUM DETECT CONSOLE QUERIES (Trace search syntax)
    # ================================================================
    # These are copy-paste-ready queries for:
    #   Threat Response > Trace > Search  (Recorder DB query)
    #   Tanium Detect > Alerts search bar
    #
    # Tanium Trace query syntax reference:
    #   type:process              - process start events
    #   type:image_load           - DLL/module load events
    #   type:registry             - registry write events
    #   type:network              - network connection events
    #   process_name:X            - filter by process name
    #   file_path contains "X"    - path substring match
    #   NOT process_name:X        - exclusion
    #   AND / OR                  - boolean operators

    $queryFile = Join-Path $OutDir "TaniumDetect_Console_Queries.txt"
    $queryContent = [System.Text.StringBuilder]::new()

    $null = $queryContent.AppendLine("# ============================================================")
    $null = $queryContent.AppendLine("# Tanium Detect / Threat Response Trace Console Queries")
    $null = $queryContent.AppendLine("# Generated: $timestamp")
    $null = $queryContent.AppendLine("# Source: Loaded-Potato EDR Gap Matrix (Score=100 APIs)")
    $null = $queryContent.AppendLine("#")
    $null = $queryContent.AppendLine("# HOW TO USE:")
    $null = $queryContent.AppendLine("#   1. Tanium Console -> Threat Response -> Trace")
    $null = $queryContent.AppendLine("#   2. Select a connection group (or 'All Computers')")
    $null = $queryContent.AppendLine("#   3. Paste a query below into the search bar")
    $null = $queryContent.AppendLine("#   4. Set time range (e.g. last 7 days, last 30 days)")
    $null = $queryContent.AppendLine("#   5. Review results for true positives")
    $null = $queryContent.AppendLine("#")
    $null = $queryContent.AppendLine("# For Tanium Detect alert rules:")
    $null = $queryContent.AppendLine("#   - Import the .json signal files via Intel -> Import")
    $null = $queryContent.AppendLine("#   - These queries are for ad-hoc hunting / validation")
    $null = $queryContent.AppendLine("# ============================================================")
    $null = $queryContent.AppendLine("")

    foreach ($sig in $signalFamilies) {
        $sigApis = @($generated | Where-Object { $_.SignalId -eq $sig.Id })
        if ($sigApis.Count -eq 0) { continue }

        $null = $queryContent.AppendLine("# --------------------------------------------------------------")
        $null = $queryContent.AppendLine("# $($sig.Id): $($sig.Name)")
        $null = $queryContent.AppendLine("# Severity: $($sig.Severity.ToUpper())  |  MITRE: $($sig.MitreId) ($($sig.MitreName))")
        $null = $queryContent.AppendLine("# $($sig.Description -replace '\r?\n',' ')")
        $null = $queryContent.AppendLine("# --------------------------------------------------------------")
        $null = $queryContent.AppendLine("")

        # Build exclusion string (shared across query types)
        $exclParts = @()
        foreach ($excl in $sig.ExcludeProcs) {
            $exclParts += "NOT process_name:$excl"
        }
        $exclString = if ($exclParts.Count -gt 0) { " AND " + ($exclParts -join " AND ") } else { "" }

        switch ($sig.DetectionType) {
            'moduleLoad' {
                # image_load events for the target DLLs
                foreach ($dll in $sig.TargetDlls) {
                    $null = $queryContent.AppendLine("# -- $dll loaded by non-system process (image_load) --")
                    $null = $queryContent.AppendLine("type:image_load AND file_path contains `"$dll`"$exclString")
                    $null = $queryContent.AppendLine("")
                }
                if ($sig.TargetDlls.Count -gt 1) {
                    $dllOr = ($sig.TargetDlls | ForEach-Object { "file_path contains `"$_`"" }) -join " OR "
                    $null = $queryContent.AppendLine("# -- Combined (any of the target DLLs) --")
                    $null = $queryContent.AppendLine("type:image_load AND ($dllOr)$exclString")
                    $null = $queryContent.AppendLine("")
                }
            }
            'crossProcess' {
                # cross_process events
                $null = $queryContent.AppendLine("# -- Cross-process operations (Recorder cross_process events) --")
                if ($sig.CrossProcessTarget -and $sig.CrossProcessTarget -ne '*') {
                    $null = $queryContent.AppendLine("type:cross_process AND target_process_name:$($sig.CrossProcessTarget)$exclString")
                } else {
                    $null = $queryContent.AppendLine("type:cross_process$exclString")
                }
                $null = $queryContent.AppendLine("")
                # Also check image_load for the carrier DLLs from staging paths
                foreach ($dll in $sig.TargetDlls) {
                    $null = $queryContent.AppendLine("# -- $dll loaded from staging path (image_load) --")
                    $null = $queryContent.AppendLine("type:image_load AND file_path contains `"$dll`" AND (process_path contains `"\Temp\`" OR process_path contains `"\AppData\`" OR process_path contains `"\Downloads\`" OR process_path contains `"\Public\`")$exclString")
                    $null = $queryContent.AppendLine("")
                }
            }
            'processPath' {
                # Process start from staging paths + DLL load
                $apiList = ($sigApis | ForEach-Object { ($_.API -split '!')[-1] }) -join ', '
                $null = $queryContent.AppendLine("# -- Process from staging path loading $($sig.TargetDlls -join '/') (carrier for: $apiList) --")
                $pathOr = @('\Temp\','\AppData\Local\Temp\','\Downloads\','\ProgramData\','\Public\','\Users\Public\') |
                    ForEach-Object { "file_path contains `"$_`"" }
                $null = $queryContent.AppendLine("type:process AND ($($pathOr -join ' OR '))$exclString")
                $null = $queryContent.AppendLine("")
                foreach ($dll in $sig.TargetDlls) {
                    $null = $queryContent.AppendLine("# -- $dll loaded by process from staging path --")
                    $null = $queryContent.AppendLine("type:image_load AND file_path contains `"$dll`" AND (process_path contains `"\Temp\`" OR process_path contains `"\AppData\`" OR process_path contains `"\Downloads\`" OR process_path contains `"\Public\`")$exclString")
                    $null = $queryContent.AppendLine("")
                }
            }
        }
    }

    # Bonus: composite high-severity queries
    $null = $queryContent.AppendLine("# ==============================================================")
    $null = $queryContent.AppendLine("# COMPOSITE: Any critical credential-dumping DLL loaded outside")
    $null = $queryContent.AppendLine("# system processes (combines TR-CRED-001 + TR-CRED-002)")
    $null = $queryContent.AppendLine("# ==============================================================")
    $null = $queryContent.AppendLine("type:image_load AND (file_path contains `"samlib.dll`" OR file_path contains `"cryptdll.dll`") AND NOT process_name:lsass.exe AND NOT process_name:services.exe AND NOT process_name:svchost.exe AND NOT process_name:csrss.exe")
    $null = $queryContent.AppendLine("")
    $null = $queryContent.AppendLine("# ==============================================================")
    $null = $queryContent.AppendLine("# COMPOSITE: Cross-process access to LSASS (credential theft)")
    $null = $queryContent.AppendLine("# ==============================================================")
    $null = $queryContent.AppendLine("type:cross_process AND target_process_name:lsass.exe AND NOT process_name:lsass.exe AND NOT process_name:csrss.exe AND NOT process_name:services.exe AND NOT process_name:svchost.exe AND NOT process_name:wininit.exe AND NOT process_name:MsMpEng.exe")
    $null = $queryContent.AppendLine("")
    $null = $queryContent.AppendLine("# ==============================================================")
    $null = $queryContent.AppendLine("# COMPOSITE: CLR + LDAP + Credential DLLs (broad sweep)")
    $null = $queryContent.AppendLine("# Any of these DLLs loading is unusual outside expected procs.")
    $null = $queryContent.AppendLine("# ==============================================================")
    $null = $queryContent.AppendLine("type:image_load AND (file_path contains `"samlib.dll`" OR file_path contains `"cryptdll.dll`" OR file_path contains `"mscoree.dll`" OR file_path contains `"wldap32.dll`") AND NOT process_name:lsass.exe AND NOT process_name:services.exe AND NOT process_name:svchost.exe AND NOT process_name:csrss.exe AND NOT process_name:powershell.exe AND NOT process_name:searchindexer.exe AND NOT process_name:explorer.exe AND NOT process_name:outlook.exe AND NOT process_name:mmc.exe")
    $null = $queryContent.AppendLine("")
    $null = $queryContent.AppendLine("# ==============================================================")
    $null = $queryContent.AppendLine("# COMPOSITE: Any process from staging path with cross-process op")
    $null = $queryContent.AppendLine("# ==============================================================")
    $null = $queryContent.AppendLine("type:cross_process AND (process_path contains `"\Temp\`" OR process_path contains `"\AppData\`" OR process_path contains `"\Downloads\`" OR process_path contains `"\Public\`" OR process_path contains `"\ProgramData\`")")
    $null = $queryContent.AppendLine("")

    Set-Content -Path $queryFile -Value $queryContent.ToString() -Encoding UTF8
    Write-Host ""
    Write-Host "[QUERIES] Tanium Detect console queries saved to:" -ForegroundColor Green
    Write-Host "          $queryFile" -ForegroundColor DarkCyan

    # ================================================================
    # 5. SUMMARY CSV
    # ================================================================
    $csvPath = Join-Path $OutDir "TaniumSignals_Summary.csv"
    $generated | Export-Csv -Path $csvPath -NoTypeInformation
    Write-Host ""
    Write-Host "[DONE] Generated $fileCount Tanium Threat Response signals ($($generated.Count) API mappings)." -ForegroundColor Green
    Write-Host "       Import bundle:   $importFile" -ForegroundColor DarkCyan
    Write-Host "       Console queries: $queryFile" -ForegroundColor DarkCyan
    Write-Host "       Summary CSV:     $csvPath" -ForegroundColor DarkCyan

    # ================================================================
    # 6. CONSOLE SUMMARY TABLE
    # ================================================================
    Write-Host ""
    Write-Host "=== Signal Summary ===" -ForegroundColor Cyan
    Write-Host ("{0,-16} {1,-8} {2,-55} {3,-5} {4}" -f "ID","Severity","Name","APIs","Total MalHits") -ForegroundColor DarkCyan
    Write-Host ("-" * 105) -ForegroundColor DarkGray

    foreach ($sig in $signalFamilies) {
        $sigApis = @($generated | Where-Object { $_.SignalId -eq $sig.Id })
        if ($sigApis.Count -eq 0) { continue }
        $totalHits = ($sigApis | Measure-Object -Property MalCount -Sum).Sum
        $sevColor = switch ($sig.Severity) {
            'critical' { 'Red' }
            'high'     { 'Yellow' }
            'medium'   { 'DarkYellow' }
            default    { 'Gray' }
        }
        Write-Host ("{0,-16} " -f $sig.Id) -NoNewline -ForegroundColor White
        Write-Host ("{0,-8} " -f $sig.Severity.ToUpper()) -NoNewline -ForegroundColor $sevColor
        Write-Host ("{0,-55} {1,-5} {2}" -f $sig.Name, $sigApis.Count, $totalHits)
    }

    Write-Host ""
    Write-Host "=== How to use ===" -ForegroundColor Cyan
    Write-Host "  IMMEDIATE HUNTING (ad-hoc):" -ForegroundColor DarkCyan
    Write-Host "    1. Open Tanium Console -> Threat Response -> Trace" -ForegroundColor Gray
    Write-Host "    2. Select connection group or 'All Computers'" -ForegroundColor Gray
    Write-Host "    3. Copy a query from: $queryFile" -ForegroundColor White
    Write-Host "    4. Paste into search bar, set time range (last 7-30 days), run" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  ONGOING DETECTION (persistent):" -ForegroundColor DarkCyan
    Write-Host "    1. Open Tanium Console -> Threat Response -> Intel" -ForegroundColor Gray
    Write-Host "    2. Click 'Import' -> 'From File' -> select:" -ForegroundColor Gray
    Write-Host "       $(try { (Resolve-Path $importFile).Path } catch { $importFile })" -ForegroundColor White
    Write-Host "    3. Enable each signal. Adjust process exclusions as needed." -ForegroundColor Gray
    Write-Host "    4. Signals evaluate against Recorder data on every scan cycle." -ForegroundColor Gray
}

Export-ModuleMember -Function New-TaniumSignalsFromEDRMatrix
