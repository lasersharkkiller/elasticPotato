rule PicusRedReport2026_GhostCrypt_PureRAT_ProcessHypnosis {
    meta:
        description = "Detects GhostCrypt loader and PureRAT - uses Process Hypnosis technique to execute malicious code by manipulating legitimate process internal execution logic without creating/hijacking threads. Abuses asynchronous execution mechanisms and TLS callbacks. Picus Red Report 2026 T1055.005, T1055."
        author = "Loaded Potato - Picus Red Report 2026 Analysis"
        date = "2026-04-09"
        reference = "https://www.picussecurity.com/red-report-2026"
        mitre_attack = "T1055.005, T1055"
        malware_family = "GhostCrypt, PureRAT"

    strings:
        $s_ghostcrypt = "GhostCrypt" ascii wide nocase
        $s_purerat = "PureRAT" ascii wide nocase
        $s_hypnosis = "hypnosis" ascii wide nocase
        $tls1 = "TlsSetValue" ascii
        $tls2 = "TlsGetValue" ascii
        $tls3 = "TlsAlloc" ascii
        $tls4 = "TLS" ascii wide
        $api1 = "resolve_api_hash" ascii
        $api2 = "GetCurrentDirectoryW" ascii
        $api3 = "Thread Information Block" ascii
        $inject1 = "VirtualAllocEx" ascii
        $inject2 = "WriteProcessMemory" ascii
        $inject3 = "NtQueueApcThread" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            any of ($s_ghostcrypt, $s_purerat) or
            ($s_hypnosis and any of ($inject*)) or
            (2 of ($tls*) and 2 of ($inject*)) or
            ($api1 and $api2)
        )
}
