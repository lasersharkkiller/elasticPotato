rule PicusRedReport2026_CANONSTAGER_TLS {
    meta:
        description = "Detects CANONSTAGER malware - uses Thread Local Storage (TLS) injection to execute malicious code stealthily. Stores payload and config data isolated to a specific thread via TlsSetValue. Picus Red Report 2026 T1055.005."
        author = "Loaded Potato - Picus Red Report 2026 Analysis"
        date = "2026-04-09"
        reference = "https://www.picussecurity.com/red-report-2026"
        mitre_attack = "T1055.005"
        malware_family = "CANONSTAGER"

    strings:
        $s_name = "CANONSTAGER" ascii wide nocase
        $s_canon = "canon" ascii wide nocase
        $tls1 = "TlsSetValue" ascii
        $tls2 = "TlsGetValue" ascii
        $tls3 = "TlsAlloc" ascii
        $api1 = "VirtualAlloc" ascii
        $api2 = "VirtualProtect" ascii
        $api3 = "CreateThread" ascii
        $stager1 = "stage" ascii wide nocase
        $stager2 = "payload" ascii wide nocase
        $stager3 = "loader" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            $s_name or
            (2 of ($tls*) and 2 of ($api*) and any of ($stager*))
        )
}
