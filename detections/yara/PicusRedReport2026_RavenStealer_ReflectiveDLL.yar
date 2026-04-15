rule PicusRedReport2026_RavenStealer_ReflectiveDLL {
    meta:
        description = "Detects Raven Stealer - uses reflective DLL injection to decrypt and inject DLL payload directly in memory without writing to disk. Self-loading reflective loader avoids LoadLibrary API monitoring by EDR. Picus Red Report 2026 T1055.001."
        author = "Loaded Potato - Picus Red Report 2026 Analysis"
        date = "2026-04-09"
        reference = "https://www.picussecurity.com/red-report-2026"
        mitre_attack = "T1055.001"
        malware_family = "RavenStealer"

    strings:
        $s_name = "RavenStealer" ascii wide nocase
        $s_raven = "Raven Stealer" ascii wide nocase
        $reflective1 = "ReflectiveLoader" ascii
        $reflective2 = "reflective" ascii wide nocase
        $api1 = "VirtualAlloc" ascii
        $api2 = "GetProcAddress" ascii
        $api3 = "LoadLibrary" ascii
        $api4 = "NtFlushInstructionCache" ascii
        $pe_header = "This program cannot be run in DOS mode" ascii
        $stealer1 = "\\Login Data" ascii wide
        $stealer2 = "\\Cookies" ascii wide
        $stealer3 = "wallet" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            any of ($s_name, $s_raven) or
            (2 of ($reflective*) and 2 of ($api*) and any of ($stealer*))
        )
}
