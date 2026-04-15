rule PicusRedReport2026_NoisyBear_ThreadHijacking {
    meta:
        description = "Detects NoisyBear APT thread execution hijacking from Operation BarrelFire targeting Kazakhstan oil and gas sector. Uses spoofed government-themed emails, anti-analysis checks, then creates suspended process, injects payload via SetThreadContext. Picus Red Report 2026 T1055.003."
        author = "Loaded Potato - Picus Red Report 2026 Analysis"
        date = "2026-04-09"
        reference = "https://www.picussecurity.com/red-report-2026"
        mitre_attack = "T1055.003"
        malware_family = "NoisyBear"

    strings:
        $s_name1 = "NoisyBear" ascii wide nocase
        $s_name2 = "BarrelFire" ascii wide nocase
        $api1 = "GetThreadContext" ascii
        $api2 = "SetThreadContext" ascii
        $api3 = "VirtualAllocEx" ascii
        $api4 = "WriteProcessMemory" ascii
        $api5 = "ResumeThread" ascii
        $api6 = "CreateProcessA" ascii
        $register1 = "Rip" ascii
        $register2 = "CONTEXT" ascii
        $anti1 = "IsDebuggerPresent" ascii
        $anti2 = "CheckRemoteDebuggerPresent" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            any of ($s_name*) or
            ($api1 and $api2 and $api3 and $api4 and $api5)
        )
}
