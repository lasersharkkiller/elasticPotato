rule PicusRedReport2026_SplatCloak_MustangPanda {
    meta:
        description = "Detects SplatCloak EDR evasion tool used by Mustang Panda. Designed to impair Windows Defender and EDR agents by disabling security features. Used alongside Paklog and Corklog keyloggers. Picus Red Report 2026 T1562."
        author = "Loaded Potato - Picus Red Report 2026 Analysis"
        date = "2026-04-09"
        reference = "https://www.picussecurity.com/red-report-2026"
        mitre_attack = "T1562.001"
        malware_family = "SplatCloak"

    strings:
        $s_name1 = "SplatCloak" ascii wide nocase
        $s_name2 = "Paklog" ascii wide nocase
        $s_name3 = "Corklog" ascii wide nocase
        $edr1 = "Windows Defender" ascii wide
        $edr2 = "MsMpEng" ascii wide
        $edr3 = "MpCmdRun" ascii wide
        $edr4 = "WdFilter" ascii wide
        $disable1 = "DisableRealtimeMonitoring" ascii wide
        $disable2 = "DisableAntiSpyware" ascii wide
        $disable3 = "TamperProtection" ascii wide
        $driver1 = "DeviceIoControl" ascii
        $driver2 = "NtLoadDriver" ascii
        $driver3 = "\\Registry\\Machine\\System" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            any of ($s_name*) or
            (2 of ($edr*) and any of ($disable*)) or
            (any of ($disable*) and any of ($driver*))
        )
}
