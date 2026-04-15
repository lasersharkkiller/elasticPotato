rule HKTL_PicusSim2026_SharpHide
{
    meta:
        description = "Detects SharpHide - a tool that creates hidden registry Run keys using null-byte prefixed value names invisible to regedit"
        author = "Loaded Potato - Picus Simulation 2026-04-12"
        date = "2026-04-13"
        reference = "https://github.com/outflanknl/SharpHide"
        mitre_attack = "T1564.001,T1547.001"
        score = 90

    strings:
        $s1 = "SharpHide" ascii wide
        $s2 = "RegOpenKeyEx" ascii wide
        $s3 = "NtSetValueKey" ascii wide
        $s4 = "\\CurrentVersion\\Run" ascii wide
        $s5 = "Hidden registry" ascii wide nocase
        $s6 = "UNICODE_STRING" ascii wide
        $s7 = "\\x00" ascii  // null byte prefix technique

        $net1 = "System.Runtime" ascii
        $net2 = "Microsoft.Win32" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        (
            ($s1 and 2 of ($s2, $s3, $s4, $s5)) or
            ($s3 and $s4 and any of ($net*))
        )
}
