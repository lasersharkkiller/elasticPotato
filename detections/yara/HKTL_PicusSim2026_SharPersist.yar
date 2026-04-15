rule HKTL_PicusSim2026_SharPersist
{
    meta:
        description = "Detects SharPersist - a .NET persistence toolkit supporting scheduled tasks, services, registry run keys, and startup folder persistence"
        author = "Loaded Potato - Picus Simulation 2026-04-12"
        date = "2026-04-13"
        reference = "https://github.com/mandiant/SharPersist"
        mitre_attack = "T1543.003,T1053.005,T1547.001"
        score = 90

    strings:
        $s1 = "SharPersist" ascii wide
        $s2 = "sharpersist" ascii wide nocase
        $s3 = "-t service" ascii wide
        $s4 = "-t schtask" ascii wide
        $s5 = "-t reg" ascii wide
        $s6 = "-t startupfolder" ascii wide
        $s7 = "-m add" ascii wide
        $s8 = "-m remove" ascii wide
        $s9 = "-m check" ascii wide
        $s10 = "-m list" ascii wide

        $net1 = "System.ServiceProcess" ascii
        $net2 = "TaskScheduler" ascii
        $net3 = "RegistryKey" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            ($s1 or $s2) and any of ($s3, $s4, $s5, $s6) or
            3 of ($s3, $s4, $s5, $s6, $s7, $s8, $s9, $s10)
        )
}
