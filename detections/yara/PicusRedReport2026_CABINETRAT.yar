rule PicusRedReport2026_CABINETRAT {
    meta:
        description = "Detects CABINETRAT malware - Windows RAT targeting South Asia. Creates scheduled tasks every 12 hours from fake Microsoft Office paths, checks admin via whoami/SID S-1-5-32-544, uses Run registry key persistence disguised as ChromeUpdater. Picus Red Report 2026 T1059.003, T1547."
        author = "Loaded Potato - Picus Red Report 2026 Analysis"
        date = "2026-04-09"
        reference = "https://www.picussecurity.com/red-report-2026"
        mitre_attack = "T1059.003, T1547.001, T1053.005"
        malware_family = "CABINETRAT"

    strings:
        $s_name = "CABINETRAT" ascii wide nocase
        $s_cabinet = "cabinet" ascii wide nocase
        $cmd1 = "schtasks.exe /create /sc hourly /mo 12" ascii wide
        $cmd2 = "whoami /groups" ascii wide
        $cmd3 = "S-1-5-32-544" ascii wide
        $cmd4 = "ChromeUpdater" ascii wide
        $cmd5 = "\\Microsoft\\Office\\" ascii wide
        $persistence1 = "CurrentVersion\\Run" ascii wide
        $persistence2 = "reg add" ascii wide
        $persistence3 = "schtasks" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            $s_name or
            ($cmd1 and $cmd5) or
            ($cmd2 and $cmd3 and any of ($persistence*)) or
            ($cmd4 and any of ($persistence*))
        )
}
