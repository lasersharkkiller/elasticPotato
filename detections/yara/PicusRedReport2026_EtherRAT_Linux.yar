rule PicusRedReport2026_EtherRAT_Linux {
    meta:
        description = "Detects EtherRAT Linux malware - creates hidden .desktop files in XDG autostart directories for persistence, launches silently with every user login. Part of T1547 Boot or Logon Autostart Execution trend documented in Picus Red Report 2026."
        author = "Loaded Potato - Picus Red Report 2026 Analysis"
        date = "2026-04-09"
        reference = "https://www.picussecurity.com/red-report-2026"
        mitre_attack = "T1547"
        malware_family = "EtherRAT"

    strings:
        $s_name = "EtherRAT" ascii wide nocase
        $s_ether = "ether" ascii wide nocase
        $desktop1 = ".desktop" ascii
        $desktop2 = "autostart" ascii
        $desktop3 = "[Desktop Entry]" ascii
        $desktop4 = "Exec=" ascii
        $desktop5 = "Hidden=true" ascii
        $xdg1 = ".config/autostart" ascii
        $xdg2 = ".local/share/autostart" ascii
        $c2_1 = "socket" ascii
        $c2_2 = "connect" ascii
        $c2_3 = "recv" ascii

    condition:
        (uint32(0) == 0x464C457F) and  // ELF magic
        filesize < 10MB and
        (
            $s_name or
            (2 of ($desktop*) and any of ($xdg*)) or
            ($s_ether and any of ($desktop*) and any of ($c2_*))
        )
}
