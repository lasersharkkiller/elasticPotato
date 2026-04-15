rule PicusRedReport2026_Anubis_Ransomware {
    meta:
        description = "Detects Anubis ransomware - extracts embedded branding assets (icon.ico, wall.jpg) to C:\\ProgramData and sets ransom wallpaper via registry modification. Uses cmd.exe for visual psychological pressure. Picus Red Report 2026 T1059.003, T1486."
        author = "Loaded Potato - Picus Red Report 2026 Analysis"
        date = "2026-04-09"
        reference = "https://www.picussecurity.com/red-report-2026"
        mitre_attack = "T1486, T1059.003"
        malware_family = "Anubis"

    strings:
        $s_name1 = "Anubis" ascii wide nocase
        $s_name2 = "anubis" ascii
        $wallpaper1 = "wall.jpg" ascii wide
        $wallpaper2 = "icon.ico" ascii wide
        $wallpaper3 = "ProgramData" ascii wide
        $wallpaper4 = "Wallpaper" ascii wide
        $reg1 = "Policies\\System" ascii wide
        $reg2 = "reg add" ascii wide
        $ransom1 = "Your files" ascii wide nocase
        $ransom2 = "bitcoin" ascii wide nocase
        $ransom3 = "decrypt" ascii wide nocase
        $vss1 = "vssadmin" ascii wide nocase
        $vss2 = "Delete Shadows" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 20MB and
        (
            ($s_name1 and (any of ($wallpaper*) or any of ($ransom*))) or
            (2 of ($wallpaper*) and any of ($reg*) and any of ($vss*))
        )
}
