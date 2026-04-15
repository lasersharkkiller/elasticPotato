rule PicusRedReport2026_BRICKSTORM_WarpPanda {
    meta:
        description = "Detects BRICKSTORM and Junction malware associated with Warp Panda (China-nexus). Uses masquerading (T1036) with invalid/expired digital signatures. BRICKSTORM is a multi-platform backdoor. Picus Red Report 2026."
        author = "Loaded Potato - Picus Red Report 2026 Analysis"
        date = "2026-04-09"
        reference = "https://www.picussecurity.com/red-report-2026"
        mitre_attack = "T1036"
        malware_family = "BRICKSTORM"

    strings:
        $s_name1 = "BRICKSTORM" ascii wide nocase
        $s_name2 = "Junction" ascii wide
        $s_warp = "WarpPanda" ascii wide nocase
        $tunnel1 = "tunnel" ascii wide
        $tunnel2 = "proxy" ascii wide
        $tunnel3 = "socks" ascii wide nocase
        $c2_1 = "websocket" ascii wide nocase
        $c2_2 = "wss://" ascii wide
        $file_mgmt1 = "upload" ascii wide nocase
        $file_mgmt2 = "download" ascii wide nocase
        $file_mgmt3 = "listdir" ascii wide nocase

    condition:
        filesize < 15MB and
        (
            any of ($s_name*) or
            ($s_warp) or
            (2 of ($tunnel*) and any of ($c2_*) and any of ($file_mgmt*))
        )
}
