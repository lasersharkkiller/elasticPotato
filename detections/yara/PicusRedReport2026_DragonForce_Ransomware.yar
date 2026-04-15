rule PicusRedReport2026_DragonForce_Ransomware {
    meta:
        description = "Detects DragonForce ransomware - uses PowerShell one-liners with -nop -w hidden for in-memory payload delivery, hybrid encryption (AES/ChaCha20 + RSA), VSS shadow deletion. Also uses T1059 command and scripting interpreter. Picus Red Report 2026 T1059, T1486."
        author = "Loaded Potato - Picus Red Report 2026 Analysis"
        date = "2026-04-09"
        reference = "https://www.picussecurity.com/red-report-2026"
        mitre_attack = "T1486, T1059.001"
        malware_family = "DragonForce"

    strings:
        $s_name1 = "DragonForce" ascii wide nocase
        $s_name2 = "DRAGON" ascii wide
        $ransom_note1 = "Your files have been encrypted" ascii wide nocase
        $ransom_note2 = ".dragonforce" ascii wide nocase
        $crypto1 = "ChaCha20" ascii wide
        $crypto2 = "RSA" ascii wide
        $crypto3 = "AES-256" ascii wide
        $vss1 = "vssadmin" ascii wide nocase
        $vss2 = "Delete Shadows" ascii wide nocase
        $vss3 = "shadowcopy delete" ascii wide nocase
        $ps1 = "powershell" ascii wide nocase
        $ps2 = "-nop" ascii wide
        $ps3 = "-w hidden" ascii wide
        $ps4 = "DownloadString" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 20MB and
        (
            (any of ($s_name*) and (any of ($crypto*) or any of ($vss*))) or
            (any of ($ransom_note*) and any of ($crypto*) and any of ($vss*))
        )
}
