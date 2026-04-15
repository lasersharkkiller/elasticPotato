rule PicusRedReport2026_Deadlock_Ransomware {
    meta:
        description = "Detects Deadlock ransomware - abuses SystemSettingsAdminFlows.exe to disable Defender real-time protection and cloud reporting silently. Uses T1562 Impair Defenses as standard first step before encryption. Also uses remote access tools for persistence. Picus Red Report 2026 T1562, T1219, T1486."
        author = "Loaded Potato - Picus Red Report 2026 Analysis"
        date = "2026-04-09"
        reference = "https://www.picussecurity.com/red-report-2026"
        mitre_attack = "T1562.001, T1486, T1219"
        malware_family = "Deadlock"

    strings:
        $s_name1 = "Deadlock" ascii wide nocase
        $s_name2 = "DeadLock" ascii wide
        $defender1 = "SystemSettingsAdminFlows" ascii wide
        $defender2 = "DisableRealtimeMonitoring" ascii wide
        $defender3 = "DisableAntiSpyware" ascii wide
        $defender4 = "Windows Defender" ascii wide
        $ransom1 = "Your files have been encrypted" ascii wide nocase
        $ransom2 = ".deadlock" ascii wide nocase
        $vss1 = "vssadmin" ascii wide nocase
        $vss2 = "Delete Shadows" ascii wide nocase
        $crypto1 = "AES" ascii wide
        $crypto2 = "RSA" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 20MB and
        (
            ($s_name1 and ($defender1 or any of ($ransom*))) or
            ($s_name2 and any of ($crypto*)) or
            ($defender1 and any of ($defender2, $defender3) and any of ($vss*))
        )
}
