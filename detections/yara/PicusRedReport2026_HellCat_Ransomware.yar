rule PicusRedReport2026_HellCat_Ransomware {
    meta:
        description = "Detects HellCat ransomware - uses multi-stage PowerShell chains with Invoke-WebRequest, ScriptBlock::Create for in-memory execution, and persistent Run-key at HKCU\\Run\\maintenance. Downloads follow-on payloads from attacker infrastructure. Picus Red Report 2026 T1059.001, T1547.001."
        author = "Loaded Potato - Picus Red Report 2026 Analysis"
        date = "2026-04-09"
        reference = "https://www.picussecurity.com/red-report-2026"
        mitre_attack = "T1059.001, T1547.001, T1486"
        malware_family = "HellCat"

    strings:
        $s_name1 = "HellCat" ascii wide nocase
        $s_name2 = "hellcat" ascii
        $ps1 = "ScriptBlock" ascii wide
        $ps2 = "::Create" ascii wide
        $ps3 = "Invoke-WebRequest" ascii wide
        $ps4 = "iwr" ascii wide
        $ps5 = "payload.ps1" ascii wide
        $persist1 = "maintenance" ascii wide
        $persist2 = "CurrentVersion\\Run" ascii wide
        $ransom1 = "Your files" ascii wide nocase
        $ransom2 = ".hellcat" ascii wide nocase
        $crypto1 = "AES" ascii wide
        $crypto2 = "RSA" ascii wide

    condition:
        filesize < 20MB and
        (
            (any of ($s_name*) and (any of ($ps*) or any of ($ransom*))) or
            ($persist1 and $persist2 and 2 of ($ps*))
        )
}
