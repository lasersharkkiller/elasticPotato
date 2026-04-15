rule HKTL_PicusSim2026_ContiRansomware
{
    meta:
        description = "Detects Conti ransomware indicators including shadowops flag and encryption routines"
        author = "Loaded Potato - Picus Simulation 2026-04-12"
        date = "2026-04-13"
        reference = "https://attack.mitre.org/techniques/T1490/"
        score = 95

    strings:
        $name1 = "ContiRansomware" ascii wide
        $name2 = "conti" ascii wide nocase
        $flag1 = "-shadowops" ascii wide
        $flag2 = "-encrypt" ascii wide
        $flag3 = "-path" ascii wide
        $ransom1 = "readme.txt" ascii wide nocase
        $ransom2 = "CONTI_README" ascii wide
        $ransom3 = ".CONTI" ascii wide
        $crypto1 = "ChaCha20" ascii wide
        $crypto2 = "CryptEncrypt" ascii wide
        $vss = "vssadmin" ascii wide nocase
        $shadow = "delete shadows" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            $flag1 |
            ($name1 and 1 of ($crypto*)) |
            ($name2 and $vss and $shadow) |
            2 of ($ransom*) and 1 of ($crypto*)
        )
}

rule HKTL_PicusSim2026_BlackByteEncryptor
{
    meta:
        description = "Detects BlackByte ransomware encryptor"
        author = "Loaded Potato - Picus Simulation 2026-04-12"
        date = "2026-04-13"
        reference = "https://attack.mitre.org/techniques/T1486/"
        score = 95

    strings:
        $name1 = "BlackByteEncryptor" ascii wide
        $name2 = "BlackByte" ascii wide
        $ext = ".blackbyte" ascii wide nocase
        $note1 = "BlackByte_restoremyfiles" ascii wide
        $note2 = "restore_files" ascii wide
        $crypto1 = "AES" ascii wide
        $crypto2 = "RSA" ascii wide
        $kill1 = "taskkill" ascii wide
        $kill2 = "sc stop" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            $name1 |
            ($name2 and ($ext or 1 of ($note*))) |
            ($name2 and 1 of ($crypto*) and 1 of ($kill*))
        )
}

rule HKTL_PicusSim2026_RansomEXX
{
    meta:
        description = "Detects RansomEXX ransomware"
        author = "Loaded Potato - Picus Simulation 2026-04-12"
        date = "2026-04-13"
        reference = "https://attack.mitre.org/techniques/T1486/"
        score = 95

    strings:
        $name1 = "RansomEXX" ascii wide nocase
        $name2 = "ransom_exx" ascii wide nocase
        $note1 = "!NEWS!" ascii wide
        $note2 = "YOUR FILES ARE ENCRYPTED" ascii wide nocase
        $mutex = "Global\\RansomEXX" ascii wide
        $crypto = "mbedtls" ascii wide
        $ext = ".exx" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            $name1 or $name2 or $mutex |
            ($ext and $note1) |
            ($crypto and 1 of ($note*))
        )
}

rule HKTL_PicusSim2026_BianLian
{
    meta:
        description = "Detects BianLian ransomware encryptor (Go-based)"
        author = "Loaded Potato - Picus Simulation 2026-04-12"
        date = "2026-04-13"
        reference = "https://attack.mitre.org/techniques/T1486/"
        score = 95

    strings:
        $name1 = "BianMain" ascii wide
        $name2 = "BianLian" ascii wide nocase
        $name3 = "bianlian" ascii
        $go1 = "main.encryptFile" ascii
        $go2 = "main.walkDir" ascii
        $go3 = "Go build" ascii
        $ext = ".bianlian" ascii wide
        $note = "Look at this instruction" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        (
            $name1 or $name3 |
            ($name2 and ($ext or 1 of ($go*))) |
            ($ext and $note)
        )
}

rule HKTL_PicusSim2026_IOCTL_VOLSNAP
{
    meta:
        description = "Detects IOCTL_VOLSNAP_SET_MAX_DIFF_AREA_SIZE tool used in ransomware pre-encryption to manipulate volume shadow copies"
        author = "Loaded Potato - Picus Simulation 2026-04-12"
        date = "2026-04-13"
        reference = "https://attack.mitre.org/techniques/T1490/"
        score = 90

    strings:
        $name = "IOCTL_VOLSNAP" ascii wide
        $ioctl1 = "DeviceIoControl" ascii wide
        $ioctl2 = "VOLSNAP" ascii wide
        $ioctl3 = "SET_MAX_DIFF_AREA_SIZE" ascii wide
        $vol1 = "VolSnap" ascii wide
        $vol2 = "\\\\.\\VolSnap" ascii wide
        $vol3 = "shadow" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 500KB and
        (
            $name |
            ($ioctl1 and ($ioctl2 or $ioctl3)) |
            ($vol2 and $ioctl1)
        )
}
