rule PicusRedReport2026_SantaStealer {
    meta:
        description = "Detects SantaStealer malware - bypasses Chrome AppBound encryption by abusing legitimate browser APIs to request decrypted passwords. Targets browser credential stores. Picus Red Report 2026 T1555.003."
        author = "Loaded Potato - Picus Red Report 2026 Analysis"
        date = "2026-04-09"
        reference = "https://www.picussecurity.com/red-report-2026"
        mitre_attack = "T1555.003"
        malware_family = "SantaStealer"

    strings:
        $s_name = "SantaStealer" ascii wide nocase
        $s_santa = "santa" ascii wide nocase
        $browser1 = "\\Google\\Chrome\\User Data" ascii wide
        $browser2 = "\\Login Data" ascii wide
        $browser3 = "\\Local State" ascii wide
        $browser4 = "AppBound" ascii wide
        $browser5 = "encrypted_key" ascii wide
        $browser6 = "os_crypt" ascii wide
        $api1 = "CryptUnprotectData" ascii
        $api2 = "BCryptDecrypt" ascii
        $exfil1 = "POST" ascii wide
        $exfil2 = "multipart" ascii wide
        $exfil3 = "Content-Disposition" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            $s_name or
            (3 of ($browser*) and any of ($api*)) or
            ($s_santa and 2 of ($browser*) and any of ($exfil*))
        )
}
