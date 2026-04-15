rule PicusRedReport2026_LummaC2_Stealer {
    meta:
        description = "Detects LummaC2 v4.0 stealer - uses trigonometric mouse movement analysis for sandbox evasion (Euclidean distance/angle calculation), process doppelganging via IDAT Loader, and browser credential theft. MaaS group. Ranked under T1055, T1497, T1555 in Picus Red Report 2026."
        author = "Loaded Potato - Picus Red Report 2026 Analysis"
        date = "2026-04-09"
        reference = "https://www.picussecurity.com/red-report-2026"
        mitre_attack = "T1055.013, T1497, T1555.003"
        malware_family = "LummaC2"
        hash = ""

    strings:
        $api_getcursorpos = "GetCursorPos" ascii wide
        $api_sqrt = "sqrt" ascii
        $api_atan2 = "atan2" ascii
        $s_lumma1 = "LummaC2" ascii wide nocase
        $s_lumma2 = "lumma" ascii wide nocase
        $s_euclidean = "euclidean" ascii wide nocase
        $s_mouse_check = "mouse_moved" ascii wide
        $s_browser_path1 = "\\Google\\Chrome\\User Data" ascii wide
        $s_browser_path2 = "\\Login Data" ascii wide
        $s_browser_path3 = "\\Local State" ascii wide
        $s_browser_path4 = "Cookies" ascii wide
        $s_wallet1 = "exodus" ascii wide nocase
        $s_wallet2 = "metamask" ascii wide nocase
        $s_vm_check1 = "vmware" ascii wide nocase
        $s_vm_check2 = "virtualbox" ascii wide nocase
        $s_vm_check3 = "sandbox" ascii wide nocase
        $inject1 = "NtWriteVirtualMemory" ascii
        $inject2 = "explorer.exe" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            (any of ($s_lumma*)) or
            (2 of ($api_*) and 2 of ($s_browser_path*)) or
            (2 of ($s_vm_check*) and $api_getcursorpos and any of ($s_browser_path*)) or
            (all of ($inject*) and 2 of ($s_browser_path*) and any of ($s_vm_check*))
        )
}
