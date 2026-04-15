rule PicusRedReport2026_AutoColor_Linux_Backdoor {
    meta:
        description = "Detects Auto-Color Linux backdoor - uses masquerading (T1036) to disguise as legitimate system processes. Associated with targeted attacks. Picus Red Report 2026."
        author = "Loaded Potato - Picus Red Report 2026 Analysis"
        date = "2026-04-09"
        reference = "https://www.picussecurity.com/red-report-2026"
        mitre_attack = "T1036"
        malware_family = "Auto-Color"

    strings:
        $s_name1 = "Auto-Color" ascii wide nocase
        $s_name2 = "autocolor" ascii wide nocase
        $masq1 = "[kworker/" ascii
        $masq2 = "[migration/" ascii
        $masq3 = "dbus-daemon" ascii
        $ld_preload = "LD_PRELOAD" ascii
        $proc1 = "/proc/self" ascii
        $proc2 = "/proc/net" ascii
        $shell1 = "/bin/sh" ascii
        $shell2 = "/bin/bash" ascii
        $hide1 = "unlink" ascii
        $hide2 = "memfd_create" ascii

    condition:
        (uint32(0) == 0x464C457F) and  // ELF magic
        filesize < 5MB and
        (
            any of ($s_name*) or
            (any of ($masq*) and $ld_preload and any of ($shell*)) or
            ($hide2 and any of ($masq*) and any of ($proc*))
        )
}
