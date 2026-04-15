rule PicusRedReport2026_BPFDoor_Linux {
    meta:
        description = "Detects BPFDoor Linux backdoor - uses Berkeley Packet Filter for covert C2 channel, avoids opening listening ports. Associated with Gold Melody and attributed under T1036 Masquerading in Picus Red Report 2026. Multiple variants observed."
        author = "Loaded Potato - Picus Red Report 2026 Analysis"
        date = "2026-04-09"
        reference = "https://www.picussecurity.com/red-report-2026"
        mitre_attack = "T1036, T1071"
        malware_family = "BPFDoor"

    strings:
        $s_name = "BPFDoor" ascii wide nocase
        $s_bpf1 = "bpf" ascii
        $s_bpf2 = "BPF_PROG" ascii
        $s_bpf3 = "setsockopt" ascii
        $s_bpf4 = "SO_ATTACH_FILTER" ascii
        $s_bpf5 = "AF_PACKET" ascii
        $magic1 = { 21 31 } // BPFDoor magic bytes pattern
        $shell1 = "/bin/sh" ascii
        $shell2 = "/bin/bash" ascii
        $proc1 = "/proc/self/exe" ascii
        $masq1 = "[kworker" ascii
        $masq2 = "avahi-daemon" ascii
        $masq3 = "dbus-daemon" ascii

    condition:
        (uint32(0) == 0x464C457F) and  // ELF magic
        filesize < 5MB and
        (
            $s_name or
            (2 of ($s_bpf*) and any of ($shell*)) or
            (any of ($s_bpf*) and any of ($masq*) and any of ($shell*))
        )
}
