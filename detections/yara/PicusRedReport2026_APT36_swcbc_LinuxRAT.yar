rule PicusRedReport2026_APT36_swcbc_LinuxRAT {
    meta:
        description = "Detects swcbc Linux RAT used by APT36 (Transparent Tribe). Python-based RAT compiled into 64-bit ELF via PyInstaller. Targets Indian government BOSS Linux systems. Persists via systemd user service. Picus Red Report 2026 T1059.006."
        author = "Loaded Potato - Picus Red Report 2026 Analysis"
        date = "2026-04-09"
        reference = "https://www.picussecurity.com/red-report-2026"
        mitre_attack = "T1059.006, T1547"
        malware_family = "swcbc"
        threat_actor = "APT36"

    strings:
        $s_name = "swcbc" ascii wide
        $pyinstaller1 = "pyiboot" ascii
        $pyinstaller2 = "PyInstaller" ascii
        $pyinstaller3 = "_MEIPASS" ascii
        $systemd1 = "systemd/user/" ascii
        $systemd2 = ".service" ascii
        $systemd3 = "daemon-reload" ascii
        $systemd4 = "WantedBy=default.target" ascii
        $service_content = "Restart=always" ascii
        $c2_1 = "socket" ascii
        $c2_2 = "subprocess" ascii
        $c2_3 = "platform" ascii

    condition:
        (uint32(0) == 0x464C457F) and  // ELF magic
        filesize < 50MB and
        (
            ($s_name and any of ($pyinstaller*)) or
            ($s_name and any of ($systemd*)) or
            (2 of ($pyinstaller*) and 2 of ($systemd*) and any of ($c2_*))
        )
}
