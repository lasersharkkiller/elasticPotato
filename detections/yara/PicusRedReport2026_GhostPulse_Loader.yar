rule PicusRedReport2026_GhostPulse_Loader {
    meta:
        description = "Detects GhostPulse loader - uses process doppelganging via NTFS transactions to deploy secondary malware (NetSupport, Rhadamanthys, SectopRAT, Vidar). Uses create_transaction, create_section, roll_back_transaction, spawn_suspended_process pattern. Picus Red Report 2026 T1055.013."
        author = "Loaded Potato - Picus Red Report 2026 Analysis"
        date = "2026-04-09"
        reference = "https://www.picussecurity.com/red-report-2026"
        mitre_attack = "T1055.013"
        malware_family = "GhostPulse"

    strings:
        $s_name1 = "GhostPulse" ascii wide nocase
        $s_name2 = "ghostpulse" ascii wide nocase
        $func1 = "create_transaction" ascii
        $func2 = "create_section" ascii
        $func3 = "roll_back" ascii
        $func4 = "spawn_suspended" ascii
        $func5 = "map_view_section" ascii
        $func6 = "set_eip" ascii
        $func7 = "resume_thread" ascii
        $api1 = "NtCreateTransaction" ascii
        $api2 = "NtRollbackTransaction" ascii
        $api3 = "NtCreateSection" ascii
        $api4 = "NtCreateProcessEx" ascii
        $api5 = "CreateFileTransacted" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        (
            any of ($s_name*) or
            (3 of ($func*)) or
            (3 of ($api*))
        )
}
