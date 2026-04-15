rule PicusRedReport2026_ClickFix_PE_Injection {
    meta:
        description = "Detects ClickFix malware - uses PE injection to execute final payload entirely in memory, avoiding dropping detectable EXE on disk. Uses CreateProcessA with CREATE_SUSPENDED, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread pattern. Picus Red Report 2026 T1055.002."
        author = "Loaded Potato - Picus Red Report 2026 Analysis"
        date = "2026-04-09"
        reference = "https://www.picussecurity.com/red-report-2026"
        mitre_attack = "T1055.002"
        malware_family = "ClickFix"

    strings:
        $s_name = "ClickFix" ascii wide nocase
        $api1 = "CreateProcessA" ascii
        $api2 = "VirtualAllocEx" ascii
        $api3 = "WriteProcessMemory" ascii
        $api4 = "CreateRemoteThread" ascii
        $api5 = "WaitForSingleObject" ascii
        $api6 = "TerminateProcess" ascii
        $flag1 = "CREATE_SUSPENDED" ascii wide
        $flag2 = { 04 00 00 00 } // CREATE_SUSPENDED flag value
        $mem1 = "MEM_COMMIT" ascii wide
        $mem2 = "PAGE_EXECUTE_READWRITE" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            $s_name or
            (4 of ($api*) and any of ($flag*))
        )
}
