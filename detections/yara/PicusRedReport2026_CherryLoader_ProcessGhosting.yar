rule PicusRedReport2026_CherryLoader_ProcessGhosting {
    meta:
        description = "Detects CherryLoader malware - uses process ghosting technique with delete-pending file execution. Creates file with DELETE flag, sets FILE_DISPOSITION_INFORMATION, writes decrypted malware, creates image section via NtCreateSection, then NtCreateProcess from mapped section. Picus Red Report 2026 T1055."
        author = "Loaded Potato - Picus Red Report 2026 Analysis"
        date = "2026-04-09"
        reference = "https://www.picussecurity.com/red-report-2026"
        mitre_attack = "T1055.012"
        malware_family = "CherryLoader"

    strings:
        $s_name = "CherryLoader" ascii wide nocase
        $api1 = "NtSetInformationFile" ascii
        $api2 = "NtCreateSection" ascii
        $api3 = "NtCreateProcess" ascii
        $api4 = "CreateFileMappingA" ascii
        $api5 = "MapViewOfFile" ascii
        $api6 = "RtlCreateProcessParameters" ascii
        $api7 = "NtCreateThreadEx" ascii
        $api8 = "CreateEnvironmentBlock" ascii
        $s_delete_pending = "DeleteFile" ascii
        $s_ghost1 = "ghosting" ascii wide nocase
        $s_ghost2 = "delete-pending" ascii wide nocase
        $s_success = "Success - Thread ID" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            $s_name or
            (4 of ($api*) and ($s_delete_pending or $s_success)) or
            (5 of ($api*))
        )
}
