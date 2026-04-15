rule HKTL_PicusSim2026_SharpEventPersist
{
    meta:
        description = "Detects SharpEventPersist tool that stores shellcode payloads inside Windows Event Log entries for fileless persistence"
        author = "Loaded Potato - Picus Simulation 2026-04-12"
        date = "2026-04-13"
        reference = "https://attack.mitre.org/techniques/T1546/"
        score = 90

    strings:
        $name1 = "SharpEventPersist" ascii wide
        $name2 = "EventPersist" ascii wide
        $api1 = "EventLog" ascii wide
        $api2 = "WriteEvent" ascii wide
        $api3 = "EventWrite" ascii wide
        $s1 = "shellcode" ascii wide nocase
        $s2 = "payload" ascii wide nocase
        $s3 = "EventData" ascii wide
        $net1 = "System.Diagnostics.Eventing" ascii wide
        $net2 = "System.Diagnostics.EventLog" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 500KB and
        ($name1 or $name2) and
        (1 of ($api*) or 1 of ($net*))
}

rule HKTL_PicusSim2026_SharpEventLoader
{
    meta:
        description = "Detects SharpEventLoader that retrieves and executes shellcode stored in Windows Event Log entries"
        author = "Loaded Potato - Picus Simulation 2026-04-12"
        date = "2026-04-13"
        reference = "https://attack.mitre.org/techniques/T1546/"
        score = 90

    strings:
        $name1 = "SharpEventLoader" ascii wide
        $name2 = "EventLoader" ascii wide
        $api1 = "EventLog" ascii wide
        $api2 = "ReadEvent" ascii wide
        $api3 = "EventRecord" ascii wide
        $exec1 = "VirtualAlloc" ascii wide
        $exec2 = "CreateThread" ascii wide
        $exec3 = "Marshal.Copy" ascii wide
        $exec4 = "RtlMoveMemory" ascii wide
        $net1 = "System.Diagnostics.Eventing" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 500KB and
        ($name1 or $name2) and
        1 of ($api*) and
        1 of ($exec*)
}
