rule HKTL_PicusSim2026_ServiceDLL_Hijack
{
    meta:
        description = "Detects tools that create svchost-hosted service DLL persistence by registering malicious ServiceDll entries"
        author = "Loaded Potato - Picus Simulation 2026-04-12"
        date = "2026-04-13"
        reference = "https://attack.mitre.org/techniques/T1543/003/"
        score = 85

    strings:
        $reg1 = "CurrentControlSet\\Services" ascii wide
        $reg2 = "Parameters" ascii wide
        $reg3 = "ServiceDll" ascii wide
        $reg4 = "SvcHost" ascii wide
        $reg5 = "REG_MULTI_SZ" ascii wide
        $svc1 = "MPSEvtMan" ascii wide
        $svc2 = "StorSyncSvc" ascii wide
        $svc3 = "SvcHostDemo" ascii wide
        $api1 = "RegSetValueEx" ascii wide
        $api2 = "CreateService" ascii wide
        $net = "Microsoft.Win32" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 500KB and
        (
            ($reg3 and ($reg1 or $reg2) and ($api1 or $api2 or $net)) |
            1 of ($svc*) and $reg3 |
            ($reg4 and $reg5 and ($api1 or $net))
        )
}
