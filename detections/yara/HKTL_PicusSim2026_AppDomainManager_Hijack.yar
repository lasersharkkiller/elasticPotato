rule HKTL_PicusSim2026_AppDomainManager_Hijack
{
    meta:
        description = "Detects DLLs designed for .NET AppDomainManager hijacking - malicious assemblies that override CLR initialization to achieve code execution in any .NET process"
        author = "Loaded Potato - Picus Simulation 2026-04-12"
        date = "2026-04-13"
        mitre_attack = "T1574.014"
        score = 80

    strings:
        $s1 = "AppDomainManager" ascii wide
        $s2 = "InitializeNewDomain" ascii wide
        $s3 = "DomainManager" ascii wide
        $s4 = "APPDOMAIN_MANAGER_ASM" ascii wide
        $s5 = "APPDOMAIN_MANAGER_TYPE" ascii wide
        $s6 = "AppDomainInitializer" ascii wide

        $net1 = "System.AppDomainManager" ascii
        $net2 = "System.Runtime" ascii
        $net3 = "_CorDllMain" ascii

    condition:
        filesize < 2MB and
        (
            ($s4 and $s5) or
            ($s1 and $s2 and any of ($net*)) or
            ($s3 and $s2 and $net3) or
            (2 of ($s1, $s2, $s6) and $net1)
        )
}
