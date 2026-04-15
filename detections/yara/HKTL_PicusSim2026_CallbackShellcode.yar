rule HKTL_PicusSim2026_CallbackShellcodeExec
{
    meta:
        description = "Detects Windows API callback-based shellcode execution tools that abuse legitimate API callbacks to run shellcode without CreateThread/CreateRemoteThread"
        author = "Loaded Potato - Picus Simulation 2026-04-12"
        date = "2026-04-13"
        reference = "https://attack.mitre.org/techniques/T1106/"
        score = 85

    strings:
        $cb1 = "EnumWindows" ascii wide
        $cb2 = "EnumFontFamiliesExW" ascii wide
        $cb3 = "CertEnumSystemStoreLocation" ascii wide
        $cb4 = "CryptEnumOIDInfo" ascii wide
        $cb5 = "CreateThreadPoolWait" ascii wide
        $cb6 = "FlsAlloc" ascii wide
        $cb7 = "EnumSystemGeoID" ascii wide
        $cb8 = "EnumTimeFormatsEx" ascii wide
        $cb9 = "EnumUILanguagesW" ascii wide
        $cb10 = "InitOnceExecuteOnce" ascii wide
        $cb11 = "ImmEnumInputContext" ascii wide
        $cb12 = "SymFindFileInPath" ascii wide
        $cb13 = "VerifierEnumerateResource" ascii wide
        $cb14 = "SetTimer" ascii wide
        $cb15 = "EnumDesktopWindows" ascii wide

        $sc1 = "VirtualAlloc" ascii wide
        $sc2 = "VirtualProtect" ascii wide
        $sc3 = "RtlMoveMemory" ascii wide
        $sc4 = { FC 48 83 E4 F0 }
        $sc5 = "shellcode" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 500KB and
        2 of ($cb*) and 1 of ($sc*)
}

rule HKTL_PicusSim2026_CBT_ShellcodeRunner
{
    meta:
        description = "Detects CBT_ prefixed callback-based shellcode runner tools from Picus simulation"
        author = "Loaded Potato - Picus Simulation 2026-04-12"
        date = "2026-04-13"
        reference = "https://attack.mitre.org/techniques/T1106/"
        score = 85

    strings:
        $prefix = "CBT_" ascii wide
        $sc1 = "VirtualAlloc" ascii wide
        $sc2 = "VirtualProtect" ascii wide
        $sc3 = "RtlMoveMemory" ascii wide
        $cb1 = "CallbackFunction" ascii wide
        $cb2 = "SetWindowsHookEx" ascii wide
        $cb3 = "HCBT" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 500KB and
        $prefix and
        1 of ($sc*) and
        1 of ($cb*)
}
