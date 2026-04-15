rule HKTL_PicusSim2026_TamperETW
{
    meta:
        description = "Detects TamperETW tool that patches ETW functions in ntdll.dll to blind EDR telemetry"
        author = "Loaded Potato - Picus Simulation 2026-04-12"
        date = "2026-04-13"
        reference = "https://attack.mitre.org/techniques/T1562/006/"
        hash = ""
        score = 90

    strings:
        $name1 = "TamperETW" ascii wide
        $name2 = "tamperetw" ascii wide nocase
        $api1 = "EtwEventWrite" ascii wide
        $api2 = "NtTraceEvent" ascii wide
        $api3 = "EtwNotificationRegister" ascii wide
        $patch1 = "WriteProcessMemory" ascii wide
        $patch2 = "VirtualProtect" ascii wide
        $ntdll = "ntdll.dll" ascii wide nocase
        $s1 = "GetProcAddress" ascii wide
        $s2 = "LoadLibrary" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 500KB and
        (
            ($name1 or $name2) and 1 of ($api*) |
            2 of ($api*) and ($patch1 or $patch2) and $ntdll
        )
}

rule HKTL_PicusSim2026_PatchETW_Rust
{
    meta:
        description = "Detects patch_etw_rust Rust-based ETW patching tool"
        author = "Loaded Potato - Picus Simulation 2026-04-12"
        date = "2026-04-13"
        reference = "https://attack.mitre.org/techniques/T1562/006/"
        score = 90

    strings:
        $name = "patch_etw" ascii wide
        $rust1 = "patch_etw_rust" ascii
        $api1 = "EtwEventWrite" ascii wide
        $api2 = "NtTraceEvent" ascii wide
        $ntdll = "ntdll" ascii wide
        $rust_ind1 = ".cargo" ascii
        $rust_ind2 = "rust_begin_unwind" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        ($name or $rust1) and
        1 of ($api*) and
        $ntdll
}

rule HKTL_PicusSim2026_Etwunhook
{
    meta:
        description = "Detects Etwunhook tool that unhooks ETW instrumentation"
        author = "Loaded Potato - Picus Simulation 2026-04-12"
        date = "2026-04-13"
        reference = "https://attack.mitre.org/techniques/T1562/006/"
        score = 90

    strings:
        $name = "Etwunhook" ascii wide nocase
        $api1 = "EtwEventWrite" ascii wide
        $api2 = "NtTraceEvent" ascii wide
        $unhook = "unhook" ascii wide nocase
        $ntdll = "ntdll" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 500KB and
        $name and $ntdll and
        1 of ($api*)
}

rule HKTL_PicusSim2026_SnD_AMSI_ETW
{
    meta:
        description = "Detects SnD_AMSI combined AMSI and ETW bypass tool"
        author = "Loaded Potato - Picus Simulation 2026-04-12"
        date = "2026-04-13"
        reference = "https://attack.mitre.org/techniques/T1562/006/"
        score = 90

    strings:
        $name = "SnD_AMSI" ascii wide
        $amsi1 = "AmsiScanBuffer" ascii wide
        $amsi2 = "amsi.dll" ascii wide nocase
        $etw1 = "EtwEventWrite" ascii wide
        $etw2 = "NtTraceEvent" ascii wide
        $patch = "VirtualProtect" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 500KB and
        (
            $name and ($patch or 1 of ($amsi*) or 1 of ($etw*)) |
            1 of ($amsi*) and 1 of ($etw*) and $patch
        )
}
