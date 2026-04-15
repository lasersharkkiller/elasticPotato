rule PicusRedReport2026_ShadowVector_HookInjection {
    meta:
        description = "Detects Shadow Vector malware - sets Windows input hooks using SetWindowsHookEx with WH_KEYBOARD_LL to capture keystrokes via hooking injection while remaining hidden through in-memory execution. Picus Red Report 2026 T1055.001, T1056.001."
        author = "Loaded Potato - Picus Red Report 2026 Analysis"
        date = "2026-04-09"
        reference = "https://www.picussecurity.com/red-report-2026"
        mitre_attack = "T1055.001, T1056.001"
        malware_family = "ShadowVector"

    strings:
        $s_name = "ShadowVector" ascii wide nocase
        $s_shadow = "Shadow Vector" ascii wide nocase
        $api1 = "SetWindowsHookEx" ascii wide
        $api2 = "GetModuleHandle" ascii wide
        $api3 = "WH_KEYBOARD_LL" ascii wide
        $api4 = "WHKEYBOARDLL" ascii wide
        $api5 = "LowLevelKeyboardProc" ascii wide
        $api6 = "GetCurrentProcess" ascii wide
        $lime1 = "LimeLogger" ascii wide
        $lime2 = "Lime.Logger" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            any of ($s_name, $s_shadow) or
            any of ($lime*) or
            ($api1 and ($api3 or $api4) and $api5)
        )
}
