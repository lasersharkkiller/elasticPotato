rule HKTL_PicusSim2026_WiretapKey_Keylogger
{
    meta:
        description = "Detects WiretapKey keylogger and similar GetAsyncKeyState-based keylogging tools observed in Picus simulation"
        author = "Loaded Potato - Picus Simulation 2026-04-12"
        date = "2026-04-13"
        mitre_attack = "T1056.001"
        score = 85

    strings:
        $name1 = "WiretapKey" ascii wide nocase
        $name2 = "getasynckeystate" ascii wide nocase
        $name3 = "capture_keystrokes" ascii wide nocase

        $api1 = "GetAsyncKeyState" ascii wide
        $api2 = "GetKeyState" ascii wide
        $api3 = "SetWindowsHookEx" ascii wide
        $api4 = "GetForegroundWindow" ascii wide
        $api5 = "GetWindowText" ascii wide

        $log1 = "keylog" ascii wide nocase
        $log2 = "keystroke" ascii wide nocase
        $log3 = "keypress" ascii wide nocase
        $log4 = "[ENTER]" ascii wide
        $log5 = "[BACKSPACE]" ascii wide
        $log6 = "[TAB]" ascii wide
        $log7 = "[SHIFT]" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            any of ($name*) or
            (2 of ($api*) and 2 of ($log*)) or
            ($api1 and $api4 and $api5 and any of ($log*))
        )
}
