rule PicusRedReport2026_TinkyWinkey_Keylogger {
    meta:
        description = "Detects Tinky Winkey keylogger - uses DLL injection into legitimate Windows processes via CreateRemoteThread+LoadLibrary, records keystrokes and steals data while hidden. Delivered through malicious installers and trojanized apps. Picus Red Report 2026 T1055.001."
        author = "Loaded Potato - Picus Red Report 2026 Analysis"
        date = "2026-04-09"
        reference = "https://www.picussecurity.com/red-report-2026"
        mitre_attack = "T1055.001, T1056.001"
        malware_family = "TinkyWinkey"

    strings:
        $s_name1 = "TinkyWinkey" ascii wide nocase
        $s_name2 = "Tinky Winkey" ascii wide nocase
        $api1 = "CreateRemoteThread" ascii
        $api2 = "LoadLibraryW" ascii
        $api3 = "VirtualAllocEx" ascii
        $api4 = "WriteProcessMemory" ascii
        $api5 = "OpenProcess" ascii
        $api6 = "SetWindowsHookEx" ascii
        $keylog1 = "GetAsyncKeyState" ascii
        $keylog2 = "GetKeyState" ascii
        $keylog3 = "keylog" ascii wide nocase
        $keylog4 = "keystroke" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            any of ($s_name*) or
            (3 of ($api*) and any of ($keylog*))
        )
}
