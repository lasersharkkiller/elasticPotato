rule HKTL_PicusSim2026_RecycleBinPersistence
{
    meta:
        description = "Detects tools that abuse the Recycle Bin CLSID COM handler for persistence by modifying the shell\\open\\command registry key"
        author = "Loaded Potato - Picus Simulation 2026-04-12"
        date = "2026-04-13"
        mitre_attack = "T1546.015"
        score = 85

    strings:
        $clsid = "{645FF040-5081-101B-9F08-00AA002F954E}" ascii wide nocase
        $shell_cmd = "shell\\open\\command" ascii wide nocase
        $recycle1 = "RecycleBin" ascii wide nocase
        $recycle2 = "RecycleBinPersistence" ascii wide nocase

        $reg1 = "RegSetValueEx" ascii wide
        $reg2 = "RegCreateKeyEx" ascii wide
        $reg3 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\CLSID" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            ($clsid and $shell_cmd) or
            ($recycle2) or
            ($clsid and any of ($reg*))
        )
}
