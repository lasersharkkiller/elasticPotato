rule HKTL_PicusSim2026_CheeseDCOM
{
    meta:
        description = "Detects CheeseDCOM lateral movement tool abusing DCOM objects"
        author = "Loaded Potato - Picus Simulation 2026-04-12"
        date = "2026-04-13"
        reference = "https://attack.mitre.org/techniques/T1021/003/"
        score = 90

    strings:
        $name = "CheeseDCOM" ascii wide
        $dcom1 = "MMC20.Application" ascii wide
        $dcom2 = "ShellWindows" ascii wide
        $dcom3 = "ShellBrowserWindow" ascii wide
        $dcom4 = "ExcelDDE" ascii wide
        $dcom5 = "{9BA05972-F6A8-11CF-A442-00A0C90A8F39}" ascii wide
        $net1 = "System.Runtime.InteropServices" ascii wide
        $net2 = "System.Activator" ascii wide
        $method = "CreateInstance" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 500KB and
        (
            $name and 1 of ($dcom*) |
            2 of ($dcom*) and ($net1 or $net2 or $method)
        )
}

rule HKTL_PicusSim2026_CsDCOM
{
    meta:
        description = "Detects CsDCOM C# DCOM lateral movement tool"
        author = "Loaded Potato - Picus Simulation 2026-04-12"
        date = "2026-04-13"
        reference = "https://attack.mitre.org/techniques/T1021/003/"
        score = 90

    strings:
        $name = "CsDCOM" ascii wide
        $dcom1 = "MMC20Application" ascii wide
        $dcom2 = "ShellWindows" ascii wide
        $dcom3 = "ShellBrowserWindow" ascii wide
        $s1 = "ExecuteShellCommand" ascii wide
        $s2 = "Document.ActiveView" ascii wide
        $s3 = "InvokeMethod" ascii wide
        $net = "System.Runtime.InteropServices" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 500KB and
        $name and
        (1 of ($dcom*) or 1 of ($s*))
}
