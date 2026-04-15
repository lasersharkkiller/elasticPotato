rule PicusRedReport2026_NodeInitRAT {
    meta:
        description = "Detects NodeInitRAT - Node.js-based RAT delivered by Mocha Manakin via paste-and-run PowerShell. Establishes persistence via Registry Run key disguised as ChromeUpdater, executing through legitimate node.exe with .log extension payload. Picus Red Report 2026 T1059."
        author = "Loaded Potato - Picus Red Report 2026 Analysis"
        date = "2026-04-09"
        reference = "https://www.picussecurity.com/red-report-2026"
        mitre_attack = "T1059.007, T1547.001"
        malware_family = "NodeInitRAT"

    strings:
        $s_name = "NodeInitRAT" ascii wide nocase
        $s_nodeinit = "nodeinit" ascii wide nocase
        $node1 = "node-v" ascii wide
        $node2 = "node.exe" ascii wide
        $persistence1 = "ChromeUpdater" ascii wide
        $persistence2 = "CurrentVersion\\Run" ascii wide
        $log_ext = ".log" ascii wide
        $net1 = "require('net')" ascii
        $net2 = "require('http')" ascii
        $net3 = "require('child_process')" ascii
        $net4 = "require('os')" ascii

    condition:
        filesize < 15MB and
        (
            any of ($s_name, $s_nodeinit) or
            (any of ($node*) and $persistence1 and $persistence2) or
            (2 of ($net*) and any of ($node*))
        )
}
