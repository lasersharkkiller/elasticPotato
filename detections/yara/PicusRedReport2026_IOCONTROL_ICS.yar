rule PicusRedReport2026_IOCONTROL_ICS {
    meta:
        description = "Detects IOCONTROL malware - used by Cyber Av3ngers (Iran-linked) targeting ICS/OT environments via Application Layer Protocol (T1071). Communicates through standard protocols to blend with normal industrial network traffic. Picus Red Report 2026."
        author = "Loaded Potato - Picus Red Report 2026 Analysis"
        date = "2026-04-09"
        reference = "https://www.picussecurity.com/red-report-2026"
        mitre_attack = "T1071"
        malware_family = "IOCONTROL"

    strings:
        $s_name1 = "IOCONTROL" ascii wide nocase
        $s_name2 = "iocontrol" ascii
        $modbus1 = "modbus" ascii wide nocase
        $modbus2 = { 00 01 00 00 00 06 } // Modbus TCP header
        $plc1 = "PLC" ascii wide
        $plc2 = "SCADA" ascii wide
        $plc3 = "HMI" ascii wide
        $net1 = "socket" ascii
        $net2 = "connect" ascii
        $net3 = "recv" ascii
        $net4 = "send" ascii

    condition:
        filesize < 10MB and
        (
            any of ($s_name*) or
            (any of ($modbus*) and 2 of ($net*) and any of ($plc*))
        )
}
