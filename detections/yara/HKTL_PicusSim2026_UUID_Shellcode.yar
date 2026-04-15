rule HKTL_PicusSim2026_UUID_Shellcode_Staging
{
    meta:
        description = "Detects UUID-based shellcode staging tools that convert shellcode to UUID strings and execute via UuidFromStringA + HeapAlloc + EnumSystemLocalesA callback"
        author = "Loaded Potato - Picus Simulation 2026-04-12"
        date = "2026-04-14"
        reference = "https://attack.mitre.org/techniques/T1027/002/"
        mitre_attack = "T1027.002,T1620"
        score = 90

    strings:
        // Tool names
        $tool1 = "UUIDExec" ascii wide
        $tool2 = "goUUID" ascii wide
        $tool3 = "NinjaUUIDDropper" ascii wide
        $tool4 = "ExecScUUID" ascii wide
        $tool5 = "mac2binGo" ascii wide
        $tool6 = "ip2binGo" ascii wide
        $tool7 = "uuid_exec" ascii wide
        $tool8 = "UuidShellcodeExec" ascii wide

        // Core API pattern: UUID string to binary conversion
        $api1 = "UuidFromStringA" ascii wide
        $api2 = "UuidFromStringW" ascii wide
        $api3 = "RpcStringBindingCompose" ascii wide

        // Heap allocation for staging
        $heap1 = "HeapAlloc" ascii wide
        $heap2 = "HeapCreate" ascii wide
        $heap3 = "VirtualAlloc" ascii wide

        // Callback execution trampolines
        $cb1 = "EnumSystemLocalesA" ascii wide
        $cb2 = "EnumSystemLocalesW" ascii wide
        $cb3 = "EnumSystemCodePagesA" ascii wide
        $cb4 = "EnumSystemCodePagesW" ascii wide
        $cb5 = "EnumDateFormatsA" ascii wide
        $cb6 = "EnumTimeFormatsA" ascii wide

        // UUID format pattern (regex-like hex bytes in string)
        $uuid_fmt = "%08x-%04x-%04x" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            any of ($tool*) |
            (($api1 or $api2) and 1 of ($heap*) and 1 of ($cb*)) |
            ($api1 or $api2) and $uuid_fmt and 1 of ($cb*)
        )
}

rule HKTL_PicusSim2026_MAC_IP_Shellcode_Staging
{
    meta:
        description = "Detects MAC/IP address-based shellcode staging tools that encode shellcode as MAC or IPv4/IPv6 addresses"
        author = "Loaded Potato - Picus Simulation 2026-04-12"
        date = "2026-04-14"
        reference = "https://attack.mitre.org/techniques/T1027/002/"
        mitre_attack = "T1027.002,T1620"
        score = 85

    strings:
        $tool1 = "mac2binGo" ascii wide
        $tool2 = "ip2binGo" ascii wide
        $tool3 = "MacShellcode" ascii wide
        $tool4 = "IpShellcode" ascii wide

        // MAC/IP to binary conversion APIs
        $api1 = "RtlEthernetAddressToStringA" ascii wide
        $api2 = "RtlEthernetStringToAddressA" ascii wide
        $api3 = "RtlIpv4AddressToStringA" ascii wide
        $api4 = "RtlIpv4StringToAddressA" ascii wide
        $api5 = "RtlIpv6AddressToStringA" ascii wide
        $api6 = "RtlIpv6StringToAddressA" ascii wide

        $heap = "HeapAlloc" ascii wide
        $cb1 = "EnumSystemLocalesA" ascii wide
        $cb2 = "EnumSystemCodePagesA" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        (
            any of ($tool*) and 1 of ($api*) |
            2 of ($api*) and $heap and 1 of ($cb*)
        )
}
