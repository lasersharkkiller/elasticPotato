rule RegPhantom_Kernel_Rootkit {
    meta:
        description = "Detects RegPhantom kernel rootkit - a Windows kernel driver that abuses CmRegisterCallback to intercept registry writes as a covert C2 channel, reflectively loads arbitrary PEs into kernel memory invisible to PsLoadedModuleList. Uses XOR-encrypted 56-byte command payloads, CFG obfuscation with opaque predicates, and valid Chinese code-signing certificates to bypass DSE. China-nexus attribution (moderate confidence). Active development June-August 2025."
        author = "Loaded Potato"
        date = "2026-04-10"
        reference = "https://www.nextron-systems.com/2026/03/20/regphantom-backdoor-threat-analysis/"
        mitre_attack = "T1014, T1553.002, T1112, T1055.001, T1027, T1070.004, T1543.003, T1106"
        malware_family = "RegPhantom"
        hash1 = "006e08f1b8cad821f7849c282dc11d317e76ce66a5bcd84053dd5e7752e0606f"
        hash2 = "703dfb12edc6da592e3dfb951ca2d84bf349e6a16ad3a2ab32b275349956e7c4"

    strings:
        // XOR decrypt loop (from Nextron rule MAL_Kernel_RegPhantom_Mar26)
        $xor_decrypt = {
            48 8b 09        // mov     rcx, [rcx]
            0f b6 14 08     // movzx   edx, byte ptr [rax+rcx]
            4c 31 c2        // xor     rdx, r8
            88 14 08        // mov     [rax+rcx], dl
        }

        // Command selector - checks command_code == 0x77 (load and execute PE)
        $cmd_selector = {
            c6 01 01        // mov     byte ptr [rcx], 1
            48 83 38 77     // cmp     qword ptr [rax], 77h
            0f 94 c0        // setz    al
            24 01           // and     al, 1
        }

        // Kernel API strings used in execution chain
        $api1 = "CmRegisterCallback" ascii fullword
        $api2 = "PsSetCreateThreadNotifyRoutine" ascii fullword
        $api3 = "RtlFindExportedRoutineByName" ascii fullword
        $api4 = "CmUnRegisterCallback" ascii fullword

        // Driver filenames observed across samples
        $fn1 = "MapDriver" ascii wide nocase
        $fn2 = "TestDriver" ascii wide nocase
        $fn3 = "FsFilter" ascii wide nocase
        $fn4 = "DevDriver" ascii wide nocase

        // Code-signing certificate subjects
        $cert1 = "Autel Intelligent Technology" ascii wide
        $cert2 = "Guangzhou Xuanfeng Technology" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 200KB and
        (
            ($xor_decrypt and $cmd_selector) or
            ($api1 and $api2 and ($xor_decrypt or $cmd_selector)) or
            (any of ($cert*) and $api1 and $api2) or
            (2 of ($api*) and any of ($fn*) and ($xor_decrypt or $cmd_selector))
        )
}
