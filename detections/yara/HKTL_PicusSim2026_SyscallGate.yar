rule HKTL_PicusSim2026_HellsGate
{
    meta:
        description = "Detects Hell's Gate technique - dynamically resolves syscall numbers from ntdll to execute direct syscalls, bypassing EDR userland hooks"
        author = "Loaded Potato - Picus Simulation 2026-04-12"
        date = "2026-04-14"
        reference = "https://attack.mitre.org/techniques/T1106/"
        mitre_attack = "T1106,T1562.001"
        score = 90

    strings:
        $name1 = "HellsGate" ascii wide nocase
        $name2 = "Hells_Gate" ascii wide
        $name3 = "hells-gate" ascii wide

        // Syscall stub pattern: mov r10, rcx; mov eax, <syscall_num>; syscall
        $stub = { 4C 8B D1 B8 ?? ?? 00 00 0F 05 C3 }

        // Gate resolution strings
        $s1 = "VX_TABLE" ascii wide
        $s2 = "VX_TABLE_ENTRY" ascii wide
        $s3 = "GetVxTableEntry" ascii wide
        $s4 = "HellGate" ascii wide
        $s5 = "HellDescent" ascii wide
        $s6 = "GetSSN" ascii wide

        // NtAPI targets
        $nt1 = "NtAllocateVirtualMemory" ascii wide
        $nt2 = "NtProtectVirtualMemory" ascii wide
        $nt3 = "NtCreateThreadEx" ascii wide
        $nt4 = "NtWriteVirtualMemory" ascii wide
        $nt5 = "NtCreateSection" ascii wide
        $nt6 = "NtMapViewOfSection" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            any of ($name*) and (1 of ($nt*) or $stub) |
            2 of ($s*) and 1 of ($nt*) |
            $stub and 3 of ($nt*) and 1 of ($s*)
        )
}

rule HKTL_PicusSim2026_TartarusGate
{
    meta:
        description = "Detects Tartarus' Gate - evolution of Hell's Gate that handles hooked ntdll by searching neighboring syscall stubs for clean SSNs"
        author = "Loaded Potato - Picus Simulation 2026-04-12"
        date = "2026-04-14"
        reference = "https://attack.mitre.org/techniques/T1106/"
        mitre_attack = "T1106,T1562.001"
        score = 90

    strings:
        $name1 = "TartarusGate" ascii wide nocase
        $name2 = "Tartarus_Gate" ascii wide
        $name3 = "tartarus" ascii wide

        // Hooked stub detection: look for jmp (E9) at syscall entry
        $hook_check = { 0F B6 ?? E9 }  // movzx + check for jmp opcode

        $s1 = "GetSSN" ascii wide
        $s2 = "VX_TABLE" ascii wide
        $s3 = "Halos" ascii wide  // Halo's Gate variant indicator
        $s4 = "HalosGate" ascii wide

        $nt1 = "NtAllocateVirtualMemory" ascii wide
        $nt2 = "NtProtectVirtualMemory" ascii wide
        $nt3 = "NtCreateThreadEx" ascii wide
        $nt4 = "NtWriteVirtualMemory" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            ($name1 or $name2) and 1 of ($nt*) |
            ($name3 or $s3 or $s4) and 2 of ($nt*) and ($s1 or $s2) |
            $hook_check and $s1 and 2 of ($nt*)
        )
}

rule HKTL_PicusSim2026_ParallelSyscalls
{
    meta:
        description = "Detects Parallel Syscalls technique - maps a second clean copy of ntdll from disk to resolve unhooked syscall stubs"
        author = "Loaded Potato - Picus Simulation 2026-04-12"
        date = "2026-04-14"
        reference = "https://attack.mitre.org/techniques/T1106/"
        mitre_attack = "T1106,T1562.001"
        score = 90

    strings:
        $name1 = "ParallelSyscalls" ascii wide
        $name2 = "parallel_syscall" ascii wide nocase
        $name3 = "SyscallTrampoline" ascii wide

        // Technique: remap ntdll from disk
        $s1 = "\\KnownDlls\\ntdll.dll" ascii wide
        $s2 = "NtOpenSection" ascii wide
        $s3 = "NtMapViewOfSection" ascii wide
        $s4 = "NtCreateSection" ascii wide

        // Trampoline / indirect syscall pattern
        $s5 = "syscall_trampoline" ascii wide
        $s6 = "indirect_syscall" ascii wide
        $s7 = "SyscallPrepare" ascii wide

        // Clean ntdll mapping strings
        $s8 = "ntdll_copy" ascii wide
        $s9 = "fresh_ntdll" ascii wide
        $s10 = "clean_ntdll" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            any of ($name*) and (1 of ($s1, $s2, $s3, $s4) or 1 of ($s5, $s6, $s7)) |
            $s1 and ($s3 or $s4) and 1 of ($s5, $s6, $s7) |
            2 of ($s2, $s3, $s4) and any of ($s8, $s9, $s10)
        )
}

rule HKTL_PicusSim2026_SyscallUnhooking_Generic
{
    meta:
        description = "Detects generic syscall-based EDR unhooking tools that restore original ntdll bytes or use direct/indirect syscalls to bypass hooks"
        author = "Loaded Potato - Picus Simulation 2026-04-12"
        date = "2026-04-14"
        reference = "https://attack.mitre.org/techniques/T1562/001/"
        mitre_attack = "T1106,T1562.001"
        score = 85

    strings:
        // Tool names from Picus simulation
        $tool1 = "NtdllUnhooker" ascii wide
        $tool2 = "NtdllPipe" ascii wide
        $tool3 = "SuspendedUnhook" ascii wide
        $tool4 = "RefleXXion" ascii wide
        $tool5 = "VehApiResolve" ascii wide
        $tool6 = "SyscallNumberExtractor" ascii wide
        $tool7 = "SharpCall" ascii wide
        $tool8 = "NimGetSyscallStub" ascii wide
        $tool9 = "DInvokeLazyImport" ascii wide
        $tool10 = "PerunsFart" ascii wide
        $tool11 = "dogePerunsFart" ascii wide
        $tool12 = "GolangInSharp" ascii wide
        $tool13 = "EDR-Freeze" ascii wide
        $tool14 = "Evasor" ascii wide

        // Common unhooking technique strings
        $unhook1 = "unhook" ascii wide nocase
        $unhook2 = "Unhook_NativeAPI" ascii wide
        $unhook3 = "UnhookNtdll" ascii wide
        $unhook4 = "restore_ntdll" ascii wide

        // Syscall resolution
        $ssn1 = "GetSyscallNumber" ascii wide
        $ssn2 = "GetSSN" ascii wide
        $ssn3 = "SyscallStub" ascii wide
        $ssn4 = "syscall_number" ascii wide

        $ntdll = "ntdll" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            any of ($tool*) |
            2 of ($unhook*) and $ntdll |
            1 of ($unhook*) and 1 of ($ssn*) and $ntdll
        )
}
