/*
   EDR Execution Gap Detections — Techniques with Low/No API Hook Coverage
   -----------------------------------------------------------------------
   These rules target execution-capable APIs that have ZERO or BEHAVIORAL-ONLY
   coverage across most EDR products (identified via api_call_matrix.ps1 gap analysis).

   Gap summary (# of 7 EDRs with NO hook, source: api_call_matrix.ps1):
     Timer Callbacks:   5/7 blind  (MDE=-, CB=-, EL=-, XDR=-, TM=-)
     CallWindowProc:    6/7 blind  (S1=-, MDE=-, CB=-, EL=-, XDR=-, TM=-)
     CLR In-Process:    6/7 behav  (CS=B, S1=B, CB=B, EL=B, XDR=B, TM=B)
     Memory Primitives: 7/7 blind  (ALL EDRs = -)
     Heap-Only Staging: 7/7 blind  (ALL EDRs = -)
     DLL Search Order:  5/7 blind  (MDE=-, CB=-, EL=-, XDR=-, TM=-)

   Already covered in MAL_UnhookedExec_CallbackAbuse.yar:
     - EnumSystem*/EnumWindows/CertFind* callback abuse
     - Fiber execution (CreateFiber + SwitchToFiber)
     - Thread pool (CreateThreadpoolWork, QueueUserWorkItem)
     - File-backed section mapping (MapViewOfFile + CreateFileMapping)
     - Multi-technique loader combo

   Author: Loaded Potato / lasersharkkiller
   Date:   2026-04-06
*/

import "pe"

// ---------------------------------------------------------------------------
// TIMER CALLBACK SHELLCODE EXECUTION
// SetWaitableTimer / CreateTimerQueueTimer accept an APC-style callback pointer.
// Shellcode placed in heap or mapped memory is executed when the timer fires
// without any CreateRemoteThread or CreateThread call — those hooks are never hit.
// Gap: MDE=-, CB=-, EL=-, XDR=-, TM=- (5 of 7 EDRs completely blind)
// ---------------------------------------------------------------------------

rule MAL_EDRGap_TimerCallback_MemAlloc {
   meta:
      description = "PE imports waitable timer or timer-queue APIs alongside memory allocation — APC-style shellcode execution that avoids CreateThread hooks"
      author = "Loaded Potato / lasersharkkiller"
      date = "2026-04-06"
      score = 75
      mitre_technique = "T1055"
      edr_gap = "MDE=-, CB=-, EL=-, XDR=-, TM=- (5/7 blind)"
      reference = "https://www.ired.team/offensive-security/code-injection-process-injection"
      id = "a1b2c3d4-e5f6-7890-abcd-111222333444"
   condition:
      uint16(0) == 0x5a4d and filesize < 20MB and
      (
         pe.imports("kernel32.dll", "SetWaitableTimer") or
         pe.imports("kernel32.dll", "SetWaitableTimerEx") or
         pe.imports("kernel32.dll", "CreateTimerQueueTimer") or
         pe.imports("kernel32.dll", "CreateWaitableTimer") or
         pe.imports("kernel32.dll", "CreateWaitableTimerEx") or
         pe.imports("ntdll.dll",    "RtlRegisterWait")
      ) and
      (
         pe.imports("kernel32.dll", "VirtualAlloc") or
         pe.imports("kernel32.dll", "VirtualAllocEx") or
         pe.imports("kernel32.dll", "HeapAlloc") or
         pe.imports("kernel32.dll", "HeapCreate") or
         pe.imports("kernel32.dll", "LocalAlloc")
      ) and
      // Filter legitimate Windows service frameworks (use timer + service registration together)
      not pe.imports("advapi32.dll", "RegisterServiceCtrlHandlerW") and
      // Filter multimedia/audio timer usage (game engines, DAW software)
      not pe.imports("winmm.dll", "timeSetEvent")
}

// ---------------------------------------------------------------------------
// CALLWINDOWPROC SHELLCODE EXECUTION
// CallWindowProcA/W accepts a WNDPROC function pointer — an attacker sets
// this to shellcode. The OS calls it directly with no hook triggered.
// Legitimate uses always subclass windows with SetWindowLong first.
// Gap: S1=-, MDE=-, CB=-, EL=-, XDR=-, TM=- (6 of 7 EDRs completely blind)
// ---------------------------------------------------------------------------

rule MAL_EDRGap_CallWindowProc_Exec {
   meta:
      description = "PE imports CallWindowProc with memory allocation but without SetWindowLong subclassing — shellcode masquerading as a WndProc callback"
      author = "Loaded Potato / lasersharkkiller"
      date = "2026-04-06"
      score = 80
      mitre_technique = "T1055.012"
      edr_gap = "S1=-, MDE=-, CB=-, EL=-, XDR=-, TM=- (6/7 blind)"
      reference = "https://github.com/aahmad097/AlternativeShellcodeExec"
      id = "b2c3d4e5-f6a7-8901-bcde-222333444555"
   condition:
      uint16(0) == 0x5a4d and filesize < 20MB and
      (
         pe.imports("user32.dll", "CallWindowProcA") or
         pe.imports("user32.dll", "CallWindowProcW")
      ) and
      (
         pe.imports("kernel32.dll", "VirtualAlloc") or
         pe.imports("kernel32.dll", "HeapAlloc") or
         pe.imports("kernel32.dll", "LocalAlloc") or
         pe.imports("kernel32.dll", "GlobalAlloc")
      ) and
      // Legitimate CallWindowProc always subclasses the window first
      not (
         pe.imports("user32.dll", "SetWindowLongA")   or
         pe.imports("user32.dll", "SetWindowLongW")   or
         pe.imports("user32.dll", "SetWindowLongPtrA") or
         pe.imports("user32.dll", "SetWindowLongPtrW")
      )
}

// ---------------------------------------------------------------------------
// CLR IN-PROCESS HOSTING (execute-assembly / SharpPick pattern)
// CLRCreateInstance / CorBindToRuntimeEx used to load and run .NET assemblies
// inside a native loader without going through normal .NET startup paths.
// Legitimate .NET hosts import many more mscoree exports and have richer imports.
// Gap: CS=B, S1=B, CB=B, EL=B, XDR=B, TM=B (6/7 behavioral only — no direct hook)
// ---------------------------------------------------------------------------

rule MAL_EDRGap_CLR_InProcess_Hosting {
   meta:
      description = "PE imports CLR hosting APIs (CLRCreateInstance/CorBindToRuntime) with a thin import profile — in-process .NET execution for execute-assembly or SharpPick"
      author = "Loaded Potato / lasersharkkiller"
      date = "2026-04-06"
      score = 75
      mitre_technique = "T1055"
      edr_gap = "CS=B, S1=B, CB=B, EL=B, XDR=B, TM=B (6/7 behavioral only)"
      reference = "https://www.ired.team/offensive-security/code-injection-process-injection/injecting-and-executing-.net-code"
      id = "c3d4e5f6-a7b8-9012-cdef-333444555666"
   condition:
      uint16(0) == 0x5a4d and filesize < 20MB and
      (
         pe.imports("mscoree.dll", "CLRCreateInstance") or
         pe.imports("mscoree.dll", "CorBindToRuntimeEx") or
         pe.imports("mscoree.dll", "CorBindToCurrentRuntime") or
         pe.imports("mscoree.dll", "CorExeMain")
      ) and
      (
         pe.imports("kernel32.dll", "VirtualAlloc") or
         pe.imports("kernel32.dll", "HeapAlloc") or
         pe.imports("kernel32.dll", "LoadLibraryA") or
         pe.imports("kernel32.dll", "LoadLibraryW")
      ) and
      // Legitimate .NET hosts have a richer import table; thin profile = loader/injector
      pe.number_of_imports < 8
}

// ---------------------------------------------------------------------------
// RTLMOVEMEMORY / RTLCOPYMEMORY AS SHELLCODE STAGING PRIMITIVE
// Used instead of WriteProcessMemory (widely hooked) to copy shellcode bytes
// into pre-allocated memory without triggering any hook.
// Combined with VirtualProtect (to flip to RX) but without WriteProcessMemory.
// Gap: ALL 7 EDRs = not monitored at API level
// ---------------------------------------------------------------------------

rule MAL_EDRGap_MemCopy_Staging_NoWriteProcessMemory {
   meta:
      description = "PE imports RtlMoveMemory/RtlCopyMemory with VirtualProtect but without WriteProcessMemory — shellcode copy that bypasses WriteProcessMemory hooks entirely"
      author = "Loaded Potato / lasersharkkiller"
      date = "2026-04-06"
      score = 70
      mitre_technique = "T1620"
      edr_gap = "ALL 7 EDRs = not monitored at API level"
      reference = "https://www.ired.team/offensive-security/defense-evasion/bypassing-windows-defender-using-rtlmovememory"
      id = "d4e5f6a7-b8c9-0123-defa-444555666777"
   condition:
      uint16(0) == 0x5a4d and filesize < 20MB and
      (
         pe.imports("ntdll.dll",    "RtlMoveMemory") or
         pe.imports("kernel32.dll", "RtlMoveMemory") or
         pe.imports("ntdll.dll",    "RtlCopyMemory") or
         pe.imports("kernel32.dll", "RtlCopyMemory")
      ) and
      (
         pe.imports("kernel32.dll", "VirtualAlloc")   or
         pe.imports("kernel32.dll", "VirtualProtect")
      ) and
      // If WriteProcessMemory is present, standard injection already catches it
      not pe.imports("kernel32.dll", "WriteProcessMemory") and
      // Thin import profile distinguishes loaders from general-purpose apps
      pe.number_of_imports < 6
}

// ---------------------------------------------------------------------------
// HEAP-ONLY SHELLCODE STAGING (no VirtualAlloc)
// Allocate shellcode in a private heap via HeapCreate + HeapAlloc, bypassing
// VirtualAlloc hooks entirely. Combined with any unhooked execution primitive.
// Gap: ALL 7 EDRs = not monitored at API level
// ---------------------------------------------------------------------------

rule MAL_EDRGap_HeapOnly_NoVirtualAlloc {
   meta:
      description = "PE uses HeapCreate+HeapAlloc without VirtualAlloc alongside an unhooked execution primitive — shellcode staging that avoids VirtualAlloc hooks"
      author = "Loaded Potato / lasersharkkiller"
      date = "2026-04-06"
      score = 70
      mitre_technique = "T1620"
      edr_gap = "ALL 7 EDRs = not monitored at API level"
      reference = "https://www.ired.team/offensive-security/defense-evasion"
      id = "e5f6a7b8-c9d0-1234-efab-555666777888"
   condition:
      uint16(0) == 0x5a4d and filesize < 20MB and
      pe.imports("kernel32.dll", "HeapCreate") and
      pe.imports("kernel32.dll", "HeapAlloc") and
      // Key discriminator: no VirtualAlloc (unusual for legitimate code)
      not pe.imports("kernel32.dll", "VirtualAlloc") and
      not pe.imports("kernel32.dll", "VirtualAllocEx") and
      // Must have an execution primitive to fire
      (
         pe.imports("kernel32.dll", "CreateThread")           or
         pe.imports("kernel32.dll", "QueueUserWorkItem")      or
         pe.imports("kernel32.dll", "CreateFiber")            or
         pe.imports("kernel32.dll", "SetWaitableTimer")       or
         pe.imports("kernel32.dll", "CreateTimerQueueTimer")  or
         pe.imports("kernel32.dll", "EnumSystemLocalesA")     or
         pe.imports("kernel32.dll", "EnumSystemLocalesW")     or
         pe.imports("user32.dll",   "CallWindowProcA")        or
         pe.imports("user32.dll",   "CallWindowProcW")
      )
}

// ---------------------------------------------------------------------------
// DLL SEARCH ORDER HIJACK SETUP
// SetDllDirectory / AddDllDirectory used to insert an attacker-controlled path
// before the normal Windows DLL search order, then LoadLibrary loads the
// malicious copy. 5 of 7 EDRs do not monitor these APIs.
// Gap: MDE=-, CB=-, EL=-, XDR=-, TM=- (5/7 blind)
// ---------------------------------------------------------------------------

rule MAL_EDRGap_DLL_SearchOrder_Hijack {
   meta:
      description = "PE imports DLL directory manipulation with LoadLibrary but without installer-typical file/registry write patterns — DLL search order hijack for sideloading"
      author = "Loaded Potato / lasersharkkiller"
      date = "2026-04-06"
      score = 65
      mitre_technique = "T1574.001"
      edr_gap = "MDE=-, CB=-, EL=-, XDR=-, TM=- (5/7 blind)"
      reference = "https://attack.mitre.org/techniques/T1574/001/"
      id = "f6a7b8c9-d0e1-2345-fabc-666777888999"
   condition:
      uint16(0) == 0x5a4d and filesize < 20MB and
      (
         pe.imports("kernel32.dll", "SetDllDirectoryA") or
         pe.imports("kernel32.dll", "SetDllDirectoryW") or
         pe.imports("kernel32.dll", "AddDllDirectory")
      ) and
      (
         pe.imports("kernel32.dll", "LoadLibraryA")   or
         pe.imports("kernel32.dll", "LoadLibraryW")   or
         pe.imports("kernel32.dll", "LoadLibraryExA") or
         pe.imports("kernel32.dll", "LoadLibraryExW")
      ) and
      // Legitimate installers pair DLL directory changes with file writes and registry edits
      not (
         pe.imports("kernel32.dll", "WriteFile") and
         pe.imports("advapi32.dll", "RegSetValueExW")
      )
}

// ---------------------------------------------------------------------------
// HIGH-CONFIDENCE COMBINATION: HEAP-ONLY ALLOC + UNHOOKED TIMER/CALLBACK
// Avoids BOTH VirtualAlloc hooks (memory tier) AND CreateThread hooks (exec tier).
// This combination has extremely limited EDR visibility across all vendors.
// Gap: ALL 7 EDRs have limited or no visibility on this combination
// ---------------------------------------------------------------------------

rule MAL_EDRGap_HeapStaging_UnhookedExec_Combo {
   meta:
      description = "PE combines heap-only allocation (no VirtualAlloc) with an unhooked execution path — evades both memory allocation hooks and thread creation hooks simultaneously"
      author = "Loaded Potato / lasersharkkiller"
      date = "2026-04-06"
      score = 90
      mitre_technique = "T1055.012"
      edr_gap = "ALL 7 EDRs have limited or no visibility on this combination"
      reference = "https://github.com/aahmad097/AlternativeShellcodeExec"
      id = "a7b8c9d0-e1f2-3456-abcd-777888999000"
   condition:
      uint16(0) == 0x5a4d and filesize < 20MB and
      // Heap-only staging (no VirtualAlloc hook to trigger)
      (
         pe.imports("kernel32.dll", "HeapCreate") or
         pe.imports("kernel32.dll", "HeapAlloc")  or
         pe.imports("kernel32.dll", "LocalAlloc") or
         pe.imports("kernel32.dll", "GlobalAlloc")
      ) and
      not pe.imports("kernel32.dll", "VirtualAlloc") and
      // Unhooked execution primitive (no CreateRemoteThread hook to trigger)
      (
         pe.imports("kernel32.dll", "SetWaitableTimer")      or
         pe.imports("kernel32.dll", "CreateTimerQueueTimer") or
         pe.imports("user32.dll",   "CallWindowProcA")       or
         pe.imports("user32.dll",   "CallWindowProcW")       or
         pe.imports("kernel32.dll", "CreateFiber")           or
         pe.imports("kernel32.dll", "EnumSystemLocalesA")    or
         pe.imports("kernel32.dll", "EnumSystemLocalesW")    or
         pe.imports("kernel32.dll", "EnumSystemLanguageGroupsA") or
         pe.imports("kernel32.dll", "EnumSystemLanguageGroupsW")
      )
}
