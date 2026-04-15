/*
   Comprehensive Unhooked Execution Technique Coverage
   -----------------------------------------------------------------------
   One YARA rule per technique group covering EVERY unhooked-exec API
   identified in api_call_matrix.ps1 (EDR Evasion & Gap Matrix).

   Technique groups mirror the matrix:
     1.  Callback Abuse          (EnumSystem*, EnumWindows*, CertFind*, CryptEnum*)
     2.  Fiber Execution         (CreateFiber, SwitchToFiber)
     3.  Thread Pool             (QueueUserWorkItem, CreateThreadpoolWork/Timer/Wait)
     4.  Timer Callbacks         (SetTimer, SetWaitableTimer, CreateTimerQueueTimer)
     5.  Window Proc / Message   (CallWindowProc, SendMessage, PostMessage, DispatchMessage)
     6.  File-Backed Mapping     (MapViewOfFile, CreateFileMapping)
     7.  COM / CLR Hosting       (CLRCreateInstance, CorBindToRuntime)
     8.  Memory Copy Primitives  (RtlMoveMemory, RtlCopyMemory, RtlZeroMemory)
     9.  Heap Staging            (HeapCreate, HeapAlloc, GlobalAlloc, LocalAlloc)
    10.  DLL Load Indirect       (SetDllDirectory, AddDllDirectory, LoadPackagedLibrary)
    11.  Direct Thread           (CreateThread local, RtlCreateThread)
    12.  Multi-Technique Combos  (high-confidence loader signatures)

   Cross-reference: more targeted rules for each group also exist in:
     MAL_UnhookedExec_CallbackAbuse.yar  (callback, fiber, thread pool, file mapping)
     MAL_EDRGap_ExecutionGaps.yar        (timer, callwindowproc, CLR, memcopy, heap, DLL)

   Author: Loaded Potato / lasersharkkiller
   Date:   2026-04-06
*/

import "pe"

// ===========================================================================
// GROUP 1 — CALLBACK ABUSE
// Enumeration APIs accept a function pointer which the OS calls directly.
// EDRs do not hook the enumerator itself — only the allocation that fills it.
// ===========================================================================

rule MAL_AllUH_CallbackAbuse_EnumLocale_Lang {
   meta:
      description = "PE imports locale/language enumeration callbacks alongside memory allocation — highest-confidence callback shellcode execution (score=100 in APIDifferential)"
      author = "Loaded Potato / lasersharkkiller"
      date = "2026-04-06"
      score = 85
      mitre_technique = "T1055.012"
      edr_gap = "MDE=-, CB=-, EL=-, XDR=-, TM=- (5/7 blind)"
      id = "10000001-0000-0000-0000-000000000001"
   condition:
      uint16(0) == 0x5a4d and filesize < 20MB and
      (
         pe.imports("kernel32.dll", "EnumSystemLanguageGroupsA") or
         pe.imports("kernel32.dll", "EnumSystemLanguageGroupsW") or
         pe.imports("kernel32.dll", "EnumSystemLocalesA")        or
         pe.imports("kernel32.dll", "EnumSystemLocalesW")        or
         pe.imports("kernel32.dll", "EnumUILanguagesA")          or
         pe.imports("kernel32.dll", "EnumUILanguagesW")
      ) and
      (
         pe.imports("kernel32.dll", "VirtualAlloc")   or
         pe.imports("kernel32.dll", "VirtualAllocEx") or
         pe.imports("kernel32.dll", "HeapAlloc")      or
         pe.imports("kernel32.dll", "HeapCreate")     or
         pe.imports("kernel32.dll", "LocalAlloc")     or
         pe.imports("kernel32.dll", "GlobalAlloc")
      )
}

rule MAL_AllUH_CallbackAbuse_EnumWindows {
   meta:
      description = "PE imports window/desktop/thread enumeration callback without typical GUI management imports — shellcode via window enumeration callback"
      author = "Loaded Potato / lasersharkkiller"
      date = "2026-04-06"
      score = 70
      mitre_technique = "T1055.012"
      edr_gap = "MDE=-, CB=-, EL=-, XDR=-, TM=- (5/7 blind)"
      id = "10000001-0000-0000-0000-000000000002"
   condition:
      uint16(0) == 0x5a4d and filesize < 20MB and
      (
         pe.imports("user32.dll", "EnumWindows")        or
         pe.imports("user32.dll", "EnumChildWindows")   or
         pe.imports("user32.dll", "EnumDesktopWindows") or
         pe.imports("user32.dll", "EnumThreadWindows")
      ) and
      (
         pe.imports("kernel32.dll", "VirtualAlloc") or
         pe.imports("kernel32.dll", "HeapAlloc")    or
         pe.imports("kernel32.dll", "LocalAlloc")
      ) and
      not (
         pe.imports("user32.dll", "SetWindowTextA")   or
         pe.imports("user32.dll", "SetWindowTextW")   or
         pe.imports("user32.dll", "GetWindowTextA")   or
         pe.imports("user32.dll", "GetWindowTextW")   or
         pe.imports("user32.dll", "ShowWindow")       or
         pe.imports("user32.dll", "CreateWindowExA")  or
         pe.imports("user32.dll", "CreateWindowExW")
      )
}

rule MAL_AllUH_CallbackAbuse_EnumResource {
   meta:
      description = "PE imports resource enumeration callbacks alongside memory allocation — shellcode via resource enumeration (EnumResourceTypes/Names/Languages)"
      author = "Loaded Potato / lasersharkkiller"
      date = "2026-04-06"
      score = 75
      mitre_technique = "T1055.012"
      edr_gap = "MDE=-, CB=-, EL=-, XDR=-, TM=- (5/7 blind)"
      id = "10000001-0000-0000-0000-000000000003"
   condition:
      uint16(0) == 0x5a4d and filesize < 20MB and
      (
         pe.imports("kernel32.dll", "EnumResourceTypesA")     or
         pe.imports("kernel32.dll", "EnumResourceTypesW")     or
         pe.imports("kernel32.dll", "EnumResourceNamesA")     or
         pe.imports("kernel32.dll", "EnumResourceNamesW")     or
         pe.imports("kernel32.dll", "EnumResourceLanguagesA") or
         pe.imports("kernel32.dll", "EnumResourceLanguagesW")
      ) and
      (
         pe.imports("kernel32.dll", "VirtualAlloc") or
         pe.imports("kernel32.dll", "HeapAlloc")    or
         pe.imports("kernel32.dll", "LocalAlloc")
      )
}

rule MAL_AllUH_CallbackAbuse_CertCrypto {
   meta:
      description = "PE imports certificate/crypto enumeration callbacks alongside memory allocation — shellcode via CertFindCertificateInStore or CryptEnumOIDInfo callback"
      author = "Loaded Potato / lasersharkkiller"
      date = "2026-04-06"
      score = 75
      mitre_technique = "T1055.012"
      edr_gap = "MDE=-, CB=-, EL=-, XDR=-, TM=- (5/7 blind)"
      id = "10000001-0000-0000-0000-000000000004"
   condition:
      uint16(0) == 0x5a4d and filesize < 20MB and
      (
         pe.imports("crypt32.dll",  "CertFindCertificateInStore") or
         pe.imports("crypt32.dll",  "CryptEnumOIDInfo")           or
         pe.imports("imagehlp.dll", "ImageEnumerateCertificates")
      ) and
      (
         pe.imports("kernel32.dll", "VirtualAlloc") or
         pe.imports("kernel32.dll", "HeapAlloc")    or
         pe.imports("kernel32.dll", "LocalAlloc")
      ) and
      // Legitimate TLS/cert code has a rich crypt32 import footprint
      pe.number_of_imports < 6
}

// ===========================================================================
// GROUP 2 — FIBER EXECUTION
// Fibers run inside the calling thread — no CreateThread/CreateRemoteThread
// hook is triggered. ShellCode is set as the fiber start address.
// ===========================================================================

rule MAL_AllUH_FiberExecution {
   meta:
      description = "PE imports fiber execution APIs with memory allocation — shellcode runs inside calling thread via fiber without triggering any CreateThread hook"
      author = "Loaded Potato / lasersharkkiller"
      date = "2026-04-06"
      score = 70
      mitre_technique = "T1055"
      edr_gap = "MDE=-, CB=-, XDR=-, TM=- (4/7 blind); CS=B, S1=B, EL=B (behavioral)"
      id = "10000002-0000-0000-0000-000000000001"
   condition:
      uint16(0) == 0x5a4d and filesize < 20MB and
      pe.imports("kernel32.dll", "CreateFiber") and
      pe.imports("kernel32.dll", "SwitchToFiber") and
      (
         pe.imports("kernel32.dll", "VirtualAlloc") or
         pe.imports("kernel32.dll", "HeapAlloc")    or
         pe.imports("kernel32.dll", "LocalAlloc")
      )
}

// ===========================================================================
// GROUP 3 — THREAD POOL EXECUTION
// Thread pool callbacks execute via pool worker threads — no call to
// CreateRemoteThread (hooked) is made. Pool workers are pre-existing threads.
// ===========================================================================

rule MAL_AllUH_ThreadPool_Work {
   meta:
      description = "PE submits shellcode as thread pool work item via CreateThreadpoolWork or QueueUserWorkItem — avoids CreateRemoteThread hooks"
      author = "Loaded Potato / lasersharkkiller"
      date = "2026-04-06"
      score = 65
      mitre_technique = "T1055"
      edr_gap = "MDE=-, CB=- (2/7 blind); S1=B, EL=B, XDR=B, TM=B (behavioral)"
      id = "10000003-0000-0000-0000-000000000001"
   condition:
      uint16(0) == 0x5a4d and filesize < 20MB and
      (
         (pe.imports("kernel32.dll", "CreateThreadpoolWork") and
          pe.imports("kernel32.dll", "SubmitThreadpoolWork")) or
         pe.imports("kernel32.dll", "QueueUserWorkItem")
      ) and
      (
         pe.imports("kernel32.dll", "VirtualAlloc") or
         pe.imports("kernel32.dll", "HeapAlloc")    or
         pe.imports("kernel32.dll", "LocalAlloc")
      ) and
      not pe.imports("advapi32.dll", "RegisterServiceCtrlHandlerW")
}

rule MAL_AllUH_ThreadPool_TimerWait {
   meta:
      description = "PE uses thread pool timer or wait objects to trigger shellcode callback — execution deferred via pool without direct thread creation"
      author = "Loaded Potato / lasersharkkiller"
      date = "2026-04-06"
      score = 65
      mitre_technique = "T1055"
      edr_gap = "MDE=-, CB=- (2/7 blind); S1=B, EL=B, XDR=B, TM=B (behavioral)"
      id = "10000003-0000-0000-0000-000000000002"
   condition:
      uint16(0) == 0x5a4d and filesize < 20MB and
      (
         (pe.imports("kernel32.dll", "CreateThreadpoolTimer") and
          pe.imports("kernel32.dll", "SetThreadpoolTimer"))   or
         (pe.imports("kernel32.dll", "CreateThreadpoolWait") and
          pe.imports("kernel32.dll", "SetThreadpoolWait"))
      ) and
      (
         pe.imports("kernel32.dll", "VirtualAlloc") or
         pe.imports("kernel32.dll", "HeapAlloc")    or
         pe.imports("kernel32.dll", "LocalAlloc")
      )
}

// ===========================================================================
// GROUP 4 — TIMER CALLBACKS
// OS-dispatched callbacks via waitable timers or message-loop timers.
// No new thread created — shellcode executes in the APC or WndProc context.
// ===========================================================================

rule MAL_AllUH_TimerCallback_Waitable {
   meta:
      description = "PE imports waitable timer or timer-queue APIs with memory allocation — APC-style shellcode execution; no CreateThread call made"
      author = "Loaded Potato / lasersharkkiller"
      date = "2026-04-06"
      score = 75
      mitre_technique = "T1055"
      edr_gap = "MDE=-, CB=-, EL=-, XDR=-, TM=- (5/7 blind)"
      id = "10000004-0000-0000-0000-000000000001"
   condition:
      uint16(0) == 0x5a4d and filesize < 20MB and
      (
         pe.imports("kernel32.dll", "SetWaitableTimer")      or
         pe.imports("kernel32.dll", "SetWaitableTimerEx")    or
         pe.imports("kernel32.dll", "CreateTimerQueueTimer") or
         pe.imports("kernel32.dll", "CreateWaitableTimer")   or
         pe.imports("kernel32.dll", "CreateWaitableTimerEx") or
         pe.imports("ntdll.dll",    "RtlRegisterWait")
      ) and
      (
         pe.imports("kernel32.dll", "VirtualAlloc") or
         pe.imports("kernel32.dll", "HeapAlloc")    or
         pe.imports("kernel32.dll", "HeapCreate")   or
         pe.imports("kernel32.dll", "LocalAlloc")
      ) and
      not pe.imports("advapi32.dll", "RegisterServiceCtrlHandlerW") and
      not pe.imports("winmm.dll",    "timeSetEvent")
}

rule MAL_AllUH_TimerCallback_SetTimer {
   meta:
      description = "PE imports SetTimer (user32 message-loop timer) alongside memory allocation without a window creation — shellcode in timer callback without thread creation"
      author = "Loaded Potato / lasersharkkiller"
      date = "2026-04-06"
      score = 65
      mitre_technique = "T1055"
      edr_gap = "MDE=-, CB=-, EL=-, XDR=-, TM=- (5/7 blind)"
      id = "10000004-0000-0000-0000-000000000002"
   condition:
      uint16(0) == 0x5a4d and filesize < 20MB and
      pe.imports("user32.dll", "SetTimer") and
      (
         pe.imports("kernel32.dll", "VirtualAlloc") or
         pe.imports("kernel32.dll", "HeapAlloc")    or
         pe.imports("kernel32.dll", "LocalAlloc")
      ) and
      // Legitimate SetTimer always pairs with a window; missing window creation = suspicious
      not (
         pe.imports("user32.dll", "CreateWindowExA") or
         pe.imports("user32.dll", "CreateWindowExW") or
         pe.imports("user32.dll", "RegisterClassExA") or
         pe.imports("user32.dll", "RegisterClassExW")
      )
}

// ===========================================================================
// GROUP 5 — WINDOW PROC / MESSAGE ABUSE
// Shellcode is pointed at by a window procedure or delivered via message.
// OS dispatches the message, calling attacker-controlled code directly.
// ===========================================================================

rule MAL_AllUH_WindowProc_CallWindowProc {
   meta:
      description = "PE imports CallWindowProc with memory allocation but without SetWindowLong subclassing — shellcode executing as a spoofed WndProc"
      author = "Loaded Potato / lasersharkkiller"
      date = "2026-04-06"
      score = 80
      mitre_technique = "T1055.012"
      edr_gap = "S1=-, MDE=-, CB=-, EL=-, XDR=-, TM=- (6/7 blind)"
      id = "10000005-0000-0000-0000-000000000001"
   condition:
      uint16(0) == 0x5a4d and filesize < 20MB and
      (
         pe.imports("user32.dll", "CallWindowProcA") or
         pe.imports("user32.dll", "CallWindowProcW")
      ) and
      (
         pe.imports("kernel32.dll", "VirtualAlloc") or
         pe.imports("kernel32.dll", "HeapAlloc")    or
         pe.imports("kernel32.dll", "LocalAlloc")   or
         pe.imports("kernel32.dll", "GlobalAlloc")
      ) and
      not (
         pe.imports("user32.dll", "SetWindowLongA")    or
         pe.imports("user32.dll", "SetWindowLongW")    or
         pe.imports("user32.dll", "SetWindowLongPtrA") or
         pe.imports("user32.dll", "SetWindowLongPtrW")
      )
}

rule MAL_AllUH_WindowMessage_NoGUI {
   meta:
      description = "PE imports SendMessage/PostMessage/DispatchMessage with memory allocation but without window creation — message-dispatch shellcode execution without visible GUI"
      author = "Loaded Potato / lasersharkkiller"
      date = "2026-04-06"
      score = 60
      mitre_technique = "T1055"
      edr_gap = "S1=-, MDE=-, CB=-, EL=-, XDR=-, TM=- (6/7 blind)"
      id = "10000005-0000-0000-0000-000000000002"
   condition:
      uint16(0) == 0x5a4d and filesize < 20MB and
      (
         pe.imports("user32.dll", "SendMessageA")    or
         pe.imports("user32.dll", "SendMessageW")    or
         pe.imports("user32.dll", "PostMessageA")    or
         pe.imports("user32.dll", "PostMessageW")    or
         pe.imports("user32.dll", "DispatchMessageA") or
         pe.imports("user32.dll", "DispatchMessageW")
      ) and
      (
         pe.imports("kernel32.dll", "VirtualAlloc") or
         pe.imports("kernel32.dll", "HeapAlloc")
      ) and
      not (
         pe.imports("user32.dll", "CreateWindowExA")   or
         pe.imports("user32.dll", "CreateWindowExW")   or
         pe.imports("user32.dll", "RegisterClassExA")  or
         pe.imports("user32.dll", "RegisterClassExW")  or
         pe.imports("user32.dll", "DefWindowProcA")    or
         pe.imports("user32.dll", "DefWindowProcW")
      )
}

// ===========================================================================
// GROUP 6 — FILE-BACKED SECTION MAPPING
// Map a file-backed section as executable — no VirtualAlloc call needed.
// Attacker writes shellcode to a file, maps it RX, then executes.
// ===========================================================================

rule MAL_AllUH_FileMappingExec {
   meta:
      description = "PE imports CreateFileMapping + MapViewOfFile without standard file I/O — file-backed section mapped as executable for shellcode without VirtualAlloc"
      author = "Loaded Potato / lasersharkkiller"
      date = "2026-04-06"
      score = 65
      mitre_technique = "T1055.003"
      edr_gap = "MDE=- (1/7 blind); CS=H, S1=H, CB=H, EL=H, XDR=H, TM=H"
      id = "10000006-0000-0000-0000-000000000001"
   condition:
      uint16(0) == 0x5a4d and filesize < 20MB and
      (
         pe.imports("kernel32.dll", "CreateFileMappingA") or
         pe.imports("kernel32.dll", "CreateFileMappingW")
      ) and
      (
         pe.imports("kernel32.dll", "MapViewOfFile")   or
         pe.imports("kernel32.dll", "MapViewOfFileEx")
      ) and
      not (
         pe.imports("kernel32.dll", "ReadFile")  or
         pe.imports("kernel32.dll", "WriteFile")
      ) and
      not (
         pe.imports("kernel32.dll", "FlushViewOfFile") and
         pe.imports("kernel32.dll", "SetEndOfFile")
      )
}

// ===========================================================================
// GROUP 7 — COM / CLR IN-PROCESS HOSTING
// Run .NET assemblies or COM scripts inside a native process using CLR hosting
// interfaces. Used by execute-assembly, SharpPick, and reflective loaders.
// ===========================================================================

rule MAL_AllUH_CLR_InProcess {
   meta:
      description = "PE imports CLR hosting APIs (CLRCreateInstance/CorBindToRuntime) with a thin import profile — in-process .NET execution without spawning a new process"
      author = "Loaded Potato / lasersharkkiller"
      date = "2026-04-06"
      score = 75
      mitre_technique = "T1055"
      edr_gap = "CS=B, S1=B, CB=B, EL=B, XDR=B, TM=B (6/7 behavioral only — MDE=H)"
      id = "10000007-0000-0000-0000-000000000001"
   condition:
      uint16(0) == 0x5a4d and filesize < 20MB and
      (
         pe.imports("mscoree.dll", "CLRCreateInstance")        or
         pe.imports("mscoree.dll", "CorBindToRuntimeEx")       or
         pe.imports("mscoree.dll", "CorBindToCurrentRuntime")  or
         pe.imports("mscoree.dll", "CorExeMain")               or
         pe.imports("mscoree.dll", "_CorDllMain")
      ) and
      (
         pe.imports("kernel32.dll", "VirtualAlloc")  or
         pe.imports("kernel32.dll", "HeapAlloc")     or
         pe.imports("kernel32.dll", "LoadLibraryA")  or
         pe.imports("kernel32.dll", "LoadLibraryW")
      ) and
      pe.number_of_imports < 8
}

// ===========================================================================
// GROUP 8 — MEMORY COPY PRIMITIVES (shellcode staging without WriteProcessMemory)
// RtlMoveMemory / RtlCopyMemory / RtlZeroMemory used to copy shellcode bytes
// into pre-allocated memory, bypassing WriteProcessMemory hooks entirely.
// ALL 7 EDRs have no hook on these primitives.
// ===========================================================================

rule MAL_AllUH_MemCopy_RtlMove_RtlCopy {
   meta:
      description = "PE imports RtlMoveMemory or RtlCopyMemory with VirtualProtect but without WriteProcessMemory — shellcode staging that bypasses WriteProcessMemory hooks"
      author = "Loaded Potato / lasersharkkiller"
      date = "2026-04-06"
      score = 70
      mitre_technique = "T1620"
      edr_gap = "ALL 7 EDRs = not monitored at API level"
      id = "10000008-0000-0000-0000-000000000001"
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
      not pe.imports("kernel32.dll", "WriteProcessMemory") and
      pe.number_of_imports < 6
}

rule MAL_AllUH_MemCopy_RtlZero_Fill {
   meta:
      description = "PE imports RtlZeroMemory or RtlFillMemory alongside memory allocation — memory wiping primitives used to erase shellcode evidence or zero-fill staging buffers"
      author = "Loaded Potato / lasersharkkiller"
      date = "2026-04-06"
      score = 55
      mitre_technique = "T1620"
      edr_gap = "ALL 7 EDRs = not monitored at API level"
      id = "10000008-0000-0000-0000-000000000002"
   condition:
      uint16(0) == 0x5a4d and filesize < 20MB and
      (
         pe.imports("ntdll.dll",    "RtlZeroMemory")     or
         pe.imports("kernel32.dll", "RtlZeroMemory")     or
         pe.imports("ntdll.dll",    "RtlFillTileMemory") or
         pe.imports("kernel32.dll", "RtlFillTileMemory")
      ) and
      (
         pe.imports("kernel32.dll", "VirtualAlloc")   or
         pe.imports("kernel32.dll", "VirtualProtect") or
         pe.imports("kernel32.dll", "HeapAlloc")
      ) and
      // Alone RtlZeroMemory is benign; suspicious only with execution primitive
      (
         pe.imports("kernel32.dll", "CreateThread")         or
         pe.imports("kernel32.dll", "CreateFiber")          or
         pe.imports("kernel32.dll", "SetWaitableTimer")     or
         pe.imports("kernel32.dll", "EnumSystemLocalesA")   or
         pe.imports("kernel32.dll", "EnumSystemLocalesW")   or
         pe.imports("user32.dll",   "CallWindowProcA")      or
         pe.imports("user32.dll",   "CallWindowProcW")
      ) and
      pe.number_of_imports < 6
}

// ===========================================================================
// GROUP 9 — HEAP STAGING (allocation without VirtualAlloc hook)
// Private heap or legacy global/local heap allocations place shellcode in
// memory without triggering the VirtualAlloc hook most EDRs rely on.
// ALL 7 EDRs have no hook on these allocation primitives.
// ===========================================================================

rule MAL_AllUH_HeapStaging_NoVirtualAlloc {
   meta:
      description = "PE allocates memory via HeapCreate+HeapAlloc without VirtualAlloc alongside an execution primitive — shellcode staging that bypasses VirtualAlloc hooks"
      author = "Loaded Potato / lasersharkkiller"
      date = "2026-04-06"
      score = 70
      mitre_technique = "T1620"
      edr_gap = "ALL 7 EDRs = not monitored at API level"
      id = "10000009-0000-0000-0000-000000000001"
   condition:
      uint16(0) == 0x5a4d and filesize < 20MB and
      pe.imports("kernel32.dll", "HeapCreate") and
      pe.imports("kernel32.dll", "HeapAlloc") and
      not pe.imports("kernel32.dll", "VirtualAlloc") and
      not pe.imports("kernel32.dll", "VirtualAllocEx") and
      (
         pe.imports("kernel32.dll", "CreateThread")              or
         pe.imports("kernel32.dll", "QueueUserWorkItem")         or
         pe.imports("kernel32.dll", "CreateFiber")               or
         pe.imports("kernel32.dll", "SetWaitableTimer")          or
         pe.imports("kernel32.dll", "CreateTimerQueueTimer")     or
         pe.imports("kernel32.dll", "EnumSystemLocalesA")        or
         pe.imports("kernel32.dll", "EnumSystemLocalesW")        or
         pe.imports("kernel32.dll", "EnumSystemLanguageGroupsA") or
         pe.imports("user32.dll",   "CallWindowProcA")           or
         pe.imports("user32.dll",   "CallWindowProcW")
      )
}

rule MAL_AllUH_GlobalLocalAlloc_NoVirtualAlloc {
   meta:
      description = "PE uses GlobalAlloc or LocalAlloc (legacy heap) without VirtualAlloc alongside execution primitive — shellcode in legacy heap bypasses modern allocation hooks"
      author = "Loaded Potato / lasersharkkiller"
      date = "2026-04-06"
      score = 60
      mitre_technique = "T1620"
      edr_gap = "ALL 7 EDRs = not monitored at API level"
      id = "10000009-0000-0000-0000-000000000002"
   condition:
      uint16(0) == 0x5a4d and filesize < 20MB and
      (
         pe.imports("kernel32.dll", "GlobalAlloc") or
         pe.imports("kernel32.dll", "LocalAlloc")
      ) and
      not pe.imports("kernel32.dll", "VirtualAlloc") and
      not pe.imports("kernel32.dll", "HeapCreate") and
      (
         pe.imports("kernel32.dll", "CreateThread")              or
         pe.imports("kernel32.dll", "CreateFiber")               or
         pe.imports("kernel32.dll", "SetWaitableTimer")          or
         pe.imports("kernel32.dll", "CreateTimerQueueTimer")     or
         pe.imports("kernel32.dll", "EnumSystemLocalesA")        or
         pe.imports("kernel32.dll", "EnumSystemLocalesW")        or
         pe.imports("kernel32.dll", "EnumSystemLanguageGroupsA") or
         pe.imports("user32.dll",   "CallWindowProcA")           or
         pe.imports("user32.dll",   "CallWindowProcW")
      ) and
      pe.number_of_imports < 5
}

// ===========================================================================
// GROUP 10 — DLL LOAD INDIRECT
// Load malicious DLL without using the monitored LoadLibrary path or by
// manipulating the DLL search order before the load call.
// ===========================================================================

rule MAL_AllUH_DLL_SearchOrder_Hijack {
   meta:
      description = "PE manipulates DLL search directory then calls LoadLibrary — DLL search order hijack / sideloading without installer-typical file/registry writes"
      author = "Loaded Potato / lasersharkkiller"
      date = "2026-04-06"
      score = 65
      mitre_technique = "T1574.001"
      edr_gap = "MDE=-, CB=-, EL=-, XDR=-, TM=- (5/7 blind)"
      id = "10000010-0000-0000-0000-000000000001"
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
      not (
         pe.imports("kernel32.dll", "WriteFile") and
         pe.imports("advapi32.dll", "RegSetValueExW")
      )
}

rule MAL_AllUH_LoadPackagedLibrary {
   meta:
      description = "PE imports LoadPackagedLibrary alongside memory allocation — loads DLL via app-package path, often unmonitored alternative to LoadLibrary"
      author = "Loaded Potato / lasersharkkiller"
      date = "2026-04-06"
      score = 60
      mitre_technique = "T1574"
      edr_gap = "MDE=-, CB=-, EL=-, XDR=-, TM=- (5/7 blind)"
      id = "10000010-0000-0000-0000-000000000002"
   condition:
      uint16(0) == 0x5a4d and filesize < 20MB and
      pe.imports("kernel32.dll", "LoadPackagedLibrary") and
      (
         pe.imports("kernel32.dll", "VirtualAlloc") or
         pe.imports("kernel32.dll", "HeapAlloc")
      ) and
      pe.number_of_imports < 6
}

// ===========================================================================
// GROUP 11 — DIRECT THREAD CREATION (local, sometimes unhooked)
// CreateThread (local) may not be intercepted if the EDR only hooks
// CreateRemoteThread. RtlCreateThread bypasses the kernel32 hook entirely.
// ALL 7 EDRs hook CreateThread, but it is included for completeness and
// to detect combined patterns where CreateThread is the exec vector.
// ===========================================================================

rule MAL_AllUH_RtlCreateThread {
   meta:
      description = "PE imports RtlCreateThread alongside memory allocation — Rtl-level thread creation that may bypass kernel32 CreateThread hooks in some EDR configurations"
      author = "Loaded Potato / lasersharkkiller"
      date = "2026-04-06"
      score = 60
      mitre_technique = "T1055"
      edr_gap = "All major EDRs hook this; included for combined-technique coverage"
      id = "10000011-0000-0000-0000-000000000001"
   condition:
      uint16(0) == 0x5a4d and filesize < 20MB and
      pe.imports("ntdll.dll", "RtlCreateThread") and
      (
         pe.imports("kernel32.dll", "VirtualAlloc")   or
         pe.imports("kernel32.dll", "VirtualAllocEx") or
         pe.imports("kernel32.dll", "HeapAlloc")
      ) and
      // Only flag when combined with another unhooked primitive
      (
         pe.imports("kernel32.dll", "EnumSystemLocalesA")    or
         pe.imports("kernel32.dll", "EnumSystemLocalesW")    or
         pe.imports("kernel32.dll", "CreateFiber")           or
         pe.imports("kernel32.dll", "SetWaitableTimer")      or
         pe.imports("user32.dll",   "CallWindowProcA")       or
         pe.imports("user32.dll",   "CallWindowProcW")       or
         pe.imports("kernel32.dll", "MapViewOfFile")
      )
}

// ===========================================================================
// GROUP 12 — HIGH-CONFIDENCE MULTI-TECHNIQUE COMBINATIONS
// Binaries that combine MULTIPLE unhooked techniques provide near-certain
// evidence of a purpose-built loader designed to evade EDR API hooks.
// ===========================================================================

rule MAL_AllUH_MultiTech_CallbackPlusTimer {
   meta:
      description = "PE combines locale/resource callback abuse with timer-based execution — two independent unhooked exec paths in one binary = sophisticated EDR-aware loader"
      author = "Loaded Potato / lasersharkkiller"
      date = "2026-04-06"
      score = 90
      mitre_technique = "T1055.012"
      edr_gap = "Combined pattern has no reliable hook across all 7 EDRs"
      id = "10000012-0000-0000-0000-000000000001"
   condition:
      uint16(0) == 0x5a4d and filesize < 20MB and
      (
         pe.imports("kernel32.dll", "EnumSystemLocalesA")        or
         pe.imports("kernel32.dll", "EnumSystemLocalesW")        or
         pe.imports("kernel32.dll", "EnumSystemLanguageGroupsA") or
         pe.imports("kernel32.dll", "EnumSystemLanguageGroupsW") or
         pe.imports("kernel32.dll", "EnumResourceNamesA")        or
         pe.imports("kernel32.dll", "EnumResourceNamesW")
      ) and
      (
         pe.imports("kernel32.dll", "SetWaitableTimer")      or
         pe.imports("kernel32.dll", "CreateTimerQueueTimer") or
         pe.imports("user32.dll",   "SetTimer")
      )
}

rule MAL_AllUH_MultiTech_HeapAllocPlusUnhookedExec {
   meta:
      description = "PE combines heap-only allocation (no VirtualAlloc) with an unhooked execution primitive — evades both the memory allocation hook tier AND the thread creation hook tier simultaneously"
      author = "Loaded Potato / lasersharkkiller"
      date = "2026-04-06"
      score = 90
      mitre_technique = "T1055.012"
      edr_gap = "ALL 7 EDRs have limited/no visibility on this combination"
      id = "10000012-0000-0000-0000-000000000002"
   condition:
      uint16(0) == 0x5a4d and filesize < 20MB and
      (
         pe.imports("kernel32.dll", "HeapCreate") or
         pe.imports("kernel32.dll", "HeapAlloc")  or
         pe.imports("kernel32.dll", "LocalAlloc") or
         pe.imports("kernel32.dll", "GlobalAlloc")
      ) and
      not pe.imports("kernel32.dll", "VirtualAlloc") and
      (
         pe.imports("kernel32.dll", "SetWaitableTimer")          or
         pe.imports("kernel32.dll", "CreateTimerQueueTimer")     or
         pe.imports("user32.dll",   "CallWindowProcA")           or
         pe.imports("user32.dll",   "CallWindowProcW")           or
         pe.imports("kernel32.dll", "CreateFiber")               or
         pe.imports("kernel32.dll", "EnumSystemLocalesA")        or
         pe.imports("kernel32.dll", "EnumSystemLocalesW")        or
         pe.imports("kernel32.dll", "EnumSystemLanguageGroupsA") or
         pe.imports("kernel32.dll", "EnumSystemLanguageGroupsW")
      )
}

rule MAL_AllUH_MultiTech_FiberPlusThreadPool {
   meta:
      description = "PE combines fiber execution with thread pool submission — two separate unhooked execution paths that share no common hook point"
      author = "Loaded Potato / lasersharkkiller"
      date = "2026-04-06"
      score = 85
      mitre_technique = "T1055"
      edr_gap = "No common hook point across this combination for any EDR"
      id = "10000012-0000-0000-0000-000000000003"
   condition:
      uint16(0) == 0x5a4d and filesize < 20MB and
      pe.imports("kernel32.dll", "CreateFiber") and
      pe.imports("kernel32.dll", "SwitchToFiber") and
      (
         pe.imports("kernel32.dll", "CreateThreadpoolWork") or
         pe.imports("kernel32.dll", "QueueUserWorkItem")
      )
}

rule MAL_AllUH_MultiTech_CLR_Plus_Callback {
   meta:
      description = "PE combines CLR in-process hosting with callback abuse — .NET assembly loaded and executed without spawning a process or triggering standard injection hooks"
      author = "Loaded Potato / lasersharkkiller"
      date = "2026-04-06"
      score = 88
      mitre_technique = "T1055"
      edr_gap = "MDE partial (AMSI); all other EDRs have no combined hook for this pattern"
      id = "10000012-0000-0000-0000-000000000004"
   condition:
      uint16(0) == 0x5a4d and filesize < 20MB and
      (
         pe.imports("mscoree.dll", "CLRCreateInstance")    or
         pe.imports("mscoree.dll", "CorBindToRuntimeEx")
      ) and
      (
         pe.imports("kernel32.dll", "EnumSystemLocalesA")        or
         pe.imports("kernel32.dll", "EnumSystemLocalesW")        or
         pe.imports("kernel32.dll", "EnumSystemLanguageGroupsA") or
         pe.imports("kernel32.dll", "SetWaitableTimer")          or
         pe.imports("kernel32.dll", "CreateFiber")               or
         pe.imports("user32.dll",   "CallWindowProcA")           or
         pe.imports("user32.dll",   "CallWindowProcW")
      )
}
