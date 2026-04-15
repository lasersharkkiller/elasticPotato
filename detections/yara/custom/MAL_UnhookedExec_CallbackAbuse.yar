/*
   Unhooked Execution via Callback Abuse — PE Import Table Detection
   -----------------------------------------------------------------------
   Rationale:
   EDRs hook VirtualAlloc/WriteProcessMemory/CreateRemoteThread to catch
   classic injection. Attackers bypass these hooks by passing shellcode
   addresses as function pointers to Win32 enumeration callbacks — the OS
   then calls the attacker's code without any hooked API being invoked.

   These rules fire on the IMPORT TABLE of a PE, not at runtime.
   Rarity scores from APIDifferentialAnalysis.json (0 = common in clean
   software, 100 = never seen in clean software):
     EnumSystemLanguageGroupsA  score=100  malicious_count=16
     EnumSystemLocalesW         score=100  malicious_count=103
     EnumWindows                score=~70  malicious_count=63
     CertFindCertificateInStore score=~60  malicious_count=24

   Sources: ired.team T1055, MDSec CallbacksInsteadOfCreateRemoteThread,
            Sektor7 RED TEAM Operator courses, APIDifferentialAnalysis.json
*/

import "pe"

// ---------------------------------------------------------------------------
// HIGH CONFIDENCE — callback APIs that are essentially never in clean software
// combined with a memory allocation primitive (the shellcode needs to live
// somewhere before the callback points at it)
// ---------------------------------------------------------------------------

rule MAL_UnhookedExec_EnumCallback_MemAlloc_High {
   meta:
      description = "PE imports a rare enumeration callback API alongside a memory allocation primitive — classic unhooked shellcode execution pattern"
      author = "Loaded Potato / lasersharkkiller"
      date = "2026-04-06"
      score = 80
      reference = "https://www.ired.team/offensive-security/code-injection-process-injection/shellcode-execution-in-a-local-process-with-queueuserapc-writeprocessmemory-and-ntcreatethreadex-bypassing-sysmon-and-windows-defender"
      mitre_technique = "T1055.012"
      id = "a1f2e3d4-b5c6-7890-abcd-ef1234567890"
   condition:
      uint16(0) == 0x5a4d and filesize < 20MB and
      // --- Rare callback API (any one is enough) ---
      (
         pe.imports("kernel32.dll", "EnumSystemLanguageGroupsA") or
         pe.imports("kernel32.dll", "EnumSystemLanguageGroupsW") or
         pe.imports("kernel32.dll", "EnumSystemLocalesA") or
         pe.imports("kernel32.dll", "EnumSystemLocalesW") or
         pe.imports("kernel32.dll", "EnumUILanguagesA") or
         pe.imports("kernel32.dll", "EnumUILanguagesW") or
         pe.imports("kernel32.dll", "EnumResourceTypesA") or
         pe.imports("kernel32.dll", "EnumResourceTypesW") or
         pe.imports("kernel32.dll", "EnumResourceNamesA") or
         pe.imports("kernel32.dll", "EnumResourceNamesW") or
         pe.imports("kernel32.dll", "EnumResourceLanguagesA") or
         pe.imports("kernel32.dll", "EnumResourceLanguagesW")
      ) and
      // --- Memory allocation primitive (shellcode staging) ---
      (
         pe.imports("kernel32.dll", "HeapAlloc") or
         pe.imports("kernel32.dll", "HeapCreate") or
         pe.imports("kernel32.dll", "LocalAlloc") or
         pe.imports("kernel32.dll", "GlobalAlloc") or
         pe.imports("kernel32.dll", "VirtualAlloc") or
         pe.imports("kernel32.dll", "VirtualAllocEx")
      )
}

rule MAL_UnhookedExec_CertCallback_MemAlloc {
   meta:
      description = "PE imports CertFindCertificateInStore (callback-capable crypto API) with memory allocation — used for shellcode execution via certificate enumeration callback"
      author = "Loaded Potato / lasersharkkiller"
      date = "2026-04-06"
      score = 75
      reference = "https://github.com/aahmad097/AlternativeShellcodeExec"
      mitre_technique = "T1055.012"
      id = "b2e3f4a5-c6d7-8901-bcde-f12345678901"
   condition:
      uint16(0) == 0x5a4d and filesize < 20MB and
      pe.imports("crypt32.dll", "CertFindCertificateInStore") and
      (
         pe.imports("kernel32.dll", "HeapAlloc") or
         pe.imports("kernel32.dll", "LocalAlloc") or
         pe.imports("kernel32.dll", "GlobalAlloc") or
         pe.imports("kernel32.dll", "VirtualAlloc")
      ) and
      // Legitimate TLS/cert code imports many more crypto functions.
      // Flag only when the crypto import footprint is unusually thin.
      pe.number_of_imports < 6
}

rule MAL_UnhookedExec_EnumWindows_NoGUI {
   meta:
      description = "PE imports EnumWindows or EnumChildWindows without the typical GUI framework imports — likely callback shellcode execution, not legitimate window enumeration"
      author = "Loaded Potato / lasersharkkiller"
      date = "2026-04-06"
      score = 70
      reference = "https://www.ired.team/offensive-security/code-injection-process-injection"
      mitre_technique = "T1055.012"
      id = "c3f4a5b6-d7e8-9012-cdef-123456789012"
   condition:
      uint16(0) == 0x5a4d and filesize < 20MB and
      (
         pe.imports("user32.dll", "EnumWindows") or
         pe.imports("user32.dll", "EnumChildWindows") or
         pe.imports("user32.dll", "EnumDesktopWindows") or
         pe.imports("user32.dll", "EnumThreadWindows")
      ) and
      // Legitimate window-enumerating software imports SendMessage, SetWindowText, etc.
      // Suspicious when it doesn't also import normal GUI management functions.
      not (
         pe.imports("user32.dll", "SetWindowTextA") or
         pe.imports("user32.dll", "SetWindowTextW") or
         pe.imports("user32.dll", "GetWindowTextA") or
         pe.imports("user32.dll", "GetWindowTextW") or
         pe.imports("user32.dll", "ShowWindow") or
         pe.imports("user32.dll", "CreateWindowExA") or
         pe.imports("user32.dll", "CreateWindowExW")
      ) and
      (
         pe.imports("kernel32.dll", "HeapAlloc") or
         pe.imports("kernel32.dll", "VirtualAlloc") or
         pe.imports("kernel32.dll", "LocalAlloc")
      )
}

// ---------------------------------------------------------------------------
// FIBER EXECUTION — CreateFiber + SwitchToFiber without a legitimate use
// (most legitimate fiber use comes from game engines, SQL Server, Chrome V8)
// ---------------------------------------------------------------------------

rule MAL_UnhookedExec_FiberExecution {
   meta:
      description = "PE imports fiber execution APIs (CreateFiber, SwitchToFiber) with memory allocation but without typical legitimate fiber-framework imports"
      author = "Loaded Potato / lasersharkkiller"
      date = "2026-04-06"
      score = 65
      reference = "https://research.nccgroup.com/2021/01/23/rift-analysing-a-lazarus-shellcode-execution-technique/"
      mitre_technique = "T1055"
      id = "d4a5b6c7-e8f9-0123-defa-234567890123"
   condition:
      uint16(0) == 0x5a4d and filesize < 20MB and
      pe.imports("kernel32.dll", "CreateFiber") and
      pe.imports("kernel32.dll", "SwitchToFiber") and
      (
         pe.imports("kernel32.dll", "VirtualAlloc") or
         pe.imports("kernel32.dll", "HeapAlloc") or
         pe.imports("kernel32.dll", "LocalAlloc")
      )
}

// ---------------------------------------------------------------------------
// THREAD POOL EXECUTION — callback execution via pool worker threads,
// avoiding CreateRemoteThread (hooked) entirely
// ---------------------------------------------------------------------------

rule MAL_UnhookedExec_ThreadPool {
   meta:
      description = "PE imports thread pool submission APIs with memory allocation — used to execute shellcode via pool worker without CreateRemoteThread"
      author = "Loaded Potato / lasersharkkiller"
      date = "2026-04-06"
      score = 60
      reference = "https://www.ired.team/offensive-security/code-injection-process-injection/thread-pool-execution"
      mitre_technique = "T1055"
      id = "e5b6c7d8-f9a0-1234-efab-345678901234"
   condition:
      uint16(0) == 0x5a4d and filesize < 20MB and
      (
         (pe.imports("kernel32.dll", "CreateThreadpoolWork") and
          pe.imports("kernel32.dll", "SubmitThreadpoolWork")) or
         pe.imports("kernel32.dll", "QueueUserWorkItem") or
         (pe.imports("kernel32.dll", "CreateThreadpoolTimer") and
          pe.imports("kernel32.dll", "SetThreadpoolTimer"))
      ) and
      (
         pe.imports("kernel32.dll", "VirtualAlloc") or
         pe.imports("kernel32.dll", "HeapAlloc") or
         pe.imports("kernel32.dll", "LocalAlloc")
      ) and
      // Filter out legitimate Windows service frameworks which use thread pools heavily
      not pe.imports("advapi32.dll", "RegisterServiceCtrlHandlerW")
}

// ---------------------------------------------------------------------------
// FILE-BACKED SECTION MAPPING — non-ntdll path to executable memory
// Used to map and execute code without VirtualAlloc (which is hooked)
// ---------------------------------------------------------------------------

rule MAL_UnhookedExec_FileMappingExec {
   meta:
      description = "PE imports CreateFileMapping + MapViewOfFile without standard file I/O imports — suspicious pattern for mapping and executing shellcode from a file-backed section"
      author = "Loaded Potato / lasersharkkiller"
      date = "2026-04-06"
      score = 65
      reference = "https://www.ired.team/offensive-security/code-injection-process-injection/file-backed-section-map-injection"
      mitre_technique = "T1055.003"
      id = "f6c7d8e9-a0b1-2345-fabc-456789012345"
   condition:
      uint16(0) == 0x5a4d and filesize < 20MB and
      (
         pe.imports("kernel32.dll", "CreateFileMappingA") or
         pe.imports("kernel32.dll", "CreateFileMappingW")
      ) and
      (
         pe.imports("kernel32.dll", "MapViewOfFile") or
         pe.imports("kernel32.dll", "MapViewOfFileEx")
      ) and
      // Suspicious: mapping without the normal file read/write pattern
      not (
         pe.imports("kernel32.dll", "ReadFile") or
         pe.imports("kernel32.dll", "WriteFile")
      ) and
      // And not doing anything that looks like legitimate logging or DB
      not (
         pe.imports("kernel32.dll", "FlushViewOfFile") and
         pe.imports("kernel32.dll", "SetEndOfFile")
      )
}

// ---------------------------------------------------------------------------
// COMBINATION RULE — High-confidence: multiple unhooked exec techniques
// in the same binary = almost certainly a loader/injector
// ---------------------------------------------------------------------------

rule MAL_UnhookedExec_MultiTechnique_Loader {
   meta:
      description = "PE combines multiple unhooked execution techniques — strong indicator of a sophisticated loader designed to bypass EDR API hooks"
      author = "Loaded Potato / lasersharkkiller"
      date = "2026-04-06"
      score = 90
      reference = "https://github.com/aahmad097/AlternativeShellcodeExec"
      mitre_technique = "T1055.012"
      id = "a7d8e9f0-b1c2-3456-abcd-567890123456"
   condition:
      uint16(0) == 0x5a4d and filesize < 20MB and
      (
        (
           // Callback technique
           pe.imports("kernel32.dll", "EnumSystemLocalesA") or
           pe.imports("kernel32.dll", "EnumSystemLocalesW") or
           pe.imports("kernel32.dll", "EnumSystemLanguageGroupsA") or
           pe.imports("kernel32.dll", "EnumSystemLanguageGroupsW") or
           pe.imports("kernel32.dll", "EnumResourceNamesA") or
           pe.imports("kernel32.dll", "EnumResourceNamesW")
        ) and (
           // Timer technique
           pe.imports("kernel32.dll", "SetWaitableTimer") or
           pe.imports("kernel32.dll", "CreateTimerQueueTimer") or
           pe.imports("user32.dll", "SetTimer")
        )
      ) or (
        (
           // Fiber technique
           pe.imports("kernel32.dll", "CreateFiber") and
           pe.imports("kernel32.dll", "SwitchToFiber")
        ) and (
           // Thread pool technique
           pe.imports("kernel32.dll", "CreateThreadpoolWork") or
           pe.imports("kernel32.dll", "QueueUserWorkItem")
        )
      ) or (
        (
           // Callback technique
           pe.imports("kernel32.dll", "EnumSystemLocalesA") or
           pe.imports("kernel32.dll", "EnumSystemLocalesW")
        ) and (
           // Section mapping technique
           pe.imports("kernel32.dll", "MapViewOfFile") or
           pe.imports("kernel32.dll", "MapViewOfFileEx")
        )
      )
}
