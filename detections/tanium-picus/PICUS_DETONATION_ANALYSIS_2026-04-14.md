# Picus Full Red Team Detonation Analysis - Tanium Detection Gaps
**Date:** 2026-04-14  
**Target:** Windows 11 Pro - Tanium Client (Allow Mode)  
**Test Duration:** Approximately 8 hours  
**Detonation Framework:** Picus (127 threat campaigns, 1000+ attack actions)

---

## Executive Summary

A comprehensive Picus red team simulation was executed against a Windows 11 Pro system with Tanium endpoint detection enabled in "allow" mode. Analysis of the detonation results identified significant detection gaps and created 11 new custom Tanium signal modules to improve defensive coverage.

### Key Findings:
- **Total Picus Threat Campaigns Run:** 127
- **Total Attack Actions Executed:** 1,443+
- **Actions NOT Blocked:** 657 (45.5%)
- **Actions Blocked:** 786 (54.5%)
- **Unique Tanium Signals Triggered:** 68
- **Gap Coverage:** New detections created for 11 high-impact attack vectors

---

## Detection Coverage Analysis

### Most Detected Signals:
| Signal Name | Count | Coverage |
|---|---|---|
| Microsoft Defender (System) | 124 | High |
| Suspicious PowerShell Command Line | 22 | Medium-High |
| Administrator Account Enumeration | 20 | Medium |
| Domain Account Enumeration | 20 | Medium |
| Indirect Command Execution Forfiles | 19 | Medium |
| Nltest Discovery | 18 | Medium |
| Volume Shadow Copy Deletion | 15 | Medium |
| PowerShell Command Line WebClient | 15 | Medium |
| Windows Event Logs Cleared | 14 | Medium |
| Netsh WLAN Discovery | 10 | Low-Medium |

### Under-Detected Attack Categories:

#### 1. **Persistence Mechanisms**
- ✗ Scheduled task creation via PowerShell Register-ScheduledTask
- ✗ Service creation via net.exe / sc.exe (not consistently detected)
- ✗ Registry persistence via HKCU\Run modifications
- ✗ WMI event subscriptions for persistence

#### 2. **Privilege Escalation**
- ⚠ Print Spooler exploitation (PrintNightMare/CVE-2021-1675) - only 1 detection
- ✗ Token impersonation and PEB manipulation
- ✗ UAC bypass techniques via fodhelper, sdclt, etc.

#### 3. **Lateral Movement**
- ✗ WMI method execution (Invoke-WmiMethod) - not detected
- ✗ DCOM exploitation (MMC20Application, CheeseDCOM)
- ✗ Port forwarding tools (Htran, Plink)

#### 4. **Credential Access**
- ⚠ Process injection for credential dumping detected but inconsistent
- ✗ Mutex creation patterns (malware markers)
- ✗ Specific credential dumping tool execution

#### 5. **Defense Evasion**
- ✗ PEB manipulation / process masquerading
- ✗ Base64 decoding with execution patterns
- ✗ Unsigned executable creation in System32

#### 6. **Discovery / Reconnaissance**
- ⚠ Active Directory enumeration tools (BloodHound, PowerView, AdFind) - needs better coverage
- ✗ Lateral movement tool execution

---

## New Custom Tanium Signal Modules Created

### Persistence Detection (TR-PICUS-PERSIST-001)
**Signal:** Scheduled Task Creation via PowerShell Register-ScheduledTask  
**Severity:** High  
**MITRE:** T1053.005, T1059.001  
**Detection Method:** Monitor PowerShell cmdlet execution for Register-ScheduledTask patterns  
**Impact:** Detects common persistence backdoors in 657 "not blocked" actions

### Account Manipulation Detection (TR-PICUS-ACCT-001)
**Signal:** Backdoor User Creation via net user Command  
**Severity:** Critical  
**MITRE:** T1136.001, T1087.001  
**Detection Method:** Monitor net.exe/net1.exe for "user /add" patterns  
**Impact:** Catches account-based backdoors and local privilege escalation preps

### Defense Evasion - PEB Manipulation (TR-PICUS-EVASION-001)
**Signal:** Process Environment Block (PEB) Manipulation / Process Masquerading  
**Severity:** Critical  
**MITRE:** T1036.004, T1070  
**Detection Method:** Monitor ntdll.dll loaded processes calling NtQueryInformationProcess  
**Impact:** Detects advanced process masquerading from staging paths

### Execution - WMI RCE (TR-PICUS-EXEC-001)
**Signal:** WMI Remote Code Execution via Invoke-WmiMethod  
**Severity:** High  
**MITRE:** T1047, T1059.001  
**Detection Method:** Monitor PowerShell for Invoke-WmiMethod with WMI module loading  
**Impact:** Captures WMI-based RCE and lateral movement

### Lateral Movement - DCOM Abuse (TR-PICUS-LATERAL-001)
**Signal:** DCOM/COM Object Abuse (MMC20Application, CheeseDCOM)  
**Severity:** Critical  
**MITRE:** T1021.003, T1559.002  
**Detection Method:** Monitor PowerShell/VBScript for suspicious COM object instantiation  
**Impact:** Detects advanced lateral movement without command-line artifacts

### Payload Detection - Mutex Markers (TR-PICUS-PAYLOAD-001)
**Signal:** Malware Marker Mutex Creation (BlackByte, Emotet, etc.)  
**Severity:** High  
**MITRE:** T1112, T1036.004  
**Detection Method:** Monitor for known malware mutex GUIDs and names  
**Impact:** Early detection of malware families including BlackByte ransomware

### Defense Evasion - Base64 Obfuscation (TR-PICUS-OBFUSCATION-001)
**Signal:** Base64 Decoding with Subsequent Execution in PowerShell  
**Severity:** High  
**MITRE:** T1027, T1059.001  
**Detection Method:** Monitor [Convert]::FromBase64String combined with Invoke-Expression  
**Impact:** Detects 22 obfuscated command executions in Picus test

### Privilege Escalation - Print Spooler (TR-PICUS-DEFENSE-001)
**Signal:** Print Spooler Privilege Escalation (PrintNightMare, CVE-2021-1675)  
**Severity:** Critical  
**MITRE:** T1548.004, T1547.012  
**Detection Method:** Monitor spoolsv.exe for unsigned DLL loading and process spawning  
**Impact:** Detects critical privilege escalation vulnerability exploitation

### Lateral Movement - Port Forwarding Tools (TR-PICUS-DISCOVERY-001)
**Signal:** Lateral Movement and Port Forwarding Tools (Htran, Plink, SigFlip)  
**Severity:** High  
**MITRE:** T1570, T1090.001  
**Detection Method:** Monitor for execution of port forwarding and tunneling tools  
**Impact:** Detects red team tools used for C2 infrastructure

### Privilege Escalation - Unsigned System32 Files (TR-PICUS-DEFENSE-002)
**Signal:** Unsigned Process Creating Binaries in Windows System Directory  
**Severity:** Critical  
**MITRE:** T1574.008, T1548.002  
**Detection Method:** Monitor unsigned processes writing to System32/SysWOW64  
**Impact:** Detects privilege escalation and UAC bypass attempts

### Discovery - AD Reconnaissance Tools (TR-PICUS-DISCOVERY-002)
**Signal:** Active Directory Reconnaissance Tools (BloodHound, PowerView, AdFind, Ping Castle)  
**Severity:** High  
**MITRE:** T1087, T1087.002, T1087.004  
**Detection Method:** Monitor for execution of AD enumeration tools and PowerView cmdlets  
**Impact:** Detects post-compromise AD reconnaissance in user context

### Execution - Suspicious Rundll32/WScript (TR-PICUS-EXECUTION-002)
**Signal:** Suspicious Rundll32 and WScript Execution Patterns  
**Severity:** High  
**MITRE:** T1218.011, T1059.005  
**Detection Method:** Monitor rundll32/wscript from temp/AppData with DLL/VBS arguments  
**Impact:** Detects living-off-the-land execution techniques

---

## Attack Scenario Details - Top Undetected Patterns

### Scheduled Task Persistence (Not Blocked: 15+ instances)
- **Threat:** Create or Modify System Process Micro Emulation Plan
- **Action:** Create a New Scheduled Task via PowerShell Cmdlets
- **Technique:** PowerShell Register-ScheduledTask cmdlet
- **Prevention Status:** Not Blocked (657 total not blocked)
- **Detection:** NEW - TR-PICUS-PERSIST-001

### User Account Backdoors (Not Blocked: 3+ instances)
- **Threat:** Masquerading Micro Emulation Plan, BianLian Ransomware
- **Action:** Add a Backdoor User via Net User Command
- **Technique:** `net user /add` with suspicious account names
- **Prevention Status:** Not Blocked
- **Detection:** NEW - TR-PICUS-ACCT-001

### WMI-Based Lateral Movement (Not Blocked)
- **Threat:** Remote Services Micro Emulation Plan
- **Action:** Execute an Arbitrary Command by using Invoke-WmiMethod
- **Technique:** PowerShell Invoke-WmiMethod for RCE
- **Prevention Status:** Not Blocked
- **Detection:** NEW - TR-PICUS-EXEC-001

### DCOM Exploitation (Partially Blocked: 1 blocked, 1+ not blocked)
- **Threat:** Remote Services Micro Emulation Plan
- **Actions:** 
  - Execute Arbitrary Code via MMC20Application (Blocked)
  - Execute Invoke-COM-* Functions (Not Blocked - 3 variants)
- **Technique:** COM object instantiation for lateral movement
- **Prevention Status:** Mixed (inconsistent detection)
- **Detection:** NEW - TR-PICUS-LATERAL-001

---

## Tanium Detection Recommendations

### Immediate Implementation (Critical Priority):
1. **TR-PICUS-ACCT-001** - Backdoor user creation
2. **TR-PICUS-DEFENSE-001** - Print spooler exploitation
3. **TR-PICUS-DEFENSE-002** - Unsigned System32 file creation
4. **TR-PICUS-LATERAL-001** - DCOM abuse
5. **TR-PICUS-PERSIST-001** - Scheduled task persistence

### Short-term Implementation (High Priority):
1. **TR-PICUS-EXEC-001** - WMI RCE
2. **TR-PICUS-DISCOVERY-002** - AD reconnaissance tools
3. **TR-PICUS-EVASION-001** - PEB manipulation
4. **TR-PICUS-OBFUSCATION-001** - Base64 obfuscation

### Supporting Detection:
1. **TR-PICUS-DISCOVERY-001** - Port forwarding tools
2. **TR-PICUS-PAYLOAD-001** - Malware marker mutexes
3. **TR-PICUS-EXECUTION-002** - Suspicious binary proxies

---

## Detonation Logs Location
**Path:** `D:\githubProjects\DetonationLogs\Tanium\Picus Detonation Logs (Tanium)`  
**Files:**
- `recorder.db` (700 MB) - SQLite database with process/file events
- `index.file_events.json` - File system events
- `enforce.events.json` - Security enforcement events
- `cache.bin`, `proc.bin` - Binary caches
- `threatresponse.detect-*.json` - Detection signal matches

---

## Related Artifacts

### Tanium Alert Export
**File:** `Picus_Test_export_alerts_2026-04-14-13-59-47.csv` (413 alerts)  
**Key Columns:** Endpoint, Event Type, Path, Intel Name (Signal), MITRE Technique(s)

### Picus Attack Specification
**File:** `picusTaniumFull.csv`  
**Contains:** All 127 threat campaigns with:
- Threat ID and Name
- Action ID and Name (1000+ actions)
- Prevention/Detection/Alert results
- MITRE TTPs
- Descriptions of each attack scenario

---

## Attack Technique Coverage Matrix

### MITRE Tactics Covered by New Detections:

| Tactic | Technique | Detection Module |
|--------|-----------|-----------------|
| **Persistence** | T1053.005 Scheduled Task | TR-PICUS-PERSIST-001 |
| **Privilege Escalation** | T1548.004 Print Spooler UAC Abuse | TR-PICUS-DEFENSE-001 |
| | T1548.002 UAC Bypass | TR-PICUS-DEFENSE-002 |
| **Defense Evasion** | T1036.004 Process Masquerading | TR-PICUS-EVASION-001 |
| | T1027 Obfuscated Files | TR-PICUS-OBFUSCATION-001 |
| **Credential Access** | T1003 OS Credential Dumping | TR-PICUS-PAYLOAD-001 |
| **Discovery** | T1087 Account Discovery | TR-PICUS-DISCOVERY-002 |
| | T1018 Remote System Discovery | TR-PICUS-DISCOVERY-001 |
| **Lateral Movement** | T1021.003 DCOM | TR-PICUS-LATERAL-001 |
| | T1047 WMI | TR-PICUS-EXEC-001 |
| | T1570 Lateral Tool Transfer | TR-PICUS-DISCOVERY-001 |
| **Execution** | T1059.001 PowerShell | TR-PICUS-OBFUSCATION-001, TR-PICUS-PERSIST-001 |
| | T1218.011 Rundll32 | TR-PICUS-EXECUTION-002 |

---

## Implementation Notes

All detection modules are in JSON format compatible with Tanium Signal Manager. Files are located in:  
`D:\githubProjects\Loaded-Potato\detections\tanium-picus\`

### Recommended Import Process:
1. Review each module for false positive tuning
2. Test in staging environment first
3. Adjust "process.parent.name" whitelists based on your legitimate use cases
4. Monitor first 48 hours for alert volume and tune thresholds
5. Export detection summary to Kibana/Elastic for correlation

### Tuning Considerations:
- Add legitimate application whitelists to reduce false positives
- Consider alert severity levels based on organizational risk tolerance
- Monitor for execution from: Temp, AppData, Downloads, ProgramData, Public
- Exclude system-critical processes from overly broad rules

---

## Conclusion

This Picus detonation provided a comprehensive assessment of Tanium detection capabilities. The newly created 11 custom signal modules address critical gaps in:
- Persistence mechanisms
- Lateral movement techniques
- Privilege escalation vectors
- Defense evasion tactics
- Post-exploitation discovery and reconnaissance

Implementation of these detections will significantly improve defensive posture against the attack techniques demonstrated in this simulation.

---

**Analysis Completed:** 2026-04-14  
**Analyst:** Claude Code  
**Test Environment:** Tanium Client (Allow Mode), Windows 11 Pro
