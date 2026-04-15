# ElasticAlertAgent Offline Analysis - Tuning Guide

## Overview

The `Invoke-ElasticAlertAgentAnalysis` function performs offline analysis of detonation logs with a built-in heuristic scoring engine. This guide documents the whitelists and tuning points that can be adjusted to reduce false positives (FP) while maintaining high-fidelity detection.

---

## DNS Domain Whitelists

DNS queries are evaluated against two whitelist regex patterns to separate benign traffic from suspicious/C2 activity.

### 1. **Network Traffic Classification Whitelist** (Line ~850)
- **Variable:** `$benignClassRx`
- **Purpose:** Classifies observed domains as BENIGN, DDNS, or C2 for final verdict
- **Applied in:** Network traffic classification section (4f)

### 2. **C2 DNS Detection Whitelist** (Line ~1391)
- **Variable:** `$c2DNS`
- **Purpose:** Filters out benign domains from "suspicious non-Microsoft DNS" alert
- **Applied in:** Per-session network summary (offline NDJSON processing)

### Current Whitelist Categories

#### Certificate Authorities & OCSP Responders
```
ocsp.|sectigo.com|verisign.com|godaddy.com|comodo.com|globalsign.com
let'sencrypt.org|isrg.x3.letsencrypt|letsencrypt.org|crt.sh|crl.|pki.
```

**Why:** Legitimate certificate verification and revocation checking
- OCSP = Online Certificate Status Protocol (required by browsers)
- CRL = Certificate Revocation Lists
- CA = Certificate Authorities (issued and signing certificates)

#### Time/NTP Services
```
ntp.org|time.nist.gov|pool.ntp.org
```

**Why:** Windows and Linux systems sync time with NTP pools - legitimate background traffic

#### Package Repositories
```
packages.ubuntu.com|archive.ubuntu.com|deb.debian.org|security.debian.org
fedoraproject.org|dl.fedoraproject.org|mirror.centos.org|yum.baseurl
```

**Why:** Linux package update infrastructure - legitimate system management

#### Browser/Chrome Update Infrastructure
```
chromeupdate|gvt1.com|gstatic.com|googleapis.com
```

**Why:** Browser auto-update and Google CDN infrastructure

#### Microsoft/OS Vendors (Pre-existing)
```
microsoft.com|windows.com|office365|azure.|windowsupdate
msauth|msoidentity|msftncsi
```

---

## How to Extend the Whitelists

### Add a Domain to Both Whitelists

If you encounter a false positive for a legitimate domain (e.g., `example.com`), update BOTH regex patterns:

1. **Line ~850** - `$benignClassRx` (Network traffic classification)
   ```powershell
   $benignClassRx = '(?i)...existing...|example\.com'
   ```

2. **Line ~1391** - `$c2DNS` filter
   ```powershell
   $_.Name -notmatch '...existing...|example\.com'
   ```

### Escaping Special Characters

Regex patterns need escaping:
- Dots: `\.` (literal dot in `example.com`)
- Hyphens at start/end of pattern groups: No escaping needed mid-pattern
- Pipes: `|` (alternation operator - should NOT be escaped)

### Examples

**Add Kubernetes cluster domain:**
```
kubernetes\.io|k8s\.io
```

**Add enterprise internal domain:**
```
example\.corp\.com|internal\.example\.com
```

**Add additional NTP pool:**
```
ntp\.ubuntu\.com|ntp\.debian\.org
```

---

## Other Tuning Points

### 1. DDNS Provider List (Line ~802)
- **Variable:** `$ddnsRx`
- **Purpose:** Identifies known DDNS providers (high indicator of C2 infrastructure)
- **Current patterns:** bounceme.net, serveminecraft.net, no-ip.*, dyndns.org, etc.
- **When to adjust:** Only if you observe legitimate use of DDNS in your environment
  - ⚠️ Very rare - DDNS is almost always suspicious in enterprise

### 2. C2 Beaconing Threshold (Line ~810)
- **Rule:** Domain queried by same process >= 5 times = "C2 Beaconing Pattern"
- **Current:** Configured as `>= 5`
- **When to adjust:** If you have high false positive rate for legitimate polling
  - Consider: Increase to 10+ for higher confidence, lower to 3+ for higher sensitivity

### 3. LOL Bins List (Line ~712)
- **Variable:** `$lolBinNames`
- **Purpose:** Known Living-off-the-Land Binaries that are commonly abused
- **Current:** mshta.exe, wscript.exe, cscript.exe, regsvr32.exe, etc.
- **When to adjust:** Only if you have legitimate use cases for these in process chains
  - ⚠️ Modifying this reduces security posture - consider testing before adding

---

## Testing Your Tuning

### 1. Verify the Whitelist Syntax
Run a quick regex test in PowerShell:
```powershell
$benignClassRx = '(?i)microsoft\.com|ocsp\.sectigo\.com'
"ocsp.sectigo.com" -match $benignClassRx  # Should be True
"evil-domain.com" -match $benignClassRx   # Should be False
```

### 2. Re-run Analysis
After updating the whitelists, re-run option 4b with the same detonation logs:
```powershell
Invoke-ElasticAlertAgentAnalysis -DetonationLogsDir "D:\path\to\logs"
```

### 3. Compare Reports
- Check the "NETWORK TRAFFIC CLASSIFICATION" section
- Verify that previously flagged legitimate domains are now categorized as BENIGN
- Confirm that actual C2 domains (Telegram, DDNS services, etc.) are still flagged

---

## Domain Classification Reference

When a domain is processed, it's categorized as:

| Category | Meaning | Example |
|----------|---------|---------|
| **BENIGN** | Whitelisted legitimate domain | ocsp.sectigo.com, windowsupdate |
| **DDNS/SUSPICIOUS** | Known DDNS provider (threat indicator) | attacker-c2.no-ip.org |
| **C2** | Confirmed C2 domain in threat intel | empire.github.io (backdoor C2) |
| **UNKNOWN** | Not whitelisted, not C2 | example.com |

---

## Recent Tuning Changes (2026-04-08)

Added legitimate domains to reduce false positives:

✅ **Certificate & OCSP Services**
- ocsp.sectigo.com, ocsp.verisign.com, ocsp.godaddy.com
- Let's Encrypt (letsencrypt.org, isrg.x3.letsencrypt)
- CRL endpoints (crl.*, pki.*)

✅ **Time Synchronization**
- NTP pools (ntp.org, time.nist.gov, pool.ntp.org)

✅ **Package Repositories**
- Ubuntu, Debian, Fedora, CentOS repos

✅ **Browser Infrastructure**
- Chrome update (chromeupdate, gvt1.com)
- Google CDN (gstatic.com, googleapis.com)

---

## Recommendations

1. **Weekly Review:** Check the "Suspicious DNS" section of offline analysis reports
2. **Document FPs:** When you find legitimate domains being flagged, add them immediately
3. **Threshold Review:** Every quarter, review DDNS and beaconing thresholds based on your environment
4. **Backup:** Before major tuning, commit your changes to git or save a backup

---

**Last Updated:** 2026-04-08  
**Contact:** Loaded Potato Security Analysis Team
