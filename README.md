# elasticPotato

Interactive PowerShell triage toolkit for security operations. Bridges live Elastic / Security Onion telemetry to offline forensic verdicts using a Bayesian, corpus-normalized fidelity index built from VirusTotal behavioral analyses.

Sister repo: [`statisticalDifferentialPotato`](https://github.com/lasersharkkiller/statisticalDifferentialPotato) — builds the `fidelity-index.json` this toolkit consumes.

---

## Menu at a glance

Launch: `.\elasticPotato_Main.ps1` — then pick an option.

### Group 1 — Remote Collection Tool Deployment

Push offline forensic collectors to hosts you don't have EDR on.

| Opt | Function | Notes |
|---|---|---|
| **1a** | Deploy [UAC Collector](https://github.com/tclahr/uac) to remote Linux host(s) | Runs `uac-<version>.tar.gz` from `.\tools\`; captures a full artefact snapshot |
| **1b** | Deploy [KAPE](https://www.kroll.com/en/services/cyber/incident-response-litigation-support/kroll-artifact-parser-extractor-kape) to remote Windows host(s) | Requires KAPE staged under `.\tools\kape\` (licensed binary) |
| **1c** | Deploy [DFIR-ORC](https://github.com/dfir-orc/dfir-orc) to remote Windows host(s) | Requires DFIR-ORC binaries under `.\tools\dfir-orc\` |
| **1d** | `Save-RouterDump` (live SSH) | Pulls ~75 forensic commands from a live router; ~15 vendor platforms auto-detected (Cisco IOS-XE / NX-OS / Junos / FortiOS / PAN-OS / MikroTik / SEL / TP-Link / GL.iNet / Linksys). Saves offline dump for `2c` |

### Group 2 — Linux / UAC Forensic Triage

Offline analysis of UAC dumps + edge-router captures. Rootkit detection, C2 attribution, credential-access scan, timeline, MITRE ATT&CK mapping.

| Opt | Function | Notes |
|---|---|---|
| **2a** | `Invoke-UACTriage` on an extracted UAC dump | Rootkit / C2 / credential / timeline / attribution rollup. Uses `apt/` intel from sibling repo if available |
| **2b** | Live SSH → Edge Router APT Triage | One-shot: pulls router dump AND runs full analysis in a single flow |
| **2c** | Offline Edge Router APT Triage on a saved dump directory | Same analysis as `2b` on air-gapped output from `1d` |

### Group 3 — Elastic Alert Triage 🔥

The core of the toolkit. Query an Elastic stack, pull a detonation window, produce a forensic verdict with kill-chain rollup and C2 framework attribution.

| Opt | Function | Notes |
|---|---|---|
| **3a** | **Pull + Triage** (recommended entry point) | Runs `3d` to pull logs, detects Windows vs Linux from filenames + `host.os.type` probe, dispatches to `3b` or `3c` automatically |
| **3b** | `Invoke-ElasticAlertAgentAnalysis` (offline Windows) | Reads NDJSON from `-DetonationLogsDir`; 60+ finding categories (masquerade / persistence / lateral / credential / C2 / process injection); Bayesian fidelity scoring; HTML report |
| **3c** | `Invoke-ElasticLinuxTriage` (offline Linux) | Auditd / auth / syslog / journald; MITRE ATT&CK coverage |
| **3d** | Pull Elastic logs from a detonation window | Prompts for start/end (accepts `8PM EST` / `2026-03-18 20:00 UTC` etc.). **Auto-detects Security Onion 3.0** by 302 probe → routes through SSH connector. Vanilla ES → direct HTTP with vault Basic/ApiKey auth |
| **3e** | Thor / Loki IOC + YARA scanner | Auto-detects which scanner is installed; runs against downloaded malicious files |
| **3f** | Offline analysis + IOC/YARA scan | Runs `3b` then `3e` in one pass |
| **3g** | `Update-LolDriversCache` | Refreshes `loldrivers.io` cache + LOLDrivers Sigma + SigmaHQ rules |
| **3h** | `Update-ElasticYaraRules` | Pulls latest `elastic/protections-artifacts` into `.\detections\yara\` |

### Group 4 — Elastic Baseline

Discover unusual processes / drivers in your environment.

| Opt | Function | Notes |
|---|---|---|
| **4a** | Baseline a specific process name | Enrich via VirusTotal / APIVoid / signer / signer chain / hash rarity |
| **4b** | New drivers in the environment | LOLDrivers matching + signer + last-30-day novelty |
| **4c** | New unverified processes | Broken / expired / self-signed |
| **4d** | New unsigned Windows processes | Prime hunting ground |
| **4e** | New unsigned Linux processes | Elastic Agent on Linux endpoints |

---

## Fidelity index v2

Every artefact scored via a Bayesian, corpus-normalized 3-axis model:

- **RiskScore** ∈ `[0,1]` = `1 − I_{0.5}(M+1, G·(Mtotal/Gtotal)+1)` — corpus-normalized posterior. `(M=47, G=1)` → ~0.9999. `(M=1, G=0)` → 0.75. `(M=47, G=47)` in 1:3.8 goodware-heavy corpus → ~0.79. `(M=0, G=47)` → ~0.
- **PMI** ∈ `[−1, +1]` = `tanh(log2((M+0.5)/(Mtotal+1)) − log2((G+0.5)/(Gtotal+1)) / 3)` — corpus-rarity independent axis
- **Confidence** ∈ `[0,1]` = `min(1, log10(M+G+1) / log10(p95_total[dim]+1))` — per-dimension volume, corpus-relative

**Verdict enable gate**: consumer refuses to use v2 scoring unless the calibration runner records `manifest.scoring.calibration_passed=true`. Pilot mode via `Test-FidelityIndexCalibration -MinCorpora 3` lowers the default 20-corpus floor.

Detection dimensions (19 per-field indices + manifest + flat compat shim):

`ip · dns · process · file · registry · sigma-rule · yara-rule · cert-status · cert-publisher · mitre-technique · service · scheduled-task · module-load · command-execution · mutex · pipe · win-api · vt-tag`

Cert dimensions use **status** (`SignedVerified | SelfSigned | Unsigned | SignedExpired | SignedRevoked | InvalidSignature | CatalogSigned`) and **publisher** (normalized CN) — thumbprints are too high-cardinality to score well.

---

## Elastic stack compatibility

Auto-detection at pull time:

| Stack | Detection | Auth | Data path |
|---|---|---|---|
| **Security Onion 3.0** (Kratos-fronted) | HTTP 302 → `/auth/self-service/login/browser` | SSH connector (`Save-TorchElasticDetonationLogs`) via `TORCH_SSH_Host` / `_User` / `_Pass` / `_KeyPath` | `sudo so-elasticsearch-query` on the SO manager |
| **Vanilla Elasticsearch** (self-managed / ECE / on-prem) | HTTP 200 on `/_cluster/health` | Basic (`Elastic_User` / `Elastic_Pass`) or ApiKey (`Elastic_ApiKey`) | Direct REST to `Elastic_URL` |
| **Elastic Cloud Serverless** | Detected via `X-elastic-product` header | ApiKey mandatory | REST (no SSH) |

The 3a orchestrator handles either capture format:
- **Dataset-named** files (`windows.sysmon_operational.ndjson`, `linux.auditd.ndjson`) from the SSH path
- **Category-named** files (`process_events.ndjson`, `network_events.ndjson`) from the HTTP path

---

## Vault secrets

PowerShell SecretManagement (`Microsoft.PowerShell.SecretStore`). Required:

| Secret | Purpose | Notes |
|---|---|---|
| `Elastic_URL` | Cluster endpoint | e.g. `https://elastic-lab:9200` (vanilla) or `https://so-host/elasticsearch` (SO 3.0 proxy) |
| `Elastic_ApiKey` OR `Elastic_User`+`Elastic_Pass` | Auth | ApiKey takes precedence when both are present |
| `Kibana_URL` | Kibana endpoint | Only used by `4b`-`4e` process baselining |
| `TORCH_SSH_Host` / `_User` / `_Pass` / `_KeyPath` | SO 3.0 SSH connector | Only used when the 302 probe fires. Safe to keep pointed at a decommissioned SO host — reactivates when it's back online |

Optional third-party enrichment keys:

`VT_API_Key_1/2` · `MalwareBazaar_AuthKey` · `ThreatFox_AuthKey` · `URLhaus_AuthKey` · `HybridAnalysis_API_Key` · `OTX_API_Key` · `APIVoid_API_Key` · `Intezer_API_Key` · `ThreatGrid_API_Key` · `Github_Access_Token`

Set with: `Set-Secret -Name '<name>' -Secret '<value>'`

---

## Detonation log importer

Replay historical detonations into a per-session Elastic index for Kibana browsing:

```powershell
Import-Module .\purpleTeaming\Push-DetonationLogsToElastic.psm1
Push-DetonationLogsToElastic -SourceDir '<path>' [-DryRun]
```

Auto-detects wrapped (`{_index, _source: {...}}`) vs flat NDJSON shape. Target index pattern `detonation-replay-<label>-<YYYYMMDD>` never collides with prod `logs-*` data streams. Preserves original `@timestamp` so Kibana shows the detonation in its real window.

Also see `.\output\import-existing-detonations.ps1` for a one-shot orchestrator over multiple corpora.

---

## Architecture

```
elasticPotato/
├── agentic/                     Elastic alert triage AI agents (3a/3b/3c/3f)
│   ├── ElasticAlertAgent.psm1       Windows offline analyzer (60+ findings)
│   ├── Invoke-ElasticLinuxTriage.psm1  Linux/UAC analyzer
│   └── Invoke-SigmaElasticScan.psm1 Sigma → Elastic query translator
├── purpleTeaming/               Detection engineering + capture
│   ├── GetElasticDetonationLogs.psm1        Vanilla ES puller (3d)
│   ├── Invoke-TorchElasticQuery.psm1        SO 3.0 SSH connector
│   ├── Push-DetonationLogsToElastic.psm1    Replay importer
│   └── elasticAlertsandThreats.psm1         Sigma / YARA / threat feed sync
├── NewProcsModules/             Baseline enrichment (4a-4e)
├── detections/                  Sigma / YARA / LOLDrivers rules
├── baseline/                    Loki / NSRL / VT baseline helpers
├── forensics/                   UAC + router triage engines (1d / 2a-2c)
├── output-baseline/             Fidelity indices (produced by sibling repo)
│   ├── fidelity-manifest.json       Manifest — scoring config + build_signature
│   ├── fidelity-index.json          Legacy flat compat shim
│   └── fidelity-<dim>.json          19 per-field indices
└── elasticPotato_Main.ps1       Interactive menu dispatcher
```

---

## Requirements

- PowerShell 7+ (5.1 works with degraded performance)
- Modules: `Microsoft.PowerShell.SecretManagement` · `Microsoft.PowerShell.SecretStore` · `Posh-SSH` (for SO 3.0 + router)
- Optional: `powershell-yaml` (Sigma), `PSSQLite` (some enrichment), `sigma-cli` + Elastic backend

Install helpers:

```powershell
Install-Module -Name Microsoft.PowerShell.SecretManagement, Microsoft.PowerShell.SecretStore -Scope CurrentUser -Force
Install-Module -Name Posh-SSH -Scope CurrentUser -Force
Register-SecretVault -Name LocalSecrets -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault
```

---

## Contributing

Every module ships with a comment-help block explaining its Elastic query shape, its expected input NDJSON schema, and its scoring contract. Add findings to `ElasticAlertAgent.psm1` by extending the `Add-FidelityHit` pipeline with a `-Dimension` matching one of the 19 fidelity dimensions.

## License

See LICENSE.
