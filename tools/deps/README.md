# Offline dependency staging

`Get-Dependencies-Offline.ps1` stages the elasticPotato toolkit's **own runtime
dependencies** for an air-gapped analysis VM — the same download-once-carry-over
pattern as [../deploy/Get-KAPE-Offline.ps1](../deploy/Get-KAPE-Offline.ps1), but for
the things the toolkit needs to *run* (not the collector packages it deploys).

It is wired to menu **Group 1 → `1a) Download Dependencies`**.

## Two modes

```powershell
# 1. On an INTERNET-connected host — fetch everything into tools\deps\
.\Get-Dependencies-Offline.ps1 -Mode Download -IncludeTools

# 2. Carry the whole elasticPotato tree to the air-gapped VM, then:
.\Get-Dependencies-Offline.ps1 -Mode Install -IncludeTools
```

Run with no `-Mode` and it prompts. Use `-DryRun` to preview without touching disk/network.

**Download** stages into `tools\deps\` (git-ignored):
- `psmodules\` — `Save-Module` from PSGallery
- `pip\` — `pip download` wheels
- `tools\` — redistributable release binaries (with `-IncludeTools`)

**Install** distributes them on the offline VM: copies the modules into your
PowerShell module path, `pip install --no-index` the wheels, places the tools where
the toolkit looks for them, and offers to register the `LocalSecrets` SecretStore vault.

## What it stages

| Dependency | Kind | License | Hard? | Notes |
|---|---|---|---|---|
| Microsoft.PowerShell.SecretManagement | PS module | MIT | **yes** | `Get-Secret` — used everywhere |
| Microsoft.PowerShell.SecretStore | PS module | MIT | **yes** | encrypted vault backend |
| Posh-SSH | PS module | MIT | no | SSH transport; `ssh.exe` is the fallback |
| PSSQLite | PS module | MIT | no | NSRL SQLite enrichment path |
| powershell-yaml | PS module | Apache-2.0 | no | declared for Sigma; not currently called |
| sigma-cli + pysigma-backend-elasticsearch | pip | LGPL-2.1 | no | Sigma→Elastic conversion (needs Python) |
| YARA (`yara64.exe`) | tool | BSD-3 | no | `-IncludeTools` → `codeScanning\` |
| OpenSSF Scorecard | tool | Apache-2.0 | no | `-IncludeTools` → `codeScanning\` |
| Loki | tool | GPL-3.0 | no | `-IncludeTools` → `tools\loki\` |
| UAC | collector | Apache-2.0 | no | `-IncludeTools` → `tools\` (Deploy-UAC / 2a) |
| DFIR-ORC | collector | LGPL-2.1 | no | `-IncludeTools` → `tools\` (Deploy-DFIR-ORC / 2c) |

## NOT handled automatically (guidance only)

- **KAPE** — proprietary Kroll EULA; use [../deploy/Get-KAPE-Offline.ps1](../deploy/Get-KAPE-Offline.ps1).
- **THOR / THOR Lite** — Nextron registration required; place `thor*.exe` under `.\tools`.
- **Python / Git / 7-Zip / OpenSSH client** — vendor installers or Windows optional features.
- **VirusTotal / abuse.ch / OTX / Hybrid-Analysis** — live APIs, cannot be bundled. Set the
  API-key secrets and pre-run enrichment online (results cache under `output-baseline\`).

Everything staged is git-ignored (`tools/deps/*`, plus the tool destinations) so it never
enters this public repo; only this README and the helper script are tracked.
