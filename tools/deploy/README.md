Deployment scripts for offline remote staging:
- Deploy-UAC.ps1      (Linux SSH or Windows SMB)
- Deploy-KAPE.ps1     (Windows SMB)
- Deploy-DFIR-ORC.ps1 (Windows SMB)

All deploy scripts are offline-first and do not download internet content.
You must pre-stage the collector packages in the `tools` folder. Each deploy
script auto-discovers its package there:
- Deploy-KAPE.ps1     -> `tools/kape` (or `tools/KAPE`, `tools/kape.zip`, `tools/KAPE.zip`)

---

## Staging KAPE (`Get-KAPE-Offline.ps1`)

KAPE's core binaries (`kape.exe` / `gkape.exe`) are **Kroll's proprietary
software** — *"licensed, not sold"* under the [KAPE EULA](https://www.kroll.com/en/kape-license-agreement),
which forbids copying, redistributing, or transferring them. They are therefore
**git-ignored and must never be committed** to this public repo (see `.gitignore`:
`tools/kape`, `tools/KAPE`, `tools/kape.zip`, `tools/KAPE.zip`). Only the staging
helper and the ignore guard are tracked in git.

The MIT-licensed pieces — the KapeFiles Targets/Modules and Eric Zimmerman's EZ
Tools — *are* fetched automatically by the helper.

### Workflow (one carry, then fully offline)

1. **On an internet-connected Windows host**, download KAPE from
   <https://www.kroll.com/kape> (registration + EULA acceptance — the one step
   no script can do for you). You get a `KAPE.zip` or an extracted `KAPE\` folder.

2. **Build a complete offline KAPE tree** into `tools/kape`:
   ```powershell
   cd tools\deploy
   .\Get-KAPE-Offline.ps1 -KapeSource 'C:\path\to\KAPE.zip'
   ```
   The helper stages the Kroll binaries from your `-KapeSource`, then (best effort,
   needs internet):
   - runs `Get-KAPEUpdate.ps1` to update `kape.exe`,
   - runs `kape.exe --sync` to pull Targets/Modules from EricZimmerman/KapeFiles,
   - runs `Get-ZimmermanTools.ps1` to populate `Modules\bin` with the EZ Tools.

   It finishes with a `git check-ignore` self-check so a staged KAPE can never
   slip into a commit. Preview everything without touching disk/network with
   `-DryRun`.

3. **Carry the whole `elasticPotato` tree** to the air-gapped DFIR VM (removable
   media / robocopy). The git-ignored KAPE payload copies at the filesystem level
   — `.gitignore` only affects git, not file copies.

4. **On the VM**, run `elasticPotato_Main.ps1` → option **2b**. It auto-discovers
   `tools\kape` and pushes KAPE to your Windows targets over SMB (default
   `C:\IRTools\KAPE`) with zero internet calls.

### Common options

| Option | Purpose |
|--------|---------|
| `-KapeSource <path>` | Your Kroll-downloaded KAPE (folder with `kape.exe`, or a `.zip`). Required unless a KAPE already sits at the destination. |
| `-Destination <path>` | Where to stage (default `<repo>\tools\kape`). |
| `-NetVersion <0\|4\|6\|9>` | EZ Tools .NET flavor (default 9; 0 = all, nests under `net<n>` subfolders). |
| `-SyncUrl <url>` | Override the KapeFiles sync source (e.g. a fork's archive zip). |
| `-SkipKapeUpdate` / `-SkipSync` / `-SkipEZTools` | Skip an individual enrichment phase. |
| `-Force` | Overwrite an existing staged KAPE. |
| `-DryRun` | Print the plan without downloading or copying. |

If the EZ Tools phase fails (e.g. flaky network), KAPE still collects artifacts —
only the parsing Modules need those binaries. Retry later on the internet host with
KAPE's own module: `.\kape.exe --msource <dest> --mdest %TEMP%\null --module !!ToolSync --debug`.
