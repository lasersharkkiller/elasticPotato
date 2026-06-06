# calibration_samples/

Labeled detonation corpora for fidelity-index calibration (Phase 4 of
`Test-FidelityIndexCalibration`).

## Layout

Each immediate subdirectory is treated as one labeled corpus. A corpus may be
materialized in either of two ways:

1. **Inline corpus** - the subdirectory contains the NDJSON datasets directly
   (e.g. `windows.sysmon_operational.ndjson`, `system.security.ndjson`, ...).
   The calibration runner walks the directory as it always has.

2. **Pointer corpus** - the subdirectory contains a single `pointer.json` file
   that resolves to an external absolute path. This is the preferred layout for
   large detonation corpora that would otherwise bloat this repo.

   Pointer schema:

   ```json
   {
     "label": "COMPROMISED",
     "framework": "Sliver",
     "absolute_path": "C:\\githubProjects\\DetonationLogs\\C2Frameworks\\Sliver_...",
     "expected_verdict": "COMPROMISED",
     "datasets": ["windows.sysmon_operational.ndjson", "..."]
   }
   ```

   When `pointer.json` is present the runner ignores any sibling NDJSON files in
   the pointer directory and walks the resolved `absolute_path` instead.

## Currently staged

| Subdir   | Label        | Source                                                       |
|----------|--------------|--------------------------------------------------------------|
| Havoc/   | COMPROMISED  | C2Frameworks/Havoc_2026-05-28_16-50_to_16-54UTC              |
| Merlin/  | COMPROMISED  | C2Frameworks/Merlin_2026-05-28_16-33_to_16-36UTC             |
| Sliver/  | COMPROMISED  | C2Frameworks/Sliver_2026-05-28_16-12_to_16-17UTC             |

## Pilot-mode caveat

The default binding-gate floor is **20 corpora** (so a single disagreement still
sits under the 5% bar). With only 3 COMPROMISED corpora staged the calibration
runner will SKIP Phase 4 unless the caller passes `-MinCorpora 3`:

```powershell
Test-FidelityIndexCalibration -MinCorpora 3 -Verbose
```

Pilot mode weakens `calibration_passed` semantics (statistical confidence is
materially reduced). Stage additional corpora - **especially CLEAN-labeled
baselines** - before relying on the gate in production. A directory whose name
matches `clean|baseline|benign` (case-insensitive) is auto-labeled CLEAN.
