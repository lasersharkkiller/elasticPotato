#Requires -Version 5.1
# HardenedGPO.psm1

Set-StrictMode -Version Latest

# Private helpers
foreach ($f in (Get-ChildItem "$PSScriptRoot\Private\*.ps1" -ErrorAction SilentlyContinue)) {
    try { . $f.FullName } catch { Write-Error "Failed loading $($f.Name): $_" }
}

# Public functions
$public = Get-ChildItem "$PSScriptRoot\Public\*.ps1" -ErrorAction SilentlyContinue
foreach ($f in $public) {
    try { . $f.FullName } catch { Write-Error "Failed loading $($f.Name): $_" }
}

Export-ModuleMember -Function $public.BaseName
