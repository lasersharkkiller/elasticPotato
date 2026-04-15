#Requires -Version 5.1
# ComplianceScan.psm1

foreach ($file in (Get-ChildItem "$PSScriptRoot\Private\*.ps1" -ErrorAction SilentlyContinue)) {
    try { . $file.FullName } catch { Write-Error "Failed loading $($file.Name): $_" }
}

$public = Get-ChildItem "$PSScriptRoot\Public\*.ps1" -ErrorAction SilentlyContinue
foreach ($file in $public) {
    try { . $file.FullName } catch { Write-Error "Failed loading $($file.Name): $_" }
}

Export-ModuleMember -Function $public.BaseName
