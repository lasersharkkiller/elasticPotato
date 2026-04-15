# -- Private helpers for ComplianceScan ---------------------------------------

function Write-Pass { param([string]$m) Write-Host "[PASS] $m" -ForegroundColor Green  }
function Write-Fail { param([string]$m) Write-Host "[FAIL] $m" -ForegroundColor Red    }
function Write-Warn { param([string]$m) Write-Host "[WARN] $m" -ForegroundColor Yellow }
function Write-Info { param([string]$m) Write-Host "[INFO] $m" -ForegroundColor DarkCyan   }
function Write-Section { param([string]$m) Write-Host "`n--- $m ---" -ForegroundColor Magenta }

function New-FindingList {
    return [System.Collections.Generic.List[PSCustomObject]]::new()
}

function Add-Finding {
    param(
        [System.Collections.Generic.List[PSCustomObject]]$List,
        [string]$Category,
        [string]$Setting,
        [string]$CurrentValue,
        [string]$RecommendedValue,
        [ValidateSet("Pass","Fail","Warn","Info")][string]$Status,
        [string]$Reference = "",
        [string]$Profile   = "All"
    )
    $List.Add([PSCustomObject]@{
        Profile          = $Profile
        Category         = $Category
        Setting          = $Setting
        CurrentValue     = $CurrentValue
        RecommendedValue = $RecommendedValue
        Status           = $Status
        Reference        = $Reference
    })
    $label = if ($Profile -ne "All") { "[$Profile] " } else { "" }
    switch ($Status) {
        "Pass" { Write-Pass "$label$Category | $Setting" }
        "Fail" { Write-Fail "$label$Category | $Setting = $CurrentValue  (expected: $RecommendedValue)" }
        "Warn" { Write-Warn "$label$Category | $Setting = $CurrentValue  (recommended: $RecommendedValue)" }
        "Info" { Write-Info "$label$Category | $Setting = $CurrentValue" }
    }
}

function Get-NetAccountsValue {
    param([string[]]$Output, [string]$Label)
    ($Output | Where-Object { $_ -match $Label }) -replace ".*:\s*", "" | ForEach-Object { $_.Trim() }
}

function Test-RegistrySetting {
    param(
        [System.Collections.Generic.List[PSCustomObject]]$List,
        [string]$Path,
        [string]$Name,
        $Expected,
        [string]$Description,
        [string]$Reference,
        [string]$Profile = "All"
    )
    try {
        $val = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
        $st  = if ($val -eq $Expected) { "Pass" } else { "Fail" }
        Add-Finding $List -Category "Registry" -Setting $Description `
            -CurrentValue "$val" -RecommendedValue "$Expected" -Status $st -Reference $Reference -Profile $Profile
    } catch {
        Add-Finding $List -Category "Registry" -Setting $Description `
            -CurrentValue "NOT SET" -RecommendedValue "$Expected" -Status "Fail" -Reference $Reference -Profile $Profile
    }
}
