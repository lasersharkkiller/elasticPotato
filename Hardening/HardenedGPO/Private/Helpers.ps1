function Write-Pass { param([string]$m) Write-Host "[PASS] $m" -ForegroundColor Green  }
function Write-Fail { param([string]$m) Write-Host "[FAIL] $m" -ForegroundColor Red    }
function Write-Warn { param([string]$m) Write-Host "[WARN] $m" -ForegroundColor Yellow }
function Write-Info { param([string]$m) Write-Host "[INFO] $m" -ForegroundColor DarkCyan   }
