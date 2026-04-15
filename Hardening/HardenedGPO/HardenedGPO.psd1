@{
    ModuleVersion     = '1.0.0'
    GUID              = 'c9f3e2a1-7d4b-4f6c-a2e1-3b8d5f9a2c4e'
    RootModule        = 'HardenedGPO.psm1'
    Author            = 'HardenedGPO Module'
    Description       = 'Generates pre-built, import-ready hardened GPO backups for Workstation, Server, and DomainController profiles. CIS/STIG-aligned. No scanning required.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('New-HardenedGPO','Import-HardenedGPO','Invoke-LocalHardening')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData = @{
        PSData = @{
            Tags = @('GPO','GroupPolicy','Hardening','CIS','STIG','ActiveDirectory','Workstation','Server','DomainController')
        }
    }
}
