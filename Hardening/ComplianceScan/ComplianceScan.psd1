@{
    ModuleVersion     = '1.0.0'
    GUID              = 'b7e4d2f1-9a3c-4e8b-b1f5-2d7a9c3e6f8b'
    RootModule        = 'ComplianceScan.psm1'
    Author            = 'ComplianceScan Module'
    Description       = 'Read-only security compliance scanner for Windows endpoints. Evaluates Workstation, Server, and Domain Controller configurations against CIS/STIG baselines.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Invoke-ComplianceScan','Export-ScanReport','Invoke-CISScan','Export-CISScanReport','Invoke-CMMCScan','Export-CMMCScanReport','Invoke-NIST800171Scan','Export-NIST800171Report')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData = @{
        PSData = @{
            Tags = @('Compliance','Audit','CIS','STIG','Security','Workstation','Server','DomainController')
        }
    }
}
