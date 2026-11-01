@{
    RootModule           = 'EdrCanary.psm1'
    ModuleVersion        = '1.0.0'
    GUID                 = '7b3c2f0e-8d4a-4c61-9a4e-2f6b9e1d5a37'
    Author               = 'blackdalc'
    Description          = 'Ransomware canary with kernel ETW file/disk I/O monitoring, parent-child process tree anomaly detection and safe containment.'
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    FunctionsToExport    = @(
        'Start-EdrMonitor', 'Invoke-EdrEvent', 'New-EdrContext', 'New-EdrCanaryFile',
        'Suspend-EdrProcess', 'Resume-EdrProcess', 'Get-EdrForensicSnapshot', 'Assert-EdrContainmentAllowed',
        'Install-EdrTraceEvent', 'Get-EdrSettings', 'Import-EdrDotEnv',
        'Get-EdrProcessAncestry', 'Format-EdrAncestry', 'New-EdrReplaySource', 'ConvertTo-EdrEvent'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{ PSData = @{ Tags = @('EDR', 'ETW', 'Ransomware', 'DFIR', 'BlueTeam'); LicenseUri = 'https://opensource.org/licenses/MIT' } }
}
