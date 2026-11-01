#Requires -Version 5.1
Set-StrictMode -Version Latest

# EdrCanary module loader.
# Dot-sources every script in Private/ (internal helpers) and Public/ (commands), in name
# order, then exports only the public surface listed below. $script:ProjectRoot points at
# the project folder so commands can find config/rules.psd1 and .env without parameters.

$script:ModuleRoot = $PSScriptRoot
$script:ProjectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

foreach ($folder in 'Private', 'Public') {
    foreach ($file in Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot $folder) -Filter '*.ps1' | Sort-Object Name) {
        . $file.FullName
    }
}

Export-ModuleMember -Function @(
    'Start-EdrMonitor', 'Invoke-EdrEvent', 'New-EdrContext', 'New-EdrCanaryFile',
    'Suspend-EdrProcess', 'Resume-EdrProcess', 'Get-EdrForensicSnapshot', 'Assert-EdrContainmentAllowed',
    'Install-EdrTraceEvent', 'Get-EdrSettings', 'Import-EdrDotEnv',
    'Get-EdrProcessAncestry', 'Format-EdrAncestry', 'New-EdrReplaySource', 'ConvertTo-EdrEvent'
)
