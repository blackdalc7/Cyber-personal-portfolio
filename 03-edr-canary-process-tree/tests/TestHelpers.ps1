# Dot-sourced by every test file.
$script:ProjectRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $script:ProjectRoot 'src/EdrCanary/EdrCanary.psd1') -Force

function New-TestSettings {
    param([string]$OutputDir = (Join-Path $TestDrive 'out'), [hashtable]$Override = @{})
    $o = @{ OutputDir = $OutputDir; SiemHost = ''; AutoContain = $false }
    foreach ($k in $Override.Keys) { $o[$k] = $Override[$k] }
    Get-EdrSettings -Override $o
}

function New-TestEvent {
    param([string]$Type, [int]$ProcessId, [int]$ParentProcessId = 0, [string]$ImageName = '', [string]$CommandLine = '',
          [string]$FilePath = '', [double]$Offset = 0)
    [pscustomobject]@{
        Type = $Type; TimeStamp = ([datetime]'2026-10-26T09:00:00Z').ToUniversalTime().AddSeconds($Offset)
        ProcessId = $ProcessId; ParentProcessId = $ParentProcessId; ImageName = $ImageName
        CommandLine = $CommandLine; FilePath = $FilePath; Size = 0
    }
}
