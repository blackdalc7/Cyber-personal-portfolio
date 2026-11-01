<#
.SYNOPSIS
    Replays a labelled NDJSON fixture and prints the process-tree verdict for every test case.
.DESCRIPTION
    Each ProcessStart line in the fixture may carry a "Case" label. Lines labelled "setup" only
    build the process tree (parents such as explorer.exe or wmiprvse.exe). For every other
    labelled line the script prints which rule fired, its severity and the command-line markers,
    or "no alert". Run it before and after a rule change to get a reviewable diff of behaviour.
    Replay only: no processes are started and nothing outside the temp output folder is written.
.EXAMPLE
    .\scripts\Invoke-RuleRegression.ps1
.EXAMPLE
    .\scripts\Invoke-RuleRegression.ps1 -Path tests/fixtures/encoded_powershell_cases.ndjson | Format-Table -AutoSize
#>
[CmdletBinding()]
param(
    [string]$Path = (Join-Path (Split-Path -Parent $PSScriptRoot) 'tests/fixtures/encoded_powershell_cases.ndjson')
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $projectRoot 'src/EdrCanary/EdrCanary.psd1') -Force

$out = Join-Path ([IO.Path]::GetTempPath()) "edr-regression-$([guid]::NewGuid())"
$settings = Get-EdrSettings -Override @{ OutputDir = $out; SiemHost = ''; AutoContain = $false }
$ctx = New-EdrContext -Settings $settings

try {
    foreach ($line in Get-Content -LiteralPath $Path) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $raw = $line | ConvertFrom-Json
        $edrEvent = [pscustomobject]@{
            Type = $raw.Type; TimeStamp = [datetime]$raw.TimeStamp; ProcessId = [int]$raw.ProcessId
            ParentProcessId = [int]$raw.ParentProcessId; ImageName = $raw.ImageName; CommandLine = $raw.CommandLine
        }
        $alerts = @(Invoke-EdrEvent -Context $ctx -EdrEvent $edrEvent)
        $case = if ($raw.PSObject.Properties['Case']) { $raw.Case } else { '' }
        if (-not $case -or $case -eq 'setup') { continue }
        if ($alerts.Count -eq 0) {
            [pscustomobject]@{ Case = $case; Pid = $edrEvent.ProcessId; Rule = '-'; Severity = 'no alert'; Markers = '' }
        }
        foreach ($a in $alerts) {
            $sev = @{ 21 = 'low'; 47 = 'medium'; 73 = 'high'; 99 = 'critical' }[[int]$a.event.severity]
            $markers = if ($a.Contains('edr') -and $a.edr.ContainsKey('markers')) { (@($a.edr.markers) -join ', ') } else { '' }
            [pscustomobject]@{ Case = $case; Pid = $edrEvent.ProcessId; Rule = $a.rule.id; Severity = $sev; Markers = $markers }
        }
    }
}
finally {
    Remove-Item -LiteralPath $out -Recurse -Force -ErrorAction SilentlyContinue
}
