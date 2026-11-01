<#
.SYNOPSIS
    Benign lab simulation that exercises every detection without any malicious behaviour.
.DESCRIPTION
    Two modes:

    Replay (default, any OS)
        Feeds tests/fixtures/maldoc_ransomware_chain.ndjson (WINWORD -> cmd -enc -> powershell
        -enc, then mass file writes, a .lockbit artefact and a canary write) through the full
        pipeline and prints which rules fired. No processes are started and no files outside
        the lab directory are touched.

    Live (Windows, run while Start-EdrCanary.ps1 is watching -LabPath)
        Starts a child PowerShell (no -EncodedCommand, no network) that writes plain text
        files into the lab directory fast enough to trip EDR-RW-001, then appends a line to
        the canary to trip EDR-CN-001. Nothing is encrypted, deleted or exfiltrated. The
        lab directory is removed afterwards unless -Keep is given.
.EXAMPLE
    .\scripts\Invoke-SafeSimulation.ps1
.EXAMPLE
    .\scripts\Invoke-SafeSimulation.ps1 -Mode Live -LabPath C:\EdrLab
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('Replay', 'Live')][string]$Mode = 'Replay',
    [string]$LabPath = (Join-Path ([IO.Path]::GetTempPath()) 'edr-lab'),
    [int]$FileCount = 40,
    [switch]$Keep
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $projectRoot 'src/EdrCanary/EdrCanary.psd1') -Force

if ($Mode -eq 'Replay') {
    $fixture = Join-Path $projectRoot 'tests/fixtures/maldoc_ransomware_chain.ndjson'
    $out = Join-Path $LabPath 'out'
    # The fixture was recorded on a host whose canary lived at C:\Share\Finance (seen by the kernel
    # as \Device\HarddiskVolume3\Share\Finance), so that path is registered as the canary here.
    $settings = Get-EdrSettings -Override @{ OutputDir = $out; SiemHost = ''; AutoContain = $false }
    New-Item -ItemType Directory -Force -Path $out | Out-Null
    $ctx = New-EdrContext -Settings $settings -Canaries @{ 'C:\Share\Finance\0_passwords.docx' = 'replay' }
    $src = New-EdrReplaySource -Path $fixture
    $alerts = @(while (-not $src.IsCompleted()) { Invoke-EdrEvent -Context $ctx -EdrEvent $src.Next(0) })
    $src.Dispose()
    $rows = foreach ($id in @($alerts | ForEach-Object { $_.rule.id } | Sort-Object -Unique)) {
        $group = @($alerts | Where-Object { $_.rule.id -eq $id })
        [pscustomobject]@{ Rule = $id; Name = $group[0].rule.name; Count = $group.Count; Severity = $group[0].event.severity }
    }
    $rows | Format-Table -AutoSize | Out-String -Width 160 | Write-Host
    Write-Information "Alerts written to $(Join-Path $out 'alerts.ndjson')" -InformationAction Continue
    if (-not $Keep) { Remove-Item -LiteralPath $LabPath -Recurse -Force -ErrorAction SilentlyContinue }
    return
}

if (-not ($PSVersionTable.PSEdition -eq 'Desktop' -or $IsWindows)) { throw 'Live mode needs Windows; use -Mode Replay elsewhere.' }
$full = [IO.Path]::GetFullPath($LabPath)
if ($full -match '^[A-Za-z]:\\?$' -or $full -like "$env:SystemRoot*") { throw "Refusing to use $full as a lab directory" }
if (-not $PSCmdlet.ShouldProcess($full, "Write $FileCount benign files and touch the canary")) { return }
New-Item -ItemType Directory -Force -Path $full | Out-Null
$canary = Join-Path $full '0_passwords.docx'
if (-not (Test-Path -LiteralPath $canary)) {
    Write-Warning "No canary at $canary. Start the monitor first: .\scripts\Start-EdrCanary.ps1 -WatchPaths '$full'"
}
$child = @"
`$ErrorActionPreference = 'Stop'
1..$FileCount | ForEach-Object { [IO.File]::WriteAllText((Join-Path '$full' ("sim_{0:D3}.txt" -f `$_)), 'benign simulation file') }
if (Test-Path -LiteralPath '$canary') { Add-Content -LiteralPath '$canary' -Value 'simulation touch' }
"@
$exe = (Get-Process -Id $PID).Path
$proc = Start-Process -FilePath $exe -ArgumentList @('-NoLogo', '-NoProfile', '-Command', $child) -PassThru -Wait -WindowStyle Hidden
Write-Information "Simulation child PID $($proc.Id) exited with $($proc.ExitCode). Expect EDR-RW-001 and EDR-CN-001 for that PID." -InformationAction Continue
if (-not $Keep) {
    Start-Sleep -Seconds 2
    Get-ChildItem -LiteralPath $full -Filter 'sim_*.txt' | Remove-Item -Force
}
