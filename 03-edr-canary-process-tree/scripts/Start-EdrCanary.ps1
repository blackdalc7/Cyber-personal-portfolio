<#
.SYNOPSIS
    Entry point for running the EDR canary as an elevated console job or a scheduled task.
.DESCRIPTION
    Loads .env, checks for elevation when the kernel ETW source is requested (the NT Kernel
    Logger session needs administrator rights), then runs Start-EdrMonitor. All settings come
    from EDR_* environment variables; the parameters below override them for one run.
.EXAMPLE
    .\scripts\Start-EdrCanary.ps1 -WatchPaths 'C:\Share\Finance','D:\Projects'
.EXAMPLE
    .\scripts\Start-EdrCanary.ps1 -Source Replay -ReplayPath .\tests\fixtures\maldoc_ransomware_chain.ndjson -WatchPaths "$env:TEMP\edr-lab"
#>
[CmdletBinding()]
param(
    [string[]]$WatchPaths,
    [ValidateSet('Etw', 'Fallback', 'Replay')][string]$Source = 'Etw',
    [string]$ReplayPath,
    [switch]$AutoContain,
    [int]$DurationSeconds = 0,
    [string]$EnvFile = (Join-Path (Split-Path -Parent $PSScriptRoot) '.env')
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\src\EdrCanary\EdrCanary.psd1') -Force

if ($Source -eq 'Etw') {
    if (-not ($PSVersionTable.PSEdition -eq 'Desktop' -or $IsWindows)) { throw 'Kernel ETW needs Windows. Use -Source Replay on other platforms.' }
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Kernel ETW needs an elevated session (the NT Kernel Logger is administrator-only).'
    }
}

$monitorArgs = @{ Source = $Source; DurationSeconds = $DurationSeconds; EnvFile = $EnvFile }
if ($WatchPaths) { $monitorArgs.WatchPaths = $WatchPaths }
if ($ReplayPath) { $monitorArgs.ReplayPath = $ReplayPath }
if ($AutoContain) { $monitorArgs.AutoContain = $true }
Start-EdrMonitor @monitorArgs
