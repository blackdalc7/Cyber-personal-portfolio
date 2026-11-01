<#
.SYNOPSIS
    Installs the pinned Microsoft.Diagnostics.Tracing.TraceEvent library into lib/traceevent.
.DESCRIPTION
    Thin wrapper over Install-EdrTraceEvent. The package hash is pinned in the module, so a
    substituted or tampered package is refused before it is extracted or loaded.
.EXAMPLE
    .\scripts\Install-TraceEvent.ps1
#>
[CmdletBinding(SupportsShouldProcess)]
param([string]$Destination)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\src\EdrCanary\EdrCanary.psd1') -Force
$installArgs = @{}
if ($Destination) { $installArgs.Destination = $Destination }
Install-EdrTraceEvent @installArgs -WhatIf:$WhatIfPreference
