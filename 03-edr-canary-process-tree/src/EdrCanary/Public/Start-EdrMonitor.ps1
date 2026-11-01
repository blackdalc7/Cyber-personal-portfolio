function Start-EdrMonitor {
    <#
    .SYNOPSIS
        Runs the EDR canary: deploys decoys, consumes kernel ETW, maps the process tree, alerts and contains.
    .PARAMETER WatchPaths
        Directories that receive canary files. Defaults to EDR_WATCH_PATHS (semicolon separated).
    .PARAMETER Source
        Etw (default on Windows), Fallback (WMI + FileSystemWatcher), or Replay (with -ReplayPath).
    .PARAMETER AutoContain
        Suspend the offending process automatically. Off by default: detection without action is the safe default.
    .PARAMETER DurationSeconds
        Stop after this many seconds (0 = until Ctrl+C or the source ends).
    .EXAMPLE
        Start-EdrMonitor -WatchPaths C:\Share\Finance -AutoContain
    .EXAMPLE
        Start-EdrMonitor -Source Replay -ReplayPath .\tests\fixtures\maldoc_chain.ndjson -WatchPaths C:\Share
    #>
    [CmdletBinding()]
    param(
        [string[]]$WatchPaths,
        [ValidateSet('Etw', 'Fallback', 'Replay')][string]$Source = 'Etw',
        [string]$ReplayPath,
        [switch]$AutoContain,
        [int]$DurationSeconds = 0,
        [string]$EnvFile = (Join-Path (Get-Location) '.env'),
        [string]$OutputDir,
        [scriptblock]$Contain,
        [switch]$PassThru
    )
    [void](Import-EdrDotEnv -Path $EnvFile)
    $override = @{}
    if ($WatchPaths) { $override.WatchPaths = $WatchPaths }
    if ($OutputDir) { $override.OutputDir = $OutputDir }
    if ($AutoContain) { $override.AutoContain = $true }
    $settings = Get-EdrSettings -Override $override
    if (-not $settings.WatchPaths) { throw 'No watch paths: pass -WatchPaths or set EDR_WATCH_PATHS' }
    New-Item -ItemType Directory -Force -Path $settings.OutputDir | Out-Null

    $canaries = @{}
    foreach ($dir in $settings.WatchPaths) {
        foreach ($name in $settings.Canary.FileNames) {
            $c = New-EdrCanaryFile -Directory $dir -Name $name -Hidden
            $canaries[$c.Path] = $c.Sha256
        }
    }
    $ctxArgs = @{ Settings = $settings; Canaries = $canaries }
    if ($Contain) { $ctxArgs.Contain = $Contain }
    $ctx = New-EdrContext @ctxArgs

    $src = switch ($Source) {
        'Replay' { if (-not $ReplayPath) { throw '-ReplayPath is required with -Source Replay' }; New-EdrReplaySource -Path $ReplayPath }
        'Fallback' { New-EdrFallbackSource -Canaries $canaries }
        default {
            try { New-EdrEtwSource -Settings $settings }
            catch {
                Write-Warning "Kernel ETW unavailable ($($_.Exception.Message)); falling back to WMI + FileSystemWatcher."
                New-EdrFallbackSource -Canaries $canaries
            }
        }
    }
    if ($src.Kind -ne 'replay') { [void](Initialize-EdrProcessTable -Table $ctx.Table) }
    Write-Information ("EDR canary running: source={0}, canaries={1}, auto-contain={2}, alerts={3}" -f
        $src.Kind, $canaries.Count, $settings.AutoContain, $ctx.AlertPath) -InformationAction Continue

    $deadline = if ($DurationSeconds -gt 0) { [datetime]::UtcNow.AddSeconds($DurationSeconds) } else { [datetime]::MaxValue }
    $lastPrune = [datetime]::UtcNow
    $all = New-Object System.Collections.Generic.List[object]
    try {
        while ([datetime]::UtcNow -lt $deadline -and -not $src.IsCompleted()) {
            $evt = $src.Next(250)
            if ($null -eq $evt) { continue }
            foreach ($a in Invoke-EdrEvent -Context $ctx -EdrEvent $evt) {
                Write-Warning $a.message
                if ($PassThru) { $all.Add($a) }
            }
            if (([datetime]::UtcNow - $lastPrune).TotalSeconds -ge 30) {
                Clear-EdrProcessTable -Table $ctx.Table
                $lastPrune = [datetime]::UtcNow
            }
        }
    }
    finally {
        $src.Dispose()
        $summary = $ctx.Counters + @{ source = $src.Kind } + $src.Stats()
        Write-Information ("EDR canary stopped: {0}" -f ($summary | ConvertTo-Json -Compress)) -InformationAction Continue
    }
    if ($PassThru) {
        [pscustomobject]@{ Alerts = $all.ToArray(); Counters = $ctx.Counters; Canaries = $canaries; Context = $ctx }
    }
}
