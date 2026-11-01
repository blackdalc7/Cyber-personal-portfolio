<#
    Event sources all expose the same shape, so the detection loop is identical whether
    events come from the kernel, a recorded replay, or the degraded fallback:

        $src.Kind           'etw' | 'replay' | 'fallback'
        $src.Next(<ms>)     next normalised event, or $null on timeout
        $src.IsCompleted()  $true once the source can produce no more events
        $src.Stats()        hashtable of counters
        $src.Dispose()      releases the kernel session / watchers
#>

$script:EventTypes = @('ProcessStart', 'ProcessStop', 'FileCreate', 'FileWrite', 'FileRename', 'FileDelete', 'DiskWrite')

function ConvertTo-EdrEvent {
    <# Normalises a dictionary / PSObject from any source into the canonical event shape. #>
    [CmdletBinding()]
    param([Parameter(Mandatory, ValueFromPipeline)]$InputObject)
    process {
        $get = {
            param($name)
            if ($InputObject -is [System.Collections.IDictionary]) { return $InputObject[$name] }
            $prop = $InputObject.PSObject.Properties[$name]
            if ($prop) { return $prop.Value }
            return $null
        }
        $type = [string](& $get 'Type')
        if ($type -notin $script:EventTypes) { return }
        $ts = & $get 'TimeStamp'
        $stamp = if ($ts -is [datetime]) { $ts.ToUniversalTime() }
                 elseif ($ts) { [datetime]::Parse([string]$ts, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal) }
                 else { [datetime]::UtcNow }
        [pscustomobject]@{
            Type            = $type
            TimeStamp       = $stamp
            ProcessId       = [int](& $get 'ProcessId')
            ParentProcessId = [int](& $get 'ParentProcessId')
            ImageName       = [string](& $get 'ImageName')
            CommandLine     = [string](& $get 'CommandLine')
            FilePath        = [string](& $get 'FilePath')
            Size            = [int64](& $get 'Size')
        }
    }
}

function New-EdrReplaySource {
    <#
    .SYNOPSIS
        Replays recorded events (NDJSON, one event per line) through the live detection loop.
    .DESCRIPTION
        Used for regression tests, purple-team rehearsal and incident reconstruction: export
        events from a capture once, then replay them deterministically on any OS.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "Replay file not found: $Path" }
    $queue = New-Object System.Collections.Generic.Queue[object]
    $bad = 0
    foreach ($line in [IO.File]::ReadLines((Resolve-Path -LiteralPath $Path).ProviderPath)) {
        if (-not $line.Trim()) { continue }
        try { $evt = $line | ConvertFrom-Json | ConvertTo-EdrEvent } catch { $bad++; continue }
        if ($evt) { $queue.Enqueue($evt) } else { $bad++ }
    }
    $src = [pscustomobject]@{ Kind = 'replay'; Queue = $queue; Malformed = $bad; Served = 0 }
    $src | Add-Member -MemberType ScriptMethod -Name Next -Value {
        param([int]$TimeoutMs)
        if ($this.Queue.Count -eq 0) { return $null }
        $this.Served++
        return $this.Queue.Dequeue()
    }
    $src | Add-Member -MemberType ScriptMethod -Name IsCompleted -Value { $this.Queue.Count -eq 0 }
    $src | Add-Member -MemberType ScriptMethod -Name Stats -Value { @{ served = $this.Served; malformed = $this.Malformed; remaining = $this.Queue.Count } }
    $src | Add-Member -MemberType ScriptMethod -Name Dispose -Value { $this.Queue.Clear() }
    return $src
}

function Import-EdrTraceEvent {
    <# Loads TraceEvent and compiles the C# kernel consumer (once per session). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$LibraryPath)
    if ('EdrCanary.EtwKernelConsumer' -as [type]) { return }
    $te = Join-Path $LibraryPath 'Microsoft.Diagnostics.Tracing.TraceEvent.dll'
    $fs = Join-Path $LibraryPath 'Microsoft.Diagnostics.FastSerialization.dll'
    if (-not (Test-Path -LiteralPath $te)) {
        throw "TraceEvent not found in $LibraryPath. Run scripts/Install-TraceEvent.ps1 (verifies a pinned SHA-256)."
    }
    Add-Type -LiteralPath $fs, $te
    $source = Get-Content -Raw -LiteralPath (Join-Path $script:ModuleRoot 'Native/EtwKernelConsumer.cs')
    $refs = @($te, $fs)
    if ($PSVersionTable.PSEdition -eq 'Core') {
        $refs += @('System.Collections', 'System.Collections.Concurrent', 'System.Threading', 'System.Threading.Thread', 'netstandard')
    }
    else {
        $refs += @('System.Core', ([System.Reflection.Assembly]::Load('netstandard, Version=2.0.0.0, Culture=neutral, PublicKeyToken=cc7b13ffcd2ddd51')).Location)
    }
    Add-Type -TypeDefinition $source -ReferencedAssemblies $refs
}

function New-EdrEtwSource {
    <#
    .SYNOPSIS
        Starts a real-time kernel ETW session (process + file I/O + disk I/O).
    .DESCRIPTION
        Requires Windows and an elevated session. Events come from the kernel's own
        instrumentation, so user-mode tampering (API unhooking, direct syscalls) does not
        hide them, and every file operation carries the PID that issued it.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Settings)
    if (-not (Test-EdrIsWindows)) { throw 'Kernel ETW is only available on Windows' }
    Import-EdrTraceEvent -LibraryPath $Settings.TraceEventPath
    if (-not [EdrCanary.EtwKernelConsumer]::IsElevated()) { throw 'Kernel ETW sessions require an elevated (Administrator) session' }
    $consumer = New-Object EdrCanary.EtwKernelConsumer -ArgumentList $Settings.QueueCapacity
    $consumer.Start($true, [bool]$Settings.IncludeDiskIo)
    $src = [pscustomobject]@{ Kind = 'etw'; Consumer = $consumer }
    $src | Add-Member -MemberType ScriptMethod -Name Next -Value {
        param([int]$TimeoutMs)
        $raw = $this.Consumer.Take($TimeoutMs)
        if ($null -eq $raw) { return $null }
        return ConvertTo-EdrEvent -InputObject $raw
    }
    $src | Add-Member -MemberType ScriptMethod -Name IsCompleted -Value { $this.Consumer.IsCompleted }
    $src | Add-Member -MemberType ScriptMethod -Name Stats -Value {
        @{ received = $this.Consumer.Received; dropped = $this.Consumer.Dropped; error = $this.Consumer.LastError }
    }
    $src | Add-Member -MemberType ScriptMethod -Name Dispose -Value { $this.Consumer.Dispose() }
    return $src
}

function New-EdrFallbackSource {
    <#
    .SYNOPSIS
        Degraded mode when TraceEvent is unavailable: WMI process-start traces + FileSystemWatcher on canaries.
    .DESCRIPTION
        Win32_ProcessStartTrace is itself fed by the kernel process provider, so the process
        tree keeps working. File events lose the PID (FileSystemWatcher cannot attribute), so
        canary trips are reported with ProcessId 0 and containment is skipped.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Canaries)
    if (-not (Test-EdrIsWindows)) { throw 'The WMI fallback source is only available on Windows' }
    $queue = [System.Collections.Concurrent.ConcurrentQueue[object]]::new()
    $subs = @()
    $subs += Register-CimIndicationEvent -ClassName Win32_ProcessStartTrace -SourceIdentifier "EdrCanary.Proc.$([guid]::NewGuid())" `
        -MessageData $queue -Action {
            $e = $Event.SourceEventArgs.NewEvent
            $Event.MessageData.Enqueue(@{ Type = 'ProcessStart'; TimeStamp = [datetime]::UtcNow; ProcessId = [int]$e.ProcessID
                                          ParentProcessId = [int]$e.ParentProcessID; ImageName = $e.ProcessName; CommandLine = '' })
        }
    $watchers = @()
    foreach ($canary in $Canaries.Keys) {
        $w = New-Object System.IO.FileSystemWatcher -ArgumentList (Split-Path -Parent $canary), (Split-Path -Leaf $canary)
        $w.NotifyFilter = [IO.NotifyFilters]'LastWrite, FileName, Size'
        $w.EnableRaisingEvents = $true
        $watchers += $w
        foreach ($name in 'Changed', 'Renamed', 'Deleted') {
            $subs += Register-ObjectEvent -InputObject $w -EventName $name -MessageData $queue -Action {
                $type = @{ Changed = 'FileWrite'; Renamed = 'FileRename'; Deleted = 'FileDelete' }[[string]$Event.SourceEventArgs.ChangeType]
                $path = if ($Event.SourceEventArgs.OldFullPath) { $Event.SourceEventArgs.OldFullPath } else { $Event.SourceEventArgs.FullPath }
                $Event.MessageData.Enqueue(@{ Type = $type; TimeStamp = [datetime]::UtcNow; ProcessId = 0; FilePath = $path })
            }
        }
    }
    $src = [pscustomobject]@{ Kind = 'fallback'; Queue = $queue; Subscriptions = $subs; Watchers = $watchers }
    $src | Add-Member -MemberType ScriptMethod -Name Next -Value {
        param([int]$TimeoutMs)
        $deadline = [datetime]::UtcNow.AddMilliseconds($TimeoutMs)
        do {
            $item = $null
            if ($this.Queue.TryDequeue([ref]$item)) { return ConvertTo-EdrEvent -InputObject $item }
            Start-Sleep -Milliseconds 50
        } while ([datetime]::UtcNow -lt $deadline)
        return $null
    }
    $src | Add-Member -MemberType ScriptMethod -Name IsCompleted -Value { $false }
    $src | Add-Member -MemberType ScriptMethod -Name Stats -Value { @{ queued = $this.Queue.Count } }
    $src | Add-Member -MemberType ScriptMethod -Name Dispose -Value {
        foreach ($s in $this.Subscriptions) { Unregister-Event -SourceIdentifier $s.Name -ErrorAction SilentlyContinue; Remove-Job -Id $s.Id -Force -ErrorAction SilentlyContinue }
        foreach ($w in $this.Watchers) { $w.EnableRaisingEvents = $false; $w.Dispose() }
    }
    return $src
}
