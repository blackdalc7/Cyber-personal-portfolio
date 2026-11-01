function Assert-EdrContainmentAllowed {
    <#
    .SYNOPSIS
        Throws unless it is safe to freeze the given process.
    .DESCRIPTION
        Suspending csrss/lsass/services hangs or bug-checks the machine, and suspending the
        monitor itself would blind the sensor. Both are refused whatever the detection says.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][int]$ProcessId, [string]$ImageName = '', [Parameter(Mandatory)][hashtable]$Settings)
    $name = Get-EdrImageName $ImageName
    $protectedNames = @($Settings.Containment.ProtectedNames | ForEach-Object { $_.ToLowerInvariant() })
    if ($ProcessId -in $Settings.Containment.ProtectedPids) { throw "Refusing to contain protected PID $ProcessId" }
    if ($name -and ($protectedNames -contains $name -or $protectedNames -contains ($name -replace '\.exe$', ''))) {
        throw "Refusing to contain protected system process '$name' (PID $ProcessId)"
    }
    if ($ProcessId -eq $PID) { throw "Refusing to contain the monitor's own process (PID $PID)" }
}

function Initialize-EdrThreadControl {
    <# Compiles the kernel32 OpenThread/SuspendThread/ResumeThread/CloseHandle P/Invoke signatures once per session. #>
    if ('EdrCanary.ThreadControl' -as [type]) { return }
    Add-Type -Namespace 'EdrCanary' -Name 'ThreadControl' -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
public static extern System.IntPtr OpenThread(uint access, bool inherit, uint threadId);
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
public static extern uint SuspendThread(System.IntPtr hThread);
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
public static extern int ResumeThread(System.IntPtr hThread);
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
public static extern bool CloseHandle(System.IntPtr hObject);
public const uint THREAD_SUSPEND_RESUME = 0x0002;
'@
}

function Set-EdrThreadState {
    <# Suspends or resumes every thread of a process with the documented kernel32 thread APIs. #>
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory)][int]$ProcessId, [Parameter(Mandatory)][ValidateSet('Suspend', 'Resume')][string]$State)
    if (-not (Test-EdrIsWindows)) { throw 'Thread suspension is only available on Windows' }
    Initialize-EdrThreadControl
    $proc = Get-Process -Id $ProcessId -ErrorAction Stop
    $affected = 0
    foreach ($t in $proc.Threads) {
        $h = [EdrCanary.ThreadControl]::OpenThread([EdrCanary.ThreadControl]::THREAD_SUSPEND_RESUME, $false, [uint32]$t.Id)
        if ($h -eq [IntPtr]::Zero) { continue }
        try {
            $rc = if ($State -eq 'Suspend') { [EdrCanary.ThreadControl]::SuspendThread($h) } else { [EdrCanary.ThreadControl]::ResumeThread($h) }
            if ($rc -ne [uint32]::MaxValue -and $rc -ne -1) { $affected++ }
        }
        finally { [void][EdrCanary.ThreadControl]::CloseHandle($h) }
    }
    return $affected
}

function Get-EdrForensicSnapshot {
    <# Metadata-only triage record (image, hash, command line, parent, owner, modules). No memory is read. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][int]$ProcessId)
    $cim = Get-CimInstance Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction SilentlyContinue
    $proc = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    $image = if ($cim) { $cim.ExecutablePath } elseif ($proc) { $proc.Path } else { $null }
    $sha256 = $null
    if ($image -and (Test-Path -LiteralPath $image)) {
        $sha256 = (Get-FileHash -LiteralPath $image -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
    }
    $owner = $null
    if ($cim) {
        $o = Invoke-CimMethod -InputObject $cim -MethodName GetOwner -ErrorAction SilentlyContinue
        if ($o -and $o.User) { $owner = "$($o.Domain)\$($o.User)" }
    }
    $modules = @()
    if ($proc) {
        try { $modules = @($proc.Modules | Select-Object -First 50 | ForEach-Object { $_.FileName }) }
        catch { $modules = @('<access denied: run elevated for the module list>') }
    }
    [ordered]@{
        collected_utc  = [datetime]::UtcNow.ToString('o')
        host           = [Environment]::MachineName
        process_id     = $ProcessId
        name           = if ($proc) { $proc.ProcessName } elseif ($cim) { $cim.Name } else { $null }
        image_path     = $image
        image_sha256   = $sha256
        command_line   = if ($cim) { $cim.CommandLine } else { $null }
        parent_pid     = if ($cim) { $cim.ParentProcessId } else { $null }
        owner          = $owner
        thread_count   = if ($proc) { $proc.Threads.Count } else { $null }
        loaded_modules = $modules
    }
}

function Suspend-EdrProcess {
    <#
    .SYNOPSIS
        Captures a forensic snapshot, then freezes every thread of the process.
    .DESCRIPTION
        Suspension halts encryption or a running payload immediately while keeping the
        process (and its memory) intact for investigation, unlike termination.
    .EXAMPLE
        Suspend-EdrProcess -ProcessId 4321 -SnapshotDir C:\IR\snapshots
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][int]$ProcessId,
        [string]$ImageName = '',
        [string]$SnapshotDir = (Join-Path ([IO.Path]::GetTempPath()) 'EdrCanary/forensics'),
        [hashtable]$Settings = (Get-EdrSettings)
    )
    if (-not $ImageName) {
        $p = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if ($p) { $ImageName = "$($p.ProcessName).exe" }
    }
    Assert-EdrContainmentAllowed -ProcessId $ProcessId -ImageName $ImageName -Settings $Settings
    $snapshotPath = $null
    if (Test-EdrIsWindows) {
        New-Item -ItemType Directory -Force -Path $SnapshotDir | Out-Null
        $snapshotPath = Join-Path $SnapshotDir ('snapshot_{0}_{1:yyyyMMddTHHmmss}.json' -f $ProcessId, [datetime]::UtcNow)
        Get-EdrForensicSnapshot -ProcessId $ProcessId | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $snapshotPath -Encoding UTF8
    }
    $threads = 0
    if ($PSCmdlet.ShouldProcess("PID $ProcessId ($ImageName)", 'Suspend all threads')) {
        $threads = Set-EdrThreadState -ProcessId $ProcessId -State Suspend
    }
    [pscustomobject]@{ ProcessId = $ProcessId; ImageName = $ImageName; ThreadsSuspended = $threads; Snapshot = $snapshotPath }
}

function Resume-EdrProcess {
    <#
    .SYNOPSIS
        Resumes every thread of a process previously suspended by Suspend-EdrProcess.
    .DESCRIPTION
        Use this to release a false positive after triage. Supports -WhatIf and -Confirm.
    .PARAMETER ProcessId
        PID of the suspended process.
    .EXAMPLE
        Resume-EdrProcess -ProcessId 4242
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][int]$ProcessId)
    if ($PSCmdlet.ShouldProcess("PID $ProcessId", 'Resume all threads')) {
        $n = Set-EdrThreadState -ProcessId $ProcessId -State Resume
        [pscustomobject]@{ ProcessId = $ProcessId; ThreadsResumed = $n }
    }
}
