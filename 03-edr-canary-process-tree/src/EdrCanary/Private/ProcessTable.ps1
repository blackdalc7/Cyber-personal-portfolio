function New-EdrProcessTable {
    <#
    .SYNOPSIS
        Creates the in-memory process table that backs parent-child tree mapping.
    .DESCRIPTION
        Keyed by PID. Windows reuses PIDs, so every entry also carries its start time and a
        stopped flag; a ProcessStart for a PID that is already present replaces the old
        entry (the old process must have exited) instead of corrupting the lineage.
        Stopped processes are retained for RetainSeconds so a child that outlives its parent
        (the classic "winword spawns cmd and exits") can still be attributed.
    #>
    [CmdletBinding()]
    param([int]$RetainSeconds = 600, [int]$MaxEntries = 50000)
    [pscustomobject]@{
        Entries       = @{}
        RetainSeconds = $RetainSeconds
        MaxEntries    = $MaxEntries
    }
}

function Get-EdrImageName {
    <# Normalises "C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" -> "winword.exe". #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][AllowEmptyString()][string]$Image)
    if ([string]::IsNullOrWhiteSpace($Image)) { return '' }
    $name = ($Image.Trim('"') -split '[\\/]')[-1].ToLowerInvariant()
    if ($name -and $name -notmatch '\.[a-z0-9]{2,4}$') { $name = "$name.exe" }
    return $name
}

function Add-EdrProcess {
    <#
    .SYNOPSIS
        Adds or replaces a process entry in the process table.
    .DESCRIPTION
        Records the PID, parent PID, normalised image name, command line and start time.
        A reused PID overwrites the old entry; Get-EdrProcessAncestry then uses StartTime
        to avoid treating an unrelated, newer process as a parent.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Table,
        [Parameter(Mandatory)][int]$ProcessId,
        [int]$ParentProcessId = 0,
        [string]$ImageName = '',
        [string]$CommandLine = '',
        [datetime]$StartTime = [datetime]::UtcNow
    )
    $Table.Entries[$ProcessId] = [pscustomobject]@{
        ProcessId       = $ProcessId
        ParentProcessId = $ParentProcessId
        ImageName       = Get-EdrImageName $ImageName
        CommandLine     = $CommandLine
        StartTime       = $StartTime
        StoppedAt       = $null
    }
    if ($Table.Entries.Count -gt $Table.MaxEntries) { Clear-EdrProcessTable -Table $Table -Now $StartTime -Force }
}

function Update-EdrProcessTable {
    <# Applies a ProcessStart / ProcessStop event to the table. Returns the affected entry. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Table, [Parameter(Mandatory)]$EdrEvent)
    switch ($EdrEvent.Type) {
        'ProcessStart' {
            Add-EdrProcess -Table $Table -ProcessId $EdrEvent.ProcessId -ParentProcessId $EdrEvent.ParentProcessId `
                -ImageName $EdrEvent.ImageName -CommandLine $EdrEvent.CommandLine -StartTime $EdrEvent.TimeStamp
            return $Table.Entries[[int]$EdrEvent.ProcessId]
        }
        'ProcessStop' {
            $entry = $Table.Entries[[int]$EdrEvent.ProcessId]
            if ($entry) { $entry.StoppedAt = $EdrEvent.TimeStamp }
            return $entry
        }
    }
}

function Clear-EdrProcessTable {
    <# Drops processes that stopped more than RetainSeconds ago (and, with -Force, the oldest half). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Table, [datetime]$Now = [datetime]::UtcNow, [switch]$Force)
    $cutoff = $Now.AddSeconds(-$Table.RetainSeconds)
    foreach ($procId in @($Table.Entries.Keys)) {
        $e = $Table.Entries[$procId]
        if ($e.StoppedAt -and $e.StoppedAt -lt $cutoff) { $Table.Entries.Remove($procId) }
    }
    if ($Force -and $Table.Entries.Count -gt $Table.MaxEntries) {
        $drop = $Table.Entries.Values | Sort-Object StartTime | Select-Object -First ([int]($Table.Entries.Count / 2))
        foreach ($e in $drop) { $Table.Entries.Remove($e.ProcessId) }
    }
}

function Get-EdrProcessAncestry {
    <#
    .SYNOPSIS
        Returns the chain [process, parent, grandparent, ...] for a PID.
    .DESCRIPTION
        Guards against the two ways real process tables lie: PID reuse (a "parent" that
        started after its child is not the real parent, so the walk stops) and cycles.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Table, [Parameter(Mandatory)][int]$ProcessId, [int]$MaxDepth = 16)
    $chain = New-Object System.Collections.Generic.List[object]
    $seen = New-Object System.Collections.Generic.HashSet[int]
    $current = $Table.Entries[$ProcessId]
    while ($current -and $chain.Count -le $MaxDepth -and $seen.Add([int]$current.ProcessId)) {
        $chain.Add($current)
        $parent = $Table.Entries[[int]$current.ParentProcessId]
        if (-not $parent -or $parent.ProcessId -eq $current.ProcessId -or $parent.StartTime -gt $current.StartTime) { break }
        $current = $parent
    }
    return , $chain.ToArray()
}

function Format-EdrAncestry {
    <# Renders an ancestry chain oldest-first, e.g. 'explorer.exe(10) -> winword.exe(20) -> cmd.exe(30)'. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([object[]]$Chain)
    $names = @($Chain | ForEach-Object { '{0}({1})' -f $_.ImageName, $_.ProcessId })
    [array]::Reverse($names)
    return ($names -join ' -> ')
}

function Initialize-EdrProcessTable {
    <# Seeds the table from a live CIM snapshot so processes started before the monitor are known. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Table)
    if (-not (Test-EdrIsWindows)) { return 0 }
    $count = 0
    foreach ($p in Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue) {
        $start = if ($p.CreationDate) { $p.CreationDate.ToUniversalTime() } else { [datetime]::MinValue }
        Add-EdrProcess -Table $Table -ProcessId $p.ProcessId -ParentProcessId $p.ParentProcessId `
            -ImageName $p.Name -CommandLine $p.CommandLine -StartTime $start
        $count++
    }
    return $count
}
