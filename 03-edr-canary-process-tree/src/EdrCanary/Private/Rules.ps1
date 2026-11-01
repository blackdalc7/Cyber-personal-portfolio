$script:SeverityOrder = @('low', 'medium', 'high', 'critical')

function Step-EdrSeverity {
    <# Returns the next severity up (low -> medium -> high -> critical); critical stays critical. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$Severity)
    $i = [array]::IndexOf($script:SeverityOrder, $Severity)
    return $script:SeverityOrder[[math]::Min($i + 1, $script:SeverityOrder.Count - 1)]
}

function Test-EdrProcessTreeAnomaly {
    <#
    .SYNOPSIS
        Evaluates a newly started process against the parent-child rules.
    .OUTPUTS
        Zero or more alert hashtables.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Table, [Parameter(Mandatory)][int]$ProcessId, [Parameter(Mandatory)][hashtable]$Settings)
    $chain = Get-EdrProcessAncestry -Table $Table -ProcessId $ProcessId -MaxDepth ($Settings.ProcessTree.AncestorDepth + 1)
    if ($chain.Count -lt 2) { return }
    $child = $chain[0]
    $cmd = [string]$child.CommandLine
    $markers = @($Settings.ProcessTree.SuspiciousCommandLine | Where-Object { $cmd.ToLowerInvariant().Contains($_) })

    foreach ($rule in $Settings.ProcessTree.Rules) {
        if ($rule.Children -notcontains $child.ImageName) { continue }
        for ($depth = 1; $depth -lt $chain.Count -and $depth -le $Settings.ProcessTree.AncestorDepth; $depth++) {
            $ancestor = $chain[$depth]
            if ($rule.Parents -notcontains $ancestor.ImageName) { continue }
            $severity = $rule.Severity
            if ($markers.Count -gt 0) { $severity = Step-EdrSeverity $severity }
            $relation = if ($depth -eq 1) { 'spawned' } else { "is a depth-$depth descendant of" }
            @{
                RuleId      = $rule.Id
                RuleName    = $rule.Name
                Severity    = $severity
                Mitre       = $rule.Mitre
                ProcessId   = $child.ProcessId
                ImageName   = $child.ImageName
                CommandLine = $cmd
                ParentImage = $ancestor.ImageName
                ParentId    = $ancestor.ProcessId
                Depth       = $depth
                Ancestry    = Format-EdrAncestry $chain
                Markers     = $markers
                Message     = "$($ancestor.ImageName) $relation $($child.ImageName) (PID $($child.ProcessId))"
            }
            break   # nearest matching ancestor is enough for this rule
        }
    }
}

function Get-EdrCanaryMatch {
    <# Returns the canary path when a file event touches a deployed canary, else $null. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$EdrEvent, [Parameter(Mandatory)][hashtable]$Canaries)
    if ($EdrEvent.Type -notin @('FileWrite', 'FileRename', 'FileDelete', 'DiskWrite')) { return $null }
    $path = [string]$EdrEvent.FilePath
    if (-not $path) { return $null }
    # Kernel paths can arrive as \Device\HarddiskVolume3\...; compare on the tail so both forms match.
    $norm = $path.Replace('/', '\').ToLowerInvariant()
    foreach ($canary in $Canaries.Keys) {
        $c = $canary.Replace('/', '\').ToLowerInvariant()
        $tail = $c.Substring([math]::Max(0, $c.IndexOf(':') + 1))
        if ($norm -eq $c -or $norm.EndsWith($tail)) { return $canary }
    }
    return $null
}

function New-EdrBehaviorState {
    <# Creates the per-process state used by Test-EdrRansomwareBehavior: write windows and alerted PIDs. #>
    [CmdletBinding()]
    param()
    [pscustomobject]@{ Windows = @{}; Alerted = @{} }
}

function Test-EdrRansomwareBehavior {
    <#
    .SYNOPSIS
        Per-process sliding-window heuristic for mass file modification.
    .DESCRIPTION
        Fires when one PID touches DistinctFileThreshold different files inside WindowSeconds,
        or immediately when it creates a file with a known ransomware extension or a
        ransom-note name. Alerts once per PID to avoid a storm while encryption runs.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)]$EdrEvent, [Parameter(Mandatory)][hashtable]$Settings)
    if ($EdrEvent.Type -notin @('FileCreate', 'FileWrite', 'FileRename', 'FileDelete')) { return }
    $procId = [int]$EdrEvent.ProcessId
    if ($procId -le 4 -or $State.Alerted.ContainsKey($procId)) { return }
    $cfg = $Settings.Ransomware
    $path = [string]$EdrEvent.FilePath
    $leaf = ($path -split '[\\/]')[-1].ToLowerInvariant()
    $ext = [IO.Path]::GetExtension($leaf)

    if ($EdrEvent.Type -in @('FileCreate', 'FileWrite', 'FileRename')) {
        $reason = $null
        if ($ext -and $cfg.SuspiciousExtensions -contains $ext) { $reason = "wrote file with ransomware extension '$ext'" }
        elseif (@($cfg.RansomNotePatterns | Where-Object { $leaf -like $_ }).Count -gt 0) { $reason = "dropped ransom-note style file '$leaf'" }
        if ($reason) {
            $State.Alerted[$procId] = $true
            return @{ RuleId = 'EDR-RW-002'; RuleName = 'Ransomware artefact written'; Severity = 'critical';
                      Mitre = @('T1486'); ProcessId = $procId; FilePath = $path; Message = "PID $procId $reason" }
        }
    }

    if (-not $State.Windows.ContainsKey($procId)) {
        $State.Windows[$procId] = New-Object System.Collections.Generic.Queue[object]
    }
    $q = $State.Windows[$procId]
    $ts = [datetime]$EdrEvent.TimeStamp
    $q.Enqueue([pscustomobject]@{ T = $ts; P = $path.ToLowerInvariant() })
    $cutoff = $ts.AddSeconds(-$cfg.WindowSeconds)
    while ($q.Count -gt 0 -and $q.Peek().T -lt $cutoff) { [void]$q.Dequeue() }
    $distinct = @($q | Select-Object -ExpandProperty P -Unique).Count
    if ($distinct -ge $cfg.DistinctFileThreshold) {
        $State.Alerted[$procId] = $true
        $State.Windows.Remove($procId)
        return @{ RuleId = 'EDR-RW-001'; RuleName = 'Mass file modification (possible encryption)'; Severity = 'critical';
                  Mitre = @('T1486'); ProcessId = $procId; FilePath = $path; DistinctFiles = $distinct
                  Message = "PID $procId modified $distinct distinct files in $($cfg.WindowSeconds)s" }
    }
}
