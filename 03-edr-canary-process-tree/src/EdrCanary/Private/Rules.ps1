$script:SeverityOrder = @('low', 'medium', 'high', 'critical')

function Step-EdrSeverity {
    <# Returns the next severity up (low -> medium -> high -> critical); critical stays critical. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$Severity)
    $i = [array]::IndexOf($script:SeverityOrder, $Severity)
    return $script:SeverityOrder[[math]::Min($i + 1, $script:SeverityOrder.Count - 1)]
}

# Every abbreviation powershell.exe / pwsh.exe accepts for -EncodedCommand (-e, -ec, -en ... -encodedcommand),
# introduced by '-', '/' or a typographic dash, followed by the Base64 argument. Requiring whitespace after the
# flag keeps '-Encoding', '-ExecutionPolicy' and '-EncodedArguments' from matching.
$script:EncodedCommandPattern = '(?i)(?:^|\s)[-/–—](?:ec|e(?:n(?:c(?:o(?:d(?:e(?:d(?:c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?)?)?)?)?)?)?)?)\s+["'']?([A-Za-z0-9+/]{8,}={0,2})'

function Get-EdrEncodedCommand {
    <#
    .SYNOPSIS
        Finds a PowerShell -EncodedCommand argument in a command line and decodes it.
    .DESCRIPTION
        PowerShell expects the argument to be Base64 of UTF-16LE text. A payload that is not
        valid Base64 is still reported (Decoded is $null) because the flag itself is the signal.
    .OUTPUTS
        A hashtable with Payload and Decoded, or $null when no encoded command is present.
    #>
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$CommandLine)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }
    $m = [regex]::Match($CommandLine, $script:EncodedCommandPattern)
    if (-not $m.Success) { return $null }
    $payload = $m.Groups[1].Value
    $decoded = $null
    try {
        $padded = $payload.PadRight($payload.Length + ((4 - $payload.Length % 4) % 4), '=')
        $decoded = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($padded))
    }
    catch { $decoded = $null }
    return @{ Payload = $payload; Decoded = $decoded }
}

function Get-EdrCommandLineMarker {
    <#
    .SYNOPSIS
        Returns the obfuscation and download-cradle markers present in a command line.
    .DESCRIPTION
        Substring markers come from ProcessTree.SuspiciousCommandLine. An encoded command adds
        the marker 'encodedcommand', and the decoded text is checked against the same substrings;
        those hits are reported with a 'decoded:' prefix so the analyst can see where they came from.
    #>
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$CommandLine, [Parameter(Mandatory)][hashtable]$Settings)
    $needles = @($Settings.ProcessTree.SuspiciousCommandLine)
    $lower = ([string]$CommandLine).ToLowerInvariant()
    $markers = New-Object System.Collections.Generic.List[string]
    foreach ($n in $needles) { if ($lower.Contains($n)) { $markers.Add($n) } }
    $encoded = Get-EdrEncodedCommand -CommandLine $CommandLine
    if ($encoded) {
        $markers.Add('encodedcommand')
        if ($encoded.Decoded) {
            $text = $encoded.Decoded.ToLowerInvariant()
            foreach ($n in $needles) { if ($text.Contains($n)) { $markers.Add("decoded:$n") } }
        }
    }
    return @{ Markers = $markers.ToArray(); Encoded = $encoded }
}

function Test-EdrContainmentSeverity {
    <# True when an alert's severity reaches Containment.MinSeverity (default 'high'), the floor for auto-containment. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([string]$Severity, [Parameter(Mandatory)][hashtable]$Settings)
    $floor = if ($Settings.Containment -and $Settings.Containment.MinSeverity) { $Settings.Containment.MinSeverity } else { 'high' }
    return [array]::IndexOf($script:SeverityOrder, $Severity) -ge [array]::IndexOf($script:SeverityOrder, $floor)
}

function Test-EdrProcessTreeAnomaly {
    <#
    .SYNOPSIS
        Evaluates a newly started process against the parent-child rules and the encoded PowerShell rule.
    .DESCRIPTION
        Parent-child rules (EDR-PT-001 to 004) look up to AncestorDepth ancestors and are raised
        one severity level when the command line carries a marker. EDR-PT-005 covers encoded
        PowerShell whatever the parent; it only fires when no parent-child rule already matched
        the same process, so one process produces one process-tree alert per rule family.
    .OUTPUTS
        Zero or more alert hashtables.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Table, [Parameter(Mandatory)][int]$ProcessId, [Parameter(Mandatory)][hashtable]$Settings)
    $chain = Get-EdrProcessAncestry -Table $Table -ProcessId $ProcessId -MaxDepth ($Settings.ProcessTree.AncestorDepth + 1)
    if ($chain.Count -lt 1) { return }
    $child = $chain[0]
    $cmd = [string]$child.CommandLine
    $scan = Get-EdrCommandLineMarker -CommandLine $cmd -Settings $Settings
    $markers = @($scan.Markers)
    $hits = New-Object System.Collections.Generic.List[hashtable]

    foreach ($rule in $Settings.ProcessTree.Rules) {
        if ($rule.Children -notcontains $child.ImageName) { continue }
        for ($depth = 1; $depth -lt $chain.Count -and $depth -le $Settings.ProcessTree.AncestorDepth; $depth++) {
            $ancestor = $chain[$depth]
            if ($rule.Parents -notcontains $ancestor.ImageName) { continue }
            $severity = $rule.Severity
            if ($markers.Count -gt 0) { $severity = Step-EdrSeverity $severity }
            $message = if ($depth -eq 1) {
                "$($ancestor.ImageName) spawned $($child.ImageName) (PID $($child.ProcessId))"
            }
            else {
                "$($child.ImageName) (PID $($child.ProcessId)) is a depth-$depth descendant of $($ancestor.ImageName)"
            }
            $hits.Add(@{
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
                Decoded     = if ($scan.Encoded) { $scan.Encoded.Decoded } else { $null }
                Message     = $message
            })
            break   # nearest matching ancestor is enough for this rule
        }
    }

    $enc = $Settings.ProcessTree.EncodedPowerShell
    if ($hits.Count -eq 0 -and $enc -and $scan.Encoded -and $enc.Images -contains $child.ImageName) {
        $parent = if ($chain.Count -gt 1) { $chain[1] } else { $null }
        $parentName = if ($parent) { $parent.ImageName } else { '' }
        $severity = $enc.Severity
        $context = 'unclassified parent'
        # Markers found in the decoded payload, as opposed to wrapper flags on the command line.
        $payloadMarkers = @($markers | Where-Object { $_ -like 'decoded:*' })
        $wrapperMarkers = @($markers | Where-Object { $_ -ne 'encodedcommand' -and $_ -notlike 'decoded:*' })
        if ($enc.ManagementParents -contains $parentName) {
            # Agents routinely pass -ExecutionPolicy Bypass and hidden windows, so only the payload can raise this.
            $severity = 'low'; $context = 'management agent parent'
            if ($payloadMarkers.Count -gt 0) { $severity = Step-EdrSeverity $severity }
        }
        else {
            if ($enc.RemoteExecParents -contains $parentName) { $severity = Step-EdrSeverity $severity; $context = 'remote execution parent' }
            if ($payloadMarkers.Count + $wrapperMarkers.Count -gt 0) { $severity = Step-EdrSeverity $severity }
        }
        # A command line alone does not show what the payload did, so this rule stops at 'high'.
        if ($severity -eq 'critical') { $severity = 'high' }
        $hits.Add(@{
            RuleId      = $enc.Id
            RuleName    = $enc.Name
            Severity    = $severity
            Mitre       = $enc.Mitre
            ProcessId   = $child.ProcessId
            ImageName   = $child.ImageName
            CommandLine = $cmd
            ParentImage = $parentName
            ParentId    = if ($parent) { $parent.ProcessId } else { 0 }
            Depth       = 1
            Ancestry    = Format-EdrAncestry $chain
            Markers     = $markers
            Decoded     = $scan.Encoded.Decoded
            Message     = "$($child.ImageName) (PID $($child.ProcessId)) ran an encoded command; $context '$parentName'"
        })
    }
    return $hits.ToArray()
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
