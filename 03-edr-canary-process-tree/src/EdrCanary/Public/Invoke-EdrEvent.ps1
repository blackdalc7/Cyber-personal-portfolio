function New-EdrContext {
    <#
    .SYNOPSIS
        Creates the mutable detection state shared by every event (process table, windows, canaries).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Settings,
        [hashtable]$Canaries = @{},
        # Receives (ProcessId, ImageName, Settings). Injected in tests; defaults to thread suspension.
        [scriptblock]$Contain = {
            param($ProcessId, $ImageName, $Settings)
            Suspend-EdrProcess -ProcessId $ProcessId -ImageName $ImageName -Settings $Settings -Confirm:$false
        }
    )
    $out = $Settings.OutputDir
    [pscustomobject]@{
        Settings   = $Settings
        Table      = New-EdrProcessTable
        Behavior   = New-EdrBehaviorState
        Canaries   = $Canaries
        AlertPath  = Join-Path $out 'alerts.ndjson'
        Contain    = $Contain
        Contained  = New-Object System.Collections.Generic.HashSet[int]
        Counters   = @{ events = 0; alerts = 0; contained = 0; containment_refused = 0 }
    }
}

function Invoke-EdrEvent {
    <#
    .SYNOPSIS
        Runs one normalised event through every detection and returns the alerts it produced.
    .DESCRIPTION
        Order matters: the process table is updated first so a ProcessStart can be evaluated
        against its own ancestry, then canary, ransomware-behaviour and process-tree rules run.
        Each alert is written to disk, the event log, and (if configured) the SIEM; with
        AutoContain the offending process is suspended once.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)]$EdrEvent)
    $ctx = $Context
    $s = $ctx.Settings
    $ctx.Counters.events++
    $hits = New-Object System.Collections.Generic.List[hashtable]

    switch ($EdrEvent.Type) {
        'ProcessStart' {
            [void](Update-EdrProcessTable -Table $ctx.Table -EdrEvent $EdrEvent)
            foreach ($h in @(Test-EdrProcessTreeAnomaly -Table $ctx.Table -ProcessId $EdrEvent.ProcessId -Settings $s)) { if ($h) { $hits.Add($h) } }
        }
        'ProcessStop' {
            [void](Update-EdrProcessTable -Table $ctx.Table -EdrEvent $EdrEvent)
            $ctx.Behavior.Windows.Remove([int]$EdrEvent.ProcessId)
            $ctx.Behavior.Alerted.Remove([int]$EdrEvent.ProcessId)
        }
        default {
            $canary = Get-EdrCanaryMatch -EdrEvent $EdrEvent -Canaries $ctx.Canaries
            if ($canary) {
                $entry = $ctx.Table.Entries[[int]$EdrEvent.ProcessId]
                $image = if ($entry) { $entry.ImageName } else { '' }
                $hits.Add(@{ RuleId = 'EDR-CN-001'; RuleName = 'Canary file tampered'; Severity = 'critical'
                             Mitre = @('T1486', 'T1485'); ProcessId = [int]$EdrEvent.ProcessId; ImageName = $image
                             FilePath = $EdrEvent.FilePath
                             Message = "$($EdrEvent.Type) on canary $canary by $image (PID $($EdrEvent.ProcessId))" })
            }
            foreach ($h in @(Test-EdrRansomwareBehavior -State $ctx.Behavior -EdrEvent $EdrEvent -Settings $s)) { if ($h) { $hits.Add($h) } }
        }
    }

    $alerts = foreach ($hit in $hits) {
        if (-not $hit['ImageName']) {
            $entry = $ctx.Table.Entries[[int]$hit['ProcessId']]
            if ($entry) { $hit['ImageName'] = $entry.ImageName; $hit['CommandLine'] = $entry.CommandLine }
        }
        $alert = New-EdrAlert -Hit $hit -EdrEvent $EdrEvent
        if ($s.AutoContain -and $hit['ProcessId'] -gt 0 -and -not $ctx.Contained.Contains([int]$hit['ProcessId']) -and
            (Test-EdrContainmentSeverity -Severity $hit['Severity'] -Settings $s)) {
            try {
                $result = & $ctx.Contain $hit['ProcessId'] $hit['ImageName'] $s
                [void]$ctx.Contained.Add([int]$hit['ProcessId'])
                $ctx.Counters.contained++
                $alert['edr_response'] = @{ action = 'suspend'; status = 'success'; snapshot = $result.Snapshot }
            }
            catch {
                $ctx.Counters.containment_refused++
                $alert['edr_response'] = @{ action = 'suspend'; status = 'refused'; reason = $_.Exception.Message }
            }
        }
        Write-EdrAlert -Alert $alert -Path $ctx.AlertPath -MaxBytes $s.AlertMaxBytes -Backups $s.AlertBackups
        Write-EdrEventLog -Alert $alert
        if ($s.SiemHost) { Send-EdrSyslog -Alert $alert -Server $s.SiemHost -Port $s.SiemPort }
        $ctx.Counters.alerts++
        $alert
    }
    return @($alerts)
}
