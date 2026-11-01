$script:SeverityScore = @{ low = 21; medium = 47; high = 73; critical = 99 }
$script:EventIds = @{ 'EDR-CN' = 9001; 'EDR-RW' = 9002; 'EDR-PT' = 9003 }

function New-EdrAlert {
    <#
    .SYNOPSIS
        Wraps a rule hit in an ECS 8.x-shaped alert document (the same schema Project 01 emits).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Hit, $EdrEvent, [string]$HostName = [Environment]::MachineName)
    $ts = if ($EdrEvent -and $EdrEvent.TimeStamp) { ([datetime]$EdrEvent.TimeStamp).ToUniversalTime() } else { [datetime]::UtcNow }
    $doc = [ordered]@{
        '@timestamp' = $ts.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        ecs          = @{ version = '8.11.0' }
        message      = "[$(([string]$Hit['Severity']).ToUpperInvariant())] $($Hit['RuleName']): $($Hit['Message'])"
        event        = [ordered]@{
            id         = [guid]::NewGuid().ToString()
            kind       = 'alert'
            category   = @(if ($Hit['RuleId'] -like 'EDR-PT*') { 'process' } else { 'file' }; 'intrusion_detection')
            type       = @('indicator')
            module     = 'edr_canary'
            dataset    = 'edr_canary.alerts'
            severity   = $script:SeverityScore[$Hit['Severity']]
            risk_score = [double]$script:SeverityScore[$Hit['Severity']]
            reason     = $Hit['Message']
            provider   = 'Microsoft-Windows-Kernel-ETW'
        }
        rule         = @{ id = $Hit['RuleId']; name = $Hit['RuleName']; ruleset = 'edr-canary' }
        threat       = @{ framework = 'MITRE ATT&CK'; technique = @{ id = @($Hit['Mitre']) } }
        host         = @{ hostname = $HostName; name = $HostName }
        process      = [ordered]@{ pid = [int]$Hit['ProcessId'] }
        tags         = @('edr', 'etw')
    }
    if ($Hit['ImageName']) { $doc.process.name = $Hit['ImageName'] }
    if ($Hit['CommandLine']) { $doc.process.command_line = $Hit['CommandLine'] }
    if ($Hit['ParentImage']) { $doc.process.parent = @{ name = $Hit['ParentImage']; pid = [int]$Hit['ParentId'] } }
    if ($Hit['FilePath']) { $doc.file = @{ path = $Hit['FilePath'] } }
    if ($Hit['Ancestry']) { $doc.edr = @{ ancestry = $Hit['Ancestry']; depth = $Hit['Depth']; markers = @($Hit['Markers']) } }
    if ($Hit['DistinctFiles']) { $doc.edr = @{ distinct_files = $Hit['DistinctFiles'] } }
    return $doc
}

function Write-EdrAlert {
    <#
    .SYNOPSIS
        Appends an alert as one NDJSON line, rotating the file at MaxBytes (keeps Backups copies).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Alert,
        [Parameter(Mandatory)][string]$Path,
        [int64]$MaxBytes = 10MB,
        [int]$Backups = 5
    )
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    if ((Test-Path -LiteralPath $Path) -and (Get-Item -LiteralPath $Path).Length -ge $MaxBytes) {
        for ($i = $Backups - 1; $i -ge 1; $i--) {
            $src = "$Path.$i"
            if (Test-Path -LiteralPath $src) { Move-Item -LiteralPath $src -Destination "$Path.$($i + 1)" -Force }
        }
        Move-Item -LiteralPath $Path -Destination "$Path.1" -Force
        $overflow = "$Path.$($Backups + 1)"
        if (Test-Path -LiteralPath $overflow) { Remove-Item -LiteralPath $overflow -Force }
    }
    $line = $Alert | ConvertTo-Json -Depth 8 -Compress
    [IO.File]::AppendAllText($Path, $line + [Environment]::NewLine, (New-Object System.Text.UTF8Encoding($false)))
}

function ConvertTo-EdrSyslog {
    <# RFC 5424 frame: <PRI>1 TIMESTAMP HOST APP PROCID MSGID - MSG (facility local4). #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)]$Alert)
    $sev = switch ($Alert.event.severity) { { $_ -ge 90 } { 2; break } { $_ -ge 70 } { 3; break } { $_ -ge 40 } { 4; break } default { 5 } }
    $pri = 20 * 8 + $sev
    $hostName = ($Alert.host.hostname -replace '\s', '_')
    $json = $Alert | ConvertTo-Json -Depth 8 -Compress
    return "<$pri>1 $($Alert.'@timestamp') $hostName edr-canary $PID $($Alert.rule.id) - $json"
}

function Send-EdrSyslog {
    <# Fire-and-forget UDP delivery to the SIEM (Project 01 listens on 5514/udp). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Alert, [Parameter(Mandatory)][string]$Server, [int]$Port = 5514)
    $client = New-Object System.Net.Sockets.UdpClient
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes((ConvertTo-EdrSyslog -Alert $Alert))
        [void]$client.Send($bytes, $bytes.Length, $Server, $Port)
    }
    catch {
        Write-Warning "SIEM syslog delivery to ${Server}:$Port failed: $($_.Exception.Message)"
    }
    finally { $client.Dispose() }
}

function Write-EdrEventLog {
    <# Writes to the Windows Application log (EventID 9001/9002/9003) when the source is registered. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Alert)
    if (-not (Test-EdrIsWindows)) { return }
    try {
        $source = 'EdrCanary'
        if (-not [System.Diagnostics.EventLog]::SourceExists($source)) { return }  # registration needs admin: see Install docs
        $prefix = ($Alert.rule.id -split '-')[0..1] -join '-'
        $id = $script:EventIds[$prefix]
        if (-not $id) { $id = 9000 }
        $type = if ($Alert.event.severity -ge 70) { 'Error' } else { 'Warning' }
        [System.Diagnostics.EventLog]::WriteEntry($source, ($Alert | ConvertTo-Json -Depth 8), $type, $id)
    }
    catch { Write-Verbose "Event log write skipped: $($_.Exception.Message)" }
}
