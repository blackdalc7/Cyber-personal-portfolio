function Test-EdrIsWindows {
    <# True on Windows PowerShell 5.1 and on PowerShell 7 running on Windows. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    if ($PSVersionTable.PSEdition -eq 'Desktop') { return $true }
    return [bool]$IsWindows
}

function Import-EdrDotEnv {
    <#
    .SYNOPSIS
        Loads KEY=VALUE pairs from a .env file into the process environment.
    .DESCRIPTION
        Existing environment variables win (12-factor convention), so a value set by the
        deployment platform is never overridden by a stale file. Supports comments, blank
        lines, optional "export " prefix and single/double-quoted values.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][string]$Path)

    $loaded = @{}
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $loaded }
    foreach ($raw in Get-Content -LiteralPath $Path -Encoding UTF8) {
        $line = $raw.Trim()
        if (-not $line -or $line.StartsWith('#')) { continue }
        if ($line.StartsWith('export ')) { $line = $line.Substring(7).TrimStart() }
        $eq = $line.IndexOf('=')
        if ($eq -lt 1) { continue }
        $key = $line.Substring(0, $eq).Trim()
        if ($key -notmatch '^[A-Za-z_][A-Za-z0-9_]*$') { continue }
        $value = $line.Substring($eq + 1).Trim()
        if ($value.Length -ge 2 -and (($value[0] -eq '"' -and $value[-1] -eq '"') -or ($value[0] -eq "'" -and $value[-1] -eq "'"))) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        elseif ($value -match '^(.*?)\s+#') {
            $value = $Matches[1]
        }
        if ($null -eq [Environment]::GetEnvironmentVariable($key)) {
            [Environment]::SetEnvironmentVariable($key, $value)
            $loaded[$key] = $value
        }
    }
    return $loaded
}

function Get-EdrSettings {
    <#
    .SYNOPSIS
        Builds the effective configuration: rules.psd1 + EDR_* environment variables + explicit overrides.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [string]$RulesPath = (Join-Path $script:ProjectRoot 'config/rules.psd1'),
        [hashtable]$Override = @{}
    )
    if (-not (Test-Path -LiteralPath $RulesPath)) { throw "Rules file not found: $RulesPath" }
    $rules = Import-PowerShellDataFile -LiteralPath $RulesPath

    # Environment variable value, or $Default when it is unset or blank.
    function Get-EnvOr([string]$Name, $Default) {
        $v = [Environment]::GetEnvironmentVariable($Name)
        if ([string]::IsNullOrWhiteSpace($v)) { return $Default }
        return $v
    }

    $watch = Get-EnvOr 'EDR_WATCH_PATHS' ''
    $settings = @{
        WatchPaths      = @($watch -split ';' | Where-Object { $_ })
        OutputDir       = Get-EnvOr 'EDR_OUTPUT_DIR' (Join-Path ([IO.Path]::GetTempPath()) 'EdrCanary')
        AlertMaxBytes   = [int64](Get-EnvOr 'EDR_ALERT_MAX_BYTES' 10485760)
        AlertBackups    = [int](Get-EnvOr 'EDR_ALERT_BACKUPS' 5)
        AutoContain     = (Get-EnvOr 'EDR_AUTO_CONTAIN' 'false') -in @('1', 'true', 'yes', 'on')
        SiemHost        = Get-EnvOr 'EDR_SIEM_HOST' ''
        SiemPort        = [int](Get-EnvOr 'EDR_SIEM_PORT' 5514)
        QueueCapacity   = [int](Get-EnvOr 'EDR_QUEUE_CAPACITY' 50000)
        TraceEventPath  = Get-EnvOr 'EDR_TRACEEVENT_PATH' (Join-Path $script:ProjectRoot 'lib/traceevent')
        IncludeDiskIo   = (Get-EnvOr 'EDR_INCLUDE_DISK_IO' 'true') -in @('1', 'true', 'yes', 'on')
        ProcessTree     = $rules.ProcessTree
        Canary          = $rules.Canary
        Ransomware      = $rules.Ransomware
        Containment     = $rules.Containment
    }
    foreach ($k in $Override.Keys) { $settings[$k] = $Override[$k] }
    if ($settings.SiemPort -lt 1 -or $settings.SiemPort -gt 65535) { throw 'EDR_SIEM_PORT must be 1-65535' }
    return $settings
}
