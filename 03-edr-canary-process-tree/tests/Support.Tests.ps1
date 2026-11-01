BeforeDiscovery { Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'src/EdrCanary/EdrCanary.psd1') -Force }
BeforeAll { . (Join-Path $PSScriptRoot 'TestHelpers.ps1') }

Describe 'Import-EdrDotEnv' {
    BeforeEach {
        foreach ($k in 'EDR_T_A', 'EDR_T_B', 'EDR_T_C', 'EDR_T_D', 'EDR_T_KEEP') { [Environment]::SetEnvironmentVariable($k, $null) }
    }
    It 'parses quotes, comments, export prefixes and never overrides existing variables' {
        $f = Join-Path $TestDrive '.env'
        @(
            '# comment', '', 'EDR_T_A=plain', 'export EDR_T_B="quoted value"', "EDR_T_C='single'",
            'EDR_T_D=value # trailing comment', 'EDR_T_KEEP=from-file', 'not a pair', '1BAD=x'
        ) | Set-Content -LiteralPath $f
        $env:EDR_T_KEEP = 'from-env'
        $loaded = Import-EdrDotEnv -Path $f
        $env:EDR_T_A | Should -Be 'plain'
        $env:EDR_T_B | Should -Be 'quoted value'
        $env:EDR_T_C | Should -Be 'single'
        $env:EDR_T_D | Should -Be 'value'
        $env:EDR_T_KEEP | Should -Be 'from-env'
        $loaded.Keys | Should -Not -Contain 'EDR_T_KEEP'
    }
    It 'returns nothing for a missing file' {
        (Import-EdrDotEnv -Path (Join-Path $TestDrive 'missing')).Count | Should -Be 0
    }
}

Describe 'Get-EdrSettings' {
    AfterEach { foreach ($k in 'EDR_WATCH_PATHS', 'EDR_AUTO_CONTAIN', 'EDR_SIEM_PORT') { [Environment]::SetEnvironmentVariable($k, $null) } }
    It 'reads environment variables and rules' {
        $env:EDR_WATCH_PATHS = 'C:\a;C:\b'
        $env:EDR_AUTO_CONTAIN = 'true'
        $s = Get-EdrSettings
        $s.WatchPaths | Should -Be @('C:\a', 'C:\b')
        $s.AutoContain | Should -BeTrue
        $s.ProcessTree.Rules.Count | Should -Be 4
        $s.Containment.ProtectedNames | Should -Contain 'lsass.exe'
    }
    It 'validates the SIEM port' {
        $env:EDR_SIEM_PORT = '70000'
        { Get-EdrSettings } | Should -Throw '*EDR_SIEM_PORT*'
    }
    It 'fails clearly on a missing rules file' {
        { Get-EdrSettings -RulesPath (Join-Path $TestDrive 'nope.psd1') } | Should -Throw '*Rules file not found*'
    }
}

Describe 'Canary deployment' {
    It 'creates the decoy and returns its hash' {
        $c = New-EdrCanaryFile -Directory (Join-Path $TestDrive 'share') -Name '0_passwords.docx'
        Test-Path $c.Path | Should -BeTrue
        $c.Sha256 | Should -Be (Get-FileHash -LiteralPath $c.Path -Algorithm SHA256).Hash
        Get-Content -LiteralPath $c.Path -Raw | Should -Match 'CANARY DECOY'
    }
    It 'rejects path traversal in the name' {
        { New-EdrCanaryFile -Directory $TestDrive -Name '..\evil.docx' } | Should -Throw
    }
    It 'honours -WhatIf' {
        $r = New-EdrCanaryFile -Directory (Join-Path $TestDrive 'whatif') -WhatIf
        $r.Sha256 | Should -BeNullOrEmpty
    }
}

Describe 'Alert output' {
    InModuleScope EdrCanary {
        BeforeAll {
            $script:hit = @{ RuleId = 'EDR-PT-001'; RuleName = 'Office spawned shell'; Severity = 'high'; Mitre = @('T1566.001')
                             ProcessId = 51; ImageName = 'cmd.exe'; CommandLine = 'cmd /c whoami'; ParentImage = 'winword.exe'; ParentId = 50
                             Ancestry = 'winword.exe(50) -> cmd.exe(51)'; Depth = 1; Markers = @(); Message = 'winword.exe spawned cmd.exe' }
        }
        It 'builds an ECS-shaped alert' {
            $e = [pscustomobject]@{ TimeStamp = [datetime]'2026-10-26T09:00:00Z' }
            $a = New-EdrAlert -Hit $hit -EdrEvent $e -HostName 'WS01'
            $a.'@timestamp' | Should -Be '2026-10-26T09:00:00.000Z'
            $a.event.kind | Should -Be 'alert'
            $a.event.severity | Should -Be 73
            $a.event.category | Should -Be @('process', 'intrusion_detection')
            $a.process.parent.name | Should -Be 'winword.exe'
            $a.threat.technique.id | Should -Be @('T1566.001')
            $a.host.hostname | Should -Be 'WS01'
        }
        It 'rotates the NDJSON file and caps backups' {
            $p = Join-Path $TestDrive 'rot/alerts.ndjson'
            $a = New-EdrAlert -Hit $hit
            1..60 | ForEach-Object { Write-EdrAlert -Alert $a -Path $p -MaxBytes 2KB -Backups 2 }
            (Get-ChildItem (Split-Path $p) | Sort-Object Name).Name | Should -Be @('alerts.ndjson', 'alerts.ndjson.1', 'alerts.ndjson.2')
            Get-Content $p | ForEach-Object { { $_ | ConvertFrom-Json } | Should -Not -Throw }
        }
        It 'frames RFC 5424 syslog the SIEM (Project 01) can parse' {
            $a = New-EdrAlert -Hit $hit -HostName 'WS 01'
            $line = ConvertTo-EdrSyslog -Alert $a
            $line | Should -Match '^<163>1 \d{4}-\d\d-\d\dT\S+Z WS_01 edr-canary \d+ EDR-PT-001 - \{'
        }
        It 'delivers syslog over UDP' {
            $listener = [System.Net.Sockets.UdpClient]::new([System.Net.IPEndPoint]::new([System.Net.IPAddress]::Loopback, 0))
            try {
                $listener.Client.ReceiveTimeout = 3000
                $port = $listener.Client.LocalEndPoint.Port
                Send-EdrSyslog -Alert (New-EdrAlert -Hit $hit) -Server '127.0.0.1' -Port $port
                $remote = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
                $text = [Text.Encoding]::UTF8.GetString($listener.Receive([ref]$remote))
                $text | Should -Match 'EDR-PT-001'
            }
            finally { $listener.Dispose() }
        }
    }
}

Describe 'Event normalisation and replay' {
    It 'normalises dictionaries and JSON objects, dropping unknown types' {
        $d = @{ Type = 'FileWrite'; TimeStamp = '2026-10-26T09:00:00Z'; ProcessId = '42'; FilePath = 'C:\x' }
        $e = ConvertTo-EdrEvent -InputObject $d
        $e.ProcessId | Should -Be 42
        $e.TimeStamp.Kind | Should -Be 'Utc'
        ConvertTo-EdrEvent -InputObject @{ Type = 'Nope' } | Should -BeNullOrEmpty
    }
    It 'replay source serves events in order and reports malformed lines' {
        $src = New-EdrReplaySource -Path (Join-Path $PSScriptRoot 'fixtures/maldoc_ransomware_chain.ndjson')
        $first = $src.Next(0)
        $first.ImageName | Should -Be 'wininit.exe'
        $src.Stats().malformed | Should -Be 2
        $src.Dispose()
        $src.IsCompleted() | Should -BeTrue
    }
    It 'fails for a missing replay file' {
        { New-EdrReplaySource -Path (Join-Path $TestDrive 'missing.ndjson') } | Should -Throw '*not found*'
    }
}

Describe 'Kernel ETW consumer' {
    It 'compiles against TraceEvent when the library is installed' -Skip:(-not (Test-Path (Join-Path (Split-Path -Parent $PSScriptRoot) 'lib/traceevent/Microsoft.Diagnostics.Tracing.TraceEvent.dll'))) {
        InModuleScope EdrCanary {
            Import-EdrTraceEvent -LibraryPath (Join-Path $script:ProjectRoot 'lib/traceevent')
            $c = New-Object EdrCanary.EtwKernelConsumer -ArgumentList 8
            $c.Take(1) | Should -BeNullOrEmpty
            $c.Dispose()
        }
    }
    It 'reports a clear error when TraceEvent is missing' {
        InModuleScope EdrCanary {
            if ('EdrCanary.EtwKernelConsumer' -as [type]) { Set-ItResult -Skipped -Because 'already loaded in this session' }
            { Import-EdrTraceEvent -LibraryPath (Join-Path $TestDrive 'empty') } | Should -Throw '*Install-TraceEvent*'
        }
    }
    It 'refuses to start off Windows' -Skip:($IsWindows -or $PSVersionTable.PSEdition -eq 'Desktop') {
        InModuleScope EdrCanary { { New-EdrEtwSource -Settings (Get-EdrSettings) } | Should -Throw '*only available on Windows*' }
    }
}
