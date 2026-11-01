BeforeDiscovery { Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'src/EdrCanary/EdrCanary.psd1') -Force }
BeforeAll { . (Join-Path $PSScriptRoot 'TestHelpers.ps1') }

Describe 'Process tree mapping' {
    InModuleScope EdrCanary {
        BeforeEach {
            $script:t = New-EdrProcessTable
            $base = [datetime]'2026-10-26T09:00:00Z'
            Add-EdrProcess -Table $t -ProcessId 1200 -ParentProcessId 1000 -ImageName 'C:\Windows\explorer.exe' -StartTime $base
            Add-EdrProcess -Table $t -ProcessId 3100 -ParentProcessId 1200 -ImageName 'C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE' -StartTime $base.AddSeconds(10)
            Add-EdrProcess -Table $t -ProcessId 3150 -ParentProcessId 3100 -ImageName 'cmd.exe' -StartTime $base.AddSeconds(12)
            Add-EdrProcess -Table $t -ProcessId 3160 -ParentProcessId 3150 -ImageName 'powershell' -StartTime $base.AddSeconds(13)
        }

        It 'normalises image names from full paths and bare names' {
            Get-EdrImageName 'C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE' | Should -Be 'winword.exe'
            Get-EdrImageName '"C:\x\cmd.exe"' | Should -Be 'cmd.exe'
            Get-EdrImageName 'powershell' | Should -Be 'powershell.exe'
            Get-EdrImageName '' | Should -Be ''
        }

        It 'walks the ancestry child-first' {
            $chain = Get-EdrProcessAncestry -Table $t -ProcessId 3160
            $chain.ImageName | Should -Be @('powershell.exe', 'cmd.exe', 'winword.exe', 'explorer.exe')
            Format-EdrAncestry $chain | Should -Be 'explorer.exe(1200) -> winword.exe(3100) -> cmd.exe(3150) -> powershell.exe(3160)'
        }

        It 'stops at a reused parent PID that started after the child' {
            Add-EdrProcess -Table $t -ProcessId 3100 -ParentProcessId 1200 -ImageName 'calc.exe' -StartTime ([datetime]'2026-10-26T10:00:00Z')
            (Get-EdrProcessAncestry -Table $t -ProcessId 3150).Count | Should -Be 1
        }

        It 'survives cycles and self-parenting' {
            Add-EdrProcess -Table $t -ProcessId 10 -ParentProcessId 11 -ImageName 'a.exe' -StartTime ([datetime]'2026-01-01')
            Add-EdrProcess -Table $t -ProcessId 11 -ParentProcessId 10 -ImageName 'b.exe' -StartTime ([datetime]'2026-01-01')
            Add-EdrProcess -Table $t -ProcessId 12 -ParentProcessId 12 -ImageName 'c.exe' -StartTime ([datetime]'2026-01-01')
            (Get-EdrProcessAncestry -Table $t -ProcessId 10).Count | Should -Be 2
            (Get-EdrProcessAncestry -Table $t -ProcessId 12).Count | Should -Be 1
        }

        It 'returns an empty chain for unknown PIDs' {
            (Get-EdrProcessAncestry -Table $t -ProcessId 999).Count | Should -Be 0
        }

        It 'keeps stopped parents for attribution, then prunes them' {
            $stop = [pscustomobject]@{ Type = 'ProcessStop'; ProcessId = 3100; TimeStamp = [datetime]'2026-10-26T09:00:20Z' }
            Update-EdrProcessTable -Table $t -EdrEvent $stop | Out-Null
            (Get-EdrProcessAncestry -Table $t -ProcessId 3160).Count | Should -Be 4
            Clear-EdrProcessTable -Table $t -Now ([datetime]'2026-10-26T09:30:00Z')
            $t.Entries.ContainsKey(3100) | Should -BeFalse
            $t.Entries.ContainsKey(1200) | Should -BeTrue
        }

        It 'caps memory by evicting the oldest half' {
            $small = New-EdrProcessTable -MaxEntries 10
            1..11 | ForEach-Object { Add-EdrProcess -Table $small -ProcessId $_ -ImageName 'x.exe' -StartTime ([datetime]'2026-01-01').AddSeconds($_) }
            $small.Entries.Count | Should -BeLessOrEqual 10
            $small.Entries.ContainsKey(11) | Should -BeTrue
        }
    }
}

Describe 'Parent-child anomaly rules' {
    InModuleScope EdrCanary {
        BeforeAll { $script:settings = Get-EdrSettings -Override @{ OutputDir = $TestDrive } }
        BeforeEach {
            $script:t = New-EdrProcessTable
            $b = [datetime]'2026-10-26T09:00:00Z'
            Add-EdrProcess -Table $t -ProcessId 1 -ImageName 'explorer.exe' -StartTime $b
            Add-EdrProcess -Table $t -ProcessId 2 -ParentProcessId 1 -ImageName 'WINWORD.EXE' -StartTime $b.AddSeconds(1)
        }

        It 'flags <parent> spawning <child>' -TestCases @(
            @{ parent = 'WINWORD.EXE'; child = 'powershell.exe'; rule = 'EDR-PT-001' }
            @{ parent = 'excel.exe'; child = 'cmd.exe'; rule = 'EDR-PT-001' }
            @{ parent = 'outlook.exe'; child = 'mshta.exe'; rule = 'EDR-PT-001' }
            @{ parent = 'winword.exe'; child = 'certutil.exe'; rule = 'EDR-PT-002' }
            @{ parent = 'wscript.exe'; child = 'powershell.exe'; rule = 'EDR-PT-003' }
            @{ parent = 'w3wp.exe'; child = 'cmd.exe'; rule = 'EDR-PT-004' }
        ) {
            Add-EdrProcess -Table $t -ProcessId 50 -ParentProcessId 1 -ImageName $parent -StartTime ([datetime]'2026-10-26T09:00:02Z')
            Add-EdrProcess -Table $t -ProcessId 51 -ParentProcessId 50 -ImageName $child -StartTime ([datetime]'2026-10-26T09:00:03Z')
            $hits = @(Test-EdrProcessTreeAnomaly -Table $t -ProcessId 51 -Settings $settings)
            $hits.RuleId | Should -Contain $rule
            $hits[0].Depth | Should -Be 1
        }

        It 'does not flag <parent> spawning <child>' -TestCases @(
            @{ parent = 'explorer.exe'; child = 'powershell.exe' }
            @{ parent = 'winword.exe'; child = 'splwow64.exe' }
            @{ parent = 'services.exe'; child = 'svchost.exe' }
            @{ parent = 'cmd.exe'; child = 'powershell.exe' }
        ) {
            Add-EdrProcess -Table $t -ProcessId 60 -ParentProcessId 1 -ImageName $parent -StartTime ([datetime]'2026-10-26T09:00:02Z')
            Add-EdrProcess -Table $t -ProcessId 61 -ParentProcessId 60 -ImageName $child -StartTime ([datetime]'2026-10-26T09:00:03Z')
            @(Test-EdrProcessTreeAnomaly -Table $t -ProcessId 61 -Settings $settings).Count | Should -Be 0
        }

        It 'catches an indirect descendant (winword -> rundll32 -> powershell)' {
            Add-EdrProcess -Table $t -ProcessId 3 -ParentProcessId 2 -ImageName 'rundll32.exe' -StartTime ([datetime]'2026-10-26T09:00:02Z')
            Add-EdrProcess -Table $t -ProcessId 4 -ParentProcessId 3 -ImageName 'powershell.exe' -StartTime ([datetime]'2026-10-26T09:00:03Z')
            $hit = @(Test-EdrProcessTreeAnomaly -Table $t -ProcessId 4 -Settings $settings)[0]
            $hit.RuleId | Should -Be 'EDR-PT-001'
            $hit.Depth | Should -Be 2
            $hit.Message | Should -Match 'depth-2 descendant'
        }

        It 'respects the ancestor depth limit' {
            $prev = 2
            foreach ($i in 10..14) {
                Add-EdrProcess -Table $t -ProcessId $i -ParentProcessId $prev -ImageName 'conhost.exe' -StartTime ([datetime]'2026-10-26T09:00:02Z').AddSeconds($i)
                $prev = $i
            }
            Add-EdrProcess -Table $t -ProcessId 20 -ParentProcessId $prev -ImageName 'cmd.exe' -StartTime ([datetime]'2026-10-26T09:01:00Z')
            @(Test-EdrProcessTreeAnomaly -Table $t -ProcessId 20 -Settings $settings).Count | Should -Be 0
        }

        It 'escalates severity for obfuscated command lines' {
            Add-EdrProcess -Table $t -ProcessId 5 -ParentProcessId 2 -ImageName 'powershell.exe' -CommandLine 'powershell -w hidden -enc SQBFAFgA' -StartTime ([datetime]'2026-10-26T09:00:02Z')
            $hit = @(Test-EdrProcessTreeAnomaly -Table $t -ProcessId 5 -Settings $settings)[0]
            $hit.Severity | Should -Be 'critical'
            $hit.Markers | Should -Contain '-enc'
        }
    }
}
