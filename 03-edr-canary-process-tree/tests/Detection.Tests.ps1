BeforeDiscovery { Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'src/EdrCanary/EdrCanary.psd1') -Force }
BeforeAll { . (Join-Path $PSScriptRoot 'TestHelpers.ps1') }

Describe 'Canary matching' {
    InModuleScope EdrCanary {
        It 'matches DOS paths, kernel device paths and is case-insensitive' {
            $c = @{ 'C:\Share\Finance\0_passwords.docx' = 'hash' }
            foreach ($p in 'C:\Share\Finance\0_passwords.docx', '\Device\HarddiskVolume3\Share\Finance\0_PASSWORDS.DOCX') {
                $e = [pscustomobject]@{ Type = 'FileWrite'; FilePath = $p }
                Get-EdrCanaryMatch -EdrEvent $e -Canaries $c | Should -Be 'C:\Share\Finance\0_passwords.docx'
            }
        }
        It 'ignores other files, reads and process events' {
            $c = @{ 'C:\Share\0_passwords.docx' = 'h' }
            Get-EdrCanaryMatch -EdrEvent ([pscustomobject]@{ Type = 'FileWrite'; FilePath = 'C:\Share\budget.xlsx' }) -Canaries $c | Should -BeNullOrEmpty
            Get-EdrCanaryMatch -EdrEvent ([pscustomobject]@{ Type = 'FileCreate'; FilePath = 'C:\Share\0_passwords.docx' }) -Canaries $c | Should -BeNullOrEmpty
            Get-EdrCanaryMatch -EdrEvent ([pscustomobject]@{ Type = 'ProcessStart'; FilePath = '' }) -Canaries $c | Should -BeNullOrEmpty
        }
    }
}

Describe 'Ransomware behaviour heuristic' {
    InModuleScope EdrCanary {
        BeforeAll { $script:settings = Get-EdrSettings -Override @{ OutputDir = $TestDrive } }
        BeforeEach { $script:state = New-EdrBehaviorState }

        It 'fires once when one PID touches the threshold of distinct files inside the window' {
            $alerts = @(foreach ($i in 0..39) {
                $e = [pscustomobject]@{ Type = 'FileWrite'; ProcessId = 4100; FilePath = "C:\Share\f$i.docx"; TimeStamp = ([datetime]'2026-10-26T09:00:00Z').AddMilliseconds($i * 100) }
                Test-EdrRansomwareBehavior -State $state -EdrEvent $e -Settings $settings
            })
            @($alerts).Count | Should -Be 1
            $alerts[0].RuleId | Should -Be 'EDR-RW-001'
            $alerts[0].DistinctFiles | Should -Be 25
        }

        It 'does not fire for repeated writes to the same file or slow activity' {
            $alerts = foreach ($i in 0..99) {
                $e = [pscustomobject]@{ Type = 'FileWrite'; ProcessId = 1; FilePath = 'C:\db\log.ldf'; TimeStamp = ([datetime]'2026-10-26T09:00:00Z').AddMilliseconds($i) }
                Test-EdrRansomwareBehavior -State $state -EdrEvent $e -Settings $settings
            }
            $alerts += foreach ($i in 0..49) {
                $e = [pscustomobject]@{ Type = 'FileWrite'; ProcessId = 2; FilePath = "C:\backup\f$i"; TimeStamp = ([datetime]'2026-10-26T09:00:00Z').AddSeconds($i * 2) }
                Test-EdrRansomwareBehavior -State $state -EdrEvent $e -Settings $settings
            }
            @($alerts | Where-Object { $_ }).Count | Should -Be 0
        }

        It 'fires immediately on a ransomware extension or ransom note' -TestCases @(
            @{ path = 'C:\Share\q3.xlsx.lockbit' }
            @{ path = 'C:\Share\HOW_TO_DECRYPT_FILES.txt' }
            @{ path = 'C:\Share\README_decrypt.html' }
        ) {
            $e = [pscustomobject]@{ Type = 'FileCreate'; ProcessId = 77; FilePath = $path; TimeStamp = [datetime]::UtcNow }
            (Test-EdrRansomwareBehavior -State $state -EdrEvent $e -Settings $settings).RuleId | Should -Be 'EDR-RW-002'
        }

        It 'ignores System (PID 4) and kernel-attributed I/O' {
            $e = [pscustomobject]@{ Type = 'FileCreate'; ProcessId = 4; FilePath = 'C:\x.locked'; TimeStamp = [datetime]::UtcNow }
            Test-EdrRansomwareBehavior -State $state -EdrEvent $e -Settings $settings | Should -BeNullOrEmpty
        }
    }
}

Describe 'Containment guard' {
    BeforeAll { $script:settings = New-TestSettings }

    It 'refuses protected process <name>' -TestCases @(
        @{ name = 'lsass.exe'; procId = 700 }, @{ name = 'csrss.exe'; procId = 500 }, @{ name = 'System'; procId = 4 },
        @{ name = 'svchost.exe'; procId = 900 }, @{ name = 'MsMpEng.exe'; procId = 3000 }
    ) {
        { Assert-EdrContainmentAllowed -ProcessId $procId -ImageName $name -Settings $settings } | Should -Throw '*protected*'
    }

    It 'refuses to suspend itself' {
        { Assert-EdrContainmentAllowed -ProcessId $PID -ImageName 'pwsh.exe' -Settings $settings } | Should -Throw '*own process*'
    }

    It 'allows ordinary processes' {
        { Assert-EdrContainmentAllowed -ProcessId 4100 -ImageName 'svch0st.exe' -Settings $settings } | Should -Not -Throw
    }

    It 'Suspend-EdrProcess enforces the guard before touching anything' {
        { Suspend-EdrProcess -ProcessId 700 -ImageName 'lsass.exe' -Settings $settings -Confirm:$false } | Should -Throw '*protected*'
    }

    It 'thread suspension is refused off Windows' -Skip:($IsWindows -or $PSVersionTable.PSEdition -eq 'Desktop') {
        { Suspend-EdrProcess -ProcessId 999999 -ImageName 'x.exe' -Settings $settings -Confirm:$false } | Should -Throw '*only available on Windows*'
    }
}
