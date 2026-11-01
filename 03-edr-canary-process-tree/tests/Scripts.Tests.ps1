BeforeDiscovery { Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'src/EdrCanary/EdrCanary.psd1') -Force }
BeforeAll { . (Join-Path $PSScriptRoot 'TestHelpers.ps1') }

Describe 'Invoke-SafeSimulation (replay)' {
    It 'raises every detection class from the recorded chain and cleans up the lab' {
        $lab = Join-Path $TestDrive 'lab'
        $output = & (Join-Path $script:ProjectRoot 'scripts/Invoke-SafeSimulation.ps1') -LabPath $lab 6>&1 | Out-String
        $output | Should -Match 'EDR-CN-001'
        $output | Should -Match 'EDR-PT-001'
        $output | Should -Match 'EDR-PT-002'
        $output | Should -Match 'EDR-RW-001'
        Test-Path -LiteralPath $lab | Should -BeFalse
    }
    It 'keeps the alert file with -Keep' {
        $lab = Join-Path $TestDrive 'lab-keep'
        & (Join-Path $script:ProjectRoot 'scripts/Invoke-SafeSimulation.ps1') -LabPath $lab -Keep 6>&1 | Out-Null
        $lines = @(Get-Content -LiteralPath (Join-Path $lab 'out/alerts.ndjson'))
        $lines.Count | Should -Be 5
        ($lines[0] | ConvertFrom-Json).ecs.version | Should -Be '8.11.0'
    }
    It 'refuses live mode off Windows' -Skip:($IsWindows -or $PSVersionTable.PSEdition -eq 'Desktop') {
        { & (Join-Path $script:ProjectRoot 'scripts/Invoke-SafeSimulation.ps1') -Mode Live -LabPath (Join-Path $TestDrive 'x') } |
            Should -Throw '*needs Windows*'
    }
}

Describe 'Start-EdrCanary.ps1' {
    It 'refuses kernel ETW off Windows with a clear message' -Skip:($IsWindows -or $PSVersionTable.PSEdition -eq 'Desktop') {
        { & (Join-Path $script:ProjectRoot 'scripts/Start-EdrCanary.ps1') -WatchPaths $TestDrive } | Should -Throw '*needs Windows*'
    }
    It 'runs the replay source end to end' {
        $fixture = Join-Path $script:ProjectRoot 'tests/fixtures/maldoc_ransomware_chain.ndjson'
        $env:EDR_OUTPUT_DIR = Join-Path $TestDrive 'canary-out'
        try {
            & (Join-Path $script:ProjectRoot 'scripts/Start-EdrCanary.ps1') -Source Replay -ReplayPath $fixture `
                -WatchPaths (Join-Path $TestDrive 'share') -EnvFile (Join-Path $TestDrive 'none.env') 3>$null 6>$null
        }
        finally { Remove-Item Env:EDR_OUTPUT_DIR }
        Test-Path (Join-Path $TestDrive 'canary-out/alerts.ndjson') | Should -BeTrue
    }
}
