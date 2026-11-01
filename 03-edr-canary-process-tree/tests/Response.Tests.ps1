BeforeDiscovery { Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'src/EdrCanary/EdrCanary.psd1') -Force }
BeforeAll { . (Join-Path $PSScriptRoot 'TestHelpers.ps1') }

Describe 'Suspend-EdrProcess / Resume-EdrProcess' {
    BeforeAll { $script:settings = New-TestSettings }

    It 'snapshots first, then suspends, and reports the thread count' {
        Mock Test-EdrIsWindows -ModuleName EdrCanary { $true }
        Mock Get-EdrForensicSnapshot -ModuleName EdrCanary { [ordered]@{ process_id = $ProcessId; name = 'svch0st' } }
        Mock Set-EdrThreadState -ModuleName EdrCanary { 7 }
        $r = Suspend-EdrProcess -ProcessId 4100 -ImageName 'svch0st.exe' -SnapshotDir (Join-Path $TestDrive 'ir') -Settings $settings -Confirm:$false
        $r.ThreadsSuspended | Should -Be 7
        (Get-Content -LiteralPath $r.Snapshot -Raw | ConvertFrom-Json).process_id | Should -Be 4100
        Should -Invoke Set-EdrThreadState -ModuleName EdrCanary -Times 1 -ParameterFilter { $ProcessId -eq 4100 -and $State -eq 'Suspend' }
    }

    It 'never touches a protected process, even when asked directly' {
        Mock Set-EdrThreadState -ModuleName EdrCanary { 1 }
        { Suspend-EdrProcess -ProcessId 700 -ImageName 'lsass.exe' -Settings $settings -Confirm:$false } | Should -Throw '*protected*'
        Should -Invoke Set-EdrThreadState -ModuleName EdrCanary -Times 0
    }

    It 'honours -WhatIf' {
        Mock Test-EdrIsWindows -ModuleName EdrCanary { $false }
        Mock Set-EdrThreadState -ModuleName EdrCanary { 1 }
        $r = Suspend-EdrProcess -ProcessId 4100 -ImageName 'svch0st.exe' -Settings $settings -WhatIf
        $r.ThreadsSuspended | Should -Be 0
        Should -Invoke Set-EdrThreadState -ModuleName EdrCanary -Times 0
    }

    It 'resumes every thread' {
        Mock Set-EdrThreadState -ModuleName EdrCanary { 3 }
        (Resume-EdrProcess -ProcessId 4100 -Confirm:$false).ThreadsResumed | Should -Be 3
        Should -Invoke Set-EdrThreadState -ModuleName EdrCanary -ParameterFilter { $State -eq 'Resume' }
    }

    It 'refuses thread control off Windows' -Skip:($IsWindows -or $PSVersionTable.PSEdition -eq 'Desktop') {
        InModuleScope EdrCanary { { Set-EdrThreadState -ProcessId 1 -State Suspend } | Should -Throw '*only available on Windows*' }
    }

    It 'freezes and thaws a real child process' -Skip:(-not ($IsWindows -or $PSVersionTable.PSEdition -eq 'Desktop')) {
        $child = Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList '-NoProfile', '-Command', 'Start-Sleep 30' -PassThru -WindowStyle Hidden
        try {
            (Suspend-EdrProcess -ProcessId $child.Id -SnapshotDir (Join-Path $TestDrive 'ir2') -Settings $settings -Confirm:$false).ThreadsSuspended |
                Should -BeGreaterThan 0
            (Resume-EdrProcess -ProcessId $child.Id -Confirm:$false).ThreadsResumed | Should -BeGreaterThan 0
        }
        finally { Stop-Process -Id $child.Id -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Install-EdrTraceEvent' {
    BeforeAll {
        # A stand-in package with the same layout as the real nupkg.
        $staging = Join-Path $TestDrive 'pkg'
        New-Item -ItemType Directory -Force -Path (Join-Path $staging 'lib/netstandard2.0') | Out-Null
        Set-Content -LiteralPath (Join-Path $staging 'lib/netstandard2.0/Microsoft.Diagnostics.Tracing.TraceEvent.dll') -Value 'stub'
        $script:package = Join-Path $TestDrive 'traceevent.zip'
        Compress-Archive -Path (Join-Path $staging '*') -DestinationPath $package
        $script:packageHash = (Get-FileHash -LiteralPath $package -Algorithm SHA256).Hash
    }

    It 'installs the package when the pinned hash matches' {
        Mock Invoke-WebRequest -ModuleName EdrCanary { Copy-Item -LiteralPath $script:package -Destination $OutFile }
        $dest = Join-Path $TestDrive 'lib-ok'
        $dlls = Install-EdrTraceEvent -Destination $dest -Sha256 $packageHash -Confirm:$false
        @($dlls).Name | Should -Contain 'Microsoft.Diagnostics.Tracing.TraceEvent.dll'
        Should -Invoke Invoke-WebRequest -ModuleName EdrCanary -ParameterFilter { $Uri -like 'https://api.nuget.org/*/3.2.8/*' }
    }

    It 'refuses a package whose hash does not match and extracts nothing' {
        Mock Invoke-WebRequest -ModuleName EdrCanary { Copy-Item -LiteralPath $script:package -Destination $OutFile }
        $dest = Join-Path $TestDrive 'lib-bad'
        { Install-EdrTraceEvent -Destination $dest -Sha256 ('0' * 64) -Confirm:$false } | Should -Throw '*SHA-256 mismatch*'
        Test-Path -LiteralPath $dest | Should -BeFalse
    }
}
