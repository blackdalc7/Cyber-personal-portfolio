# PowerShell dependencies. CI installs these with:
#   Install-Module Pester -RequiredVersion 5.7.1 -Force -SkipPublisherCheck
#   Install-Module PSScriptAnalyzer -RequiredVersion 1.23.0 -Force
# TraceEvent (the kernel ETW library) is a NuGet package installed by scripts/Install-TraceEvent.ps1
# with a pinned SHA-256.
@{
    PowerShell = '5.1'
    Modules    = @(
        @{ Name = 'Pester'; RequiredVersion = '5.7.1'; Scope = 'Test' }
        @{ Name = 'PSScriptAnalyzer'; RequiredVersion = '1.23.0'; Scope = 'Lint' }
    )
    NuGet      = @(
        @{ Id = 'Microsoft.Diagnostics.Tracing.TraceEvent'; Version = '3.2.8'
           Sha256 = '37284F885E75326BBD1858BF19F20C9DA2818FEC7A3BD49803209209BE5FD38D' }
    )
}
