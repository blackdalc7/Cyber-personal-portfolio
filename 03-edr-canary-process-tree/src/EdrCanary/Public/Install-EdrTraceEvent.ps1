function Install-EdrTraceEvent {
    <#
    .SYNOPSIS
        Downloads Microsoft.Diagnostics.Tracing.TraceEvent from nuget.org and verifies a pinned SHA-256.
    .DESCRIPTION
        Supply-chain hygiene: the package hash is pinned, so a tampered or substituted
        package is rejected before anything is extracted or loaded.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$Destination = (Join-Path $script:ProjectRoot 'lib/traceevent'),
        [string]$Version = '3.2.8',
        [string]$Sha256 = '37284F885E75326BBD1858BF19F20C9DA2818FEC7A3BD49803209209BE5FD38D'
    )
    $id = 'microsoft.diagnostics.tracing.traceevent'
    $url = "https://api.nuget.org/v3-flatcontainer/$id/$Version/$id.$Version.nupkg"
    $tmp = Join-Path ([IO.Path]::GetTempPath()) "$id.$Version.$([guid]::NewGuid()).zip"
    if (-not $PSCmdlet.ShouldProcess($Destination, "Install TraceEvent $Version")) { return }
    try {
        Invoke-WebRequest -Uri $url -OutFile $tmp -UseBasicParsing
        $actual = (Get-FileHash -LiteralPath $tmp -Algorithm SHA256).Hash
        if ($actual -ne $Sha256.ToUpperInvariant()) { throw "SHA-256 mismatch for TraceEvent $Version (got $actual)" }
        $extract = "$tmp.d"
        Expand-Archive -LiteralPath $tmp -DestinationPath $extract -Force
        New-Item -ItemType Directory -Force -Path $Destination | Out-Null
        Copy-Item -Path (Join-Path $extract 'lib/netstandard2.0/*.dll') -Destination $Destination -Force
        $arch = if ([Environment]::Is64BitProcess) { 'amd64' } else { 'x86' }
        $native = Join-Path $extract "build/native/$arch"
        if (Test-Path $native) { Copy-Item -Path (Join-Path $native '*.dll') -Destination $Destination -Force }
        Remove-Item -LiteralPath $extract -Recurse -Force
        Get-ChildItem -LiteralPath $Destination -Filter *.dll
    }
    finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
}
