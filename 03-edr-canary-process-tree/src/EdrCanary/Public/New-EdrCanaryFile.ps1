function New-EdrCanaryFile {
    <#
    .SYNOPSIS
        Deploys a decoy file that no legitimate process should ever modify.
    .DESCRIPTION
        Ransomware enumerates and encrypts breadth-first, and a name like "0_passwords.docx"
        sorts first, so the decoy is typically among the first files touched. Returns the
        path and its baseline SHA-256 so tampering can be proven after the fact.
    .EXAMPLE
        New-EdrCanaryFile -Directory C:\Share\Finance -Name 0_passwords.docx
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Directory,
        [string]$Name = '0_passwords.docx',
        [switch]$Hidden
    )
    if ($Name -match '[\\/]' -or $Name -in @('.', '..')) { throw "Canary name must be a plain file name: $Name" }
    $path = Join-Path $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Directory) $Name
    if ($PSCmdlet.ShouldProcess($path, 'Deploy canary file')) {
        New-Item -ItemType Directory -Force -Path $Directory | Out-Null
        $content = @(
            'CONFIDENTIAL - CANARY DECOY FILE - DO NOT MODIFY'
            'This file is a ransomware tripwire placed by the EDR canary. Any write, rename or'
            'delete raises a critical alert attributed to the responsible process.'
            "Generated $([datetime]::UtcNow.ToString('o')) on $([Environment]::MachineName)"
        ) -join [Environment]::NewLine
        [IO.File]::WriteAllText($path, $content, (New-Object System.Text.UTF8Encoding($false)))
        if ($Hidden -and (Test-EdrIsWindows)) { (Get-Item -LiteralPath $path).Attributes = 'Hidden' }
    }
    $hash = if (Test-Path -LiteralPath $path) { (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash } else { $null }
    [pscustomobject]@{ Path = [IO.Path]::GetFullPath($path); Sha256 = $hash }
}
