@{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        # Console entry points report progress to the operator on purpose.
        'PSAvoidUsingWriteHost'
    )
    Rules        = @{
        PSUseCompatibleSyntax = @{ Enable = $true; TargetVersions = @('5.1', '7.4') }
    }
}
