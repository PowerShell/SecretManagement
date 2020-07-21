@{
    ModuleVersion = '1.0'
    RootModule = '.\AKVaultScript.Extension.psm1'
    FunctionsToExport = @('Set-Secret','Get-Secret','Remove-Secret','Get-SecretInfo','Test-SecretVault')
}
