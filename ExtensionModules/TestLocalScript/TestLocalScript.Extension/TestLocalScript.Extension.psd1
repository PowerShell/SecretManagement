@{
    ModuleVersion = '1.0'
    RootModule = '.\TestLocalScript.Extension.psm1'
    FunctionsToExport = @('Set-Secret','Get-Secret','Remove-Secret','Get-SecretInfo','Test-SecretVault','Unregister-SecretVault')
}
