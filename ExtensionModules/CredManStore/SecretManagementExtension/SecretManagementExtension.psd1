@{
    ModuleVersion = '1.0'
    RootModule = '.\SecretManagementExtension.psm1'
    RequiredAssemblies = '..\Microsoft.PowerShell.CredManStore.dll'
    FunctionsToExport = @('Set-Secret','Get-Secret','Remove-Secret','Get-SecretInfo','Test-SecretVault')
}
