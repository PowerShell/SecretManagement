# CHANGELOG

## 0.5.4-Preview5 - 2020-11-4

### Fixes

### Changes

- `Get-Secret` `-Name` parameter now accepts arguments with wild card characters as literals (Issue #67)

- The `Verbose` parameter switch is now passed to extension vault module functions as an `AdditionalParameters` name/value pair (Issue #66)

- `Get-SecretVault` `-Name` parameter now takes a `string[]` type argument (Issue #59)

- `Test-SecretVault` `-Name` parameter now takes a `string[]` type argument and accepts wild card characters (Issue #56)

- `Register-SecretVault` now has a `-PassThru` parameter to return information on the secret vault just registered

### New Features

- When an extension vault is unregistered and if the vault provides a `Unregister-SecretVault` function, that extension vault function will be called before the extension vault is unregistered (Issue #60)

- Vault name and Secret name completers have been added to the cmdlets (Issue #35)

## 0.5.3-Preview4 - 2020-09-24

### Fixes

- Windows PowerShell cannot register extension vaults (Error: Cannot bind argument to parameter 'Path' ...)  

### Changes

- Change SecretVaultInfo `VaultName` property to `Name`, for consistency

- `Test-SecretVault` `-Vault` parameter changed to `-Name` for consistency

### New Features

- Add `-AllowClobber` parameter switch to `Register-SecretVault`, to allow overwriting existing vault

- `Register-SecretVault` `-Name` parameter is now optional, and will use module name if not provided

- `Unregister-SecretVault` now supports `Name` parameter argument from pipeline

- `Set-DefaultVault` now supports `Name` and `SecretVaultVaultInfo` parameter arguments from pipeline

- `Set-Secret` now supports `SecretInfo` objects from the pipeline

- Add `WhatIf` support to `Secret-Secret`

- Add `WhatIf` support to `Remove-Secret`
