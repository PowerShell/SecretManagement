# CHANGELOG

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
