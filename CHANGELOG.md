# CHANGELOG

## 1.0.0 - 2021-4-5

### Fixes

- Fix manifest license link (Issue #112)

- Fix help document md to xml file compilation (Issue #90, #106)

### Changes

- Add constructor for `SecretInformation` class that accepts metadata as a hash table (Issue #108)

### New Features

## 0.9.1 - 2021-3-1

### Fixes

- `Get-Secret` and `Remove-Secret` cmdlets now honor the `VaultName` parameter from a piped in `SecretInformation` object (Issue #97)

- Secret name and vault name autocompletion now correctly handles names with spaces (Issue #91)

### Changes

- A warning is now displayed when secret cmdlets are used and no vaults are currently registered

### New Features

- `SecretInformation` class now has a new `Metadata` property to support the new secret metadata support (Issue #46)

- `Set-Secret` cmdlet now has a new optional `-Metadata` property to include additional non-sensitive data associated with a secret (Issue #46)

- New `Set-SecretInfo` cmdlet that takes a `-Metadata` property which sets additional non-sensitive data to a secret (Issue #46)

## 0.9.0 - 2021-1-15

### Fixes

- `Register-SecretVault` no longer emits error when strict language mode is set (Issue #81)

### Changes

- `Set-DefaultVault` cmdlet has been renamed to `Set-SecretVaultDefault` (Issue #79)

- ReadME.md document now includes installation information (Issue #86)

### New Features

## 0.5.5-Preview5 - 2020-11-16

### Fixes

- Incompatibility with WindowsPowerShell 5.1 (Issue #73)

### Changes

- The first extension vault added will automatically be designated the default vault (Issue #61)

- `Unregister-SecretVault` `-Name` property now supports string[] type and wild cards (Issue #57,#58)

- `Register-SecretVault` now checks `-VaultParameters` hashtable for reserved `Verbose` entry and throws error if found

- `Set-DefaultVault` now has a `-ClearDefault` parameter that designates no registered vault as the default vault

### New Features

- `Register-SecretVault` now supports a `-Description` parameter and registration information will include an optional extension vault description (Issue #46)

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
