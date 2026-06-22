---
Module Name: Microsoft.PowerShell.SecretManagement
Module Guid: a5c858f6-4a8e-41f1-b1ee-0ff8f6ad69d3
ms.date: 05/23/2025
Download Help Link: https://aka.ms/ps-modules-help
Help Version: 0.1.0.0
Locale: en-US
---

# Microsoft.PowerShell.SecretManagement Module

## Description

PowerShell SecretManagement module provides a convenient way for a user to store and retrieve
secrets. The secrets are stored in SecretManagement extension vaults. An extension vault is a
PowerShell module that has been registered to SecretManagement, and exports five module functions
required by SecretManagement. An extension vault can store secrets locally or remotely. Extension
vaults are registered to the current logged in user context, and are available only to that user.

## Microsoft.PowerShell.SecretManagement Cmdlets

### [Get-Secret](Get-Secret.md)

Finds and returns a secret by name from registered vaults.

### [Get-SecretInfo](Get-SecretInfo.md)

Finds and returns metadata information about secrets in registered vaults.

### [Get-SecretVault](Get-SecretVault.md)

Finds and returns registered vault information.

### [Register-SecretVault](Register-SecretVault.md)

Registers a SecretManagement extension vault module for the current user.

### [Remove-Secret](Remove-Secret.md)

Removes a secret from a specified registered extension vault.

### [Set-Secret](Set-Secret.md)

Adds a secret to a SecretManagement registered vault.

### [Set-SecretInfo](Set-SecretInfo.md)

Adds or replaces additional secret metadata to a secret currently stored in a vault.

### [Set-SecretVaultDefault](Set-SecretVaultDefault.md)

Sets the provided vault name as the default vault for the current user.

### [Test-SecretVault](Test-SecretVault.md)

Runs an extension vault self test.

### [Unlock-SecretVault](Unlock-SecretVault.md)

Unlocks an extension vault so that it can be access in the current session.

### [Unregister-SecretVault](Unregister-SecretVault.md)

Un-registers an extension vault from SecretManagement for the current user.
