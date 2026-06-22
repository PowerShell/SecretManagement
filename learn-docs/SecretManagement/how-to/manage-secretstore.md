---
description: Explains how to manage a local SecretStore vault
ms.date: 06/28/2023
title: Managing a SecretStore vault
---
# Managing a SecretStore vault

The **SecretStore** module is an extension vault for the PowerShell **SecretManagement** module. It
stores secrets, locally, in files for the current user account context, and uses .NET crypto APIs to
encrypt file contents. The **SecretStore** module has several configuration options. In the default
configuration, a password is required to store and access secrets, and provides the strongest
protection. **SecretStore** also supports the storage of metadata about secrets.

## Registering a new vault

Before you can create new secret you must register a vault. The **Name** parameter is a friendly
name and can be any valid string.

```powershell
Register-SecretVault -Name SecretStore -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault
```

> [!IMPORTANT]
> The **SecretManagement** module allows an extension vault to be registered multiple times, because
> it's possible that an extension vault may support different contexts via the registration
> **VaultParameters**. However, the **SecretStore** vault currently _always_ operates in the logged on
> user scope. Registering multiple **SecretStore** vaults with different names just results in
> duplication of the same store.

Use the following command to see a list of registered vaults:

```powershell
Get-SecretVault

Name        ModuleName                       IsDefaultVault
----        ----------                       --------------
Edge        SecretManagement.Chromium        False
SecretStore Microsoft.PowerShell.SecretStore True
```

In this example there are two vaults registered using different extension modules.

## Configuring a vault

Use the `Get-SecretStoreConfiguration` cmdlet to see a vault's configuration.

```powershell
Get-SecretStoreConfiguration

      Scope Authentication PasswordTimeout Interaction
      ----- -------------- --------------- -----------
CurrentUser       Password             900      Prompt
```

**SecretStore** vaults have the following configuration settings:

- **Authentication** - `Password` (default) or `None`
- **PasswordTimeout** - `900` seconds (default)
- **Interaction** - `Prompt` (default) or `None`

The default configuration requires a password, sets the session password timeout to 15 minutes, and
prompts the user for a password to unlock the vault.

For non-interactive automation scenarios, the **Interaction** can be configured as `None` to
suppress user prompting. If a password is required, vault commands return
**Microsoft.PowerShell.SecretStore.PasswordRequiredException** exception if there is no valid
session password. The `Unlock-SecretStore` cmdlet can be used to provide the password for the
current PowerShell session. The vault remains unlocked until the timeout expires.

Vault configuration and data are stored in separate files. The file location depends on the platform
operating system.

- For Windows platforms the location is: `$env:LOCALAPPDATA\Microsoft\PowerShell\secretmanagement\localstore\`
- For Non-Windows platforms the location is: `$HOME/.secretmanagement/localstore/`

### Changing the configuration

You can change the configuration of a vault using the `Set-SecretStoreConfiguration` cmdlet. The
cmdlet provides the parameters **Authentication**, **PasswordTimeout**, and **Interaction** that are
used to change the corresponding configuration properties. There is also a **Default** parameter to
reset the configuration back to the default values.

There are two ways to set the password on the vault.

1. The `Set-SecretStoreConfiguration` cmdlet has the **Password** parameter that takes a
   **SecureString** value.
1. The `Set-SecretStorePassword` cmdlet changes the vault password. The cmdlet takes no parameters
   and can only be used interactively. You are prompted the for old and new passwords.

### Adding metadata

The **SecretStore** module allows you to add non-sensitive metadata to your secrets. The metadata
can be used to document the intended purpose of a secret. For example, to indicate that a secret
is intended for a particular subscription or application scenario. You could also add metadata
about the secret's creation date, expiration time, or other information used to manage the secret
lifecycle.

The metadata can be any arbitrary key-value pair. The **SecretStore** module supports the following
value types for metadata:

- **string**
- **int**
- **DateTime**

To create a new secret with metadata:

```powershell
$metadata = @{
    Purpose = 'Testing'
    Expires = (Get-Date).AddDays(30)
    Limit = 5
}
Set-Secret -Name TestSecret -Secret NewSecret -Metadata $metadata
```

To view secret metadata you can then run the command:

```powershell
Get-SecretInfo -Name TestSecret | Format-List *

Name      : TestSecret
Type      : String
VaultName : SecretStore
Metadata  : {[Limit, 5], [Expires, 6/23/2022 1:45:09 PM], [Purpose, Testing]}
```

You can also set metadata for an existing secret using the `Set-SecretInfo` cmdlet:

```powershell
Set-SecretInfo TestSecret -Metadata @{Purpose = "showing the new cmdlet"}
Get-SecretInfo -Name TestSecret | Select-Object Metadata

Metadata
--------
{[Purpose, showing the new cmdlet]}
```

> [!CAUTION]
> This overwrites any existing metadata with the new values.

### Resetting or removing a vault

The `Reset-SecretStore` cmdlet resets the **SecretStore** vault by deleting all secret data and
configuring the store with default options. It is intended to be used only when the required
password is lost or data files become corrupted. The default configuration options can be overridden
by specifying individual command configuration option parameters.

## Related links

- [Get-SecretInfo](xref:Microsoft.PowerShell.SecretManagement.Get-SecretInfo)
- [Get-SecretStoreConfiguration](xref:Microsoft.PowerShell.SecretStore.Get-SecretStoreConfiguration)
- [Register-SecretVault](xref:Microsoft.PowerShell.SecretManagement.Register-SecretVault)
- [Reset-SecretStore](xref:Microsoft.PowerShell.SecretStore.Reset-SecretStore)
- [Set-Secret](xref:Microsoft.PowerShell.SecretManagement.Set-Secret)
- [Set-SecretInfo](xref:Microsoft.PowerShell.SecretManagement.Set-SecretInfo)
- [Set-SecretStoreConfiguration](xref:Microsoft.PowerShell.SecretStore.Set-SecretStoreConfiguration)
- [Set-SecretStorePassword](xref:Microsoft.PowerShell.SecretStore.Set-SecretStorePassword)
- [Unlock-SecretStore](xref:Microsoft.PowerShell.SecretStore.Unlock-SecretStore)
