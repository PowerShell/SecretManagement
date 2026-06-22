---
description: How to install and use the SecretManagement and SecretStore modules
ms.date: 11/10/2023
title: Get started with the SecretStore module
---
# Get started with the SecretStore module

The **SecretManagement** and **SecretStore** modules are available from the PowerShell Gallery and
can be installed using **PowerShellGet** commands.

```powershell
# Install with PowerShellGet 2.x
Install-Module Microsoft.PowerShell.SecretManagement
Install-Module Microsoft.PowerShell.SecretStore
```

or

```powershell
# Install with PSResourceGet 1.x
Install-PSResource Microsoft.PowerShell.SecretManagement
Install-PSResource Microsoft.PowerShell.SecretStore
```

Once you have installed the modules, you can load the modules and begin using or creating new
secrets.

```powershell
Import-Module Microsoft.PowerShell.SecretManagement
Import-Module Microsoft.PowerShell.SecretStore
```

## Create a vault and add a secret

First you must register the vault. The **Name** parameter is a friendly name and can be any valid
string.

```powershell
Register-SecretVault -Name SecretStore -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault
```

The **DefaultVault** parameter makes this the default vault.

Now you can create a secret.

```powershell
Set-Secret -Name TestSecret -Secret "TestSecretPassword"
```

This example passes a plaintext string for the value of the secret. The secret value can be one of
five supported types:

- **byte[]**
- **String**
- **SecureString**
- **PSCredential**
- **Hashtable**

The first time you access the vault you must provide a password for the new vault. This password is
used to lock and unlock the vault.

```Output
Vault SecretStore requires a password.
Enter password:
********
Enter password again for verification:
********
```

Run `Get-Secret` to retrieve the secret. Using the **AsPlainText** switch returns the secret as an
unencrypted string.

```powershell
PS> Get-Secret -Name TestSecret -AsPlainText
TestSecretPassword
```

To get the list of all of your secrets, you can run:

```powershell
PS> Get-SecretInfo

Name       Type   VaultName
----       ----   ---------
TestSecret String SecretStore
```

## Notes

When you run `Set-Secret` with the **Name** parameter to specify the name of the secret, the cmdlet
calls `GetSecret()` that's implemented by the vault extension. `Set-Secret` passes through the name
as provided by the user. The vault extension looks up the secret by that name. If `GetSecret()`
returns a match, `Set-Secret` overwrites the secret unless you use the **NoClobber** parameter. The
vault extension always writes the secret information it receives.

It's up to the vault extension implementation to decide whether or not to use a case-sensitive
comparison on the name. For example, secret names in the **Microsoft.PowerShell.SecretStore**
extension vault are case-insensitive. If the name you pass to `Set-Secret` differs only by case with
the name of an existing secret in a SecretStore vault, the name is overwritten with the new value
you provided.

## Related links

- [Register-SecretVault][02]
- [Get-Secret][01]
- [Set-Secret][03]

<!-- link references -->
[01]: xref:Microsoft.PowerShell.SecretManagement.Get-Secret
[02]: xref:Microsoft.PowerShell.SecretManagement.Register-SecretVault
[03]: xref:Microsoft.PowerShell.SecretManagement.Set-Secret
