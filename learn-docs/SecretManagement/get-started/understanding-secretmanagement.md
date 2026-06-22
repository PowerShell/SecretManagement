---
description: Explains concepts and usage of the SecretManagement module
ms.date: 06/28/2023
title: Understanding the SecretManagement module
---
# Understanding the SecretManagement module

The purpose of the **SecretManagement** module is to provide secure storage and access of secrets
through registered extension vaults. The registered extension vaults are PowerShell modules that
conform to **SecretManagement** module requirements. The extension vaults perform the actual work of
authentication and securely storing and retrieving secrets. An extension vault can store secrets
locally or remotely for a cloud-based store.

The **SecretManagement** module provides commands for registering vault extensions, and accessing
vault secrets. This greatly reduces the temptation to hardcode secrets directly into production
source code. Instead, the **SecretManagement** module allows you to dynamically retrieve secrets at
runtime.

Extension vaults are registered for the current user context. Vault registration is stored
separately from vault data files. The file location depends on the platform operating system.

- For Windows platforms the location is:
  `$env:LOCALAPPDATA\Microsoft\PowerShell\secretmanagement\secretvaultregistry\`
- For Non-Windows platforms the location is: `$HOME/.secretmanagement/secretvaultregistry/`

## Getting started with SecretManagement

Once you have **SecretManagement** installed you can run `Get-SecretVault` to see what secret vaults
you have registered. If this is your first time using the module, this command returns nothing. Once
you have a vault registered you can use the **SecretManagement** cmdlets to view, get, set, and
remove secrets. To see an example of registering a vault, see
[Get started with the SecretStore module][04].

The **SecretManagement** module helps users manage secrets by providing a common set of cmdlets to
interface with secrets across vaults. For a full list of cmdlets, see the
[Microsoft.PowerShell.SecretManagement][01] module page in the documentation.

## Building an extension vault

The value of the **SecretManagement** interface comes from the underlying vault and becomes more
useful with each extension vault module. For more information on the design of SecretManagement and
how to build extension vaults, see the [design document][02] in the **SecretManagement** repository.
This document describes a reference implementation **TestVault** module. Also, reviewing the source
code of the [SecretStore][03] module may serve as an example for extension vault authors looking to
build off of existing vaults.

## Windows Managed Accounts

**SecretManagement** doesn't currently work for Windows managed accounts. The module depends on both
`$env:LOCALAPPDATA` folders to store registry information and Windows Data Protection APIs (DPAPI)
for safely handling secrets with the .NET **SecureString** type. Windows managed accounts do not
have profiles or `$env:LOCALAPPDATA` folders and DPAPI doesn't support managed accounts.

<!-- link references -->
[01]: /powershell/module/microsoft.powershell.secretmanagement
[02]: https://github.com/PowerShell/SecretManagement/blob/master/Docs/ARCHITECTURE.md
[03]: https://github.com/PowerShell/SecretStore
[04]: using-secretstore.md
