---
description: Overview of the SecretManagement and SecretStore modules
ms.date: 06/28/2023
title: Overview of the SecretManagement and SecretStore modules
---
# Overview of the SecretManagement and SecretStore modules

The **SecretManagement** module helps users manage secrets by providing a common set of cmdlets that
interface with secrets vaults. **SecretManagement** provides an extensible model where local and
remote vaults can be registered for use. This allows you to separate the specific details for
accessing and managing the vault from your scripts that need secrets.

Since **SecretManagement** is a module abstraction layer in PowerShell, it becomes useful once
extension vaults are registered. There are trade-offs between security, usability, and specificity
for any vault so it's up to the user to configure **SecretManagement** to integrate with the vaults
that best match their requirements, as well as to assess the extent to which they trust any vault
extensions not developed by Microsoft.

**SecretManagement** doesn't impose authentication requirements for extension vaults. This allows
each individual vault to provide its own mechanism. Some may require a password or token, while
others may leverage current account credentials.

**SecretManagement** enables the following key scenarios:

- Sharing a script across your organization without knowing the local vault of all the users
- Running your deployment script in local, test, and production environments with the change of only
  a single parameter, **Vault**
- Changing the backend of the authentication method to meet specific security or organizational
  needs without needing to update all your scripts

## Extension Vault Ecosystem

**SecretManagement** becomes useful once you install and register extension vaults. Extension
vaults, which are PowerShell modules with a particular structure, provide the connection between the
**SecretManagement** module and any local or remote Secret Vault.

**SecretStore** is a cross-platform extension module that implements a local vault. The
**SecretStore** vault stores secrets, locally in a file, for the current user. It uses .NET Core
cryptographic APIs to encrypt file contents. This extension vault works on all platforms that
support PowerShell 7.

### Discovering and Installing Vault Extensions

To find extension vault modules, search the PowerShell Gallery for the
[SecretManagement tag][03].

Some community vault extensions that are available:

- [Azure KeyVault][04] (Microsoft Owned)
- [KeePass][07]
- [LastPass][09]
- [Hashicorp Vault][05]
- [KeyChain][08]
- [CredMan][06]

## Community feedback and support

Community feedback has been essential to the iterative development of these modules. To file issues
or get support for the SecretManagement interface or vault development experience please use the
[SecretManagement][01] repository. For issues with the SecretStore module please use the
[SecretStore][02] repository.

<!-- link references -->
[01]: https://github.com/PowerShell/SecretManagement/issues
[02]: https://github.com/PowerShell/SecretStore/issues
[03]: https://www.powershellgallery.com/packages?q=Tags%3A%22SecretManagement%22
[04]: https://www.powershellgallery.com/packages/Az.KeyVault
[05]: https://www.powershellgallery.com/packages/SecretManagement.Hashicorp.Vault.KV
[06]: https://www.powershellgallery.com/packages/SecretManagement.JustinGrote.CredMan
[07]: https://www.powershellgallery.com/packages/SecretManagement.KeePass
[08]: https://www.powershellgallery.com/packages/SecretManagement.KeyChain
[09]: https://www.powershellgallery.com/packages/SecretManagement.LastPass
