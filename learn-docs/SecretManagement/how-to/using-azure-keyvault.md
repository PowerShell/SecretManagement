---
description: This article explains how to use an Azure Key Vault module, as a SecretManagement extension vault, in an automation scenario to securely retrieve and use passwords or other secret material.
ms.date: 12/05/2023
title: Use Azure Key Vault in automation
---
# Use Azure Key Vault in automation

This article provides an example for using Azure Key Vault in an automation scenario. Azure Key
Vault provides you a way to securely store and retrieve the passwords, tokens and other secrets,
that are stored outside of the local machine, and use them in your automation pipeline.

## Set up the host that runs the automation

Beginning with **Az.KeyVault** 3.3.0, the module includes a **SecretManagement** extension that
allows you to use the **SecretManagement** cmdlets to interact with secrets stored in Azure Key
Vault.

First, you should create a Key Vault in your Azure subscription and add your secrets. For more
information, see
[Quickstart: Set and retrieve a key from Azure Key Vault using Azure PowerShell][azkv-quick].

To use the Azure Key Vault with **SecretManagement** first ensure that you have the
[Az.KeyVault][Az.KeyVault] module.

Next, register the vault using your **AZKVaultName** and **SubscriptionId**. These commands must be
run in the user context of the automation account on the automation host.

```powershell
Install-Module -Name Microsoft.PowerShell.SecretManagement -Repository PSGallery -Force
Install-Module Az.KeyVault -Repository PSGallery -Force
Import-Module Microsoft.PowerShell.SecretManagement
Import-Module Az.KeyVault

$VaultParameters = @{
    AZKVaultName = $vaultName
    SubscriptionId = $subID
}
Register-SecretVault -Module Az.KeyVault -Name AzKV -VaultParameters $VaultParameters
```

## Use Azure Key Vault secrets in automation

Now that you have registered your Azure Key Vault with **SecretManagement** you can view secrets
with `Get-SecretInfo`, get secrets with `Get-Secret`, create and update secrets with `Set-Secret`,
and remove secrets with `Remove-Secret`.

<!-- reference links -->
[azkv-quick]: /azure/key-vault/keys/quick-create-powershell
[Az.KeyVault]: https://www.powershellgallery.com/packages/Az.KeyVault
