---
description: This article explains how to use a SecretStore vault in an automation scenario to securely retrieve an use passwords or other secret material.
ms.date: 03/06/2024
title: Use the SecretStore in automation
---
# Use the SecretStore in automation

This article provides an example for using a **Microsoft.PowerShell.SecretStore** vault in an
automation scenario. A **SecretStore** vault provides you a way to securely store and retrieve the
passwords, tokens and other secrets you need to use in your automation pipeline on the local
machine.

## Set up the host that runs the automation

For this example you must first install and configure the SecretManagement modules. This example
assumes that your automation host is running Windows. These commands must be run in the user context
of the automation account on the host.

```powershell
Install-Module -Name Microsoft.PowerShell.SecretStore -Repository PSGallery -Force
Install-Module -Name Microsoft.PowerShell.SecretManagement -Repository PSGallery -Force
Import-Module Microsoft.PowerShell.SecretStore
Import-Module Microsoft.PowerShell.SecretManagement
```

## Configure the SecretStore vault

You must also create a password as a **SecureString** that's used to secure the SecretStore vault.
The automation system you use might have a way to securely provide a password that you can use to
secure the vault. For example, GitHub provides a way to securely store and use secrets in GitHub
Actions. For more information, see [Using secrets in GitHub Actions][01].

In this example, the password is a **SecureString** that is securely exported to an XML file and
encrypted by Windows Data Protection (DPAPI). The following command prompts you for a password. In
this example the **UserName** is unimportant.

```powershell
PS> $credential = Get-Credential -UserName 'SecureStore'

PowerShell credential request
Enter your credentials.
Password for user SecureStore: **************
```

Once you have the password you can save it to an encrypted XML file.

```powershell
$securePasswordPath = 'C:\automation\passwd.xml'
$credential.Password |  Export-Clixml -Path $securePasswordPath
```

Next you must configure the **SecretStore** vault. The configuration sets user interaction to
`None`, so that **SecretStore** never prompts the user. The configuration requires a password, and
the password is passed in as a **SecureString** object. The `-Confirm:false` parameter is used so
that PowerShell does not prompt for confirmation.

```powershell
Register-SecretVault -Name SecretStore -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault
$password = Import-CliXml -Path $securePasswordPath

$storeConfiguration = @{
    Authentication = 'Password'
    PasswordTimeout = 3600 # 1 hour
    Interaction = 'None'
    Password = $password
    Confirm = $false
}
Set-SecretStoreConfiguration @storeConfiguration
```

Now that you have the vault installed and configured, you can use `Set-Secret` to add the secrets
you need for your automation scripts.

## Use secrets in automation

The **SecretStore** password must be provided in a secure fashion. Here the password is being
imported from a file that was encrypted using Windows Data Protection (DPAPI).

> [!NOTE]
> This is a Windows-only solution, but another option is to use a secure variable provided by a CI
> system like GitHub Actions.

The automation script needs to unlock the vault to retrieve the secrets needed in the script. The
`Unlock-SecretStore` cmdlet is used to unlock the **SecretStore** for this session. The password
timeout was configured for 1 hour. The vault remains unlocked in the session for that amount of
time. After the timeout, the vault must be unlocked again before secrets can be accessed.

```powershell
$password = Import-CliXml -Path $securePasswordPath
Unlock-SecretStore -Password $password
$automationPassword = Get-Secret -Name CIJobSecret
```

<!-- link references -->
[01]: https://docs.github.com/actions/security-guides/using-secrets-in-github-actions
