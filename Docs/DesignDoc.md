# PowerShell Secrets Management Module Design

## Description

The purpose of the secrets management module is to provide secure storage and access of secrets on a local machine.
It consists of an always available local storage solution, along with a 'vault' extension mechanism that provides registration of other secrets storage/retrieval solutions.
A registered vault extension can implement a storage solution locally or remotely.  

The secrets management module provides commands for registering vault extensions, and accessing vault secrets.
This greatly reduces the temptation to hard code secrets directly into production source code, and instead use the Secrets Management module to dynamically retrieve secrets at runtime.  

Example:

```powershell
Import-Module Microsoft.PowerShell.SecretManagement

# Publish a module to the PowerShell Gallery
Publish-Module -Path C:\Modules\Publish\MyNewModule -NuGetApiKey (Get-Secret NuGetApiKey -AsPlainText)

# Run management script on multiple machines
Invoke-Command -Cn $machines -FilePath .\MyMgmtScript.ps1 -Credential (Get-Secret MgmtCred)
```

The design is based on the [Secrets Management RFC](https://github.com/PowerShell/PowerShell-RFC/pull/208).  

## Built-In local secrets store

The core of the Secrets Management design is the 'built-in vault' local secrets store.
This local store is always available and can securely store secrets based on the current user context.
On Windows platforms, the Windows Credential Manager (CredMan) is used as the local built-in vault.
On Linux platforms, Gnome Keyring will be considered.
And for macOS, KeyChain.  

The built-in local vault can be used directly to store and retrieve secrets.
But it is also used to store secrets used by other registered vault extensions.  

## Supported secret types

Secret objects supported by this module are currently limited to:

- byte[] - Blob secret

- string - String secret

- SecureString - Secure string secret

- PSCredential - PowerShell credential secret

- Hashtable - Hash table of name value pairs, where values are restricted to the above secret types.  

## Vault extension registration

Extension vaults are registered to a user context.
Information about the extension vault is collected via a registration cmdlet and information is stored as a json file in a user context based location.  

Example:

``` json
{
  "AzKeyVault": {
    "ModulePath": "C:\\Users\\paulhi\\OneDrive - Microsoft\\Documents\\PowerShell\\Modules\\AzKeyVault",
    "ImplementingType": {
      "AssemblyName": "AKVaultExtension",
      "TypeName": "AKVaultExtension.AKVaultExtension"
    },
    "ImplementingFunctions": false,
    "ModuleName": "AzKeyVault",
    "VaultParameters": "_SPT_Parameters_AzKeyVault_"
  }
}
```

Validation checks are performed on each module before being registered.  

## Extension vaults

Vault extensions are PowerShell modules that provide implementations of five required functions:

- SetSecret - Adds a secret to the vault

- GetSecret - Retrieves a secret from the vault

- RemoveSecret - Removes a secret from the vault

- GetSecretInfo - Returns information about one or more secrets (but not the secret itself)

- TestVault - Tests extension vault functions and returns True or diagnostic errors

The extension module can expose the above functions either through a C# class implementing an abstract type, or by publicly exporting script cmdlet functions.
Each function implementation takes a set of parameter arguments needed for secret manipulation and error reporting.
In addition, each function implementation takes an optional parameter argument that is a dictionary of additional parameters, specific to that implementation.
When registering the vault extension, the additional parameters are stored securely in the built-in local vault as a hashtable.
At runtime the additional parameters are read from the built-in local vault and passed to the vault implementing functions.  

### C# class implementation

The PowerShell module must include a 'RequiredAssemblies' entry in the module manifest which provides the name of the binary that implements the abstract type.  

```powershell
@{
    ModuleVersion = '1.0'
    RequiredAssemblies = @('AKVaultExtension')
}
```

```C#
// AKVaultExtension implements these abstract methods
public abstract bool SetSecret(
    string name,
    object secret,
    string vaultName,
    IReadOnlyDictionary<string, object> additionalParameters,
    out Exception error);

public abstract object GetSecret(
    string name,
    string vaultName,
    IReadOnlyDictionary<string, object> additionalParameters,
    out Exception error);

public abstract bool RemoveSecret(
    string name,
    string vaultName,
    IReadOnlyDictionary<string, object> additionalParameters,
    out Exception error);

public abstract SecretInformation[] GetSecretInfo(
    string filter,
    string vaultName,
    IReadOnlyDictionary<string, object> additionalParameters,
    out Exception error);

public abstract bool TestVault(
    string vaultName,
    IReadOnlyDictionary<string, object> additionalParameters,
    out Exception[] errors);
```

When PowerShell loads the module, the required assembly will be loaded and the implementing type becomes available.

### PowerShell script implementation

For a script implementation, the PowerShell module must include a subdirectory named 'SecretManagementExtension' in the same directory containing the module manifest file.
The SecretManagementExtension subdirectory must contain PowerShell script module files named 'SecretManagementExtension' that implements the required script functions.  

SecretManagementExtension.psd1

```powershell
@{
    ModuleVersion = '1.0'
    RootModule = '.\SecretManagementExtension.psm1'
    FunctionsToExport = @('Set-Secret','Get-Secret','Remove-Secret','Get-SecretInfo','Test-Vault')
}
```

SecretManagementExtension.psm1

```powershell
function Set-Secret
{
    param (
        [string] $Name,
        [object] $Secret,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )
}

function Get-Secret
{
    param (
        [string] $Name,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )
}

function Remove-Secret
{
    param (
        [string] $Name,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )
}

function Get-SecretInfo
{
    param (
        [string] $Filter,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )
}

function Test-Vault
{
    param (
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )
}
```

## Vault registration cmdlets

The following cmdlets are provided for vault extension registration.  

```powershell
Register-SecretVault
Get-SecretVault
Unregister-SecretVault
```

`Register-SecretVault` registers a PowerShell module as an extension vault for the current user context.
Validation is performed to ensure the module either provides the required binary with implementing type or the required script commands.
If a dictionary of additional parameters is specified then it will be stored securely in the built-in local vault.  

`Get-SecretVault` returns a list of extension vaults currently registered in the user context.  

`Unregister-SecretVault` un-registers an extension vault.

`Test-Vault` tests a registered extension vault functions and returns True if good.

## Secrets cmdlets

The following cmdlets are provided for manipulating secrets.  

```powershell
Add-Secret
Get-Secret
Get-SecretInfo
Remove-Secret
```

`Add-Secret` Adds a secret to a specified vault.  

`Get-Secret` returns a single secret from a given name.
When retrieving a string secret type, the Get-Secret cmdlet will convert the string secret to a SecureString type and return that.
Unless the `-AsPlainText` switch is used, in which case the secret string will be returned as plain text.
See the [Security]() section of this document for more information.  

`Get-SecretInfo` returns information about each secret stored in all registered vaults, including the built-in local vault.
This does not return the actual secret, which can only be obtained via the `Get-Secret` cmdlet.
Information returned is `Name, TypeName, VaultName`.  

`Remove-Secret` removes a secret by name from a given vault.  

## Security

### Extension vault security

Extension vault module implementations are responsible for working securely.  

### Local Built-in vault security

The local built-in vault implementations (for different platforms) will use known secure solutions for storing blobs, such as CredMan for Windows, Keyring for Linux, and KeyChain for macOS.  

### Intermediate secret objects

The Secrets Management module makes a best effort to zero out any intermediate secret objects not returned to the user.
For example byte arrays used in storing and retrieving SecureString blobs are zeroed out after use.
But strings are immutable in C# and cannot be easily or reliably altered, and so must rely on the CLR garbage collection.

### Plain text secrets

The Secrets Management module supports storing and retrieving plain text secret types, such as passwords and API keys.
The secret string type will be stored securely, but when retrieved will be converted to a SecureString type.
Unless the user specifically requests the secret string to be returned as plain text by using the `-AsPlainText` switch on the `Get-Secret` cmdlet.
This is to prevent inadvertent exposure of secrets as plain text to a display or transcript/history/log collections.  

On Windows platform, SecureString types contain an encrypted version of the text data that is keyed to the current user context and local machine.
But for all other platforms (Linux, macOS) this kind of default encryption is not possible so the dotNet SecureString type contains an unencrypted blob of the text.
However, SecureString still serves a purpose on non-Windows platforms, since it will not provide the plain text directly, and another dotNet API is needed to return the string contents in plain text.
So on non-Windows platforms SecureString still provides some security through obscurity (but not encryption).
