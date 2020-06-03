# PowerShell Secrets Management module

PowerShell Secrets Management module provides a convenient way for a user to store secrets from a local machine.
It can store the secret locally using the built-in local vault.
In addition other secret storage solutions, or extension vaults, can be registered that provide either local or remote secret storage.  

The module supports the following secret types:

- byte[]
- string
- SecureString
- PSCredential
- Hashtable

The module exposes cmdlets for for accessing and manipulating secrets, and also cmdlets for registering and manipulating vault extensions.  

Registering extension vaults:

- Register-SecretVault
- Get-SecretVault
- Unregister-SecretVault
- Test-SecretVault

Accessing secrets:

- Set-Secret
- Get-Secret
- Get-SecretInfo
- Remove-Secret

## Vault extension registration

Vault extensions are registered to the current user context.
They are registered as PowerShell modules that expose required methods used by Secrets Management to manipulate secrets.
The required methods can be exposed in two different module types: a binary module or a script module.
There are four methods that Secrets Management requires an extension vault to provide:

- Get-Secret  
Retrieves a single secret object from the extension vault (required).
- Get-SecretInfo  
Enumerates all secrets from the extension vault (required).
Only information about the secret is returned: secret name, secret type.
The actual secret is not returned.
- SetSecret  
Stores a single secret object to the extension vault (optional).
- Remove-Secret  
Removes a single secret object from the extension vault (optional).

### Binary module vault extension

This is a PowerShell module with a manifest file (.psd1) that specifies a managed assembly that implements the SecretManagementExtension abstract class.
An example of such a module has been provided in the `TestExtensionModules\AKVault\` directory.
This binary module uses the Azure `Az.Accounts` and `Az.KeyVault` PowerShell modules to add/remove/retrieve SecureString secrets from an Azure KeyVault resource.
See the `TestExtensionModules\AKVault\build\AKVaultExtension\AKVaultExtension.cs` source file for details.
This module requires extra information in order to connect to an Azure KeyVault resource, and uses the Secrets Management optional `-VaultParameters` optional dictionary parameter to provide that information to the implementation module.
Since the Secrets Management can't know if the `-VaultParameters` contain secrets, the dictionary is always securely stored as a hashtable in the built-in local vault.
An example registration of a working vault extension using this module is:

```powershell
Register-SecretVault -Name AzKeyVault -ModuleName AKVault -VaultParameters @{ AZKVaultName = 'MyAzKeyVault'; SubscriptionId = 'f3bc301d-40b7-4bcb-8e66-b1b238200f02' }
```

This module basically implements the five required methods as a C# class implementing the abstract SecretManagementExtension class (again see the `AKVaultExtension.cs` source file for details).

```C#
public override object GetSecret(
    string name,
    string vaultName,
    IReadOnlyDictionary<string, object> additionalParameters,
    out Exception error)
{ }

public override KeyValuePair<string, string>[] GetSecretInfo(
    string filter,
    string vaultName,
    IReadOnlyDictionary<string, object> additionalParameters,
    out Exception error)
{ }

public override bool SetSecret(
    string name,
    object secret,
    string vaultName,
    IReadOnlyDictionary<string, object> additionalParameters,
    out Exception error)
{ }

public override bool RemoveSecret(
    string name,
    string vaultName,
    IReadOnlyDictionary<string, object> additionalParameters,
    out Exception error)
{ }

public override bool TestVault(
    string vaultName,
    IReadOnlyDictionary<string, object> additionalParameters,
    out Exception[] errors)
{ }
```

### Script module vault extension

NOTE: This example applies to Microsoft.PowerShell.SecretManagement module version 0.2.0 or higher.  

This is a PowerShell module that implements the required four methods as PowerShell script functions.
The actual module containing the script implementation is in a subdirectory of the vault module and named `SecretManagementExtension`.
This is done to "hide" the implementing module from PowerShell command discovery, which prevents the implementing module script functions from being exposed to the user on the command line.
An example of such a module has been provided in the `TestExtensionModules\AKVaultScript\` directory.  

This module provides the same Azure KeyVault extension functions as the binary module above, but does so with PowerShell script functions rather than a managed binary implementing type.
It consists of an SecretManagementExtension module that implements the script functions defined in the `SecretManagementExtension.psm1` file, and exports the four required functions in the `SecretManagementExtension.psd1` manifest file.  

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
function Get-Secret
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

function Set-Secret
{
    param (
        [string] $Name,
        [object] $Secret,
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

function Test-Vault
{
    param (
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

}
```

A vault extension doesn't need to provide full implementation of all required methods.
For example, a vault extension does not need to provide a way to add or remove a secret through the Secrets Management cmdlets.
However, it should always implement secret retrieval (GetSecret, GetSecretInfo).
If a vault extension doesn't support some functionality (such as add/remove a secret, or a particular secret type), then it should throw an exception with a meaningful error message.  

Both of the binary and script modules implement the four functions in similar ways.
The method/functions take the same parameters, including optional additional parameters, and return the same object(s).

- Get-Secret  
Input Parameters: Name, VaultName, AdditionalParameters  
Output: Secret object
- Get-SecretInfo  
Input Parameters: Filter, VaultName, AdditionalParameters  
Output: PSObject with two properties: Name, TypeName
- Set-Secret  
Input Parameters: Name, Secret, VaultName, AdditionalParameters  
Output: True on success, False otherwise
- Remove-Secret  
Input Parameters: Name, VaultName, AdditionalParameters  
Output: True on success, False otherwise
- Test-Vault
Input Parameters VaultName, AdditionalParameters
Output: True for valid vault, False otherwise

You have to be careful with PowerShell script functions, because there are many ways for objects to be added to the output pipeline and the Secrets Management module expects very specific output objects from the functions.
Make sure your script implementation does not inadvertently insert spurious objects to the pipeline, which will confuse the Secrets Management module.
