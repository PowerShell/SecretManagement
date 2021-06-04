# PowerShell SecretManagement Module Architecture

## Description

The purpose of the SecretManagement module is to provide secure storage and access of secrets, through registered extension vaults.
The registered extension vaults are PowerShell modules that conform to SecretManagement module requirements.
The extension vaults perform the actual work of authentication, and securely storing and retrieving secrets.
An extension vault can store secrets locally or remotely for a cloud based store.
Extension vault registration registers vaults for the current user context.
So, the SecretManagement module is essentially an orchestrator of extension vaults.  

The SecretManagement module provides commands for registering vault extensions, and accessing vault secrets.
This greatly reduces the temptation to hard code secrets directly into production source code, and instead use the SecretManagement module to dynamically retrieve secrets at runtime.  

### Using SecretManagement

```powershell
Import-Module Microsoft.PowerShell.SecretManagement

# See what extension vaults are registered for current user
Get-SecretVault

VaultName  ModuleName                        IsDefaultVault
---------  ----------                        --------------
CredMan    Microsoft.PowerShell.CredManStore False
LocalStore Microsoft.PowerShell.SecretStore  True

# Publish a module to the PowerShell Gallery, using a key from the SecretManagement default extension vault
Publish-Module -Path C:\Modules\Publish\MyNewModule -NuGetApiKey (Get-Secret NuGetApiKey -AsPlainText)

# Run management script on multiple machines, using stored credentials from the default extension vault
Invoke-Command -Cn $machines -FilePath .\MyMgmtScript.ps1 -Credential (Get-Secret MgmtCred)
```

The design is based on the [SecretManagement RFC](https://github.com/PowerShell/PowerShell-RFC/pull/208).  

## Supported secret types

Secret objects supported by this module are currently limited to:

- byte[] - Blob secret

- string - String secret

- SecureString - Secure string secret

- PSCredential - PowerShell credential secret

- Hashtable - Hash table of name value pairs, where values are restricted to the above secret types.  

## Secret metadata

Extension vaults can optionally support storing and retrieving additional secret metadata, that is data associated with the secret.  
Secret metadata is not security sensitive and does not need to be stored securely in the extension vault.  

Secret metadata can be included by using the `-Metadata` parameter: `Set-Secret -Metadata @{ Name=Value }`.
The `-Metadata` parameter takes a `Hashtable` type argument consisting of name/value pairs.  
Extension vaults should at minimum support the following value types:  

- string

- int

- DateTime

The secret metadata is included in the `SecretInformation` type object returned by `Get-SecretInfo`, in a `Metadata` property.  
The `Metadata` property is a `ReadonlyDictionary<string, object>` type.  

## Vault extension hosting

Extension vault modules are hosted in a separate PowerShell runspace session that is separate from the current user PowerShell session.
This provides a layer of isolation between the user and extension vault operations.
But it also means that extension vaults cannot depend on any shared state with the user session, such as variables or loaded modules.
An extension vault must ensure all module dependencies are listed in its manifest, and any required information is passed in explicitly to the module.  

There is one shared component between the extension vault session and the current user session, and that is the PowerShell host (PSHost).
The PSHost is the object used by PowerShell to communicate with a user in an interactive session.
When the extension vault runspace session is created, the current user session PSHost object is transferred to the vault session.
This provides extension vaults with the ability to write error, warning, verbose, etc. information to the host for the user, including directly prompting the user interactively (for example prompting the user for a password).  

Vault extension modules were originally hosted in the same session as the user session.
However, this prevented SecretManagement from running in a constrained language mode session.
Consequently, starting with v1.1, the extension vaults are hosted in a separate runspace process.  

## Vault extension registration

Extension vaults are registered to the current user context.
Information about the extension vault is collected via a registration cmdlet and information is stored as a json file in a user context based location.  

Example:

``` json
{
  "Vaults": {
    "CredMan": {
      "VaultParameters": {},
      "ModulePath": "C:\\Modules\\Microsoft.PowerShell.CredManStore",
      "ModuleName": "Microsoft.PowerShell.CredManStore"
    },
    "LocalStore": {
      "VaultParameters": {
        "DefaultLocation": "None"
      },
      "ModulePath": "C:\\Modules\\Microsoft.PowerShell.SecretStore",
      "ModuleName": "Microsoft.PowerShell.SecretStore"
    }
  },
  "DefaultVaultName": "LocalStore"
}
```

Validation checks are performed on each module before being registered.  

## Extension vaults

Vault extensions are PowerShell modules that provide five required functions, and one optional function

### Extension vault module required functions

#### Set-Secret

Adds a secret to the vault

#### Set-SecretInfo

Adds or replaces additional secret metadata to an existing secret in the vault.
Metadata is not stored securely.

#### Get-Secret

Retrieves a secret from the vault

#### Remove-Secret

Removes a secret from the vault

#### Get-SecretInfo

Returns information about one or more secrets (but not the secret itself)

#### Test-SecretVault

Tests that extension vault functions and returns True or diagnostic errors

#### Unregister-SecretVault

This function is called if provided by the extension vault, to allow the extension vault to perform an clean up tasks before the vault extension is unregistered

### Unlock-SecretVault

Unlocks the extension vault through a passed in SecureString password

#### Verbose and AdditionalParameters

Each extension vault function takes a set of parameter arguments that includes an `AdditionalParameters` hash table.
The values of the hash table come from the `VaultParameters` field of the registered vault, which are additional parameters an extension vault implementation might need beyond the specific parameters of a particular function.
The `AdditionalParameters` hash table can also include an automatic `Verbose` boolean parameter.
If the extension vault function is being called with the `-Verbose` common parameter, then the `Verbose` boolean parameter will be included in the `AdditionalParameters` hash table.
The `Verbose` parameter is reserved and provided automatically by SecretManagement when verbose output is specified.
It cannot be included in `VaultParameters`.

Example:

```powershell
function Get-Secret
{
    [CmdletBinding()]
    param (
        [string] $Name,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    # Enable verbose output if directed
    if ($AdditionalParameters.ContainsKey('Verbose') -and ($AdditionalParameters['Verbose'] -eq $true)) {
        $VerbosePreference = 'Continue'
    }

    ...
}
```

### Script module vault extension example

This is a minimal vault extension example to demonstrate the directory structure and functional requirements of an extension vault module.
The extension vault module name is 'TestVault'.  

#### Module directory structure

./TestVault  
./TestVault/TestVault.psd1  
./TestVault/TestStoreImplementation.dll  
./TestVault/TestVault.Extension  
./TestVault/TestVault.Extension/TestVault.Extension.psd1  
./TestVault/TestVault.Extension/TestVault.Extension.psm1  

#### TestVault.psd1 file

```powershell
@{
    ModuleVersion = '1.0'
    RootModule = '.\TestStoreImplementation.dll'
    NestedModules = @('.\TestVault.Extension')
    CmdletsToExport = @('Set-TestStoreConfiguration','Get-TestStoreConfiguration')
}
```

The TestVault extension module has a binary component (TestStoreImplementation.dll) which implements the vault.  It publicly exports two cmdlets that are used to configure the store.
It also declares the required nested module (TestVault.Extension) that exports the five functions required by SecretManagement registration.  

Note that the nested module conforms to the required naming format:  
'[ModuleName].Extension'  

Note that only the 'NestedModules' entry is required because it loads 'TestVault.Extension' into the module scope, and allows SecretManagement access to the required five functions.
The 'RootModule' and 'CmdletsToExport' entries are only for configuring the TestStore in this specific case, and are not needed in general.  

#### TestVault.Extension.psd1 file

```powershell
@{
    ModuleVersion = '1.0'
    RootModule = '.\TestVault.Extension.psm1'
    RequiredAssemblies = '..\TestStoreImplementation.dll'
    FunctionsToExport = @('Set-Secret','Get-Secret','Remove-Secret','Get-SecretInfo','Test-SecretVault')
}
```

This nested module implements and exports the five functions required by SecretManagement.
It also specifies the TestStoreImplementation.dll binary as a 'RequiredAssemblies' because the five exported functions depend on it.  

#### TestVault.Extension.psm1 file

```powershell
function Get-Secret
{
    [CmdletBinding()]
    param (
        [string] $Name,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    return [TestStore]::GetItem($Name, $AdditionalParameters)
}

function Get-SecretInfo
{
    [CmdletBinding()]
    param (
        [string] $Filter,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    # return [TestStore]::GetItemInfo($Filter, $AdditionalParameters)
    return @(,[Microsoft.PowerShell.SecretManagement.SecretInformation]::new(
        "Name",        # Name of secret
        "String",      # Secret data type [Microsoft.PowerShell.SecretManagement.SecretType]
        $VaultName,    # Name of vault
        $Metadata)     # Optional ReadonlyDictionary<string, object> secret metadata
}

function Set-Secret
{
    [CmdletBinding()]
    param (
        [string] $Name,
        [object] $Secret,
        [string] $VaultName,
        [hashtable] $AdditionalParameters,
        [hashtable] $Metadata                # Optional metadata parameter
    )

    [TestStore]::SetItem($Name, $Secret)
}

# Optional function
function Set-SecretInfo
{
    [CmdletBinding()]
    param (
        [string] $Name,
        [hashtable] $Metadata,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    [TestStore]::SetItemMetadata($Name, $Metadata)
}

function Remove-Secret
{
    [CmdletBinding()]
    param (
        [string] $Name,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    [TestStore]::RemoveItem($Name)
}

function Test-SecretVault
{
    [CmdletBinding()]
    param (
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    return [TestStore]::TestVault()
}

# Optional function
function Unregister-SecretVault
{
    [CmdletBinding()]
    param (
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    # Perform optional work to extension vault before it is unregistered
    [TestStore]::RunUnregisterCleanup()
}

# Optional function
function Unlock-SecretVault
{
    [CmdletBinding()]
    param (
        [SecureString] $Password,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    [TestStore]::UnlockVault($Password)
}
```

This module script implements the five required functions, as cmdlets.
It also implements an optional `Unregister-SecretVault` function that is called during vault extension un-registration.
It also implements an optional function `Set-SecretInfo` function that sets secret metadata to a specific secret in the vault.
It also implements an optional `Unlock-SecretVault` function that unlocks the vault for the current session based on a provided password.  

The `Set-Secret`, `Set-SecretInfo`, `Remove-Secret`, `Unregister-SecretVault` functions do not write any data to the pipeline, i.e., they do not return any data.  

The `Get-Secret` cmdlet writes the retrieved secret value to the output pipeline on return, or null if no secret was found.
It should write an error only if an abnormal condition occurs.  

The `Get-SecretInfo` cmdlet writes an array of [Microsoft.PowerShell.SecretManagement.SecretInformation] type objects to the output pipeline or an empty array if no matches were found.  

The `Test-SecretVault` cmdlet should write all errors that occur during the test.
But only a single true/false boolean should be written the the output pipeline indicating success.  

The `Unlock-SecretVault` cmdlet is optional and will be called on the extension vault if available.
It's purpose is to unlock an extension vault for use without having to prompt the user, and is useful for unattended scripts where user interaction is not possible.  

In general, these cmdlets should write to the error stream only for abnormal conditions that prevent successful completion.
And write to the output stream only the data as indicated above, and expected by SecretManagement.  

In addition, these cmdlets should perform proper authentication and provide errors, and instructions to authenticate, as appropriate.
Or prompt the user if needed, for example if a passphrase is required.  

A vault extension doesn't need to provide full implementation of all required functions.
For example, a vault extension does not need to provide a way to add or remove a secret through the SecretManagement cmdlets, and can just provide retrieval services.
If a vault extension doesn't support some functionality, then it should write an appropriate error with a meaningful message.  

## Vault registration cmdlets

The following cmdlets are provided for vault extension registration.  

```powershell
Register-SecretVault
Get-SecretVault
Unregister-SecretVault
Set-SecretVaultDefault
Test-SecretVault
```

### Register-SecretVault

Registers a PowerShell module as an extension vault for the current user context.
Validation is performed to ensure the module provides the required functions.  

### Get-SecretVault

Returns a list of extension vaults currently registered in the user context.  

### Unregister-SecretVault

Un-registers an extension vault.  

### Set-SecretVaultDefault

Sets one registered extension vault as the default vault.  

### Test-SecretVault

Runs an extension vault 'Test-SecretVault' function and returns the test result.  

### Unlock-SecretVault

Unlocks the extension vault through a passed in SecureString password.  

## Secrets cmdlets

The following cmdlets are provided for manipulating secrets.  

```powershell
Set-Secret
Get-Secret
Get-SecretInfo
Remove-Secret
```

### Set-Secret

Adds a secret to a specified vault.  
Returns True or False to indicate success.  

### Get-Secret

Returns a single secret for a provided name.  

### Get-SecretInfo

Returns information about each secret stored in all registered vaults, but not the secret itself.  
The information is returned in a `Microsoft.PowerShell.SecretManagement.SecretInformation` type.

### Remove-Secret

Removes a secret by name from a given vault.  
Returns True or False to indicate success.  

## Security

### Extension vault security

All extension vault module implementations are responsible for working securely.  
In addition each extension vault module is responsible for authentication within the current user context, and to provide appropriate informational and error messages to the user, including instructions for authenticating.
Extension vaults are also responsible for prompting the user for a passphrase, if needed, in interactive sessions.
If an extension vault supports optional secret metadata, the metadata is not sensitive information and does not need to be stored securely.
If an extension vault requires a password before use, it can support the optional `Unlock-SecretVault` function to allow the vault to be unlocked from unattended script, without any user interaction.  

### Intermediate secret objects

The SecretManagement module makes a best effort to zero out any intermediate secret objects not returned to the user.
For example byte arrays used in storing and retrieving SecureString blobs are zeroed out after use.
But strings are immutable in C# and cannot be easily or reliably altered, and so must rely on the CLR garbage collection.  

### Plain text secrets

The SecretManagement module supports both `string` and `SecureString` secret data types.
To avoid inadvertently exposing these secrets as plain text, either in a command shell or logs, these secret types are always returned by `Get-Secret` as `SecureString` objects by default.
`Get-Secret` will return these data types as strings only if the `-AsPlainText` parameter switch is used.  

This behavior also extends to `hashtable` secret types.
Since hashtable entries can include `string` and `SecureString` data types, these appear in the hashtable as `SecureString` unless `-AsPlainText` switch is used.  

On Windows platform, `SecureString` types contain an encrypted version of the text data, using Windows DPAPI, that is keyed to the current user context and local machine.
But for all other platforms (Linux, macOS) this kind of default encryption is not possible so the dotNet `SecureString` type contains an unencrypted blob of the text.
However, `SecureString` still serves a purpose on non-Windows platforms, since it will not expose the plain text directly, and another dotNet API is needed to return the string contents in plain text.
So on non-Windows platforms `SecureString` still provides some security through obscurity (but not encryption).

### Extension vault module cross talk

SecretManagement extension vault modules all run in a single PowerShell runspace session that is separate from the current user PowerShell session, although both sessions run within the same process.
This means there is a layer of isolation between extension vault modules and the user session, but no significant isolation between each loaded extension vault.
Since authentication is usually based on current session or user context, this means a malicious vault extension could harvest secrets from other registered vaults.  

This can easily be done by directly calling each registered vault secret management cmdlets.  

One possible mitigation is for an extension vault to require a passphrase.
But usually the passphrase remains valid for a period of time (e.g., sudo), and the malicious extension vault can obtain secrets during that time.  

The best defense is to use known secure extension vaults from reputable sources, that are signed certified.  

## Extension vault registry file location

SecretManagement is designed to be installed and run within a user account on both Windows and non-Windows platforms.
The extension vault registry file is located in a user account protected directory.  

For Windows platforms the location is:  
%LOCALAPPDATA%\Microsoft\PowerShell\secretmanagement  

For non-Windows platforms the location:  
$HOME/.secretmanagement

## Windows Managed Accounts

SecretManagement does not currently work for Windows managed accounts.  

SecretManagement depends on both %LOCALAPPDATA% folders to store registry information, and Data Protection APIs for safely handling secrets with the .Net `SecureString` type.  
However, Windows managed accounts do not have profiles or %LOCALAPPDATA% folders, and Windows Data Protection APIs do not work for managed accounts.  
Consequently, SecretManagement will not run under managed accounts.
