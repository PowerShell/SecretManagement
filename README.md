# PowerShell SecretManagement module

PowerShell SecretManagement module provides a convenient way for a user to store and retrieve secrets.
The secrets are stored in SecretManagement extension vaults.
An extension vault is a PowerShell module that has been registered to SecretManagement, and exports five module functions required by SecretManagement.
An extension vault can store secrets locally or remotely.
Extension vaults are registered to the current logged in user context, and will be available only to that user (unless also registered to other users).  

In addition to implementing the five required SecretManagement functions, extension vaults are responsible for any authentication, including prompting the user for passphrases, and providing error and informational messages specific to the vault implementation.
Error and informational messages common to all extension vaults are provided by SecretManagement.  

PowerShell SecretManagement module is essentially an orchestrator for extension vaults which perform the actual secret storage and encryption.
The extension vault may implement its own store, or wrap an existing secure store solution, such as Azure KeyVault, KeePass, Keyring, etc.  

PowerShell SecretManagement supports the following secret data types:

- byte[]
- string
- SecureString
- PSCredential
- Hashtable  

All extension vault implementations must also support these data types.  

PowerShell SecretManagement module provides cmdlets for for accessing and manipulating secrets, and also cmdlets for registering and manipulating vault extensions.  

## Vault extension registration cmdlets

### Register-SecretVault

Registers a single extension vault to the current user

### Get-SecretVault

Retrieves information about one or more registered extension vaults

### Unregister-SecretVault

Unregisters a single extension vault

### Set-DefaultVault

Sets one registered extension vault as the default vault

### Test-SecretVault

Runs the Test-SecretVault function provided by the extension vault

## Accessing secrets cmdlets

### Set-Secret

Adds a secret to a specific extension vault, or to the default vault if no vault is specified

### Get-Secret

Retrieves a secret from a specific extension vault, or first found over all vaults

### Get-SecretInfo

Retrieves information about one or more secrets, but not the secret itself

### Remove-Secret

Removes a secret from a specific vault

## Vault extension registration

Vault extensions are registered to the current user context.
They are registered as PowerShell modules that expose required functions used by SecretManagement to manipulate secrets.
The required functions are provided as PowerShell cmdlets, and can be implemented as script or binary cmdlets.  

Since each extension vault module exports the same five cmdlets, the module must conform to a directory structure that hides cmdlets from the user and PowerShell command discovery.
Therefore the extension vault module itself does not export the five required cmdlets directly, but are instead exported from a nested module that resides within the extension vault module directory.
This nested module must have a name that is the parent module name with '.Extension' appended to it.  

It is recommended that the parent module manifest file (.psd1) include the 'SecretManagement' tag in its PrivateData section.
This allows [PowerShellGallery](https://www.powershellgallery.com) to associate it with the SecretManagement module.  

### Example: Script module vault extension

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
    PrivateData = @{
        PSData = @{
            Tags = @('SecretManagement')
        }
    }
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

    # return [TestStore]::GetItem($Name, $AdditionalParameters)
    return $null
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
        $VaultName))   # Name of vault
}

function Set-Secret
{
    [CmdletBinding()]
    param (
        [string] $Name,
        [object] $Secret,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    # return [TestStore]::SetItem($Name, $Secret)
    return $false
}

function Remove-Secret
{
    [CmdletBinding()]
    param (
        [string] $Name,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    # return [TestStore]::RemoveItem($Name)
    return $false
}

function Test-SecretVault
{
    [CmdletBinding()]
    param (
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    # return [TestStore]::TestVault()
    return $true
}
```

This module script implements the five functions, as cmdlets, required by SecretManagement.  

The Set-Secret, Remove-Secret, Test-SecretVault cmdlets write a boolean to the pipeline on return, indicating success.  

The Get-Secret cmdlet writes the retrieved secret value to the output pipeline on return, or null if no secret was found.
It should write an error only if an abnormal condition occurs.  

The Get-SecretInfo cmdlet writes an array of `Microsoft.PowerShell.SecretManagement.SecretInformation` type objects to the output pipeline or an empty array if no matches were found.  

The Test-SecretVault cmdlet should write all errors that occur during the test.
But only a single true/false boolean should be written the the output pipeline indicating success.  

In general, these cmdlets should write to the error stream only for abnormal conditions that prevent successful completion.
And write to the output stream only the data as indicated above, and expected by SecretManagement.  

In addition, these cmdlets should perform proper authentication and provide errors, and instructions to authenticate, as appropriate.
Or prompt the user if needed, for example if a passphrase is required.  

A vault extension doesn't need to provide full implementation of all required functions.
For example, a vault extension does not need to provide a way to add or remove a secret through the SecretManagement cmdlets, and can just provide retrieval services.
If a vault extension doesn't support some functionality, then it should write an appropriate error with a meaningful message.  

Be careful with module implementation with scripts, because any data returned by function or method calls are automatically written to the output pipeline (if not assigned to a variable).
SecretManagement expects only specific data to appear in the output pipeline, and if other data is inadvertently written, that will cause SecretManagement to not function properly.  

### Registering the vault

Once the TestVault module is created, it is registered as follows:

```powershell
Register-SecretVault -Name LocalStore -ModuleName ./TestVault -VaultParameters @{ None="ReallyNeeded" } -DefaultVault

Get-SecretVault

VaultName  ModuleName  IsDefaultVault
---------  ----------  --------------
LocalStore TestVault   True

```
