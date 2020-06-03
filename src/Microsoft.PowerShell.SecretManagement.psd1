# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

@{

# Script module or binary module file associated with this manifest.
RootModule = '.\Microsoft.PowerShell.SecretManagement.dll'

# Version number of this module.
ModuleVersion = '0.3.0'

# Supported PSEditions
CompatiblePSEditions = @('Core')

# ID used to uniquely identify this module
GUID = '766a9266-f2ba-4146-bec2-bb30bf5a4f0a'

# Author of this module
Author = 'Microsoft Corporation'

# Company or vendor of this module
CompanyName = 'Microsoft Corporation'

# Copyright statement for this module
Copyright = '(c) Microsoft Corporation. All rights reserved.'

# Description of the functionality provided by this module
Description = "
This module helps manage secrets by providing a set of cmdlets that lets you store secrets
locally using a local vault provider, and access secrets from remote vaults.
Local and remote vaults can be registered and unregistered on the local machine, per user,
for use in managing and retrieving secrets.

*****
Breaking change for 0.2.0: The script extension vault module name has been changed from 
'ImplementingModule' to 'SecretManagementExtension'.
Any registered script extension vault module will have to be renamed accordingly.
*****

*****
Breaking change for 0.2.1: Module and cmdlets renamed.  Changes to required functions.
All previous vault extensions will need to be updated.
*****

*****
This is an alpha version of the module that currently works only on Windows platforms.
*****

*****
Breaking change for 0.3.0: Adding new local secure store that works cross platform.
*****
"

# Minimum version of the PowerShell engine required by this module
PowerShellVersion = '5.1'

# Format files (.ps1xml) to be loaded when importing this module
FormatsToProcess = @('Microsoft.PowerShell.SecretManagement.format.ps1xml')

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = @()

# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
CmdletsToExport = @(
    'Register-SecretVault','Unregister-SecretVault','Get-SecretVault','Set-Secret','Remove-Secret','Get-Secret','Get-SecretInfo','Test-SecretVault',
    'Unlock-LocalStore','Update-LocalStorePassword','Get-LocalStoreConfiguration','Set-LocalStoreConfiguration','Reset-LocalStore')

# Variables to export from this module
VariablesToExport = '*'

# Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
AliasesToExport = @()

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        # Tags = @()

        # A URL to the license for this module.
        LicenseUri = 'https://github.com/PowerShell/Modules/License.txt'

        # A URL to the main website for this project.
        # ProjectUri = ''

        # A URL to an icon representing this module.
        # IconUri = ''

        # ReleaseNotes of this module
        # ReleaseNotes = ''

        # Prerelease string of this module
        Prerelease = 'alpha1'

        # Flag to indicate whether the module requires explicit user acceptance for install/update/save
        # RequireLicenseAcceptance = $false

        # External dependent modules of this module
        # ExternalModuleDependencies = @()
    } # End of PSData hashtable

} # End of PrivateData hashtable

# HelpInfo URI of this module
# HelpInfoURI = ''

}
