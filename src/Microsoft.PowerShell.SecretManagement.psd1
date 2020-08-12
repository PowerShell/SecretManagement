# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

@{

# Script module or binary module file associated with this manifest.
RootModule = '.\Microsoft.PowerShell.SecretManagement.dll'

# Version number of this module.
ModuleVersion = '0.5.0'

# Supported PSEditions
CompatiblePSEditions = @('Core')

# ID used to uniquely identify this module
GUID = 'a5c858f6-4a8e-41f1-b1ee-0ff8f6ad69d3'

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
"

# Minimum version of the PowerShell engine required by this module
PowerShellVersion = '5.1'

# Format files (.ps1xml) to be loaded when importing this module
FormatsToProcess = @('Microsoft.PowerShell.SecretManagement.format.ps1xml')

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = @()

# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
CmdletsToExport = @(
    'Register-SecretVault','Unregister-SecretVault','Get-SecretVault','Set-DefaultVault','Test-SecretVault',
    'Set-Secret','Get-Secret','Get-SecretInfo','Remove-Secret')

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
        Prerelease = 'alpha4'

        # Flag to indicate whether the module requires explicit user acceptance for install/update/save
        # RequireLicenseAcceptance = $false

        # External dependent modules of this module
        # ExternalModuleDependencies = @()
    } # End of PSData hashtable

} # End of PrivateData hashtable

# HelpInfo URI of this module
# HelpInfoURI = ''

}
