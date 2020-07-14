# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

@{

# Script module or binary module file associated with this manifest.
RootModule = '.\Microsoft.PowerShell.SecretStore.dll'

NestedModules = @('.\SecretManagementExtension')

# Version number of this module.
ModuleVersion = '0.4.0'

# Supported PSEditions
CompatiblePSEditions = @('Core')

# ID used to uniquely identify this module
GUID = '6b983e67-c297-431a-916c-f4ce24dd7bac'

# Author of this module
Author = 'Microsoft Corporation'

# Company or vendor of this module
CompanyName = 'Microsoft Corporation'

# Copyright statement for this module
Copyright = '(c) Microsoft Corporation. All rights reserved.'

# Description of the functionality provided by this module
Description = "
This PowerShell module is an extension vault module for the PowerShell SecretManagement module.
As an extension vault, this module stores secrets to the local machine based on the current user account context.
The secrets are encrypted on file using .NET Crypto APIs.
A password is required for each user account store.
"

# Minimum version of the PowerShell engine required by this module
PowerShellVersion = '5.1'

# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
CmdletsToExport = @('Unlock-LocalStore','Update-LocalStorePassword','Get-LocalStoreConfiguration','Set-LocalStoreConfiguration','Reset-LocalStore')

FunctionsToExport = @()

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
