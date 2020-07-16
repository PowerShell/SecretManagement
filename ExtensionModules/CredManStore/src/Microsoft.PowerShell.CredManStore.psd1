# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

@{

# Script module or binary module file associated with this manifest.
RootModule = '.\Microsoft.PowerShell.CredManStore.dll'

NestedModules = @('.\SecretManagementExtension')

# Version number of this module.
ModuleVersion = '1.0.0'

# Supported PSEditions
CompatiblePSEditions = @('Core')

# ID used to uniquely identify this module
GUID = '4b4bc3ec-190a-493f-a869-5ebdb239895d'

# Author of this module
Author = 'Microsoft Corporation'

# Company or vendor of this module
CompanyName = 'Microsoft Corporation'

# Copyright statement for this module
Copyright = '(c) Microsoft Corporation. All rights reserved.'

# Description of the functionality provided by this module
Description = "
This PowerShell module is an extension vault module for the PowerShell SecretManagement module.
As an extension vault, this module uses Windows Credential Manager to store secrets to the local machine based on the current interactive user account context.
This extension vault module will run only on Windows platforms.
"

# Minimum version of the PowerShell engine required by this module
PowerShellVersion = '5.1'

# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
CmdletsToExport = @()

# This is critical to ensure no nested module functions are exposed publicly.
FunctionsToExport = @()

# HelpInfo URI of this module
# HelpInfoURI = ''

}
