# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

function Get-Secret
{
    [CmdletBinding()]
    param (
        [string] $Name,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    $errorCode = 0
    $outSecret = $null
    if ([Microsoft.PowerShell.CredManStore.LocalCredManStore]::ReadObject(
        $Name,
        [ref] $outSecret,
        [ref] $errorCode))
    {
        Write-Output $outSecret -NoEnumerate
        return
    }

    if (($errorCode -ne 0) -and 
        ($errorCode -ne [Microsoft.PowerShell.CredManStore.NativeUtils]::ERROR_NOT_FOUND))
    {
        $ErrorMessage = [Microsoft.PowerShell.CredManStore.LocalCredManStore]::GetErrorMessage($errorCode)
        Write-Error -Exception ([System.Management.Automation.PSInvalidOperationException]::new(
                "Error while retrieving secret from vault $VaultName : $ErrorMessage")) `
            -Category "InvalidOperation" `
            -ErrorId "CredManVaultGetError"
    }
}

function Get-SecretInfo
{
    [CmdletBinding()]
    param (
        [string] $Filter,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    $errorCode = 0
    $outObjectInfos = $null
    if ([Microsoft.PowerShell.CredManStore.LocalCredManStore]::EnumerateObjectInfo(
        $Filter,
        [ref] $outObjectInfos,
        [ref] $errorCode))
    {
        $secretInfoList = [System.Collections.Generic.List[[Microsoft.PowerShell.SecretManagement.SecretInformation]]]::new()
        foreach ($item in $outObjectInfos)
        {
            $secretInfoList.Add(
                [Microsoft.PowerShell.SecretManagement.SecretInformation]::new(
                    $item.Key,
                    $item.Value,
                    $VaultName))
        }

        Write-Output $secretInfoList.ToArray() -NoEnumerate
        return
    }

    if (($errorCode -ne 0) -and 
        ($errorCode -ne [Microsoft.PowerShell.CredManStore.NativeUtils]::ERROR_NOT_FOUND))
    {
        $ErrorMessage = [Microsoft.PowerShell.CredManStore.LocalCredManStore]::GetErrorMessage($errorCode)
        Write-Error -Exception ([System.Management.Automation.PSInvalidOperationException]::new(
                "Error while retrieving secret information from vault $VaultName : $ErrorMessage")) `
            -Category "InvalidOperation" `
            -ErrorId "CredManVaultGetInfoError"
    }
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

    $errorCode = 0
    if (![Microsoft.PowerShell.CredManStore.LocalCredManStore]::WriteObject(
        $Name,
        $Secret,
        [ref] $errorCode))
    {
        $ErrorMessage = [Microsoft.PowerShell.CredManStore.LocalCredManStore]::GetErrorMessage($errorCode)
        Write-Error -Exception ([System.Management.Automation.PSInvalidOperationException]::new(
                "Error while writing secret to vault $VaultName : $ErrorMessage")) `
            -Category "InvalidOperation" `
            -ErrorId "CredManVaultWriteError"
    }
}

function Remove-Secret
{
    [CmdletBinding()]
    param (
        [string] $Name,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    $errorCode = 0
    if (![Microsoft.PowerShell.CredManStore.LocalCredManStore]::DeleteObject(
        $Name,
        [ref] $errorCode))
    {
        $ErrorMessage = [Microsoft.PowerShell.CredManStore.LocalCredManStore]::GetErrorMessage($errorCode)
        Write-Error -Exception ([System.Management.Automation.PSInvalidOperationException]::new(
                "Error while deleting secret from vault $VaultName : $ErrorMessage")) `
            -Category "InvalidOperation" `
            -ErrorId "CredManVaultDeleteError"
    }
}

function Test-SecretVault
{
    [CmdletBinding()]
    param (
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    # TODO: Implement
    return $true
}
