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

    $errorMsg = ""
    $count = 0
    do
    {
        try
        {
            $outSecret = $null
            if ([Microsoft.PowerShell.SecretStore.LocalSecretStore]::GetInstance().ReadObject(
                $Name,
                [ref] $outSecret,
                [ref] $errorMsg))
            {
                Write-Output $outSecret -NoEnumerate
            }

            break
        }
        catch [Microsoft.PowerShell.SecretStore.PasswordRequiredException]
        {
            if (! [Microsoft.PowerShell.SecretStore.LocalSecretStore]::AllowPrompting -or
                ($count -gt 0))
            {
                throw
            }

            [Microsoft.PowerShell.SecretStore.LocalSecretStore]::PromptAndUnlockVault($VaultName, $PSCmdlet)
        }
    } while ($count++ -lt 1)

    if (! [string]::IsNullOrEmpty($errorMsg))
    {
        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
            [System.Management.Automation.PSInvalidOperationException]::new("Get-Secret error in vault $VaultName : $errorMsg"),
            "SecretStoreGetSecretFailed",
            [System.Management.Automation.ErrorCategory]::InvalidOperation,
            $null)
        Write-Error -ErrorRecord $errorRecord
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

    $errorMsg = ""
    $count = 0
    do
    {
        try
        {
            $outSecretInfo = $null
            if ([Microsoft.PowerShell.SecretStore.LocalSecretStore]::GetInstance().EnumerateObjectInfo(
                $Filter,
                [ref] $outSecretInfo,
                $VaultName,
                [ref] $errorMsg))
            {
                Write-Output $outSecretInfo
            }
            
            break
        }
        catch [Microsoft.PowerShell.SecretStore.PasswordRequiredException]
        {
            if (! [Microsoft.PowerShell.SecretStore.LocalSecretStore]::AllowPrompting -or
                ($count -gt 0))
            {
                throw
            }

            [Microsoft.PowerShell.SecretStore.LocalSecretStore]::PromptAndUnlockVault($VaultName, $PSCmdlet)
        }
    } while ($count++ -lt 1)

    if (! [string]::IsNullOrEmpty($errorMsg))
    {
        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
            [System.Management.Automation.ItemNotFoundException]::new("Get-SecretInfo error in vault $VaultName : $errorMsg"),
            "SecretStoreGetSecretInfoFailed",
            [System.Management.Automation.ErrorCategory]::InvalidOperation,
            $null)
        Write-Error -ErrorRecord $errorRecord
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

    $errorMsg = ""
    $count = 0
    do
    {
        try
        {
            if ([Microsoft.PowerShell.SecretStore.LocalSecretStore]::GetInstance().WriteObject(
                $Name,
                $Secret,
                [ref] $errorMsg))
            {
                return
            }
        }
        catch [Microsoft.PowerShell.SecretStore.PasswordRequiredException]
        {
            if (! [Microsoft.PowerShell.SecretStore.LocalSecretStore]::AllowPrompting -or
                ($count -gt 0))
            {
                throw
            }

            [Microsoft.PowerShell.SecretStore.LocalSecretStore]::PromptAndUnlockVault($VaultName, $PSCmdlet)
        }
    } while ($count++ -lt 1)

    if (! [string]::IsNullOrEmpty($errorMsg))
    {
        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
            [System.Management.Automation.ItemNotFoundException]::new("Set-Secret error in vault $VaultName : $errorMsg"),
            "SecretStoreSetSecretFailed",
            [System.Management.Automation.ErrorCategory]::InvalidOperation,
            $null)
        Write-Error -ErrorRecord $errorRecord
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

    $errorMsg = ""
    $count = 0
    do
    {
        try
        {
            if ([Microsoft.PowerShell.SecretStore.LocalSecretStore]::GetInstance().DeleteObject(
                $Name,
                [ref] $errorMsg))
            {
                return
            }
        }
        catch [Microsoft.PowerShell.SecretStore.PasswordRequiredException]
        {
            if (! [Microsoft.PowerShell.SecretStore.LocalSecretStore]::AllowPrompting -or
                ($count -gt 0))
            {
                throw
            }

            [Microsoft.PowerShell.SecretStore.LocalSecretStore]::PromptAndUnlockVault($VaultName, $PSCmdlet)
        }
    } while ($count++ -lt 1)

    if (! [string]::IsNullOrEmpty($errorMsg))
    {
        $Msg = "Remove-Secret error in vault $VaultName : $errorMsg"
    }
    else
    {
        $Msg = "Remove-Secret error in vault $VaultName : Secret not found"
    }

    $errorRecord = [System.Management.Automation.ErrorRecord]::new(
        [System.Management.Automation.ItemNotFoundException]::new($Msg),
        "SecretStoreRemoveSecretFailed",
        [System.Management.Automation.ErrorCategory]::InvalidOperation,
        $null)
    Write-Error -ErrorRecord $errorRecord
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
