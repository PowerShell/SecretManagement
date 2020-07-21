# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

function Get-Path
{
    param (
        [string] $VaultName
    )

    $path = Join-Path $env:TEMP $VaultName
    if (! (Test-Path -Path $path))
    {
        [System.IO.Directory]::CreateDirectory($path)
    }

    return $path
}

function Get-Secret
{
    param (
        [string] $Name,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    if ([WildcardPattern]::ContainsWildcardCharacters($Name))
    {
        throw "The Name parameter cannot contain wild card characters."
    }

    $filePath = Join-Path -Path (Get-Path $VaultName) -ChildPath "${Name}.xml"
    if (! (Test-Path -Path $filePath))
    {
        return
    }

    $secret = Import-Clixml -Path $filePath

    if ($secret.GetType().IsArray)
    {
        return @(,[byte[]] $secret)
    }

    return $secret
}

function Set-Secret
{
    param (
        [string] $Name,
        [object] $Secret,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    $filePath = Join-Path -Path (Get-Path $VaultName) -ChildPath "${Name}.xml"
    if (Test-Path -Path $filePath)
    {
        Write-Error "Secret name, $Name, is already used in this vault."
        return $false
    }

    $Secret | Export-Clixml -Path $filePath
    return $true
}

function Remove-Secret
{
    param (
        [string] $Name,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    $filePath = Join-Path -Path (Get-Path $VaultName) -ChildPath "${Name}.xml"
    if (! (Test-Path -Path $filePath))
    {
        Write-Error "The secret, $Name, does not exist."
        return $false
    }

    Remove-Item -Path $filePath
    return $true
}

function Get-SecretInfo
{
    param(
        [string] $Filter,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    if ([string]::IsNullOrEmpty($Filter)) { $Filter = "*" }

    $files = Get-ChildItem -Path (Join-Path -Path (Get-Path $VaultName) -ChildPath "${Filter}.xml") 2>$null

    foreach ($file in $files)
    {
        $secretName = [System.IO.Path]::GetFileNameWithoutExtension((Split-Path -Path $file -Leaf))
        $secret = Import-Clixml -Path $file.FullName
        $type = if ($secret.gettype().IsArray) { [Microsoft.PowerShell.SecretManagement.SecretType]::ByteArray }
                    elseif ($secret -is [string]) { [Microsoft.PowerShell.SecretManagement.SecretType]::String }
                    elseif ($secret -is [securestring]) { [Microsoft.PowerShell.SecretManagement.SecretType]::SecureString }
                    elseif ($secret -is [PSCredential]) { [Microsoft.PowerShell.SecretManagement.SecretType]::PSCredential }
                    elseif ($secret -is [hashtable]) { [Microsoft.PowerShell.SecretManagement.SecretType]::Hashtable }
                    else { [Microsoft.PowerShell.SecretManagement.SecretType]::Unknown }
        
        Write-Output (
            [Microsoft.PowerShell.SecretManagement.SecretInformation]::new(
                $secretName,
                $type,
                $VaultName)
        )
    }
}

function Test-SecretVault
{
    param (
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    return $true
}
