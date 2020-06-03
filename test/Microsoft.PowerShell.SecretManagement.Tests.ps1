# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

Describe "Test Microsoft.PowerShell.SecretManagement module" -tags CI {

    BeforeAll {

        if ((Get-Module -Name Microsoft.PowerShell.SecretManagement -ErrorAction Ignore) -eq $null)
        {
            Import-Module -Name Microsoft.PowerShell.SecretManagement
        }

        # Reset the local store and configure it for no-password access
        # TODO: This deletes all local store data!!
        Reset-LocalStore -Scope CurrentUser -PasswordRequired:$false -PasswordTimeout: -1 -DoNotPrompt -Force

        # Binary extension module
        $classImplementation = @'
            using Microsoft.PowerShell.SecretManagement;
            using System;
            using System.Collections;
            using System.Collections.Generic;
            using System.Management.Automation;
            
            namespace VaultExtension
            {
                public static class Store
                {
                    private static Dictionary<string, object> _store = new Dictionary<string, object>();
                    public static Dictionary<string, object> Dict { get { return _store; } }
                }

                public class TestExtVault : SecretManagementExtension
                {
                    private Dictionary<string, object> _store = Store.Dict;
            
                    public TestExtVault(string vaultName) : base(vaultName) { }

                    public override bool TestSecretVault(
                        string vaultName,
                        IReadOnlyDictionary<string, object> additionalParameters,
                        out Exception[] errors)
                    {
                        var valid = true;
                        var errorList = new List<Exception>();
                        if (!additionalParameters.ContainsKey("AccessToken"))
                        {
                            valid = false;
                            errorList.Add(
                                new System.InvalidOperationException("Missing AccessToken parameter"));
                        }
                        if (!additionalParameters.ContainsKey("SubscriptionId"))
                        {
                            valid = false;
                            errorList.Add(
                                new System.InvalidOperationException("Missing SubscriptionId parameter"));
                        }

                        errors = errorList.ToArray();
                        return valid;
                    }
            
                    public override bool SetSecret(
                        string name,
                        object secret,
                        string vaultName,
                        IReadOnlyDictionary<string, object> additionalParameters,
                        out Exception error)
                    {
                        error = null;
                        if (!_store.TryAdd(name, secret))
                        {
                            error = new InvalidOperationException("SecretAlreadyExists");
                            return false;
                        }
            
                        return true;
                    }
            
                    public override object GetSecret(
                        string name,
                        string vaultName,
                        IReadOnlyDictionary<string, object> additionalParameters,
                        out Exception error)
                    {
                        error = null;
                        if (_store.TryGetValue(name, out object secret))
                        {
                            return secret;
                        }
            
                        error = new InvalidOperationException("SecretNotFoundInStore");
                        return null;
                    }
            
                    public override bool RemoveSecret(
                        string name,
                        string vaultName,
                        IReadOnlyDictionary<string, object> additionalParameters,
                        out Exception error)
                    {
                        error = null;
                        if (_store.Remove(name))
                        {
                            return true;
                        }
            
                        error = new InvalidOperationException("SecretNotRemoved");
                        return false;
                    }
            
                    public override SecretInformation[] GetSecretInfo(
                        string filter,
                        string vaultName,
                        IReadOnlyDictionary<string, object> additionalParameters,
                        out Exception error)
                    {
                        error = null;
                        var list = new List<SecretInformation>(_store.Count);
                        foreach (var item in _store)
                        {
                            SecretType type;
                            switch (item.Value)
                            {
                                case byte[] blob:
                                    type = SecretType.ByteArray;
                                    break;

                                case string str:
                                    type = SecretType.String;
                                    break;

                                case System.Security.SecureString sstr:
                                    type = SecretType.SecureString;
                                    break;
                                
                                case PSCredential cred:
                                    type = SecretType.PSCredential;
                                    break;

                                case Hashtable ht:
                                    type = SecretType.Hashtable;
                                    break;

                                default:
                                    type = SecretType.Unknown;
                                    break;
                            }

                            list.Add(
                                new SecretInformation(
                                    item.Key,
                                    type,
                                    vaultName));
                        }

                        return list.ToArray();
                    }
                }
            }
'@

        $binModuleName = "TVaultBin"
        $binModulePath = Join-Path $PSScriptRoot $binModuleName
        $script:binModuleFilePath = Join-Path $binModulePath "${binModuleName}.psd1"
        $binModuleAssemblyPath = Join-Path $binModulePath "${binModuleName}.dll"
        if (! (Test-Path -Path $binModulePath))
        {
            New-Item -ItemType Directory $binModulePath -Force
            $types = Add-Type -TypeDefinition $classImplementation `
                -ReferencedAssemblies @('netstandard','Microsoft.PowerShell.SecretManagement','System.Collections','System.Management.Automation','System.Runtime.Extensions') `
                -OutputAssembly $binModuleAssemblyPath -ErrorAction SilentlyContinue -PassThru
            
            # We have to rename the assembly file to be the same as the randomly generated assemblyl name, otherwise
            # PowerShell won't load it during module import.
            $assemblyFileName = $types[0].Module.Assembly.ManifestModule.ScopeName
            $newBinModuleAssemblyPath = Join-Path $binModulePath "${assemblyFileName}"
            Copy-Item -Path $binModuleAssemblyPath -Dest $newBinModuleAssemblyPath
            "@{ ModuleVersion = '1.0'; RequiredAssemblies = @('$assemblyFileName') }" | Out-File -FilePath $script:binModuleFilePath
        }

        # Script extension module
        $scriptImplementation = @'
            $script:store = [VaultExtension.Store]::Dict

            function Get-Secret
            {
                param (
                    [string] $Name,
                    [string] $VaultName,
                    [hashtable] $AdditionalParameters
                )

                $secret = $script:store[$Name]
                if ($secret -eq $null)
                {
                    Write-Error("CannotFindSecret")
                }

                if ($secret -is [byte[]])
                {
                    return @(,$secret)
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

                return $script:store.TryAdd($Name, $Secret)
            }

            function Remove-Secret
            {
                param (
                    [string] $Name,
                    [string] $VaultName,
                    [hashtable] $AdditionalParameters
                )

                return $script:store.Remove($Name)
            }

            function Get-SecretInfo
            {
                param (
                    [string] $Filter,
                    [string] $VaultName,
                    [hashtable] $AdditionalParameters
                )

                if ([string]::IsNullOrEmpty($Filter))
                {
                    $Filter = '*'
                }
                $pattern = [WildcardPattern]::new($Filter)
                foreach ($key in $script:store.Keys)
                {
                    if ($pattern.IsMatch($key))
                    {
                        $secret = $script:store[$key]
                        $type = if ($secret -is [byte[]]) { [Microsoft.PowerShell.SecretManagement.SecretType]::ByteArray }
                        elseif ($secret -is [string]) { [Microsoft.PowerShell.SecretManagement.SecretType]::String }
                        elseif ($secret -is [securestring]) { [Microsoft.PowerShell.SecretManagement.SecretType]::SecureString }
                        elseif ($secret -is [PSCredential]) { [Microsoft.PowerShell.SecretManagement.SecretType]::PSCredential }
                        elseif ($secret -is [hashtable]) { [Microsoft.PowerShell.SecretManagement.SecretType]::Hashtable }
                        else { [Microsoft.PowerShell.SecretManagement.SecretType]::Unknown }

                        Write-Output ([Microsoft.PowerShell.SecretManagement.SecretInformation]::new($key, $type, $VaultName))
                    }
                }
            }

            function Test-SecretVault
            {
                param (
                    [string] $VaultName,
                    [hashtable] $AdditionalParameters
                )

                $valid = $true
                if (! $AdditionalParameters.ContainsKey('AccessToken'))
                {
                    $valid = $false
                    Write-Error 'Missing AccessToken parameter'
                }
                if (! $AdditionalParameters.ContainsKey('SubscriptionId'))
                {
                    $valid = $false
                    Write-Error 'Missing SubscriptionId parameter'
                }

                return $valid
            }
'@
        $scriptModuleName = "TVaultScript"
        $scriptModulePath = Join-Path $testdrive $scriptModuleName
        New-Item -ItemType Directory $scriptModulePath -Force
        $script:scriptModuleFilePath = Join-Path $scriptModulePath "${scriptModuleName}.psd1"
        "@{ ModuleVersion = '1.0' }" | Out-File -FilePath $script:scriptModuleFilePath

        $implementingModuleName = "SecretManagementExtension"
        $implementingModulePath = Join-Path $scriptModulePath $implementingModuleName
        New-Item -ItemType Directory $implementingModulePath -Force
        $implementingManifestFilePath = Join-Path $implementingModulePath "${implementingModuleName}.psd1"
        $manifestInfo = "
        @{{
            ModuleVersion = '1.0'
            RootModule = '{0}'
            FunctionsToExport = @('Set-Secret','Get-Secret','Remove-Secret','Get-SecretInfo','Test-SecretVault')
        }}
        " -f $implementingModuleName
        $manifestInfo | Out-File -FilePath $implementingManifestFilePath
        $implementingModuleFilePath = Join-Path $implementingModulePath "${implementingModuleName}.psm1"
        $scriptImplementation | Out-File -FilePath $implementingModuleFilePath
    }

    AfterAll {

        Unregister-SecretVault -Name BinaryTestVault -ErrorAction Ignore
        Unregister-SecretVault -Name ScriptTestVault -ErrorAction Ignore
    }

    Context "Local store cmdlet tests" {

        It "Verifies local store configuration for tests" {
            $config = Get-LocalStoreConfiguration
            $config.Scope | Should -BeExactly "CurrentUser"
            $config.PasswordRequired | Should -BeFalse
            $config.PasswordTimeout | Should -Be -1
            $config.DoNotPrompt | Should -BeTrue
        }

        It "Verifies local store AllUsers option is not implement" {
            { Set-LocalStoreConfiguration -Scope AllUsers } | Should -Throw -ErrorId 'LocalStoreConfigurationNotSupported,Microsoft.PowerShell.SecretManagement.SetLocalStoreConfiguration'
        }

        It "Verifies Unlock-LocalStore throws expected error when in no password mode" {
            { Unlock-LocalStore -Password None } | Should -Throw -ErrorId 'InvalidOperation,Microsoft.PowerShell.SecretManagement.UnlockLocalStoreCommand'
        }
    }

    Context "Built-in local store errors" {

        It "Should throw error when registering the reserved 'BuiltInLocalVault' vault name" {
            { Register-SecretVault -Name BuiltInLocalVault -Module 'c:\' } | Should -Throw -ErrorId 'RegisterSecretVaultInvalidVaultName'
        }
    }

    Context "Built-in local store Byte[] type" {

        $bytesToWrite = [System.Text.Encoding]::UTF8.GetBytes("Hello!!!")

        It "Verifies byte[] write to local store" {
            Set-Secret -Name __Test_ByteArray_ -Secret $bytesToWrite -Vault BuiltInLocalVault -ErrorVariable err
            $err.Count | Should -Be 0
        }

        It "Verifes byte[] read from local store" {
            $bytesRead = Get-Secret -Name __Test_ByteArray_ -Vault BuiltInLocalVault -ErrorVariable err
            $err.Count | Should -Be 0
            [System.Text.Encoding]::UTF8.GetString($bytesRead) | Should -BeExactly "Hello!!!"
        }

        It "Verifes byte[] clobber error in local store" {
            { Set-Secret -Name __Test_ByteArray_ -Secret $bytesToWrite -Vault BuiltInLocalVault -NoClobber } | Should -Throw -ErrorId "AddSecretAlreadyExists"
        }

        It "Verifies byte[] enumeration from local store" {
            $blobInfo = Get-SecretInfo -Name __Test_ByteArray_ -Vault BuiltInLocalVault -ErrorVariable err
            $err.Count | Should -Be 0
            $blobInfo.Name | Should -BeExactly "__Test_ByteArray_"
            $blobInfo.Type | Should -BeExactly "ByteArray"
            $blobInfo.VaultName | Should -BeExactly "BuiltInLocalVault"
        }

        It "Verifies Remove byte[] secret" {
            { Remove-Secret -Name __Test_ByteArray_ -Vault BuiltInLocalVault -ErrorVariable err } | Should -Not -Throw
            $err.Count | Should -Be 0
            { Get-Secret -Name __Test_ByteArray_ -Vault BuiltInLocalVault -ErrorAction Stop } | Should -Throw -ErrorId 'GetSecretNotFound,Microsoft.PowerShell.SecretManagement.GetSecretCommand'
        }
    }

    Context "Built-in local store String type" {

        It "Verifes string write to local store" {
            Set-Secret -Name __Test_String_ -Secret "Hello!!Secret" -Vault BuiltInLocalVault -ErrorVariable err
            $err.Count | Should -Be 0
        }

        It "Verifies string read from local store" {
            $strRead = Get-Secret -Name __Test_String_ -Vault BuiltInLocalVault -ErrorVariable err
            $err.Count | Should -Be 0
            ($strRead -is [SecureString]) | Should -BeTrue

            $strRead = Get-Secret -Name __Test_String_ -Vault BuiltInLocalVault -AsPlainText -ErrorVariable err
            $err.Count | Should -Be 0
            $strRead | Should -BeExactly "Hello!!Secret"
        }

        It "Verifies string enumeration from local store" {
            $strInfo = Get-SecretInfo -Name __Test_String_ -Vault BuiltInLocalVault -ErrorVariable err
            $err.Count | Should -Be 0
            $strInfo.Name | Should -BeExactly "__Test_String_"
            $strInfo.Type | Should -BeExactly "String"
            $strInfo.VaultName | Should -BeExactly "BuiltInLocalVault"
        }

        It "Verifies string remove from local store" {
            { Remove-Secret -Name __Test_String_ -Vault BuiltInLocalVault -ErrorVariable err } | Should -Not -Throw
            $err.Count | Should -Be 0
            { Get-Secret -Name __Test_String_ -Vault BuiltInLocalVault -ErrorAction Stop } | Should -Throw -ErrorId 'GetSecretNotFound,Microsoft.PowerShell.SecretManagement.GetSecretCommand'
        }
    }

    Context "Built-in local store SecureString type" {

	$randomSecret = [System.IO.Path]::GetRandomFileName()
        $secureStringToWrite = ConvertTo-SecureString -String $randomSecret -AsPlainText -Force

        It "Verifies SecureString write to local store" {
            Set-Secret -Name __Test_SecureString_ -Secret $secureStringToWrite -Vault BuiltInLocalVault -ErrorVariable err
            $err.Count | Should -Be 0
        }

        It "Verifies SecureString read from local store" {
            $ssRead = Get-Secret -Name __Test_SecureString_ -Vault BuiltInLocalVault -ErrorVariable err
            $err.Count | Should -Be 0
            [System.Net.NetworkCredential]::new('',$ssRead).Password | Should -BeExactly $randomSecret
        }

        It "Verifies SecureString enumeration from local store" {
            $ssInfo = Get-SecretInfo -Name __Test_SecureString_ -Vault BuiltInLocalVault -ErrorVariable err
            $err.Count | Should -Be 0
            $ssInfo.Name | Should -BeExactly "__Test_SecureString_"
            $ssInfo.Type | Should -BeExactly "SecureString"
            $ssInfo.VaultName | Should -BeExactly "BuiltInLocalVault"
        }

        It "Verifies SecureString remove from local store" {
            { Remove-Secret -Name __Test_SecureString_ -Vault BuiltInLocalVault -ErrorVariable err } | Should -Not -Throw
            $err.Count | Should -Be 0
            { Get-Secret -Name __Test_SecureString_ -Vault BuiltInLocalVault -ErrorAction Stop } | Should -Throw `
                -ErrorId 'GetSecretNotFound,Microsoft.PowerShell.SecretManagement.GetSecretCommand'
        }

        It "Verifies SecureString write with alternate parameter set" {
            Set-Secret -Name __Test_SecureStringA_ -SecureStringSecret $secureStringToWrite -Vault BuiltInLocalVault -ErrorVariable err
            $err.Count | Should -Be 0
        }

        It "Verifies SecureString read from alternate parameter set" {
            $ssRead = Get-Secret -Name __Test_SecureStringA_ -Vault BuiltInLocalVault -ErrorVariable err
            $err.Count | Should -Be 0
            [System.Net.NetworkCredential]::new('',$ssRead).Password | Should -BeExactly $randomSecret
        }

        It "Verifes SecureString remove from alternate parameter set" {
            { Remove-Secret -Name __Test_SecureStringA_ -Vault BuiltInLocalVault -ErrorVariable err } | Should -Not -Throw
            $err.Count | Should -Be 0
        }
    }

    Context "Built-in local store PSCredential type" {

        $randomSecret = [System.IO.Path]::GetRandomFileName()

        It "Verifies PSCredential type write to local store" {
            $cred = [pscredential]::new('UserL', (ConvertTo-SecureString $randomSecret -AsPlainText -Force))
            Set-Secret -Name __Test_PSCredential_ -Secret $cred -Vault BuiltInLocalVault -ErrorVariable err
            $err.Count | Should -Be 0
        }

        It "Verifies PSCredential read from local store" {
            $cred = Get-Secret -Name __Test_PSCredential_ -Vault BuiltInLocalVault -ErrorVariable err
            $err.Count | Should -Be 0
            $cred.UserName | Should -BeExactly "UserL"
            [System.Net.NetworkCredential]::new('', ($cred.Password)).Password | Should -BeExactly $randomSecret
        }

        It "Verifies PSCredential enumeration from local store" {
            $credInfo = Get-SecretInfo -Name __Test_PSCredential_ -Vault BuiltInLocalVault -ErrorVariable err
            $credInfo.Name | Should -BeExactly "__Test_PSCredential_"
            $credInfo.Type | Should -BeExactly "PSCredential"
            $credInfo.VaultName | Should -BeExactly "BuiltInLocalVault"
        }

        It "Verifies PSCredential remove from local store" {
            Remove-Secret -Name __Test_PSCredential_ -Vault BuiltInLocalVault -ErrorVariable err
            $err.Count | Should -Be 0
            { Get-Secret -Name __Test_PSCredential_ -Vault BuiltInLocalVault -ErrorAction Stop } | Should -Throw `
                -ErrorId 'GetSecretNotFound,Microsoft.PowerShell.SecretManagement.GetSecretCommand'
        }
    }

    Context "Built-in local store Hashtable type" {
        $randomSecretA = [System.IO.Path]::GetRandomFileName()
        $randomSecretB = [System.IO.Path]::GetRandomFileName()

        It "Verifies Hashtable type write to local store" {
            $ht = @{
                Blob = ([byte[]] @(1,2))
                Str = "Hello"
                SecureString = (ConvertTo-SecureString $randomSecretA -AsPlainText -Force)
                Cred = ([pscredential]::New("UserA", (ConvertTo-SecureString $randomSecretB -AsPlainText -Force)))
            }
            Set-Secret -Name __Test_Hashtable_ -Secret $ht -Vault BuiltInLocalVault -ErrorVariable err
            $err.Count | Should -Be 0
        }

        It "Verifies Hashtable read from local store" {
            $ht = Get-Secret -Name __Test_Hashtable_ -Vault BuiltInLocalVault -ErrorVariable err
            $err.Count | Should -Be 0
            $ht.Blob.Count | Should -Be 2
            $ht.Str | Should -BeExactly "Hello"
            [System.Net.NetworkCredential]::new('', ($ht.SecureString)).Password | Should -BeExactly $randomSecretA
            $ht.Cred.UserName | Should -BeExactly "UserA"
            [System.Net.NetworkCredential]::New('', ($ht.Cred.Password)).Password | Should -BeExactly $randomSecretB
        }

        It "Verifies Hashtable enumeration from local store" {
            $htInfo = Get-SecretInfo -Name __Test_Hashtable_ -Vault BuiltInLocalVault -ErrorVariable err
            $err.Count | Should -Be 0
            $htInfo.Name | Should -BeExactly "__Test_Hashtable_"
            $htInfo.Type | Should -BeExactly "Hashtable"
            $htInfo.VaultName | Should -BeExactly "BuiltInLocalVault"
        }

        It "Verifies Hashtable remove from local store" {
            Remove-Secret -Name __Test_Hashtable_ -Vault BuiltInLocalVault -ErrorVariable err
            $err.Count | Should -Be 0
            { Get-Secret -Name __Test_Hashtable_ -Vault BuiltInLocalVault -ErrorAction Stop } | Should -Throw `
                -ErrorId 'GetSecretNotFound,Microsoft.PowerShell.SecretManagement.GetSecretCommand'
        }
    }

    function VerifyByteArrayType
    {
        param (
            [string] $Title,
            [string] $VaultName
        )

        It "Verifies writing byte[] type to $Title vault" {
            $bytes = [System.Text.Encoding]::UTF8.GetBytes("BinVaultHelloStr")
            Set-Secret -Name BinVaultBlob -Secret $bytes -Vault $VaultName -ErrorVariable err
            $err.Count | Should -Be 0
        }

        It "Verifies reading byte[] type from $Title vault" {
            $blob = Get-Secret -Name BinVaultBlob -Vault $VaultName -ErrorVariable err
            $err.Count | Should -Be 0
            [System.Text.Encoding]::UTF8.GetString($blob) | Should -BeExactly "BinVaultHelloStr"
        }

        It "Verifies enumerating byte[] type from $Title vault" {
            $blobInfo = Get-SecretInfo -Name BinVaultBlob -Vault $VaultName -ErrorVariable err
            $err.Count | Should -Be 0
            $blobInfo.Name | Should -BeExactly "BinVaultBlob"
            $blobInfo.Type | Should -BeExactly "ByteArray"
            $blobInfo.VaultName | Should -BeExactly $VaultName
        }

        It "Verifies removing byte[] type from $Title vault" {
            Remove-Secret -Name BinVaultBlob -Vault $VaultName -ErrorVariable err
            $err.Count | Should -Be 0
            { Get-Secret -Name BinVaultBlob -Vault $VaultName -ErrorAction Stop } | Should -Throw `
                -ErrorId 'InvokeGetSecretError,Microsoft.PowerShell.SecretManagement.GetSecretCommand'
        }
    }

    function VerifyStringType
    {
        param (
            [string] $Title,
            [string] $VaultName
        )

        It "Verifies writing string type to $Title vault" {
            Set-Secret -Name BinVaultStr -Secret "HelloBinVault" -Vault $VaultName -ErrorVariable err
            $err.Count | Should -Be 0
        }

        It "Verifies reading string type from $Title vault" {
            $str = Get-Secret -Name BinVaultStr -Vault $VaultName -ErrorVariable err
            $err.Count | Should -Be 0
            ($str -is [SecureString]) | Should -BeTrue

            $str = Get-Secret -Name BinVaultStr -Vault $VaultName -AsPlainText -ErrorVariable err
            $err.Count | Should -Be 0
            $str | Should -BeExactly "HelloBinVault"
        }

        It "Verifies enumerating string type from $Title vault" {
            $strInfo = Get-SecretInfo -Name BinVaultStr -Vault $VaultName -ErrorVariable err
            $err.Count | Should -Be 0
            $strInfo.Name | Should -BeExactly "BinVaultStr"
            $strInfo.Type | Should -BeExactly "String"
            $strInfo.VaultName | Should -BeExactly $VaultName
        }

        It "Verifies removing string type from $Title vault" {
            Remove-Secret -Name BinVaultStr -Vault $VaultName -ErrorVariable err
            $err.Count | Should -Be 0
            { Get-Secret -Name BinVaultStr -Vault $VaultName -ErrorAction Stop } | Should -Throw `
                -ErrorId 'InvokeGetSecretError,Microsoft.PowerShell.SecretManagement.GetSecretCommand'
        }
    }

    function VerifySecureStringType
    {
        param (
            [string] $Title,
            [string] $VaultName
        )

        $randomSecret = [System.IO.Path]::GetRandomFileName()
        $secureStringToWrite = ConvertTo-SecureString $randomSecret -AsPlainText -Force

        It "Verifies writing SecureString type to $Title vault" {
            Set-Secret -Name BinVaultSecureStr -Secret $secureStringToWrite `
                -Vault $VaultName -ErrorVariable err
            $err.Count | Should -Be 0
        }

        It "Verifies reading SecureString type from $Title vault" {
            $ss = Get-Secret -Name BinVaultSecureStr -Vault $VaultName -ErrorVariable err
            $err.Count | Should -Be 0
            [System.Net.NetworkCredential]::new('',$ss).Password | Should -BeExactly $randomSecret
        }

        It "Verifies enumerating SecureString type from $Title vault" {
            $ssInfo = Get-SecretInfo -Name BinVaultSecureStr -Vault $VaultName -ErrorVariable err
            $err.Count | Should -Be 0
            $ssInfo.Name | Should -BeExactly "BinVaultSecureStr"
            $ssInfo.Type | Should -BeExactly "SecureString"
            $ssInfo.VaultName | Should -BeExactly $VaultName
        }

        It "Verifies removing SecureString type from $Title vault" {
            Remove-Secret -Name BinVaultSecureStr -Vault $VaultName -ErrorVariable err
            $err.Count | Should -Be 0
            { Get-Secret -Name BinVaultSecureStr -Vault $VaultName -ErrorAction Stop } | Should -Throw `
                -ErrorId 'InvokeGetSecretError,Microsoft.PowerShell.SecretManagement.GetSecretCommand'
        }

        It "Verifies SecureString write with alternate parameter set" {
            Set-Secret -Name BinVaultSecureStrA -SecureStringSecret $secureStringToWrite `
                -Vault BuiltInLocalVault -ErrorVariable err
            $err.Count | Should -Be 0
        }

        It "Verifies SecureString read from alternate parameter set" {
            $ssRead = Get-Secret -Name BinVaultSecureStrA -Vault BuiltInLocalVault -ErrorVariable err
            $err.Count | Should -Be 0
            [System.Net.NetworkCredential]::new('',$ssRead).Password | Should -BeExactly $randomSecret
        }

        It "Verifes SecureString remove from alternate parameter set" {
            { Remove-Secret -Name BinVaultSecureStrA -Vault BuiltInLocalVault -ErrorVariable err } | Should -Not -Throw
            $err.Count | Should -Be 0
        }
    }

    function VerifyPSCredentialType
    {
        param (
            [string] $Title,
            [string] $VaultName
        )

        $randomSecret = [System.IO.Path]::GetRandomFileName()

        It "Verifies writing PSCredential to $Title vault" {
            $cred = [pscredential]::new('UserName', (ConvertTo-SecureString $randomSecret -AsPlainText -Force))
            Set-Secret -Name BinVaultCred -Secret $cred -Vault $VaultName -ErrorVariable err
            $err.Count | Should -Be 0
        }

        It "Verifies reading PSCredential type from $Title vault" {
            $cred = Get-Secret -Name BinVaultCred -Vault $VaultName -ErrorVariable err
            $err.Count | Should -Be 0
            $cred.UserName | Should -BeExactly "UserName"
            [System.Net.NetworkCredential]::new('', ($cred.Password)).Password | Should -BeExactly $randomSecret
        }

        It "Verifies enumerating PSCredential type from $Title vault" {
            $credInfo = Get-SecretInfo -Name BinVaultCred -Vault $VaultName -ErrorVariable err
            $err.Count | Should -Be 0
            $credInfo.Name | Should -BeExactly "BinVaultCred"
            $credInfo.Type | Should -BeExactly "PSCredential"
            $credInfo.VaultName | Should -BeExactly $VaultName
        }

        It "Verifies removing PSCredential type from $Title vault" {
            Remove-Secret -Name BinVaultCred -Vault $VaultName -ErrorVariable err
            $err.Count | Should -Be 0
            { Get-Secret -Name BinVaultCred -Vault $VaultName -ErrorAction Stop } | Should -Throw `
                -ErrorId 'InvokeGetSecretError,Microsoft.PowerShell.SecretManagement.GetSecretCommand'
        }
    }

    function VerifyHashType
    {
        param (
            [string] $Title,
            [string] $VaultName
        )

        $randomSecretA = [System.IO.Path]::GetRandomFileName()
        $randomSecretB = [System.IO.Path]::GetRandomFileName()

        It "Verifies writing Hashtable type to $Title vault" {
            $ht = @{ 
                Blob = ([byte[]] @(1,2))
                Str = "Hello"
                SecureString = (ConvertTo-SecureString $randomSecretA -AsPlainText -Force)
                Cred = ([pscredential]::New("UserA", (ConvertTo-SecureString $randomSecretB -AsPlainText -Force)))
            }
            Set-Secret -Name BinVaultHT -Vault $VaultName -Secret $ht -ErrorVariable err
            $err.Count | Should -Be 0
        }

        It "Verifies reading Hashtable type from $Title vault" {
            $ht = Get-Secret -Name BinVaultHT -Vault $VaultName -ErrorVariable err
            $err.Count | Should -Be 0
            $ht.Blob.Count | Should -Be 2
            $ht.Str | Should -BeExactly "Hello"
            [System.Net.NetworkCredential]::new('', $ht.SecureString).Password | Should -BeExactly $randomSecretA
            $ht.Cred.UserName | Should -BeExactly "UserA"
            [System.Net.NetworkCredential]::new('', $ht.Cred.Password).Password | Should -BeExactly $randomSecretB
        }

        It "Verifies enumerating Hashtable type from $Title vault" {
            $htInfo = Get-SecretInfo -Name BinVaultHT -Vault $VaultName -ErrorVariable err
            $err.Count | Should -Be 0
            $htInfo.Name | Should -BeExactly "BinVaultHT"
            $htInfo.Type | Should -BeExactly "Hashtable"
            $htInfo.VaultName | Should -BeExactly $VaultName
        }

        It "Verifies removing Hashtable type from $Title vault" {
            Remove-Secret -Name BinVaultHT -Vault $VaultName -ErrorVariable err
            $err.Count | Should -Be 0
            { Get-Secret -Name BinVaultHT -Vault $VaultName -ErrorAction Stop } | Should -Throw `
                -ErrorId 'InvokeGetSecretError,Microsoft.PowerShell.SecretManagement.GetSecretCommand'
        }
    }

    Context "Binary extension vault registration tests" {

        It "Should register the binary vault extension successfullyy but with invalid parameters" {
            $additionalParameters = @{ Hello = "There" }
            { Register-SecretVault -Name BinaryTestVault -ModuleName $script:binModuleFilePath -VaultParameters $additionalParameters -ErrorVariable err } | Should -Not -Throw
            $err.Count | Should -Be 0
        }

        It "Verifies Test-SecretVault fails with errors" {
            Test-SecretVault -Vault BinaryTestVault -ErrorVariable err -ErrorAction SilentlyContinue | Should -BeFalse
            $err.Count | Should -Be 2
        }

        It "Should successfully unregister binary vault extension" {
            { Unregister-SecretVault -Name BinaryTestVault -ErrorVariable err } | Should -Not -Throw
            $err.Count | Should -Be 0
        }

        It "Should register the binary vault extension successfully" {
            $additionalParameters = @{ AccessToken = "SecretAT"; SubscriptionId = "1234567890" }
            { Register-SecretVault -Name BinaryTestVault -ModuleName $script:binModuleFilePath -VaultParameters $additionalParameters -ErrorVariable err } | Should -Not -Throw
            $err.Count | Should -Be 0
        }

        It "Should throw error when registering existing registered vault extension" {
            $additionalParameters = @{ AccessToken = "SecretAT"; SubscriptionId = "1234567890" }
            { Register-SecretVault -Name BinaryTestVault -ModuleName $script:binModuleFilePath -VaultParameters $additionalParameters } | Should -Throw -ErrorId 'RegisterSecretVaultInvalidVaultName'
        }

        It "Verifies Test-SecretVault succeeds" {
            Test-SecretVault -Vault BinaryTestVault | Should -BeTrue
        }
    }

    Context "Binary extension vault byte[] type tests" {

        [VaultExtension.Store]::Dict.Clear()

        VerifyByteArrayType -Title "binary" -VaultName "BinaryTestVault"
    }

    Context "Binary extension vault string type tests" {

        [VaultExtension.Store]::Dict.Clear()

        VerifyStringType -Title "binary" -VaultName "BinaryTestVault"
    }

    Context "Binary extension vault SecureString type tests" {

        [VaultExtension.Store]::Dict.Clear()

        VerifySecureStringType -Title "binary" -VaultName "BinaryTestVault"
    }

    Context "Binary extension vault PSCredential type tests" {

        [VaultExtension.Store]::Dict.Clear()

        VerifyPSCredentialType -Title "binary" -VaultName "BinaryTestVault"
    }

    Context "Binary extension vault Hashtable type tests" {

        [VaultExtension.Store]::Dict.Clear()

        VerifyHashType -Title "binary" -VaultName "BinaryTestVault"
    }

    Context "Script extension vault tests" {

        It "Should register the script vault extension successfully but with invalid parameters" {
            $additionalParameters = @{ Hello = "There" }
            { Register-SecretVault -Name ScriptTestVault -ModuleName $script:scriptModuleFilePath -VaultParameters $additionalParameters -ErrorVariable err } | Should -Not -Throw
            $err.Count | Should -Be 0
        }

        It "Verifies Test-SecretVault fails with errors" {
            Test-SecretVault -Vault ScriptTestVault -ErrorVariable err -ErrorAction SilentlyContinue | Should -BeFalse
            $err.Count | Should -Be 2
        }

        It "Should successfully unregister script vault extension" {
            { Unregister-SecretVault -Name ScriptTestVault -ErrorVariable err } | Should -Not -Throw
            $err.Count | Should -Be 0
        }

        It "Should register the script vault extension successfully" {
            $additionalParameters = @{ AccessToken = "SecretAT"; SubscriptionId = "1234567890" }
            { Register-SecretVault -Name ScriptTestVault -ModuleName $script:scriptModuleFilePath -VaultParameters $additionalParameters -ErrorVariable err } | Should -Not -Throw
            $err.Count | Should -Be 0
        }

        It "Should throw error when registering existing registered vault extension" {
            $additionalParameters = @{ AccessToken = "SecretAT"; SubscriptionId = "1234567890" }
            { Register-SecretVault -Name ScriptTestVault -ModuleName $script:binModuleFilePath -VaultParameters $additionalParameters } | Should -Throw -ErrorId 'RegisterSecretVaultInvalidVaultName'
        }

        It "Verifies Test-SecretVault succeeds" {
            Test-SecretVault -Vault BinaryTestVault | Should -BeTrue
        }
    }

    Context "Script extension vault byte[] type tests" {

        [VaultExtension.Store]::Dict.Clear()

        VerifyByteArrayType -Title "script" -VaultName "ScriptTestVault"
    }

    Context "Script extension vault String type tests" {

        [VaultExtension.Store]::Dict.Clear()

        VerifyStringType -Title "script" -VaultName "ScriptTestVault"
    }

    Context "Script extension vault SecureString type tests" {

        [VaultExtension.Store]::Dict.Clear()

        VerifySecureStringType -Title "script" -VaultName "ScriptTestVault"
    }

    Context "Script extension vault PSCredential type tests" {

        [VaultExtension.Store]::Dict.Clear()

        VerifyPSCredentialType -Title "script" -VaultName "ScriptTestVault"
    }

    Context "Script extension vault Hashtable type tests" {

        [VaultExtension.Store]::Dict.Clear()

        VerifyHashType -Title "script" -VaultName "ScriptTestVault"
    }
}
