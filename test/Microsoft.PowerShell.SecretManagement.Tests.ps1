# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

Describe "Test Microsoft.PowerShell.SecretManagement module" -tags CI {

    BeforeAll {

        if ((Get-Module -Name Microsoft.PowerShell.SecretManagement -ErrorAction Ignore) -eq $null)
        {
            Import-Module -Name Microsoft.PowerShell.SecretManagement
        }

        $global:oldAllowPrompting = (Get-Option).AllowPrompting
        Set-Option -AllowPrompting:$false

        # Binary extension module
        $classImplementation = @'
            using Microsoft.PowerShell.SecretManagement;
            using System;
            using System.Collections;
            using System.Collections.Generic;
            using System.Management.Automation;
            using System.Security;
            
            namespace VaultExtension
            {
                public static class Store
                {
                    private static Dictionary<string, object> _store = new Dictionary<string, object>();
                    public static Dictionary<string, object> Dict { get { return _store; } }
                    public static bool Locked { get; set; }
                    static Store() { Locked = false; }
                }

                public class TestExtVault : SecretManagementExtension
                {
                    private Dictionary<string, object> _store = Store.Dict;
            
                    public TestExtVault(string vaultName) : base(vaultName) { }

                    public void SetVaultLock(bool locked) { Store.Locked = locked; }

                    public override bool UnlockSecretVault(
                        SecureString vaultKey,
                        string vaultName,
                        out Exception error)
                    {
                        error = null;
                        Store.Locked = false;
                        return true;
                    }

                    public override bool TestSecretVault(
                        string vaultName,
                        IReadOnlyDictionary<string, object> additionalParameters,
                        out Exception[] errors)
                    {
                        if (Store.Locked) { throw new Microsoft.PowerShell.SecretManagement.PasswordRequiredException("Pass phrase required"); }
                        var valid = true;
                        var errorList = new List<Exception>();
                        if (!additionalParameters.ContainsKey("AccessId"))
                        {
                            valid = false;
                            errorList.Add(
                                new System.InvalidOperationException("Missing AccessId parameter"));
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
                        if (Store.Locked) { throw new Microsoft.PowerShell.SecretManagement.PasswordRequiredException("Pass phrase required"); }
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
                        if (Store.Locked) { throw new Microsoft.PowerShell.SecretManagement.PasswordRequiredException("Pass phrase required"); }
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
                        if (Store.Locked) { throw new Microsoft.PowerShell.SecretManagement.PasswordRequiredException("Pass phrase required"); }
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
                        if (Store.Locked) { throw new Microsoft.PowerShell.SecretManagement.PasswordRequiredException("Pass phrase required"); }
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
        $scriptModuleName = "TVaultScript"
        $scriptModulePath = Join-Path $testdrive $scriptModuleName
        New-Item -ItemType Directory $scriptModulePath -Force
        $script:scriptModuleFilePath = Join-Path $scriptModulePath "${scriptModuleName}.psd1"
        "@{ ModuleVersion = '1.0' }" | Out-File -FilePath $script:scriptModuleFilePath
        $scriptLockedFilePath = Join-Path $scriptModulePath 'Locked.xml'
        $false | Export-Clixml -Path $scriptLockedFilePath

        $scriptImplementation = @'
            $script:store = [VaultExtension.Store]::Dict
            $script:lockPath = '{0}'

            function GetVaultLock
            {{
                return [bool] (Import-CliXml -Path $script:lockPath)
            }}

            function SetVaultLock
            {{
                param (
                    [bool] $Lock
                )

                $Lock | Export-CliXml -Path $script:lockPath
            }}

            function Get-Secret
            {{
                param (
                    [string] $Name,
                    [string] $VaultName,
                    [hashtable] $AdditionalParameters
                )

                if (GetVaultLock) {{ throw [Microsoft.PowerShell.SecretManagement.PasswordRequiredException]::new("Pass phrase required") }}

                $secret = $script:store[$Name]
                if ($secret -eq $null)
                {{
                    Write-Error("CannotFindSecret")
                }}

                if ($secret -is [byte[]])
                {{
                    return @(,$secret)
                }}

                return $secret
            }}

            function Set-Secret
            {{
                param (
                    [string] $Name,
                    [object] $Secret,
                    [string] $VaultName,
                    [hashtable] $AdditionalParameters
                )

                if (GetVaultLock) {{ throw [Microsoft.PowerShell.SecretManagement.PasswordRequiredException]::new("Pass phrase required") }}

                return $script:store.TryAdd($Name, $Secret)
            }}

            function Remove-Secret
            {{
                param (
                    [string] $Name,
                    [string] $VaultName,
                    [hashtable] $AdditionalParameters
                )

                if (GetVaultLock) {{ throw [Microsoft.PowerShell.SecretManagement.PasswordRequiredException]::new("Pass phrase required") }}

                return $script:store.Remove($Name)
            }}

            function Get-SecretInfo
            {{
                param (
                    [string] $Filter,
                    [string] $VaultName,
                    [hashtable] $AdditionalParameters
                )

                if (GetVaultLock) {{ throw [Microsoft.PowerShell.SecretManagement.PasswordRequiredException]::new("Pass phrase required") }}

                if ([string]::IsNullOrEmpty($Filter))
                {{
                    $Filter = '*'
                }}
                $pattern = [WildcardPattern]::new($Filter)
                foreach ($key in $script:store.Keys)
                {{
                    if ($pattern.IsMatch($key))
                    {{
                        $secret = $script:store[$key]
                        $type = if ($secret -is [byte[]]) {{ [Microsoft.PowerShell.SecretManagement.SecretType]::ByteArray }}
                        elseif ($secret -is [string]) {{ [Microsoft.PowerShell.SecretManagement.SecretType]::String }}
                        elseif ($secret -is [securestring]) {{ [Microsoft.PowerShell.SecretManagement.SecretType]::SecureString }}
                        elseif ($secret -is [PSCredential]) {{ [Microsoft.PowerShell.SecretManagement.SecretType]::PSCredential }}
                        elseif ($secret -is [hashtable]) {{ [Microsoft.PowerShell.SecretManagement.SecretType]::Hashtable }}
                        else {{ [Microsoft.PowerShell.SecretManagement.SecretType]::Unknown }}

                        Write-Output ([Microsoft.PowerShell.SecretManagement.SecretInformation]::new($key, $type, $VaultName))
                    }}
                }}
            }}

            function Unlock-SecretVault
            {{
                param (
                    [securestring] $VaultKey,
                    [string] $VaultName,
                    [hashtable] $AdditionalParameters
                )

                SetVaultLock -Lock $false
                return $true
            }}

            function Test-SecretVault
            {{
                param (
                    [string] $VaultName,
                    [hashtable] $AdditionalParameters
                )

                if (GetVaultLock) {{ throw [Microsoft.PowerShell.SecretManagement.PasswordRequiredException]::new("Pass phrase required") }}

                $valid = $true
                if (! $AdditionalParameters.ContainsKey('AccessId'))
                {{
                    $valid = $false
                    Write-Error 'Missing AccessId parameter'
                }}
                if (! $AdditionalParameters.ContainsKey('SubscriptionId'))
                {{
                    $valid = $false
                    Write-Error 'Missing SubscriptionId parameter'
                }}

                return $valid
            }}
'@ -f $scriptLockedFilePath

        $implementingModuleName = "SecretManagementExtension"
        $implementingModulePath = Join-Path $scriptModulePath $implementingModuleName
        New-Item -ItemType Directory $implementingModulePath -Force
        $implementingManifestFilePath = Join-Path $implementingModulePath "${implementingModuleName}.psd1"
        $manifestInfo = "
        @{{
            ModuleVersion = '1.0'
            RootModule = '{0}'
            FunctionsToExport = @('Set-Secret','Get-Secret','Remove-Secret','Get-SecretInfo','Test-SecretVault','Unlock-SecretVault')
        }}
        " -f $implementingModuleName
        $manifestInfo | Out-File -FilePath $implementingManifestFilePath
        $implementingModuleFilePath = Join-Path $implementingModulePath "${implementingModuleName}.psm1"
        $scriptImplementation | Out-File -FilePath $implementingModuleFilePath
    }

    AfterAll {

        Unregister-SecretVault -Name BinaryTestVault -ErrorAction Ignore
        Unregister-SecretVault -Name ScriptTestVault -ErrorAction Ignore
        Set-Option -AllowPrompting:$($global:oldAllowPrompting)
    }

    function GetVaultLock
    {
        return Import-CliXml -Path $scriptLockedFilePath
    }

    function SetVaultLock
    {
        param (
            [bool] $Lock
        )

        $Lock | Export-Clixml -Path $scriptLockedFilePath -Force
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
                -Vault $VaultName -ErrorVariable err
            $err.Count | Should -Be 0
        }

        It "Verifies SecureString read from alternate parameter set" {
            $ssRead = Get-Secret -Name BinVaultSecureStrA -Vault $VaultName -ErrorVariable err
            $err.Count | Should -Be 0
            [System.Net.NetworkCredential]::new('',$ssRead).Password | Should -BeExactly $randomSecret
        }

        It "Verifes SecureString remove from alternate parameter set" {
            { Remove-Secret -Name BinVaultSecureStrA -Vault $VaultName -ErrorVariable err } | Should -Not -Throw
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

    function VerifyVaultLock
    {
        param (
            [string] $VaultName
        )

        It "Verifies Set-Secret expected error on locked vault: $VaultName" {
            { Set-Secret -Name None -Secret ([System.IO.Path]::GetRandomFileName()) -Vault $VaultName } | `
                Should -Throw -ExceptionType ([Microsoft.PowerShell.SecretManagement.PasswordRequiredException])
        }

        It "Verifies Get-Secret expected error on locked vault: $VaultName" {
            { Get-Secret -Name None -Vault $VaultName } | `
                Should -Throw -ExceptionType ([Microsoft.PowerShell.SecretManagement.PasswordRequiredException])
        }

        It "Verifies Get-SecretInfo expected error on locked vault: $VaultName" {
            { Get-SecretInfo -Vault $VaultName } | `
                Should -Throw -ExceptionType ([Microsoft.PowerShell.SecretManagement.PasswordRequiredException])
        }

        It "Verifies Remove-Secret expected error on locked vault: $VaultName" {
            { Remove-Secret -Name None -Vault $VaultName } | `
                Should -Throw -ExceptionType ([Microsoft.PowerShell.SecretManagement.PasswordRequiredException])
        }

        It "Verifies Test-SecretVault expected error on locked vault: $VaultName" {
            { Test-SecretVault -Vault $VaultName } | `
                Should -Throw -ExceptionType ([Microsoft.PowerShell.SecretManagement.PasswordRequiredException])
        }
    }

    function VerifyVaultUnlock
    {
        param (
            [string] $VaultName
        )

        $fakeKey = [System.IO.Path]::GetRandomFileName()
        Unlock-SecretVault -Name $VaultName -Key (ConvertTo-SecureString -String $fakeKey -AsPlainText -Force)

        It "Verifies Set-Secret no error on unlocked vault: $VaultName" {
            { Set-Secret -Name None -Secret ([System.IO.Path]::GetRandomFileName()) -Vault $VaultName } | Should -Not -Throw
        }

        It "Verifies Get-Secret no error on unlocked vault: $VaultName" {
            { Get-Secret -Name None -Vault $VaultName } | Should -Not -Throw
        }

        It "Verifies Get-SecretInfo no error on unlocked vault: $VaultName" {
            { Get-SecretInfo -Vault $VaultName } | Should -Not -Throw
        }

        It "Verifies Remove-Secret no error on unlocked vault: $VaultName" {
            { Remove-Secret -Name None -Vault $VaultName } | Should -Not -Throw
        }

        It "Verifies Test-SecretVault no error on unlocked vault: $VaultName" {
            { Test-SecretVault -Vault $VaultName } | Should -Not -Throw
        }
    }

    Context "Binary extension (default) vault registration tests" {

        $randomSecretC = [System.IO.Path]::GetRandomFileName()

        It "Should register the binary vault extension successfully but with invalid parameters" {
            $additionalParameters = @{ Hello = "There" }
            { Register-SecretVault -Name BinaryTestVault -ModuleName $script:binModuleFilePath -VaultParameters $additionalParameters -DefaultVault -ErrorVariable err } | Should -Not -Throw
            $err.Count | Should -Be 0
        }

        It "Verifies the binary vault extension is designated as the default vault" {
            $vaultInfo = Get-SecretVault -Name BinaryTestVault
            $vaultInfo.IsDefault | Should -BeTrue
        }

        It "Verifies that a secret item added with no vault specified goes to default vault" {
            Set-Secret -Name TestDefaultItem -Secret $randomSecretC
            Get-Secret -Name TestDefaultItem -Vault BinaryTestVault -AsPlainText | Should -BeExactly $randomSecretC
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
            $additionalParameters = @{ AccessId = "AccessAT"; SubscriptionId = "1234567890" }
            { Register-SecretVault -Name BinaryTestVault -ModuleName $script:binModuleFilePath -VaultParameters $additionalParameters -ErrorVariable err } | Should -Not -Throw
            $err.Count | Should -Be 0
        }

        It "Should throw error when registering existing registered vault extension" {
            $additionalParameters = @{ AccessId = "AccessAT"; SubscriptionId = "1234567890" }
            { Register-SecretVault -Name BinaryTestVault -ModuleName $script:binModuleFilePath -VaultParameters $additionalParameters } | Should -Throw -ErrorId 'RegisterSecretVaultInvalidVaultName'
        }

        It "Verifies Test-SecretVault succeeds" {
            Test-SecretVault -Vault BinaryTestVault | Should -BeTrue
        }
    }

    Context "Binary extension vault lock" {

        [VaultExtension.Store]::Locked = $true
        try
        {
            VerifyVaultLock -VaultName BinaryTestVault
        }
        finally
        {
            [VaultExtension.Store]::Locked = $false
        }
    }

    Context "Binary extension vault unlock" {

        [VaultExtension.Store]::Locked = $true
        try
        {
            VerifyVaultUnlock -VaultName BinaryTestVault
        }
        finally
        {
            [VaultExtension.Store]::Locked = $false
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

    Context "Script extension (non-default) vault tests" {

        $randomSecretD = [System.IO.Path]::GetRandomFileName()

        It "Should register the script vault extension successfully but with invalid parameters" {
            $additionalParameters = @{ Hello = "There" }
            { Register-SecretVault -Name ScriptTestVault -ModuleName $script:scriptModuleFilePath -VaultParameters $additionalParameters -ErrorVariable err } | Should -Not -Throw
            $err.Count | Should -Be 0
        }

        It "Verifies the script vault extension is *not* designated as the default vault" {
            $vaultInfo = Get-SecretVault -Name ScriptTestVault
            $vaultInfo.IsDefault | Should -BeFalse
        }

        It "Verifies that a secret item added with no default vault designated results in error" {
            { Set-Secret -Name TestDefaultItem -Secret $randomSecretD } | Should -Throw -ErrorId 'SetSecretFailNoVault,Microsoft.PowerShell.SecretManagement.SetSecretCommand'
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
            $additionalParameters = @{ AccessId = "AccessAT"; SubscriptionId = "1234567890" }
            { Register-SecretVault -Name ScriptTestVault -ModuleName $script:scriptModuleFilePath -VaultParameters $additionalParameters -ErrorVariable err } | Should -Not -Throw
            $err.Count | Should -Be 0
        }

        It "Should throw error when registering existing registered vault extension" {
            $additionalParameters = @{ AccessId = "AccessAT"; SubscriptionId = "1234567890" }
            { Register-SecretVault -Name ScriptTestVault -ModuleName $script:binModuleFilePath -VaultParameters $additionalParameters } | Should -Throw -ErrorId 'RegisterSecretVaultInvalidVaultName'
        }

        It "Verifies Test-SecretVault succeeds" {
            Test-SecretVault -Vault BinaryTestVault | Should -BeTrue
        }
    }

    Context "Set-DefaultVault cmdlet tests" {

        $randomSecretE = [System.IO.Path]::GetRandomFileName()

        It "Should throw error when setting non existent vault as default" {
            { Set-DefaultVault -Name NoSuchVault } | Should -Throw -ErrorId 'VaultNotFound,Microsoft.PowerShell.SecretManagement.SetDefaultVaultCommand'
        }

        It "Verifies cmdlet successfully sets default vault" {
            Set-DefaultVault -Name BinaryTestVault
            (Get-SecretVault -Name BinaryTestVault).IsDefault | Should -BeTrue
            (Get-SecretVault -Name ScriptTestVault).IsDefault | Should -BeFalse

            Set-DefaultVault -Name ScriptTestVault
            (Get-SecretVault -Name BinaryTestVault).IsDefault | Should -BeFalse
            (Get-SecretVault -Name ScriptTestVault).IsDefault | Should -BeTrue
        }

        It "Verifies setting default vault works as default" {
            Set-DefaultVault -Name BinaryTestVault
            Set-Secret -Name GoesToDefaultVault -Secret $randomSecretE
            Get-Secret -Name GoesToDefaultVault -Vault BinaryTestVault -AsPlainText | Should -BeExactly $randomSecretE
        }
    }

    Context "Script extension vault lock" {

        SetVaultLock -Lock $true
        try
        {
            VerifyVaultLock -VaultName ScriptTestVault
        }
        finally
        {
            SetVaultLock -Lock $false
        }
    }

    Context "Script extension vault unlock" {

        SetVaultLock -Lock $true
        try
        {
            VerifyVaultUnlock -VaultName ScriptTestVault
        }
        finally
        {
            SetVaultLock -Lock $false
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
