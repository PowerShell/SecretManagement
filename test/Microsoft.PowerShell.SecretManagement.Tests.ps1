# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

Describe "Test Microsoft.PowerShell.SecretManagement module" -tags CI {

    BeforeAll {

        if ((Get-Module -Name Microsoft.PowerShell.SecretManagement -ErrorAction Ignore) -eq $null)
        {
            Import-Module -Name ..\..\Microsoft.PowerShell.SecretManagement
        }

        Get-SecretVault | Unregister-SecretVault

        # Script extension module
        $scriptModuleName = "TVaultScript"
        $implementingModuleName = "TVaultScript.Extension"
        $scriptModulePath = Join-Path $testdrive $scriptModuleName
        New-Item -ItemType Directory $scriptModulePath -Force
        $script:scriptModuleFilePath = Join-Path $scriptModulePath "${scriptModuleName}.psd1"
        "@{{
            ModuleVersion = '1.0'
            NestedModules = @('.\{0}')
            FunctionsToExport = @() 
        }}" -f $implementingModuleName | Out-File -FilePath $script:scriptModuleFilePath

        # Store Paths
        if ($isWindows)
        {
            $bPath = $env:TEMP
        }
        else 
        {
            $bPath = [System.Environment]::GetEnvironmentVariable("HOME")    
        }
        if ($bPath -eq $null -or !(Test-Path -Path $bPath))
        {
            $bPath = $PSScriptRoot
        }
        $basePath = Join-Path $bPath "SecretManagementStorePath"
        if (! (Test-Path -Path $basePath))
        {
            [System.IO.Directory]::CreateDirectory($basePath)
        }
        $storePath = Join-Path $basePath "StorePath.xml"
        [System.Collections.Generic.Dictionary[[string],[object]]]::new() | Export-Clixml -Path $storePath

        $metaStorePath = Join-Path $basePath "MetaStorePath.xml"
        [System.Collections.Generic.Dictionary[[string],[object]]]::new() | Export-CliXml -Path $metaStorePath

        $scriptImplementationTemplate = @'
            $storePath = "{0}"
            function SetStore
            {{
                param (
                    [string] $name,
                    [object] $value
                )

                $store = Import-CliXml -Path $script:storePath
                if ($store.ContainsKey($name))
                {{
                    $null = $store.Remove($name)
                }}
                $null = $store.Add($name, $value)
                $store | Export-Clixml -Path $script:storePath
            }}
            function GetStore
            {{
                param (
                    [string] $name
                )

                $store = Import-CliXml -Path $script:storePath
                return $store[$name]
            }}
            function RemoveStore
            {{
                param (
                    [string] $Name
                )

                $store = Import-CliXml -Path $script:storePath
                $null = $store.Remove($Name)
                $store | Export-CliXml -Path $script:StorePath
            }}

            $metaStorePath = "{1}"
            function SetMetaStore
            {{
                param (
                    [string] $name,
                    [object] $value
                )

                $store = Import-CliXml -Path $script:metaStorePath
                if ($store.ContainsKey($name))
                {{
                    $null = $store.Remove($name)
                }}
                $null = $store.Add($name, $value)
                $store | Export-Clixml -Path $script:metaStorePath
            }}
            function GetMetaStore
            {{
                param (
                    [string] $name
                )

                $store = Import-CliXml -Path $script:metaStorePath
                return $store[$name]
            }}
            function RemoveMetaStore
            {{
                param (
                    [string] $Name
                )

                $store = Import-CliXml -Path $script:metaStorePath
                $null = $store.Remove($Name)
                $store | Export-CliXml -Path $script:metaStorePath
            }}

            function Get-Secret
            {{
                param (
                    [string] $Name,
                    [string] $VaultName,
                    [hashtable] $AdditionalParameters
                )

                $secret = GetStore $Name

                if ($secret -is [byte[]])
                {{
                    return @(,$secret)
                }}

                return $secret
            }}

            # NOTE: Metadata is supported only through Set-SecretInfo (not Set-Secret)
            function Set-Secret
            {{
                param (
                    [string] $Name,
                    [object] $Secret,
                    [string] $VaultName,
                    [hashtable] $AdditionalParameters
                )

                try {{
                    SetStore $Name $Secret
                    return $true
                }}
                catch {{ }}

                return $false
            }}

            function Set-SecretInfo
            {{
                param (
                    [string] $Name,
                    [hashtable] $Metadata,
                    [string] $VaultName,
                    [hashtable] $AdditionalParameters
                )

                if ($Metadata["Fail"] -eq $true) {{
                    throw [System.Management.Automation.CommandNotFoundException]
                }}

                SetMetaStore $Name $Metadata
            }}

            function Remove-Secret
            {{
                param (
                    [string] $Name,
                    [string] $VaultName,
                    [hashtable] $AdditionalParameters
                )

                
                RemoveStore $Name
                RemoveMetaStore $Name
            }}

            function Get-SecretInfo
            {{
                param (
                    [string] $Filter,
                    [string] $VaultName,
                    [hashtable] $AdditionalParameters
                )

                if ([string]::IsNullOrEmpty($Filter))
                {{
                    $Filter = '*'
                }}
                $store = Import-CliXml -Path $script:storePath
                $metaStore = Import-CliXml -Path $script:metaStorePath
                $pattern = [WildcardPattern]::new($Filter)
                foreach ($key in $store.Keys)
                {{
                    if ($pattern.IsMatch($key))
                    {{
                        $secret = $store[$key]
                        $type = if ($secret -is [byte[]]) {{ [Microsoft.PowerShell.SecretManagement.SecretType]::ByteArray }}
                        elseif ($secret -is [string]) {{ [Microsoft.PowerShell.SecretManagement.SecretType]::String }}
                        elseif ($secret -is [securestring]) {{ [Microsoft.PowerShell.SecretManagement.SecretType]::SecureString }}
                        elseif ($secret -is [PSCredential]) {{ [Microsoft.PowerShell.SecretManagement.SecretType]::PSCredential }}
                        elseif ($secret -is [hashtable]) {{ [Microsoft.PowerShell.SecretManagement.SecretType]::Hashtable }}
                        else {{ [Microsoft.PowerShell.SecretManagement.SecretType]::Unknown }}

                        $metadataDict = [System.Collections.Generic.Dictionary[[string],[object]]]::new()
                        $metadataHashtable = if ($metaStore.ContainsKey($key)) {{ $metaStore[$key] }} else {{ $null }}
                        if ($metadataHashtable -ne $null) {{
                            foreach ($key in $metadataHashtable.Keys) {{
                                if (! $metadataDict.ContainsKey($key))
                                {{
                                    $metadataDict.Add($key, $metadataHashtable[$key])
                                }}
                            }}
                        }}

                        Write-Output ([Microsoft.PowerShell.SecretManagement.SecretInformation]::new($key, $type, $VaultName, $metadataDict))
                    }}
                }}
            }}

            function Test-SecretVault
            {{
                param (
                    [string] $VaultName,
                    [hashtable] $AdditionalParameters
                )

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

                # Used for data stream redirection test.
                Write-Warning 'Test-SecretVault: Bogus Warning'
                Write-Information 'Test-SecretVault: Bogus Information'

                return $valid
            }}

            function Unregister-SecretVault
            {{
                param (
                    [string] $VaultName,
                    [hashtable] $AdditionalParameters
                )

                SetStore "UnRegisterSecretVaultCalled" $true
            }}

            function Unlock-SecretVault
            {{
                param (
                    [string] $Name,
                    [SecureString] $Password,
                    [string] $VaultName,
                    [hashtable] $AdditionalParameters
                )

                try {{
                    SetStore 'UnlockState' '0x11580'
                }}
                catch
                {{
                    Write-Verbose -Verbose 'Unlock-SecretVault: SetStore failed.'
                }}
            }}
'@
        $scriptImplementation = $scriptImplementationTemplate -f $storePath,$metaStorePath

        $implementingModulePath = Join-Path $scriptModulePath $implementingModuleName
        New-Item -ItemType Directory $implementingModulePath -Force
        $implementingManifestFilePath = Join-Path $implementingModulePath "${implementingModuleName}.psd1"
        $manifestInfo = "
        @{{
            ModuleVersion = '1.0'
            RootModule = '{0}'
            FunctionsToExport = @('Set-Secret','Set-SecretInfo','Get-Secret','Remove-Secret','Get-SecretInfo','Test-SecretVault','Unregister-SecretVault','Unlock-SecretVault')
        }}
        " -f $implementingModuleName
        $manifestInfo | Out-File -FilePath $implementingManifestFilePath
        $implementingModuleFilePath = Join-Path $implementingModulePath "${implementingModuleName}.psm1"
        $scriptImplementation | Out-File -FilePath $implementingModuleFilePath
    }

    AfterAll {

        Unregister-SecretVault -Name ScriptTestVault -ErrorAction Ignore
        Remove-Module -Name TVaultScript -Force -ErrorAction Ignore
        if ($basePath -ne $null -and (Test-Path -Path $basePath))
        {
            Remove-Item -Path $basePath -Recurse -Force -ErrorAction SilentlyContinue
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
                -ErrorId 'GetSecretNotFound,Microsoft.PowerShell.SecretManagement.GetSecretCommand'
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
                -ErrorId 'GetSecretNotFound,Microsoft.PowerShell.SecretManagement.GetSecretCommand'
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
                -ErrorId 'GetSecretNotFound,Microsoft.PowerShell.SecretManagement.GetSecretCommand'
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
                -ErrorId 'GetSecretNotFound,Microsoft.PowerShell.SecretManagement.GetSecretCommand'
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
            $ht = Get-Secret -Name BinVaultHT -Vault $VaultName -AsPlainText -ErrorVariable err
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
                -ErrorId 'GetSecretNotFound,Microsoft.PowerShell.SecretManagement.GetSecretCommand'
        }
    }

    Context "API Tests" {

        It "Verifies the SecretInformation constructor" {
            $metadata = @{ Name='Name1'; Target='Target1' }
            $secretInfo = [Microsoft.PowerShell.SecretManagement.SecretInformation]::new(
                'MyName',
                [Microsoft.PowerShell.SecretManagement.SecretType]::String,
                'MyVault',
                $metadata)

            $secretInfo.Name | Should -BeExactly 'MyName'
            $secretInfo.Type | Should -BeExactly 'String'
            $secretInfo.VaultName | Should -BeExactly 'MyVault'
            $secretInfo.Metadata['Name'] | Should -BeExactly 'Name1'
            $secretInfo.Metadata['Target'] | Should -BeExactly 'Target1'
        }
    }

    Context "Script extension (non-default) vault tests" {

        $randomSecretD = [System.IO.Path]::GetRandomFileName()

        It "Verifies reserved 'Verbose' keyword in VaultParameters throws expected error" {
            { Register-SecretVault -Name ScriptTestVault -ModuleName $script:scriptModuleFilePath -VaultParameters @{ Verbose = $true } } | Should -Throw -ErrorId 'RegisterSecretVaultCommandCannotUseReservedName,Microsoft.PowerShell.SecretManagement.RegisterSecretVaultCommand'
        }

        It "Should register the script vault extension successfully but with invalid parameters" {
            $additionalParameters = @{ Hello = "There" }
            { Register-SecretVault -Name ScriptTestVault -ModuleName $script:scriptModuleFilePath -VaultParameters $additionalParameters -ErrorVariable err } | Should -Not -Throw
            $err.Count | Should -Be 0
        }

        It "Verifies Test-SecretVault fails with errors" {
            Test-SecretVault -Name ScriptTestVault 2>$null | Should -BeFalse
        }

        It "Verifies the only script vault extension is designated as the default vault" {
            $vaultInfo = Get-SecretVault -Name ScriptTestVault
            $vaultInfo.IsDefault | Should -BeTrue
        }

        It "Verifies that a secret item added with default vault designated results in no error" {
            { Set-Secret -Name TestDefaultItem -Secret $randomSecretD } | Should -Not -Throw
        }

        It "Should successfully unregister script vault extension" {
            { Unregister-SecretVault -Name ScriptTestVault -ErrorVariable err } | Should -Not -Throw
            $err.Count | Should -Be 0
        }

        It "Should register the script vault extension successfully" {
            $additionalParameters = @{ AccessId = "AccessAT"; SubscriptionId = "1234567890" }
            { Register-SecretVault -Name ScriptTestVault -ModuleName $script:scriptModuleFilePath -VaultParameters $additionalParameters `
                -Description 'ScriptTestVaultDescription' -ErrorVariable err } | Should -Not -Throw
            $err.Count | Should -Be 0
        }

        It "Verifies description field for registered test vault" {
            (Get-SecretVault -Name ScriptTestVault).Description | Should -BeExactly 'ScriptTestVaultDescription'
        }

        It "Should throw error when registering existing registered vault extension" {
            $additionalParameters = @{ AccessId = "AccessAT"; SubscriptionId = "1234567890" }
            { Register-SecretVault -Name ScriptTestVault -ModuleName $script:scriptModuleFilePath -VaultParameters $additionalParameters } | Should -Throw -ErrorId 'RegisterSecretVaultInvalidVaultName'
        }

        It "Verifies Test-SecretVault succeeds" {
            Test-SecretVault -Name ScriptTestVault | Should -BeTrue
        }

        It "Verifes Test-SecretVault extension vault data streams can be redirected" {
            $results = Test-SecretVault -Name ScriptTestVault 3>&1 6>&1
            $results[0] | Should -BeExactly 'Test-SecretVault: Bogus Warning'
            $results[1] | Should -BeExactly 'Test-SecretVault: Bogus Information'
            $results[2] | Should -BeTrue
        }

        It "Verifies Set-Secret with metadata succeeds" {
            { Set-Secret -Name TestDefaultMeta -Secret $randomSecretD -Metadata @{ Fail = $false } -ErrorVariable err } | Should -Not -Throw
            $err.Count | Should -Be 0
            $info = Get-SecretInfo -Name TestDefaultMeta
            $info.Metadata | Should -Not -BeNullOrEmpty
            $info.Metadata["Fail"] | Should -BeFalse
        }

        It "Verifes Set-SecretInfo function" {
            { Set-SecretInfo -Name TestDefaultMeta -Metadata @{ Fail = $false; Data = "MyData" } -ErrorVariable err } | Should -Not -Throw
            $err.Count | Should -Be 0
            $info = Get-SecretInfo -Name TestDefaultMeta
            $info.Metadata | Should -Not -BeNullOrEmpty
            $info.Metadata["Data"] | Should -BeExactly "MyData"
        }

        It "Verifies unsupported Set-SecretInfo fails with error" {
            Set-SecretInfo -Name TestDefaultMeta -Metadata @{ Fail = $true } -ErrorVariable err 2>$null
            $err | Should -HaveCount 1
            $err[0].FullyQualifiedErrorId | Should -BeExactly 'SetSecretMetadataInvalidOperation,Microsoft.PowerShell.SecretManagement.SetSecretInfoCommand'
        }

        It "Verifies Unlock-SecretVault command" {
            [System.Collections.Generic.Dictionary[[string],[object]]]::new() | Export-Clixml -Path $storePath
            [System.Collections.Generic.Dictionary[[string],[object]]]::new() | Export-CliXml -Path $metaStorePath

            Unlock-SecretVault -Name ScriptTestVault -Password (ConvertTo-SecureString -String $randomSecretD -AsPlainText -Force) -ErrorVariable err 2>$null

            # Verify vault 'Unlock-SecretVault' function was called.
            $dict = Import-Clixml -Path $storePath
            $dict['UnlockState'] | Should -BeExactly '0x11580'
        }
    }

    Context "Set-SecretVaultDefault cmdlet tests" {

        $randomSecretE = [System.IO.Path]::GetRandomFileName()

        It "Should throw error when setting non existent vault as default" {
            { Set-SecretVaultDefault -Name NoSuchVault } | Should -Throw -ErrorId 'VaultNotFound,Microsoft.PowerShell.SecretManagement.SetSecretVaultDefaultCommand'
        }

        It "Verifies cmdlet successfully sets default vault" {
            Set-SecretVaultDefault -Name ScriptTestVault
            (Get-SecretVault -Name ScriptTestVault).IsDefault | Should -BeTrue
        }

        It "Verifies cmdlet successfully clears default vault" {
            Set-SecretVaultDefault -ClearDefault
            (Get-SecretVault -Name ScriptTestVault).IsDefault | Should -BeFalse
        }

        It "Verifies setting default vault works as default" {
            Set-SecretVaultDefault -Name ScriptTestVault
            (Get-SecretVault -Name ScriptTestVault).IsDefault | Should -BeTrue
            Set-Secret -Name GoesToDefaultVault -Secret $randomSecretE
            Get-Secret -Name GoesToDefaultVault -Vault ScriptTestVault -AsPlainText | Should -BeExactly $randomSecretE
        }
    }

    Context "Script extension vault byte[] type tests" {

        [System.Collections.Generic.Dictionary[[string],[object]]]::new() | Export-Clixml -Path $storePath
        [System.Collections.Generic.Dictionary[[string],[object]]]::new() | Export-CliXml -Path $metaStorePath

        VerifyByteArrayType -Title "script" -VaultName "ScriptTestVault"
    }

    Context "Script extension vault String type tests" {

        [System.Collections.Generic.Dictionary[[string],[object]]]::new() | Export-Clixml -Path $storePath
        [System.Collections.Generic.Dictionary[[string],[object]]]::new() | Export-CliXml -Path $metaStorePath

        VerifyStringType -Title "script" -VaultName "ScriptTestVault"
    }

    Context "Script extension vault SecureString type tests" {

        [System.Collections.Generic.Dictionary[[string],[object]]]::new() | Export-Clixml -Path $storePath
        [System.Collections.Generic.Dictionary[[string],[object]]]::new() | Export-CliXml -Path $metaStorePath

        VerifySecureStringType -Title "script" -VaultName "ScriptTestVault"
    }

    Context "Script extension vault PSCredential type tests" {

        [System.Collections.Generic.Dictionary[[string],[object]]]::new() | Export-Clixml -Path $storePath
        [System.Collections.Generic.Dictionary[[string],[object]]]::new() | Export-CliXml -Path $metaStorePath

        VerifyPSCredentialType -Title "script" -VaultName "ScriptTestVault"
    }

    Context "Script extension vault Hashtable type tests" {

        [System.Collections.Generic.Dictionary[[string],[object]]]::new() | Export-Clixml -Path $storePath
        [System.Collections.Generic.Dictionary[[string],[object]]]::new() | Export-CliXml -Path $metaStorePath

        VerifyHashType -Title "script" -VaultName "ScriptTestVault"
    }

    Context "Unregister-SecretVault cmdlet tests" {

        It "Verifies unregister operation calls the extension 'Unregister-SecretVault' function before unregistering" {
            [System.Collections.Generic.Dictionary[[string],[object]]]::new() | Export-Clixml -Path $storePath
            [System.Collections.Generic.Dictionary[[string],[object]]]::new() | Export-CliXml -Path $metaStorePath

            { Unregister-SecretVault -Name ScriptTestVault -ErrorVariable err } | Should -Not -Throw
            $err.Count | Should -Be 0

            $store = Import-Clixml -Path $storePath
            $store['UnRegisterSecretVaultCalled'] | Should -BeTrue

            <#
            # Restore the extension module registration.
            $additionalParameters = @{ AccessId = "AccessAT"; SubscriptionId = "1234567890" }
            { Register-SecretVault -Name ScriptTestVault -ModuleName $script:scriptModuleFilePath -VaultParameters $additionalParameters -ErrorVariable err } | Should -Not -Throw
            $err.Count | Should -Be 0
            #>
        }
    }
}
