# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

Describe "Test Microsoft.PowerShell.SecretManagement module" {
    BeforeDiscovery {
        $TestCases = 'ByteArray', 'String', 'SecureString', 'PSCredential', 'Hashtable'
    }

    BeforeAll {
        $ProjectRoot = Split-Path $PSScriptRoot
        $ModulePath = Join-Path $ProjectRoot "module"
        $ManifestPath = Join-Path $ModulePath "Microsoft.PowerShell.SecretManagement.psd1"

        $BasePath = Join-Path $TestDrive "SecretManagementStorePath"
        New-Item -ItemType Directory -Path $BasePath -Force

        $StorePath = Join-Path $BasePath "StorePath.xml"
        $MetaStorePath = Join-Path $BasePath "MetaStorePath.xml"

        # Script extension module
        $scriptModuleName = "TVaultScript"
        $implementingModuleName = "TVaultScript.Extension"
        $scriptModulePath = Join-Path $TestDrive $scriptModuleName
        New-Item -ItemType Directory $scriptModulePath -Force

        $scriptModuleFilePath = Join-Path $scriptModulePath "${scriptModuleName}.psd1"
        "@{{
            ModuleVersion = '1.0'
            NestedModules = @('.\{0}')
            FunctionsToExport = @()
        }}" -f $implementingModuleName | Out-File -FilePath $scriptModuleFilePath

        [System.Collections.Generic.Dictionary[[string],[object]]]::new() | Export-Clixml -Path $StorePath
        [System.Collections.Generic.Dictionary[[string],[object]]]::new() | Export-Clixml -Path $MetaStorePath

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

        $scriptImplementation = $scriptImplementationTemplate -f $StorePath, $MetaStorePath

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

        Import-Module -Force -Name $ManifestPath

        $PreviousSecretVaults = Get-SecretVault
        $PreviousSecretVaults | Unregister-SecretVault

        $StoreTypes = @{
            ByteArray = @{
                Kind = 'ByteArray'
                Title = 'script'
                Vault = 'ScriptTestVault'
                Name = 'BinVaultBlob'
                Value = [System.Text.Encoding]::UTF8.GetBytes('BinVaultHelloStr')
                Stringifier = {
                    param([byte[]] $Blob)

                    $sb = [System.Text.StringBuilder]::new()
                    $null = & {
                        $sb = $sb
                        foreach ($byte in $Blob) {
                            $sb.AppendFormat('{0:X2}', $byte)
                        }
                    }

                    return $sb.ToString()
                }
            }
            String = @{
                Kind = 'String'
                Title = 'script'
                Vault = 'ScriptTestVault'
                Name = 'BinVaultStr'
                Value = 'HelloBinVault'
                Stringifier = {
                    if ($args[0] -is [securestring]) {
                        return & $StoreTypes['SecureString']['Stringifier'] $args[0]
                    }

                    return $args[0]
                }
            }
            SecureString = @{
                Kind = 'SecureString'
                Title = 'script'
                Vault = 'ScriptTestVault'
                Name = 'BinVaultSecureStr'
                Value = ConvertTo-SecureString ([System.IO.Path]::GetRandomFileName()) -AsPlainText -Force
                Stringifier = {
                    $ptr = [IntPtr]::Zero
                    try {
                        $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($args[0])
                        $value = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
                        return $value
                    } finally {
                        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
                    }
                }
            }
            PSCredential = @{
                Kind = 'PSCredential'
                Title = 'script'
                Vault = 'ScriptTestVault'
                Name = 'BinVaultCred'
                Value = [pscredential]::new('UserName', (ConvertTo-SecureString ([System.IO.Path]::GetRandomFileName()) -AsPlainText -Force))
                Stringifier = {
                    $networkCred = ([pscredential]$args[0]).GetNetworkCredential()
                    return "u:$($networkCred.UserName)p:$($networkCred.Password)"
                }
            }
            Hashtable = @{
                Kind = 'Hashtable'
                Title = 'script'
                Vault = 'ScriptTestVault'
                Name = 'BinVaultStr'
                Value = @{
                    Blob = ([byte[]] @(1,2))
                    Str = "Hello"
                    SecureString = (ConvertTo-SecureString ([System.IO.Path]::GetRandomFileName()) -AsPlainText -Force)
                    Cred = ([pscredential]::New("UserA", (ConvertTo-SecureString ([System.IO.Path]::GetRandomFileName()) -AsPlainText -Force)))
                }
                Stringifier = {
                    param([hashtable] $ht)
                    end {
                        $sb = [System.Text.StringBuilder]::new('{')
                        $null = & {
                            $sb = $sb
                            $first = $true
                            foreach ($entry in $ht.GetEnumerator() | Sort-Object Key) {
                                if ($first) {
                                    $first = $false
                                } else {
                                    $sb.Append('|')
                                }
                                $sb.Append($entry.Key).Append(':')
                                if ($entry.Value -is [hashtable]) {
                                    $sb.Append((& $StoreTypes['Hashtable']['Stringifier'] $entry.Value))
                                    continue
                                }

                                if ($entry.Value -is [securestring]) {
                                    $sb.Append((& $StoreTypes['SecureString']['Stringifier'] $entry.Value))
                                    continue
                                }

                                if ($entry.Value -is [byte[]] -or $entry.Value -is [object[]]) {
                                    $sb.Append((& $StoreTypes['ByteArray']['Stringifier'] $entry.Value))
                                    continue
                                }

                                if ($entry.Value -is [pscredential]) {
                                    $sb.Append((& $StoreTypes['PSCredential']['Stringifier'] $entry.Value))
                                    continue
                                }

                                $sb.Append([string]$entry.Value)
                            }

                            $sb.Append('}')
                        }

                        return $sb.ToString()
                    }
                }
            }
        }
    }

    AfterAll {
        Unregister-SecretVault -Name ScriptTestVault -ErrorAction Ignore
        foreach ($vault in $PreviousSecretVaults) {
            $params = @{
                ModuleName = $vault.ModuleName
                DefaultVault = $vault.IsDefault
            }

            if ($vault.VaultParameters -and $vault.VaultParameters.Count -gt 0) {
                $params['VaultParameters'] = $vault.VaultParameters
            }

            Register-SecretVault @params
        }

        Remove-Module -Name TVaultScript -Force -ErrorAction Ignore
    }

    Context "Script extension vault <_> type tests" -ForEach $TestCases {
        BeforeAll {
            $SecretTestInfo = $StoreTypes[$_]

            Register-SecretVault -Name ScriptTestVault -ModuleName $scriptModuleFilePath
            [System.Collections.Generic.Dictionary[[string],[object]]]::new() | Export-Clixml -Path $StorePath
            [System.Collections.Generic.Dictionary[[string],[object]]]::new() | Export-CliXml -Path $MetaStorePath
        }

        AfterAll {
            Get-SecretVault ScriptTestVault | Unregister-SecretVault
        }

        It "Verifies writing <_> type to script vault" {
            Set-Secret -Name $SecretTestInfo['Name'] -Secret $SecretTestInfo['Value'] -Vault $SecretTestInfo['Vault'] -ErrorAction Stop
        }

        It "Verifies reading <_> type from script vault" {
            $result = Get-Secret -Name $SecretTestInfo['Name'] -Vault $SecretTestInfo['Vault'] -ErrorAction Stop
            $secretString = & $SecretTestInfo['Stringifier'] $SecretTestInfo['Value']
            $resultString = & $SecretTestInfo['Stringifier'] $result
            $resultString | Should -BeExactly $secretString
        }

        It "Verifies enumerating <_> type from script vault" {
            $blobInfo = Get-SecretInfo -Name $SecretTestInfo['Name'] -Vault $SecretTestInfo['Vault'] -ErrorAction Stop
            $blobInfo.Name | Should -BeExactly $SecretTestInfo['Name']
            $blobInfo.Type | Should -BeExactly $SecretTestInfo['Kind']
            $blobInfo.VaultName | Should -BeExactly $SecretTestInfo['Vault']
        }

        It "Verifies removing <_> type from script vault" {
            Remove-Secret -Name $SecretTestInfo['Name'] -Vault $SecretTestInfo['Vault'] -ErrorAction Stop
            { Get-Secret -Name $SecretTestInfo['Name'] -Vault $SecretTestInfo['Vault'] -ErrorAction Stop } |
                Should -Throw -ErrorId 'GetSecretNotFound,Microsoft.PowerShell.SecretManagement.GetSecretCommand'
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

        BeforeAll {
            $randomSecretD = [System.IO.Path]::GetRandomFileName()
        }

        It "Verifies reserved 'Verbose' keyword in VaultParameters throws expected error" {
            { Register-SecretVault -Name ScriptTestVault -ModuleName $scriptModuleFilePath -VaultParameters @{ Verbose = $true } -ErrorAction Stop } |
                Should -Throw -ErrorId 'RegisterSecretVaultCommandCannotUseReservedName,Microsoft.PowerShell.SecretManagement.RegisterSecretVaultCommand'
        }

        It "Should register the script vault extension successfully but with invalid parameters" {
            $additionalParameters = @{ Hello = "There" }
            Register-SecretVault -Name ScriptTestVault -ModuleName $scriptModuleFilePath -VaultParameters $additionalParameters -ErrorAction Stop
        }

        It "Verifies Test-SecretVault fails with errors" {
            { Test-SecretVault -Name ScriptTestVault -ErrorAction Stop } | 
                Should -Throw -ErrorId 'Microsoft.PowerShell.Commands.WriteErrorException,Microsoft.PowerShell.SecretManagement.TestSecretVaultCommand'
        }

        It "Verifies the only script vault extension is designated as the default vault" {
            $vaultInfo = Get-SecretVault -Name ScriptTestVault
            $vaultInfo.IsDefault | Should -BeTrue
        }

        It "Verifies that a secret item added with default vault designated results in no error" {
            Set-Secret -Name TestDefaultItem -Secret $randomSecretD -ErrorAction Stop
        }

        It "Should successfully unregister script vault extension" {
            Unregister-SecretVault -Name ScriptTestVault -ErrorAction Stop
        }

        It "Should register the script vault extension successfully" {
            $additionalParameters = @{ AccessId = "AccessAT"; SubscriptionId = "1234567890" }
            Register-SecretVault -Name ScriptTestVault -ModuleName $scriptModuleFilePath -VaultParameters $additionalParameters `
                -Description 'ScriptTestVaultDescription' -ErrorAction Stop
        }

        It "Verifies description field for registered test vault" {
            (Get-SecretVault -Name ScriptTestVault).Description | Should -BeExactly 'ScriptTestVaultDescription'
        }

        It "Should throw error when registering existing registered vault extension" {
            $additionalParameters = @{ AccessId = "AccessAT"; SubscriptionId = "1234567890" }
            { Register-SecretVault -Name ScriptTestVault -ModuleName $scriptModuleFilePath -VaultParameters $additionalParameters } |
                Should -Throw -ErrorId 'RegisterSecretVaultInvalidVaultName,Microsoft.PowerShell.SecretManagement.RegisterSecretVaultCommand'
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

        # Metadata is set through extension vault 'Set-SecretInfo' command, and not via a Metadata
        # parameter on 'Set-Secret' command.
        It "Verifies Set-Secret with metadata succeeds" {
            Set-Secret -Name TestDefaultMeta -Secret $randomSecretD -Metadata @{ Fail = $false } -ErrorAction Stop
            $info = Get-SecretInfo -Name TestDefaultMeta
            $info.Metadata | Should -Not -BeNullOrEmpty
            $info.Metadata["Fail"] | Should -BeFalse
        }

        It "Verifes Set-SecretInfo function" {
            Set-SecretInfo -Name TestDefaultMeta -Metadata @{ Fail = $false; Data = "MyData" } -ErrorAction Stop
            $info = Get-SecretInfo -Name TestDefaultMeta
            $info.Metadata | Should -Not -BeNullOrEmpty
            $info.Metadata["Data"] | Should -BeExactly "MyData"
        }

        It "Verifies unsupported Set-SecretInfo fails with error" {
            { Set-SecretInfo -Name TestDefaultMeta -Metadata @{ Fail = $true } -ErrorAction Stop } |
                Should -Throw -ErrorId 'SetSecretMetadataInvalidOperation,Microsoft.PowerShell.SecretManagement.SetSecretInfoCommand'
        }

        It "Verifies Unlock-SecretVault command" {
            [System.Collections.Generic.Dictionary[[string],[object]]]::new() | Export-Clixml -Path $StorePath
            [System.Collections.Generic.Dictionary[[string],[object]]]::new() | Export-CliXml -Path $MetaStorePath

            Unlock-SecretVault -Name ScriptTestVault -Password (ConvertTo-SecureString -String $randomSecretD -AsPlainText -Force) -ErrorAction Stop

            # Verify vault 'Unlock-SecretVault' function was called.
            $dict = Import-Clixml -Path $StorePath
            $dict['UnlockState'] | Should -BeExactly '0x11580'
        }
    }

    Context "Set-SecretVaultDefault cmdlet tests" {

        BeforeAll {
            $randomSecretE = [System.IO.Path]::GetRandomFileName()
        }

        It "Should throw error when setting non existent vault as default" {
            { Set-SecretVaultDefault -Name NoSuchVault } |
                Should -Throw -ErrorId 'VaultNotFound,Microsoft.PowerShell.SecretManagement.SetSecretVaultDefaultCommand'
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

    Context "Unregister-SecretVault cmdlet tests" {

        It "Verifies unregister operation calls the extension 'Unregister-SecretVault' function before unregistering" {
            [System.Collections.Generic.Dictionary[[string],[object]]]::new() | Export-Clixml -Path $StorePath
            [System.Collections.Generic.Dictionary[[string],[object]]]::new() | Export-Clixml -Path $MetaStorePath

            Unregister-SecretVault -Name ScriptTestVault -ErrorAction Stop

            $store = Import-Clixml -Path $StorePath
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
