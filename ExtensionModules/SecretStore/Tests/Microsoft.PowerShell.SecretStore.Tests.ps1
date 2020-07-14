# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

Describe "Test Microsoft.PowerShell.SecretStore module" -tags CI {

    BeforeAll {

        if ((Get-Module -Name Microsoft.PowerShell.SecretManagement -ErrorAction Ignore) -eq $null)
        {
            Import-Module -Name Microsoft.PowerShell.SecretManagement
        }

        Unregister-SecretVault -Name TestLocalVault -ErrorAction SilentlyContinue
        Register-SecretVault -Name TestLocalVault -ModuleName ../Microsoft.PowerShell.SecretStore.psd1 -DefaultVault
        
        if ((Get-Module -Name Microsoft.PowerShell.SecretStore -ErrorAction Ignore) -eq $null)
        {
            Import-Module -Name ..\Microsoft.PowerShell.SecretStore.psd1
        }

        # Reset the local store and configure it for no-password access
        # TODO: This deletes all local store data!!
        Reset-LocalStore -Scope CurrentUser -PasswordRequired:$false -PasswordTimeout: -1 -DoNotPrompt -Force
    }

    AfterAll {

        Unregister-SecretVault -Name TestLocalVault -ErrorAction SilentlyContinue
    }

    Context "Local Store file permission tests" {

        BeforeAll {
            Get-SecretInfo

            if ($IsWindows)
            {
                $storePath = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::LocalApplicationData)
                $storePath = Join-Path -Path $storePath -ChildPath 'Microsoft\PowerShell\secretmanagement\localstore'
                $storeConfigFilePath = Join-Path -Path $storePath -ChildPath 'storeconfig'
                $storeFilePath = Join-Path -Path $storePath -ChildPath 'storefile'
            }
            else
            {
                $storePath = Join-Path -Path "$home" -ChildPath '.secretmanagement/localstore'
                $storeConfigFilePath = Join-Path -Path $storePath -ChildPath 'storeconfig'
                $storeFilePath = Join-Path -Path $storePath -ChildPath 'storefile'
            }
        }

        if ($IsWindows)
        {
            It "Verifies local store directory ACLs" {
                $acl = Get-Acl $storePath
                $acl.Access | Should -HaveCount 1
                $accessRule = $acl.Access[0]

                $accessRule.FileSystemRights | Should -BeExactly 'FullControl'
                $accessRule.AccessControlType | Should -BeExactly 'Allow'
                $accessRule.IdentityReference | Should -BeExactly ([System.Security.Principal.WindowsIdentity]::GetCurrent()).Name
                $accessRule.IsInherited | Should -BeFalse
                $accessRule.InheritanceFlags | Should -BeExactly 'ContainerInherit, ObjectInherit'
                $accessRule.PropagationFlags | Should -BeExactly 'None'
            }

            It "Verifies local store configuration file ACLs" {
                $acl = Get-Acl $storeConfigFilePath
                $acl.Access | Should -HaveCount 1
                $accessRule = $acl.Access[0]

                $accessRule.FileSystemRights | Should -BeExactly 'FullControl'
                $accessRule.AccessControlType | Should -BeExactly 'Allow'
                $accessRule.IdentityReference | Should -BeExactly ([System.Security.Principal.WindowsIdentity]::GetCurrent()).Name
                $accessRule.IsInherited | Should -BeTrue
                $accessRule.InheritanceFlags | Should -BeExactly 'None'
                $accessRule.PropagationFlags | Should -BeExactly 'None'
            }

            It "Verifies local store file ACLs" {
                $acl = Get-Acl $storeFilePath
                $acl.Access | Should -HaveCount 1
                $accessRule = $acl.Access[0]

                $accessRule.FileSystemRights | Should -BeExactly 'FullControl'
                $accessRule.AccessControlType | Should -BeExactly 'Allow'
                $accessRule.IdentityReference | Should -BeExactly ([System.Security.Principal.WindowsIdentity]::GetCurrent()).Name
                $accessRule.IsInherited | Should -BeTrue
                $accessRule.InheritanceFlags | Should -BeExactly 'None'
                $accessRule.PropagationFlags | Should -BeExactly 'None'
            }
        }
        else
        {
            # drwx------ 2 <user> <user> 4096 Jun 30 16:03 <path>
            $userName = [System.Environment]::GetEnvironmentVariable("USER")

            It "Verifies local store directory permissions" {
                $permissions = (ls -ld "$storePath").Split(' ')
                $permissions[0] | Should -BeExactly 'drwx------'
                $permissions[2] | Should -BeExactly $userName
                $permissions[3] | Should -BeExactly $userName
            }

            It "Verfies local store configuration file permissions" {
                $permissions = (ls -ld "$storeConfigFilePath").Split(' ')
                $permissions[0] | Should -BeExactly '-rw-------'
                $permissions[2] | Should -BeExactly $userName
                $permissions[3] | Should -BeExactly $userName
            }

            It "Verifes local store file permissions" {
                $permissions = (ls -ld "$storeFilePath").Split(' ')
                $permissions[0] | Should -BeExactly '-rw-------'
                $permissions[2] | Should -BeExactly $userName
                $permissions[3] | Should -BeExactly $userName
            }
        }
    }

    Context "Local Store Vault cmdlet tests" {

        It "Verifies local store configuration for tests" {
            $config = Get-LocalStoreConfiguration
            $config.Scope | Should -BeExactly "CurrentUser"
            $config.PasswordRequired | Should -BeFalse
            $config.PasswordTimeout | Should -Be -1
            $config.DoNotPrompt | Should -BeTrue
        }

        It "Verifies local store AllUsers option is not implement" {
            { Set-LocalStoreConfiguration -Scope AllUsers } | Should -Throw -ErrorId 'LocalStoreConfigurationNotSupported,Microsoft.PowerShell.SecretStore.SetLocalStoreConfiguration'
        }

        It "Verifies Unlock-LocalStore throws expected error when in no password mode" {
            { Unlock-LocalStore -Password None } | Should -Throw -ErrorId 'InvalidOperation,Microsoft.PowerShell.SecretStore.UnlockLocalStoreCommand'
        }
    }

    Context "Local Store Vault Byte[] type" {

        $bytesToWrite = [System.Text.Encoding]::UTF8.GetBytes("Hello!!!")

        It "Verifies byte[] write to local store" {
            Set-Secret -Name __Test_ByteArray_ -Secret $bytesToWrite -Vault TestLocalVault -ErrorVariable err
            $err.Count | Should -Be 0
        }

        It "Verifes byte[] read from local store" {
            $bytesRead = Get-Secret -Name __Test_ByteArray_ -Vault TestLocalVault -ErrorVariable err
            $err.Count | Should -Be 0
            [System.Text.Encoding]::UTF8.GetString($bytesRead) | Should -BeExactly "Hello!!!"
        }

        It "Verifes byte[] clobber error in local store" {
            { Set-Secret -Name __Test_ByteArray_ -Secret $bytesToWrite -Vault TestLocalVault -NoClobber } | Should -Throw -ErrorId "AddSecretAlreadyExists"
        }

        It "Verifies byte[] enumeration from local store" {
            $blobInfo = Get-SecretInfo -Name __Test_ByteArray_ -Vault TestLocalVault -ErrorVariable err
            $err.Count | Should -Be 0
            $blobInfo.Name | Should -BeExactly "__Test_ByteArray_"
            $blobInfo.Type | Should -BeExactly "ByteArray"
            $blobInfo.VaultName | Should -BeExactly "TestLocalVault"
        }

        It "Verifies Remove byte[] secret" {
            { Remove-Secret -Name __Test_ByteArray_ -Vault TestLocalVault -ErrorVariable err } | Should -Not -Throw
            $err.Count | Should -Be 0
            { Get-Secret -Name __Test_ByteArray_ -Vault TestLocalVault -ErrorAction Stop } | Should -Throw -ErrorId 'GetSecretNotFound,Microsoft.PowerShell.SecretManagement.GetSecretCommand'
        }
    }

    Context "Local Store Vault String type" {

        It "Verifes string write to local store" {
            Set-Secret -Name __Test_String_ -Secret "Hello!!Secret" -Vault TestLocalVault -ErrorVariable err
            $err.Count | Should -Be 0
        }

        It "Verifies string read from local store" {
            $strRead = Get-Secret -Name __Test_String_ -Vault TestLocalVault -ErrorVariable err
            $err.Count | Should -Be 0
            ($strRead -is [SecureString]) | Should -BeTrue

            $strRead = Get-Secret -Name __Test_String_ -Vault TestLocalVault -AsPlainText -ErrorVariable err
            $err.Count | Should -Be 0
            $strRead | Should -BeExactly "Hello!!Secret"
        }

        It "Verifies string enumeration from local store" {
            $strInfo = Get-SecretInfo -Name __Test_String_ -Vault TestLocalVault -ErrorVariable err
            $err.Count | Should -Be 0
            $strInfo.Name | Should -BeExactly "__Test_String_"
            $strInfo.Type | Should -BeExactly "String"
            $strInfo.VaultName | Should -BeExactly "TestLocalVault"
        }

        It "Verifies string remove from local store" {
            { Remove-Secret -Name __Test_String_ -Vault TestLocalVault -ErrorVariable err } | Should -Not -Throw
            $err.Count | Should -Be 0
            { Get-Secret -Name __Test_String_ -Vault TestLocalVault -ErrorAction Stop } | Should -Throw -ErrorId 'GetSecretNotFound,Microsoft.PowerShell.SecretManagement.GetSecretCommand'
        }
    }

    Context "Local Store Vault SecureString type" {

        $randomSecret = [System.IO.Path]::GetRandomFileName()
            $secureStringToWrite = ConvertTo-SecureString -String $randomSecret -AsPlainText -Force

        It "Verifies SecureString write to local store" {
            Set-Secret -Name __Test_SecureString_ -Secret $secureStringToWrite -Vault TestLocalVault -ErrorVariable err
            $err.Count | Should -Be 0
        }

        It "Verifies SecureString read from local store" {
            $ssRead = Get-Secret -Name __Test_SecureString_ -Vault TestLocalVault -ErrorVariable err
            $err.Count | Should -Be 0
            [System.Net.NetworkCredential]::new('',$ssRead).Password | Should -BeExactly $randomSecret
        }

        It "Verifies SecureString enumeration from local store" {
            $ssInfo = Get-SecretInfo -Name __Test_SecureString_ -Vault TestLocalVault -ErrorVariable err
            $err.Count | Should -Be 0
            $ssInfo.Name | Should -BeExactly "__Test_SecureString_"
            $ssInfo.Type | Should -BeExactly "SecureString"
            $ssInfo.VaultName | Should -BeExactly "TestLocalVault"
        }

        It "Verifies SecureString remove from local store" {
            { Remove-Secret -Name __Test_SecureString_ -Vault TestLocalVault -ErrorVariable err } | Should -Not -Throw
            $err.Count | Should -Be 0
            { Get-Secret -Name __Test_SecureString_ -Vault TestLocalVault -ErrorAction Stop } | Should -Throw `
                -ErrorId 'GetSecretNotFound,Microsoft.PowerShell.SecretManagement.GetSecretCommand'
        }

        It "Verifies SecureString write with alternate parameter set" {
            Set-Secret -Name __Test_SecureStringA_ -SecureStringSecret $secureStringToWrite -Vault TestLocalVault -ErrorVariable err
            $err.Count | Should -Be 0
        }

        It "Verifies SecureString read from alternate parameter set" {
            $ssRead = Get-Secret -Name __Test_SecureStringA_ -Vault TestLocalVault -ErrorVariable err
            $err.Count | Should -Be 0
            [System.Net.NetworkCredential]::new('',$ssRead).Password | Should -BeExactly $randomSecret
        }

        It "Verifes SecureString remove from alternate parameter set" {
            { Remove-Secret -Name __Test_SecureStringA_ -Vault TestLocalVault -ErrorVariable err } | Should -Not -Throw
            $err.Count | Should -Be 0
        }
    }

    Context "Local Store Vault PSCredential type" {

        $randomSecret = [System.IO.Path]::GetRandomFileName()

        It "Verifies PSCredential type write to local store" {
            $cred = [pscredential]::new('UserL', (ConvertTo-SecureString $randomSecret -AsPlainText -Force))
            Set-Secret -Name __Test_PSCredential_ -Secret $cred -Vault TestLocalVault -ErrorVariable err
            $err.Count | Should -Be 0
        }

        It "Verifies PSCredential read from local store" {
            $cred = Get-Secret -Name __Test_PSCredential_ -Vault TestLocalVault -ErrorVariable err
            $err.Count | Should -Be 0
            $cred.UserName | Should -BeExactly "UserL"
            [System.Net.NetworkCredential]::new('', ($cred.Password)).Password | Should -BeExactly $randomSecret
        }

        It "Verifies PSCredential enumeration from local store" {
            $credInfo = Get-SecretInfo -Name __Test_PSCredential_ -Vault TestLocalVault -ErrorVariable err
            $credInfo.Name | Should -BeExactly "__Test_PSCredential_"
            $credInfo.Type | Should -BeExactly "PSCredential"
            $credInfo.VaultName | Should -BeExactly "TestLocalVault"
        }

        It "Verifies PSCredential remove from local store" {
            Remove-Secret -Name __Test_PSCredential_ -Vault TestLocalVault -ErrorVariable err
            $err.Count | Should -Be 0
            { Get-Secret -Name __Test_PSCredential_ -Vault TestLocalVault -ErrorAction Stop } | Should -Throw `
                -ErrorId 'GetSecretNotFound,Microsoft.PowerShell.SecretManagement.GetSecretCommand'
        }
    }

    Context "Local Store Vault Hashtable type" {
        $randomSecretA = [System.IO.Path]::GetRandomFileName()
        $randomSecretB = [System.IO.Path]::GetRandomFileName()

        It "Verifies Hashtable type write to local store" {
            $ht = @{
                Blob = ([byte[]] @(1,2))
                Str = "Hello"
                SecureString = (ConvertTo-SecureString $randomSecretA -AsPlainText -Force)
                Cred = ([pscredential]::New("UserA", (ConvertTo-SecureString $randomSecretB -AsPlainText -Force)))
            }
            Set-Secret -Name __Test_Hashtable_ -Secret $ht -Vault TestLocalVault -ErrorVariable err
            $err.Count | Should -Be 0
        }

        It "Verifies Hashtable read from local store" {
            $ht = Get-Secret -Name __Test_Hashtable_ -Vault TestLocalVault -ErrorVariable err
            $err.Count | Should -Be 0
            $ht.Blob.Count | Should -Be 2
            $ht.Str | Should -BeExactly "Hello"
            [System.Net.NetworkCredential]::new('', ($ht.SecureString)).Password | Should -BeExactly $randomSecretA
            $ht.Cred.UserName | Should -BeExactly "UserA"
            [System.Net.NetworkCredential]::New('', ($ht.Cred.Password)).Password | Should -BeExactly $randomSecretB
        }

        It "Verifies Hashtable enumeration from local store" {
            $htInfo = Get-SecretInfo -Name __Test_Hashtable_ -Vault TestLocalVault -ErrorVariable err
            $err.Count | Should -Be 0
            $htInfo.Name | Should -BeExactly "__Test_Hashtable_"
            $htInfo.Type | Should -BeExactly "Hashtable"
            $htInfo.VaultName | Should -BeExactly "TestLocalVault"
        }

        It "Verifies Hashtable remove from local store" {
            Remove-Secret -Name __Test_Hashtable_ -Vault TestLocalVault -ErrorVariable err
            $err.Count | Should -Be 0
            { Get-Secret -Name __Test_Hashtable_ -Vault TestLocalVault -ErrorAction Stop } | Should -Throw `
                -ErrorId 'GetSecretNotFound,Microsoft.PowerShell.SecretManagement.GetSecretCommand'
        }
    }
}
