# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

Describe "Test Microsoft.PowerShell.SecretStore module" -tags CI {

    BeforeAll {

        if ((Get-Module -Name Microsoft.PowerShell.SecretManagement -ErrorAction Ignore) -eq $null)
        {
            Import-Module -Name Microsoft.PowerShell.SecretManagement
        }

        # Reset the local store and configure it for no-password access
        # TODO: This deletes all local store data!!
        Reset-LocalStore -Scope CurrentUser -PasswordRequired:$false -PasswordTimeout: -1 -DoNotPrompt -Force
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
            { Set-LocalStoreConfiguration -Scope AllUsers } | Should -Throw -ErrorId 'LocalStoreConfigurationNotSupported,Microsoft.PowerShell.SecretManagement.SetLocalStoreConfiguration'
        }

        It "Verifies Unlock-LocalStore throws expected error when in no password mode" {
            { Unlock-LocalStore -Password None } | Should -Throw -ErrorId 'InvalidOperation,Microsoft.PowerShell.SecretManagement.UnlockLocalStoreCommand'
        }
    }

    Context "Local Store Vault Byte[] type" {

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

    Context "Local Store Vault String type" {

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

    Context "Local Store Vault SecureString type" {

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

    Context "Local Store Vault PSCredential type" {

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
}
