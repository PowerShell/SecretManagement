# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

Describe "Test Microsoft.PowerShell.CredManStore module" -Skip:(-Not $IsWindows) {
    BeforeAll {
        $ProjectRoot = Split-Path $PSScriptRoot | Split-Path | Split-Path
        $ModuleRoot = Join-Path $ProjectRoot "artifacts/publish/Microsoft.PowerShell.CredManStore/release"
        Import-Module -Force -Name $ProjectRoot/module/Microsoft.PowerShell.SecretManagement.psd1
        Import-Module -Force -Name $ModuleRoot/Microsoft.PowerShell.CredManStore.psd1
    }

    Context "CredMan Store Vault Byte[] type" {
        BeforeAll {
            $secretName = [System.IO.Path]::GetFileNameWithoutExtension([System.IO.Path]::GetRandomFileName())
            $bytesToWrite = [System.Text.Encoding]::UTF8.GetBytes('TestStringForBytes')
            $errorCode = 0
        }

        It "Verifies byte[] write to store" {
            $success = [Microsoft.PowerShell.CredManStore.LocalCredManStore]::WriteObject(
                $secretName,
                $bytesToWrite,
                [ref] $errorCode)

            $success | Should -BeTrue
            $errorCode | Should -Be 0
        }

        It "Verifes byte[] read from store" {
            $outBytes = $null
            $success = [Microsoft.PowerShell.CredManStore.LocalCredManStore]::ReadObject(
                $secretName,
                [ref] $outBytes,
                [ref] $errorCode)

            $success | Should -BeTrue
            $errorCode | Should -Be 0
            [System.Text.Encoding]::UTF8.GetString($outBytes) | Should -BeExactly 'TestStringForBytes'
        }

        It "Verifies byte[] enumeration from store" {
            $outInfo = $null
            $success = [Microsoft.PowerShell.CredManStore.LocalCredManStore]::EnumerateObjectInfo(
                $secretName,
                [ref] $outInfo,
                [ref] $errorCode)

            $success | Should -BeTrue
            $errorCode | Should -Be 0
            $outInfo.Key | Should -BeExactly $secretName
            $outInfo.Value | Should -BeExactly 'ByteArray'
        }

        It "Verifies Remove byte[] secret from store" {
            $success = [Microsoft.PowerShell.CredManStore.LocalCredManStore]::DeleteObject(
                $secretName,
                [ref] $errorCode)

            $success | Should -BeTrue
            $errorCode | Should -Be 0
        }
    }

    Context "CredMan Store Vault String type" {
        BeforeAll {
            $secretName = [System.IO.Path]::GetFileNameWithoutExtension([System.IO.Path]::GetRandomFileName())
            $stringToWrite = 'TestStringForString'
            $errorCode = 0
        }

        It "Verifes string write to store" {
            $success = [Microsoft.PowerShell.CredManStore.LocalCredManStore]::WriteObject(
                $secretName,
                $stringToWrite,
                [ref] $errorCode)

            $success | Should -BeTrue
            $errorCode | Should -Be 0
        }

        It "Verifies string read from store" {
            $outString = $null
            $success = [Microsoft.PowerShell.CredManStore.LocalCredManStore]::ReadObject(
                $secretName,
                [ref] $outString,
                [ref] $errorCode)

            $success | Should -BeTrue
            $errorCode | Should -Be 0
            $outString | Should -BeExactly 'TestStringForString'
        }

        It "Verifies string enumeration from store" {
            $outInfo = $null
            $success = [Microsoft.PowerShell.CredManStore.LocalCredManStore]::EnumerateObjectInfo(
                $secretName,
                [ref] $outInfo,
                [ref] $errorCode)

            $success | Should -BeTrue
            $errorCode | Should -Be 0
            $outInfo.Key | Should -BeExactly $secretName
            $outInfo.Value | Should -BeExactly 'String'
        }

        It "Verifies string remove from store" {
            $success = [Microsoft.PowerShell.CredManStore.LocalCredManStore]::DeleteObject(
                $secretName,
                [ref] $errorCode)

            $success | Should -BeTrue
            $errorCode | Should -Be 0
        }
    }

    Context "CredMan Store Vault SecureString type" {
        BeforeAll {
            $secretName = [System.IO.Path]::GetFileNameWithoutExtension([System.IO.Path]::GetRandomFileName())
            $randomSecret = [System.IO.Path]::GetRandomFileName()
            $secureStringToWrite = ConvertTo-SecureString -String $randomSecret -AsPlainText -Force
            $errorCode = 0
        }

        It "Verifies SecureString write to store" {
            $success = [Microsoft.PowerShell.CredManStore.LocalCredManStore]::WriteObject(
                $secretName,
                $secureStringToWrite,
                [ref] $errorCode)

            $success | Should -BeTrue
            $errorCode | Should -Be 0
        }

        It "Verifies SecureString read from store" {
            $outSecureString = $null
            $success = [Microsoft.PowerShell.CredManStore.LocalCredManStore]::ReadObject(
                $secretName,
                [ref] $outSecureString,
                [ref] $errorCode)

            $success | Should -BeTrue
            $errorCode | Should -Be 0
            [System.Net.NetworkCredential]::new('',$outSecureString).Password | Should -BeExactly $randomSecret
        }

        It "Verifies SecureString enumeration from store" {
            $outInfo = $null
            $success = [Microsoft.PowerShell.CredManStore.LocalCredManStore]::EnumerateObjectInfo(
                $secretName,
                [ref] $outInfo,
                [ref] $errorCode)

            $success | Should -BeTrue
            $errorCode | Should -Be 0
            $outInfo.Key | Should -BeExactly $secretName
            $outInfo.Value | Should -BeExactly 'SecureString'
        }

        It "Verifies SecureString remove from store" {
            $success = [Microsoft.PowerShell.CredManStore.LocalCredManStore]::DeleteObject(
                $secretName,
                [ref] $errorCode)

            $success | Should -BeTrue
            $errorCode | Should -Be 0
        }
    }

    Context "CredMan Store Vault PSCredential type" {
        BeforeAll {
            $secretName = [System.IO.Path]::GetFileNameWithoutExtension([System.IO.Path]::GetRandomFileName())
            $randomSecret = [System.IO.Path]::GetRandomFileName()
            $errorCode = 0
        }

        It "Verifies PSCredential type write to store" {
            $cred = [pscredential]::new('UserL', (ConvertTo-SecureString $randomSecret -AsPlainText -Force))
            $success = [Microsoft.PowerShell.CredManStore.LocalCredManStore]::WriteObject(
                $secretName,
                $cred,
                [ref] $errorCode)

            $success | Should -BeTrue
            $errorCode | Should -Be 0
        }

        It "Verifies PSCredential read from store" {
            $outCred = $null
            $success = [Microsoft.PowerShell.CredManStore.LocalCredManStore]::ReadObject(
                $secretName,
                [ref] $outCred,
                [ref] $errorCode)

            $success | Should -BeTrue
            $errorCode | Should -Be 0
            $outCred.UserName | Should -BeExactly "UserL"
            [System.Net.NetworkCredential]::new('', ($outCred.Password)).Password | Should -BeExactly $randomSecret
        }

        It "Verifies PSCredential enumeration from store" {
            $outInfo = $null
            $success = [Microsoft.PowerShell.CredManStore.LocalCredManStore]::EnumerateObjectInfo(
                $secretName,
                [ref] $outInfo,
                [ref] $errorCode)

            $success | Should -BeTrue
            $errorCode | Should -Be 0
            $outInfo.Key | Should -BeExactly $secretName
            $outInfo.Value | Should -BeExactly 'PSCredential'
        }

        It "Verifies PSCredential remove from store" {
            $success = [Microsoft.PowerShell.CredManStore.LocalCredManStore]::DeleteObject(
                $secretName,
                [ref] $errorCode)

            $success | Should -BeTrue
            $errorCode | Should -Be 0
        }
    }

    Context "CredMan Store Vault Hashtable type" {
        BeforeAll {
            $secretName = [System.IO.Path]::GetFileNameWithoutExtension([System.IO.Path]::GetRandomFileName())
            $randomSecretA = [System.IO.Path]::GetRandomFileName()
            $randomSecretB = [System.IO.Path]::GetRandomFileName()
            $errorCode = 0
        }

        It "Verifies Hashtable type write to store" {
            $ht = @{
                Blob = ([byte[]] @(1,2))
                Str = "TestStoreString"
                SecureString = (ConvertTo-SecureString $randomSecretA -AsPlainText -Force)
                Cred = ([pscredential]::New("UserA", (ConvertTo-SecureString $randomSecretB -AsPlainText -Force)))
            }

            $success = [Microsoft.PowerShell.CredManStore.LocalCredManStore]::WriteObject(
                $secretName,
                $ht,
                [ref] $errorCode)

            $success | Should -BeTrue
            $errorCode | Should -Be 0
        }

        It "Verifies Hashtable read from store" {
            $outHT = $null
            $success = [Microsoft.PowerShell.CredManStore.LocalCredManStore]::ReadObject(
                $secretName,
                [ref] $outHT,
                [ref] $errorCode)

            $success | Should -BeTrue
            $errorCode | Should -Be 0
            $outHT.Blob.Count | Should -Be 2
            $outHT.Str | Should -BeExactly 'TestStoreString'
            [System.Net.NetworkCredential]::new('', ($outHT.SecureString)).Password | Should -BeExactly $randomSecretA
            $outHT.Cred.UserName | Should -BeExactly 'UserA'
            [System.Net.NetworkCredential]::New('', ($outHT.Cred.Password)).Password | Should -BeExactly $randomSecretB
        }

        It "Verifies Hashtable enumeration from store" {
            $outInfo = $null
            $success = [Microsoft.PowerShell.CredManStore.LocalCredManStore]::EnumerateObjectInfo(
                $secretName,
                [ref] $outInfo,
                [ref] $errorCode)

            $success | Should -BeTrue
            $errorCode | Should -Be 0
            $outInfo.Key | Should -BeExactly $secretName
            $outInfo.Value | Should -BeExactly 'Hashtable'
        }

        It "Verifies Hashtable remove from store" {
            $success = [Microsoft.PowerShell.CredManStore.LocalCredManStore]::DeleteObject(
                $secretName,
                [ref] $errorCode)

            $success | Should -BeTrue
            $errorCode | Should -Be 0
        }
    }
}
