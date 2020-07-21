# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

Describe "Test Microsoft.PowerShell.CredManStore module" -tags CI {

    BeforeAll {

    }

    AfterAll {

    }

    Context "CredMan Store basic tests" {

        BeforeAll {

        }

        if ($IsWindows)
        {
            
        }
    }

    Context "CredMan Store Vault Byte[] type" {

        $bytesToWrite = [System.Text.Encoding]::UTF8.GetBytes("Hello!!!")

        It "Verifies byte[] write to local store" {

        }

        It "Verifes byte[] read from local store" {

        }

        It "Verifes byte[] clobber error in local store" {
            
        }

        It "Verifies byte[] enumeration from local store" {
            
        }

        It "Verifies Remove byte[] secret" {
            
        }
    }

    Context "CredMan Store Vault String type" {

        It "Verifes string write to local store" {
            
        }

        It "Verifies string read from local store" {
            
        }

        It "Verifies string enumeration from local store" {
            
        }

        It "Verifies string remove from local store" {
            
        }
    }

    Context "CredMan Store Vault SecureString type" {

        $randomSecret = [System.IO.Path]::GetRandomFileName()
        $secureStringToWrite = ConvertTo-SecureString -String $randomSecret -AsPlainText -Force

        It "Verifies SecureString write to local store" {
            
        }

        It "Verifies SecureString read from local store" {
            
        }

        It "Verifies SecureString enumeration from local store" {
            
        }

        It "Verifies SecureString remove from local store" {
            
        }

        It "Verifies SecureString write with alternate parameter set" {
            
        }

        It "Verifies SecureString read from alternate parameter set" {
            
        }

        It "Verifes SecureString remove from alternate parameter set" {
            
        }
    }

    Context "CredMan Store Vault PSCredential type" {

        $randomSecret = [System.IO.Path]::GetRandomFileName()

        It "Verifies PSCredential type write to local store" {
            
        }

        It "Verifies PSCredential read from local store" {
            
        }

        It "Verifies PSCredential enumeration from local store" {
            
        }

        It "Verifies PSCredential remove from local store" {
            
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
            
        }

        It "Verifies Hashtable read from local store" {
            $ht = Get-Secret -Name __Test_Hashtable_ -Vault TestLocalVault -AsPlainText -ErrorVariable err
            
        }

        It "Verifies Hashtable enumeration from local store" {
            $htInfo = Get-SecretInfo -Name __Test_Hashtable_ -Vault TestLocalVault -ErrorVariable err
            
        }

        It "Verifies Hashtable remove from local store" {
            Remove-Secret -Name __Test_Hashtable_ -Vault TestLocalVault -ErrorVariable err
            
        }
    }
}
