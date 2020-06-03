// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.PowerShell.SecretManagement;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Security;

namespace AKVaultBin
{
    #region AKVaultBinExtension

    public sealed class AKVaultBinExtension : SecretManagementExtension
    {
        #region Scripts

        private const string CheckSubscriptionLogIn = @"
            param ([string] $SubscriptionId)

            Import-Module -Name Az.Accounts
            
            $azContext = Az.Accounts\Get-AzContext
            return (($azContext -ne $null) -and ($azContext.Subscription.Id -eq $SubscriptionId))
        ";

        private const string GetSecretScript = @"
            param (
                [string] $Name,
                [string] $AZVaultName
            )

            Import-Module -Name Az.KeyVault

            $secret = Az.KeyVault\Get-AzKeyVaultSecret -Name $Name -VaultName $AZVaultName
            if ($secret -ne $null)
            {
                Write-Output $secret.SecretValue
            }
        ";

        private const string SetSecretScript = @"
            param (
                [string] $Name,
                [SecureString] $Secret,
                [string] $AZVaultName
            )

            Import-Module -Name Az.KeyVault

            Az.KeyVault\Set-AzKeyVaultSecret -Name $Name -SecretValue $Secret -VaultName $AZVaultName
        ";

        private const string RemoveSecretScript = @"
            param (
                [string] $Name,
                [string] $AZVaultName
            )

            Import-Module -Name Az.KeyVault

            Az.KeyVault\Remove-AzKeyVaultSecret -Name $Name -VaultName $AZVaultName -Force
        ";

        private const string EnumerateSecretsScript = @"
            param (
                [string] $Filter = ""*"",
                [string] $AZVaultName
            )

            $pattern = [WildcardPattern]::new($Filter)
            $vaultSecretInfos = Az.KeyVault\Get-AzKeyVaultSecret -VaultName $AZVaultName
            foreach ($vaultSecretInfo in $vaultSecretInfos)
            {
                if ($pattern.IsMatch($vaultSecretInfo.Name))
                {
                    Write-Output ([pscustomobject] @{
                        Name = $vaultSecretInfo.Name
                    })
                }
            }
        ";

        #endregion

        #region Constructors

        private AKVaultBinExtension() : base(string.Empty) { }

        public AKVaultBinExtension(string vaultName) : base(vaultName) { }

        #endregion

        #region Abstract implementations

        public override object GetSecret(
            string name, 
            string vaultName,
            IReadOnlyDictionary<string, object> parameters, 
            out Exception error)
        {
            string azkVaultName = (string)parameters["AZKVaultName"];
            string subscriptionId = (string)parameters["SubscriptionId"];

            // Ensure user is logged in to required Azure subscription.
            if (!CheckAzureSubscriptionLogIn(
                subscriptionId: subscriptionId,
                error: out error))
            {
                return false;
            }

            var results = PowerShellInvoker.InvokeScript(
                script: GetSecretScript,
                args: new object[] { name, azkVaultName },
                error: out error);

            return results.Count > 0 ? results[0].BaseObject : null;
        }

        public override bool SetSecret(
            string name, 
            object secret, 
            string vaultName,
            IReadOnlyDictionary<string, object> parameters, 
            out Exception error)
        {
            if (! (secret is SecureString))
            {
                error = new ArgumentException("The secret must be of type SecureString.");
                return false;
            }

            string azkVaultName = (string) parameters["AZKVaultName"];
            string subscriptionId = (string)parameters["SubscriptionId"];

            // Ensure user is logged in to required Azure subscription.
            if (!CheckAzureSubscriptionLogIn(
                subscriptionId: subscriptionId,
                error: out error))
            {
                return false;
            }

            // Add the secret
            PowerShellInvoker.InvokeScript(
                script: SetSecretScript,
                args: new object[] { name, secret, azkVaultName },
                error: out error);

            return (error == null);
        }

        public override bool RemoveSecret(
            string name, 
            string vaultName,
            IReadOnlyDictionary<string, object> parameters, 
            out Exception error)
        {
            string azkVaultName = (string)parameters["AZKVaultName"];
            string subscriptionId = (string)parameters["SubscriptionId"];

            // Ensure user is logged in to required Azure subscription.
            if (!CheckAzureSubscriptionLogIn(
                subscriptionId: subscriptionId,
                error: out error))
            {
                return false;
            }

            // Remove the secret
            PowerShellInvoker.InvokeScript(
                script: RemoveSecretScript,
                args: new object[] { name, azkVaultName },
                error: out error);

            return (error == null);
        }

        public override SecretInformation[] GetSecretInfo(
            string filter,
            string vaultName,
            IReadOnlyDictionary<string, object> parameters,
            out Exception error)
        {
            string azkVaultName = (string)parameters["AZKVaultName"];
            string subscriptionId = (string)parameters["SubscriptionId"];

            // Ensure user is logged in to required Azure subscription.
            if (!CheckAzureSubscriptionLogIn(
                subscriptionId: subscriptionId,
                error: out error))
            {
                return new SecretInformation[0];
            }

            var results = PowerShellInvoker.InvokeScript(
                script: EnumerateSecretsScript,
                args: new object[] { filter, azkVaultName },
                error: out error);

            var list = new List<SecretInformation>(results.Count);
            foreach (dynamic result in results)
            {
                list.Add(
                    new SecretInformation(
                        name: result.Name,
                        type: SecretType.SecureString,
                        vaultName: vaultName));
            }

            return list.ToArray();
        }

        public override bool TestSecretVault(
            string vaultName,
            IReadOnlyDictionary<string, object> parameters,
            out Exception[] errors)
        {
            if (!CheckAzureSubscriptionLogIn(
                subscriptionId: (string)parameters["SubscriptionId"],
                error: out Exception error))
            {
                errors = new Exception[1] {
                    error
                };
                return false;
            }

            errors = null;
            return true;
        }
        
        #endregion

        #region Private methods

        private bool CheckAzureSubscriptionLogIn(
            string subscriptionId,
            out Exception error)
        {
            var results = PowerShellInvoker.InvokeScript(
                script: CheckSubscriptionLogIn,
                args: new object[] { subscriptionId },
                error: out Exception _);

            dynamic checkResult = results.Count > 0 ? results[0] : false;
            if (!checkResult)
            {
                var msg = string.Format(
                    CultureInfo.InstalledUICulture,
                    "To use the {0} vault, the current user needs to be logged into Azure account subscription '{1}'.  Run 'Connect-AzAccount -Subscription '{1}''",
                    VaultName,
                    subscriptionId);
                error = new InvalidOperationException(msg);
                return false;
            }

            error = null;
            return true;
        }

        #endregion
    }

    #endregion

    #region PowerShellInvoker

    internal static class PowerShellInvoker
    {
        #region Methods

        public static Collection<PSObject> InvokeScript(
            string script,
            object[] args,
            out Exception error)
        {
            using (var powerShell = System.Management.Automation.PowerShell.Create())
            {
                error = null;
                Collection<PSObject> results;
                try
                {
                    results = powerShell.AddScript(script).AddParameters(args).Invoke();
                    if (powerShell.Streams.Error.Count > 0)
                    {
                        error = powerShell.Streams.Error[0].Exception;
                    }
                }
                catch (Exception ex)
                {
                    error = ex;
                    results = new Collection<PSObject>();
                }

                return results;
            }
        }

        #endregion
    }

    #endregion
}
