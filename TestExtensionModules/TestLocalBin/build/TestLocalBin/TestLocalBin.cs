// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.PowerShell.SecretManagement;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Security;

namespace TestLocalBin
{

    #region TestLocalBin

    public class TestLocalBinExtension : SecretManagementExtension
    {
        #region Constructors

        private TestLocalBinExtension() : base(string.Empty)
        { }

        public TestLocalBinExtension(string vaultName) : base(vaultName)
        { }

        #endregion

        #region Abstract implementations

        public override bool SetSecret(
            string name,
            object secret,
            string vaultName,
            IReadOnlyDictionary<string, object> parameters,
            out Exception error)
        {
            var results = PowerShellInvoker.InvokeCommand(
                command: "Set-Secret",
                args: new object[] { name, secret, vaultName },
                dataStreams: out PSDataStreams dataStreams);

            if (dataStreams.Error.Count > 0)
            {
                error = dataStreams.Error[0].Exception;
                return false;
            }

            error = null;
            return true;
        }

        public override object GetSecret(
            string name,
            string vaultName,
            IReadOnlyDictionary<string, object> parameters,
            out Exception error)
        {
            var result = PowerShellInvoker.InvokeCommand(
                command: "Get-Secret",
                args: new object[] { name, vaultName },
                dataStreams: out PSDataStreams dataStreams);

            error = dataStreams.Error.Count > 0 ? dataStreams.Error[0].Exception : null;

            return result.Count > 0 ? result[0] : null;
        }

        public override bool RemoveSecret(
            string name,
            string vaultName,
            IReadOnlyDictionary<string, object> parameters,
            out Exception error)
        {
            PowerShellInvoker.InvokeCommand(
                command: "Remove-Secret",
                args: new object[] { name, vaultName },
                dataStreams: out PSDataStreams dataStreams);

            if (dataStreams.Error.Count > 0)
            {
                error = dataStreams.Error[0].Exception;
                return false;
            }

            error = null;
            return true;
        }

        public override SecretInformation[] GetSecretInfo(
            string filter,
            string vaultName,
            IReadOnlyDictionary<string, object> parameters,
            out Exception error)
        {
            var results = PowerShellInvoker.InvokeCommand(
                command: "Get-SecretInfo",
                args: new object[] { filter, vaultName },
                dataStreams: out PSDataStreams dataStreams);

            error = dataStreams.Error.Count > 0 ? dataStreams.Error[0].Exception : null;

            var list = new List<SecretInformation>(results.Count);
            foreach (var result in results)
            {
                SecretInformation item = ((result is PSObject) ? result.BaseObject : null) as SecretInformation;
                if (item != null)
                {
                    list.Add(item);
                }
            }

            return list.ToArray();
        }

        public override bool TestSecretVault(
            string vaultName,
            IReadOnlyDictionary<string, object> parameters,
            out Exception[] errors)
        {
            errors = null;
            return true;
        }

        #endregion
    }

    #endregion

    #region PowerShellInvoker

    internal static class PowerShellInvoker
    {
        #region Members

        private const string FunctionsDefScript = @"
            function Get-Path
            {
                param(
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
                param(
                    [Parameter(Mandatory=$true)]
                    [ValidateNotNullOrEmpty()]
                    [string] $Name,

                    [string] $VaultName
                )

                if ([WildcardPattern]::ContainsWildcardCharacters($Name))
                {
                    throw ""The Name parameter cannot contain any wild card characters.""
                }

                $filePath = Join-Path -Path (Get-Path $VaultName) -ChildPath ""${Name}.xml""
    
                if (! (Test-Path -Path $filePath))
                {
                    return
                }

                $secret = Import-CliXml -Path $filePath
                if ($secret.GetType().IsArray)
                {
                    return @(,[byte[]] $secret)
                }

                return $secret
            }

            function Get-SecretInfo
            {
                param(
                    [string] $Name,
                    [string] $VaultName
                )

                if ([string]::IsNullOrEmpty($Name)) { $Name = '*' }

                $files = dir (Join-Path -Path (Get-Path $VaultName) -ChildPath ""${Name}.xml"") 2>$null

                foreach ($file in $files)
                {
                    $secretName = [System.IO.Path]::GetFileNameWithoutExtension((Split-Path $file -Leaf))
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
                            $VaultName))
                }
            }

            function Set-Secret
            {
                param(
                    [Parameter(Mandatory=$true)]
                    [ValidateNotNullOrEmpty()]
                    [string] $Name,

                    [Parameter(Mandatory=$true)]
                    [ValidateNotNull()]
                    [object] $Secret,

                    [string] $VaultName
                )

                $filePath = Join-Path -Path (Get-Path $VaultName) ""${Name}.xml""
                if (Test-Path -Path $filePath)
                {
                    Write-Error ""Secret name, $Name, is already used in this vault.""
                    return
                }

                $Secret | Export-Clixml -Path $filePath
            }

            function Remove-Secret
            {
                param(
                    [string] $Name,
                    [string] $VaultName
                )

                $filePath = Join-Path -Path (Get-Path $VaultName) ""${Name}.xml""
                if (! (Test-Path -Path $filePath))
                {
                    Write-Error ""The secret $Name does not exist""
                    return
                }

                Remove-Item -Path $filePath
            }
        ";

        #endregion

        #region Methods

        public static Collection<PSObject> InvokeCommand(
            string command,
            object[] args,
            out PSDataStreams dataStreams)
        {
            using (var powerShell = System.Management.Automation.PowerShell.Create())
            {
                powerShell.AddScript(FunctionsDefScript).Invoke();
                powerShell.Commands.Clear();

                var results = powerShell.AddCommand(command).AddParameters(args).Invoke();
                dataStreams = powerShell.Streams;
                return results;
            }
        }
    }

    #endregion

    #endregion
}
