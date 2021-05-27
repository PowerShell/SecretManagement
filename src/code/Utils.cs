// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Management.Automation;
using System.Management.Automation.Language;
using System.Management.Automation.Runspaces;
using System.Security;

namespace Microsoft.PowerShell.SecretManagement
{
    #region Utils

    internal static class Utils
    {
        #region Members

        private const string NoVaultRegistered = @"
        There are currently no extension vaults registered.
        At least one vault must be registered before SecretManagement can add or retrieve secrets.
        You can download SecretManagement extension vault modules from PowerShellGallery.
        https://aka.ms/SecretManagementVaults
        ";

        private const string ImplementingExtension = "Extension";

        private const string ConvertJsonToHashtableScript = @"
            param (
                [string] $json
            )

            function ConvertToHash
            {
                param (
                    [pscustomobject] $object
                )

                $output = @{}
                $object | Microsoft.PowerShell.Utility\Get-Member -MemberType NoteProperty | ForEach-Object {
                    $name = $_.Name
                    $value = $object.($name)

                    if ($value -is [object[]])
                    {
                        $array = @()
                        $value | ForEach-Object {
                            $array += (ConvertToHash $_)
                        }
                        $output.($name) = $array
                    }
                    elseif ($value -is [pscustomobject])
                    {
                        $output.($name) = (ConvertToHash $value)
                    }
                    else
                    {
                        $output.($name) = $value
                    }
                }

                $output
            }

            $customObject = Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $json
            return ConvertToHash $customObject
        ";

        #endregion

        #region Methods

        public static Hashtable ConvertJsonToHashtable(string json)
        {
            using (var ps = System.Management.Automation.PowerShell.Create(RunspaceMode.NewRunspace))
            {
                var results = PowerShellInvoker.InvokeScriptOnPowerShell<Hashtable>(
                    script: ConvertJsonToHashtableScript,
                    args: new object[] { json },
                    psToUse: ps,
                    error: out ErrorRecord _);

                return (results.Count > 0) ? results[0] : null;
            }
        }

        public static Hashtable ConvertDictToHashtable(IDictionary<string, object> dict)
        {
            var returnHashtable = new Hashtable();
            if (dict != null)
            {
                foreach (var item in dict)
                {
                    returnHashtable.Add(item.Key, item.Value);
                }
            }

            return returnHashtable;
        }

        public static string ConvertHashtableToJson(Hashtable hashtable)
        {
            var results = PowerShellInvoker.InvokeScript<string>(
                script: @"param ([hashtable] $hashtable) Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject $hashtable -Depth 10",
                args: new object[] { hashtable },
                error: out ErrorRecord _);

            return (results.Count > 0) ? results[0] : null;
        }

        public static SecureString ConvertToSecureString(string secret)
        {
            var results = PowerShellInvoker.InvokeScript<SecureString>(
                script: @"param([string] $value) Microsoft.PowerShell.Security\ConvertTo-SecureString -String $value -AsPlainText -Force",
                args: new object[] { secret },
                error: out ErrorRecord _);
            
            return (results.Count > 0) ? results[0] : null;
        }

        public static string GetModuleExtensionName(string moduleName)
        {
            return string.Format(CultureInfo.InvariantCulture, 
                @"{0}.{1}", moduleName, ImplementingExtension);
        }

        public static string TrimQuotes(string name)
        {
            return name.Trim('\'', '"');
        }

        public static string QuoteName(string name)
        {
            bool quotesNeeded = false;
            foreach (var c in name)
            {
                if (Char.IsWhiteSpace(c))
                {
                    quotesNeeded = true;
                    break;
                }
            }

            if (!quotesNeeded)
            {
                return name;
            }

            return "'" + CodeGeneration.EscapeSingleQuotedStringContent(name) + "'";
        }

        public static void CheckForRegisteredVaults(PSCmdlet cmdlet)
        {
            if (RegisteredVaultCache.VaultExtensions.Count == 0)
            {
                cmdlet.WriteWarning(NoVaultRegistered);
            }
        }

        #endregion
    }

    #endregion

    #region Enums

    /// <summary>
    /// Supported secret types
    /// </summary>
    public enum SecretType
    {
        Unknown = 0,
        ByteArray,
        String,
        SecureString,
        PSCredential,
        Hashtable
    };

    #endregion

    #region Exceptions

    public sealed class PasswordRequiredException : InvalidOperationException
    {
        #region Constructor

        public PasswordRequiredException(string msg)
            : base(msg)
        {
        }

        #endregion
    }

    #endregion

    #region SecretInformation class

    public sealed class SecretInformation
    {
        #region Properties
        
        /// <summary>
        /// Gets the name of the secret.
        /// </summary>
        public string Name
        {
            get; 
        }

        /// <summary>
        /// Gets the object type of the secret.
        /// </summary>
        public SecretType Type
        {
            get;
        }

        /// <summary>
        /// Gets the vault name where the secret resides.
        /// </summary>
        public string VaultName
        {
            get;
        }

        /// <summary>
        /// Gets metadata of the secret.
        /// </summary>
        public ReadOnlyDictionary<string, object> Metadata
        {
            get;
        }

        #endregion

        #region Constructor

        /// <summary>
        /// Constructor
        /// </summary>
        public SecretInformation(
            string name,
            SecretType type,
            string vaultName)
        {
            Name = name;
            Type = type;
            VaultName = vaultName;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        public SecretInformation(
            string name,
            SecretType type,
            string vaultName,
            ReadOnlyDictionary<string, object> metadata) : this(name, type, vaultName)
        {
            Metadata = metadata;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        public SecretInformation(
            string name,
            SecretType type,
            string vaultName,
            Hashtable metadata) : this(name, type, vaultName)
        {
            if (metadata == null) { return; }

            Dictionary<string, object> metaDictionary = new Dictionary<string, object>(metadata.Count);
            foreach (var key in metadata.Keys)
            {
                metaDictionary.Add((string)key, metadata[key]);
            }
            Metadata = new ReadOnlyDictionary<string, object>(metaDictionary);
        }

        private SecretInformation()
        {
        }

        #endregion
    }

    #endregion

    #region Extension vault module class

    /// <summary>
    /// Class that contains all vault module information and secret manipulation methods.
    /// </summary>
    internal class ExtensionVaultModule
    {
        #region Members

        #region Script

        // Invokes Get-Secret, Set-Secret, Get-SecretInfo, Remove-Secret, Test-SecretVault commands in
        // nested module within provided module path.
        // Assumes the following directory structure:
        //  Module directory (parent module)
        //      Module.psd1
        //      Module.psm1
        //      ImplementingModule directory (nested module)
        //          ImplementingModule.psd1
        //          ImplementingModule.psm1
        private const string RunCommandScript = @"
            param (
                [string] $ModuleName,
                [string] $ModulePath,
                [string] $ImplementingModuleName,
                [string] $Command,
                [hashtable] $Params
            )

            $verboseEnabled = $Params.AdditionalParameters.ContainsKey('Verbose') -and ($Params.AdditionalParameters['Verbose'] -eq $true)
            $module = Microsoft.PowerShell.Core\Get-Module -Name $ModuleName -ErrorAction Ignore
            if ($null -eq $module) {
                $module = Microsoft.PowerShell.Core\Import-Module -Name $ModulePath -PassThru
            }
            if ($null -eq $module) {
                return
            }
            Write-Verbose ""Invoking command $Command on module $ImplementingModuleName"" -Verbose:$verboseEnabled
            & $module ""$ImplementingModuleName\$Command"" @Params
        ";

        // Conditionally invokes an optional command if supported by the implementing module.
        // Assumes the following directory structure:
        //  Module directory (parent module)
        //      Module.psd1
        //      Module.psm1
        //      ImplementingModule directory (nested module)
        //          ImplementingModule.psd1
        //          ImplementingModule.psm1
        private const string RunIfCommandScript = @"
            param (
                [string] $ModuleName,
                [string] $ModulePath,
                [string] $ImplementingModuleName,
                [string] $Command,
                [hashtable] $Params
            )
        
            $verboseEnabled = $Params.AdditionalParameters.ContainsKey('Verbose') -and ($Params.AdditionalParameters['Verbose'] -eq $true)
            $module = Microsoft.PowerShell.Core\Get-Module -Name $ModuleName -ErrorAction Ignore
            if ($null -eq $module) {
                $module = Microsoft.PowerShell.Core\Import-Module -Name $ModulePath -PassThru
            }
            if ($null -eq $module) {
                return
            }
            try {
                Write-Verbose ""Invoking command $Command on module $ImplementingModuleName"" -Verbose:$verboseEnabled
                & $module ""$ImplementingModuleName\$Command"" @Params
            }
            catch [System.Management.Automation.CommandNotFoundException] {
                Write-Verbose ""Module $ImplementingModuleName does not support command : $Command"" -Verbose:$verboseEnabled
            }
        ";

        // Return values:
        // 0 - Command ran (command will emit any error message)
        // 1 - Module not found
        // 2 - Command not found
        private const string RunConditionalCommandScript = @"
            param (
                [string] $ModuleName,
                [string] $ModulePath,
                [string] $ImplementingModuleName,
                [string] $Command,
                [hashtable] $Params
            )
        
            $verboseEnabled = $Params.AdditionalParameters.ContainsKey('Verbose') -and ($Params.AdditionalParameters['Verbose'] -eq $true)
            $module = Microsoft.PowerShell.Core\Get-Module -Name $ModuleName -ErrorAction Ignore
            if ($null -eq $module) {
                $module = Microsoft.PowerShell.Core\Import-Module -Name $ModulePath -PassThru
            }
            if ($null -eq $module) {
                return 1
            }
            try {
                Write-Verbose ""Invoking command $Command on module $ImplementingModuleName"" -Verbose:$verboseEnabled
                $null = & $module ""$ImplementingModuleName\$Command"" @Params
                return 0
            }
            catch [System.Management.Automation.CommandNotFoundException] {
                return 2
            }
        ";

        #endregion

        internal const string GetSecretCmd = "Get-Secret";
        internal const string GetSecretInfoCmd = "Get-SecretInfo";
        internal const string SetSecretCmd = "Set-Secret";
        internal const string SetSecretInfoCmd = "Set-SecretInfo";
        internal const string RemoveSecretCmd = "Remove-Secret";
        internal const string UnlockVaultCmd = "Unlock-SecretVault";
        internal const string TestVaultCmd = "Test-SecretVault";
        internal const string UnregisterSecretVaultCommand = "Unregister-SecretVault";
        internal const string ModuleNameStr = "ModuleName";
        internal const string ModulePathStr = "ModulePath";
        internal const string VaultParametersStr = "VaultParameters";
        internal const string DescriptionStr = "Description";
        internal const string SetSecretSupportsMetadataStr = "SetSecretSupportsMetadata";
        
        #endregion

        #region Properties

        /// <summary>
        /// Name of extension vault.
        /// </summary>
        public string VaultName { get; }

        /// <summary>
        /// Module name to qualify module commands.
        /// </summary>
        public string ModuleName { get; }

        /// <summary>
        /// Name of module extension which implements required functions.
        /// </summary>
        public string ModuleExtensionName { get; }

        /// <summary>
        /// Module path.
        /// </summary>
        public string ModulePath { get; }

        /// <summary>
        /// Additional vault parameters.
        /// <summary>
        public IReadOnlyDictionary<string, object> VaultParameters { get; }

        /// <summary>
        /// True when this extension vault is the default vault.
        /// </summary>
        public bool IsDefault { get; }

        /// <summary>
        /// Optional description string for vault.
        /// </summary>
        public string Description { get; }

        /// <summary>
        /// True when this extension vault Set-Secret function supports the Metadata parameter.
        /// </summary>
        public bool SetSecretSupportsMetadata { get; }

        #endregion

        #region Constructor

        private ExtensionVaultModule() 
        {
        }

        /// <summary>
        /// Initializes a new instance of ExtensionVaultModule.
        /// </summary>
        public ExtensionVaultModule(
            string vaultName,
            Hashtable vaultInfo,
            bool isDefault)
        {
            // Module information.
            IsDefault = isDefault;
            VaultName = vaultName;
            ModuleName = (string) vaultInfo[ModuleNameStr];
            ModuleExtensionName = Utils.GetModuleExtensionName(ModuleName);
            ModulePath = (string) vaultInfo[ModulePathStr];
            Description = vaultInfo.ContainsKey(DescriptionStr) ? (string) vaultInfo[DescriptionStr] : string.Empty;
            SetSecretSupportsMetadata = vaultInfo.ContainsKey(SetSecretSupportsMetadataStr) ? 
                (bool) vaultInfo[SetSecretSupportsMetadataStr] : false;

            // Additional parameters.
            var vaultParameters = new Dictionary<string, object>();
            if (vaultInfo.ContainsKey(VaultParametersStr))
            {
                var vaultParamsHashtable = (Hashtable) vaultInfo[VaultParametersStr];
                foreach (string key in vaultParamsHashtable.Keys)
                {
                    vaultParameters.Add(
                        key: key,
                        value: vaultParamsHashtable[key]);
                }
            }
            VaultParameters = new ReadOnlyDictionary<string, object>(vaultParameters);
        }

        /// <summary>
        /// Initializes a new instance of ExtensionVaultModule from an existing instance.
        /// </summary>
        public ExtensionVaultModule(
            ExtensionVaultModule module)
        {
            VaultName = module.VaultName;
            ModuleName = module.ModuleName;
            ModuleExtensionName = module.ModuleExtensionName;
            ModulePath = module.ModulePath;
            Description = module.Description;
            VaultParameters = module.VaultParameters;
            IsDefault = module.IsDefault;
            SetSecretSupportsMetadata = module.SetSecretSupportsMetadata;
        }

        #endregion

        #region Public methods

        /// <summary>
        /// Invoke SetSecret method on vault extension.
        /// </summary>
        /// <param name="name">Name of secret to add.</param>
        /// <param name="secret">Secret object to add.</param>
        /// <param name="vaultName">Name of registered vault.</param>
        /// <param name="metadata">Optional metadata associated with the secret.</param>
        /// <param name="cmdlet">Calling cmdlet.</param>
        public void InvokeSetSecret(
            string name,
            object secret,
            string vaultName,
            Hashtable metadata,
            PSCmdlet cmdlet)
        {
            var additionalParameters = GetAdditionalParams(cmdlet);
            var parameters = new Hashtable() {
                { "Name", name },
                { "Secret", secret },
                { "VaultName", vaultName },
                { "AdditionalParameters", additionalParameters }
            };

            // Include metadata if supported by vault.
            if (SetSecretSupportsMetadata)
            {
                parameters.Add(
                    key: "Metadata",
                    value: metadata ?? new Hashtable());
            }

            PowerShellInvoker.InvokeScriptWithHost(
                cmdlet: cmdlet,
                script: RunCommandScript,
                args: new object[] { ModuleName, ModulePath, ModuleExtensionName, SetSecretCmd, parameters },
                out Exception terminatingError);
            
            if (terminatingError != null)
            {
                ThrowPasswordRequiredException(terminatingError);

                cmdlet.WriteError(
                    new ErrorRecord(
                        new PSInvalidOperationException(
                            message: string.Format(CultureInfo.InvariantCulture, "Unable to add secret {0} to vault {1}", name, VaultName),
                            innerException: terminatingError),
                        "SetSecretInvalidOperation",
                        ErrorCategory.InvalidOperation,
                        this));

                return;
            }

            // If metadata is provided but not supported through Set-Secret parameter, then attempt to call 
            // the separate vault Set-SecretInfo function as an alternative.
            if (metadata?.Count > 0 && !SetSecretSupportsMetadata &&
                !InvokeSetSecretMetadata(
                    name: name,
                    metadata: metadata,
                    vaultName: vaultName,
                    cmdlet: cmdlet))
            {
                // Unable to write metadata, probably because metadata is not supported by the extension vault.
                // Remove the secret from the vault, since it did not fully write.
                InvokeRemoveSecret(
                    name: name,
                    vaultName: vaultName,
                    cmdlet: cmdlet);
                
                return;
            }
            
            cmdlet.WriteVerbose(
                string.Format(CultureInfo.InvariantCulture, "Secret {0} was successfully added to vault {1}.", name, VaultName));
        }

        public bool InvokeUnlockSecretVault(
            SecureString password,
            string vaultName,
            PSCmdlet cmdlet)
        {
            var additionalParameters = GetAdditionalParams(cmdlet);
            var parameters = new Hashtable() {
                { "Password", password },
                { "VaultName", vaultName },
                { "AdditionalParameters", additionalParameters }
            };

            // Result values:
            // 0 - Command ran (command will emit any error message)
            // 1 - Module not found
            // 2 - Command not found
            var results = PowerShellInvoker.InvokeScriptWithHost<int>(
                cmdlet: cmdlet,
                script: RunConditionalCommandScript,
                args: new object[] { ModuleName, ModulePath, ModuleExtensionName, UnlockVaultCmd, parameters },
                out Exception terminatingError);
            
            if (terminatingError != null)
            {
                ThrowPasswordRequiredException(terminatingError);

                cmdlet.WriteError(
                    new ErrorRecord(
                        new PSInvalidOperationException(
                            message: string.Format(CultureInfo.InvariantCulture, "Unlocking vault '{0}' failed with error: {1}", vaultName, terminatingError.Message),
                            innerException: terminatingError),
                        "UnlockSecretVaultInvalidOperation",
                        ErrorCategory.InvalidOperation,
                        this));

                return false;
            }

            int result = (results.Count > 0) ? results[0] : 0;
            switch (result)
            {
                case 0:
                    cmdlet.WriteVerbose(
                        string.Format(CultureInfo.InvariantCulture, "Secret vault '{0}' was successfully unlocked.", vaultName));
                    break;

                case 1:
                    cmdlet.WriteError(
                        new ErrorRecord(
                            new PSInvalidOperationException(
                                message: string.Format(CultureInfo.InvariantCulture, "Cannot unlock extension vault '{0}': Extension module could not load.", 
                                    vaultName)),
                            "UnlockSecretVaultCommandModuleLoadFail",
                            ErrorCategory.InvalidOperation,
                            this));
                    break;

                case 2:
                    cmdlet.WriteWarning(
                        string.Format(CultureInfo.InvariantCulture, 
                            "Cannot unlock extension vault '{0}': The vault does not support the Unlock-SecretVault function.",
                            vaultName));
                    break;
            }

            return result == 0;
        }

        public bool InvokeSetSecretMetadata(
            string name,
            Hashtable metadata,
            string vaultName,
            PSCmdlet cmdlet)
        {
            var additionalParameters = GetAdditionalParams(cmdlet);
            var parameters = new Hashtable() {
                { "Name", name },
                { "Metadata", metadata },
                { "VaultName", vaultName },
                { "AdditionalParameters", additionalParameters }
            };

            // Result values:
            // 0 - Command ran (command will emit any error message)
            // 1 - Module not found
            // 2 - Command not found
            var results = PowerShellInvoker.InvokeScriptWithHost<int>(
                cmdlet: cmdlet,
                script: RunConditionalCommandScript,
                args: new object[] { ModuleName, ModulePath, ModuleExtensionName, SetSecretInfoCmd, parameters },
                out Exception terminatingError);
            
            if (terminatingError != null)
            {
                ThrowPasswordRequiredException(terminatingError);

                cmdlet.WriteError(
                    new ErrorRecord(
                        new PSInvalidOperationException(
                            message: string.Format(CultureInfo.InvariantCulture, "Cannot add secret metadata '{0}' to vault '{1}'", name, VaultName),
                            innerException: terminatingError),
                        "SetSecretMetadataInvalidOperation",
                        ErrorCategory.InvalidOperation,
                        this));

                return false;
            }

            int result = (results.Count > 0) ? results[0] : 0;
            switch (result)
            {
                case 0:
                    cmdlet.WriteVerbose(
                        string.Format(CultureInfo.InvariantCulture, "Secret metadata '{0}' was successfully added to vault '{1}'.", name, VaultName));
                    break;

                case 1:
                    cmdlet.WriteError(
                        new ErrorRecord(
                            new PSInvalidOperationException(
                                message: string.Format(CultureInfo.InvariantCulture, "Cannot add secret metadata '{0}' to vault '{1}': Extension module could not load.", 
                                    name, VaultName)),
                            "SetSecretMetaDataCommandModuleLoadFail",
                            ErrorCategory.InvalidOperation,
                            this));
                    break;

                case 2:
                    cmdlet.WriteError(
                        new ErrorRecord(
                            new PSNotSupportedException(
                                message: string.Format(CultureInfo.InvariantCulture, "Cannot add secret metadata '{0}' to vault '{1}: The vault does not support the Set-SecretInfo function.", 
                                    name, VaultName)),
                            "SetSecretMetadataCommandNotSupported",
                            ErrorCategory.NotImplemented,
                            this));
                    break;
            }

            return result == 0;
        }

        /// <summary>
        /// Looks up a single secret by name.
        /// </summary>
        /// <returns>Secret object</returns>
        public object InvokeGetSecret(
            string name,
            string vaultName,
            PSCmdlet cmdlet)
        {
            var additionalParameters = GetAdditionalParams(cmdlet);
            var parameters = new Hashtable() {
                { "Name", name },
                { "VaultName", vaultName },
                { "AdditionalParameters", additionalParameters }
            };

            var results = PowerShellInvoker.InvokeScriptWithHost<object>(
                cmdlet: cmdlet,
                script: RunCommandScript,
                args: new object[] { ModuleName, ModulePath, ModuleExtensionName, GetSecretCmd, parameters },
                out Exception terminatingError);
            
            if (terminatingError != null)
            {
                ThrowPasswordRequiredException(terminatingError);

                cmdlet.WriteError(
                    new ErrorRecord(
                        new PSInvalidOperationException(
                            message: string.Format(CultureInfo.InvariantCulture, "Unable to get secret {0} from vault {1}", name, VaultName),
                            innerException: terminatingError),
                        "GetSecretInvalidOperation",
                        ErrorCategory.InvalidOperation,
                        this));
            }
            else
            {
                cmdlet.WriteVerbose(
                    string.Format(CultureInfo.InvariantCulture, "Secret {0} was successfully retrieved from vault {1}.", name, VaultName));
            }

            if (results.Count == 0)
            {
                return null;
            }

            object returnValue;
            if (results[0] is byte)
            {
                // Re-wrap collection of bytes into a byte array.
                byte[] byteArray = new byte[results.Count];
                for (int i=0; i<results.Count; i++)
                {
                    byteArray[i] = (byte) results[i];
                }
                returnValue = byteArray;
            }
            else
            {
                returnValue = results[0];
            }

            // Special case for PowerShell wrapping weirdness.
            if (returnValue is List<object> listWrap && listWrap.Count > 0)
            {
                returnValue = listWrap[0];
            }

            // Return only allowed types.
            switch (returnValue)
            {
                case string strValue:
                    return strValue;

                case SecureString secureStrValue:
                    return secureStrValue;

                case byte[] byteArrayValue:
                    return byteArrayValue;

                case PSCredential psCredValue:
                    return psCredValue;

                case Hashtable hashTableValue:
                    return hashTableValue;
                
                default:
                    cmdlet.WriteError(
                    new ErrorRecord(
                        new PSInvalidOperationException(
                            message: string.Format(
                                CultureInfo.InvariantCulture,
                                "Secret object returned for '{0}' from vault '{1}' is of invalid type '{2}'",
                                name,
                                VaultName,
                                returnValue.GetType().ToString()),
                            innerException: terminatingError),
                        "GetSecretInvalidOperation",
                        ErrorCategory.InvalidOperation,
                        this));
                    return null;
            }
        }

        /// <summary>
        /// Remove a single secret.
        /// </summary>
        public void InvokeRemoveSecret(
            string name,
            string vaultName,
            PSCmdlet cmdlet)
        {
            var additionalParameters = GetAdditionalParams(cmdlet);
            var parameters = new Hashtable() {
                { "Name", name },
                { "VaultName", vaultName },
                { "AdditionalParameters", additionalParameters }
            };

            PowerShellInvoker.InvokeScriptWithHost(
                cmdlet: cmdlet,
                script: RunCommandScript,
                args: new object[] { ModuleName, ModulePath, ModuleExtensionName, RemoveSecretCmd, parameters },
                out Exception terminatingError);

            if (terminatingError != null)
            {
                ThrowPasswordRequiredException(terminatingError);

                cmdlet.WriteError(
                    new ErrorRecord(
                        new PSInvalidOperationException(
                            message: string.Format(CultureInfo.InvariantCulture, "Unable to remove secret {0} from vault {1}", name, VaultName),
                            innerException: terminatingError),
                        "RemoveSecretInvalidOperation",
                        ErrorCategory.InvalidOperation,
                        this));
            }
            else
            {
                cmdlet.WriteVerbose(
                    string.Format(CultureInfo.InvariantCulture, "Secret {0} was successfully removed from vault {1}.", name, VaultName));
            }
        }

        /// <summary>
        /// Returns secret meta data.
        /// </summary>
        public SecretInformation[] InvokeGetSecretInfo(
            string filter,
            string vaultName,
            PSCmdlet cmdlet)
        {
            var additionalParameters = GetAdditionalParams(cmdlet);
            var parameters = new Hashtable() {
                { "Filter", filter },
                { "VaultName", vaultName },
                { "AdditionalParameters", additionalParameters }
            };

            var results = PowerShellInvoker.InvokeScriptWithHost<SecretInformation>(
                cmdlet: cmdlet,
                script: RunCommandScript,
                args: new object[] { ModuleName, ModulePath, ModuleExtensionName, GetSecretInfoCmd, parameters },
                out Exception terminatingError);
            
            if (terminatingError != null)
            {
                ThrowPasswordRequiredException(terminatingError);

                cmdlet.WriteError(
                    new ErrorRecord(
                        new PSInvalidOperationException(
                            message: string.Format(CultureInfo.InvariantCulture, "Unable to get secret information from vault {0}", VaultName),
                            innerException: terminatingError),
                        "GetSecretInfoInvalidOperation",
                        ErrorCategory.InvalidOperation,
                        this));
            }
            else
            {
                cmdlet.WriteVerbose(
                    string.Format(CultureInfo.InvariantCulture, "Secret information was successfully retrieved from vault {0}.", VaultName));
            }

            var secretInfo = new SecretInformation[results.Count];
            results.CopyTo(secretInfo, 0);
            return secretInfo;
        }

        public bool InvokeTestVault(
            string vaultName,
            PSCmdlet cmdlet)
        {
            var additionalParameters = GetAdditionalParams(cmdlet);
            var parameters = new Hashtable() {
                { "VaultName", VaultName },
                { "AdditionalParameters", additionalParameters }
            };

            var results = PowerShellInvoker.InvokeScriptWithHost<bool>(
                cmdlet: cmdlet,
                script: RunCommandScript,
                args: new object[] { ModuleName, ModulePath, ModuleExtensionName, TestVaultCmd, parameters },
                out Exception terminatingError);

            if (terminatingError != null)
            {
                ThrowPasswordRequiredException(terminatingError);

                cmdlet.WriteError(
                    new ErrorRecord(
                        new PSInvalidOperationException(
                            message: string.Format(CultureInfo.InvariantCulture, "Unable to run Test-SecretVault on vault {0}", VaultName),
                            innerException: terminatingError),
                        "TestSecretVaultInvalidOperation",
                        ErrorCategory.InvalidOperation,
                        this));
            }

            return (results.Count > 0) ? results[0] : false;
        }

        /// <Summary>
        /// Optional Unregister-Vault extension command.  Will invoke if available.
        /// </Summary>
        public void InvokeUnregisterVault(
            PSCmdlet cmdlet)
        {
            var additionalParameters = GetAdditionalParams(cmdlet);
            var parameters = new Hashtable() {
                { "VaultName", VaultName },
                { "AdditionalParameters", additionalParameters }
            };

            PowerShellInvoker.InvokeScriptWithHost(
                cmdlet: cmdlet,
                script: RunIfCommandScript,
                args: new object[] { ModuleName, ModulePath, ModuleExtensionName, UnregisterSecretVaultCommand, parameters },
                out Exception terminatingError);
            
            if (terminatingError != null)
            {
                ThrowPasswordRequiredException(terminatingError);

                cmdlet.WriteError(
                    new ErrorRecord(
                        new PSInvalidOperationException(
                            message: string.Format(CultureInfo.InvariantCulture, "An error occurred while running Unregister-SecretVault on vault {0}, Error: {1}", 
                                VaultName, terminatingError.Message),
                            innerException: terminatingError),
                        "UnregisterSecretVaultInvalidOperation",
                        ErrorCategory.InvalidOperation,
                        this));
            }
        }

        /// <summary>
        /// Creates copy of this extension module object instance.
        /// </summary>
        public ExtensionVaultModule Clone()
        {
            return new ExtensionVaultModule(this);
        }
        
        #endregion

        #region Private methods

        private void ThrowPasswordRequiredException(Exception ex)
        {
            // Unwrap a PasswordRequiredException inner exception and throw directly.
            if (ex.InnerException is PasswordRequiredException passwordRequiredEx)
            {
                throw passwordRequiredEx;
            }
        }

        private Hashtable GetAdditionalParams(PSCmdlet cmdlet)
        {
            var additionalParams = new Hashtable();
            foreach (var item in VaultParameters)
            {
                additionalParams.Add(
                    key: item.Key,
                    value: item.Value);
            }

            bool verboseEnabled = cmdlet.MyInvocation.BoundParameters.TryGetValue("Verbose", out dynamic verbose)
                ? verbose.IsPresent : false;
            if (additionalParams.ContainsKey("Verbose"))
            {
                additionalParams.Remove("Verbose");
            }
            additionalParams.Add("Verbose", verboseEnabled);

            return additionalParams;
        }

        #endregion
    }

    #endregion

    #region RegisteredVaultCache

    internal static class RegisteredVaultCache
    {
        #region Members

        #region Strings

        private static readonly string RegistryFilePath;

        #endregion

        private static readonly FileSystemWatcher _registryWatcher;
        private static readonly Dictionary<string, ExtensionVaultModule> _vaultCache;
        private static Hashtable _vaultInfoCache;
        private static object _syncObject;
        private static string _defaultVaultName = string.Empty;
        private static bool _allowAutoRefresh;
        private static readonly bool _isLocationPathValid;
        private static readonly bool _isWindows;

        #endregion

        #region Properties

        /// <summary>
        /// Gets a dictionary of registered vault extensions, sorted by vault name.
        /// </summary>
        public static SortedDictionary<string, ExtensionVaultModule> VaultExtensions
        {
            get 
            {
                lock (_syncObject)
                {
                    var returnVaults = new SortedDictionary<string, ExtensionVaultModule>(StringComparer.OrdinalIgnoreCase);
                    foreach (var vaultName in _vaultCache.Keys)
                    {
                        returnVaults.Add(vaultName, _vaultCache[vaultName].Clone());
                    }
                    return returnVaults;
                }
            }
        }

        public static string DefaultVaultName
        {
            get => _defaultVaultName;
        }

        #endregion

        #region Constructor

        static RegisteredVaultCache()
        {
            _syncObject = new object();
            _vaultInfoCache = new Hashtable();
            _vaultCache = new Dictionary<string, ExtensionVaultModule>(StringComparer.OrdinalIgnoreCase);

            // Create file location paths based on current user context.
            string locationPath;
            string secretManagementLocalPath;
            _isWindows = System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows);
            if (_isWindows)
            {
                // Windows platform.
                locationPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                secretManagementLocalPath = Path.Combine(locationPath, "Microsoft", "PowerShell", "secretmanagement");
            }
            else
            {
                // Non-Windows platform.
                locationPath = Environment.GetEnvironmentVariable("HOME");
                secretManagementLocalPath = Path.Combine(locationPath, ".secretmanagement");
            }

            _isLocationPathValid = !string.IsNullOrEmpty(locationPath);
            if (!_isLocationPathValid)
            {
                // File location path can be invalid for some Windows built-in account scenarios.
                // Surface the error later when not initializing a type.
                return;
            }

            var registryDirectoryPath = Path.Combine(secretManagementLocalPath, "secretvaultregistry");
            RegistryFilePath = Path.Combine(registryDirectoryPath, "vaultinfo");

            // Create new registry directory if needed.
            if (!Directory.Exists(registryDirectoryPath))
            {
                // TODO: Need to specify directory/file permissions.
                Directory.CreateDirectory(registryDirectoryPath);
            }

            // Create file watcher.
            _registryWatcher = new FileSystemWatcher(registryDirectoryPath);
            _registryWatcher.NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName;
            _registryWatcher.Filter = "VaultInfo";
            _registryWatcher.EnableRaisingEvents = true;
            _registryWatcher.Changed += (sender, args) => { if (_allowAutoRefresh) { RefreshCache(); } };
            _registryWatcher.Created += (sender, args) => { if (_allowAutoRefresh) { RefreshCache(); } };
            _registryWatcher.Deleted += (sender, args) => { if (_allowAutoRefresh) { RefreshCache(); } };

            RefreshCache();
            _allowAutoRefresh = true;
        }

        #endregion

        #region Public methods

        /// <summary>
        /// Retrieve all vault items from cache.
        /// </summary>
        /// <returns>Hashtable of vault items.</returns>
        public static Hashtable GetAll()
        {
            lock (_syncObject)
            {
                var vaultItems = (Hashtable) _vaultInfoCache.Clone();
                return vaultItems;
            }
        }

        /// <summary>
        /// Add item to cache.
        /// </summary>
        /// <param name="vaultInfo">Hashtable of vault information.</param>
        /// <param name="defaultVault">When true, this vault is designated as the default vault.</param>
        /// <param name="overWriteExisting">When true, this will overwrite an existing vault with the same name.</param>
        /// <returns>True when item is successfully added.</returns>
        public static bool Add(
            string keyName,
            Hashtable vaultInfo,
            bool defaultVault,
            bool overWriteExisting)
        {
            var vaultItems = GetAll();
            if (vaultItems.ContainsKey(keyName))
            {
                if (!overWriteExisting)
                {
                    return false;
                }
                
                vaultItems.Remove(keyName);
            }

            vaultItems.Add(keyName, vaultInfo);
            WriteSecretVaultRegistry(
                vaultInfo: vaultItems,
                defaultVaultName: defaultVault ? keyName : _defaultVaultName);
            
            return true;
        }

        public static void SetDefaultVault(
            string vaultName)
        {
            if (string.IsNullOrEmpty(vaultName))
            {
                _defaultVaultName = string.Empty;
            }
            else if (VaultExtensions.TryGetValue(
                key: vaultName,
                value: out ExtensionVaultModule vault))
            {
                _defaultVaultName = vault.VaultName;
            }
            else
            {
                throw new ItemNotFoundException("Vault name was not found.");
            }

            WriteSecretVaultRegistry(
                vaultInfo: GetAll(),
                defaultVaultName: _defaultVaultName);
        }

        /// <summary>
        /// Remove item from cache.
        /// </summary>
        /// <param name="keyName">Name of item to remove.</param>
        /// <returns>Vault informmation that was removed.</returns>
        public static Hashtable Remove(string keyName)
        {
            var vaultItems = GetAll();
            if (!vaultItems.ContainsKey(keyName))
            {
                return null;
            }

            // Remove vault from registry
            Hashtable vaultInfo = (Hashtable) vaultItems[keyName];
            vaultItems.Remove(keyName);
            WriteSecretVaultRegistry(
                vaultInfo: vaultItems,
                defaultVaultName: _defaultVaultName.Equals(keyName, StringComparison.OrdinalIgnoreCase) ? string.Empty : _defaultVaultName);

            return vaultInfo;
        }

        #endregion

        #region Private methods

        //
        // Vault registry json example:
        //
        /*
        {
          "DefaultVaultName": "TestLocalBin",
          "Vaults": {
            "TestLocalBin": {
              "ModuleName": "TestLocalBin",
              "ModulePath": "E:\\temp\\Modules\\Microsoft.PowerShell.SecretManagement\\ExtModules\\TestLocalBin",
              "Description": "Simple local store binary extension vault module",
              "SetSecretSupportsMetadata": false
              "VaultParameters": {
                "Param1": "Hello",
                "Param2": 102
              },
            },
            "TestLocalScript": {
              "ModuleName": "TestLocalScript",
              "ModulePath": "E:\\temp\\Modules\\Microsoft.PowerShell.SecretManagement\\ExtModules\\TestLocalScript"
              "Description": "Simple local store script extension vault module",
              "SetSecretSupportsMetadata": true
              "VaultParameters": {
                "Param": "SessionId"
              },
            }
          }
        }
        */

        private static void CheckFilePath()
        {
            if (!_isLocationPathValid)
            {
                var msg = _isWindows ? 
                            "Unable to find a Local Application Data folder location for the current user, which is needed to store vault registry information.\nWindows built-in accounts do not provide the Location Application Data folder and are not currently supported." :
                            "Unable to find a 'HOME' path location for the current user, which is needed to store vault registry information.";
                throw new InvalidOperationException(msg);
            }
        }

        private static void RefreshCache()
        {
            if (!TryReadSecretVaultRegistry(
                vaultInfo: out Hashtable vaultItems,
                defaultVaultName: out string defaultVaultName))
            {
                return;
            }

            try
            {
                lock (_syncObject)
                {
                    _defaultVaultName = defaultVaultName;
                    _vaultInfoCache = vaultItems;

                    _vaultCache.Clear();
                    foreach (string vaultKey in _vaultInfoCache.Keys)
                    {
                        _vaultCache.Add(
                            key: vaultKey, 
                            value: new ExtensionVaultModule(
                                vaultName: vaultKey,
                                vaultInfo: (Hashtable) _vaultInfoCache[vaultKey],
                                isDefault: vaultKey.Equals(_defaultVaultName, StringComparison.OrdinalIgnoreCase)));
                    }
                }
            }
            catch (Exception)
            {
                // If an exception is thrown while parsing the registry file, assume the file is corrupted and delete it.
                DeleteSecretVaultRegistryFile();
            }
        }

        /// <summary>
        /// Reads the current user secret vault registry information from file.
        /// </summary>
        /// <param name="vaultInfo">Resulting Hashtable out parameter.</param>
        /// <param name="defaultVaultName">Specified default vault.</param>
        /// <returns>True if file is successfully read and converted from json.</returns>
        private static bool TryReadSecretVaultRegistry(
            out Hashtable vaultInfo,
            out string defaultVaultName)
        {
            defaultVaultName = string.Empty;
            vaultInfo =  new Hashtable();

            if (!File.Exists(RegistryFilePath))
            {
                return false;
            }

            var count = 0;
            do
            {
                try
                {
                    string jsonInfo = File.ReadAllText(RegistryFilePath);
                    var registryInfo = Utils.ConvertJsonToHashtable(jsonInfo);
                    var fileDefaultVaultName = (string) registryInfo["DefaultVaultName"];
                    var fileVaultInfo = (Hashtable) registryInfo["Vaults"];
                    if (fileDefaultVaultName == null || fileVaultInfo == null)
                    {
                        // Missing expected values.  Assume file is corrupt.
                        DeleteSecretVaultRegistryFile();
                        return false;
                    }

                    defaultVaultName = fileDefaultVaultName;
                    vaultInfo = fileVaultInfo;
                    return true;
                }
                catch (IOException)
                {
                    // Make up to four attempts.
                }
                catch
                {
                    // Unknown error.
                    break;
                }

                System.Threading.Thread.Sleep(250);

            } while (++count < 4);

            return false;
        }

        private static void DeleteSecretVaultRegistryFile()
        {
            try
            {
                File.Delete(RegistryFilePath);
            }
            catch (Exception)
            {
            }
        }

        /// <summary>
        /// Writes the Hashtable registered vault information data to file as json.
        /// </summary>
        /// <param name="vaultInfo">Hashtable containing registered vault information.</param>
        /// <param name="defaultVaultName">The default vault name.</param>
        /// </summary>
        private static void WriteSecretVaultRegistry(
            Hashtable vaultInfo,
            string defaultVaultName)
        {
            // SecretManagement vault registry relies on LocalApplicationData or HOME user context
            // file locations.  Some Windows accounts do not support this and we surface the error here.  
            CheckFilePath();

            var registryInfo = new Hashtable()
            {
                { "DefaultVaultName", defaultVaultName },
                { "Vaults", vaultInfo }
            };
            string jsonInfo = Utils.ConvertHashtableToJson(registryInfo);

            _allowAutoRefresh = false;
            try
            {
                var count = 0;
                do
                {
                    try
                    {
                        File.WriteAllText(RegistryFilePath, jsonInfo);
                        RefreshCache();
                        return;
                    }
                    catch (IOException)
                    {
                        // Make up to four attempts.
                    }
                    catch
                    {
                        // Unknown error.
                        break;
                    }

                    System.Threading.Thread.Sleep(250);

                } while (++count < 4);
            }
            finally
            {
                _allowAutoRefresh = true;
            }

            // TODO: Look into checking for missing registry file and create as needed.
        }

        #endregion
    }

    #endregion

    #region PowerShellInvoker

    internal static class PowerShellInvoker
    {
        #region Members

        private static System.Management.Automation.PowerShell _powershell = 
            System.Management.Automation.PowerShell.Create(RunspaceMode.NewRunspace);

        private static Runspace _runspace;

        #endregion

        #region Methods

        public static Collection<PSObject> InvokeScriptWithHost(
            PSCmdlet cmdlet,
            string script,
            object[] args,
            out Exception terminatingError)
        {
            return InvokeScriptWithHost<PSObject>(
                cmdlet,
                script,
                args,
                out terminatingError);
        }

        public static Collection<T> InvokeScriptWithHost<T>(
            PSCmdlet cmdlet,
            string script,
            object[] args,
            out Exception terminatingError)
        {
            Collection<T> returnCollection = new Collection<T>();
            terminatingError = null;

            if (_runspace == null || _runspace.RunspaceStateInfo.State != RunspaceState.Opened)
            {
                if (_runspace != null)
                {
                    _runspace.Dispose();
                }

                var iss = InitialSessionState.CreateDefault2();
                // We are running trusted script.
                iss.LanguageMode = PSLanguageMode.FullLanguage;
                // Import the current Microsoft.PowerShell.SecretManagement module.
                var modPathObjects = cmdlet.InvokeCommand.InvokeScript(
                    script: "(Get-Module -Name Microsoft.PowerShell.SecretManagement).Path");
                string modPath = (modPathObjects.Count > 0 &&
                                  modPathObjects[0].BaseObject is string modPathStr)
                                  ? modPathStr : string.Empty;
                if (!string.IsNullOrEmpty(modPath))
                {
                    iss.ImportPSModule(new string[] { modPath });
                }

                try
                {
                    _runspace = RunspaceFactory.CreateRunspace(cmdlet.Host, iss);
                    _runspace.Open();
                }
                catch (Exception ex)
                {
                    terminatingError = ex;
                    return returnCollection;
                }
            }

            using (var ps = System.Management.Automation.PowerShell.Create())
            {
                ps.Runspace = _runspace;

                var cmd = new Command(
                    command: script, 
                    isScript: true, 
                    useLocalScope: true);
                cmd.MergeMyResults(
                    myResult: PipelineResultTypes.Error,
                    toResult: PipelineResultTypes.Output);
                ps.Commands.AddCommand(cmd);
                foreach (var arg in args)
                {
                    ps.Commands.AddArgument(arg);
                }
                
                try
                {
                    // Invoke the script.
                    var results = ps.Invoke();

                    // Extract expected output types from results pipeline.
                    foreach (var psItem in results)
                    {
                        if (psItem == null || psItem.BaseObject == null) { continue; }

                        switch (psItem.BaseObject)
                        {
                            case T result:
                                returnCollection.Add(result);
                                break;

                            case T[] resultArray:
                                foreach (var item in resultArray)
                                {
                                    returnCollection.Add(item);
                                }
                                break;

                            case ErrorRecord error:
                                cmdlet.WriteError(error);
                                break;
                        }
                    }
                }
                catch (Exception ex)
                {
                    terminatingError = ex;
                }
            }

            return returnCollection;
        }

        public static Collection<T> InvokeScript<T>(
            string script,
            object[] args,
            out ErrorRecord error)
        {
            return InvokeScriptOnPowerShell<T>(
                script,
                args,
                _powershell,
                out error);
        }

        public static Collection<T> InvokeScriptOnPowerShell<T>(
            string script,
            object[] args,
            System.Management.Automation.PowerShell psToUse,
            out ErrorRecord error)
        {
            Collection<T> results;
            try
            {
                results = psToUse.AddScript(script).AddParameters(args).Invoke<T>();
                error = (psToUse.Streams.Error.Count > 0) ? psToUse.Streams.Error[0] : null;
            }
            catch (Exception ex)
            {
                error = new ErrorRecord(
                    exception: ex,
                    errorId: "PowerShellInvokerInvalidOperation",
                    errorCategory: ErrorCategory.InvalidOperation,
                    targetObject: null);
                results = new Collection<T>();
            }
            finally
            {
                psToUse.Commands.Clear();
            }

            return results;
        }

        #endregion
    }

    #endregion
}
