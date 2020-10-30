// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Security;

using Dbg = System.Diagnostics.Debug;

namespace Microsoft.PowerShell.SecretManagement
{
    #region Utils

    internal static class Utils
    {
        #region Members

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
                $object | Get-Member -MemberType NoteProperty | ForEach-Object {
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

            $customObject = ConvertFrom-Json -InputObject $json
            return ConvertToHash $customObject
        ";

        #endregion

        #region Constructor

        static Utils()
        {
            IsWindows = System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(
                System.Runtime.InteropServices.OSPlatform.Windows);

            if (IsWindows)
            {
                var locationPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                SecretManagementLocalPath = Path.Combine(locationPath, "Microsoft", "PowerShell", "secretmanagement");
            }
            else
            {
                var locationPath = Environment.GetEnvironmentVariable("HOME");
                SecretManagementLocalPath = Path.Combine(locationPath, ".secretmanagement");
            }
        }

        #endregion

        #region Properties

        public static string SecretManagementLocalPath { get; }

        public static bool IsWindows { get; }

        #endregion

        #region Methods

        public static Hashtable ConvertJsonToHashtable(string json)
        {
            var results = PowerShellInvoker.InvokeScript<Hashtable>(
                script: ConvertJsonToHashtableScript,
                args: new object[] { json },
                error: out ErrorRecord _);

            return (results.Count > 0) ? results[0] : null;
        }

        public static string ConvertHashtableToJson(Hashtable hashtable)
        {
            var results = PowerShellInvoker.InvokeScript<string>(
                script: @"param ([hashtable] $hashtable) ConvertTo-Json -InputObject $hashtable -Depth 10",
                args: new object[] { hashtable },
                error: out ErrorRecord _);

            return (results.Count > 0) ? results[0] : null;
        }

        public static SecureString ConvertToSecureString(string secret)
        {
            var results = PowerShellInvoker.InvokeScript<SecureString>(
                script: @"param([string] $value) ConvertTo-SecureString -String $value -AsPlainText -Force",
                args: new object[] { secret },
                error: out ErrorRecord _);
            
            return (results.Count > 0) ? results[0] : null;
        }

        public static string GetModuleExtensionName(string moduleName)
        {
            return string.Format(CultureInfo.InvariantCulture, 
                @"{0}.{1}", moduleName, ImplementingExtension);
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
        /// Gets or sets the name of the secret.
        /// </summary>
        public string Name
        {
            get; 
        }

        /// <summary>
        /// Gets or sets the object type of the secret.
        /// </summary>
        public SecretType Type
        {
            get;
        }

        /// <summary>
        /// Gets or sets the vault name where the secret resides.
        /// </summary>
        public string VaultName
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
                [string] $ModulePath,
                [string] $ImplementingModuleName,
                [string] $Command,
                [hashtable] $Params
            )

            $verboseEnabled = $Params.AdditionalParameters.ContainsKey('Verbose') -and ($Params.AdditionalParameters['Verbose'] -eq $true)
            $module = Get-Module -Name ([System.IO.Path]::GetFileNameWithoutExtension($ImplementingModuleName)) -ErrorAction SilentlyContinue
            if ($null -eq $module) {
                $module = Import-Module -Name $ModulePath -PassThru
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
                [string] $ModulePath,
                [string] $ImplementingModuleName,
                [string] $Command,
                [hashtable] $Params
            )
        
            $verboseEnabled = $Params.AdditionalParameters.ContainsKey('Verbose') -and ($Params.AdditionalParameters['Verbose'] -eq $true)
            $module = Get-Module -Name ([System.IO.Path]::GetFileNameWithoutExtension($ImplementingModuleName)) -ErrorAction SilentlyContinue
            if ($null -eq $module) {
                $module = Import-Module -Name $ModulePath -PassThru
            }
            if ($null -eq $module) {
                return
            }
            try
            {
                Write-Verbose ""Invoking command $Command on module $ImplementingModuleName"" -Verbose:$verboseEnabled
                & $module ""$ImplementingModuleName\$Command"" @Params
            }
            catch [System.Management.Automation.CommandNotFoundException]
            {
                Write-Verbose ""Module $ImplementingModuleName does not support command : $Command"" -Verbose:$verboseEnabled
            }
        ";

        #endregion

        internal const string GetSecretCmd = "Get-Secret";
        internal const string GetSecretInfoCmd = "Get-SecretInfo";
        internal const string SetSecretCmd = "Set-Secret";
        internal const string RemoveSecretCmd = "Remove-Secret";
        internal const string TestVaultCmd = "Test-SecretVault";
        internal const string UnregisterSecretVaultCommand = "Unregister-SecretVault";
        internal const string ModuleNameStr = "ModuleName";
        internal const string ModulePathStr = "ModulePath";
        internal const string VaultParametersStr = "VaultParameters";
        
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

        public bool IsDefault { get; }

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
            VaultParameters = module.VaultParameters;
            IsDefault = module.IsDefault;
        }

        #endregion

        #region Public methods

        /// <summary>
        /// Invoke SetSecret method on vault extension.
        /// </summary>
        /// <param name="name">Name of secret to add.</param>
        /// <param name="secret">Secret object to add.</param>
        /// <param name="vaultName">Name of registered vault.</param>
        /// <param name="cmdlet">Calling cmdlet.</param>
        public void InvokeSetSecret(
            string name,
            object secret,
            string vaultName,
            PSCmdlet cmdlet)
        {
            var additionalParameters = GetAdditionalParams(cmdlet);
            var parameters = new Hashtable() {
                { "Name", name },
                { "Secret", secret },
                { "VaultName", vaultName },
                { "AdditionalParameters", additionalParameters }
            };

            InvokeOnCmdlet(
                cmdlet: cmdlet,
                script: RunCommandScript,
                args: new object[] { ModulePath, ModuleExtensionName, SetSecretCmd, parameters },
                out Exception terminatingError);
            
            if (terminatingError != null)
            {
                ThrowPasswordRequiredException(terminatingError);

                cmdlet.WriteError(
                    new ErrorRecord(
                        new PSInvalidOperationException(
                            message: string.Format("Unable to add secret {0} to vault {1}", name, VaultName),
                            innerException: terminatingError),
                        "SetSecretInvalidOperation",
                        ErrorCategory.InvalidOperation,
                        this));
            }
            else
            {
                cmdlet.WriteVerbose(
                    string.Format("Secret {0} was successfully added to vault {1}.", name, VaultName));
            }
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

            var results = InvokeOnCmdlet<object>(
                cmdlet: cmdlet,
                script: RunCommandScript,
                args: new object[] { ModulePath, ModuleExtensionName, GetSecretCmd, parameters },
                out Exception terminatingError);
            
            if (terminatingError != null)
            {
                ThrowPasswordRequiredException(terminatingError);

                cmdlet.WriteError(
                    new ErrorRecord(
                        new PSInvalidOperationException(
                            message: string.Format("Unable to get secret {0} from vault {1}", name, VaultName),
                            innerException: terminatingError),
                        "GetSecretInvalidOperation",
                        ErrorCategory.InvalidOperation,
                        this));
            }
            else
            {
                cmdlet.WriteVerbose(
                    string.Format("Secret {0} was successfully retrieved from vault {1}.", name, VaultName));
            }

            if (results.Count > 0)
            {
                if (results[0] is byte)
                {
                    // Re-wrap collection of bytes into a byte array.
                    byte[] byteArray = new byte[results.Count];
                    for (int i=0; i<results.Count; i++)
                    {
                        byteArray[i] = (byte) results[i];
                    }
                    return byteArray;
                }

                return results[0];
            }
            
            return null;
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

            InvokeOnCmdlet(
                cmdlet: cmdlet,
                script: RunCommandScript,
                args: new object[] { ModulePath, ModuleExtensionName, RemoveSecretCmd, parameters },
                out Exception terminatingError);

            if (terminatingError != null)
            {
                ThrowPasswordRequiredException(terminatingError);

                cmdlet.WriteError(
                    new ErrorRecord(
                        new PSInvalidOperationException(
                            message: string.Format("Unable to remove secret {0} from vault {1}", name, VaultName),
                            innerException: terminatingError),
                        "RemoveSecretInvalidOperation",
                        ErrorCategory.InvalidOperation,
                        this));
            }
            else
            {
                cmdlet.WriteVerbose(
                    string.Format("Secret {0} was successfully removed from vault {1}.", name, VaultName));
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

            var results = InvokeOnCmdlet<SecretInformation>(
                cmdlet: cmdlet,
                script: RunCommandScript,
                args: new object[] { ModulePath, ModuleExtensionName, GetSecretInfoCmd, parameters },
                out Exception terminatingError);
            
            if (terminatingError != null)
            {
                ThrowPasswordRequiredException(terminatingError);

                cmdlet.WriteError(
                    new ErrorRecord(
                        new PSInvalidOperationException(
                            message: string.Format("Unable to get secret information from vault {0}", VaultName),
                            innerException: terminatingError),
                        "GetSecretInfoInvalidOperation",
                        ErrorCategory.InvalidOperation,
                        this));
            }
            else
            {
                cmdlet.WriteVerbose(
                    string.Format("Secret information was successfully retrieved from vault {0}.", VaultName));
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

            var results = InvokeOnCmdlet<bool>(
                cmdlet: cmdlet,
                script: RunCommandScript,
                args: new object[] { ModulePath, ModuleExtensionName, TestVaultCmd, parameters },
                out Exception terminatingError);

            if (terminatingError != null)
            {
                ThrowPasswordRequiredException(terminatingError);

                cmdlet.WriteError(
                    new ErrorRecord(
                        new PSInvalidOperationException(
                            message: string.Format("Unable to run Test-SecretVault on vault {0}", VaultName),
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

            InvokeOnCmdlet(
                cmdlet: cmdlet,
                script: RunIfCommandScript,
                args: new object[] { ModulePath, ModuleExtensionName, UnregisterSecretVaultCommand, parameters },
                out Exception terminatingError);
            
            if (terminatingError != null)
            {
                ThrowPasswordRequiredException(terminatingError);

                cmdlet.WriteError(
                    new ErrorRecord(
                        new PSInvalidOperationException(
                            message: string.Format("An error occurred while running Unregister-SecretVault on vault {0}, Error: {1}", 
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
            bool verboseEnabled = cmdlet.MyInvocation.BoundParameters.TryGetValue("Verbose", out dynamic verbose)
                ? verbose.IsPresent : false;

            var additionalParams = new Hashtable();
            foreach (var item in VaultParameters)
            {
                additionalParams.Add(
                    key: item.Key,
                    value: item.Value);
            }
            additionalParams.Add("Verbose", verboseEnabled);

            return additionalParams;
        }

        private static Collection<PSObject> InvokeOnCmdlet(
            PSCmdlet cmdlet,
            string script,
            object[] args,
            out Exception terminatingError)
        {
            try
            {
                terminatingError = null;
                return cmdlet.InvokeCommand.InvokeScript(
                    script: script,
                    useNewScope: true,
                    writeToPipeline: PipelineResultTypes.Error,
                    input: null,
                    args: args);
            }
            catch (Exception ex)
            {
                terminatingError = ex;
                return new Collection<PSObject>();
            }
        }

        private static Collection<T> InvokeOnCmdlet<T>(
            PSCmdlet cmdlet,
            string script,
            object[] args,
            out Exception terminatingError)
        {
            var results = InvokeOnCmdlet(
                cmdlet: cmdlet,
                script: script,
                args: args,
                out terminatingError);

            var returnCollection = new Collection<T>();
            if (terminatingError != null || results.Count == 0)
            {
                return returnCollection;
            }

            foreach (var psItem in results)
            {
                if (psItem != null && psItem.BaseObject is T result)
                {
                    returnCollection.Add(result);
                }
            }

            return returnCollection;
        }

        #endregion
    }

    #endregion

    #region RegisteredVaultCache

    internal static class RegisteredVaultCache
    {
        #region Members

        #region Strings

        private static readonly string RegistryDirectoryPath = Path.Combine(Utils.SecretManagementLocalPath, "secretvaultregistry");
        private static readonly string RegistryFilePath = Path.Combine(RegistryDirectoryPath, "vaultinfo");

        #endregion

        private static readonly FileSystemWatcher _registryWatcher;
        private static readonly Dictionary<string, ExtensionVaultModule> _vaultCache;
        private static Hashtable _vaultInfoCache;
        private static object _syncObject;
        private static string _defaultVaultName = string.Empty;
        private static bool _allowAutoRefresh;

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
            // Verify path or create.
            if (!Directory.Exists(RegistryDirectoryPath))
            {
                // TODO: Need to specify directory/file permissions.
                Directory.CreateDirectory(RegistryDirectoryPath);
            }

            _syncObject = new object();
            _vaultInfoCache = new Hashtable();
            _vaultCache = new Dictionary<string, ExtensionVaultModule>(StringComparer.OrdinalIgnoreCase);

            // Create file watcher.
            _registryWatcher = new FileSystemWatcher(RegistryDirectoryPath);
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
              "ImplementingType": {
                "AssemblyName": "TestLocalBin",
                "TypeName": "TestLocalBin.TestLocalBinExtension"
              },
              "ModulePath": "E:\\temp\\Modules\\Microsoft.PowerShell.SecretManagement\\ExtModules\\TestLocalBin",
              "ImplementingFunctions": false,
              "VaultParameters": {
                "Param1": "Hello",
                "Param2": 102
              },
            },
            "TestLocalScript": {
              "ModuleName": "TestLocalScript",
              "ImplementingType": {
                "AssemblyName": "",
                "TypeName": ""
              },
              "ImplementingFunctions": true,
              "VaultParameters": {
                "Param": "SessionId"
              },
              "ModulePath": "E:\\temp\\Modules\\Microsoft.PowerShell.SecretManagement\\ExtModules\\TestLocalScript"
            }
          }
        }
        */

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

            Dbg.Assert(false, "Unable to write vault registry file!");
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

        #endregion

        #region Methods

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
