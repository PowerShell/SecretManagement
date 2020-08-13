// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Management.Automation;
using System.Security;

using Dbg = System.Diagnostics.Debug;

namespace Microsoft.PowerShell.SecretManagement
{
    #region SecretVaultInfo

    /// <summary>
    /// Class that contains secret vault information.
    /// </summary>
    public sealed class SecretVaultInfo
    {
        #region Parameters

        /// <summary>
        /// Gets name of extension vault.
        /// </summary>
        public string VaultName { get; }

        /// <summary>
        /// Gets name of extension vault module.
        /// </summary>
        public string ModuleName { get; }

        /// <summary>
        /// Gets extension vault module path.
        /// </summary>
        public string ModulePath { get; }

        /// <summary>
        /// Additional parameters used by vault module.
        /// </summary>
        public IReadOnlyDictionary<string, object> VaultParameters { get; }

        /// <summary>
        /// True when vault is designated as the default vault.
        /// </summary>
        public bool IsDefault { get; }

        #endregion

        #region Constructor

        internal SecretVaultInfo(
            string name,
            ExtensionVaultModule vaultInfo)
        {
            VaultName = name;
            ModuleName = vaultInfo.ModuleName;
            ModulePath = vaultInfo.ModulePath;
            VaultParameters = vaultInfo.VaultParameters;
            IsDefault = vaultInfo.IsDefault;
        }

        #endregion
    }

    #endregion

    #region Register-SecretVault

    /// <summary>
    /// Cmdlet to register a remote secret vaults provider module
    /// </summary>
    [Cmdlet(VerbsLifecycle.Register, "SecretVault", SupportsShouldProcess = true)]
    public sealed class RegisterSecretVaultCommand : PSCmdlet
    {
        #region Parameters

        /// <summary>
        /// Gets or sets a friendly name for the registered secret vault.
        /// The name must be unique.
        /// </summary>
        [Parameter(Position=0, Mandatory=true)]
        [ValidateNotNullOrEmpty]
        public string Name { get; set; }

        /// <summary>
        /// Gets or sets the module name or file path of the vault extension module to register.
        /// </summary>
        [Parameter(Position=1, Mandatory=true)]
        [ValidateNotNullOrEmpty]
        public string ModuleName { get; set; }

        /// <summary>
        /// Gets or sets an optional Hashtable of parameters by name/value pairs.
        /// The hashtable is stored securely in the local store, and is made available to the 
        /// extension implementing module script functions.
        /// </summary>
        [Parameter]
        public Hashtable VaultParameters { get; set; } = new Hashtable();

        /// <summary>
        /// Gets or sets a flag that designates this vault as the Default vault.
        /// </summary>
        [Parameter]
        public SwitchParameter DefaultVault { get; set; }

        #endregion

        #region Overrides

        protected override void EndProcessing()
        {
            var vaultInfo = new Hashtable();

            // Validate mandatory parameters.
            var vaultItems = RegisteredVaultCache.GetAll();
            if (vaultItems.ContainsKey(Name))
            {
                ThrowTerminatingError(
                    new ErrorRecord(
                        new InvalidOperationException("Provided Name for vault is already being used."),
                        "RegisterSecretVaultInvalidVaultName",
                        ErrorCategory.InvalidArgument,
                        this));
            }

            if (!ShouldProcess(Name, VerbsLifecycle.Register))
            {
                return;
            }

            // Resolve the module name path in calling context, if it is a path and not a name.
            var results = InvokeCommand.InvokeScript(
                script: "param([string] $path) (Resolve-Path -Path $path -EA Silent).Path",
                args: new object[] { ModuleName });
            string resolvedPath = (results.Count == 1 && results[0] != null) ? (string) results[0].BaseObject : null;
            string moduleNameOrPath = resolvedPath ?? ModuleName;

            results = InvokeCommand.InvokeScript(
                script: "(Get-Module -Name Microsoft.PowerShell.SecretManagement).ModuleBase");
            string secretMgtModulePath = (results.Count == 1 && results[0] != null) ? (string) results[0].BaseObject : string.Empty;
            secretMgtModulePath = System.IO.Path.Combine(secretMgtModulePath, "Microsoft.PowerShell.SecretManagement.psd1");

            var moduleInfo = GetModuleInfo(
                modulePath: moduleNameOrPath,
                secretMgtModulePath: secretMgtModulePath,
                error: out ErrorRecord moduleLoadError);
            if (moduleInfo == null)
            {
                var msg = string.Format(CultureInfo.InvariantCulture, 
                    "Could not load and retrieve module information for module: {0} with error : {1}.",
                    ModuleName, moduleLoadError?.ToString() ?? string.Empty);

                ThrowTerminatingError(
                    new ErrorRecord(
                        new PSInvalidOperationException(msg),
                        "RegisterSecretVaultCantGetModuleInfo",
                        ErrorCategory.InvalidOperation,
                        this));
            }

            var modulePath = moduleInfo.Path;
            var dirPath = System.IO.File.Exists(modulePath) ? System.IO.Path.GetDirectoryName(modulePath) : modulePath;

            if (!CheckForImplementingModule(
                dirPath: dirPath,
                moduleName: moduleInfo.Name,
                secretMgtModulePath: secretMgtModulePath,
                error: out Exception error))
            {
                var invalidException = new PSInvalidOperationException(
                    message: "Could not find a SecretManagement extension implementing script module.",
                    innerException: error);

                ThrowTerminatingError(
                    new ErrorRecord(
                        invalidException,
                        "RegisterSecretVaultCantFindImplementingScriptModule",
                        ErrorCategory.ObjectNotFound,
                        this));
            }

            // Store module information.
            vaultInfo.Add(
                key: ExtensionVaultModule.ModulePathStr,
                value: dirPath);
            vaultInfo.Add(
                key: ExtensionVaultModule.ModuleNameStr,
                value: moduleInfo.Name);

            // Store optional vault parameters.
            vaultInfo.Add(
                key: ExtensionVaultModule.VaultParametersStr,
                value: VaultParameters);

            // Register new secret vault information.
            RegisteredVaultCache.Add(
                keyName: Name,
                vaultInfo: vaultInfo,
                defaultVault: DefaultVault);
        }

        #endregion

        #region Private methods

        private static bool CheckForImplementingModule(
            string dirPath,
            string moduleName,
            string secretMgtModulePath,
            out Exception error)
        {
            // An implementing module will be in a subfolder with module name 'ModuleName.Extension',
            // and will export the five required functions: Set-Secret, Get-Secret, Remove-Secret, Get-SecretInfo, Test-SecretVault.
            var implementingModuleName = Utils.GetModuleExtensionName(moduleName);
            var implementingModulePath = System.IO.Path.Combine(dirPath, implementingModuleName);
            var moduleInfo = GetModuleInfo(
                modulePath: implementingModulePath,
                secretMgtModulePath: secretMgtModulePath,
                error: out ErrorRecord moduleLoadError);
            if (moduleInfo == null)
            {
                error = new ItemNotFoundException(
                    string.Format(CultureInfo.InvariantCulture, 
                    @"Implementing script module not found at : {0} with error : {1}.", 
                    implementingModulePath, moduleLoadError?.ToString() ?? string.Empty));
                return false;
            }

            // Get-Secret function
            if (!moduleInfo.ExportedCommands.ContainsKey("Get-Secret"))
            {
                error = new ItemNotFoundException("Get-Secret function not found.");
                return false;
            }
            var funcInfo = moduleInfo.ExportedCommands["Get-Secret"];
            if (!funcInfo.Parameters.ContainsKey("Name"))
            {
                error = new ItemNotFoundException("Get-Secret Name parameter not found.");
                return false;
            }
            if (!funcInfo.Parameters.ContainsKey("VaultName"))
            {
                error = new ItemNotFoundException("Get-Secret VaultName parameter not found.");
                return false;
            }
            if (!funcInfo.Parameters.ContainsKey("AdditionalParameters"))
            {
                error = new ItemNotFoundException("Get-Secret AdditionalParameters parameter not found.");
                return false;
            }

            // Set-Secret function
            if (!moduleInfo.ExportedCommands.ContainsKey("Set-Secret"))
            {
                error = new ItemNotFoundException("Set-Secret function not found.");
                return false;
            }
            funcInfo = moduleInfo.ExportedCommands["Set-Secret"];
            if (!funcInfo.Parameters.ContainsKey("Name"))
            {
                error = new ItemNotFoundException("Set-Secret Name parameter not found.");
                return false;
            }
            if (!funcInfo.Parameters.ContainsKey("Secret"))
            {
                error = new ItemNotFoundException("Set-Secret Secret parameter not found.");
                return false;
            }
            if (!funcInfo.Parameters.ContainsKey("VaultName"))
            {
                error = new ItemNotFoundException("Set-Secret VaultName parameter not found.");
                return false;
            }
            if (!funcInfo.Parameters.ContainsKey("AdditionalParameters"))
            {
                error = new ItemNotFoundException("Set-Secret AdditionalParameters parameter not found.");
                return false;
            }

            // Remove-Secret function
            if (!moduleInfo.ExportedCommands.ContainsKey("Remove-Secret"))
            {
                error = new ItemNotFoundException("Remove-Secret function not found.");
                return false;
            }
            funcInfo = moduleInfo.ExportedCommands["Remove-Secret"];
            if (!funcInfo.Parameters.ContainsKey("Name"))
            {
                error = new ItemNotFoundException("Remove-Secret Name parameter not found.");
                return false;
            }
            if (!funcInfo.Parameters.ContainsKey("VaultName"))
            {
                error = new ItemNotFoundException("Remove-Secret VaultName parameter not found.");
                return false;
            }
            if (!funcInfo.Parameters.ContainsKey("AdditionalParameters"))
            {
                error = new ItemNotFoundException("Remove-Secret AdditionalParameters parameter not found.");
                return false;
            }

            // Get-SecretInfo function
            if (!moduleInfo.ExportedCommands.ContainsKey("Get-SecretInfo"))
            {
                error = new ItemNotFoundException("Get-SecretInfo function not found.");
                return false;
            }
            funcInfo = moduleInfo.ExportedCommands["Get-SecretInfo"];
            if (!funcInfo.Parameters.ContainsKey("Filter"))
            {
                error = new ItemNotFoundException("Get-SecretInfo Filter parameter not found.");
                return false;
            }
            if (!funcInfo.Parameters.ContainsKey("VaultName"))
            {
                error = new ItemNotFoundException("Get-SecretInfo VaultName parameter not found.");
                return false;
            }
            if (!funcInfo.Parameters.ContainsKey("AdditionalParameters"))
            {
                error = new ItemNotFoundException("Get-SecretInfo AdditionalParameters parameter not found.");
                return false;
            }

            // Test-SecretVault function
            if (!moduleInfo.ExportedCommands.ContainsKey("Test-SecretVault"))
            {
                error = new ItemNotFoundException("Test-SecretVault function not found.");
                return false;
            }
            funcInfo = moduleInfo.ExportedCommands["Test-SecretVault"];
            if (!funcInfo.Parameters.ContainsKey("VaultName"))
            {
                error = new ItemNotFoundException("Test-SecretVault VaultName parameter not found.");
                return false;
            }
            if (!funcInfo.Parameters.ContainsKey("AdditionalParameters"))
            {
                error = new ItemNotFoundException("Test-SecretVault AdditionalParameters parameter not found.");
                return false;
            }

            error = null;
            return true;
        }

        private static PSModuleInfo GetModuleInfo(
            string modulePath,
            string secretMgtModulePath,
            out ErrorRecord error)
        {
            // Get module information by loading it.
            var results = PowerShellInvoker.InvokeScript<PSModuleInfo>(
                script: @"
                    param ([string] $ModulePath, [string] $SecretMgtModulePath)

                    # ModulePath module may have a dependency on SecretManagement module,
                    # so make sure it is loaded.
                    $null = Import-Module -Name $SecretMgtModulePath -ErrorAction SilentlyContinue

                    Import-Module -Name $ModulePath -Force -PassThru
                ",
                args: new object[] { modulePath, secretMgtModulePath },
                out error);

            return (results.Count == 1) ? results[0] : null;
        }

        #endregion
    }

    #endregion

    #region Unregister-SecretVault

    /// <summary>
    /// Cmdlet to unregister a secret vault.
    /// </summary>
    [Cmdlet(VerbsLifecycle.Unregister, "SecretVault", SupportsShouldProcess = true)]
    public sealed class UnregisterSecretVaultCommand : PSCmdlet
    {
        #region Parameters

        private const string NameParameterSet = "NameParameterSet";
        private const string SecretVaultParameterSet = "SecretVaultParameterSet";

        /// <summary>
        /// Gets or sets a name of the secret vault to unregister.
        /// </summary>
        [Parameter(ParameterSetName = NameParameterSet,
                   Position = 0, 
                   Mandatory = true)]
        [ValidateNotNullOrEmpty]
        public string Name { get; set; }

        [Parameter(ParameterSetName = SecretVaultParameterSet,
                   Position = 0,
                   Mandatory = true,
                   ValueFromPipeline = true,
                   ValueFromPipelineByPropertyName = true)]
        [ValidateNotNull]
        public SecretVaultInfo SecretVault { get; set; }

        #endregion

        #region Overrides

        /// <summary>
        /// Process input
        /// </summary>
        protected override void ProcessRecord()
        {
            if (!ShouldProcess(Name, VerbsLifecycle.Unregister))
            {
                return;
            }

            string vaultName;
            switch (ParameterSetName)
            {
                case NameParameterSet:
                    vaultName = Name;
                    break;
                
                case SecretVaultParameterSet:
                    vaultName = SecretVault.VaultName;
                    break;

                default:
                    Dbg.Assert(false, "Invalid parameter set");
                    vaultName = string.Empty;
                    break;
            }

            var removedVaultInfo = RegisteredVaultCache.Remove(vaultName);
            if (removedVaultInfo == null)
            {
                var msg = string.Format(CultureInfo.InvariantCulture,
                    "Unable to find secret vault {0} to unregister it.", vaultName);
                WriteError(
                    new ErrorRecord(
                        new ItemNotFoundException(msg),
                        "UnregisterSecretVaultObjectNotFound",
                        ErrorCategory.ObjectNotFound,
                        this));

                return;
            }
        }

        #endregion
    }

    #endregion

    #region Set-DefaultVault

    /// <summary>
    /// Cmdlet sets the provided registered vault name as the default vault.
    /// </summary>
    [Cmdlet(VerbsCommon.Set, "DefaultVault")]
    public sealed class SetDefaultVaultCommand : PSCmdlet
    {
        #region Parameters

        [Parameter (Position=0)]
        public string Name { get; set; }

        #endregion

        #region Overrides

        protected override void EndProcessing()
        {
            try
            {
                RegisteredVaultCache.SetDefaultVault(Name);
            }
            catch (Exception ex)
            {
                ThrowTerminatingError(
                    new ErrorRecord(
                        exception: ex,
                        errorId: "VaultNotFound",
                        errorCategory: ErrorCategory.ObjectNotFound,
                        this));
            }
        }

        #endregion
    }

    #endregion

    #region SecretCmdlet

    public abstract class SecretCmdlet : PSCmdlet
    {
        /// <summary>
        /// Look up and return specified extension module by name.
        /// </summary>
        /// <param name="name">Name of extension vault to return.</param>
        /// <returns>Extension vault.</returns>
        internal ExtensionVaultModule GetExtensionVault(string name)
        {
            // Look up extension module.
            if (!RegisteredVaultCache.VaultExtensions.TryGetValue(
                    key: name,
                    value: out ExtensionVaultModule extensionModule))
                {
                    var msg = string.Format(CultureInfo.InvariantCulture, "Vault not found in registry: {0}", name);
                    ThrowTerminatingError(
                        new ErrorRecord(
                            new PSInvalidOperationException(msg),
                            "GetSecretVaultNotFound",
                            ErrorCategory.ObjectNotFound,
                            this));
                }

            return extensionModule;
        }
    }

    #endregion

    #region Get-SecretVault

    /// <summary>
    /// Cmdlet to return registered secret vaults as SecretVaultInfo objects.
    /// If no name is provided then all registered secret vaults will be returned.
    /// </summary>
    [Cmdlet(VerbsCommon.Get, "SecretVault")]
    [OutputType(typeof(SecretVaultInfo))]
    public sealed class GetSecretVaultCommand : SecretCmdlet
    {
        #region Parameters

        /// <summary>
        /// Gets or sets an optional name of the secret vault to return.
        /// <summary>
        [Parameter (Position=0)]
        public string Name { get; set; }

        #endregion

        #region Overrides

        protected override void EndProcessing()
        {
            var namePattern = new WildcardPattern(
                (!string.IsNullOrEmpty(Name)) ? Name : "*", 
                WildcardOptions.IgnoreCase);

            // List extension vaults in sorted order.
            var vaultExtensions = RegisteredVaultCache.VaultExtensions;
            foreach (var vaultName in vaultExtensions.Keys)
            {
                if (namePattern.IsMatch(vaultName))
                {
                    if (vaultExtensions.TryGetValue(vaultName, out ExtensionVaultModule extensionModule))
                    {
                        WriteObject(
                            new SecretVaultInfo(
                                vaultName,
                                extensionModule));
                    }
                }
            }
        }

        #endregion
    }

    #endregion

    #region Get-SecretInfo

    /// <summary>
    /// Enumerates secrets by name, wild cards are allowed.
    /// If no name is provided then all secrets are returned.
    /// If no vault is specified then all vaults are searched.
    /// </summary>
    [Cmdlet(VerbsCommon.Get, "SecretInfo")]
    [OutputType(typeof(SecretInformation))]
    public sealed class GetSecretInfoCommand : SecretCmdlet
    {
        #region Parameters

        /// <summary>
        /// Gets or sets a name used to match and return secret information.
        /// </summary>
        [Parameter(Position=0)]
        public string Name { get; set; }

        /// <summary>
        /// Gets or sets an optional name of the vault to retrieve the secret from.
        /// </summary>
        [Parameter(Position=1)]
        public string Vault { get; set; }

        #endregion

        #region Overrides

        protected override void EndProcessing()
        {
            if (string.IsNullOrEmpty(Name))
            {
                Name = "*";
            }

            // Search for specified single vault.
            if (!string.IsNullOrEmpty(Vault))
            {
                var extensionModule = GetExtensionVault(Vault);
                WriteExtensionResults(extensionModule);
                return;
            }

            // Search the default vault first.
            if (!string.IsNullOrEmpty(RegisteredVaultCache.DefaultVaultName))
            {
                var extensionModule = GetExtensionVault(RegisteredVaultCache.DefaultVaultName);
                WriteExtensionResults(extensionModule);
            }

            // Then search through all other extension vaults.
            foreach (var extensionModule in RegisteredVaultCache.VaultExtensions.Values)
            {
                if (extensionModule.VaultName.Equals(RegisteredVaultCache.DefaultVaultName, 
                    StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                WriteExtensionResults(extensionModule);
            }
        }

        #endregion

        #region Private methods

        private void WriteExtensionResults(ExtensionVaultModule extensionModule)
        {
            try
            {
                WriteResults(
                    extensionModule.InvokeGetSecretInfo(
                        filter: Name,
                        vaultName: extensionModule.VaultName,
                        cmdlet: this));
            }
            catch (Exception ex)
            {
                WriteError(
                    new ErrorRecord(
                        ex,
                        "GetSecretInfoException",
                        ErrorCategory.InvalidOperation,
                        this));
            }
        }

        private void WriteResults(SecretInformation[] results)
        {
            if (results == null) { return; }

            // Ensure each vaults results are sorted by secret name.
            var sortedList = new SortedDictionary<string, SecretInformation>(StringComparer.OrdinalIgnoreCase);
            foreach (var item in results)
            {
                sortedList.Add(
                    key: item.Name,
                    value: item);
            }

            foreach (var item in sortedList.Values)
            {
                WriteObject(item);
            }
        }

        #endregion
    }

    #endregion

    #region Get-Secret

    /// <summary>
    /// Retrieves a secret by name, wild cards are not allowed.
    /// If no vault is specified then all vaults are searched.
    /// The first secret matching the Name parameter is returned.
    /// </summary>
    [Cmdlet(VerbsCommon.Get, "Secret")]
    [OutputType(typeof(object))]
    public sealed class GetSecretCommand : SecretCmdlet
    {
        #region Parameters

        /// <summary>
        /// Gets or sets a name of secret to retrieve.
        /// <summary>
        [Parameter(Position=0, 
                   Mandatory=true,
                   ValueFromPipeline=true,
                   ValueFromPipelineByPropertyName=true)]
        public string Name { get; set; }

        /// <summary>
        /// Gets or sets an optional name of the vault to retrieve the secret from.
        /// </summary>
        [Parameter(Position=1)]
        public string Vault { get; set; }

        /// <summary>
        /// Gets or sets a switch that forces a string secret type to be returned as plain text.
        /// Otherwise the string is returned as a SecureString type.
        /// </summary>
        [Parameter]
        public SwitchParameter AsPlainText { get; set; }

        #endregion

        #region Enums

        enum InvokeResult
        {
            Success = 0,
            Failed,
            FailedWithTerminatingError
        };

        #endregion

        #region Overrides

        protected override void ProcessRecord()
        {
            // Wild card characters are not supported in this cmdlet.
            if (WildcardPattern.ContainsWildcardCharacters(Name))
            {
                WriteError(
                    new ErrorRecord(
                        new ArgumentException("Name parameter cannot contain wildcard characters."),
                        "GetSecretNoWildcardCharsAllowed",
                        ErrorCategory.InvalidArgument,
                        this));
            }

            // Search single vault.
            if (!string.IsNullOrEmpty(Vault))
            {
                var extensionModule = GetExtensionVault(Vault);
                if (TryInvokeAndWrite(extensionModule) == InvokeResult.Failed)
                {
                    WriteNotFoundError();
                }

                return;
            }

            // First search the default vault.
            if (!string.IsNullOrEmpty(RegisteredVaultCache.DefaultVaultName))
            {
                var extensionModule = GetExtensionVault(RegisteredVaultCache.DefaultVaultName);
                if (TryInvokeAndWrite(extensionModule) == InvokeResult.Success)
                {
                    return;
                }
            }

            // Then search through all other extension vaults.
            foreach (var extensionModule in RegisteredVaultCache.VaultExtensions.Values)
            {
                if (extensionModule.VaultName.Equals(RegisteredVaultCache.DefaultVaultName, 
                    StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (TryInvokeAndWrite(extensionModule) == InvokeResult.Success)
                {
                    return;
                }
            }

            WriteNotFoundError();
        }

        #endregion

        #region Private methods

        private InvokeResult TryInvokeAndWrite(ExtensionVaultModule extensionModule)
        {
            try
            {
                var result = extensionModule.InvokeGetSecret(
                    name: Name,
                    vaultName: extensionModule.VaultName,
                    cmdlet: this);
                    
                if (result != null)
                {
                    WriteSecret(result);
                    return InvokeResult.Success;
                }
            }
            catch (Exception ex)
            {
                WriteError(
                    new ErrorRecord(
                        ex,
                        "GetSecretException",
                        ErrorCategory.InvalidOperation,
                        this));
                return InvokeResult.FailedWithTerminatingError;
            }

            return InvokeResult.Failed;
        }

        private void WriteSecret(object secret)
        {
            if (secret is PSObject secretPSObject)
            {
                secret = secretPSObject.BaseObject;
            }

            if (secret is Hashtable secretHashtable)
            {
                WriteObject(
                    ConvertHashtableElements(secretHashtable));
                return;
            }

            WriteObject(
                ConvertSecureString(secret));
        }

        private Hashtable ConvertHashtableElements(Hashtable hashtable)
        {
            Hashtable returnHashtable = new Hashtable(hashtable.Count);
            foreach (var key in hashtable.Keys)
            {
                returnHashtable.Add(key, ConvertSecureString(hashtable[key]));
            }

            return returnHashtable;
        }

        // All string secrets are converted to SecureString objects, unless AsPlainText
        // is selected, in which case both string and SecureString secrets are returned as strings.
        private object ConvertSecureString(object item)
        {
            if (!AsPlainText && item is string stringItem)
            {
                return Utils.ConvertToSecureString(stringItem);
            }
            else if (AsPlainText && item is SecureString secureStringItem)
            {
                var networkCred = new System.Net.NetworkCredential("", secureStringItem);
                return networkCred.Password;
            }

            return item;
        }

        private void WriteNotFoundError()
        {
            var msg = string.Format(CultureInfo.InvariantCulture, "The secret {0} was not found.", Name);
            WriteError(
                new ErrorRecord(
                    new ItemNotFoundException(msg),
                    "GetSecretNotFound",
                    ErrorCategory.ObjectNotFound,
                    this));
        }

        #endregion
    }

    #endregion

    #region Set-Secret

    /// <summary>
    /// Adds a provided secret to the specified extension vault, 
    /// or the built-in default store if an extension vault is not specified.
    /// </summary>
    [Cmdlet(VerbsCommon.Set, "Secret", 
            DefaultParameterSetName = SecureStringParameterSet)]
    public sealed class SetSecretCommand : SecretCmdlet
    {
        #region Members

        private const string SecureStringParameterSet = "SecureStringParameterSet";
        private const string ObjectParameterSet = "ObjectParameterSet";

        #endregion

        #region Parameters

        /// <summary>
        /// Gets or sets a name of the secret to be added.
        /// </summary>
        [Parameter(Position=0, Mandatory=true)]
        [ValidateNotNullOrEmpty]
        public string Name { get; set; }

        /// <summary>
        /// Gets or sets a value that is the secret to be added.
        /// Supported types:
        ///     PSCredential
        ///     SecureString
        ///     String
        ///     Hashtable
        ///     byte[]
        /// </summary>
        [Parameter(Position=1, Mandatory=true, ValueFromPipeline=true,
                   ParameterSetName = ObjectParameterSet)]
        public object Secret { get; set; }

        /// <summary>
        /// Gets or sets a SecureString value to be added to a vault.
        /// </summary>
        [Parameter(Position=1, Mandatory=true, ValueFromPipeline=true,
                   ParameterSetName = SecureStringParameterSet)]
        public SecureString SecureStringSecret { get; set; }

        /// <summary>
        /// Gets or sets an optional extension vault name.
        /// </summary>
        [Parameter(Position=2)]
        public string Vault { get; set; }

        /// <summary>
        /// Gets or sets a flag indicating whether an existing secret with the same name is overwritten.
        /// </summary>
        [Parameter]
        public SwitchParameter NoClobber { get; set; }

        #endregion

        #region Overrides

        protected override void EndProcessing()
        {
            if (ParameterSetName == SecureStringParameterSet)
            {
                Secret = SecureStringSecret;
            }

            var secretToWrite = (Secret is PSObject psObject) ? psObject.BaseObject : Secret;

            // Add to specified vault.
            if (!string.IsNullOrEmpty(Vault))
            {
                WriteSecret(
                    extensionModule: GetExtensionVault(Vault),
                    secretToWrite: secretToWrite);
                return;
            }

            // Add to default vault, if available.
            if (!string.IsNullOrEmpty(RegisteredVaultCache.DefaultVaultName))
            {
                WriteSecret(
                    extensionModule: GetExtensionVault(RegisteredVaultCache.DefaultVaultName),
                    secretToWrite: secretToWrite);
                return;
            }

            ThrowTerminatingError(
                new ErrorRecord(
                    exception: new PSInvalidOperationException(
                        "Unable to set secret because no vault was provided and there is no default vault designated."
                    ),
                    "SetSecretFailNoVault",
                    ErrorCategory.InvalidOperation,
                    this));
        }

        #endregion

        #region Private methods

        private void WriteSecret(
            ExtensionVaultModule extensionModule,
            object secretToWrite)
        {
            // If NoClobber is selected, then check to see if it already exists.
            if (NoClobber)
            {
                var result = extensionModule.InvokeGetSecret(
                    name: Name,
                    vaultName: extensionModule.VaultName,
                    cmdlet: this);

                if (result != null)
                {
                    var msg = string.Format(CultureInfo.InvariantCulture, 
                        "A secret with name {0} already exists in vault {1}.", Name, extensionModule.VaultName);
                    ThrowTerminatingError(
                        new ErrorRecord(
                            new PSInvalidOperationException(msg),
                            "AddSecretAlreadyExists",
                            ErrorCategory.ResourceExists,
                            this));
                }
            }

            // Add new secret to vault.
            extensionModule.InvokeSetSecret(
                name: Name,
                secret: secretToWrite,
                vaultName: extensionModule.VaultName,
                cmdlet: this);
        }

        #endregion
    }

    #endregion

    #region Remove-Secret

    /// <summary>
    /// Removes a secret by name from the local default vault.
    /// <summary>
    [Cmdlet(VerbsCommon.Remove, "Secret")]
    public sealed class RemoveSecretCommand : SecretCmdlet
    {
        #region Parameters

        /// <summary>
        /// Gets or sets a name of the secret to be removed.
        /// </summary>
        [Parameter(Position=0, 
                   Mandatory=true,
                   ValueFromPipeline=true,
                   ValueFromPipelineByPropertyName=true)]
        [ValidateNotNullOrEmpty]
        public string Name { get; set; }

        /// <summary>
        /// Gets or sets an optional extension vault name.
        /// </summary>
        [Parameter(Position=1, Mandatory=true)]
        [ValidateNotNullOrEmpty]
        public string Vault { get; set; }

        #endregion

        #region Overrides

        protected override void ProcessRecord()
        {
            // Remove from extension vault.
            var extensionModule = GetExtensionVault(Vault);
            extensionModule.InvokeRemoveSecret(
                name: Name,
                vaultName: Vault,
                cmdlet: this);
        }

        #endregion
    }

    #endregion

    #region Test-SecretVault

    /// <summary>
    /// Runs vault internal validation test.
    /// </summary>
    [Cmdlet(VerbsDiagnostic.Test, "SecretVault")]
    [OutputType(typeof(bool))]
    public sealed class TestSecretVaultCommand : SecretCmdlet
    {
        #region Parameters

        [Parameter(Position=1, Mandatory=true)]
        [ValidateNotNullOrEmpty]
        public string Vault { get; set; }

        #endregion

        #region Overrides

        protected override void EndProcessing()
        {
            var extensionModule = GetExtensionVault(Vault);
            var success = extensionModule.InvokeTestVault(
                vaultName: Vault,
                cmdlet: this);

            var resultMessage = success ?
                string.Format(CultureInfo.InvariantCulture, @"Vault {0} succeeded validation test", Vault) :
                string.Format(CultureInfo.InvariantCulture, @"Vault {0} failed validation test", Vault);
            WriteVerbose(resultMessage);

            // Return boolean for test result
            WriteObject(success);
        }

        #endregion
    }

    #endregion
}
