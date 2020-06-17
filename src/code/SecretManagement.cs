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
        public string Name { get; }

        /// <summary>
        /// Gets name of extension vault module.
        /// </summary>
        public string ModuleName { get; }

        /// <summary>
        /// Gets extension vault module path.
        /// </summary>
        public string ModulePath { get; }

        /// <summary>
        /// Name of assembly implementing the SecretManagementExtension type.
        /// </summary>
        public string ImplementingTypeAssemblyName { get; }

        /// <summary>
        /// Name of type that implements the SecretManagementExtension type.
        /// </summary>
        public string ImplementingTypeName { get; }

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
            Name = name;
            ModuleName = vaultInfo.ModuleName;
            ModulePath = vaultInfo.ModulePath;
            VaultParameters = vaultInfo.VaultParameters;
            ImplementingTypeAssemblyName = vaultInfo.ImplementingTypeAssemblyName;
            ImplementingTypeName = vaultInfo.ImplementingTypeName;
            IsDefault = vaultInfo.IsDefault;
        }

        #endregion
    }

    #endregion

    #region SecretManagementOption

    public sealed class SecretManagementOption
    {
        #region Parameters

        /// <summary>
        /// Class that contains SecretManagement options.
        public bool AllowPrompting 
        { 
            get; 
            private set;
        }

        #endregion

        #region Constructor

        internal SecretManagementOption(bool allowPrompting)
        {
            AllowPrompting = allowPrompting;
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
        #region Members

        internal const string ImplementingModule = "SecretManagementExtension";

        #endregion

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
        /// SecretManagementExtension implementing type or module script functions.
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
            var results = SessionState.InvokeCommand.InvokeScript(
                script: "param([string] $path) (Resolve-Path -Path $path -EA Silent).Path",
                args: new object[] { ModuleName });
            string resolvedPath = (results.Count == 1 && results[0] != null) ? (string) results[0].BaseObject : null;
            string moduleNameOrPath = resolvedPath ?? ModuleName;

            var moduleInfo = GetModuleInfo(moduleNameOrPath);
            if (moduleInfo == null)
            {
                var msg = string.Format(CultureInfo.InvariantCulture, 
                    "Could not load and retrieve module information for module: {0}.",
                    ModuleName);

                ThrowTerminatingError(
                    new ErrorRecord(
                        new PSInvalidOperationException(msg),
                        "RegisterSecretVaultCantGetModuleInfo",
                        ErrorCategory.InvalidOperation,
                        this));
            }

            var modulePath = moduleInfo.Path;
            var dirPath = System.IO.File.Exists(modulePath) ? System.IO.Path.GetDirectoryName(modulePath) : modulePath;

            // Check module required modules for implementing type of SecretManagementExtension class.
            Type implementingType = GetImplementingTypeFromRequiredAssemblies(moduleInfo);

            // Check if module supports implementing functions.
            var haveScriptFunctionImplementation = CheckForImplementingModule(
                dirPath: dirPath,
                error: out Exception error);

            if (implementingType == null && !haveScriptFunctionImplementation)
            {
                var invalidException = new PSInvalidOperationException(
                    message: "Could not find a SecretManagementExtension implementing type, or a valid implementing script module.",
                    innerException: error);

                ThrowTerminatingError(
                    new ErrorRecord(
                        invalidException,
                        "RegisterSecretVaultCantFindImplementingTypeOrScriptModule",
                        ErrorCategory.ObjectNotFound,
                        this));
            }

            vaultInfo.Add(
                key: ExtensionVaultModule.ModulePathStr,
                value: dirPath);
            
            vaultInfo.Add(
                key: ExtensionVaultModule.ModuleNameStr,
                value: moduleInfo.Name);

            vaultInfo.Add(
                key: ExtensionVaultModule.ImplementingTypeStr, 
                value: new Hashtable() {
                    { "AssemblyName", implementingType != null ? implementingType.Assembly.GetName().Name : string.Empty },
                    { "TypeName", implementingType != null ? implementingType.FullName: string.Empty }
                });

            vaultInfo.Add(
                key: ExtensionVaultModule.ImplementingFunctionsStr,
                value: haveScriptFunctionImplementation);

            // Store optional vault parameters
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

        private static Type GetImplementingTypeFromRequiredAssemblies(
            PSModuleInfo moduleInfo)
        {
            var extensionType = typeof(Microsoft.PowerShell.SecretManagement.SecretManagementExtension);
            foreach (var requiredAssembly in moduleInfo.RequiredAssemblies)
            {
                var assemblyName = System.IO.Path.GetFileNameWithoutExtension(requiredAssembly);
                foreach (var assembly in System.AppDomain.CurrentDomain.GetAssemblies())
                {
                    if (assembly.GetName().Name.Equals(assemblyName, StringComparison.OrdinalIgnoreCase))
                    {
                        foreach (var assemblyType in assembly.GetTypes())
                        {
                            if (extensionType.IsAssignableFrom(assemblyType))
                            {
                                return assemblyType;
                            }
                        }
                    }
                }
            }

            return null;
        }

        private static bool CheckForImplementingModule(
            string dirPath,
            out Exception error)
        {
            // An implementing module will be in a subfolder with module name 'SecretManagementExtension',
            // and will export the four required functions: Set-Secret, Get-Secret, Remove-Secret, Get-SecretInfo.
            var implementingModulePath = System.IO.Path.Combine(dirPath, ImplementingModule);
            var moduleInfo = GetModuleInfo(implementingModulePath);
            if (moduleInfo == null)
            {
                error = new ItemNotFoundException("Implementing script module not found.");
                return false;
            }

            // Get-Secret function
            if (!moduleInfo.ExportedFunctions.ContainsKey("Get-Secret"))
            {
                error = new ItemNotFoundException("Get-Secret function not found.");
                return false;
            }
            var funcInfo = moduleInfo.ExportedFunctions["Get-Secret"];
            if (!funcInfo.Parameters.ContainsKey("Name"))
            {
                error = new ItemNotFoundException("Get-Secret Name parameter not found.");
                return false;
            }
            if (!funcInfo.Parameters.ContainsKey("AdditionalParameters"))
            {
                error = new ItemNotFoundException("Get-Secret AdditionalParameters parameter not found.");
                return false;
            }

            // Set-Secret function
            if (!moduleInfo.ExportedFunctions.ContainsKey("Set-Secret"))
            {
                error = new ItemNotFoundException("Set-Secret function not found.");
                return false;
            }
            funcInfo = moduleInfo.ExportedFunctions["Set-Secret"];
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
            if (!funcInfo.Parameters.ContainsKey("AdditionalParameters"))
            {
                error = new ItemNotFoundException("Set-Secret AdditionalParameters parameter not found.");
                return false;
            }

            // Remove-Secret function
            if (!moduleInfo.ExportedFunctions.ContainsKey("Remove-Secret"))
            {
                error = new ItemNotFoundException("Remove-Secret function not found.");
                return false;
            }
            funcInfo = moduleInfo.ExportedFunctions["Remove-Secret"];
            if (!funcInfo.Parameters.ContainsKey("Name"))
            {
                error = new ItemNotFoundException("Remove-Secret Name parameter not found.");
                return false;
            }
            if (!funcInfo.Parameters.ContainsKey("AdditionalParameters"))
            {
                error = new ItemNotFoundException("Remove-Secret AdditionalParameters parameter not found.");
                return false;
            }

            // Get-SecretInfo function
            if (!moduleInfo.ExportedFunctions.ContainsKey("Get-SecretInfo"))
            {
                error = new ItemNotFoundException("Get-SecretInfo function not found.");
                return false;
            }
            funcInfo = moduleInfo.ExportedFunctions["Get-SecretInfo"];
            if (!funcInfo.Parameters.ContainsKey("Filter"))
            {
                error = new ItemNotFoundException("Get-SecretInfo Filter parameter not found.");
                return false;
            }
            if (!funcInfo.Parameters.ContainsKey("AdditionalParameters"))
            {
                error = new ItemNotFoundException("Get-SecretInfo AdditionalParameters parameter not found.");
                return false;
            }

            // Test-SecretVault function
            if (!moduleInfo.ExportedFunctions.ContainsKey("Test-SecretVault"))
            {
                error = new ItemNotFoundException("Test-SecretVault function not found.");
                return false;
            }
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
            string modulePath)
        {
            // Get module information by loading it.
            var results = PowerShellInvoker.InvokeScript<PSModuleInfo>(
                script: @"
                    param ([string] $ModulePath)

                    Import-Module -Name $ModulePath -Force -PassThru
                ",
                args: new object[] { modulePath },
                out Exception _);
            
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
                    vaultName = SecretVault.Name;
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

        [Parameter (Position=0, Mandatory=true)]
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

    #region Set-Option

    [Cmdlet(VerbsCommon.Set, "Option")]
    [OutputType(typeof(SecretManagementOption))]
    public sealed class SetOptionCommand : PSCmdlet
    {
        #region Parameters

        [Parameter (Position=0)]
        public SwitchParameter AllowPrompting { get; set; }

        #endregion

        #region Overrides

        protected override void EndProcessing()
        {
            var option = new SecretManagementOption(AllowPrompting);
            RegisteredVaultCache.SetOption(option);
            WriteObject(option);
        }

        #endregion
    }

    #endregion

    #region Get-Option

    [Cmdlet(VerbsCommon.Get, "Option")]
    [OutputType(typeof(SecretVaultInfo))]
    public sealed class GetOptionCommand : PSCmdlet
    {
        #region Overrides

        protected override void EndProcessing()
        {
            WriteObject(RegisteredVaultCache.Option);
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
    [OutputType(typeof(PSObject))]
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
                WriteResults(
                    extensionModule.InvokeGetSecretInfo(
                        filter: Name,
                        vaultName: extensionModule.VaultName,
                        cmdlet: this));
                
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
        [Parameter(Position=0, Mandatory=true)]
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
        [Parameter(Position=2)]
        public SwitchParameter AsPlainText { get; set; }

        #endregion

        #region Overrides

        protected override void EndProcessing()
        {
            // Wild card characters are not supported in this cmdlet.
            if (WildcardPattern.ContainsWildcardCharacters(Name))
            {
                ThrowTerminatingError(
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
                var result = extensionModule.InvokeGetSecret(
                    name: Name,
                    vaultName: Vault,
                    cmdlet: this);

                if (result != null)
                {
                    WriteSecret(result);
                }
                else
                {
                    WriteNotFoundError();
                }

                return;
            }

            // First search the default vault.
            if (!string.IsNullOrEmpty(RegisteredVaultCache.DefaultVaultName))
            {
                var extensionModule = GetExtensionVault(RegisteredVaultCache.DefaultVaultName);
                if (TryInvokeAndWrite(extensionModule))
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

                if (TryInvokeAndWrite(extensionModule))
                {
                    return;
                }
            }

            WriteNotFoundError();
        }

        #endregion

        #region Private methods

        private bool TryInvokeAndWrite(ExtensionVaultModule extensionModule)
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
                    return true;
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
            }

            return false;
        }

        private void WriteSecret(object secret)
        {
            if (secret is PSObject secretPSObject)
            {
                secret = secretPSObject.BaseObject;
            }

            if (!AsPlainText && secret is string stringSecret)
            {
                // Write a string secret type only if explicitly requested with the -AsPlainText
                // parameter switch.  Otherwise return it as a SecureString type.
                WriteObject(Utils.ConvertToSecureString(stringSecret));
                return;
            }

            if (AsPlainText && secret is SecureString secureString)
            {
                // Convert secure string to plain text.
                var networkCred = new System.Net.NetworkCredential("", secureString);
                WriteObject(networkCred.Password);
                return;
            }

            WriteObject(secret);
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

    #region Unlock-SecretVault

    /// <summary>
    /// Unlocks a vault with the provided key.
    /// </summary>
    [Cmdlet(VerbsCommon.Unlock, "SecretVault")]
    public sealed class UnlockSecretVaultCommand : SecretCmdlet
    {
        #region Parameters

        /// <summary>
        /// Gets or sets the vault name to be unlocked.
        /// </summary>
        [Parameter(Position=0, Mandatory=true)]
        [ValidateNotNullOrEmpty]
        public string Name { get; set; }
        
        /// <summary>
        /// Gets or sets the key to unlock the vault.
        /// </summary>
        [Parameter(Position=1, Mandatory=true)]
        public SecureString Key { get; set; }

        #endregion

        #region Overrides

        protected override void EndProcessing()
        {
            var extensionModule = GetExtensionVault(Name);
            extensionModule.InvokeUnlockVault(
                vaultKey: Key,
                vaultName: Name,
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
