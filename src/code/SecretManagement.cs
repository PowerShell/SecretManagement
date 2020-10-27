// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Management.Automation;
using System.Management.Automation.Language;
using System.Management.Automation.Runspaces;
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
            IsDefault = vaultInfo.IsDefault;
        }

        #endregion
    }

    #endregion

    #region VaultNameCompleter

    internal class VaultNameCompleter : IArgumentCompleter
    {
        private SortedDictionary<string, ExtensionVaultModule> _vaultExtensions;

        public IEnumerable<CompletionResult> CompleteArgument(
            string commandName,
            string parameterName,
            string wordToComplete,
            CommandAst commandAst,
            IDictionary fakeBoundParameters)
        {
            if (_vaultExtensions == null)
            {
                _vaultExtensions = RegisteredVaultCache.VaultExtensions;
            }

            var wordToCompletePattern = WildcardPattern.Get(
                pattern: string.IsNullOrWhiteSpace(wordToComplete) ? "*" : wordToComplete + "*",
                options: WildcardOptions.IgnoreCase);
            
            foreach (var vaultName in _vaultExtensions.Keys)
            {
                if (wordToCompletePattern.IsMatch(vaultName))
                {
                    yield return new CompletionResult(vaultName, vaultName, CompletionResultType.Text, vaultName);
                }
            }
        }
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
        /// Gets or sets the module name or file path of the vault extension module to register.
        /// </summary>
        [Parameter(Position=0, Mandatory=true)]
        [ValidateNotNullOrEmpty]
        public string ModuleName { get; set; }

        /// <summary>
        /// Gets or sets a friendly name for the registered secret vault.
        /// The name must be unique.
        /// If no Name is provided then the ModuleName is used as the friendly name.
        /// </summary>
        [Parameter(Position=1)]
        [ValidateNotNullOrEmpty]
        public string Name { get; set; }

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

        /// <summary>
        /// Gets or sets a flag that overwrites an existing secret vault with the same name.
        /// </summary>
        [Parameter]
        public SwitchParameter AllowClobber { get; set; }

        /// <summary>
        /// Gets or sets a flag that will return the registered extension vault information.
        /// </summary>
        [Parameter]
        public SwitchParameter PassThru { get; set; }

        #endregion

        #region Overrides

        protected override void BeginProcessing()
        {
            if (!this.MyInvocation.BoundParameters.ContainsKey(nameof(Name)))
            {
                // Let the friendly Name be the module name.
                var results = InvokeCommand.InvokeScript(
                    script: @"param([string] $path) Split-Path -Path $path -Leaf",
                    useNewScope: true,
                    writeToPipeline: PipelineResultTypes.Error,
                    input: null,
                    args: new object[] { ModuleName });
                string moduleName = (results.Count == 1 && results[0] != null) ? (string) results[0].BaseObject : null;
                if (string.IsNullOrEmpty(moduleName))
                {
                    var msg = string.Format(CultureInfo.InvariantCulture,
                        @"Unable to get friendly name from ModuleName : {0}",
                        ModuleName);

                    ThrowTerminatingError(
                        new ErrorRecord(
                            exception: new PSInvalidOperationException(msg),
                            errorId: "RegisterSecretVaultCommandCannotParseModuleName",
                            errorCategory: ErrorCategory.InvalidOperation,
                            this));
                }

                var extension = System.IO.Path.GetExtension(moduleName);
                if (extension.Equals(".psd1", StringComparison.OrdinalIgnoreCase) ||
                    extension.Equals(".psm1", StringComparison.OrdinalIgnoreCase))
                {
                    moduleName = System.IO.Path.GetFileNameWithoutExtension(moduleName);
                }

                Name = moduleName;
            }
        }

        protected override void EndProcessing()
        {
            var vaultInfo = new Hashtable();

            // Validate mandatory parameters.
            var vaultItems = RegisteredVaultCache.GetAll();
            if (vaultItems.ContainsKey(Name) && !(AllowClobber.IsPresent))
            {
                ThrowTerminatingError(
                    new ErrorRecord(
                        new InvalidOperationException("Provided Name for vault is already being used."),
                        "RegisterSecretVaultInvalidVaultName",
                        ErrorCategory.InvalidArgument,
                        this));
            }

            if (!ShouldProcess(Name, "Register module as a SecretManagement extension vault for current user"))
            {
                return;
            }

            // Resolve the module name path in calling context, if it is a path and not a name.
            var results = InvokeCommand.InvokeScript(
                    script: @"param([string] $path) (Resolve-Path -Path $path -ErrorAction Ignore).Path",
                    useNewScope: true,
                    writeToPipeline: PipelineResultTypes.Error,
                    input: null,
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

            if (!CheckForImplementingModule(
                dirPath: moduleInfo.ModuleBase,
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

            // Find base path of module without version folder, to store in vault registry.
            string dirPath;
            if (System.IO.Path.GetFileName(moduleInfo.ModuleBase).Equals(moduleInfo.Name, StringComparison.OrdinalIgnoreCase))
            {
                dirPath = moduleInfo.ModuleBase;
            }
            else
            {
                var parent = System.IO.Directory.GetParent(moduleInfo.ModuleBase);
                while (parent != null && !parent.Name.Equals(moduleInfo.Name, StringComparison.OrdinalIgnoreCase))
                {
                    parent = parent.Parent;
                }
                dirPath = parent?.FullName ?? moduleInfo.ModuleBase;
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
                defaultVault: DefaultVault,
                overWriteExisting: true);

            if (PassThru.IsPresent)
            {
                if (RegisteredVaultCache.VaultExtensions.TryGetValue(
                    key: Name,
                    out ExtensionVaultModule extensionVault))
                {
                    WriteObject(
                        new SecretVaultInfo(
                            extensionVault.VaultName,
                            extensionVault));
                }
            }
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
                    @"Implementing script module could not be found or loaded at : {0} with error : {1}.", 
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
                    $null = Import-Module -Name $SecretMgtModulePath -ErrorAction Ignore

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
                   Mandatory = true,
                   ValueFromPipeline = true)]
        [ArgumentCompleter(typeof(VaultNameCompleter))]
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
            if (!ShouldProcess(Name, "Unregister SecretManagement extension vault module for current user"))
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

            // Invoke the optional 'Unregister-SecretVault' method on the extension vault
            if (!RegisteredVaultCache.VaultExtensions.TryGetValue(
                key: vaultName,
                out ExtensionVaultModule extensionVault))
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

            extensionVault.InvokeUnregisterVault(this);

            // Remove vault from registry
            RegisteredVaultCache.Remove(vaultName);
            WriteVerbose(
                string.Format(CultureInfo.InvariantCulture, 
                    "Removed vault {0} from registry.", extensionVault.VaultName)
            );
        }

        #endregion
    }

    #endregion

    #region Set-DefaultVault

    /// <summary>
    /// Cmdlet sets the provided registered vault name as the default vault.
    /// </summary>
    [Cmdlet(VerbsCommon.Set, "DefaultVault", SupportsShouldProcess = true)]
    public sealed class SetDefaultVaultCommand : PSCmdlet
    {
        #region Parameters

        private const string NameParameterSet = "NameParameterSet";
        private const string SecretVaultParameterSet = "SecretVaultParameterSet";

        /// <summary>
        /// Gets or sets a name of the secret vault to unregister.
        /// </summary>
        [Parameter(ParameterSetName = NameParameterSet,
                   Position = 0, 
                   Mandatory = true,
                   ValueFromPipeline = true)]
        [ArgumentCompleter(typeof(VaultNameCompleter))]
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

        protected override void EndProcessing()
        {
            if (!ShouldProcess(Name, "Set vault as default"))
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

            try
            {
                RegisteredVaultCache.SetDefaultVault(vaultName);
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

    #region SecretNameCompleter

    internal class SecretNameCompleter : IArgumentCompleter
    {
        private List<string> _secretNames;

        public IEnumerable<CompletionResult> CompleteArgument(
            string commandName,
            string parameterName,
            string wordToComplete,
            CommandAst commandAst,
            IDictionary fakeBoundParameters)
        {
            if (_secretNames == null)
            {
                var results = PowerShellInvoker.InvokeScript<SecretInformation>(
                    script: "Get-SecretInfo",
                    args: new object[] {},
                    out ErrorRecord error);

                if (error != null || results == null)
                {
                    yield break;
                }
                
                _secretNames = new List<string>();
                foreach (var secretInfo in results)
                {
                    _secretNames.Add(secretInfo.Name);
                }
            }

            var wordToCompletePattern = WildcardPattern.Get(
                pattern: string.IsNullOrWhiteSpace(wordToComplete) ? "*" : wordToComplete + "*",
                options: WildcardOptions.IgnoreCase);
            
            foreach (var secretName in _secretNames)
            {
                if (wordToCompletePattern.IsMatch(secretName))
                {
                    yield return new CompletionResult(secretName, secretName, CompletionResultType.Text, secretName);
                }
            }
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
        [ArgumentCompleter(typeof(VaultNameCompleter))]
        public string[] Name { get; set; }

        #endregion

        #region Overrides

        protected override void EndProcessing()
        {
            Name = Name ?? new string[] { "*" };
            var vaultExtensions = RegisteredVaultCache.VaultExtensions;

            foreach (var name in Name)
            {
                if (WildcardPattern.ContainsWildcardCharacters(name))
                {
                    var namePattern = new WildcardPattern(name, WildcardOptions.IgnoreCase);
                    foreach (var vaultName in vaultExtensions.Keys)
                    {
                        if (namePattern.IsMatch(vaultName))
                        {
                            if (vaultExtensions.TryGetValue(vaultName, out ExtensionVaultModule extensionModule))
                            {
                                WriteObject(
                                    new SecretVaultInfo(
                                        extensionModule.VaultName,
                                        extensionModule));
                            }
                        }
                    }
                }
                else if (vaultExtensions.TryGetValue(name, out ExtensionVaultModule extensionModule))
                {
                    WriteObject(
                        new SecretVaultInfo(
                            extensionModule.VaultName,
                            extensionModule));
                }
                else
                {
                    var msg = string.Format(CultureInfo.InvariantCulture,
                        "Vault {0} does not exist in registry.", name);
                    WriteError(
                        new ErrorRecord(
                            new ItemNotFoundException(msg),
                            "GetSecretVaultNotFound",
                            ErrorCategory.ObjectNotFound,
                            this));
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
        [ArgumentCompleter(typeof(SecretNameCompleter))]
        public string Name { get; set; }

        /// <summary>
        /// Gets or sets an optional name of the vault to retrieve the secret from.
        /// </summary>
        [Parameter(Position=1)]
        [ArgumentCompleter(typeof(VaultNameCompleter))]
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
        [ArgumentCompleter(typeof(SecretNameCompleter))]
        public string Name { get; set; }

        /// <summary>
        /// Gets or sets an optional name of the vault to retrieve the secret from.
        /// </summary>
        [Parameter(Position=1)]
        [ArgumentCompleter(typeof(VaultNameCompleter))]
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
    [Cmdlet(VerbsCommon.Set, "Secret", SupportsShouldProcess = true,
            DefaultParameterSetName = SecureStringParameterSet)]
    public sealed class SetSecretCommand : SecretCmdlet
    {
        #region Members

        private const string SecureStringParameterSet = "SecureStringParameterSet";
        private const string ObjectParameterSet = "ObjectParameterSet";
        private const string SecretInfoParameterSet = "SecretInfoParameterSet";
        private const string SecretExistsError = "A secret with name {0} already exists in vault {1}.";

        #endregion

        #region Parameters

        /// <summary>
        /// Gets or sets a name of the secret to be added.
        /// </summary>
        [Parameter(ParameterSetName = ObjectParameterSet, Position=0, Mandatory=true)]
        [Parameter(ParameterSetName = SecureStringParameterSet, Position=0, Mandatory=true)]
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

        [Parameter(Position=1, Mandatory=true, ValueFromPipeline=true,
                   ParameterSetName = SecretInfoParameterSet)]
        public SecretInformation SecretInfo { get; set; }

        /// <summary>
        /// Gets or sets an optional extension vault name.
        /// </summary>
        [Parameter(Position=2, ParameterSetName = ObjectParameterSet)]
        [Parameter(Position=2, ParameterSetName = SecureStringParameterSet)]
        [Parameter(ParameterSetName = SecretInfoParameterSet, Mandatory=true)]
        [ArgumentCompleter(typeof(VaultNameCompleter))]
        public string Vault { get; set; }

        /// <summary>
        /// Gets or sets a flag indicating whether an existing secret with the same name is overwritten.
        /// </summary>
        [Parameter]
        public SwitchParameter NoClobber { get; set; }

        #endregion

        #region Overrides

        protected override void ProcessRecord()
        {
            if (!ShouldProcess(Vault, "Write secret to vault and override any existing secret of the same name"))
            {
                return;
            }

            object secretToWrite = null;
            switch (ParameterSetName)
            {
                case SecretInfoParameterSet:
                    // Get and add secret to specified vault.
                    // Get secret from secretinfo.
                    var sourceExtensionModule = GetExtensionVault(SecretInfo.VaultName);
                    var secret = sourceExtensionModule.InvokeGetSecret(
                        name: SecretInfo.Name,
                        vaultName: SecretInfo.VaultName,
                        cmdlet: this);

                    // Check for overwrite error.
                    var destExtensionModule = GetExtensionVault(Vault);
                    if (NoClobber &&
                        SecretExistsInVault(
                            extensionModule: destExtensionModule,
                            name: SecretInfo.Name))
                    {
                        var msg = string.Format(CultureInfo.InvariantCulture, 
                            SecretExistsError, SecretInfo.Name, destExtensionModule.VaultName);
                        WriteError(
                            new ErrorRecord(
                                new PSInvalidOperationException(msg),
                                "SetSecretAlreadyExistsWithNoClobber",
                                ErrorCategory.ResourceExists,
                                this));
                        return;
                    }
                    
                    // Set secret to specified vault name.
                    destExtensionModule.InvokeSetSecret(
                        name: SecretInfo.Name,
                        secret: secret,
                        vaultName: Vault,
                        cmdlet: this);
                    return;

                case SecureStringParameterSet:
                    secretToWrite = SecureStringSecret;
                    break;

                case ObjectParameterSet:
                    secretToWrite = (Secret is PSObject psObject) ? psObject.BaseObject : Secret;
                    break;
            }

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
            if (NoClobber &&
                SecretExistsInVault(
                    extensionModule: extensionModule,
                    name: Name))
            {
                var msg = string.Format(CultureInfo.InvariantCulture, 
                    SecretExistsError, Name, extensionModule.VaultName);
                ThrowTerminatingError(
                    new ErrorRecord(
                        new PSInvalidOperationException(msg),
                        "SetSecretAlreadyExistsWithNoClobber",
                        ErrorCategory.ResourceExists,
                        this));
            }

            // Add new secret to vault.
            extensionModule.InvokeSetSecret(
                name: Name,
                secret: secretToWrite,
                vaultName: extensionModule.VaultName,
                cmdlet: this);
        }

        private bool SecretExistsInVault(
            ExtensionVaultModule extensionModule,
            string name)
        {
            var result = extensionModule.InvokeGetSecret(
                    name: name,
                    vaultName: extensionModule.VaultName,
                    cmdlet: this);

            return (result != null);
        }

        #endregion
    }

    #endregion

    #region Remove-Secret

    /// <summary>
    /// Removes a secret by name from the local default vault.
    /// <summary>
    [Cmdlet(VerbsCommon.Remove, "Secret", SupportsShouldProcess = true)]
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
        [ArgumentCompleter(typeof(SecretNameCompleter))]
        [ValidateNotNullOrEmpty]
        public string Name { get; set; }

        /// <summary>
        /// Gets or sets an optional extension vault name.
        /// </summary>
        [Parameter(Position=1, Mandatory=true)]
        [ArgumentCompleter(typeof(VaultNameCompleter))]
        [ValidateNotNullOrEmpty]
        public string Vault { get; set; }

        #endregion

        #region Overrides

        protected override void ProcessRecord()
        {
            if (!ShouldProcess(Vault, "Remove secret by name from vault"))
            {
                return;
            }

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

        [Parameter(Position=0,
                   ValueFromPipeline=true,
                   ValueFromPipelineByPropertyName=true)]
        [ArgumentCompleter(typeof(VaultNameCompleter))]
        public string[] Name { get; set; }

        #endregion

        #region Overrides

        protected override void ProcessRecord()
        {
            Name = Name ?? new string[] { "*" };
            var vaultExtensions = RegisteredVaultCache.VaultExtensions;
            var count = 0;
            var result = true;

            foreach (var name in Name)
            {
                if (WildcardPattern.ContainsWildcardCharacters(name))
                {
                    var namePattern = new WildcardPattern(name, WildcardOptions.IgnoreCase);
                    foreach (var vaultName in vaultExtensions.Keys)
                    {
                        if (namePattern.IsMatch(vaultName))
                        {
                            ++count;
                            RunTest(
                                vaultName,
                                vaultExtensions,
                                out bool success);
                            if (!success && result)
                            {
                                result = false;
                            }
                        }
                    }
                }
                else if (RunTest(
                    vaultName: name,
                    vaultExtensions: vaultExtensions,
                    out bool success))
                {
                    ++count;
                    if (!success && result)
                    {
                        result = false;
                    }
                }
            }

            if (count > 0)
            {
                // Return boolean result from test(s)
                WriteObject(result);
            }
        }

        #endregion

        #region Private methods

        private bool RunTest(
            string vaultName,
            SortedDictionary<string, ExtensionVaultModule> vaultExtensions,
            out bool result)
        {
            if (vaultExtensions.TryGetValue(vaultName, out ExtensionVaultModule extensionModule))
            {
                result = extensionModule.InvokeTestVault(
                    vaultName: vaultName,
                    cmdlet: this);

                var resultMessage = result ?
                    string.Format(CultureInfo.InvariantCulture, @"Vault {0} succeeded validation test", extensionModule.VaultName) :
                    string.Format(CultureInfo.InvariantCulture, @"Vault {0} failed validation test", extensionModule.VaultName);
                WriteVerbose(resultMessage);

                return true;
            }

            var msg = string.Format(CultureInfo.InvariantCulture,
                "Vault {0} does not exist in registry.", vaultName);
            WriteError(
                new ErrorRecord(
                    new ItemNotFoundException(msg),
                    "TestSecretVaultNotFound",
                    ErrorCategory.ObjectNotFound,
                    this));

            result = false;
            return false;
        }

        #endregion
    }

    #endregion
}
