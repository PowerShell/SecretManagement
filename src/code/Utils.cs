// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Management.Automation;
using System.Runtime.InteropServices;
using System.Security;

using Dbg = System.Diagnostics.Debug;

namespace Microsoft.PowerShell.SecretManagement
{
    #region Utils

    internal static class Utils
    {
        #region Members

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

        public static string SecretManagementLocalPath
        {
            get;
            private set;
        }

        public static bool IsWindows
        {
            get;
            private set;
        }

        #endregion

        #region Methods

        public static Hashtable ConvertJsonToHashtable(string json)
        {
            var results = PowerShellInvoker.InvokeScriptCommon<Hashtable>(
                script: ConvertJsonToHashtableScript,
                args: new object[] { json },
                error: out ErrorRecord _);

            return (results.Count > 0) ? results[0] : null;
        }

        public static string ConvertHashtableToJson(Hashtable hashtable)
        {
            var results = PowerShellInvoker.InvokeScriptCommon<string>(
                script: @"param ([hashtable] $hashtable) ConvertTo-Json -InputObject $hashtable -Depth 10",
                args: new object[] { hashtable },
                error: out ErrorRecord _);

            return (results.Count > 0) ? results[0] : null;
        }

        public static SecureString ConvertToSecureString(string secret)
        {
            var results = PowerShellInvoker.InvokeScriptCommon<SecureString>(
                script: @"param([string] $value) ConvertTo-SecureString -String $value -AsPlainText -Force",
                args: new object[] { secret },
                error: out ErrorRecord _);
            
            return (results.Count > 0) ? results[0] : null;
        }

        private static bool ComparePasswords(
            SecureString password1,
            SecureString password2)
        {
            if (password1.Length != password2.Length)
            {
                return false;
            }

            IntPtr ptrPassword1 = IntPtr.Zero;
            IntPtr ptrPassword2 = IntPtr.Zero;
            try
            {
                ptrPassword1 = Marshal.SecureStringToCoTaskMemUnicode(password1);
                ptrPassword2 = Marshal.SecureStringToCoTaskMemUnicode(password2);
                if (ptrPassword1 != IntPtr.Zero && ptrPassword2 != IntPtr.Zero)
                {
                    for (int i=0; i<(password1.Length * 2); i++)
                    {
                        if (Marshal.ReadByte(ptrPassword1, i) != Marshal.ReadByte(ptrPassword2, i))
                        {
                            return false;
                        }
                    }

                    return true;
                }
            }
            finally
            {
                if (ptrPassword1 != IntPtr.Zero)
                {
                    Marshal.ZeroFreeCoTaskMemUnicode(ptrPassword1);
                }

                if (ptrPassword2 != IntPtr.Zero)
                {
                    Marshal.ZeroFreeCoTaskMemUnicode(ptrPassword2);
                }
            }

            return false;
        }

        public static SecureString PromptForPassword(
            PSCmdlet cmdlet,
            bool verifyPassword = false,
            string message = null)
        {
            if (cmdlet.Host == null || cmdlet.Host.UI == null)
            {
                throw new PSInvalidOperationException(
                    "Cannot prompt for password. No host available.");
            }

            SecureString password = null;

            cmdlet.Host.UI.WriteLine(
                string.IsNullOrEmpty(message) ? 
                    "A password is required for Microsoft.PowerShell.SecretStore vault."
                    : message);

            var isVerified = !verifyPassword;
            do
            {
                // Initial prompt
                cmdlet.Host.UI.WriteLine("Enter password:");
                password = cmdlet.Host.UI.ReadLineAsSecureString();

                if (verifyPassword)
                {
                    // Verification prompt
                    cmdlet.Host.UI.WriteLine("Enter password again for verification:");
                    var passwordVerified = cmdlet.Host.UI.ReadLineAsSecureString();

                    isVerified = ComparePasswords(password, passwordVerified);

                    if (!isVerified)
                    {
                        cmdlet.Host.UI.WriteLine("\nThe two entered passwords do not match.  Please re-enter the passwords.\n");
                    }
                }
            } while (!isVerified);

            return password;
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
            private set;
        }

        /// <summary>
        /// Gets or sets the object type of the secret.
        /// </summary>
        public SecretType Type
        {
            get;
            private set;
        }

        /// <summary>
        /// Gets or sets the vault name where the secret resides.
        /// </summary>
        public string VaultName
        {
            get;
            private set;
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

    #region SecretManagementExtension class

    /// <summary>
    /// Abstract class which SecretManagement extension vault modules will implement
    /// to provide secret management functions for plugin local or remote vaults.
    /// </summary>
    public abstract class SecretManagementExtension
    {
        #region Properties

        /// <summary>
        /// Name of the registered vault associated with this extension instance.
        /// </summary>
        public string VaultName { get; }

        #endregion

        #region Constructor

        private SecretManagementExtension() { }

        /// <summary>
        /// Initializes a new instance of the <see cref="SecretManagementExtension"/> class.
        /// </summary>
        public SecretManagementExtension(string vaultName)
        {
            if (string.IsNullOrEmpty(vaultName))
            {
                throw new ArgumentNullException("vaultName");
            }

            VaultName = vaultName;
        }

        #endregion

        #region Abstract methods

        /// <summary>
        /// Adds a secret to the vault.
        /// Currently supported secret types are:
        ///     PSCredential
        ///     SecureString
        ///     String
        ///     Hashtable
        ///     byte[]
        /// </summary>
        /// <param name="name">Name under which secret will be stored.</param>
        /// <param name="secret">Secret to be stored.</param>
        /// <param name="vaultName">Name of registered vault.</param>
        /// <param name="additionalParameters">Optional additional parameters.</param>
        /// <param name="error">Optional exception object on failure.</param>
        /// <returns>True on success.</returns>
        public abstract bool SetSecret(
            string name,
            object secret,
            string vaultName,
            IReadOnlyDictionary<string, object> additionalParameters,
            out Exception error);

        /// <summary>
        /// Gets a secret from the vault.
        /// </summary>
        /// <param name="name">Name of the secret to retrieve.</param>
        /// <param name="vaultName">Name of registered vault.</param>
        /// <param name="additionalParameters">Optional additional parameters.</param>
        /// <param name="error">Optional exception object on failure.</param>
        /// <returns>Secret object retrieved from the vault.  Null returned if not found.</returns>
        public abstract object GetSecret(
            string name,
            string vaultName,
            IReadOnlyDictionary<string, object> additionalParameters,
            out Exception error);
        
        /// <summary>
        /// Removes a secret from the vault.
        /// </summary>
        /// <param name="name">Name of the secret to remove.</param>
        /// <param name="vaultName">Name of registered vault.</param>
        /// <param name="additionalParameters">Optional additional parameters.</param>
        /// <param name="error">Optional exception object on failure.</param>
        /// <returns>True on success.</returns>
        public abstract bool RemoveSecret(
            string name,
            string vaultName,
            IReadOnlyDictionary<string, object> additionalParameters,
            out Exception error);

        /// <summary>
        /// Returns a list of key/value pairs for each found vault secret, where
        ///     key   (string): is the name of the secret.
        ///     value (object): is the corresponding secret object.
        /// </summary>
        /// <param name="filter">
        /// A string, including wildcard characters, used to search secret names.
        /// A null value, empty string, or "*" will return all vault secrets.
        /// </param>
        /// <param name="vaultName">Name of registered vault.</param>
        /// <param name="additionalParameters">Optional additional parameters.</param>
        /// <param name="error">Optional exception object on failure.</param>
        /// <returns>Array of SecretInformation objects.</returns>
        public abstract SecretInformation[] GetSecretInfo(
            string filter,
            string vaultName,
            IReadOnlyDictionary<string, object> additionalParameters,
            out Exception error);

        /// <summary>
        /// This is an optional method to unlock an extension vault with a key.
        /// </summary>
        /// <param name="vaultKey">A key SecureString object that unlocks the vault.</param>
        /// <param name="vaultName">Name of registered vault.</param>
        /// <param name="error">Optional exception object on failure.</param>
        /// <returns>True if unlock operation succeeds.</returns>
        public abstract bool UnlockSecretVault(
            SecureString vaultKey,
            string vaultName,
            out Exception error);

        /// <summary>
        /// Validates operation of the registered vault extension. 
        /// </summary>
        /// <param name="vaultName">Name of registered vault.</param>
        /// <param name="additionalParameters">Optional parameters for validation.</param>
        /// <param name="error">Optional exception object on failure.</param>
        /// <returns>True if extension is functioning.</returns>
        public abstract bool TestSecretVault(
            string vaultName,
            IReadOnlyDictionary<string, object> additionalParameters,
            out Exception[] errors);

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

        internal const string GetSecretCmd = "Get-Secret";
        internal const string GetSecretInfoCmd = "Get-SecretInfo";
        internal const string SetSecretCmd = "Set-Secret";
        internal const string RemoveSecretCmd = "Remove-Secret";
        internal const string TestVaultCmd = "Test-SecretVault";
        internal const string UnlockVaultCmd = "Unlock-SecretVault";
        internal const string ModuleNameStr = "ModuleName";
        internal const string ModulePathStr = "ModulePath";
        internal const string VaultParametersStr = "VaultParameters";
        internal const string ImplementingTypeStr = "ImplementingType";
        internal const string ImplementingFunctionsStr = "ImplementingFunctions";
        internal const string VaultPaswordPrompt = "Vault {0} requires a password.";

        private Lazy<SecretManagementExtension> _vaultExtentsion;
        
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
        /// Module path.
        /// </summary>
        public string ModulePath { get; }

        /// <summary>
        /// Name of the assembly implementing the SecretManagementExtension derived type.
        /// </summary>
        public string ImplementingTypeAssemblyName { get; }

        /// <summary>
        /// Name of type implementing SecretManagementExtension abstract class.
        /// </summary>
        public string ImplementingTypeName { get; }

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
            // Required module information.
            IsDefault = isDefault;
            VaultName = vaultName;
            ModuleName = (string) vaultInfo[ModuleNameStr];
            ModulePath = (string) vaultInfo[ModulePathStr];

            var implementingType = (Hashtable) vaultInfo[ImplementingTypeStr];
            ImplementingTypeAssemblyName = (string) implementingType["AssemblyName"];
            ImplementingTypeName = (string) implementingType["TypeName"];

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

            Init();
        }

        /// <summary>
        /// Initializes a new instance of ExtensionVaultModule from an existing instance.
        /// </summary>
        public ExtensionVaultModule(
            ExtensionVaultModule module)
        {
            VaultName = module.VaultName;
            ModuleName = module.ModuleName;
            ModulePath = module.ModulePath;
            ImplementingTypeAssemblyName = module.ImplementingTypeAssemblyName;
            ImplementingTypeName = module.ImplementingTypeName;
            VaultParameters = module.VaultParameters;
            IsDefault = module.IsDefault;

            Init();
        }

        private void Init()
        {
            _vaultExtentsion = new Lazy<SecretManagementExtension>(() => {
                foreach (var assembly in AppDomain.CurrentDomain.GetAssemblies())
                {
                    if (assembly.GetName().Name.Equals(ImplementingTypeAssemblyName, StringComparison.OrdinalIgnoreCase))
                    {
                        var implementingType = assembly.GetType(ImplementingTypeName);
                        if (implementingType != null)
                        {
                            // SecretManagementExtension abstract class constructor takes a single 'vaultName' parameter.
                            return (SecretManagementExtension) Activator.CreateInstance(
                                type: implementingType,
                                args: new object[] { VaultName });
                        }
                    }
                }

                throw new InvalidOperationException(
                    string.Format(CultureInfo.InvariantCulture, 
                        "Unable to find and create SecretManagementExtension type instance from vault {0}", VaultName));
            });
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
            var count = 0;
            do
            {
                try
                {
                    if (!string.IsNullOrEmpty(ImplementingTypeName))
                    {
                        InvokeSetSecretOnImplementingType(name, secret, vaultName, cmdlet);
                    }
                    else
                    {
                        InvokeSetSecretOnScriptFn(name, secret, vaultName, cmdlet);
                    }
                }
                catch (PasswordRequiredException)
                {
                    if (!RegisteredVaultCache.Option.AllowPrompting || 
                        count > 0 ||
                        !TryPromptAndUnlockVault(vaultName, cmdlet))
                    {
                        throw;
                    }
                }
            } while (count++ < 1);
        }

        /// <summary>
        /// Looks up a single secret by name.
        /// </summary>
        public object InvokeGetSecret(
            string name,
            string vaultName,
            PSCmdlet cmdlet)
        {
            var count = 0;
            do
            {
                try 
                {
                    if (!string.IsNullOrEmpty(this.ImplementingTypeName))
                    {
                        return InvokeGetSecretOnImplementingType(name, vaultName, cmdlet);
                    }
                    else
                    {
                        return InvokeGetSecretOnScriptFn(name, vaultName, cmdlet);
                    }
                }
                catch (PasswordRequiredException)
                {
                    if (!RegisteredVaultCache.Option.AllowPrompting || 
                        count > 0 ||
                        !TryPromptAndUnlockVault(vaultName, cmdlet))
                    {
                        throw;
                    }
                }
            } while (count++ < 1);

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
            var count = 0;
            do
            {
                try
                {
                    if (!string.IsNullOrEmpty(this.ImplementingTypeName))
                    {
                        InvokeRemoveSecretOnImplementingType(name, vaultName, cmdlet);
                    }
                    else
                    {
                        InvokeRemoveSecretOnScriptFn(name, vaultName, cmdlet);
                    }
                }
                catch (PasswordRequiredException)
                {
                    if (!RegisteredVaultCache.Option.AllowPrompting || 
                        count > 0 ||
                        !TryPromptAndUnlockVault(vaultName, cmdlet))
                    {
                        throw;
                    }
                }
            }
            while (count++ < 1);
        }

        public SecretInformation[] InvokeGetSecretInfo(
            string filter,
            string vaultName,
            PSCmdlet cmdlet)
        {
            var count = 0;
            do
            {
                try
                {
                    if (!string.IsNullOrEmpty(this.ImplementingTypeName))
                    {
                        return InvokeGetSecretInfoOnImplementingType(filter, vaultName, cmdlet);
                    }
                    else
                    {
                        return InvokeGetSecretInfoOnScriptFn(filter, vaultName, cmdlet);
                    }
                }
                catch (PasswordRequiredException)
                {
                    if (!RegisteredVaultCache.Option.AllowPrompting || 
                        count > 0 ||
                        !TryPromptAndUnlockVault(vaultName, cmdlet))
                    {
                        throw;
                    }
                }
            }
            while (count++ < 1);

            return new SecretInformation[0];
        }

        public bool InvokeTestVault(
            string vaultName,
            PSCmdlet cmdlet)
        {
            var count = 0;
            do
            {
                try
                {
                    if (!string.IsNullOrEmpty(this.ImplementingTypeName))
                    {
                        return InvokeTestVaultOnImplementingType(vaultName, cmdlet);
                    }
                    else
                    {
                        return InvokeTestVaultOnScriptFn(vaultName, cmdlet);
                    }
                }
                catch (PasswordRequiredException)
                {
                    if (!RegisteredVaultCache.Option.AllowPrompting || 
                        count > 0 ||
                        !TryPromptAndUnlockVault(vaultName, cmdlet))
                    {
                        throw;
                    }
                }
            }
            while (count++ < 1);

            return false;
        }

        public bool InvokeUnlockVault(
            SecureString vaultKey,
            string vaultName,
            PSCmdlet cmdlet)
        {
            if (vaultKey == null) { return false; }

            if (!string.IsNullOrEmpty(this.ImplementingTypeName))
            {
                return InvokeUnlockVaultOnImplementingType(vaultKey, vaultName, cmdlet);
            }
            else
            {
                return InvokeUnlockVaultOnScriptFn(vaultKey, vaultName, cmdlet);
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

        #region Implementing type implementation

        private void InvokeSetSecretOnImplementingType(
            string name,
            object secret,
            string vaultName,
            PSCmdlet cmdlet)
        {
            // Ensure the module has been imported so that the extension
            // binary assembly is loaded.
            ImportPSModule(cmdlet);

            bool success = false;
            Exception error = null;

            try
            {
                success = _vaultExtentsion.Value.SetSecret(
                    name: name,
                    secret: secret,
                    vaultName: vaultName,
                    additionalParameters: VaultParameters,
                    out error);
            }
            catch (PasswordRequiredException)
            {
                throw;
            }
            catch (Exception ex)
            {
                error = ex;
            }

            if (!success || error != null)
            {
                if (error == null)
                {
                    var msg = string.Format(
                        CultureInfo.InvariantCulture, 
                        "Could not add secret {0} to vault {1}.",
                        name, VaultName);

                    error = new InvalidOperationException(msg);
                }

                cmdlet.WriteError(
                    new ErrorRecord(
                        error,
                        "InvokeSetSecretError",
                        ErrorCategory.InvalidOperation,
                        this));
            }
            else
            {
                cmdlet.WriteVerbose(
                    string.Format("Secret {0} was successfully added to vault {1}.", name, VaultName));
            }
        }

        private object InvokeGetSecretOnImplementingType(
            string name,
            string vaultName,
            PSCmdlet cmdlet)
        {
            // Ensure the module has been imported so that the extension
            // binary assembly is loaded.
            ImportPSModule(cmdlet);

            object secret = null;
            Exception error = null;
            
            try
            {
                secret = _vaultExtentsion.Value.GetSecret(
                    name: name,
                    vaultName: vaultName,
                    additionalParameters: VaultParameters,
                    out error);
            }
            catch (PasswordRequiredException)
            {
                throw;
            }
            catch (Exception ex)
            {
                error = ex;
            }

            if (error != null)
            {
                cmdlet.WriteError(
                    new ErrorRecord(
                        error,
                        "InvokeGetSecretError",
                        ErrorCategory.InvalidOperation,
                        this));
            }

            return secret;
        }

        private void InvokeRemoveSecretOnImplementingType(
            string name,
            string vaultName,
            PSCmdlet cmdlet)
        {
            // Ensure the module has been imported so that the extension
            // binary assembly is loaded.
            ImportPSModule(cmdlet);

            var success = false;
            Exception error = null;

            try
            {
                success = _vaultExtentsion.Value.RemoveSecret(
                    name: name,
                    vaultName: vaultName,
                    additionalParameters: VaultParameters,
                    out error);
            }
            catch (PasswordRequiredException)
            {
                throw;
            }
            catch (Exception ex)
            {
                error = ex;
            }

            if (!success || error != null)
            {
                if (error == null)
                {
                    var msg = string.Format(
                        CultureInfo.InvariantCulture, 
                        "Could not remove secret {0} from vault {1}.",
                        name, VaultName);

                    error = new InvalidOperationException(msg);
                }

                cmdlet.WriteError(
                    new ErrorRecord(
                        error,
                        "InvokeRemoveSecretError",
                        ErrorCategory.InvalidOperation,
                        this));
            }
            else
            {
                cmdlet.WriteVerbose(
                    string.Format("Secret {0} was successfully removed from vault {1}.", name, VaultName));
            }
        }

        private SecretInformation[] InvokeGetSecretInfoOnImplementingType(
            string filter,
            string vaultName,
            PSCmdlet cmdlet)
        {
            // Ensure the module has been imported so that the extension
            // binary assembly is loaded.
            ImportPSModule(cmdlet);

            SecretInformation[] results = null;
            Exception error = null;

            try
            {
                results = _vaultExtentsion.Value.GetSecretInfo(
                    filter: filter,
                    vaultName: vaultName,
                    additionalParameters: VaultParameters,
                    out error);
            }
            catch (PasswordRequiredException)
            {
                throw;
            }
            catch (Exception ex)
            {
                error = ex;
            }
            
            if (error != null)
            {
                cmdlet.WriteError(
                    new ErrorRecord(
                        error,
                        "InvokeGetSecretInfoError",
                        ErrorCategory.InvalidOperation,
                        this));
            }

            return results;
        }

        private bool InvokeUnlockVaultOnImplementingType(
            SecureString vaultKey,
            string vaultName,
            PSCmdlet cmdlet)
        {
            // Ensure the module has been imported so that the extension
            // binary assembly is loaded.
            ImportPSModule(cmdlet);

            Exception error = null;
            try
            {
                return _vaultExtentsion.Value.UnlockSecretVault(
                    vaultKey: vaultKey,
                    vaultName: vaultName,
                    out error);
            }
            catch (Exception ex)
            {
                error = ex;
            }

            if (error != null)
            {
                cmdlet.WriteError(
                    new ErrorRecord(
                        error,
                        "InvokeUnlockVaultError",
                        ErrorCategory.InvalidOperation,
                        this));
            }

            return false;
        }

        private bool InvokeTestVaultOnImplementingType(
            string vaultName,
            PSCmdlet cmdlet)
        {
            // Ensure the module has been imported so that the extension
            // binary assembly is loaded.
            ImportPSModule(cmdlet);

            Exception[] errors;
            bool success;

            try
            {
                success = _vaultExtentsion.Value.TestSecretVault(
                    vaultName: vaultName,
                    additionalParameters: VaultParameters,
                    errors: out errors);
            }
            catch (PasswordRequiredException)
            {
                throw;
            }
            catch (Exception ex)
            {
                success = false;
                errors = new Exception[1] { ex };
            }

            if (errors != null)
            {
                foreach (var error in errors)
                {
                    cmdlet.WriteError(
                        new ErrorRecord(
                            exception: error,
                            errorId: "TestVaultInvalidOperation",
                            errorCategory: ErrorCategory.InvalidOperation,
                            targetObject: null));
                }
            }

            return success;
        }

        #endregion

        #region Script function implementation

        private const string RunCommandScript = @"
            param (
                [string] $ModulePath,
                [string] $ModuleName,
                [string] $Command,
                [hashtable] $Params
            )
        
            Import-Module -Name $ModulePath
            & ""$ModuleName\$Command"" @Params
        ";

        private void InvokeSetSecretOnScriptFn(
            string name,
            object secret,
            string vaultName,
            PSCmdlet cmdlet)
        {
            var additionalParameters = GetAdditionalParams();
            var parameters = new Hashtable() {
                { "Name", name },
                { "Secret", secret },
                { "VaultName", vaultName },
                { "AdditionalParameters", additionalParameters }
            };

            var implementingModulePath = System.IO.Path.Combine(ModulePath, RegisterSecretVaultCommand.ImplementingModule);
            var results = PowerShellInvoker.InvokeScript<bool>(
                script: RunCommandScript,
                args: new object[] { implementingModulePath, RegisterSecretVaultCommand.ImplementingModule, SetSecretCmd, parameters },
                error: out Exception error);

            bool success = results.Count > 0 ? results[0] : false;
            
            if (!success || error != null)
            {
                cmdlet.WriteError(
                    new ErrorRecord(
                        error,
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

        private object InvokeGetSecretOnScriptFn(
            string name,
            string vaultName,
            PSCmdlet cmdlet)
        {
            var additionalParameters = GetAdditionalParams();
            var parameters = new Hashtable() {
                { "Name", name },
                { "VaultName", vaultName },
                { "AdditionalParameters", additionalParameters }
            };

            var implementingModulePath = System.IO.Path.Combine(ModulePath, RegisterSecretVaultCommand.ImplementingModule);
            var results = PowerShellInvoker.InvokeScript<object>(
                script: RunCommandScript,
                args: new object[] { implementingModulePath, RegisterSecretVaultCommand.ImplementingModule, GetSecretCmd, parameters },
                error: out Exception error);
            
            if (error != null)
            {
                cmdlet.WriteError(
                    new ErrorRecord(
                        error,
                        "InvokeGetSecretError",
                        ErrorCategory.InvalidOperation,
                        this));
            }
            
            return results.Count > 0 ? results[0] : null;
        }

        private void InvokeRemoveSecretOnScriptFn(
            string name,
            string vaultName,
            PSCmdlet cmdlet)
        {
            var additionalParameters = GetAdditionalParams();
            var parameters = new Hashtable() {
                { "Name", name },
                { "VaultName", vaultName },
                { "AdditionalParameters", additionalParameters }
            };

            var implementingModulePath = System.IO.Path.Combine(ModulePath, RegisterSecretVaultCommand.ImplementingModule);
            var results = PowerShellInvoker.InvokeScript<bool>(
                script: RunCommandScript,
                args: new object[] { implementingModulePath, RegisterSecretVaultCommand.ImplementingModule, RemoveSecretCmd, parameters },
                error: out Exception error);

            bool success = results.Count > 0 ? results[0] : false;
            if (!success || error != null)
            {
                cmdlet.WriteError(
                    new ErrorRecord(
                        error,
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

        private SecretInformation[] InvokeGetSecretInfoOnScriptFn(
            string filter,
            string vaultName,
            PSCmdlet cmdlet)
        {
            var additionalParameters = GetAdditionalParams();
            var parameters = new Hashtable() {
                { "Filter", filter },
                { "VaultName", vaultName },
                { "AdditionalParameters", additionalParameters }
            };

            var implementingModulePath = System.IO.Path.Combine(ModulePath, RegisterSecretVaultCommand.ImplementingModule);
            var results = PowerShellInvoker.InvokeScript<SecretInformation>(
                script: RunCommandScript,
                args: new object[] { implementingModulePath, RegisterSecretVaultCommand.ImplementingModule, GetSecretInfoCmd, parameters },
                error: out Exception error);
            
            if (error != null)
            {
                cmdlet.WriteError(
                    new ErrorRecord(
                        error,
                        "GetSecretInvalidOperation",
                        ErrorCategory.InvalidOperation,
                        this));
            }

            var secretInfo = new SecretInformation[results.Count];
            results.CopyTo(secretInfo, 0);
            return secretInfo;
        }

        private bool InvokeUnlockVaultOnScriptFn(
            SecureString vaultKey,
            string vaultName,
            PSCmdlet cmdlet)
        {
            var additionalParameters = GetAdditionalParams();
            var parameters = new Hashtable() {
                { "VaultKey", vaultKey },
                { "VaultName", vaultName },
                { "AdditionalParameters", additionalParameters }
            };

            var implementingModulePath = System.IO.Path.Combine(ModulePath, RegisterSecretVaultCommand.ImplementingModule);
            var results = PowerShellInvoker.InvokeScript<bool>(
                script: RunCommandScript,
                args: new object[] { implementingModulePath, RegisterSecretVaultCommand.ImplementingModule, UnlockVaultCmd, parameters },
                error: out Exception error);
            
            bool success = results.Count > 0 ? results[0] : false;
            if (!success || error != null)
            {
                cmdlet.WriteError(
                    new ErrorRecord(
                        error,
                        "RemoveSecretInvalidOperation",
                        ErrorCategory.InvalidOperation,
                        this));
            }
            else
            {
                cmdlet.WriteVerbose(
                    string.Format("Vault {0} was successfully unlocked.", VaultName));
            }

            return success;
        }

        private bool InvokeTestVaultOnScriptFn(
            string vaultName,
            PSCmdlet cmdlet)
        {
            var additionalParameters = GetAdditionalParams();
            var parameters = new Hashtable() {
                { "VaultName", VaultName },
                { "AdditionalParameters", additionalParameters }
            };

            var implementingModulePath = System.IO.Path.Combine(ModulePath, RegisterSecretVaultCommand.ImplementingModule);
            ErrorRecord[] errors = null;
            var results = PowerShellInvoker.InvokeScript<bool>(
                script: RunCommandScript,
                args: new object[] { implementingModulePath, RegisterSecretVaultCommand.ImplementingModule, TestVaultCmd, parameters },
                errors: out errors);
            
            foreach (var error in errors)
            {
                cmdlet.WriteError(error);
            }

            return (results.Count > 0) ? results[0] : false;
        }

        #endregion

        #region Private methods

        private bool TryPromptAndUnlockVault(
            string vaultName,
            PSCmdlet cmdlet)
        {
            var promptMessage = string.Format(CultureInfo.InvariantCulture,
                VaultPaswordPrompt, vaultName);

            var vaultKey = Utils.PromptForPassword(
                cmdlet: cmdlet,
                verifyPassword: false,
                message: promptMessage);

            return InvokeUnlockVault(vaultKey, vaultName, cmdlet);
        }
        
        internal void ImportPSModule(PSCmdlet cmdlet)
        {
            cmdlet.InvokeCommand.InvokeScript(
                script: @"
                    param ([string] $ModulePath)

                    Import-Module -Name $ModulePath -Scope Local
                ",
                useNewScope: false,
                writeToPipeline: System.Management.Automation.Runspaces.PipelineResultTypes.None,
                input: null,
                args: new object[] { this.ModulePath });
        }

        private Hashtable GetAdditionalParams()
        {
            var additionalParams = new Hashtable();
            foreach (var item in VaultParameters)
            {
                additionalParams.Add(
                    key: item.Key,
                    value: item.Value);
            }

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

        private static readonly string RegistryDirectoryPath = Path.Combine(Utils.SecretManagementLocalPath, "secretvaultregistry");
        private static readonly string RegistryFilePath = Path.Combine(RegistryDirectoryPath, "vaultinfo");

        #endregion

        private static readonly FileSystemWatcher _registryWatcher;
        private static readonly Dictionary<string, ExtensionVaultModule> _vaultCache;
        private static Hashtable _vaultInfoCache;
        private static string _defaultVaultName = "";
        private static bool _allowAutoRefresh;
        private static bool _allowPrompting;

        #endregion

        #region Properties

        /// <summary>
        /// Gets a dictionary of registered vault extensions, sorted by vault name.
        /// </summary>
        public static SortedDictionary<string, ExtensionVaultModule> VaultExtensions
        {
            get 
            {
                lock (_vaultInfoCache)
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
            get
            {
                return _defaultVaultName;
            }
        }

        public static SecretManagementOption Option
        {
            get
            {
                return new SecretManagementOption(_allowPrompting);
            }
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
            lock (_vaultInfoCache)
            {
                var vaultItems = (Hashtable) _vaultInfoCache.Clone();
                return vaultItems;
            }
        }

        /// <summary>
        /// Add item to cache.
        /// </summary>
        /// <param name="vaultInfo">Hashtable of vault information.</param>
        /// <param name="defaultName">When true, this vault is designated as the default vault.</param>
        /// <returns>True when item is successfully added.</returns>
        public static bool Add(
            string keyName,
            Hashtable vaultInfo,
            bool defaultVault)
        {
            var vaultItems = GetAll();
            if (!vaultItems.ContainsKey(keyName))
            {
                vaultItems.Add(keyName, vaultInfo);
                _defaultVaultName = defaultVault ? keyName : _defaultVaultName;
                WriteSecretVaultRegistry(
                    vaultInfo: vaultItems,
                    defaultVaultName: _defaultVaultName,
                    allowPrompting: _allowPrompting);
                return true;
            }

            return false;
        }

        public static void SetDefaultVault(
            string vaultName)
        {
            if (!VaultExtensions.TryGetValue(
                key: vaultName,
                value: out ExtensionVaultModule vault))
            {
                throw new ItemNotFoundException("Vault name was not found.");
            }

            _defaultVaultName = vault.VaultName;
            WriteSecretVaultRegistry(
                vaultInfo: GetAll(),
                defaultVaultName: _defaultVaultName,
                allowPrompting: _allowPrompting);
        }

        public static void SetOption(
            SecretManagementOption option)
        {
            WriteSecretVaultRegistry(
                vaultInfo: GetAll(),
                defaultVaultName: _defaultVaultName,
                allowPrompting: option.AllowPrompting);
        }

        /// <summary>
        /// Remove item from cache.
        /// </summary>
        /// <param name="keyName">Name of item to remove.</param>
        /// <returns>Vault informmation that was removed.</returns>
        public static Hashtable Remove(string keyName)
        {
            var vaultItems = GetAll();
            if (vaultItems.ContainsKey(keyName))
            {
                Hashtable vaultInfo = (Hashtable) vaultItems[keyName];
                vaultItems.Remove(keyName);
                WriteSecretVaultRegistry(
                    vaultInfo: vaultItems,
                    defaultVaultName: _defaultVaultName.Equals(keyName, StringComparison.OrdinalIgnoreCase) ? string.Empty : _defaultVaultName,
                    allowPrompting: _allowPrompting);
                return vaultInfo;
            }

            return null;
        }

        #endregion

        #region Private methods

        //
        // Vault registry json example:
        //
        /*
        {
          "AllowPrompting": true,
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
                defaultVaultName: out _defaultVaultName,
                allowPrompting: out _allowPrompting))
            {
                return;
            }

            try
            {
                lock (_vaultInfoCache)
                {
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
        /// <param name="allowPrompting">Specifies whether user prompting is allowed.</param>
        /// <returns>True if file is successfully read and converted from json.</returns>
        private static bool TryReadSecretVaultRegistry(
            out Hashtable vaultInfo,
            out string defaultVaultName,
            out bool allowPrompting)
        {
            vaultInfo = null;
            defaultVaultName = "";
            allowPrompting = true;

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
                    defaultVaultName = (string) registryInfo["DefaultVaultName"];
                    allowPrompting = (bool) registryInfo["AllowPrompting"];
                    vaultInfo = (Hashtable) registryInfo["Vaults"];
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
        /// <param name="allowPrompting">Indicates if user prompting is allowed.</param>
        /// </summary>
        private static void WriteSecretVaultRegistry(
            Hashtable vaultInfo,
            string defaultVaultName,
            bool allowPrompting)
        {
            var registryInfo = new Hashtable()
            {
                { "DefaultVaultName", defaultVaultName },
                { "AllowPrompting", allowPrompting },
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
            out ErrorRecord[] errors)
        {
            using (var powerShell = System.Management.Automation.PowerShell.Create())
            {
                powerShell.Commands.Clear();
                Collection<T> results;
                try
                {
                    results = powerShell.AddScript(script).AddParameters(args).Invoke<T>();
                    errors = new ErrorRecord[powerShell.Streams.Error.Count];
                    powerShell.Streams.Error.CopyTo(errors, 0);
                }
                catch (Exception ex)
                {
                    if (ex is PasswordRequiredException)
                    {
                        throw;
                    }

                    errors = new ErrorRecord[1] {
                        new ErrorRecord(
                            exception: ex,
                            errorId: "PowerShellInvokerInvalidOperation",
                            errorCategory: ErrorCategory.InvalidOperation,
                            targetObject: null)
                    };
                    results = new Collection<T>();
                }

                return results;
            }
        }

        public static Collection<T> InvokeScript<T>(
            string script,
            object[] args,
            out Exception error)
        {
            var results = InvokeScript<T>(
                script,
                args,
                out ErrorRecord[] errors);
            
            error = (errors.Length > 0) ? errors[0].Exception : null;
            return results;
        }

        public static Collection<T> InvokeScriptCommon<T>(
            string script,
            object[] args,
            out ErrorRecord error)
        {
            Collection<T> results;
            try
            {
                results = _powershell.AddScript(script).AddParameters(args).Invoke<T>();
                error = (_powershell.Streams.Error.Count > 0) ? _powershell.Streams.Error[0] : null;
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
                _powershell.Commands.Clear();
            }

            return results;
        }

        #endregion
    }

    #endregion
}
