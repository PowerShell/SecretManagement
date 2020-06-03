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
using System.Security.Cryptography;
using System.Text;
using System.Threading;

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

        public static PSObject ConvertJsonToPSObject(string json)
        {
            var results = PowerShellInvoker.InvokeScriptCommon<PSObject>(
                script: @"param ([string] $json) ConvertFrom-Json -InputObject $json",
                args: new object[] { json },
                error: out ErrorRecord _);

            return (results.Count > 0) ? results[0] : null;
        }

        public static string ConvertHashtableToJson(Hashtable hashtable)
        {
            var results = PowerShellInvoker.InvokeScriptCommon<string>(
                script: @"param ([hashtable] $hashtable) ConvertTo-Json -InputObject $hashtable",
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

        public static bool GetSecureStringFromData(
            byte[] data,
            out SecureString outSecureString)
        {
            if ((data.Length % 2) != 0)
            {
                Dbg.Assert(false, "Blob length for SecureString secure must be even.");
                outSecureString = null;
                return false;
            }

            outSecureString = new SecureString();
            var strLen = data.Length / 2;
            for (int i=0; i < strLen; i++)
            {
                int index = (2 * i);

                var ch = (char)(data[index + 1] * 256 + data[index]);
                outSecureString.AppendChar(ch);
            }

            return true;
        }

        public static bool GetDataFromSecureString(
            SecureString secureString,
            out byte[] data)
        {
            IntPtr ptr = Marshal.SecureStringToCoTaskMemUnicode(secureString);

            if (ptr != IntPtr.Zero)
            {
                try
                {
                    data = new byte[secureString.Length * 2];
                    Marshal.Copy(ptr, data, 0, data.Length);
                    return true;
                }
                finally
                {
                    Marshal.ZeroFreeCoTaskMemUnicode(ptr);
                }
            }

            data = null;
            return false;
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
                    "A password is required for Secret Management module local store"
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

    #region SecureStore

    internal static class CryptoUtils
    {
        #region Public methods

        public static byte[] GenerateKey()
        {
            using (var aes = Aes.Create())
            {
                return aes.Key;
            }
        }

        public static byte[] EncryptWithKey(
            SecureString passWord,
            byte[] key,
            byte[] data)
        {
            var keyToUse = (passWord != null) ?
                DeriveFromKey(passWord, key) :
                key;

            using (var aes = Aes.Create())
            {
                aes.IV = new byte[16];      // Set IV to zero
                aes.Key = keyToUse;
                using (var encryptor = aes.CreateEncryptor())
                using (var sourceStream = new MemoryStream(data))
                using (var targetStream = new MemoryStream())
                {
                    using (var cryptoStream = new CryptoStream(targetStream, encryptor, CryptoStreamMode.Write))
                    {
                        sourceStream.CopyTo(cryptoStream);
                    }

                    return targetStream.ToArray();
                }
            }
        }

        public static byte[] DecryptWithKey(
            SecureString passWord,
            byte[] key,
            byte[] data)
        {
            var keyToUse = (passWord != null) ?
                DeriveFromKey(passWord, key) :
                key;
            
            using (var aes = Aes.Create())
            {
                aes.IV = new byte[16];      // Set IV to zero
                aes.Key = keyToUse;
                using (var decryptor = aes.CreateDecryptor())
                using (var sourceStream = new MemoryStream(data))
                using (var targetStream = new MemoryStream())
                {
                    using (var cryptoStream = new CryptoStream(sourceStream, decryptor, CryptoStreamMode.Read))
                    {
                        try
                        {
                            cryptoStream.CopyTo(targetStream);
                        }
                        catch (CryptographicException)
                        {
                            throw new SecureStorePasswordException();
                        }
                    }

                    return targetStream.ToArray();
                }
            }
        }

        public static void ZeroOutData(byte[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                data[i] = 0;
            }
        }

        #endregion

        #region Private methods

        private static byte[] DeriveFromKey(
            SecureString passWord,
            byte[] key)
        {
            var passWordData = GetDataFromSecureString(passWord);
            try
            {
                var derivedBytes = new Rfc2898DeriveBytes(passWordData, key, 1000);
                return derivedBytes.GetBytes(key.Length);
            }
            finally
            {
                ZeroOutData(passWordData);
            }
        }

        private static byte[] GetDataFromSecureString(SecureString secureString)
        {
            IntPtr ptr = Marshal.SecureStringToCoTaskMemUnicode(secureString);
            if (ptr == IntPtr.Zero)
            {
                throw new InvalidOperationException("Unable to read secure string.");
            }

            try
            {
                var data = new byte[secureString.Length * 2];
                Marshal.Copy(ptr, data, 0, data.Length);
                return data;
            }
            finally
            {
                Marshal.ZeroFreeCoTaskMemUnicode(ptr);
            }
        }

        #endregion
    }

    public enum SecureStoreScope
    {
        CurrentUser = 1,
        AllUsers
    }

    internal sealed class SecureStoreConfig
    {
        #region Properties

        public SecureStoreScope Scope 
        {
            get;
            private set;
        }

        public bool PasswordRequired
        {
            get;
            private set;
        }

        /// <Summary>
        /// Password timeout time in seconds
        /// </Summary>
        public int PasswordTimeout
        {
            get;
            private set;
        }

        public bool DoNotPrompt
        {
            get;
            private set;
        }

        #endregion

        #region Constructor

        private SecureStoreConfig()
        {
        }

        public SecureStoreConfig(
            SecureStoreScope scope,
            bool passwordRequired,
            int passwordTimeout,
            bool doNotPrompt)
        {
            Scope = scope;
            PasswordRequired = passwordRequired;
            PasswordTimeout = passwordTimeout;
            DoNotPrompt = doNotPrompt;
        }

        public SecureStoreConfig(
            string json)
        {
            ConvertFromJson(json);
        }

        #endregion

        # region Public methods

        public string ConvertToJson()
        {
            // Config data
            var configHashtable = new Hashtable();
            configHashtable.Add(
                key: "StoreScope",
                value: Scope);
            configHashtable.Add(
                key: "PasswordRequired",
                value: PasswordRequired);
            configHashtable.Add(
                key: "PasswordTimeout",
                value: PasswordTimeout);
            configHashtable.Add(
                key: "DoNotPrompt",
                value: DoNotPrompt);

            var dataDictionary = new Hashtable();
            dataDictionary.Add(
                key: "ConfigData",
                value: configHashtable);

            return Utils.ConvertHashtableToJson(dataDictionary);
        }

        #endregion

        #region Private methods

        private void ConvertFromJson(string json)
        {
            dynamic configDataObj = (Utils.ConvertJsonToPSObject(json));
            Scope = (SecureStoreScope) configDataObj.ConfigData.StoreScope;
            PasswordRequired = (bool) configDataObj.ConfigData.PasswordRequired;
            PasswordTimeout = (int) configDataObj.ConfigData.PasswordTimeout;
            DoNotPrompt = (bool) configDataObj.ConfigData.DoNotPrompt;
        }

        #endregion

        #region Static methods

        public static SecureStoreConfig GetDefault()
        {
            return new SecureStoreConfig(
                scope: SecureStoreScope.CurrentUser,
                passwordRequired: true,
                passwordTimeout: 900,
                doNotPrompt: false);
        }

        #endregion
    }

    internal sealed class SecureStoreMetadata
    {
        #region Properties

        public string Name
        {
            get;
            private set;
        }

        public string TypeName
        {
            get;
            private set;
        }

        public int Offset
        {
            get;
            set;
        }

        public int Size
        {
            get;
            private set;
        }

        public ReadOnlyDictionary<string, object> Attributes
        {
            get;
            private set;
        }

        #endregion

        #region Constructor

        private SecureStoreMetadata()
        {
        }

        public SecureStoreMetadata(
            string name,
            string typeName,
            int offset,
            int size,
            ReadOnlyDictionary<string, object> attributes)
        {
            Name = name;
            TypeName = typeName;
            Offset = offset;
            Size = size;
            Attributes = attributes;
        }

        #endregion
    }

    internal sealed class SecureStoreData
    {
        #region Properties

        internal byte[] Key { get; set; }
        internal byte[] Blob { get; set; }
        internal Dictionary<string, SecureStoreMetadata> MetaData { get; set; }

        #endregion

        #region Constructor

        public SecureStoreData()
        {
        }

        public SecureStoreData(
            byte[] key,
            string json,
            byte[] blob)
        {
            Key = key;
            Blob = blob;
            ConvertJsonToMeta(json);
        }

        #endregion
        
        #region Public methods

        // Example of store data as Hashtable
        /*
        @{
        ConfigData =
            @{
                StoreScope='LocalScope'
                PasswordRequired=$true
                PasswordTimeout=-1,
                DoNotPrompt=$false
            }
            MetaData =
            @(
                @{Name='TestSecret1'; Type='SecureString'; Offset=14434; Size=5000; Attributes=@{}}
                @{Name='TestSecret2'; Type='String'; Offset=34593; Size=5100; Attributes=@{}}
                @{Name='TestSecret3'; Type='PSCredential'; Offset=59837; Size=4900; Attributes=@{UserName='UserA'}}
                @{Name='TestSecret4'; Type='Hashtable'; Offset=77856; Size=3500; Attributes=@{Element1='SecretElement1'; Element2='SecretElement2'}}
            )
        }
        */

        public string ConvertMetaToJson()
        {
            // Meta data array
            var listMetadata = new List<Hashtable>(MetaData.Count);
            foreach (var item in MetaData.Values)
            {
                var metaHashtable = new Hashtable();
                metaHashtable.Add(
                    key: "Name",
                    value: item.Name);
                metaHashtable.Add(
                    key: "Type",
                    value: item.TypeName);
                metaHashtable.Add(
                    key: "Offset",
                    value: item.Offset);
                metaHashtable.Add(
                    key: "Size",
                    value: item.Size);
                metaHashtable.Add(
                    key: "Attributes",
                    value: item.Attributes);
                
                listMetadata.Add(metaHashtable);
            }
            
            var dataDictionary = new Hashtable();
            dataDictionary.Add(
                key: "MetaData",
                value: listMetadata.ToArray());
            
            return Utils.ConvertHashtableToJson(dataDictionary);
        }

        public void Clear()
        {
            if (Key != null)
            {
                CryptoUtils.ZeroOutData(Key);
            }

            if (Blob != null)
            {
                CryptoUtils.ZeroOutData(Blob);
            }

            if (MetaData != null)
            {
                MetaData.Clear();
            }
        }

        #endregion

        #region Static methods

        public static SecureStoreData CreateEmpty()
        {
            return new SecureStoreData()
            {
                Key = CryptoUtils.GenerateKey(),
                Blob = new byte[0],
                MetaData = new Dictionary<string, SecureStoreMetadata>(StringComparer.InvariantCultureIgnoreCase)
            };
        }

        #endregion

        #region Private methods

        // Example meta data json
        /*
            "MetaData": [
            {
                "Name": "TestSecret1",
                "Type": "String",
                "Offset": 34593,
                "Size": 3500,
                "Attributes": {}
            },
            {
                "Name": "TestSecret2",
                "Type": "PSCredential",
                "Offset": 59837,
                "Size": 4200,
                "Attributes": {
                    "UserName": "UserA"
                },
            }
            ]
        }
        */

        private void ConvertJsonToMeta(string json)
        {
            dynamic data = Utils.ConvertJsonToPSObject(json);

            // Validate
            if (data == null)
            {
                throw new InvalidDataException("The data from the local secure store is unusable.");
            }

            // Meta data
            dynamic metaDataArray = data.MetaData;
            MetaData = new Dictionary<string, SecureStoreMetadata>(
                metaDataArray.Length,
                StringComparer.CurrentCultureIgnoreCase);
            foreach (var item in metaDataArray)
            {
                var attributesDictionary = new Dictionary<string, object>();
                var attributes = item.Attributes;
                foreach (var prop in ((PSObject)attributes).Properties)
                {
                    attributesDictionary.Add(
                        key: prop.Name,
                        value: prop.Value);
                }

                MetaData.Add(
                    key: item.Name,
                    value: new SecureStoreMetadata(
                        name: item.Name,
                        typeName: item.Type,
                        offset: (int) item.Offset,
                        size: (int) item.Size,
                        attributes: new ReadOnlyDictionary<string, object>(attributesDictionary)));
            }
        }

        #endregion
    }

    internal sealed class SecureStorePasswordException : InvalidOperationException
    {
        #region Constructor

        public SecureStorePasswordException()
            : base("Password is required to access local store.")
        {
        }

        public SecureStorePasswordException(string msg)
            : base(msg)
        {
        }

        #endregion
    }

    internal sealed class SecureStore : IDisposable
    {
        #region Members

        private SecureString _password;
        private SecureStoreData _data;
        private SecureStoreConfig _configData;
        private Timer _passwordTimer;
        private readonly object _syncObject = new object();
        private static TimeSpan _updateDelay = TimeSpan.FromSeconds(5);

        #endregion

        #region Properties

        public SecureStoreData Data => _data;

        public SecureStoreConfig ConfigData => _configData;

        internal SecureString Password
        {
            get 
            {
                lock (_syncObject)
                {
                    if (ConfigData.PasswordRequired && (_password == null))
                    {
                        throw new SecureStorePasswordException();
                    }

                    return (_password != null) ? _password.Copy() : null;
                }
            }
        }

        #endregion

        #region Constructor

        public SecureStore(
            SecureStoreData data,
            SecureStoreConfig configData,
            SecureString password = null)
        {
            _data = data;
            _configData = configData;
            SetPassword(password);

            SecureStoreFile.DataUpdated += (sender, args) => HandleDataUpdateEvent(sender, args);
            SecureStoreFile.ConfigUpdated += (sender, args) => HandleConfigUpdateEvent(sender, args);
        }

        #endregion

        #region Events

        public event EventHandler<EventArgs> StoreConfigUpdated;
        private void RaiseStoreConfigUpdatedEvent()
        {
            if (StoreConfigUpdated != null)
            {
                StoreConfigUpdated.Invoke(this, null);
            }
        }

        #endregion

        #region IDisposable

        public void Dispose()
        {
            _passwordTimer?.Dispose();
            _password?.Clear();
            _data?.Clear();
        }

        #endregion
        
        #region Public methods

        /// <summary>
        /// Sets the current session password, and resets the password timeout.
        /// </summary>
        public void SetPassword(SecureString password)
        {
            if (password != null)
            {
                VerifyPasswordRequired();
            }

            lock (_syncObject)
            {
                _password = password;
                if (password != null)
                {
                    SetPasswordTimer(_configData.PasswordTimeout);
                }
            }
        }

        public void SetPasswordTimer(int timeoutSecs)
        {
            if (_passwordTimer != null)
            {
                _passwordTimer.Dispose();
                _passwordTimer = null;
            }

            if (timeoutSecs > 0)
            {
                _passwordTimer = new Timer(
                    callback: (_) => 
                        { 
                            lock (_syncObject)
                            {
                                _password = null;
                            }
                        },
                    state: null,
                    dueTime: timeoutSecs * 1000,
                    period: Timeout.Infinite);
            }
        }

        /// <summary>
        /// Updates the store password to the new value provided.
        /// Re-encrypts secret data and store file with new password.
        /// </summary>
        public void UpdatePassword(
            SecureString newpassword,
            SecureString oldPassword,
            bool skipPasswordRequiredCheck)
        {
            if (!skipPasswordRequiredCheck)
            {
                VerifyPasswordRequired();
            }

            lock (_syncObject)
            {
                // Verify password.
                var errorMsg = "";
                if (!SecureStoreFile.ReadFile(
                    oldPassword,
                    out SecureStoreData data,
                    ref errorMsg))
                {
                    throw new SecureStorePasswordException("Unable to access local store with provided oldPassword.");
                }

                // Re-encrypt blob data with new password.
                var newBlob = ReEncryptBlob(
                    newPassword: newpassword,
                    oldPassword: oldPassword,
                    metaData: data.MetaData,
                    key: data.Key,
                    blob: data.Blob,
                    outMetaData: out Dictionary<string, SecureStoreMetadata> newMetaData);

                // Write data to file with new password.
                var newData = new SecureStoreData()
                {
                    Key = data.Key,
                    Blob = newBlob,
                    MetaData = newMetaData
                };

                if (!SecureStoreFile.WriteFile(
                    password: newpassword,
                    data: newData,
                    errorMsg: ref errorMsg))
                {
                    throw new PSInvalidOperationException(
                        string.Format(CultureInfo.InvariantCulture,
                            @"Unable to update password with error: {0}",
                            errorMsg));
                }

                _data = newData;
                SetPassword(newpassword);

                // Password change is considered a configuration change.
                // Induce a configuration change event by writing to the config file.
                SecureStoreFile.WriteConfigFile(
                    configData: _configData,
                    ref errorMsg);
            }
        }

        public bool WriteBlob(
            string name,
            byte[] blob,
            string typeName,
            Dictionary<string, object> attributes,
            ref string errorMsg)
        {
            if (EnumerateBlobs(
                filter: name,
                metaData: out SecureStoreMetadata[] _,
                ref errorMsg))
            {
                return ReplaceBlobImpl(
                    name,
                    blob,
                    typeName,
                    attributes,
                    ref errorMsg);
            }

            return WriteBlobImpl(
                name,
                blob,
                typeName,
                attributes,
                ref errorMsg);
        }

        public bool ReadBlob(
            string name,
            out byte[] blob,
            out SecureStoreMetadata metaData,
            ref string errorMsg)
        {
            byte[] encryptedBlob = null;
            byte[] key = null;
            lock (_syncObject)
            {
                // Get blob
                if (!_data.MetaData.TryGetValue(
                    key: name,
                    value: out metaData))
                {
                    errorMsg = string.Format(
                        CultureInfo.InvariantCulture,
                        @"Unable to read item {0}.",
                        name);
                    blob = null;
                    metaData = null;
                    return false;
                }

                key = _data.Key;
                var offset = metaData.Offset;
                var size = metaData.Size;
                encryptedBlob = new byte[size];
                Buffer.BlockCopy(_data.Blob, offset, encryptedBlob, 0, size);
            }
            
            // Decrypt blob
            var password = Password;
            try
            {
                blob = CryptoUtils.DecryptWithKey(
                    passWord: password,
                    key: key,
                    data: encryptedBlob);
            }
            finally
            {
                if (password != null)
                {
                    password.Clear();
                }
            }

            return true;
        }

        public bool EnumerateBlobs(
            string filter,
            out SecureStoreMetadata[] metaData,
            ref string errorMsg)
        {
            var filterPattern = new WildcardPattern(
                pattern: filter,
                options: WildcardOptions.IgnoreCase);
            var foundBlobs = new List<SecureStoreMetadata>();

            lock (_syncObject)
            {
                foreach (var key in _data.MetaData.Keys)
                {
                    if (filterPattern.IsMatch(key))
                    {
                        var data = _data.MetaData[key];
                        foundBlobs.Add(
                            new SecureStoreMetadata(
                                name: data.Name,
                                typeName: data.TypeName,
                                offset: data.Offset,
                                size: data.Size,
                                attributes: data.Attributes));
                    }
                }
            }

            metaData = foundBlobs.ToArray();
            return (metaData.Length > 0);
        }

        public bool DeleteBlob(
            string name,
            ref string errorMsg)
        {
            lock (_syncObject)
            {
                if (!_data.MetaData.TryGetValue(
                    key: name,
                    value: out SecureStoreMetadata metaData))
                {
                    errorMsg = string.Format(
                        CultureInfo.InvariantCulture,
                        @"Unable to find item {0} for removal.",
                        name);
                    return false;
                }
                _data.MetaData.Remove(name);

                // Create new blob
                var oldBlob = _data.Blob;
                var offset = metaData.Offset;
                var size = metaData.Size;
                var newSize = (oldBlob.Length - size);
                var newBlob = new byte[newSize];
                Buffer.BlockCopy(oldBlob, 0, newBlob, 0, offset);
                Buffer.BlockCopy(oldBlob, (offset + size), newBlob, offset, (newSize - offset));
                _data.Blob = newBlob;
                CryptoUtils.ZeroOutData(oldBlob);

                // Fix up meta data offsets
                foreach (var metaItem in _data.MetaData.Values)
                {
                    if (metaItem.Offset > offset)
                    {
                        metaItem.Offset -= size;
                    }
                }
            }

            // Write to file
            var password = Password;
            try
            {
                return SecureStoreFile.WriteFile(
                    password: password,
                    data: _data,
                    ref errorMsg);
            }
            finally
            {
                if (password != null)
                {
                    password.Clear();
                }
            }
        }

        public bool UpdateConfigData(
            SecureStoreConfig newConfigData,
            PSCmdlet cmdlet,
            ref string errorMsg)
        {
            // First update the configuration information.
            SecureStoreConfig oldConfigData;
            lock (_syncObject)
            {
                oldConfigData = _configData;
                _configData = newConfigData;
            }
            if (!SecureStoreFile.WriteConfigFile(
                newConfigData,
                ref errorMsg))
            {
                lock(_syncObject)
                {
                    _configData = oldConfigData;
                }

                return false;
            }

            // If password requirement changed, then change password encryption as needed.
            if (oldConfigData.PasswordRequired != newConfigData.PasswordRequired)
            {
                bool success;
                try
                {
                    SecureString oldPassword;
                    SecureString newPassword;
                    if (newConfigData.PasswordRequired)
                    {
                        // Prompt for new password
                        oldPassword = null;
                        newPassword = Utils.PromptForPassword(
                            cmdlet: cmdlet,
                            verifyPassword: true,
                            message: "A password is now required for the local store configuration.\nTo complete the change please provide new password.");
                        
                        if (newPassword == null)
                        {
                            throw new PSInvalidOperationException("New password was not provided.");
                        }
                    }
                    else
                    {
                        // Prompt for old password
                        newPassword = null;
                        oldPassword = Utils.PromptForPassword(
                            cmdlet: cmdlet,
                            verifyPassword: false,
                            message: "A password is no longer required for the local store configuration.\nTo complete the change please provide the current password.");

                        if (oldPassword == null)
                        {
                            throw new PSInvalidOperationException("Old password was not provided.");
                        }
                    }

                    UpdatePassword(
                        newPassword,
                        oldPassword,
                        skipPasswordRequiredCheck: true);

                    success = true;
                }
                catch (Exception ex)
                {
                    errorMsg = string.Format(CultureInfo.InvariantCulture,
                        @"Unable to update local store data from configuration change with error: {0}",
                        ex.Message);
                    success = false;
                }

                if (!success)
                {
                    // Attempt to revert back to original configuration.
                    lock(_syncObject)
                    {
                        _configData = oldConfigData;
                    }

                    SecureStoreFile.WriteConfigFile(
                        oldConfigData,
                        ref errorMsg);

                    return false;
                }
            }
            else if ((oldConfigData.PasswordTimeout != newConfigData.PasswordTimeout) && (_password != null))
            {
                SetPasswordTimer(newConfigData.PasswordTimeout);
            }

            return true;
        }

        public void UpdateDataFromFile()
        {
            var errorMsg = "";
            SecureStoreData data;
            if (!SecureStoreFile.ReadFile(
                password: Password,
                data: out data,
                ref errorMsg))
            {
                data = SecureStoreData.CreateEmpty();
            }
            
            lock (_syncObject)
            {
                _data = data;
            }
        }

        #endregion

        #region Private methods

        private void UpdateConfigFromFile()
        {
            var errorMsg = "";
            if (!SecureStoreFile.ReadConfigFile(
                configData: out SecureStoreConfig configData,
                ref errorMsg))
            {
                throw new PSInvalidOperationException(errorMsg);
            }

            lock (_syncObject)
            {
                _configData = configData;
            }

            // Refresh secret data
            UpdateDataFromFile();
        }

        private void HandleConfigUpdateEvent(object sender, FileUpdateEventArgs args)
        {
            try
            {
                if ((args.FileChangedTime - SecureStoreFile.LastWriteTime) > _updateDelay)
                {
                    UpdateConfigFromFile();
                }

                RaiseStoreConfigUpdatedEvent();
            }
            catch
            {
            }
        }

        private void HandleDataUpdateEvent(object sender, FileUpdateEventArgs args)
        {
            try
            {
                if ((args.FileChangedTime - SecureStoreFile.LastWriteTime) > _updateDelay)
                {
                    UpdateDataFromFile();
                }
            }
            catch
            {
            }
        }

        private static byte[] ReEncryptBlob(
            SecureString newPassword,
            SecureString oldPassword,
            Dictionary<string, SecureStoreMetadata> metaData,
            byte[] key,
            byte[] blob,
            out Dictionary<string, SecureStoreMetadata> outMetaData)
        {
            if (blob.Length == 0)
            {
                outMetaData = metaData;
                return blob;
            }

            outMetaData = new Dictionary<string, SecureStoreMetadata>(metaData.Count, StringComparer.InvariantCultureIgnoreCase);
            List<byte> newBlobArray = new List<byte>(blob.Length);

            int offset = 0;
            foreach (var metaItem in metaData.Values)
            {
                var oldBlobItem = new byte[metaItem.Size];
                Buffer.BlockCopy(blob, metaItem.Offset, oldBlobItem, 0, metaItem.Size);
                var decryptedBlobItem = CryptoUtils.DecryptWithKey(
                    passWord: oldPassword,
                    key: key,
                    data: oldBlobItem);
                
                byte[] newBlobItem;
                try
                {
                    newBlobItem = CryptoUtils.EncryptWithKey(
                        passWord: newPassword,
                        key: key,
                        data: decryptedBlobItem);
                }
                finally
                {
                    CryptoUtils.ZeroOutData(decryptedBlobItem);
                }

                outMetaData.Add(
                    key: metaItem.Name,
                    value: new SecureStoreMetadata(
                        name: metaItem.Name,
                        typeName: metaItem.TypeName,
                        offset: offset,
                        size: newBlobItem.Length,
                        attributes: metaItem.Attributes));
                    
                newBlobArray.AddRange(newBlobItem);

                offset += newBlobItem.Length;
            }

            return newBlobArray.ToArray();
        }

        private bool WriteBlobImpl(
            string name,
            byte[] blob,
            string typeName,
            Dictionary<string, object> attributes,
            ref string errorMsg)
        {
            var password = Password;
            try
            {
                var newData = new SecureStoreData();
                newData.MetaData = _data.MetaData;
                newData.Key = _data.Key;

                // Encrypt blob
                var blobToWrite = CryptoUtils.EncryptWithKey(
                    passWord: password,
                    key: _data.Key,
                    data: blob);

                lock (_syncObject)
                {
                    // Create new store blob
                    var oldBlob = _data.Blob;
                    var offset = oldBlob.Length;
                    var newBlob = new byte[offset + blobToWrite.Length];
                    Buffer.BlockCopy(oldBlob, 0, newBlob, 0, offset);
                    Buffer.BlockCopy(blobToWrite, 0, newBlob, offset, blobToWrite.Length);
                    newData.Blob = newBlob;

                    // Create new meta item
                    newData.MetaData.Add(
                        key: name,
                        value: new SecureStoreMetadata(
                            name: name,
                            typeName: typeName,
                            offset: offset,
                            size: blobToWrite.Length,
                            attributes: new ReadOnlyDictionary<string, object>(attributes)));

                    // Update store data
                    _data = newData;
                    CryptoUtils.ZeroOutData(oldBlob);
                }

                // Write to file
                return SecureStoreFile.WriteFile(
                    password: password,
                    data: _data,
                    ref errorMsg);
            }
            finally
            {
                if (password != null)
                {
                    password.Clear();
                }
            }
        }

        private bool ReplaceBlobImpl(
            string name,
            byte[] blob,
            string typeName,
            Dictionary<string, object> attributes,
            ref string errorMsg)
        {
            lock (_syncObject)
            {
                // Remove old blob
                if (!DeleteBlob(
                    name: name,
                    ref errorMsg))
                {
                    errorMsg = "Unable to replace existing store item, error: " + errorMsg;
                    return false;
                }

                // Add new blob
                return WriteBlobImpl(
                    name: name,
                    blob: blob,
                    typeName: typeName,
                    attributes: attributes,
                    ref errorMsg);
            }
        }

        private void VerifyPasswordRequired()
        {
            if (!_configData.PasswordRequired)
            {
                throw new PSInvalidOperationException(
                    "The local store is not configured to use a password.");
            }
        }

        #endregion

        #region Static methods

        private static SecureStore GetDefault(
            SecureStoreConfig configData)
        {
            var data = SecureStoreData.CreateEmpty();

            return new SecureStore(
                data: data,
                configData: configData);
        }

        public static SecureStore GetStore(
            SecureString password)
        {
            string errorMsg = "";

            // Read config from file.
            SecureStoreConfig configData;
            if (!SecureStoreFile.ReadConfigFile(
                configData: out configData,
                errorMsg: ref errorMsg))
            {
                if (errorMsg.Equals("NoConfigFile", StringComparison.OrdinalIgnoreCase))
                {
                    if (SecureStoreFile.StoreFileExists())
                    {
                        // This indicates a corrupted store configuration or inadvertent file deletion.
                        // settings needed for store, or must re-create local store.
                        throw new InvalidOperationException("Secure local store is in inconsistent state.  TODO: Provide user instructions.");
                    }

                    // First time, use default configuration.
                    configData = SecureStoreConfig.GetDefault();
                    if (!SecureStoreFile.WriteConfigFile(
                        configData,
                        ref errorMsg))
                    {
                        throw new PSInvalidOperationException(errorMsg);
                    }
                }
            }
            
            // Enforce required password configuration.
            if (configData.PasswordRequired && (password == null))
            {
                throw new SecureStorePasswordException();
            }

            // Check password configuration consistency.
            if ((password != null) && !configData.PasswordRequired)
            {
                throw new PSInvalidOperationException(
                    "The local store is not configured to use a password. First change the store configuration to require a password.");
            }

            // Read store from file.
            if (SecureStoreFile.ReadFile(
                password: password,
                data: out SecureStoreData data,
                ref errorMsg))
            {
                return new SecureStore(
                    data: data, 
                    configData: configData,
                    password: password);
            }

            // If no file, create a default store
            if (errorMsg.Equals("NoFile", StringComparison.OrdinalIgnoreCase))
            {
                var secureStore = GetDefault(configData);
                if (!SecureStoreFile.WriteFile(
                    password: password,
                    data: secureStore.Data,
                    ref errorMsg))
                {
                    throw new PSInvalidOperationException(
                        string.Format(CultureInfo.InvariantCulture, 
                        @"Unable to write store data to file with error: {0}", errorMsg));
                }

                secureStore.SetPassword(password);
                return secureStore;
            }

            throw new PSInvalidOperationException(errorMsg);
        }

        #endregion
    }

    internal static class SecureStoreFile
    {
        #region Members

        private const string StoreFileName = "storefile";
        private const string StoreConfigName = "storeconfig";

        private static readonly string LocalStorePath;
        private static readonly string LocalStoreFilePath;
        private static readonly string LocalConfigFilePath;

        private static readonly FileSystemWatcher _storeFileWatcher;
        private static readonly Timer _updateEventTimer;
        private static readonly object _syncObject;
        private static DateTime _lastWriteTime;
        private static DateTime _lastFileChange;

        #endregion

        #region Constructor

        static SecureStoreFile()
        {
            LocalStorePath = Path.Combine(Utils.SecretManagementLocalPath, "localstore");
            LocalStoreFilePath = Path.Combine(LocalStorePath, StoreFileName);
            LocalConfigFilePath = Path.Combine(LocalStorePath, StoreConfigName);

            if (!Directory.Exists(LocalStorePath))
            {
                // TODO: Need to specify directory/file permissions.
                Directory.CreateDirectory(LocalStorePath);
            }

            _storeFileWatcher = new FileSystemWatcher(LocalStorePath);
            _storeFileWatcher.NotifyFilter = NotifyFilters.LastWrite;
            _storeFileWatcher.Filter = "store*";    // storefile, storeconfig
            _storeFileWatcher.EnableRaisingEvents = true;
            _storeFileWatcher.Changed += (sender, args) => { UpdateData(args); };

            _syncObject = new object();
            _lastWriteTime = DateTime.MinValue;
            _updateEventTimer = new Timer(
                (state) => {
                    try
                    {
                        DateTime fileChangeTime;
                        lock (_syncObject)
                        {
                            fileChangeTime = _lastFileChange;
                        }

                        RaiseDataUpdatedEvent(
                            new FileUpdateEventArgs(fileChangeTime));
                    }
                    catch
                    {
                    }
                });
        }

        #endregion

        #region Events

        public static event EventHandler<FileUpdateEventArgs> DataUpdated;
        private static void RaiseDataUpdatedEvent(FileUpdateEventArgs args)
        {
            if (DataUpdated != null)
            {
                DataUpdated.Invoke(null, args);
            }
        }

        public static event EventHandler<FileUpdateEventArgs> ConfigUpdated;
        private static void RaiseConfigUpdatedEvent(FileUpdateEventArgs args)
        {
            if (ConfigUpdated != null)
            {
                ConfigUpdated.Invoke(null, args);
            }
        }

        #endregion

        #region Properties

        public static DateTime LastWriteTime
        {
            get
            {
                lock (_syncObject)
                {
                    return _lastWriteTime;
                }
            }
        }

        public static bool ConfigAllowsPrompting
        {
            get
            {
                // Try to read the local store configuration file.
                string errorMsg = "";
                if (ReadConfigFile(
                    configData: out SecureStoreConfig configData,
                    ref errorMsg))
                {
                    return !configData.DoNotPrompt;
                }

                // Default behavior is to allow password prompting.
                return true;
            }
        }

        #endregion
        
        #region Public methods

        // File structure
        /*
        int:    key blob size
        int:    json blob size
        byte[]: key blob
        byte[]: json blob
        byte[]: data blob
        */

        public static bool WriteFile(
            SecureString password,
            SecureStoreData data,
            ref string errorMsg)
        {
            var count = 0;
            Exception exFail = null;
            do
            {
                try
                {
                    // Encrypt json meta data.
                    var jsonStr = data.ConvertMetaToJson();
                    var jsonBlob = CryptoUtils.EncryptWithKey(
                        passWord: password,
                        key: data.Key,
                        data: Encoding.UTF8.GetBytes(jsonStr));

                    using (var fileStream = File.OpenWrite(LocalStoreFilePath))
                    {
                        fileStream.Seek(0, 0);

                        // Write blob sizes
                        var intSize = sizeof(Int32);
                        var keyBlobSize = data.Key.Length;
                        var jsonBlobSize = jsonBlob.Length;
                        byte[] intField = BitConverter.GetBytes(keyBlobSize);
                        fileStream.Write(intField, 0, intSize);
                        intField = BitConverter.GetBytes(jsonBlobSize);
                        fileStream.Write(intField, 0, intSize);
                        
                        // Write key blob
                        fileStream.Write(data.Key, 0, keyBlobSize);

                        // Write json blob
                        fileStream.Write(jsonBlob, 0, jsonBlobSize);

                        // Write data blob
                        fileStream.Write(data.Blob, 0, data.Blob.Length);

                        if (fileStream.Position != fileStream.Length)
                        {
                            fileStream.SetLength(fileStream.Position);
                        }

                        lock (_syncObject)
                        {
                            _lastWriteTime = DateTime.Now;
                        }

                        return true;
                    }
                }
                catch (IOException exIO)
                {
                    // Make up to four attempts.
                    exFail = exIO;
                }
                catch (Exception ex)
                {
                    // Unexpected error.
                    exFail = ex;
                    break;
                }

                System.Threading.Thread.Sleep(250);

            } while (++count < 4);

            errorMsg = string.Format(
                CultureInfo.InvariantCulture,
                @"Unable to write to local store file with error: {0}",
                exFail.Message);

            return false;
        }

        public static bool ReadFile(
            SecureString password,
            out SecureStoreData data,
            ref string errorMsg)
        {
            data = null;

            if (!File.Exists(LocalStoreFilePath))
            {
                errorMsg = "NoFile";
                return false;
            }

            // Open and read from file stream
            var count = 0;
            Exception exFail = null;
            do
            {
                try
                {
                    using (var fileStream = File.OpenRead(LocalStoreFilePath))
                    {
                        // Read offsets
                        var intSize = sizeof(Int32);
                        byte[] intField = new byte[intSize];
                        fileStream.Read(intField, 0, intSize);
                        var keyBlobSize = BitConverter.ToInt32(intField, 0);
                        fileStream.Read(intField, 0, intSize);
                        var jsonBlobSize = BitConverter.ToInt32(intField, 0);

                        // Read key blob
                        byte[] keyBlob = new byte[keyBlobSize];
                        fileStream.Read(keyBlob, 0, keyBlobSize);

                        // Read json blob and decrypt
                        byte[] jsonBlob = new byte[jsonBlobSize];
                        fileStream.Read(jsonBlob, 0, jsonBlobSize);
                        var jsonStr = Encoding.UTF8.GetString(
                            CryptoUtils.DecryptWithKey(
                                passWord: password,
                                key: keyBlob,
                                jsonBlob));

                        // Read data blob
                        var dataBlobSize = (int) (fileStream.Length - (keyBlobSize + jsonBlobSize + (intSize * 2 )));
                        byte[] dataBlob = new byte[dataBlobSize];
                        fileStream.Read(dataBlob, 0, dataBlobSize);

                        data = new SecureStoreData(
                            key: keyBlob,
                            json: jsonStr,
                            blob: dataBlob);

                        return true;
                    }
                }
                catch (IOException exIO)
                {
                    // Make up to four attempts.
                    exFail = exIO;
                }
                catch (Exception ex)
                {
                    // Unexpected error.
                    exFail = ex;
                    break;
                }

                System.Threading.Thread.Sleep(250);

            } while (++count < 4);

            errorMsg = string.Format(
                CultureInfo.InvariantCulture,
                @"Unable to read from local store file with error: {0}",
                exFail.Message);

            return false;
        }

        public static bool WriteConfigFile(
            SecureStoreConfig configData,
            ref string errorMsg)
        {
            var count = 0;
            Exception exFail = null;
            do
            {
                try
                {
                    // Encrypt json meta data.
                    var jsonStr = configData.ConvertToJson();
                    File.WriteAllText(
                        path: LocalConfigFilePath,
                        contents: jsonStr);
                
                    return true;
                }
                catch (IOException exIO)
                {
                    // Make up to four attempts.
                    exFail = exIO;
                }
                catch (Exception ex)
                {
                    // Unexpected error.
                    exFail = ex;
                    break;
                }

                System.Threading.Thread.Sleep(250);

            } while (++count < 4);

            errorMsg = string.Format(
                CultureInfo.InvariantCulture,
                @"Unable to write to local configuration file with error: {0}",
                exFail.Message);

            return false;
        }

        public static bool ReadConfigFile(
            out SecureStoreConfig configData,
            ref string errorMsg)
        {
            configData = null;

            if ((!File.Exists(LocalConfigFilePath)))
            {
                errorMsg = "NoConfigFile";
                return false;
            }

            // Open and read from file stream
            var count = 0;
            Exception exFail = null;
            do
            {
                try
                {
                    var configJson = File.ReadAllText(LocalConfigFilePath);
                    configData = new SecureStoreConfig(configJson);
                    return true;
                }
                catch (IOException exIO)
                {
                    // Make up to four attempts.
                    exFail = exIO;
                }
                catch (Exception ex)
                {
                    // Unexpected error.
                    exFail = ex;
                    break;
                }

                System.Threading.Thread.Sleep(250);

            } while (++count < 4);

            errorMsg = string.Format(
                CultureInfo.InvariantCulture,
                @"Unable to read from local store configuration file with error: {0}",
                exFail.Message);

            return false;
        }

        public static bool RemoveStoreFile(ref string errorMsg)
        {
            var count = 0;
            Exception exFail = null;
            do
            {
                try
                {
                    File.Delete(LocalStoreFilePath);
                    return true;
                }
                catch (IOException exIO)
                {
                    // Make up to four attempts.
                    exFail = exIO;
                }
                catch (Exception ex)
                {
                    // Unexpected error.
                    exFail = ex;
                    break;
                }

                System.Threading.Thread.Sleep(250);

            } while (++count < 4);

            errorMsg = string.Format(
                CultureInfo.InvariantCulture,
                @"Unable to remove the local store file with error: {0}",
                exFail.Message);

            return false;
        }

        public static bool StoreFileExists()
        {
            return File.Exists(LocalStoreFilePath);
        }

        #endregion

        #region Private methods

        private static void UpdateData(FileSystemEventArgs args)
        {

            try
            {
                var lastFileChange = System.IO.File.GetLastWriteTime(args.FullPath);
                var fileName = System.IO.Path.GetFileNameWithoutExtension(args.FullPath);
                if (fileName.Equals(StoreFileName))
                {
                    lock (_syncObject)
                    {
                        // Set/reset event callback timer for each file change event.
                        // This is to smooth out multiple file changes into a single update event.
                        _lastFileChange = lastFileChange;
                        _updateEventTimer.Change(
                            dueTime: 5000,              // 5 second delay
                            period: Timeout.Infinite);
                    }
                }
                else if (fileName.Equals(StoreConfigName))
                {
                    RaiseConfigUpdatedEvent(
                        new FileUpdateEventArgs(lastFileChange));
                }
            }
            catch
            {
            }
        }

        #endregion
    }

    #region Event args

    internal sealed class FileUpdateEventArgs : EventArgs
    {
        public DateTime FileChangedTime
        {
            get;
            private set;
        }

        public FileUpdateEventArgs(DateTime fileChangedTime)
        {
            FileChangedTime = fileChangedTime;
        }
    }

    #endregion

    #endregion

    #region LocalSecretStore

    /// <summary>
    /// Default local secret store
    /// </summary>
    internal sealed class LocalSecretStore : IDisposable
    {
        #region Members

        private const string PSTag = "ps:";
        private const string PSHashtableTag = "psht:";
        private const string ByteArrayType = "ByteArrayType";
        private const string StringType = "StringType";
        private const string SecureStringType = "SecureStringType";
        private const string PSCredentialType = "CredentialType";
        private const string HashtableType = "HashtableType";
        private const int MaxHashtableItemCount = 20;

        private readonly SecureStore _secureStore;

        private static object SyncObject;
        private static LocalSecretStore LocalStore;
        private static Dictionary<string, object> DefaultTag;

        #endregion

        #region Properties

        public SecureStoreConfig Configuration
        {
            get
            {
                return new SecureStoreConfig(
                    scope: _secureStore.ConfigData.Scope,
                    passwordRequired: _secureStore.ConfigData.PasswordRequired,
                    passwordTimeout: _secureStore.ConfigData.PasswordTimeout,
                    doNotPrompt: _secureStore.ConfigData.DoNotPrompt);
            }
        }

        #endregion
        
        #region Constructor

        private LocalSecretStore()
        {
        }

        public LocalSecretStore(
            SecureStore secureStore)
        {
            _secureStore = secureStore;
            _secureStore.StoreConfigUpdated += (sender, args) => {
                // If the local store configuration changed, then reload the store from file.
                LocalSecretStore.Reset();
            };
        }

        static LocalSecretStore()
        {
            SyncObject = new object();

            DefaultTag = new Dictionary<string, object>()
                {
                    { "Tag", "PSItem" }
                };
        }

        #endregion
    
        #region IDisposable

        public void Dispose()
        {
            if (_secureStore != null)
            {
                _secureStore.Dispose();
            }
        }

        #endregion

        #region Public static

        public static LocalSecretStore GetInstance(
            SecureString password = null,
            PSCmdlet cmdlet = null)
        {
            if (LocalStore == null)
            {
                lock (SyncObject)
                {
                    if (LocalStore == null)
                    {
                        bool storeFileExists = SecureStoreFile.StoreFileExists();

                        try
                        {
                            LocalStore = new LocalSecretStore(
                                SecureStore.GetStore(password));
                        }
                        catch (SecureStorePasswordException)
                        {
                            if ((cmdlet != null) && SecureStoreFile.ConfigAllowsPrompting)
                            {
                                if (SecureStoreFile.StoreFileExists())
                                {
                                    // Prompt for existing local store file.
                                    password = Utils.PromptForPassword(cmdlet);
                                }
                                else
                                {
                                    // Prompt for creation of new store file.
                                    password = Utils.PromptForPassword(
                                        cmdlet: cmdlet,
                                        verifyPassword: true,
                                        message: "Creating new store file. A password is required by the current store configuration.");
                                }

                                LocalStore = new LocalSecretStore(
                                    SecureStore.GetStore(password));

                                return LocalStore;
                            }

                            // Cannot access store without password.
                            throw;
                        }
                    }
                }
            }

            return LocalStore;
        }

        public static void Reset()
        {
            lock (SyncObject)
            {
                LocalStore?.Dispose();
                LocalStore = null;
            }
        }

        #endregion

        #region Public methods

        public bool WriteObject<T>(
            string name,
            T objectToWrite,
            PSCmdlet cmdlet,
            ref string errorMsg)
        {
            var count = 0;
            do
            {
                try
                {
                    return WriteObjectImpl(
                        PrependTag(name),
                        objectToWrite,
                        ref errorMsg);
                }
                catch (SecureStorePasswordException)
                {
                    if (_secureStore.ConfigData.DoNotPrompt || cmdlet == null)
                    {
                        throw;
                    }

                    _secureStore.SetPassword(
                        Utils.PromptForPassword(cmdlet: cmdlet));
                }
            } while (count++ < 1);

            return false;
        }

        private bool WriteObjectImpl<T>(
            string name,
            T objectToWrite,
            ref string errorMsg)
        {
            switch (objectToWrite)
            {
                case byte[] blobToWrite:
                    return WriteBlob(
                        name,
                        blobToWrite,
                        ByteArrayType,
                        ref errorMsg);

                case string stringToWrite:
                    return WriteString(
                        name,
                        stringToWrite,
                        ref errorMsg);

                case SecureString secureStringToWrite:
                    return WriteSecureString(
                        name,
                        secureStringToWrite,
                        ref errorMsg);

                case PSCredential credentialToWrite:
                    return WritePSCredential(
                        name,
                        credentialToWrite,
                        ref errorMsg);

                case Hashtable hashtableToWrite:
                    return WriteHashtable(
                        name,
                        hashtableToWrite,
                        ref errorMsg);
                
                default:
                    throw new InvalidOperationException("Invalid type. Types supported: byte[], string, SecureString, PSCredential, Hashtable");
            }
        }

        public bool ReadObject(
            string name,
            out object outObject,
            PSCmdlet cmdlet,
            ref string errorMsg)
        {
            var count = 0;
            do
            {
                try
                {
                    return ReadObjectImpl(
                        PrependTag(name),
                        out outObject,
                        ref errorMsg);
                }
                catch (SecureStorePasswordException)
                {
                    if (_secureStore.ConfigData.DoNotPrompt || cmdlet == null)
                    {
                        throw;
                    }

                    _secureStore.SetPassword(
                        Utils.PromptForPassword(cmdlet: cmdlet));
                }
            } while (count++ < 1);

            outObject = null;
            return false;
        }

        private bool ReadObjectImpl(
            string name,
            out object outObject,
            ref string errorMsg)
        {
            if (!ReadBlob(
                name,
                out byte[] outBlob,
                out string typeName,
                ref errorMsg))
            {
                outObject = null;
                return false;
            }

            switch (typeName)
            {
                case ByteArrayType:
                    outObject = outBlob;
                    return true;

                case StringType:
                    return ReadString(
                        outBlob,
                        out outObject);

                case SecureStringType:
                    return ReadSecureString(
                        outBlob,
                        out outObject);

                case PSCredentialType:
                    return ReadPSCredential(
                        outBlob,
                        out outObject);
                
                case HashtableType:
                    return ReadHashtable(
                        name,
                        outBlob,
                        out outObject,
                        ref errorMsg);

                default:
                    throw new InvalidOperationException("Invalid type. Types supported: byte[], string, SecureString, PSCredential, Hashtable");
            }
        }

        public bool EnumerateObjectInfo(
            string filter,
            out SecretInformation[] outSecretInfo,
            PSCmdlet cmdlet,
            ref string errorMsg)
        {
            var count = 0;
            EnumeratedBlob[] outBlobs = null;
            do
            {
                try
                {
                    if (!EnumerateBlobs(
                        PrependTag(filter),
                        out outBlobs,
                        ref errorMsg))
                    {
                        outSecretInfo = null;
                        return false;
                    }
                }
                catch (SecureStorePasswordException)
                {
                    if (_secureStore.ConfigData.DoNotPrompt || cmdlet == null)
                    {
                        throw;
                    }

                    _secureStore.SetPassword(
                        Utils.PromptForPassword(cmdlet: cmdlet));
                }
            } while (count++ < 1);

            if (outBlobs == null)
            {
                outSecretInfo = null;
                return false;
            }

            var outList = new List<SecretInformation>(outBlobs.Length);
            foreach (var item in outBlobs)
            {
                switch (item.TypeName)
                {
                    case ByteArrayType:
                        outList.Add(
                            new SecretInformation(
                                name: RemoveTag(item.Name),
                                type: SecretType.ByteArray,
                                vaultName: RegisterSecretVaultCommand.BuiltInLocalVault));
                        break;

                    case StringType:
                        outList.Add(
                            new SecretInformation(
                                name: RemoveTag(item.Name),
                                type: SecretType.String,
                                vaultName: RegisterSecretVaultCommand.BuiltInLocalVault));
                        break;

                    case SecureStringType:
                        outList.Add(
                            new SecretInformation(
                                name: RemoveTag(item.Name),
                                type: SecretType.SecureString,
                                vaultName: RegisterSecretVaultCommand.BuiltInLocalVault));
                        break;

                    case PSCredentialType:
                        outList.Add(
                            new SecretInformation(
                                name: RemoveTag(item.Name),
                                type: SecretType.PSCredential,
                                vaultName: RegisterSecretVaultCommand.BuiltInLocalVault));
                        break;

                    case HashtableType:
                        outList.Add(
                            new SecretInformation(
                                name: RemoveTag(item.Name),
                                type: SecretType.Hashtable,
                                vaultName: RegisterSecretVaultCommand.BuiltInLocalVault));
                        break;
                }
            }

            outSecretInfo = outList.ToArray();
            return true;
        }

        public bool DeleteObject(
            string name,
            PSCmdlet cmdlet,
            ref string errorMsg)
        {
            var count = 0;
            object outObject = null;
            do
            {
                try
                {
                    if (!ReadObject(
                        name: name,
                        outObject: out outObject,
                        cmdlet: null,
                        ref errorMsg))
                    {
                        return false;
                    }
                }
                catch (SecureStorePasswordException)
                {
                    if (_secureStore.ConfigData.DoNotPrompt || cmdlet == null)
                    {
                        throw;
                    }

                    _secureStore.SetPassword(
                        Utils.PromptForPassword(cmdlet: cmdlet));
                }
            } while (count++ < 1);

            if (outObject == null)
            {
                return false;
            }

            name = PrependTag(name);

            switch (outObject)
            {
                case Hashtable hashtable:
                    return DeleteHashtable(
                        name,
                        ref errorMsg);

                default:
                    return DeleteBlob(
                        name,
                        ref errorMsg);
            }
        }

        public void UnlockLocalStore(
            SecureString password,
            int? passwordTimeout = null)
        {
            _secureStore.SetPassword(password);
            
            try
            {
                _secureStore.UpdateDataFromFile();
            }
            catch (SecureStorePasswordException)
            {
                throw new SecureStorePasswordException("Unable to unlock local store. Password is invalid.");
            }

            if (passwordTimeout.HasValue)
            {
                _secureStore.SetPasswordTimer(passwordTimeout.Value);
            }
        }

        public void UpdatePassword(
            SecureString newPassword,
            SecureString oldPassword)
        {
            _secureStore.UpdatePassword(
                newPassword,
                oldPassword,
                skipPasswordRequiredCheck: false);
        }

        public bool UpdateConfiguration(
            SecureStoreConfig newConfigData,
            PSCmdlet cmdlet,
            ref string errorMsg)
        {
            return _secureStore.UpdateConfigData(
                newConfigData,
                cmdlet,
                ref errorMsg);
        }

        #endregion

        #region Private methods

        #region Helper methods

        private static string PrependTag(string str)
        {
            return PSTag + str;
        }

        private static bool IsTagged(string str)
        {
            return str.StartsWith(PSTag);
        }

        private static string RemoveTag(string str)
        {
            if (IsTagged(str))
            {
                return str.Substring(PSTag.Length);
            }

            return str;
        }

        private static string PrependHTTag(
            string hashName,
            string keyName)
        {
            return PSHashtableTag + hashName + keyName;
        }

        private static string RecoverKeyname(
            string str,
            string hashName)
        {
            return str.Substring((PSHashtableTag + hashName).Length);
        }

        #endregion

        #region Blob methods

        private bool WriteBlob(
            string name,
            byte[] blob,
            string typeName,
            ref string errorMsg)
        {
            return _secureStore.WriteBlob(
                name: name,
                blob: blob,
                typeName: typeName,
                attributes: DefaultTag,
                errorMsg: ref errorMsg);
        }

        private bool ReadBlob(
            string name,
            out byte[] blob,
            out string typeName,
            ref string errorMsg)
        {
            if (!_secureStore.ReadBlob(
                name: name,
                blob: out blob,
                metaData: out SecureStoreMetadata metadata,
                errorMsg: ref errorMsg))
            {
                typeName = null;
                return false;
            }
            
            typeName = metadata.TypeName;
            return true;
        }

        private struct EnumeratedBlob
        {
            public string Name;
            public string TypeName;
        }

        private bool EnumerateBlobs(
            string filter,
            out EnumeratedBlob[] blobs,
            ref string errorMsg)
        {
            if (!_secureStore.EnumerateBlobs(
                filter: filter,
                metaData: out SecureStoreMetadata[] metadata,
                ref errorMsg))
            {
                blobs = null;
                return false;
            }

            List<EnumeratedBlob> blobArray = new List<EnumeratedBlob>(metadata.Length);
            foreach (var metaItem in metadata)
            {
                blobArray.Add(
                    new EnumeratedBlob
                    {
                        Name = metaItem.Name,
                        TypeName = metaItem.TypeName
                    });
            }

            blobs = blobArray.ToArray();
            return true;
        }

        private bool DeleteBlob(
            string name,
            ref string errorMsg)
        {
            return _secureStore.DeleteBlob(
                name: name,
                errorMsg: ref errorMsg);
        }

        #endregion

        #region String methods

        private bool WriteString(
            string name,
            string strToWrite,
            ref string errorMsg)
        {
            return WriteBlob(
                name: name,
                blob: Encoding.UTF8.GetBytes(strToWrite),
                typeName: StringType,
                errorMsg: ref errorMsg);
        }

        private static bool ReadString(
            byte[] blob,
            out object outString)
        {
            outString = Encoding.UTF8.GetString(blob);
            return true;
        }

        #endregion

        #region String array methods

        //
        // String arrays are stored as a blob:
        //  <arrayCount>    - number of strings in array (sizeof(int32))
        //  <length1>       - length of first string     (sizeof(int32))
        //  <string1>       - first string bytes         (length1)
        //  <length2>       - length of second string    (sizeof(int32))
        //  <string2>       - second string bytes        (length2)
        //  ...
        //

        private bool WriteStringArray(
            string name,
            string[] strsToWrite,
            ref string errorMsg)
        {
            // Compute blob size
            int arrayCount = strsToWrite.Length;
            int blobLength = sizeof(Int32) * (arrayCount + 1);
            int[] aStrSizeBytes = new int[arrayCount];
            int iCount = 0;
            foreach (string str in strsToWrite)
            {
                var strSizeBytes = Encoding.UTF8.GetByteCount(str);
                aStrSizeBytes[iCount++] = strSizeBytes;
                blobLength += strSizeBytes;
            }

            byte[] blob = new byte[blobLength];
            var index = 0;

            // Array count
            byte[] data = BitConverter.GetBytes(arrayCount);
            foreach (var b in data)
            {
                blob[index++] = b;
            }

            // Array strings
            iCount = 0;
            foreach (var str in strsToWrite)
            {
                // String length
                data = BitConverter.GetBytes(aStrSizeBytes[iCount++]);
                foreach (var b in data)
                {
                    blob[index++] = b;
                }

                // String bytes
                data = Encoding.UTF8.GetBytes(str);
                foreach (var b in data)
                {
                    blob[index++] = b;
                }
            }

            Dbg.Assert(index == blobLength, "Blob size must be consistent");

            // Write blob
            return WriteBlob(
                name: name,
                blob: blob,
                typeName: HashtableType,
                errorMsg: ref errorMsg);
        }

        private static void ReadStringArray(
            byte[] blob,
            out string[] outStrArray)
        {
            int index = 0;
            int arrayCount = BitConverter.ToInt32(blob, index);
            index += sizeof(Int32);

            outStrArray = new string[arrayCount];
            for (int iCount = 0; iCount < arrayCount; iCount++)
            {
                int strSizeBytes = BitConverter.ToInt32(blob, index);
                index += sizeof(Int32);

                outStrArray[iCount] = Encoding.UTF8.GetString(blob, index, strSizeBytes);
                index += strSizeBytes;
            }

            Dbg.Assert(index == blob.Length, "Blob length must be consistent");
        }

        #endregion
    
        #region SecureString methods

        private bool WriteSecureString(
            string name,
            SecureString strToWrite,
            ref string errorMsg)
        {
            if (Utils.GetDataFromSecureString(
                secureString: strToWrite,
                data: out byte[] data))
            {
                try
                {
                    return WriteBlob(
                        name: name,
                        blob: data,
                        typeName: SecureStringType,
                        errorMsg: ref errorMsg);
                }
                finally
                {
                    CryptoUtils.ZeroOutData(data);
                }
            }
            
            return false;
        }

        private static bool ReadSecureString(
            byte[] ssBlob,
            out object outSecureString)
        {
            try
            {
                if (Utils.GetSecureStringFromData(
                    data: ssBlob, 
                    outSecureString: out SecureString outString))
                {
                    outSecureString = outString;
                    return true;
                }
            }
            finally
            {
                CryptoUtils.ZeroOutData(ssBlob);
            }

            outSecureString = null;
            return false;
        }

        #endregion

        #region PSCredential methods

        //
        // PSCredential blob packing:
        //      <offset>    Contains offset to password data        Length: sizeof(int)
        //      <userName>  Contains UserName string bytes          Length: userData bytes
        //      <password>  Contains Password SecureString bytes    Length: ssData bytes
        //

        private bool WritePSCredential(
            string name,
            PSCredential credential,
            ref string errorMsg)
        {
            if (Utils.GetDataFromSecureString(
                secureString: credential.Password,
                data: out byte[] ssData))
            {
                byte[] blob = null;
                try
                {
                    // Get username string bytes
                    var userData = Encoding.UTF8.GetBytes(credential.UserName);

                    // Create offset bytes to SecureString data
                    var offset = userData.Length + sizeof(Int32);
                    var offsetData = BitConverter.GetBytes(offset);

                    // Create blob
                    blob = new byte[offset + ssData.Length];

                    // Copy all to blob
                    var index = 0;
                    foreach (var b in offsetData)
                    {
                        blob[index++] = b;
                    }
                    foreach (var b in userData)
                    {
                        blob[index++] = b;
                    }
                    foreach (var b in ssData)
                    {
                        blob[index++] = b;
                    }

                    // Write blob
                    return WriteBlob(
                        name: name,
                        blob: blob,
                        typeName: PSCredentialType,
                        errorMsg: ref errorMsg);
                }
                finally
                {
                    CryptoUtils.ZeroOutData(ssData);

                    if (blob != null)
                    {
                        CryptoUtils.ZeroOutData(blob);
                    }
                }
            }
            
            return false;
        }

        private static bool ReadPSCredential(
            byte[] blob,
            out object credential)
        {
            byte[] ssData = null;

            try
            {
                // UserName
                var offset = BitConverter.ToInt32(blob, 0);
                int index = sizeof(Int32);
                var userName = Encoding.UTF8.GetString(blob, index, (offset - index));

                // SecureString
                ssData = new byte[(blob.Length - offset)];
                index = 0;
                for (int i = offset; i < blob.Length; i++)
                {
                    ssData[index++] = blob[i];
                }

                if (Utils.GetSecureStringFromData(
                    ssData,
                    out SecureString secureString))
                {
                    credential = new PSCredential(userName, secureString);
                    return true;
                }
            }
            finally
            {
                CryptoUtils.ZeroOutData(blob);
                
                if (ssData != null)
                {
                    CryptoUtils.ZeroOutData(ssData);
                }
            }

            credential = null;
            return false;
        }

        #endregion

        #region Hashtable methods

        //
        // Hash table values will be limited to the currently supported secret types:
        //  byte[]
        //  string
        //  SecureString
        //  PSCredential
        //
        // The values are stored as separate secrets with special name tags.
        //  <secretName1>
        //  <secretName2>
        //  <secretName3>
        //   ...
        //
    
        private bool WriteHashtable(
            string name,
            Hashtable hashtable,
            ref string errorMsg)
        {
            // Impose size limit
            if (hashtable.Count > MaxHashtableItemCount)
            {
                throw new ArgumentException(
                    string.Format(CultureInfo.InvariantCulture, 
                        "The provided Hashtable, {0}, has too many entries. The maximum number of entries is {1}.",
                        name, MaxHashtableItemCount));
            }

            // Create a list of hashtable entries.
            var entries = new Dictionary<string, object>();
            foreach (var key in hashtable.Keys)
            {
                var entry = hashtable[key];
                if (entry is PSObject psObjectEntry)
                {
                    entry = psObjectEntry.BaseObject;
                }
                var entryType = entry.GetType();
                if (entryType == typeof(byte[]) ||
                    entryType == typeof(string) ||
                    entryType == typeof(SecureString) ||
                    entryType == typeof(PSCredential))
                {
                    var entryName = PrependHTTag(name, key.ToString());
                    entries.Add(entryName, entry);
                }
                else
                {
                    throw new ArgumentException(
                        string.Format(CultureInfo.InstalledUICulture, 
                        "The object type for {0} Hashtable entry is not supported. Supported types are byte[], string, SecureString, PSCredential",
                        key));
                }
            }

            // Write the member name array.
            var hashTableEntryNames = new List<string>();
            foreach (var entry in entries)
            {
                hashTableEntryNames.Add(entry.Key);
            }
            if (!WriteStringArray(
                name: name,
                strsToWrite: hashTableEntryNames.ToArray(),
                errorMsg: ref errorMsg))
            {
                return false;
            }

            // Write each entry as a separate secret.  Roll back on any failure.
            var success = false;
            try
            {
                foreach (var entry in entries)
                {
                    success = WriteObjectImpl(
                        name: entry.Key,
                        objectToWrite: entry.Value,
                        errorMsg: ref errorMsg);
                    
                    if (!success)
                    {
                        break;
                    }
                }

                return success;
            }
            finally
            {
                if (!success)
                {
                    // Roll back.
                    // Remove any Hashtable secret that was written, ignore errors.
                    string error = "";
                    foreach (var entry in entries)
                    {
                        DeleteBlob(
                            name: entry.Key,
                            errorMsg: ref error);
                    }

                    // Remove the Hashtable member names.
                    DeleteBlob(
                        name: name,
                        errorMsg: ref error);
                }
            }
        }

        private bool ReadHashtable(
            string name,
            byte[] blob,
            out object outHashtable,
            ref string errorMsg)
        {
            // Get array of Hashtable secret names.
            ReadStringArray(
                blob,
                out string[] entryNames);
            
            outHashtable = null;
            var hashtable = new Hashtable();
            foreach (var entryName in entryNames)
            {
                if (ReadObjectImpl(
                    entryName,
                    out object outObject,
                    ref errorMsg))
                {
                    hashtable.Add(
                    RecoverKeyname(entryName, name),
                    outObject);
                }
            }

            outHashtable = hashtable;
            return true;
        }

        private bool DeleteHashtable(
            string name,
            ref string errorMsg)
        {
            // Get array of Hashtable secret names.
            if (!ReadBlob(
                name,
                out byte[] blob,
                out string typeName,
                ref errorMsg))
            {
                return false;
            }

            ReadStringArray(
                blob,
                out string[] entryNames);

            // Delete each Hashtable entry secret.
            foreach (var entryName in entryNames)
            {
                DeleteBlob(
                    name: entryName,
                    ref errorMsg);
            }

            // Delete the Hashtable secret names list.
            DeleteBlob(
                name: name,
                ref errorMsg);

            return true;
        }

        #endregion
    
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
        internal const string ModuleNameStr = "ModuleName";
        internal const string ModulePathStr = "ModulePath";
        internal const string VaultParametersStr = "VaultParameters";
        internal const string ImplementingTypeStr = "ImplementingType";
        internal const string ImplementingFunctionsStr = "ImplementingFunctions";

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
        /// Optional local store name for additional vault parameters.
        /// <summary>
        public string VaultParametersName { get; }

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
            Hashtable vaultInfo)
        {
            // Required module information.
            VaultName = vaultName;
            ModuleName = (string) vaultInfo[ModuleNameStr];
            ModulePath = (string) vaultInfo[ModulePathStr];

            var implementingType = (Hashtable) vaultInfo[ImplementingTypeStr];
            ImplementingTypeAssemblyName = (string) implementingType["AssemblyName"];
            ImplementingTypeName = (string) implementingType["TypeName"];

            VaultParametersName = (vaultInfo.ContainsKey(VaultParametersStr)) ?
                (string) (string) vaultInfo[VaultParametersStr] : string.Empty;

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
            VaultParametersName = module.VaultParametersName;

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
            if (!string.IsNullOrEmpty(this.ImplementingTypeName))
            {
                InvokeSetSecretOnImplementingType(name, secret, vaultName, cmdlet);
            }
            else
            {
                InvokeSetSecretOnScriptFn(name, secret, vaultName, cmdlet);
            }
        }

        /// <summary>
        /// Looks up a single secret by name.
        /// </summary>
        public object InvokeGetSecret(
            string name,
            string vaultName,
            PSCmdlet cmdlet)
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

        /// <summary>
        /// Remove a single secret.
        /// </summary>
        public void InvokeRemoveSecret(
            string name,
            string vaultName,
            PSCmdlet cmdlet)
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

        public SecretInformation[] InvokeGetSecretInfo(
            string filter,
            string vaultName,
            PSCmdlet cmdlet)
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

        public bool InvokeTestVault(
            string vaultName,
            PSCmdlet cmdlet)
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

            var parameters = GetParamsFromStore(VaultParametersName);
            bool success = false;
            Exception error = null;

            try
            {
                success = _vaultExtentsion.Value.SetSecret(
                    name: name,
                    secret: secret,
                    vaultName: vaultName,
                    additionalParameters: parameters,
                    out error);
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

            var parameters = GetParamsFromStore(VaultParametersName);
            object secret = null;
            Exception error = null;
            
            try
            {
                secret = _vaultExtentsion.Value.GetSecret(
                    name: name,
                    vaultName: vaultName,
                    additionalParameters: parameters,
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

            var parameters = GetParamsFromStore(VaultParametersName);
            var success = false;
            Exception error = null;

            try
            {
                success = _vaultExtentsion.Value.RemoveSecret(
                    name: name,
                    vaultName: vaultName,
                    additionalParameters: parameters,
                    out error);
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

            var parameters = GetParamsFromStore(VaultParametersName);
            SecretInformation[] results = null;
            Exception error = null;

            try
            {
                results = _vaultExtentsion.Value.GetSecretInfo(
                    filter: filter,
                    vaultName: vaultName,
                    additionalParameters: parameters,
                    out error);
            }
            catch (Exception ex)
            {
                error = ex;
            }
            
            if (error != null)
            {
                if (error == null)
                {
                    var msg = string.Format(
                        CultureInfo.InvariantCulture, 
                        "Could not get secret information from vault {0}.",
                        VaultName);

                    error = new InvalidOperationException(msg);
                }

                cmdlet.WriteError(
                    new ErrorRecord(
                        error,
                        "InvokeGetSecretInfoError",
                        ErrorCategory.InvalidOperation,
                        this));
            }

            return results;
        }

        private bool InvokeTestVaultOnImplementingType(
            string vaultName,
            PSCmdlet cmdlet)
        {
            // Ensure the module has been imported so that the extension
            // binary assembly is loaded.
            ImportPSModule(cmdlet);

            var parameters = GetParamsFromStore(VaultParametersName);
            Exception[] errors;
            bool success;

            try
            {
                success = _vaultExtentsion.Value.TestSecretVault(
                    vaultName: vaultName,
                    additionalParameters: parameters,
                    errors: out errors);
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
            if (!string.IsNullOrEmpty(VaultParametersName))
            {
                string errorMsg = "";
                if (LocalSecretStore.GetInstance().ReadObject(
                    name: VaultParametersName,
                    outObject: out object outObject,
                    cmdlet: null,
                    ref errorMsg))
                {
                    if (outObject is Hashtable hashtable)
                    {
                        return hashtable;
                    }
                }
            }

            return new Hashtable();
        }

        private static IReadOnlyDictionary<string, object> GetParamsFromStore(string paramsName)
        {
            if (!string.IsNullOrEmpty(paramsName))
            {
                string errorMsg = "";
                if (LocalSecretStore.GetInstance().ReadObject(
                    name: paramsName,
                    outObject: out object outObject,
                    cmdlet: null,
                    ref errorMsg))
                {
                    var hashtable = outObject as Hashtable;
                    var dictionary = new Dictionary<string, object>(hashtable.Count);
                    foreach (var key in hashtable.Keys)
                    {
                        dictionary.Add((string) key, hashtable[key]);
                    }
                    return new ReadOnlyDictionary<string, object>(dictionary);
                }
            }

            return new ReadOnlyDictionary<string, object>(
                new Dictionary<string, object>());
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
                lock (_vaultInfoCache)
                {
                    var returnVaults = new SortedDictionary<string, ExtensionVaultModule>(StringComparer.InvariantCultureIgnoreCase);
                    foreach (var vaultName in _vaultCache.Keys)
                    {
                        returnVaults.Add(vaultName, _vaultCache[vaultName].Clone());
                    }
                    return returnVaults;
                }
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
            _vaultCache = new Dictionary<string, ExtensionVaultModule>(StringComparer.InvariantCultureIgnoreCase);

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
        /// <returns>True when item is successfully added.</returns>
        public static bool Add(
            string keyName,
            Hashtable vaultInfo)
        {
            var vaultItems = GetAll();
            if (!vaultItems.ContainsKey(keyName))
            {
                vaultItems.Add(keyName, vaultInfo);
                WriteSecretVaultRegistry(vaultItems);
                return true;
            }

            return false;
        }

        /// <summary>
        /// Remove item from cache.
        /// </summary>
        /// <param name="keyName">Name of item to remove.</param>
        /// <returns>True when item is successfully removed.</returns>
        public static Hashtable Remove(string keyName)
        {
            var vaultItems = GetAll();
            if (vaultItems.ContainsKey(keyName))
            {
                Hashtable vaultInfo = (Hashtable) vaultItems[keyName];
                vaultItems.Remove(keyName);
                WriteSecretVaultRegistry(vaultItems);
                return vaultInfo;
            }

            return null;
        }

        #endregion

        #region Private methods

        private static void RefreshCache()
        {
            if (!TryReadSecretVaultRegistry(out Hashtable vaultItems))
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
                            value: new ExtensionVaultModule(vaultKey, (Hashtable) _vaultInfoCache[vaultKey]));
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
        /// <returns>True if file is successfully read and converted from json.</returns>
        private static bool TryReadSecretVaultRegistry(
            out Hashtable vaultInfo)
        {
            vaultInfo = null;

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
                    vaultInfo = Utils.ConvertJsonToHashtable(jsonInfo);
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
        /// <param>Hashtable containing registered vault information.</param>
        private static void WriteSecretVaultRegistry(Hashtable dataToWrite)
        {
            string jsonInfo = Utils.ConvertHashtableToJson(dataToWrite);

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
