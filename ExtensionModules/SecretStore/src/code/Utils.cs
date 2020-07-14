// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.PowerShell.SecretManagement;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Management.Automation;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;

using Dbg = System.Diagnostics.Debug;

namespace Microsoft.PowerShell.SecretStore
{
    #region Utils

    internal static class Utils
    {
        #region Members

        internal const string PasswordRequiredMessage = "A valid password is required to access the Microsoft.PowerShell.SecretStore vault.";

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
            if (secureString == null)
            {
                data = null;
                return false;
            }

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

    #region SecureStore

    #region CryptoUtils

    internal static class CryptoUtils
    {
        #region Private members

        private static byte[] salt = new byte[32]
        {
            154, 146, 58, 204, 7, 124, 237, 132,
            248, 95, 158, 243, 108, 235, 163, 103,
            148, 95, 205, 190, 109, 184, 116, 92,
            155, 12, 6, 99, 0, 91, 54, 250
        };

        #endregion

        #region Public methods

        public static AesKey GenerateKey()
        {
            // By default this creates a 256 AES key with 128 block size.
            // IV size then, is 16.
            byte[] key;
            byte[] iv;
            using (var aes = Aes.Create())
            {
                key = aes.Key;
                iv = new byte[aes.BlockSize / 8];
            }
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(iv);
            }

            return new AesKey(key, iv);
        }

        public static AesKey GenerateKeyFromPassword(
            string password)
        {
            var key = DeriveKeyFromPassword(
                passwordData: Encoding.UTF8.GetBytes(password),
                keyLength: 32);

            var iv = new byte[16];  // Zero IV.
            
            return new AesKey(key, iv);
        }

        public static byte[] EncryptWithKey(
            SecureString passWord,
            AesKey key,
            byte[] data)
        {
            var keyToUse = (passWord != null) ? DeriveKeyFromSecureString(passWord, key.Key) : key.Key;
            try
            {
                using (var aes = Aes.Create())
                {
                    aes.Key = keyToUse;
                    aes.IV = key.IV;
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
            finally
            {
                if (passWord != null)
                {
                    ZeroOutData(keyToUse);
                }
            }
        }

        public static byte[] DecryptWithKey(
            SecureString passWord,
            AesKey key,
            byte[] data)
        {
            var keyToUse = (passWord != null) ? DeriveKeyFromSecureString(passWord, key.Key) : key.Key;
            try
            {
                using (var aes = Aes.Create())
                {
                    aes.IV = key.IV;
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
                                throw new PasswordRequiredException(Utils.PasswordRequiredMessage);
                            }
                        }

                        return targetStream.ToArray();
                    }
                }
            }
            finally
            {
                if (passWord != null)
                {
                    ZeroOutData(keyToUse);
                }
            }
        }

        public static byte[] ComputeHashWithPasswordOrUser(
            SecureString passWord,
            byte[] dataToHash)
        {
            byte[] keyToUse = DeriveKeyFromPasswordOrUser(passWord);
            try
            {
                return ComputeHash(keyToUse, dataToHash);
            }
            finally
            {
                ZeroOutData(keyToUse);
            }
        }

        public static bool ValidateHashWithPasswordOrUser(
            SecureString passWord,
            byte[] hash,
            byte[] dataToValidate)
        {
            var keyToUse = DeriveKeyFromPasswordOrUser(passWord);
            try
            {
                return ValidateHash(
                    key: keyToUse,
                    hashToCompare: hash,
                    dataToValidate: dataToValidate);
            }
            finally
            {
                ZeroOutData(keyToUse);
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

        private static byte[] DeriveKeyFromSecureString(
            SecureString passWord,
            byte[] key)
        {
            if (Utils.GetDataFromSecureString(
                secureString: passWord,
                data: out byte[] passWordData))
            {
                return DeriveKeyFromPassword(
                    passwordData: passWordData,
                    keyLength: key.Length);
            }

            throw new PSInvalidOperationException("Cannot read password SecureString data.");
        }

        private static byte[] DeriveKeyFromPassword(
            byte[] passwordData,
            int keyLength)
        {
            try
            {
                using (var derivedBytes = new Rfc2898DeriveBytes(
                    password: passwordData, 
                    salt: salt, 
                    iterations: 1000))
                {
                    return derivedBytes.GetBytes(keyLength);
                }
            }
            finally
            {
                ZeroOutData(passwordData);
            }
        }

        private static byte[] DeriveKeyFromPasswordOrUser(
            SecureString passWord)
        {
            // Create hash key with either provided password or current user name.
            byte[] passWordData;
            if (!Utils.GetDataFromSecureString(
                secureString: passWord,
                data: out passWordData))
            {
                passWordData = Encoding.UTF8.GetBytes(Environment.UserName);
            }

            return DeriveKeyFromPassword(
                passwordData: passWordData,
                keyLength: 64);
        }

        private static byte[] ComputeHash(
            byte[] key,
            byte[] dataToHash)
        {
            using (var hMac = new HMACSHA256(key))
            {
                return hMac.ComputeHash(dataToHash);
            }
        }

        private static bool ValidateHash(
            byte[] key,
            byte[] hashToCompare,
            byte[] dataToValidate)
        {
            var computedHash = ComputeHash(
                key: key,
                dataToHash: dataToValidate);
            
            if (hashToCompare.Length != computedHash.Length)
            {
                return false;
            }

            for (int i=0; i<hashToCompare.Length; i++)
            {
                if (hashToCompare[i] != computedHash[i])
                {
                    return false;
                }
            }

            return true;
        }

        #endregion
    }

    #endregion

    #region SecureStoreScope

    public enum SecureStoreScope
    {
        CurrentUser = 1,
        AllUsers
    }

    #endregion

    #region SecureStoreConfig

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
            if (configDataObj == null)
            {
                throw new InvalidDataException("Unable to read store configuration json data.");
            }
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

    #endregion

    #region SecureStoreMetada

    internal sealed class SecureStoreMetadata
    {
        #region Properties

        public string Name
        {
            get;
        }

        public string TypeName
        {
            get;
        }

        public int Offset
        {
            get;
            set;
        }

        public int Size
        {
            get;
        }

        public ReadOnlyDictionary<string, object> Attributes
        {
            get;
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

    #endregion

    #region AesKey

    internal sealed class AesKey
    {
        #region Properties

        public byte[] Key { get; }
        public byte[] IV { get; }

        #endregion

        #region Constructor

        public AesKey(
            byte[] key,
            byte[] iv)
        {
            Key = key;
            IV = iv;
        }

        #endregion

        #region Public methods

        public void Clear()
        {
            if (Key != null)
            {
                CryptoUtils.ZeroOutData(Key);
            }
            if (IV != null)
            {
                CryptoUtils.ZeroOutData(IV);
            }
        }

        #endregion
    }

    #endregion

    #region SecureStoreData

    internal sealed class SecureStoreData
    {
        #region Properties

        public AesKey Key { get; set; }
        public byte[] Blob { get; set; }
        public Dictionary<string, SecureStoreMetadata> MetaData { get; set; }

        #endregion

        #region Constructor

        public SecureStoreData()
        {
        }

        public SecureStoreData(
            AesKey key,
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
            Key.Clear();

            if (Blob != null)
            {
                CryptoUtils.ZeroOutData(Blob);
            }

            MetaData?.Clear();
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
        {
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
                throw new InvalidDataException("Unable to read store json meta data.");
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

    #endregion

    #region SecureStore

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
                        throw new PasswordRequiredException(Utils.PasswordRequiredMessage);
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

            SecureStoreFile.ClearDataUpdateEventList();
            SecureStoreFile.DataUpdated += (sender, args) => HandleDataUpdateEvent(sender, args);

            SecureStoreFile.ClearConfigUpdateEventList();
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
            bool skipPasswordRequiredCheck,
            bool skipConfigFileWrite)
        {
            if (!skipPasswordRequiredCheck)
            {
                VerifyPasswordRequired();
            }

            lock (_syncObject)
            {
                // Verify password.
                if (!SecureStoreFile.ReadFile(
                    oldPassword,
                    out SecureStoreData data,
                    out _))
                {
                    throw new PasswordRequiredException("Unable to access the Microsoft.PowerShell.SecretStore vault with provided oldPassword.");
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
                    errorMsg: out string errorMsg))
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
                if (!skipConfigFileWrite)
                {
                    SecureStoreFile.WriteConfigFile(
                        configData: _configData,
                        out string _);
                }
            }
        }

        public bool WriteBlob(
            string name,
            byte[] blob,
            string typeName,
            Dictionary<string, object> attributes,
            out string errorMsg)
        {
            if (EnumerateBlobs(
                filter: name,
                metaData: out SecureStoreMetadata[] _,
                out errorMsg))
            {
                return ReplaceBlobImpl(
                    name,
                    blob,
                    typeName,
                    attributes,
                    out errorMsg);
            }

            return WriteBlobImpl(
                name,
                blob,
                typeName,
                attributes,
                out errorMsg);
        }

        public bool ReadBlob(
            string name,
            out byte[] blob,
            out SecureStoreMetadata metaData,
            out string errorMsg)
        {
            errorMsg = string.Empty;
            byte[] encryptedBlob = null;
            AesKey key = null;
            lock (_syncObject)
            {
                // Get blob
                if (!_data.MetaData.TryGetValue(
                    key: name,
                    value: out metaData))
                {
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
                password?.Clear();
            }

            return true;
        }

        public bool EnumerateBlobs(
            string filter,
            out SecureStoreMetadata[] metaData,
            out string errorMsg)
        {
            errorMsg = string.Empty;
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
            out string errorMsg)
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
                    out errorMsg);
            }
            finally
            {
                password?.Clear();
            }
        }

        public bool UpdateConfigData(
            SecureStoreConfig newConfigData,
            PSCmdlet cmdlet,
            out string errorMsg)
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
                out errorMsg))
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
                        skipPasswordRequiredCheck: true,
                        skipConfigFileWrite: true);

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
                        out errorMsg);

                    return false;
                }
            }
            else if ((oldConfigData.PasswordTimeout != newConfigData.PasswordTimeout) && (_password != null))
            {
                SetPasswordTimer(newConfigData.PasswordTimeout);
            }

            errorMsg = string.Empty;
            return true;
        }

        public void UpdateDataFromFile()
        {
            SecureStoreData data;
            SecureString password = Password;
            try
            {
                if (!SecureStoreFile.ReadFile(
                    password: Password,
                    data: out data,
                    out string _))
                {
                    data = SecureStoreData.CreateEmpty();
                }
            }
            finally
            {
                password?.Clear();
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
            if (!SecureStoreFile.ReadConfigFile(
                configData: out SecureStoreConfig configData,
                out string errorMsg))
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
                if ((args.FileChangedTime - SecureStoreFile.LastConfigWriteTime) > _updateDelay)
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
                if ((args.FileChangedTime - SecureStoreFile.LastStoreWriteTime) > _updateDelay)
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
            AesKey key,
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
            out string errorMsg)
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
                    out errorMsg);
            }
            finally
            {
                password?.Clear();
            }
        }

        private bool ReplaceBlobImpl(
            string name,
            byte[] blob,
            string typeName,
            Dictionary<string, object> attributes,
            out string errorMsg)
        {
            lock (_syncObject)
            {
                // Remove old blob
                if (!DeleteBlob(
                    name: name,
                    out errorMsg))
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
                    out errorMsg);
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
            // Read config from file.
            SecureStoreConfig configData;
            if (!SecureStoreFile.ReadConfigFile(
                configData: out configData,
                errorMsg: out string errorMsg))
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
                        out errorMsg))
                    {
                        throw new PSInvalidOperationException(errorMsg);
                    }
                }
            }
            
            // Enforce required password configuration.
            if (configData.PasswordRequired && (password == null))
            {
                throw new PasswordRequiredException(Utils.PasswordRequiredMessage);
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
                out errorMsg))
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
                    out errorMsg))
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

    #endregion

    #region SecureStoreFile

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
        private static DateTime _lastConfigWriteTime;
        private static DateTime _lastStoreWriteTime;
        private static DateTime _lastStoreFileChange;

        #endregion

        #region Constructor

        static SecureStoreFile()
        {
            LocalStorePath = Path.Combine(Utils.SecretManagementLocalPath, "localstore");
            LocalStoreFilePath = Path.Combine(LocalStorePath, StoreFileName);
            LocalConfigFilePath = Path.Combine(LocalStorePath, StoreConfigName);

            if (!Directory.Exists(LocalStorePath))
            {
                Directory.CreateDirectory(LocalStorePath);

                if (Utils.IsWindows)
                {
                    SetDirectoryACLs(LocalStorePath);
                }
                else
                {
                    SetFilePermissions(
                        filePath: LocalStorePath,
                        isDirectory: true);
                }
            }

            _storeFileWatcher = new FileSystemWatcher(LocalStorePath);
            _storeFileWatcher.NotifyFilter = NotifyFilters.LastWrite;
            _storeFileWatcher.Filter = "store*";    // storefile, storeconfig
            _storeFileWatcher.EnableRaisingEvents = true;
            _storeFileWatcher.Changed += (sender, args) => { UpdateData(args); };

            _syncObject = new object();
            _lastConfigWriteTime = DateTime.MinValue;
            _lastStoreWriteTime = DateTime.MinValue;
            _updateEventTimer = new Timer(
                (state) => {
                    try
                    {
                        DateTime fileChangeTime;
                        lock (_syncObject)
                        {
                            fileChangeTime = _lastStoreFileChange;
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
        public static void ClearDataUpdateEventList()
        {
            if (DataUpdated != null)
            {
                foreach (var handlerDelegate in DataUpdated.GetInvocationList())
                {
                    DataUpdated -= (EventHandler<FileUpdateEventArgs>) handlerDelegate;
                }
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
        public static void ClearConfigUpdateEventList()
        {
            if (ConfigUpdated != null)
            {
                foreach (var handlerDelegate in ConfigUpdated.GetInvocationList())
                {
                    ConfigUpdated -= (EventHandler<FileUpdateEventArgs>) handlerDelegate;
                }
            }
        }

        #endregion

        #region Properties

        public static DateTime LastConfigWriteTime
        {
            get
            {
                lock (_syncObject)
                {
                    return _lastConfigWriteTime;
                }
            }
        }

        public static DateTime LastStoreWriteTime
        {
            get
            {
                lock (_syncObject)
                {
                    return _lastStoreWriteTime;
                }
            }
        }

        public static bool ConfigAllowsPrompting
        {
            get
            {
                // Try to read the local store configuration file.
                if (ReadConfigFile(
                    configData: out SecureStoreConfig configData,
                    out string _))
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
        int:    data hash size
        byte[]: data hash
        <Data>
        int:    key blob size
        int:    iv blob size
        int:    json blob size
        byte[]: key blob
        byte[]: iv blob
        byte[]: json blob
        byte[]: data blob
        </Data>
        */

        public static bool WriteFile(
            SecureString password,
            SecureStoreData data,
            out string errorMsg)
        {
            // Encrypt json meta data.
            var jsonStr = data.ConvertMetaToJson();
            var jsonBlob = CryptoUtils.EncryptWithKey(
                passWord: password,
                key: data.Key,
                data: Encoding.UTF8.GetBytes(jsonStr));

            // Create single file data blob.
            var intSize = sizeof(Int32);
            var keyBlobSize = data.Key.Key.Length;
            var ivBlobSize = data.Key.IV.Length;
            var jsonBlobSize = jsonBlob.Length;
            var fileDataBlobSize = (intSize * 3) + keyBlobSize + ivBlobSize + jsonBlobSize + data.Blob.Length;
            var fileDataBlob = new byte[fileDataBlobSize];
            var index = 0;

            // Copy key size.
            Buffer.BlockCopy(
                src: BitConverter.GetBytes(keyBlobSize),
                srcOffset: 0,
                dst: fileDataBlob,
                dstOffset: index,
                count: intSize);
            index += intSize;

            // Copy iv size.
            Buffer.BlockCopy(
                src: BitConverter.GetBytes(ivBlobSize),
                srcOffset: 0,
                dst: fileDataBlob,
                dstOffset: index,
                count: intSize);
            index += intSize;
            
            // Copy json blob size.
            Buffer.BlockCopy(
                src: BitConverter.GetBytes(jsonBlobSize),
                srcOffset: 0,
                dst: fileDataBlob,
                dstOffset: index,
                count: intSize);
            index += intSize;

            // Copy key blob.
            Buffer.BlockCopy(
                src: data.Key.Key,
                srcOffset: 0,
                dst: fileDataBlob,
                dstOffset: index,
                count: keyBlobSize);
            index += keyBlobSize;

            // Copy iv blob.
            Buffer.BlockCopy(
                src: data.Key.IV,
                srcOffset: 0,
                dst: fileDataBlob,
                dstOffset: index,
                count: ivBlobSize);
            index += ivBlobSize;

            // Copy json blob.
            Buffer.BlockCopy(
                src: jsonBlob,
                srcOffset: 0,
                dst: fileDataBlob,
                dstOffset: index,
                count: jsonBlobSize);
            index += jsonBlobSize;

            // Copy data blob.
            Buffer.BlockCopy(
                src: data.Blob,
                srcOffset: 0,
                dst: fileDataBlob,
                dstOffset: index,
                count: data.Blob.Length);

            // Compute hash.
            var dataHash = CryptoUtils.ComputeHashWithPasswordOrUser(
                passWord: password,
                dataToHash: fileDataBlob);

            var count = 0;
            Exception exFail = null;
            do
            {
                try
                {
                    if (!Utils.IsWindows && !File.Exists(LocalStoreFilePath))
                    {
                        // Non-Windows platform file permissions must be set individually.
                        // Windows platform file ACLs are inherited from containing directory.
                        using (File.Create(LocalStoreFilePath)) { }
                        SetFilePermissions(
                            filePath: LocalStoreFilePath,
                            isDirectory: false);
                    }

                    // Write to file.
                    using (var fileStream = File.OpenWrite(LocalStoreFilePath))
                    {
                        fileStream.Seek(0, 0);

                        // Write hash length and hash to file.
                        fileStream.Write(
                            array: BitConverter.GetBytes(dataHash.Length),
                            offset: 0,
                            count: intSize);
                        fileStream.Write(
                            array: dataHash,
                            offset: 0,
                            count: dataHash.Length);
                        
                        // Write data blob to file.
                        fileStream.Write(
                            array: fileDataBlob,
                            offset: 0,
                            count: fileDataBlob.Length);

                        if (fileStream.Position != fileStream.Length)
                        {
                            fileStream.SetLength(fileStream.Position);
                        }

                        lock (_syncObject)
                        {
                            _lastStoreWriteTime = DateTime.Now;
                        }

                        errorMsg = string.Empty;
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
            out string errorMsg)
        {
            data = null;

            if (!File.Exists(LocalStoreFilePath))
            {
                errorMsg = "NoFile";
                return false;
            }

            // Open and read from file stream
            var intSize = sizeof(Int32);
            byte[] intField = new byte[intSize];
            byte[] hash = null;
            byte[] fileDataBlob = null;

            var count = 0;
            Exception exFail = null;
            do
            {
                try
                {
                    using (var fileStream = File.OpenRead(LocalStoreFilePath))
                    {
                        // Read file data hash.
                        fileStream.Read(intField, 0, intSize);
                        var hashSize = BitConverter.ToInt32(intField, 0);
                        hash = new byte[hashSize];
                        fileStream.Read(hash, 0, hashSize);

                        // Read file data blob.
                        var fileDataBlobSize = (int) (fileStream.Length - (intSize + hashSize));
                        fileDataBlob = new byte[fileDataBlobSize];
                        fileStream.Read(fileDataBlob, 0, fileDataBlobSize);

                        break;
                    }
                }
                catch (IOException exIO)
                {
                    // Make up to four attempts.
                    exFail = exIO;
                }
                catch (PasswordRequiredException)
                {
                    // Propagate password required.
                    throw;
                }
                catch (Exception ex)
                {
                    // Unexpected error.
                    exFail = ex;
                    break;
                }

                System.Threading.Thread.Sleep(250);

            } while (++count < 4);

            if (exFail != null || hash == null || fileDataBlob == null)
            {
                errorMsg = string.Format(
                    CultureInfo.InvariantCulture,
                    @"Unable to read from local store file with error: {0}",
                    (exFail != null) ? exFail.Message : string.Empty);

                return false;
            }

            // Validate file data blob integrity.
            if (!CryptoUtils.ValidateHashWithPasswordOrUser(
                passWord: password,
                hash: hash,
                dataToValidate: fileDataBlob))
            {
                errorMsg = "Store file integrity check failed.";
                return false;
            }

            // Extract key blob size.
            var index = 0;
            Buffer.BlockCopy(
                src: fileDataBlob,
                srcOffset: index,
                dst: intField,
                dstOffset: 0,
                count: intSize);
            index += intSize;
            var keyBlobSize = BitConverter.ToInt32(intField, 0);

            // Extract iv blob size.
            Buffer.BlockCopy(
                src: fileDataBlob,
                srcOffset: index,
                dst: intField,
                dstOffset: 0,
                count: intSize);
            index += intSize;
            var ivBlobSize = BitConverter.ToInt32(intField, 0);

            // Extract json blob size.
            Buffer.BlockCopy(
                src: fileDataBlob,
                srcOffset: index,
                dst: intField,
                dstOffset: 0,
                count: intSize);
            index += intSize;
            var jsonBlobSize = BitConverter.ToInt32(intField, 0);

            // Extract key blob
            var keyBlob = new byte[keyBlobSize];
            Buffer.BlockCopy(
                src: fileDataBlob,
                srcOffset: index,
                dst: keyBlob,
                dstOffset: 0,
                count: keyBlobSize);
            index += keyBlobSize;

            // Extract iv blob
            var ivBlob = new byte[ivBlobSize];
            Buffer.BlockCopy(
                src: fileDataBlob,
                srcOffset: index,
                dst: ivBlob,
                dstOffset: 0,
                count: ivBlobSize);
            index += ivBlobSize;

            var key = new AesKey(
                key: keyBlob,
                iv: ivBlob);

            // Extract json blob
            var jsonBlob = new byte[jsonBlobSize];
            Buffer.BlockCopy(
                src: fileDataBlob,
                srcOffset: index,
                dst: jsonBlob,
                dstOffset: 0,
                count: jsonBlobSize);
            index += jsonBlobSize;

            var jsonStr = Encoding.UTF8.GetString(
                CryptoUtils.DecryptWithKey(
                    passWord: password,
                    key: key,
                    data: jsonBlob));

            // Extract data blob
            var dataBlobSize = (fileDataBlob.Length - (keyBlobSize + ivBlobSize + jsonBlobSize +(intSize * 3)));
            var dataBlob = new byte[dataBlobSize];
            Buffer.BlockCopy(
                src: fileDataBlob,
                srcOffset: index,
                dst: dataBlob,
                dstOffset: 0,
                count: dataBlobSize);

            data = new SecureStoreData(
                key: key,
                json: jsonStr,
                blob: dataBlob);

            errorMsg = string.Empty;
            return true;
        }

        public static bool WriteConfigFile(
            SecureStoreConfig configData,
            out string errorMsg)
        {
            AesKey key = null;
            var count = 0;
            Exception exFail = null;
            do
            {
                try
                {
                    var jsonStr = configData.ConvertToJson();

                    // Encrypt config json data.
                    key = CryptoUtils.GenerateKeyFromPassword(Environment.UserName);
                    var jsonEncrypted = CryptoUtils.EncryptWithKey(
                        passWord: null,
                        key: key,
                        Encoding.UTF8.GetBytes(jsonStr));

                    lock (_syncObject)
                    {
                        _lastConfigWriteTime = DateTime.Now;
                    }

                    if (!Utils.IsWindows && !File.Exists(LocalConfigFilePath))
                    {
                        // Non-Windows platform file permissions must be set individually.
                        // Windows platform file ACLs are inherited from containing directory.
                        using (File.Create(LocalConfigFilePath)) { }
                        SetFilePermissions(
                            filePath: LocalConfigFilePath,
                            isDirectory: false);
                    }

                    File.WriteAllBytes(
                        path: LocalConfigFilePath,
                        bytes: jsonEncrypted);
                
                    errorMsg = string.Empty;
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
                finally
                {
                    key?.Clear();
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
            out string errorMsg)
        {
            configData = null;

            if ((!File.Exists(LocalConfigFilePath)))
            {
                errorMsg = "NoConfigFile";
                return false;
            }

            // Open and read from file stream
            AesKey key = null;
            var count = 0;
            Exception exFail = null;
            do
            {
                try
                {
                    var encryptedConfigJson = File.ReadAllBytes(LocalConfigFilePath);

                    // Decrypt config json data.
                    key = CryptoUtils.GenerateKeyFromPassword(Environment.UserName);
                    var configJsonBlob = CryptoUtils.DecryptWithKey(
                        passWord: null,
                        key: key,
                        data: encryptedConfigJson);

                    var configJson = Encoding.UTF8.GetString(configJsonBlob);
                    configData = new SecureStoreConfig(configJson);
                    errorMsg = string.Empty;
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
                finally
                {
                    key?.Clear();
                }

                System.Threading.Thread.Sleep(250);

            } while (++count < 4);

            errorMsg = string.Format(
                CultureInfo.InvariantCulture,
                @"Unable to read from local store configuration file with error: {0}",
                exFail.Message);

            return false;
        }

        public static bool RemoveStoreFile(out string errorMsg)
        {
            var count = 0;
            Exception exFail = null;
            do
            {
                try
                {
                    File.Delete(LocalStoreFilePath);
                    errorMsg = string.Empty;
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
                        _lastStoreFileChange = lastFileChange;
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

        private static void SetDirectoryACLs(string directoryPath)
        {
            // Windows platform.

            // For Windows, file permissions are set to FullAccess for current user account only.
            var dirInfo = new DirectoryInfo(directoryPath);
            var dirSecurity = new DirectorySecurity();

            // SetAccessRule method applies to this directory.
            dirSecurity.SetAccessRule(
                new FileSystemAccessRule(
                    identity: WindowsIdentity.GetCurrent().User,
                    type: AccessControlType.Allow,
                    fileSystemRights: FileSystemRights.FullControl,
                    inheritanceFlags: InheritanceFlags.None,
                    propagationFlags: PropagationFlags.None));

            // AddAccessRule method applies to child directories and files.
            dirSecurity.AddAccessRule(
                new FileSystemAccessRule(
                identity: WindowsIdentity.GetCurrent().User,
                fileSystemRights: FileSystemRights.FullControl,
                type: AccessControlType.Allow,
                inheritanceFlags: InheritanceFlags.ObjectInherit | InheritanceFlags.ContainerInherit,
                propagationFlags: PropagationFlags.InheritOnly));

            // Set access rule protections.
            dirSecurity.SetAccessRuleProtection(
                isProtected: true,
                preserveInheritance: false);

            // Set directory owner.
            dirSecurity.SetOwner(WindowsIdentity.GetCurrent().User);

            // Apply rules.
            dirInfo.SetAccessControl(dirSecurity);
        }

        private static void SetFilePermissions(
            string filePath,
            bool isDirectory)
        {
            // Non-Windows platforms.

            // Set directory permissions to current user only.
            /*
                Current user is user owner.
                Current user is group owner.
                Permission for user (dir) owner:    rw(x)   (execute for directories only)
                Permissions for group owner:        ---     (no access)
                Permissions for others:             ---     (no access)
            */
            var script = isDirectory ? 
                string.Format(CultureInfo.InvariantCulture, @"chmod u=rwx,g=---,o=--- {0}", filePath) :
                string.Format(CultureInfo.InvariantCulture, @"chmod u=rw-,g=---,o=--- {0}", filePath);
            PowerShellInvoker.InvokeScriptCommon<PSObject>(
                script: script,
                args: new object[0] ,
                error: out ErrorRecord error);
        }

        /*
        private const string s_permissionsWarningMessage = "Store access rules have been modified.";
        // TODO: CheckFileACLs, CheckFilePermissions
        private static bool CheckDirectoryACLs(
            string directoryPath,
            out string warningMessage)
        {
            // Windows platform.
            var dirInfo = new DirectoryInfo(directoryPath);
            var dirAccessRules = dirInfo.GetAccessControl().GetAccessRules(
                includeExplicit: true,
                includeInherited: false,
                targetType: typeof(SecurityIdentifier));

            if (dirAccessRules.Count > 1)
            {
                warningMessage = s_permissionsWarningMessage;
                return false;
            }

            var rule = dirAccessRules[0];

            if (rule.IsInherited ||
                rule.IdentityReference != WindowsIdentity.GetCurrent().User ||
                !rule.InheritanceFlags.HasFlag(InheritanceFlags.ContainerInherit) ||
                !rule.InheritanceFlags.HasFlag(InheritanceFlags.ObjectInherit) ||
                rule.PropagationFlags != PropagationFlags.None)
            {
                warningMessage = s_permissionsWarningMessage;
                return false;
            }

            warningMessage = string.Empty;
            return true;
        }

        private static bool CheckDirectoryPermissions(
            string directoryPath,
            out string warningMessage)
        {
            // TODO:
            warningMessage = "Not yet supported.";
            return false;
        }
        */

        #endregion
    }

    #endregion

    #region Event args

    internal sealed class FileUpdateEventArgs : EventArgs
    {
        public DateTime FileChangedTime
        {
            get;
        }

        public FileUpdateEventArgs(DateTime fileChangedTime)
        {
            FileChangedTime = fileChangedTime;
        }
    }

    #endregion

    #endregion

    #region PowerShellInvoker

    internal static class PowerShellInvoker
    {
        #region Members

        private static System.Management.Automation.PowerShell _powershell = 
            System.Management.Automation.PowerShell.Create(RunspaceMode.NewRunspace);

        #endregion

        #region Methods

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

    #region LocalSecretStore

    /// <summary>
    /// Local secret store
    /// </summary>
    public sealed class LocalSecretStore : IDisposable
    {
        #region Members

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

        internal SecureStoreConfig Configuration
        {
            get => new SecureStoreConfig(
                        scope: _secureStore.ConfigData.Scope,
                        passwordRequired: _secureStore.ConfigData.PasswordRequired,
                        passwordTimeout: _secureStore.ConfigData.PasswordTimeout,
                        doNotPrompt: _secureStore.ConfigData.DoNotPrompt);
        }

        public static bool AllowPrompting
        {
            get => SecureStoreFile.ConfigAllowsPrompting;
        }

        #endregion
        
        #region Constructor

        private LocalSecretStore()
        {
        }

        internal LocalSecretStore(
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
            _secureStore?.Dispose();
        }

        #endregion

        #region Public static

        public static LocalSecretStore GetInstance(
            SecureString password = null,
            PSCmdlet cmdlet = null)
        {
            if (password != null)
            {
                lock (SyncObject)
                {
                    LocalStore = null;
                }
            }

            if (LocalStore == null)
            {
                lock (SyncObject)
                {
                    if (LocalStore == null)
                    {
                        try
                        {
                            LocalStore = new LocalSecretStore(
                                SecureStore.GetStore(password));
                        }
                        catch (PasswordRequiredException)
                        {
                            if (password != null)
                            {
                                throw new PasswordRequiredException("The provided password is incorrect for the Microsoft.PowerShell.SecretStore module vault.");
                            }

                            if (cmdlet != null && AllowPrompting)
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
                                        message: "Creating a new Microsoft.PowerShell.SecretStore module vault store file. A password is required by the current store configuration.");
                                }

                                LocalStore = new LocalSecretStore(
                                    SecureStore.GetStore(password));

                                return LocalStore;
                            }

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

        private const string VaultPaswordPrompt = "Vault {0} requires a password.";
        public static void PromptAndUnlockVault(
            string vaultName,
            PSCmdlet cmdlet)
        {
            var promptMessage = string.Format(CultureInfo.InvariantCulture,
                VaultPaswordPrompt, vaultName);

            var vaultKey = Utils.PromptForPassword(
                cmdlet: cmdlet,
                verifyPassword: false,
                message: promptMessage);

            LocalSecretStore.GetInstance(vaultKey).UnlockLocalStore(vaultKey);
        }

        #endregion
        
        #region Public methods

        public bool WriteObject<T>(
            string name,
            T objectToWrite,
            out string errorMsg)
        {
            switch (objectToWrite)
            {
                case byte[] blobToWrite:
                    return WriteBlob(
                        name,
                        blobToWrite,
                        ByteArrayType,
                        out errorMsg);

                case string stringToWrite:
                    return WriteString(
                        name,
                        stringToWrite,
                        out errorMsg);

                case SecureString secureStringToWrite:
                    return WriteSecureString(
                        name,
                        secureStringToWrite,
                        out errorMsg);

                case PSCredential credentialToWrite:
                    return WritePSCredential(
                        name,
                        credentialToWrite,
                        out errorMsg);

                case Hashtable hashtableToWrite:
                    return WriteHashtable(
                        name,
                        hashtableToWrite,
                        out errorMsg);
                
                default:
                    throw new InvalidOperationException("Invalid type. Types supported: byte[], string, SecureString, PSCredential, Hashtable");
            }
        }

        public bool ReadObject(
            string name,
            out object outObject,
            out string errorMsg)
        {
            if (!ReadBlob(
                name,
                out byte[] outBlob,
                out string typeName,
                out errorMsg))
            {
                outObject = null;
                return false;
            }

            errorMsg = string.Empty;
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
                        out errorMsg);

                default:
                    throw new InvalidOperationException("Invalid type. Types supported: byte[], string, SecureString, PSCredential, Hashtable");
            }
        }

        public bool EnumerateObjectInfo(
            string filter,
            out SecretInformation[] outSecretInfo,
            string vaultName,
            out string errorMsg)
        {
            if (!EnumerateBlobs(
                filter,
                out EnumeratedBlob[] outBlobs,
                out errorMsg))
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
                                name: item.Name,
                                type: SecretType.ByteArray,
                                vaultName: vaultName));
                        break;

                    case StringType:
                        outList.Add(
                            new SecretInformation(
                                name: item.Name,
                                type: SecretType.String,
                                vaultName: vaultName));
                        break;

                    case SecureStringType:
                        outList.Add(
                            new SecretInformation(
                                name: item.Name,
                                type: SecretType.SecureString,
                                vaultName: vaultName));
                        break;

                    case PSCredentialType:
                        outList.Add(
                            new SecretInformation(
                                name: item.Name,
                                type: SecretType.PSCredential,
                                vaultName: vaultName));
                        break;

                    case HashtableType:
                        outList.Add(
                            new SecretInformation(
                                name: item.Name,
                                type: SecretType.Hashtable,
                                vaultName: vaultName));
                        break;
                }
            }

            outSecretInfo = outList.ToArray();
            errorMsg = string.Empty;
            return true;
        }

        public bool DeleteObject(
            string name,
            out string errorMsg)
        {
            if (!ReadObject(
                name: name,
                outObject: out object outObject,
                out errorMsg))
            {
                return false;
            }

            switch (outObject)
            {
                case Hashtable hashtable:
                    return DeleteHashtable(
                        name,
                        out errorMsg);

                default:
                    return DeleteBlob(
                        name,
                        out errorMsg);
            }
        }

        #endregion

        #region Internal methods

        internal void UnlockLocalStore(
            SecureString password,
            int? passwordTimeout = null)
        {
            _secureStore.SetPassword(password);
            
            try
            {
                _secureStore.UpdateDataFromFile();
            }
            catch (PasswordRequiredException)
            {
                throw new PasswordRequiredException("Unable to unlock Microsoft.PowerShell.SecretStore vault. Password is invalid.");
            }

            if (passwordTimeout.HasValue)
            {
                _secureStore.SetPasswordTimer(passwordTimeout.Value);
            }
        }

        internal void UpdatePassword(
            SecureString newPassword,
            SecureString oldPassword)
        {
            _secureStore.UpdatePassword(
                newPassword,
                oldPassword,
                skipPasswordRequiredCheck: false,
                skipConfigFileWrite: false);
        }

        internal bool UpdateConfiguration(
            SecureStoreConfig newConfigData,
            PSCmdlet cmdlet,
            out string errorMsg)
        {
            return _secureStore.UpdateConfigData(
                newConfigData,
                cmdlet,
                out errorMsg);
        }

        #endregion

        #region Private methods

        #region Helper methods

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

        internal static bool IsHTTagged(string str)
        {
            return str.StartsWith(PSHashtableTag);
        }

        #endregion

        #region Blob methods

        private bool WriteBlob(
            string name,
            byte[] blob,
            string typeName,
            out string errorMsg)
        {
            return _secureStore.WriteBlob(
                name: name,
                blob: blob,
                typeName: typeName,
                attributes: DefaultTag,
                errorMsg: out errorMsg);
        }

        private bool ReadBlob(
            string name,
            out byte[] blob,
            out string typeName,
            out string errorMsg)
        {
            if (!_secureStore.ReadBlob(
                name: name,
                blob: out blob,
                metaData: out SecureStoreMetadata metadata,
                errorMsg: out errorMsg))
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
            out string errorMsg)
        {
            if (!_secureStore.EnumerateBlobs(
                filter: filter,
                metaData: out SecureStoreMetadata[] metadata,
                out errorMsg))
            {
                blobs = null;
                return false;
            }

            List<EnumeratedBlob> blobArray = new List<EnumeratedBlob>(metadata.Length);
            foreach (var metaItem in metadata)
            {
                if (!IsHTTagged(metaItem.Name))
                {
                    blobArray.Add(
                        new EnumeratedBlob
                        {
                            Name = metaItem.Name,
                            TypeName = metaItem.TypeName
                        });
                }
            }

            blobs = blobArray.ToArray();
            return true;
        }

        private bool DeleteBlob(
            string name,
            out string errorMsg)
        {
            return _secureStore.DeleteBlob(
                name: name,
                errorMsg: out errorMsg);
        }

        #endregion

        #region String methods

        private bool WriteString(
            string name,
            string strToWrite,
            out string errorMsg)
        {
            return WriteBlob(
                name: name,
                blob: Encoding.UTF8.GetBytes(strToWrite),
                typeName: StringType,
                errorMsg: out errorMsg);
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
            out string errorMsg)
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
                errorMsg: out errorMsg);
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
            out string errorMsg)
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
                        errorMsg: out errorMsg);
                }
                finally
                {
                    CryptoUtils.ZeroOutData(data);
                }
            }
            
            errorMsg = "Unable to read SecureString data.";
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
            out string errorMsg)
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
                        errorMsg: out errorMsg);
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
            
            errorMsg = "Unable to read SecureString data.";
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
            out string errorMsg)
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
                errorMsg: out errorMsg))
            {
                return false;
            }

            // Write each entry as a separate secret.  Roll back on any failure.
            var success = false;
            try
            {
                foreach (var entry in entries)
                {
                    success = WriteObject(
                        name: entry.Key,
                        objectToWrite: entry.Value,
                        errorMsg: out errorMsg);
                    
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
                    foreach (var entry in entries)
                    {
                        DeleteBlob(
                            name: entry.Key,
                            errorMsg: out string _);
                    }

                    // Remove the Hashtable member names.
                    DeleteBlob(
                        name: name,
                        errorMsg: out string _);
                }
            }
        }

        private bool ReadHashtable(
            string name,
            byte[] blob,
            out object outHashtable,
            out string errorMsg)
        {
            // Get array of Hashtable secret names.
            ReadStringArray(
                blob,
                out string[] entryNames);
            
            outHashtable = null;
            var hashtable = new Hashtable();
            foreach (var entryName in entryNames)
            {
                if (ReadObject(
                    entryName,
                    out object outObject,
                    out errorMsg))
                {
                    hashtable.Add(
                    RecoverKeyname(entryName, name),
                    outObject);
                }
            }

            outHashtable = hashtable;
            errorMsg = string.Empty;
            return true;
        }

        private bool DeleteHashtable(
            string name,
            out string errorMsg)
        {
            // Get array of Hashtable secret names.
            if (!ReadBlob(
                name,
                out byte[] blob,
                out string typeName,
                out errorMsg))
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
                    out errorMsg);
            }

            // Delete the Hashtable secret names list.
            DeleteBlob(
                name: name,
                out errorMsg);

            return true;
        }

        #endregion
    
        #endregion
    }

    #endregion
}
